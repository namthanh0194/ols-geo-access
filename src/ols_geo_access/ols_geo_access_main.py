import importlib
import copy
import json
import os
import re
import subprocess
from pathlib import Path
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from functools import wraps

import lib.maxmind as maxmind_module
import lib.bot_activity as bot_activity_module
import lib.cloudflare_ranges as cloudflare_ranges_module
import lib.config_generator as config_generator_module
import lib.config_store as config_store_module
import lib.paths as paths_module
import lib.proxy_trust_config as proxy_trust_config_module
import lib.proxy_trust_transaction as proxy_trust_transaction_module
import lib.rollback as rollback_module
import lib.service_sources as service_sources_module
import lib.updater as updater_module
import lib.traffic_detection as traffic_detection_module
import lib.domain_inventory as domain_inventory_module
import lib.backend_detector as backend_detector_module
import lib.nginx_adapter as nginx_adapter_module

importlib.reload(paths_module)
importlib.reload(maxmind_module)
importlib.reload(bot_activity_module)
importlib.reload(cloudflare_ranges_module)
importlib.reload(config_store_module)
importlib.reload(config_generator_module)
importlib.reload(proxy_trust_config_module)
importlib.reload(proxy_trust_transaction_module)
importlib.reload(rollback_module)
importlib.reload(service_sources_module)
importlib.reload(updater_module)
importlib.reload(traffic_detection_module)
importlib.reload(domain_inventory_module)
importlib.reload(backend_detector_module)
importlib.reload(nginx_adapter_module)
from lib import nginx_rollback as nginx_transactions
importlib.reload(nginx_transactions)
from lib import nginx_manager as nginx_manager_module
importlib.reload(nginx_manager_module)
from lib.updater import PluginUpdater
from lib.nginx_manager import NginxManager
from lib import nginx_prerequisites
importlib.reload(nginx_prerequisites)
from lib.traffic_detection import classify_addresses, local_origin_addresses, observe, resolve_addresses

from lib.baseline_audit import audit_baseline as build_baseline_report
from lib.baseline_repair import _atomic_write
from lib.bot_activity import (
    BOT_LABELS,
    SERVICE_LABELS,
    TRAFFIC_SOURCE_TYPES,
    collect_bot_activity,
    collect_traffic_activity,
)
from lib.cloudflare_ranges import (
    download_cloudflare_ranges,
    prepare_cloudflare_snapshot,
    snapshot_freshness,
    validate_cloudflare_snapshot,
)
from lib.feed_updater import PROVIDER_SOURCES, enabled_feeds, enabled_snapshot_names
from lib.ols_adapter import OLSAdapter
from lib.nginx_adapter import NginxAdapter
from lib.backend_detector import detect_webserver_environment, load_persisted_backend
from lib.proxy_trust_audit import (
    ProxyTrustBlocking,
    ProxyTrustResult,
    assert_proxy_trust,
    audit_proxy_trust as build_proxy_trust_report,
    load_proxy_prefix_snapshot,
)
from lib.proxy_trust_config import inspect_global_proxy_config
from lib.proxy_trust_transaction import (
    ProxyTrustRecoveryRequired,
    apply_proxy_trust_update,
    inspect_proxy_trust_recovery,
    load_proxy_trust_state,
)
from lib.audit_log import AuditLogger
from lib.config_store import load_json, save_json
from lib.config_validator import (
    apply_geoip_proposal,
    build_geoip_proposal,
    prune_geoip_history,
    restore_geoip_transaction,
)
from lib.deployment_journal import (
    RecoveryRequired,
    begin_operation,
    inspect_interrupted_release,
    prune_operation_history,
    recover_interrupted_release,
    set_operation_status,
)
from lib.domain_inventory import collect_domains, collect_domains_nginx
from lib.maxmind import (
    MaxMindRecoveryRequired,
    create_country_lookup,
    get_credential_status,
    install_country_database,
    save_credentials,
    stage_country_database,
)
from lib.paths import PluginPaths
from lib.service_sources import (
    MANAGED_SERVICE_IDS,
    describe_service_sources,
    download_hubspot_feed,
    download_jetpack_feed,
    merge_jetpack_allowlist,
    normalize_jetpack_feed,
    prepare_hubspot_allowlist,
    prepare_jetpack_allowlist,
)
from lib.rollback import (
    apply_release as apply_managed_release,
    build_staging as build_managed_staging,
    list_releases as list_managed_releases,
    prune_release_history,
)
from lib.transaction import deployment_lock, process_lock


def _backend_api(ols_only=True, nginx=False, runtime_only=False):
    def decorate(method):
        @wraps(method)
        def dispatch(self, *args, **kwargs):
            backend = self._backend_status()
            if ols_only and not backend["mutation_allowed"] and not (nginx and runtime_only and backend['runtime_verified']):
                return self._backend_refusal(backend)
            if ols_only and self._webserver_type == 'nginx' and not nginx:
                return {'status': False, 'code': 'nginx_endpoint_unavailable', 'msg': 'Thao tác này chỉ dành cho OpenLiteSpeed.',
                        'webserver_type': 'nginx', 'backend': backend}
            try:
                response = method(self, *args, **kwargs)
            except (OSError, ValueError) as error:
                if ols_only:
                    raise
                response = {"status": False, "code": "backend_read_error", "msg": str(error)}
            response.setdefault("webserver_type", backend["webserver_type"])
            response.setdefault("backend", backend)
            return response
        return dispatch
    return decorate


class ols_geo_access_main:
    VERSION = "0.1.0"

    def __init__(
        self,
        adapter=None,
        vhost_root=None,
        server_config_path=None,
        required_proxy_prefixes=None,
        releases_root=None,
        state_root=None,
        geoip_database=Path("/usr/local/share/GeoIP/GeoLite2-Country.mmdb"),
        plugin_root=Path("/www/server/panel/plugin/ols_geo_access"),
        database_path=Path("/www/server/panel/data/default.db"),
        snapshots_root=None,
        service_pid_path=Path("/tmp/lshttpd/lshttpd.pid"),
        logs_root=Path("/www/wwwlogs"),
        maxmind_downloader=stage_country_database,
        service_feed_downloader=download_jetpack_feed,
        hubspot_feed_downloader=download_hubspot_feed,
        cloudflare_downloader=download_cloudflare_ranges,
        country_lookup=None,
        clock=None,
        traffic_resolver=resolve_addresses,
        origin_address_loader=local_origin_addresses,
        environment_reader=None,
    ):
        self._plugin_root = Path(plugin_root)
        self._paths = PluginPaths(self._plugin_root)
        self._environment_reader = environment_reader or detect_webserver_environment
        self._environment = {}
        self._persisted_backend = "unknown"
        self._adapter_error = ""
        try:
            self._environment = self._environment_reader()
            self._persisted_backend = load_persisted_backend(self._paths)
        except (OSError, ValueError) as error:
            self._adapter_error = str(error)
        detected = self._environment.get("backend", "unknown")
        self._webserver_type = self._persisted_backend if self._persisted_backend != "unknown" else detected
        if self._webserver_type not in {"openlitespeed", "nginx"}:
            self._webserver_type = "unknown"
        nginx = self._webserver_type == "nginx"
        self._vhost_root = Path(vhost_root or ("/www/server/panel/vhost/nginx" if nginx else "/www/server/panel/vhost/openlitespeed"))
        self._server_config_path = Path(server_config_path or self._environment.get("main_config") or (
            "/www/server/nginx/conf/nginx.conf" if nginx else "/usr/local/lsws/conf/httpd_config.conf"
        ))
        runtime_verified = self._backend_status()["runtime_verified"]
        self._adapter = adapter
        if self._adapter is None and runtime_verified:
            try:
                self._adapter = NginxAdapter(
                    self._environment["binary"], self._server_config_path,
                    prefix=self._environment.get("prefix"), environment_reader=self._environment_reader,
                ) if nginx else OLSAdapter()
            except (OSError, ValueError) as error:
                self._adapter_error = str(error)
        self._updater = PluginUpdater(plugin_dir=self._plugin_root)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._traffic_resolver = traffic_resolver
        self._origin_address_loader = origin_address_loader
        self._cloudflare_downloader = cloudflare_downloader
        self._cloudflare_snapshot = None
        self._proxy_trust_state = load_proxy_trust_state(
            self._paths.data_file("proxy_trust_state")
        )
        self._proxy_freshness = {
            "state": "stale_blocking",
            "age_seconds": None,
            "blocking": True,
            "checked_at": self._proxy_trust_state.get("last_success_at"),
        }
        self._proxy_prefix_override = required_proxy_prefixes is not None
        self._proxy_prefix_error = None
        if required_proxy_prefixes is None:
            self._reload_cloudflare_state()
        else:
            self._required_proxy_prefixes = tuple(required_proxy_prefixes)
            self._proxy_freshness = {
                "state": "fresh",
                "age_seconds": 0,
                "blocking": False,
                "checked_at": None,
            }
        self._releases_root = Path(releases_root or self._plugin_root / "generated" / ("nginx-releases" if nginx else "releases"))
        self._state_root = Path(state_root or self._paths.data / ("nginx-release-state" if nginx else "release-state"))
        self._geoip_database = Path(geoip_database)
        self._database_path = Path(database_path)
        self._snapshots_root = Path(snapshots_root) if snapshots_root else self._plugin_root / "data" / "snapshots"
        self._audit = AuditLogger(self._plugin_root / "logs" / "audit.log")
        self._service_pid_path = Path(service_pid_path)
        self._logs_root = Path(logs_root)
        self._maxmind_credentials = self._plugin_root / "data" / "secrets" / "maxmind.json"
        self._maxmind_downloader = maxmind_downloader
        self._service_feed_downloader = service_feed_downloader
        self._hubspot_feed_downloader = hubspot_feed_downloader
        self._geoip_proposals = self._plugin_root / "data" / "geoip-proposals"
        self._geoip_transactions = self._plugin_root / "data" / "geoip-transactions"
        self._maxmind_staging = self._plugin_root / "tmp" / "maxmind"
        self._country_lookup_override = country_lookup
        self._cached_country_lookup = None
        self._cached_geoip_signature = None
        self._nginx = NginxManager(self) if nginx else None

    def _backend_status(self):
        environment = {}
        persisted = "unknown"
        code = None
        reason = ""
        try:
            environment = self._environment_reader()
            persisted = load_persisted_backend(self._paths)
            if self._adapter_error:
                code, reason = "backend_identity_error", self._adapter_error
            elif (environment.get("confidence") != "verified" or environment.get("is_container")
                  or environment.get("backend") not in {"openlitespeed", "nginx"}
                  or not all(environment.get(key) for key in ("binary", "main_config", "master_pid", "start_time"))):
                code, reason = "backend_unverified", "Chưa xác minh được webserver host; không thay đổi cấu hình."
            elif persisted == "unknown":
                code, reason = "backend_identity_missing", "Chưa có định danh backend được lưu; không tự nhận quyền quản lý webserver."
            elif persisted != environment["backend"]:
                code, reason = "backend_identity_mismatch", "Webserver hiện tại khác backend đã lưu; cần xử lý chuyển đổi riêng."
            elif persisted != self._persisted_backend:
                code, reason = "backend_identity_changed", "Định danh backend đã thay đổi; hãy mở lại plugin để kiểm tra."
            elif any(environment.get(key) != self._environment.get(key) for key in (
                "backend", "binary", "main_config", "prefix", "master_pid", "start_time", "is_container",
            )):
                code, reason = "backend_runtime_changed", "Runtime webserver đã thay đổi; hãy mở lại plugin để kiểm tra."
            elif hasattr(self, "_adapter") and self._adapter is None:
                code, reason = "backend_adapter_unavailable", "Adapter webserver chưa sẵn sàng; hãy mở lại plugin để kiểm tra."
        except (OSError, ValueError) as error:
            code, reason = "backend_identity_error", str(error)
        verified = code is None
        if verified and self._webserver_type == "nginx":
            manager = getattr(self, '_nginx', None)
            missing = manager.requirements() if manager is not None else ['Backend đang khởi tạo']
            if missing:
                code = 'nginx_diagnostic_only'
                reason = 'Chưa thể áp dụng Nginx: ' + '; '.join(missing)
        return {
            "webserver_type": self._webserver_type,
            "detected_webserver_type": environment.get("backend", "unknown"),
            "persisted_webserver_type": persisted,
            "runtime_diagnostic": {key: environment.get(key) for key in ("confidence", "reason", "master_pid", "is_container")},
            "runtime_verified": verified,
            "diagnostic_only": code is not None,
            "mutation_allowed": code is None,
            "code": code, "reason": reason,
        }

    @staticmethod
    def _backend_refusal(backend):
        return {"status": False, "code": backend["code"], "msg": backend["reason"],
                "webserver_type": backend["webserver_type"], "backend": backend}

    def _require_ols_backend(self):
        backend = self._backend_status()
        if self._webserver_type != 'openlitespeed' or not backend["mutation_allowed"]:
            raise RuntimeError(backend["reason"])

    def _collect_backend_domains(self, settings):
        arguments = {
            "traffic_modes": {domain: value["traffic_mode"] for domain, value in settings.items()},
            "managed_domains": {domain for domain, value in settings.items() if value.get("enabled") and value.get("group") != "NONE"},
        }
        if self._webserver_type == "nginx":
            return collect_domains_nginx(self._database_path, self._vhost_root,
                                         config_prefix=self._server_config_path.parent, **arguments)
        return collect_domains(self._database_path, self._vhost_root, **arguments)

    def _country_lookup(self):
        if self._country_lookup_override is not None:
            return self._country_lookup_override
        try:
            if not self._geoip_database.is_file():
                return None
            stat = self._geoip_database.stat()
            signature = (str(self._geoip_database.resolve()), stat.st_mtime, stat.st_size)
            if signature != self._cached_geoip_signature:
                self._cached_country_lookup = create_country_lookup(self._geoip_database)
                self._cached_geoip_signature = signature
            return self._cached_country_lookup
        except OSError:
            return None

    def _reload_cloudflare_state(self):
        if self._proxy_prefix_override:
            return
        try:
            snapshot_path = self._paths.data_file("cloudflare_prefixes")
            if snapshot_path.is_symlink() or not snapshot_path.is_file():
                raise ValueError("Cloudflare prefix snapshot is unavailable")
            snapshot = validate_cloudflare_snapshot(
                json.loads(snapshot_path.read_text())
            )
            state = load_proxy_trust_state(
                self._paths.data_file("proxy_trust_state")
            )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self._cloudflare_snapshot = None
            self._required_proxy_prefixes = ()
            self._proxy_prefix_error = str(error)
            return
        freshness = snapshot_freshness(
            snapshot if self._webserver_type == 'nginx' else {"checked_at": state.get("last_success_at")},
            now=self._clock(),
        )
        self._cloudflare_snapshot = snapshot
        self._proxy_trust_state = state
        self._required_proxy_prefixes = tuple(snapshot["prefixes"])
        self._proxy_freshness = {
            **freshness,
            "checked_at": state.get("last_success_at"),
        }
        self._proxy_prefix_error = None

    @staticmethod
    def _json_bytes(name, payload):
        validator = config_store_module.VALIDATORS.get(name)
        if validator:
            validator(payload)
        return (
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()

    def _server_config_text(self):
        if not self._server_config_path.is_file():
            return ""
        return self._server_config_path.read_text(errors="replace")

    def _proxy_trust_report(self, domain, traffic_mode, server_config_text=None):
        self._reload_cloudflare_state()
        if traffic_mode == "cloudflare" and self._proxy_prefix_error:
            return ProxyTrustResult(
                domain=domain,
                traffic_mode=traffic_mode,
                state="proxy_prefix_snapshot_invalid",
                blocking=True,
                trusted_only=False,
                ipv4_complete=False,
                ipv6_complete=False,
                configured_prefixes=(),
                missing_prefixes=(),
                remediation=(
                    "Install a valid packaged Cloudflare IPv4 and IPv6 prefix snapshot.",
                ),
                snapshot_freshness="stale_blocking",
                snapshot_checked_at=self._proxy_trust_state.get("last_success_at"),
                snapshot_blocking=True,
            )
        return build_proxy_trust_report(
            domain,
            traffic_mode,
            self._server_config_text() if server_config_text is None else server_config_text,
            self._required_proxy_prefixes,
            freshness=self._proxy_freshness,
        )

    def _assert_proxy_trust(self, assignments):
        self._reload_cloudflare_state()
        protected_cloudflare = {
            domain: assignment
            for domain, assignment in assignments.items()
            if assignment.get("enabled")
            and assignment.get("group") != "NONE"
            and assignment.get("traffic_mode") == "cloudflare"
        }
        if not protected_cloudflare:
            return ()
        if self._proxy_prefix_error:
            raise ProxyTrustBlocking(
                self._proxy_trust_report(domain, "cloudflare")
                for domain in sorted(protected_cloudflare)
            )
        return assert_proxy_trust(
            protected_cloudflare,
            self._server_config_text(),
            self._required_proxy_prefixes,
            freshness=self._proxy_freshness,
        )

    @staticmethod
    def _proxy_block_response(error):
        stale = any(
            report.state == "proxy_prefix_snapshot_stale"
            for report in error.reports
        )
        return {
            "status": False,
            "code": "cloudflare_snapshot_stale" if stale else "proxy_trust_blocking",
            "msg": (
                "Danh sách IP Cloudflare chưa được kiểm tra thành công trong 72 giờ; rule đang chạy không bị thay đổi."
                if stale
                else "Cloudflare client-IP trust is not ready; no rule was changed."
            ),
            "domains": [asdict(report) for report in error.reports],
        }

    @staticmethod
    def _proxy_recovery_response(error):
        return {
            "status": False,
            "code": "proxy_trust_recovery_required",
            "msg": str(error),
            "recovery_required": True,
        }

    def _assert_proxy_recovery_clear(self):
        recovery = inspect_proxy_trust_recovery(
            self._plugin_root,
            self._server_config_path,
        )
        if recovery["blocking"]:
            raise ProxyTrustRecoveryRequired(recovery["reason"])
        return recovery

    def _recover_before_mutation(self):
        self._require_ols_backend()
        return recover_interrupted_release(
            self._plugin_root,
            self._state_root,
            self._releases_root,
            self._vhost_root,
            self._adapter.run_config_test,
            self._reload,
            acquire_lock=False,
            audit=self._audit,
        )

    def _finish_failed_operation(self, operation, original_error):
        if operation is None:
            raise original_error
        try:
            self._recover_before_mutation()
        except BaseException as recovery_error:
            if isinstance(recovery_error, RecoveryRequired):
                raise
            raise RecoveryRequired(
                "Managed state deployment recovery failed",
                deployment_error=original_error,
                recovery_error=recovery_error,
            ) from original_error
        original_error.rolled_back = True
        raise original_error

    def _prune_managed_history(self):
        try:
            removed = prune_release_history(
                self._releases_root, self._state_root, keep_completed=10
            )
            removed.extend(
                prune_operation_history(self._state_root, keep_completed=10)
            )
        except BaseException as error:
            self._audit.record_action(
                "retention.managed",
                {"result": "error", "error_type": type(error).__name__, "error": str(error)},
            )
            return []
        if removed:
            self._audit.record_action(
                "retention.managed", {"result": "success", "removed": removed}
            )
        return removed

    def _prune_geoip_history(self):
        try:
            removed = prune_geoip_history(
                self._plugin_root / "data", keep_completed=5
            )
        except BaseException as error:
            self._audit.record_action(
                "retention.geoip",
                {"result": "error", "error_type": type(error).__name__, "error": str(error)},
            )
            return []
        if removed:
            self._audit.record_action(
                "retention.geoip", {"result": "success", "removed": removed}
            )
        return removed

    def _deploy_state_change(
        self,
        *,
        state_changes,
        assignments,
        build_overrides=None,
        action_name,
        expected_domains=None,
    ):
        if self._webserver_type == 'nginx':
            backend = self._backend_status()
            if not backend['mutation_allowed']:
                raise RuntimeError(backend['reason'])
            return self._nginx.deploy(state_changes=state_changes, assignments=assignments, build_overrides=build_overrides,
                action_name=action_name, expected_domains=expected_domains)
        self._require_ols_backend()
        proposed_bytes = {
            str(self._paths.data_file(name).relative_to(self._paths.root)):
                self._json_bytes(name, payload)
            for name, payload in state_changes.items()
        }
        with deployment_lock(self._state_root):
            if expected_domains is not None and load_json(self._paths, "domains") != expected_domains:
                raise ValueError("Cấu hình website đã thay đổi; bỏ kết quả cũ và thử lại")
            self._assert_proxy_trust(assignments)
            self._assert_proxy_recovery_clear()
            self._recover_before_mutation()
            if expected_domains is not None and load_json(self._paths, "domains") != expected_domains:
                raise ValueError("Cấu hình website đã thay đổi sau khôi phục; thử lại")
            current_path = self._state_root / "current.json"
            current = json.loads(current_path.read_text()) if current_path.is_file() else {}
            try:
                manifest = self._build_staging(
                    assignments,
                    build_overrides=build_overrides,
                )
            except BaseException as error:
                error.deployment_stage = "build_release"
                raise
            operation = begin_operation(
                self._plugin_root,
                self._state_root,
                manifest["release_id"],
                current.get("release_id"),
                proposed_bytes,
            )
            operation_dir = (
                self._state_root / "operations" / operation["operation_id"]
            )
            stage = "save_state"
            try:
                for name, payload in state_changes.items():
                    save_json(self._paths, name, payload, audit=self._audit)
                set_operation_status(operation_dir, "state_written")
                set_operation_status(operation_dir, "release_applying")
                stage = "apply_release"
                deployment = apply_managed_release(
                    manifest["release_id"],
                    self._releases_root,
                    self._vhost_root,
                    self._state_root,
                    self._adapter.run_config_test,
                    self._reload,
                    transaction_id=operation["operation_id"],
                    acquire_lock=False,
                    audit=self._audit,
                )
                set_operation_status(operation_dir, "release_reloaded")
                set_operation_status(operation_dir, "committed")
            except BaseException as error:
                error.deployment_stage = stage
                self._audit.record_action(
                    action_name,
                    {
                        "result": "error",
                        "stage": stage,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    },
                )
                self._finish_failed_operation(operation, error)
            self._prune_managed_history()
            self._audit.record_action(
                action_name,
                {
                    "result": "success",
                    "operation_id": operation["operation_id"],
                    "release_id": manifest["release_id"],
                },
            )
            return deployment

    def _deploy_existing_release(self, release_id, action_name):
        self._require_ols_backend()
        with deployment_lock(self._state_root):
            self._recover_before_mutation()
            current_path = self._state_root / "current.json"
            current = json.loads(current_path.read_text()) if current_path.is_file() else {}
            operation = begin_operation(
                self._plugin_root,
                self._state_root,
                release_id,
                current.get("release_id"),
                {},
            )
            operation_dir = (
                self._state_root / "operations" / operation["operation_id"]
            )
            try:
                set_operation_status(operation_dir, "release_applying")
                deployment = apply_managed_release(
                    release_id,
                    self._releases_root,
                    self._vhost_root,
                    self._state_root,
                    self._adapter.run_config_test,
                    self._reload,
                    transaction_id=operation["operation_id"],
                    acquire_lock=False,
                    audit=self._audit,
                )
                set_operation_status(operation_dir, "release_reloaded")
                set_operation_status(operation_dir, "committed")
            except BaseException as error:
                self._audit.record_action(
                    action_name,
                    {
                        "result": "error",
                        "error_type": type(error).__name__,
                        "error": str(error),
                    },
                )
                self._finish_failed_operation(operation, error)
            self._prune_managed_history()
            self._audit.record_action(
                action_name,
                {
                    "result": "success",
                    "operation_id": operation["operation_id"],
                    "release_id": release_id,
                },
            )
            return deployment

    def _apply_allowlist(self, payload, previous=None, action_name="ip_allowlist.auto_apply"):
        assignments = load_json(self._paths, "domains")["domains"]
        return self._deploy_state_change(
            state_changes={"ip_allowlist": payload},
            assignments=assignments,
            build_overrides={"allowlist": payload["entries"]},
            action_name=action_name,
        )

    @_backend_api(nginx=True)
    def apply_scheduled_updates(self, snapshot_candidates, allowlist_candidate=None):
        if self._webserver_type == 'nginx':
            return self._nginx.scheduled(snapshot_candidates, allowlist_candidate)
        if not isinstance(snapshot_candidates, dict):
            raise ValueError("snapshot candidates must be an object")
        try:
            with deployment_lock(self._state_root):
                self._recover_before_mutation()
                providers = load_json(self._paths, "providers")
                enabled = set(enabled_feeds(providers))
                snapshots = {}
                if self._snapshots_root.is_dir():
                    for path in sorted(self._snapshots_root.glob("*.json")):
                        if path.stem in enabled:
                            snapshots[path.stem] = json.loads(path.read_text())
                state_changes = {}
                changed = []
                for provider, candidate in sorted(snapshot_candidates.items()):
                    if provider not in enabled or provider not in PROVIDER_SOURCES:
                        raise ValueError(f"provider is not enabled: {provider}")
                    if not isinstance(candidate, dict) or candidate.get("provider") != provider:
                        raise ValueError(f"invalid snapshot candidate: {provider}")
                    previous = snapshots.get(provider)
                    if not previous or previous.get("checksum") != candidate.get("checksum"):
                        changed.append(provider)
                    snapshots[provider] = candidate
                    relative = Path("data/snapshots") / f"{provider}.json"
                    content = self._json_bytes("snapshot", candidate)
                    target = self._plugin_root / relative
                    if not target.is_file() or target.read_bytes() != content:
                        state_changes[str(relative)] = content

                allowlist = load_json(self._paths, "ip_allowlist")
                state = load_json(self._paths, "state")
                service_changed = False
                if allowlist_candidate is not None:
                    if not isinstance(allowlist_candidate, tuple) or len(allowlist_candidate) != 3:
                        raise ValueError("invalid allowlist candidate")
                    allowlist, service_meta, service_changed = allowlist_candidate
                    allowlist_bytes = self._json_bytes("ip_allowlist", allowlist)
                    allowlist_path = self._paths.data_file("ip_allowlist")
                    if allowlist_path.read_bytes() != allowlist_bytes:
                        state_changes["data/ip_allowlist.json"] = allowlist_bytes
                    if not isinstance(state, dict):
                        state = {"schema_version": 1}
                    state = dict(state)
                    sources = dict(state.get("service_sources", {}))
                    items = service_meta.items() if isinstance(service_meta, dict) and not service_meta.get("id") else [(service_meta.get("id", "jetpack"), service_meta)]
                    for service_id, meta in items:
                        if service_id not in {"hubspot", "jetpack"} or not isinstance(meta, dict):
                            raise ValueError("invalid managed service candidate")
                        previous_service = dict(sources.get(service_id, {}))
                        previous_service.update({
                            key: value for key, value in meta.items()
                            if key != "id"
                        })
                        if service_changed or not previous_service.get("last_updated"):
                            previous_service["last_updated"] = meta.get("last_checked")
                        sources[service_id] = previous_service
                    state["service_sources"] = sources
                    state_bytes = self._json_bytes("state", state)
                    state_path = self._paths.data_file("state")
                    if not state_path.is_file() or state_path.read_bytes() != state_bytes:
                        state_changes["data/state.json"] = state_bytes

                if not state_changes:
                    return {
                        "status": True,
                        "updated": changed,
                        "service_updated": service_changed,
                        "deployment": None,
                    }

                assignments = load_json(self._paths, "domains")["domains"]
                protected = any(
                    item.get("enabled") and item.get("group") != "NONE"
                    for item in assignments.values()
                )
                rules_changed = bool(changed or service_changed)
                requires_release = protected and rules_changed
                if requires_release:
                    self._assert_proxy_trust(assignments)
                    self._assert_proxy_recovery_clear()
                    try:
                        manifest = self._build_staging(
                            assignments,
                            build_overrides={
                                "snapshots": snapshots,
                                "allowlist": allowlist["entries"],
                            },
                        )
                    except BaseException as error:
                        error.deployment_stage = "build_release"
                        raise
                    release_id = manifest["release_id"]
                else:
                    current_path = self._state_root / "current.json"
                    current = json.loads(current_path.read_text()) if current_path.is_file() else {}
                    release_id = current.get("release_id")

                current_path = self._state_root / "current.json"
                current = json.loads(current_path.read_text()) if current_path.is_file() else {}
                operation = begin_operation(
                    self._plugin_root,
                    self._state_root,
                    release_id,
                    current.get("release_id"),
                    state_changes,
                    requires_reload=requires_release,
                )
                operation_dir = self._state_root / "operations" / operation["operation_id"]
                try:
                    for relative, content in state_changes.items():
                        _atomic_write(self._plugin_root / relative, content)
                    set_operation_status(operation_dir, "state_written")
                    deployment = None
                    if requires_release:
                        set_operation_status(operation_dir, "release_applying")
                        deployment = apply_managed_release(
                            release_id,
                            self._releases_root,
                            self._vhost_root,
                            self._state_root,
                            self._adapter.run_config_test,
                            self._reload,
                            transaction_id=operation["operation_id"],
                            acquire_lock=False,
                            audit=self._audit,
                        )
                        set_operation_status(operation_dir, "release_reloaded")
                    set_operation_status(operation_dir, "committed")
                except BaseException as error:
                    error.deployment_stage = getattr(error, "deployment_stage", "apply_scheduled_updates")
                    self._finish_failed_operation(operation, error)
                self._prune_managed_history()
                self._audit.record_action(
                    "feeds.batch_update",
                    {
                        "result": "success",
                        "operation_id": operation["operation_id"],
                        "providers": changed,
                        "service_updated": service_changed,
                        "release_id": release_id,
                    },
                )
                return {
                    "status": True,
                    "updated": changed,
                    "service_updated": service_changed,
                    "deployment": deployment,
                }
        except ProxyTrustBlocking as error:
            response = self._proxy_block_response(error)
            response["updated"] = []
            response["service_updated"] = False
            response["deployment"] = None
            return response
        except ProxyTrustRecoveryRequired as error:
            response = self._proxy_recovery_response(error)
            response.update(
                {"updated": [], "service_updated": False, "deployment": None}
            )
            return response
        except BaseException as error:
            self._audit.record_action(
                "feeds.batch_update",
                {
                    "result": "error",
                    "stage": getattr(error, "deployment_stage", "unknown"),
                    "error_type": type(error).__name__,
                    "error": str(error),
                },
            )
            return {
                "status": False,
                "code": "deployment_failed",
                "msg": str(error),
                "updated": [],
                "service_updated": False,
                "deployment": None,
                "recovery_required": isinstance(error, (RecoveryRequired, nginx_transactions.NginxRecoveryRequired)),
            }

    @staticmethod
    def _payload(request):
        payload = request.get("payload", request)
        if hasattr(payload, "get_items"):
            payload = payload.get_items()
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        return payload

    def get_version(self, _request):
        version = self._updater.get_current_version() if hasattr(self, "_updater") else self.VERSION
        return {
            "status": True,
            "version": version,
        }

    def check_update(self, request):
        force = False
        if hasattr(request, "get"):
            force = request.get("force") in {True, "1", "true", "True"}
        elif hasattr(request, "force"):
            force = getattr(request, "force") in {True, "1", "true", "True"}
        return self._updater.check_for_updates(force=force)

    def get_update_status(self, _request):
        return self._updater.get_update_status()

    def update_plugin(self, request):
        operation_id = request.get("operation_id") if hasattr(request, "get") else getattr(request, "operation_id", None)
        version = request.get("version") if hasattr(request, "get") else getattr(request, "version", None)
        download_url = request.get("download_url") if hasattr(request, "get") else getattr(request, "download_url", None)
        if not version:
            check = self._updater.check_for_updates(force=True)
            if not check.get("has_update"):
                return {"status": False, "msg": "Không có phiên bản mới để cập nhật."}
            version = check.get("latest_version")
            download_url = check.get("download_url")
        try:
            res = self._updater.apply_update(version, download_url=download_url, operation_id=operation_id)
            self._audit.record_action("plugin.update", {"version": version, "result": "success"})
            return res
        except Exception as error:
            self._audit.record_action("plugin.update", {"version": version, "result": "error", "error": str(error)})
            return {"status": False, "msg": str(error)}

    def rollback_plugin(self, request):
        operation_id = request.get("operation_id") if hasattr(request, "get") else getattr(request, "operation_id", None)
        try:
            res = self._updater.rollback(operation_id=operation_id)
            self._audit.record_action("plugin.rollback", {"result": "success" if res.get("status") else "error"})
            return res
        except Exception as error:
            self._audit.record_action("plugin.rollback", {"result": "error", "error": str(error)})
            return {"status": False, "msg": str(error)}

    @_backend_api()
    def audit_baseline(self, _request):
        return {
            "status": True,
            "report": build_baseline_report(
                self._adapter.run_config_test(), self._vhost_root
            ),
        }

    @_backend_api()
    def audit_proxy_trust(self, request):
        domain = request.get("domain", "")
        traffic_mode = request.get("traffic_mode", "unknown")
        report = self._proxy_trust_report(domain, traffic_mode)
        return {"status": True, "report": asdict(report)}

    @_backend_api(nginx=True)
    def get_cloudflare_trust_status(self, _request):
        if self._webserver_type == 'nginx':
            self._reload_cloudflare_state()
            snapshot = self._cloudflare_snapshot or {'etag': None, 'counts': {'ipv4': 0, 'ipv6': 0}, 'prefixes': []}
            return {
                'status': True,
                'cloudflare': {
                    'freshness': self._proxy_freshness['state'],
                    'last_checked_at': snapshot.get('checked_at'),
                    'last_success_at': snapshot.get('checked_at'),
                    'etag': snapshot.get('etag'),
                    'ipv4_count': snapshot.get('counts', {}).get('ipv4', 0),
                    'ipv6_count': snapshot.get('counts', {}).get('ipv6', 0),
                    'configured_count': len(snapshot.get('prefixes', ())),
                    'missing_prefixes': [],
                    'stale_prefixes': [],
                    'header_state': 'trusted_only',
                    'recovery_required': False,
                    'last_error_code': None,
                },
            }
        self._reload_cloudflare_state()
        snapshot = self._cloudflare_snapshot or {
            "etag": None,
            "counts": {"ipv4": 0, "ipv6": 0},
            "prefixes": [],
        }
        state = self._proxy_trust_state
        try:
            inspection = inspect_global_proxy_config(
                self._server_config_text().encode()
            )
        except ValueError:
            inspection = {"trusted_only": None, "configured_prefixes": ()}
            header_state = "ambiguous"
        else:
            if inspection["trusted_only"] is True:
                header_state = "trusted_only"
            elif inspection["trusted_only"] is None:
                header_state = "missing"
            else:
                header_state = "trust_all"
        desired = set(snapshot.get("prefixes", ()))
        configured = set(inspection.get("configured_prefixes", ()))
        managed = set(state.get("managed_prefixes", ()))
        recovery = inspect_proxy_trust_recovery(
            self._plugin_root,
            self._server_config_path,
        )
        return {
            "status": True,
            "cloudflare": {
                "freshness": self._proxy_freshness["state"],
                "last_checked_at": state.get("last_checked_at"),
                "last_success_at": state.get("last_success_at"),
                "etag": state.get("last_etag") or snapshot.get("etag"),
                "ipv4_count": snapshot.get("counts", {}).get("ipv4", 0),
                "ipv6_count": snapshot.get("counts", {}).get("ipv6", 0),
                "configured_count": len(desired & configured),
                "missing_prefixes": sorted(desired - configured),
                "stale_prefixes": sorted(managed - desired),
                "header_state": header_state,
                "recovery_required": recovery["blocking"],
                "last_error_code": state.get("last_error_code"),
            },
        }

    @_backend_api(ols_only=False)
    def check_cloudflare_ranges(self, _request):
        self._reload_cloudflare_state()
        try:
            candidate = prepare_cloudflare_snapshot(
                self._cloudflare_downloader(),
                previous=self._cloudflare_snapshot,
                checked_at=self._clock().isoformat(),
            )
        except Exception as error:
            return {
                "status": False,
                "code": getattr(error, "code", "cloudflare_download_error"),
                "msg": f"Không thể kiểm tra dải IP Cloudflare: {error}",
            }
        current = self._cloudflare_snapshot
        update_available = current is None or any(
            candidate.get(key) != current.get(key)
            for key in ("etag", "prefixes", "checksum")
        )
        return {
            "status": True,
            "cloudflare": {
                "etag": candidate["etag"],
                "checked_at": candidate["checked_at"],
                "counts": candidate["counts"],
                "update_available": update_available,
            },
        }

    @_backend_api(nginx=True)
    def repair_cloudflare_trust(self, _request):
        if self._webserver_type == 'nginx':
            return self._nginx.refresh_cloudflare()
        self._reload_cloudflare_state()
        recovery = inspect_proxy_trust_recovery(
            self._plugin_root,
            self._server_config_path,
        )
        if recovery["blocking"]:
            return self._proxy_recovery_response(
                ProxyTrustRecoveryRequired(recovery["reason"])
            )
        if self._cloudflare_snapshot is None:
            return {
                "status": False,
                "code": "cloudflare_snapshot_missing",
                "msg": "Không có snapshot Cloudflare hợp lệ để sửa Trusted Proxy.",
            }
        try:
            result = apply_proxy_trust_update(
                self._plugin_root,
                self._server_config_path,
                self._cloudflare_snapshot,
                self._adapter.run_config_test,
                self._reload,
                audit=self._audit,
                checked_live=False,
            )
        except ProxyTrustRecoveryRequired as error:
            return self._proxy_recovery_response(error)
        except Exception as error:
            return {
                "status": False,
                "code": getattr(error, "code", "proxy_trust_update_failed"),
                "msg": f"Không thể sửa Trusted Proxy: {error}",
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "recovery_required": bool(
                    getattr(error, "recovery_required", False)
                ),
            }
        self._reload_cloudflare_state()
        return {
            "status": True,
            "transaction_id": result["transaction_id"],
            "changed": result["changed"],
            "config_changed": result["config_changed"],
            "reloaded": result["reloaded"],
        }

    def _build_staging(self, assignments, payload=None, build_overrides=None):
        if self._webserver_type == 'nginx':
            if not self._backend_status()['mutation_allowed']:
                raise RuntimeError(self._backend_status()['reason'])
            release_id, expected = self._nginx.build(assignments, overrides=build_overrides)
            return {'release_id': release_id, 'backend': 'nginx'}
        self._require_ols_backend()
        payload = payload or {}
        build_overrides = build_overrides or {}
        exceptions = build_overrides.get("exceptions")
        if exceptions is None:
            exceptions = load_json(self._paths, "woo_exceptions")["exceptions"]
        allowlist = build_overrides.get("allowlist")
        if allowlist is None:
            allowlist = load_json(self._paths, "ip_allowlist")["entries"]
        snapshots = build_overrides.get("snapshots")
        if snapshots is None:
            snapshots = {}
            if self._snapshots_root.is_dir():
                for path in sorted(self._snapshots_root.glob("*.json")):
                    snapshots[path.stem] = json.loads(path.read_text())
        enabled = set(enabled_snapshot_names(load_json(self._paths, "providers")))
        snapshots = {
            provider: snapshot
            for provider, snapshot in snapshots.items()
            if provider in enabled
        }
        current_path = self._state_root / "current.json"
        current = json.loads(current_path.read_text()) if current_path.is_file() else {}
        return build_managed_staging(
            assignments,
            snapshots,
            self._releases_root,
            self._geoip_database,
            exceptions=tuple(exceptions),
            allowlist=tuple(allowlist),
            health_paths=payload.get("health_paths"),
            origin_prefixes=payload.get("origin_prefixes"),
            release_id=payload.get("release_id"),
            parent_release=current.get("release_id"),
            audit=self._audit,
        )

    @_backend_api(nginx=True)
    def build_staging(self, request):
        payload = self._payload(request) if request else {}
        assignments = load_json(self._paths, "domains")["domains"]
        manifest = self._build_staging(assignments, payload)
        return {"status": True, "release": manifest}

    def _reload(self):
        self._require_ols_backend()
        try:
            token = self._adapter.issue_reload_token()
            result = self._adapter.reload_gracefully(token)
        except BaseException as error:
            self._audit.record_action(
                "ols.reload",
                {"result": "error", "error_type": type(error).__name__, "error": str(error)},
            )
            raise
        self._audit.record_action(
            "ols.reload",
            {
                "result": "success" if getattr(result, "returncode", 0) == 0 else "error",
                "returncode": getattr(result, "returncode", None),
            },
        )
        if getattr(result, "returncode", 0) != 0:
            raise RuntimeError("OpenLiteSpeed graceful reload failed")
        return result

    def _ensure_geoip_config(self):
        self._require_ols_backend()
        text = self._server_config_path.read_text(errors="replace")
        expected = re.compile(r"(?m)^\s*geoipdb\s+" + re.escape(str(self._geoip_database)) + r"\s*\{")
        if expected.search(text):
            return None
        if re.search(r"(?im)^\s*geoipdb\s+", text):
            raise ValueError("another GeoIP database is already configured")
        proposal = build_geoip_proposal(
            self._server_config_path,
            self._geoip_database,
            self._geoip_proposals,
            audit=self._audit,
        )
        transaction = apply_geoip_proposal(
            proposal["proposal_id"],
            self._geoip_proposals,
            self._server_config_path,
            self._geoip_transactions,
            self._adapter.run_config_test,
            audit=self._audit,
        )
        return transaction

    def _restore_geoip_config(self, transaction):
        if transaction is None:
            return None
        return restore_geoip_transaction(
            transaction["transaction_id"],
            self._geoip_transactions,
            self._server_config_path,
            audit=self._audit,
        )

    def _install_maxmind_candidate(self, candidate):
        if self._webserver_type == 'nginx':
            if not self._backend_status()['runtime_verified']:
                raise ValueError('Nginx runtime is not verified')
            return nginx_prerequisites.install_database(
                self._plugin_root, self._adapter, self._geoip_database, candidate)
        self._require_ols_backend()
        return install_country_database(
            candidate,
            self._geoip_database,
            self._ensure_geoip_config,
            self._restore_geoip_config,
            self._adapter.run_config_test,
            self._reload,
            self._geoip_transactions,
            audit=self._audit,
        )

    @_backend_api(nginx=True)
    def apply_release(self, request):
        if self._webserver_type == 'nginx':
            return {'status': True, 'deployment': self._nginx.apply_staged(request.get('release_id', ''))}
        deployment = self._deploy_existing_release(
            request["release_id"], "release.manual_apply"
        )
        return {"status": True, "deployment": deployment}

    @_backend_api(nginx=True, runtime_only=True)
    def list_releases(self, _request):
        if self._webserver_type == 'nginx':
            return {'status': True, 'releases': nginx_transactions.list_nginx_releases(self._releases_root)}
        return {
            "status": True,
            "releases": list_managed_releases(self._releases_root, self._state_root),
        }

    @_backend_api(nginx=True, runtime_only=True)
    def get_deployment_recovery_status(self, _request):
        if self._webserver_type == 'nginx':
            try:
                recovery = self._nginx.status()
            except (OSError, ValueError, RuntimeError) as error:
                recovery = {'status': 'recovery_required', 'blocking': True, 'safe_action': 'manual', 'reason': str(error)}
            return {'status': True, 'recovery': recovery, 'proxy_trust_recovery': {'status': 'not_applicable'}}
        return {
            "status": True,
            "recovery": inspect_interrupted_release(
                self._plugin_root,
                self._state_root,
                self._releases_root,
                self._vhost_root,
            ),
            "proxy_trust_recovery": inspect_proxy_trust_recovery(
                self._plugin_root,
                self._server_config_path,
            ),
        }

    @_backend_api(nginx=True, runtime_only=True)
    def recover_deployment(self, _request):
        if self._webserver_type == 'nginx':
            try:
                return {'status': True, 'recovery': self._nginx.recover()}
            except (OSError, ValueError, RuntimeError) as error:
                return {'status': False, 'recovery_required': True, 'msg': str(error)}
        try:
            recovery = recover_interrupted_release(
                self._plugin_root,
                self._state_root,
                self._releases_root,
                self._vhost_root,
                self._adapter.run_config_test,
                self._reload,
                audit=self._audit,
            )
        except RecoveryRequired as error:
            return {
                "status": False,
                "code": "deployment_recovery_required",
                "msg": str(error),
            }
        return {"status": True, "recovery": recovery}

    @_backend_api(nginx=True)
    def rollback_release(self, request):
        if self._webserver_type == 'nginx':
            return {'status': True, 'deployment': self._nginx.rollback()}
        current_path = self._state_root / "current.json"
        if not current_path.is_file():
            raise ValueError("no current release")
        current = json.loads(current_path.read_text())
        previous = current.get("previous_release")
        if not previous:
            raise ValueError("no previous release")
        deployment = self._deploy_existing_release(previous, "release.manual_rollback")
        return {"status": True, "deployment": deployment}

    @_backend_api(ols_only=False)
    def get_dashboard(self, _request):
        backend = self._backend_status()
        if not backend["runtime_verified"]:
            return {"status": True, "backend": backend, "dashboard": {
                "service": {"pid": None},
                "config_test": {"valid": None, "exit_code": None, "errors": 0, "warnings": 0,
                                "error_lines": [], "warning_lines": [backend["reason"]], "skipped": True},
                "geoip": {"path": str(self._geoip_database), "checked": False, "readable": None},
                "domains": {"total": None, "protected": None, "active": None},
                "feeds": {}, "release": {"current": None, "previous": None}, "capabilities": {},
            }}
        nginx = self._webserver_type == "nginx"
        capabilities = {}
        config_test = None
        if nginx:
            capabilities = {"realip": self._adapter.check_realip_support(), "geoip2": self._adapter.check_geoip2_support()}
            if capabilities["geoip2"]:
                config_test = self._adapter.test_config()
        else:
            config_test = self._adapter.run_config_test()
        domains_config = load_json(self._paths, "domains")
        managed_domains = {
            domain for domain, settings in domains_config["domains"].items()
            if settings.get("enabled") and settings.get("group") != "NONE"
        }
        records = self._collect_backend_domains(domains_config["domains"])
        feeds = {}
        if self._snapshots_root.is_dir():
            for path in sorted(self._snapshots_root.glob("*.json")):
                feeds[path.stem] = json.loads(path.read_text())
        current_path = self._state_root / "current.json"
        current = json.loads(current_path.read_text()) if current_path.is_file() else {}
        if nginx:
            recovery = self.get_deployment_recovery_status({})['recovery']
            current = recovery.get('current') or {}
            if recovery.get('blocking') or (current and not self._nginx.probe(current)):
                current = {}
        service_pid = self._environment.get("master_pid") if nginx else None
        if not nginx and self._service_pid_path.is_file():
            service_pid = self._service_pid_path.read_text(errors="replace").strip().split()[0]
        config_report = {"valid": config_test.valid, "exit_code": config_test.exit_code, "errors": len(config_test.errors), "warnings": len(config_test.warnings), "error_lines": list(config_test.errors), "warning_lines": list(config_test.warnings)} if config_test is not None else {
            "valid": None, "exit_code": None, "errors": 0, "warnings": 1, "error_lines": [],
            "warning_lines": ["Thiếu module GeoIP2 trong Nginx đang chạy; plugin không tự cài module."], "skipped": True,
        }
        return {"status": True, "backend": backend, "dashboard": {
            "service": {"pid": service_pid},
            "config_test": config_report,
            "capabilities": capabilities,
            "geoip": {"path": str(self._geoip_database), "checked": True, "readable": self._geoip_database.is_file() and os.access(self._geoip_database, os.R_OK)},
            "domains": {"total": len(records), "protected": len(current.get('managed_snippets', {})) if nginx and current else None if nginx else len(managed_domains), "configured": len(managed_domains), "active": sum(item.status == "active" for item in records)},
            "feeds": feeds,
            "release": {"current": current.get("release_id"), "previous": current.get("parent_release") if nginx else current.get("previous_release")},
        }}

    @_backend_api(ols_only=False)
    def get_domains(self, _request):
        backend = self._backend_status()
        if not backend["runtime_verified"]:
            return self._backend_refusal(backend)
        settings = load_json(self._paths, "domains")["domains"]
        observations = self._load_traffic_detection()["domains"]
        records = self._collect_backend_domains(settings)
        result = []
        server_config_text = self._server_config_text() if self._webserver_type == "openlitespeed" else None
        verification = {'domains': [], 'release_id': None, 'reason': ''}
        if self._webserver_type == 'nginx' and any(
                item.get('enabled') and item.get('group') != 'NONE' for item in settings.values()):
            verification = self._nginx.inspect_protection(settings)
        for record in records:
            item = asdict(record)
            item.update(settings.get(record.domain, {"group": "NONE", "traffic_mode": "unknown", "enabled": False}))
            item.setdefault("traffic_auto", record.domain not in settings)
            observation = observations.get(record.domain)
            item["traffic_detection"] = observation if item["traffic_auto"] and observation and observation.get("assignment") == settings.get(record.domain) else None
            item["can_edit"] = backend["mutation_allowed"]
            if self._webserver_type == "nginx":
                item['can_edit'] = backend['mutation_allowed'] and record.supported_for_protection
                item['integration_release'] = None
                item['integration_reason'] = verification['reason'] or (
                    'Chính sách website chưa khớp bản cấu hình đã áp dụng'
                    if item.get('enabled') and item.get('group') != 'NONE' else '')
                if record.domain in verification['domains'] and record.supported_for_protection:
                    item['integration'] = 'verified'
                    item['integration_release'] = verification['release_id']
                    item['integration_reason'] = 'Checksum, quyền quản lý, cấu hình và runtime Nginx đã khớp; chưa thay thế kiểm thử truy cập thực tế.'
                item["proxy_trust_state"] = 'server-scoped' if record.supported_for_protection else 'not_verified'
                item["proxy_trust_blocking"] = not record.supported_for_protection
                item["proxy_trust_remediation"] = [record.unsupported_reason] if record.unsupported_reason else []
                result.append(item)
                continue
            proxy_report = self._proxy_trust_report(
                record.domain,
                item["traffic_mode"],
                server_config_text,
            )
            item["proxy_trust_state"] = proxy_report.state
            item["proxy_trust_blocking"] = proxy_report.blocking
            item["proxy_trust_remediation"] = list(proxy_report.remediation)
            result.append(item)
        return {"status": True, "domains": result}

    def _load_traffic_detection(self):
        path = self._paths.data_file("traffic_detection")
        if path.is_symlink():
            raise ValueError("Traffic detection state must not be a symlink")
        try:
            payload = load_json(self._paths, "traffic_detection")
        except FileNotFoundError:
            return {"schema_version": 1, "domains": {}}
        config_store_module.validate_traffic_detection(payload)
        return payload

    @_backend_api(nginx=True)
    def refresh_traffic_modes(self, _request):
        try:
            with process_lock(self._state_root / "traffic-detection.lock"):
                return self._refresh_traffic_modes()
        except (OSError, ValueError, RuntimeError) as error:
            return {"status": False, "msg": str(error)}

    def _refresh_traffic_modes(self):
        if self._webserver_type != 'nginx':
            self._require_ols_backend()
        baseline = load_json(self._paths, "domains")
        previous = self._load_traffic_detection()["domains"]
        proposed = copy.deepcopy(baseline)
        observations = {}
        self._reload_cloudflare_state()
        prefixes = self._required_proxy_prefixes if not self._proxy_freshness["blocking"] else ()
        try:
            origins = self._origin_address_loader()
        except (OSError, ValueError, subprocess.SubprocessError):
            origins = ()
        for domain, assignment in baseline["domains"].items():
            if not assignment.get("traffic_auto", False):
                continue
            try:
                addresses = self._traffic_resolver(domain)
                result = classify_addresses(addresses, prefixes, origins)
            except (OSError, ValueError, TimeoutError) as error:
                result = {"mode": "unknown", "reason": "Không kiểm tra được DNS: " + str(error)[:200]}
            old = previous.get(domain)
            if old and old.get("assignment") != assignment:
                old = None
            observation = observe(old, result, self._clock())
            if observation["status"] == "confirmed":
                proposed["domains"][domain]["traffic_mode"] = observation["mode"]
            observation["assignment"] = copy.deepcopy(proposed["domains"][domain])
            observations[domain] = observation
        detection = {"schema_version": 1, "domains": observations}
        if proposed != baseline:
            try:
                deployment = self._deploy_state_change(
                    state_changes={"domains": proposed, "traffic_detection": detection},
                    assignments=proposed["domains"], action_name="domains.traffic_detect",
                    expected_domains=baseline,
                )
                return {"status": True, "checked": len(observations), "deployment": deployment}
            except Exception as error:
                for domain, observation in observations.items():
                    observation["assignment"] = copy.deepcopy(baseline["domains"][domain])
                    if proposed["domains"][domain] != baseline["domains"][domain]:
                        observation["status"] = "blocked"
                        observation["error"] = str(error)[:400]
                with deployment_lock(self._state_root):
                    if load_json(self._paths, "domains") == baseline:
                        save_json(self._paths, "traffic_detection", detection, audit=self._audit)
                self._audit.record_action("domains.traffic_detect", {"result": "blocked", "error": str(error)[:400]})
                return {"status": False, "checked": len(observations), "msg": str(error)}
        with deployment_lock(self._state_root):
            if load_json(self._paths, "domains") != baseline:
                raise ValueError("Cấu hình website đã thay đổi trong lúc kiểm tra DNS; thử lại ở lượt sau")
            if detection != {"schema_version": 1, "domains": previous}:
                save_json(self._paths, "traffic_detection", detection, audit=self._audit)
        return {"status": True, "checked": len(observations)}

    @_backend_api()
    def get_bot_activity(self, request):
        period = request.get("period", "24h")
        if period not in {"24h", "7d"}:
            raise ValueError("invalid activity period")
        selected_domain = request.get("domain", "")
        selected_provider = request.get("provider", "")
        assignments = load_json(self._paths, "domains")["domains"]
        available_domains = sorted(
            domain for domain, settings in assignments.items()
            if settings.get("enabled") and settings.get("group") != "NONE"
        )
        domains = list(available_domains)
        if selected_domain:
            if selected_domain not in domains:
                raise ValueError("invalid activity domain")
            domains = [selected_domain]
        snapshots = {}
        if self._snapshots_root.is_dir():
            for path in sorted(self._snapshots_root.glob("*.json")):
                snapshots[path.stem] = json.loads(path.read_text())
        available_providers = sorted(snapshots)
        all_snapshots = snapshots
        if selected_provider:
            if selected_provider not in snapshots:
                raise ValueError("invalid activity provider")
            snapshots = {selected_provider: snapshots[selected_provider]}
        now = datetime.now(timezone.utc)
        activity = collect_bot_activity(
            domains=domains,
            snapshots=snapshots,
            logs_root=self._logs_root,
            since=now - timedelta(hours=24 if period == "24h" else 24 * 7),
        )
        provider_activity = activity
        if selected_provider:
            provider_activity = collect_bot_activity(
                domains=domains,
                snapshots=all_snapshots,
                logs_root=self._logs_root,
                since=now - timedelta(hours=24 if period == "24h" else 24 * 7),
            )
        config = load_json(self._paths, "config")
        providers = load_json(self._paths, "providers")
        activity["provider_status"] = bot_activity_module.summarize_provider_status(
            enabled_feeds(providers),
            all_snapshots,
            provider_activity["events"],
            config.get("feed_max_age_hours", 72),
            now=now,
        )
        current_path = self._state_root / "current.json"
        current = {}
        manifest = None
        if current_path.is_file():
            current = json.loads(current_path.read_text())
            release_id = current.get("release_id")
            if isinstance(release_id, str) and re.fullmatch(r"[a-f0-9]{32}", release_id):
                manifest_path = self._releases_root / release_id / "manifest.json"
                if manifest_path.is_file():
                    manifest = json.loads(manifest_path.read_text())
        classified = bot_activity_module.classify_blocked_events(
            activity["events"], all_snapshots, manifest, current,
            intentional_index_blocks={
                domain for domain, settings in assignments.items()
                if settings.get("bot_indexing_disabled")
            },
        )
        activity["events"] = classified["events"]
        activity["classification"] = classified["classification"]
        activity.update({
            "domains": domains,
            "providers": sorted(snapshots),
            "available_domains": available_domains,
            "available_providers": available_providers,
            "period": period,
            "deployment_id": current.get("deployment_id"),
        })
        return {"status": True, "activity": activity}

    @_backend_api()
    def get_traffic_activity(self, request):
        period = request.get("period", "24h")
        if period not in {"24h", "7d"}:
            raise ValueError("invalid activity period")
        selected_domain = request.get("domain", "")
        selected_source = request.get("source", "")
        selected_country = request.get("country", "")
        selected_outcome = request.get("outcome", "")
        selected_decision = request.get("decision", "")
        if selected_source and selected_source not in TRAFFIC_SOURCE_TYPES:
            raise ValueError("invalid activity source")
        if selected_country and selected_country not in {"vietnam", "foreign", "unknown"}:
            raise ValueError("invalid activity country")
        if selected_outcome and selected_outcome not in {"allowed", "blocked", "other"}:
            raise ValueError("invalid activity outcome")
        if selected_decision and selected_decision not in {
            "expected",
            "unexpected_allow",
            "unexpected_block",
            "other",
        }:
            raise ValueError("invalid activity decision")
        assignments = load_json(self._paths, "domains")["domains"]
        available_domains = sorted(
            domain for domain, settings in assignments.items()
            if settings.get("enabled") and settings.get("group") != "NONE"
        )
        domains = list(available_domains)
        if selected_domain:
            if selected_domain not in domains:
                raise ValueError("invalid activity domain")
            domains = [selected_domain]
        snapshots = {}
        if self._snapshots_root.is_dir():
            for path in sorted(self._snapshots_root.glob("*.json")):
                snapshots[path.stem] = json.loads(path.read_text())
        allowlist = load_json(self._paths, "ip_allowlist")
        now = self._clock()
        filters = {
            "source": selected_source,
            "country": selected_country,
            "outcome": selected_outcome,
            "decision": selected_decision,
        }
        activity = collect_traffic_activity(
            domains=domains,
            snapshots=snapshots,
            allowlist=allowlist,
            logs_root=self._logs_root,
            since=now - timedelta(hours=24 if period == "24h" else 24 * 7),
            country_lookup=self._country_lookup(),
            filters={key: value for key, value in filters.items() if value},
            limit=200,
        )
        provider_activity = collect_bot_activity(
            domains=domains,
            snapshots=snapshots,
            logs_root=self._logs_root,
            since=now - timedelta(hours=24 if period == "24h" else 24 * 7),
        )
        config = load_json(self._paths, "config")
        providers = load_json(self._paths, "providers")
        activity["provider_status"] = bot_activity_module.summarize_provider_status(
            enabled_feeds(providers),
            snapshots,
            provider_activity["events"],
            config.get("feed_max_age_hours", 72),
            now=now,
        )
        current_path = self._state_root / "current.json"
        current = {}
        if current_path.is_file():
            current = json.loads(current_path.read_text())
        activity.update({
            "domains": domains,
            "available_domains": available_domains,
            "available_sources": list(TRAFFIC_SOURCE_TYPES),
            "period": period,
            "filters": {
                "domain": selected_domain,
                "source": selected_source,
                "country": selected_country,
                "outcome": selected_outcome,
                "decision": selected_decision,
            },
            "deployment_id": current.get("deployment_id"),
            "geoip": {
                "state": "ready" if self._country_lookup() is not None else "missing",
                "path": str(self._geoip_database),
            },
        })
        return {"status": True, "activity": activity}

    @_backend_api()
    def get_access_policy_status(self, request):
        period = request.get("period", "24h")
        traffic_report = self.get_traffic_activity({"period": period})
        assignments = load_json(self._paths, "domains")["domains"]
        current_path = self._state_root / "current.json"
        current = {}
        manifest = None
        if current_path.is_file():
            current = json.loads(current_path.read_text())
            release_id = current.get("release_id")
            if isinstance(release_id, str) and re.fullmatch(r"[a-f0-9]{32}", release_id):
                manifest_path = self._releases_root / release_id / "manifest.json"
                if manifest_path.is_file():
                    manifest = json.loads(manifest_path.read_text())
        by_domain_events = {}
        for event in traffic_report["activity"]["events"]:
            by_domain_events.setdefault(event["domain"], []).append(event)
        items = []
        server_config_text = self._server_config_text()
        for domain, assignment in sorted(assignments.items()):
            if not assignment.get("enabled") or assignment.get("group") == "NONE":
                continue
            proxy_report = self._proxy_trust_report(
                domain,
                assignment.get("traffic_mode", "unknown"),
                server_config_text,
            )
            events = by_domain_events.get(domain, [])
            summary = bot_activity_module._traffic_summary(events)
            issues = []
            if proxy_report.blocking:
                issues.append("Chưa tin cậy IP thật từ Cloudflare")
            if summary["unexpected_block"] > 0:
                issues.append(f"{summary['unexpected_block']} request bị chặn bất thường")
            if summary["unexpected_allow"] > 0:
                issues.append(f"{summary['unexpected_allow']} request ngoại quốc lọt qua")
            if traffic_report["activity"]["geoip"]["state"] != "ready":
                issues.append("Thiếu database GeoIP để nhận diện quốc gia")
            if manifest:
                generated_checksum = manifest.get("generated_checksums", {}).get(domain, {}).get("sha256")
                managed_checksum = (current or {}).get("managed_files", {}).get(domain, {}).get("sha256")
                if not generated_checksum or generated_checksum != managed_checksum:
                    issues.append("Rule đang áp dụng không khớp release")
            status = "ready" if not issues else "warning" if not proxy_report.blocking else "blocking"
            items.append({
                "domain": domain,
                "policy": assignment.get("group"),
                "traffic_mode": assignment.get("traffic_mode"),
                "proxy_trust_state": proxy_report.state,
                "status": status,
                "issues": issues,
                "evidence": summary,
            })
        return {
            "status": True,
            "policy": {
                "period": period,
                "geoip": traffic_report["activity"]["geoip"],
                "domains": items,
                "summary": traffic_report["activity"]["summary"],
            },
        }
    @_backend_api(nginx=True)
    def save_domains(self, request):
        payload = self._payload(request)
        try:
            config_store_module.validate_domains(payload)
            baseline = load_json(self._paths, "domains")
            payload = copy.deepcopy(payload)
            state_changes = {"domains": payload}
            detection = None
            for domain, assignment in payload["domains"].items():
                if assignment.get("traffic_auto", False):
                    current_mode = baseline["domains"].get(domain, {}).get("traffic_mode", "unknown")
                    if current_mode not in {"direct", "cloudflare"}:
                        try:
                            self._reload_cloudflare_state()
                            prefixes = self._required_proxy_prefixes if not self._proxy_freshness["blocking"] else ()
                            try:
                                origins = self._origin_address_loader()
                            except (OSError, ValueError, subprocess.SubprocessError):
                                origins = ()
                            addresses = self._traffic_resolver(domain)
                            probe_result = classify_addresses(addresses, prefixes, origins)
                            if probe_result.get("mode") in {"direct", "cloudflare"}:
                                current_mode = probe_result["mode"]
                                if detection is None:
                                    detection = copy.deepcopy(self._load_traffic_detection())
                                det_domains = detection.setdefault("domains", {})
                                obs = observe(det_domains.get(domain), probe_result, self._clock())
                                obs["status"] = "confirmed"
                                obs["assignment"] = copy.deepcopy(assignment)
                                obs["assignment"]["traffic_mode"] = current_mode
                                det_domains[domain] = obs
                                state_changes["traffic_detection"] = detection
                        except Exception:
                            pass
                    assignment["traffic_mode"] = current_mode
                    if assignment["traffic_mode"] not in {"direct", "cloudflare"} and assignment["enabled"] and assignment["group"] != "NONE":
                        return {"status": False, "msg": domain + ": hãy lưu Tự động khi chưa bật bảo vệ, đợi nhận diện rồi bật; hoặc chọn luồng thủ công đã xác minh."}
            deployment = self._deploy_state_change(
                state_changes=state_changes,
                assignments=payload["domains"],
                action_name="domains.auto_apply",
                expected_domains=baseline if any(item.get("traffic_auto", False) for item in payload["domains"].values()) else None,
            )
        except ProxyTrustBlocking as error:
            return self._proxy_block_response(error)
        except ProxyTrustRecoveryRequired as error:
            return self._proxy_recovery_response(error)
        except BaseException as error:
            self._audit.record_action("domains.auto_apply", {
                "result": "error",
                "stage": getattr(error, "deployment_stage", "unknown"),
                "error_type": type(error).__name__,
                "error": str(error),
            })
            return {
                "status": False,
                "stage": getattr(error, "deployment_stage", "unknown"),
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "recovery_required": isinstance(error, (RecoveryRequired, nginx_transactions.NginxRecoveryRequired)),
                "msg": f"Không thể áp dụng rule website: {error}" if str(error) else "Không thể áp dụng rule website.",
            }
        return {"status": True, "deployment": deployment}

    def get_exceptions(self, _request):
        return {
            "status": True,
            "exceptions": load_json(self._paths, "woo_exceptions"),
        }

    @_backend_api(nginx=True)
    def save_exceptions(self, request):
        payload = self._payload(request)
        assignments = load_json(self._paths, "domains")["domains"]
        try:
            deployment = self._deploy_state_change(
                state_changes={"woo_exceptions": payload},
                assignments=assignments,
                build_overrides={"exceptions": payload["exceptions"]},
                action_name="exceptions.auto_apply",
            )
        except ProxyTrustBlocking as error:
            return self._proxy_block_response(error)
        except ProxyTrustRecoveryRequired as error:
            return self._proxy_recovery_response(error)
        except BaseException as error:
            return {
                "status": False,
                "stage": getattr(error, "deployment_stage", "unknown"),
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "recovery_required": isinstance(error, (RecoveryRequired, nginx_transactions.NginxRecoveryRequired)),
                "msg": "Không thể áp dụng ngoại lệ.",
            }
        return {
            "status": True,
            "exceptions": payload,
            "deployment": deployment,
        }

    def get_ip_allowlist(self, _request):
        return {"status": True, "allowlist": load_json(self._paths, "ip_allowlist")}

    @_backend_api(nginx=True)
    def save_ip_allowlist(self, request):
        payload = self._payload(request)
        previous = load_json(self._paths, "ip_allowlist")
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ValueError("entries must be a list")
        if any(not isinstance(entry, dict) for entry in entries):
            raise ValueError("allowlist entry must be an object")
        user_entries = [
            entry for entry in entries
            if entry.get("id") != "local-origin"
            and entry.get("id") not in MANAGED_SERVICE_IDS
        ]
        entry_ids = [entry.get("id") for entry in user_entries if isinstance(entry, dict)]
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("allowlist entry ids must be unique")
        payload = dict(payload)
        payload["entries"] = (
            [entry for entry in previous["entries"] if entry.get("id") == "local-origin"]
            + user_entries
            + [entry for entry in previous["entries"] if entry.get("id") in MANAGED_SERVICE_IDS]
        )
        try:
            deployment = self._apply_allowlist(payload, previous=previous, action_name="ip_allowlist.auto_apply")
        except ProxyTrustBlocking as error:
            return self._proxy_block_response(error)
        except ProxyTrustRecoveryRequired as error:
            return self._proxy_recovery_response(error)
        except BaseException as error:
            return {
                "status": False,
                "stage": getattr(error, "deployment_stage", "unknown"),
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "recovery_required": isinstance(error, (RecoveryRequired, nginx_transactions.NginxRecoveryRequired)),
                "msg": "Không thể áp dụng IP tin cậy.",
            }
        return {"status": True, "deployment": deployment, "allowlist": payload}

    def get_service_ip_sources(self, _request):
        allowlist = load_json(self._paths, "ip_allowlist")
        state = load_json(self._paths, "state")
        return {
            "status": True,
            "sources": describe_service_sources(allowlist, state),
        }

    @_backend_api(nginx=True)
    def update_service_ip_sources(self, request):
        payload = self._payload(request) if request else {}
        target_id = payload.get("id", "jetpack")
        sources = {
            "hubspot": (
                "HubSpot",
                self._hubspot_feed_downloader,
                prepare_hubspot_allowlist,
            ),
            "jetpack": (
                "Jetpack",
                self._service_feed_downloader,
                prepare_jetpack_allowlist,
            ),
        }
        if target_id not in sources:
            return {"status": False, "msg": "Nguồn IP này chỉ hỗ trợ đối soát thủ công."}
        source_name, downloader, preparer = sources[target_id]
        allowlist = load_json(self._paths, "ip_allowlist")
        now = datetime.now(timezone.utc).isoformat()
        try:
            feed_bytes = downloader()
            candidate = preparer(
                allowlist, feed_bytes, checked_at=now
            )
        except Exception as error:
            self._audit.record_action("service_sources.update", {
                "id": target_id,
                "result": "error",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            return {
                "status": False,
                "code": getattr(error, "code", "download_error"),
                "msg": f"Không thể tải feed {source_name}: {error}",
            }
        result = self.apply_scheduled_updates({}, candidate)
        if not result["status"]:
            return {
                "status": False,
                "code": result.get("code", "deployment_failed"),
                "msg": f"Không thể áp dụng feed {source_name}: {result['msg']}",
            }
        allowlist = load_json(self._paths, "ip_allowlist")
        state = load_json(self._paths, "state")
        self._audit.record_action("service_sources.update", {
            "id": target_id,
            "result": "success",
            "updated": candidate[2],
            "checksum": candidate[1]["checksum"],
        })
        return {
            "status": True,
            "updated": candidate[2],
            "deployment": result["deployment"],
            "sources": describe_service_sources(allowlist, state),
        }

    def get_maxmind_status(self, _request):
        credentials = get_credential_status(self._maxmind_credentials)
        database = {"path": str(self._geoip_database), "readable": self._geoip_database.is_file() and os.access(self._geoip_database, os.R_OK)}
        if database["readable"]:
            database.update({"size": self._geoip_database.stat().st_size, "modified_at": self._geoip_database.stat().st_mtime})
        return {"status": True, "credentials": credentials, "database": database}

    @_backend_api(nginx=True, runtime_only=True)
    def save_maxmind_credentials(self, request):
        payload = self._payload(request)
        candidate = None
        candidate_credentials = (
            self._plugin_root
            / "tmp"
            / f"maxmind-credentials-{os.getpid()}-{datetime.now(timezone.utc).timestamp():.6f}.json"
        )
        try:
            credentials = save_credentials(
                candidate_credentials,
                payload.get("account_id", ""),
                payload.get("license_key", ""),
            )
            candidate = self._maxmind_downloader(
                candidate_credentials, self._maxmind_staging
            )
            database = self._install_maxmind_candidate(candidate)
            self._prune_geoip_history()
            credentials = save_credentials(
                self._maxmind_credentials,
                payload.get("account_id", ""),
                payload.get("license_key", ""),
            )
        except Exception as error:
            self._audit.record_action("maxmind.credentials.save", {
                "result": "error",
                "stage": getattr(error, "maxmind_stage", "download"),
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "error_type": type(error).__name__,
            })
            return {
                "status": False,
                "stage": getattr(error, "maxmind_stage", "download"),
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "recovery_required": isinstance(error, (MaxMindRecoveryRequired, nginx_prerequisites.PrerequisiteRecoveryRequired)),
                "msg": "Thiết lập GeoIP thất bại.",
            }
        finally:
            candidate_credentials.unlink(missing_ok=True)
            if self._webserver_type == 'nginx':
                nginx_prerequisites.cleanup_candidate(self._plugin_root, candidate)
        self._audit.record_action("maxmind.credentials.save", {
            "result": "success",
            "account_id": credentials["account_id"],
            "transaction_id": database["transaction_id"],
        })
        return {
            "status": True,
            "credentials": credentials,
            "database": database,
            "geoip": {"active": self._webserver_type != 'nginx', "database_ready": True, "transaction": database["config_transaction"]},
        }

    @_backend_api(nginx=True, runtime_only=True)
    def update_geoip_database(self, _request):
        candidate = None
        try:
            candidate = self._maxmind_downloader(
                self._maxmind_credentials, self._maxmind_staging
            )
            result = self._install_maxmind_candidate(candidate)
            self._prune_geoip_history()
        except Exception as error:
            self._audit.record_action(
                "maxmind.database.update",
                {
                    "result": "error",
                    "stage": getattr(error, "maxmind_stage", "download"),
                    "rolled_back": bool(getattr(error, "rolled_back", False)),
                    "error_type": type(error).__name__,
                },
            )
            return {
                "status": False,
                "stage": getattr(error, "maxmind_stage", "download"),
                "rolled_back": bool(getattr(error, "rolled_back", False)),
                "recovery_required": isinstance(error, (MaxMindRecoveryRequired, nginx_prerequisites.PrerequisiteRecoveryRequired)),
                "msg": "Không thể cập nhật GeoIP.",
            }
        finally:
            if self._webserver_type == 'nginx':
                nginx_prerequisites.cleanup_candidate(self._plugin_root, candidate)
        self._audit.record_action(
            "maxmind.database.update", {**result, "result": "success"}
        )
        return {
            "status": True,
            "database": result,
            "geoip": {"active": self._webserver_type != 'nginx', "database_ready": True, "transaction": result["config_transaction"]},
        }

    @_backend_api()
    def issue_reload_token(self, _request):
        return {"status": True, "token": self._adapter.issue_reload_token()}

    @_backend_api()
    def reload_ols(self, request):
        try:
            result = self._adapter.reload_gracefully(request.get("token", ""))
        except BaseException as error:
            self._audit.record_action(
                "ols.reload",
                {"result": "error", "error_type": type(error).__name__, "error": str(error)},
            )
            return {"status": False, "output": str(error)}
        returncode = getattr(result, "returncode", 0)
        self._audit.record_action(
            "ols.reload",
            {
                "result": "success" if returncode == 0 else "error",
                "returncode": returncode,
            },
        )
        return {
            "status": returncode == 0,
            "output": getattr(result, "stdout", "") or getattr(result, "stderr", ""),
        }
