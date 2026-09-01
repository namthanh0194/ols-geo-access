import importlib
import json
import os
import re
from pathlib import Path
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import lib.maxmind as maxmind_module
import lib.bot_activity as bot_activity_module
import lib.config_generator as config_generator_module
import lib.config_store as config_store_module
import lib.rollback as rollback_module

importlib.reload(maxmind_module)
importlib.reload(bot_activity_module)
importlib.reload(config_store_module)
importlib.reload(config_generator_module)
importlib.reload(rollback_module)

from lib.baseline_audit import audit_baseline as build_baseline_report
from lib.bot_activity import collect_bot_activity
from lib.feed_updater import enabled_feeds
from lib.ols_adapter import OLSAdapter
from lib.proxy_trust_audit import audit_proxy_trust as build_proxy_trust_report
from lib.audit_log import AuditLogger
from lib.config_store import load_json, save_json
from lib.config_validator import build_geoip_proposal, apply_geoip_proposal, restore_geoip_transaction
from lib.domain_inventory import collect_domains
from lib.maxmind import download_country_database, get_credential_status, save_credentials
from lib.paths import PluginPaths
from lib.rollback import (
    apply_release as apply_managed_release,
    build_staging as build_managed_staging,
    list_releases as list_managed_releases,
    rollback_release as rollback_managed_release,
)


class ols_geo_access_main:
    VERSION = "0.1.0"

    def __init__(
        self,
        adapter=None,
        vhost_root=Path("/www/server/panel/vhost/openlitespeed"),
        server_config_path=Path("/usr/local/lsws/conf/httpd_config.conf"),
        required_proxy_prefixes=(),
        releases_root=Path("/www/server/panel/plugin/ols_geo_access/generated/releases"),
        state_root=Path("/www/server/panel/plugin/ols_geo_access/data/release-state"),
        geoip_database=Path("/usr/local/share/GeoIP/GeoLite2-Country.mmdb"),
        plugin_root=Path("/www/server/panel/plugin/ols_geo_access"),
        database_path=Path("/www/server/panel/data/default.db"),
        snapshots_root=None,
        service_pid_path=Path("/tmp/lshttpd/lshttpd.pid"),
        logs_root=Path("/www/wwwlogs"),
        maxmind_downloader=download_country_database,
    ):
        self._adapter = adapter or OLSAdapter()
        self._vhost_root = Path(vhost_root)
        self._server_config_path = Path(server_config_path)
        self._required_proxy_prefixes = tuple(required_proxy_prefixes)
        self._releases_root = Path(releases_root)
        self._state_root = Path(state_root)
        self._geoip_database = Path(geoip_database)
        self._plugin_root = Path(plugin_root)
        self._paths = PluginPaths(self._plugin_root)
        self._database_path = Path(database_path)
        self._snapshots_root = Path(snapshots_root) if snapshots_root else self._plugin_root / "data" / "snapshots"
        self._audit = AuditLogger(self._plugin_root / "logs" / "audit.log")
        self._service_pid_path = Path(service_pid_path)
        self._logs_root = Path(logs_root)
        self._maxmind_credentials = self._plugin_root / "data" / "secrets" / "maxmind.json"
        self._maxmind_downloader = maxmind_downloader
        self._geoip_proposals = self._plugin_root / "data" / "geoip-proposals"
        self._geoip_transactions = self._plugin_root / "data" / "geoip-transactions"

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
        return {
            "status": True,
            "version": self.VERSION,
        }

    def audit_baseline(self, _request):
        return {
            "status": True,
            "report": build_baseline_report(
                self._adapter.run_config_test(), self._vhost_root
            ),
        }

    def audit_proxy_trust(self, request):
        domain = request.get("domain", "")
        traffic_mode = request.get("traffic_mode", "unknown")
        report = build_proxy_trust_report(
            domain,
            traffic_mode,
            self._server_config_path.read_text(errors="replace"),
            self._required_proxy_prefixes,
        )
        return {"status": True, "report": asdict(report)}

    def _build_staging(self, assignments, payload=None):
        payload = payload or {}
        exceptions = load_json(self._paths, "woo_exceptions")["exceptions"]
        allowlist = load_json(self._paths, "ip_allowlist")["entries"]
        snapshots = {}
        if self._snapshots_root.is_dir():
            for path in sorted(self._snapshots_root.glob("*.json")):
                snapshots[path.stem] = json.loads(path.read_text())
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
        )

    def build_staging(self, request):
        payload = self._payload(request) if request else {}
        assignments = load_json(self._paths, "domains")["domains"]
        manifest = self._build_staging(assignments, payload)
        return {"status": True, "release": manifest}

    def _reload(self):
        token = self._adapter.issue_reload_token()
        result = self._adapter.reload_gracefully(token)
        if getattr(result, "returncode", 0) != 0:
            raise RuntimeError("OpenLiteSpeed graceful reload failed")
        return result

    def _ensure_geoip_config(self):
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
        try:
            self._reload()
        except BaseException as error:
            restore_geoip_transaction(
                transaction["transaction_id"],
                self._geoip_transactions,
                self._server_config_path,
                audit=self._audit,
            )
            raise
        return transaction

    def apply_release(self, request):
        deployment = apply_managed_release(
            request["release_id"],
            self._releases_root,
            self._vhost_root,
            self._state_root,
            self._adapter.run_config_test,
            transaction_id=request.get("transaction_id"),
        )
        return {"status": True, "deployment": deployment}

    def list_releases(self, _request):
        return {
            "status": True,
            "releases": list_managed_releases(self._releases_root, self._state_root),
        }

    def rollback_release(self, request):
        deployment = rollback_managed_release(
            self._releases_root,
            self._vhost_root,
            self._state_root,
            self._adapter.run_config_test,
            transaction_id=request.get("transaction_id"),
        )
        return {"status": True, "deployment": deployment}

    def get_dashboard(self, _request):
        config_test = self._adapter.run_config_test()
        domains_config = load_json(self._paths, "domains")
        managed_domains = {
            domain for domain, settings in domains_config["domains"].items()
            if settings.get("enabled") and settings.get("group") != "NONE"
        }
        records = collect_domains(
            self._database_path,
            self._vhost_root,
            traffic_modes={domain: value["traffic_mode"] for domain, value in domains_config["domains"].items()},
            managed_domains=managed_domains,
        )
        feeds = {}
        if self._snapshots_root.is_dir():
            for path in sorted(self._snapshots_root.glob("*.json")):
                feeds[path.stem] = json.loads(path.read_text())
        current_path = self._state_root / "current.json"
        current = json.loads(current_path.read_text()) if current_path.is_file() else {}
        service_pid = None
        if self._service_pid_path.is_file():
            service_pid = self._service_pid_path.read_text(errors="replace").strip().split()[0]
        return {"status": True, "dashboard": {
            "service": {"pid": service_pid},
            "config_test": {"valid": config_test.valid, "exit_code": config_test.exit_code, "errors": len(config_test.errors), "warnings": len(config_test.warnings), "error_lines": list(config_test.errors), "warning_lines": list(config_test.warnings)},
            "geoip": {"path": str(self._geoip_database), "readable": self._geoip_database.is_file() and os.access(self._geoip_database, os.R_OK)},
            "domains": {"total": len(records), "protected": len(managed_domains), "active": sum(item.status == "active" for item in records)},
            "feeds": feeds,
            "release": {"current": current.get("release_id"), "previous": current.get("previous_release")},
        }}

    def get_domains(self, _request):
        settings = load_json(self._paths, "domains")["domains"]
        managed = {domain for domain, item in settings.items() if item.get("enabled") and item.get("group") != "NONE"}
        records = collect_domains(self._database_path, self._vhost_root, traffic_modes={domain: item["traffic_mode"] for domain, item in settings.items()}, managed_domains=managed)
        result = []
        for record in records:
            item = asdict(record)
            item.update(settings.get(record.domain, {"group": "NONE", "traffic_mode": "unknown", "enabled": False}))
            result.append(item)
        return {"status": True, "domains": result}

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

    def save_domains(self, request):
        payload = self._payload(request)
        previous = load_json(self._paths, "domains")
        rollback_manifest = None
        stage = "build_rollback"
        try:
            rollback_manifest = self._build_staging(previous["domains"])
            stage = "save_domains"
            save_json(self._paths, "domains", payload, audit=self._audit)
            stage = "build_release"
            manifest = self._build_staging(payload["domains"])
            stage = "apply_release"
            deployment = apply_managed_release(
                manifest["release_id"], self._releases_root, self._vhost_root,
                self._state_root, self._adapter.run_config_test,
            )
            stage = "reload_ols"
            self._reload()
        except BaseException as error:
            save_json(self._paths, "domains", previous, audit=self._audit)
            if rollback_manifest:
                try:
                    apply_managed_release(
                        rollback_manifest["release_id"], self._releases_root,
                        self._vhost_root, self._state_root, self._adapter.run_config_test,
                    )
                    self._reload()
                except BaseException:
                    pass
            self._audit.record_action("domains.auto_apply", {
                "result": "error",
                "stage": stage,
                "error_type": type(error).__name__,
                "error": str(error),
            })
            return {"status": False, "msg": "Không thể áp dụng rule website; cấu hình trước đó đã được khôi phục."}
        return {"status": True, "deployment": deployment}

    def save_exceptions(self, request):
        payload = self._payload(request)
        save_json(self._paths, "woo_exceptions", payload, audit=self._audit)
        return {"status": True}

    def get_ip_allowlist(self, _request):
        return {"status": True, "allowlist": load_json(self._paths, "ip_allowlist")}

    def save_ip_allowlist(self, request):
        payload = self._payload(request)
        previous = load_json(self._paths, "ip_allowlist")
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ValueError("entries must be a list")
        user_entries = [entry for entry in entries if entry.get("id") != "local-origin"]
        entry_ids = [entry.get("id") for entry in user_entries if isinstance(entry, dict)]
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("allowlist entry ids must be unique")
        payload = dict(payload)
        payload["entries"] = [entry for entry in previous["entries"] if entry.get("id") == "local-origin"] + user_entries
        assignments = load_json(self._paths, "domains")["domains"]
        rollback_manifest = None
        stage = "build_rollback"
        try:
            rollback_manifest = self._build_staging(assignments)
            stage = "save_allowlist"
            save_json(self._paths, "ip_allowlist", payload, audit=self._audit)
            stage = "build_release"
            manifest = self._build_staging(assignments)
            stage = "apply_release"
            deployment = apply_managed_release(
                manifest["release_id"], self._releases_root, self._vhost_root,
                self._state_root, self._adapter.run_config_test,
            )
            stage = "reload_ols"
            self._reload()
        except BaseException as error:
            save_json(self._paths, "ip_allowlist", previous, audit=self._audit)
            if rollback_manifest:
                try:
                    apply_managed_release(
                        rollback_manifest["release_id"], self._releases_root,
                        self._vhost_root, self._state_root, self._adapter.run_config_test,
                    )
                    self._reload()
                except BaseException:
                    pass
            self._audit.record_action("ip_allowlist.auto_apply", {
                "result": "error",
                "stage": stage,
                "error_type": type(error).__name__,
                "error": str(error),
            })
            return {"status": False, "msg": "Không thể áp dụng IP tin cậy; cấu hình trước đó đã được khôi phục."}
        return {"status": True, "deployment": deployment, "allowlist": payload}

    def get_maxmind_status(self, _request):
        credentials = get_credential_status(self._maxmind_credentials)
        database = {"path": str(self._geoip_database), "readable": self._geoip_database.is_file() and os.access(self._geoip_database, os.R_OK)}
        if database["readable"]:
            database.update({"size": self._geoip_database.stat().st_size, "modified_at": self._geoip_database.stat().st_mtime})
        return {"status": True, "credentials": credentials, "database": database}

    def save_maxmind_credentials(self, request):
        payload = self._payload(request)
        try:
            credentials = save_credentials(
                self._maxmind_credentials,
                payload.get("account_id", ""),
                payload.get("license_key", ""),
            )
            self._audit.record_action("maxmind.credentials.save", {"account_id": credentials["account_id"]})
            database = self._maxmind_downloader(self._maxmind_credentials, self._geoip_database)
            transaction = self._ensure_geoip_config()
        except Exception as error:
            self._audit.record_action("maxmind.credentials.save", {"result": "error", "error_type": type(error).__name__})
            return {"status": False, "msg": "Thiết lập GeoIP thất bại; cấu hình OLS hiện tại vẫn được giữ nguyên."}
        return {"status": True, "credentials": credentials, "database": database, "geoip": {"active": True, "transaction": transaction}}

    def update_geoip_database(self, _request):
        try:
            result = self._maxmind_downloader(self._maxmind_credentials, self._geoip_database)
            transaction = self._ensure_geoip_config()
            if result["updated"] and transaction is None:
                self._reload()
        except Exception as error:
            self._audit.record_action(
                "maxmind.database.update",
                {"result": "error", "error_type": type(error).__name__},
            )
            return {"status": False, "msg": "Không thể tải GeoIP. Hãy kiểm tra tài khoản hoặc thử lại."}
        self._audit.record_action("maxmind.database.update", result)
        return {"status": True, "database": result, "geoip": {"active": True, "transaction": transaction}}

    def issue_reload_token(self, _request):
        return {"status": True, "token": self._adapter.issue_reload_token()}

    def reload_ols(self, request):
        result = self._adapter.reload_gracefully(request.get("token", ""))
        self._audit.record_action("ols.reload", {"result": "success", "config_test_exit": 0})
        return {"status": result.returncode == 0, "output": getattr(result, "stdout", "")}
