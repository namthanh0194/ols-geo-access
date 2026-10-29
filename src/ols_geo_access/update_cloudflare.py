#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib.audit_log import AuditLogger, rotate_log_file
from lib.backend_detector import load_persisted_backend
from lib.paths import PluginPaths
from lib.cloudflare_ranges import (
    CloudflareRangeRefusal,
    download_cloudflare_ranges,
    prepare_cloudflare_snapshot,
    select_install_fallback,
    validate_cloudflare_snapshot,
)
from lib.ols_adapter import OLSAdapter
from lib.proxy_trust_transaction import (
    apply_proxy_trust_update,
    record_proxy_trust_check_failure,
)


def _timestamp(now):
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Cloudflare clock requires timezone")
    return current.isoformat()


def _reject_symlinks(path, allow_leaf_symlink=False):
    path = Path(path)
    if ".." in path.parts or not path.is_absolute():
        raise ValueError("unsafe path")
    current = Path(path.anchor)
    parts = path.parts[1:-1] if allow_leaf_symlink else path.parts[1:]
    for part in parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"unsafe symlink path: {current}")
    return path


def _validate_executable(path):
    path = _reject_symlinks(path, allow_leaf_symlink=True)
    try:
        resolved = path.resolve(strict=True)
        executable_root = path.parent.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"OpenLiteSpeed executable is unavailable: {path}") from error
    if resolved.parent != executable_root:
        raise ValueError(f"unsafe OpenLiteSpeed executable symlink: {path}")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"OpenLiteSpeed executable is unavailable: {path}")
    return path


def _runtime_paths(plugin_root, prefix):
    prefix = _reject_symlinks(prefix)
    plugin_root = _reject_symlinks(plugin_root)
    expected_plugin_root = prefix / "www/server/panel/plugin/ols_geo_access"
    if plugin_root != expected_plugin_root or not plugin_root.is_dir():
        raise ValueError("plugin directory is unavailable")
    server_config = prefix / "usr/local/lsws/conf/httpd_config.conf"
    openlitespeed = prefix / "usr/local/lsws/bin/openlitespeed"
    lswsctrl = prefix / "usr/local/lsws/bin/lswsctrl"
    for executable in (openlitespeed, lswsctrl):
        _validate_executable(executable)
    _reject_symlinks(server_config)
    if not server_config.is_file():
        raise ValueError("OpenLiteSpeed server configuration is unavailable")
    return server_config, openlitespeed, lswsctrl


def _load_optional_snapshot(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return None
    try:
        return validate_cloudflare_snapshot(json.loads(path.read_text()))
    except (CloudflareRangeRefusal, json.JSONDecodeError, OSError):
        return None


def _failure_code(error):
    code = getattr(error, "code", None)
    if isinstance(code, str) and code:
        return code
    if isinstance(error, (OSError, TimeoutError)):
        return "cloudflare_download_error"
    return "cloudflare_invalid_format"


def run(
    mode,
    plugin_root,
    prefix,
    downloader=download_cloudflare_ranges,
    now=None,
    allow_packaged_fallback=False,
):
    if mode not in {"ensure", "scheduled", "check-only"}:
        raise ValueError("invalid Cloudflare update mode")
    if allow_packaged_fallback and mode != "ensure":
        raise ValueError("packaged fallback is valid only for ensure mode")
    plugin_root = Path(plugin_root)
    if load_persisted_backend(PluginPaths(plugin_root)) == 'nginx':
        from backend_lifecycle import nginx_app
        app = nginx_app(plugin_root, str(prefix))
        missing = app._nginx.requirements()
        state = app._nginx.status()
        if missing or not state['current'] or state['current']['status'] == 'deactivated':
            return {'status': True, 'skipped': 'nginx_not_active', 'requirements': missing}
        if mode != 'scheduled':
            return {'status': False, 'code': 'nginx_explicit_apply_required'}
        app._cloudflare_downloader = downloader
        return app._nginx.refresh_cloudflare()
    server_config, openlitespeed, lswsctrl = _runtime_paths(plugin_root, Path(prefix))
    timestamp = _timestamp(now)
    runtime_path = plugin_root / "data/cloudflare_prefixes.json"
    packaged_path = plugin_root / "data/cloudflare_prefixes.default.json"
    runtime_snapshot = _load_optional_snapshot(runtime_path)
    packaged_snapshot = _load_optional_snapshot(packaged_path)

    try:
        payload = downloader()
        candidate = prepare_cloudflare_snapshot(
            payload,
            previous=runtime_snapshot,
            checked_at=timestamp,
        )
    except Exception as error:
        code = _failure_code(error)
        if mode == "ensure" and allow_packaged_fallback:
            try:
                candidate = select_install_fallback(runtime_snapshot, packaged_snapshot)
            except CloudflareRangeRefusal as fallback_error:
                return {
                    "status": False,
                    "code": fallback_error.code,
                    "error": str(fallback_error),
                    "fallback_used": False,
                }
            fallback_used = True
        elif mode == "scheduled":
            audit = AuditLogger(plugin_root / "logs/audit.log")
            try:
                record_proxy_trust_check_failure(
                    plugin_root,
                    server_config,
                    code,
                    timestamp,
                    audit=audit,
                )
            except Exception as state_error:
                return {
                    "status": False,
                    "code": getattr(state_error, "code", "proxy_recovery_required"),
                    "error": str(state_error),
                    "fallback_used": False,
                }
            return {
                "status": False,
                "code": code,
                "error": str(error),
                "fallback_used": False,
            }
        else:
            return {
                "status": False,
                "code": code,
                "error": str(error),
                "fallback_used": False,
            }
    else:
        fallback_used = False

    if mode == "check-only":
        update_available = runtime_snapshot is None or any(
            candidate.get(key) != runtime_snapshot.get(key)
            for key in ("etag", "prefixes", "checksum")
        )
        return {
            "status": True,
            "mode": mode,
            "etag": candidate["etag"],
            "counts": candidate["counts"],
            "checked_at": candidate["checked_at"],
            "update_available": update_available,
            "fallback_used": False,
        }

    adapter = OLSAdapter()
    adapter.CONFIG_TEST_COMMAND = (str(openlitespeed), "-t")
    adapter.RELOAD_COMMAND = (str(lswsctrl), "reload")

    def reload_ols():
        result = adapter._run(adapter.RELOAD_COMMAND, timeout=60)
        if result.returncode != 0:
            raise RuntimeError("OpenLiteSpeed graceful reload failed")
        return result

    try:
        transaction = apply_proxy_trust_update(
            plugin_root,
            server_config,
            candidate,
            adapter.run_config_test,
            reload_ols,
            audit=AuditLogger(plugin_root / "logs/audit.log"),
            checked_live=not fallback_used,
        )
    except Exception as error:
        return {
            "status": False,
            "code": getattr(error, "code", "proxy_trust_update_failed"),
            "error": str(error),
            "fallback_used": fallback_used,
            "rolled_back": getattr(error, "rolled_back", False),
            "recovery_required": getattr(error, "recovery_required", False),
        }
    return {
        "status": True,
        "mode": mode,
        "etag": candidate["etag"],
        "counts": candidate["counts"],
        "checked_at": candidate["checked_at"],
        "fallback_used": fallback_used,
        "transaction": transaction,
    }


def _parser():
    parser = argparse.ArgumentParser(
        description="Update Cloudflare CIDRs and OpenLiteSpeed trusted proxies."
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--ensure", action="store_true")
    modes.add_argument("--scheduled", action="store_true")
    modes.add_argument("--check-only", action="store_true")
    parser.add_argument("--allow-packaged-fallback", action="store_true")
    return parser


def main(argv=None):
    parser = _parser()
    arguments = parser.parse_args(argv)
    mode = "ensure" if arguments.ensure else "scheduled" if arguments.scheduled else "check-only"
    if arguments.allow_packaged_fallback and mode != "ensure":
        parser.error("--allow-packaged-fallback requires --ensure")
    prefix_text = os.environ.get("OLS_GEO_ACCESS_PREFIX", "")
    prefix = Path(prefix_text or "/")
    plugin_root = prefix / "www/server/panel/plugin/ols_geo_access"
    try:
        result = run(
            mode,
            plugin_root,
            prefix,
            allow_packaged_fallback=arguments.allow_packaged_fallback,
        )
    except Exception as error:
        result = {
            "status": False,
            "code": getattr(error, "code", "cloudflare_update_failed"),
            "error": str(error),
            "fallback_used": False,
        }
    try:
        rotate_log_file(plugin_root / "logs" / "cloudflare-update.log")
    except Exception:
        pass
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("status") else 1


if __name__ == "__main__":
    raise SystemExit(main())
