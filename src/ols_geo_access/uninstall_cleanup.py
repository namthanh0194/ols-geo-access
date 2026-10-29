#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib.audit_log import AuditLogger
from lib.ols_adapter import OLSAdapter
from lib.rollback import deactivate_managed_release
from backend_lifecycle import nginx_app
from lib.backend_detector import load_persisted_backend
from lib.paths import PluginPaths


def main():
    prefix_text = os.environ.get("OLS_GEO_ACCESS_PREFIX", "")
    if ".." in Path(prefix_text).parts:
        raise ValueError("unsafe prefix")
    prefix = Path(prefix_text or "/")
    plugin_root = prefix / "www/server/panel/plugin/ols_geo_access"
    if not plugin_root.is_dir() or plugin_root.is_symlink():
        raise ValueError("plugin directory is unavailable")
    if load_persisted_backend(PluginPaths(plugin_root)) == 'nginx':
        app = nginx_app(plugin_root, prefix_text)
        result = app._nginx.deactivate()
        print(json.dumps({'status': True, 'deployment': result, 'webserver_type': 'nginx'}))
        return 0
    adapter = OLSAdapter()
    adapter.CONFIG_TEST_COMMAND = (
        str(prefix / "usr/local/lsws/bin/openlitespeed"),
        "-t",
    )
    adapter.RELOAD_COMMAND = (str(prefix / "usr/local/lsws/bin/lswsctrl"), "reload")

    def reload_ols():
        result = adapter._run(adapter.RELOAD_COMMAND, timeout=60)
        if result.returncode != 0:
            raise RuntimeError("OpenLiteSpeed graceful reload failed")
        return result

    audit = AuditLogger(plugin_root / "logs/audit.log")
    result = deactivate_managed_release(
        prefix / "www/server/panel/vhost/openlitespeed",
        plugin_root / "data/release-state",
        adapter.run_config_test,
        reload_ols,
        audit=audit,
    )
    audit.record_action(
        "plugin.uninstall",
        {"result": "success", "proxy_trust_retained": True},
    )
    print(
        json.dumps(
            {
                "status": True,
                "result": result,
                "proxy_trust_retained": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": False,
                    "error_type": type(error).__name__,
                    "error": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
    raise SystemExit(exit_code)
