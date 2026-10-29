#!/usr/bin/env python3
import sys
import os
from pathlib import Path

from ols_geo_access_main import ols_geo_access_main
from lib.backend_detector import load_persisted_backend
from lib.paths import PluginPaths


def main():
    plugin_root = Path(__file__).resolve().parent
    manager = None
    if load_persisted_backend(PluginPaths(plugin_root)) == 'nginx':
        from backend_lifecycle import nginx_app
        manager = nginx_app(plugin_root, os.environ.get('OLS_GEO_ACCESS_PREFIX', ''))
        state = manager._nginx.status()
        if manager._nginx.requirements() or not state['current'] or state['current']['status'] == 'deactivated':
            return 0
    manager = manager or ols_geo_access_main(
        plugin_root=plugin_root,
        state_root=plugin_root / 'data' / 'release-state',
        releases_root=plugin_root / 'generated' / 'releases',
        snapshots_root=plugin_root / 'data' / 'snapshots',
    )
    result = manager.refresh_traffic_modes({})
    if not result.get('status'):
        manager._audit.record_action('traffic.scheduler', {
            'result': 'failed', 'error': str(result.get('msg', 'unknown error'))[:400],
        })
    return 0 if result.get('status') else 1


if __name__ == '__main__':
    sys.exit(main())
