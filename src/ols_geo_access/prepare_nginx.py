#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from backend_lifecycle import nginx_app
from lib import nginx_prerequisites
from lib.maxmind import get_credential_status


def prepare(plugin_root, prefix=''):
    app = nginx_app(plugin_root, prefix)
    print(json.dumps({'stage': 'geoip2_module', 'message': 'Checking/building compatible Nginx GeoIP2 module'}), flush=True)
    module = nginx_prerequisites.prepare_module(Path(plugin_root), app._adapter)
    candidate = None
    database = {'status': 'needs_credentials', 'updated': False}
    try:
        if app._geoip_database.exists():
            nginx_prerequisites.ensure_reader(app._plugin_root)
        try:
            import maxminddb
            with maxminddb.open_database(str(app._geoip_database)) as reader:
                if reader.metadata().database_type == 'GeoLite2-Country':
                    database['status'] = 'ready'
        except (ImportError, OSError, ValueError):
            pass
        if database['status'] != 'ready' and get_credential_status(app._maxmind_credentials)['configured']:
            print(json.dumps({'stage': 'geoip_database', 'message': 'Downloading/verifying GeoLite2-Country'}), flush=True)
            candidate = app._maxmind_downloader(app._maxmind_credentials, app._maxmind_staging)
            database = app._install_maxmind_candidate(candidate)
    finally:
        nginx_prerequisites.cleanup_candidate(app._plugin_root, candidate)
    print(json.dumps({'stage': 'crawler_snapshots', 'message': 'Preparing enabled crawler feeds without activating rules'}), flush=True)
    try:
        subprocess.run([sys.executable, str(app._plugin_root / 'update_feeds.py'), '--prepare-only'],
                       capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        pass
    missing = app._nginx.missing_snapshots()
    feeds = {'ready': not missing, 'missing': missing}
    if missing:
        feeds['warning'] = 'Crawler feed initialization failed; the daily feed task will retry before protection is enabled'
    return {'status': True, 'module': module, 'database': database, 'feeds': feeds, 'rules_activated': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('plugin_root')
    arguments = parser.parse_args()
    print(json.dumps(prepare(Path(arguments.plugin_root), os.environ.get('OLS_GEO_ACCESS_PREFIX', ''))), flush=True)


if __name__ == '__main__':
    main()
