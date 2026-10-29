#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

from lib.backend_detector import detect_webserver_environment, load_persisted_backend, persist_backend_identity
from lib.paths import PluginPaths


def resolve_backend(plugin_root, prefix=''):
    root = Path(prefix or '/')
    plugin_root = Path(plugin_root)
    for path in (root, plugin_root):
        if not path.is_absolute() or '..' in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError('Unsafe lifecycle path')
    environment = detect_webserver_environment(prefix)
    backend = environment.get('backend')
    if backend not in {'openlitespeed', 'nginx'} or environment.get('confidence') != 'verified' or environment.get('is_container'):
        raise ValueError('Cannot verify aaPanel webserver: ' + environment.get('reason', 'unknown'))
    previous = load_persisted_backend(PluginPaths(plugin_root))
    if previous not in {'unknown', backend}:
        raise ValueError('Webserver differs from persisted backend; explicit migration required')
    return backend


def require_diagnostic_nginx(plugin_root):
    root = Path(plugin_root)
    for relative in ('data/nginx-release-state', 'generated/nginx-releases', 'data/release-state', 'generated/releases'):
        path = root / relative
        if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
            raise ValueError('Managed release state exists; diagnostic lifecycle cannot change it: ' + str(path))

def nginx_app(plugin_root, prefix=''):
    from ols_geo_access_main import ols_geo_access_main
    from lib.nginx_adapter import NginxAdapter
    root = Path(prefix or '/')
    if resolve_backend(plugin_root, prefix) != 'nginx':
        raise ValueError('Expected Nginx backend')
    reader = lambda: detect_webserver_environment(prefix)
    environment = reader()
    adapter = NginxAdapter(environment['binary'], environment['main_config'], prefix=environment['prefix'],
        environment_reader=reader, proc_root=root / 'proc')
    return ols_geo_access_main(plugin_root=Path(plugin_root), adapter=adapter,
        environment_reader=reader,
        vhost_root=root / 'www/server/panel/vhost/nginx',
        database_path=root / 'www/server/panel/data/default.db',
        geoip_database=root / 'usr/local/share/GeoIP/GeoLite2-Country.mmdb')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('check', 'persist'))
    parser.add_argument('plugin_root')
    arguments = parser.parse_args()
    backend = resolve_backend(arguments.plugin_root, os.environ.get('OLS_GEO_ACCESS_PREFIX', ''))
    if backend == 'nginx':
        app = nginx_app(arguments.plugin_root, os.environ.get('OLS_GEO_ACCESS_PREFIX', ''))
        status = app._nginx.status()
        if status['pending']:
            raise ValueError('Nginx transaction recovery is required before install/upgrade')
    if arguments.operation == 'persist':
        persist_backend_identity(PluginPaths(arguments.plugin_root), backend)
    print(backend)


if __name__ == '__main__':
    main()
