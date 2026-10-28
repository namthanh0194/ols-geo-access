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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('check', 'persist'))
    parser.add_argument('plugin_root')
    arguments = parser.parse_args()
    backend = resolve_backend(arguments.plugin_root, os.environ.get('OLS_GEO_ACCESS_PREFIX', ''))
    if backend == 'nginx':
        require_diagnostic_nginx(arguments.plugin_root)
    if arguments.operation == 'persist':
        persist_backend_identity(PluginPaths(arguments.plugin_root), backend)
    print(backend)


if __name__ == '__main__':
    main()
