import fcntl
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
from pathlib import Path

from lib.baseline_repair import _atomic_write
from lib.config_validator import validate_domain

BACKENDS = {'openlitespeed', 'nginx'}
PROCESS_NAMES = {'nginx', 'lshttpd', 'litespeed', 'openlitespeed', 'apache2', 'httpd'}
BINARIES = {
    'nginx': 'www/server/nginx/sbin/nginx',
    'openlitespeed': 'usr/local/lsws/bin/openlitespeed',
}


def _safe_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe backend path')
    target = Path(root)
    for part in relative.parts:
        target = target / part
        if target.is_symlink():
            raise ValueError('Backend state/config must not contain symlinks')
    return target


def _listener_inodes(proc):
    inodes = set()
    for name in ('tcp', 'tcp6'):
        path = proc / 'net' / name
        if name == 'tcp6' and not path.exists():
            continue
        try:
            text = path.read_text()
        except (OSError, PermissionError):
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) in {80, 443}:
                inodes.add(fields[9])
    return inodes


def _start_time(process):
    return (process / 'stat').read_text().rsplit(')', 1)[1].split()[19]


def _compiled_nginx_prefix(binary):
    result = subprocess.run(
        [str(binary), '-V'],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError('Unable to read compiled nginx prefix')
    match = re.search(r'--prefix=([^\s]+)', result.stderr + '\n' + result.stdout)
    if not match:
        raise ValueError('Compiled nginx prefix is missing')
    prefix = Path(match.group(1))
    if not prefix.is_absolute() or '..' in prefix.parts:
        raise ValueError('Invalid compiled nginx prefix')
    return prefix


def _nginx_paths(root, binary, command):
    arguments = shlex.split(command.removeprefix('nginx: master process '))
    options = {}
    arguments = arguments[1:]
    while arguments:
        option = arguments.pop(0)
        if option not in {'-c', '-p'} or not arguments or option in options:
            raise ValueError('Nginx launch arguments require manual verification')
        options[option] = arguments.pop(0)
    if '-c' not in options:
        raise ValueError('Nginx main config is not explicit in master arguments')
    prefix = Path(options['-p']) if '-p' in options else _compiled_nginx_prefix(binary)
    if not prefix.is_absolute() or '..' in prefix.parts:
        raise ValueError('Nginx runtime prefix must be absolute')
    config = Path(options['-c'])
    if not config.is_absolute():
        config = prefix / config
    return _safe_path(root, str(prefix).lstrip('/')), _safe_path(root, str(config).lstrip('/'))


def detect_webserver_environment(prefix=''):
    root = Path(prefix or '/').resolve()
    proc = root / 'proc'
    unknown = {
        'backend': 'unknown', 'binary': None, 'main_config': None,
        'prefix': None, 'master_pid': None, 'start_time': None,
        'is_container': False, 'confidence': 'unknown', 'reason': '',
    }
    candidates = []
    try:
        inodes = _listener_inodes(proc)
        namespaces = {name: os.readlink(proc / '1/ns' / name) for name in ('net', 'mnt')}
        for process in sorted(proc.iterdir()):
            if not process.name.isdigit():
                continue
            try:
                if (process / 'comm').read_text().strip() not in PROCESS_NAMES:
                    continue
                cgroup = (process / 'cgroup').read_text()
                if re.search(r'docker|kubepods|containerd|libpod|lxc', cgroup):
                    continue
                if any(os.readlink(process / 'ns' / name) != value for name, value in namespaces.items()):
                    continue
                master_sockets = _process_sockets(process)
                matched_inodes = {inode for inode in inodes if f'socket:[{inode}]' in master_sockets}
                if not matched_inodes:
                    # Nếu master đã đóng listener sau fork hoặc dùng SO_REUSEPORT, tìm worker thuộc master này
                    for child in proc.iterdir():
                        if not child.name.isdigit():
                            continue
                        try:
                            status_text = (child / 'status').read_text()
                            ppid_match = re.search(r'^PPid:\s+(\d+)', status_text, re.M)
                            if ppid_match and ppid_match.group(1) == process.name:
                                child_sockets = _process_sockets(child)
                                matched_inodes.update({inode for inode in inodes if f'socket:[{inode}]' in child_sockets})
                        except (OSError, PermissionError):
                            pass
                if not matched_inodes:
                    continue
                start_time = _start_time(process)
                binary = (process / 'exe').resolve(strict=True)
                backend = next((name for name, path in BINARIES.items() if binary == (root / path).resolve()), None)
                if backend is None:
                    raise ValueError('HTTP listener belongs to a non-aaPanel webserver')
                command = (process / 'cmdline').read_bytes().replace(b'\0', b' ').decode().strip()
                if backend == 'nginx':
                    if not command.startswith('nginx: master process '):
                        continue
                    runtime_prefix, config = _nginx_paths(root, binary, command)
                else:
                    pid = (root / 'tmp/lshttpd/lshttpd.pid').read_text().strip()
                    if pid != process.name or command != 'openlitespeed (lshttpd - main)':
                        continue
                    runtime_prefix = root / 'usr/local/lsws'
                    config = _safe_path(root, 'usr/local/lsws/conf/httpd_config.conf')
                include = f'/www/server/panel/vhost/{backend}/*.conf'
                if not re.search(r'^\s*include\s+[\"\x27]?' + re.escape(include) + r'[\"\x27]?\s*(?:;|$)', config.read_text(), re.M):
                    raise ValueError('Runtime config does not include the aaPanel vhosts')
                if not (root / 'www/server/panel/vhost' / backend).is_dir():
                    raise ValueError('aaPanel vhost directory is missing')
                if _start_time(process) != start_time or (process / 'exe').resolve(strict=True) != binary:
                    raise ValueError('Webserver process changed during detection')
                candidates.append({
                    'backend': backend, 'binary': binary, 'main_config': config,
                    'prefix': runtime_prefix, 'master_pid': int(process.name),
                    'start_time': start_time, 'is_container': False,
                    'confidence': 'verified', 'reason': 'Verified aaPanel master and HTTP listener',
                })
            except FileNotFoundError:
                if process.exists():
                    raise
        if len(candidates) == 1:
            return candidates[0]
        unknown['reason'] = 'Multiple active aaPanel masters' if candidates else 'No verified active aaPanel master'
    except (OSError, ValueError, IndexError) as error:
        unknown['reason'] = str(error)
    return unknown


def _read_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'r', encoding='utf-8') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError('Backend state must be a regular file')
        content = handle.read(1048577)
        if len(content) > 1048576:
            raise ValueError('Backend state is too large')
        payload = json.loads(content)
    if not isinstance(payload, dict) or payload.get('schema_version') != 1:
        raise ValueError('Invalid backend state schema')
    return payload


def _legacy_backend(paths):
    current_path = _safe_path(paths.root, 'data/release-state/current.json')
    if not current_path.exists():
        return 'unknown'
    current = _read_json(current_path)
    release_id = current.get('release_id')
    if release_id is None and current.get('managed_files') == {}:
        return 'unknown'
    if not isinstance(release_id, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', release_id):
        raise ValueError('Invalid legacy release id')
    release_root = _safe_path(paths.root, Path('generated/releases') / release_id)
    release = _read_json(_safe_path(release_root, 'manifest.json'))
    generated = release.get('generated_checksums')
    managed = current.get('managed_files')
    if release.get('release_id') != release_id or not isinstance(generated, dict) or not generated or not isinstance(managed, dict):
        raise ValueError('Unverified legacy OLS provenance')
    if not set(managed).issubset(generated):
        raise ValueError('Legacy managed files do not match the release')
    for domain, metadata in generated.items():
        validate_domain(domain)
        relative = Path('domains') / domain / 'urlrewrite/00-ols-geo-access.conf'
        if not isinstance(metadata, dict) or metadata.get('relative_path') != str(relative):
            raise ValueError('Invalid legacy generated path')
        content = _safe_path(release_root, relative).read_bytes()
        if hashlib.sha256(content).hexdigest() != metadata.get('sha256'):
            raise ValueError('Legacy release checksum mismatch')
        if not content.startswith(b'# Managed by OLS Geo Access Manager. Do not edit.\n') or b'RewriteRule ' not in content:
            raise ValueError('Legacy release is not identifiable as OLS')
        if domain in managed:
            expected = {'relative_path': str(Path('proxy') / domain / 'urlrewrite/00-ols-geo-access.conf'), 'sha256': metadata['sha256']}
            if managed[domain] != expected:
                raise ValueError('Legacy managed metadata mismatch')
    return 'openlitespeed'


def load_persisted_backend(paths):
    identity_path = _safe_path(paths.root, 'data/backend_identity.json')
    legacy = _legacy_backend(paths)
    if not identity_path.exists():
        return legacy
    payload = _read_json(identity_path)
    backend = payload.get('backend')
    if not isinstance(backend, str) or backend not in BACKENDS:
        raise ValueError('Invalid persisted backend')
    if legacy != 'unknown' and backend != legacy:
        raise ValueError('Persisted backend conflicts with legacy OLS state')
    return backend


def persist_backend_identity(paths, backend):
    if not isinstance(backend, str) or backend not in BACKENDS:
        raise ValueError('Unsupported backend identity')
    target = _safe_path(paths.root, 'data/backend_identity.json')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    lock = _safe_path(paths.root, 'data/backend-identity.lock')
    descriptor = os.open(lock, flags, 0o600)
    with os.fdopen(descriptor, 'a') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError('Backend identity lock must be a regular file')
        fcntl.flock(handle, fcntl.LOCK_EX)
        previous = load_persisted_backend(paths)
        if previous not in {'unknown', backend}:
            raise ValueError('Changing the persisted webserver requires explicit migration')
        if not target.exists():
            payload = {'schema_version': 1, 'backend': backend}
            _atomic_write(target, (json.dumps(payload, sort_keys=True) + '\n').encode(), 0o600)
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
def _process_sockets(process):
    sockets = set()
    try:
        for fd in (process / 'fd').iterdir():
            try:
                target = os.readlink(fd)
                if target.startswith('socket:['):
                    sockets.add(target)
            except (OSError, PermissionError):
                pass
    except (OSError, PermissionError):
        pass
    return sockets
