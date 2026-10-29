import fcntl
import importlib
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from lib import nginx_rollback as engine

NGINX_SOURCES = {'1.28.3': '2c96a946bfb0882a21744ed429770a2123ae1828c7c48665092993ddee91a918'}
MODULE_COMMIT = '445df24ef3781e488cee3dfe8a1e111997fc1dfe'
MODULE_SHA256 = '5e2113ed09cdd710908df8c6d1630616eeacb9216ef8705a06c25733394ddf28'
TERMINAL = {'applied', 'rolled_back'}


class PrerequisiteRecoveryRequired(RuntimeError):
    pass


def pending_operations(plugin_root):
    root = engine._safe_path(Path(plugin_root) / 'data/nginx-prerequisites')
    return [str(path.parent) for path in sorted(root.glob('*/manifest.json'))
            if engine._load_json(path).get('status') not in TERMINAL]


def _private_directory(path):
    with engine._parent(Path(path) / '.workspace', create=True) as (descriptor, name):
        os.fchmod(descriptor, 0o700)


@contextmanager
def prerequisite_lock(plugin_root):
    path = Path(plugin_root) / 'data/nginx-release-state/deployment.lock'
    with engine._parent(path, create=True) as (directory, name):
        descriptor = os.open(name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError('Unsafe Nginx prerequisite lock')
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != (linked.st_dev, linked.st_ino):
                raise ValueError('Nginx prerequisite lock changed')
            if pending_operations(plugin_root):
                raise PrerequisiteRecoveryRequired('Unfinished Nginx prerequisite transaction; preserve backup and inspect recovery')
            transactions = engine._safe_path(Path(plugin_root) / 'data/nginx-release-state/transactions')
            if transactions.exists():
                for directory in sorted(transactions.iterdir()):
                    journal = engine._load_json(directory / 'manifest.json')
                    if (journal.get('schema_version') != engine.SCHEMA_VERSION or journal.get('backend') != 'nginx'
                            or journal.get('status') not in engine.TERMINAL_STATUSES):
                        raise PrerequisiteRecoveryRequired('Unfinished Nginx deployment blocks prerequisite changes')
            yield
        finally:
            os.close(descriptor)


def _prune(plugin_root):
    root = engine._safe_path(Path(plugin_root) / 'data/nginx-prerequisites')
    completed = [path.parent for path in root.glob('*/manifest.json')
                 if engine._load_json(path).get('status') in TERMINAL]
    for directory in sorted(completed, key=lambda path: path.stat().st_mtime_ns, reverse=True)[5:]:
        engine._safe_path(directory)
        shutil.rmtree(directory)


def _change(plugin_root, adapter, target, content, kind, verify=None, reload=True, expected=None):
    identity = adapter._runtime()
    binary_hash = engine.sha256_bytes(Path(adapter.binary_path).read_bytes())
    previous, before = engine._read_file(target)
    if expected is not None and before != expected:
        raise ValueError('Nginx configuration changed before prerequisite transaction')
    after = engine._snapshot(content, before if before['exists'] else None)
    if before == after:
        return {'status': 'ready', 'updated': False, 'sha256': after['sha256'],
                'transaction_id': None, 'size': len(content), 'config_transaction': None}
    if not adapter.test_config().valid:
        raise RuntimeError('Nginx config test failed before prerequisite change')
    directory = engine._safe_path(Path(plugin_root) / 'data/nginx-prerequisites' / secrets.token_hex(16))
    engine._mkdir(directory)
    if previous is not None:
        engine._write_file(directory / 'backup', previous, engine._snapshot(previous, {'mode': 0o600, 'uid': os.geteuid(), 'gid': os.getegid()}), engine.ABSENT)
    journal = {'schema_version': 1, 'status': 'prepared', 'kind': kind, 'target': str(target),
               'before': before, 'after': after, 'binary_sha256': binary_hash,
               'runtime': list(identity), 'reload_requested': False}
    manifest = directory / 'manifest.json'
    engine._write_json(manifest, journal)
    try:
        if adapter._runtime() != identity or engine.sha256_bytes(Path(adapter.binary_path).read_bytes()) != binary_hash:
            raise ValueError('Nginx runtime changed during prerequisite setup')
        journal['status'] = 'applying'
        engine._write_json(manifest, journal)
        engine._write_file(target, content, after, before)
        if not adapter.test_config().valid:
            raise RuntimeError('Nginx config test failed after prerequisite change')
        if reload:
            journal.update(status='reloading', reload_requested=True)
            engine._write_json(manifest, journal)
            if not adapter.reload_service():
                raise RuntimeError('Nginx prerequisite reload failed')
        if verify is not None and not verify():
            raise RuntimeError('Nginx prerequisite runtime verification failed')
        if engine._read_file(target)[1] != after or adapter._runtime() != identity:
            raise RuntimeError('Nginx prerequisite changed after activation')
        journal['status'] = 'applied'
        engine._write_json(manifest, journal)
    except BaseException as error:
        try:
            if adapter._runtime() != identity or engine.sha256_bytes(Path(adapter.binary_path).read_bytes()) != binary_hash:
                raise RuntimeError('Nginx runtime changed; automatic rollback refused')
            current = engine._read_file(target)[1]
            if current != before:
                engine._write_file(target, previous, before, after)
            if not adapter.test_config().valid:
                raise RuntimeError('Nginx config test failed during prerequisite rollback')
            if journal['reload_requested'] and not adapter.reload_service():
                raise RuntimeError('Nginx prerequisite rollback reload failed')
            journal['status'] = 'rolled_back'
            engine._write_json(manifest, journal)
            _prune(plugin_root)
            error.rolled_back = True
            error.maxmind_stage = kind
        except BaseException as recovery:
            journal.update(status='recovery_required', error_type=type(error).__name__, recovery_error=str(recovery)[:1024])
            engine._write_json(manifest, journal)
            raise PrerequisiteRecoveryRequired('Nginx prerequisite recovery required: ' + str(directory)) from error
        raise
    _prune(plugin_root)
    return {'status': 'applied', 'updated': True, 'transaction_id': directory.name,
            'sha256': after['sha256'], 'size': len(content), 'config_transaction': None}


def _download(url, destination, checksum):
    with urlopen(Request(url, headers={'User-Agent': 'ols-geo-access-installer'}), timeout=60) as response:
        final = urlsplit(response.url)
        if final.scheme != 'https' or final.hostname not in {'nginx.org', 'codeload.github.com'}:
            raise ValueError('Untrusted Nginx source download redirect')
        content = response.read(64 * 1024 * 1024 + 1)
    if len(content) > 64 * 1024 * 1024 or engine.sha256_bytes(content) != checksum:
        raise ValueError('Nginx source checksum mismatch')
    destination.write_bytes(content)


def extract_source(archive, destination, checksum):
    if engine.sha256_bytes(archive.read_bytes()) != checksum:
        raise ValueError('Nginx source checksum mismatch')
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        if len(members) > 30000 or sum(member.size for member in members) > 256 * 1024 * 1024:
            raise ValueError('Oversized source archive')
        for member in members:
            relative = Path(member.name)
            if relative.is_absolute() or '..' in relative.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe source archive entry')
        for member in members:
            target = engine._safe_path(destination / member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as original, target.open('xb') as output:
                    shutil.copyfileobj(original, output)
                target.chmod(member.mode & 0o755)


def _run(arguments, workspace, timeout=1200):
    result = subprocess.run(arguments, cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, check=False, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError('Nginx prerequisite command failed (' + arguments[0] + '): ' + result.stdout[-3000:])
    return result.stdout


def _dependencies(workspace, arguments=()):
    if not Path('/usr/bin/apt-get').is_file():
        raise ValueError('Automatic GeoIP2 compilation currently requires Debian/Ubuntu apt-get')
    packages = ['build-essential', 'libmaxminddb-dev', 'libpcre3-dev', 'zlib1g-dev']
    if any('ssl' in argument or 'http_v3' in argument for argument in arguments):
        packages.append('libssl-dev')
    if '--with-http_image_filter_module' in arguments:
        packages.append('libgd-dev')
    if '--with-http_xslt_module' in arguments:
        packages.append('libxslt1-dev')
    missing = []
    for package in packages:
        result = subprocess.run(['dpkg-query', '-W', '-f=${Status}', package], capture_output=True, text=True, check=False)
        if result.returncode or result.stdout.strip() != 'install ok installed':
            missing.append(package)
    if missing:
        options = ['--no-upgrade', '--no-install-recommends', '--no-remove']
        plan = _run(['apt-get', '--simulate', *options, 'install', *missing], workspace)
        if re.search(r'^Inst \S+ \[', plan, re.M) or re.search(r'^Remv ', plan, re.M):
            raise ValueError('Build dependencies require a package upgrade/removal; automatic setup refused')
        archives = workspace / 'apt-archives'
        (archives / 'partial').mkdir(parents=True)
        _run(['apt-get', '-y', *options,
              '-o', 'Dir::Cache::archives=' + str(archives), 'install', *missing], workspace)


def verify_module(adapter, content, workspace):
    signature = re.compile(rb'\d+,\d+,\d+,[01]{20,}(?=\x00)')
    binary = Path(adapter.binary_path).read_bytes()
    expected = set(signature.findall(binary))
    if len(expected) != 1 or set(signature.findall(content)) != expected:
        raise ValueError('Nginx GeoIP2 module ABI signature mismatch')
    module = workspace / 'candidate.so'
    module.write_bytes(content)
    dependencies = _run(['ldd', str(module)], workspace, timeout=30)
    if 'not found' in dependencies or str(workspace) in dependencies:
        raise ValueError('Nginx GeoIP2 runtime library is missing or temporary')
    probe = workspace / 'probe.conf'
    probe.write_text('load_module "' + str(module) + '";\nerror_log stderr;\nevents {}\nhttp {}\n')
    _run([str(adapter.binary_path), '-t', '-p', str(adapter.prefix) + '/', '-c', str(probe)], workspace, timeout=30)


def build_module(adapter, workspace):
    description = _run([str(adapter.binary_path), '-V'], workspace, timeout=30)
    version = re.search(r'nginx/(\d+\.\d+\.\d+)', description)
    if not version or version[1] not in NGINX_SOURCES:
        raise ValueError('Nginx version has no pinned source checksum for automatic GeoIP2 compilation')
    version = version[1]
    if 'configure arguments:' not in description:
        raise ValueError('Cannot read Nginx build configuration')
    excluded = ('--add-module=', '--add-dynamic-module=', '--with-openssl=', '--with-pcre=', '--with-ld-opt=', '--with-cc-opt=')
    arguments = [argument for argument in shlex.split(description.split('configure arguments:', 1)[1].strip())
                 if not argument.startswith(excluded)]
    archives = [('nginx.tar.gz', 'https://nginx.org/download/nginx-' + version + '.tar.gz', NGINX_SOURCES[version]),
                ('geoip2.tar.gz', 'https://codeload.github.com/leev/ngx_http_geoip2_module/tar.gz/' + MODULE_COMMIT, MODULE_SHA256)]
    for name, url, checksum in archives:
        _download(url, workspace / name, checksum)
        extract_source(workspace / name, workspace, checksum)
    _dependencies(workspace, arguments)
    source = workspace / ('nginx-' + version)
    module = workspace / ('ngx_http_geoip2_module-' + MODULE_COMMIT)
    arguments += ['--add-dynamic-module=' + str(module)]
    _run(['./configure', *arguments], source)
    _run(['make', '-j2', 'modules'], source)
    return (source / 'objs/ngx_http_geoip2_module.so').read_bytes()


def prepare_module(plugin_root, adapter, builder=build_module):
    plugin_root = engine._safe_path(plugin_root)
    with prerequisite_lock(plugin_root):
        adapter._runtime()
        if adapter.check_geoip2_support():
            return {'status': 'ready', 'updated': False}
        state = plugin_root / 'data/nginx-release-state/current.json'
        if state.exists():
            raise ValueError('Cannot prepare GeoIP2 while an active Nginx release exists')
        target = engine._safe_path(Path(adapter.conf_path))
        original, snapshot = engine._read_file(target)
        if original is None or re.search(rb'^\s*load_module\b[^;]*geoip2', original, re.M):
            raise ValueError('Nginx configuration already references GeoIP2 but runtime is not verified')
        module = engine._safe_path(Path(adapter.prefix) / 'modules/ngx_http_geoip2_module.so')
        if '"' in str(module) or '\\' in str(module):
            raise ValueError('Unsafe Nginx module configuration path')
        previous, previous_snapshot = engine._read_file(module)
        build_root = plugin_root / 'tmp/nginx-build'
        _private_directory(build_root)
        with tempfile.TemporaryDirectory(prefix='build-', dir=build_root) as temporary:
            workspace = Path(temporary)
            content = previous if previous is not None else builder(adapter, workspace)
            verify_module(adapter, content, workspace)
            installed = engine._snapshot(content)
            module_created = False
            notice_created = False
            proposed = ('load_module "' + str(module) + '";\n').encode() + original
            try:
                if previous is None:
                    notice = module.with_suffix('.LICENSE')
                    if engine._read_file(notice)[0] is None:
                        license_content = (Path(__file__).resolve().parents[1] / 'THIRD_PARTY_LICENSES.md').read_bytes()
                        engine._write_file(notice, license_content, engine._snapshot(license_content), engine.ABSENT)
                        notice_created = True
                    engine._write_file(module, content, installed, previous_snapshot)
                    module_created = True
                if engine._read_file(target)[1] != snapshot:
                    raise ValueError('Nginx main configuration changed while compiling GeoIP2')
                return _change(plugin_root, adapter, target, proposed, 'module', adapter.check_geoip2_support, expected=snapshot)
            except BaseException:
                if not pending_operations(plugin_root) and engine._read_file(target)[1] == snapshot:
                    if module_created:
                        engine._write_file(module, None, engine.ABSENT, installed)
                    if notice_created and engine._read_file(notice)[1] == engine._snapshot(license_content):
                        engine._write_file(notice, None, engine.ABSENT, engine._snapshot(license_content))
                raise


def install_database(plugin_root, adapter, destination, candidate):
    plugin_root = engine._safe_path(plugin_root)
    source = engine._safe_path(Path(candidate.get('candidate_path', '')))
    staging = plugin_root / 'tmp/maxmind'
    if not source.is_relative_to(staging) or not source.is_file():
        raise ValueError('MaxMind candidate is outside the plugin staging directory')
    content = source.read_bytes()
    if (engine.sha256_bytes(content) != candidate.get('sha256') or len(content) != candidate.get('size')
            or len(content) > engine.MAX_FILE_BYTES):
        raise ValueError('MaxMind candidate checksum mismatch')
    ensure_reader(plugin_root)
    try:
        import maxminddb
        with maxminddb.open_database(str(source)) as reader:
            if reader.metadata().database_type != 'GeoLite2-Country':
                raise ValueError('Expected GeoLite2-Country database')
    except ImportError as error:
        raise ValueError('Install the maxminddb Python reader in the panel Python environment') from error
    with prerequisite_lock(plugin_root):
        if (plugin_root / 'data/nginx-release-state/current.json').exists():
            raise ValueError('GeoIP database replacement is blocked while Nginx protection is active')
        result = _change(plugin_root, adapter, engine._safe_path(destination), content, 'database', reload=False)
    source.unlink()
    return result


def ensure_reader(plugin_root):
    try:
        import maxminddb
        return
    except ImportError:
        pass
    panel_python = Path(plugin_root).parent.parent / 'pyenv'
    if sys.prefix == sys.base_prefix and not Path(sys.executable).is_relative_to(panel_python):
        raise ValueError('Use the panel Python environment to install the MaxMind reader; system Python is not modified')
    root = engine._safe_path(Path(plugin_root) / 'tmp/maxmind-reader')
    _private_directory(root)
    with tempfile.TemporaryDirectory(prefix='install-', dir=root) as temporary:
        workspace = Path(temporary)
        requirements = workspace / 'requirements.txt'
        requirements.write_text('maxminddb==2.8.2 --hash=sha256:26a8e536228d8cc28c5b8f574a571a2704befce3b368ceca593a76d56b6590f9\n')
        _run([sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--require-hashes',
              '--disable-pip-version-check', '-r', str(requirements)], workspace, timeout=300)
    importlib.invalidate_caches()
    import maxminddb


def cleanup_candidate(plugin_root, candidate):
    if not isinstance(candidate, dict) or not candidate.get('candidate_path'):
        return
    source = Path(candidate['candidate_path'])
    staging = Path(plugin_root) / 'tmp/maxmind'
    if source.is_absolute() and '..' not in source.parts and source.is_relative_to(staging):
        engine._safe_path(source).unlink(missing_ok=True)
