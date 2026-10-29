import ctypes
import errno
import fcntl
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from lib.backend_detector import load_persisted_backend
from lib.baseline_repair import sha256_bytes
from lib.config_validator import validate_domain
from lib.domain_inventory import collect_domains_nginx
from lib.paths import PluginPaths
from lib.domain_inventory import _nginx_parse

IDENTIFIER_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")
MANAGED_NAME = "00-ols-geo-access.conf"
SCHEMA_VERSION = 2
MAX_FILE_BYTES = 16 * 1024 * 1024
TERMINAL_STATUSES = {"applied", "deactivated", "rolled_back", "restored"}
TRANSACTION_STATUSES = TERMINAL_STATUSES | {
    "prepared", "files_written", "config_validated", "reload_requested",
    "verified", "restoring", "recovery_required",
}
ABSENT = {"exists": False}
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2


class NginxRecoveryRequired(RuntimeError):
    def __init__(self, message, deployment_error=None, recovery_error=None):
        super().__init__(message)
        self.deployment_error = deployment_error
        self.recovery_error = recovery_error

class NginxWriteConflict(NginxRecoveryRequired):
    pass

def _rename_at(descriptor, source, destination, flags):
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "Safe Nginx writes require renameat2") from error
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(descriptor, os.fsencode(source), descriptor, os.fsencode(destination), flags) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError("invalid Nginx identifier")
    return value


def _safe_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(ord(char) < 32 for char in str(path)):
        raise ValueError("unsafe Nginx path")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("Nginx paths must not contain symlinks")
    return path


@contextmanager
def _parent(path, create=False):
    path = _safe_path(path)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, path.name
    finally:
        os.close(descriptor)


def _snapshot(content, metadata=None):
    if content is None:
        return dict(ABSENT)
    metadata = metadata or {"mode": 0o644, "uid": os.geteuid(), "gid": os.getegid()}
    return {"exists": True, "sha256": sha256_bytes(content),
            "mode": metadata["mode"], "uid": metadata["uid"], "gid": metadata["gid"]}


def _read_at(descriptor, name):
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    except FileNotFoundError:
        return None, dict(ABSENT)
    with os.fdopen(handle, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Nginx artifacts must be regular, non-hardlinked files")
        content = stream.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("Nginx artifact exceeds size limit")
        after = os.fstat(stream.fileno())
        linked = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_size) != (
                after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size
        ) or (after.st_dev, after.st_ino) != (linked.st_dev, linked.st_ino):
            raise ValueError("Nginx artifact changed while reading")
    return content, _snapshot(content, {"mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid})


def _read_file(path):
    try:
        with _parent(path) as (descriptor, name):
            return _read_at(descriptor, name)
    except FileNotFoundError:
        return None, dict(ABSENT)


def _write_file(path, content, desired, expected):
    if content is None and expected == ABSENT:
        if _read_file(path)[1] != ABSENT:
            raise RuntimeError("Nginx target changed before deletion")
        return
    with _parent(path, create=content is not None) as (descriptor, name):
        if _read_at(descriptor, name)[1] != expected:
            raise RuntimeError("Nginx target checksum or metadata changed before write")
        temporary = ".ols-geo-" + secrets.token_hex(16)
        preserve = False
        owns_temporary = False
        try:
            if content is None:
                _rename_at(descriptor, name, temporary, RENAME_NOREPLACE)
                owns_temporary = True
            else:
                handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
                owns_temporary = True
                with os.fdopen(handle, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fchown(stream.fileno(), desired["uid"], desired["gid"])
                    os.fchmod(stream.fileno(), desired["mode"])
                    os.fsync(stream.fileno())
                if _read_at(descriptor, name)[1] != expected:
                    raise RuntimeError("Nginx target changed during write")
                _rename_at(descriptor, temporary, name, RENAME_EXCHANGE if expected["exists"] else RENAME_NOREPLACE)
            preserve = expected["exists"]
            try:
                os.fsync(descriptor)
                if preserve and _read_at(descriptor, temporary)[1] != expected:
                    raise RuntimeError("Nginx displaced file changed during mutation")
                if _read_file(path)[1] != desired:
                    raise RuntimeError("Nginx target changed after write")
            except (OSError, ValueError, RuntimeError) as error:
                if preserve:
                    raise NginxWriteConflict("Nginx write conflict; displaced file retained at " + str(Path(path).parent / temporary)) from error
                raise
            preserve = False
        finally:
            if owns_temporary and not preserve:
                try:
                    os.unlink(temporary, dir_fd=descriptor)
                except FileNotFoundError:
                    pass
        os.fsync(descriptor)
    if _read_file(path)[1] != desired:
        raise RuntimeError("Nginx target changed after write")


def _json_bytes(payload):
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()


def _load_json(path):
    content, metadata = _read_file(path)
    if not metadata["exists"]:
        raise ValueError("Missing Nginx metadata: " + str(path))
    payload = json.loads(content)
    if not isinstance(payload, dict):
        raise ValueError("Invalid Nginx metadata object")
    return payload


def _write_json(path, payload):
    content = _json_bytes(payload)
    metadata = {"mode": 0o600, "uid": os.geteuid(), "gid": os.getegid()}
    _write_file(path, content, _snapshot(content, metadata), _read_file(path)[1])


def _mkdir(path):
    with _parent(path, create=True) as (descriptor, name):
        os.mkdir(name, 0o700, dir_fd=descriptor)
        os.fsync(descriptor)


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _validate_snapshot(snapshot):
    if isinstance(snapshot, dict) and set(snapshot) == {"exists"} and snapshot["exists"] is False:
        return
    if (not isinstance(snapshot, dict) or snapshot.get("exists") is not True
            or set(snapshot) != {"exists", "sha256", "mode", "uid", "gid"}
            or not isinstance(snapshot.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", snapshot["sha256"])
            or any(type(snapshot.get(key)) is not int or snapshot[key] < 0 for key in ("mode", "uid", "gid"))
            or snapshot["mode"] > 0o7777):
        raise ValueError("Invalid Nginx file snapshot")


def _release_manifest(manifest, release_id):
    if (manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("backend") != "nginx"
            or manifest.get("release_id") != release_id or not isinstance(manifest.get("server_snippets"), dict)
            or not isinstance(manifest.get("http_conf"), dict)):
        raise ValueError("Unbound or invalid Nginx release manifest")
    for domain, metadata in manifest["server_snippets"].items():
        validate_domain(domain)
        if not isinstance(metadata, dict) or metadata.get("relative_path") != f"extension/{domain}/{MANAGED_NAME}":
            raise ValueError("Invalid Nginx snippet path binding")


def _setting_name(name):
    allowed = set(PluginPaths.DATA_FILES.values()) - {'backend_identity.json', 'proxy_trust_state.json'}
    if not isinstance(name, str) or (name not in allowed and not re.fullmatch(r'snapshots/[a-z][a-z0-9_-]{0,63}\.json', name)):
        raise ValueError('Invalid Nginx settings path')
    return name

def _candidate_settings(context, release_id):
    root = context.releases / _identifier(release_id)
    manifest = _load_json(root / 'manifest.json')
    settings = manifest.get('settings', {})
    if not isinstance(settings, dict) or len(settings) > 128:
        raise ValueError('Invalid Nginx settings manifest')
    output = {}
    for name, digest in settings.items():
        content, snapshot = _read_file(root / 'settings' / _setting_name(name))
        if not snapshot['exists'] or snapshot['sha256'] != digest:
            raise ValueError('Nginx release settings checksum mismatch')
        output[name] = content
    return output

def _setting_entries(context, journal):
    entries = journal.get('settings', {})
    if not isinstance(entries, dict) or len(entries) > 128:
        raise ValueError('Invalid Nginx settings journal')
    for name, change in entries.items():
        _setting_name(name)
        if not isinstance(change, dict) or set(change) != {'before', 'after', 'restored'} or change['restored'] != change['before']:
            raise ValueError('Invalid Nginx settings transition')
        for snapshot in change.values():
            _validate_snapshot(snapshot)
    return entries

def build_nginx_release(release_id, releases_root, http_conf_content, server_snippets,
                        parent_release=None, created_at=None, *, settings=None):
    _identifier(release_id)
    if parent_release is not None:
        _identifier(parent_release)
    root = _safe_path(releases_root) / release_id
    bodies = {"http.conf": http_conf_content}
    settings = settings or {}
    if not isinstance(settings, dict) or len(settings) > 128:
        raise ValueError('Invalid Nginx release settings')
    for name, content in settings.items():
        bodies['settings/' + _setting_name(name)] = content
    for domain, content in server_snippets.items():
        validate_domain(domain)
        bodies[f"snippets/{domain}.conf"] = content
    bodies = {name: content.encode() if isinstance(content, str) else content for name, content in bodies.items()}
    if any(not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES for content in bodies.values()):
        raise ValueError("Invalid Nginx candidate content")
    _mkdir(root)
    for relative, content in bodies.items():
        _write_file(root / relative, content, _snapshot(content), ABSENT)
    manifest = {
        "schema_version": SCHEMA_VERSION, "backend": "nginx", "release_id": release_id,
        "parent_release": parent_release, "created_at": created_at or _timestamp(),
        "http_conf": {"sha256": sha256_bytes(bodies["http.conf"])},
        "server_snippets": {domain: {"relative_path": f"extension/{domain}/{MANAGED_NAME}",
                                    "sha256": sha256_bytes(bodies[f"snippets/{domain}.conf"])} for domain in sorted(server_snippets)},
        "settings": {name: sha256_bytes(bodies['settings/' + name]) for name in settings},
    }
    _write_json(root / "manifest.json", manifest)
    return manifest


def list_nginx_releases(releases_root):
    root = _safe_path(releases_root)
    if not root.is_dir():
        return []
    releases = []
    for directory in sorted(root.iterdir()):
        try:
            _identifier(directory.name)
            manifest = _load_json(directory / "manifest.json")
            _release_manifest(manifest, directory.name)
            releases.append(manifest)
        except (ValueError, OSError):
            continue
    return sorted(releases, key=lambda release: str(release.get("created_at", "")), reverse=True)


class _Context:
    def __init__(self, vhost_root, http_conf_target, state_root, adapter, database_path, probe):
        self.state = _safe_path(state_root)
        if self.state.name != "nginx-release-state" or self.state.parent.name != "data":
            raise ValueError("Nginx state must use data/nginx-release-state")
        self.paths = PluginPaths(self.state.parent.parent)
        self.releases = self.paths.root / "generated/nginx-releases"
        self.vhosts = _safe_path(vhost_root)
        self.http = _safe_path(http_conf_target)
        self.database = _safe_path(database_path)
        if not callable(probe):
            raise ValueError("An explicit Nginx service probe is required")
        self.adapter, self.probe = adapter, probe
        self.runtime = self._runtime()
        legacy_http = self.http.parent == Path(self.runtime['main_config']).parent and self.http.name == 'ols_geo_access_http.conf'
        wildcard_http = self.http == self.vhosts / '00-ols-geo-access-http.conf'
        if not legacy_http and not wildcard_http:
            raise ValueError("Invalid managed Nginx HTTP target")
        if wildcard_http:
            self._verify_http_include()
        if self.vhosts.is_relative_to(self.paths.root) or self.http.is_relative_to(self.paths.root):
            raise ValueError("Nginx live targets overlap plugin state")
        self.binding = {"runtime": self.runtime, "scope": {
            "state_root": str(self.state), "releases_root": str(self.releases),
            "vhost_root": str(self.vhosts), "http_conf_target": str(self.http), "database_path": str(self.database),
        }}

    def _runtime(self):
        if load_persisted_backend(self.paths) != "nginx":
            raise ValueError("Persisted backend is not Nginx")
        runtime = self.adapter.get_runtime_identity()
        if (not isinstance(runtime, dict) or runtime.get("backend") != "nginx"
                or runtime.get("confidence") != "verified" or runtime.get("is_container") is not False
                or type(runtime.get("master_pid")) is not int or runtime["master_pid"] <= 1
                or not isinstance(runtime.get("start_time"), str) or not runtime["start_time"].isdigit()
                or any(not isinstance(runtime.get(key), (str, Path)) for key in ("binary", "main_config", "prefix"))):
            raise ValueError("Unverified Nginx runtime identity")
        return {"backend": "nginx", "master_pid": runtime["master_pid"], "start_time": runtime["start_time"],
                **{key: str(_safe_path(runtime[key])) for key in ("binary", "main_config", "prefix")}}

    def _verify_http_include(self):
        tree = _nginx_parse(_read_file(self.runtime['main_config'])[0].decode())
        blocks = [children for fields, children in tree if fields == ('http',) and children is not None]
        expected = ('include', str(self.vhosts / '*.conf'))
        if len(blocks) != 1 or sum(fields == expected and children is None for fields, children in blocks[0]) != 1:
            raise ValueError('Missing unique aaPanel HTTP vhost include')

    @contextmanager
    def lock(self):
        with _parent(self.state / "deployment.lock", create=True) as (directory, name):
            descriptor = os.open(name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("Unsafe Nginx deployment lock")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (metadata.st_dev, metadata.st_ino) != (linked.st_dev, linked.st_ino):
                    raise ValueError("Nginx deployment lock changed")
                os.fchmod(descriptor, 0o600)
                os.fsync(directory)
                self._lock_identity = (metadata.st_dev, metadata.st_ino)
                self.verify()
                yield
            finally:
                self._lock_identity = None
                os.close(descriptor)

    def inventory(self):
        records = collect_domains_nginx(self.database, self.vhosts, config_prefix=Path(self.runtime["main_config"]).parent)
        evidence = {"main_config": _read_file(self.runtime["main_config"])[1], "sites": {}}
        if not evidence["main_config"]["exists"]:
            raise ValueError("Nginx main configuration is missing")
        for record in records:
            values = asdict(record)
            values.pop("integration")
            values["vhost_snapshot"] = _read_file(record.vhost_path)[1]
            evidence["sites"][record.domain] = values
        return {record.domain: record for record in records}, sha256_bytes(_json_bytes(evidence))

    def verify(self, inventory=None, orphaned_domains=()):
        if getattr(self, "_lock_identity", None) is not None:
            lock = _safe_path(self.state / "deployment.lock").stat(follow_symlinks=False)
            if (lock.st_dev, lock.st_ino) != self._lock_identity or lock.st_nlink != 1:
                raise ValueError("Nginx deployment lock was replaced")
        if self._runtime() != self.runtime:
            raise ValueError("Nginx runtime changed")
        if inventory is not None:
            records, signature = self.inventory()
            if signature != inventory:
                raise ValueError("Nginx inventory or main configuration changed")
            if not isinstance(orphaned_domains, (list, tuple, set)) or any(
                    not self.deleted(domain, records) for domain in orphaned_domains):
                raise ValueError("Nginx orphan proof changed")

    def target(self, key):
        if key == "http":
            return self.http
        validate_domain(key)
        return self.vhosts / "extension" / key / MANAGED_NAME

    def deleted(self, domain, records):
        validate_domain(domain)
        return (domain not in records and not any(domain in record.aliases for record in records.values())
                and not _read_file(self.vhosts / (domain + ".conf"))[1]["exists"])

    def validate_current(self, current):
        if current is None:
            return
        if (not isinstance(current, dict) or current.get("schema_version") != SCHEMA_VERSION or current.get("backend") != "nginx"
                or current.get("binding") != self.binding or not isinstance(current.get("status"), str)
                or current["status"] not in {"active", "deactivated"}
                or not isinstance(current.get("managed_snippets"), dict)):
            raise ValueError("Unbound or changed Nginx current state")
        _identifier(current.get("release_id"))
        _identifier(current.get("transaction_id"))
        if current.get("parent_release") is not None:
            _identifier(current["parent_release"])
        _validate_snapshot(current.get("http_conf"))
        if not current["http_conf"]["exists"] and current['status'] != 'deactivated':
            raise ValueError("Nginx current state has no HTTP ownership")
        for domain, snapshot in current["managed_snippets"].items():
            validate_domain(domain)
            _validate_snapshot(snapshot)
            if not snapshot["exists"]:
                raise ValueError("Invalid Nginx snippet ownership")
        if current["status"] == "deactivated" and current["managed_snippets"]:
            raise ValueError("Deactivated state still owns snippets")


def _journal(context, transaction_id):
    _identifier(transaction_id)
    journal = _load_json(context.state / "transactions" / transaction_id / "manifest.json")
    if (journal.get("schema_version") != SCHEMA_VERSION or journal.get("backend") != "nginx"
            or journal.get("transaction_id") != transaction_id or journal.get("binding") != context.binding
            or not isinstance(journal.get("status"), str) or journal["status"] not in TRANSACTION_STATUSES
            or not isinstance(journal.get("next_current"), dict)
            or not isinstance(journal.get("state_snapshots"), dict)
            or not isinstance(journal.get("changes"), dict)
            or not {"previous_current", "restored_current", "inventory", "operation", "orphaned_domains", "reload_attempted"}.issubset(journal)):
        raise ValueError("Invalid Nginx transaction binding or status")
    return journal


def _pending(context, allowed=None):
    directory = _safe_path(context.state / "transactions")
    if not directory.exists():
        return
    for path in sorted(directory.iterdir()):
        try:
            journal = _journal(context, path.name)
            if journal["status"] not in TERMINAL_STATUSES and path.name != allowed:
                raise ValueError("unfinished transaction " + path.name)
        except (OSError, ValueError) as error:
            raise NginxRecoveryRequired("Nginx recovery required: " + str(error)) from error


def _candidate(context, release_id, releases_root):
    _identifier(release_id)
    if _safe_path(releases_root) != context.releases:
        raise ValueError("Nginx releases must use generated/nginx-releases")
    root = context.releases / release_id
    manifest = _load_json(root / "manifest.json")
    _release_manifest(manifest, release_id)
    bodies = {}
    for key, relative, metadata in [("http", "http.conf", manifest.get("http_conf", {}))] + [
        (domain, f"snippets/{domain}.conf", metadata) for domain, metadata in manifest["server_snippets"].items()
    ]:
        content, snapshot = _read_file(root / relative)
        if not snapshot["exists"] or snapshot["sha256"] != metadata.get("sha256"):
            raise RuntimeError("Nginx candidate checksum mismatch: " + key)
        bodies[key] = content
    return bodies


def _backup_path(directory, key):
    if key == "http":
        return directory / "backup/http.conf"
    if key == "current":
        return directory / "backup/current.json"
    validate_domain(key)
    return directory / "backup/snippets" / (key + ".conf")


def _save_backup(directory, key, content):
    if content is not None:
        metadata = {"mode": 0o600, "uid": os.geteuid(), "gid": os.getegid()}
        _write_file(_backup_path(directory, key), content, _snapshot(content, metadata), ABSENT)


def _load_backup(directory, key, snapshot):
    content, actual = _read_file(_backup_path(directory, key))
    if actual["exists"] != snapshot["exists"] or (actual["exists"] and actual["sha256"] != snapshot["sha256"]):
        raise ValueError("Nginx backup checksum mismatch: " + key)
    return content


def _state_snapshot(current, metadata=None):
    return _snapshot(None if current is None else _json_bytes(current), metadata or {"mode": 0o600, "uid": os.geteuid(), "gid": os.getegid()})


def _prepare(context, release_id, bodies, operation, transaction_id, settings=None, expected_settings=None):
    current_bytes, current_snapshot = _read_file(context.state / "current.json")
    current = json.loads(current_bytes) if current_bytes is not None else None
    context.validate_current(current)
    records, inventory = context.inventory()
    owned = {"http": current["http_conf"], **current["managed_snippets"]} if current else {}
    orphaned = {domain for domain in set(owned) | set(bodies) if domain != "http" and context.deleted(domain, records)}
    bodies = {key: content for key, content in bodies.items() if key not in orphaned}
    for domain in bodies:
        if domain != "http" and (domain not in records or not records[domain].supported_for_protection):
            raise ValueError("Nginx site is not eligible for protection: " + domain)
    changes, backups = {}, {}
    for key in ["http", *sorted((set(owned) | set(bodies)) - {"http"})]:
        content, before = _read_file(context.target(key))
        if key in owned:
            if before != owned[key] and not (before == ABSENT and key in orphaned):
                raise RuntimeError("Managed Nginx checksum changed or missing: " + key)
        elif before != ABSENT:
            raise RuntimeError("Nginx ownership collision: " + key)
        after = _snapshot(bodies.get(key), before if before["exists"] else None)
        changes[key] = {"before": before, "after": after, "restored": dict(ABSENT) if key in orphaned else before}
        backups[key] = content
    restored_current = json.loads(json.dumps(current)) if current else None
    if restored_current:
        for domain in orphaned:
            restored_current["managed_snippets"].pop(domain, None)
    next_current = {
        "schema_version": SCHEMA_VERSION, "backend": "nginx", "binding": context.binding,
        "release_id": release_id, "parent_release": (current.get('parent_release') if operation == 'metadata' else current['release_id']) if current else None,
        "status": "deactivated" if operation == "deactivate" else "active",
        "transaction_id": transaction_id, "applied_at": _timestamp(),
        "http_conf": changes["http"]["after"],
        "managed_snippets": {key: change["after"] for key, change in changes.items() if key != "http" and change["after"]["exists"]},
    }
    restored_bytes = current_bytes if restored_current == current else _json_bytes(restored_current)
    journal = {
        "schema_version": SCHEMA_VERSION, "backend": "nginx", "binding": context.binding,
        "transaction_id": transaction_id, "release_id": release_id, "operation": operation,
        "status": "prepared", "created_at": _timestamp(), "reload_attempted": False,
        "inventory": inventory, "orphaned_domains": sorted(orphaned), "changes": changes,
        "previous_current": current, "next_current": next_current, "restored_current": restored_current,
        "state_snapshots": {"before": current_snapshot, "after": _state_snapshot(next_current),
                            "restored": _snapshot(restored_bytes, current_snapshot if current_snapshot["exists"] else None)},
    }
    context.verify(inventory, orphaned)
    _validate_transition(journal)
    directory = context.state / "transactions" / transaction_id
    journal['settings'] = {}
    setting_backups = {}
    for name, content in (settings or {}).items():
        target = context.paths.data / _setting_name(name)
        previous, before = _read_file(target)
        if expected_settings is not None and before != expected_settings.get(name, before):
            raise ValueError('Nginx settings changed before deployment')
        if not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES:
            raise ValueError('Invalid Nginx settings content')
        after = _snapshot(content, before if before['exists'] else None)
        journal['settings'][name] = {'before': before, 'after': after, 'restored': before}
        if previous is not None:
            setting_backups[name] = previous
    _mkdir(directory)
    for name, previous in setting_backups.items():
        _write_file(directory / 'backup/settings' / name, previous, _snapshot(previous), ABSENT)
    for key, content in backups.items():
        _save_backup(directory, key, content)
    _save_backup(directory, "current", current_bytes)
    _write_json(directory / "manifest.json", journal)
    return journal


def _assert_view(context, journal, phase, current_snapshot):
    context.verify(journal["inventory"], journal["orphaned_domains"])
    for name, change in _setting_entries(context, journal).items():
        if _read_file(context.paths.data / name)[1] != change[phase]:
            raise ValueError('Nginx settings changed during transaction')
    for key, change in journal["changes"].items():
        if _read_file(context.target(key))[1] != change[phase]:
            raise ValueError("Nginx file changed before service operation: " + key)
    if _read_file(context.state / "current.json")[1] != current_snapshot:
        raise ValueError("Nginx current state changed before service operation")


def _validate_transition(journal):
    previous = journal["previous_current"]
    proposed = journal["next_current"]
    restored = journal["restored_current"]
    operation = journal.get("operation")
    metadata_only = operation == 'metadata'
    if metadata_only and (not previous or previous['status'] != 'active' or proposed['release_id'] != previous['release_id']
                          or any(change['before'] != change['after'] for change in journal['changes'].values())):
        raise ValueError('Metadata transaction cannot change Nginx configuration')
    expected_parent = (previous.get('parent_release') if metadata_only else previous['release_id']) if previous else None
    if (not isinstance(operation, str) or operation not in {"apply", "rollback", "deactivate", "metadata"}
            or type(journal.get("reload_attempted")) is not bool
            or proposed["transaction_id"] != journal["transaction_id"]
            or proposed["release_id"] != journal["release_id"]
            or proposed.get("parent_release") != expected_parent
            or proposed["status"] != ("deactivated" if operation == "deactivate" else "active")
            or (journal["status"] in {"applied", "deactivated", "verified", "reload_requested"} and not journal["reload_attempted"] and not metadata_only)):
        raise ValueError("Invalid Nginx transaction transition")
    ownership = []
    for current in (previous, proposed, restored):
        ownership.append({"http": current["http_conf"], **current["managed_snippets"]} if current else {})
    before, after, recovered = ownership
    if set(journal["changes"]) != set(before) | set(after):
        raise ValueError("Nginx journal omits or adds managed files")
    for key, change in journal["changes"].items():
        if (change["after"] != after.get(key, ABSENT) or change["restored"] != recovered.get(key, ABSENT)
                or (change["before"] != before.get(key, ABSENT)
                    and not (key in journal["orphaned_domains"] and change["before"] == ABSENT))):
            raise ValueError("Nginx journal does not match ownership")


def _restore(context, transaction_id):
    journal = _journal(context, transaction_id)
    if journal.get("write_conflict"):
        raise NginxWriteConflict(journal.get("recovery_error", "Nginx write conflict requires manual reconciliation"))
    directory = context.state / "transactions" / transaction_id
    changes = journal.get("changes")
    state = journal.get("state_snapshots", {})
    if not isinstance(changes, dict) or "http" not in changes or set(state) != {"before", "after", "restored"}:
        raise ValueError("Invalid Nginx recovery changes")
    for snapshot in state.values():
        _validate_snapshot(snapshot)
    current_actual = _read_file(context.state / "current.json")[1]
    if journal["status"] in {"applied", "deactivated"} and current_actual != state["after"]:
        raise ValueError("Stale Nginx transaction cannot replace newer state")
    if journal["status"] in {"rolled_back", "restored"} and current_actual != state["restored"]:
        raise ValueError("Stale restored Nginx transaction")
    if current_actual not in state.values():
        raise ValueError("Nginx current state changed externally")
    context.verify(journal["inventory"], journal["orphaned_domains"])
    for current in (journal.get("previous_current"), journal.get("next_current"), journal.get("restored_current")):
        context.validate_current(current)
    previous_bytes = _load_backup(directory, "current", state["before"])
    if (json.loads(previous_bytes) if previous_bytes is not None else None) != journal["previous_current"]:
        raise ValueError("Nginx prior state backup mismatch")
    restored_bytes = previous_bytes if journal["restored_current"] == journal["previous_current"] else _json_bytes(journal["restored_current"])
    if _state_snapshot(journal["next_current"], state["after"]) != state["after"] or _snapshot(restored_bytes, state["restored"] if state["restored"]["exists"] else None) != state["restored"]:
        raise ValueError("Nginx state checksum mismatch")
    records, _signature = context.inventory()
    orphaned = journal.get("orphaned_domains", [])
    if not isinstance(orphaned, list) or any(not context.deleted(domain, records) for domain in orphaned):
        raise ValueError("Nginx orphan proof changed")
    expected_restored = json.loads(json.dumps(journal["previous_current"]))
    if expected_restored:
        for domain in orphaned:
            expected_restored["managed_snippets"].pop(domain, None)
    if expected_restored != journal["restored_current"]:
        raise ValueError("Invalid Nginx restored ownership")
    backups, actual = {}, {}
    for key, change in changes.items():
        context.target(key)
        if not isinstance(change, dict) or set(change) != {"before", "after", "restored"}:
            raise ValueError("Invalid Nginx recovery change")
        for snapshot in change.values():
            _validate_snapshot(snapshot)
        if change["restored"] != (ABSENT if key in orphaned else change["before"]):
            raise ValueError("Invalid Nginx restoration target")
        backups[key] = _load_backup(directory, key, change["before"])
        actual[key] = _read_file(context.target(key))[1]
        if actual[key] not in change.values():
            raise ValueError("Nginx file changed externally during recovery: " + key)
    _validate_transition(journal)
    settings_actual, settings_backups = {}, {}
    for name, change in _setting_entries(context, journal).items():
        actual_setting = _read_file(context.paths.data / name)[1]
        if actual_setting not in change.values():
            raise ValueError('Nginx settings changed externally during recovery')
        previous, snapshot = _read_file(directory / 'backup/settings' / name)
        if snapshot['exists'] != change['before']['exists'] or (snapshot['exists'] and snapshot['sha256'] != change['before']['sha256']):
            raise ValueError('Nginx settings backup checksum mismatch')
        settings_actual[name], settings_backups[name] = actual_setting, previous
    if journal["status"] in {"rolled_back", "restored"}:
        if any(settings_actual[name] != change['restored'] for name, change in _setting_entries(context, journal).items()):
            raise ValueError('Previously restored Nginx settings changed')
        if any(actual[key] != change["restored"] for key, change in changes.items()):
            raise ValueError("Previously restored Nginx files changed")
        return journal
    journal["status"] = "restoring"
    _write_json(directory / "manifest.json", journal)
    for name, change in _setting_entries(context, journal).items():
        context.verify(journal['inventory'], journal['orphaned_domains'])
        _write_file(context.paths.data / name, settings_backups[name], change['restored'], settings_actual[name])
    for key in [*sorted(set(changes) - {"http"}), "http"]:
        context.verify(journal["inventory"], journal["orphaned_domains"])
        change = changes[key]
        content = backups[key] if change["restored"]["exists"] else None
        _write_file(context.target(key), content, change["restored"], actual[key])
    _assert_view(context, journal, "restored", current_actual)
    if not context.adapter.test_config().valid:
        raise RuntimeError("Nginx recovery config test failed")
    _assert_view(context, journal, "restored", current_actual)
    if journal.get("reload_attempted") and context.adapter.reload_service() is not True:
        raise RuntimeError("Nginx recovery reload failed")
    context.verify(journal["inventory"], journal["orphaned_domains"])
    if context.probe(journal["restored_current"]) is not True:
        raise RuntimeError("Nginx recovery probe failed")
    context.verify(journal["inventory"], journal["orphaned_domains"])
    for key, change in changes.items():
        if _read_file(context.target(key))[1] != change["restored"]:
            raise ValueError("Restored Nginx file changed before commit")
    context.verify(journal["inventory"], journal["orphaned_domains"])
    _write_file(context.state / "current.json", restored_bytes, state["restored"], current_actual)
    context.verify(journal["inventory"], journal["orphaned_domains"])
    journal["status"] = "rolled_back"
    journal["restored_at"] = _timestamp()
    _write_json(directory / "manifest.json", journal)
    return journal


def _mark_recovery(context, transaction_id, error):
    path = context.state / "transactions" / transaction_id / "manifest.json"
    journal = _load_json(path)
    journal["status"] = "recovery_required"
    journal["recovery_error"] = str(error)
    if isinstance(error, NginxWriteConflict):
        journal["write_conflict"] = True
    _write_json(path, journal)


def _execute(context, release_id, bodies, operation, transaction_id=None, settings=None, expected_settings=None):
    transaction_id = _identifier(transaction_id or secrets.token_hex(16))
    _pending(context)
    journal = _prepare(context, release_id, bodies, operation, transaction_id, settings, expected_settings)
    path = context.state / "transactions" / transaction_id / "manifest.json"
    try:
        for key, change in journal["changes"].items():
            context.verify(journal["inventory"], journal["orphaned_domains"])
            _write_file(context.target(key), bodies.get(key) if change["after"]["exists"] else None,
                        change["after"], change["before"])
        for name, change in _setting_entries(context, journal).items():
            context.verify(journal['inventory'], journal['orphaned_domains'])
            _write_file(context.paths.data / name, settings[name], change['after'], change['before'])
        journal["status"] = "files_written"
        _write_json(path, journal)
        _assert_view(context, journal, "after", journal["state_snapshots"]["before"])
        if not context.adapter.test_config().valid:
            raise RuntimeError("Nginx config test failed")
        journal["status"] = "config_validated"
        _write_json(path, journal)
        context.verify(journal["inventory"], journal["orphaned_domains"])
        if operation != 'metadata':
            journal["reload_attempted"] = True
            journal["status"] = "reload_requested"
            _write_json(path, journal)
            _assert_view(context, journal, "after", journal["state_snapshots"]["before"])
            if context.adapter.reload_service() is not True:
                raise RuntimeError("Nginx reload failed")
        context.verify(journal["inventory"], journal["orphaned_domains"])
        if context.probe(journal["next_current"]) is not True:
            raise RuntimeError("Nginx service probe failed")
        context.verify(journal["inventory"], journal["orphaned_domains"])
        for key, change in journal["changes"].items():
            if _read_file(context.target(key))[1] != change["after"]:
                raise ValueError("Nginx file changed before commit")
        journal["status"] = "verified"
        _write_json(path, journal)
        _assert_view(context, journal, 'after', journal['state_snapshots']['before'])
        for name, change in _setting_entries(context, journal).items():
            if _read_file(context.paths.data / name)[1] != change['after']:
                raise ValueError('Nginx settings changed before commit')
        context.verify(journal["inventory"], journal["orphaned_domains"])
        _write_file(context.state / "current.json", _json_bytes(journal["next_current"]),
                    journal["state_snapshots"]["after"], journal["state_snapshots"]["before"])
        context.verify(journal["inventory"], journal["orphaned_domains"])
        journal["status"] = "deactivated" if operation == "deactivate" else "applied"
        journal["completed_at"] = _timestamp()
        _write_json(path, journal)
        return {"status": journal["status"], "release_id": release_id, "transaction_id": transaction_id}
    except BaseException as deployment_error:
        if isinstance(deployment_error, NginxWriteConflict):
            _mark_recovery(context, transaction_id, deployment_error)
            raise
        try:
            _restore(context, transaction_id)
        except BaseException as recovery_error:
            try:
                _mark_recovery(context, transaction_id, recovery_error)
            except (OSError, ValueError):
                pass
            raise NginxRecoveryRequired("Managed Nginx release requires recovery", deployment_error, recovery_error) from deployment_error
        raise


def apply_nginx_release(release_id, releases_root, vhost_root, http_conf_target, state_root,
                        adapter, transaction_id=None, acquire_lock=True, *, database_path, probe, expected_settings=None):
    _identifier(release_id)
    if transaction_id is not None:
        _identifier(transaction_id)
    if acquire_lock is not True:
        raise ValueError("Unlocked Nginx mutations are not allowed")
    context = _Context(vhost_root, http_conf_target, state_root, adapter, database_path, probe)
    with context.lock():
        _pending(context)
        bodies = _candidate(context, release_id, releases_root)
        settings = _candidate_settings(context, release_id)
        content, metadata = _read_file(context.state / 'current.json')
        current = json.loads(content) if content is not None else None
        context.validate_current(current)
        if current and current['status'] == 'active' and current['release_id'] == release_id:
            owned = {'http': current['http_conf'], **current['managed_snippets']}
            if set(owned) == set(bodies) and all(_read_file(context.target(key)) == (body, owned[key]) for key, body in bodies.items()):
                if all(_read_file(context.paths.data / name)[0] == body for name, body in settings.items()):
                    if context.probe(current) is not True:
                        raise NginxRecoveryRequired('Current Nginx release probe failed')
                    return {'status': 'unchanged', 'release_id': release_id, 'transaction_id': current['transaction_id']}
        return _execute(context, release_id, bodies, "apply", transaction_id, settings, expected_settings)


def restore_nginx_release_transaction(transaction_id, state_root, vhost_root, http_conf_target,
                                      adapter, *, database_path, probe):
    _identifier(transaction_id)
    context = _Context(vhost_root, http_conf_target, state_root, adapter, database_path, probe)
    with context.lock():
        _pending(context, allowed=transaction_id)
        try:
            return _restore(context, transaction_id)
        except (OSError, ValueError, RuntimeError) as error:
            journal = _journal(context, transaction_id)
            owns_current = _read_file(context.state / "current.json")[1] == journal.get("state_snapshots", {}).get("after")
            if journal["status"] not in TERMINAL_STATUSES or owns_current:
                _mark_recovery(context, transaction_id, error)
            raise


def rollback_nginx_release(releases_root, vhost_root, http_conf_target, state_root, adapter,
                           target_release_id=None, *, database_path, probe):
    context = _Context(vhost_root, http_conf_target, state_root, adapter, database_path, probe)
    with context.lock():
        _pending(context)
        current = _load_json(context.state / "current.json")
        context.validate_current(current)
        release_id = target_release_id or (current["release_id"] if current["status"] == "deactivated" else current.get("parent_release"))
        _identifier(release_id)
        return _execute(context, release_id, _candidate(context, release_id, releases_root), "rollback",
                        settings=_candidate_settings(context, release_id))


def deactivate_nginx_managed_release(vhost_root, http_conf_target, state_root, adapter, *, database_path, probe,
                                     http_content=b'# deactivated\n', settings=None, remove_http=False):
    context = _Context(vhost_root, http_conf_target, state_root, adapter, database_path, probe)
    with context.lock():
        _pending(context)
        content, _metadata = _read_file(context.state / "current.json")
        current = json.loads(content) if content is not None else None
        context.validate_current(current)
        if current is None:
            return {"status": "deactivated", "managed_files": 0, "transaction_id": None}
        if current["status"] == "deactivated":
            if _read_file(context.http)[1] != current["http_conf"]:
                raise ValueError("Deactivated Nginx placeholder changed")
            return {"status": "deactivated", "managed_files": 1, "transaction_id": current["transaction_id"]}
        return _execute(context, current["release_id"], {} if remove_http else {"http": http_content}, "deactivate", settings=settings)
