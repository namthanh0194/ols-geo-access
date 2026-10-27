import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from lib.cloudflare_ranges import validate_cloudflare_snapshot
from lib.proxy_trust_config import plan_proxy_trust_config
from lib.transaction import deployment_lock


TERMINAL_STATUSES = {"committed", "rolled_back"}
VALID_STATUSES = {
    "prepared",
    "config_written",
    "state_written",
    "reloaded",
    "committed",
    "rolled_back",
    "recovery_required",
}
ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}")
TRANSACTION_ID = re.compile(r"[0-9a-f]{32}")
DEFAULT_STATE = {
    "schema_version": 1,
    "managed_prefixes": [],
    "last_checked_at": None,
    "last_success_at": None,
    "last_etag": None,
    "last_error_code": None,
    "last_transaction_id": None,
}


class ProxyTrustRecoveryRequired(RuntimeError):
    pass


def _sha256(content):
    return hashlib.sha256(content).hexdigest()


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _validate_timestamp(value):
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("invalid proxy trust timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("proxy trust timestamp requires timezone")


def _validate_state(document):
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("unsupported proxy trust state")
    prefixes = document.get("managed_prefixes")
    if not isinstance(prefixes, list) or any(
        not isinstance(prefix, str) or not prefix for prefix in prefixes
    ):
        raise ValueError("invalid managed proxy prefixes")
    from ipaddress import ip_network

    normalized = []
    for prefix in prefixes:
        try:
            network = ip_network(prefix, strict=True)
        except ValueError as error:
            raise ValueError("invalid managed proxy prefix") from error
        if prefix != str(network):
            raise ValueError("managed proxy prefix is not canonical")
        normalized.append(prefix)
    if len(normalized) != len(set(normalized)) or normalized != sorted(
        normalized,
        key=lambda value: (
            ip_network(value).version,
            int(ip_network(value).network_address),
            ip_network(value).prefixlen,
        ),
    ):
        raise ValueError("managed proxy prefixes must be unique and sorted")
    for key in ("last_checked_at", "last_success_at"):
        _validate_timestamp(document.get(key))
    etag = document.get("last_etag")
    if etag is not None and (not isinstance(etag, str) or not etag):
        raise ValueError("invalid proxy trust ETag")
    error_code = document.get("last_error_code")
    if error_code is not None and (
        not isinstance(error_code, str) or not ERROR_CODE.fullmatch(error_code)
    ):
        raise ValueError("invalid proxy trust error code")
    transaction_id = document.get("last_transaction_id")
    if transaction_id is not None and (
        not isinstance(transaction_id, str)
        or not TRANSACTION_ID.fullmatch(transaction_id)
    ):
        raise ValueError("invalid proxy trust transaction id")
    return {
        "schema_version": 1,
        "managed_prefixes": list(normalized),
        "last_checked_at": document.get("last_checked_at"),
        "last_success_at": document.get("last_success_at"),
        "last_etag": etag,
        "last_error_code": error_code,
        "last_transaction_id": transaction_id,
    }


def load_proxy_trust_state(path):
    path = Path(path)
    if not path.is_file():
        if path.exists():
            raise ValueError("proxy trust state must be a regular file")
        return dict(DEFAULT_STATE)
    if path.is_symlink():
        raise ValueError("proxy trust state must not be a symlink")
    with path.open(encoding="utf-8") as handle:
        return _validate_state(json.load(handle))


def _json_bytes(document):
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def _assert_safe_target(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"unsafe symlink target: {path}")
    current = path.parent
    while current != current.parent:
        if current.is_symlink():
            raise ValueError(f"unsafe symlink parent: {current}")
        current = current.parent
    if path.exists() and not path.is_file():
        raise ValueError(f"target must be a regular file: {path}")
    return path


def _resource(path):
    path = _assert_safe_target(path)
    if not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "sha256": None,
            "mode": 0o600,
            "uid": os.geteuid(),
            "gid": os.getegid(),
        }
    metadata = path.stat()
    return {
        "path": str(path),
        "exists": True,
        "sha256": _sha256(path.read_bytes()),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _proposed_resource(path, content, source):
    return {
        "path": str(path),
        "exists": True,
        "sha256": _sha256(content),
        "mode": source["mode"],
        "uid": source["uid"],
        "gid": source["gid"],
    }


def _fsync_directory(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path, content, metadata):
    path = _assert_safe_target(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, metadata["mode"])
        os.fchown(descriptor, metadata["uid"], metadata["gid"])
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _write_json(path, document, metadata=None):
    metadata = metadata or {
        "mode": 0o600,
        "uid": os.geteuid(),
        "gid": os.getegid(),
    }
    _atomic_write(path, _json_bytes(document), metadata)


def _paths(plugin_root):
    plugin_root = Path(plugin_root)
    if plugin_root.is_symlink():
        raise ValueError("plugin root must not be a symlink")
    data = plugin_root / "data"
    return {
        "plugin": plugin_root,
        "data": data,
        "snapshot": data / "cloudflare_prefixes.json",
        "state": data / "proxy_trust_state.json",
        "transactions": data / "proxy-trust-transactions",
        "release_state": data / "release-state",
    }


def _manifest_path(transactions, transaction_id):
    if not isinstance(transaction_id, str) or not TRANSACTION_ID.fullmatch(transaction_id):
        raise ValueError("invalid proxy trust transaction id")
    return Path(transactions) / transaction_id / "manifest.json"


def _load_manifest(path):
    with Path(path).open(encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("status") not in VALID_STATUSES:
        raise ValueError("invalid proxy trust transaction status")
    return document


def _set_status(transaction_dir, manifest, status, **fields):
    if status not in VALID_STATUSES:
        raise ValueError("invalid proxy trust transaction status")
    manifest.update(fields)
    manifest["status"] = status
    manifest["updated_at"] = _timestamp()
    _write_json(transaction_dir / "manifest.json", manifest)


def _capture_resources(server_config_path, paths):
    return {
        "server_config": _resource(server_config_path),
        "snapshot": _resource(paths["snapshot"]),
        "state": _resource(paths["state"]),
    }


def _backup_resources(transaction_dir, resources):
    backup = transaction_dir / "backup"
    backup.mkdir(parents=True, mode=0o700)
    for name, metadata in resources.items():
        if metadata["exists"]:
            content = Path(metadata["path"]).read_bytes()
            _atomic_write(backup / name, content, metadata)


def _current_resource_state(source, proposed):
    path = Path(source["path"])
    if not path.exists():
        return "source" if not source["exists"] else "external"
    if path.is_symlink() or not path.is_file():
        return "external"
    checksum = _sha256(path.read_bytes())
    if checksum == proposed["sha256"]:
        return "proposed"
    if source["exists"] and checksum == source["sha256"]:
        return "source"
    return "external"


def _incomplete_manifests(paths):
    transactions = paths["transactions"]
    if not transactions.is_dir():
        return []
    result = []
    for manifest_path in sorted(transactions.glob("*/manifest.json")):
        manifest = _load_manifest(manifest_path)
        if manifest["status"] not in TERMINAL_STATUSES:
            result.append((manifest_path.parent, manifest))
    return result


def inspect_proxy_trust_recovery(plugin_root, server_config_path):
    paths = _paths(plugin_root)
    incomplete = _incomplete_manifests(paths)
    if not incomplete:
        return {
            "blocking": False,
            "transaction_id": None,
            "status": None,
            "safe_action": None,
            "reason": None,
        }
    if len(incomplete) != 1:
        return {
            "blocking": True,
            "transaction_id": None,
            "status": "multiple",
            "safe_action": "manual",
            "reason": "Multiple proxy-trust transactions require manual review.",
        }
    _transaction_dir, manifest = incomplete[0]
    if manifest.get("server_config_path") != str(Path(server_config_path)):
        return {
            "blocking": True,
            "transaction_id": manifest.get("transaction_id"),
            "status": manifest.get("status"),
            "safe_action": "manual",
            "reason": "Proxy-trust transaction targets another server config.",
        }
    source = manifest.get("source")
    proposed = manifest.get("proposed")
    if not isinstance(source, dict) or not isinstance(proposed, dict):
        return {
            "blocking": True,
            "transaction_id": manifest.get("transaction_id"),
            "status": manifest.get("status"),
            "safe_action": "manual",
            "reason": "Proxy-trust transaction metadata is incomplete.",
        }
    states = {
        name: _current_resource_state(source[name], proposed[name])
        for name in ("server_config", "snapshot", "state")
        if name in source and name in proposed
    }
    if set(states) != {"server_config", "snapshot", "state"} or "external" in states.values():
        action = "manual"
        reason = "Proxy-trust resources contain external changes."
    elif manifest["status"] == "reloaded" and all(
        state == "proposed" for state in states.values()
    ):
        action = "finalize"
        reason = "Reloaded proxy-trust resources match the journal."
    else:
        action = "rollback"
        reason = "Proxy-trust transaction can restore its previous resources."
    return {
        "blocking": True,
        "transaction_id": manifest["transaction_id"],
        "status": manifest["status"],
        "safe_action": action,
        "reason": reason,
    }


def _restore_resources(transaction_dir, manifest):
    source = manifest["source"]
    proposed = manifest["proposed"]
    for name in ("server_config", "snapshot", "state"):
        if _current_resource_state(source[name], proposed[name]) == "external":
            raise ProxyTrustRecoveryRequired(
                f"proxy-trust resource changed externally: {name}"
            )
    for name in ("server_config", "snapshot", "state"):
        metadata = source[name]
        path = Path(metadata["path"])
        if metadata["exists"]:
            backup = (transaction_dir / "backup" / name).read_bytes()
            if _sha256(backup) != metadata["sha256"]:
                raise ProxyTrustRecoveryRequired(
                    f"proxy-trust backup checksum mismatch: {name}"
                )
            _atomic_write(path, backup, metadata)
        else:
            path.unlink(missing_ok=True)


def _require_valid_config(config_test):
    result = config_test()
    if not getattr(result, "valid", False):
        raise RuntimeError("OpenLiteSpeed configuration contains errors")
    return result


def _rollback(transaction_dir, manifest, config_test, reload_ols):
    try:
        _restore_resources(transaction_dir, manifest)
        _require_valid_config(config_test)
        if manifest.get("reload_attempted"):
            result = reload_ols()
            if getattr(result, "returncode", 0) != 0:
                raise RuntimeError("OpenLiteSpeed restored reload failed")
        _set_status(
            transaction_dir,
            manifest,
            "rolled_back",
            rolled_back_at=_timestamp(),
        )
    except BaseException as error:
        _set_status(
            transaction_dir,
            manifest,
            "recovery_required",
            recovery_error_type=type(error).__name__,
            recovery_error=str(error),
        )
        raise ProxyTrustRecoveryRequired(
            "proxy-trust rollback requires manual recovery"
        ) from error


def recover_proxy_trust_transaction(
    plugin_root,
    server_config_path,
    config_test,
    reload_ols,
    audit=None,
    acquire_lock=True,
):
    paths = _paths(plugin_root)

    def recover():
        report = inspect_proxy_trust_recovery(plugin_root, server_config_path)
        if not report["blocking"]:
            return {**report, "action": "none"}
        if report["safe_action"] == "manual":
            raise ProxyTrustRecoveryRequired(report["reason"])
        manifest_path = _manifest_path(paths["transactions"], report["transaction_id"])
        transaction_dir = manifest_path.parent
        manifest = _load_manifest(manifest_path)
        if report["safe_action"] == "finalize":
            _set_status(
                transaction_dir,
                manifest,
                "committed",
                committed_at=_timestamp(),
            )
            action = "finalized"
        else:
            _rollback(transaction_dir, manifest, config_test, reload_ols)
            action = "rolled_back"
        if audit:
            audit.record_action(
                "proxy_trust.recover",
                {
                    "result": "success",
                    "transaction_id": report["transaction_id"],
                    "action": action,
                },
            )
        return {**report, "blocking": False, "action": action}

    if acquire_lock:
        with deployment_lock(paths["release_state"]):
            return recover()
    return recover()


def _write_changed(path, content, source, proposed):
    current = path.read_bytes() if path.is_file() else None
    if current == content:
        return False
    _atomic_write(path, content, proposed)
    return True


def apply_proxy_trust_update(
    plugin_root,
    server_config_path,
    snapshot,
    config_test,
    reload_ols,
    audit=None,
    checked_live=False,
):
    snapshot = validate_cloudflare_snapshot(snapshot)
    paths = _paths(plugin_root)
    paths["data"].mkdir(parents=True, exist_ok=True, mode=0o700)
    paths["transactions"].mkdir(parents=True, exist_ok=True, mode=0o700)
    paths["release_state"].mkdir(parents=True, exist_ok=True, mode=0o700)
    server_config_path = _assert_safe_target(server_config_path)
    _assert_safe_target(paths["snapshot"])
    _assert_safe_target(paths["state"])
    if not server_config_path.is_file():
        raise ValueError("OpenLiteSpeed server configuration is unavailable")

    with deployment_lock(paths["release_state"]):
        recover_proxy_trust_transaction(
            plugin_root,
            server_config_path,
            config_test,
            reload_ols,
            audit=audit,
            acquire_lock=False,
        )
        state = load_proxy_trust_state(paths["state"])
        plan = plan_proxy_trust_config(
            server_config_path.read_bytes(),
            snapshot["prefixes"],
            state["managed_prefixes"],
        )
        proposed_state = {
            **state,
            "managed_prefixes": list(plan.managed_prefixes),
            "last_etag": snapshot["etag"],
        }
        if checked_live:
            proposed_state.update(
                {
                    "last_checked_at": snapshot["checked_at"],
                    "last_success_at": snapshot["checked_at"],
                    "last_error_code": None,
                }
            )
        proposed_state = _validate_state(proposed_state)
        snapshot_bytes = _json_bytes(snapshot)
        existing_snapshot = (
            paths["snapshot"].read_bytes() if paths["snapshot"].is_file() else None
        )
        existing_state = paths["state"].read_bytes() if paths["state"].is_file() else None
        provisional_state_bytes = _json_bytes(proposed_state)
        if (
            not plan.changed
            and existing_snapshot == snapshot_bytes
            and existing_state == provisional_state_bytes
        ):
            return {
                "status": "unchanged",
                "transaction_id": state["last_transaction_id"],
                "changed": False,
                "config_changed": False,
                "snapshot_changed": False,
                "state_changed": False,
                "reloaded": False,
            }

        transaction_id = secrets.token_hex(16)
        proposed_state["last_transaction_id"] = transaction_id
        proposed_state = _validate_state(proposed_state)
        state_bytes = _json_bytes(proposed_state)
        transaction_dir = paths["transactions"] / transaction_id
        transaction_dir.mkdir(mode=0o700)
        source = _capture_resources(server_config_path, paths)
        proposed = {
            "server_config": _proposed_resource(
                server_config_path, plan.proposed_bytes, source["server_config"]
            ),
            "snapshot": _proposed_resource(
                paths["snapshot"], snapshot_bytes, source["snapshot"]
            ),
            "state": _proposed_resource(paths["state"], state_bytes, source["state"]),
        }
        _backup_resources(transaction_dir, source)
        manifest = {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "status": "prepared",
            "created_at": _timestamp(),
            "updated_at": _timestamp(),
            "server_config_path": str(server_config_path),
            "source": source,
            "proposed": proposed,
            "etag": snapshot["etag"],
            "managed_prefixes": list(plan.managed_prefixes),
            "checked_live": bool(checked_live),
            "reload_required": plan.changed,
            "reload_attempted": False,
        }
        _write_json(transaction_dir / "manifest.json", manifest)
        try:
            config_changed = _write_changed(
                server_config_path,
                plan.proposed_bytes,
                source["server_config"],
                proposed["server_config"],
            )
            if config_changed:
                _set_status(transaction_dir, manifest, "config_written")
                _require_valid_config(config_test)
            snapshot_changed = _write_changed(
                paths["snapshot"],
                snapshot_bytes,
                source["snapshot"],
                proposed["snapshot"],
            )
            state_changed = _write_changed(
                paths["state"], state_bytes, source["state"], proposed["state"]
            )
            _set_status(transaction_dir, manifest, "state_written")
            reloaded = False
            if config_changed:
                manifest["reload_attempted"] = True
                _write_json(transaction_dir / "manifest.json", manifest)
                result = reload_ols()
                if getattr(result, "returncode", 0) != 0:
                    raise RuntimeError("OpenLiteSpeed graceful reload failed")
                reloaded = True
                _set_status(
                    transaction_dir,
                    manifest,
                    "reloaded",
                    reloaded_at=_timestamp(),
                )
                _require_valid_config(config_test)
            _set_status(
                transaction_dir,
                manifest,
                "committed",
                committed_at=_timestamp(),
            )
        except BaseException as error:
            try:
                _rollback(transaction_dir, manifest, config_test, reload_ols)
            except ProxyTrustRecoveryRequired as recovery_error:
                error.rolled_back = False
                error.recovery_required = True
                recovery_error.rolled_back = False
                recovery_error.recovery_required = True
                raise recovery_error from error
            error.rolled_back = True
            error.recovery_required = False
            if audit:
                audit.record_action(
                    "proxy_trust.update",
                    {
                        "result": "error",
                        "transaction_id": transaction_id,
                        "error_type": type(error).__name__,
                        "rolled_back": True,
                    },
                )
            raise
        prune_proxy_trust_history(plugin_root, keep_completed=5)
        if audit:
            audit.record_action(
                "proxy_trust.update",
                {
                    "result": "success",
                    "transaction_id": transaction_id,
                    "etag": snapshot["etag"],
                    "config_changed": config_changed,
                    "reloaded": reloaded,
                },
            )
        return {
            "status": "committed",
            "transaction_id": transaction_id,
            "changed": config_changed or snapshot_changed or state_changed,
            "config_changed": config_changed,
            "snapshot_changed": snapshot_changed,
            "state_changed": state_changed,
            "reloaded": reloaded,
        }


def record_proxy_trust_check_failure(
    plugin_root,
    server_config_path,
    code,
    checked_at,
    audit=None,
):
    if not isinstance(code, str) or not ERROR_CODE.fullmatch(code):
        raise ValueError("invalid proxy trust error code")
    _validate_timestamp(checked_at)
    paths = _paths(plugin_root)
    paths["data"].mkdir(parents=True, exist_ok=True, mode=0o700)
    paths["release_state"].mkdir(parents=True, exist_ok=True, mode=0o700)
    with deployment_lock(paths["release_state"]):
        recovery = inspect_proxy_trust_recovery(
            plugin_root,
            server_config_path,
        )
        if recovery["blocking"]:
            raise ProxyTrustRecoveryRequired(recovery["reason"])
        state = load_proxy_trust_state(paths["state"])
        state["last_checked_at"] = checked_at
        state["last_error_code"] = code
        state = _validate_state(state)
        metadata = _resource(paths["state"])
        _write_json(paths["state"], state, metadata)
    if audit:
        audit.record_action(
            "proxy_trust.check",
            {"result": "error", "code": code, "checked_at": checked_at},
        )
    return state


def prune_proxy_trust_history(plugin_root, keep_completed=5):
    if not isinstance(keep_completed, int) or keep_completed < 0:
        raise ValueError("invalid proxy trust retention count")
    transactions = _paths(plugin_root)["transactions"]
    if not transactions.is_dir():
        return []
    completed = []
    for manifest_path in transactions.glob("*/manifest.json"):
        manifest = _load_manifest(manifest_path)
        if manifest["status"] in TERMINAL_STATUSES:
            completed.append(
                (
                    manifest.get("committed_at")
                    or manifest.get("rolled_back_at")
                    or manifest.get("updated_at")
                    or manifest.get("created_at", ""),
                    manifest["transaction_id"],
                    manifest_path.parent,
                )
            )
    completed.sort(reverse=True)
    removed = []
    for _timestamp_value, transaction_id, path in completed[keep_completed:]:
        shutil.rmtree(path)
        removed.append(f"proxy-trust-transactions/{transaction_id}")
    return removed
