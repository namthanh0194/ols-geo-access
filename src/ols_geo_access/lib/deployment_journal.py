import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

from lib.baseline_repair import _atomic_write, sha256_bytes
from lib.transaction import deployment_lock

OPERATION_STATUSES = {
    "prepared",
    "state_written",
    "release_applying",
    "release_reloaded",
    "committed",
    "rolled_back",
    "recovery_required",
}
TERMINAL_OPERATION_STATUSES = {"committed", "rolled_back"}


class RecoveryRequired(RuntimeError):
    def __init__(self, message, deployment_error=None, recovery_error=None):
        super().__init__(message)
        self.deployment_error = deployment_error
        self.recovery_error = recovery_error


def _load_json(path):
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path, data):
    _atomic_write(
        Path(path),
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(),
    )


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _operation_dir(state_root, operation_id):
    if not isinstance(operation_id, str) or len(operation_id) != 32:
        raise ValueError("invalid operation id")
    try:
        int(operation_id, 16)
    except ValueError as error:
        raise ValueError("invalid operation id") from error
    return Path(state_root).resolve() / "operations" / operation_id


def _safe_target(plugin_root, relative_path):
    root = Path(plugin_root).resolve()
    relative = Path(relative_path)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("operation state path must be relative")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("operation state path must not contain symlinks")
    target = root / relative
    try:
        target.parent.resolve().relative_to(root)
    except ValueError as error:
        raise ValueError("operation state path is outside plugin root") from error
    if target.exists() and not target.is_file():
        raise ValueError("operation state target must be a regular file")
    return target, relative


def begin_operation(
    plugin_root,
    state_root,
    release_id,
    previous_release,
    state_changes,
    requires_reload=True,
):
    if not isinstance(state_changes, dict):
        raise ValueError("state changes must be a mapping")
    operation_id = secrets.token_hex(16)
    operation_dir = _operation_dir(state_root, operation_id)
    operation_dir.mkdir(parents=True, mode=0o700)
    os.chmod(operation_dir, 0o700)
    entries = []
    try:
        for relative_name in sorted(state_changes):
            proposed = state_changes[relative_name]
            if not isinstance(proposed, bytes):
                raise ValueError("proposed state content must be bytes")
            target, relative = _safe_target(plugin_root, relative_name)
            previous_exists = target.is_file()
            previous = target.read_bytes() if previous_exists else b""
            if previous_exists:
                _atomic_write(operation_dir / "previous" / relative, previous)
            _atomic_write(operation_dir / "proposed" / relative, proposed)
            entries.append(
                {
                    "relative_path": str(relative),
                    "previous_exists": previous_exists,
                    "previous_sha256": sha256_bytes(previous) if previous_exists else None,
                    "proposed_sha256": sha256_bytes(proposed),
                }
            )
        now = _timestamp()
        manifest = {
            "schema_version": 1,
            "operation_id": operation_id,
            "status": "prepared",
            "release_id": release_id,
            "previous_release": previous_release,
            "requires_reload": bool(requires_reload),
            "created_at": now,
            "updated_at": now,
            "state_changes": entries,
        }
        _write_json(operation_dir / "manifest.json", manifest)
        return manifest
    except BaseException:
        import shutil
        shutil.rmtree(operation_dir, ignore_errors=True)
        raise


def set_operation_status(operation_dir, status, **fields):
    if status not in OPERATION_STATUSES:
        raise ValueError("invalid operation status")
    operation_dir = Path(operation_dir).resolve()
    manifest_path = operation_dir / "manifest.json"
    manifest = _load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported operation schema")
    manifest["status"] = status
    manifest["updated_at"] = _timestamp()
    for key, value in fields.items():
        if key in {"error", "error_type"} and value is not None:
            value = str(value)[:2048]
        manifest[key] = value
    _write_json(manifest_path, manifest)
    return manifest


def incomplete_operations(state_root):
    root = Path(state_root).resolve() / "operations"
    if not root.is_dir():
        return []
    operations = []
    for path in sorted(root.iterdir()):
        if not path.is_dir():
            continue
        manifest_path = path / "manifest.json"
        if not manifest_path.is_file():
            raise RecoveryRequired("Operation journal is missing its manifest")
        manifest = _load_json(manifest_path)
        if manifest.get("status") not in OPERATION_STATUSES:
            raise RecoveryRequired("Operation journal has an invalid status")
        if manifest["status"] not in TERMINAL_OPERATION_STATUSES:
            operations.append(manifest)
    return sorted(operations, key=lambda item: (item.get("created_at", ""), item["operation_id"]))


def _file_state(path, previous_exists, previous_sha256, proposed_sha256):
    if path.is_file():
        checksum = sha256_bytes(path.read_bytes())
        if previous_exists and checksum == previous_sha256:
            return "previous"
        if checksum == proposed_sha256:
            return "proposed"
        return "external"
    if path.exists():
        return "external"
    return "previous" if not previous_exists else "external"


def _state_file_states(plugin_root, operation):
    states = []
    for item in operation["state_changes"]:
        target, _relative = _safe_target(plugin_root, item["relative_path"])
        states.append(
            _file_state(
                target,
                item["previous_exists"],
                item["previous_sha256"],
                item["proposed_sha256"],
            )
        )
    return states


def _target_states(transaction, transaction_dir, vhost_root):
    from lib.rollback import _managed_target

    states = []
    for item in transaction.get("backups", []):
        target = _managed_target(vhost_root, item["domain"])
        states.append(
            _file_state(
                target,
                item["existed"],
                item["sha256"],
                item.get("proposed_sha256"),
            )
        )
    return states


def _current_state(state_root, operation, transaction):
    current_path = Path(state_root).resolve() / "current.json"
    previous = transaction.get("previous_current") if transaction else None
    if not current_path.is_file():
        if current_path.exists():
            return "external"
        return "previous" if previous is None and operation.get("previous_release") is None else "external"
    try:
        current = _load_json(current_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return "external"
    if previous is not None and current == previous:
        return "previous"
    if (
        transaction is None
        and current.get("release_id") == operation.get("previous_release")
    ):
        return "previous"
    if (
        current.get("release_id") == operation.get("release_id")
        and current.get("deployment_id") == operation.get("operation_id")
    ):
        return "proposed"
    return "external"


def inspect_interrupted_release(plugin_root, state_root, releases_root, vhost_root):
    operations = incomplete_operations(state_root)
    if not operations:
        return {
            "blocking": False,
            "operation_id": None,
            "operation_status": None,
            "release_transaction_status": None,
            "safe_action": None,
            "reason": None,
        }
    if len(operations) != 1:
        return {
            "blocking": True,
            "operation_id": None,
            "operation_status": "multiple",
            "release_transaction_status": None,
            "safe_action": "manual",
            "reason": "Multiple interrupted deployments require manual review.",
        }
    operation = operations[0]
    operation_id = operation["operation_id"]
    transaction_dir = Path(state_root).resolve() / "transactions" / operation_id
    transaction_path = transaction_dir / "manifest.json"
    transaction = _load_json(transaction_path) if transaction_path.is_file() else None
    state_states = _state_file_states(plugin_root, operation)
    target_states = (
        _target_states(transaction, transaction_dir, vhost_root)
        if transaction is not None
        else []
    )
    current_state = _current_state(state_root, operation, transaction)
    if (
        "external" in state_states
        or "external" in target_states
        or current_state == "external"
    ):
        safe_action = "manual"
        reason = "Interrupted deployment contains externally modified files; manual review required."
    elif (
        transaction is not None
        and transaction.get("status") in {"reloaded", "applied"}
        and all(state == "proposed" for state in state_states)
        and all(state == "proposed" for state in target_states)
    ):
        safe_action = "finalize"
        reason = "Reload completed and proposed files match the journal."
    else:
        safe_action = "rollback"
        reason = "Deployment did not reach a committed reload and can be restored."
    return {
        "blocking": True,
        "operation_id": operation_id,
        "operation_status": operation["status"],
        "release_transaction_status": transaction.get("status") if transaction else None,
        "safe_action": safe_action,
        "reason": reason,
    }


def _restore_state_files(plugin_root, operation_dir, operation):
    for item in operation["state_changes"]:
        target, relative = _safe_target(plugin_root, item["relative_path"])
        state = _file_state(
            target,
            item["previous_exists"],
            item["previous_sha256"],
            item["proposed_sha256"],
        )
        if state == "external":
            raise RecoveryRequired(
                "Interrupted deployment contains externally modified files; manual review required"
            )
        if item["previous_exists"]:
            previous = (operation_dir / "previous" / relative).read_bytes()
            if sha256_bytes(previous) != item["previous_sha256"]:
                raise RecoveryRequired("Operation state backup checksum mismatch")
            _atomic_write(target, previous)
        else:
            try:
                target.unlink()
            except FileNotFoundError:
                pass


def _recover_interrupted_release(
    plugin_root,
    state_root,
    releases_root,
    vhost_root,
    config_test,
    reload_ols,
):
    report = inspect_interrupted_release(
        plugin_root, state_root, releases_root, vhost_root
    )
    if not report["blocking"]:
        return {"status": True, "result": "no_recovery_needed", "report": report}
    if report["safe_action"] == "manual":
        raise RecoveryRequired(report["reason"])
    operation_dir = _operation_dir(state_root, report["operation_id"])
    operation = _load_json(operation_dir / "manifest.json")
    try:
        if report["safe_action"] == "finalize":
            from lib.rollback import finalize_release_transaction

            finalize_release_transaction(
                operation["release_id"],
                releases_root,
                vhost_root,
                state_root,
                operation["operation_id"],
            )
            set_operation_status(operation_dir, "committed")
            return {
                "status": True,
                "result": "proposed_fully_committed",
                "operation_id": operation["operation_id"],
            }

        _restore_state_files(plugin_root, operation_dir, operation)
        transaction_path = (
            Path(state_root).resolve()
            / "transactions"
            / operation["operation_id"]
            / "manifest.json"
        )
        if transaction_path.is_file():
            transaction = _load_json(transaction_path)
            if transaction.get("status") != "rolled_back":
                from lib.rollback import restore_release_transaction

                restore_release_transaction(
                    operation["operation_id"],
                    state_root,
                    vhost_root,
                    config_test,
                    reload_ols,
                    acquire_lock=False,
                )
        elif operation.get("requires_reload", True):
            result = config_test()
            if not getattr(result, "valid", False):
                raise RuntimeError("OpenLiteSpeed config test failed during recovery")
            reload_ols()
        set_operation_status(operation_dir, "rolled_back")
        return {
            "status": True,
            "result": "previous_fully_restored",
            "operation_id": operation["operation_id"],
        }
    except BaseException as error:
        set_operation_status(
            operation_dir,
            "recovery_required",
            error_type=type(error).__name__,
            error=str(error),
        )
        if isinstance(error, RecoveryRequired):
            raise
        raise RecoveryRequired("Interrupted deployment recovery failed", recovery_error=error) from error


def recover_interrupted_release(
    plugin_root,
    state_root,
    releases_root,
    vhost_root,
    config_test,
    reload_ols,
    acquire_lock=True,
    audit=None,
):
    try:
        if acquire_lock:
            with deployment_lock(state_root):
                result = _recover_interrupted_release(
                    plugin_root,
                    state_root,
                    releases_root,
                    vhost_root,
                    config_test,
                    reload_ols,
                )
        else:
            result = _recover_interrupted_release(
                plugin_root,
                state_root,
                releases_root,
                vhost_root,
                config_test,
                reload_ols,
            )
    except BaseException as error:
        if audit is not None:
            audit.record_action(
                "release.recovery",
                {"result": "error", "error_type": type(error).__name__, "error": str(error)},
            )
        raise
    if audit is not None:
        audit.record_action("release.recovery", {"result": "success", "details": result})
    return result

def prune_operation_history(state_root, keep_completed=10):
    if not isinstance(keep_completed, int) or keep_completed < 0:
        raise ValueError("invalid operation retention count")
    state_root = Path(state_root).resolve()
    removed = []
    for directory_name, completed_statuses in (
        ("transactions", {"applied", "rolled_back"}),
        ("operations", {"committed", "rolled_back"}),
    ):
        root = state_root / directory_name
        completed = []
        if root.is_dir():
            for item in root.iterdir():
                manifest_path = item / "manifest.json"
                if not item.is_dir() or not manifest_path.is_file():
                    continue
                manifest = _load_json(manifest_path)
                if manifest.get("status") in completed_statuses:
                    completed.append(
                        (
                            manifest.get("updated_at")
                            or manifest.get("applied_at")
                            or manifest.get("rolled_back_at")
                            or manifest.get("created_at", ""),
                            item.name,
                            item,
                        )
                    )
        completed.sort(reverse=True)
        for _timestamp, item_id, item in completed[keep_completed:]:
            shutil.rmtree(item)
            removed.append(f"{directory_name}/{item_id}")
    return removed
