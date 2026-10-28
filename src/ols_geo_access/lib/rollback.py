import json
import os
import re
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

from lib.baseline_repair import _atomic_write, sha256_bytes
from lib.audit_log import audited_mutation
from lib.config_generator import build_release
from lib.deployment_journal import RecoveryRequired
from lib.transaction import deployment_lock

IDENTIFIER_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")
MANAGED_NAME = "00-ols-geo-access.conf"

def _load_json(path):
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)

def _write_json(path, data):
    _atomic_write(
        Path(path),
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(),
    )

def _release_manifest(releases_root, release_id):
    if not IDENTIFIER_PATTERN.fullmatch(release_id):
        raise ValueError("invalid release id")
    manifest = _load_json(Path(releases_root).resolve() / release_id / "manifest.json")
    if manifest.get("release_id") != release_id:
        raise ValueError("release manifest id mismatch")
    return manifest

def _is_vhost_present(vhost_root, domain):
    root = Path(vhost_root).resolve()
    return (
        (root / "proxy" / domain).is_dir()
        or (root / f"{domain}.conf").is_file()
        or (root / "detail" / f"{domain}.conf").is_file()
    )


def _managed_target(vhost_root, domain):
    if not re.fullmatch(
        r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        domain,
    ):
        raise ValueError("unsafe managed domain")
    return Path(vhost_root).resolve() / "proxy" / domain / "urlrewrite" / MANAGED_NAME

def _validate_release_files(releases_root, release):
    release_dir = Path(releases_root).resolve() / release["release_id"]
    contents = {}
    for domain, metadata in release["generated_checksums"].items():
        expected = Path("domains") / domain / "urlrewrite" / MANAGED_NAME
        if metadata.get("relative_path") != str(expected):
            raise ValueError("release contains a non-owned path")
        content = (release_dir / expected).read_bytes()
        if sha256_bytes(content) != metadata.get("sha256"):
            raise RuntimeError("release file checksum mismatch")
        contents[domain] = content
    return contents

def _config_result(result):
    return {
        "valid": bool(getattr(result, "valid", False)),
        "exit_code": getattr(result, "exit_code", None),
        "errors": list(getattr(result, "errors", ())),
        "warnings": list(getattr(result, "warnings", ())),
    }

@audited_mutation("release.stage", target_index=2)
def build_staging(*args, parent_release=None, **kwargs):
    return build_release(*args, parent_release=parent_release, **kwargs)

@audited_mutation("release.apply", target_index=0)
def apply_release(
    release_id,
    releases_root,
    vhost_root,
    state_root,
    config_test,
    reload_ols,
    transaction_id=None,
    acquire_lock=True,
    audit=None,
):
    if acquire_lock:
        with deployment_lock(state_root):
            return _apply_release_unlocked(
                release_id,
                releases_root,
                vhost_root,
                state_root,
                config_test,
                reload_ols,
                transaction_id,
            )
    return _apply_release_unlocked(
        release_id,
        releases_root,
        vhost_root,
        state_root,
        config_test,
        reload_ols,
        transaction_id,
    )


def _managed_files(new_contents):
    return {
        domain: {
            "relative_path": str(Path("proxy") / domain / "urlrewrite" / MANAGED_NAME),
            "sha256": sha256_bytes(content),
        }
        for domain, content in sorted(new_contents.items())
    }


def _target_matches_known_state(target, backup):
    if target.is_file():
        checksum = sha256_bytes(target.read_bytes())
        if backup["existed"] and checksum == backup["sha256"]:
            return True
        return backup["proposed_exists"] and checksum == backup["proposed_sha256"]
    if target.exists():
        return False
    return not backup["existed"] or not backup["proposed_exists"]


def _restore_previous_current(state_root, transaction):
    current_path = Path(state_root).resolve() / "current.json"
    previous = transaction.get("previous_current")
    if previous is None:
        try:
            current_path.unlink()
        except FileNotFoundError:
            pass
    else:
        _write_json(current_path, previous)


def _restore_release_transaction_unlocked(
    transaction_id,
    state_root,
    vhost_root,
    config_test,
    reload_ols,
):
    transaction_dir = Path(state_root).resolve() / "transactions" / transaction_id
    transaction = _load_json(transaction_dir / "manifest.json")
    try:
        for backup in transaction["backups"]:
            target = _managed_target(vhost_root, backup["domain"])
            if not _target_matches_known_state(target, backup):
                raise RecoveryRequired(
                    f"managed integration checksum changed: {backup['domain']}"
                )
        for backup in transaction["backups"]:
            target = _managed_target(vhost_root, backup["domain"])
            if backup["existed"]:
                content = (
                    transaction_dir / "backup" / f"{backup['domain']}.conf"
                ).read_bytes()
                if sha256_bytes(content) != backup["sha256"]:
                    raise RecoveryRequired(
                        f"managed backup checksum changed: {backup['domain']}"
                    )
                _atomic_write(target, content, backup["mode"])
            else:
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
        result = config_test()
        result_data = _config_result(result)
        if not result_data["valid"]:
            raise RuntimeError("OpenLiteSpeed config test failed during rollback")
        reload_ols()
        _restore_previous_current(state_root, transaction)
        transaction["status"] = "rolled_back"
        transaction["rollback_config_test"] = result_data
        transaction["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
        transaction.pop("error", None)
        transaction.pop("error_type", None)
        _write_json(transaction_dir / "manifest.json", transaction)
        return transaction
    except BaseException as error:
        transaction["status"] = "recovery_required"
        transaction["error_type"] = type(error).__name__
        transaction["error"] = str(error)[:2048]
        _write_json(transaction_dir / "manifest.json", transaction)
        raise


def restore_release_transaction(
    transaction_id,
    state_root,
    vhost_root,
    config_test,
    reload_ols,
    acquire_lock=True,
):
    if acquire_lock:
        with deployment_lock(state_root):
            return _restore_release_transaction_unlocked(
                transaction_id,
                state_root,
                vhost_root,
                config_test,
                reload_ols,
            )
    return _restore_release_transaction_unlocked(
        transaction_id,
        state_root,
        vhost_root,
        config_test,
        reload_ols,
    )


@audited_mutation("release.deactivate", target_index=1)
def deactivate_managed_release(
    vhost_root,
    state_root,
    config_test,
    reload_ols,
    audit=None,
):
    vhost_root = Path(vhost_root).resolve()
    state_root = Path(state_root).resolve()
    plugin_root = state_root.parent.parent
    releases_root = plugin_root / "generated" / "releases"
    with deployment_lock(state_root):
        from lib.deployment_journal import recover_interrupted_release

        recover_interrupted_release(
            plugin_root,
            state_root,
            releases_root,
            vhost_root,
            config_test,
            reload_ols,
            acquire_lock=False,
            audit=audit,
        )
        current_path = state_root / "current.json"
        if not current_path.is_file():
            return {"status": "deactivated", "managed_files": 0, "transaction_id": None}
        current = _load_json(current_path)
        current_files = current.get("managed_files")
        if not isinstance(current_files, dict):
            raise ValueError("current release contains invalid managed files")
        if not current_files:
            return {"status": "deactivated", "managed_files": 0, "transaction_id": None}

        backups = []
        for domain, metadata in sorted(current_files.items()):
            if not isinstance(metadata, dict):
                raise ValueError(f"invalid managed integration metadata: {domain}")
            expected_relative = str(
                Path("proxy") / domain / "urlrewrite" / MANAGED_NAME
            )
            if metadata.get("relative_path") != expected_relative:
                raise ValueError(f"managed integration path changed: {domain}")
            target = _managed_target(vhost_root, domain)
            if not target.is_file():
                if not _is_vhost_present(vhost_root, domain):
                    continue
                raise RuntimeError(f"managed integration is missing: {domain}")
            content = target.read_bytes()
            if sha256_bytes(content) != metadata.get("sha256"):
                raise RuntimeError(f"managed integration checksum changed: {domain}")
            backups.append(
                {
                    "domain": domain,
                    "relative_path": expected_relative,
                    "existed": True,
                    "sha256": sha256_bytes(content),
                    "mode": target.stat().st_mode & 0o777,
                    "proposed_exists": False,
                    "proposed_sha256": None,
                }
            )

        transaction_id = secrets.token_hex(16)
        transaction_dir = state_root / "transactions" / transaction_id
        transaction_dir.mkdir(parents=True, mode=0o700)
        for backup in backups:
            content = _managed_target(vhost_root, backup["domain"]).read_bytes()
            _atomic_write(
                transaction_dir / "backup" / f"{backup['domain']}.conf",
                content,
                backup["mode"],
            )
        transaction = {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "release_id": current.get("release_id"),
            "parent_release": current.get("previous_release"),
            "previous_current": current,
            "status": "applying",
            "operation": "deactivate",
            "backups": backups,
        }
        _write_json(transaction_dir / "manifest.json", transaction)
        try:
            for backup in backups:
                _managed_target(vhost_root, backup["domain"]).unlink()
            result = config_test()
            result_data = _config_result(result)
            if not result_data["valid"]:
                raise RuntimeError("OpenLiteSpeed config test failed during deactivation")
            transaction["status"] = "config_validated"
            transaction["config_test"] = result_data
            _write_json(transaction_dir / "manifest.json", transaction)
            reload_ols()
            _write_json(
                current_path,
                {
                    "schema_version": 1,
                    "release_id": None,
                    "previous_release": None,
                    "managed_files": {},
                    "deployment_id": transaction_id,
                },
            )
            transaction["status"] = "applied"
            transaction["applied_at"] = datetime.now(timezone.utc).isoformat()
            _write_json(transaction_dir / "manifest.json", transaction)
            return {
                "status": "deactivated",
                "managed_files": len(backups),
                "transaction_id": transaction_id,
            }
        except BaseException as deactivation_error:
            try:
                _restore_release_transaction_unlocked(
                    transaction_id,
                    state_root,
                    vhost_root,
                    config_test,
                    reload_ols,
                )
            except BaseException as recovery_error:
                raise RecoveryRequired(
                    "Managed release deactivation failed and rollback could not be reloaded",
                    deployment_error=deactivation_error,
                    recovery_error=recovery_error,
                ) from deactivation_error
            raise


def finalize_release_transaction(
    release_id,
    releases_root,
    vhost_root,
    state_root,
    transaction_id,
):
    releases_root = Path(releases_root).resolve()
    vhost_root = Path(vhost_root).resolve()
    state_root = Path(state_root).resolve()
    release = _release_manifest(releases_root, release_id)
    new_contents = _validate_release_files(releases_root, release)
    transaction_dir = state_root / "transactions" / transaction_id
    transaction_path = transaction_dir / "manifest.json"
    transaction = _load_json(transaction_path)
    if transaction.get("release_id") != release_id:
        raise RecoveryRequired("release transaction id mismatch")
    if transaction.get("status") not in {"reloaded", "applied"}:
        raise RecoveryRequired("release transaction is not ready to finalize")
    for domain, content in new_contents.items():
        target = _managed_target(vhost_root, domain)
        if not target.is_file() or sha256_bytes(target.read_bytes()) != sha256_bytes(content):
            raise RecoveryRequired(f"managed integration checksum changed: {domain}")
    deployment = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "release_id": release_id,
        "parent_release": transaction.get("parent_release"),
        "applied_at": transaction.get("reloaded_at") or datetime.now(timezone.utc).isoformat(),
        "status": "applied",
        "domain_assignments": release["domain_assignments"],
        "feed_checksums": release["feed_checksums"],
        "generated_checksums": release["generated_checksums"],
        "config_test": transaction.get("config_test", {}),
    }
    _write_json(state_root / "deployments" / f"{transaction_id}.json", deployment)
    _write_json(
        state_root / "current.json",
        {
            "schema_version": 1,
            "release_id": release_id,
            "previous_release": transaction.get("parent_release"),
            "managed_files": _managed_files(new_contents),
            "deployment_id": transaction_id,
        },
    )
    transaction["status"] = "applied"
    transaction["applied_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(transaction_path, transaction)
    return deployment


def _apply_release_unlocked(
    release_id,
    releases_root,
    vhost_root,
    state_root,
    config_test,
    reload_ols,
    transaction_id,
):
    releases_root = Path(releases_root).resolve()
    vhost_root = Path(vhost_root).resolve()
    state_root = Path(state_root).resolve()
    release = _release_manifest(releases_root, release_id)
    new_contents = _validate_release_files(releases_root, release)
    transaction_id = transaction_id or secrets.token_hex(16)
    if not IDENTIFIER_PATTERN.fullmatch(transaction_id):
        raise ValueError("invalid transaction id")
    current_path = state_root / "current.json"
    current = _load_json(current_path) if current_path.is_file() else None
    current_files = current.get("managed_files", {}) if current else {}
    for domain, metadata in current_files.items():
        target = _managed_target(vhost_root, domain)
        if not target.is_file():
            if not _is_vhost_present(vhost_root, domain):
                continue
            raise RuntimeError(f"managed integration checksum changed: {domain}")
        if sha256_bytes(target.read_bytes()) != metadata["sha256"]:
            raise RuntimeError(f"managed integration checksum changed: {domain}")
    for domain in new_contents:
        target = _managed_target(vhost_root, domain)
        if domain not in current_files and target.exists():
            raise RuntimeError(f"ownership collision: {domain}")

    transaction_dir = state_root / "transactions" / transaction_id
    try:
        transaction_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError as error:
        raise ValueError("managed transaction already exists") from error
    domains = sorted(set(current_files) | set(new_contents))
    backups = []
    for domain in domains:
        target = _managed_target(vhost_root, domain)
        existed = target.is_file()
        content = target.read_bytes() if existed else b""
        if existed:
            _atomic_write(transaction_dir / "backup" / f"{domain}.conf", content)
        backups.append(
            {
                "domain": domain,
                "relative_path": str(
                    Path("proxy") / domain / "urlrewrite" / MANAGED_NAME
                ),
                "existed": existed,
                "sha256": sha256_bytes(content) if existed else None,
                "mode": target.stat().st_mode & 0o777 if existed else 0o600,
                "proposed_exists": domain in new_contents,
                "proposed_sha256": (
                    sha256_bytes(new_contents[domain]) if domain in new_contents else None
                ),
            }
        )
    transaction = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "release_id": release_id,
        "parent_release": current.get("release_id") if current else None,
        "previous_current": current,
        "status": "applying",
        "backups": backups,
    }
    _write_json(transaction_dir / "manifest.json", transaction)

    try:
        for domain in domains:
            target = _managed_target(vhost_root, domain)
            if domain in new_contents:
                _atomic_write(target, new_contents[domain])
            else:
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
        result = config_test()
        result_data = _config_result(result)
        if not result_data["valid"]:
            raise RuntimeError("OpenLiteSpeed config test failed")
        transaction["status"] = "config_validated"
        transaction["config_test"] = result_data
        _write_json(transaction_dir / "manifest.json", transaction)
        reload_ols()
        transaction["status"] = "reloaded"
        transaction["reloaded_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(transaction_dir / "manifest.json", transaction)
        return finalize_release_transaction(
            release_id,
            releases_root,
            vhost_root,
            state_root,
            transaction_id,
        )
    except BaseException as deployment_error:
        try:
            _restore_release_transaction_unlocked(
                transaction_id,
                state_root,
                vhost_root,
                config_test,
                reload_ols,
            )
        except BaseException as recovery_error:
            raise RecoveryRequired(
                "Managed release failed and rollback could not be reloaded",
                deployment_error=deployment_error,
                recovery_error=recovery_error,
            ) from deployment_error
        raise

@audited_mutation("release.rollback", target_index=2)
def rollback_release(
    releases_root,
    vhost_root,
    state_root,
    config_test,
    reload_ols,
    transaction_id=None,
    acquire_lock=True,
):
    current_path = Path(state_root).resolve() / "current.json"
    if not current_path.is_file():
        raise ValueError("no current release")
    current = _load_json(current_path)
    previous = current.get("previous_release")
    if not previous:
        raise ValueError("no previous release")
    return apply_release(
        previous,
        releases_root,
        vhost_root,
        state_root,
        config_test,
        reload_ols,
        transaction_id=transaction_id,
        acquire_lock=acquire_lock,
    )

def list_releases(releases_root, state_root):
    releases = []
    root = Path(releases_root).resolve()
    if root.is_dir():
        for path in root.iterdir():
            manifest = path / "manifest.json"
            if path.is_dir() and manifest.is_file():
                releases.append(_load_json(manifest))
    return sorted(releases, key=lambda item: (item.get("created_at", ""), item["release_id"]), reverse=True)

def prune_release_history(releases_root, state_root, keep_completed=10):
    if not isinstance(keep_completed, int) or keep_completed < 0:
        raise ValueError("invalid release retention count")
    releases_root = Path(releases_root).resolve()
    state_root = Path(state_root).resolve()
    protected = set()
    current_path = state_root / "current.json"
    if current_path.is_file():
        current = _load_json(current_path)
        protected.update(
            value
            for value in (current.get("release_id"), current.get("previous_release"))
            if isinstance(value, str) and value
        )
    operations_root = state_root / "operations"
    if operations_root.is_dir():
        for operation_dir in operations_root.iterdir():
            manifest_path = operation_dir / "manifest.json"
            if not manifest_path.is_file():
                continue
            operation = _load_json(manifest_path)
            if operation.get("status") not in {"committed", "rolled_back"}:
                protected.update(
                    value
                    for value in (
                        operation.get("release_id"),
                        operation.get("previous_release"),
                    )
                    if isinstance(value, str) and value
                )
    completed = []
    if releases_root.is_dir():
        for release_dir in releases_root.iterdir():
            manifest_path = release_dir / "manifest.json"
            if not release_dir.is_dir() or not manifest_path.is_file():
                continue
            manifest = _load_json(manifest_path)
            release_id = manifest.get("release_id")
            if release_id not in protected:
                completed.append(
                    (manifest.get("created_at", ""), str(release_id), release_dir)
                )
    completed.sort(reverse=True)
    removed = []
    for _created_at, release_id, release_dir in completed[keep_completed:]:
        shutil.rmtree(release_dir)
        removed.append(release_id)
    return removed
