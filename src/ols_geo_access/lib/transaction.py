import json
import fcntl
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from lib.baseline_repair import _atomic_write, sha256_bytes
from lib.audit_log import audited_mutation

IDENTIFIER_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")

class process_lock:
    def __init__(self, path):
        self._path = Path(path)
        self._handle = None

    def __enter__(self):
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._handle = self._path.open("a+")
        os.chmod(self._path, 0o600)
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._handle.close()
            self._handle = None
            raise RuntimeError("another managed transaction is active") from error
        return self

    def __exit__(self, *_args):
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None

def _load_manifest(root, identifier):
    if not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise ValueError("invalid identifier")
    path = Path(root).resolve() / identifier / "manifest.json"
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def _target(vhost_root, relative_path):
    root = Path(vhost_root).resolve()
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("transaction target is outside vhost root") from error
    return path

def _write_manifest(transaction_dir, manifest):
    _atomic_write(
        transaction_dir / "manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
    )

def _restore_files(transaction_dir, vhost_root, files, require_proposed_checksum):
    for item in files:
        target = _target(vhost_root, item["relative_path"])
        if require_proposed_checksum:
            current = target.read_bytes()
            if sha256_bytes(current) != item["proposed_sha256"]:
                raise RuntimeError(f"current checksum changed: {item['relative_path']}")
    for item in files:
        target = _target(vhost_root, item["relative_path"])
        backup = (transaction_dir / "backup" / item["relative_path"]).read_bytes()
        if sha256_bytes(backup) != item["source_sha256"]:
            raise RuntimeError(f"backup checksum mismatch: {item['relative_path']}")
        _atomic_write(target, backup, item["source_mode"])

@audited_mutation("baseline.repair.apply", target_index=0)
def apply_repair(
    proposal_id,
    proposals_root,
    vhost_root,
    transactions_root,
    config_test,
    transaction_id=None,
    created_at=None,
):
    proposal = _load_manifest(proposals_root, proposal_id)
    vhost_root = Path(vhost_root).resolve()
    if proposal.get("vhost_root") != str(vhost_root):
        raise ValueError("proposal vhost root does not match")
    proposal_dir = Path(proposals_root).resolve() / proposal_id

    prepared = []
    for item in proposal["files"]:
        target = _target(vhost_root, item["relative_path"])
        current = target.read_bytes()
        if sha256_bytes(current) != item["source_sha256"]:
            raise RuntimeError(f"source checksum changed: {item['relative_path']}")
        proposed = (proposal_dir / "files" / item["relative_path"]).read_bytes()
        if sha256_bytes(proposed) != item["proposed_sha256"]:
            raise RuntimeError(f"proposal checksum mismatch: {item['relative_path']}")
        prepared.append((item, target, current, proposed, target.stat().st_mode & 0o777))

    transaction_id = transaction_id or secrets.token_hex(16)
    if not IDENTIFIER_PATTERN.fullmatch(transaction_id):
        raise ValueError("invalid transaction id")
    transaction_dir = Path(transactions_root).resolve() / transaction_id
    try:
        transaction_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError as error:
        raise ValueError("transaction already exists") from error

    files = []
    for item, _target_path, current, _proposed, source_mode in prepared:
        _atomic_write(
            transaction_dir / "backup" / item["relative_path"], current, 0o600
        )
        files.append({**item, "source_mode": source_mode})
    manifest = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "proposal_id": proposal_id,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "status": "applying",
        "files": files,
    }
    _write_manifest(transaction_dir, manifest)

    try:
        for item, target, _current, proposed, source_mode in prepared:
            _atomic_write(target, proposed, source_mode)
        result = config_test()
        if not getattr(result, "valid", False):
            raise RuntimeError("OpenLiteSpeed config test failed")
    except BaseException:
        _restore_files(transaction_dir, vhost_root, files, False)
        manifest["status"] = "rolled_back"
        _write_manifest(transaction_dir, manifest)
        raise

    manifest["status"] = "applied"
    _write_manifest(transaction_dir, manifest)
    return manifest

@audited_mutation("baseline.repair.restore", target_index=0)
def restore_transaction(transaction_id, transactions_root, vhost_root):
    transaction_dir = Path(transactions_root).resolve() / transaction_id
    manifest = _load_manifest(transactions_root, transaction_id)
    if manifest.get("status") != "applied":
        raise ValueError("transaction is not applied")
    _restore_files(transaction_dir, vhost_root, manifest["files"], True)
    manifest["status"] = "restored"
    manifest["restored_at"] = datetime.now(timezone.utc).isoformat()
    _write_manifest(transaction_dir, manifest)
    return manifest
