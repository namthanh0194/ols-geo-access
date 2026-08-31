import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from lib.baseline_repair import _atomic_write, sha256_bytes
from lib.audit_log import audited_mutation
from lib.config_generator import build_release
from lib.transaction import process_lock

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
    transaction_id=None,
):
    releases_root = Path(releases_root).resolve()
    vhost_root = Path(vhost_root).resolve()
    state_root = Path(state_root).resolve()
    release = _release_manifest(releases_root, release_id)
    new_contents = _validate_release_files(releases_root, release)
    transaction_id = transaction_id or secrets.token_hex(16)
    if not IDENTIFIER_PATTERN.fullmatch(transaction_id):
        raise ValueError("invalid transaction id")

    with process_lock(state_root / "apply.lock"):
        current_path = state_root / "current.json"
        current = _load_json(current_path) if current_path.is_file() else None
        current_files = current.get("managed_files", {}) if current else {}
        for domain, metadata in current_files.items():
            target = _managed_target(vhost_root, domain)
            if not target.is_file() or sha256_bytes(target.read_bytes()) != metadata["sha256"]:
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
                    "existed": existed,
                    "sha256": sha256_bytes(content) if existed else None,
                    "mode": target.stat().st_mode & 0o777 if existed else 0o600,
                }
            )
        transaction = {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "release_id": release_id,
            "parent_release": current.get("release_id") if current else None,
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
        except BaseException:
            for backup in backups:
                target = _managed_target(vhost_root, backup["domain"])
                if backup["existed"]:
                    content = (transaction_dir / "backup" / f"{backup['domain']}.conf").read_bytes()
                    _atomic_write(target, content, backup["mode"])
                else:
                    try:
                        target.unlink()
                    except FileNotFoundError:
                        pass
            transaction["status"] = "rolled_back"
            _write_json(transaction_dir / "manifest.json", transaction)
            raise

        managed_files = {
            domain: {
                "relative_path": str(Path("proxy") / domain / "urlrewrite" / MANAGED_NAME),
                "sha256": sha256_bytes(content),
            }
            for domain, content in sorted(new_contents.items())
        }
        deployment = {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "release_id": release_id,
            "parent_release": current.get("release_id") if current else None,
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "status": "applied",
            "domain_assignments": release["domain_assignments"],
            "feed_checksums": release["feed_checksums"],
            "generated_checksums": release["generated_checksums"],
            "config_test": result_data,
        }
        _write_json(state_root / "deployments" / f"{transaction_id}.json", deployment)
        _write_json(
            current_path,
            {
                "schema_version": 1,
                "release_id": release_id,
                "previous_release": current.get("release_id") if current else None,
                "managed_files": managed_files,
                "deployment_id": transaction_id,
            },
        )
        transaction["status"] = "applied"
        _write_json(transaction_dir / "manifest.json", transaction)
        return deployment

@audited_mutation("release.rollback", target_index=2)
def rollback_release(
    releases_root,
    vhost_root,
    state_root,
    config_test,
    transaction_id=None,
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
        transaction_id=transaction_id,
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
