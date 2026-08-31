import ipaddress
import difflib
import hashlib
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from lib.audit_log import audited_mutation

METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
FORBIDDEN_PATHS = {"/", "/wp-json/", "/wp-json/wc/"}
DOMAIN_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
IDENTIFIER_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")

def validate_domain(domain):
    if not isinstance(domain, str) or not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("unsafe domain")

def validate_exact_path(path):
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path in FORBIDDEN_PATHS
        or path.endswith("/")
        or any(character in path for character in "*?#[\r\n\t ")
    ):
        raise ValueError("exception path must be exact")

def validate_exception(exception):
    if not isinstance(exception, dict):
        raise ValueError("exception must be an object")
    validate_domain(exception.get("domain"))
    paths = exception.get("paths")
    methods = exception.get("methods")
    prefixes = exception.get("source_prefixes")
    if not isinstance(paths, list) or not paths:
        raise ValueError("exception paths are required")
    for path in paths:
        validate_exact_path(path)
    if not isinstance(methods, list) or not methods or any(method not in METHODS for method in methods):
        raise ValueError("invalid exception methods")
    if not isinstance(prefixes, list) or not prefixes:
        raise ValueError("exception source prefixes are required")
    try:
        for prefix in prefixes:
            ipaddress.ip_network(prefix, strict=True)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid exception source prefix") from error

def validate_geoip_database(path):
    path = Path(path)
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ValueError("GeoIP database is not readable")
    return path.resolve()

def validate_generated_config(text):
    if not text.endswith("\n"):
        raise ValueError("generated config must end with newline")
    if "RewriteRule ^ - [F,L]" not in text:
        raise ValueError("generated config must end with deny rule")
    if "%{ENV:GEOIP_COUNTRY_CODE}" not in text:
        raise ValueError("generated config is missing GeoIP country condition")
    return True

def _sha256(content):
    return hashlib.sha256(content).hexdigest()

def _atomic_write(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

def _write_json(path, data):
    _atomic_write(
        path,
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(),
        0o600,
    )

def _load_manifest(root, identifier):
    if not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise ValueError("invalid identifier")
    with (Path(root).resolve() / identifier / "manifest.json").open(encoding="utf-8") as handle:
        return json.load(handle)

@audited_mutation("geoip.proposal.build", target_index=0)
def build_geoip_proposal(
    server_config_path,
    mmdb_path,
    proposals_root,
    proposal_id=None,
    created_at=None,
):
    server_config_path = Path(server_config_path).resolve()
    mmdb_path = validate_geoip_database(mmdb_path)
    source = server_config_path.read_bytes()
    source_text = source.decode("utf-8")
    if re.search(r"(?im)^\s*geoipdb\s+", source_text):
        raise ValueError("GeoIP database is already declared")
    proposal_id = proposal_id or secrets.token_hex(16)
    if not IDENTIFIER_PATTERN.fullmatch(proposal_id):
        raise ValueError("invalid proposal id")
    proposal_dir = Path(proposals_root).resolve() / proposal_id
    try:
        proposal_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError as error:
        raise ValueError("GeoIP proposal already exists") from error

    block = f"geoipdb {mmdb_path} {{\n  geoipDBName COUNTRY_DB\n}}\n"
    proposed_text = source_text.rstrip() + "\n\n" + block
    proposed = proposed_text.encode()
    manifest = {
        "schema_version": 1,
        "proposal_id": proposal_id,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "server_config_path": str(server_config_path),
        "mmdb_path": str(mmdb_path),
        "source_mode": server_config_path.stat().st_mode & 0o777,
        "source_sha256": _sha256(source),
        "proposed_sha256": _sha256(proposed),
    }
    try:
        _atomic_write(proposal_dir / "proposed.conf", proposed, 0o600)
        diff = "".join(
            difflib.unified_diff(
                source_text.splitlines(keepends=True),
                proposed_text.splitlines(keepends=True),
                fromfile=str(server_config_path),
                tofile=str(proposal_dir / "proposed.conf"),
            )
        ).encode()
        _atomic_write(proposal_dir / "proposal.diff", diff, 0o600)
        _write_json(proposal_dir / "manifest.json", manifest)
        return manifest
    except BaseException:
        import shutil
        shutil.rmtree(proposal_dir, ignore_errors=True)
        raise

@audited_mutation("geoip.proposal.apply", target_index=0)
def apply_geoip_proposal(
    proposal_id,
    proposals_root,
    server_config_path,
    transactions_root,
    config_test,
    transaction_id=None,
):
    proposal = _load_manifest(proposals_root, proposal_id)
    server_config_path = Path(server_config_path).resolve()
    if proposal["server_config_path"] != str(server_config_path):
        raise ValueError("GeoIP proposal target does not match")
    source = server_config_path.read_bytes()
    if _sha256(source) != proposal["source_sha256"]:
        raise RuntimeError("GeoIP source checksum changed")
    proposed = (Path(proposals_root).resolve() / proposal_id / "proposed.conf").read_bytes()
    if _sha256(proposed) != proposal["proposed_sha256"]:
        raise RuntimeError("GeoIP proposal checksum mismatch")

    transaction_id = transaction_id or secrets.token_hex(16)
    if not IDENTIFIER_PATTERN.fullmatch(transaction_id):
        raise ValueError("invalid transaction id")
    transaction_dir = Path(transactions_root).resolve() / transaction_id
    try:
        transaction_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError as error:
        raise ValueError("GeoIP transaction already exists") from error
    _atomic_write(transaction_dir / "backup.conf", source, 0o600)
    transaction = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "proposal_id": proposal_id,
        "server_config_path": str(server_config_path),
        "source_mode": proposal["source_mode"],
        "source_sha256": proposal["source_sha256"],
        "proposed_sha256": proposal["proposed_sha256"],
        "status": "applying",
    }
    _write_json(transaction_dir / "manifest.json", transaction)
    try:
        _atomic_write(server_config_path, proposed, proposal["source_mode"])
        if not getattr(config_test(), "valid", False):
            raise RuntimeError("OpenLiteSpeed config test failed")
    except BaseException:
        _atomic_write(server_config_path, source, proposal["source_mode"])
        transaction["status"] = "rolled_back"
        _write_json(transaction_dir / "manifest.json", transaction)
        raise
    transaction["status"] = "applied"
    _write_json(transaction_dir / "manifest.json", transaction)
    return transaction

@audited_mutation("geoip.proposal.restore", target_index=0)
def restore_geoip_transaction(transaction_id, transactions_root, server_config_path):
    transaction = _load_manifest(transactions_root, transaction_id)
    server_config_path = Path(server_config_path).resolve()
    if transaction["status"] != "applied" or transaction["server_config_path"] != str(server_config_path):
        raise ValueError("GeoIP transaction is not restorable")
    current = server_config_path.read_bytes()
    if _sha256(current) != transaction["proposed_sha256"]:
        raise RuntimeError("GeoIP current checksum changed")
    transaction_dir = Path(transactions_root).resolve() / transaction_id
    backup = (transaction_dir / "backup.conf").read_bytes()
    if _sha256(backup) != transaction["source_sha256"]:
        raise RuntimeError("GeoIP backup checksum mismatch")
    _atomic_write(server_config_path, backup, transaction["source_mode"])
    transaction["status"] = "restored"
    transaction["restored_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(transaction_dir / "manifest.json", transaction)
    return transaction
