import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from lib.audit_log import audited_mutation

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{1,20}")
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_DATABASE_SIZE = 256 * 1024 * 1024
METADATA_MARKER = b"MaxMind.com"


def create_country_lookup(database_path):
    path = Path(database_path).resolve()
    if not path.is_file() or path.is_symlink():
        return None
    if importlib.util.find_spec("geoip2") and importlib.util.find_spec("maxminddb"):
        try:
            import geoip2.database  # type: ignore

            reader = geoip2.database.Reader(str(path))

            def _lookup(address):
                try:
                    response = reader.country(address)
                    return response.country.iso_code
                except Exception:
                    return None

            return _lookup
        except Exception:
            pass
    if importlib.util.find_spec("maxminddb"):
        try:
            import maxminddb  # type: ignore

            reader = maxminddb.open_database(str(path))

            def _lookup(address):
                try:
                    record = reader.get(address)
                    if isinstance(record, dict):
                        return record.get("country", {}).get("iso_code")
                except Exception:
                    return None
                return None

            return _lookup
        except Exception:
            pass
    return None


class MaxMindRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        if redirected and urlsplit(request.full_url).netloc != urlsplit(new_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


def _validate_credentials(account_id, license_key):
    account_id = str(account_id).strip()
    license_key = str(license_key).strip()
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ValueError("invalid MaxMind account ID")
    if not 8 <= len(license_key) <= 128 or any(character.isspace() for character in license_key):
        raise ValueError("invalid MaxMind license key")
    return account_id, license_key


def _atomic_write(path, content, mode):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("unsafe MaxMind storage path")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def save_credentials(path, account_id, license_key):
    account_id, license_key = _validate_credentials(account_id, license_key)
    content = json.dumps(
        {"schema_version": 1, "account_id": account_id, "license_key": license_key},
        sort_keys=True,
    ).encode() + b"\n"
    _atomic_write(path, content, 0o600)
    return {"configured": True, "account_id": account_id}


def _load_credentials(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError("MaxMind credentials are not configured safely")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported MaxMind credential schema")
    return _validate_credentials(data.get("account_id", ""), data.get("license_key", ""))


def get_credential_status(path):
    path = Path(path)
    if not path.is_file():
        return {"configured": False, "account_id": ""}
    account_id, _license_key = _load_credentials(path)
    return {"configured": True, "account_id": account_id}


def _read_limited(response, limit):
    chunks = []
    size = 0
    while True:
        chunk = response.read(1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise ValueError("MaxMind download is too large")
        chunks.append(chunk)


def _extract_database(archive_content):
    with tarfile.open(fileobj=__import__("io").BytesIO(archive_content), mode="r:gz") as archive:
        matches = [
            member for member in archive.getmembers()
            if member.isfile() and Path(member.name).name == "GeoLite2-Country.mmdb"
        ]
        if len(matches) != 1 or matches[0].size > MAX_DATABASE_SIZE:
            raise ValueError("invalid MaxMind archive")
        extracted = archive.extractfile(matches[0])
        if extracted is None:
            raise ValueError("MaxMind database is missing")
        content = extracted.read(MAX_DATABASE_SIZE + 1)
    if len(content) > MAX_DATABASE_SIZE or METADATA_MARKER not in content[-131072:]:
        raise ValueError("invalid MaxMind database")
    return content


def stage_country_database(credentials_path, staging_root, opener=None):
    account_id, license_key = _load_credentials(credentials_path)
    token = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
    request = Request(
        DOWNLOAD_URL,
        headers={"Authorization": f"Basic {token}", "User-Agent": "ols-geo-access/0.1.0"},
    )
    opener = opener or build_opener(MaxMindRedirectHandler()).open
    with opener(request, timeout=60) as response:
        archive_content = _read_limited(response, MAX_ARCHIVE_SIZE)
    database = _extract_database(archive_content)
    checksum = hashlib.sha256(database).hexdigest()
    staging_root = Path(staging_root)
    if staging_root.is_symlink():
        raise ValueError("unsafe MaxMind staging path")
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(staging_root, 0o700)
    candidate_path = staging_root / f"GeoLite2-Country-{secrets.token_hex(16)}.mmdb"
    _atomic_write(candidate_path, database, 0o600)
    return {
        "candidate_path": str(candidate_path),
        "sha256": checksum,
        "size": len(database),
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
    }

def _write_json(path, document):
    _atomic_write(
        path,
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(),
        0o600,
    )

class MaxMindRecoveryRequired(RuntimeError):
    pass

@audited_mutation("maxmind.database.install", target_index=1)
def install_country_database(
    candidate,
    destination,
    config_apply,
    config_restore,
    config_test,
    reload_ols,
    transactions_root,
    audit=None,
):
    if not isinstance(candidate, dict):
        raise ValueError("invalid MaxMind candidate")
    candidate_path = Path(candidate.get("candidate_path", ""))
    if not candidate_path.is_file() or candidate_path.is_symlink():
        raise ValueError("MaxMind candidate is unavailable")
    content = candidate_path.read_bytes()
    checksum = hashlib.sha256(content).hexdigest()
    if (
        checksum != candidate.get("sha256")
        or len(content) != candidate.get("size")
        or METADATA_MARKER not in content[-131072:]
    ):
        raise ValueError("MaxMind candidate checksum mismatch")

    destination = Path(destination)
    if destination.is_symlink() or destination.parent.is_symlink():
        raise ValueError("unsafe MaxMind destination")
    transactions_root = Path(transactions_root)
    if transactions_root.is_symlink():
        raise ValueError("unsafe MaxMind transaction path")
    transactions_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(transactions_root, 0o700)
    transaction_id = secrets.token_hex(16)
    transaction_dir = transactions_root / transaction_id
    transaction_dir.mkdir(mode=0o700)
    previous_exists = destination.is_file()
    previous = destination.read_bytes() if previous_exists else b""
    previous_mode = destination.stat().st_mode & 0o777 if previous_exists else 0o644
    if previous_exists:
        _atomic_write(transaction_dir / "backup.mmdb", previous, 0o600)
    transaction = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "status": "applying",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "destination": str(destination.resolve()),
        "previous_exists": previous_exists,
        "previous_sha256": hashlib.sha256(previous).hexdigest() if previous_exists else None,
        "previous_mode": previous_mode,
        "proposed_sha256": checksum,
        "proposed_size": len(content),
        "config_transaction": None,
    }
    _write_json(transaction_dir / "manifest.json", transaction)
    config_transaction = None
    stage = "replace_database"
    try:
        _atomic_write(destination, content, previous_mode)
        stage = "config_apply"
        config_transaction = config_apply()
        transaction["config_transaction"] = config_transaction
        _write_json(transaction_dir / "manifest.json", transaction)
        stage = "config_test"
        result = config_test()
        if not getattr(result, "valid", False):
            raise RuntimeError("OpenLiteSpeed config test failed")
        stage = "reload"
        reload_ols()
        transaction["status"] = "applied"
        transaction["applied_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(transaction_dir / "manifest.json", transaction)
        candidate_path.unlink()
        return {
            "updated": not previous_exists or hashlib.sha256(previous).hexdigest() != checksum,
            "sha256": checksum,
            "size": len(content),
            "downloaded_at": candidate.get("downloaded_at"),
            "transaction_id": transaction_id,
            "status": "applied",
            "config_transaction": config_transaction,
        }
    except BaseException as deployment_error:
        try:
            if previous_exists:
                backup = (transaction_dir / "backup.mmdb").read_bytes()
                if hashlib.sha256(backup).hexdigest() != transaction["previous_sha256"]:
                    raise RuntimeError("MaxMind backup checksum mismatch")
                _atomic_write(destination, backup, previous_mode)
            else:
                try:
                    destination.unlink()
                except FileNotFoundError:
                    pass
            if config_transaction is not None:
                config_restore(config_transaction)
            rollback_result = config_test()
            if not getattr(rollback_result, "valid", False):
                raise RuntimeError("OpenLiteSpeed config test failed during MaxMind rollback")
            reload_ols()
            transaction["status"] = "rolled_back"
            transaction["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            transaction["failed_stage"] = stage
            transaction["error_type"] = type(deployment_error).__name__
            transaction["error"] = str(deployment_error)[:2048]
            _write_json(transaction_dir / "manifest.json", transaction)
            candidate_path.unlink(missing_ok=True)
        except BaseException as recovery_error:
            transaction["status"] = "recovery_required"
            transaction["failed_stage"] = stage
            transaction["error_type"] = type(deployment_error).__name__
            transaction["error"] = str(deployment_error)[:2048]
            transaction["recovery_error_type"] = type(recovery_error).__name__
            transaction["recovery_error"] = str(recovery_error)[:2048]
            _write_json(transaction_dir / "manifest.json", transaction)
            error = MaxMindRecoveryRequired(
                "MaxMind update failed and rollback could not be reloaded"
            )
            error.maxmind_stage = stage
            error.rolled_back = False
            raise error from deployment_error
        deployment_error.maxmind_stage = stage
        deployment_error.rolled_back = True
        raise

def download_country_database(credentials_path, destination, opener=None):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".maxmind-stage-", dir=destination.parent) as directory:
        candidate = stage_country_database(credentials_path, directory, opener=opener)
        database = Path(candidate["candidate_path"]).read_bytes()
    old_checksum = hashlib.sha256(destination.read_bytes()).hexdigest() if destination.is_file() else None
    checksum = hashlib.sha256(database).hexdigest()
    if checksum != old_checksum:
        _atomic_write(destination, database, 0o644)
    return {
        "updated": checksum != old_checksum,
        "sha256": checksum,
        "size": len(database),
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
    }
