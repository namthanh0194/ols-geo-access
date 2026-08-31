import base64
import hashlib
import json
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{1,20}")
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_DATABASE_SIZE = 256 * 1024 * 1024
METADATA_MARKER = b"MaxMind.com"


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


def download_country_database(credentials_path, destination, opener=None):
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
    destination = Path(destination)
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
