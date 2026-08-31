import ipaddress
import re
from datetime import datetime, timezone

BING_SUFFIX = ".search.msn.com"
HOSTNAME_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)

def valid_bing_hostname(hostname):
    if not isinstance(hostname, str):
        return False
    normalized = hostname.rstrip(".").lower()
    return bool(HOSTNAME_PATTERN.fullmatch(normalized)) and normalized.endswith(BING_SUFFIX)

def forward_confirms(client_ip, resolved_addresses):
    try:
        expected = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for address in resolved_addresses:
        try:
            if ipaddress.ip_address(address) == expected:
                return True
        except ValueError:
            continue
    return False

def cache_entry_expired(expires_at, now=None):
    if not isinstance(expires_at, str):
        raise ValueError("expiry must be an ISO timestamp")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("invalid cache expiry") from error
    now = now or datetime.now(timezone.utc)
    if expiry.tzinfo is None or now.tzinfo is None:
        raise ValueError("cache timestamps must include timezone")
    return expiry <= now
