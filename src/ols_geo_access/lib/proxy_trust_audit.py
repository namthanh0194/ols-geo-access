import ipaddress
import re
from dataclasses import dataclass

PROXY_HEADER_PATTERN = re.compile(
    r"^\s*useIpInProxyHeader\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE
)
ALLOW_PATTERN = re.compile(r"^\s*allow\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
DOMAIN_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

@dataclass(frozen=True)
class ProxyTrustResult:
    domain: str
    traffic_mode: str
    state: str
    blocking: bool
    trusted_only: bool
    ipv4_complete: bool
    ipv6_complete: bool
    configured_prefixes: tuple[str, ...]
    missing_prefixes: tuple[str, ...]
    remediation: tuple[str, ...]

def _prefixes(config_text):
    prefixes = set()
    for value in ALLOW_PATTERN.findall(config_text):
        for candidate in re.split(r"[\s,]+", value.strip()):
            try:
                prefixes.add(str(ipaddress.ip_network(candidate, strict=True)))
            except ValueError:
                continue
    return tuple(sorted(prefixes))

def _trusted_only(config_text):
    match = PROXY_HEADER_PATTERN.search(config_text)
    if not match:
        return None
    value = re.sub(r"[\s_-]+", " ", match.group(1).strip().lower())
    return value in {"2", "trusted ip only"}

def audit_proxy_trust(domain, traffic_mode, server_config_text, required_prefixes):
    if not isinstance(domain, str) or not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("unsafe domain")
    if not isinstance(server_config_text, str):
        raise ValueError("server config must be text")
    configured = _prefixes(server_config_text)
    required = tuple(dict.fromkeys(str(ipaddress.ip_network(item, strict=True)) for item in required_prefixes))
    missing = tuple(item for item in required if item not in configured)
    required_v4 = tuple(item for item in required if ipaddress.ip_network(item).version == 4)
    required_v6 = tuple(item for item in required if ipaddress.ip_network(item).version == 6)
    ipv4_complete = bool(required_v4) and not any(item in missing for item in required_v4)
    ipv6_complete = bool(required_v6) and not any(item in missing for item in required_v6)

    if traffic_mode in {"direct", "external_origin"}:
        return ProxyTrustResult(domain, traffic_mode, "not_required", False, False, ipv4_complete, ipv6_complete, configured, missing, ())
    if traffic_mode != "cloudflare":
        return ProxyTrustResult(domain, traffic_mode, "unknown_traffic_mode", True, False, ipv4_complete, ipv6_complete, configured, missing, ("Set traffic_mode to direct, cloudflare, or external_origin after verification.",))

    trusted_only = _trusted_only(server_config_text)
    if trusted_only is None:
        state = "proxy_header_mode_missing"
    elif not trusted_only:
        state = "proxy_header_trust_all"
    elif missing or not required_v4 or not required_v6:
        state = "trusted_prefixes_incomplete"
    else:
        state = "trusted"

    remediation = ()
    if state != "trusted":
        items = []
        if trusted_only is not True:
            items.append("Set useIpInProxyHeader to Trusted IP Only (2).")
        if missing:
            items.append("Add missing trusted proxy prefixes: " + ", ".join(missing))
        if not required_v4 or not required_v6:
            items.append("Provide validated Cloudflare IPv4 and IPv6 prefix lists.")
        remediation = tuple(items)
    return ProxyTrustResult(domain, traffic_mode, state, state != "trusted", trusted_only is True, ipv4_complete, ipv6_complete, configured, missing, remediation)
