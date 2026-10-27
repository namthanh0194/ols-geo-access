import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import re

from lib.proxy_trust_config import inspect_global_proxy_config

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
    snapshot_freshness: str = "unknown"
    snapshot_checked_at: str | None = None
    snapshot_blocking: bool = False


class ProxyTrustBlocking(RuntimeError):
    def __init__(self, reports):
        self.reports = tuple(reports)
        super().__init__("Cloudflare client-IP trust is not ready")


def _network_key(prefix):
    network = ipaddress.ip_network(prefix, strict=True)
    return network.version, int(network.network_address), network.prefixlen


def load_proxy_prefix_snapshot(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Cloudflare prefix snapshot is not a regular file")
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported Cloudflare prefix schema")
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources or any(
        not isinstance(source, str) or not source for source in sources
    ):
        raise ValueError("invalid Cloudflare prefix sources")
    checked_at = data.get("checked_at")
    try:
        checked = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("invalid Cloudflare prefix timestamp") from error
    if checked.tzinfo is None:
        raise ValueError("Cloudflare prefix timestamp must include timezone")
    values = data.get("prefixes")
    if not isinstance(values, list) or not values:
        raise ValueError("Cloudflare prefixes must be non-empty")
    try:
        networks = [ipaddress.ip_network(value, strict=True) for value in values]
    except (TypeError, ValueError) as error:
        raise ValueError("invalid Cloudflare prefix") from error
    if len(networks) != len(set(networks)):
        raise ValueError("duplicate Cloudflare prefix")
    if {network.version for network in networks} != {4, 6}:
        raise ValueError("Cloudflare prefix snapshot must include IPv4 and IPv6")
    normalized = tuple(str(network) for network in sorted(networks, key=_network_key))
    if tuple(values) != normalized:
        raise ValueError("Cloudflare prefixes must be normalized and sorted")
    return normalized

def audit_proxy_trust(
    domain,
    traffic_mode,
    server_config_text,
    required_prefixes,
    freshness=None,
):
    if not isinstance(domain, str) or not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("unsafe domain")
    if not isinstance(server_config_text, str):
        raise ValueError("server config must be text")
    inspection = inspect_global_proxy_config(server_config_text.encode())
    configured = inspection["configured_prefixes"]
    required = tuple(
        dict.fromkeys(
            str(ipaddress.ip_network(item, strict=True))
            for item in required_prefixes
        )
    )
    missing = tuple(item for item in required if item not in configured)
    required_v4 = tuple(
        item for item in required if ipaddress.ip_network(item).version == 4
    )
    required_v6 = tuple(
        item for item in required if ipaddress.ip_network(item).version == 6
    )
    ipv4_complete = bool(required_v4) and not any(
        item in missing for item in required_v4
    )
    ipv6_complete = bool(required_v6) and not any(
        item in missing for item in required_v6
    )
    freshness = freshness if isinstance(freshness, dict) else {}
    freshness_state = freshness.get("state", "unknown")
    freshness_checked_at = freshness.get("checked_at")
    freshness_blocking = bool(freshness.get("blocking", False))

    if traffic_mode in {"direct", "external_origin"}:
        return ProxyTrustResult(
            domain,
            traffic_mode,
            "not_required",
            False,
            False,
            ipv4_complete,
            ipv6_complete,
            configured,
            missing,
            (),
            freshness_state,
            freshness_checked_at,
            freshness_blocking,
        )
    if traffic_mode != "cloudflare":
        return ProxyTrustResult(
            domain,
            traffic_mode,
            "unknown_traffic_mode",
            True,
            False,
            ipv4_complete,
            ipv6_complete,
            configured,
            missing,
            ("Set traffic_mode to direct, cloudflare, or external_origin after verification.",),
            freshness_state,
            freshness_checked_at,
            freshness_blocking,
        )

    trusted_only = inspection["trusted_only"]
    if trusted_only is None:
        state = "proxy_header_mode_missing"
    elif not trusted_only:
        state = "proxy_header_trust_all"
    elif freshness_blocking:
        state = "proxy_prefix_snapshot_stale"
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
            items.append(
                "Add missing trusted proxy prefixes with the LiteSpeed T suffix: "
                + ", ".join(f"{prefix}T" for prefix in missing)
            )
        if not required_v4 or not required_v6:
            items.append("Provide validated Cloudflare IPv4 and IPv6 prefix lists.")
        if freshness_blocking:
            items.append(
                "Refresh the Cloudflare prefix snapshot from the approved live source."
            )
        remediation = tuple(items)
    return ProxyTrustResult(
        domain,
        traffic_mode,
        state,
        state != "trusted",
        trusted_only is True,
        ipv4_complete,
        ipv6_complete,
        configured,
        missing,
        remediation,
        freshness_state,
        freshness_checked_at,
        freshness_blocking,
    )


def assert_proxy_trust(
    assignments,
    server_config_text,
    required_prefixes,
    freshness=None,
):
    if not isinstance(assignments, dict):
        raise ValueError("domain assignments must be an object")
    reports = []
    for domain in sorted(assignments):
        assignment = assignments[domain]
        if not isinstance(assignment, dict):
            raise ValueError("domain assignment must be an object")
        if (
            not assignment.get("enabled")
            or assignment.get("group") == "NONE"
            or assignment.get("traffic_mode") != "cloudflare"
        ):
            continue
        report = audit_proxy_trust(
            domain,
            "cloudflare",
            server_config_text,
            required_prefixes,
            freshness=freshness,
        )
        if report.blocking:
            reports.append(report)
    if reports:
        raise ProxyTrustBlocking(reports)
    return ()
