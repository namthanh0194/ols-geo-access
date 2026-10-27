import copy
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen


CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
MIN_PREFIX_LENGTH = {4: 8, 6: 24}
MIN_TOTAL_PREFIXES = 6
MAX_TOTAL_PREFIXES = 256
MAX_REDUCTION = 0.5
MAX_COVERAGE_GROWTH = 4


class CloudflareRangeRefusal(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _refuse(code, message):
    raise CloudflareRangeRefusal(code, message)


def _timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise CloudflareRangeRefusal(
            "cloudflare_invalid_format", "invalid Cloudflare timestamp"
        ) from error
    if parsed.tzinfo is None:
        _refuse("cloudflare_invalid_format", "Cloudflare timestamp requires timezone")
    return parsed


def _network_key(network):
    return network.version, int(network.network_address), network.prefixlen


def _parse_networks(ipv4_values, ipv6_values):
    if not isinstance(ipv4_values, list) or not isinstance(ipv6_values, list):
        _refuse("cloudflare_invalid_format", "Cloudflare CIDRs must be lists")
    if not ipv4_values or not ipv6_values:
        _refuse("cloudflare_invalid_format", "Cloudflare CIDRs require both families")
    values = ipv4_values + ipv6_values
    if not MIN_TOTAL_PREFIXES <= len(values) <= MAX_TOTAL_PREFIXES:
        _refuse("cloudflare_invalid_format", "Cloudflare CIDR count is outside policy")
    networks = []
    for expected_version, family_values in ((4, ipv4_values), (6, ipv6_values)):
        for raw in family_values:
            if not isinstance(raw, str) or not raw:
                _refuse("cloudflare_invalid_format", "Cloudflare CIDR must be text")
            try:
                network = ipaddress.ip_network(raw, strict=True)
            except ValueError as error:
                raise CloudflareRangeRefusal(
                    "cloudflare_invalid_format", "Cloudflare CIDR is invalid"
                ) from error
            if network.version != expected_version or raw != str(network):
                _refuse("cloudflare_invalid_format", "Cloudflare CIDR is not canonical")
            if network.prefixlen < MIN_PREFIX_LENGTH[network.version]:
                _refuse(
                    "cloudflare_prefix_too_broad",
                    f"Cloudflare CIDR is broader than policy: {network}",
                )
            if not network.is_global:
                _refuse("cloudflare_invalid_format", "Cloudflare CIDR is not global")
            networks.append(network)
    ordered = sorted(networks, key=_network_key)
    for index, network in enumerate(ordered):
        for previous in ordered[:index]:
            if previous.version == network.version and previous.overlaps(network):
                _refuse(
                    "cloudflare_prefix_overlap",
                    f"Cloudflare CIDRs overlap: {previous}, {network}",
                )
    return ordered


def _coverage(networks):
    result = {4: 0, 6: 0}
    for network in networks:
        result[network.version] += network.num_addresses
    return result


def _previous_networks(previous):
    if not previous:
        return []
    values = previous.get("prefixes") if isinstance(previous, dict) else None
    if not isinstance(values, list):
        _refuse("cloudflare_invalid_format", "previous Cloudflare snapshot is invalid")
    networks = []
    for raw in values:
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except (TypeError, ValueError) as error:
            raise CloudflareRangeRefusal(
                "cloudflare_invalid_format", "previous Cloudflare snapshot is invalid"
            ) from error
        networks.append(network)
    return networks


def _validate_transition(previous, candidate_networks):
    previous_networks = _previous_networks(previous)
    if not previous_networks:
        return
    reduction = (len(previous_networks) - len(candidate_networks)) / len(
        previous_networks
    )
    if reduction > MAX_REDUCTION:
        _refuse(
            "cloudflare_prefix_reduction_exceeded",
            "Cloudflare prefix reduction exceeds policy",
        )
    previous_coverage = _coverage(previous_networks)
    candidate_coverage = _coverage(candidate_networks)
    for version in (4, 6):
        if (
            previous_coverage[version]
            and candidate_coverage[version]
            > previous_coverage[version] * MAX_COVERAGE_GROWTH
        ):
            _refuse(
                "cloudflare_coverage_growth_exceeded",
                f"Cloudflare IPv{version} coverage growth exceeds policy",
            )


def download_cloudflare_ranges(
    opener=urlopen,
    timeout=15,
    max_bytes=256 * 1024,
):
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("invalid Cloudflare timeout")
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("invalid Cloudflare response limit")
    request = Request(
        CLOUDFLARE_IPS_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "ols-geo-access/0.1.0",
        },
        method="GET",
    )
    chunks = []
    total = 0
    with opener(request, timeout=timeout) as response:
        if response.geturl() != CLOUDFLARE_IPS_URL:
            _refuse("cloudflare_invalid_source", "Cloudflare source redirected")
        while True:
            chunk = response.read(min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                _refuse(
                    "cloudflare_response_too_large",
                    "Cloudflare response exceeds size limit",
                )
    return b"".join(chunks)


def prepare_cloudflare_snapshot(payload, previous=None, checked_at=None):
    try:
        document = json.loads(payload)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CloudflareRangeRefusal(
            "cloudflare_invalid_format", "Cloudflare response is not valid JSON"
        ) from error
    if not isinstance(document, dict) or document.get("success") is not True:
        _refuse("cloudflare_invalid_format", "Cloudflare response was unsuccessful")
    result = document.get("result")
    if not isinstance(result, dict):
        _refuse("cloudflare_invalid_format", "Cloudflare result is missing")
    etag = result.get("etag")
    if not isinstance(etag, str) or not etag:
        _refuse("cloudflare_invalid_format", "Cloudflare ETag is missing")
    networks = _parse_networks(
        result.get("ipv4_cidrs"), result.get("ipv6_cidrs")
    )
    _validate_transition(previous, networks)
    prefixes = [str(network) for network in networks]
    canonical = ("\n".join(prefixes) + "\n").encode()
    timestamp = checked_at or datetime.now(timezone.utc).isoformat()
    _timestamp(timestamp)
    return {
        "schema_version": 1,
        "sources": [CLOUDFLARE_IPS_URL],
        "checked_at": timestamp,
        "etag": etag,
        "prefixes": prefixes,
        "counts": {
            "total": len(prefixes),
            "ipv4": sum(network.version == 4 for network in networks),
            "ipv6": sum(network.version == 6 for network in networks),
        },
        "checksum": hashlib.sha256(canonical).hexdigest(),
    }


def validate_cloudflare_snapshot(document):
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        _refuse("cloudflare_invalid_format", "unsupported Cloudflare snapshot")
    if document.get("sources") != [CLOUDFLARE_IPS_URL]:
        _refuse("cloudflare_invalid_source", "unapproved Cloudflare snapshot source")
    checked_at = document.get("checked_at")
    _timestamp(checked_at)
    etag = document.get("etag")
    if not isinstance(etag, str) or not etag:
        _refuse("cloudflare_invalid_format", "Cloudflare snapshot ETag is missing")
    values = document.get("prefixes")
    if not isinstance(values, list):
        _refuse("cloudflare_invalid_format", "Cloudflare snapshot prefixes are missing")
    ipv4 = []
    ipv6 = []
    for value in values:
        try:
            version = ipaddress.ip_network(value, strict=True).version
        except (TypeError, ValueError) as error:
            raise CloudflareRangeRefusal(
                "cloudflare_invalid_format", "Cloudflare snapshot CIDR is invalid"
            ) from error
        (ipv4 if version == 4 else ipv6).append(value)
    networks = _parse_networks(ipv4, ipv6)
    normalized = [str(network) for network in networks]
    if values != normalized:
        _refuse("cloudflare_invalid_format", "Cloudflare snapshot is not sorted")
    counts = {
        "total": len(networks),
        "ipv4": len(ipv4),
        "ipv6": len(ipv6),
    }
    if document.get("counts") != counts:
        _refuse("cloudflare_invalid_format", "Cloudflare snapshot counts mismatch")
    checksum = hashlib.sha256(("\n".join(normalized) + "\n").encode()).hexdigest()
    if document.get("checksum") != checksum:
        _refuse("cloudflare_invalid_format", "Cloudflare snapshot checksum mismatch")
    return copy.deepcopy(document)


def select_install_fallback(runtime_snapshot, packaged_snapshot):
    candidates = []
    for document in (runtime_snapshot, packaged_snapshot):
        if document is None:
            continue
        try:
            validated = validate_cloudflare_snapshot(document)
        except CloudflareRangeRefusal:
            continue
        candidates.append((_timestamp(validated["checked_at"]), validated))
    if not candidates:
        _refuse("cloudflare_snapshot_missing", "no valid Cloudflare snapshot exists")
    candidates.sort(key=lambda item: item[0], reverse=True)
    return copy.deepcopy(candidates[0][1])


def snapshot_freshness(snapshot, now=None):
    checked_at = snapshot.get("checked_at") if isinstance(snapshot, dict) else None
    try:
        checked = _timestamp(checked_at)
    except CloudflareRangeRefusal:
        return {"state": "stale_blocking", "age_seconds": None, "blocking": True}
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("freshness clock requires timezone")
    age = int((current - checked).total_seconds())
    if age < 0:
        return {"state": "stale_blocking", "age_seconds": age, "blocking": True}
    if age < 24 * 60 * 60:
        state = "fresh"
    elif age <= 72 * 60 * 60:
        state = "warning"
    else:
        state = "stale_blocking"
    return {"state": state, "age_seconds": age, "blocking": state == "stale_blocking"}
