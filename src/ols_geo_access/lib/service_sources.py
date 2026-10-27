import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from lib.feed_updater import FeedRefusal, validate_feed_network


HUBSPOT_SOURCE = "https://api.hubapi.com/meta/network-origins/2026-03/ip-ranges"
JETPACK_SOURCE = "https://jetpack.com/ips-v4.txt"
WORD_FENCE_SOURCE = "https://www.wordfence.com/help/advanced/"
WORD_FENCE_PREFIXES = (
    "44.235.211.232/32",
    "54.68.32.247/32",
    "54.71.203.174/32",
)
MANAGED_SERVICE_IDS = {"hubspot", "jetpack", "wordfence-central"}
ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def download_hubspot_feed(opener=urlopen, timeout=15, max_bytes=64 * 1024):
    request = Request(
        HUBSPOT_SOURCE,
        headers={"Accept": "application/json", "User-Agent": "ols-geo-access/0.1.0"},
        method="GET",
    )
    chunks = []
    total = 0
    with opener(request, timeout=timeout) as response:
        while True:
            chunk = response.read(min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError("HubSpot feed response is too large")
    return b"".join(chunks)


def normalize_hubspot_feed(payload, checked_at=None):
    if not isinstance(payload, bytes):
        raise ValueError("HubSpot feed payload must be bytes")
    try:
        decoded = payload.decode("utf-8")
        document = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FeedRefusal("invalid_format", "invalid HubSpot feed JSON") from error
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list) or not results:
        raise FeedRefusal("invalid_format", "HubSpot results must be a non-empty list")
    networks = set()
    for item in results:
        if not isinstance(item, dict):
            raise FeedRefusal("invalid_format", "invalid HubSpot item")
        if item.get("direction") != "EGRESS" or item.get("service") != "API":
            continue
        raw_prefix = item.get("cidr")
        if not isinstance(raw_prefix, str) or not raw_prefix.strip():
            raise FeedRefusal("invalid_format", "invalid HubSpot CIDR prefix")
        try:
            network = ipaddress.ip_network(raw_prefix.strip(), strict=False)
        except ValueError as error:
            raise FeedRefusal("invalid_format", "invalid HubSpot network prefix") from error
        validate_feed_network("hubspot", network)
        try:
            network = ipaddress.ip_network(raw_prefix.strip(), strict=True)
        except ValueError as error:
            raise FeedRefusal(
                "invalid_format", "HubSpot network prefix is not canonical"
            ) from error
        networks.add(network)
    if not networks:
        raise FeedRefusal("invalid_format", "HubSpot EGRESS API prefixes must be non-empty")
    ordered = sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))
    prefixes = [str(item) for item in ordered]
    canonical = ("\n".join(prefixes) + "\n").encode()
    return {
        "source": HUBSPOT_SOURCE,
        "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
        "prefixes": prefixes,
        "counts": {
            "total": len(prefixes),
            "ipv4": sum(item.version == 4 for item in ordered),
            "ipv6": sum(item.version == 6 for item in ordered),
        },
        "checksum": hashlib.sha256(canonical).hexdigest(),
    }


def _merge_service_entry(data, service_id, snapshot):
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError("invalid IP allowlist")
    entry = {
        "id": service_id,
        "domains": ["*"],
        "source_prefixes": list(snapshot["prefixes"]),
        "methods": list(ALL_METHODS),
        "paths": [],
    }
    entries = []
    changed = True
    replaced = False
    for current in data["entries"]:
        if current.get("id") == service_id:
            changed = current != entry
            entries.append(entry)
            replaced = True
        else:
            entries.append(current)
    if not replaced:
        entries.append(entry)
    updated = dict(data)
    updated["entries"] = entries
    return updated, changed


def merge_hubspot_allowlist(data, snapshot):
    return _merge_service_entry(data, "hubspot", snapshot)


def download_jetpack_feed(opener=urlopen, timeout=15, max_bytes=64 * 1024):
    request = Request(
        JETPACK_SOURCE,
        headers={"Accept": "text/plain", "User-Agent": "ols-geo-access/0.1.0"},
        method="GET",
    )
    chunks = []
    total = 0
    with opener(request, timeout=timeout) as response:
        while True:
            chunk = response.read(min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError("Jetpack feed response is too large")
    return b"".join(chunks)


def normalize_jetpack_feed(payload, checked_at=None):
    if not isinstance(payload, bytes):
        raise ValueError("Jetpack feed payload must be bytes")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FeedRefusal("invalid_format", "invalid Jetpack feed encoding") from error
    networks = set()
    for value in decoded.splitlines():
        value = value.strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise FeedRefusal("invalid_format", "invalid Jetpack network prefix") from error
        if network.version != 4:
            raise FeedRefusal(
                "invalid_format", "Jetpack IPv4 feed contains a non-IPv4 prefix"
            )
        validate_feed_network("jetpack", network)
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise FeedRefusal(
                "invalid_format", "Jetpack network prefix is not canonical"
            ) from error
        networks.add(network)
    if not networks:
        raise FeedRefusal("invalid_format", "Jetpack feed prefixes must be non-empty")
    ordered = sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen))
    prefixes = [str(item) for item in ordered]
    canonical = ("\n".join(prefixes) + "\n").encode()
    return {
        "source": JETPACK_SOURCE,
        "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
        "prefixes": prefixes,
        "counts": {"total": len(prefixes), "ipv4": len(prefixes), "ipv6": 0},
        "checksum": hashlib.sha256(canonical).hexdigest(),
    }


def merge_jetpack_allowlist(data, snapshot):
    return _merge_service_entry(data, "jetpack", snapshot)


def prepare_hubspot_allowlist(current_allowlist, payload, checked_at=None):
    snapshot = normalize_hubspot_feed(payload, checked_at=checked_at)
    updated_allowlist, changed = merge_hubspot_allowlist(current_allowlist, snapshot)
    return (
        updated_allowlist,
        {"id": "hubspot", "last_checked": snapshot["checked_at"], "checksum": snapshot["checksum"], "error": None},
        changed,
    )


def prepare_jetpack_allowlist(current_allowlist, payload, checked_at=None):
    snapshot = normalize_jetpack_feed(payload, checked_at=checked_at)
    updated_allowlist, changed = merge_jetpack_allowlist(current_allowlist, snapshot)
    return (
        updated_allowlist,
        {"id": "jetpack", "last_checked": snapshot["checked_at"], "checksum": snapshot["checksum"], "error": None},
        changed,
    )


def prepare_service_allowlist(current_allowlist, payloads, checked_at=None):
    preparers = {
        "hubspot": prepare_hubspot_allowlist,
        "jetpack": prepare_jetpack_allowlist,
    }
    updated = current_allowlist
    sources = {}
    any_changed = False
    for service_id, preparer in sorted(preparers.items()):
        if service_id not in payloads:
            continue
        payload = payloads[service_id]
        if payload is None:
            continue
        updated, source_meta, changed = preparer(
            updated, payload, checked_at=checked_at
        )
        sources[service_id] = source_meta
        any_changed = any_changed or changed
    return updated, sources, any_changed
def describe_service_sources(allowlist, state):
    entries = {entry.get("id"): entry for entry in allowlist.get("entries", [])}
    source_state = state.get("service_sources", {}) if isinstance(state, dict) else {}
    jetpack_state = source_state.get("jetpack", {})
    hubspot_state = source_state.get("hubspot", {})
    wordfence_state = source_state.get("wordfence-central", {})
    jetpack = entries.get("jetpack", {})
    hubspot = entries.get("hubspot", {})
    wordfence = entries.get("wordfence-central", {})
    return [
        {
            "id": "hubspot",
            "name": "HubSpot",
            "mode": "automatic",
            "source": HUBSPOT_SOURCE,
            "prefixes": hubspot.get("source_prefixes", []),
            "last_checked": hubspot_state.get("last_checked"),
            "last_updated": hubspot_state.get("last_updated"),
            "status": "error" if hubspot_state.get("error") else "ready" if hubspot_state.get("last_checked") else "pending",
            "error": hubspot_state.get("error"),
        },
        {
            "id": "jetpack",
            "name": "Jetpack",
            "mode": "automatic",
            "source": JETPACK_SOURCE,
            "prefixes": jetpack.get("source_prefixes", []),
            "last_checked": jetpack_state.get("last_checked"),
            "last_updated": jetpack_state.get("last_updated"),
            "status": "error" if jetpack_state.get("error") else "ready" if jetpack_state.get("last_checked") else "pending",
            "error": jetpack_state.get("error"),
        },
        {
            "id": "wordfence-central",
            "name": "Wordfence Central",
            "mode": "manual",
            "source": WORD_FENCE_SOURCE,
            "prefixes": wordfence.get("source_prefixes", list(WORD_FENCE_PREFIXES)),
            "last_checked": wordfence_state.get("last_reviewed"),
            "last_updated": wordfence_state.get("last_reviewed"),
            "status": "manual",
            "error": None,
        },
    ]
