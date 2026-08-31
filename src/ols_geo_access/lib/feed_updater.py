import hashlib
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from lib.audit_log import audited_mutation

PROVIDER_SOURCES = {
    "bing": "https://www.bing.com/toolbox/bingbot.json",
    "applebot": "https://search.developer.apple.com/applebot.json",
    "duckduckbot": "https://duckduckgo.com/duckduckbot.json",
    "google": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "oai_searchbot": "https://openai.com/searchbot.json",
    "gptbot": "https://openai.com/gptbot.json",
    "chatgpt_user": "https://openai.com/chatgpt-user.json",
    "perplexity": "https://www.perplexity.com/perplexitybot.json",
    "uptimerobot": "https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt",
}

def enabled_feeds(config):
    names = []
    for section, key, provider in (
        ("bing", "bingbot", "bing"),
        ("apple", "applebot", "applebot"),
        ("duckduckgo", "duckduckbot", "duckduckbot"),
        ("google", "googlebot", "google"),
    ):
        if config.get(section, {}).get(key):
            names.append(provider)
    for name in ("oai_searchbot", "gptbot", "chatgpt_user"):
        if config.get("openai", {}).get(name):
            names.append(name)
    if config.get("perplexity", {}).get("perplexitybot"):
        names.append("perplexity")
    if config.get("uptimerobot", {}).get("monitoring", True):
        names.append("uptimerobot")
    return names

def _validate_source(provider, source):
    if PROVIDER_SOURCES.get(provider) != source:
        raise ValueError("source is not approved for provider")

def download_feed(provider, source, opener=urlopen, timeout=15, max_bytes=1024 * 1024):
    _validate_source(provider, source)
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("invalid maximum feed size")
    request = Request(
        source,
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
                raise RuntimeError("feed response is too large")
    return b"".join(chunks)

def normalize_feed(provider, source, payload, created_at=None):
    _validate_source(provider, source)
    if not isinstance(payload, bytes):
        raise ValueError("feed payload must be bytes")
    try:
        decoded = payload.decode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid feed JSON") from error
    if provider == "uptimerobot":
        document = {}
        items = []
        for value in decoded.splitlines():
            value = value.strip()
            if not value:
                continue
            address = ipaddress.ip_address(value)
            key = "ipv4Prefix" if address.version == 4 else "ipv6Prefix"
            bits = 32 if address.version == 4 else 128
            items.append({key: f"{address}/{bits}"})
    else:
        try:
            document = json.loads(decoded)
        except json.JSONDecodeError as error:
            raise ValueError("invalid feed JSON") from error
        items = document.get("prefixes") if isinstance(document, dict) else None
    if not isinstance(items, list) or not items:
        raise ValueError("feed prefixes must be a non-empty list")

    networks = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("invalid prefix entry")
        keys = [key for key in ("ipv4Prefix", "ipv6Prefix") if key in item]
        if len(keys) != 1 or not isinstance(item[keys[0]], str):
            raise ValueError("invalid prefix entry")
        try:
            network = ipaddress.ip_network(item[keys[0]], strict=True)
        except ValueError as error:
            raise ValueError("invalid network prefix") from error
        expected_version = 4 if keys[0] == "ipv4Prefix" else 6
        if network.version != expected_version:
            raise ValueError("prefix family does not match field")
        networks.add(network)

    ordered = sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))
    prefixes = [str(item) for item in ordered]
    canonical = ("\n".join(prefixes) + "\n").encode()
    return {
        "schema_version": 1,
        "provider": provider,
        "source": source,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "source_created_at": document.get("creationTime"),
        "prefixes": prefixes,
        "counts": {
            "total": len(prefixes),
            "ipv4": sum(item.version == 4 for item in ordered),
            "ipv6": sum(item.version == 6 for item in ordered),
        },
        "checksum": hashlib.sha256(canonical).hexdigest(),
    }

def _atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

@audited_mutation("feed.update", target_index=0)
def update_snapshot(
    provider,
    source,
    payload,
    snapshots_root,
    max_reduction=0.5,
    created_at=None,
):
    if not isinstance(max_reduction, (int, float)) or not 0 <= max_reduction <= 1:
        raise ValueError("invalid maximum reduction")
    snapshot = normalize_feed(provider, source, payload, created_at=created_at)
    target = Path(snapshots_root).resolve() / f"{provider}.json"
    if target.is_file():
        previous = json.loads(target.read_text(encoding="utf-8"))
        previous_count = previous.get("counts", {}).get("total", 0)
        current_count = snapshot["counts"]["total"]
        if previous_count and (previous_count - current_count) / previous_count > max_reduction:
            raise RuntimeError("feed prefix-count reduction exceeds configured limit")
    _atomic_json(target, snapshot)
    return snapshot
