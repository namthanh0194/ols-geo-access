import ipaddress
import math
import re
from datetime import datetime, timezone
from pathlib import Path

from lib.service_sources import MANAGED_SERVICE_IDS


LOG_PATTERN = re.compile(
    r"^'?(?P<forwarded>\S+) (?P<remote>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) .* "(?P<user_agent>[^"]*)"\'?$'
)
USER_AGENT_HINTS = (
    "bingbot",
    "coccocbot",
    "applebot",
    "duckduckbot",
    "googlebot",
    "google-inspectiontool",
    "oai-searchbot",
    "chatgpt-user",
    "perplexitybot",
    "uptimerobot",
    "facebookexternalhit",
    "facebot",
    "meta-externalagent",
)
BOT_LABELS = {
    "anthropic": "Anthropic / Claude",
    "applebot": "Applebot",
    "bing": "Bingbot",
    "coccoc": "CocCocBot",
    "chatgpt_user": "ChatGPT-User",
    "duckduckbot": "DuckDuckBot",
    "google": "Googlebot",
    "meta": "Meta / Facebook",
    "oai_searchbot": "OAI-SearchBot",
    "perplexity": "PerplexityBot",
    "uptimerobot": "UptimeRobot",
}
SERVICE_LABELS = {
    "hubspot": "HubSpot",
    "jetpack": "Jetpack",
    "wordfence-central": "Wordfence Central",
}
TRAFFIC_SOURCE_TYPES = (
    "bot",
    "trusted_ip",
    "service",
    "vietnam",
    "foreign",
    "unknown",
)

class _ReverseLineReader:
    def __init__(self, path, block_size, max_bytes):
        self.path = Path(path)
        self.block_size = block_size
        self.max_bytes = max_bytes
        self.scanned_bytes = 0
        self.truncated = False

    def __iter__(self):
        size = self.path.stat().st_size
        position = size
        pending = b""
        with self.path.open("rb") as handle:
            while position > 0 and self.scanned_bytes < self.max_bytes:
                read_size = min(
                    self.block_size,
                    position,
                    self.max_bytes - self.scanned_bytes,
                )
                position -= read_size
                handle.seek(position)
                chunk = handle.read(read_size)
                self.scanned_bytes += len(chunk)
                parts = (chunk + pending).split(b"\n")
                pending = parts[0]
                for line in reversed(parts[1:]):
                    yield line.decode("utf-8", errors="replace")
        if position == 0:
            if pending:
                yield pending.decode("utf-8", errors="replace")
        else:
            self.truncated = True

def _iter_lines_reverse(path, block_size=65536, max_bytes=64 * 1024 * 1024):
    if not isinstance(block_size, int) or block_size < 1:
        raise ValueError("invalid reverse-line block size")
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("invalid reverse-line byte limit")
    return _ReverseLineReader(path, block_size, max_bytes)


def _networks(snapshots):
    result = []
    for provider, snapshot in sorted(snapshots.items()):
        for prefix in snapshot.get("prefixes", ()):
            result.append((provider, ipaddress.ip_network(prefix, strict=True)))
    return tuple(result)


def _provider_for(address, networks):
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return None
    for provider, network in networks:
        if value in network:
            return provider
    return None


def _allowlist_networks(allowlist):
    result = []
    entries = allowlist.get("entries", ()) if isinstance(allowlist, dict) else ()
    for entry in sorted(entries, key=lambda item: item.get("id", "")):
        source_id = entry.get("id")
        if not isinstance(source_id, str) or not source_id:
            continue
        for prefix in entry.get("source_prefixes", ()):
            result.append((entry, ipaddress.ip_network(prefix, strict=True)))
    return tuple(result)


def _allowlist_source_for(address, domain, method, path, networks):
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return None, False
    matches = []
    for entry, network in networks:
        if value not in network:
            continue
        domains = entry.get("domains", ())
        methods = entry.get("methods", ())
        paths = entry.get("paths", ())
        applies = (
            ("*" in domains or domain in domains)
            and method in methods
            and (not paths or path in paths)
        )
        matches.append((not applies, entry.get("id", ""), entry, applies))
    if not matches:
        return None, False
    _not_applies, _source_id, entry, applies = sorted(matches)[0]
    return entry, applies


def _country_code(address, country_lookup):
    if country_lookup is None:
        return None
    try:
        code = country_lookup(address)
    except Exception:
        return None
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z]{2}", code):
        return None
    return code.upper()


def _outcome(status):
    if 200 <= status < 400:
        return "allowed"
    if status == 403:
        return "blocked"
    return "other"


def _source_label(source_type, source_id):
    if source_type == "bot":
        return BOT_LABELS.get(source_id, source_id)
    if source_type == "service":
        return SERVICE_LABELS.get(source_id, source_id)
    if source_type == "trusted_ip":
        return f"IP tin cậy: {source_id}"
    if source_type == "vietnam":
        return "Việt Nam"
    if source_type == "foreign":
        return "Quốc tế"
    return "Không xác định"


def _classify_traffic_event(event, bot_networks, allowlist_networks, country_lookup):
    provider = _provider_for(event["ip"], bot_networks)
    allowlist_entry, allowlist_applies = _allowlist_source_for(
        event["ip"], event["domain"], event["method"], event["path"],
        allowlist_networks,
    )
    country_code = _country_code(event["ip"], country_lookup)
    country_scope = (
        "vietnam" if country_code == "VN"
        else "foreign" if country_code
        else "unknown"
    )
    if provider:
        source_type = "bot"
        source_id = provider
        bypass_applies = event["method"] in {"GET", "HEAD"}
    elif allowlist_entry:
        source_id = allowlist_entry["id"]
        source_type = "service" if source_id in MANAGED_SERVICE_IDS else "trusted_ip"
        bypass_applies = allowlist_applies
    elif country_scope == "vietnam":
        source_type = "vietnam"
        source_id = "geo-vn"
        bypass_applies = False
    elif country_scope == "foreign":
        source_type = "foreign"
        source_id = "geo-foreign"
        bypass_applies = False
    else:
        source_type = "unknown"
        source_id = "geo-unknown"
        bypass_applies = False

    if bypass_applies:
        expected_outcome = "allowed"
        reason = source_id
    elif country_scope == "vietnam":
        expected_outcome = "allowed"
        reason = "geo_vn"
    elif country_scope == "foreign":
        expected_outcome = "blocked"
        reason = "geo_foreign"
    else:
        expected_outcome = None
        reason = "geo_unknown"

    outcome = event["outcome"]
    if outcome == "other" or expected_outcome is None:
        decision = "other"
    elif outcome == expected_outcome:
        decision = "expected"
    elif outcome == "allowed":
        decision = "unexpected_allow"
    else:
        decision = "unexpected_block"

    event.update({
        "provider": provider,
        "source_type": source_type,
        "source_id": source_id,
        "source_label": _source_label(source_type, source_id),
        "country_code": country_code,
        "country_scope": country_scope,
        "bypass_applies": bypass_applies,
        "decision": decision,
        "reason": reason,
    })
    return event


def _traffic_summary(events):
    summary = {
        "total": len(events),
        "allowed": 0,
        "blocked": 0,
        "other": 0,
        "vietnam_allowed": 0,
        "vietnam_blocked": 0,
        "foreign_allowed": 0,
        "foreign_blocked": 0,
        "bypass_allowed": 0,
        "bypass_blocked": 0,
        "unexpected_allow": 0,
        "unexpected_block": 0,
    }
    for event in events:
        outcome = event["outcome"]
        summary[outcome] += 1
        if event["source_type"] == "vietnam" and outcome in {"allowed", "blocked"}:
            summary[f"vietnam_{outcome}"] += 1
        if event["source_type"] == "foreign" and outcome in {"allowed", "blocked"}:
            summary[f"foreign_{outcome}"] += 1
        if event["bypass_applies"] and outcome in {"allowed", "blocked"}:
            summary[f"bypass_{outcome}"] += 1
        if event["decision"] in {"unexpected_allow", "unexpected_block"}:
            summary[event["decision"]] += 1
    return summary


def _matches_filters(event, filters):
    if not filters:
        return True
    return all(
        not value or (
            event["source_type"] == value if key == "source"
            else event["country_scope"] == value if key == "country"
            else event.get(key) == value
        )
        for key, value in filters.items()
    )

def summarize_provider_status(providers, snapshots, events, max_age_hours, now=None):
    if not isinstance(max_age_hours, (int, float)) or max_age_hours < 1:
        raise ValueError("invalid feed maximum age")
    now = now or datetime.now().astimezone()
    if now.tzinfo is None:
        raise ValueError("provider status time must include timezone")
    latest = {}
    for event in events:
        provider = event.get("provider")
        if provider and provider not in latest:
            latest[provider] = {
                key: event[key]
                for key in ("timestamp", "domain", "status", "outcome")
                if key in event
            }
    result = []
    for provider in sorted(set(providers)):
        snapshot = snapshots.get(provider)
        item = {
            "provider": provider,
            "feed_status": "missing",
            "source": None,
            "created_at": None,
            "source_created_at": None,
            "counts": {"total": 0, "ipv4": 0, "ipv6": 0},
            "last_activity": latest.get(provider),
        }
        if snapshot is not None:
            item["source"] = snapshot.get("source")
            item["created_at"] = snapshot.get("created_at")
            item["source_created_at"] = snapshot.get("source_created_at")
            counts = snapshot.get("counts")
            try:
                created_at = datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
                if created_at.tzinfo is None or not isinstance(counts, dict):
                    raise ValueError
                parsed_counts = {
                    key: counts[key] for key in ("total", "ipv4", "ipv6")
                }
                if not all(isinstance(value, int) and value >= 0 for value in parsed_counts.values()):
                    raise ValueError
                item["counts"] = parsed_counts
                age_hours = (now.astimezone(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds() / 3600
                item["feed_status"] = "stale" if age_hours > max_age_hours else "ready"
            except (AttributeError, KeyError, TypeError, ValueError):
                item["feed_status"] = "invalid"
        result.append(item)
    return result

def classify_blocked_events(events, snapshots, manifest, deployment, intentional_index_blocks=()):
    result = []
    classification = {"needs_attention": 0, "expected": 0, "historical": 0}
    for source in events:
        event = dict(source)
        if event.get("status") != 403:
            result.append(event)
            continue
        if event.get("method") not in {"GET", "HEAD"}:
            event.update({
                "block_source": "plugin_policy",
                "block_reason": "Bot đã xác minh nhưng phương thức này không được bypass",
            })
            classification["expected"] += 1
            result.append(event)
            continue
        try:
            timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            release_time = datetime.fromisoformat(manifest["created_at"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None or release_time.tzinfo is None:
                raise ValueError
        except (AttributeError, KeyError, TypeError, ValueError):
            event.update({
                "block_source": "unknown",
                "block_reason": "Thiếu dữ liệu release để xác định nguồn 403",
            })
            classification["needs_attention"] += 1
            result.append(event)
            continue
        if timestamp < release_time:
            event.update({
                "block_source": "historical",
                "block_reason": "Request xảy ra trước lần áp dụng feed hiện tại",
            })
            classification["historical"] += 1
            result.append(event)
            continue
        provider = event.get("provider")
        domain = event.get("domain")
        snapshot_checksum = snapshots.get(provider, {}).get("checksum")
        manifest_checksum = manifest.get("feed_checksums", {}).get(provider)
        generated_checksum = manifest.get("generated_checksums", {}).get(domain, {}).get("sha256")
        managed_checksum = (deployment or {}).get("managed_files", {}).get(domain, {}).get("sha256")
        release_matches = (deployment or {}).get("release_id") == manifest.get("release_id")
        if (
            not snapshot_checksum
            or snapshot_checksum != manifest_checksum
            or not generated_checksum
            or generated_checksum != managed_checksum
            or not release_matches
        ):
            event.update({
                "block_source": "rule_error",
                "block_reason": "Checksum feed hoặc file rule đang áp dụng không khớp release",
            })
        elif domain in intentional_index_blocks:
            event.update({
                "block_source": "intentional_index_block",
                "block_reason": "Website được đánh dấu chủ ý không cho bot index",
            })
            classification["expected"] += 1
            result.append(event)
            continue
        else:
            event.update({
                "block_source": "downstream",
                "block_reason": "Request đã bypass Geo Access; website hoặc WAF trả 403",
            })
        classification["needs_attention"] += 1
        result.append(event)
    return {"events": result, "classification": classification}


def collect_bot_activity(
    domains,
    snapshots,
    logs_root,
    since,
    limit=200,
    max_scan_bytes=64 * 1024 * 1024,
):
    activity = collect_traffic_activity(
        domains=domains,
        snapshots=snapshots,
        allowlist={"entries": []},
        logs_root=logs_root,
        since=since,
        country_lookup=None,
        filters={"source": "bot"},
        limit=limit,
        max_scan_bytes=max_scan_bytes,
    )
    activity["summary"] = {
        key: activity["summary"][key]
        for key in ("allowed", "blocked", "other")
    }
    return activity


def collect_traffic_activity(
    domains,
    snapshots,
    allowlist,
    logs_root,
    since,
    country_lookup=None,
    filters=None,
    limit=500,
    max_scan_bytes=64 * 1024 * 1024,
):
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("invalid activity limit")
    if not isinstance(max_scan_bytes, int) or max_scan_bytes < 1:
        raise ValueError("invalid activity byte limit")
    if not isinstance(since, datetime) or since.tzinfo is None:
        raise ValueError("activity since must include timezone")
    domain_names = sorted(set(domains))
    if any(
        not isinstance(domain, str)
        or not re.fullmatch(r"[A-Za-z0-9.-]+", domain)
        or ".." in domain
        for domain in domain_names
    ):
        raise ValueError("invalid activity domain")
    bot_networks = _networks(snapshots)
    trusted_networks = _allowlist_networks(allowlist)
    events = []
    root = Path(logs_root).resolve()
    if not root.is_dir() or not domain_names:
        return {
            "events": [],
            "summary": _traffic_summary([]),
            "scanned_bytes": 0,
            "scanned_files": 0,
            "truncated": False,
        }
    per_domain_limit = max(1, math.ceil(limit / len(domain_names)))
    per_domain_bytes = max(1, max_scan_bytes // len(domain_names))
    scanned_bytes = 0
    scanned_files = 0
    truncated = False
    for domain in domain_names:
        candidates = []
        for path in root.glob(f"{domain}_ols.access_log*"):
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
                stat = path.stat()
            except (OSError, ValueError):
                continue
            if (
                path.is_file()
                and not path.is_symlink()
                and path.suffix != ".gz"
                and stat.st_mtime >= since.timestamp()
            ):
                candidates.append((stat.st_mtime, resolved))
        candidates.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
        domain_bytes = 0
        domain_events = 0
        for candidate_index, (_mtime, path) in enumerate(candidates):
            remaining = min(
                per_domain_bytes - domain_bytes,
                max_scan_bytes - scanned_bytes,
            )
            if remaining <= 0:
                truncated = True
                break
            reader = _iter_lines_reverse(path, max_bytes=remaining)
            scanned_files += 1
            for line in reader:
                match = LOG_PATTERN.match(line.strip())
                if not match:
                    continue
                try:
                    timestamp = datetime.strptime(
                        match["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
                    )
                except ValueError:
                    continue
                if timestamp < since:
                    continue
                status = int(match["status"])
                event = _classify_traffic_event({
                    "domain": domain,
                    "ip": match["remote"],
                    "timestamp": timestamp.isoformat(),
                    "method": match["method"],
                    "path": match["path"],
                    "status": status,
                    "outcome": _outcome(status),
                }, bot_networks, trusted_networks, country_lookup)
                if not _matches_filters(event, filters):
                    continue
                events.append(event)
                domain_events += 1
                if domain_events >= per_domain_limit:
                    reader.truncated = True
                    break
            scanned_bytes += reader.scanned_bytes
            domain_bytes += reader.scanned_bytes
            truncated = truncated or reader.truncated
            if domain_events >= per_domain_limit or domain_bytes >= per_domain_bytes:
                truncated = truncated or bool(candidates[candidate_index + 1:])
                break
        if scanned_bytes >= max_scan_bytes:
            truncated = True
            break
    events.sort(key=lambda item: item["timestamp"], reverse=True)
    if len(events) > limit:
        truncated = True
    events = events[:limit]
    return {
        "events": events,
        "summary": _traffic_summary(events),
        "scanned_bytes": scanned_bytes,
        "scanned_files": scanned_files,
        "truncated": truncated,
    }
