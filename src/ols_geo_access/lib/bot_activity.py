import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path


LOG_PATTERN = re.compile(
    r"^'?(?P<forwarded>\S+) (?P<remote>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) .* "(?P<user_agent>[^"]*)"\'?$'
)
USER_AGENT_HINTS = (
    "bingbot",
    "applebot",
    "duckduckbot",
    "googlebot",
    "google-inspectiontool",
    "oai-searchbot",
    "chatgpt-user",
    "perplexitybot",
    "uptimerobot",
)


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


def _outcome(status):
    if 200 <= status < 400:
        return "allowed"
    if status == 403:
        return "blocked"
    return "other"

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
            "counts": {"total": 0, "ipv4": 0, "ipv6": 0},
            "last_activity": latest.get(provider),
        }
        if snapshot is not None:
            item["source"] = snapshot.get("source")
            item["created_at"] = snapshot.get("created_at")
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


def collect_bot_activity(domains, snapshots, logs_root, since, limit=200):
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("invalid activity limit")
    if not isinstance(since, datetime) or since.tzinfo is None:
        raise ValueError("activity since must include timezone")
    networks = _networks(snapshots)
    events = []
    root = Path(logs_root).resolve()
    for domain in sorted(set(domains)):
        for path in sorted(root.glob(f"{domain}_ols.access_log*")):
            if (
                not path.is_file()
                or path.suffix == ".gz"
                or path.stat().st_mtime < since.timestamp()
            ):
                continue
            with path.open(errors="replace") as handle:
                for line in handle:
                    lowered = line.lower()
                    if not any(hint in lowered for hint in USER_AGENT_HINTS):
                        continue
                    match = LOG_PATTERN.match(line.strip())
                    if not match:
                        continue
                    timestamp = datetime.strptime(
                        match["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
                    )
                    if timestamp < since:
                        continue
                    provider = _provider_for(match["remote"], networks)
                    if provider is None:
                        continue
                    status = int(match["status"])
                    events.append({
                        "domain": domain,
                        "provider": provider,
                        "ip": match["remote"],
                        "timestamp": timestamp.isoformat(),
                        "method": match["method"],
                        "path": match["path"],
                        "status": status,
                        "outcome": _outcome(status),
                    })
    events.sort(key=lambda item: item["timestamp"], reverse=True)
    events = events[:limit]
    summary = {"allowed": 0, "blocked": 0, "other": 0}
    for item in events:
        summary[item["outcome"]] += 1
    return {"events": events, "summary": summary}
