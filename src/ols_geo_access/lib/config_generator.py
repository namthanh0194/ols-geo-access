import hashlib
import ipaddress
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from lib.audit_log import audited_mutation

from lib.config_validator import (
    validate_domain,
    validate_exception,
    validate_generated_config,
    validate_geoip_database,
)

GROUPS = {"NONE", "VN_ONLY"}

def _network_key(prefix):
    network = ipaddress.ip_network(prefix, strict=True)
    return network.version, int(network.network_address), network.prefixlen

def _crawler_prefixes(snapshots):
    prefixes = set()
    for provider in sorted(snapshots):
        snapshot = snapshots[provider]
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("checksum"), str):
            raise ValueError("invalid provider snapshot")
        for prefix in snapshot.get("prefixes", ()):
            prefixes.add(str(ipaddress.ip_network(prefix, strict=True)))
    return tuple(sorted(prefixes, key=_network_key))

def _octet_range_pattern(start, end):
    return "(?:" + "|".join(str(value) for value in range(start, end + 1)) + ")"

def _network_pattern(prefix):
    network = ipaddress.ip_network(prefix, strict=True)
    if network.version == 4:
        octets = str(network.network_address).split(".")
        fixed, remaining = divmod(network.prefixlen, 8)
        parts = [re.escape(value) for value in octets[:fixed]]
        if remaining:
            start = int(octets[fixed])
            parts.append(_octet_range_pattern(start, start + (1 << (8 - remaining)) - 1))
            fixed += 1
        parts.extend(r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})" for _ in range(4 - fixed))
        return "^" + r"\.".join(parts) + "$"

    if network.prefixlen == 128:
        return "^" + re.escape(str(network.network_address)) + "$"
    if network.prefixlen % 16:
        raise ValueError("IPv6 allowlist prefix must align to a hextet")
    hextets = network.network_address.exploded.split(":")[:network.prefixlen // 16]
    if any(value == "0000" for value in hextets):
        raise ValueError("IPv6 allowlist prefix must not contain compressed hextets")
    return "^" + ":".join(format(int(value, 16), "x") for value in hextets) + ":"

def _allow_rule(path=None, methods=None, prefix=None):
    lines = []
    if path is not None:
        path_pattern = re.escape(path).replace(r"\-", "-")
        lines.append(f"RewriteCond %{{REQUEST_URI}} ^{path_pattern}$")
    if methods:
        lines.append(f"RewriteCond %{{REQUEST_METHOD}} ^(?:{'|'.join(sorted(methods))})$")
    if prefix is not None:
        lines.append(f"RewriteCond %{{REMOTE_ADDR}} {_network_pattern(prefix)}")
    lines.append("RewriteRule ^ - [L]")
    return lines

def _section(title, rules):
    return [f"# {title}", *rules, ""]

def generate_domain_rules(
    domain,
    assignment,
    snapshots,
    exceptions=(),
    health_paths=(),
    origin_prefixes=(),
    allowlist=(),
    emergency_disable=False,
):
    validate_domain(domain)
    if not isinstance(assignment, dict) or assignment.get("group") not in GROUPS:
        raise ValueError("invalid domain assignment")
    if not isinstance(assignment.get("enabled"), bool):
        raise ValueError("domain enabled flag is required")
    if emergency_disable or not assignment["enabled"] or assignment["group"] == "NONE":
        return None

    lines = [
        "# Managed by OLS Geo Access Manager. Do not edit.",
        f"# Domain: {domain}",
        "",
    ]
    exception_rules = []
    for exception in sorted(exceptions, key=lambda item: (item.get("domain", ""), item.get("paths", []))):
        validate_exception(exception)
        if exception["domain"] != domain:
            continue
        for path in sorted(exception["paths"]):
            for prefix in sorted(set(exception["source_prefixes"]), key=_network_key):
                exception_rules.extend(_allow_rule(path, exception["methods"], prefix))
    if exception_rules:
        lines.extend(_section("Exact WooCommerce provider exceptions", exception_rules))
    trusted_rules = []
    for entry in sorted(allowlist, key=lambda item: item["id"]):
        if domain not in entry["domains"] and "*" not in entry["domains"]:
            continue
        paths = entry["paths"] or (None,)
        for path in paths:
            for prefix in sorted(set(entry["source_prefixes"]), key=_network_key):
                trusted_rules.extend(_allow_rule(path, entry["methods"], prefix))
    if trusted_rules:
        lines.extend(_section("Manual trusted sources", trusted_rules))
    cron_rules = []
    for prefix in sorted({str(ipaddress.ip_network(item, strict=True)) for item in origin_prefixes}, key=_network_key):
        cron_rules.extend(_allow_rule("/wp-cron.php", ("POST",), prefix))
        cron_rules.extend(_allow_rule("/wp-admin/admin-ajax.php", ("POST",), prefix))
    if cron_rules:
        lines.extend(_section("Internal cron from origin sources", cron_rules))

    lines.extend(
        _section(
            "Required ACME challenge",
            ["RewriteCond %{REQUEST_URI} ^/\\.well-known/acme-challenge/", "RewriteRule ^ - [L]"],
        )
    )
    health_rules = []
    for path in sorted(set(health_paths)):
        validate_exact = path
        if not isinstance(validate_exact, str) or not validate_exact.startswith("/") or validate_exact.endswith("/"):
            raise ValueError("health-check path must be exact")
        health_rules.extend(_allow_rule(path))
    if health_rules:
        lines.extend(_section("Explicit health checks", health_rules))

    crawler_rules = []
    for prefix in _crawler_prefixes(snapshots):
        crawler_rules.extend(_allow_rule(methods=("GET", "HEAD"), prefix=prefix))
    if crawler_rules:
        lines.extend(_section("Verified crawler sources (GET/HEAD only)", crawler_rules))
    lines.extend(
        _section(
            "Vietnam GeoIP",
            ["RewriteCond %{ENV:GEOIP_COUNTRY_CODE} ^VN$", "RewriteRule ^ - [L]"],
        )
    )
    lines.extend(["# Default deny", "RewriteRule ^ - [F,L]"])
    generated = "\n".join(lines) + "\n"
    validate_generated_config(generated)
    return generated

def _atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise

@audited_mutation("release.build", target_index=2)
def build_release(
    assignments,
    snapshots,
    releases_root,
    geoip_database,
    exceptions=(),
    health_paths=None,
    origin_prefixes=None,
    allowlist=(),
    release_id=None,
    created_at=None,
    parent_release=None,
):
    geoip_database = validate_geoip_database(geoip_database)
    release_id = release_id or secrets.token_hex(16)
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", release_id):
        raise ValueError("invalid release id")
    release_dir = Path(releases_root).resolve() / release_id
    try:
        release_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError as error:
        raise ValueError("release already exists") from error
    health_paths = health_paths or {}
    origin_prefixes = origin_prefixes or {}
    generated_checksums = {}
    try:
        for domain in sorted(assignments):
            text = generate_domain_rules(
                domain,
                assignments[domain],
                snapshots,
                exceptions=exceptions,
                health_paths=health_paths.get(domain, ()),
                origin_prefixes=origin_prefixes.get(domain, ()),
                allowlist=allowlist,
            )
            if text is None:
                continue
            relative = Path("domains") / domain / "urlrewrite" / "00-ols-geo-access.conf"
            content = text.encode()
            _atomic_write(release_dir / relative, content)
            generated_checksums[domain] = {
                "relative_path": str(relative),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        manifest = {
            "schema_version": 1,
            "release_id": release_id,
            "created_at": created_at or datetime.now(timezone.utc).isoformat(),
            "geoip_database": str(geoip_database),
            "parent_release": parent_release,
            "domain_assignments": {
                domain: assignments[domain] for domain in sorted(assignments)
            },
            "feed_checksums": {
                provider: snapshots[provider]["checksum"] for provider in sorted(snapshots)
            },
            "generated_checksums": generated_checksums,
        }
        _atomic_write(
            release_dir / "manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        )
        return manifest
    except BaseException:
        import shutil
        shutil.rmtree(release_dir, ignore_errors=True)
        raise
