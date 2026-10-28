import hashlib
import ipaddress
import json
import re
from pathlib import Path

from lib.config_store import METHODS, validate_domains, validate_ip_allowlist
from lib.config_validator import validate_domain, validate_exact_path, validate_exception, validate_geoip_database


def _prefixes(values, reject_universal=False):
    if not isinstance(values, (list, tuple)):
        raise ValueError("prefixes must be a list")
    networks = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("prefix must be a string")
        network = ipaddress.ip_network(value, strict=True)
        if reject_universal and network.prefixlen == 0:
            raise ValueError("universal Cloudflare trust is not allowed")
        networks.add(network)
    return [str(network) for network in sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))]


def _paths(values):
    if not isinstance(values, (list, tuple)):
        raise ValueError("paths must be a list")
    for value in values:
        validate_exact_path(value)
        if (any(char in value for char in '$"\';{}\\|%')
                or any(ord(char) < 33 or ord(char) > 126 for char in value)
                or "//" in value or any(part in {".", ".."} for part in value.split("/"))):
            raise ValueError("unsafe or noncanonical Nginx path")
    return sorted(set(values))


def _methods(values):
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError("methods must be a nonempty list")
    if any(not isinstance(value, str) or value not in METHODS for value in values):
        raise ValueError("invalid HTTP method")
    return sorted(set(values))


def _active(domain, assignment, cloudflare):
    validate_domain(domain)
    validate_domains({"schema_version": 1, "domains": {domain: assignment}})
    if not assignment["enabled"] or assignment["group"] == "NONE":
        return False
    if assignment["traffic_mode"] not in {"direct", "cloudflare"}:
        raise ValueError("active protection requires direct or Cloudflare traffic")
    if assignment["traffic_mode"] == "cloudflare" and not cloudflare:
        raise ValueError("Cloudflare protection requires trusted ranges")
    return True


def _site_name(domain, assignment, cloudflare):
    identity = [domain, assignment["traffic_mode"]]
    if assignment["traffic_mode"] == "cloudflare":
        identity.append(cloudflare)
    digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:24]
    return "oga_" + digest


def _quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _geo(source, name, prefixes, default=0):
    lines = ["geo " + source + " $" + name + " {", "    default " + str(default) + ";"]
    lines.extend("    " + ("255.255.255.255" if prefix == "255.255.255.255/32" else prefix)
                 + " " + str(1 - default) + ";" for prefix in prefixes)
    return "\n".join(lines + ["}", ""])


def _map(source, name, rules, default=0):
    lines = ["map " + _quote(source) + " $" + name + " {", "    volatile;", "    default " + str(default) + ";"]
    lines.extend("    " + _quote(pattern) + " " + str(result) + ";" for pattern, result in rules)
    return "\n".join(lines + ["}", ""])


def _grant(name, client, methods, paths, prefixes=None, path_prefix=None):
    output = ""
    source_flag = "1"
    if prefixes is not None:
        source_flag = "$" + name + "_source"
        output += _geo(client, name + "_source", prefixes)
    method_pattern = "(?:" + "|".join(methods) + ")" if methods else "[^:]+"
    if path_prefix is not None:
        path_pattern = re.escape(path_prefix) + ".*"
    elif paths:
        path_pattern = "(?:" + "|".join(re.escape(path) for path in paths) + ")"
    else:
        path_pattern = ".*"
    pattern = "~^" + method_pattern + ":1:" + path_pattern + r"\z"
    return output + _map("$request_method:" + source_flag + ":$uri", name, [(pattern, 1)])


def generate_nginx_http_conf(mmdb_path, cloudflare_prefixes, *, assignments=None, snapshots=None,
                             exceptions=(), allowlist=(), health_paths=None, origin_prefixes=None):
    database = Path(mmdb_path)
    if (not database.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(database))
            or ".." in database.parts or any(path.is_symlink() for path in (database, *database.parents))):
        raise ValueError("unsafe GeoIP database path")
    database = validate_geoip_database(database)
    cloudflare = _prefixes(cloudflare_prefixes, reject_universal=True)
    assignments = {} if assignments is None else assignments
    validate_domains({"schema_version": 1, "domains": assignments})
    active = []
    for domain, assignment in sorted(assignments.items()):
        if _active(domain, assignment, cloudflare):
            active.append((domain, assignment))
    crawlers = []
    for snapshot in (snapshots or {}).values():
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("checksum"), str) or not snapshot["checksum"]:
            raise ValueError("snapshot checksum missing")
        crawlers.extend(_prefixes(snapshot.get("prefixes", [])))
    crawlers = _prefixes(crawlers)
    validated_exceptions = []
    for item in exceptions:
        validate_exception(item)
        validated_exceptions.append({"domain": item["domain"], "paths": _paths(item["paths"]),
                                     "methods": _methods(item["methods"]), "prefixes": _prefixes(item["source_prefixes"])})
    validate_ip_allowlist({"schema_version": 1, "entries": list(allowlist)})
    validated_allowlist = []
    for item in allowlist:
        for domain in item["domains"]:
            if domain != "*":
                validate_domain(domain)
        validated_allowlist.append({"domains": sorted(set(item["domains"])), "paths": _paths(item.get("paths", [])),
                                   "methods": _methods(item["methods"]), "prefixes": _prefixes(item["source_prefixes"])})
    health = {}
    origins = {}
    for domain, paths in (health_paths or {}).items():
        validate_domain(domain)
        health[domain] = _paths(paths)
    for domain, prefixes in (origin_prefixes or {}).items():
        validate_domain(domain)
        origins[domain] = _prefixes(prefixes)
    output = _geo("$realip_remote_addr", "oga_cf_peer", cloudflare)
    output += _geo("$http_cf_connecting_ip", "oga_cf_header_valid", ["255.255.255.255/32"], default=1)
    output += _map("$realip_remote_addr,$remote_addr", "oga_cf_rewritten",
                   [(r"~^(?<oga_same_ip>[^,]+),\k<oga_same_ip>$", 0)], default=1)
    output += _map("$oga_cf_peer:$oga_cf_header_valid:$oga_cf_rewritten", "oga_cf_bad",
                   [("~^1:(?:0:[01]|1:0)$", 1)])
    output += _map("$oga_cf_peer", "oga_cf_client", [("1", "$remote_addr")], default="$realip_remote_addr")
    output += 'geoip2 "' + str(database) + '" {\n'
    output += "    $oga_country_direct default=ZZ source=$realip_remote_addr country iso_code;\n"
    output += "    $oga_country_cf default=ZZ source=$oga_cf_client country iso_code;\n}\n"
    for domain, assignment in active:
        name = _site_name(domain, assignment, cloudflare)
        is_cloudflare = assignment["traffic_mode"] == "cloudflare"
        client = "$oga_cf_client" if is_cloudflare else "$realip_remote_addr"
        grants = []
        for category, entries in (("woo", validated_exceptions), ("trusted", validated_allowlist)):
            applicable = [item for item in entries if item.get("domain") == domain
                          or domain in item.get("domains", []) or "*" in item.get("domains", [])]
            for index, item in enumerate(sorted(applicable, key=lambda value: json.dumps(value, sort_keys=True))):
                grant = name + "_" + category + "_" + str(index)
                output += _grant(grant, client, item["methods"], item["paths"], item["prefixes"])
                grants.append("$" + grant)
        output += _grant(name + "_cron", client, ["POST"], ["/wp-cron.php", "/wp-admin/admin-ajax.php"], origins.get(domain, []))
        output += _grant(name + "_acme", client, [], [], path_prefix="/.well-known/acme-challenge/")
        if health.get(domain):
            output += _grant(name + "_health", client, [], health[domain])
        else:
            output += _map("$uri", name + "_health", [])
        output += _grant(name + "_crawler", client, ["GET", "HEAD"], [], crawlers)
        grants.extend("$" + name + "_" + suffix for suffix in ("cron", "acme", "health", "crawler"))
        guard = "$oga_cf_bad" if is_cloudflare else "0"
        country = "$oga_country_cf" if is_cloudflare else "$oga_country_direct"
        rules = [("~^1:", 1)]
        rules.extend(("~^0:" + "[01]:" * index + "1:", 0) for index in range(len(grants)))
        rules.append(("~^0:" + "[01]:" * len(grants) + "VN$", 0))
        output += _map(":".join([guard, *grants, country]), name + "_deny", rules, default=1)
    return output


def generate_nginx_server_snippet(domain, assignment, *, cloudflare_prefixes=()):
    cloudflare = _prefixes(cloudflare_prefixes, reject_universal=True)
    if not _active(domain, assignment, cloudflare):
        return ""
    output = ""
    if assignment["traffic_mode"] == "cloudflare":
        output += "".join("set_real_ip_from " + prefix + ";\n" for prefix in cloudflare)
        output += "real_ip_header CF-Connecting-IP;\nreal_ip_recursive off;\n"
    name = _site_name(domain, assignment, cloudflare)
    return output + "if ($" + name + "_deny) {\n    return 403;\n}\n"
