import ipaddress
import json
import os
import tempfile

from lib.audit_log import audited_mutation


GROUPS = {"NONE", "VN_ONLY"}
TRAFFIC_MODES = {"direct", "cloudflare", "external_origin", "unknown"}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def _require_schema(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported schema")


def validate_domains(data):
    _require_schema(data)
    domains = data.get("domains")
    if not isinstance(domains, dict):
        raise ValueError("domains must be an object")
    for domain, settings in domains.items():
        if not isinstance(domain, str) or not domain or any(char in domain for char in "/\\* \t\r\n"):
            raise ValueError("invalid domain")
        if not isinstance(settings, dict):
            raise ValueError("domain settings must be an object")
        if settings.get("group") not in GROUPS:
            raise ValueError("invalid rule group")
        if settings.get("traffic_mode") not in TRAFFIC_MODES:
            raise ValueError("invalid traffic mode")
        if not isinstance(settings.get("enabled"), bool):
            raise ValueError("enabled must be boolean")
        if "bot_indexing_disabled" in settings and not isinstance(settings["bot_indexing_disabled"], bool):
            raise ValueError("bot indexing disabled must be boolean")


def validate_exceptions(data):
    _require_schema(data)
    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list):
        raise ValueError("exceptions must be a list")
    for item in exceptions:
        if not isinstance(item, dict):
            raise ValueError("exception must be an object")
        for field in ("id", "domain", "provider", "description", "review_after"):
            if not isinstance(item.get(field), str) or not item[field]:
                raise ValueError(f"invalid {field}")
        paths = item.get("paths")
        if not isinstance(paths, list) or not paths or any(not isinstance(path, str) or not path.startswith("/") for path in paths):
            raise ValueError("invalid paths")
        methods = item.get("methods")
        if not isinstance(methods, list) or not methods or any(method not in METHODS for method in methods):
            raise ValueError("invalid methods")
        prefixes = item.get("source_prefixes")
        if not isinstance(prefixes, list) or not prefixes:
            raise ValueError("invalid source prefixes")
        try:
            for prefix in prefixes:
                ipaddress.ip_network(prefix, strict=True)
        except (TypeError, ValueError) as error:
            raise ValueError("invalid source prefix") from error
        if not isinstance(item.get("signature_required"), bool):
            raise ValueError("signature_required must be boolean")

def validate_ip_allowlist(data):
    _require_schema(data)
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValueError("entries must be a list")
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("invalid allowlist entry")
        domains = item.get("domains")
        if not isinstance(domains, list) or not domains or any(not isinstance(domain, str) or not domain for domain in domains):
            raise ValueError("invalid allowlist domains")
        methods = item.get("methods")
        if not isinstance(methods, list) or not methods or any(method not in METHODS for method in methods):
            raise ValueError("invalid allowlist methods")
        paths = item.get("paths")
        if not isinstance(paths, list) or any(not isinstance(path, str) or not path.startswith("/") for path in paths):
            raise ValueError("invalid allowlist paths")
        prefixes = item.get("source_prefixes")
        if not isinstance(prefixes, list) or not prefixes:
            raise ValueError("invalid allowlist prefixes")
        try:
            for prefix in prefixes:
                ipaddress.ip_network(prefix, strict=True)
        except (TypeError, ValueError) as error:
            raise ValueError("invalid allowlist prefix") from error


VALIDATORS = {
    "domains": validate_domains,
    "woo_exceptions": validate_exceptions,
    "ip_allowlist": validate_ip_allowlist,
}


def load_json(paths, name):
    path = paths.data_file(name)
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if name == "domains":
        for settings in data.get("domains", {}).values():
            if settings.get("group") == "VN_ONLY_WOOCOMMERCE":
                settings["group"] = "VN_ONLY"
    return data


@audited_mutation("config.save", target_index=1)
def save_json(paths, name, data):
    validator = VALIDATORS.get(name)
    if validator:
        validator(data)
    target = paths.data_file(name)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
