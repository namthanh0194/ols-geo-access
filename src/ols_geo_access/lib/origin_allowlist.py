import ipaddress

def merge_origin_entry(data, addresses):
    prefixes = []
    for value in addresses:
        address = ipaddress.ip_address(value)
        if address.is_global:
            prefixes.append(f"{address}/{32 if address.version == 4 else 128}")
    entries = [entry for entry in data.get("entries", []) if entry.get("id") != "local-origin"]
    if prefixes:
        entries.append({
            "id": "local-origin",
            "domains": ["*"],
            "source_prefixes": sorted(set(prefixes)),
            "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "paths": [],
        })
    return {"schema_version": 1, "entries": entries}
