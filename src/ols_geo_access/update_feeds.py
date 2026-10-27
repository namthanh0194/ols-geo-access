#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib.feed_updater import PROVIDER_SOURCES, download_feed, enabled_feeds, prepare_snapshot
from lib.service_sources import (
    download_hubspot_feed,
    download_jetpack_feed,
    prepare_service_allowlist,
)
from ols_geo_access_main import ols_geo_access_main

def main():
    data = ROOT / "data"
    settings = json.loads((data / "config.json").read_text())
    if not settings.get("auto_update_feeds", True):
        return 0
    providers = json.loads((data / "providers.json").read_text())
    snapshots = data / "snapshots"
    candidates = {}
    errors = {}
    for provider in enabled_feeds(providers):
        try:
            source = PROVIDER_SOURCES[provider]
            target = snapshots / f"{provider}.json"
            previous = json.loads(target.read_text()) if target.is_file() else None
            payload = download_feed(provider, source)
        except Exception as error:
            errors[provider] = "download_error"
            continue
        try:
            candidates[provider] = prepare_snapshot(
                provider, source, payload, previous=previous
            )
        except Exception as error:
            errors[provider] = getattr(error, "code", "invalid_format")

    service_payloads = {}
    service_fetchers = {
        "hubspot": download_hubspot_feed,
        "jetpack": download_jetpack_feed,
    }
    for service_id, fetcher in sorted(service_fetchers.items()):
        try:
            service_payloads[service_id] = fetcher()
        except Exception as error:
            errors[service_id] = getattr(error, "code", "download_error")

    allowlist_candidate = None
    if service_payloads:
        try:
            allowlist = json.loads((data / "ip_allowlist.json").read_text())
            allowlist_candidate = prepare_service_allowlist(allowlist, service_payloads)
        except Exception as error:
            errors["service_allowlist"] = getattr(error, "code", "invalid_format")

    manager = ols_geo_access_main(plugin_root=ROOT)
    result = manager.apply_scheduled_updates(candidates, allowlist_candidate)
    if not result.get("status"):
        errors["deployment"] = result.get("code", "deployment_failed")
    print(json.dumps({
        "changed": result.get("updated", []),
        "errors": errors,
        "service_sources": {
            "hubspot": "hubspot" in service_payloads and result.get("service_updated", False),
            "jetpack": "jetpack" in service_payloads and result.get("service_updated", False),
        },
    }, sort_keys=True))
    return 0 if not errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
