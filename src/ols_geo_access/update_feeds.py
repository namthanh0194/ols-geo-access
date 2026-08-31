#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib.feed_updater import PROVIDER_SOURCES, download_feed, enabled_feeds, update_snapshot
from ols_geo_access_main import ols_geo_access_main

def main():
    data = ROOT / "data"
    settings = json.loads((data / "config.json").read_text())
    if not settings.get("auto_update_feeds", True):
        return 0
    providers = json.loads((data / "providers.json").read_text())
    snapshots = data / "snapshots"
    changed = []
    errors = {}
    for provider in enabled_feeds(providers):
        try:
            source = PROVIDER_SOURCES[provider]
            target = snapshots / f"{provider}.json"
            before = json.loads(target.read_text()).get("checksum") if target.is_file() else None
            snapshot = update_snapshot(provider, source, download_feed(provider, source), snapshots)
            if before != snapshot["checksum"]:
                changed.append(provider)
        except Exception as error:
            errors[provider] = type(error).__name__
    domains = json.loads((data / "domains.json").read_text())
    protected = any(item.get("enabled") and item.get("group") != "NONE" for item in domains.get("domains", {}).values())
    if changed and protected:
        manager = ols_geo_access_main(plugin_root=ROOT)
        result = manager.save_domains({"payload": json.dumps(domains)})
        if not result.get("status"):
            raise RuntimeError(result.get("msg", "cannot apply crawler feeds"))
    print(json.dumps({"changed": changed, "errors": errors}, sort_keys=True))
    return 0 if not errors or changed else 1

if __name__ == "__main__":
    raise SystemExit(main())
