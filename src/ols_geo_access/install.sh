#!/bin/sh
set -eu

prefix=${OLS_GEO_ACCESS_PREFIX:-}
case "$prefix" in *..*) echo "Unsafe prefix" >&2; exit 1;; esac
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
plugin_parent="$prefix/www/server/panel/plugin"
plugin_dir="$plugin_parent/ols_geo_access"
ols_bin="$prefix/usr/local/lsws/bin/openlitespeed"

test -x "$ols_bin"
test -d "$plugin_parent"
mkdir -p "$plugin_dir/data" "$plugin_dir/data/secrets" "$plugin_dir/data/snapshots" "$plugin_dir/data/release-state" "$plugin_dir/generated/releases" "$plugin_dir/logs" "$plugin_dir/tmp"
chmod 700 "$plugin_dir/data" "$plugin_dir/data/secrets" "$plugin_dir/data/snapshots" "$plugin_dir/data/release-state" "$plugin_dir/generated" "$plugin_dir/generated/releases" "$plugin_dir/logs" "$plugin_dir/tmp"
for name in config domains providers woo_exceptions ip_allowlist; do
  target="$plugin_dir/data/$name.json"
  test -f "$target" || cp "$source_dir/data/$name.default.json" "$target"
  chmod 600 "$target"
done
python3 - "$plugin_dir" "$source_dir" <<'PY'
import json, subprocess, sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from lib.origin_allowlist import merge_origin_entry

addresses = []
try:
    result = subprocess.run(["ip", "-j", "address", "show", "scope", "global"], check=True, text=True, capture_output=True)
    for interface in json.loads(result.stdout):
        for item in interface.get("addr_info", []):
            if item.get("family") in {"inet", "inet6"}:
                addresses.append(item.get("local", ""))
except Exception:
    pass
path = root / "data" / "ip_allowlist.json"
path.write_text(json.dumps(merge_origin_entry(json.loads(path.read_text()), addresses), ensure_ascii=False, indent=2, sort_keys=True) + "\n")
PY
chmod 600 "$plugin_dir/data/ip_allowlist.json"
state="$plugin_dir/data/state.json"
if test ! -f "$state"; then printf '%s\n' '{"schema_version":1}' > "$state"; fi
chmod 600 "$state"
cron_dir="$prefix/etc/cron.d"
mkdir -p "$cron_dir"
printf '%s\n' '17 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_feeds.py >> /www/server/panel/plugin/ols_geo_access/logs/feed-update.log 2>&1' > "$cron_dir/ols-geo-access"
chmod 644 "$cron_dir/ols-geo-access"
python3 "$plugin_dir/update_feeds.py" >> "$plugin_dir/logs/feed-update.log" 2>&1 || true
printf '{"schema_version":1,"result":"ok","ols_binary":"%s"}\n' "$ols_bin" > "$plugin_dir/logs/install-audit.json"
chmod 600 "$plugin_dir/logs/install-audit.json"
