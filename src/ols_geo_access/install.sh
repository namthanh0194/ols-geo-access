#!/bin/sh
set -eu

python_bin=${OLS_GEO_ACCESS_PYTHON:-/usr/bin/python3}
"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo 'Python 3.10 or newer is required.' >&2
  exit 1
}

prefix=${OLS_GEO_ACCESS_PREFIX:-}
case "$prefix" in *..*) echo "Unsafe prefix" >&2; exit 1;; esac
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
plugin_parent="$prefix/www/server/panel/plugin"
plugin_dir="$plugin_parent/ols_geo_access"
ols_bin="$prefix/usr/local/lsws/bin/openlitespeed"

test -x "$ols_bin"
test -d "$plugin_parent"
mkdir -p "$plugin_dir"
if test "$source_dir" != "$plugin_dir"; then
  cp -R "$source_dir"/. "$plugin_dir"/
fi
mkdir -p "$plugin_dir/data" "$plugin_dir/data/secrets" "$plugin_dir/data/snapshots" "$plugin_dir/data/release-state" "$plugin_dir/data/proxy-trust-transactions" "$plugin_dir/generated/releases" "$plugin_dir/logs" "$plugin_dir/tmp"
chmod 700 "$plugin_dir/data" "$plugin_dir/data/secrets" "$plugin_dir/data/snapshots" "$plugin_dir/data/release-state" "$plugin_dir/data/proxy-trust-transactions" "$plugin_dir/generated" "$plugin_dir/generated/releases" "$plugin_dir/logs" "$plugin_dir/tmp"
for name in config domains providers woo_exceptions ip_allowlist cloudflare_prefixes proxy_trust_state; do
  target="$plugin_dir/data/$name.json"
  test -f "$target" || cp "$source_dir/data/$name.default.json" "$target"
  chmod 600 "$target"
done
"$python_bin" - "$plugin_dir" "$source_dir" <<'PY'
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
cloudflare_result=$("$python_bin" "$plugin_dir/update_cloudflare.py" --ensure --allow-packaged-fallback)
cron_dir="$prefix/etc/cron.d"
mkdir -p "$cron_dir"
printf '%s\n' \
  '17 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_feeds.py >> /www/server/panel/plugin/ols_geo_access/logs/feed-update.log 2>&1' \
  '23 */6 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_cloudflare.py --scheduled >> /www/server/panel/plugin/ols_geo_access/logs/cloudflare-update.log 2>&1' \
  > "$cron_dir/ols-geo-access"
chmod 644 "$cron_dir/ols-geo-access"
"$python_bin" "$plugin_dir/update_feeds.py" >> "$plugin_dir/logs/feed-update.log" 2>&1 || true
"$python_bin" - "$plugin_dir/logs/install-audit.json" "$ols_bin" "$cloudflare_result" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
document = {
    "schema_version": 1,
    "result": "ok",
    "ols_binary": sys.argv[2],
    "cloudflare": json.loads(sys.argv[3]),
}
path.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n")
PY
chmod 600 "$plugin_dir/logs/install-audit.json"
