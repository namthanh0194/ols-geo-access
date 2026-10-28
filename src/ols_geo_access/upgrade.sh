#!/bin/sh
set -eu
python_bin=${OLS_GEO_ACCESS_PYTHON:-/usr/bin/python3}
"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo 'Python 3.10 or newer is required.' >&2
  exit 1
}
prefix=${OLS_GEO_ACCESS_PREFIX:-}
case "$prefix" in *..*) echo "Unsafe prefix" >&2; exit 1;; esac
plugin_dir="$prefix/www/server/panel/plugin/ols_geo_access"
data_dir="$plugin_dir/data"
test -d "$data_dir"
if test ! -f "$data_dir/traffic_detection.json"; then
  cp "$data_dir/traffic_detection.default.json" "$data_dir/traffic_detection.json"
  chmod 600 "$data_dir/traffic_detection.json"
fi
if test ! -f "$data_dir/ip_allowlist.json"; then
  cp "$plugin_dir/data/ip_allowlist.default.json" "$data_dir/ip_allowlist.json"
  chmod 600 "$data_dir/ip_allowlist.json"
fi
if test ! -f "$data_dir/cloudflare_prefixes.json"; then
  cp "$plugin_dir/data/cloudflare_prefixes.default.json" "$data_dir/cloudflare_prefixes.json"
  chmod 600 "$data_dir/cloudflare_prefixes.json"
fi
if test ! -f "$data_dir/proxy_trust_state.json"; then
  cp "$plugin_dir/data/proxy_trust_state.default.json" "$data_dir/proxy_trust_state.json"
  chmod 600 "$data_dir/proxy_trust_state.json"
fi
stamp=${OLS_GEO_ACCESS_UPGRADE_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
backup="$data_dir/backups/upgrade-$stamp"
test ! -e "$backup"
mkdir -p "$backup"
chmod 700 "$data_dir/backups" "$backup"
for file in config.json domains.json providers.json woo_exceptions.json ip_allowlist.json cloudflare_prefixes.json proxy_trust_state.json state.json; do
  test ! -f "$data_dir/$file" || cp -p "$data_dir/$file" "$backup/$file"
done
restore() {
  for file in "$backup"/*.json; do test -e "$file" || continue; cp -p "$file" "$data_dir/$(basename "$file")"; done
}
trap 'restore' HUP INT TERM
if ! "$python_bin" - "$data_dir" "$plugin_dir/data/providers.default.json" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
root = Path(sys.argv[1])

def merge_missing(current, defaults):
    for key, value in defaults.items():
        if key not in current:
            current[key] = value
        elif isinstance(current[key], dict) and isinstance(value, dict):
            merge_missing(current[key], value)

providers_path = root / "providers.json"
providers = json.loads(providers_path.read_text())
defaults_path = Path(sys.argv[2])
if defaults_path.is_file():
    merge_missing(providers, json.loads(defaults_path.read_text()))
    providers_path.write_text(json.dumps(providers, indent=2, sort_keys=True) + "\n")
    os.chmod(providers_path, 0o600)

for path in sorted(root.glob("*.json")):
    if path.name.endswith(".default.json") or path.name.startswith("update-") or path.name in {"update-cache.json"}:
        continue
    data = json.loads(path.read_text())
    version = data.get("schema_version")
    if version != 1:
        raise SystemExit(f"unsupported schema in {path.name}: {version}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=root)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush(); os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
PY
then
  restore
  exit 1
fi
if ! "$python_bin" "$plugin_dir/update_cloudflare.py" --ensure --allow-packaged-fallback; then
  restore
  exit 1
fi
trap - HUP INT TERM
cron_dir="$prefix/etc/cron.d"
mkdir -p "$cron_dir"
printf '%s\n' \
  '17 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_feeds.py >> /www/server/panel/plugin/ols_geo_access/logs/feed-update.log 2>&1' \
  '23 */6 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_cloudflare.py --scheduled >> /www/server/panel/plugin/ols_geo_access/logs/cloudflare-update.log 2>&1' \
  '*/15 * * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_traffic.py >/dev/null 2>&1' \
  > "$cron_dir/ols-geo-access"
chmod 644 "$cron_dir/ols-geo-access"
"$python_bin" - "$data_dir/backups" <<'PY'
import shutil, sys
from pathlib import Path

root = Path(sys.argv[1])
backups = sorted(
    (path for path in root.glob("upgrade-*") if path.is_dir()),
    key=lambda path: (path.stat().st_mtime_ns, path.name),
    reverse=True,
)
for path in backups[5:]:
    shutil.rmtree(path)
PY
"$python_bin" "$plugin_dir/sync_icon.py"
