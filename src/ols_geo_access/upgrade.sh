#!/bin/sh
set -eu
python_bin=${OLS_GEO_ACCESS_PYTHON:-/usr/bin/python3}
prefix=${OLS_GEO_ACCESS_PREFIX:-}
case "$prefix" in *..*) echo "Unsafe prefix" >&2; exit 1;; esac
if test -z "${OLS_GEO_ACCESS_PYTHON:-}" && test -x "$prefix/www/server/panel/pyenv/bin/python3"; then
  python_bin="$prefix/www/server/panel/pyenv/bin/python3"
fi
"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo 'Python 3.10 or newer is required.' >&2
  exit 1
}
plugin_dir="$prefix/www/server/panel/plugin/ols_geo_access"
data_dir="$plugin_dir/data"
test -d "$data_dir"
backend=$("$python_bin" "$plugin_dir/backend_lifecycle.py" check "$plugin_dir")
if test -L "$data_dir/traffic_detection.json"; then
  echo 'traffic_detection.json must not be a symlink' >&2
  exit 1
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
for file in config.json domains.json traffic_detection.json providers.json woo_exceptions.json ip_allowlist.json cloudflare_prefixes.json proxy_trust_state.json state.json backend_identity.json; do
  test ! -f "$data_dir/$file" || cp -p "$data_dir/$file" "$backup/$file"
done
restore() {
  for file in "$backup"/*.json; do test -e "$file" || continue; cp -p "$file" "$data_dir/$(basename "$file")"; done
  if test ! -f "$backup/traffic_detection.json"; then
    rm -f "$data_dir/traffic_detection.json"
  fi
  if test ! -f "$backup/backend_identity.json"; then
    rm -f "$data_dir/backend_identity.json"
  fi
}
trap 'restore' HUP INT TERM
if ! "$python_bin" - "$data_dir" "$plugin_dir/data/providers.default.json" "$backend" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
root = Path(sys.argv[1])
if sys.argv[3] == 'nginx':
    for path in root.glob('*.json'):
        if path.is_symlink():
            raise SystemExit('Symlinked Nginx data file')
        if not path.name.startswith('update-') and not path.name.endswith('.default.json'):
            if json.loads(path.read_text()).get('schema_version') != 1:
                raise SystemExit('Unsupported Nginx data schema')
    traffic = root / 'traffic_detection.json'
    if not traffic.exists():
        traffic.write_text('{"schema_version":1,"domains":{}}\n')
        traffic.chmod(0o600)
    sys.exit(0)

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

traffic_path = root / "traffic_detection.json"
paths = sorted(root.glob("*.json"))
if not traffic_path.exists():
    paths.append(traffic_path)
for path in paths:
    if path.name.endswith(".default.json") or path.name.startswith("update-") or path.name in {"update-cache.json"}:
        continue
    data = {"schema_version": 1, "domains": {}} if path == traffic_path and not path.exists() else json.loads(path.read_text())
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
if test "$backend" = openlitespeed && ! "$python_bin" "$plugin_dir/update_cloudflare.py" --ensure --allow-packaged-fallback; then
  restore
  exit 1
fi
if ! "$python_bin" "$plugin_dir/backend_lifecycle.py" persist "$plugin_dir" >/dev/null; then
  restore
  exit 1
fi
if test "$backend" = nginx && ! "$python_bin" "$plugin_dir/prepare_nginx.py" "$plugin_dir"; then
  restore
  exit 1
fi
trap - HUP INT TERM
cron_dir="$prefix/etc/cron.d"
mkdir -p "$cron_dir"
printf '%s\n' \
  '17 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_feeds.py >> /www/server/panel/plugin/ols_geo_access/logs/feed-update.log 2>&1' \
  '23 */6 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_cloudflare.py --scheduled >> /www/server/panel/plugin/ols_geo_access/logs/cloudflare-update.log 2>&1' \
  '0 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_traffic.py >/dev/null 2>&1' \
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
