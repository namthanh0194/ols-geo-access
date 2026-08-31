#!/bin/sh
set -eu
prefix=${OLS_GEO_ACCESS_PREFIX:-}
rm -f "$prefix/etc/cron.d/ols-geo-access"
prefix=${OLS_GEO_ACCESS_PREFIX:-}
plugin_dir="$prefix/www/server/panel/plugin/ols_geo_access"
current="$plugin_dir/data/release-state/current.json"
confirmed=false
test "${1:-}" = "--confirm-active-rules" && confirmed=true
if test -s "$current" && grep -q '"managed_files"[[:space:]]*:[[:space:]]*{[[:space:]]*"' "$current" && test "$confirmed" != true; then
  echo "Managed rules are active; rollback them or pass --confirm-active-rules." >&2
  exit 1
fi
exit 0
