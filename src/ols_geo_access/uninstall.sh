#!/bin/sh
set -eu
prefix=${OLS_GEO_ACCESS_PREFIX:-}
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
plugin_dir="$prefix/www/server/panel/plugin/ols_geo_access"
test -d "$plugin_dir"
cleanup="$plugin_dir/uninstall_cleanup.py"
test -f "$cleanup" || cleanup="$source_dir/uninstall_cleanup.py"
python3 "$cleanup"
rm -f "$prefix/etc/cron.d/ols-geo-access"
exit 0
