#!/bin/sh
set -eu
prefix=${OLS_GEO_ACCESS_PREFIX:-}
plugin_dir="$prefix/www/server/panel/plugin/ols_geo_access"
test -d "$plugin_dir"
mkdir -p "$plugin_dir/data" "$plugin_dir/data/snapshots" "$plugin_dir/data/release-state" "$plugin_dir/generated/releases" "$plugin_dir/logs" "$plugin_dir/tmp"
chmod 700 "$plugin_dir/data" "$plugin_dir/data/snapshots" "$plugin_dir/data/release-state" "$plugin_dir/generated" "$plugin_dir/generated/releases" "$plugin_dir/logs" "$plugin_dir/tmp"
find "$plugin_dir/data" "$plugin_dir/logs" -type f -exec chmod 600 {} +
exit 0
