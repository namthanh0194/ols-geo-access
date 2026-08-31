#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$root/src/ols_geo_access"
out="$root/dist/ols_geo_access-0.1.0.zip"
test -d "$source_dir"
mkdir -p "$root/dist"
python3 - "$source_dir" "$out" <<'PY'
import os, stat, sys, zipfile
from pathlib import Path
source = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
entries = []
for path in source.rglob("*"):
    relative = path.relative_to(source)
    if any(part in {"__pycache__", "tmp", "logs"} for part in relative.parts):
        continue
    if path.is_symlink():
        raise SystemExit(f"symlink forbidden: {relative}")
    if path.is_file() and path.suffix != ".pyc":
        entries.append((relative.as_posix(), path))
temporary = out.with_suffix(".zip.tmp")
with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for relative, path in sorted(entries):
        info = zipfile.ZipInfo(f"ols_geo_access/{relative}", (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        mode = 0o755 if os.access(path, os.X_OK) else 0o644
        info.external_attr = (stat.S_IFREG | mode) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, path.read_bytes())
os.replace(temporary, out)
PY
printf '%s\n' "$out"
