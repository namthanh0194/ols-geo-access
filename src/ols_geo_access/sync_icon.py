#!/usr/bin/env python3
import os
import tempfile
from pathlib import Path


def main():
    prefix = Path(os.environ.get("OLS_GEO_ACCESS_PREFIX") or "/")
    if not prefix.is_absolute() or ".." in prefix.parts:
        raise ValueError("unsafe prefix")
    panel = prefix / "www/server/panel"
    source = panel / "plugin/ols_geo_access/icon.png"
    destination = panel / "BTPanel/static/img/soft_ico/ico-ols_geo_access.png"
    for path in (source, destination):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError("icon paths must not contain symlinks")
    content = source.read_bytes()
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("plugin icon must be PNG")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ols-icon-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fchmod(handle.fileno(), 0o644)
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
