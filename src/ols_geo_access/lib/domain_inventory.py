import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path


DOMAIN_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
PHP_PATTERN = re.compile(r"/lsphp([0-9]+)/bin/lsphp\b")


@dataclass(frozen=True)
class DomainRecord:
    domain: str
    status: str
    root: str
    root_exists: bool
    proxy: bool
    php_version: str | None
    application: str
    integration: str
    project_type: str
    traffic_mode: str


def _validate_domain(domain):
    normalized = domain.strip().lower()
    if normalized != domain or not DOMAIN_PATTERN.fullmatch(normalized):
        raise ValueError(f"unsafe domain: {domain}")
    return normalized


def _read_directive(path, name):
    if not path.is_file():
        return None
    for line in path.read_text(errors="replace").splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0].lower() == name.lower():
            return fields[1].strip()
    return None


def _has_proxy(proxy_directory):
    if not proxy_directory.is_dir():
        return False
    for path in proxy_directory.glob("*.conf"):
        if path.name == "00-ols-geo-access.conf":
            continue
        if re.search(r"^\s*type\s+proxy\s*$", path.read_text(errors="replace"), re.MULTILINE | re.IGNORECASE):
            return True
    return False


def _application(site_path, proxy, project_type):
    if proxy:
        return "proxy"
    if (site_path / "wp-config.php").is_file():
        if (site_path / "wp-content" / "plugins" / "woocommerce").is_dir():
            return "woocommerce"
        return "wordpress"
    return project_type.lower() if project_type else "unknown"


def collect_domains(
    database_path,
    vhost_root,
    stopped_root=Path("/www/server/stop"),
    traffic_modes=None,
    managed_domains=None,
):
    database_path = Path(database_path).resolve()
    vhost_root = Path(vhost_root).resolve()
    stopped_root = Path(stopped_root).resolve()
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "select name, status, path, project_type from sites order by name"
        ).fetchall()
    finally:
        connection.close()

    traffic_modes = traffic_modes or {}
    managed_domains = set(managed_domains or ())
    records = []
    for name, database_status, database_path_value, project_type in rows:
        domain = _validate_domain(name)
        wrapper = vhost_root / f"{domain}.conf"
        detail = vhost_root / "detail" / f"{domain}.conf"
        root_value = _read_directive(wrapper, "vhRoot") or database_path_value
        root = Path(root_value).resolve()
        proxy = _has_proxy(vhost_root / "proxy" / domain)
        detail_text = detail.read_text(errors="replace") if detail.is_file() else ""
        php_match = PHP_PATTERN.search(detail_text)
        managed = vhost_root / "proxy" / domain / "urlrewrite" / "00-ols-geo-access.conf"
        status = "stopped" if not database_status or root == stopped_root else "active"
        records.append(
            DomainRecord(
                domain=domain,
                status=status,
                root=str(root),
                root_exists=root.exists(),
                proxy=proxy,
                php_version=php_match.group(1) if php_match else None,
                application=_application(Path(database_path_value), proxy, project_type),
                integration=(
                    "healthy"
                    if managed.is_file()
                    else "missing"
                    if domain in managed_domains
                    else "not-managed"
                ),
                project_type=project_type or "",
                traffic_mode=traffic_modes.get(domain, "unknown"),
            )
        )
    return records
