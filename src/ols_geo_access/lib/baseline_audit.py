import re
from pathlib import Path


VHOST_PATTERN = re.compile(r"vhost:([^]:]+)")
PROXY_PATTERN = re.compile(r"http://(proxy_[a-f0-9]+)/")


def _proxy_sources(vhost_root, proxy_names):
    sources = {}
    proxy_root = Path(vhost_root) / "proxy"
    if not proxy_root.is_dir():
        return sources
    for path in proxy_root.glob("*/urlrewrite/*.conf"):
        content = path.read_text(errors="replace")
        for proxy_name in proxy_names:
            if proxy_name in content and "Proxy-Host:$host" in content:
                sources[proxy_name] = (path.parent.parent.name, str(path))
    return sources


def audit_baseline(config_result, vhost_root):
    errors = list(config_result.errors)
    php_domains = sorted(
        {
            match.group(1)
            for line in errors
            if "lsphp00/bin/lsphp" in line
            for match in [VHOST_PATTERN.search(line)]
            if match
        }
    )
    php_errors = [
        line
        for line in errors
        if any(f"vhost:{domain}:" in line for domain in php_domains)
    ]

    proxy_names = sorted(
        {
            match.group(1)
            for line in errors
            for match in [PROXY_PATTERN.search(line)]
            if match
        }
    )
    proxy_sources = _proxy_sources(vhost_root, proxy_names)
    proxy_errors = [line for line in errors if PROXY_PATTERN.search(line)]
    classified = set(php_errors + proxy_errors)
    unclassified = [line for line in errors if line not in classified]

    root_causes = []
    if php_domains:
        root_causes.append(
            {
                "code": "invalid_lsphp00",
                "error_count": len(php_errors),
                "domains": php_domains,
                "source_files": [
                    str(Path(vhost_root) / "detail" / f"{domain}.conf")
                    for domain in php_domains
                ],
            }
        )
    if proxy_names:
        root_causes.append(
            {
                "code": "invalid_proxy_host",
                "error_count": len(proxy_errors),
                "domains": sorted(
                    {proxy_sources[name][0] for name in proxy_names if name in proxy_sources}
                ),
                "source_files": sorted(
                    proxy_sources[name][1] for name in proxy_names if name in proxy_sources
                ),
            }
        )

    repair_eligible = (
        not unclassified
        and len(php_domains) * 3 == len(php_errors)
        and len(proxy_names) == len(proxy_errors) == len(proxy_sources)
    )
    return {
        "config_test": {
            "exit_code": config_result.exit_code,
            "errors": len(config_result.errors),
            "warnings": len(config_result.warnings),
            "valid": config_result.valid,
        },
        "root_causes": root_causes,
        "unclassified_errors": unclassified,
        "repair_eligible": repair_eligible,
    }
