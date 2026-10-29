import fnmatch
import glob
import os
import re
import sqlite3
import stat
from dataclasses import dataclass, replace
from itertools import islice
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


@dataclass(frozen=True)
class NginxDomainRecord(DomainRecord):
    site_id: int
    aliases: tuple[str, ...]
    vhost_path: str
    snippet_path: str
    server_blocks: int
    supported_for_protection: bool
    unsupported_reason: str


_NGINX_GUARD = object()


def _nginx_path(value, roots=None):
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or any(char in str(path) for char in "$\\")
            or any(ord(char) < 32 for char in str(path))
            or any(part.is_symlink() for part in (path, *path.parents))):
        raise ValueError("Unsafe or symlinked Nginx path: " + str(path))
    if roots is not None and not any(path.is_relative_to(root) for root in roots):
        raise ValueError("Nginx include is outside approved roots: " + str(path))
    return path


def _nginx_lua_end(text, index):
    depth = 1
    while index < len(text):
        if text[index] == '\x00':
            raise ValueError('NUL in Lua block')
        comment = text.startswith('--', index)
        if comment:
            index += 2
        long_string = re.match(r'\[(=*)\[', text[index:]) if text[index:index + 1] == '[' else None
        if long_string:
            ending = ']' + long_string.group(1) + ']'
            end = text.find(ending, index + len(long_string.group()))
            if end < 0:
                raise ValueError('Unterminated Lua long string')
            index = end + len(ending)
        elif comment:
            newline = text.find('\n', index)
            if newline < 0:
                raise ValueError('Unterminated Lua block')
            index = newline + 1
        elif text[index] in '\"\'':
            quote = text[index]
            index += 1
            while index < len(text) and text[index] != quote:
                index += 2 if text[index] == '\\' else 1
            if index >= len(text):
                raise ValueError('Unterminated Lua string')
            index += 1
        elif text[index] == '{':
            depth += 1
            if depth > 64:
                raise ValueError('Lua nesting limit exceeded')
            index += 1
        elif text[index] == '}':
            depth -= 1
            index += 1
            if not depth:
                return index
        else:
            index += 1
    raise ValueError('Unterminated Lua block')

def _nginx_tokens(text):
    tokens = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == "#":
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char in "{};":
            directive = []
            for kind, value in reversed(tokens):
                if kind != 'word':
                    break
                directive.insert(0, value)
            tokens.append((char, char))
            index += 1
            if char == '{' and directive and directive[0].endswith('_by_lua_block'):
                index = _nginx_lua_end(text, index)
                tokens.append(('}', '}'))
        else:
            word = []
            quote = None
            while index < len(text):
                char = text[index]
                if char == "\x00":
                    raise ValueError("NUL in Nginx configuration")
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise ValueError("Unterminated Nginx escape")
                    escaped = text[index]
                    word.append({"n": "\n", "r": "\r", "t": "\t"}.get(escaped, escaped if escaped in "\"'\\" else "\\" + escaped))
                    index += 1
                elif quote:
                    if char == quote:
                        quote = None
                        if index + 1 < len(text) and text[index + 1] not in " \t\r\n;{)":
                            raise ValueError("Unexpected text after Nginx quoted token")
                    else:
                        word.append(char)
                    index += 1
                elif char in "\"'" and not word:
                    quote = char
                    index += 1
                elif char == "{" and word and word[-1] == "$":
                    end = text.find("}", index)
                    if end < 0:
                        raise ValueError("Unterminated Nginx variable")
                    word.append(text[index:end + 1])
                    index = end + 1
                elif char in " \t\r\n{};":
                    break
                else:
                    word.append(char)
                    index += 1
            if quote:
                raise ValueError("Unterminated Nginx quote")
            tokens.append(("word", "".join(word)))
        if len(tokens) > 50000:
            raise ValueError("Nginx token limit exceeded")
    return tokens


def _nginx_parse(text):
    tokens = _nginx_tokens(text)
    index = 0

    def block(depth):
        nonlocal index
        if depth > 64:
            raise ValueError("Nginx nesting limit exceeded")
        nodes = []
        arguments = []
        while index < len(tokens):
            kind, value = tokens[index]
            index += 1
            if kind == "word":
                arguments.append(value)
            elif kind == "}" and not arguments and depth:
                return tuple(nodes)
            elif kind in {";", "{"} and arguments:
                children = block(depth + 1) if kind == "{" else None
                nodes.append((tuple(arguments), children))
                arguments = []
            else:
                raise ValueError("Malformed Nginx block or missing semicolon")
        if depth or arguments:
            raise ValueError("Unterminated Nginx block or directive")
        return tuple(nodes)

    return block(0)


def _nginx_load(path, context, depth=0):
    path = _nginx_path(path, context["roots"])
    if path in context["stack"] or len(context["stack"]) >= 16:
        raise ValueError("Nginx include cycle or depth limit: " + str(path))
    context["files"] += 1
    if context["files"] > 64:
        raise ValueError("Nginx include file limit exceeded")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 524288:
            raise ValueError("Nginx include is not a bounded regular file")
        content = source.read(524289)
    context["bytes"] += len(content)
    if len(content) > 524288 or context["bytes"] > 2097152:
        raise ValueError("Nginx include size limit exceeded")
    context["stack"].add(path)
    try:
        return _nginx_expand(_nginx_parse(content.decode("utf-8")), context, depth)
    finally:
        context["stack"].remove(path)


def _nginx_expand(nodes, context, depth=0):
    if depth > 64:
        raise ValueError("Nginx expanded nesting limit exceeded")
    output = []
    for arguments, children in nodes:
        if arguments[0] != "include":
            output.append((arguments, _nginx_expand(children, context, depth + 1) if children is not None else None))
            continue
        if len(arguments) != 2 or children is not None:
            raise ValueError("Malformed Nginx include")
        pattern = Path(arguments[1])
        if not pattern.is_absolute():
            if context["prefix"] is None:
                raise ValueError("Relative includes require the verified main config directory")
            pattern = context["prefix"] / pattern
        pattern = _nginx_path(pattern, context["roots"])
        if any(glob.has_magic(part) for part in pattern.parent.parts):
            raise ValueError("Wildcard include directories are not supported")
        output.append((("include", str(pattern)), None))
        snippet = context["snippet"]
        if pattern.parent == snippet.parent and glob.has_magic(pattern.name) and pattern.name not in {"*", "*.conf"}:
            raise ValueError("Noncanonical extension glob requires manual review")
        point = pattern.parent == snippet.parent and pattern.name in {"*", "*.conf", snippet.name}
        if glob.has_magic(pattern.name):
            matches = sorted(Path(value) for value in islice(glob.iglob(str(pattern)), 65))
            if len(matches) > 64:
                raise ValueError("Nginx glob limit exceeded")
        else:
            matches = [pattern]
        inserted = False
        for match in matches:
            if point and not inserted and match.name >= snippet.name:
                output.append(((_NGINX_GUARD,), None))
                inserted = True
            output.extend(_nginx_load(match, context, depth))
        if point and not inserted:
            output.append(((_NGINX_GUARD,), None))
    return tuple(output)


def _nginx_walk(nodes):
    for arguments, children in nodes:
        yield arguments, children
        if children is not None:
            yield from _nginx_walk(children)


def _nginx_name(value, allow_wildcard=False):
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("Invalid Nginx server name")
    normalized = value.lower().removesuffix(".")
    if allow_wildcard and normalized.startswith("*."):
        return "*." + _validate_domain(normalized[2:])
    return _validate_domain(normalized)


def _nginx_database(database_path):
    database = _nginx_path(database_path)
    if not database.is_file():
        raise ValueError("aaPanel site database is unavailable")
    try:
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            rows = connection.execute("SELECT id, name, status, path, project_type FROM sites ORDER BY name").fetchall()
            bindings = connection.execute("SELECT pid, name FROM domain").fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise ValueError("Unable to read aaPanel site/domain schema: " + str(error)) from error
    sites = {}
    owners = {}
    for site_id, name, status, root, project_type in rows:
        normalized_status = int(status) if isinstance(status, str) and status.isdigit() else status
        if (type(site_id) is not int or site_id <= 0 or site_id in sites or not isinstance(name, str)
                or type(normalized_status) is not int or normalized_status not in {0, 1} or not isinstance(root, str)
                or not Path(root).is_absolute() or "\x00" in root
                or project_type is not None and not isinstance(project_type, str)):
            raise ValueError("Invalid or ambiguous aaPanel site record")
        status = normalized_status
        domain = _validate_domain(name)
        if domain in owners:
            raise ValueError("Duplicate aaPanel site name")
        sites[site_id] = {"row": (domain, status, root, project_type), "names": {domain}}
        owners[domain] = site_id
    for site_id, name in bindings:
        domain = _nginx_name(name, allow_wildcard=True)
        if site_id not in sites or domain in owners and owners[domain] != site_id:
            raise ValueError("Conflicting aaPanel alias ownership")
        owners[domain] = site_id
        sites[site_id]["names"].add(domain)
    return sites


def _nginx_servers(tree, expected_names):
    servers = []
    seen_names = set()
    roots = set()
    for arguments, children in tree:
        if arguments[0] == "include" and children is None:
            continue
        if arguments[0] == 'proxy_cache_path' and children is None:
            continue
        if arguments != ("server",) or children is None:
            raise ValueError("Unsupported top-level Nginx structure")
        servers.append(children)
        names = [value for fields, nested in children if fields[0] == "server_name" and nested is None for value in fields[1:]]
        if not names:
            raise ValueError("Missing server_name binding")
        normalized = {_nginx_name(name) for name in names}
        if not normalized <= expected_names:
            raise ValueError("Nginx server names do not match aaPanel aliases")
        seen_names.update(normalized)
        points = [index for index, (fields, nested) in enumerate(children) if fields[0] is _NGINX_GUARD]
        all_points = sum(fields[0] is _NGINX_GUARD for fields, nested in _nginx_walk(children))
        if len(points) != 1 or all_points != 1:
            raise ValueError("Every server block requires exactly one server-level extension include")
        if any(fields[0] in {"return", "rewrite", "if"} or '_by_lua' in str(fields[0])
               for fields, nested in children[:points[0]]):
            raise ValueError("Server rewrite/return can bypass the extension guard")
        if any(str(fields[0]).startswith(('rewrite_by_lua', 'server_rewrite_by_lua'))
               for fields, nested in _nginx_walk(children)):
            raise ValueError('Lua rewrite phase requires manual review')
        for fields, nested in children:
            if fields[0] == "root":
                if nested is not None or len(fields) != 2 or "$" in fields[1] or not Path(fields[1]).is_absolute():
                    raise ValueError("Unsupported Nginx document root")
                roots.add(str(Path(fields[1]).resolve()))
    if not servers or seen_names != expected_names:
        raise ValueError("Nginx server blocks do not cover aaPanel aliases")
    if len(roots) > 1:
        raise ValueError("Multiple Nginx document roots require manual review")
    return len(servers), next(iter(roots), None)


def collect_nginx_access_logs(domains, vhost_root, logs_root, *, config_prefix):
    vhost_root = _nginx_path(vhost_root)
    prefix = _nginx_path(config_prefix)
    logs_root = _nginx_path(logs_root)
    roots = (vhost_root, _nginx_path(vhost_root.parent / 'rewrite'), prefix)
    result = {}
    for domain in sorted(set(domains)):
        _validate_domain(domain)
        item = {'paths': [], 'state': 'unavailable', 'issues': []}
        result[domain] = item
        try:
            context = {'roots': roots, 'prefix': prefix, 'stack': set(), 'files': 0, 'bytes': 0,
                       'snippet': vhost_root / 'extension' / domain / '00-ols-geo-access.conf'}
            tree = _nginx_load(vhost_root / (domain + '.conf'), context)
            servers = [children for fields, children in tree if fields == ('server',) and children is not None]
            if not servers:
                raise ValueError('Không tìm thấy server block của website')
            disabled = False
            def inspect_scope(nodes, server_level=False):
                nonlocal disabled
                directives = [(fields, nested) for fields, nested in nodes if fields[0] == 'access_log']
                if server_level and not directives:
                    item['issues'].append('Chưa có access_log riêng ở cấp server; log kế thừa chưa được hỗ trợ')
                supported = []
                unsupported = []
                scope_disabled = False
                for fields, nested in directives:
                    if len(fields) >= 2 and fields[1] in {'off', '/dev/null'} and nested is None:
                        scope_disabled = True
                        continue
                    if (nested is not None or len(fields) < 2 or
                            fields[1] != str(logs_root / (domain + '.log')) or
                            (len(fields) > 2 and fields[2] != 'combined') or
                            any(value.startswith(('gzip', 'if=')) for value in fields[3:])):
                        unsupported.append('Chưa hỗ trợ access_log tùy chỉnh: ' + ' '.join(fields[1:]))
                        continue
                    supported.append(fields[1])
                item['paths'].extend(supported)
                if not supported:
                    disabled = disabled or scope_disabled
                    item['issues'].extend(unsupported)
                for fields, children in nodes:
                    if children is not None:
                        inspect_scope(children)
            for server in servers:
                inspect_scope(server, server_level=True)
            item['paths'] = sorted(set(item['paths']))
            if item['paths']:
                if disabled:
                    item['issues'].append('Một số server/location đang tắt access_log')
                item['state'] = 'partial' if item['issues'] else 'ready'
            elif item['issues']:
                item['state'] = 'unsupported'
            else:
                item['state'] = 'disabled'
                item['issues'].append('Website đã tắt access_log')
        except (OSError, ValueError) as error:
            item['issues'].append('Không đọc được cấu hình access_log: ' + str(error))
    return result

def collect_domains_nginx(database_path, vhost_root, traffic_modes=None, managed_domains=None,
                          *, config_prefix=None, include_roots=()):
    vhost_root = _nginx_path(vhost_root)
    if not vhost_root.is_dir():
        raise ValueError("Nginx vhost directory is unavailable")
    prefix = _nginx_path(config_prefix) if config_prefix is not None else None
    roots = (vhost_root, _nginx_path(vhost_root.parent / 'rewrite'),
             *(_nginx_path(root) for root in include_roots), *((prefix,) if prefix else ()))
    sites = _nginx_database(database_path)
    traffic_modes = traffic_modes or {}
    managed_domains = set(managed_domains or ())
    records = []
    references = []
    claims = []
    for site_id, site in sites.items():
        domain, database_status, database_root, project_type = site["row"]
        vhost = vhost_root / (domain + ".conf")
        snippet = vhost_root / "extension" / domain / "00-ols-geo-access.conf"
        root = str(Path(database_root).resolve())
        proxy = False
        php_version = None
        server_count = 0
        reason = ""
        referenced = []
        claimed = set()
        try:
            _nginx_path(snippet, roots)
            context = {"roots": roots, "prefix": prefix, "snippet": snippet, "stack": set(), "files": 0, "bytes": 0}
            tree = _nginx_load(vhost, context)
            flat = list(_nginx_walk(tree))
            referenced = [fields[1] for fields, nested in flat if fields[0] == "include"]
            for fields, nested in flat:
                if fields[0] == "server_name":
                    for name in fields[1:]:
                        try:
                            claimed.add(_nginx_name(name))
                        except ValueError:
                            continue
            server_count = sum(fields == ("server",) and nested is not None for fields, nested in tree)
            server_count, configured_root = _nginx_servers(tree, site["names"])
            root = configured_root or root
            proxy = any(fields[0] in {"proxy_pass", "grpc_pass"} for fields, nested in flat)
            versions = {match.group(1) for path in referenced if (match := re.fullmatch(r"enable-php-([0-9]+)\.conf", Path(path).name))}
            php_version = next(iter(versions)) if len(versions) == 1 else None
        except (OSError, ValueError) as error:
            reason = str(error)
        integration = "present-unverified" if snippet.is_file() and not snippet.is_symlink() else "missing" if domain in managed_domains else "not-managed"
        records.append(NginxDomainRecord(
            domain=domain, status="stopped" if not database_status or root == "/www/server/stop" else "active",
            root=root, root_exists=Path(root).exists(), proxy=proxy, php_version=php_version,
            application=_application(Path(database_root), proxy, project_type), integration=integration,
            project_type=project_type or "", traffic_mode=traffic_modes.get(domain, "unknown"),
            site_id=site_id, aliases=tuple(sorted(site["names"] - {domain})), vhost_path=str(vhost),
            snippet_path=str(snippet), server_blocks=server_count, supported_for_protection=not reason,
            unsupported_reason=reason,
        ))
        references.append(referenced)
        claims.append(claimed)
    for index, record in enumerate(records):
        if any(other != index and any(Path(pattern).parent == Path(record.snippet_path).parent
                                      and fnmatch.fnmatchcase(Path(record.snippet_path).name, Path(pattern).name) for pattern in patterns)
               for other, patterns in enumerate(references)):
            records[index] = replace(record, supported_for_protection=False,
                                     unsupported_reason="Extension snippet is referenced by another aaPanel site")
        if any(other != index and names.intersection({record.domain, *record.aliases}) for other, names in enumerate(claims)):
            records[index] = replace(records[index], supported_for_protection=False,
                                     unsupported_reason="Another aaPanel vhost claims this site's domain or alias")
    return records
