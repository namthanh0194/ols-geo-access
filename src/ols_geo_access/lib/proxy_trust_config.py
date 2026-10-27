import ipaddress
import re
from dataclasses import dataclass


IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")


class ProxyConfigError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _Item:
    kind: str
    name: str
    start: int
    end: int
    line_start: int
    line_end: int
    body_start: int | None = None
    body_end: int | None = None
    value: str | None = None


@dataclass(frozen=True)
class ProxyTrustPlan:
    proposed_bytes: bytes
    changed: bool
    managed_prefixes: tuple[str, ...]
    added_prefixes: tuple[str, ...]
    removed_prefixes: tuple[str, ...]
    preserved_manual_prefixes: tuple[str, ...]
    header_changed: bool


def _error(message, code="proxy_config_ambiguous"):
    raise ProxyConfigError(code, message)


def _line_start(text, offset):
    return text.rfind("\n", 0, offset) + 1


def _line_end(text, offset):
    found = text.find("\n", offset)
    return len(text) if found < 0 else found + 1


def _find_block_end(text, opening):
    depth = 0
    quote = None
    escaped = False
    comment = False
    for index in range(opening, len(text)):
        character = text[index]
        if comment:
            if character == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character == "#":
            comment = True
        elif character in {'"', "'"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    _error("OpenLiteSpeed configuration contains unbalanced braces")


def _opening_brace(text, start):
    quote = None
    escaped = False
    for index in range(start, _line_end(text, start)):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "#":
            return None
        elif character == "{":
            return index
    return None


def _items(text):
    items = []
    index = 0
    while index < len(text):
        character = text[index]
        if character.isspace():
            index += 1
            continue
        if character == "#":
            index = _line_end(text, index)
            continue
        match = IDENTIFIER.match(text, index)
        if not match:
            index = _line_end(text, index)
            continue
        name = match.group(0)
        cursor = match.end()
        while cursor < len(text) and text[cursor] in " \t\r":
            cursor += 1
        line_start = _line_start(text, index)
        opening = _opening_brace(text, cursor)
        if opening is not None:
            closing = _find_block_end(text, opening)
            end = closing + 1
            items.append(
                _Item(
                    "block",
                    name,
                    index,
                    end,
                    line_start,
                    _line_end(text, end),
                    opening + 1,
                    closing,
                )
            )
            index = end
            continue
        line_end = _line_end(text, cursor)
        value_end = line_end - 1 if line_end <= len(text) and text[line_end - 1:line_end] == "\n" else line_end
        items.append(
            _Item(
                "directive",
                name,
                index,
                value_end,
                line_start,
                line_end,
                value=text[cursor:value_end].strip(),
            )
        )
        index = line_end
    return items


def _split_comment(value):
    quote = None
    escaped = False
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "#":
            return value[:index].rstrip(), value[index:]
    return value.rstrip(), ""


def _tokens(value):
    content, comment = _split_comment(value or "")
    return [item for item in re.split(r"[\s,]+", content.strip()) if item], comment


def _normalize_prefixes(values):
    normalized = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError) as error:
            raise ProxyConfigError(
                "proxy_config_invalid_prefix", "invalid trusted proxy prefix"
            ) from error
        normalized.append(str(network))
    if len(normalized) != len(set(normalized)):
        raise ProxyConfigError(
            "proxy_config_invalid_prefix", "duplicate trusted proxy prefix"
        )
    return tuple(
        sorted(
            normalized,
            key=lambda value: (
                ipaddress.ip_network(value).version,
                int(ipaddress.ip_network(value).network_address),
                ipaddress.ip_network(value).prefixlen,
            ),
        )
    )


def _trusted_token(token):
    if not token.upper().endswith("T"):
        return None
    try:
        return str(ipaddress.ip_network(token[:-1], strict=True))
    except ValueError:
        return None


def _global_items(text, name, kind=None):
    lowered = name.lower()
    return [
        item
        for item in _items(text)
        if item.name.lower() == lowered and (kind is None or item.kind == kind)
    ]


def inspect_global_proxy_config(config_bytes):
    try:
        text = config_bytes.decode("utf-8")
    except (AttributeError, UnicodeDecodeError) as error:
        raise ProxyConfigError(
            "proxy_config_ambiguous", "OpenLiteSpeed configuration is not UTF-8"
        ) from error
    header_items = _global_items(text, "useIpInProxyHeader", "directive")
    access_items = _global_items(text, "accessControl", "block")
    if len(header_items) > 1 or len(access_items) > 1:
        _error("OpenLiteSpeed proxy trust configuration is ambiguous")
    header_value = None
    trusted_only = None
    if header_items:
        header_value, _comment = _split_comment(header_items[0].value or "")
        normalized = re.sub(r"[\s_-]+", " ", header_value.strip().lower())
        trusted_only = normalized in {"2", "trusted ip only"}
    configured = set()
    allow_tokens = []
    if access_items:
        block = access_items[0]
        body = text[block.body_start:block.body_end]
        for item in _global_items(body, "allow", "directive"):
            tokens, _comment = _tokens(item.value)
            allow_tokens.extend(tokens)
            for token in tokens:
                prefix = _trusted_token(token)
                if prefix:
                    configured.add(prefix)
    return {
        "header_value": header_value,
        "trusted_only": trusted_only,
        "access_control_present": bool(access_items),
        "allow_tokens": tuple(allow_tokens),
        "configured_prefixes": tuple(sorted(configured)),
    }


def _rewrite_access_control(text, desired, previous):
    access_items = _global_items(text, "accessControl", "block")
    if len(access_items) > 1:
        _error("multiple global accessControl blocks")
    if not access_items:
        separator = "" if not text or text.endswith("\n") else "\n"
        managed_tokens = ",".join(f"{prefix}T" for prefix in desired)
        block = f"accessControl {{\n    allow ALL,{managed_tokens}\n    deny\n}}\n"
        return text + separator + block, set(desired), set(desired), set(), set()

    block = access_items[0]
    body = text[block.body_start:block.body_end]
    allow_items = _global_items(body, "allow", "directive")
    original_tokens = []
    first_comment = ""
    for index, item in enumerate(allow_items):
        tokens, comment = _tokens(item.value)
        original_tokens.extend(tokens)
        if index == 0:
            first_comment = comment

    existing = {prefix for token in original_tokens if (prefix := _trusted_token(token))}
    desired_set = set(desired)
    previous_set = set(previous)
    manual_desired = (existing & desired_set) - previous_set
    managed = (previous_set & desired_set) | (desired_set - existing)
    added = desired_set - existing
    removed = (previous_set - desired_set) & existing

    preserved_tokens = []
    for token in original_tokens:
        prefix = _trusted_token(token)
        if prefix in previous_set:
            continue
        preserved_tokens.append(token)
    if not allow_items and not any(token.upper() == "ALL" for token in preserved_tokens):
        preserved_tokens.insert(0, "ALL")
    managed_tokens = [f"{prefix}T" for prefix in _normalize_prefixes(managed)]
    rendered_tokens = preserved_tokens + managed_tokens
    rendered = ",".join(rendered_tokens)

    if allow_items:
        replacements = []
        for index, item in enumerate(allow_items):
            line_start = block.body_start + item.line_start
            line_end = block.body_start + item.line_end
            if index == 0:
                indent = body[item.line_start:item.start]
                suffix = f" {first_comment}" if first_comment else ""
                newline = "\n" if body[item.line_end - 1:item.line_end] == "\n" else ""
                replacement = f"{indent}allow {rendered}{suffix}{newline}"
            else:
                replacement = ""
            replacements.append((line_start, line_end, replacement))
        for start, end, replacement in reversed(replacements):
            text = text[:start] + replacement + text[end:]
    else:
        block_indent = text[block.line_start:block.start]
        indent = block_indent + "    "
        insertion = block.body_start
        if text[insertion:insertion + 1] == "\n":
            insertion += 1
            replacement = f"{indent}allow {rendered}\n"
        else:
            replacement = f"\n{indent}allow {rendered}\n"
        text = text[:insertion] + replacement + text[insertion:]
    return text, managed, added, removed, manual_desired


def _rewrite_header(text):
    header_items = _global_items(text, "useIpInProxyHeader", "directive")
    if len(header_items) > 1:
        _error("multiple global useIpInProxyHeader directives")
    if header_items:
        item = header_items[0]
        current, comment = _split_comment(item.value or "")
        normalized = re.sub(r"[\s_-]+", " ", current.strip().lower())
        if normalized in {"2", "trusted ip only"}:
            return text, False
        indent = text[item.line_start:item.start]
        suffix = f" {comment}" if comment else ""
        newline = "\n" if text[item.line_end - 1:item.line_end] == "\n" else ""
        replacement = f"{indent}useIpInProxyHeader 2{suffix}{newline}"
        return text[:item.line_start] + replacement + text[item.line_end:], True
    access = _global_items(text, "accessControl", "block")
    if len(access) != 1:
        _error("global accessControl block is unavailable")
    insertion = access[0].line_start
    return text[:insertion] + "useIpInProxyHeader 2\n" + text[insertion:], True


def plan_proxy_trust_config(
    config_bytes,
    desired_prefixes,
    previously_managed_prefixes,
):
    try:
        source_text = config_bytes.decode("utf-8")
    except (AttributeError, UnicodeDecodeError) as error:
        raise ProxyConfigError(
            "proxy_config_ambiguous", "OpenLiteSpeed configuration is not UTF-8"
        ) from error
    desired = _normalize_prefixes(desired_prefixes)
    previous = _normalize_prefixes(previously_managed_prefixes)
    text, managed, added, removed, manual = _rewrite_access_control(
        source_text, desired, previous
    )
    text, header_changed = _rewrite_header(text)
    proposed = text.encode()
    inspect_global_proxy_config(proposed)
    return ProxyTrustPlan(
        proposed_bytes=proposed,
        changed=proposed != config_bytes,
        managed_prefixes=_normalize_prefixes(managed),
        added_prefixes=_normalize_prefixes(added),
        removed_prefixes=_normalize_prefixes(removed),
        preserved_manual_prefixes=_normalize_prefixes(manual),
        header_changed=header_changed,
    )
