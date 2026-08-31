import functools
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|license[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_QUERY_PATTERN = re.compile(
    r"(?:token|access_token|auth|authorization|password|secret|api[_-]?key|license[_-]?key)",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----", re.IGNORECASE)
ACTION_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")

def _redact_url(value):
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.query:
        return value
    query = [
        (key, REDACTED if SENSITIVE_QUERY_PATTERN.search(key) else item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

def _sanitize(value, max_string_length, depth=0):
    if depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 100:
                result["[TRUNCATED]"] = True
                break
            key = str(key)[:max_string_length]
            result[key] = (
                REDACTED
                if SENSITIVE_KEY_PATTERN.search(key)
                else _sanitize(item, max_string_length, depth + 1)
            )
        return result
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item, max_string_length, depth + 1) for item in list(value)[:50]]
    if isinstance(value, str):
        if PRIVATE_KEY_PATTERN.search(value):
            return REDACTED
        return _redact_url(value)[:max_string_length]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:max_string_length]

class AuditLogger:
    def __init__(self, path, clock=None, max_string_length=2048):
        self.path = Path(path)
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        if not isinstance(max_string_length, int) or max_string_length < 32:
            raise ValueError("invalid audit string limit")
        self.max_string_length = max_string_length

    def record_action(self, action, metadata):
        if not isinstance(action, str) or not ACTION_PATTERN.fullmatch(action):
            raise ValueError("invalid audit action")
        if not isinstance(metadata, dict):
            raise ValueError("audit metadata must be an object")
        if self.path.is_symlink():
            raise ValueError("audit log path must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.exists():
            mode = self.path.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise ValueError("audit log path must be a regular file")
        record = {
            "timestamp": self.clock(),
            "action": action,
            "metadata": _sanitize(metadata, self.max_string_length),
        }
        content = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise ValueError("unable to open audit log safely") from error
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return record

def audited_mutation(action, target_index=None):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            audit = kwargs.pop("audit", None)
            target = None
            if target_index is not None and len(args) > target_index:
                target = str(args[target_index])
            try:
                result = function(*args, **kwargs)
            except BaseException as error:
                if audit is not None:
                    audit.record_action(
                        action,
                        {"target": target, "result": "error", "error": str(error)},
                    )
                raise
            if audit is not None:
                details = result if isinstance(result, dict) else None
                audit.record_action(
                    action,
                    {"target": target, "result": "success", "details": details},
                )
            return result
        return wrapped
    return decorate
