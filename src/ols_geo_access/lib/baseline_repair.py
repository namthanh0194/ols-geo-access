import difflib
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from lib.audit_log import audited_mutation

PROPOSAL_ID_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")
BLOCK_NAMES = ("scripthandler", "extprocessor", "phpIniOverride")

def sha256_bytes(content):
    return hashlib.sha256(content).hexdigest()

def _inside(path, root):
    path = Path(path).resolve()
    root = Path(root).resolve()
    try:
        return path.relative_to(root)
    except ValueError as error:
        raise ValueError("repair source is outside vhost root") from error

def _remove_block(text, name):
    pattern = re.compile(
        rf"(?im)^[ \t]*{re.escape(name)}(?:[ \t]+[^{{\r\n]+)?[ \t]*{{"
    )
    match = pattern.search(text)
    if not match:
        raise ValueError(f"missing {name} block")
    depth = 0
    end = None
    for index in range(match.end() - 1, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end is None:
        raise ValueError(f"unterminated {name} block")
    return text[:match.start()] + text[end:]

def _repair_php(text):
    if "/lsphp00/bin/lsphp" not in text:
        raise ValueError("PHP repair is limited to lsphp00")
    repaired = text
    removed = 0
    for name in BLOCK_NAMES:
        repaired = _remove_block(repaired, name)
        removed += 1
    repaired = re.sub(
        r"\n(?:[ \t]*\n)+(?=[ \t]*expires[ \t]*{)",
        "\n\n\n\n\n",
        repaired,
        count=1,
        flags=re.IGNORECASE,
    )
    return repaired, removed

def _repair_proxy(text, domain):
    repaired, replacements = re.subn(
        r"E=Proxy-Host:\$host(?=[\],])", f"E=Proxy-Host:{domain}", text
    )
    if replacements != 1:
        raise ValueError("expected exactly one unsafe Proxy-Host value")
    return repaired, replacements

def _atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise

@audited_mutation("baseline.proposal.build", target_index=0)
def build_repair_proposal(
    vhost_root,
    audit_report,
    proposals_root,
    proposal_id=None,
    created_at=None,
):
    if not audit_report.get("repair_eligible") or audit_report.get("unclassified_errors"):
        raise ValueError("baseline is not repair eligible")
    proposal_id = proposal_id or secrets.token_hex(16)
    if not PROPOSAL_ID_PATTERN.fullmatch(proposal_id):
        raise ValueError("invalid proposal id")
    vhost_root = Path(vhost_root).resolve()
    proposal_dir = Path(proposals_root).resolve() / proposal_id
    try:
        proposal_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError as error:
        raise ValueError("proposal already exists") from error

    cause_map = {item["code"]: item for item in audit_report["root_causes"]}
    php = cause_map.get("invalid_lsphp00", {})
    proxy = cause_map.get("invalid_proxy_host", {})
    if len(php.get("source_files", ())) != len(php.get("domains", ())):
        raise ValueError("ambiguous PHP repair sources")
    if len(proxy.get("source_files", ())) != len(proxy.get("domains", ())):
        raise ValueError("ambiguous proxy repair sources")

    entries = []
    diff_parts = []
    php_removed = 0
    proxy_replaced = 0
    work = [
        ("remove_lsphp00", domain, source)
        for domain, source in zip(php.get("domains", ()), php.get("source_files", ()))
    ] + [
        ("replace_proxy_host", domain, source)
        for domain, source in zip(proxy.get("domains", ()), proxy.get("source_files", ()))
    ]
    try:
        for kind, domain, source in work:
            source_path = Path(source).resolve()
            relative = _inside(source_path, vhost_root)
            original = source_path.read_bytes()
            original_text = original.decode("utf-8")
            if kind == "remove_lsphp00":
                proposed_text, count = _repair_php(original_text)
                php_removed += count
            else:
                if source_path.parent.parent.name != domain:
                    raise ValueError("proxy domain does not match source path")
                proposed_text, count = _repair_proxy(original_text, domain)
                proxy_replaced += count
            proposed = proposed_text.encode("utf-8")
            _atomic_write(proposal_dir / "files" / relative, proposed)
            entries.append(
                {
                    "relative_path": str(relative),
                    "domain": domain,
                    "kind": kind,
                    "source_sha256": sha256_bytes(original),
                    "proposed_sha256": sha256_bytes(proposed),
                }
            )
            diff_parts.extend(
                difflib.unified_diff(
                    original_text.splitlines(keepends=True),
                    proposed_text.splitlines(keepends=True),
                    fromfile=str(source_path),
                    tofile=str(proposal_dir / "files" / relative),
                )
            )
        manifest = {
            "schema_version": 1,
            "proposal_id": proposal_id,
            "created_at": created_at or datetime.now(timezone.utc).isoformat(),
            "vhost_root": str(vhost_root),
            "files": entries,
            "summary": {
                "files": len(entries),
                "php_blocks_removed": php_removed,
                "proxy_hosts_replaced": proxy_replaced,
            },
        }
        _atomic_write(
            proposal_dir / "manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        )
        _atomic_write(proposal_dir / "proposal.diff", "".join(diff_parts).encode())
        return manifest
    except BaseException:
        import shutil
        shutil.rmtree(proposal_dir, ignore_errors=True)
        raise
