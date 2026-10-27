# Cloudflare Trusted Proxy Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically configure, refresh, validate, repair, and recover Cloudflare trusted proxy settings for OpenLiteSpeed without requiring SSH or WebAdmin.

**Architecture:** A bounded Cloudflare source adapter prepares canonical snapshots, a side-effect-free planner edits only global proxy-trust settings, and a checksum-aware transaction manager commits OpenLiteSpeed configuration plus runtime ownership state under the existing deployment lock. Install, upgrade, cron, and UI call the same transaction path; unchanged data never reloads OpenLiteSpeed.

**Tech Stack:** Python 3.10+ standard library, POSIX shell, aaPanel plugin routes, OpenLiteSpeed global configuration, JSON journals, `fcntl.flock`, assert-based checks under `tmp/`.

## Global Constraints

- `/root/ols-geo-access` is the only development source.
- Do not edit aaPanel core files under `/www/server/panel/class` or `/www/server/panel/class_v2`.
- Do not edit `/www/server/panel/plugin/ols_geo_access` until every source gate in Task 8 passes and the user approves production rollout.
- Use Python 3.10+ standard library only; add no Python, JavaScript, PHP, or shell dependency.
- All tests, fixtures, diagnostics, backups, and rollout artifacts created during development live under `/root/ols-geo-access/tmp/` and are excluded from the package.
- Preserve `trusted-vps` with `45.33.54.225/32` and `51.79.248.182/32` in runtime and package defaults.
- Never add Cloudflare CIDRs to Geo Access `ip_allowlist.json`.
- Never set `useIpInProxyHeader` to trust all headers; the only accepted effective value is `2` / Trusted IP Only.
- Preserve `ALL`, deny policy, comments, unrelated access-control values, and manually managed trusted IPs.
- Remove a CIDR automatically only when `proxy_trust_state.json` records it as plugin-managed.
- Every global OpenLiteSpeed mutation uses `data/release-state/deployment.lock`, atomic writes, checksums, backup, config test, rollback, recovery, and audit.
- Treat OpenLiteSpeed config test as valid when parsed output contains zero `[ERROR]` lines; do not rely on exit code alone.
- Reload OpenLiteSpeed only when effective global proxy-trust configuration changes.
- A download, validation, config-test, or reload failure must leave the last committed configuration and snapshot active.
- Keep existing rules active during Cloudflare source failure; block only new managed publication when no successful live check exists within 72 hours.
- Do not configure Cloudflare DNS, account APIs, firewall rules, origin lockdown, Authenticated Origin Pulls, or tunnels.
- Uninstall retains global trusted proxy configuration and states this in audit output.
- Do not commit or push unless the user explicitly requests it.

---

### Task 1: Add Cloudflare automation regression harness

**Files:**
- Create: `tmp/cloudflare_proxy_automation_check.py`
- Modify: `tmp/self_check.py:1629`

**Interfaces:**
- Produces: `CHECKS: dict[str, Callable[[], None]]` with selectors `ranges`, `planner`, `transaction`, `cli`, `manager`, and `ui`.
- Produces: `main(selected: tuple[str, ...] = ()) -> int`.
- Consumes later interfaces from Tasks 2–7 through imports inside each check so every task can run its own selector.

- [ ] **Step 1: Create deterministic fixture builders**

Add helpers that create all data under a caller-supplied temporary root:

```python
def cloudflare_payload(etag="etag-1", ipv4=None, ipv6=None):
    return json.dumps({
        "success": True,
        "errors": [],
        "messages": [],
        "result": {
            "etag": etag,
            "ipv4_cidrs": ipv4 or [
                "173.245.48.0/20",
                "103.21.244.0/22",
                "103.22.200.0/22",
            ],
            "ipv6_cidrs": ipv6 or [
                "2400:cb00::/32",
                "2405:8100::/32",
                "2606:4700::/32",
            ],
        },
    }).encode()


def server_config(header=None, allow="ALL"):
    header_line = "" if header is None else f"useIpInProxyHeader {header}\n"
    return (
        "# global fixture\n"
        + header_line
        + "accessControl {\n"
        + f"    allow {allow}\n"
        + "    deny\n"
        + "}\n"
        + "extProcessor lsphp {\n    type lsapi\n}\n"
    ).encode()
```

Add a fake adapter that returns `ConfigTestResult`, records reload count, can fail config test once, can fail reload once, and never invokes a real binary.

- [ ] **Step 2: Add selector-based checks before production modules exist**

Define these checks with imports inside the function body:

```python
CHECKS = {
    "ranges": check_cloudflare_range_source,
    "planner": check_proxy_trust_planner,
    "transaction": check_proxy_trust_transaction,
    "cli": check_cloudflare_cli_and_lifecycle,
    "manager": check_manager_proxy_trust_contract,
    "ui": check_cloudflare_ui_contract,
}
```

The initial checks assert the interfaces and behaviors specified in their corresponding tasks. `main()` runs all checks when no selector is supplied, prints `PASS: <name>` per selector, prints full traceback on failure, and exits `1` when any selector fails.

- [ ] **Step 3: Register the harness in the aggregate self-check**

Add:

```python
def check_cloudflare_proxy_automation():
    path = ROOT / "tmp" / "cloudflare_proxy_automation_check.py"
    spec = importlib.util.spec_from_file_location(
        "cloudflare_proxy_automation_check", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(()) == 0
```

Call `check_cloudflare_proxy_automation()` before the final `print("self-check: ok")`. Reuse the existing local-module loading pattern in `tmp/self_check.py`; do not create a test framework dependency.

- [ ] **Step 4: Run the expected failing check**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py ranges
```

Expected: exit `1` because `lib.cloudflare_ranges` does not exist. Confirm the failure names the missing production interface rather than a fixture or syntax error.

- [ ] **Step 5: Check test-file syntax**

Run:

```bash
python3 -m py_compile tmp/cloudflare_proxy_automation_check.py
git diff --check
```

Expected: both commands exit `0`; the behavioral selector remains red.

---

### Task 2: Implement bounded Cloudflare range source

**Files:**
- Create: `src/ols_geo_access/lib/cloudflare_ranges.py`
- Modify: `src/ols_geo_access/data/cloudflare_prefixes.default.json:1`
- Modify: `tmp/cloudflare_proxy_automation_check.py`

**Interfaces:**
- Produces: `CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"`.
- Produces: `class CloudflareRangeRefusal(ValueError)` with `.code`.
- Produces: `download_cloudflare_ranges(opener=urlopen, timeout=15, max_bytes=256 * 1024) -> bytes`.
- Produces: `prepare_cloudflare_snapshot(payload, previous=None, checked_at=None) -> dict`.
- Produces: `select_install_fallback(runtime_snapshot, packaged_snapshot) -> dict`.
- Produces: `snapshot_freshness(snapshot, now=None) -> dict`.

- [ ] **Step 1: Complete the failing range-source checks**

`check_cloudflare_range_source()` must assert:

```python
candidate = prepare_cloudflare_snapshot(
    cloudflare_payload(),
    checked_at="2026-09-02T00:00:00+00:00",
)
assert candidate == {
    "schema_version": 1,
    "sources": [CLOUDFLARE_IPS_URL],
    "checked_at": "2026-09-02T00:00:00+00:00",
    "etag": "etag-1",
    "prefixes": [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "173.245.48.0/20",
        "2400:cb00::/32",
        "2405:8100::/32",
        "2606:4700::/32",
    ],
    "counts": {"total": 6, "ipv4": 3, "ipv6": 3},
    "checksum": expected_checksum,
}
```

Also assert bounded reads, invalid `success`, empty ETag, wrong family, non-canonical networks, duplicate/overlapping networks, private/reserved networks, IPv4 broader than `/8`, IPv6 broader than `/24`, fewer than six total production CIDRs, more than 256 CIDRs, reduction over 50 percent, and coverage growth over four times are refused with stable error codes.

Assert fallback chooses the newest valid `checked_at` document and never downgrades a newer runtime snapshot. Assert freshness classifications at 23:59:59, 24 hours, 72 hours, and 72 hours plus one second.

- [ ] **Step 2: Verify the range selector fails for missing behavior**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py ranges
```

Expected: exit `1` because the module or required functions are missing.

- [ ] **Step 3: Implement refusal and bounded download**

Use these constants and exception shape:

```python
CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
MIN_PREFIX_LENGTH = {4: 8, 6: 24}
MIN_TOTAL_PREFIXES = 6
MAX_TOTAL_PREFIXES = 256
MAX_REDUCTION = 0.5
MAX_COVERAGE_GROWTH = 4


class CloudflareRangeRefusal(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
```

`download_cloudflare_ranges()` creates one fixed `Request`, requires `response.geturl()` to remain exactly `CLOUDFLARE_IPS_URL`, reads at most `max_bytes + 1` bytes in 64 KiB chunks, rejects an unexpected redirect with `cloudflare_invalid_source`, rejects an oversized body with `cloudflare_response_too_large`, and returns bytes. It must reject a non-positive timeout or maximum size before opening a connection.

- [ ] **Step 4: Implement canonical snapshot preparation**

Parse JSON from bytes, require the exact response fields, normalize via `ipaddress.ip_network(value, strict=True)`, reject non-global networks and overlap, sort by `(version, int(network_address), prefixlen)`, and hash:

```python
canonical = ("\n".join(prefixes) + "\n").encode()
checksum = hashlib.sha256(canonical).hexdigest()
```

Compare a candidate with `previous` by total prefix reduction and per-family address coverage before returning it. Preserve no unknown upstream fields.

- [ ] **Step 5: Implement fallback and freshness**

`select_install_fallback()` validates both supplied documents with the local snapshot validator, discards invalid inputs, sorts valid inputs by parsed timezone-aware `checked_at`, and returns a deep copy of the newest. Raise `CloudflareRangeRefusal("cloudflare_snapshot_missing", ...)` if neither is valid.

`snapshot_freshness()` returns:

```python
{
    "state": "fresh" | "warning" | "stale_blocking",
    "age_seconds": int | None,
    "blocking": bool,
}
```

A missing or invalid `checked_at` is `stale_blocking`. Age below 24 hours is `fresh`; 24 through 72 hours is `warning`; greater than 72 hours is `stale_blocking`.

- [ ] **Step 6: Upgrade the packaged default schema**

Keep the current 22 normalized prefixes and sources, then add `etag`, `counts`, and `checksum` generated from the canonical newline-separated prefix list. Keep the existing September 2, 2026 `checked_at` value. Do not fetch or write production runtime state in this task.

- [ ] **Step 7: Run source and regression checks**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py ranges
python3 tmp/p0_deployment_safety_check.py
python3 tmp/package_check.py
git diff --check
```

Expected: all commands exit `0`.

---

### Task 3: Add side-effect-free OpenLiteSpeed planner

**Files:**
- Create: `src/ols_geo_access/lib/proxy_trust_config.py`
- Modify: `src/ols_geo_access/lib/proxy_trust_audit.py:1`
- Modify: `tmp/cloudflare_proxy_automation_check.py`

**Interfaces:**
- Produces: immutable `ProxyTrustPlan` dataclass.
- Produces: `plan_proxy_trust_config(config_bytes, desired_prefixes, previously_managed_prefixes) -> ProxyTrustPlan`.
- Produces: `inspect_global_proxy_config(config_bytes) -> dict` for audit and UI reuse.
- Changes: proxy-trust audit uses the same parser rather than independent global regex matching.

- [ ] **Step 1: Complete planner regression checks**

`check_proxy_trust_planner()` must cover:

- Missing header becomes one top-level `useIpInProxyHeader 2`.
- Header values `1`, `yes`, and trust-all become `2`.
- Existing `2` remains byte-stable when CIDRs also match.
- Existing `ALL`, `deny`, comments, non-Cloudflare values, and manually trusted `203.0.113.10/32T` remain.
- Desired prefixes are present once with uppercase `T` semantics and deterministic ordering.
- Only prefixes in `previously_managed_prefixes` are removed when no longer desired.
- A desired prefix already present before adoption is preserved but omitted from returned `managed_prefixes`.
- Nested `accessControl` or `useIpInProxyHeader` text does not count as a global item.
- Duplicate effective top-level header directives raise `ProxyConfigError("proxy_config_ambiguous", ...)`.
- Multiple top-level global `accessControl` blocks raise the same stable error.
- Invalid UTF-8, symlink-like path concerns handled by the transaction layer, and invalid desired CIDRs are refused without output.

- [ ] **Step 2: Verify planner selector is red**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py planner
```

Expected: exit `1` because `lib.proxy_trust_config` does not exist.

- [ ] **Step 3: Implement a brace-aware top-level scanner**

Scan decoded text once while tracking brace depth, quoted strings, escapes, and `#` comments. Emit top-level directive spans and named block spans without interpreting nested content. Reject unbalanced braces or unterminated quoted strings with `proxy_config_ambiguous`.

Use explicit internal records:

```python
@dataclass(frozen=True)
class _Item:
    kind: str
    name: str
    start: int
    end: int
    body_start: int | None
    body_end: int | None
```

Do not use a single multiline regex to locate or rewrite the global block.

- [ ] **Step 4: Implement planner ownership rules**

Define:

```python
@dataclass(frozen=True)
class ProxyTrustPlan:
    proposed_bytes: bytes
    changed: bool
    managed_prefixes: tuple[str, ...]
    added_prefixes: tuple[str, ...]
    removed_prefixes: tuple[str, ...]
    preserved_manual_prefixes: tuple[str, ...]
    header_changed: bool
```

Normalize desired and previous networks. Inspect existing `allow` tokens ending in `T`. Existing desired Cloudflare tokens not present in `previously_managed_prefixes` are manual and remain excluded from returned ownership. New desired tokens are plugin-managed. Previously managed tokens absent from desired are removed. Previously managed tokens still desired stay managed.

Render one deterministic global `allow` value from preserved tokens plus managed Cloudflare `T` tokens. Preserve `ALL`; if no `allow` directive exists, insert `allow ALL,<trusted tokens>`. Preserve the original `deny` directive and block indentation.

- [ ] **Step 5: Share inspection with proxy audit**

Replace `PROXY_HEADER_PATTERN`, `ALLOW_PATTERN`, `_prefixes()`, and `_trusted_only()` with `inspect_global_proxy_config()`. Keep the public `ProxyTrustResult`, `audit_proxy_trust()`, and `assert_proxy_trust()` behavior unchanged in this task.

- [ ] **Step 6: Run planner and existing proxy checks**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py planner
python3 tmp/p0_deployment_safety_check.py
python3 tmp/self_check.py
git diff --check
```

Expected: all commands exit `0`.

---

### Task 4: Add proxy-trust transaction and recovery

**Files:**
- Create: `src/ols_geo_access/lib/proxy_trust_transaction.py`
- Create: `src/ols_geo_access/data/proxy_trust_state.default.json`
- Modify: `src/ols_geo_access/lib/paths.py:3`
- Modify: `tmp/cloudflare_proxy_automation_check.py`
- Modify: `tmp/p1_operations_check.py:222`

**Interfaces:**
- Produces: `ProxyTrustRecoveryRequired(RuntimeError)`.
- Produces: `load_proxy_trust_state(path) -> dict`.
- Produces: `apply_proxy_trust_update(plugin_root, server_config_path, snapshot, config_test, reload_ols, audit=None, checked_live=False) -> dict`.
- Produces: `inspect_proxy_trust_recovery(plugin_root, server_config_path) -> dict`.
- Produces: `recover_proxy_trust_transaction(plugin_root, server_config_path, config_test, reload_ols, audit=None, acquire_lock=True) -> dict`.
- Produces: `record_proxy_trust_check_failure(plugin_root, server_config_path, code, checked_at, audit=None) -> dict`.
- Produces: `prune_proxy_trust_history(plugin_root, keep_completed=5) -> list[str]`.

- [ ] **Step 1: Complete transaction regression checks**

`check_proxy_trust_transaction()` must assert:

- First valid apply writes header, trusted CIDRs, snapshot, state, one committed manifest, and exactly one reload.
- A second identical apply writes no OpenLiteSpeed bytes and performs zero additional reloads.
- A successful unchanged live check updates `last_checked_at`, `last_success_at`, and ETag without reload.
- Config-test failure restores exact server config, snapshot, state, mode, UID/GID fixture metadata, and records `rolled_back`.
- Reload failure restores all resources, invokes restored reload once, and records `rolled_back`.
- Restore checksum drift refuses overwrite and records `recovery_required`.
- A crash fixture at `prepared`, `config_written`, `state_written`, and `reloaded` yields deterministic rollback or finalize behavior.
- Multiple incomplete transactions yield manual recovery state.
- Concurrent transaction and existing managed deployment serialize on the same `deployment.lock`.
- Retention keeps five completed transactions plus every incomplete transaction.

- [ ] **Step 2: Verify transaction selector is red**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py transaction
```

Expected: exit `1` because the transaction module and state default do not exist.

- [ ] **Step 3: Add runtime state path and validator**

Add to `PluginPaths.DATA_FILES`:

```python
"proxy_trust_state": "proxy_trust_state.json",
```

The state loader accepts only schema version `1`, a list of normalized unique `managed_prefixes`, timezone-aware timestamp strings or `null`, non-empty ETag or `null`, stable error code or `null`, and transaction ID or `null`. Missing runtime state loads the packaged default in memory but is written only inside a transaction or successful check-state update.

- [ ] **Step 4: Implement safe resource capture and writes**

Reject symlink targets and parents. Resolve the server config to the exact prefix-adjusted OpenLiteSpeed path supplied by the caller and runtime state beneath the resolved plugin root. Capture bytes, existence, SHA-256, mode, UID, and GID.

Use a module-local atomic writer that creates a temporary regular file in the target directory, writes and fsyncs bytes, applies captured mode and ownership with `os.fchmod` and `os.fchown`, then replaces and fsyncs the parent directory.

- [ ] **Step 5: Implement the journaled transaction**

Create `data/proxy-trust-transactions/<32-hex-id>/` with mode `0700`. Write backup resources and this manifest before canonical writes:

```python
{
    "schema_version": 1,
    "transaction_id": transaction_id,
    "status": "prepared",
    "created_at": timestamp,
    "updated_at": timestamp,
    "server_config_path": str(server_config_path),
    "source": resource_metadata,
    "proposed": proposed_metadata,
    "etag": snapshot["etag"],
    "managed_prefixes": list(plan.managed_prefixes),
    "checked_live": checked_live,
    "reload_required": plan.changed,
}
```

Use statuses exactly as the design spec. Call `plan_proxy_trust_config()` with ownership from current state. After server config write, config test, state writes, and reload, update the manifest atomically at every boundary. A live unchanged result updates state timestamps in the transaction but skips server write and reload.

- [ ] **Step 6: Implement rollback and recovery**

Rollback only when a canonical resource is absent as proposed or its current checksum equals the proposed checksum. Restore exact backups or remove a newly created runtime file. If a new configuration had reached `reloaded`, config-test and reload the restored server configuration before marking rollback complete.

Recovery rules:

```text
prepared/config_written/state_written -> rollback when checksums are known
reloaded + all proposed checksums -> finalize committed
external checksum drift -> recovery_required
multiple incomplete transactions -> manual recovery
```

Every failure response and exception exposes `rolled_back` and `recovery_required` truthfully.

`record_proxy_trust_check_failure()` validates the stable error code, acquires the same deployment lock, atomically updates only `last_checked_at` and `last_error_code`, preserves `last_success_at`, ETag, managed prefixes, snapshot, and server config, and records a non-sensitive audit action. It refuses to write while proxy-trust recovery is blocking.

- [ ] **Step 7: Add retention to P1 checks**

Extend `check_retention_protects_live_state()` to create eight completed and two incomplete proxy-trust transactions. Assert five newest completed remain and both incomplete remain after `prune_proxy_trust_history(..., keep_completed=5)`.

- [ ] **Step 8: Run transaction and P1 gates**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py transaction
python3 tmp/p1_operations_check.py
python3 tmp/p0_deployment_safety_check.py
git diff --check
```

Expected: all commands exit `0`.

---

### Task 5: Integrate CLI, install, upgrade, cron, and uninstall

**Files:**
- Create: `src/ols_geo_access/update_cloudflare.py`
- Modify: `src/ols_geo_access/install.sh:13`
- Modify: `src/ols_geo_access/upgrade.sh:8`
- Modify: `src/ols_geo_access/uninstall_cleanup.py:14`
- Modify: `tmp/cloudflare_proxy_automation_check.py`
- Modify: `tmp/p1_operations_check.py:375`

**Interfaces:**
- Produces CLI modes: `--ensure --allow-packaged-fallback`, `--scheduled`, and `--check-only`.
- Produces: `run(mode, plugin_root, prefix, downloader=download_cloudflare_ranges, now=None) -> dict` for tests and manager reuse.
- Changes `/etc/cron.d/ols-geo-access` to contain isolated daily feed and six-hour Cloudflare schedules.

- [ ] **Step 1: Complete CLI and lifecycle checks**

`check_cloudflare_cli_and_lifecycle()` must create a prefix fixture containing fake OpenLiteSpeed binaries and plugin paths, then assert:

- `--ensure` uses live data when available.
- `--ensure --allow-packaged-fallback` uses the newest valid runtime or packaged snapshot after download failure.
- A fallback result has `fallback_used=True` and leaves `last_success_at` unset.
- `--scheduled` failure exits nonzero, preserves canonical snapshot/config, records a stable last error, and can be retried.
- `--scheduled` unchanged live data exits zero without reload.
- `--check-only` never writes state, config, transaction, or logs through the mutation audit.
- `install.sh` creates both cron lines, invokes ensure without `|| true`, and fails when no valid live or fallback snapshot exists.
- `upgrade.sh` backs up `proxy_trust_state.json`, invokes ensure before panel restart, and restores runtime JSON when ensure fails.
- `uninstall_cleanup.py` leaves global proxy config bytes unchanged and records `proxy_trust_retained=True`.
- Python 3.10 floor, prefix safety, shell syntax, and existing lifecycle checks remain green.

- [ ] **Step 2: Verify CLI selector is red**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py cli
```

Expected: exit `1` because `update_cloudflare.py` and lifecycle integration are missing.

- [ ] **Step 3: Implement CLI parsing and operation flow**

Accept exactly one mode. Resolve:

```python
prefix = Path(os.environ.get("OLS_GEO_ACCESS_PREFIX", "") or "/")
plugin_root = prefix / "www/server/panel/plugin/ols_geo_access"
server_config = prefix / "usr/local/lsws/conf/httpd_config.conf"
```

Reject `..`, symlinks, missing plugin roots, and unavailable OpenLiteSpeed binaries. Configure `OLSAdapter.CONFIG_TEST_COMMAND` and `RELOAD_COMMAND` with prefix-adjusted paths.

For `--ensure`, attempt live preparation first. On approved fallback, choose runtime versus packaged default, then call `apply_proxy_trust_update(..., checked_live=False)`. For live success call it with `checked_live=True`.

For `--scheduled`, never use fallback after a download or validation failure. Call `record_proxy_trust_check_failure()` under the deployment lock, print JSON, and exit `1` without changing canonical snapshot or server config.

For `--check-only`, return candidate counts, ETag, transition decision, and `update_available`; do not call the transaction manager.

- [ ] **Step 4: Update install lifecycle**

Create `data/proxy-trust-transactions` with mode `0700`. Add `proxy_trust_state` to default initialization. Write cron exactly as:

```cron
17 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_feeds.py >> /www/server/panel/plugin/ols_geo_access/logs/feed-update.log 2>&1
23 */6 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_cloudflare.py --scheduled >> /www/server/panel/plugin/ols_geo_access/logs/cloudflare-update.log 2>&1
```

Call:

```sh
"$python_bin" "$plugin_dir/update_cloudflare.py" --ensure --allow-packaged-fallback
```

before the best-effort bot/Jetpack update and before writing successful install audit. Include Cloudflare result in `install-audit.json` rather than logging only the OLS binary.

- [ ] **Step 5: Update upgrade and uninstall behavior**

Include `proxy_trust_state.json` in upgrade backup/restore. Ensure a missing default is initialized, then invoke the same ensure command while the shell restore trap remains active. Only after success remove the trap, prune backups, and restart the panel.

On uninstall, do not call planner or transaction restoration. Add an audit action containing:

```python
{
    "result": "success",
    "proxy_trust_retained": True,
}
```

The shell continues removing `/etc/cron.d/ols-geo-access`.

- [ ] **Step 6: Run CLI and lifecycle checks**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py cli
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/p1_operations_check.py
for file in src/ols_geo_access/*.sh scripts/*.sh; do sh -n "$file" || exit 1; done
git diff --check
```

Expected: all commands exit `0`.

---

### Task 6: Integrate manager APIs, freshness, and publication blocking

**Files:**
- Modify: `src/ols_geo_access/lib/proxy_trust_audit.py:12`
- Modify: `src/ols_geo_access/ols_geo_access_main.py:9`
- Modify: `tmp/cloudflare_proxy_automation_check.py`
- Modify: `tmp/p0_deployment_safety_check.py`

**Interfaces:**
- Produces: `get_cloudflare_trust_status(_request) -> dict`.
- Produces: `check_cloudflare_ranges(_request) -> dict`.
- Produces: `repair_cloudflare_trust(_request) -> dict`.
- Changes: per-domain `ProxyTrustResult` includes snapshot freshness and stale-blocking state.
- Changes: deployment recovery response includes `proxy_trust_recovery` beside managed release recovery.

- [ ] **Step 1: Complete manager contract checks**

`check_manager_proxy_trust_contract()` must assert the exact status shape from the spec, including:

```python
response["cloudflare"] == {
    "freshness": "fresh",
    "last_checked_at": "2026-09-02T00:00:00+00:00",
    "last_success_at": "2026-09-02T00:00:00+00:00",
    "etag": "etag-1",
    "ipv4_count": 3,
    "ipv6_count": 3,
    "configured_count": 6,
    "missing_prefixes": [],
    "stale_prefixes": [],
    "header_state": "trusted_only",
    "recovery_required": False,
    "last_error_code": None,
}
```

Use the six-prefix fixture from Task 1 and matching fixture config. Also assert:

- `check_cloudflare_ranges()` reports update availability but writes nothing.
- `repair_cloudflare_trust()` commits through the transaction and returns reload status.
- Repair refuses recovery-required state.
- A 24–72 hour snapshot is warning but permits publication.
- A snapshot older than 72 hours produces `proxy_prefix_snapshot_stale` and blocks `save_domains`, exception saves, service-source changes, and scheduled feed deployments without changing state or vhosts.
- Manual apply or rollback of an already-built release remains available for recovery and does not build a new release from stale Cloudflare data.
- Direct and `external_origin` assignments remain unaffected by Cloudflare freshness.
- Deployment recovery API reports managed and proxy-trust recovery independently.

- [ ] **Step 2: Verify manager selector is red**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py manager
```

Expected: exit `1` because manager endpoints and freshness integration are absent.

- [ ] **Step 3: Extend proxy result without duplicating parsing**

Add these fields to `ProxyTrustResult`:

```python
snapshot_freshness: str
snapshot_checked_at: str | None
snapshot_blocking: bool
```

Update `audit_proxy_trust()` and `assert_proxy_trust()` to accept a freshness result. For Cloudflare traffic, map blocking freshness to state `proxy_prefix_snapshot_stale` after malformed snapshot errors but before ordinary prefix completeness. Direct and external-origin modes remain `not_required`.

- [ ] **Step 4: Load Cloudflare document and state in manager**

Import and reload `cloudflare_ranges`, `proxy_trust_config`, and `proxy_trust_transaction` alongside existing reloadable modules. Add injectable `cloudflare_downloader=download_cloudflare_ranges` to the constructor. Store paths for packaged default, runtime snapshot, ownership state, and proxy transactions.

Add one `_reload_cloudflare_state()` helper that validates runtime documents and refreshes cached prefixes after a committed repair. Do not leave constructor-only stale caches after a UI update.

Operational freshness is based on the last successful live check, not the packaged snapshot timestamp. Call `snapshot_freshness({"checked_at": state.get("last_success_at")}, now=...)`; a fallback install with `last_success_at=None` therefore remains stale-blocking until the first successful live check.

- [ ] **Step 5: Add status, check, and repair endpoints**

`get_cloudflare_trust_status()` combines snapshot/state freshness, `inspect_global_proxy_config()`, missing desired prefixes, managed prefixes no longer desired, and recovery inspection.

`check_cloudflare_ranges()` downloads and prepares a candidate with the current snapshot as transition baseline. Return Vietnamese error response with stable code; do not write audit mutation state.

`repair_cloudflare_trust()` uses the latest validated runtime snapshot, invokes `apply_proxy_trust_update()`, refreshes cached state, records audit, and returns transaction/reload fields. It never forces a refused live candidate.

- [ ] **Step 6: Integrate recovery and publication gate**

Before managed mutations that build a new release, inspect proxy recovery under the same deployment lock. Refuse when proxy recovery is blocking. Extend `_assert_proxy_trust()` so protected Cloudflare assignments require a valid, non-stale snapshot plus complete global trust. Keep `_deploy_existing_release()` available for manual rollback and application of an already-built release.

Return:

```python
{
    "status": False,
    "code": "cloudflare_snapshot_stale",
    "msg": "Danh sách IP Cloudflare chưa được kiểm tra thành công trong 72 giờ; rule đang chạy không bị thay đổi.",
    "domains": [...],
}
```

Do not alter existing active releases on refusal.

- [ ] **Step 7: Run manager and deployment gates**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py manager
python3 tmp/p0_deployment_safety_check.py
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/p1_operations_check.py
git diff --check
```

Expected: all commands exit `0`.

---

### Task 7: Add Cloudflare status and repair UI

**Files:**
- Modify: `src/ols_geo_access/index.html:1`
- Modify: `tmp/cloudflare_proxy_automation_check.py`
- Modify: `tmp/popup_layout_check.py`

**Interfaces:**
- Consumes manager actions `get_cloudflare_trust_status`, `check_cloudflare_ranges`, and `repair_cloudflare_trust`.
- Produces accessible UI state for fresh, warning, stale-blocking, candidate-refused, update-available, updating, recovery-required, and success states.

- [ ] **Step 1: Complete UI contract checks**

`check_cloudflare_ui_contract()` reads `index.html` and asserts:

- The health tab contains `cloudflare-trust-status`, `cloudflare-check-now`, and `cloudflare-repair` elements.
- Buttons have explicit Vietnamese labels and are disabled while requests run.
- Status rendering includes IPv4, IPv6, configured, missing, last checked, last success, ETag, and last error.
- The stale message states that existing rules remain active while new publication is blocked.
- Recovery-required state hides or disables automatic repair.
- `check_cloudflare_ranges` never implies configuration was changed.
- `repair_cloudflare_trust` success refreshes dashboard, domains, recovery, and Cloudflare status.
- Error output is text-escaped through existing `esc()` rather than inserted as raw HTML.

- [ ] **Step 2: Verify UI selector is red**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py ui
```

Expected: exit `1` because the Cloudflare controls are absent.

- [ ] **Step 3: Add compact health-tab markup**

Add one `.oga-settings` section under system health:

```html
<section class="oga-settings" aria-labelledby="cloudflare-trust-title">
  <h3 id="cloudflare-trust-title">Cloudflare Trusted Proxy</h3>
  <div id="cloudflare-trust-status" aria-live="polite"></div>
  <div class="oga-actions">
    <button id="cloudflare-check-now" type="button">Kiểm tra Cloudflare ngay</button>
    <button id="cloudflare-repair" type="button">Tự động sửa Trusted Proxy</button>
  </div>
</section>
```

Reuse existing styles; add only status-color selectors needed for warning and blocking states.

- [ ] **Step 4: Add deterministic client logic**

Add `loadCloudflareTrust()`, `checkCloudflareNow()`, and `repairCloudflareTrust()` using the existing `api()` wrapper. Render all server strings through `esc()`. Disable both buttons while either request is active. Disable repair when recovery is required or no valid runtime snapshot exists.

On successful repair, call:

```javascript
loadCloudflareTrust();
loadDashboard();
loadDomains();
loadRecovery();
```

Do not automatically trigger repair on tab open; install/cron perform automation and UI remains an explicit recovery surface.

- [ ] **Step 5: Run UI and layout checks**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py ui
python3 tmp/popup_layout_check.py
python3 tmp/save_feedback_ui_check.py
python3 tmp/vietnamese_ui_check.py
git diff --check
```

Expected: all commands exit `0`.

---

### Task 8: Complete documentation, package, and full source gate

**Files:**
- Modify: `README.md:42`
- Modify: `tmp/package_check.py:11`
- Modify: `tmp/self_check.py:1629`
- Package: `dist/ols_geo_access-0.1.0.zip`

**Interfaces:**
- Produces a deterministic ZIP containing all new code/default files and no runtime snapshot, state, transaction, log, secret, cache, or `tmp/` content.
- Produces operator documentation matching actual install, cron, freshness, rollback, recovery, UI, and uninstall behavior.

- [ ] **Step 1: Update README contracts**

Document:

- Automatic trusted-only setup during install and upgrade.
- Public Cloudflare endpoint, no token requirement, and six-hour schedule.
- Packaged fallback behavior.
- No reload for unchanged ETag/prefixes.
- 24-hour warning and 72-hour publication block.
- Transaction rollback and recovery-required behavior.
- UI check and repair controls.
- Uninstall retaining global trusted proxy settings.
- Cloudflare CIDRs never entering Geo Access bypass allowlist.
- Existing `trusted-vps` exception remaining intentional.

- [ ] **Step 2: Strengthen package assertions**

Add these required files:

```python
"ols_geo_access/update_cloudflare.py",
"ols_geo_access/data/proxy_trust_state.default.json",
"ols_geo_access/lib/cloudflare_ranges.py",
"ols_geo_access/lib/proxy_trust_config.py",
"ols_geo_access/lib/proxy_trust_transaction.py",
```

Add forbidden runtime names matching `proxy_trust_state.json`, `proxy-trust-transactions/`, and `cloudflare-update.log` while allowing their `.default.json` and source-code definitions.

- [ ] **Step 3: Run syntax gates**

Run:

```bash
python3 - <<'PY'
import ast
from pathlib import Path
files = sorted(Path("src/ols_geo_access").rglob("*.py"))
for path in files:
    ast.parse(path.read_text(), filename=str(path))
print("python-ast:", len(files), "ok")
PY
for file in src/ols_geo_access/*.sh scripts/*.sh; do sh -n "$file" || exit 1; done
```

Expected: both gates exit `0`.

- [ ] **Step 4: Run focused and full regression gates**

Run:

```bash
python3 tmp/cloudflare_proxy_automation_check.py
python3 tmp/p0_deployment_safety_check.py
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/p1_operations_check.py
python3 tmp/maxmind_check.py
python3 tmp/bot_activity_check.py
python3 tmp/bot_activity_api_check.py
python3 tmp/service_sources_check.py
python3 tmp/self_check.py
python3 tmp/package_check.py
git diff --check
git status --short
```

Expected: every behavioral command exits `0`; status contains only intentional source, spec, plan, and test changes.

- [ ] **Step 5: Independently verify ZIP/source equality**

Open the generated archive with `zipfile`, assert sorted deterministic entries, and compare every entry byte-for-byte with its source path. Confirm no runtime JSON except `.default.json`, no transaction directories, no logs, no secrets, no cache, and no test files are present.

- [ ] **Step 6: Stop for production approval**

Report source-gate results, expected global config change, expected one graceful reload on the current VPS, fallback policy, and rollback location. Do not sync, run upgrade, edit `httpd_config.conf`, or reload production until the user replies `ok` to the rollout summary.

---

### Task 9: Perform controlled production adoption and canary

**Files:**
- Source: `src/ols_geo_access/`
- Package: `dist/ols_geo_access-0.1.0.zip`
- Production after explicit approval: `/www/server/panel/plugin/ols_geo_access/`
- Runtime global config after explicit approval: `/usr/local/lsws/conf/httpd_config.conf`
- Audit artifacts: `tmp/deploy-cloudflare-trust-<timestamp>/`

**Interfaces:**
- Produces verified source/production equality, proxy-trust transaction report, health report, and canary report.

- [ ] **Step 1: Capture production pre-state**

Under a new timestamped directory record:

```text
OLS main PID
openlitespeed -t output, exit code, parsed errors, parsed warnings
httpd_config.conf bytes, mode, UID/GID, and SHA-256
cloudflare_prefixes.json and proxy_trust_state.json checksums
incomplete managed and proxy-trust operations
current.json checksum
33 managed target checksums
/etc/cron.d/ols-geo-access checksum
production packaged-code checksums
```

Require zero `[ERROR]` lines, no blocking recovery, and all 33 managed target checksums matching `current.json` before sync.

- [ ] **Step 2: Backup and sync packaged code only**

Backup every overwritten production code/default/template file under the timestamped directory. Sync archive entries without overwriting:

```text
data/*.json except newly missing defaults
data/secrets/
data/snapshots/
data/release-state/
data/proxy-trust-transactions/
generated/releases/
logs/
tmp/
```

Run `cmp -s` for every archive entry between source and production immediately after sync.

- [ ] **Step 3: Run upgrade ensure under lock**

Execute production `upgrade.sh` with synchronous panel restart disabled unless required by the existing aaPanel workflow. The Cloudflare ensure path must acquire `deployment.lock`, fetch the live source, prepare the candidate, modify global config transactionally, pass config test, and graceful reload once because the current VPS lacks trusted proxy configuration.

Capture JSON output, transaction manifest, before/after global config checksum, OLS PID, config-test output, and reload audit. Graceful reload may retain the main PID; verify process health rather than requiring a PID change.

- [ ] **Step 4: Verify adoption invariants**

Assert:

- Effective header mode is Trusted IP Only.
- All current live Cloudflare CIDRs have `T` trust.
- No Cloudflare CIDR appears in runtime `ip_allowlist.json`.
- Both accepted `trusted-vps` addresses remain in runtime and default allowlists.
- Manual access-control tokens and unrelated global config bytes remain semantically intact.
- Runtime snapshot matches the live endpoint ETag and normalized CIDRs.
- Freshness is `fresh`, recovery is non-blocking, and the transaction is committed.
- Config test has zero `[ERROR]` lines.
- Exactly 33 managed vhost rule checksums remain unchanged by global adoption.
- Cron contains one daily feed job and one six-hour Cloudflare job.
- Package/source/production equality passes for every packaged file.

- [ ] **Step 5: Verify UI-only operation**

Call the production manager endpoints read-only and verify dashboard, domains, Cloudflare status, live check, MaxMind status, service-source status, and both recovery statuses. Confirm all 22 configured Cloudflare websites report trusted and fresh before applying any domain change.

- [ ] **Step 6: Stop for canary approval**

Present one candidate domain and its current assignment, vhost checksum, expected rule change, HTTP verification method, and rollback release. Do not apply the canary until the user approves that domain.

- [ ] **Step 7: Apply and verify one canary**

Apply one approved domain through the plugin API/UI path. Verify one committed managed operation, one applied release transaction, one graceful reload, canonical JSON/current release agreement, expected vhost-only change, real client IP through Cloudflare, direct-origin forged-header resistance, trusted VPS bypass, Jetpack/Wordfence access, crawler access, and bot activity.

- [ ] **Step 8: Expand gradually**

Apply small approved batches. After each batch verify config test, both recovery statuses, current checksum, managed target checksums, Vietnamese client behavior, non-Vietnamese blocking, direct-origin spoof resistance, service allowlists, crawler access, and audit truthfulness.

---

## Final Acceptance Checklist

- [ ] Install and upgrade automatically configure Trusted IP Only and complete Cloudflare CIDRs.
- [ ] The public Cloudflare source is checked every six hours without credentials.
- [ ] Unchanged ETag and prefixes cause no OpenLiteSpeed reload.
- [ ] Candidate validation rejects malformed, broad, overlapping, suspiciously reduced, or explosively expanded data.
- [ ] Global config, runtime snapshot, and ownership state commit or roll back together.
- [ ] Recovery never overwrites externally changed files.
- [ ] Manual trusted entries and unrelated OpenLiteSpeed configuration remain intact.
- [ ] Warning begins after 24 hours and new publication blocks after 72 hours.
- [ ] Existing rules remain active during source failure or stale state.
- [ ] UI provides status, check, repair, and recovery information without requiring SSH/WebAdmin.
- [ ] Uninstall retains global trusted proxy settings and removes scheduled plugin jobs.
- [ ] Cloudflare CIDRs never enter Geo Access bypass allowlists.
- [ ] `45.33.54.225/32` and `51.79.248.182/32` remain in runtime and package defaults.
- [ ] Full P0-A, P0-B, P1, Cloudflare automation, self, syntax, and package gates pass.
- [ ] Production code matches source by `cmp` after approved sync.
- [ ] Production config test contains zero `[ERROR]` lines.
- [ ] All 22 current Cloudflare websites report trusted and fresh before canary.
- [ ] Canary proves canonical state, active release, real client IP, spoof resistance, managed checksums, and running OLS behavior agree.
