# OLS Geo Access P0–P1 Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the remaining production blockers in three independently verifiable packages: deployment consistency and Cloudflare trust, lifecycle and feed integrity, then operational reliability.

**Architecture:** All mutating operations use one deployment lock and one operation journal that covers plugin state files, generated OpenLiteSpeed rules, config validation, graceful reload, and recovery. Cloudflare publication is blocked by a read-only preflight; the plugin does not silently edit global OpenLiteSpeed proxy-trust configuration. Scheduled crawler and service-IP updates are prepared before canonical writes, applied once as a combined release, and committed through the same journal.

**Tech Stack:** Python 3.10+ standard library, POSIX shell, aaPanel plugin route, OpenLiteSpeed rewrite rules, JSON state, `fcntl.flock`, stdlib assert-based checks under `tmp/`.

## Global Constraints

- `/root/ols-geo-access` is the only development source.
- Do not edit `/www/server/panel/plugin/ols_geo_access` until the package-specific source gate passes.
- Do not edit `/www/server/panel/class`, `/www/server/panel/class_v2`, or other aaPanel core files.
- All new checks, fixtures, diagnostics, and generated audit artifacts live under `/root/ols-geo-access/tmp/` and are never packaged.
- Do not add a third-party Python, JavaScript, PHP, or shell dependency.
- Do not commit or create a branch unless the user explicitly requests it.
- Treat the current working tree as the baseline. Preserve the in-progress Jetpack and Wordfence work in `lib/service_sources.py`, `update_feeds.py`, `ols_geo_access_main.py`, `index.html`, and `ip_allowlist.default.json`.
- Preserve `trusted-vps` with `45.33.54.225/32` and `51.79.248.182/32` in production data and `ip_allowlist.default.json`. This is an explicitly accepted internal-infrastructure exception.
- Preserve the default `jetpack` and `wordfence-central` entries already present in the working tree.
- Cloudflare preflight may block publication, but this plan does not automatically modify `/usr/local/lsws/conf/httpd_config.conf` or reload OLS solely to repair proxy trust.
- Every production sync requires a fresh OpenLiteSpeed config test with zero `[ERROR]` lines and a source-to-production `cmp` check.
- Never use exit code alone to classify `openlitespeed -t`; use parsed `[ERROR]` lines, matching `ConfigTestResult.valid`.

## Current Baseline That Must Remain Intact

- Production has 33 managed domains and 22 assignments marked `traffic_mode=cloudflare` at the audit date, September 1, 2026.
- The final audit reproduced concurrent-save divergence, SIGKILL drift, pretty-JSON uninstall failure, broad-prefix acceptance, and failed-feed non-retry.
- The working tree already has uncommitted service-source edits. No package in this plan may revert or independently reimplement them.

## Package Boundaries

1. **P0-A — Deployment Safety and Cloudflare Trust**
   - One lock for save, build, apply, config test, reload, and rollback.
   - Recoverable operation journal across config files and managed rules.
   - Cloudflare preflight blocks unsafe publication without altering global OLS configuration.

2. **P0-B — Lifecycle and Feed Integrity**
   - Transactional uninstall and clean reinstall.
   - Prepare crawler and Jetpack updates before writing canonical state.
   - Apply all scheduled source changes in one release.
   - Reject dangerously broad networks and exclude disabled providers.

3. **P1 — Operational Reliability**
   - Exceptions load and apply correctly.
   - MaxMind database replacement restores the old MMDB on downstream failure.
   - Bot activity is byte-bounded and newest-first.
   - Release, transaction, proposal, and backup retention is enforced.
   - Audit records and error messages report the real result.

---

# Package 1: P0-A — Deployment Safety and Cloudflare Trust

## Package 1 Completion Gate

- Concurrent saves cannot produce a stored configuration that differs from the active release.
- A process killed at each journal boundary can be recovered deterministically.
- Recovery never overwrites an externally modified managed file.
- Config test and reload are inside the deployment transaction.
- A Cloudflare assignment cannot publish while proxy trust is missing, trust-all, or prefix-incomplete.
- Direct and `external_origin` assignments remain unaffected by Cloudflare preflight.
- The accepted `trusted-vps` IPs and current Jetpack/Wordfence defaults remain unchanged.

### Task 1: Add P0-A regression checks before implementation

**Files:**
- Create: `tmp/p0_deployment_safety_check.py`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Consumes: current `save_domains()`, `apply_release()`, and `audit_proxy_trust()`.
- Produces: one runnable check covering concurrency, crash recovery, reload failure, Cloudflare blocking, and accepted allowlist invariants.

- [ ] **Step 1: Add the concurrent-save regression**

Create two manager instances sharing one temporary plugin root. Pause request A before rule application, allow request B to enter, then release A. Assert the invariant rather than a particular winner:

```python
assert result_a["status"] is True
assert result_b["status"] is True
stored_group = json.loads(domains_path.read_text())["domains"]["example.com"]["group"]
assert active_release_group == stored_group
```

- [ ] **Step 2: Add crash-boundary regressions**

Kill child processes at these boundaries:

```text
after canonical config save, before target write
after first target write, before config test
after config test, before reload
after reload, before current.json commit
after current.json commit, before operation commit
```

For every boundary, call the recovery API and assert:

```python
assert final_state in {"previous_fully_restored", "proposed_fully_committed"}
assert config_checksum_matches_active_release()
assert no_operation_has_status("applying")
```

- [ ] **Step 3: Add reload-failure regressions**

First reload fails, rollback reload succeeds:

```python
assert response["status"] is False
assert stored_config == previous_config
assert managed_file.read_bytes() == previous_rule
assert operation_manifest["status"] == "rolled_back"
```

Both deployment reload and rollback reload fail:

```python
assert response["status"] is False
assert response["recovery_required"] is True
assert operation_manifest["status"] == "recovery_required"
```

- [ ] **Step 4: Add Cloudflare preflight regressions**

```python
assert preflight("direct", missing_config).blocking is False
assert preflight("external_origin", missing_config).blocking is False
assert preflight("cloudflare", missing_config).state == "proxy_header_mode_missing"
assert preflight("cloudflare", trust_all_config).state == "proxy_header_trust_all"
assert preflight("cloudflare", incomplete_config).state == "trusted_prefixes_incomplete"
assert preflight("cloudflare", trusted_complete_config).blocking is False
```

- [ ] **Step 5: Pin accepted default allowlist behavior**

```python
entries = {item["id"]: item for item in defaults["entries"]}
assert entries["trusted-vps"]["source_prefixes"] == [
    "45.33.54.225/32",
    "51.79.248.182/32",
]
assert entries["trusted-vps"]["domains"] == ["*"]
assert entries["trusted-vps"]["paths"] == []
assert {"jetpack", "wordfence-central"} <= set(entries)
```

- [ ] **Step 6: Run the check and confirm intended failures**

Run:

```bash
python3 tmp/p0_deployment_safety_check.py
```

Expected before implementation: concurrency, recovery, reload reporting, and Cloudflare blocking checks fail. Accepted allowlist assertions pass.

### Task 2: Introduce a deployment-wide lock and operation journal

**Files:**
- Create: `src/ols_geo_access/lib/deployment_journal.py`
- Modify: `src/ols_geo_access/lib/transaction.py`
- Modify: `src/ols_geo_access/lib/rollback.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `tmp/p0_deployment_safety_check.py`

**Interfaces:**
- Produces: `deployment_lock(state_root)`.
- Produces: `begin_operation(plugin_root, state_root, release_id, previous_release, state_changes) -> dict`.
- Produces: `set_operation_status(operation_dir, status, **fields) -> dict`.
- Produces: `incomplete_operations(state_root) -> list[dict]`.
- Changes: `apply_release(release_id, releases_root, vhost_root, state_root, config_test, reload_ols, transaction_id=None, acquire_lock=True, audit=None) -> dict`.
- Produces: `_deploy_state_change(self, *, state_changes, assignments, build_overrides=None, action_name) -> dict`, the shared path for domain, allowlist, service-source, and later exception mutations.

- [ ] **Step 1: Add the deployment lock**

In `lib/transaction.py`:

```python
from contextlib import contextmanager

@contextmanager
def deployment_lock(state_root):
    with process_lock(Path(state_root).resolve() / "deployment.lock"):
        yield
```

Keep `process_lock()` for baseline repair. Managed-release mutation paths use `deployment_lock()`.

- [ ] **Step 2: Define the operation journal schema**

`begin_operation()` creates `data/release-state/operations/<operation_id>/` with mode `0700` and writes:

```json
{
  "schema_version": 1,
  "operation_id": "32-hex-characters",
  "status": "prepared",
  "release_id": "32-hex-characters",
  "previous_release": "previous-id-or-null",
  "state_changes": [
    {
      "relative_path": "data/domains.json",
      "previous_sha256": "hex-or-null",
      "proposed_sha256": "hex"
    }
  ]
}
```

Store previous and proposed bytes under:

```text
operations/<operation_id>/previous/<relative_path>
operations/<operation_id>/proposed/<relative_path>
```

Reject absolute paths, `..`, symlinks, and paths outside the supplied plugin root.

- [ ] **Step 3: Implement explicit operation statuses**

```python
OPERATION_STATUSES = {
    "prepared",
    "state_written",
    "release_applying",
    "release_reloaded",
    "committed",
    "rolled_back",
    "recovery_required",
}
```

Every write is atomic and includes `updated_at`. Terminal failures include sanitized `error_type` and `error`.

- [ ] **Step 4: Move reload inside `apply_release()`**

Use the exact interface `apply_release(release_id, releases_root, vhost_root, state_root, config_test, reload_ols, transaction_id=None, acquire_lock=True, audit=None) -> dict`.

Execution order:

```text
backup targets
write transaction status=applying
write proposed targets
run config test
write transaction status=config_validated
run graceful reload
write transaction status=reloaded
write deployment record
write current.json
write transaction status=applied
```

Only write `current.json` after reload succeeds.

- [ ] **Step 5: Include test and reload in rollback**

On failure after target writes:

```text
restore every backup
run config test on restored files
reload restored configuration
mark transaction rolled_back
re-raise the deployment error
```

If restore, restored test, or restored reload fails, mark `recovery_required` and raise `RecoveryRequired` containing deployment and recovery error types.

- [ ] **Step 6: Add `_deploy_state_change()`**

Use the exact interface `_deploy_state_change(self, *, state_changes, assignments, build_overrides=None, action_name) -> dict`.

The method must:

```text
acquire deployment_lock
recover or reject incomplete operations
load and validate previous bytes
build previous release
build proposed release using in-memory overrides
begin operation journal
write proposed state files
mark state_written
mark release_applying
call apply_release(release_id, releases_root, vhost_root, state_root, config_test, reload_ols, transaction_id=operation_id, acquire_lock=False, audit=audit)
mark release_reloaded
verify state checksums and current release
mark committed
return deployment
```

- [ ] **Step 7: Extend staging with trusted in-memory overrides**

```python
build_overrides = {
    "exceptions": proposed_exception_list,
    "allowlist": proposed_allowlist_entries,
    "snapshots": proposed_snapshot_mapping,
}
```

Missing keys retain disk-backed behavior. External aaPanel requests cannot pass these internal overrides.

- [ ] **Step 8: Route current mutations through the shared path**

Update `save_domains`, `save_ip_allowlist`, `_apply_allowlist`, `update_service_ip_sources`, direct apply, and rollback. Remove duplicate save/build/apply/reload blocks after tests pass. Preserve current service-source behavior.

- [ ] **Step 9: Run focused checks**

```bash
python3 tmp/p0_deployment_safety_check.py
python3 tmp/self_check.py
```

Expected: concurrency and ordinary reload rollback checks pass. Crash recovery completes in Task 3.

### Task 3: Recover interrupted operations

**Files:**
- Modify: `src/ols_geo_access/lib/deployment_journal.py`
- Modify: `src/ols_geo_access/lib/rollback.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/index.html`
- Modify: `tmp/p0_deployment_safety_check.py`

**Interfaces:**
- Produces: `inspect_interrupted_release(plugin_root, state_root, releases_root, vhost_root) -> dict`.
- Produces: `recover_interrupted_release(plugin_root, state_root, releases_root, vhost_root, config_test, reload_ols, acquire_lock=True) -> dict`.
- Produces aaPanel methods: `get_deployment_recovery_status()` and `recover_deployment()`.

- [ ] **Step 1: Detect incomplete work without mutation**

Return:

```python
{
    "blocking": True,
    "operation_id": operation_id,
    "operation_status": status,
    "release_transaction_status": transaction_status,
    "safe_action": "finalize" | "rollback" | "manual",
    "reason": reason,
}
```

Use journal, release manifest, current state, backups, and actual target checksums.

- [ ] **Step 2: Finalize only a fully committed release**

```python
assert current["deployment_id"] == operation_id
assert current["release_id"] == operation["release_id"]
assert all_target_checksums_match_current()
assert all_state_checksums_match_proposed()
```

Then mark release transaction `applied` if needed and operation `committed`. Do not reload again when transaction status is already `reloaded`.

- [ ] **Step 3: Roll back only known previous/proposed states**

Every target must match its previous checksum, proposed checksum, or expected missing state. Restore target and state-file backups, run config test, reload, then mark records `rolled_back`.

- [ ] **Step 4: Refuse ambiguous recovery**

```python
raise RecoveryRequired(
    "Interrupted deployment contains externally modified files; manual review required"
)
```

Never overwrite a file matching neither previous nor proposed checksum.

- [ ] **Step 5: Recover before each mutation**

Inside the deployment lock, safe finalize/rollback happens before a new operation. Ambiguous state blocks the request before release generation.

- [ ] **Step 6: Expose status and recovery UI**

Add `get_deployment_recovery_status()` and `recover_deployment()`. Display operation ID, reason, and a recovery button only for safe finalize/rollback. Manual state shows guidance without a mutation button.

- [ ] **Step 7: Run crash-boundary checks**

```bash
python3 tmp/p0_deployment_safety_check.py
```

Expected: all boundaries recover to a consistent previous or proposed state; external modification refuses automatic recovery.

### Task 4: Enforce Cloudflare trusted-proxy preflight

**Files:**
- Create: `src/ols_geo_access/data/cloudflare_prefixes.default.json`
- Modify: `src/ols_geo_access/lib/paths.py`
- Modify: `src/ols_geo_access/lib/proxy_trust_audit.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/install.sh`
- Modify: `src/ols_geo_access/upgrade.sh`
- Modify: `src/ols_geo_access/index.html`
- Modify: `tmp/p0_deployment_safety_check.py`
- Modify: `tmp/package_check.py`

**Interfaces:**
- Produces: a versioned local Cloudflare prefix snapshot containing IPv4 and IPv6.
- Produces: `assert_proxy_trust(assignments, server_config_text, required_prefixes)`.
- Adds `proxy_trust_state` and `proxy_trust_blocking` to domain API records.

- [ ] **Step 1: Generate the packaged prefix snapshot**

Generate from Cloudflare's official IPv4 and IPv6 endpoints with this exact command:

```bash
python3 - <<'PY'
import ipaddress
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sources = (
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6",
)
networks = []
for source in sources:
    with urllib.request.urlopen(source, timeout=30) as response:
        for line in response.read().decode("ascii").splitlines():
            if line.strip():
                networks.append(ipaddress.ip_network(line.strip(), strict=True))
if {network.version for network in networks} != {4, 6}:
    raise SystemExit("Cloudflare prefix snapshot must contain IPv4 and IPv6")
networks.sort(
    key=lambda network: (
        network.version,
        int(network.network_address),
        network.prefixlen,
    )
)
payload = {
    "schema_version": 1,
    "sources": list(sources),
    "checked_at": datetime.now(timezone.utc).isoformat(),
    "prefixes": [str(network) for network in networks],
}
Path("src/ols_geo_access/data/cloudflare_prefixes.default.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
```

Review that both address families are present. The generated file is then fixed source input; packaging does not fetch the network.

- [ ] **Step 2: Install and preserve the snapshot**

Add it to `PluginPaths.DATA_FILES`. Install copies the default only when absent. Upgrade creates it when missing and preserves a valid existing file.

- [ ] **Step 3: Validate before use**

Reject unsupported schema, empty prefixes, non-strict networks, or a missing address family. Never silently use an empty required-prefix tuple.

- [ ] **Step 4: Block unsafe publication**

Inspect each enabled protected Cloudflare assignment. If any report is blocking, return:

```python
{
    "status": False,
    "code": "proxy_trust_blocking",
    "msg": "Cloudflare client-IP trust is not ready; no rule was changed.",
    "domains": [asdict(report) for report in blocking_reports],
}
```

Do not write JSON, generate a release, touch managed files, or reload OLS.

- [ ] **Step 5: Preserve rollback and recovery**

Preflight applies to new publication and scheduled updates. It does not block rollback or interrupted-operation recovery.

- [ ] **Step 6: Display actionable states**

```text
Trusted
Missing proxy-header mode
Trust-all is unsafe
Trusted prefixes incomplete
Prefix snapshot invalid
```

Show remediation only; do not add an automatic global OLS config editor.

- [ ] **Step 7: Run the P0-A gate**

```bash
python3 tmp/p0_deployment_safety_check.py
python3 tmp/self_check.py
python3 tmp/package_check.py
python3 - <<'PY'
import ast
from pathlib import Path
for path in Path("src/ols_geo_access").rglob("*.py"):
    ast.parse(path.read_text(), filename=str(path))
print("python-ast: ok")
PY
for file in src/ols_geo_access/*.sh scripts/*.sh; do sh -n "$file" || exit 1; done
```

Expected: all commands exit 0.

- [ ] **Step 8: Stop before production sync**

Report the P0-A diff, test output, preserved service-source changes, and the effect that publication may be blocked until Cloudflare trust is configured. Obtain explicit approval before production sync.

---

# Package 2: P0-B — Lifecycle and Feed Integrity

## Package 2 Completion Gate

- Uninstall removes only checksum-owned managed files, validates OLS, reloads, then removes cron.
- Failed uninstall leaves the plugin, cron, state, and managed rules recoverable.
- Reinstall can apply a release without ownership collision.
- Provider and Jetpack updates are combined into one deployment and one reload.
- A failed apply does not publish canonical snapshots or allowlist changes.
- The next cron run retries a previously failed candidate.
- `0.0.0.0/0`, `::/0`, and other prefixes wider than policy are rejected.
- Disabled providers do not contribute prefixes to generated rules.

### Task 5: Add lifecycle and feed-integrity regression checks

**Files:**
- Create: `tmp/p0_lifecycle_feeds_check.py`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Consumes: lifecycle scripts, feed normalizers, scheduled updater, service-source merger, and deployment journal.
- Produces: one runnable gate for uninstall/reinstall, failed-apply retry, broad-prefix rejection, provider filtering, and combined scheduled updates.

- [ ] **Step 1: Add pretty-JSON uninstall regression**

Create a prefixed plugin fixture with active managed files and pretty-printed `current.json`. Run uninstall and assert:

```python
assert result.returncode == 0
assert not managed_rule.exists()
assert not cron_path.exists()
assert config_test_calls == 1
assert reload_calls == 1
```

- [ ] **Step 2: Add uninstall failure rollback regression**

Force config test or reload failure after managed-file removal:

```python
assert result.returncode != 0
assert managed_rule.read_bytes() == original_rule
assert cron_path.exists()
assert current_path.exists()
```

- [ ] **Step 3: Add reinstall regression**

After successful fixture uninstall, run fixture install and apply a release:

```python
assert install.returncode == 0
assert apply_result["status"] == "applied"
assert "ownership collision" not in combined_output
```

- [ ] **Step 4: Add failed scheduled-update retry regression**

First run: candidate Google snapshot differs and apply fails. Second run: the same candidate is presented again.

```python
assert first_run.returncode != 0
assert canonical_snapshot_checksum == old_checksum
assert second_apply_calls == 1
assert second_run.returncode == 0
assert canonical_snapshot_checksum == candidate_checksum
```

- [ ] **Step 5: Add combined provider and Jetpack regression**

When Google and Jetpack both change:

```python
assert deployment_calls == 1
assert reload_calls == 1
assert release_contains_google_candidate()
assert release_contains_jetpack_allowlist_candidate()
assert canonical_google_checksum == candidate_google_checksum
assert canonical_jetpack_prefixes == candidate_jetpack_prefixes
```

- [ ] **Step 6: Add broad-prefix and disabled-provider regressions**

```python
for prefix in ("0.0.0.0/0", "10.0.0.0/8", "::/0", "2001:db8::/16"):
    with assert_raises(ValueError):
        normalize_provider_fixture(prefix)

assert "gptbot" not in enabled_snapshot_names(disabled_gptbot_config)
assert disabled_gptbot_prefix not in generated_rule
```

- [ ] **Step 7: Run the check and confirm intended failures**

```bash
python3 tmp/p0_lifecycle_feeds_check.py
```

Expected before implementation: uninstall, retry, combined-update, broad-prefix, and disabled-provider checks fail.

### Task 6: Make uninstall transactional and reinstall clean

**Files:**
- Create: `src/ols_geo_access/uninstall_cleanup.py`
- Modify: `src/ols_geo_access/uninstall.sh`
- Modify: `src/ols_geo_access/lib/rollback.py`
- Modify: `tmp/p0_lifecycle_feeds_check.py`
- Modify: `tmp/package_check.py`

**Interfaces:**
- Produces: `deactivate_managed_release(vhost_root, state_root, config_test, reload_ols, audit=None)`.
- Produces: a CLI exit code used by `uninstall.sh` before cron removal.

- [ ] **Step 1: Add transactional deactivation**

`deactivate_managed_release()` must:

```text
acquire deployment_lock
recover incomplete operations first
load current.json
verify every managed target exists and matches its recorded checksum
backup every managed target
write deactivation transaction status=applying
remove only managed 00-ols-geo-access.conf files listed in current.json
run config test
reload OLS
write an empty current state
mark transaction applied
```

If a checksum differs, refuse without deleting a file.

- [ ] **Step 2: Restore on failure**

If config test or reload fails, restore every file with its original mode, rerun config test, reload the restored configuration, and leave `current.json` unchanged. Mark the transaction `rolled_back` or `recovery_required` using Package 1 rules.

- [ ] **Step 3: Add the cleanup CLI**

`uninstall_cleanup.py` imports `OLSAdapter` and calls `deactivate_managed_release()` using prefixed plugin and OLS paths derived from `OLS_GEO_ACCESS_PREFIX`. Print one JSON result and exit nonzero on refusal or recovery failure.

- [ ] **Step 4: Reorder `uninstall.sh`**

```text
validate plugin directory
run uninstall_cleanup.py
confirm cleanup exit 0
remove cron
exit 0
```

Remove the `grep` JSON heuristic. Do not remove cron before cleanup succeeds.

- [ ] **Step 5: Run lifecycle regressions**

```bash
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/self_check.py
```

Expected: uninstall, failure rollback, and reinstall checks pass.

### Task 7: Prepare scheduled updates before canonical writes

**Files:**
- Modify: `src/ols_geo_access/lib/feed_updater.py`
- Modify: `src/ols_geo_access/lib/service_sources.py`
- Modify: `src/ols_geo_access/update_feeds.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `tmp/p0_lifecycle_feeds_check.py`

**Interfaces:**
- Produces: `prepare_snapshot(provider, source, payload, previous=None, max_reduction=0.5, created_at=None) -> dict`.
- Produces: `prepare_jetpack_allowlist(current_allowlist, payload, checked_at=None) -> tuple[dict, dict, bool]`.
- Produces: `apply_scheduled_updates(snapshot_candidates, allowlist_candidate=None) -> dict`.

- [ ] **Step 1: Split feed preparation from persistence**

```python
def prepare_snapshot(
    provider,
    source,
    payload,
    previous=None,
    max_reduction=0.5,
    created_at=None,
):
    snapshot = normalize_feed(provider, source, payload, created_at=created_at)
    validate_snapshot_transition(previous, snapshot, max_reduction=max_reduction)
    return snapshot
```

Canonical snapshot writes happen only through the operation journal after successful publication.

- [ ] **Step 2: Make Jetpack preparation pure**

Keep `download_jetpack_feed()` and `normalize_jetpack_feed()`. Add `prepare_jetpack_allowlist()` returning a candidate allowlist and candidate service-state document without saving or applying.

- [ ] **Step 3: Add one combined scheduled deployment**

`apply_scheduled_updates()` must:

```text
acquire deployment lock
recover incomplete operation
load enabled providers and current state
merge current snapshots with candidate snapshots
merge current allowlist with candidate service allowlist
build one proposed release with snapshot and allowlist overrides
journal every changed snapshot, ip_allowlist.json, and state.json
write proposed canonical state
apply, config-test, and reload exactly once
commit journal
```

If no domain is protected, commit validated state files through the journal without generating or reloading a release.

- [ ] **Step 4: Simplify `update_feeds.py`**

```text
download and prepare enabled crawler candidates
download and prepare Jetpack candidate
call apply_scheduled_updates once
print changed and error maps
exit 1 when any source or deployment error exists
exit 0 only when the batch succeeds or nothing changed
```

Remove the current `service_changed` branch that can skip crawler changes when Jetpack also changes.

- [ ] **Step 5: Preserve last-known-good state**

Network failure, malformed source, config-test failure, reload failure, and recovery failure must leave canonical snapshots, allowlist, service state, current release, and managed files in one consistent previous state.

- [ ] **Step 6: Run scheduled-update regressions**

```bash
python3 tmp/p0_lifecycle_feeds_check.py
```

Expected: failed-apply retry and combined Google/Jetpack checks pass.

### Task 8: Reject unsafe feed ranges and filter disabled providers

**Files:**
- Modify: `src/ols_geo_access/lib/feed_updater.py`
- Modify: `src/ols_geo_access/lib/config_generator.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/index.html`
- Modify: `tmp/p0_lifecycle_feeds_check.py`

**Interfaces:**
- Produces: `validate_feed_network(provider, network)`.
- Produces: `enabled_snapshot_names(provider_config) -> Sequence[str]` using `enabled_feeds()`.

- [ ] **Step 1: Enforce minimum network lengths**

```python
MIN_PREFIX_LENGTH = {4: 16, 6: 32}
```

Reject IPv4 networks wider than `/16` and IPv6 networks wider than `/32` for crawler and monitoring feeds.

- [ ] **Step 2: Compare address-space expansion**

Calculate total `network.num_addresses` separately for IPv4 and IPv6. Reject a candidate when either family grows above four times previous covered addresses, unless the previous family count is zero. Keep the 50% prefix-count reduction guard.

- [ ] **Step 3: Exclude disabled providers from staging**

`_build_staging()` loads `providers.json`, obtains `enabled_feeds()`, and includes only matching crawler snapshots. Internal service allowlists remain controlled by `ip_allowlist.json`.

- [ ] **Step 4: Separate source and download age**

Use `created_at` for local last-checked health. Display `source_created_at` separately. Do not reject an unchanged official list solely because its source timestamp is old.

- [ ] **Step 5: Report refusal reasons**

```text
download_error
invalid_format
prefix_too_broad
coverage_growth_exceeded
prefix_reduction_exceeded
deployment_failed
proxy_trust_blocking
```

- [ ] **Step 6: Run the P0-B gate**

```bash
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/p0_deployment_safety_check.py
python3 tmp/self_check.py
python3 tmp/package_check.py
```

Expected: all commands exit 0.

- [ ] **Step 7: Stop before production sync**

Report lifecycle behavior, one-apply scheduled batch behavior, accepted allowlist preservation, and exact source files changed. Obtain explicit approval before syncing Package 2.

---

# Package 3: P1 — Operational Reliability

## Package 3 Completion Gate

- Exceptions load from production state and use the deployment journal when saved.
- MaxMind keeps the old database and credentials active when download, config integration, config test, or reload fails.
- Bot activity stops after a fixed byte budget or enough newest events and reports truncation.
- Current, previous, incomplete, and recovery-required state is never pruned.
- Successful and failed apply, reload, rollback, recovery, feed, MaxMind, and uninstall actions have truthful audit records.
- Install fails clearly when `/usr/bin/python3` is below 3.10.

### Task 9: Add P1 operational regression checks

**Files:**
- Create: `tmp/p1_operations_check.py`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Consumes: exception API, MaxMind updater, bot activity collector, retention functions, audit log, and lifecycle scripts.
- Produces: one runnable P1 gate.

- [ ] **Step 1: Add exception load-and-apply regression**

```python
assert manager.get_exceptions({})["exceptions"] == stored_document
result = manager.save_exceptions({"payload": json.dumps(proposed_document)})
assert result["status"] is True
assert generated_rule_contains_exception()
assert reload_calls == 1
```

- [ ] **Step 2: Add MaxMind restore regressions**

Cover config proposal and reload failure:

```python
assert result["status"] is False
assert database_path.read_bytes() == old_database
assert credentials_path.read_bytes() == old_credentials
assert transaction_manifest["status"] == "rolled_back"
```

- [ ] **Step 3: Add bounded bot-activity regression**

Create logs larger than the byte budget and place matching newest events at the end:

```python
assert activity["events"][0]["timestamp"] == newest_timestamp
assert activity["scanned_bytes"] <= 64 * 1024 * 1024
assert activity["truncated"] is True
assert len(activity["events"]) <= 200
```

- [ ] **Step 4: Add retention protection regression**

Create 20 releases and transactions. Mark current, previous, one applying transaction, and one recovery-required operation. Assert pruning keeps protected IDs and leaves at most ten unprotected completed histories per category.

- [ ] **Step 5: Add truthful audit regression**

```python
assert response["status"] is False
assert audit_record["metadata"]["result"] == "error"
assert audit_record["metadata"]["returncode"] == 1
```

- [ ] **Step 6: Add Python floor regression**

Run fixture install with a `python3` reporting 3.9. Assert nonzero exit and `Python 3.10 or newer is required` on stderr.

- [ ] **Step 7: Run the check and confirm intended failures**

```bash
python3 tmp/p1_operations_check.py
```

Expected before implementation: exception apply, MaxMind restore, bounded scan, retention, truthful audit, and Python floor checks fail.

### Task 10: Make WooCommerce exceptions transactional and loadable

**Files:**
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/index.html`
- Modify: `tmp/p1_operations_check.py`

**Interfaces:**
- Produces: `get_exceptions(_request) -> {"status": True, "exceptions": document}`.
- Changes: `save_exceptions()` returns a deployment and uses `_deploy_state_change()`.

- [ ] **Step 1: Add `get_exceptions()`**

Return the validated `woo_exceptions.json` document without transformation.

- [ ] **Step 2: Route save through the journal**

Use current domain assignments and the proposed exception list as a build override. On success return:

```python
{
    "status": True,
    "exceptions": proposed_document,
    "deployment": deployment,
}
```

On failure preserve previous JSON and active release.

- [ ] **Step 3: Load saved exceptions in the UI**

Replace the hard-coded textarea state with `get_exceptions()`. Only initial load and successful save replace textarea content.

- [ ] **Step 4: Run exception checks**

```bash
python3 tmp/p1_operations_check.py
python3 tmp/p0_deployment_safety_check.py
```

Expected: exception checks and prior deployment checks pass.

### Task 11: Make MaxMind database replacement reversible

**Files:**
- Modify: `src/ols_geo_access/lib/maxmind.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `tmp/p1_operations_check.py`

**Interfaces:**
- Produces: `stage_country_database(credentials_path, staging_root, opener=None) -> dict`.
- Produces: `install_country_database(candidate, destination, config_apply, config_restore, config_test, reload_ols, transactions_root) -> dict`.

- [ ] **Step 1: Split download from live installation**

`stage_country_database()` downloads, size-checks, extracts, validates the metadata marker, writes a `0600` candidate under plugin `tmp/`, and returns:

```python
{
    "candidate_path": str(candidate_path),
    "sha256": checksum,
    "size": len(database),
    "downloaded_at": timestamp,
}
```

It does not modify the live MMDB.

- [ ] **Step 2: Journal live replacement**

Before replacing the live MMDB, create `data/geoip-transactions/<transaction_id>/`, backup the existing database, and record checksum and mode. Replace the database, apply or verify GeoIP config, run config test, and reload.

- [ ] **Step 3: Restore database and config on failure**

```text
restore old MMDB or remove the new file when no old DB existed
restore the GeoIP config transaction when one was created
run config test
reload restored configuration
mark transaction rolled_back
```

- [ ] **Step 4: Preserve old credentials until success**

Stage new credentials separately and use them for candidate download. Replace the live credential file only after database installation succeeds.

- [ ] **Step 5: Remove candidates in terminal paths**

Delete staged archives and candidate MMDB files after committed or rolled-back transactions. Keep transaction backups according to Task 13 retention.

- [ ] **Step 6: Run MaxMind checks**

```bash
python3 tmp/p1_operations_check.py
python3 tmp/maxmind_check.py
```

Expected: success, config failure, reload failure, credential preservation, and cleanup checks pass.

### Task 12: Bound bot-activity work and report truncation

**Files:**
- Modify: `src/ols_geo_access/lib/bot_activity.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/index.html`
- Modify: `tmp/p1_operations_check.py`

**Interfaces:**
- Produces: `_iter_lines_reverse(path, block_size=65536)`.
- Changes: `collect_bot_activity(domains, snapshots, logs_root, since, limit=200, max_scan_bytes=64 * 1024 * 1024) -> dict` returns `scanned_bytes`, `scanned_files`, and `truncated`.

- [ ] **Step 1: Add a reverse-line iterator**

Read regular non-gzip files from the end in 64 KiB blocks. Decode with replacement and yield complete lines newest-first without loading the entire file.

- [ ] **Step 2: Process newest files first**

Sort eligible files by modification time descending. Stop when 200 matching events are collected or the global byte budget reaches 64 MiB.

- [ ] **Step 3: Preserve output order**

Return events newest-first and compute summary from returned events.

- [ ] **Step 4: Return scan metadata**

```python
{
    "scanned_bytes": scanned_bytes,
    "scanned_files": scanned_files,
    "truncated": budget_exhausted,
}
```

- [ ] **Step 5: Display truncation**

When truncated, state that the view contains newest matching events inside a 64 MiB budget and is not a complete count for the selected period.

- [ ] **Step 6: Run performance checks**

```bash
python3 tmp/p1_operations_check.py
python3 tmp/bot_activity_check.py
python3 tmp/bot_activity_api_check.py
```

Expected: all checks pass without reading beyond the byte budget.

### Task 13: Add retention, truthful audit, and runtime preflight

**Files:**
- Modify: `src/ols_geo_access/lib/rollback.py`
- Modify: `src/ols_geo_access/lib/deployment_journal.py`
- Modify: `src/ols_geo_access/lib/config_validator.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/install.sh`
- Modify: `src/ols_geo_access/upgrade.sh`
- Modify: `src/ols_geo_access/data/config.default.json`
- Modify: `README.md`
- Modify: `tmp/p1_operations_check.py`

**Interfaces:**
- Produces: `prune_release_history(releases_root, state_root, keep_completed=10) -> list[str]`.
- Produces: `prune_operation_history(state_root, keep_completed=10) -> list[str]`.
- Produces: `prune_geoip_history(backup_root, keep_completed=5) -> list[str]`.

- [ ] **Step 1: Protect non-prunable state**

Never remove:

```text
current release
previous release
releases referenced by incomplete operations
transactions with applying, reloaded, or recovery_required status
operations with prepared, state_written, release_applying, release_reloaded, or recovery_required status
```

- [ ] **Step 2: Prune only after commit**

After committed managed deployment, retain ten newest unprotected completed releases, release transactions, and operation journals. After committed GeoIP update, retain five completed GeoIP proposals and transactions. Upgrade retains five newest upgrade backups.

- [ ] **Step 3: Pass audit through every mutation**

Build, apply, rollback, recovery, scheduled batch, service source, MaxMind, and uninstall cleanup calls pass `audit=self._audit` or a CLI audit logger.

- [ ] **Step 4: Record reload result after execution**

```python
result = self._adapter.reload_gracefully(token)
self._audit.record_action("ols.reload", {
    "result": "success" if result.returncode == 0 else "error",
    "returncode": result.returncode,
})
```

Return failure for nonzero result; never log success first.

- [ ] **Step 5: Report rollback truthfully**

```python
{
    "status": False,
    "stage": failed_stage,
    "rolled_back": rollback_succeeded,
    "recovery_required": recovery_required,
    "msg": localized_message,
}
```

Do not say the previous configuration was restored unless `rolled_back` is true.

- [ ] **Step 6: Enforce Python 3.10**

At the start of install and upgrade:

```bash
/usr/bin/python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo 'Python 3.10 or newer is required.' >&2
  exit 1
}
```

Keep cron on `/usr/bin/python3` after preflight succeeds.

- [ ] **Step 7: Remove unused keys from fresh defaults**

`config.default.json` becomes:

```json
{
  "auto_update_feeds": true,
  "feed_max_age_hours": 72,
  "schema_version": 1
}
```

Existing files may retain older extra keys. Validators continue ignoring them. Document that `auto_reload`, `blocked_status`, and `emergency_disable` from older installations have no effect.

- [ ] **Step 8: Update README contracts**

Document Python 3.10+, Cloudflare preflight, accepted internal allowlist, transactional uninstall, recovery banner, combined feed batch, 64 MiB bot scan limit, and retention counts.

- [ ] **Step 9: Run full P1 and regression gates**

```bash
python3 tmp/p1_operations_check.py
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/p0_deployment_safety_check.py
python3 tmp/self_check.py
python3 tmp/package_check.py
```

Expected: all commands exit 0.

### Task 14: Final package verification and controlled production rollout

**Files:**
- Package: `dist/ols_geo_access-0.1.0.zip`
- Source: `src/ols_geo_access/`
- Production after approval: `/www/server/panel/plugin/ols_geo_access/`

**Interfaces:**
- Produces: verified ZIP and source/production equality report.

- [ ] **Step 1: Run syntax and package gates**

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
python3 tmp/p0_deployment_safety_check.py
python3 tmp/p0_lifecycle_feeds_check.py
python3 tmp/p1_operations_check.py
python3 tmp/self_check.py
python3 tmp/package_check.py
git diff --check
git status --short
```

Expected: syntax and all checks pass. `git status` may still show intentional working-tree changes and this plan; no unexpected source file appears.

- [ ] **Step 2: Verify package/source equality**

Assert every non-cache source file appears once under `ols_geo_access/`, with no missing, extra, or mismatched content.

- [ ] **Step 3: Capture production pre-sync state**

Under `tmp/deploy-p0-p1-<timestamp>/`, record:

```text
OLS PID
openlitespeed -t output and parsed error count
current.json checksum
managed target checksums
cron checksum
production code checksums
```

- [ ] **Step 4: Stop for production approval**

Do not sync, import, reload, or apply a domain release until the user approves the package and Cloudflare migration effect.

- [ ] **Step 5: Sync only after approval**

Use approved aaPanel ZIP import or the existing controlled source-sync procedure. Do not overwrite runtime paths:

```text
data/*.json
data/secrets/
data/snapshots/
data/release-state/
generated/releases/
logs/
tmp/
```

- [ ] **Step 6: Verify code with `cmp`**

For each packaged code, default, and template file, run `cmp -s` between source and production. Runtime JSON is excluded except newly installed defaults.

- [ ] **Step 7: Verify no sync-time reload**

Confirm OLS PID and managed-rule checksums are unchanged immediately after code sync.

- [ ] **Step 8: Run production read-only health checks**

```text
dashboard
proxy trust audit
deployment recovery status
MaxMind status
service-source status
OpenLiteSpeed config test
```

Expected: no incomplete operation and zero `[ERROR]` lines.

- [ ] **Step 9: Apply one canary after Cloudflare trust is ready**

Choose one approved domain. Verify one committed operation, one applied release transaction, one reload, matching canonical config and active release, and no unexpected vhost change.

- [ ] **Step 10: Expand rollout gradually**

After each small batch verify config test, recovery status, current checksum, HTTP behavior from a Vietnamese client, direct-origin spoof resistance for Cloudflare domains, Jetpack/Wordfence access, crawler access, and bot activity.

---

## Deferred Items Outside These Packages

- No Cloudflare API integration.
- No automatic firewall management or origin lockdown.
- No aaPanel marketplace publication.
- No new database or external queue.
- No UI redesign beyond recovery, proxy-trust, feed-error, and truncation states required by these fixes.
- No unrelated baseline-repair refactor.

## Final Acceptance Checklist

- [ ] P0-A deployment safety gate passes.
- [ ] P0-A Cloudflare publication blocks unsafe trust states.
- [ ] P0-B uninstall/reinstall gate passes.
- [ ] P0-B scheduled updates apply once and retry after failure.
- [ ] P0-B rejects broad prefixes and excludes disabled providers.
- [ ] P1 exceptions, MaxMind, bounded logs, retention, audit, and Python floor gates pass.
- [ ] `trusted-vps`, Jetpack, and Wordfence defaults remain present exactly as approved.
- [ ] Package contains no runtime data, secrets, logs, backups, or `tmp/` files.
- [ ] Production code matches source by `cmp` after approved sync.
- [ ] OpenLiteSpeed config test contains zero `[ERROR]` lines.
- [ ] No incomplete or recovery-required deployment exists.
- [ ] One canary proves canonical JSON, current release, managed checksum, and running OLS behavior agree.
