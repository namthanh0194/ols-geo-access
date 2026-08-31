# OLS Geo Access Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an importable aaPanel third-party plugin that safely manages per-domain OpenLiteSpeed VN-only policies, verified crawler allowlists, staging, validation, apply, and rollback without modifying aaPanel core files.

**Architecture:** The plugin uses aaPanel's existing plugin loader and owns a narrow set of per-domain include files. Python stdlib modules produce immutable releases, validate all external data, and apply changes transactionally only after checksum and OpenLiteSpeed configuration checks.

**Tech Stack:** Python 3 stdlib, shell lifecycle scripts, aaPanel plugin HTML/JavaScript conventions, OpenLiteSpeed native configuration, JSON, MaxMind MMDB files.

## Global Constraints

- Do not modify `/www/server/panel/class/panelSite.py`.
- Do not modify `/www/server/panel/class_v2/panel_site_v2.py`.
- Do not reload or restart OpenLiteSpeed during installation, save, build, or apply.
- Run `/usr/local/lsws/bin/openlitespeed -t` before any reload action.
- Store tests, fixtures, and debug artifacts under `/root/ols-geo-access/tmp/`.
- Use Python stdlib only for 0.1.0.
- Treat IPv4 and IPv6 equally.
- Never trust User-Agent alone.
- Never replace last-known-good feed data with empty or invalid data.
- Modify only plugin-owned include files except through an explicitly approved baseline repair.

---

## File Map

**Plugin metadata and lifecycle**

- `src/ols_geo_access/info.json`: aaPanel plugin metadata.
- `src/ols_geo_access/install.sh`: safe installation and initial audit.
- `src/ols_geo_access/uninstall.sh`: managed-rule cleanup and plugin removal checks.
- `src/ols_geo_access/upgrade.sh`: versioned data migration.
- `src/ols_geo_access/repair.sh`: permission and directory repair only.

**Backend entry point**

- `src/ols_geo_access/ols_geo_access_main.py`: validated aaPanel-facing API methods.

**Core modules**

- `src/ols_geo_access/lib/paths.py`: fixed path allowlist and safe path resolution.
- `src/ols_geo_access/lib/config_store.py`: JSON schema validation and atomic storage.
- `src/ols_geo_access/lib/domain_inventory.py`: aaPanel DB and OLS domain inventory.
- `src/ols_geo_access/lib/proxy_trust_audit.py`: Cloudflare and forwarded-client-IP safety checks.
- `src/ols_geo_access/lib/baseline_audit.py`: read-only config-test parsing.
- `src/ols_geo_access/lib/baseline_repair.py`: approved repair proposal and transaction.
- `src/ols_geo_access/lib/feed_updater.py`: official feed download and validation.
- `src/ols_geo_access/lib/crawler_verifier.py`: prefix normalization and Bing DNS cache.
- `src/ols_geo_access/lib/config_generator.py`: deterministic OLS rule generation.
- `src/ols_geo_access/lib/config_validator.py`: release and managed-file validation.
- `src/ols_geo_access/lib/ols_adapter.py`: fixed OLS commands and output parsing.
- `src/ols_geo_access/lib/transaction.py`: lock, backup, atomic apply, restore.
- `src/ols_geo_access/lib/rollback.py`: release selection and rollback.
- `src/ols_geo_access/lib/audit_log.py`: redacted append-only audit records.

**UI**

- `src/ols_geo_access/index.html`: dashboard, domains, crawlers, exceptions, health, diff, rollback.

**Static and default data**

- `src/ols_geo_access/templates/blocked.html`: static 403 response.
- `src/ols_geo_access/data/*.default.json`: immutable defaults copied on install.

**Checks**

- `tmp/self_check.py`: runnable stdlib test suite.
- `tmp/fixtures/`: fake aaPanel DB, vhosts, feeds, MMDB metadata placeholders, and config-test outputs.

---

### Task 1: Scaffold Importable aaPanel Plugin

**Files:**
- Create: `src/ols_geo_access/info.json`
- Create: `src/ols_geo_access/install.sh`
- Create: `src/ols_geo_access/uninstall.sh`
- Create: `src/ols_geo_access/upgrade.sh`
- Create: `src/ols_geo_access/repair.sh`
- Create: `src/ols_geo_access/ols_geo_access_main.py`
- Create: `src/ols_geo_access/index.html`
- Create: `tmp/self_check.py`

**Interfaces:**
- Produces: importable directory `ols_geo_access/` and backend class `ols_geo_access_main`.

- [ ] **Step 1: Add metadata self-check**

Add a stdlib check that loads `info.json` and asserts:

```python
assert info["name"] == "ols_geo_access"
assert info["versions"] == "0.1.0"
assert info["checks"].endswith("ols_geo_access_main.py")
```

- [ ] **Step 2: Run the check and confirm failure**

Run:

```bash
python3 /root/ols-geo-access/tmp/self_check.py
```

Expected: failure because plugin files do not exist.

- [ ] **Step 3: Create minimal plugin files**

Create valid metadata, lifecycle scripts with `set -eu`, a backend class with a read-only `get_version` method, and a minimal UI that displays plugin version.

- [ ] **Step 4: Validate shell and Python syntax**

Run:

```bash
bash -n src/ols_geo_access/install.sh src/ols_geo_access/uninstall.sh src/ols_geo_access/upgrade.sh src/ols_geo_access/repair.sh
python3 -m py_compile src/ols_geo_access/ols_geo_access_main.py
python3 tmp/self_check.py
```

Expected: all commands exit 0.

### Task 2: Add Fixed Paths and Atomic JSON Store

**Files:**
- Create: `src/ols_geo_access/lib/__init__.py`
- Create: `src/ols_geo_access/lib/paths.py`
- Create: `src/ols_geo_access/lib/config_store.py`
- Create: `src/ols_geo_access/data/config.default.json`
- Create: `src/ols_geo_access/data/domains.default.json`
- Create: `src/ols_geo_access/data/providers.default.json`
- Create: `src/ols_geo_access/data/woo_exceptions.default.json`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: `PluginPaths`, `load_json(name)`, `save_json(name, data)`, and schema validators.

- [ ] **Step 1: Add failing path and schema checks**

Check that unknown file names, absolute user paths, invalid group names, invalid traffic modes, and malformed exception records raise `ValueError`.

- [ ] **Step 2: Implement fixed path resolution**

`PluginPaths` derives all paths from a constructor-supplied plugin root and exposes no arbitrary join method to callers.

- [ ] **Step 3: Implement atomic JSON writes**

Write to a temporary file in the target directory, flush, `os.fsync`, set mode, and replace using `os.replace`.

- [ ] **Step 4: Run self-check**

Run `python3 tmp/self_check.py` and expect all config-store checks to pass.

### Task 3: Build Domain Inventory

**Files:**
- Create: `src/ols_geo_access/lib/domain_inventory.py`
- Modify: `tmp/self_check.py`
- Create: `tmp/fixtures/default.db`
- Create: `tmp/fixtures/openlitespeed/`

**Interfaces:**
- Produces: `DomainRecord` and `collect_domains(db_path, vhost_root)`.

- [ ] **Step 1: Create fixture inventory**

Include active, stopped, direct, proxy, WordPress, WooCommerce, and unknown domains.

- [ ] **Step 2: Add failing inventory assertions**

Assert domain normalization, aaPanel status, `vhRoot`, proxy detection, PHP version, and integration status.

- [ ] **Step 3: Implement read-only inventory**

Read the aaPanel SQLite database and OLS wrappers/details without writing either source.

- [ ] **Step 4: Reject unsafe domain names**

Reject names containing path separators, whitespace, wildcard characters, or control characters.

- [ ] **Step 5: Run fixture self-check**

Expected: deterministic sorted inventory.

### Task 4: Implement OpenLiteSpeed Adapter

**Files:**
- Create: `src/ols_geo_access/lib/ols_adapter.py`
- Modify: `tmp/self_check.py`
- Create: `tmp/fixtures/config-test-error.txt`
- Create: `tmp/fixtures/config-test-warning.txt`

**Interfaces:**
- Produces: `ConfigTestResult`, `run_config_test()`, `reload_gracefully(confirm_token)`.

- [ ] **Step 1: Add parser tests**

Assert the known production fixture parses to 40 errors and 46 warnings. Assert the proposed fixture parses to zero errors and 46 warnings.

- [ ] **Step 2: Implement fixed command execution**

Use argument arrays with `subprocess.run`, no shell, timeout, captured output, and fixed executable paths.

- [ ] **Step 3: Gate reload**

Require a fresh zero-error config test and a server-generated one-time confirmation token.

- [ ] **Step 4: Verify no arbitrary commands**

The self-check must confirm caller input cannot alter the executable or arguments.

### Task 5: Implement Baseline Audit

**Files:**
- Create: `src/ols_geo_access/lib/baseline_audit.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: `audit_baseline()` returning error groups, affected domains, source files, and repair eligibility.

- [ ] **Step 1: Add known-error fixture assertions**

Assert eleven `lsphp00` domains, seven `$host` rules, 33 handler errors, and seven rewrite errors.

- [ ] **Step 2: Implement root-cause grouping**

Group chained handler messages under one root cause per domain instead of exposing 33 unrelated items.

- [ ] **Step 3: Expose read-only API method**

Return structured JSON only; do not return unbounded raw logs.

- [ ] **Step 4: Run audit against production read-only**

Expected: results match the existing snapshot without modifying files.

### Task 5A: Implement Proxy Trust Audit

**Files:**
- Create: `src/ols_geo_access/lib/proxy_trust_audit.py`
- Modify: `src/ols_geo_access/lib/domain_inventory.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `tmp/self_check.py`
- Create: `tmp/fixtures/proxy-trust/`

**Interfaces:**
- Produces: `ProxyTrustResult` and `audit_proxy_trust(domain, traffic_mode)`.

- [ ] **Step 1: Add unsafe and safe fixtures**

Cover missing `useIpInProxyHeader`, trust-all behavior, `Trusted IP Only`, incomplete IPv6 ranges, direct domains, and unknown domains.

- [ ] **Step 2: Implement read-only trust inspection**

Inspect OLS server configuration and trusted lists without sending spoofed production requests.

- [ ] **Step 3: Add publication gate**

Return `blocking=true` for Cloudflare domains unless trusted-only client-IP handling and both IPv4/IPv6 proxy ranges are validated.

- [ ] **Step 4: Expose remediation proposal only**

Display the minimum required configuration difference. Do not apply or reload from the audit method.

- [ ] **Step 5: Run fixture checks**

Expected: direct domains are not blocked by missing Cloudflare trust; unsafe Cloudflare domains are blocked from rule generation.

### Task 6: Implement Baseline Repair Proposal

**Files:**
- Create: `src/ols_geo_access/lib/baseline_repair.py`
- Create: `src/ols_geo_access/lib/transaction.py`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: `build_repair_proposal()`, `apply_repair(proposal_id)`, and `restore_transaction(transaction_id)`.

- [ ] **Step 1: Add failing proposal checks**

Assert the proposal touches exactly 18 approved files, removes PHP blocks only from PHP-00 sites, and replaces exactly seven `$host` values.

- [ ] **Step 2: Implement immutable proposal directory**

Store source checksum, proposed content, unified diff, affected-domain metadata, and creation timestamp.

- [ ] **Step 3: Implement checksum gate**

Refuse apply when any production source checksum differs from the proposal checksum.

- [ ] **Step 4: Implement atomic repair transaction**

Backup exact targets, replace them one at a time, run config test, and restore all targets if any `[ERROR]` remains.

- [ ] **Step 5: Test only against fixture tree**

Do not apply to production in this task. Verify successful and forced-failure rollback paths under `tmp/`.

### Task 7: Implement Official Feed Updater

**Files:**
- Create: `src/ols_geo_access/lib/feed_updater.py`
- Create: `src/ols_geo_access/lib/crawler_verifier.py`
- Modify: `tmp/self_check.py`
- Create: `tmp/fixtures/feeds/`

**Interfaces:**
- Produces: normalized provider snapshots containing source, creation time, prefixes, counts, and checksum.

- [ ] **Step 1: Add feed validation fixtures**

Include valid, empty, malformed, duplicate, IPv4-only, IPv6-only, and unexpectedly reduced feeds.

- [ ] **Step 2: Implement HTTPS download**

Use `urllib.request`, timeouts, bounded response sizes, and explicit accepted source URLs.

- [ ] **Step 3: Normalize CIDRs**

Use `ipaddress.ip_network(..., strict=True)`, deduplicate, sort, and count IPv4/IPv6.

- [ ] **Step 4: Add last-known-good gate**

Reject empty feeds and configurable large prefix-count reductions. Preserve the previous snapshot.

- [ ] **Step 5: Add provider separation**

Store Google, OAI-SearchBot, GPTBot, ChatGPT-User, and Perplexity independently.

- [ ] **Step 6: Implement Bing cache primitives**

Implement pure functions for suffix validation, forward-confirmation comparison, and expiry. Do not perform request-time DNS lookup.

### Task 8: Implement Deterministic Rule Generation

**Files:**
- Create: `src/ols_geo_access/lib/config_generator.py`
- Create: `src/ols_geo_access/lib/config_validator.py`
- Create: `src/ols_geo_access/templates/blocked.html`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: immutable release directory and per-domain managed include files.

- [ ] **Step 1: Add golden output assertions**

Create fixture domains for `NONE`, `VN_ONLY`, and `VN_ONLY_WOOCOMMERCE`. Assert exact generated text and ordering.

- [ ] **Step 2: Implement `NONE`**

Generate no managed file.

- [ ] **Step 3: Implement verified crawler allowlist generation**

Include IPv4 and IPv6 prefixes from enabled last-known-good snapshots.

- [ ] **Step 4: Implement VN country rule**

Require a configured and readable OLS GeoIP database and use the confirmed OLS country-code environment variable.

- [ ] **Step 4A: Implement GeoIP integration proposal**

Generate a separate checksum-gated proposal for the minimum server-level MMDB declaration in `/usr/local/lsws/conf/httpd_config.conf`. Test the proposal against a fixture copy, preserve an exact backup, restore on config-test failure, and never reload automatically.

- [ ] **Step 5: Implement WooCommerce exceptions**

Generate only exact path, method, and source-prefix exceptions. Reject broad path prefixes configured as `/wp-json/` or `/`.

- [ ] **Step 6: Verify deterministic releases**

Two builds from the same inputs must produce identical file checksums.

### Task 9: Implement Managed Integration and Rollback

**Files:**
- Create: `src/ols_geo_access/lib/rollback.py`
- Modify: `src/ols_geo_access/lib/transaction.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: `build_staging()`, `apply_release()`, `list_releases()`, `rollback_release()`.

- [ ] **Step 1: Add ownership tests**

Assert only `00-ols-geo-access.conf` can be written or removed.

- [ ] **Step 2: Implement release metadata**

Record domain assignments, feed checksums, generated checksums, config-test result, and parent release.

- [ ] **Step 3: Implement apply transaction**

Use a process lock, checksum precondition, backup, atomic replacement, production config test, and automatic restore.

- [ ] **Step 4: Implement rollback**

Rollback uses the same transaction path and never reloads automatically.

- [ ] **Step 5: Verify integration-loss detection**

Delete a managed fixture file and assert inventory reports `Integration missing` without silently recreating it.

### Task 10: Implement Audit Logging and Redaction

**Files:**
- Create: `src/ols_geo_access/lib/audit_log.py`
- Modify: all mutating backend modules
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: `record_action(action, metadata)` with redaction and bounded field lengths.

- [ ] **Step 1: Add secret-redaction tests**

Test cookies, authorization values, query tokens, private-key markers, passwords, and MaxMind license keys.

- [ ] **Step 2: Implement append-only JSON lines**

Include timestamp, action, target, checksums, config-test exit, and result.

- [ ] **Step 3: Set safe permissions**

Create logs with mode `0600` and reject symlink log paths.

### Task 11: Build aaPanel UI

**Files:**
- Modify: `src/ols_geo_access/index.html`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`

**Interfaces:**
- Consumes: structured backend APIs from Tasks 3–10.
- Produces: Dashboard, Domains, Crawlers, WooCommerce Exceptions, System Health, Diff, Apply, Reload, and Rollback views.

- [ ] **Step 1: Implement read-only dashboard**

Display service state, config errors/warnings, GeoIP state, feed age, domain counts, and transaction state.

- [ ] **Step 2: Implement domain assignment UI**

Use select controls for fixed enum values. Do not accept arbitrary filesystem paths or rule text.

- [ ] **Step 3: Implement crawler controls**

Display source, creation time, prefix counts, checksum, and previous-release difference.

- [ ] **Step 4: Implement exception editor**

Require exact path, methods, CIDRs, signature-required flag, description, and review date.

- [ ] **Step 5: Implement action confirmation**

Separate Save, Build, Apply, Reload, and Rollback. Reload requires a fresh confirmation token.

- [ ] **Step 6: Verify accessibility and error display**

Use labels, keyboard-operable controls, visible focus, textual status, and non-color-only warnings.

### Task 12: Complete Lifecycle Scripts

**Files:**
- Modify: `src/ols_geo_access/install.sh`
- Modify: `src/ols_geo_access/uninstall.sh`
- Modify: `src/ols_geo_access/upgrade.sh`
- Modify: `src/ols_geo_access/repair.sh`
- Modify: `tmp/self_check.py`

**Interfaces:**
- Produces: safe import, upgrade, repair, and removal behavior.

- [ ] **Step 1: Implement install**

Validate paths and OLS binary, create plugin data directories, copy defaults only when missing, set permissions, and run audit. Do not modify vhosts or reload.

- [ ] **Step 2: Implement uninstall guard**

Exit nonzero when managed rules are active unless an explicit uninstall confirmation flag is present.

- [ ] **Step 3: Implement repair**

Repair only plugin directory structure and permissions. Do not repair OLS vhosts automatically.

- [ ] **Step 4: Implement schema migration**

Upgrade copies data to a backup, migrates one schema version at a time, and restores on failure.

- [ ] **Step 5: Run lifecycle checks in a temporary prefix**

Use environment-overridden fixture roots under `tmp/`; never invoke lifecycle scripts against production during automated checks.

### Task 13: Package and Offline Validate ZIP

**Files:**
- Create: `scripts/package.sh`
- Create: `tmp/package_check.py`

**Interfaces:**
- Produces: `dist/ols_geo_access-0.1.0.zip`.

- [ ] **Step 1: Add package structure check**

Assert one archive root, required files, no `tmp/`, no logs, no credentials, no symlinks, and no files outside `ols_geo_access/`.

- [ ] **Step 2: Implement reproducible package script**

Set deterministic ordering and exclude development artifacts.

- [ ] **Step 3: Run syntax and self-check suite**

Run:

```bash
bash -n src/ols_geo_access/*.sh scripts/package.sh
python3 -m compileall -q src/ols_geo_access
python3 tmp/self_check.py
python3 tmp/package_check.py
```

Expected: all commands exit 0.

### Task 14: Import Without Enabling Rules

**Files:**
- Use package: `dist/ols_geo_access-0.1.0.zip`
- Runtime install: `/www/server/panel/plugin/ols_geo_access/`

**Interfaces:**
- Produces: installed plugin with read-only audit capability.

- [ ] **Step 1: Capture pre-install state**

Record OLS PID, config checksums, plugin directory listing, cron entries, and config-test result.

- [ ] **Step 2: Import through aaPanel Third-party Plug-ins**

Do not enable domain rules or baseline repair.

- [ ] **Step 3: Verify installation side effects**

Confirm OLS PID unchanged, vhost checksums unchanged, no reload occurred, and plugin data directories have safe permissions.

- [ ] **Step 4: Run plugin audit**

Expected: audit reproduces the known baseline errors and offers a repair proposal without modifying production.

### Task 15: Review Baseline Repair Before Production Apply

**Files:**
- Generated proposal under plugin data directory
- Existing production files listed by the proposal

**Interfaces:**
- Produces: reviewed repair transaction ready for a separate approval.

- [ ] **Step 1: Generate production proposal**

Expected: exactly 18 files and the previously reviewed transformations.

- [ ] **Step 2: Compare against audit snapshot**

Compare with `/root/tmp/ols-baseline-20260830T210408+0700/proposed.diff`.

- [ ] **Step 3: Run isolated validation**

Expected: zero `[ERROR]` lines and only known UID/GID warnings.

- [ ] **Step 4: Stop for explicit approval**

Do not apply or reload in this task.

---

## Final Verification Checklist

- [ ] `python3 tmp/self_check.py` exits 0.
- [ ] `python3 tmp/package_check.py` exits 0.
- [ ] All shell scripts pass `bash -n`.
- [ ] All Python files pass `compileall`.
- [ ] Package contains no credentials, logs, backups, or temporary fixtures.
- [ ] Install does not alter OLS configuration or PID.
- [ ] Audit identifies the known baseline errors.
- [ ] Staging does not write production files.
- [ ] Apply cannot run with stale checksums.
- [ ] Apply restores files when config test reports an error.
- [ ] Save, Build, and Apply do not reload OLS.
- [ ] Reload requires a fresh zero-error test and confirmation.
- [ ] Domains absent from the manifest remain untouched.
- [ ] IPv4 and IPv6 feed prefixes are retained.
- [ ] Invalid feeds preserve last-known-good snapshots.
- [ ] User-Agent alone never grants access.
