# MaxMind GeoIP Download Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Let an aaPanel administrator save MaxMind credentials and manually download a validated GeoLite2 Country database from the plugin UI.

**Architecture:** A new `lib/maxmind.py` owns root-only credential persistence and archive download validation. The existing plugin backend exposes write-only credential status, save, and update endpoints; `System Health` presents the inputs and update result. The download replaces only the configured MMDB path atomically and never reloads OLS.

**Tech Stack:** Python 3 standard library (`urllib`, `tarfile`, `tempfile`), aaPanel plugin AJAX, HTML/CSS/JavaScript.

## Global Constraints

- Do not modify aaPanel core files.
- Do not return, log, package, or display the license key after submission.
- Store credentials outside the ZIP with directory mode `0700` and file mode `0600`.
- Do not add dependencies, schedules, OLS rule changes, or automatic reloads.
- Place tests and test artifacts under `tmp/`.

### Task 1: Credential and downloader module

**Files:**
- Create: `src/ols_geo_access/lib/maxmind.py`
- Test: `tmp/maxmind_check.py`

- [ ] Write a failing test for write-only status and safe local archive extraction.
- [ ] Run `python3 tmp/maxmind_check.py`; expect import failure before implementation.
- [ ] Implement validation, atomic secret writes, Basic Authentication download, safe `tar.gz` member selection, MMDB validation, and atomic replacement.
- [ ] Run `python3 tmp/maxmind_check.py`; expect pass.

### Task 2: Plugin API and UI

**Files:**
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/index.html`
- Modify: `src/ols_geo_access/install.sh`
- Test: `tmp/maxmind_check.py`

- [ ] Extend the failing test for API methods without secret disclosure.
- [ ] Add status, save credential, and manual update API methods; create the secret directory during install.
- [ ] Add Account ID, password License key, save, and update controls to System Health.
- [ ] Verify the UI contract and API regression tests pass.

### Task 3: Package and production sync

**Files:**
- Modify: installed plugin equivalents under `/www/server/panel/plugin/ols_geo_access`
- Test: `tmp/maxmind_check.py`, `tmp/self_check.py`, `tmp/package_check.py`

- [ ] Copy only source changes into the installed third-party plugin.
- [ ] Run focused and existing checks.
- [ ] Rebuild the ZIP and verify source-installed parity.
