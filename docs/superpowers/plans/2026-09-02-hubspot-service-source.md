# HubSpot Service IP Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HubSpot EGRESS/API CIDRs as an automatically maintained global service-source allowlist.

**Architecture:** Extend the existing service-source module with a bounded HubSpot JSON downloader, strict EGRESS/API parser, generic managed-entry merge, and shared scheduled deployment. Seed the package default with the current five official CIDRs and surface HubSpot in the existing UI and traffic classification.

**Tech Stack:** Python 3.10+, aaPanel plugin API, OpenLiteSpeed rewrite rules, assert-based checks in `tmp/`.

## Global Constraints

- Source changes live only under `/root/ols-geo-access` until every gate passes.
- Accept only canonical public CIDRs where `direction=EGRESS` and `service=API`.
- Keep `45.33.54.225/32` and `51.79.248.182/32` unchanged.
- Preserve atomic deployment, rollback, 64 KiB response limit, and daily updater behavior.
- Place all new checks and temporary artifacts under `tmp/`.

---

### Task 1: HubSpot Feed Parser

**Files:**
- Modify: `src/ols_geo_access/lib/service_sources.py`
- Test: `tmp/service_sources_check.py`

- [ ] Add failing assertions for source filtering, canonical CIDRs, invalid JSON, empty API results, and oversized downloads.
- [ ] Implement `download_hubspot_feed()` and `normalize_hubspot_feed()` with strict bounded validation.
- [ ] Run `python3 tmp/service_sources_check.py` until green.

### Task 2: Managed Allowlist and Scheduler

**Files:**
- Modify: `src/ols_geo_access/lib/service_sources.py`
- Modify: `src/ols_geo_access/ols_geo_access_main.py`
- Modify: `src/ols_geo_access/update_feeds.py`
- Modify: `src/ols_geo_access/data/ip_allowlist.default.json`
- Test: `tmp/service_sources_check.py`
- Test: `tmp/p0_lifecycle_feeds_check.py`

- [ ] Add failing assertions for HubSpot default entry, state, manager update, and scheduled combined deployment.
- [ ] Merge HubSpot with Jetpack candidates before one atomic allowlist deployment.
- [ ] Run focused service and lifecycle checks until green.

### Task 3: UI and Traffic Classification

**Files:**
- Modify: `src/ols_geo_access/index.html`
- Test: `tmp/service_sources_check.py`
- Test: `tmp/traffic_activity_check.py`

- [ ] Add failing UI and activity assertions for HubSpot.
- [ ] Show HubSpot as automatic source and add its update button.
- [ ] Verify HubSpot requests appear as `service` in the unified activity log.

### Task 4: Verification and Production Sync

**Files:**
- Modify: `dist/ols_geo_access-0.1.0.zip`
- Sync packaged files to: `/www/server/panel/plugin/ols_geo_access`

- [ ] Run syntax, focused, P0, P1, Cloudflare, self, UI, and package gates.
- [ ] Rebuild deterministic package and verify source/archive equality.
- [ ] Back up and sync packaged files without changing runtime JSON or managed rules.
- [ ] Restart aaPanel, compare every packaged file, and call HubSpot manager endpoints through `panelPlugin.a()`.
