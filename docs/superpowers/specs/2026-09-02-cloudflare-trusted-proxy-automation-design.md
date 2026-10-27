# Cloudflare Trusted Proxy Automation Design

**Date:** September 2, 2026
**Status:** Approved September 2, 2026

## Goal

Make Cloudflare client-IP trust fully automatic for OLS Geo Access. A fresh install, plugin upgrade, scheduled CIDR change, or operator-requested repair must configure OpenLiteSpeed safely without requiring SSH or OpenLiteSpeed WebAdmin.

## User Experience

- Fresh installation configures Cloudflare trusted proxy support automatically.
- Upgrade reconciles packaged and current Cloudflare CIDRs automatically.
- A dedicated scheduled job checks Cloudflare every six hours.
- The plugin UI shows freshness, CIDR counts, OpenLiteSpeed trust state, the last error, and whether recovery is required.
- The UI provides **Check now** and **Repair automatically** actions.
- An unchanged Cloudflare response never reloads OpenLiteSpeed.
- Existing rules continue running when a download fails or a candidate is refused.
- New rule publication is blocked when the last successful Cloudflare check is older than 72 hours; the UI begins warning after 24 hours.

## Current State

- `data/cloudflare_prefixes.json` is initialized from the packaged default and is otherwise static.
- `upgrade.sh` does not refresh an existing Cloudflare snapshot.
- `/etc/cron.d/ols-geo-access` runs the bot and Jetpack updater once daily at `03:17`.
- The scheduled updater does not fetch Cloudflare CIDRs.
- Proxy-trust preflight compares OpenLiteSpeed only with the local snapshot, so an old snapshot can look internally consistent.
- The current September 2, 2026 runtime snapshot matches Cloudflare's public endpoint: 15 IPv4 plus 7 IPv6 CIDRs.

## External Source Contract

The primary source is the public, unauthenticated Cloudflare endpoint:

```text
https://api.cloudflare.com/client/v4/ips
```

The updater consumes only:

```json
{
  "success": true,
  "result": {
    "etag": "non-empty digest",
    "ipv4_cidrs": ["canonical IPv4 CIDRs"],
    "ipv6_cidrs": ["canonical IPv6 CIDRs"]
  }
}
```

The request uses HTTPS, a 15-second timeout, a fixed user agent, an `Accept: application/json` header, and a 256 KiB response limit. No Cloudflare account or API token is required.

## Architecture

### Cloudflare Range Source

Create `lib/cloudflare_ranges.py` with four responsibilities:

1. Download the approved endpoint with bounded I/O.
2. Parse and normalize strict IPv4 and IPv6 networks.
3. Validate a candidate against absolute and transition safety policies.
4. Produce a canonical snapshot without writing runtime state.

The module exposes:

```python
download_cloudflare_ranges(opener=urlopen, timeout=15, max_bytes=256 * 1024) -> bytes
prepare_cloudflare_snapshot(payload, previous=None, checked_at=None) -> dict
select_install_fallback(runtime_snapshot, packaged_snapshot) -> dict
snapshot_freshness(snapshot, now=None) -> dict
```

`select_install_fallback()` selects the newest valid snapshot by `checked_at`. It never replaces a newer runtime snapshot with an older packaged snapshot.

### OpenLiteSpeed Configuration Planner

Create `lib/proxy_trust_config.py`. It parses only the top-level server configuration in `/usr/local/lsws/conf/httpd_config.conf` and returns proposed bytes plus a change summary. Planning is side-effect free.

The planner:

- Ensures exactly one effective top-level `useIpInProxyHeader 2` directive.
- Refuses ambiguous duplicate top-level directives.
- Locates exactly one top-level `accessControl` block or appends a new block when none exists.
- Parses existing `allow` tokens without treating nested blocks as global configuration.
- Preserves `ALL`, deny policy, comments, unrelated access-control values, and manually managed trusted IPs.
- Removes a previous CIDR only when it is recorded as plugin-managed.
- Adds every desired Cloudflare CIDR with the LiteSpeed `T` suffix.
- Produces deterministic ordering and an idempotent result.

The module exposes:

```python
plan_proxy_trust_config(
    config_bytes,
    desired_prefixes,
    previously_managed_prefixes,
) -> ProxyTrustPlan
```

`ProxyTrustPlan` contains:

```python
proposed_bytes: bytes
changed: bool
managed_prefixes: tuple[str, ...]
added_prefixes: tuple[str, ...]
removed_prefixes: tuple[str, ...]
preserved_manual_prefixes: tuple[str, ...]
header_changed: bool
```

### Transaction Manager

Create `lib/proxy_trust_transaction.py`. Every mutation uses the existing deployment lock at `data/release-state/deployment.lock` so global proxy-trust updates cannot overlap managed rule deployment.

The transaction covers these resources together:

```text
/usr/local/lsws/conf/httpd_config.conf
data/cloudflare_prefixes.json
data/proxy_trust_state.json
```

Before the first canonical write, create:

```text
data/proxy-trust-transactions/<transaction_id>/manifest.json
data/proxy-trust-transactions/<transaction_id>/httpd_config.conf
data/proxy-trust-transactions/<transaction_id>/cloudflare_prefixes.json
data/proxy-trust-transactions/<transaction_id>/proxy_trust_state.json
```

The manifest records source and proposed checksums, file modes, UID/GID ownership, whether each runtime file existed, the Cloudflare ETag, managed CIDRs, timestamps, and transaction status.

Statuses are:

```text
prepared
config_written
state_written
reloaded
committed
rolled_back
recovery_required
```

The transaction sequence is:

1. Acquire the deployment lock.
2. Recover or refuse an incomplete proxy-trust transaction.
3. Read and checksum all canonical resources.
4. Create the transaction backup and manifest.
5. Atomically write the proposed OpenLiteSpeed configuration while preserving mode and UID/GID ownership.
6. Run `openlitespeed -t` and classify validity by zero `[ERROR]` lines, not exit code alone.
7. Atomically write the snapshot and ownership state.
8. Issue a graceful reload only when OpenLiteSpeed configuration changed.
9. Verify config test again and mark the transaction committed.
10. Retain the five newest completed transactions plus every incomplete transaction.

If any step fails, restore all resources whose current checksum still matches the transaction's proposed checksum, run config test, reload the restored configuration when a new configuration had already been reloaded, and mark the transaction rolled back. External checksum drift or failed restored reload produces `recovery_required` rather than overwriting unknown changes.

### Ownership State

Add `data/proxy_trust_state.json`:

```json
{
  "schema_version": 1,
  "managed_prefixes": [],
  "last_checked_at": null,
  "last_success_at": null,
  "last_etag": null,
  "last_error_code": null,
  "last_transaction_id": null
}
```

Only values in `managed_prefixes` may be automatically removed during a later Cloudflare change. A matching CIDR that existed before adoption remains manual and is never claimed or removed by the plugin.

### Scheduled Command

Create `update_cloudflare.py` as the single CLI entry point for install, upgrade, cron, and diagnostics:

```text
update_cloudflare.py --ensure --allow-packaged-fallback
update_cloudflare.py --scheduled
update_cloudflare.py --check-only
```

`--ensure --allow-packaged-fallback` is used by installation and upgrade. It tries the live endpoint first. On network failure it selects the newest valid runtime or packaged snapshot and still configures OpenLiteSpeed. The result records that fallback data was used.

`--scheduled` downloads the live endpoint. If the ETag and normalized prefix set are unchanged, it updates check freshness without modifying OpenLiteSpeed or reloading. If changed, it runs the full transaction.

`--check-only` performs download and validation without canonical writes or reload.

The cron file contains two isolated schedules:

```cron
17 3 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_feeds.py >> /www/server/panel/plugin/ols_geo_access/logs/feed-update.log 2>&1
23 */6 * * * root /usr/bin/python3 /www/server/panel/plugin/ols_geo_access/update_cloudflare.py --scheduled >> /www/server/panel/plugin/ols_geo_access/logs/cloudflare-update.log 2>&1
```

Bot and Jetpack feeds remain daily. Cloudflare checks run every six hours without causing those feeds to download four times per day.

## Candidate Validation

A Cloudflare candidate is accepted only when all conditions hold:

- `success` is exactly `true`.
- `etag` is a non-empty string.
- Both CIDR arrays are non-empty lists of strings.
- Every network parses with `ipaddress.ip_network(..., strict=True)`.
- IPv4 entries are IPv4 and IPv6 entries are IPv6.
- Networks are canonical, globally routable, unique, and non-overlapping within each family.
- IPv4 prefixes are not broader than `/8`; IPv6 prefixes are not broader than `/24`.
- Total CIDR count is between 6 and 256.
- A transition does not remove more than 50 percent of prefixes in one automatic update.
- Address coverage for either family does not grow beyond four times the previous validated coverage.

An abnormal transition is not force-applied. The UI reports `candidate_refused` with the exact reason. A future design may add explicit UI approval for exceptional source transitions; it is outside this implementation.

## Freshness Policy

- Under 24 hours since the last successful live check: `fresh`.
- From 24 through 72 hours: `warning`; scheduled retries continue and publication remains allowed.
- Over 72 hours: `stale_blocking`; existing rules remain active, but new managed releases and state changes that require rebuilding rules are blocked.
- A packaged fallback configures OpenLiteSpeed during installation but does not count as a successful live check.
- A successful unchanged live response refreshes `last_checked_at` and `last_success_at` without reload.

## Install and Upgrade

### Fresh Install

`install.sh` creates runtime directories and defaults, then calls:

```text
/usr/bin/python3 <plugin>/update_cloudflare.py --ensure --allow-packaged-fallback
```

The install is successful only when the complete transaction commits, including config validation and any required graceful reload. A live network failure is not fatal when a valid packaged snapshot is available. An unsafe or unparseable OpenLiteSpeed configuration is fatal and remains unchanged.

The install audit records live versus fallback source, ETag, config checksum, CIDR counts, reload result, and transaction ID.

### Upgrade

`upgrade.sh` backs up existing runtime JSON before invoking the same ensure command. It does not blindly overwrite `cloudflare_prefixes.json`. Candidate selection prevents snapshot downgrade. Upgrade failure restores plugin runtime files and relies on the proxy-trust transaction to restore global OpenLiteSpeed configuration.

### Repeated Install or Upgrade

The process is idempotent. Matching header mode, managed CIDRs, and snapshot produce no OpenLiteSpeed write and no reload.

## UI and API

Add manager endpoints:

```python
get_cloudflare_trust_status(_request) -> dict
check_cloudflare_ranges(_request) -> dict
repair_cloudflare_trust(_request) -> dict
```

`get_cloudflare_trust_status()` returns:

```json
{
  "status": true,
  "cloudflare": {
    "freshness": "fresh",
    "last_checked_at": "timestamp",
    "last_success_at": "timestamp",
    "etag": "digest",
    "ipv4_count": 15,
    "ipv6_count": 7,
    "configured_count": 22,
    "missing_prefixes": [],
    "stale_prefixes": [],
    "header_state": "trusted_only",
    "recovery_required": false,
    "last_error_code": null
  }
}
```

`check_cloudflare_ranges()` runs a live read-only check and reports whether an update is available. It does not write or reload.

`repair_cloudflare_trust()` uses the latest validated runtime snapshot and runs the full transaction. It does not bypass candidate refusal or recovery-required state.

The UI displays:

- Header trust mode.
- IPv4, IPv6, configured, missing, and stale-managed counts.
- Last check and last successful update times.
- Live, fallback, warning, stale-blocking, candidate-refused, and recovery-required states.
- **Check now** and **Repair automatically** buttons with explicit progress and result messages.

The existing per-domain proxy-trust status remains, but it consumes the global freshness state so a stale snapshot cannot display as fully trusted.

## Audit and Error Codes

All install, upgrade, cron, and UI operations use the existing audit logger. Stable error codes are:

```text
cloudflare_download_error
cloudflare_response_too_large
cloudflare_invalid_format
cloudflare_prefix_too_broad
cloudflare_prefix_overlap
cloudflare_prefix_reduction_exceeded
cloudflare_coverage_growth_exceeded
proxy_config_ambiguous
proxy_config_test_failed
proxy_reload_failed
proxy_rollback_failed
proxy_recovery_required
cloudflare_snapshot_stale
```

Messages shown to users are Vietnamese. Audit records retain stage, error code, error type, checksums, transaction ID, whether rollback succeeded, and whether manual recovery is required. Credentials, response bodies, and unrelated OpenLiteSpeed configuration are not logged.

## Recovery

Every initialization and mutation inspects incomplete proxy-trust transactions while holding the deployment lock.

- Before reload and with matching proposed checksums: restore the previous files.
- After successful reload with all proposed checksums present: finalize and commit.
- With external checksum changes: refuse automatic recovery and show manual recovery required.
- With multiple incomplete transactions: refuse mutation and require manual review.

The UI recovery banner covers managed-rule deployments and proxy-trust transactions separately so the operator knows which global resource is blocked.

## Uninstall Policy

Uninstall removes Geo Access rules, cron files, plugin files, and plugin-owned runtime data, but intentionally leaves `useIpInProxyHeader 2` and Cloudflare trusted CIDRs in global OpenLiteSpeed configuration.

This configuration can serve websites outside the plugin. Automatically removing it could break real-client-IP handling after uninstall. The uninstall audit states that global trusted proxy configuration was retained.

## Security Boundaries

- The plugin never sets `useIpInProxyHeader` to trust all headers.
- Only Cloudflare source CIDRs receive the `T` suffix.
- Geo Access allowlists remain separate; Cloudflare CIDRs never bypass country, path, method, or bot rules.
- Configuration and transaction targets must resolve to the expected prefix-adjusted OpenLiteSpeed and plugin roots, must be regular files or absent runtime files, and must not traverse symlinks.
- The feature does not configure Cloudflare DNS, firewall rules, authenticated origin pulls, tunnels, or origin lockdown.
- Direct-origin requests with forged forwarding headers are not trusted unless their network is explicitly present in the global trusted proxy list.
- The two accepted infrastructure bypass addresses `45.33.54.225/32` and `51.79.248.182/32` remain unchanged in `trusted-vps`.

## Testing Strategy

Create `tmp/cloudflare_proxy_automation_check.py` using temporary plugin roots, temporary OpenLiteSpeed configuration, injected downloaders, and fake adapters. It must cover:

1. Fresh install from a live candidate.
2. Offline install using packaged fallback.
3. Invalid live response falling back without accepting invalid data.
4. Unchanged ETag refreshing timestamps without config write or reload.
5. Changed CIDRs updating snapshot and OpenLiteSpeed once.
6. Repeated ensure being idempotent.
7. Preserving `ALL`, deny policy, comments, and manual trusted entries.
8. Removing only previously plugin-managed stale CIDRs.
9. Refusing duplicate top-level header directives or ambiguous global access-control blocks.
10. Rejecting missing address families, broad prefixes, overlaps, excessive reduction, and excessive coverage growth.
11. Config-test failure restoring configuration, snapshot, and ownership state.
12. Reload failure restoring and reloading the previous configuration.
13. Failed rollback producing recovery-required state.
14. Concurrent proxy update and domain deployment serializing on the same lock.
15. Freshness warning at 24 hours and publication blocking after 72 hours.
16. UI status, check, repair, and recovery contracts.
17. Install and upgrade shell syntax, Python 3.10 floor, cron creation, and audit output.
18. Package/source equality including all new files and excluding runtime state, transactions, logs, and secrets.

Existing P0 and P1 regression checks remain mandatory.

## Production Rollout

1. Run Python AST, shell syntax, Cloudflare automation, P0-A, P0-B, P1, self, and package gates.
2. Capture OLS PID, config test, global config checksum, current release, managed-rule checksums, cron, runtime snapshot, and incomplete operations.
3. Sync code without overwriting runtime JSON, transactions, generated releases, logs, secrets, or temporary files.
4. Run the upgrade ensure command under the deployment lock.
5. Verify zero `[ERROR]` lines, exactly one graceful reload when configuration changes, and rollback readiness.
6. Verify source-to-production equality for packaged files.
7. Verify 22 of 22 current Cloudflare websites report trusted and fresh.
8. Apply one approved canary domain, verify real client IP and direct-origin spoof resistance, then expand gradually.

## Acceptance Criteria

- A user can install and operate the plugin without SSH or OpenLiteSpeed WebAdmin.
- Fresh install automatically configures trusted-only client IP handling and complete Cloudflare CIDRs.
- Cloudflare CIDR changes are detected within six hours and applied transactionally.
- An unchanged response never reloads OpenLiteSpeed.
- Invalid, suspicious, stale, or unavailable upstream data never replaces the last valid configuration.
- Failed config test or reload restores the previous configuration and state.
- Manual trusted entries and unrelated OpenLiteSpeed settings remain intact.
- Snapshot age is visible, warns after 24 hours, and blocks new publication after 72 hours.
- Existing rules remain active during source or update failures.
- Cloudflare CIDRs never enter the Geo Access bypass allowlist.
- Package defaults retain both approved `trusted-vps` addresses.
- Production reaches trusted and fresh state for all configured Cloudflare domains before canary rollout.

## Non-Goals

- Cloudflare account API integration or credentials.
- DNS record changes.
- Firewall or origin-lockdown automation.
- Authenticated Origin Pulls or Cloudflare Tunnel management.
- Automatic detection that a domain is proxied by Cloudflare.
- Automatic approval of a candidate that violates transition safety limits.
- Reverting global trusted proxy configuration during uninstall.
