# OLS Geo Access Manager Design

**Date:** 2026-08-30

**Status:** Approved for implementation planning

## 1. Objective

Build an aaPanel third-party plugin named `OLS Geo Access Manager` (`ols_geo_access`) that manages per-domain OpenLiteSpeed access policies without modifying aaPanel core Python files.

The plugin must support:

- `NONE`
- `VN_ONLY`
- `VN_ONLY_WOOCOMMERCE`
- Verified crawler allowlists from official sources
- Per-domain enable/disable
- Staged generation, configuration validation, explicit apply, explicit reload, and one-click rollback
- Baseline OpenLiteSpeed error detection and separately approved repair

## 2. Non-Goals for 0.1.0

- No CrowdSec installation or management.
- No nftables, iptables, or UFW automation.
- No Cloudflare API integration.
- No automatic payment-provider discovery.
- No automatic OpenLiteSpeed reload.
- No multi-server management.
- No public aaPanel marketplace publishing.
- No modification of `/www/server/panel/class/panelSite.py` or `/www/server/panel/class_v2/panel_site_v2.py`.

## 3. Current Server Constraints

- Ubuntu 22.04.5 LTS.
- OpenLiteSpeed 1.8.4.
- aaPanel UI reports 8.0.6; the local version file did not independently confirm it.
- OpenLiteSpeed includes aaPanel-managed files from `/www/server/panel/vhost/openlitespeed/`.
- Seventy-seven OLS vhost files exist.
- Current production config test returns exit code 2 with 40 errors and 46 warnings.
- Thirty-three errors originate from eleven `lsphp00` handlers.
- Seven errors originate from reverse-proxy rules containing `E=Proxy-Host:$host`.
- OpenLiteSpeed has native MaxMind MMDB support, but no server-level MMDB declaration was found.
- IPv4 and IPv6 are public and must both be enforced.
- Some domains use Cloudflare; some resolve directly to the origin.

## 4. Safety Invariants

The plugin must enforce these invariants:

1. Saving settings never reloads or restarts OpenLiteSpeed.
2. Applying generated files requires a successful pre-apply validation.
3. Reload is a separate action with explicit confirmation.
4. A failed post-write config test restores the previous files immediately.
5. The plugin modifies only files it owns unless the user explicitly approves a baseline repair diff.
6. The plugin never trusts User-Agent alone for crawler verification.
7. Empty, malformed, stale, or unexpectedly reduced provider feeds never replace last-known-good data.
8. Domains absent from the manifest retain current behavior.
9. IPv4 and IPv6 are treated equally.
10. No private key, API secret, payment signature secret, or MaxMind license key is written to plugin logs.
11. A Cloudflare domain cannot enable a country rule until trusted-proxy validation passes.
12. Server-level GeoIP integration is a separately approved checksum-gated proposal; it is never added during plugin installation.

## 5. Plugin Location and Package

Development source:

```text
/root/ols-geo-access/
```

Installed location:

```text
/www/server/panel/plugin/ols_geo_access/
```

Import archive:

```text
ols_geo_access-0.1.0.zip
```

The archive contains one root directory named `ols_geo_access`.

## 6. File Architecture

```text
ols_geo_access/
├── info.json
├── install.sh
├── uninstall.sh
├── upgrade.sh
├── repair.sh
├── icon.png
├── index.html
├── ols_geo_access_main.py
├── lib/
│   ├── paths.py
│   ├── config_store.py
│   ├── domain_inventory.py
│   ├── baseline_audit.py
│   ├── baseline_repair.py
│   ├── feed_updater.py
│   ├── crawler_verifier.py
│   ├── config_generator.py
│   ├── config_validator.py
│   ├── ols_adapter.py
│   ├── transaction.py
│   ├── rollback.py
│   └── audit_log.py
├── templates/
│   └── blocked.html
├── data/
│   ├── config.json
│   ├── domains.json
│   ├── providers.json
│   ├── woo_exceptions.json
│   └── state.json
├── generated/
│   ├── staging/
│   ├── releases/
│   ├── current
│   └── previous
├── logs/
│   ├── audit.log
│   ├── updater.log
│   └── config-test.log
└── tmp/
```

Each module has one responsibility. No framework or new Python dependency is required.

## 7. aaPanel Integration

The plugin follows the installed aaPanel plugin pattern:

- `info.json` describes the plugin.
- `ols_geo_access_main.py` exposes backend methods through aaPanel's plugin loader.
- `index.html` provides the management UI.
- `install.sh`, `upgrade.sh`, `repair.sh`, and `uninstall.sh` manage lifecycle operations.

The plugin must not import or monkey-patch aaPanel site generator classes.

Before enabling a Cloudflare domain, the plugin audits `useIpInProxyHeader`, the trusted proxy list, and IPv4/IPv6 Cloudflare ranges. An unsafe or unknown trust state blocks rule publication for that domain.

## 8. Managed OpenLiteSpeed Files

For a protected domain, the plugin owns only these files:

```text
/www/server/panel/vhost/openlitespeed/proxy/<domain>/00-ols-geo-access.conf
/www/server/panel/vhost/openlitespeed/proxy/<domain>/urlrewrite/00-ols-geo-access.conf
```

Rules:

- The plugin may create, replace, or remove only `00-ols-geo-access.conf`.
- Existing aaPanel proxy files remain untouched.
- The plugin records checksums for all managed files.
- If aaPanel removes a managed file, the plugin reports `Integration missing`; it does not silently recreate the file unless an approved repair action runs.
- Domain `NONE` has no managed include file.

## 9. Data Model

### 9.1 Global Configuration

```json
{
  "schema_version": 1,
  "emergency_disable": false,
  "auto_update_feeds": false,
  "auto_reload": false,
  "blocked_status": 403,
  "feed_max_age_hours": 72
}
```

`auto_reload` is fixed to `false` in 0.1.0 and rejected if changed through an API request.

### 9.2 Domain Assignment

```json
{
  "schema_version": 1,
  "domains": {
    "example.com": {
      "group": "VN_ONLY",
      "traffic_mode": "direct",
      "enabled": true
    },
    "shop.example.com": {
      "group": "VN_ONLY_WOOCOMMERCE",
      "traffic_mode": "cloudflare",
      "enabled": true
    }
  }
}
```

Allowed values:

- Group: `NONE`, `VN_ONLY`, `VN_ONLY_WOOCOMMERCE`
- Traffic mode: `direct`, `cloudflare`, `external_origin`, `unknown`

### 9.3 Provider Configuration

```json
{
  "schema_version": 1,
  "google": {
    "googlebot": true,
    "special_crawlers": false,
    "user_triggered_fetchers": false
  },
  "openai": {
    "oai_searchbot": true,
    "gptbot": false,
    "chatgpt_user": true,
    "oai_adsbot": false
  },
  "perplexity": {
    "perplexitybot": true
  },
  "bing": {
    "mode": "verified_dns_cache"
  }
}
```

### 9.4 WooCommerce Exception

```json
{
  "id": "provider-domain-purpose",
  "domain": "shop.example.com",
  "provider": "provider-name",
  "paths": ["/exact/callback/path"],
  "methods": ["POST"],
  "source_prefixes": ["203.0.113.0/24", "2001:db8::/48"],
  "signature_required": true,
  "review_after": "2026-11-30",
  "description": "Payment callback"
}
```

The plugin never stores the signature secret.

## 10. Rule Semantics

### 10.1 `NONE`

- No generated rule.
- Existing domain behavior remains unchanged.

### 10.2 `VN_ONLY`

Evaluation order:

1. Emergency disable: allow current behavior.
2. Required ACME path: allow.
3. Explicit health-check exception: allow.
4. Verified crawler source: allow.
5. GeoIP country equals `VN`: allow.
6. All other requests: static 403.

### 10.3 `VN_ONLY_WOOCOMMERCE`

Evaluation order:

1. Emergency disable.
2. Exact provider exception with matching path, method, and source prefix.
3. Internal cron from validated local/origin source.
4. Verified crawler for public `GET` or `HEAD` requests.
5. GeoIP country equals `VN`.
6. Static 403.

The following paths are never globally exempted:

- `/wp-json/`
- `/wp-json/wc/`
- `/wp-admin/admin-ajax.php`
- `/xmlrpc.php`
- `/wp-login.php`
- Any generic `wc-api` request

## 11. Verified Crawler Design

### Google

- Download official Google JSON prefix feeds.
- Validate HTTPS, JSON schema, creation time, prefix count, IPv4, and IPv6.
- Runtime uses generated CIDR snapshots, not synchronous DNS.

### OpenAI

- Use official feeds for `OAI-SearchBot`, `GPTBot`, and `ChatGPT-User`.
- Keep each bot separately configurable.
- Keep `GPTBot` disabled by default.
- Keep `OAI-AdsBot` disabled until an independently verifiable official source exists.

### Perplexity

- Use the official PerplexityBot JSON feed.
- User-Agent remains a consistency signal only.

### Bing

- Maintain an asynchronous verified-IP cache.
- Reverse-resolve candidate IP.
- Require an official Bing/Microsoft hostname suffix.
- Forward-resolve the hostname.
- Require the original IP in the forward result.
- Cache the verified IP with expiry.
- Never perform blocking DNS verification in the request path.

## 12. GeoIP Design

The plugin manages a dedicated country database:

```text
/var/lib/ols-geoip/releases/<release>/GeoLite2-Country.mmdb
/var/lib/ols-geoip/current
/var/lib/ols-geoip/previous
```

Requirements:

- Do not use a WordPress plugin database.
- Do not overwrite aaPanel's internal MMDB.
- Validate MMDB readability before generation.
- Use least-privilege ownership and mode.
- Update through a temporary file and atomic release switch.
- Keep last-known-good database.
- Refuse publication when the database is missing or unreadable.

The initial plugin release detects and reports the required server-level OLS MMDB declaration but does not automatically reload after adding it.

## 13. Baseline Audit and Repair

Baseline audit is always read-only and reports:

- OLS config test exit code.
- Error and warning counts.
- `lsphp00` handlers.
- Invalid `$host` proxy rules.
- Missing include directories.
- Domain status and root mapping.
- Managed-file integrity.

Baseline repair is a separate workflow:

1. Generate a repair proposal.
2. Capture source checksums.
3. Display exact unified diff.
4. Require explicit approval.
5. Recheck source checksums.
6. Backup affected files.
7. Apply atomically.
8. Run config test.
9. Restore immediately if new errors exist.
10. Mark `APPLIED_NOT_RELOADED` on success.

The initial known repair removes invalid PHP blocks from eleven PHP-00 proxy sites and replaces seven literal `$host` values with their fixed domain names.

## 14. Transaction State Machine

```text
IDLE
AUDITED
STAGING_READY
VALIDATED
APPLIED_NOT_RELOADED
ACTIVE
ROLLBACK_READY
ERROR
```

Allowed transitions:

```text
IDLE → AUDITED
AUDITED → STAGING_READY
STAGING_READY → VALIDATED
VALIDATED → APPLIED_NOT_RELOADED
APPLIED_NOT_RELOADED → ACTIVE
ACTIVE → ROLLBACK_READY
ROLLBACK_READY → APPLIED_NOT_RELOADED
Any state → ERROR
ERROR → AUDITED
```

No direct `AUDITED → ACTIVE` transition exists.

## 15. Validation and Apply

Build flow:

```text
read configuration
→ validate schema
→ validate domain inventory
→ validate official feed snapshots
→ generate release directory
→ check owned paths
→ run isolated config test
→ calculate checksums
→ mark STAGING_READY
```

Apply flow:

```text
acquire lock
→ verify production checksums
→ backup targets
→ write temporary files
→ fsync
→ os.replace
→ run production config test
→ restore on failure
→ mark APPLIED_NOT_RELOADED
```

Reload flow:

```text
explicit confirmation
→ fresh config test
→ graceful reload
→ service/process health check
→ selected domain health checks
→ mark ACTIVE or offer rollback
```

## 16. Command and Path Allowlist

Allowed executable commands are fixed in backend code:

```text
/usr/local/lsws/bin/openlitespeed -t
/usr/local/lsws/bin/lswsctrl reload
/usr/bin/systemctl is-active lshttpd
```

The UI cannot submit shell commands or filesystem paths.

Writable roots are limited to:

```text
/www/server/panel/plugin/ols_geo_access/
/www/server/panel/vhost/openlitespeed/proxy/<known-domain>/
/var/lib/ols-geoip/
```

Baseline repair additionally allows an exact precomputed list of files shown in the approved diff.

Server-level GeoIP integration may modify `/usr/local/lsws/conf/httpd_config.conf` only through a separate, displayed, checksum-gated proposal that adds the minimum required MMDB declaration. This is OpenLiteSpeed configuration, not aaPanel core code. The action backs up the file, runs config validation, restores on failure, and never reloads automatically.

## 17. UI Design

### Dashboard

- OLS version and service status
- Production config test status
- GeoIP database state
- Provider feed state and age
- Domain counts by rule group
- Pending staging/apply/reload state
- Last rollback point

### Domains

- Domain
- aaPanel status
- Direct/Cloudflare classification
- Application type
- Rule Group
- Managed integration status

### Rule Groups

- Read-only definitions for built-in groups in 0.1.0
- Group behavior preview

### Crawlers

- Provider toggle
- Source URL label
- Last update
- Creation time
- Prefix count
- IPv4/IPv6 counts
- Checksum
- Diff from previous release

### WooCommerce Exceptions

- Explicit provider records
- Exact path and method
- CIDR validation
- Review date
- No broad REST API switch

### System Health

- Baseline audit
- Repair proposal
- Unified diff
- Config test output
- Apply and rollback actions

## 18. Logging

Audit entries contain:

- Timestamp
- aaPanel user/session identity when available
- Action
- Domain/group
- Source and target checksum
- Config test exit code
- Result

Logs exclude:

- Cookies
- Authorization headers
- Query tokens
- Private keys
- Payment secrets
- MaxMind license keys

## 19. Installation and Uninstallation

### Install

- Validate aaPanel plugin directory.
- Validate OpenLiteSpeed binary and config paths.
- Create data/log/generated directories.
- Set permissions.
- Run read-only initial audit.
- Do not modify vhosts.
- Do not create cron unless enabled by the user.
- Do not reload services.

### Uninstall

- Refuse removal while managed rules are active unless the user rolls them back or explicitly confirms removal.
- Remove only plugin-owned include files.
- Preserve backup releases by default.
- Remove plugin cron entries.
- Do not reload automatically.

## 20. Success Criteria for 0.1.0

- The ZIP imports as an aaPanel third-party plugin.
- The UI opens without changing production configuration.
- Audit reproduces the current 40 errors and identifies their two root causes.
- A baseline repair proposal matches the reviewed 18-file diff.
- A staging build never writes production files.
- Invalid or empty feeds cannot replace last-known-good feeds.
- The plugin cannot modify an unknown domain or path.
- Apply restores automatically on config-test failure.
- Save and Apply never reload OLS.
- Reload requires a separate confirmation.
- Uninstall does not leave an active inaccessible configuration.
