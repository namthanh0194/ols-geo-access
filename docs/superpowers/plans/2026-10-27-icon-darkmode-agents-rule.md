# Icon, Auto Dark Mode, Dynamic Packaging, and AGENTS.md Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a crisp Lucide Globe Lock plugin icon, automatic dark/light theme switching following aaPanel, dynamic version packaging via `scripts/package.sh`, and hardened `AGENTS.md` rules with zero writes to production `/www/server/panel/plugin/ols_geo_access`.

**Architecture:** Render a dedicated high-DPI 128x128 PNG icon locally with Lucide Globe Lock vectors; implement scoped CSS variable theming in `index.html` responding to aaPanel's dark markers (`html.dark`, `[theme-mode=dark]`, `[data-theme=dark]`, and system `prefers-color-scheme`) with a `MutationObserver`; parameterize `scripts/package.sh` to read `info.json` directly; and encode workflow rules into `AGENTS.md`.

**Tech Stack:** Python 3 (stdlib, Pillow/tkinter/pypng-free pure Python PNG generation if needed or stdlib zlib rasterizer), CSS custom properties, vanilla DOM/jQuery, POSIX shell, Markdown.

**Spec:** Current session agreements:
1. Replace plugin icon with Lucide Globe Lock icon with local self-contained asset attribution.
2. Auto dark/light mode following aaPanel without an extra manual toggle button.
3. Update `AGENTS.md` with explicit rules derived from this session.
4. Strict prohibition on updating `/www/server/panel/plugin/ols_geo_access` in this session; production updates will happen only when the user manually clicks Update.

## Global Constraints

- Never edit files in `/www/server/panel/plugin/ols_geo_access`.
- Never run production upgrade scripts or reload OpenLiteSpeed services in this session.
- Keep all test artifacts, mock servers, and temporary outputs inside `tmp/`.
- Maintain 100% passing tests for `tmp/self_check.py` and new test suites.

## Review Focus

1. Dark mode elements must maintain WCAG AA contrast (text, inputs, badges, code/pre, table headers).
2. Theme transitions must be seamless when aaPanel toggles dark mode dynamically without page reload.
3. The icon must be valid PNG format, crisp at 32x32, 48x48, and 128x128, with transparent background.
4. `package.sh` must not hardcode version strings and must package clean archives without leftover `.tmp`.
5. Production directory must remain completely untouched (`git status` and filesystem timestamps).

---

### Task 1: Generate Lucide Globe Lock Icon and Metadata

**Files:**
- Create: `tmp/generate_icon.py`
- Modify: `src/ols_geo_access/icon.png`
- Create: `src/ols_geo_access/THIRD_PARTY_LICENSES.md`
- Test: `tmp/test_icon_asset.py`

**Interfaces:**
- Produces: 128x128 valid RGBA PNG at `src/ols_geo_access/icon.png` containing Lucide Globe Lock graphic.

- [ ] **Step 1: Write test for icon asset validation**
- [ ] **Step 2: Run test to confirm it fails on current 68-byte placeholder**
- [ ] **Step 3: Implement clean icon generator script using pure Python stdlib PNG encoder**
- [ ] **Step 4: Generate `src/ols_geo_access/icon.png` and write `THIRD_PARTY_LICENSES.md`**
- [ ] **Step 5: Run icon test to confirm PASS**

---

### Task 2: Implement Auto Dark/Light Mode in Plugin UI

**Files:**
- Modify: `src/ols_geo_access/index.html`
- Test: `tmp/test_dark_mode_ui.py`

**Interfaces:**
- Produces: CSS variables scoped under `.oga` with dark mode rules triggered by:
  - Parent/Root selectors: `html.dark .oga`, `:root[theme-mode="dark"] .oga`, `body.dark-theme .oga`, `[data-theme="dark"] .oga`
  - Fallback `@media (prefers-color-scheme: dark)`
  - JavaScript observer listening for attribute/class mutations on `document.documentElement` and `document.body` to auto-refresh styles without extra buttons.

- [ ] **Step 1: Write headless DOM/HTML test checking all color variable definitions and dark overrides**
- [ ] **Step 2: Run test to confirm failure**
- [ ] **Step 3: Update `src/ols_geo_access/index.html` CSS and theme detection JS**
- [ ] **Step 4: Run test to confirm PASS**

---

### Task 3: Make `scripts/package.sh` Dynamic from `info.json`

**Files:**
- Modify: `scripts/package.sh`
- Test: `tmp/test_package_dynamic.py`

**Interfaces:**
- Consumes: `src/ols_geo_access/info.json` version string.
- Produces: `dist/ols_geo_access-<version>.zip`.

- [ ] **Step 1: Write test verifying package script produces archive matching `info.json` version**
- [ ] **Step 2: Run test to confirm failure**
- [ ] **Step 3: Update `scripts/package.sh` to parse version from `info.json`**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 4: Hardened Rules in `AGENTS.md`

**Files:**
- Modify: `AGENTS.md`
- Test: `tmp/test_agents_rules.py`

**Interfaces:**
- Produces: Clear, unambiguous operational instructions covering:
  - Strict source vs production separation.
  - User-driven manual updates via UI / GitHub Releases.
  - Theme consistency & zero custom manual theme toggles.
  - Asset cleanliness and artifact disposal.

- [ ] **Step 1: Write test checking required rule sections in `AGENTS.md`**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Update `AGENTS.md`**
- [ ] **Step 4: Run test to verify PASS**

---

### Task 5: Full Regression Testing and Production Integrity Check

**Files:**
- Verify: `tmp/self_check.py`
- Verify: Production directory `/www/server/panel/plugin/ols_geo_access` unchanged.

- [ ] **Step 1: Run `py_compile` across all Python source files**
- [ ] **Step 2: Run `tmp/self_check.py`**
- [ ] **Step 3: Run `scripts/package.sh` to generate the new release archive**
- [ ] **Step 4: Verify production directory remains completely untouched**
