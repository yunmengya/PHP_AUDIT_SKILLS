> **Skill ID**: S-030g | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: route list + middleware declarations from all prior sub-skills
> **Output**: `auth_gap_report.json` — authentication gap analysis report

# Auth Gap Analyzer

## Purpose

Perform authentication gap analysis on every route. Compare middleware per route, classify endpoints by auth level, and flag inconsistent controller methods where some actions require authentication while others in the same controller do not. This pattern — inconsistent auth within a single controller — is the most common source of privilege escalation vulnerabilities.

## Procedure

### Step 1: Load All Route Data

Merge route data from:
- `$WORK_DIR/validated_routes.json` (S-030b) — HTTP routes with middleware
- `$WORK_DIR/cli_entries.json` (S-030e) — CLI synthetic routes
- `$WORK_DIR/background_entries.json` (S-030f) — CRON/Queue/Hook synthetic routes
- `$WORK_DIR/hidden_routes.json` (S-030d) — Hidden endpoints

### Step 2: Middleware / Decorator Comparison

For each route, check its bound middleware or decorators based on framework:

| Framework | Auth Middleware Patterns |
|-----------|------------------------|
| Laravel | `auth`, `auth:sanctum`, `auth:api`, `verified`, `can:`, `role:`, `permission:` |
| Symfony | `#[IsGranted('ROLE_USER')]`, `access_control` in `security.yaml`, `#[Security]` |
| ThinkPHP | `middleware` configuration, `before_action` |
| CakePHP | `$this->Auth->allow()` / `$this->Auth->deny()` in controller `beforeFilter()` |
| CodeIgniter | Filter configuration in `app/Config/Filters.php` |
| WordPress | `current_user_can()` checks, `wp_ajax_` vs `wp_ajax_nopriv_` distinction |
| Drupal | `_permission` requirement in `*.routing.yml` |
| Yii2 | `behaviors()` method with `AccessControl` rules |
| Native PHP | Manual `session_start()` + `$_SESSION` checks |

**Flag as `AUTH_MISSING`**: Any endpoint that handles sensitive data or performs write operations but has NO auth middleware.

### Step 3: Inconsistent Auth Within Same Controller (HIGH PRIORITY)

This is the highest-value detection in this sub-skill.

1. Group all routes by their `controller` class.
2. For each controller with more than one route:
   - List which methods have auth middleware and which do not.
   - If **some methods have auth and others do not**, flag the unprotected methods as `HIGH_RISK`.
3. Example detection:

   | Controller | Method | Auth Middleware | Flag |
   |-----------|--------|----------------|------|
   | UserController | profile() | `auth:sanctum` | ✅ Protected |
   | UserController | export() | _(none)_ | ⚠️ `AUTH_MISSING` — HIGH_RISK |
   | UserController | index() | `auth:sanctum` | ✅ Protected |

   `UserController::export()` is flagged because peer methods in the same controller require authentication.

### Step 4: Classify Each Endpoint

Assign an auth classification to every route:

| Classification | Criteria |
|---------------|----------|
| `public` | No auth middleware, AND endpoint serves public content (login, register, public API) |
| `authenticated` | Has auth middleware requiring login |
| `authorized` | Has role/permission middleware (e.g., `can:admin`, `role:editor`) |
| `suspicious` | Should require auth but has no middleware — flagged by Step 2 or Step 3 |
| `system` | Synthetic routes (CLI/CRON/Queue) with `auth_level: "system"` |

### Step 5: Generate Auth Gap Report

Produce `$WORK_DIR/auth_gap_report.json`:

```json
{
  "total_routes": 85,
  "public_routes": 12,
  "authenticated_routes": 68,
  "authorized_routes": 15,
  "suspicious_routes": 5,
  "system_routes": 8,
  "gaps": [
    {
      "route_id": "route_042",
      "path": "/api/users/export",
      "method": "GET",
      "controller": "UserController@export",
      "issue": "AUTH_MISSING",
      "risk": "HIGH",
      "reason": "Same controller has auth on other methods (profile, index, update)",
      "peer_methods_with_auth": ["profile", "index", "update"],
      "peer_methods_without_auth": ["export"]
    },
    {
      "route_id": "hidden_003",
      "path": "/_debugbar",
      "method": "GET",
      "controller": null,
      "issue": "DEBUG_ENDPOINT_EXPOSED",
      "risk": "CRITICAL",
      "reason": "Debug panel accessible without authentication"
    }
  ],
  "controller_auth_summary": [
    {
      "controller": "App\\Http\\Controllers\\UserController",
      "total_methods": 5,
      "protected_methods": 4,
      "unprotected_methods": 1,
      "consistency": "INCONSISTENT"
    }
  ]
}
```

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | Routes with middleware arrays |
| hidden_routes.json | `$WORK_DIR/hidden_routes.json` | ✅ | Hidden endpoints |
| cli_entries.json | `$WORK_DIR/cli_entries.json` | ✅ | CLI synthetic routes |
| background_entries.json | `$WORK_DIR/background_entries.json` | ✅ | CRON/Queue/Hook synthetic routes |
| Target source code | `$TARGET_PATH/` | ✅ | Controller files for middleware inspection |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework` (to determine auth patterns) |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| auth_gap_report.json | `$WORK_DIR/auth_gap_report.json` | Complete auth gap analysis with risk classifications |

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-1 | Gap entries MUST reference a valid `route_id` traceable to a source file. |
| CR-4 | Auth classification MUST be based on actual middleware/decorator analysis, not assumptions. |

## Error Handling

| Error | Action |
|-------|--------|
| Middleware info missing from route entries | Attempt to resolve middleware from controller source; if impossible, classify as `"unknown"` |
| Controller file not found | Classify route auth as `"unknown"`, add note in gaps |
| No gaps found | Valid result — output report with `"gaps": []` and `"suspicious_routes": 0` |
| Security config file not found (e.g., `security.yaml`) | Log warning, rely on route-level middleware only |
