# Auth Gap Analyzer

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030f |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Perform authentication gap analysis on every route — detect missing auth and inconsistent controller protection |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | Routes with middleware arrays |
| hidden_routes.json | `$WORK_DIR/hidden_routes.json` | ✅ | Hidden endpoints |
| cli_entries.json | `$WORK_DIR/cli_entries.json` | ✅ | CLI synthetic routes |
| background_entries.json | `$WORK_DIR/background_entries.json` | ✅ | CRON/Queue/Hook synthetic routes |
| Target source code | `$TARGET_PATH/` | ✅ | Controller files for middleware inspection |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework` (to determine auth patterns) |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Gap entries MUST reference a valid `route_id` traceable to a source file | Untraceable gap report — cannot verify or fix |
| CR-4 | Auth classification MUST be based on actual middleware/decorator analysis, not assumptions | False auth gap reports — wasted audit effort |

## Fill-in Procedure

### Procedure A: Load All Route Data

| Field | Fill-in Value |
|-------|--------------|
| http_routes | {load `$WORK_DIR/validated_routes.json`} |
| cli_routes | {load `$WORK_DIR/cli_entries.json`} |
| background_routes | {load `$WORK_DIR/background_entries.json`} |
| hidden_routes | {load `$WORK_DIR/hidden_routes.json`} |
| all_routes | {merge all four sources into unified list} |

### Procedure B: Middleware / Decorator Comparison

For each route, check its bound middleware based on framework:

| Framework | Auth Middleware Patterns |
|-----------|------------------------|
| Laravel | `auth`, `auth:sanctum`, `auth:api`, `verified`, `can:`, `role:`, `permission:` |
| Symfony | `#[IsGranted('ROLE_USER')]`, `access_control` in `security.yaml`, `#[Security]` |
| ThinkPHP | `middleware` configuration, `before_action` |
| CakePHP | `$this->Auth->allow()` / `$this->Auth->deny()` in `beforeFilter()` |
| CodeIgniter | Filter configuration in `app/Config/Filters.php` |
| WordPress | `current_user_can()` checks, `wp_ajax_` vs `wp_ajax_nopriv_` distinction |
| Drupal | `_permission` requirement in `*.routing.yml` |
| Yii2 | `behaviors()` method with `AccessControl` rules |
| Native PHP | Manual `session_start()` + `$_SESSION` checks |

For each route, fill in:

| Field | Fill-in Value |
|-------|--------------|
| route_id | {route ID} |
| middleware_list | {array of auth-related middleware/decorators found} |
| has_auth | {`true` if any auth middleware present, `false` otherwise} |
| auth_missing_flag | {`AUTH_MISSING` if handles sensitive data or write ops but NO auth middleware} |

### Procedure C: Inconsistent Auth Within Same Controller (HIGH PRIORITY)

This is the highest-value detection — inconsistent auth within a single controller is the most common privilege escalation vector.

| Field | Fill-in Value |
|-------|--------------|
| controller_group | {group all routes by `controller` class} |
| protected_methods | {list methods WITH auth middleware} |
| unprotected_methods | {list methods WITHOUT auth middleware} |
| consistency | {`CONSISTENT` if all-or-none have auth; `INCONSISTENT` if mixed} |
| high_risk_methods | {unprotected methods in INCONSISTENT controllers → flag as `HIGH_RISK`} |

**Example detection pattern:**

| Controller | Method | Auth Middleware | Flag |
|-----------|--------|----------------|------|
| UserController | profile() | `auth:sanctum` | ✅ Protected |
| UserController | export() | _(none)_ | ⚠️ `AUTH_MISSING` — HIGH_RISK |
| UserController | index() | `auth:sanctum` | ✅ Protected |

### Procedure D: Classify Each Endpoint

For each route, assign classification:

| Field | Fill-in Value |
|-------|--------------|
| route_id | {route ID} |
| classification | {select from table below} |

| Classification | Criteria |
|---------------|----------|
| `public` | No auth middleware, AND endpoint serves public content (login, register, public API) |
| `authenticated` | Has auth middleware requiring login |
| `authorized` | Has role/permission middleware (e.g., `can:admin`, `role:editor`) |
| `suspicious` | Should require auth but has no middleware — flagged by Procedure B or C |
| `system` | Synthetic routes (CLI/CRON/Queue) with `auth_level: "system"` |

### Procedure E: Generate Auth Gap Report

Fill in the summary report:

| Field | Fill-in Value |
|-------|--------------|
| total_routes | {count of all routes} |
| public_routes | {count classified as `public`} |
| authenticated_routes | {count classified as `authenticated`} |
| authorized_routes | {count classified as `authorized`} |
| suspicious_routes | {count classified as `suspicious`} |
| system_routes | {count classified as `system`} |

For each gap found, fill in:

| Field | Fill-in Value |
|-------|--------------|
| route_id | {route ID} |
| path | {URL path} |
| method | {HTTP method} |
| controller | {controller@action} |
| issue | {`AUTH_MISSING` / `DEBUG_ENDPOINT_EXPOSED` / `INCONSISTENT_AUTH`} |
| risk | {`HIGH` / `CRITICAL` / `MEDIUM`} |
| reason | {explanation of why this is a gap} |
| peer_methods_with_auth | {list of sibling methods that DO have auth (for INCONSISTENT)} |
| peer_methods_without_auth | {list of sibling methods that DON'T have auth} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| auth_gap_report.json | `$WORK_DIR/原始数据/auth_gap_report.json` | See schema below | Complete auth gap analysis with risk classifications |

### Output Schema

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

## Examples

### ✅ GOOD: Inconsistent Controller Auth Gap
```json
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
}
```
References valid `route_id` (CR-1). Classification based on actual middleware analysis — peer methods verified to have `auth:sanctum` while `export()` does not (CR-4). ✅

### ❌ BAD: Assumed Auth Gap Without Verification
```json
{
  "route_id": "route_042",
  "path": "/api/users/export",
  "method": "GET",
  "controller": "UserController@export",
  "issue": "AUTH_MISSING",
  "risk": "HIGH",
  "reason": "Export endpoints typically require authentication"
}
```
Reason says "typically require" — this is an assumption, not based on actual middleware analysis — violates **CR-4**. No peer method comparison performed. Missing `peer_methods_with_auth` evidence. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Middleware info missing from route entries | Attempt to resolve middleware from controller source; if impossible, classify as `"unknown"` |
| Controller file not found | Classify route auth as `"unknown"`, add note in gaps |
| No gaps found | Valid result — output report with `"gaps": []` and `"suspicious_routes": 0` |
| Security config file not found (e.g., `security.yaml`) | Log warning, rely on route-level middleware only |
