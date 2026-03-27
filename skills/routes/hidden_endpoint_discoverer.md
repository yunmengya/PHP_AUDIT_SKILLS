> **Skill ID**: S-030d | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: frontend assets + config files + target source code
> **Output**: `hidden_routes.json` — list of hidden/undocumented endpoints

# Hidden Endpoint Discoverer

## Purpose

Discover hidden, undocumented, or debug endpoints that are not part of the framework's registered route table. These endpoints often represent significant security risks (exposed debug panels, leaked API documentation, forgotten test routes). Every hidden endpoint MUST annotate its discovery method (CR-6).

## Procedure

### Step 1: Frontend Bundle Reverse Search

Search compiled JavaScript and frontend source files for API path references:

```bash
# Compiled JS bundles
grep -oE '"/api/[^"]+"' dist/js/*.js public/js/*.js 2>/dev/null
grep -oE "'/api/[^']+'" dist/js/*.js public/js/*.js 2>/dev/null

# Vue/React source files
grep -rn -oE '"/api/[^"]+"' resources/js/ src/ 2>/dev/null
grep -rn -oE "'/api/[^']+'" resources/js/ src/ 2>/dev/null

# Axios / fetch / $.ajax URL patterns
grep -rn 'axios\.\(get\|post\|put\|delete\|patch\)(' resources/js/ src/ 2>/dev/null
grep -rn 'fetch(' resources/js/ src/ 2>/dev/null
grep -rn '\$\.ajax' resources/js/ src/ 2>/dev/null
```

For each discovered URL, set `discovery_source: "frontend_js"`.

### Step 2: WIP/Debug Endpoints in Code Comments

Search for commented-out or TODO-marked routes in PHP source:

```bash
grep -rn 'TODO.*route\|WIP.*endpoint\|FIXME.*api' --include="*.php" $TARGET_PATH/
grep -rn '//.*Route::' --include="*.php" $TARGET_PATH/routes/
grep -rn '/\*.*Route::' --include="*.php" $TARGET_PATH/routes/
```

For each match, set `discovery_source: "code_comment"`.

### Step 3: Sensitive File Leak Detection

Check for exposed configuration and backup files:

| File/Path | Risk | Check Method |
|-----------|------|-------------|
| `.env.example` | May contain real secrets if copied from `.env` | `test -f $TARGET_PATH/.env.example` |
| `.env.backup` / `.env.production` | Direct secret exposure | `find $TARGET_PATH -name '.env.*'` |
| `.git/` in web root | Full source code disclosure | `test -d $TARGET_PATH/public/.git` |
| `composer.json` / `composer.lock` | Dependency version exposure | Check if in public directory |
| `phpinfo.php` | Full PHP config exposure | `find $TARGET_PATH/public -name 'phpinfo.php'` |
| `info.php` / `test.php` | Debug/test file exposure | `find $TARGET_PATH/public -name 'info.php' -o -name 'test.php'` |

For each found, set `discovery_source: "sensitive_file"`.

### Step 4: Public Index File Probing

Check for information-leaking public files:

| File | What It Reveals |
|------|----------------|
| `robots.txt` | May disallow admin paths (reveals their existence) |
| `sitemap.xml` | May list undisclosed URLs |
| `.well-known/security.txt` | Security contact info |
| `.well-known/openid-configuration` | Auth configuration |

Parse `robots.txt` `Disallow:` entries as potential hidden admin routes.

For each found, set `discovery_source: "public_index_file"`.

### Step 5: Common Debug/Admin Path Probing

Check whether the following common debug/admin paths exist in the source code or web root:

| Path | Tool/Risk |
|------|-----------|
| `/_debugbar` | Laravel Debugbar — leaks SQL, session, request data |
| `/telescope` | Laravel Telescope — request/exception monitoring |
| `/horizon` | Laravel Horizon — queue monitoring panel |
| `/phpinfo.php` | Full PHP environment exposure |
| `/adminer.php` | Database management tool |
| `/phpmyadmin/` | Database management entry point |
| `/elfinder` | File manager |
| `/filemanager` | File manager |
| `/_profiler` | Symfony Profiler |
| `/app_dev.php` | Symfony dev front controller |

Check both:
1. File existence in public directory: `find $TARGET_PATH/public -name '{filename}'`
2. Route registration in source: `grep -rn '{path}' --include="*.php" $TARGET_PATH/`

For each found, set `discovery_source: "debug_path_probe"`.

### Step 6: Swagger/OpenAPI Documentation Leak

Check for exposed API documentation:

| Path | Format |
|------|--------|
| `/api/documentation` | Swagger UI |
| `/swagger.json` | Swagger 2.0 spec |
| `/swagger.yaml` | Swagger 2.0 spec |
| `/openapi.json` | OpenAPI 3.0 spec |
| `/openapi.yaml` | OpenAPI 3.0 spec |
| `/api-docs` | Generic API docs |
| `/docs/api` | Generic API docs |

If a Swagger/OpenAPI spec file is found, parse it to extract ALL documented endpoints and add them to the hidden routes list with `discovery_source: "swagger_spec"`.

### Step 7: Cross-Reference with Validated Routes

Compare all discovered hidden endpoints against `validated_routes.json`:
- If a hidden endpoint already exists in the validated routes → skip (not hidden).
- If it does NOT exist → add to `hidden_routes.json` with `hidden: true`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Target source code | `$TARGET_PATH/` | ✅ | All source files, public directory |
| Frontend assets | `$TARGET_PATH/public/`, `$TARGET_PATH/dist/`, `$TARGET_PATH/resources/js/` | ⚠️ Optional | JS bundles, Vue/React files |
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | For cross-reference deduplication |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| hidden_routes.json | `$WORK_DIR/hidden_routes.json` | List of hidden/undocumented endpoints |

### Output Schema (per entry)

```json
{
  "id": "hidden_{NNN}",
  "path": "/_debugbar",
  "method": "GET",
  "hidden": true,
  "discovery_source": "debug_path_probe",
  "discovery_detail": "Found /_debugbar route registered in barryvdh/laravel-debugbar ServiceProvider",
  "risk_level": "HIGH",
  "file": "vendor/barryvdh/laravel-debugbar/src/ServiceProvider.php",
  "line": 142
}
```

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-6 | Every hidden endpoint MUST have a `discovery_source` field explaining how it was found. Entries without this field are deleted. |
| CR-1 | Where possible, hidden endpoints should also include file + line provenance. |

## Error Handling

| Error | Action |
|-------|--------|
| No frontend assets directory found | Skip Step 1, log info "No frontend assets found" |
| `robots.txt` not found | Skip robots.txt parsing, continue with other checks |
| Swagger spec file is malformed JSON/YAML | Log warning, skip Swagger parsing |
| Public directory not identifiable | Try common paths: `public/`, `web/`, `htdocs/`, `www/` |
| No hidden endpoints found | Output empty `hidden_routes.json` with `"routes": []` — this is a valid result |
