# Hidden Endpoint Discoverer

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030d |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Discover hidden, undocumented, or debug endpoints not in the registered route table |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Target source code | `$TARGET_PATH/` | ✅ | All source files, public directory |
| Frontend assets | `$TARGET_PATH/public/`, `$TARGET_PATH/dist/`, `$TARGET_PATH/resources/js/` | ⚠️ Optional | JS bundles, Vue/React files |
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | For cross-reference deduplication |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-6 | Every hidden endpoint MUST have a `discovery_source` field explaining how it was found | Entry deleted — no provenance of discovery method |
| CR-1 | Hidden endpoints MUST include `file` + `line` provenance when discoverable from source code | Entry quality degraded without source traceability |

## Fill-in Procedure

### Procedure A: Frontend Bundle Reverse Search

| Field | Fill-in Value |
|-------|--------------|
| compiled_js | {`grep -oE '"/api/[^"]+"' dist/js/*.js public/js/*.js`} |
| vue_react_src | {`grep -rn -oE '"/api/[^"]+"' resources/js/ src/`} |
| ajax_patterns | {search for `axios.get/post/put/delete/patch(`, `fetch(`, `$.ajax` in frontend source} |
| discovery_source | {`frontend_js`} |

### Procedure B: WIP/Debug Endpoints in Code Comments

| Field | Fill-in Value |
|-------|--------------|
| todo_routes | {`grep -rn 'TODO.*route\|WIP.*endpoint\|FIXME.*api' --include="*.php" $TARGET_PATH/`} |
| commented_routes | {`grep -rn '//.*Route::' --include="*.php" $TARGET_PATH/routes/`} |
| block_comments | {`grep -rn '/\*.*Route::' --include="*.php" $TARGET_PATH/routes/`} |
| discovery_source | {`code_comment`} |

### Procedure C: Sensitive File Leak Detection

For each sensitive file pattern, fill in:

| Field | Fill-in Value |
|-------|--------------|
| file_checked | {file path or pattern checked} |
| found | {`true` / `false`} |
| risk | {risk description} |
| discovery_source | {`sensitive_file`} |

**Sensitive file reference:**

| File/Path | Risk | Check Method |
|-----------|------|-------------|
| `.env.example` | May contain real secrets if copied from `.env` | `test -f $TARGET_PATH/.env.example` |
| `.env.backup` / `.env.production` | Direct secret exposure | `find $TARGET_PATH -name '.env.*'` |
| `.git/` in web root | Full source code disclosure | `test -d $TARGET_PATH/public/.git` |
| `composer.json` / `composer.lock` | Dependency version exposure | Check if in public directory |
| `phpinfo.php` | Full PHP config exposure | `find $TARGET_PATH/public -name 'phpinfo.php'` |
| `info.php` / `test.php` | Debug/test file exposure | `find $TARGET_PATH/public -name 'info.php' -o -name 'test.php'` |

### Procedure D: Public Index File Probing

| Field | Fill-in Value |
|-------|--------------|
| robots_txt | {parse `robots.txt` — `Disallow:` entries reveal hidden admin paths} |
| sitemap_xml | {parse `sitemap.xml` for undisclosed URLs} |
| security_txt | {check `.well-known/security.txt`} |
| openid_config | {check `.well-known/openid-configuration`} |
| discovery_source | {`public_index_file`} |

### Procedure E: Common Debug/Admin Path Probing

For each known debug/admin path, fill in:

| Field | Fill-in Value |
|-------|--------------|
| path | {debug/admin path to check} |
| exists_in_public | {`find $TARGET_PATH/public -name '{filename}'` result} |
| exists_in_routes | {`grep -rn '{path}' --include="*.php" $TARGET_PATH/` result} |
| risk_level | {`HIGH` / `CRITICAL`} |
| discovery_source | {`debug_path_probe`} |

**Debug/admin path reference:**

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

### Procedure F: Swagger/OpenAPI Documentation Leak

| Field | Fill-in Value |
|-------|--------------|
| spec_paths_checked | {`/api/documentation`, `/swagger.json`, `/swagger.yaml`, `/openapi.json`, `/openapi.yaml`, `/api-docs`, `/docs/api`} |
| spec_found | {`true` / `false` for each path} |
| parsed_endpoints | {if spec file found, parse ALL documented endpoints from it} |
| discovery_source | {`swagger_spec`} |

### Procedure G: Cross-Reference with Validated Routes

| Field | Fill-in Value |
|-------|--------------|
| validated_routes | {load `$WORK_DIR/validated_routes.json`} |
| dedup_check | {for each discovered endpoint: if `(method, path)` exists in validated routes → skip} |
| hidden_flag | {if NOT in validated routes → set `hidden: true`} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| hidden_routes.json | `$WORK_DIR/原始数据/hidden_routes.json` | See schema below | List of hidden/undocumented endpoints |

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

## Examples

### ✅ GOOD: Debug Panel Discovery with Full Provenance
```json
{
  "id": "hidden_001",
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
`discovery_source` present (CR-6). `file` + `line` provenance included (CR-1). Risk level classified. ✅

### ❌ BAD: Missing Discovery Source
```json
{
  "id": "hidden_001",
  "path": "/_debugbar",
  "method": "GET",
  "hidden": true,
  "risk_level": "HIGH"
}
```
No `discovery_source` field — violates **CR-6**. Entry will be deleted by assembler. No `file`/`line` — also violates CR-1. ❌

## Error Handling
| Error | Action |
|-------|--------|
| No frontend assets directory found | Skip Procedure A, log info "No frontend assets found" |
| `robots.txt` not found | Skip robots.txt parsing, continue with other checks |
| Swagger spec file is malformed JSON/YAML | Log warning, skip Swagger parsing |
| Public directory not identifiable | Try common paths: `public/`, `web/`, `htdocs/`, `www/` |
| No hidden endpoints found | Output empty `hidden_routes.json` with `"routes": []` — valid result |
