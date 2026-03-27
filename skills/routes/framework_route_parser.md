# Framework Route Parser

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030a |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Parse all registered HTTP routes from PHP project source based on detected framework type |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework`, `framework_version` |
| Target source code | `$TARGET_PATH/` | ✅ | Route definition files, controller files |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every route MUST have `file` + `line` as provenance. MUST NOT speculate. | Route entry deleted from output |
| CR-3 | `controller` + `action` MUST actually exist in source code. Verify with grep. | Set `controller_verified: false` |
| CR-5 | `Route::resource` / `$routes->resources` MUST be expanded into all sub-routes. | Unexpanded resource routes are incomplete — downstream analysis misses endpoints |

## Fill-in Procedure

### Procedure A: Determine Framework Type
| Field | Fill-in Value |
|-------|--------------|
| framework | {read `framework` field from `$WORK_DIR/environment_status.json`} |
| framework_version | {read `framework_version` field from same file} |
| parser_section | {select matching section B.1–B.9 below; if `framework = "unknown"` → use B.4 Native PHP} |

### Procedure B: Parse Registered Routes

For **every** route discovered, fill in this entry:

| Field | Fill-in Value |
|-------|--------------|
| path | {URL path pattern, e.g. `/api/users/{id}`} |
| method | {HTTP method(s): GET / POST / PUT / PATCH / DELETE / ANY} |
| controller | {fully qualified controller class} |
| action | {controller method name} |
| file | {source file path where controller method is defined} |
| line | {line number of controller method definition} |
| route_file | {route definition file where route is registered} |
| route_line | {line number in route definition file} |
| middleware | {array of middleware names bound at route level} |
| route_name | {named route identifier, if declared} |

#### B.1 — Laravel Routes

| Field | Fill-in Value |
|-------|--------------|
| route_files | {scan `routes/web.php`, `routes/api.php`, `routes/admin.php`, + files loaded in `RouteServiceProvider`} |
| registration_methods | {`Route::get`, `Route::post`, `Route::any`, `Route::match`, `Route::resource`, `Route::apiResource`} |
| group_resolution | {resolve `Route::group` to inherit prefix + middleware} |
| parameter_extraction | {extract from controller method signatures — `Request $request` injection} |

**Route::resource expansion table (CR-5):**

| HTTP Method | URI Pattern | Action |
|-------------|-------------|--------|
| GET | /photos | index |
| GET | /photos/create | create |
| POST | /photos | store |
| GET | /photos/{photo} | show |
| GET | /photos/{photo}/edit | edit |
| PUT/PATCH | /photos/{photo} | update |
| DELETE | /photos/{photo} | destroy |

`Route::apiResource` excludes `create` and `edit`.

#### B.2 — ThinkPHP Routes

| Field | Fill-in Value |
|-------|--------------|
| route_files | {`route/app.php`, `route/route.php`} |
| patterns | {`Route::rule('path', 'controller/action')`, annotation routes `@route("/path")`} |
| auto_routing | {module/controller/method auto-mapped to URL} |
| config | {check `config/route.php` for global route configuration} |

#### B.3 — Yii2 Routes

| Field | Fill-in Value |
|-------|--------------|
| url_rules | {parse `'urlManager' => ['rules' => [...]]` in `config/web.php`} |
| controller_actions | {identify `action*` methods: `actionIndex`, `actionView`, etc.} |
| module_configs | {check `modules/*/config.php` for module route configurations} |

#### B.4 — Native PHP Routes

| Field | Fill-in Value |
|-------|--------------|
| entry_files | {scan all `.php` files in document root} |
| global_vars | {search for `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES` usage} |
| path_routing | {search `$_SERVER['PATH_INFO']`, `$_SERVER['REQUEST_URI']`} |
| includes | {trace `include` / `require` / `include_once` / `require_once`} |
| file_as_route | {each directly accessible `.php` file = one route (path = relative file path)} |
| custom_router | {check for `switch`/`if` on `$_SERVER['REQUEST_URI']`} |

#### B.5 — Symfony Routes

| Field | Fill-in Value |
|-------|--------------|
| yaml_routes | {parse `config/routes.yaml`, `config/routes/*.yaml`} |
| attribute_routes | {`#[Route('/path', methods: ['GET'])]` (PHP 8), `@Route("/path")` (annotations)} |
| resource_imports | {parse `resource: ../src/Controller/` in YAML configs} |

#### B.6 — CakePHP Routes

| Field | Fill-in Value |
|-------|--------------|
| route_file | {parse `config/routes.php`} |
| connect_calls | {`$routes->connect('/path', ['controller' => 'X', 'action' => 'y'])`} |
| resource_routes | {`$routes->resources('Articles')` — expand fully per CR-5} |
| prefix_routing | {`$routes->prefix('Admin', ...)`} |

#### B.7 — CodeIgniter Routes

| Field | Fill-in Value |
|-------|--------------|
| route_file | {parse `app/Config/Routes.php`} |
| explicit_routes | {`$routes->get('path', 'Controller::method')`} |
| auto_routing | {controllers auto-mapped when `$routes->setAutoRoute(true)`} |
| groups | {`$routes->group('admin', ...)`} |
| shortcuts | {`$routes->resource()`, `$routes->presenter()`} |

#### B.8 — WordPress Routes

| Field | Fill-in Value |
|-------|--------------|
| rest_routes | {`register_rest_route('wp/v2', '/custom', [...])` in `functions.php` and plugins} |
| ajax_endpoints | {`add_action('wp_ajax_*')` and `add_action('wp_ajax_nopriv_*')`} |
| wp_json_api | {all endpoints under `/wp-json/wp/v2/`} |
| rewrite_rules | {scan `.htaccess` / `web.config`} |

#### B.9 — Drupal Routes

| Field | Fill-in Value |
|-------|--------------|
| routing_yml | {parse `*.routing.yml` files for path + controller + permission} |
| hook_menu | {scan `hook_menu()` implementations (Drupal 7)} |
| rest_resources | {identify REST resources provided by modules} |
| menu_links | {parse `*.links.menu.yml` for admin menu routes} |

### Procedure C: Verify Controller Methods Exist (CR-3)

| Field | Fill-in Value |
|-------|--------------|
| verification_command | {`grep -rn "function {method}" {controller_file}`} |
| controller_verified | {`true` if method found in source code, `false` if not} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| raw_routes.json | `$WORK_DIR/原始数据/raw_routes.json` | See schema below | Array of parsed route objects with provenance |

### Output Schema (per route entry)

```json
{
  "id": "route_{NNN}",
  "path": "/api/users/{id}",
  "method": "GET",
  "controller": "App\\Http\\Controllers\\UserController",
  "action": "show",
  "file": "app/Http/Controllers/UserController.php",
  "line": 45,
  "route_file": "routes/api.php",
  "route_line": 12,
  "middleware": ["auth:sanctum"],
  "controller_verified": true,
  "framework_source": "laravel"
}
```

## Examples

### ✅ GOOD: Complete Laravel Route Entry
```json
{
  "id": "route_007",
  "path": "/api/users/{id}",
  "method": "GET",
  "controller": "App\\Http\\Controllers\\UserController",
  "action": "show",
  "file": "app/Http/Controllers/UserController.php",
  "line": 45,
  "route_file": "routes/api.php",
  "route_line": 12,
  "middleware": ["auth:sanctum"],
  "controller_verified": true,
  "framework_source": "laravel"
}
```
Every field populated from actual source code. `file` + `line` provenance present (CR-1). Controller verified (CR-3). ✅

### ❌ BAD: Missing Provenance
```json
{
  "id": "route_007",
  "path": "/api/users/{id}",
  "method": "GET",
  "controller": "App\\Http\\Controllers\\UserController",
  "action": "show",
  "middleware": ["auth:sanctum"],
  "controller_verified": true,
  "framework_source": "laravel"
}
```
Missing `file`, `line`, `route_file`, `route_line` — violates **CR-1** (no provenance). Entry will be deleted by S-030g assembler. ❌

### ❌ BAD: Unexpanded Resource Route
```json
{
  "id": "route_020",
  "path": "/photos",
  "method": "RESOURCE",
  "controller": "App\\Http\\Controllers\\PhotoController",
  "action": "resource",
  "file": "app/Http/Controllers/PhotoController.php",
  "line": 1,
  "route_file": "routes/web.php",
  "route_line": 5,
  "controller_verified": true,
  "framework_source": "laravel"
}
```
`Route::resource` not expanded into 7 individual routes — violates **CR-5**. Must generate separate entries for index/create/store/show/edit/update/destroy. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Framework not detected | Fall back to B.4 Native PHP parsing |
| Route definition file not found | Log warning, continue with other route files |
| Route file not parseable (syntax error) | Log error with file path, continue with remaining files |
| Controller file not found for a route | Set `controller_verified: false`, include route in output |
| No routes discovered at all | Output `raw_routes.json` with `"routes": []`, log warning |
