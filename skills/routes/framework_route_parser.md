> **Skill ID**: S-030a | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: source code (`TARGET_PATH`) + `environment_status.json` (framework type)
> **Output**: `raw_routes.json` — unvalidated list of parsed route definitions

# Framework Route Parser

## Purpose

Parse all registered HTTP routes from the target PHP project source code based on the detected framework type. Covers 9 framework variants (Laravel, ThinkPHP, Yii2, Native PHP, Symfony, CakePHP, CodeIgniter, WordPress, Drupal). Each route entry MUST include source file path and line number as provenance evidence.

## Procedure

### Step A: Determine Framework Type

1. Read `$WORK_DIR/environment_status.json` → extract `framework` field.
2. Select the matching framework parsing section below.
3. If `framework = "unknown"` → use section B.4 (Native PHP Routes).

### Step B: Parse Registered Routes

Execute the section matching the detected framework. For **every** route discovered, record:
- Path, HTTP method(s), controller class, action method
- Source file path + line number (CR-1 provenance)
- Middleware bindings (if declared at route level)
- Route name (if named)

---

#### B.1 — Laravel Routes

1. Parse route definition files:
   - `routes/web.php` — Web routes
   - `routes/api.php` — API routes (auto-prefixed with `/api`)
   - `routes/admin.php` (if present)
   - Any additional files loaded in `RouteServiceProvider`
2. Identify route registration methods:
   - `Route::get('/path', [Controller::class, 'method'])`
   - `Route::post('/path', 'Controller@method')`
   - `Route::any('/path', ...)`
   - `Route::match(['get', 'post'], '/path', ...)`
3. **Expand `Route::resource` into 7 RESTful routes** (CR-5):

   | HTTP Method | URI Pattern | Action |
   |-------------|-------------|--------|
   | GET | /photos | index |
   | GET | /photos/create | create |
   | POST | /photos | store |
   | GET | /photos/{photo} | show |
   | GET | /photos/{photo}/edit | edit |
   | PUT/PATCH | /photos/{photo} | update |
   | DELETE | /photos/{photo} | destroy |

4. Parse `Route::group` to resolve prefix and middleware inheritance.
5. Extract parameters from controller method signatures (`Request $request` injection).
6. Handle `Route::apiResource` (excludes `create` and `edit`).

#### B.2 — ThinkPHP Routes

1. Parse `route/app.php` or `route/route.php`.
2. Identify `Route::rule('path', 'controller/action')`.
3. Parse annotation routes `@route("/path")`.
4. Identify auto-routing: `module/controller/method` mapped to URL.
5. Check `config/route.php` for global route configuration.

#### B.3 — Yii2 Routes

1. Parse `'urlManager' => ['rules' => [...]]` in `config/web.php`.
2. Identify `action*` methods in controllers (e.g., `actionIndex`, `actionView`).
3. Check module route configurations in `modules/*/config.php`.

#### B.4 — Native PHP Routes

1. Scan all entry `.php` files in the document root.
2. Search for `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES` global variable usage.
3. Search for `$_SERVER['PATH_INFO']`, `$_SERVER['REQUEST_URI']` for path-based routing.
4. Trace dynamically included files via `include` / `require` / `include_once` / `require_once`.
5. Each directly accessible `.php` file is treated as a route (path = relative file path).
6. Check for custom router implementations (e.g., `switch`/`if` on `$_SERVER['REQUEST_URI']`).

#### B.5 — Symfony Routes

1. Parse `config/routes.yaml` or `config/routes/*.yaml`.
2. Identify annotation/attribute routes:
   - `#[Route('/path', methods: ['GET'])]` (PHP 8 attributes)
   - `@Route("/path", methods={"GET"})` (annotations)
3. Parse resource imports in `config/routes.yaml`:
   ```yaml
   controllers:
     resource: ../src/Controller/
     type: annotation
   ```
4. Check `config/routes/annotations.yaml` for resource-based loading.

#### B.6 — CakePHP Routes

1. Parse `config/routes.php`.
2. Identify `$routes->connect('/path', ['controller' => 'X', 'action' => 'y'])`.
3. Identify RESTful resource routes: `$routes->resources('Articles')` — expand fully (CR-5).
4. Parse prefix routing: `$routes->prefix('Admin', ...)`.
5. Check scoped routes and middleware application.

#### B.7 — CodeIgniter Routes

1. Parse `app/Config/Routes.php`.
2. Identify `$routes->get('path', 'Controller::method')`.
3. Identify auto-routing: controllers/methods auto-mapped when `$routes->setAutoRoute(true)`.
4. Parse `$routes->group('admin', ...)` groups.
5. Check for `$routes->resource()` and `$routes->presenter()` shortcuts.

#### B.8 — WordPress Routes

1. Scan `functions.php` and plugins for `register_rest_route()`:
   ```php
   register_rest_route('wp/v2', '/custom', [...])
   ```
2. Identify `add_action('wp_ajax_*')` and `add_action('wp_ajax_nopriv_*')` AJAX endpoints.
3. Scan `admin-ajax.php` handler functions.
4. Identify WP-JSON API: all endpoints under `/wp-json/wp/v2/`.
5. Scan rewrite rules in `.htaccess` / `web.config`.

#### B.9 — Drupal Routes

1. Parse `*.routing.yml` files:
   ```yaml
   module.route_name:
     path: '/admin/config'
     defaults:
       _controller: '\Drupal\module\Controller\X::method'
     requirements:
       _permission: 'access content'
   ```
2. Scan `hook_menu()` implementations (Drupal 7).
3. Identify REST resources provided by modules.
4. Parse `*.links.menu.yml` for admin menu routes.

### Step C: Verify Controller Methods Exist (CR-3)

For each parsed route, verify the referenced controller and method exist:

```bash
grep -rn "function {method}" {controller_file}
```

If the method does NOT exist in the source code, flag the route with `"controller_verified": false`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework`, `framework_version` |
| Target source code | `$TARGET_PATH/` | ✅ | Route definition files, controller files |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| raw_routes.json | `$WORK_DIR/raw_routes.json` | Array of parsed route objects with provenance |

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

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-1 | Every route MUST have `file` + `line` as provenance. MUST NOT speculate. |
| CR-3 | `controller` + `action` MUST actually exist in source code. Verify with grep. |
| CR-5 | `Route::resource` / `$routes->resources` MUST be expanded into all sub-routes. |

## Error Handling

| Error | Action |
|-------|--------|
| Framework not detected | Fall back to B.4 Native PHP parsing |
| Route definition file not found | Log warning, continue with other route files |
| Route file not parseable (syntax error) | Log error with file path, continue with remaining files |
| Controller file not found for a route | Set `controller_verified: false`, include route in output |
| No routes discovered at all | Output `raw_routes.json` with `"routes": []`, log warning |
