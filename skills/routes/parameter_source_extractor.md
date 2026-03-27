> **Skill ID**: S-030c | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: validated route list (`validated_routes.json`) + controller method source code
> **Output**: `route_params.json` — input sources array per route

# Parameter Source Extractor

## Purpose

For each route, analyze the controller method source code to identify all parameter input sources. This determines where user-controlled data enters the application, which is critical for downstream taint analysis. Input sources MUST be based on actual code analysis (CR-4), not guessed from route signatures.

## Procedure

### Step 1: Load Validated Routes

Read `$WORK_DIR/validated_routes.json` from S-030b. For each route entry, obtain:
- `controller` — fully qualified class name
- `action` — method name
- `file` — source file path
- `line` — line number

### Step 2: Parse Controller Method Body

For each route, locate and read the controller method body. Extract all parameter source patterns:

| Source Pattern | Label | Grep Pattern |
|---------------|-------|--------------|
| `$_GET['key']` | `$_GET` | `\$_GET\[` |
| `$_POST['key']` | `$_POST` | `\$_POST\[` |
| `$_REQUEST['key']` | `$_REQUEST` | `\$_REQUEST\[` |
| `$_FILES['key']` | `$_FILES` | `\$_FILES\[` |
| `$_COOKIE['key']` | `$_COOKIE` | `\$_COOKIE\[` |
| `$_SERVER['key']` | `$_SERVER` | `\$_SERVER\[` |
| `$request->query('key')` | `$_GET` | `\$request->query\(` |
| `$request->input('key')` | `$_POST` | `\$request->input\(` |
| `$request->get('key')` | `$_GET` | `\$request->get\(` |
| `$request->post('key')` | `$_POST` | `\$request->post\(` |
| `$request->file('key')` | `$_FILES` | `\$request->file\(` |
| `$request->all()` | `Request` | `\$request->all\(` |
| `$request->only(...)` | `Request` | `\$request->only\(` |
| `$request->except(...)` | `Request` | `\$request->except\(` |
| `$request->header('key')` | `header` | `\$request->header\(` |
| `$request->cookie('key')` | `$_COOKIE` | `\$request->cookie\(` |
| `$this->argument('key')` | `cli_arg` | `\$this->argument\(` |
| `$this->option('key')` | `cli_opt` | `\$this->option\(` |
| Route parameter `{id}` | `route_param` | Method signature type-hinted params |
| `Route::current()->parameter()` | `route_param` | `Route::current\(\)->parameter\(` |
| `request()->` | `Request` | `request\(\)->` |
| `Input::get()` | `$_GET` | `Input::get\(` |
| `json_decode(file_get_contents('php://input'))` | `raw_body` | `php://input` |

### Step 3: Trace Through Called Methods

If the controller method calls other methods (e.g., service classes, form requests), trace one level deep:
1. Identify method calls within the controller action.
2. If the called method is in the same file or an injected service, check it for parameter sources.
3. Record these as `indirect_sources` with the call chain.

### Step 4: Record Parameter Keys

For each input source found, extract the specific key name if possible:
- `$request->input('username')` → `{ "source": "$_POST", "key": "username" }`
- `$_GET['page']` → `{ "source": "$_GET", "key": "page" }`
- `$request->all()` → `{ "source": "Request", "key": "*" }` (all inputs)

### Step 5: Assemble Output

Produce `route_params.json` mapping each route ID to its input sources array.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | Route entries with controller/action/file |
| Target source code | `$TARGET_PATH/` | ✅ | Controller method bodies |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| route_params.json | `$WORK_DIR/route_params.json` | Input sources array per route ID |

### Output Schema (per route)

```json
{
  "route_id": "route_001",
  "input_sources": [
    { "source": "route_param", "key": "id", "line": 46 },
    { "source": "$_POST", "key": "username", "line": 48, "pattern": "$request->input('username')" },
    { "source": "Request", "key": "*", "line": 50, "pattern": "$request->all()" }
  ],
  "indirect_sources": [
    { "source": "$_FILES", "key": "avatar", "via": "UserService::uploadAvatar", "line": 22 }
  ]
}
```

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-4 | `input_sources` MUST come from actual code patterns. MUST NOT guess based on route path signatures alone. |
| CR-3 | Controller method MUST exist. If method not found, set `input_sources: []` and flag `"method_missing": true`. |

## Error Handling

| Error | Action |
|-------|--------|
| Controller file not found | Set `input_sources: []`, flag `"file_missing": true"` |
| Method not found in controller | Set `input_sources: []`, flag `"method_missing": true"` |
| File not readable / permission denied | Log warning, skip route, set `input_sources: []` |
| No input sources found in method | Set `input_sources: []` — this is valid (the method may use no external input) |
