# Parameter Source Extractor

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030e |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Analyze controller method source code to identify all parameter input sources per route |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | Route entries with `controller`, `action`, `file`, `line` |
| Target source code | `$TARGET_PATH/` | ✅ | Controller method bodies |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-4 | `input_sources` MUST come from actual code patterns. MUST NOT guess based on route path signatures alone. | False taint analysis — missed or phantom vulnerabilities |
| CR-3 | Controller method MUST exist. If method not found, set `input_sources: []` and flag `method_missing: true`. | Incomplete parameter extraction |

## Fill-in Procedure

### Procedure A: Load Validated Routes

| Field | Fill-in Value |
|-------|--------------|
| route_list | {read `$WORK_DIR/validated_routes.json` from previous sub-skill} |
| per_route_fields | {extract `controller`, `action`, `file`, `line` for each route entry} |

### Procedure B: Parse Controller Method Body

For each route, locate the controller method and scan for these source patterns:

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

For each matched pattern, fill in:

| Field | Fill-in Value |
|-------|--------------|
| source | {label from table above} |
| key | {extracted parameter key name, or `*` for `all()`} |
| line | {line number where pattern found} |
| pattern | {actual code pattern matched} |

### Procedure C: Trace Through Called Methods

| Field | Fill-in Value |
|-------|--------------|
| called_methods | {identify method calls within the controller action} |
| trace_depth | {one level deep — check called methods in same file or injected services} |
| indirect_sources | {parameter sources found in called methods, with call chain recorded} |

For each indirect source, fill in:

| Field | Fill-in Value |
|-------|--------------|
| source | {input source label} |
| key | {parameter key} |
| via | {call chain, e.g. `UserService::uploadAvatar`} |
| line | {line number in the called method} |

### Procedure D: Record Parameter Keys

| Field | Fill-in Value |
|-------|--------------|
| explicit_key | {`$request->input('username')` → `{"source": "$_POST", "key": "username"}`} |
| wildcard_key | {`$request->all()` → `{"source": "Request", "key": "*"}`} |
| global_key | {`$_GET['page']` → `{"source": "$_GET", "key": "page"}`} |

### Procedure E: Assemble Output

For each route, fill in:

| Field | Fill-in Value |
|-------|--------------|
| route_id | {route ID from validated_routes.json} |
| input_sources | {array of all direct input sources found in Procedure B} |
| indirect_sources | {array of all indirect sources found in Procedure C} |
| method_missing | {`true` if controller method not found, omit otherwise} |
| file_missing | {`true` if controller file not found, omit otherwise} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| route_params.json | `$WORK_DIR/原始数据/route_params.json` | See schema below | Input sources array per route ID |

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

## Examples

### ✅ GOOD: Complete Parameter Extraction
```json
{
  "route_id": "route_012",
  "input_sources": [
    { "source": "route_param", "key": "id", "line": 46 },
    { "source": "$_POST", "key": "username", "line": 48, "pattern": "$request->input('username')" },
    { "source": "$_POST", "key": "email", "line": 49, "pattern": "$request->input('email')" },
    { "source": "$_FILES", "key": "avatar", "line": 51, "pattern": "$request->file('avatar')" }
  ],
  "indirect_sources": [
    { "source": "$_FILES", "key": "avatar", "via": "UserService::uploadAvatar", "line": 22 }
  ]
}
```
All sources extracted from actual `$request->input()` / `$request->file()` code (CR-4). Controller method verified to exist (CR-3). Line numbers included. ✅

### ❌ BAD: Guessed from Route Path
```json
{
  "route_id": "route_012",
  "input_sources": [
    { "source": "route_param", "key": "id" },
    { "source": "$_POST", "key": "name" },
    { "source": "$_POST", "key": "email" }
  ]
}
```
Sources guessed from route path `/api/users/{id}` — violates **CR-4**. Actual code uses `username` not `name`. Missing `line` and `pattern` fields. No `indirect_sources` analysis performed. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Controller file not found | Set `input_sources: []`, flag `"file_missing": true` |
| Method not found in controller | Set `input_sources: []`, flag `"method_missing": true` |
| File not readable / permission denied | Log warning, skip route, set `input_sources: []` |
| No input sources found in method | Set `input_sources: []` — valid (method may use no external input) |
