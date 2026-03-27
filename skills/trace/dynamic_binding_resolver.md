## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037d |
| Phase | 3 |
| Responsibility | Resolve dynamic PHP dispatch patterns to concrete runtime targets |

# Dynamic Binding Resolver

## Purpose

PHP applications frequently use dynamic dispatch patterns that static analysis
cannot fully resolve. The Xdebug trace captures the actual runtime targets of
these calls. This sub-skill extracts and records those resolutions so that
Phase 4 auditors have a complete, concrete call chain.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Filtered trace | Trace Filter S-037c (in-memory) | Yes | Filtered call chain with raw function names |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST resolve `__call`, `__callStatic`, service container bindings, and facade accessors — static analysis alone misses 40%+ of PHP routes | FAIL — dynamic routes invisible to Phase-4 auditors |

## Fill-in Procedure

### Step 1 — Scan Trace for Dynamic Patterns

| Field | Fill-in Value |
|-------|---------------|
| `pattern_type` | {call_user_func / call_user_func_array / variable_method / late_static / dynamic_include / variable_variable / dynamic_new} |
| `expression` | {the dynamic expression found in source, e.g., $callback, $method} |
| `location_file` | {source file where pattern appears} |
| `location_line` | {line number where pattern appears} |

Search the filtered trace for the following dynamic binding patterns:

| Pattern | Example in Trace | What to Resolve |
|---------|-----------------|-----------------|
| `call_user_func($callback)` | `call_user_func → App\Services\Formatter::clean` | Actual callback function/method name |
| `call_user_func_array($callback, $args)` | Same as above | Actual callback + argument list |
| `$obj->$method()` | `App\Models\User->update` (where `$method` was a variable) | Concrete `ClassName::methodName` |
| `static::$method()` | Late static binding | Resolved class + method |
| `include $var` / `require $var` | `include → /var/www/html/app/views/user.php` | Actual included file path |
| `$$varName` | Variable variable | Actual variable name used |
| `new $className()` | Dynamic instantiation | Actual class name |

### Step 2 — Extract Resolution from Xdebug Trace

| Field | Fill-in Value |
|-------|---------------|
| `resolved_target` | {actual function/class/file name from trace entry} |
| `resolution_source` | {Xdebug trace — records actual called function, not variable expression} |

Xdebug's function trace records the **actual** called function, not the variable expression. For each dynamic pattern found:

1. Read the resolved function/class/file name from the trace entry.
2. Record a mapping: `{ "pattern": "call_user_func", "resolved": "App\\Services\\Formatter::clean", "file": "UserController.php", "line": 42 }`.

### Step 3 — Build `dynamic_bindings` Array

| Field | Fill-in Value |
|-------|---------------|
| `pattern` | {dynamic dispatch pattern type} |
| `expression` | {original dynamic expression from source} |
| `resolved` | {concrete target from Xdebug trace} |
| `file` | {source file path} |
| `line` | {source line number} |

Append all resolutions to the trace record's `dynamic_bindings` field:

```json
{
  "dynamic_bindings": [
    {
      "pattern": "call_user_func",
      "expression": "$callback",
      "resolved": "App\\Services\\Formatter::clean",
      "file": "app/Http/Controllers/UserController.php",
      "line": 42
    },
    {
      "pattern": "include $var",
      "expression": "$template",
      "resolved": "/var/www/html/resources/views/user/edit.blade.php",
      "file": "app/Http/Controllers/UserController.php",
      "line": 78
    }
  ]
}
```

### Step 4 — Back-fill into Context Pack

| Field | Fill-in Value |
|-------|---------------|
| `context_pack_exists` | {true / false} |
| `backfill_target` | {$WORK_DIR/context_packs/ — dynamic_bindings field} |

If a corresponding Context Pack exists for this route, update its `dynamic_bindings` field with the resolved targets. This improves static analysis accuracy for any subsequent re-analysis.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Resolved trace | (in-memory / piped to S-037h) | Trace with `dynamic_bindings` array populated |
| Context Pack update | `$WORK_DIR/context_packs/` | Optional back-fill of resolved bindings |

## Examples

### ✅ GOOD — Complete dynamic binding resolution

```json
{
  "dynamic_bindings": [
    {
      "pattern": "call_user_func",
      "expression": "$callback",
      "resolved": "App\\Services\\Formatter::clean",
      "file": "app/Http/Controllers/UserController.php",
      "line": 42
    }
  ]
}
```

All fields present: pattern type, original expression, resolved target, file, line.

### ❌ BAD — Missing resolution details

```json
{
  "dynamic_bindings": [
    {
      "pattern": "call_user_func",
      "resolved": "unknown"
    }
  ]
}
```

Problems: Missing `expression`, `file`, `line`. Resolved target is "unknown" instead of actual function.

## Error Handling

| Error | Action |
|-------|--------|
| No dynamic patterns found in trace | Set `dynamic_bindings: []`; proceed normally |
| Resolution ambiguous (multiple candidates) | Record all candidates with a `confidence` field |
| Trace entry missing file/line info | Record resolution with `file: "unknown"` |
