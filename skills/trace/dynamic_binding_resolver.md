> **Skill ID**: S-037d | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: Trace containing unresolved dynamic bindings
> **Output**: Trace with all dynamic calls resolved to concrete targets

# Dynamic Binding Resolver

## Purpose

PHP applications frequently use dynamic dispatch patterns that static analysis
cannot fully resolve. The Xdebug trace captures the actual runtime targets of
these calls. This sub-skill extracts and records those resolutions so that
Phase 4 auditors have a complete, concrete call chain.

## Procedure

### 1. Scan Trace for Dynamic Patterns

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

### 2. Extract Resolution from Xdebug Trace

Xdebug's function trace records the **actual** called function, not the
variable expression. For each dynamic pattern found:

1. Read the resolved function/class/file name from the trace entry.
2. Record a mapping: `{ "pattern": "call_user_func", "resolved": "App\\Services\\Formatter::clean", "file": "UserController.php", "line": 42 }`.

### 3. Build `dynamic_bindings` Array

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

### 4. Back-fill into Context Pack

If a corresponding Context Pack exists for this route, update its
`dynamic_bindings` field with the resolved targets. This improves static
analysis accuracy for any subsequent re-analysis.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Trace Filter (S-037c) | (in-memory) | Yes | Filtered call chain with raw function names |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Resolved trace | (in-memory / piped to S-037h) | Trace with `dynamic_bindings` array populated |
| Context Pack update | `$WORK_DIR/context_packs/` | Optional back-fill of resolved bindings |

## Error Handling

| Error | Action |
|-------|--------|
| No dynamic patterns found in trace | Set `dynamic_bindings: []`; proceed normally |
| Resolution ambiguous (multiple candidates) | Record all candidates with a `confidence` field |
| Trace entry missing file/line info | Record resolution with `file: "unknown"` |
