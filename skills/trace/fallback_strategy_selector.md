## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-036f |
| Phase | 3 |
| Responsibility | Select best alternative tracing approach when Xdebug is unavailable |

# Fallback Strategy Selector

## Purpose

When Xdebug cannot be installed or enabled in the target environment (common
with production images, Alpine minimal containers, or PHP version
incompatibilities), select the best alternative tracing approach from a ranked
fallback list.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `environment_status.json` | `$WORK_DIR/environment_status.json` | Yes | `xdebug_available`, `php_version` |
| Framework detection | `$WORK_DIR/route_map.json` or scan results | No | `framework_type` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST select fallback strategy based on failure type (timeout→retry, 403→auth refresh, 500→simplify payload) — generic retry wastes attempts | FAIL — wrong fallback strategy, repeated failures |

## Fill-in Procedure

### Step 1 — Decision Tree

| Field | Fill-in Value |
|-------|---------------|
| `xdebug_available` | {true / false} |
| `php_version` | {detected PHP version, e.g., 7.4, 8.1} |
| `framework_type` | {Laravel / ThinkPHP / WordPress / Other / unknown} |
| `auto_prepend_available` | {true / false} |
| `selected_approach` | {xdebug / tick_function / middleware_injection / strace} |

```
Xdebug available?
├─ Yes → Use Xdebug Function Trace (optimal; normal flow)
└─ No
   ├─ PHP >= 7.0?
   │  ├─ Yes
   │  │  ├─ Framework type identified?
   │  │  │  ├─ Yes → Approach B (Framework Middleware Injection)
   │  │  │  │  ├─ Laravel    → AuditTraceMiddleware
   │  │  │  │  ├─ ThinkPHP   → Behavior Hook
   │  │  │  │  ├─ WordPress  → mu-plugins + `all` action
   │  │  │  │  └─ Other      → Fall through to Approach A
   │  │  │  └─ No → Approach A (Tick Function tracing)
   │  │  └─ auto_prepend_file unavailable?
   │  │     └─ Approach C (strace system-level tracing)
   │  └─ No (PHP < 7.0)
   │     └─ Approach C (strace / ltrace system-level tracing)
   └─ Note: Approaches B/C have lower precision than Xdebug.
      Phase 4 auditors SHOULD supplement with context_pack static analysis.
```

---

### Step 2 — Approach A — PHP Tick Function Tracing

**Prerequisite**: PHP ≥ 7.0; entry file can be modified or `auto_prepend_file` is available.

| Field | Fill-in Value |
|-------|---------------|
| `injection_method` | {auto_prepend_file (recommended) / direct require} |
| `tracer_script` | {tick_tracer.php} |
| `tracer_destination` | {/tmp/tick_tracer.php inside container} |
| `max_trace_entries` | {20000 before flush} |
| `vendor_filter` | {exclude vendor/composer and vendor/autoload paths} |

Inject `tick_tracer.php` via one of:

| Method | Command |
|--------|---------|
| `auto_prepend_file` (recommended) | `docker exec php sh -c 'echo "auto_prepend_file=/tmp/tick_tracer.php" >> /usr/local/etc/php/conf.d/99-trace.ini'` then `docker exec php kill -USR2 1` |
| Direct `require` | `docker exec php sed -i '1a require_once "/tmp/tick_tracer.php";' /var/www/html/public/index.php` |

**Tick tracer core logic** (`tick_tracer.php`):

```php
<?php
$__trace_log = [];
$__trace_depth = 0;
$__trace_start = microtime(true);
$__trace_file = '/tmp/tick_trace_' . getmypid() . '.json';

function __tick_tracer() {
    global $__trace_log, $__trace_depth, $__trace_start;
    $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10);
    if (count($bt) < 2) return;
    $caller = $bt[1] ?? [];
    $entry = [
        'time'     => round((microtime(true) - $__trace_start) * 1000, 3),
        'file'     => $caller['file'] ?? '?',
        'line'     => $caller['line'] ?? 0,
        'function' => ($caller['class'] ?? '') . ($caller['type'] ?? '') . ($caller['function'] ?? '?'),
        'depth'    => count($bt),
    ];
    if (strpos($entry['file'], 'vendor/composer') !== false) return;
    if (strpos($entry['file'], 'vendor/autoload') !== false) return;
    $__trace_log[] = $entry;
    if (count($__trace_log) > 20000) { __tick_flush(); }
}

function __tick_flush() {
    global $__trace_log, $__trace_file;
    file_put_contents($__trace_file, json_encode($__trace_log, JSON_PRETTY_PRINT));
    $__trace_log = [];
}

register_tick_function('__tick_tracer');
register_shutdown_function('__tick_flush');
declare(ticks=1);
```

**Limitations**:
- ~10–50× performance overhead — single-request tracing only.
- Cannot capture internal (C-extension) functions; userland only.
- `declare(ticks=1)` scoped to current file; `auto_prepend_file` needed for global coverage.

---

### Step 3 — Approach B — Framework Middleware Injection

**Prerequisite**: Target framework identified (Laravel / ThinkPHP / WordPress).

| Field | Fill-in Value |
|-------|---------------|
| `framework` | {Laravel / ThinkPHP / WordPress} |
| `injection_target` | {middleware class / behavior hook / mu-plugins} |
| `injection_command` | {docker cp + registration command} |

#### Laravel — AuditTraceMiddleware

```php
<?php
namespace App\Http\Middleware;
use Closure;
use Illuminate\Http\Request;

class AuditTraceMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $traceLog = [];
        $startTime = microtime(true);
        $tickFn = function() use (&$traceLog, $startTime) {
            $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
            if (count($bt) < 2) return;
            $c = $bt[1];
            $traceLog[] = [
                'ms' => round((microtime(true) - $startTime) * 1000, 2),
                'fn' => ($c['class'] ?? '') . ($c['type'] ?? '') . ($c['function'] ?? ''),
                'file' => basename($c['file'] ?? ''),
                'line' => $c['line'] ?? 0,
            ];
        };
        register_tick_function($tickFn);
        $response = $next($request);
        unregister_tick_function($tickFn);
        file_put_contents('/tmp/laravel_trace_' . uniqid() . '.json',
            json_encode($traceLog, JSON_PRETTY_PRINT));
        return $response;
    }
}
```

Injection:
```bash
docker cp AuditTraceMiddleware.php php:/var/www/html/app/Http/Middleware/
docker exec php sed -i '/\$middleware = \[/a \ \ \ \ \\App\\Http\\Middleware\\AuditTraceMiddleware::class,' \
  /var/www/html/app/Http/Kernel.php
```

#### ThinkPHP — Behavior Hook

```php
<?php
namespace app\behavior;
class AuditTrace
{
    public function appBegin(&$params)
    {
        $GLOBALS['__tp_trace'] = [];
        register_tick_function(function() {
            $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
            if (count($bt) >= 2) {
                $GLOBALS['__tp_trace'][] = ($bt[1]['class'] ?? '') .
                    ($bt[1]['type'] ?? '') . ($bt[1]['function'] ?? '');
            }
        });
    }
    public function appEnd(&$params)
    {
        file_put_contents('/tmp/tp_trace_' . uniqid() . '.json',
            json_encode($GLOBALS['__tp_trace'] ?? [], JSON_PRETTY_PRINT));
    }
}
```

#### WordPress — mu-plugins `all` Action

```php
<?php
// wp-content/mu-plugins/audit-trace.php
$GLOBALS['__wp_trace'] = [];
add_action('all', function($tag) {
    $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
    $caller = $bt[2] ?? $bt[1] ?? [];
    $GLOBALS['__wp_trace'][] = [
        'hook' => $tag,
        'fn'   => ($caller['class'] ?? '') . ($caller['type'] ?? '') . ($caller['function'] ?? ''),
        'file' => basename($caller['file'] ?? ''),
    ];
}, 1);
add_action('shutdown', function() {
    if (!isset($_COOKIE['XDEBUG_TRIGGER']) && !isset($_GET['TRACE'])) return;
    file_put_contents('/tmp/wp_trace_' . uniqid() . '.json',
        json_encode($GLOBALS['__wp_trace'], JSON_PRETTY_PRINT));
});
```

---

### Step 4 — Approach C — strace / ltrace System-Level Tracing

**Prerequisite**: PHP < 7.0 **or** code-level injection impossible (read-only filesystem, no `auto_prepend_file`).

| Field | Fill-in Value |
|-------|---------------|
| `trace_tool` | {strace / ltrace} |
| `target_pid` | {PID of php-fpm pool worker} |
| `syscalls_to_trace` | {open, read, write, connect, execve} |
| `output_file` | {/tmp/strace_output.txt} |

```bash
strace -f -e trace=open,read,write,connect,execve \
  -p $(docker exec php pgrep -f 'php-fpm: pool www' | head -1) \
  -o /tmp/strace_output.txt &
STRACE_PID=$!
docker exec php curl -s http://nginx:80/target/route
kill $STRACE_PID

grep -E '(open|execve).*\.(php|inc|tpl)' /tmp/strace_output.txt   # loaded files
grep 'connect.*:3306' /tmp/strace_output.txt                       # MySQL
grep 'connect.*:6379' /tmp/strace_output.txt                       # Redis
```

**Interpreting strace output**:

| Pattern | Meaning |
|---------|---------|
| `open("/var/www/html/app/Models/User.php", ...)` | PHP file loaded (≈ include trace) |
| `connect(…, sin_port=htons(3306))` | Database operation |
| `execve("/bin/sh", ["sh", "-c", …])` | Command execution — RCE sink evidence |

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Selected approach | (in-memory) | One of: `xdebug`, `tick_function`, `middleware_injection`, `strace` |
| Injection artifacts | Container filesystem | Tracer scripts copied into the container |

## Examples

### ✅ GOOD — Complete strategy selection

```json
{
  "xdebug_available": false,
  "php_version": "7.4",
  "framework_type": "Laravel",
  "auto_prepend_available": true,
  "selected_approach": "middleware_injection",
  "injection_target": "App\\Http\\Middleware\\AuditTraceMiddleware",
  "fallback_chain": ["middleware_injection", "tick_function", "strace"]
}
```

All decision factors documented, approach selected with full context.

### ❌ BAD — No decision context

```json
{
  "selected_approach": "strace"
}
```

Problems: No evidence of why strace was chosen, missing `xdebug_available`, `php_version`, `framework_type`.

## Error Handling

| Error | Action |
|-------|--------|
| All approaches fail (cannot inject, strace unavailable) | Mark route as `trace_impossible`; fall back entirely to context_pack static analysis |
| `auto_prepend_file` write rejected | Try direct `require` injection; if that fails, try Approach C |
| Framework type misidentified | Fall back to Approach A (generic tick tracing) |
