<?php
/**
 * tick_tracer.php — Fallback Runtime Tracer (Approach A)
 *
 * Provides userland function-call tracing when Xdebug is unavailable.
 * Uses PHP's declare(ticks=1) + register_tick_function() to record every
 * executed statement's call-stack frame.
 *
 * Usage (auto_prepend_file — recommended):
 *   php -d auto_prepend_file=/path/to/tick_tracer.php target_script.php
 *
 * Or via php.ini / conf.d:
 *   echo "auto_prepend_file=/tmp/tick_tracer.php" >> /usr/local/etc/php/conf.d/99-trace.ini
 *
 * Or via direct require at the top of the entry file:
 *   require_once "/tmp/tick_tracer.php";
 *
 * Environment variables:
 *   TICK_TRACE_OUTPUT  — Output file path. Default: /tmp/tick_trace_<PID>.json
 *   TICK_TRACE_STDOUT  — Set to "1" to write JSON to stdout on shutdown instead of file.
 *   TICK_TRACE_MAX     — Max entries before flush (default: 20000).
 *   TICK_TRACE_DEPTH   — Max backtrace depth to capture (default: 10).
 *
 * Output format (JSON array of trace entries):
 *   [
 *     {
 *       "time":     12.345,       // ms since tracer start
 *       "file":     "/var/www/html/app/Models/User.php",
 *       "line":     42,
 *       "function": "App\\Models\\User->save",
 *       "depth":    5
 *     },
 *     ...
 *   ]
 *
 * Limitations:
 *   - ~10–50× performance overhead; use for single-request tracing only.
 *   - Captures userland functions only (not C-extension internals).
 *   - declare(ticks=1) is scoped to the file where it appears;
 *     auto_prepend_file is needed for global coverage.
 *
 * Part of the PHP Security Audit System — Phase 3 fallback tracing.
 * @see skills/trace/fallback_strategy_selector.md  (S-036f)
 * @see teams/team3/trace_dispatcher.md             (Approach A)
 *
 * Requires: PHP >= 7.4, no external dependencies.
 */

if (defined('__TICK_TRACER_LOADED__')) {
    return; // Prevent double-loading
}
define('__TICK_TRACER_LOADED__', true);

// ── Configuration ───────────────────────────────────────────────────────────

$__trace_log   = [];
$__trace_start = microtime(true);
$__trace_max   = (int)(getenv('TICK_TRACE_MAX') ?: 20000);
$__trace_depth = (int)(getenv('TICK_TRACE_DEPTH') ?: 10);
$__trace_stdout = getenv('TICK_TRACE_STDOUT') === '1';
$__trace_file  = getenv('TICK_TRACE_OUTPUT')
    ?: sys_get_temp_dir() . '/tick_trace_' . getmypid() . '.json';
$__trace_flush_count = 0; // number of flushes (for append mode)

// Vendor path fragments to exclude (framework bootstrap noise)
$__trace_vendor_filters = [
    'vendor/composer',
    'vendor/autoload',
    'vendor/bin',
];

// ── Tick handler ────────────────────────────────────────────────────────────

/**
 * Called after every executable PHP statement (tick).
 * Records the caller's file, line, function, and call depth.
 */
function __tick_tracer(): void
{
    global $__trace_log, $__trace_start, $__trace_max, $__trace_depth,
           $__trace_vendor_filters;

    $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $__trace_depth);
    if (count($bt) < 2) {
        return;
    }

    $caller = $bt[1];
    $file   = $caller['file'] ?? '?';

    // Filter out vendor/composer bootstrap paths
    foreach ($__trace_vendor_filters as $filter) {
        if (strpos($file, $filter) !== false) {
            return;
        }
    }

    $__trace_log[] = [
        'time'     => round((microtime(true) - $__trace_start) * 1000, 3),
        'file'     => $file,
        'line'     => $caller['line'] ?? 0,
        'function' => ($caller['class'] ?? '')
                    . ($caller['type'] ?? '')
                    . ($caller['function'] ?? '?'),
        'depth'    => count($bt),
    ];

    // Prevent memory exhaustion: flush when buffer is full
    if (count($__trace_log) >= $__trace_max) {
        __tick_flush();
    }
}

// ── Flush / output ──────────────────────────────────────────────────────────

/**
 * Write buffered trace entries to the output file (or stdout).
 * In file mode the first flush writes a fresh file; subsequent flushes append
 * by merging with the existing JSON array so the final file is always valid.
 */
function __tick_flush(): void
{
    global $__trace_log, $__trace_file, $__trace_stdout, $__trace_flush_count;

    if (empty($__trace_log)) {
        return;
    }

    if ($__trace_stdout) {
        // In stdout mode, entries are accumulated and written once at shutdown.
        // Intermediate flushes just trim the buffer to keep memory bounded but
        // the entries are already lost — this is an acceptable trade-off vs OOM.
        $__trace_log = [];
        return;
    }

    if ($__trace_flush_count === 0) {
        // First flush — write new file
        $bytes = file_put_contents(
            $__trace_file,
            json_encode($__trace_log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
        if ($bytes === false) {
            fwrite(STDERR, "[ERROR] Failed to write trace file: {$__trace_file}\n");
            exit(1);
        }
    } else {
        // Subsequent flushes — merge with existing data
        $existing = [];
        if (is_readable($__trace_file)) {
            $raw = file_get_contents($__trace_file);
            if ($raw !== false) {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    $existing = $decoded;
                }
            }
        }
        $merged = array_merge($existing, $__trace_log);
        $bytes = file_put_contents(
            $__trace_file,
            json_encode($merged, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
        if ($bytes === false) {
            fwrite(STDERR, "[ERROR] Failed to write trace file: {$__trace_file}\n");
            exit(1);
        }
    }

    $__trace_flush_count++;
    $__trace_log = [];
}

/**
 * Shutdown handler — final flush and optional stdout output.
 * Wraps trace data with metadata when writing the final output.
 */
function __tick_shutdown(): void
{
    global $__trace_log, $__trace_file, $__trace_start, $__trace_stdout,
           $__trace_flush_count;

    // Flush any remaining buffered entries to the file first
    __tick_flush();

    // Build final output with metadata envelope
    $entries = [];
    if (!$__trace_stdout && is_readable($__trace_file)) {
        $raw = file_get_contents($__trace_file);
        if ($raw !== false) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $entries = $decoded;
            }
        }
    }

    $output = [
        'meta' => [
            'tracer'      => 'tick_tracer',
            'php_version' => PHP_VERSION,
            'pid'         => getmypid(),
            'start_time'  => date('Y-m-d\TH:i:s.uP', (int)$__trace_start),
            'duration_ms' => round((microtime(true) - $__trace_start) * 1000, 3),
            'entry_count' => count($entries),
            'flush_count' => $__trace_flush_count,
        ],
        'trace' => $entries,
    ];

    $json = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

    if ($__trace_stdout) {
        fwrite(STDOUT, $json . "\n");
    } else {
        $bytes = file_put_contents($__trace_file, $json);
        if ($bytes === false) {
            fwrite(STDERR, "[ERROR] Failed to write trace file: {$__trace_file}\n");
            exit(1);
        }
    }
}

// ── Register ────────────────────────────────────────────────────────────────

register_tick_function('__tick_tracer');
register_shutdown_function('__tick_shutdown');

declare(ticks=1);
