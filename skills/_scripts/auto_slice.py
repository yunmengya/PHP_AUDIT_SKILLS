#!/usr/bin/env python3
import os
import re
from typing import Dict, Optional, Tuple

from common import write_text


FUNC_RE = re.compile(r"\bfunction\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b")
STATIC_RE = re.compile(r"\bstatic\b")
VAR_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
CONTROL_RE = re.compile(r"\b(if|else|elseif|for|foreach|while|switch|case|try|catch)\b", re.I)

DEFAULT_AUTH_KEYWORDS = [
    "auth", "permission", "acl", "rbac", "session", "token", "middleware", "guard",
    "login", "islogin", "checkauth", "isadmin", "authorize", "capability", "role", "policy",
]
DEFAULT_SINK_PATTERNS = [
    r"\b(system|exec|passthru|shell_exec|popen|proc_open|eval|assert)\b",
    r"\b(file_get_contents|readfile|fopen|file_put_contents|fwrite)\b",
    r"\b(curl_init|simplexml_load_string|unserialize)\b",
    r"->\s*(query|exec|prepare)\s*\(",
]

VULN_SINK_KEYS = {
    "sql_injection": ["sink_patterns_sql"],
    "sql": ["sink_patterns_sql"],
    "command_exec": ["sink_patterns_rce"],
    "rce": ["sink_patterns_rce"],
    "file": ["sink_patterns_file"],
    "ssrf": ["sink_patterns_ssrf"],
    "xxe": ["sink_patterns_xxe"],
    "ssrf_xxe": ["sink_patterns_ssrf", "sink_patterns_xxe"],
    "xss": ["sink_patterns_xss"],
    "ssti": ["sink_patterns_ssti"],
    "xss_ssti": ["sink_patterns_xss", "sink_patterns_ssti"],
    "deserialization": ["sink_patterns_serialize"],
    "serialize": ["sink_patterns_serialize"],
}

RULES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "php-audit-common", "references", "auto_slice_rules.yml")
)


def _load_rules(path: str) -> Dict[str, list]:
    rules = {"auth_keywords": [], "sink_patterns": []}
    if not os.path.exists(path):
        return rules
    current = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.endswith(":"):
                    key = line[:-1].strip()
                    if key in rules:
                        current = key
                    else:
                        current = None
                    continue
                if line.startswith("-") and current:
                    value = line[1:].strip()
                    if value:
                        rules[current].append(value)
    except Exception:
        return rules
    return rules


def _compile_auth_re() -> re.Pattern:
    rules = _load_rules(RULES_PATH)
    keywords = rules.get("auth_keywords") or []
    if not keywords:
        keywords = DEFAULT_AUTH_KEYWORDS
    escaped = [re.escape(k) for k in keywords]
    return re.compile(r"\b(" + "|".join(escaped) + r")\b", re.I)


def _compile_sink_re() -> re.Pattern:
    rules = _load_rules(RULES_PATH)
    patterns = rules.get("sink_patterns") or []
    if not patterns:
        patterns = DEFAULT_SINK_PATTERNS
    combined = "|".join(patterns)
    try:
        return re.compile(combined, re.I)
    except re.error:
        return re.compile("|".join(DEFAULT_SINK_PATTERNS), re.I)


AUTH_RE = _compile_auth_re()
GENERIC_SINK_RE = _compile_sink_re()


def _compile_sink_re_for_vuln(vuln_type: str) -> re.Pattern:
    rules = _load_rules(RULES_PATH)
    keys = VULN_SINK_KEYS.get((vuln_type or "").lower(), [])
    patterns = []
    for key in keys:
        patterns.extend(rules.get(key) or [])
    if not patterns:
        return GENERIC_SINK_RE
    combined = "|".join(patterns)
    try:
        return re.compile(combined, re.I)
    except re.error:
        return GENERIC_SINK_RE



def _resolve_sink_file(case: Dict, project_root: str) -> Optional[str]:
    sink = case.get("sink") or {}
    sink_file = sink.get("file") or ""
    if not sink_file:
        return None
    if os.path.isabs(sink_file):
        return sink_file if os.path.exists(sink_file) else None
    cand = os.path.join(project_root, sink_file)
    if os.path.exists(cand):
        return cand
    cand = os.path.join(project_root, sink_file.lstrip("./"))
    if os.path.exists(cand):
        return cand
    return None


def _resolve_sink_line(case: Dict) -> Optional[int]:
    sink = case.get("sink") or {}
    line = sink.get("line")
    if isinstance(line, int) and line > 0:
        return line
    source_path = case.get("source_path") or ""
    if ":" in source_path:
        try:
            return int(source_path.rsplit(":", 1)[-1])
        except Exception:
            pass
    trace_chain = case.get("trace_chain") or []
    if trace_chain:
        last = trace_chain[-1]
        tline = last.get("line")
        if isinstance(tline, int) and tline > 0:
            return tline
    return None


def _pick_var_from_line(line: str) -> Optional[str]:
    # Prefer variables inside call arguments
    m = re.search(r"\(([^)]*)\)", line)
    if m:
        arg_block = m.group(1)
        mv = VAR_RE.search(arg_block)
        if mv:
            return mv.group(0)
    vars_found = VAR_RE.findall(line)
    if not vars_found:
        return None
    return vars_found[-1]


def _is_auth_line(code: str) -> bool:
    return bool(AUTH_RE.search(code))


def _is_control_line(code: str) -> bool:
    if "{" in code or "}" in code:
        return True
    return bool(CONTROL_RE.search(code))


def _normalize_code(code: str) -> str:
    code = code.strip()
    if not code:
        return ""
    if not code.endswith(";"):
        code = code + ";"
    return code


def _build_trace_lines(case: Dict) -> Tuple[list, bool]:
    chain = case.get("trace_chain") or []
    sink = case.get("sink") or {}
    sink_file = sink.get("file") or ""
    sink_line = _resolve_sink_line(case)
    sink_func_pattern = sink.get("function") or ""
    vuln_type = (case.get("vuln_type") or "").lower()
    sink_re = None
    if isinstance(sink_func_pattern, str) and sink_func_pattern:
        try:
            sink_re = re.compile(sink_func_pattern)
        except re.error:
            sink_re = None
    type_sink_re = _compile_sink_re_for_vuln(vuln_type)
    lines = []
    skipped_auth = False
    seen = set()
    for node in chain:
        if not isinstance(node, dict):
            continue
        code = (node.get("code") or "").strip()
        if not code or code in ("source", "sink"):
            continue
        node_file = node.get("file") or ""
        if sink_file and node_file and os.path.normpath(node_file) != os.path.normpath(sink_file):
            continue
        node_line = node.get("line")
        if sink_line and isinstance(node_line, int) and node_line > sink_line:
            continue
        if _is_auth_line(code):
            skipped_auth = True
            continue
        if type_sink_re.search(code):
            continue
        if sink_re and sink_re.search(code):
            # skip direct sink call line
            continue
        if _is_control_line(code):
            # Avoid broken syntax blocks in slices
            continue
        code = _normalize_code(code)
        if code and code not in seen:
            seen.add(code)
            lines.append(code)
    return lines, skipped_auth


def _php_single_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _assignment_target_var(code: str) -> Optional[str]:
    # Detect simple assignments like "$x = ...;" and compound assignments.
    m = re.match(r"^\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*(=|\+=|-=|\*=|/=|\.=|%=)", code)
    if not m:
        return None
    return m.group(1)


def _render_trace_exec_block(trace_lines: list) -> str:
    out = []
    for idx, code in enumerate(trace_lines, start=1):
        expr = _php_single_quote(code)
        target = _assignment_target_var(code)
        if target:
            out.append(f"$__debug_before_{idx} = isset({target}) ? {target} : null;")
            out.append(code)
            out.append(f"$__debug_after_{idx} = isset({target}) ? {target} : null;")
            out.append(
                f"__debug_track({idx}, '{expr}', $__debug_before_{idx}, $__debug_after_{idx}, __FILE__, __LINE__, 'trace_line');"
            )
        else:
            out.append(code)
            out.append(f"__debug_track({idx}, '{expr}', null, null, __FILE__, __LINE__, 'trace_line');")
    return os.linesep.join(out)


def _debug_runtime_helpers_php() -> str:
    return """$__debug_transform_chain = [];
$__debug_transform_steps = [];

function __debug_to_text($v) {
    if (is_null($v)) { return 'null'; }
    if (is_bool($v)) { return $v ? 'true' : 'false'; }
    if (is_scalar($v)) { return (string)$v; }
    if (is_array($v)) { return json_encode($v, JSON_UNESCAPED_UNICODE); }
    if (is_object($v)) { return '[object:' . get_class($v) . ']'; }
    return '[unknown]';
}

function __debug_stack($limit = 8) {
    $frames = [];
    foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $limit) as $f) {
        $frames[] = [
            'function' => $f['function'] ?? '',
            'class' => $f['class'] ?? '',
            'type' => $f['type'] ?? '',
            'file' => $f['file'] ?? '',
            'line' => $f['line'] ?? 0,
        ];
    }
    return $frames;
}

function __debug_track($step, $expr, $before, $after, $file = '', $line = 0, $function = 'trace') {
    global $__debug_transform_chain, $__debug_transform_steps;
    $beforeText = __debug_to_text($before);
    $afterText = __debug_to_text($after);
    $changed = ($beforeText !== $afterText);
    $op = $changed ? 'weak_change' : 'no_change';
    if ($changed) {
        $exprLower = strtolower((string)$expr);
        foreach (['htmlspecialchars','htmlentities','strip_tags','intval','floatval','urlencode','rawurlencode','base64_encode','preg_replace','filter_var','trim'] as $kw) {
            if (strpos($exprLower, $kw) !== false) {
                $op = 'strong_change';
                break;
            }
        }
    }
    $__debug_transform_chain[] = $op;
    $__debug_transform_steps[] = [
        'step' => (int)$step,
        'function' => (string)$function,
        'file' => (string)$file,
        'line' => (int)$line,
        'expr' => (string)$expr,
        'op' => $op,
        'changed' => $changed,
        'before' => $beforeText,
        'after' => $afterText,
    ];
}

function __debug_emit($input, $final_value, $chain, $status, $notes = '', $sink_probe_hit = false, $taint_reached = false) {
    $beforeSink = $GLOBALS['__debug_before_sink'] ?? null;
    $result = [
        'status' => $status,
        'input' => $input,
        'final_value' => $final_value,
        'transform_chain' => $chain,
        'transform_steps' => $GLOBALS['__debug_transform_steps'] ?? [],
        'call_stack' => __debug_stack(),
        'var_snapshot' => [
            'before_sink' => __debug_to_text($beforeSink),
            'after_sink' => __debug_to_text($final_value),
            'input' => __debug_to_text($input),
            'final_value' => __debug_to_text($final_value),
            'get' => $_GET ?? [],
            'post' => $_POST ?? [],
            'body' => $GLOBALS['__debug_input_map']['BODY'] ?? [],
            'cookie' => $_COOKIE ?? [],
        ],
        'sink_probe_hit' => $sink_probe_hit ? true : false,
        'taint_var_reached_sink' => $taint_reached ? true : false,
        'notes' => $notes
    ];
    echo json_encode($result, JSON_UNESCAPED_UNICODE);
    $GLOBALS['__debug_done'] = true;
}
"""


def _find_enclosing_function(lines: list, sink_idx: int) -> Tuple[Optional[str], Optional[str], bool, Optional[int]]:
    func_name = None
    func_line = None
    is_static = False
    for i in range(sink_idx, -1, -1):
        line = lines[i]
        m = FUNC_RE.search(line)
        if m:
            func_name = m.group(1)
            func_line = i
            is_static = bool(STATIC_RE.search(line))
            break
    if func_name is None:
        return None, None, False, None

    class_name = None
    for j in range(func_line, -1, -1):
        cm = CLASS_RE.search(lines[j])
        if cm:
            class_name = cm.group(1)
            break

    param_count = None
    line = lines[func_line]
    if "(" in line and ")" in line and line.find("(") < line.rfind(")"):
        sig = line[line.find("(") + 1: line.rfind(")")]
        if sig.strip() == "":
            param_count = 0
        else:
            parts = [p for p in sig.split(",") if p.strip()]
            param_count = len(parts)
    return func_name, class_name, is_static, param_count


def _insert_probe(lines: list, sink_idx: int, var_expr: Optional[str]) -> list:
    if sink_idx < 0 or sink_idx > len(lines):
        sink_idx = len(lines)
    indent = ""
    if sink_idx < len(lines):
        indent = re.match(r"^\s*", lines[sink_idx]).group(0)
    var_expr = var_expr or "null"
    probe = [
        "%sif (function_exists('__debug_emit')) {\n" % indent,
        "%s    $__debug_before_probe = @(%s);\n" % (indent, var_expr),
        "%s    $GLOBALS['__debug_before_sink'] = $__debug_before_probe;\n" % indent,
        "%s    $__debug_final_value = $__debug_before_probe;\n" % indent,
        "%s    if (function_exists('__debug_track')) { __debug_track(9999, 'sink_probe', $__debug_before_probe, $__debug_final_value, __FILE__, __LINE__, 'sink_probe'); }\n" % indent,
        "%s    $__debug_taint_reached = ((string)($__debug_input_value ?? '') !== '' && strpos((string)$__debug_final_value, (string)($__debug_input_value ?? '')) !== false);\n" % indent,
        "%s    __debug_emit($__debug_input_value ?? '', $__debug_final_value, $__debug_transform_chain ?? [], 'done', 'auto_probe', true, $__debug_taint_reached);\n" % indent,
        "%s    exit;\n" % indent,
        "%s}\n" % indent,
    ]
    return lines[:sink_idx] + probe + lines[sink_idx:]


def _write_instrumented(case_id: str, sink_file: str, sink_line: int, out_root: str) -> Tuple[Optional[str], str]:
    try:
        with open(sink_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None, "sink_read_failed"
    if not lines:
        return None, "sink_empty"
    sink_idx = max(0, min(len(lines) - 1, sink_line - 1))
    var_expr = _pick_var_from_line(lines[sink_idx])
    new_lines = _insert_probe(lines, sink_idx, var_expr)

    inst_dir = os.path.join(out_root, "debug_verify", "instrumented")
    os.makedirs(inst_dir, exist_ok=True)
    base = os.path.basename(sink_file)
    inst_path = os.path.join(inst_dir, f"{case_id}__{base}")
    write_text(inst_path, "".join(new_lines))
    return inst_path, ""


def _slice_has_manual_content(slice_path: str) -> bool:
    if not os.path.exists(slice_path):
        return False
    try:
        text = open(slice_path, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return False
    # If user already edited, avoid overwrite.
    if "Debug slice template" in text:
        return False
    if "AUTO_SLICE" in text:
        return False
    return True


def generate_slice_for_case(case: Dict, project_root: str, out_root: str) -> str:
    case_id = case.get("case_id") or "UNSET"
    debug_script = case.get("debug_script")
    if not debug_script:
        return "auto_slice:missing_debug_script"
    if _slice_has_manual_content(debug_script):
        return "auto_slice:skip_existing_manual"

    trace_lines, skipped_auth = _build_trace_lines(case)
    sink_file = _resolve_sink_file(case, project_root)
    sink_line = _resolve_sink_line(case)

    # Prefer trace-only slice: no auth, no external deps
    if trace_lines:
        debug_dir = os.path.join(out_root, "debug_verify")
        os.makedirs(os.path.dirname(debug_script), exist_ok=True)
        sink_code = (case.get("sink") or {}).get("code") or ""
        var_expr = _pick_var_from_line(sink_code) or _pick_var_from_line(trace_lines[-1])
        trace_exec = _render_trace_exec_block(trace_lines)

        auth_note = "auth_skipped" if skipped_auth else ""
        note_text = "auto_slice_trace_only"
        if auth_note:
            note_text = f"{note_text};{auth_note}"
        note_text_q = _php_single_quote(note_text)

        if not var_expr:
            slice_content = f"""<?php
// AUTO_SLICE (TRACE_ONLY) for {case_id}
$inputMap = json_decode(getenv('DEBUG_INPUT_JSON') ?: '{{}}', true);
$_GET = $inputMap['GET'] ?? [];
$_POST = $inputMap['POST'] ?? [];
$_COOKIE = $inputMap['COOKIE'] ?? [];
$_SERVER = array_merge($_SERVER, $inputMap['HEADER'] ?? []);

$__debug_input_value = '';
foreach (['GET','POST','COOKIE','HEADER','BODY'] as $k) {{
    if (!empty($inputMap[$k]) && is_array($inputMap[$k])) {{
        $firstKey = array_key_first($inputMap[$k]);
        $__debug_input_value = (string)($inputMap[$k][$firstKey] ?? '');
        break;
    }}
}}
$GLOBALS['__debug_input_map'] = $inputMap;
{_debug_runtime_helpers_php()}

// TRACE LINES
{trace_exec}

$GLOBALS['__debug_before_sink'] = null;
__debug_emit($__debug_input_value, '__TODO__', $__debug_transform_chain ?? [], 'pending', '{note_text_q};no_var', false, false);
"""
            write_text(debug_script, slice_content)
            return note_text

        slice_content = f"""<?php
// AUTO_SLICE (TRACE_ONLY) for {case_id}
$inputMap = json_decode(getenv('DEBUG_INPUT_JSON') ?: '{{}}', true);
$_GET = $inputMap['GET'] ?? [];
$_POST = $inputMap['POST'] ?? [];
$_COOKIE = $inputMap['COOKIE'] ?? [];
$_SERVER = array_merge($_SERVER, $inputMap['HEADER'] ?? []);

$__debug_input_value = '';
foreach (['GET','POST','COOKIE','HEADER','BODY'] as $k) {{
    if (!empty($inputMap[$k]) && is_array($inputMap[$k])) {{
        $firstKey = array_key_first($inputMap[$k]);
        $__debug_input_value = (string)($inputMap[$k][$firstKey] ?? '');
        break;
    }}
}}
$GLOBALS['__debug_input_map'] = $inputMap;
{_debug_runtime_helpers_php()}

// TRACE LINES
{trace_exec}

$GLOBALS['__debug_before_sink'] = {var_expr};
$__debug_final_value = {var_expr};
$__debug_taint_reached = ((string)($__debug_input_value ?? '') !== '' && strpos((string)$__debug_final_value, (string)($__debug_input_value ?? '')) !== false);
__debug_emit($__debug_input_value, $__debug_final_value, $__debug_transform_chain ?? [], 'done', '{note_text_q}', true, $__debug_taint_reached);
"""
        write_text(debug_script, slice_content)
        return note_text

    if not sink_file or not sink_line:
        return "auto_slice:missing_sink"

    inst_path, err = _write_instrumented(case_id, sink_file, sink_line, out_root)
    if err or not inst_path:
        return f"auto_slice:{err or 'instrument_failed'}"

    try:
        with open(sink_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        lines = []

    sink_idx = max(0, min(len(lines) - 1, sink_line - 1)) if lines else 0
    func_name, class_name, is_static, param_count = _find_enclosing_function(lines, sink_idx)

    inst_rel = os.path.relpath(inst_path, os.path.dirname(debug_script))
    bootstrap_path = os.path.join(out_root, "debug_verify", "bootstrap_min.php")
    if not os.path.exists(bootstrap_path):
        os.makedirs(os.path.dirname(bootstrap_path), exist_ok=True)
        write_text(
            bootstrap_path,
            "<?php\n// Optional bootstrap for auto slice.\n// You can add project-specific requires here if needed.\n"
            "$autoload = getenv('DEBUG_AUTOLOAD') ?: '';\n"
            "if ($autoload && file_exists($autoload)) { require_once $autoload; }\n"
        )

    args_count = param_count if isinstance(param_count, int) else 1
    if args_count < 0:
        args_count = 0

    call_snippet = "/* no callable found */"
    if func_name:
        if class_name:
            if is_static:
                call_snippet = f"$__debug_callable = ['{class_name}', '{func_name}'];"
            else:
                call_snippet = (
                    f"$__debug_obj = null;\n"
                    f"try {{ $__debug_obj = new {class_name}(); }} catch (Throwable $e) {{ $__debug_obj = null; $__debug_last_error = $e; }}\n"
                    f"if ($__debug_obj) {{ $__debug_callable = [$__debug_obj, '{func_name}']; }}"
                )
        else:
            call_snippet = f"$__debug_callable = '{func_name}';"

    slice_content = f"""<?php
// AUTO_SLICE for {case_id}
$inputMap = json_decode(getenv('DEBUG_INPUT_JSON') ?: '{{}}', true);
$_GET = $inputMap['GET'] ?? [];
$_POST = $inputMap['POST'] ?? [];
$_COOKIE = $inputMap['COOKIE'] ?? [];
$_SERVER = array_merge($_SERVER, $inputMap['HEADER'] ?? []);

$__debug_input_value = '';
foreach (['GET','POST','COOKIE','HEADER','BODY'] as $k) {{
    if (!empty($inputMap[$k]) && is_array($inputMap[$k])) {{
        $firstKey = array_key_first($inputMap[$k]);
        $__debug_input_value = (string)($inputMap[$k][$firstKey] ?? '');
        break;
    }}
}}
$GLOBALS['__debug_input_map'] = $inputMap;
{_debug_runtime_helpers_php()}
$GLOBALS['__debug_done'] = false;

function __debug_build_args($count, $input) {{
    $args = [];
    if ($count <= 0) {{
        return $args;
    }}
    $args[] = $input;
    for ($i = 1; $i < $count; $i++) {{
        $args[] = null;
    }}
    return $args;
}}

require_once '{bootstrap_path}';
require_once '{inst_rel}';

$__debug_callable = null;
$__debug_last_error = null;
{call_snippet}

if ($__debug_callable) {{
    try {{
        $args = __debug_build_args({args_count}, $__debug_input_value);
        call_user_func_array($__debug_callable, $args);
    }} catch (Throwable $e) {{
        $__debug_last_error = $e;
    }}
}}

if (empty($GLOBALS['__debug_done'])) {{
    $note = $__debug_last_error ? ('call_failed:' . $__debug_last_error->getMessage()) : 'auto_slice_not_executed';
    __debug_emit($__debug_input_value, '__TODO__', $__debug_transform_chain ?? [], 'pending', $note, false, false);
}}
"""
    write_text(debug_script, slice_content)
    if skipped_auth:
        return "auth_skipped"
    return ""
