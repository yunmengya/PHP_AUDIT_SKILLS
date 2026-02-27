#!/usr/bin/env python3
import json
import os
import re
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

SQL_SINK_PATTERNS = [
    {"type": "sql", "regex": re.compile(r"\b(mysql_query|mysqli_query|pg_query|sqlite_query)\b", re.I)},
    {"type": "sql", "regex": re.compile(r"\b(PDO::query|PDO::exec|PDO::prepare)\b", re.I)},
    {"type": "sql", "regex": re.compile(r"\bDB::(select|statement|insert|update|delete|raw)\b", re.I)},
    {"type": "sql", "regex": re.compile(r"->\s*(query|exec|prepare)\s*\(", re.I)},
    {"type": "sql", "regex": re.compile(r"->\s*(whereRaw|orderByRaw|havingRaw)\s*\(", re.I)},
]

RCE_SINK_PATTERNS = [
    {"type": "rce", "regex": re.compile(r"\b(exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\b", re.I)},
    {"type": "rce", "regex": re.compile(r"\b(eval|assert)\b", re.I)},
]

FILE_SINK_PATTERNS = [
    {"type": "file", "regex": re.compile(r"\b(file_get_contents|readfile|fopen|file|file_put_contents|fwrite)\b", re.I)},
    {"type": "file", "regex": re.compile(r"\b(unlink|rename|copy|mkdir|rmdir)\b", re.I)},
    {"type": "file", "regex": re.compile(r"\b(move_uploaded_file)\b", re.I)},
]

INCLUDE_SINK_PATTERNS = [
    {"type": "include", "regex": re.compile(r"\b(include|include_once|require|require_once)\b", re.I)},
]

SSRF_SINK_PATTERNS = [
    {"type": "ssrf", "regex": re.compile(r"\b(curl_init|curl_setopt|curl_exec)\b", re.I)},
    {"type": "ssrf", "regex": re.compile(r"\b(file_get_contents|fopen|fsockopen|stream_socket_client|get_headers)\b", re.I)},
]

XXE_SINK_PATTERNS = [
    {"type": "xxe", "regex": re.compile(r"\b(simplexml_load_string|simplexml_load_file|xml_parse|xml_parse_into_struct)\b", re.I)},
    {"type": "xxe", "regex": re.compile(r"DOMDocument->\s*load(XML)?\s*\(", re.I)},
]

XSS_SINK_PATTERNS = [
    {"type": "xss", "regex": re.compile(r"\b(echo|print|printf|vprintf|die|exit)\b", re.I)},
]

SSTI_SINK_PATTERNS = [
    {"type": "ssti", "regex": re.compile(r"->\s*render\s*\(", re.I)},
    {"type": "ssti", "regex": re.compile(r"\bTwig\\Environment\b", re.I)},
]

DESERIALIZE_SINK_PATTERNS = [
    {"type": "deserialize", "regex": re.compile(r"\b(unserialize|igbinary_unserialize|yaml_parse)\b", re.I)},
    {"type": "deserialize", "regex": re.compile(r"phar://", re.I)},
]

DESERIALIZE_TRIGGER_PATTERNS = [
    {"type": "deserialize", "regex": re.compile(r"\b(unserialize|igbinary_unserialize|yaml_parse)\b", re.I)},
    {"type": "phar", "regex": re.compile(r"phar://", re.I)},
    {"type": "phar", "regex": re.compile(r"\bPhar(Data)?::\b", re.I)},
    {"type": "phar", "regex": re.compile(r"\bnew\s+Phar\b", re.I)},
]

POP_MAGIC_METHODS = [
    "__wakeup",
    "__destruct",
    "__toString",
    "__call",
    "__callStatic",
    "__get",
    "__set",
    "__invoke",
    "__clone",
]

PATH_FILTER_PATTERNS = [
    ("realpath", re.compile(r"\brealpath\s*\(", re.I)),
    ("basename", re.compile(r"\bbasename\s*\(", re.I)),
    ("dirname", re.compile(r"\bdirname\s*\(", re.I)),
    ("pathinfo", re.compile(r"\bpathinfo\s*\(", re.I)),
    ("normalize", re.compile(r"str_replace\s*\(\s*['\"]\.\./['\"]", re.I)),
    ("trimdots", re.compile(r"preg_replace\s*\(\s*/\.\./", re.I)),
    ("allowlist", re.compile(r"in_array\s*\(", re.I)),
    ("prefix_check", re.compile(r"strpos\s*\(\s*realpath\(", re.I)),
    ("traversal_check", re.compile(r"strpos\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*['\"]\.\.['\"]", re.I)),
]

URL_FILTER_PATTERNS = [
    ("parse_url", re.compile(r"\bparse_url\s*\(", re.I)),
    ("validate_url", re.compile(r"filter_var\s*\([^,]+,\s*FILTER_VALIDATE_URL", re.I)),
    ("scheme_check", re.compile(r"preg_match\s*\(\s*/\^https?:\/\//i", re.I)),
    ("host_allowlist", re.compile(r"in_array\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*\$[A-Za-z_][A-Za-z0-9_]*", re.I)),
    ("host_check", re.compile(r"parse_url\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*PHP_URL_HOST", re.I)),
]

XML_FILTER_PATTERNS = [
    ("libxml_disable_entity_loader", re.compile(r"libxml_disable_entity_loader\s*\(\s*true\s*\)", re.I)),
    ("libxml_nonet", re.compile(r"LIBXML_NONET", re.I)),
    ("external_entity_loader", re.compile(r"libxml_set_external_entity_loader", re.I)),
]

DANGEROUS_FUNCTIONS = {
    "exec": {
        "type": "rce",
        "alternatives": [
            "Prefer built-in APIs instead of shell execution",
            "If needed, use a strict allowlist and fixed argv list",
        ],
        "note": "Avoid shell execution when possible.",
    },
    "system": {
        "type": "rce",
        "alternatives": [
            "Prefer built-in APIs instead of shell execution",
            "If needed, use a strict allowlist and fixed argv list",
        ],
        "note": "Avoid shell execution when possible.",
    },
    "shell_exec": {
        "type": "rce",
        "alternatives": [
            "Prefer built-in APIs instead of shell execution",
            "If needed, use a strict allowlist and fixed argv list",
        ],
        "note": "Avoid shell execution when possible.",
    },
    "passthru": {
        "type": "rce",
        "alternatives": [
            "Prefer built-in APIs instead of shell execution",
            "If needed, use a strict allowlist and fixed argv list",
        ],
        "note": "Avoid shell execution when possible.",
    },
    "popen": {
        "type": "rce",
        "alternatives": [
            "Avoid shell pipes; use safe libraries with explicit argv",
            "Enforce allowlist + timeouts for any external process",
        ],
        "note": "Pipes are high risk with user input.",
    },
    "proc_open": {
        "type": "rce",
        "alternatives": [
            "Use fixed argv lists and disable shell where possible",
            "Enforce allowlist + timeouts for any external process",
        ],
        "note": "Process spawning is high risk with user input.",
    },
    "pcntl_exec": {
        "type": "rce",
        "alternatives": [
            "Use fixed argv lists and allowlist",
            "Avoid executing external commands if possible",
        ],
        "note": "Direct exec of external binaries is high risk.",
    },
    "eval": {
        "type": "rce",
        "alternatives": [
            "Avoid eval; use structured parsing instead (e.g., JSON)",
            "Prefer whitelisted templates or interpreters",
        ],
        "note": "Eval on user input is critical risk.",
    },
    "assert": {
        "type": "rce",
        "alternatives": [
            "Avoid assert() for data handling",
            "Use explicit checks instead of expression evaluation",
        ],
        "note": "assert() evaluates string expressions.",
    },
}

DANGEROUS_FUNC_RE = re.compile(r"\b(" + "|".join(map(re.escape, DANGEROUS_FUNCTIONS.keys())) + r")\b", re.I)

SINK_PATTERNS = (
    SQL_SINK_PATTERNS
    + RCE_SINK_PATTERNS
    + FILE_SINK_PATTERNS
    + INCLUDE_SINK_PATTERNS
    + SSRF_SINK_PATTERNS
    + XXE_SINK_PATTERNS
    + XSS_SINK_PATTERNS
    + SSTI_SINK_PATTERNS
    + DESERIALIZE_SINK_PATTERNS
)

SQL_VALIDATION_PATTERNS = [
    re.compile(r"\bintval\s*\(", re.I),
    re.compile(r"\bfloatval\s*\(", re.I),
    re.compile(r"\bfilter_var\s*\(", re.I),
    re.compile(r"\bctype_\w+\s*\(", re.I),
    re.compile(r"\bpreg_match\s*\(", re.I),
    re.compile(r"\baddslashes\s*\(", re.I),
    re.compile(r"\bmysqli_real_escape_string\s*\(", re.I),
    re.compile(r"\bPDO::quote\s*\(", re.I),
    re.compile(r"\bDB::raw\s*\(", re.I),
]

GENERIC_VALIDATION_PATTERNS = [
    re.compile(r"\bhtmlspecialchars\s*\(", re.I),
    re.compile(r"\bhtmlentities\s*\(", re.I),
    re.compile(r"\bstrip_tags\s*\(", re.I),
    # Laravel / Framework validation helpers
    re.compile(r"\brequest\s*\(\)\s*->\s*validate\s*\(", re.I),
    re.compile(r"\$request\s*->\s*validate\s*\(", re.I),
    re.compile(r"\bValidator::make\s*\(", re.I),
    re.compile(r"\bvalidate\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,", re.I),
    # Yii model validation
    re.compile(r"\b->\s*validate\s*\(", re.I),
]

SOURCE_PATTERNS = [
    re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", re.I),
    re.compile(r"getenv\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"request\s*\(\)\s*->\s*input\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\$request\s*->\s*input\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\$request\s*->\s*get\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\$request\s*->\s*post\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\binput\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\bI\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"Request::param\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    # Laravel / Symfony / Yii / CodeIgniter
    re.compile(r"request\s*\(\)\s*->\s*(get|post|query)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\$request\s*->\s*(get|post|query)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"Request::(get|post|input|query)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"Yii::\\$app->request->(get|post|getBodyParam|getQueryParam)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\$this->input->(get|post)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
]

REQUEST_KEYWORDS = [
    "php://input",
    "request()->input",
    "$request->input",
    "$request->get",
    "$request->post",
    "request()->validate",
    "$request->validate",
    "validator::make",
    "yii::$app->request",
    "$this->input->get",
    "$this->input->post",
]

SKIP_DIRS = {".git", "vendor", "node_modules", "storage", "runtime", "cache"}


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def walk_php_files(root: str) -> List[str]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.lower().endswith(".php"):
                results.append(os.path.join(dirpath, name))
    return results


def find_class_files(root: str) -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = {}
    for path in walk_php_files(root):
        try:
            text = read_text(path)
        except Exception:
            continue
        for m in re.finditer(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b", text):
            cls = m.group(1)
            index.setdefault(cls, []).append(path)
    return index


def pick_class_file(index: Dict[str, List[str]], class_name: str) -> Optional[str]:
    if not class_name:
        return None
    if class_name in index:
        return sorted(index[class_name], key=len)[0]
    return None


def extract_function_signature(text: str, func_name: str) -> Optional[str]:
    pattern = re.compile(r"function\s+%s\s*\(([^)]*)\)" % re.escape(func_name), re.I)
    m = pattern.search(text)
    if not m:
        return None
    return m.group(1)


def extract_function_block(text: str, func_name: str) -> Tuple[Optional[str], Optional[int]]:
    pattern = re.compile(r"function\s+%s\s*\([^)]*\)\s*\{" % re.escape(func_name), re.I)
    m = pattern.search(text)
    if not m:
        return None, None
    start = m.end() - 1
    depth = 0
    i = start
    end = None
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
        i += 1
    if end is None:
        return None, None
    body = text[start + 1 : end]
    body_start_line = text[: start + 1].count("\n") + 1
    return body, body_start_line


def extract_params_from_signature(sig: Optional[str]) -> List[str]:
    if not sig:
        return []
    params = re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", sig)
    return params


def extract_path_params(path: str) -> List[str]:
    params = set()
    params.update(re.findall(r"\{\s*([A-Za-z_][A-Za-z0-9_]*)", path))
    params.update(re.findall(r":([A-Za-z_][A-Za-z0-9_]*)", path))
    params.update(re.findall(r"<([A-Za-z_][A-Za-z0-9_]*)", path))
    params.update(re.findall(r"\(:([A-Za-z_][A-Za-z0-9_]*)\)", path))
    return sorted(p for p in params if p)


def detect_sources_in_lines(lines: List[str], file_path: str, start_line: int) -> List[Dict]:
    sources = []
    for idx, line in enumerate(lines, start=start_line):
        for pattern in SOURCE_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            if pattern.pattern.startswith(r"\$_"):
                kind = m.group(1).upper()
                param = m.group(2)
            else:
                kind = "REQUEST"
                idx = m.lastindex or 1
                param = m.group(idx)
            sources.append({"file": file_path, "line": idx, "param": param, "kind": kind})
        if "php://input" in line:
            sources.append({"file": file_path, "line": idx, "param": "raw", "kind": "BODY"})
    return sources


def detect_validations(lines: List[str], start_line: int) -> List[Dict]:
    items = []
    for idx, line in enumerate(lines, start=start_line):
        for pattern in SQL_VALIDATION_PATTERNS + GENERIC_VALIDATION_PATTERNS:
            if pattern.search(line):
                items.append({"line": idx, "code": line.strip()})
                break
    return items


def detect_sinks(lines: List[str], start_line: int, file_path: str) -> List[Dict]:
    sinks = []
    for idx, line in enumerate(lines, start=start_line):
        for rule in SINK_PATTERNS:
            if rule["regex"].search(line):
                sinks.append({
                    "type": rule["type"],
                    "file": file_path,
                    "line": idx,
                    "function": rule["regex"].pattern,
                    "code": line.strip(),
                })
                break
    return sinks


def extract_dangerous_function_info(code: str) -> Optional[Dict]:
    if not code:
        return None
    m = DANGEROUS_FUNC_RE.search(code)
    if not m:
        return None
    name = m.group(1).lower()
    info = DANGEROUS_FUNCTIONS.get(name)
    if not info:
        return None
    result = {"name": name}
    result.update(info)
    return result


def detect_deserialize_triggers(lines: List[str], start_line: int, file_path: str) -> List[Dict]:
    triggers = []
    for idx, line in enumerate(lines, start=start_line):
        for rule in DESERIALIZE_TRIGGER_PATTERNS:
            if rule["regex"].search(line):
                triggers.append({
                    "type": rule["type"],
                    "file": file_path,
                    "line": idx,
                    "code": line.strip(),
                })
                break
    return triggers


def _detect_filters(lines: List[str], start_line: int, patterns: List[tuple], kind: str) -> List[Dict]:
    results = []
    for idx, line in enumerate(lines, start=start_line):
        for name, regex in patterns:
            if regex.search(line):
                results.append({"line": idx, "code": line.strip(), "kind": kind, "rule": name})
                break
    return results


def detect_path_filters(lines: List[str], start_line: int) -> List[Dict]:
    return _detect_filters(lines, start_line, PATH_FILTER_PATTERNS, "path_filter")


def detect_url_filters(lines: List[str], start_line: int) -> List[Dict]:
    return _detect_filters(lines, start_line, URL_FILTER_PATTERNS, "url_filter")


def detect_xml_filters(lines: List[str], start_line: int) -> List[Dict]:
    return _detect_filters(lines, start_line, XML_FILTER_PATTERNS, "xml_filter")


class Progress:
    def __init__(self, total: int, label: str = "", enabled: bool = False):
        self.total = max(total, 0)
        self.label = label
        self.enabled = enabled and self.total > 0
        self._count = 0
        self._lock = threading.Lock()
        self._last_print = 0.0

    def update(self, n: int = 1) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._count += n
            now = time.time()
            # throttle updates to reduce noise
            if now - self._last_print < 0.1 and self._count < self.total:
                return
            self._last_print = now
            total = self.total or 1
            pct = min(self._count / total, 1.0)
            bar_len = 24
            filled = int(pct * bar_len)
            bar = "=" * filled + "-" * (bar_len - filled)
            msg = f"[{bar}] {self._count}/{total} {pct*100:5.1f}% {self.label}".rstrip()
            end = "\n" if self._count >= total else ""
            print("\r" + msg, end=end, file=sys.stderr, flush=True)


def find_pop_candidates(project_root: str) -> List[Dict]:
    candidates: List[Dict] = []
    for path in walk_php_files(project_root):
        try:
            text = read_text(path)
        except Exception:
            continue
        current_class = ""
        for idx, line in enumerate(text.splitlines(), start=1):
            m = re.search(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
            if m:
                current_class = m.group(1)
            for method in POP_MAGIC_METHODS:
                if re.search(rf"\bfunction\s+{re.escape(method)}\b", line, re.I):
                    candidates.append({
                        "class": current_class or "",
                        "method": method,
                        "file": path,
                        "line": idx,
                    })
                    break
    return candidates


def build_output_root(project_root: str, out_dir: Optional[str]) -> str:
    if out_dir:
        return os.path.abspath(out_dir)
    project_root = os.path.abspath(project_root)
    return f"{project_root.rstrip('/')}_audit"
