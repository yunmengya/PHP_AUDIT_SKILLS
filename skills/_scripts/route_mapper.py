#!/usr/bin/env python3
import argparse
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from common import (
    Progress,
    build_output_root,
    extract_function_signature,
    extract_params_from_signature,
    extract_path_params,
    find_class_files,
    pick_class_file,
    read_text,
    walk_php_files,
    write_json,
    write_text,
)




def line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end]


def parse_middlewares(line: str) -> list:
    m = re.search(r"middleware\s*\(([^)]*)\)", line, re.I)
    if not m:
        return []
    inside = m.group(1)
    return re.findall(r'["\\\']([^"\\\']+)["\\\']', inside)

def detect_frameworks(root: str) -> List[str]:
    frameworks = []
    if os.path.exists(os.path.join(root, "routes", "web.php")) or os.path.exists(
        os.path.join(root, "routes", "api.php")
    ):
        frameworks.append("laravel")
    if os.path.exists(os.path.join(root, "route")) or os.path.exists(
        os.path.join(root, "config", "route.php")
    ):
        frameworks.append("thinkphp")
    if os.path.exists(os.path.join(root, "config", "routes.yaml")) or os.path.exists(
        os.path.join(root, "config", "routes")
    ):
        frameworks.append("symfony")
    if os.path.exists(os.path.join(root, "config", "web.php")) or os.path.exists(
        os.path.join(root, "config", "main.php")
    ):
        frameworks.append("yii")
    if os.path.exists(os.path.join(root, "app", "Config", "Routes.php")) or os.path.exists(
        os.path.join(root, "application", "config", "routes.php")
    ):
        frameworks.append("codeigniter")
    if not frameworks:
        frameworks.append("generic")
    return frameworks


def parse_laravel_routes(path: str, text: str) -> List[Dict]:
    routes = []
    p1 = re.compile(
        r"Route::(?P<method>get|post|put|delete|patch|options|any)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*['\"](?P<handler>[^'\"]+)['\"]",
        re.I,
    )
    p2 = re.compile(
        r"Route::(?P<method>get|post|put|delete|patch|options|any)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*\[\s*(?P<class>[A-Za-z0-9_\\]+)::class\s*,\s*['\"](?P<action>[A-Za-z0-9_]+)['\"]\s*\]",
        re.I,
    )
    pm = re.compile(
        r"Route::match\s*\(\s*\[(?P<methods>[^\]]+)\]\s*,\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*['\"](?P<handler>[^'\"]+)['\"]",
        re.I,
    )
    for m in p1.finditer(text):
        handler = m.group("handler")
        controller, action = split_handler(handler)
        line = line_at(text, m.start())
        routes.append(make_route(m.group("method").upper(), m.group("path"), controller, action, "laravel", path, parse_middlewares(line)))
    for m in p2.finditer(text):
        controller = m.group("class").split("\\")[-1]
        action = m.group("action")
        line = line_at(text, m.start())
        routes.append(make_route(m.group("method").upper(), m.group("path"), controller, action, "laravel", path, parse_middlewares(line)))
    for m in pm.finditer(text):
        methods = normalize_methods(m.group("methods"))
        controller, action = split_handler(m.group("handler"))
        line = line_at(text, m.start())
        routes.append(make_route(methods, m.group("path"), controller, action, "laravel", path, parse_middlewares(line)))
    return routes


def parse_thinkphp_routes(path: str, text: str) -> List[Dict]:
    routes = []
    p = re.compile(
        r"Route::(?P<method>rule|get|post|put|delete|any)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*['\"](?P<handler>[^'\"]+)['\"](?:\s*,\s*['\"](?P<verbs>[^'\"]+)['\"])?",
        re.I,
    )
    for m in p.finditer(text):
        method = m.group("method").upper()
        if method == "RULE" and m.group("verbs"):
            method = m.group("verbs").upper()
        controller, action = split_thinkphp_handler(m.group("handler"))
        routes.append(make_route(method, m.group("path"), controller, action, "thinkphp", path))
    return routes


def parse_codeigniter_routes(path: str, text: str) -> List[Dict]:
    routes = []
    p4 = re.compile(
        r"\$routes->(?P<method>get|post|put|delete|patch|options|add)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*['\"](?P<handler>[^'\"]+)['\"]",
        re.I,
    )
    p3 = re.compile(
        r"\$route\[['\"](?P<path>[^'\"]+)['\"]\]\s*=\s*['\"](?P<handler>[^'\"]+)['\"]",
        re.I,
    )
    for m in p4.finditer(text):
        method = m.group("method").upper()
        if method == "ADD":
            method = "ANY"
        controller, action = split_handler(m.group("handler"), sep="::")
        routes.append(make_route(method, m.group("path"), controller, action, "codeigniter", path))
    for m in p3.finditer(text):
        controller, action = split_thinkphp_handler(m.group("handler"))
        routes.append(make_route("ANY", m.group("path"), controller, action, "codeigniter", path))
    return routes


def parse_symfony_yaml(path: str, text: str) -> List[Dict]:
    routes = []
    current_path = None
    current_methods = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("path:"):
            current_path = stripped.split(":", 1)[1].strip().strip("'\"")
        if stripped.startswith("methods:"):
            current_methods = stripped.split(":", 1)[1].strip()
        if stripped.startswith("controller:"):
            controller = stripped.split(":", 1)[1].strip().strip("'\"")
            cls, action = split_handler(controller, sep="::")
            method = normalize_methods(current_methods) if current_methods else "ANY"
            if current_path:
                routes.append(make_route(method, current_path, cls, action, "symfony", path))
            current_path = None
            current_methods = None
    return routes


def parse_symfony_attributes(path: str, text: str) -> List[Dict]:
    routes = []
    attr = re.compile(r"#\[Route\((?P<args>[^\)]*)\)\]", re.I)
    func = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = attr.search(line)
        if not m:
            continue
        args = m.group("args")
        path_val = None
        path_m = re.search(r"['\"](/[^'\"]+)['\"]", args)
        if path_m:
            path_val = path_m.group(1)
        methods_m = re.search(r"methods\s*:\s*\[([^\]]+)\]", args)
        methods = normalize_methods(methods_m.group(1)) if methods_m else "ANY"
        # find next function line
        for j in range(i + 1, min(i + 15, len(lines))):
            fm = func.search(lines[j])
            if fm:
                action = fm.group(1)
                controller = guess_class_name(text)
                if path_val:
                    routes.append(make_route(methods, path_val, controller, action, "symfony", path))
                break
    return routes


def parse_yii_routes(path: str, text: str) -> List[Dict]:
    routes = []
    p = re.compile(r"['\"](?P<path>[^'\"]+)['\"]\s*=>\s*['\"](?P<handler>[^'\"]+)['\"]")
    for m in p.finditer(text):
        controller, action = split_thinkphp_handler(m.group("handler"))
        routes.append(make_route("ANY", m.group("path"), controller, action, "yii", path))
    return routes


def extract_handler_from_args(args_text: str) -> (str, str):
    # array handler: [Class::class, 'action'] or ['Class', 'action']
    m = re.search(r"\[\s*([A-Za-z0-9_\\]+)::class\s*,\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]", args_text)
    if m:
        return m.group(1).split("\\")[-1], m.group(2)
    m = re.search(r"\[\s*['\"]([A-Za-z0-9_\\]+)['\"]\s*,\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]", args_text)
    if m:
        return m.group(1).split("\\")[-1], m.group(2)
    # string handler: "Ctrl@action" or "Ctrl::action"
    m = re.search(r"['\"]([^'\"]+)['\"]", args_text)
    if m:
        return split_handler(m.group(1))
    return "", ""


def parse_generic_routes(path: str, text: str) -> List[Dict]:
    routes = []
    # $app->get('/path', 'Ctrl@action') or Router::get(...)
    p1 = re.compile(
        r"(?:\$[A-Za-z_][A-Za-z0-9_]*|Router|Route|App|Slim\\App)\s*(?:->|::)\s*(?P<method>get|post|put|delete|patch|options|any)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<handler>[^\)]*)\)",
        re.I,
    )
    # FastRoute style: $router->addRoute('GET', '/path', 'Ctrl@action')
    p2 = re.compile(
        r"\$[A-Za-z_][A-Za-z0-9_]*->addRoute\s*\(\s*['\"](?P<methods>[^'\"]+)['\"]\s*,\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<handler>[^\)]*)\)",
        re.I,
    )
    # map([...], '/path', handler)
    p3 = re.compile(
        r"\$[A-Za-z_][A-Za-z0-9_]*->map\s*\(\s*\[(?P<methods>[^\]]+)\]\s*,\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<handler>[^\)]*)\)",
        re.I,
    )
    # Flight::route('GET /path', 'Ctrl@action')
    p4 = re.compile(
        r"Flight::route\s*\(\s*['\"](?P<spec>[^'\"]+)['\"]\s*,\s*(?P<handler>[^\)]*)\)",
        re.I,
    )

    for m in p1.finditer(text):
        controller, action = extract_handler_from_args(m.group("handler"))
        line = line_at(text, m.start())
        routes.append(make_route(m.group("method").upper(), m.group("path"), controller, action, "generic", path, parse_middlewares(line)))

    for m in p2.finditer(text):
        methods = normalize_methods(m.group("methods"))
        controller, action = extract_handler_from_args(m.group("handler"))
        line = line_at(text, m.start())
        routes.append(make_route(methods, m.group("path"), controller, action, "generic", path, parse_middlewares(line)))

    for m in p3.finditer(text):
        methods = normalize_methods(m.group("methods"))
        controller, action = extract_handler_from_args(m.group("handler"))
        line = line_at(text, m.start())
        routes.append(make_route(methods, m.group("path"), controller, action, "generic", path, parse_middlewares(line)))

    for m in p4.finditer(text):
        spec = m.group("spec")
        if " " in spec:
            method_part, path_part = spec.split(" ", 1)
            method = method_part.strip().upper()
            path_val = path_part.strip()
            controller, action = extract_handler_from_args(m.group("handler"))
            routes.append(make_route(method, path_val, controller, action, "generic", path))

    return routes


def parse_manual_routes(path: str, text: str) -> List[Dict]:
    if "REQUEST_URI" not in text:
        return []

    var_names = set()
    for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$_SERVER\[['\"]REQUEST_URI['\"]\]", text):
        var_names.add(m.group(1))

    paths = set()
    for m in re.finditer(r"case\s+['\"](/[^'\"]+)['\"]", text):
        paths.add(m.group(1))
    for m in re.finditer(r"\$_SERVER\[['\"]REQUEST_URI['\"]\]\s*([=!]==?)\s*['\"](/[^'\"]+)['\"]", text):
        paths.add(m.group(2))

    for var in var_names:
        for m in re.finditer(rf"\${var}\s*([=!]==?)\s*['\"](/[^'\"]+)['\"]", text):
            paths.add(m.group(2))
        for m in re.finditer(rf"strpos\s*\(\s*\${var}\s*,\s*['\"](/[^'\"]+)['\"]\s*\)\s*===\s*0", text):
            paths.add(m.group(1))

    routes = []
    for p in sorted(paths):
        r = make_route("ANY", p, "", "", "generic", path)
        r["controller_file"] = path
        routes.append(r)
    return routes


def find_entry_file(project_root: str) -> str:
    candidates = [
        os.path.join(project_root, "public", "index.php"),
        os.path.join(project_root, "index.php"),
        os.path.join(project_root, "app.php"),
        os.path.join(project_root, "bootstrap.php"),
        os.path.join(project_root, "server.php"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""


def split_handler(handler: str, sep: str = "@") -> (str, str):
    if sep in handler:
        parts = handler.split(sep, 1)
        controller = parts[0].split("\\")[-1]
        action = parts[1]
        return controller, action
    if "::" in handler:
        parts = handler.split("::", 1)
        return parts[0].split("\\")[-1], parts[1]
    if "/" in handler:
        return split_thinkphp_handler(handler)
    return handler, ""


def split_thinkphp_handler(handler: str) -> (str, str):
    parts = handler.replace("\\", "/").split("/")
    if len(parts) >= 2:
        return parts[-2].split("\\")[-1].split(".")[-1].title(), parts[-1]
    return handler, ""


def normalize_methods(text: str) -> str:
    if not text:
        return "ANY"
    methods = re.findall(r"['\"]([A-Za-z]+)['\"]", text)
    if methods:
        return "|".join([m.upper() for m in methods])
    return text.strip().upper()


def make_route(method: str, path: str, controller: str, action: str, framework: str, source_file: str, middlewares: list = None) -> Dict:
    return {
        "method": method,
        "path": path,
        "controller": controller,
        "action": action,
        "framework": framework,
        "source_file": source_file,
        "middlewares": middlewares or [],
    }


def guess_class_name(text: str) -> str:
    m = re.search(r"class\s+([A-Za-z_][A-Za-z0-9_]*)", text)
    return m.group(1) if m else ""


def enrich_params(routes: List[Dict], project_root: str) -> List[Dict]:
    class_index = find_class_files(project_root)
    for route in routes:
        params = []
        path_params = extract_path_params(route["path"])
        params.extend([{"name": p, "source": "path"} for p in path_params])
        controller = route.get("controller")
        action = route.get("action")
        controller_file = route.get("controller_file")
        if not controller_file:
            controller_file = pick_class_file(class_index, controller)
            route["controller_file"] = controller_file
        if controller_file and action:
            text = read_text(controller_file)
            sig = extract_function_signature(text, action)
            sig_params = extract_params_from_signature(sig)
            for p in sig_params:
                if p in ["request", "req"]:
                    continue
                if p not in path_params:
                    params.append({"name": p, "source": "unknown"})
        route["params"] = params
    return routes


def write_routes(routes: List[Dict], out_root: str) -> None:
    mapper_root = os.path.join(out_root, "route_mapper")
    os.makedirs(os.path.join(mapper_root, "burp_templates"), exist_ok=True)
    write_json(os.path.join(mapper_root, "routes.json"), routes)
    # markdown
    lines = ["# Routes", "", "| Method | Path | Controller | Action | Framework | Middlewares |", "|---|---|---|---|---|---|"]
    for r in routes:
        middlewares = ", ".join(r.get("middlewares") or []) or "none"
        lines.append(f"| {r['method']} | {r['path']} | {r['controller']} | {r['action']} | {r['framework']} | {middlewares} |")
        tpl = build_burp_template(r)
        tpl_name = f"{r['method']}_{sanitize(r['path'])}.txt"
        write_text(os.path.join(mapper_root, "burp_templates", tpl_name), tpl)
    write_text(os.path.join(mapper_root, "routes.md"), "\n".join(lines) + "\n")


def build_burp_template(route: Dict) -> str:
    path = route["path"]
    method = route["method"].split("|")[0]
    params = route.get("params", [])
    if method in ("GET", "ANY"):
        if params:
            q = "&".join([f"{p['name']}={{value}}" for p in params])
            return f"{method} {path}?{q} HTTP/1.1\nHost: {{host}}\n\n"
        return f"{method} {path} HTTP/1.1\nHost: {{host}}\n\n"
    body = "&".join([f"{p['name']}={{value}}" for p in params]) if params else ""
    return f"{method} {path} HTTP/1.1\nHost: {{host}}\nContent-Type: application/x-www-form-urlencoded\n\n{body}\n"


def sanitize(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", path.strip("/") or "root")


def normalize_threads(threads: int) -> int:
    if threads is None or threads <= 0:
        return max(os.cpu_count() or 4, 1)
    return max(threads, 1)


def scan_php_files(
    files: List[str],
    parse_fn,
    threads: int,
    progress: bool,
    label: str,
) -> List[Dict]:
    routes: List[Dict] = []
    if not files:
        return routes
    prog = Progress(len(files), label=label, enabled=progress)
    threads = normalize_threads(threads)

    def worker(path: str) -> List[Dict]:
        try:
            text = read_text(path)
        except Exception:
            return []
        try:
            return parse_fn(path, text)
        except Exception:
            return []

    if threads <= 1 or len(files) <= 1:
        for p in files:
            routes.extend(worker(p))
            prog.update()
        return routes

    with ThreadPoolExecutor(max_workers=min(threads, len(files))) as ex:
        futures = {ex.submit(worker, p): p for p in files}
        for fut in as_completed(futures):
            try:
                routes.extend(fut.result())
            except Exception:
                pass
            prog.update()
    return routes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--threads", type=int, default=0, help="Worker threads (0=auto)")
    ap.add_argument("--progress", dest="progress", action="store_true", default=True, help="Show progress bar (default: on)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="Disable progress bar")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    routes: List[Dict] = []
    threads = args.threads
    progress = args.progress
    frameworks = detect_frameworks(project_root)
    for fw in frameworks:
        if fw == "laravel":
            for fname in ["routes/web.php", "routes/api.php"]:
                path = os.path.join(project_root, fname)
                if os.path.exists(path):
                    routes.extend(parse_laravel_routes(path, read_text(path)))
        if fw == "thinkphp":
            for base in ["route", "config"]:
                dir_path = os.path.join(project_root, base)
                if os.path.isdir(dir_path):
                    for root, _, files in os.walk(dir_path):
                        for f in files:
                            if f.endswith(".php"):
                                p = os.path.join(root, f)
                                routes.extend(parse_thinkphp_routes(p, read_text(p)))
                elif os.path.isfile(dir_path + ".php"):
                    routes.extend(parse_thinkphp_routes(dir_path + ".php", read_text(dir_path + ".php")))
        if fw == "codeigniter":
            for path in [
                os.path.join(project_root, "app", "Config", "Routes.php"),
                os.path.join(project_root, "application", "config", "routes.php"),
            ]:
                if os.path.exists(path):
                    routes.extend(parse_codeigniter_routes(path, read_text(path)))
        if fw == "symfony":
            yaml_path = os.path.join(project_root, "config", "routes.yaml")
            if os.path.exists(yaml_path):
                routes.extend(parse_symfony_yaml(yaml_path, read_text(yaml_path)))
            routes_dir = os.path.join(project_root, "config", "routes")
            if os.path.isdir(routes_dir):
                for root, _, files in os.walk(routes_dir):
                    for f in files:
                        if f.endswith(".yaml") or f.endswith(".yml"):
                            p = os.path.join(root, f)
                            routes.extend(parse_symfony_yaml(p, read_text(p)))
            # attributes in php
            php_files = list(walk_php_files(project_root))
            routes.extend(scan_php_files(php_files, parse_symfony_attributes, threads, progress, "symfony_attr"))
        if fw == "yii":
            for path in [
                os.path.join(project_root, "config", "web.php"),
                os.path.join(project_root, "config", "main.php"),
            ]:
                if os.path.exists(path):
                    routes.extend(parse_yii_routes(path, read_text(path)))

    # generic fallback (router patterns + manual REQUEST_URI rules)
    if not routes:
        php_files = list(walk_php_files(project_root))

        def parse_all(path: str, text: str) -> List[Dict]:
            out = []
            out.extend(parse_generic_routes(path, text))
            out.extend(parse_manual_routes(path, text))
            return out

        routes.extend(scan_php_files(php_files, parse_all, threads, progress, "generic_routes"))

    # entry file fallback when still empty
    if not routes:
        entry = find_entry_file(project_root)
        if entry:
            r = make_route("ANY", "/", "", "", "generic", entry)
            r["controller_file"] = entry
            routes.append(r)

    # de-dup
    uniq = {}
    for r in routes:
        key = (r["method"], r["path"], r["controller"], r["action"], r["framework"])
        uniq[key] = r
    routes = list(uniq.values())

    routes = enrich_params(routes, project_root)
    write_routes(routes, out_root)

    print(f"Wrote {len(routes)} routes to {out_root}")


if __name__ == "__main__":
    main()
