#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from typing import Dict, List


def build_output_root(project_root: str, out_dir: str) -> str:
    if out_dir:
        return out_dir
    base = os.path.basename(project_root.rstrip("/"))
    return os.path.join(os.path.dirname(project_root), f"{base}_audit")


def pick_composer_bin() -> str:
    # Prefer local composer.phar packaged in this skill
    skill_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    phar = os.path.join(skill_root, "assets", "composer.phar")
    if os.path.exists(phar):
        return f"php {phar}"
    # Fallback to system composer
    found = shutil.which("composer")
    if found:
        return found
    raise SystemExit("composer not found. Install composer or provide composer.phar in skills.")


def run_audit(project_root: str, out_root: str) -> Dict:
    raw_dir = os.path.join(out_root, "mcp_raw")
    parsed_dir = os.path.join(out_root, "mcp_parsed")
    vuln_dir = os.path.join(out_root, "vuln_report")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    os.makedirs(vuln_dir, exist_ok=True)

    lock_file = os.path.join(project_root, "composer.lock")
    if not os.path.exists(lock_file):
        result = {"tool": "composer-audit-mcp", "status": "missing", "error": "composer.lock not found"}
        with open(os.path.join(parsed_dir, "composer-audit-mcp.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return result

    composer_bin = pick_composer_bin()
    cmd = f"{composer_bin} audit --format=json --no-interaction --no-plugins --no-scripts"
    proc = subprocess.run(cmd, cwd=project_root, shell=True, capture_output=True, text=True)

    raw_path = os.path.join(raw_dir, "composer-audit-mcp.json")
    raw_content = proc.stdout if proc.stdout else proc.stderr
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(raw_content or "")

    data = None
    if raw_content:
        try:
            data = json.loads(raw_content)
        except Exception:
            data = {"raw": raw_content}
    else:
        data = {"raw": ""}

    # Vulnerabilities may return non-zero exit; treat as ok if json parsed
    status = "ok" if data else "error"
    result = {"tool": "composer-audit-mcp", "status": status, "results": data}

    with open(os.path.join(parsed_dir, "composer-audit-mcp.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    with open(os.path.join(vuln_dir, "composer_audit.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # simple markdown summary
    md_lines = ["# Composer Audit", "", f"Exit code: {proc.returncode}"]
    if isinstance(data, dict) and data.get("advisories"):
        advisories = data.get("advisories", {})
        count = sum(len(v) for v in advisories.values())
        md_lines.append(f"- Advisories: {count}")
        for pkg, items in advisories.items():
            md_lines.append(f"## {pkg}")
            for item in items:
                title = item.get("title", "")
                cve = item.get("cve", "")
                md_lines.append(f"- {title} {cve}")
    md_path = os.path.join(vuln_dir, "composer_audit.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")

    # Append trigger analysis
    try:
        trigger_section = build_trigger_analysis(project_root, data)
        if trigger_section:
            with open(md_path, "a", encoding="utf-8") as f:
                f.write("\n" + trigger_section + "\n")
    except Exception:
        pass

    return result


def detect_frameworks(project_root: str, data: Dict) -> List[str]:
    frameworks = set()
    # Detect via composer.lock
    lock_path = os.path.join(project_root, "composer.lock")
    if os.path.exists(lock_path):
        try:
            lock = json.load(open(lock_path, "r", encoding="utf-8"))
            packages = (lock.get("packages") or []) + (lock.get("packages-dev") or [])
            names = {p.get("name") for p in packages if p.get("name")}
            if "laravel/framework" in names:
                frameworks.add("Laravel")
            if "topthink/framework" in names:
                frameworks.add("ThinkPHP")
            if "symfony/symfony" in names or any(n and n.startswith("symfony/") for n in names):
                frameworks.add("Symfony")
            if "yiisoft/yii2" in names:
                frameworks.add("Yii2")
            if "codeigniter/framework" in names:
                frameworks.add("CodeIgniter")
        except Exception:
            pass
    # Fallback detect via files
    if os.path.exists(os.path.join(project_root, "thinkphp")) or os.path.exists(os.path.join(project_root, "application")):
        frameworks.add("ThinkPHP")
    if os.path.exists(os.path.join(project_root, "artisan")):
        frameworks.add("Laravel")
    if os.path.exists(os.path.join(project_root, "symfony.lock")):
        frameworks.add("Symfony")
    if os.path.exists(os.path.join(project_root, "yii")):
        frameworks.add("Yii")
    if os.path.exists(os.path.join(project_root, "system", "core", "CodeIgniter.php")):
        frameworks.add("CodeIgniter")
    return sorted(frameworks) if frameworks else ["Unknown"]


def detect_entrypoints(project_root: str) -> List[str]:
    candidates = [
        "public/index.php",
        "index.php",
        "public/router.php",
    ]
    entries = []
    for c in candidates:
        p = os.path.join(project_root, c)
        if os.path.exists(p):
            entries.append(c)
    return entries or ["Unknown"]


def detect_runtime(project_root: str) -> str:
    if os.path.exists(os.path.join(project_root, "docker-compose.yml")):
        return "Docker"
    if os.path.exists(os.path.join(project_root, ".htaccess")):
        return "Apache"
    if os.path.exists(os.path.join(project_root, "nginx.conf")):
        return "Nginx"
    return "Unknown"


def build_trigger_analysis(project_root: str, data: Dict) -> str:
    frameworks = detect_frameworks(project_root, data)
    entrypoints = detect_entrypoints(project_root)
    runtime = detect_runtime(project_root)

    # derive affected components from advisories
    components = []
    if isinstance(data, dict) and data.get("advisories"):
        for pkg in data.get("advisories", {}).keys():
            components.append(pkg)

    lines = [
        "## 🔍 触发点分析（AI 生成）",
        "",
        "### 🌐 项目环境",
        f"- 框架：{', '.join(frameworks)}",
        f"- 入口文件：{', '.join(entrypoints)}",
        f"- 容器/运行环境：{runtime}",
        "",
        "### 📦 组件触发点分析",
    ]
    if not components:
        lines.append("- 未检测到可分析的组件触发点（无 advisories）。")
        return "\n".join(lines)

    for pkg in components:
        lines.append(f"#### {pkg}")
        lines.append("**常见触发点**")
        lines.append(f"- 项目中直接引用 {pkg} 的服务或工具类")
        lines.append("")
        lines.append("**危险代码模式**")
        lines.append("```php")
        lines.append(f"// TODO: 定位 {pkg} 的使用位置并检查危险调用")
        lines.append("```")
        lines.append("")
        lines.append("**受影响路由/功能点**")
        lines.append("- 结合 route_mapper 输出，定位涉及该组件的入口路由")
        lines.append("")
        lines.append("**代码搜索建议**")
        lines.append("```bash")
        lines.append(f"rg \"{pkg.split('/')[-1]}\" -g'*.php' {project_root}")
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    run_audit(project_root, out_root)


if __name__ == "__main__":
    main()
