#!/usr/bin/env python3
import argparse
import json
import os
import time
from typing import Dict, List

from common import build_output_root, write_text


def load_findings(out_root: str) -> Dict[str, List[Dict]]:
    modules: Dict[str, List[Dict]] = {}
    for root, _, files in os.walk(out_root):
        for f in files:
            if f not in ("findings.json", "auth_evidence.json"):
                continue
            path = os.path.join(root, f)
            module = os.path.basename(os.path.dirname(path))
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    modules.setdefault(module, []).extend(data)
            except Exception:
                continue
    return modules


def severity_level(sev: str) -> str:
    sev = (sev or "info").lower()
    if sev in ("high", "h", "critical", "c"):
        return "高"
    if sev in ("medium", "m"):
        return "中"
    if sev in ("low", "l", "info"):
        return "低"
    return "低"


def max_severity(findings: List[Dict]) -> str:
    order = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3, "c": 3, "h": 3, "m": 2, "l": 1}
    best = "info"
    best_score = 0
    for f in findings:
        sev = (f.get("combined_severity") or f.get("independent_severity") or f.get("severity") or "info").lower()
        score = order.get(sev, 1)
        if score > best_score:
            best_score = score
            best = sev
    return best


def render_chain(modules: Dict[str, List[Dict]]) -> str:
    auth_present = bool(modules.get("auth_audit"))
    lines = [
        "# Phase 4 漏洞验证与攻击链构建",
        f"生成时间：{time.strftime('%Y%m%d_%H%M%S')}",
        "",
        "## 自动草稿（需人工确认）",
        "| 链路 | 组合影响 | 组合等级 | 证据/说明 |",
        "|---|---|---|---|",
    ]

    chains = []
    for module, findings in modules.items():
        if not findings:
            continue
        if module == "auth_audit":
            continue
        sev = max_severity(findings)
        level = severity_level(sev)
        if auth_present:
            chain = f"认证缺失/绕过 → {module} 风险"
            impact = "放大为未认证可达"
            chains.append((chain, impact, level, "auth_audit + 其他模块"))
        # module-specific generic chain
        if module == "rce_audit":
            chains.append(("命令/代码执行 → 系统控制", "RCE", level, module))
        if module == "file_audit":
            chains.append(("文件上传/包含 → 代码执行", "RCE/读写", level, module))
        if module == "ssrf_xxe_audit":
            chains.append(("SSRF/XXE → 内网探测/凭据泄露", "数据泄露", level, module))
        if module == "xss_ssti_audit":
            chains.append(("XSS/SSTI → 会话劫持/模板执行", "权限提升", level, module))
        if module == "serialize_audit":
            chains.append(("反序列化触发 → POP 链", "远程代码执行", level, module))
        if module == "sql_audit":
            chains.append(("SQL 注入 → 数据泄露/篡改", "数据风险", level, module))

    if not chains:
        lines.append("| 无明显攻击链 | 暂无 | 低 | 需要人工复核 |")
    else:
        for chain, impact, level, note in chains:
            lines.append(f"| {chain} | {impact} | {level} | {note} |")

    lines += [
        "",
        "## 手工补充",
        "| 链路 | 组合影响 | 组合等级 | 证据/说明 |",
        "|---|---|---|---|",
        "|  |  |  |  |",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    out_root = build_output_root(os.path.abspath(args.project), args.out)
    meta_dir = os.path.join(out_root, "_meta")
    os.makedirs(meta_dir, exist_ok=True)

    modules = load_findings(out_root)
    content = render_chain(modules)
    write_text(os.path.join(meta_dir, "phase4_attack_chain.md"), content)
    print("Wrote phase4 attack chain draft")


if __name__ == "__main__":
    main()
