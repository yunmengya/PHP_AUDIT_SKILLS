#!/usr/bin/env python3
import argparse
import json
import os
import time
from typing import Dict, List

from common import build_output_root, write_text

PHASE_TEMPLATES = {
    "phase1_map.md": """# 阶段1 信息收集与攻击面识别
## 技术栈画像
| 项目 | 取值 | 证据/位置 |
|---|---|---|
| 语言 |  |  |
| 框架 |  |  |
| 数据库 |  |  |
| 中间件 |  |  |

## 模块地图
| 模块 | 责任 | 入口/功能 | 备注 |
|---|---|---|---|
|  |  |  |  |

## 攻击面清单
| 路由 | 方法 | 参数 | 是否鉴权 | 风险点 | 证据 |
|---|---|---|---|---|---|
|  |  |  |  |  |  |

## 安全机制
| 类型 | 实现 | 位置 | 备注 |
|---|---|---|---|
|  |  |  |  |

## 结论
| 高优先级模块 | 理由 |
|---|---|
|  |  |
""",
    "phase2_risk_map.md": """# 阶段2 并行扫描与风险地图
## Agent 切分
| Agent | 方向 | 搜索关键词 | 说明 |
|---|---|---|---|
|  |  |  |  |

## 高风险区域
| 文件/目录 | 风险类型 | 触发点 | 初步结论 |
|---|---|---|---|
|  |  |  |  |
""",
    "phase3_trace_log.md": """# 阶段3 关键路径手工审计
## 证据链追踪
| 输入源 | 传播路径 | 危险函数 | 可控性 | 结论 |
|---|---|---|---|---|
|  |  |  |  |  |
""",
    "phase4_attack_chain.md": """# 阶段4 漏洞验证与攻击链构建
## 验证四步
| 步骤 | 结论 | 证据 |
|---|---|---|
| 数据流完整性 |  |  |
| 防护可绕过性 |  |  |
| 前置条件可满足性 |  |  |
| 影响范围 |  |  |

## 攻击链草图
| 链路 | 组合影响 | 组合等级 |
|---|---|---|
|  |  |  |
""",
}


def ensure_meta(out_root: str) -> None:
    meta_dir = os.path.join(out_root, "_meta")
    os.makedirs(meta_dir, exist_ok=True)
    for name, content in PHASE_TEMPLATES.items():
        path = os.path.join(meta_dir, name)
        if not os.path.exists(path):
            write_text(path, content.rstrip() + "\n")


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


def summarize(findings: List[Dict]) -> Dict[str, Dict[str, int]]:
    counts = {
        "independent": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "combined": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "controllability": {"fully": 0, "conditional": 0, "none": 0},
    }
    for f in findings:
        indep = (f.get("independent_severity") or f.get("severity") or "info").lower()
        comb = (f.get("combined_severity") or f.get("severity") or "info").lower()
        if indep not in counts["independent"]:
            indep = "info"
        if comb not in counts["combined"]:
            comb = "info"
        counts["independent"][indep] += 1
        counts["combined"][comb] += 1
        ctrl = f.get("controllability") or "conditional"
        if ctrl not in counts["controllability"]:
            ctrl = "conditional"
        counts["controllability"][ctrl] += 1
    return counts




def find_report_files(out_root: str) -> List[str]:
    reports = []
    for root, _, files in os.walk(out_root):
        if os.path.basename(root) in {"route_mapper", "route_tracer", "_meta"}:
            continue
        for f in files:
            if f.endswith(".md") and "_audit_" in f:
                reports.append(os.path.join(root, f))
            if f == "composer_audit.md":
                reports.append(os.path.join(root, f))
    return sorted(set(reports))



def render_index(out_root: str, modules: Dict[str, List[Dict]]) -> str:
    lines = [
        "# 阶段5 报告输出与终止决策",
        f"生成时间：{time.strftime('%Y%m%d_%H%M%S')}",
        "",
        "## 报告清单",
        "| 模块 | 发现数 | 独立等级统计 | 组合等级统计 | 可控性统计 |",
        "|---|---|---|---|---|",
    ]

    total_findings: List[Dict] = []
    for module, items in sorted(modules.items()):
        total_findings.extend(items)
        stats = summarize(items)
        indep = stats["independent"]
        comb = stats["combined"]
        ctrl = stats["controllability"]
        indep_txt = f"高危:{indep['high']} 中危:{indep['medium']} 低危:{indep['low']}"
        comb_txt = f"高危:{comb['high']} 中危:{comb['medium']} 低危:{comb['low']}"
        ctrl_txt = f"完全可控:{ctrl['fully']} 条件可控:{ctrl['conditional']} 不可控:{ctrl['none']}"
        lines.append(f"| {module} | {len(items)} | {indep_txt} | {comb_txt} | {ctrl_txt} |")

    lines += [
        "",
        "## 报告文件列表",
        "| 文件 | 模块 | 备注 |",
        "|---|---|---|",
    ]
    for p in find_report_files(out_root):
        rel = os.path.relpath(p, out_root)
        module = rel.split(os.sep, 1)[0] if os.sep in rel else "root"
        lines.append(f"| {rel} | {module} |  |")

    lines += [
        "",
        "## 总体统计",
    ]
    total_stats = summarize(total_findings) if total_findings else summarize([])
    indep = total_stats["independent"]
    comb = total_stats["combined"]
    ctrl = total_stats["controllability"]
    lines += [
        f"- 独立等级：高危={indep['high']} 中危={indep['medium']} 低危={indep['low']} 提示={indep['info']}",
        f"- 组合等级：高危={comb['high']} 中危={comb['medium']} 低危={comb['low']} 提示={comb['info']}",
        f"- 可控性：完全可控={ctrl['fully']} 条件可控={ctrl['conditional']} 不可控={ctrl['none']}",
        "",
        "## 终止判断",
        "| 问题 | 答案 | 证据/备注 |",
        "|---|---|---|",
        "| 问题1：有没有计划搜索但没搜到的区域？ |  |  |",
        "| 问题2：发现的入口点是否都追踪到了危险函数？ |  |  |",
        "| 问题3：高风险发现之间是否可能存在跨模块关联？ |  |  |",
        "",
        "## 结论",
        "| 是否结束 | 下一轮补充方向 |",
        "|---|---|",
        "|  |  |",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    out_root = build_output_root(os.path.abspath(args.project), args.out)
    ensure_meta(out_root)

    modules = load_findings(out_root)
    content = render_index(out_root, modules)
    write_text(os.path.join(out_root, "_meta", "phase5_report_index.md"), content)
    print(f"已写入阶段5报告索引，共 {len(modules)} 个模块")


if __name__ == "__main__":
    main()
