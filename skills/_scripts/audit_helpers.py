#!/usr/bin/env python3
import hashlib
import html
import json
import os
import re
import time
import unicodedata
from typing import Dict, List

from common import build_output_root, write_json, write_text


def stable_id(prefix: str, file_path: str, line: int, extra: str = "") -> str:
    base = f"{prefix}|{file_path or ''}|{line or 0}|{extra}"
    digest = hashlib.md5(base.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def load_traces(out_root: str) -> List[Dict]:
    traces = []
    trace_root = os.path.join(out_root, "route_tracer")
    if not os.path.isdir(trace_root):
        return traces
    for root, _, files in os.walk(trace_root):
        for f in files:
            if f == "trace.json":
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        traces.append(json.load(fh))
                except Exception:
                    continue
    return traces


def load_findings(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        return []
    return []


def merge_findings(existing: List[Dict], incoming: List[Dict]) -> List[Dict]:
    merged: Dict[str, Dict] = {}
    for f in existing:
        fid = f.get("id") or stable_id("MERGE", f.get("sink", {}).get("file"), f.get("sink", {}).get("line"), "existing")
        merged[fid] = f
    for f in incoming:
        fid = f.get("id") or stable_id("MERGE", f.get("sink", {}).get("file"), f.get("sink", {}).get("line"), "incoming")
        merged[fid] = f
    return list(merged.values())


def is_rule_audit_quick_mode() -> bool:
    return os.environ.get("RULE_AUDIT_QUICK") == "1"


def apply_rule_audit_quick_filter(findings: List[Dict], module_name: str) -> List[Dict]:
    if not findings or not is_rule_audit_quick_mode():
        return findings

    def keep_finding(item: Dict) -> bool:
        indep = (item.get("independent_severity") or item.get("severity") or "").lower()
        combo = (item.get("combined_severity") or item.get("severity") or "").lower()
        ctrl = (item.get("controllability") or "").lower()
        conf = (item.get("confidence") or "").lower()
        sink = item.get("sink") or {}
        sink_type = (sink.get("type") or "").lower()

        if indep in {"high", "critical"} or combo in {"high", "critical"}:
            return True
        if ctrl == "fully":
            return True
        if conf == "high" and sink_type in {"sql", "rce", "deserialize", "file", "include", "ssrf", "xxe"}:
            return True
        if module_name in {"rce_audit", "sql_audit", "serialize_audit"} and sink_type in {"rce", "sql", "deserialize"}:
            return True
        return False

    filtered = [f for f in findings if keep_finding(f)]

    if not filtered and findings:
        filtered = [findings[0]]

    for f in filtered:
        note = f.get("notes") or ""
        tag = "quick_mode:ai_audit_ok"
        f["notes"] = f"{note}; {tag}" if note else tag

    return filtered


def build_poc_from_route(route: Dict) -> Dict:
    if not route:
        return {"method": "GET", "path": "/", "params": {"id": "1"}, "notes": "仅模板，不执行"}
    method = (route.get("method") or "GET").split("|")[0]
    path = route.get("path") or "/"
    if method in ("GET", "ANY"):
        return {"method": "GET", "path": path, "params": {"id": "1"}, "notes": "仅模板，不执行"}
    return {"method": method, "path": path, "body": {"id": "1"}, "notes": "仅模板，不执行"}


def extract_findings_from_traces(
    traces: List[Dict],
    sink_types: List[str],
    title: str,
    prefix: str,
) -> List[Dict]:
    findings = []
    for trace in traces:
        sinks = trace.get("sinks", []) or ([] if trace.get("sink") is None else [trace.get("sink")])
        for s in sinks:
            if not s or s.get("type") not in sink_types:
                continue
            route = trace.get("route")
            line = s.get("line") or 0
            fid = stable_id(prefix, s.get("file"), line, route.get("path") if route else "")
            severity = "high" if trace.get("controllability") == "fully" else "medium"
            confidence = "high" if trace.get("source") else "low"
            findings.append({
                "id": fid,
                "title": title,
                "severity": severity,
                "independent_severity": severity,
                "combined_severity": severity,
                "confidence": confidence,
                "route": route,
                "source": trace.get("source"),
                "taint": trace.get("taint"),
                "sink": s,
                "validation": trace.get("validation"),
                "controllability": trace.get("controllability", "conditional"),
                "poc": build_poc_from_route(route or {}),
                "notes": "Derived from route_tracer.",
            })
    return findings


def write_findings(out_dir: str, title: str, findings: List[Dict]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    write_json(os.path.join(out_dir, "findings.json"), findings)
    lines = [f"# {title}", "", f"Total: {len(findings)}", ""]
    for f in findings:
        sink = f.get("sink") or {}
        lines.append(f"## {f.get('id')} {f.get('title')}")
        lines.append(f"- Severity: {f.get('severity')}")
        lines.append(f"- Sink: {sink.get('file')}:{sink.get('line')}")
        lines.append("")
    write_text(os.path.join(out_dir, "findings.md"), "\n".join(lines) + "\n")


def project_name_from_out(out_root: str) -> str:
    base = os.path.basename(out_root.rstrip("/"))
    m = re.match(r"(.+?)_audit(?:_\\d{8}_\\d{6})?$", base)
    if m:
        return m.group(1)
    return base or "project"


def ascii_table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _display_width(cell))

    def line(left: str, mid: str, right: str, fill: str) -> str:
        return left + mid.join([fill * (w + 2) for w in widths]) + right

    out = [line("┌", "┬", "┐", "─")]
    out.append(
        "│"
        + "│".join([f" {_pad_cell(h, widths[i])} " for i, h in enumerate(headers)])
        + "│"
    )
    out.append(line("├", "┼", "┤", "─"))
    for row in rows:
        out.append(
            "│"
            + "│".join([f" {_pad_cell(cell, widths[i])} " for i, cell in enumerate(row)])
            + "│"
        )
    out.append(line("└", "┴", "┘", "─"))
    return "\n".join(out)


def _pad_cell(value: str, width: int) -> str:
    pad_len = max(0, width - _display_width(value))
    return value + (" " * pad_len)


def _display_width(value: str) -> int:
    if value is None:
        return 1
    text = str(value)
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        if unicodedata.east_asian_width(ch) in {"W", "F"}:
            width += 2
        else:
            width += 1
    return width


def markdown_table(headers: List[str], rows: List[List[str]]) -> str:
    def esc(value) -> str:
        if value is None:
            text = "-"
        else:
            text = str(value)
        text = text.replace("\n", "<br>")
        text = text.replace("|", "\\|")
        return text

    out = []
    out.append("| " + " | ".join([esc(h) for h in headers]) + " |")
    out.append("| " + " | ".join(["---" for _ in headers]) + " |")
    for row in rows:
        out.append("| " + " | ".join([esc(c) for c in row]) + " |")
    return "\n".join(out)


def compact_text(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, (list, tuple)):
        return compact_text("; ".join([compact_text(v) for v in value]))
    if isinstance(value, dict):
        try:
            return compact_text(json.dumps(value, ensure_ascii=False))
        except Exception:
            return compact_text(str(value))
    text = str(value)
    text = text.replace("\n", "\\n")
    text = re.sub(r"\s+", " ", text).strip()
    return text or "-"


def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("independent_severity") or f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _controllability_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {"fully": 0, "conditional": 0, "none": 0}
    for f in findings:
        ctrl = f.get("controllability") or "conditional"
        if ctrl in counts:
            counts[ctrl] += 1
    return counts


def _module_recommendations(module_name: str) -> List[str]:
    mapping = {
        "sql_audit": [
            "优先使用预编译/参数绑定",
            "对表名/列名/排序字段使用白名单",
            "统一输入校验与类型约束",
        ],
        "auth_audit": [
            "关键路由必须鉴权与权限校验",
            "资源操作增加所有权校验",
            "敏感接口增加审计日志",
        ],
        "file_audit": [
            "对路径参数使用 realpath + 目录白名单",
            "对上传文件做扩展名/MIME/内容校验",
            "上传目录禁止脚本执行",
        ],
        "rce_audit": [
            "避免使用 system/exec/eval 等高危函数",
            "如必须执行命令，使用固定 argv + 白名单",
        ],
        "ssrf_xxe_audit": [
            "限制协议与目标域名/内网地址",
            "禁用外部实体或启用 LIBXML_NONET",
        ],
        "xss_ssti_audit": [
            "输出点统一做 HTML 编码",
            "模板引擎避免渲染可控模板字符串",
        ],
        "csrf_audit": [
            "状态修改接口必须校验 CSRF Token",
            "启用 SameSite/Referer 校验",
        ],
        "var_override_audit": [
            "避免 extract/parse_str 处理外部输入",
            "避免使用 $$ 可变变量",
        ],
        "serialize_audit": [
            "避免反序列化不可信数据",
            "使用 JSON 等安全格式替代",
            "限制 phar:// 使用或关闭 phar 解析",
        ],
        "vuln_report": [
            "尽快升级受影响依赖到安全版本",
            "确认项目中是否存在可触发的使用路径",
            "为相关组件加固输入校验与访问控制",
        ],
    }
    return mapping.get(module_name, ["统一输入校验与类型约束", "增加白名单/过滤逻辑"])


def write_module_report(out_dir: str, module_name: str, title: str, findings: List[Dict]) -> str:
    out_root = os.path.dirname(out_dir.rstrip("/"))
    project_name = project_name_from_out(out_root)
    ts = time.strftime("%Y%m%d_%H%M%S")
    report_name = f"{project_name}_{module_name}_{ts}.md"
    lines = [
        f"# {project_name} - {title}",
        "",
        f"生成时间：{ts}",
        f"输出目录：{out_root}",
        "",
        "## 风险映射表",
    ]
    mapping_rows: List[List[str]] = []
    for f in findings:
        sink = f.get("sink") or {}
        loc = f"{sink.get('file','-')}:{sink.get('line','-')}"
        stype = sink.get("type") or sink.get("function") or "unknown"
        ctrl = f.get("controllability") or "conditional"
        indep = f.get("independent_severity") or f.get("severity") or "info"
        combo = f.get("combined_severity") or f.get("severity") or "info"
        mapping_rows.append([str(f.get("id") or "-"), loc, stype, ctrl, indep, combo])
    lines.append(markdown_table(["序号", "位置(文件:行)", "类型", "可控性", "独立等级", "组合等级"], mapping_rows))
    lines.append("")

    lines.append("## 风险详情表")
    detail_rows: List[List[str]] = []
    for f in findings:
        sink = f.get("sink") or {}
        route = f.get("route") or {}
        route_str = f"{route.get('method','')} {route.get('path','')}".strip()
        ai_table = f.get("ai_table") or {}
        ai_info = f.get("ai_confirm") or {}
        notes_parts: List[str] = []
        if f.get("validation"):
            notes_parts.append(f"validation={compact_text(f.get('validation'))}")
        if f.get("path_filters"):
            notes_parts.append(f"path_filters={compact_text(f.get('path_filters'))}")
        if f.get("url_filters"):
            notes_parts.append(f"url_filters={compact_text(f.get('url_filters'))}")
        if f.get("xml_filters"):
            notes_parts.append(f"xml_filters={compact_text(f.get('xml_filters'))}")
        if f.get("dangerous_function"):
            notes_parts.append(f"dangerous_function={compact_text(f.get('dangerous_function'))}")
        if f.get("notes"):
            notes_parts.append(f"notes={compact_text(f.get('notes'))}")
        evidence_summary = ai_table.get("evidence_summary") if isinstance(ai_table, dict) else None
        debug = f.get("debug_evidence") or {}
        debug_result = debug.get("result") or "-"
        debug_change = debug.get("change_type") or "-"
        detail_rows.append([
            str(f.get("id") or "-"),
            compact_text(f.get("title") or "-"),
            compact_text(f"{sink.get('file','-')}:{sink.get('line','-')}"),
            compact_text(f.get("independent_severity") or f.get("severity") or "info"),
            compact_text(f.get("combined_severity") or f.get("severity") or "info"),
            compact_text(f.get("confidence") or "-"),
            compact_text(f.get("exploitability") or "-"),
            compact_text(f.get("controllability") or "-"),
            compact_text(route_str or "-"),
            compact_text(f"{sink.get('function') or sink.get('type') or '-'}"),
            compact_text(debug_result),
            compact_text(debug_change),
            compact_text(ai_info.get("rationale") or "-"),
            compact_text(evidence_summary or "-"),
            compact_text("; ".join(notes_parts) if notes_parts else "-"),
        ])
    lines.append(
        markdown_table(
            ["ID", "标题", "位置", "独立等级", "组合等级", "置信度", "可利用性", "可控性", "路由/入口", "Sink", "Debug结论", "变化类型", "AI理由", "证据摘要", "备注"],
            detail_rows,
        )
    )
    lines.append("")

    lines.append("## 证据链表")
    evidence_rows: List[List[str]] = []
    for f in findings:
        evidence_rows.append([
            str(f.get("id") or "-"),
            compact_text(f.get("source")),
            compact_text(f.get("taint")),
            compact_text(f.get("validation")),
        ])
    lines.append(markdown_table(["ID", "Source", "Taint", "Validation"], evidence_rows))
    lines.append("")

    lines.append("## PoC 表")
    poc_rows: List[List[str]] = []
    for f in findings:
        ai_table = f.get("ai_table") or {}
        poc = ai_table.get("poc") or f.get("poc")
        poc_source = ai_table.get("poc_source") or ("template" if poc else "-")
        poc_quality = ai_table.get("poc_quality") or f.get("poc_quality") or "-"
        if poc_source == "template":
            poc_source = "template(需人工校验)"
        poc_rows.append([
            str(f.get("id") or "-"),
            poc_source,
            poc_quality,
            compact_text(poc),
        ])
    lines.append(markdown_table(["ID", "PoC来源", "PoC质量", "PoC"], poc_rows))
    lines.append("")

    lines.append("## 修复建议")
    rec_rows = [[str(i + 1), r] for i, r in enumerate(_module_recommendations(module_name))]
    lines.append(markdown_table(["序号", "建议"], rec_rows))
    lines.append("")

    write_text(os.path.join(out_dir, report_name), "\n".join(lines) + "\n")
    write_module_html(out_dir, module_name, title, findings)
    return report_name


def _safe_filename(text: str) -> str:
    cleaned = []
    for ch in str(text):
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9") or ch in ("-", "_"):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    name = "".join(cleaned).strip("_")
    return name or "finding"


def _html_escape(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, (dict, list)):
        return html.escape(json.dumps(value, ensure_ascii=False, indent=2))
    return html.escape(str(value))


def _to_float(value):
    try:
        return float(value)
    except Exception:
        return None


def _extract_cvss(finding: Dict):
    raw = finding.get("cvss_score")
    if raw is None:
        raw = finding.get("cvss")
    if isinstance(raw, dict):
        raw = raw.get("score") or raw.get("baseScore") or raw.get("cvss")
    return _to_float(raw)


def _severity_meta(finding: Dict) -> Dict[str, str]:
    sev = (finding.get("combined_severity") or finding.get("severity") or "info").lower()
    if sev not in {"critical", "high", "medium", "low", "info"}:
        sev = "info"
    cn_map = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "提示",
    }
    en_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    color_map = {
        "critical": "#d32f2f",
        "high": "#e65100",
        "medium": "#f9a825",
        "low": "#2e7d32",
        "info": "#546e7a",
    }
    cvss = _extract_cvss(finding)
    if cvss is not None:
        label = f"{cn_map[sev]} (CVSS {cvss:.1f})"
    else:
        label = f"{cn_map[sev]} ({en_map[sev]})"
    return {"label": label, "color": color_map[sev]}


def _metric_value(finding: Dict, key: str, default: str = "待评估") -> str:
    metrics = finding.get("metrics") or {}
    value = finding.get(key)
    if value is None:
        value = metrics.get(key)
    if value is None or value == "":
        return default
    return str(value)


def _format_route(route) -> str:
    if not route:
        return "-"
    if isinstance(route, dict):
        method = route.get("method") or ""
        path = route.get("path") or ""
        return f"{method} {path}".strip() or "-"
    return str(route)


def _format_location(finding: Dict) -> str:
    sink = finding.get("sink") or {}
    file_path = sink.get("file") or "-"
    line = sink.get("line") or "-"
    func = sink.get("function") or sink.get("type") or ""
    loc = f"{file_path}:{line}"
    if func:
        loc = f"{loc} ({func})"
    return loc


def _format_source(finding: Dict) -> str:
    source = finding.get("source")
    if not source:
        return "未提供"
    if isinstance(source, dict):
        param = source.get("param") or source.get("name")
        stype = source.get("type") or "param"
        if param:
            return f"{stype}:{param}"
        return json.dumps(source, ensure_ascii=False)
    return str(source)


def _format_validation(finding: Dict) -> str:
    val = finding.get("validation")
    if not val:
        return "未提供"
    if isinstance(val, (list, dict)):
        return json.dumps(val, ensure_ascii=False)
    return str(val)


def _format_taint(finding: Dict) -> str:
    taint = finding.get("taint")
    if not taint:
        return "未提供"
    if isinstance(taint, (list, dict)):
        return json.dumps(taint, ensure_ascii=False)
    return str(taint)


def finding_html_basename(finding: Dict, module_name: str) -> str:
    fid = finding.get("id")
    if not fid:
        sink = finding.get("sink") or {}
        fid = stable_id(module_name.upper(), sink.get("file"), sink.get("line"), finding.get("title") or "")
    return f"{_safe_filename(fid)}.html"


def finding_html_relpath(finding: Dict, module_name: str) -> str:
    return os.path.join(module_name, "html", finding_html_basename(finding, module_name))


def _severity_color_from_label(label: str) -> str:
    lower = (label or "").lower()
    if "critical" in lower or "严重" in lower:
        return "#d32f2f"
    if "high" in lower or "高危" in lower:
        return "#e65100"
    if "medium" in lower or "中危" in lower:
        return "#f9a825"
    if "low" in lower or "低危" in lower:
        return "#2e7d32"
    return "#546e7a"


def _require_ai_table(finding: Dict) -> Dict:
    ai_table = finding.get("ai_table")
    if isinstance(ai_table, dict):
        return ai_table
    sink = finding.get("sink") or {}
    location = f"{sink.get('file','-')}:{sink.get('line','-')}"
    severity_label = finding.get("combined_severity") or finding.get("severity") or "medium"
    return {
        "title_label": finding.get("title") or finding.get("id") or "Finding",
        "severity_label": severity_label,
        "reachability": {"desc": "-"},
        "impact": {"desc": "-"},
        "complexity": {"desc": "-"},
        "exploitability": finding.get("exploitability") or "-",
        "location": location,
        "trigger": "-",
        "input_source": "-",
        "output_mode": "-",
        "evidence": [],
        "evidence_summary": "-",
    }


def render_finding_html(finding: Dict, module_name: str) -> str:
    ai_table = _require_ai_table(finding)
    header = ai_table.get("title_label")
    if not header:
        raise ValueError("ai_table.title_label missing")
    severity_label = ai_table.get("severity_label")
    if not severity_label:
        raise ValueError("ai_table.severity_label missing")

    reachability = (ai_table.get("reachability") or {}).get("desc")
    impact = (ai_table.get("impact") or {}).get("desc")
    complexity = (ai_table.get("complexity") or {}).get("desc")
    exploitability = ai_table.get("exploitability")
    location = ai_table.get("location")
    trigger = ai_table.get("trigger")
    input_source = ai_table.get("input_source")
    output_mode = ai_table.get("output_mode")
    evidence = ai_table.get("evidence") or []

    if not all([reachability, impact, complexity, exploitability, location, trigger, input_source, output_mode]):
        raise ValueError("ai_table fields incomplete")

    ai_info = finding.get("ai_confirm") or {}
    ai_rationale = ai_info.get("rationale")
    notes = finding.get("notes") or ""
    ai_note_html = f'<div class="note">AI 理由：{_html_escape(ai_rationale)}</div>' if ai_rationale else ""
    poc = finding.get("poc")
    poc_text = json.dumps(poc, ensure_ascii=False, indent=2) if poc else "未提供"

    recommendations = _module_recommendations(module_name)
    rec_lines = "\n".join(f"<li>{_html_escape(r)}</li>" for r in recommendations)
    evidence_lines = []
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        ev_file = ev.get("file") or "-"
        ev_line = ev.get("line") or "-"
        ev_note = ev.get("note") or ""
        evidence_lines.append(f"{ev_file}:{ev_line} {ev_note}".rstrip())
    evidence_text = "\n".join(evidence_lines) if evidence_lines else "未提供"

    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_html_escape(header)}</title>
  <style>
    :root {{
      --bg: #ffffff;
      --card: #ffffff;
      --text: #1f2933;
      --muted: #667085;
      --border: #e4e7ec;
      --shadow: 0 10px 24px rgba(0,0,0,0.08);
    }}
    body {{
      margin: 0;
      padding: 32px 20px 60px;
      background: var(--bg);
      font-family: "PingFang SC","Noto Sans SC","Microsoft YaHei",system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      color: var(--text);
    }}
    .card {{
      max-width: 980px;
      margin: 0 auto;
      background: var(--card);
      border-radius: 26px;
      border: 1px solid #e6e8eb;
      box-shadow: var(--shadow);
      padding: 28px 32px 32px;
    }}
    h1 {{
      font-size: 28px;
      margin: 0 0 20px;
      font-weight: 700;
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px 28px;
      font-size: 14px;
      color: var(--muted);
      margin-bottom: 18px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 15px;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 12px 14px;
      vertical-align: top;
    }}
    th {{
      width: 200px;
      text-align: left;
      background: #f8fafc;
      color: #344054;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
    }}
    .dot {{
      width: 14px;
      height: 14px;
      border-radius: 999px;
      background: {_severity_color_from_label(severity_label)};
      box-shadow: 0 0 0 2px rgba(0,0,0,0.05) inset;
    }}
    .section {{
      margin-top: 22px;
    }}
    .section h2 {{
      font-size: 18px;
      margin: 0 0 8px;
    }}
    pre {{
      background: #f6f8fa;
      padding: 12px 14px;
      border-radius: 10px;
      font-size: 13px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    ul {{
      margin: 6px 0 0 18px;
      padding: 0;
    }}
    .note {{
      font-size: 13px;
      color: var(--muted);
      margin-top: 8px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{_html_escape(header)}</h1>
    <table>
      <tr><th>项目</th><th>信息</th></tr>
      <tr>
        <td>严重等级</td>
        <td><span class="badge"><span class="dot"></span>{_html_escape(severity_label)}</span></td>
      </tr>
      <tr><td>可达性 (R)</td><td>{_html_escape(reachability)}</td></tr>
      <tr><td>影响范围 (I)</td><td>{_html_escape(impact)}</td></tr>
      <tr><td>利用复杂度 (C)</td><td>{_html_escape(complexity)}</td></tr>
      <tr><td>可利用性</td><td>{_html_escape(exploitability)}</td></tr>
      <tr><td>位置</td><td>{_html_escape(location)}</td></tr>
      <tr><td>触发函数/组件</td><td>{_html_escape(trigger)}</td></tr>
      <tr><td>输入来源</td><td>{_html_escape(input_source)}</td></tr>
      <tr><td>回显方式</td><td>{_html_escape(output_mode)}</td></tr>
    </table>
    <div class="section">
      <h2>证据链</h2>
      <pre>{_html_escape("AI Evidence: " + evidence_text)}</pre>
    </div>
    <div class="section">
      <h2>PoC 模板（不执行）</h2>
      <pre>{_html_escape(poc_text)}</pre>
    </div>
    <div class="section">
      <h2>修复建议</h2>
      <ul>{rec_lines}</ul>
    </div>
    <div class="section">
      <h2>说明</h2>
      <div class="note">{_html_escape(notes or "无")}</div>
      {ai_note_html}
    </div>
  </div>
</body>
</html>
"""
    return html_doc


def render_module_index_html(module_name: str, title: str, findings: List[Dict]) -> str:
    rows = []
    for f in findings:
        fid = f.get("id") or "-"
        sev = (f.get("combined_severity") or f.get("severity") or "info").lower()
        location = _format_location(f)
        link = finding_html_basename(f, module_name)
        rows.append(
            f"<tr><td>{_html_escape(fid)}</td>"
            f"<td><a href=\"html/{_html_escape(link)}\">{_html_escape(f.get('title') or '漏洞')}</a></td>"
            f"<td>{_html_escape(sev)}</td>"
            f"<td>{_html_escape(location)}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=\"4\">无风险项</td></tr>")
    body_rows = "\n".join(rows)
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_html_escape(title)} 索引</title>
  <style>
    body {{
      margin: 0;
      padding: 32px;
      font-family: "PingFang SC","Noto Sans SC","Microsoft YaHei",system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      background: #f2f4f7;
      color: #1f2933;
    }}
    .card {{
      max-width: 1100px;
      margin: 0 auto;
      background: #fff;
      border-radius: 18px;
      padding: 24px 28px;
      box-shadow: 0 10px 32px rgba(0,0,0,0.1);
    }}
    h1 {{
      margin: 0 0 14px;
      font-size: 24px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid #e4e7ec;
      padding: 10px 12px;
      text-align: left;
    }}
    th {{
      background: #f8fafc;
      color: #344054;
    }}
    a {{
      color: #2563eb;
      text-decoration: none;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{_html_escape(title)} 索引</h1>
    <table>
      <tr><th>ID</th><th>标题</th><th>等级</th><th>位置</th></tr>
      {body_rows}
    </table>
  </div>
</body>
</html>
"""
    return html_doc


def write_module_html(out_dir: str, module_name: str, title: str, findings: List[Dict]) -> None:
    html_dir = os.path.join(out_dir, "html")
    os.makedirs(html_dir, exist_ok=True)
    for f in findings:
        name = finding_html_basename(f, module_name)
        path = os.path.join(html_dir, name)
        write_text(path, render_finding_html(f, module_name))
    index_html = render_module_index_html(module_name, title, findings)
    write_text(os.path.join(out_dir, "index.html"), index_html)
