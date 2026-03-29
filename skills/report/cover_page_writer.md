> **Skill ID**: S-090a | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Input**: environment_status.json, exploit_summary.json
> **Output**: `$WORK_DIR/报告/00_封面.md`

# Cover Page Writer

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-090a |
| Phase | Phase-5 (Report Generation) |
| Responsibility | Generate the audit report cover page with project metadata and vulnerability statistics |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `project_name`, `framework`, `framework_version`, `php_version`, `target_path` |
| exploit_summary.json | `$WORK_DIR/exploit_summary.json` | ✅ | `total`, `confirmed`, `suspected`, `potential`, `severity_breakdown.critical`, `severity_breakdown.high`, `severity_breakdown.medium`, `severity_breakdown.low` |
| route_map.json | `$WORK_DIR/route_map.json` | ❌ | `routes[]` (count for total routes) |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | All report text MUST be in Chinese; only technical terms (e.g., "PHP", "SQL Injection") may remain in English | Report rejected by quality checker |
| CR-2 | Every field in the cover table MUST be populated — no empty or placeholder values | Incomplete cover page fails QC |
| CR-3 | Vulnerability counts MUST match exploit_summary.json exactly — no manual calculation | Data inconsistency triggers report redo |
| CR-4 | audit_date MUST use the current date in `YYYY-MM-DD` format | Misleading audit timestamp |
| CR-5 | If environment_status.json is missing, extract project_name from `$WORK_DIR` directory name | Cover page still generated with partial data |

| CR-PRE | Pre-Submission Checklist MUST be completed before output — any ❌ MUST be fixed before submitting | Known-bad output wastes QC cycle |
## Fill-in Procedure

### Procedure A: Extract Project Metadata

Read `environment_status.json` and fill:

| Field | Fill-in Value |
|-------|---------------|
| project_name | `environment_status.json → project_name` (fallback: basename of `$WORK_DIR`) |
| audit_date | Current date in `YYYY-MM-DD` format |
| target_version | `environment_status.json → framework_version` or `"未识别"` |
| framework | `environment_status.json → framework` or `"原生PHP"` |
| php_version | `environment_status.json → php_version` or `"未检测"` |

### Procedure B: Extract Vulnerability Statistics

Read `exploit_summary.json` and fill:

| Field | Fill-in Value |
|-------|---------------|
| total_vulns | `exploit_summary.json → total` |
| critical_count | `exploit_summary.json → severity_breakdown.critical` |
| high_count | `exploit_summary.json → severity_breakdown.high` |
| medium_count | `exploit_summary.json → severity_breakdown.medium` |
| low_count | `exploit_summary.json → severity_breakdown.low` |

### Procedure C: Calculate CVSS Visual Bars

For each severity count, generate a progress bar:

| Field | Fill-in Rule |
|-------|-------------|
| critical_bar | Repeat `█` for `critical_count` times (max 20), then pad with `░` to 20 chars. Suffix: `{critical_count}个` |
| high_bar | Same rule for `high_count` |
| medium_bar | Same rule for `medium_count` |
| low_bar | Same rule for `low_count` |

If count > 20, cap at 20 `█`. If count == 0, show 20 `░`.

### Procedure D: Calculate Risk Level

| Condition | Risk Level |
|-----------|-----------|
| critical_count ≥ 1 OR confirmed ≥ 5 | 🔴 **高风险** |
| high_count ≥ 1 OR confirmed ≥ 2 | 🟠 **中风险** |
| confirmed ≥ 1 AND critical == 0 AND high == 0 | 🟡 **低风险** |
| confirmed == 0 | 🟢 **安全** |

### Procedure E: Assemble Cover Page + Executive Summary

Fill all values into the following fixed template:

````markdown
# PHP 代码安全审计报告

| 项目 | 详情 |
|------|------|
| 项目名称 | {project_name} |
| 审计日期 | {audit_date} |
| 目标版本 | {framework} {target_version} |
| PHP 版本 | {php_version} |
| 路由总数 | {total_routes} |
| 已审计路由 | {audited_routes} |
| 审计覆盖率 | {coverage_pct}% |

### 漏洞统计概览

| 严重等级 | 数量 | 可视化 |
|----------|------|--------|
| 🔴 紧急 (Critical) | {critical_count} | {critical_bar} |
| 🟠 高危 (High) | {high_count} | {high_bar} |
| 🟡 中危 (Medium) | {medium_count} | {medium_bar} |
| 🔵 低危 (Low) | {low_count} | {low_bar} |
| **合计** | **{total_vulns}** | |

> 🟢已确认 {confirmed} / 🟡疑似 {suspected} / 🔴潜在 {potential}

*本报告由 AI 辅助生成，所有漏洞均经过自动化验证。*
*报告版本: v1.0 | 生成时间: {audit_date} {audit_time} | 工具: PHP_AUDIT_SKILLS v2.0*

<br/>

---

<br/>

## 📖 目录

| 章节 | 标题 | 页内锚点 |
|------|------|----------|
| 第 0 章 | 执行摘要 | [跳转](#执行摘要) |
| 第 1 章 | 漏洞汇总表 | [跳转](#漏洞汇总表) |
| 第 2 章 | 漏洞详情 | [跳转](#漏洞详情) |
| 第 3 章 | 联合攻击链分析 | [跳转](#联合攻击链分析) |
| 第 4 章 | 审计覆盖率统计 | [跳转](#审计覆盖率统计) |
| 第 5 章 | 待补证风险池 | [跳转](#待补证风险池) |
| 第 6 章 | 审计经验总结 | [跳转](#审计经验总结) |

<br/>

---

<br/>

## 执行摘要

> 🎯 本节为审计结果一页纸总结，供管理层快速了解整体安全态势。

### 整体风险评级

| 指标 | 值 |
|------|-----|
| **整体风险等级** | {risk_level} |
| 确认漏洞数 | {confirmed} |
| 紧急漏洞数 | {critical_count} |
| 高危漏洞数 | {high_count} |
| 需立即修复 | {immediate_fix_list} |

### 关键发现

| # | 漏洞 | 等级 | 一句话描述 | 紧急程度 |
|---|------|------|-----------|---------|
| 1 | {sink_id} | {severity_emoji} | {one_line_desc} | {⚡ 立即修复 / 📋 计划修复} |
| ... | ... | ... | ... | ... |

> ⚡ 立即修复 = Critical/High | 📋 计划修复 = Medium/Low

### 审计范围概要

| 项目 | 值 |
|------|-----|
| 扫描路由数 | {total_routes} |
| 已审计路由 | {audited_routes} |
| 覆盖率 | {coverage_pct}% |
| 使用审计器 | {auditor_count} 个 |
| 攻击轮次 | 最多 {max_rounds} 轮/漏洞 |

{IF confirmed == 0: "> ✅ **恭喜！本次审计未发现可利用的安全漏洞。**"}
````

## Pre-Submission Checklist (MUST Execute)

Before submitting output, complete the self-check per `shared/pre_submission_checklist.md`:

| # | Check Item | Your Result | Pass |
|---|-----------|-------------|------|
| P1 | JSON syntax valid | {result} | {✅/❌} |
| P2 | All required fields present | {result} | {✅/❌} |
| P3 | Zero placeholder text | {result} | {✅/❌} |
| P4 | File:line citations verified | {result} | {✅/❌} |
| P5 | Output saved to correct path | {result} | {✅/❌} |
| P6 | Degradation check completed | {result} | {✅/❌} |
| P7 | No fabricated data | {result} | {✅/❌} |
| P8 | Field value ranges valid | {result} | {✅/❌} |

ANY ❌ → fix before submitting. MUST NOT submit with ❌.

## Output Contract

| Output File | Path | Description | Schema |
|-------------|------|-------------|--------|
| 00_封面.md | `$WORK_DIR/报告/00_封面.md` | Audit report cover page with project metadata and vulnerability statistics | N/A (Markdown output) |

## Examples

### ✅ GOOD: Complete Cover Page

```markdown
# PHP 代码安全审计报告

| 项目 | 详情 |
|------|------|
| 项目名称 | MyShop 电商系统 |
| 审计日期 | 2025-01-15 |
| 目标版本 | v2.3.1 |
| 框架 | Laravel |
| PHP 版本 | 8.1.27 |

## 漏洞统计概览

| 严重等级 | 数量 | 标记 |
|----------|------|------|
| 🔴 紧急 (Critical) | 2 | ██████ |
| 🟠 高危 (High) | 3 | █████ |
| 🟡 中危 (Medium) | 5 | ████ |
| 🔵 低危 (Low) | 1 | ███ |
| **合计** | **11** | |

> 🟢已确认 8 / 🟡疑似 2 / 🔴潜在 1

---

*本报告由 AI 辅助生成，所有漏洞均经过自动化验证。*
*报告生成时间: 2025-01-15*
```

All fields populated, counts match exploit_summary.json, date is correct. ✅

### ❌ BAD: Missing Fields

```markdown
# PHP 代码安全审计报告

| 项目 | 详情 |
|------|------|
| 项目名称 | |
| 审计日期 | TODO |
| 目标版本 | v2.3.1 |
| 框架 | |
| PHP 版本 | 8.1.27 |
```

Missing project_name, empty framework, placeholder date — violates CR-2 and CR-4. ❌

## Error Handling

| Error | Action |
|-------|--------|
| environment_status.json missing | Use `$WORK_DIR` basename as project_name; set framework/php_version to `"未识别"` |
| exploit_summary.json missing | Set all counts to 0; add warning note: `"⚠️ 漏洞统计数据不可用"` |
| severity_breakdown field missing | Default the missing severity count to 0 |
| Total does not match sum of severity counts | Use the sum of severity counts as total; log discrepancy |
