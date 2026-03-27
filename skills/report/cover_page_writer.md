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

### Procedure C: Assemble Cover Page

Fill all values into the following fixed template:

````markdown
# PHP 代码安全审计报告

| 项目 | 详情 |
|------|------|
| 项目名称 | {project_name} |
| 审计日期 | {audit_date} |
| 目标版本 | {target_version} |
| 框架 | {framework} |
| PHP 版本 | {php_version} |

## 漏洞统计概览

| 严重等级 | 数量 | 标记 |
|----------|------|------|
| 🔴 紧急 (Critical) | {critical_count} | ██████ |
| 🟠 高危 (High) | {high_count} | █████ |
| 🟡 中危 (Medium) | {medium_count} | ████ |
| 🔵 低危 (Low) | {low_count} | ███ |
| **合计** | **{total_vulns}** | |

> 🟢已确认 {confirmed} / 🟡疑似 {suspected} / 🔴潜在 {potential}

---

*本报告由 AI 辅助生成，所有漏洞均经过自动化验证。*
*报告生成时间: {audit_date}*
````

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| 00_封面.md | `$WORK_DIR/报告/00_封面.md` | Audit report cover page with project metadata and vulnerability statistics |

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
