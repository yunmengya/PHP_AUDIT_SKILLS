> **Skill ID**: S-090b | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Input**: exploit_results/*.json
> **Output**: `$WORK_DIR/报告/01_漏洞汇总表.md`

# Vulnerability Summary Writer

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-090b |
| Phase | Phase-5 (Report Generation) |
| Responsibility | Generate the vulnerability summary table with one row per confirmed vulnerability, sorted by severity |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| exploit_results/*.json | `$WORK_DIR/exploits/*.json` | ✅ | `sink_id`, `sink_type`, `severity`, `route`, `final_verdict`, `score`, `verification_level` |
| exploit_summary.json | `$WORK_DIR/exploit_summary.json` | ❌ | `total`, `confirmed` (for validation cross-check) |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | ONLY include entries where `final_verdict == "confirmed"` | Including unconfirmed vulns inflates report severity |
| CR-2 | Sort rows by severity: Critical → High → Medium → Low | Misordering hides critical findings |
| CR-3 | Each row MUST include the AI verification badge (🟢/🟡/🔴) | Missing verification status violates report iron rules |
| CR-4 | CVSS score MUST be the actual `score` from exploit result — no fabrication | Fabricated scores destroy report credibility |
| CR-5 | If zero confirmed vulnerabilities exist, output a "未发现已确认漏洞" notice instead of an empty table | Empty table confuses readers |

## Fill-in Procedure

### Procedure A: Collect Confirmed Vulnerabilities

1. Iterate all files matching `$WORK_DIR/exploits/*.json`
2. For each file, check `final_verdict` field
3. ONLY select entries where `final_verdict == "confirmed"`
4. Extract the following fields per entry:

| Field | Fill-in Value |
|-------|---------------|
| 编号 | `sink_id` (e.g., `C-RCE-001`) |
| 漏洞类型 | `sink_type` mapped to Chinese label (see mapping below) |
| 严重等级 | `severity` mapped to emoji+Chinese (see mapping below) |
| 路由 | `route` (HTTP method + path, e.g., `POST /api/cmd`) |
| 验证状态 | `verification_level` mapped to badge (see mapping below) |
| CVSS | `score` (numeric, e.g., `9.45`) |

### Procedure B: Apply Mappings

**Severity mapping:**

| severity value | Display |
|----------------|---------|
| critical | 🔴 紧急 |
| high | 🟠 高危 |
| medium | 🟡 中危 |
| low | 🔵 低危 |

**Verification level mapping:**

| verification_level | Display |
|--------------------|---------|
| exploited | 🟢 已实战 |
| analyzed | 🟡 已分析 |
| static_only | 🔴 纯静态 |

**Sink type mapping:**

| sink_type | Chinese Label |
|-----------|---------------|
| rce | 命令注入 |
| sqli | SQL注入 |
| xss | 跨站脚本 |
| file_upload | 文件上传 |
| file_include | 文件包含 |
| ssrf | SSRF |
| deserialization | 反序列化 |
| xxe | XXE |
| path_traversal | 路径穿越 |
| auth_bypass | 认证绕过 |
| other | 其他 |

### Procedure C: Sort and Assemble

1. Sort all collected rows by severity order: Critical → High → Medium → Low
2. Within same severity, sort by CVSS score descending
3. Fill into the following template:

````markdown
# 漏洞汇总表

> 共发现 **{confirmed_count}** 个已确认漏洞

| 编号 | 漏洞类型 | 严重等级 | 路由 | 验证状态 | CVSS |
|------|----------|----------|------|----------|------|
| {sink_id} | {漏洞类型} | {严重等级} | {路由} | {验证状态} | {score} |
| ... | ... | ... | ... | ... | ... |

> 评分公式: 可达性×0.40 + 影响×0.35 + 复杂度反转×0.25
> 等级映射: ≥8.0 🔴紧急 / 6.0-7.9 🟠高危 / 4.0-5.9 🟡中危 / <4.0 🔵低危
````

### Procedure D: Zero-Vulnerability Case

If no entries pass the `final_verdict == "confirmed"` filter:

````markdown
# 漏洞汇总表

> ✅ **未发现已确认漏洞**
>
> 所有扫描的 Sink 均未发现可利用的安全漏洞。
> 详细审计覆盖范围请参见 04_覆盖率统计.md。
````

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| 01_漏洞汇总表.md | `$WORK_DIR/报告/01_漏洞汇总表.md` | Summary table of all confirmed vulnerabilities |

## Examples

### ✅ GOOD: Properly Sorted Summary Table

```markdown
# 漏洞汇总表

> 共发现 **5** 个已确认漏洞

| 编号 | 漏洞类型 | 严重等级 | 路由 | 验证状态 | CVSS |
|------|----------|----------|------|----------|------|
| C-RCE-001 | 命令注入 | 🔴 紧急 | POST /api/cmd | 🟢 已实战 | 9.45 |
| C-DESER-001 | 反序列化 | 🔴 紧急 | POST /api/import | 🟢 已实战 | 8.80 |
| H-SQL-001 | SQL注入 | 🟠 高危 | GET /user?id= | 🟡 已分析 | 7.20 |
| H-SQL-002 | SQL注入 | 🟠 高危 | POST /search | 🟢 已实战 | 6.85 |
| M-XSS-001 | 跨站脚本 | 🟡 中危 | GET /profile | 🟡 已分析 | 4.30 |

> 评分公式: 可达性×0.40 + 影响×0.35 + 复杂度反转×0.25
> 等级映射: ≥8.0 🔴紧急 / 6.0-7.9 🟠高危 / 4.0-5.9 🟡中危 / <4.0 🔵低危
```

Sorted by severity (Critical → High → Medium), then by CVSS descending within same severity. All fields populated. ✅

### ❌ BAD: Including Unconfirmed Entries

```markdown
| C-RCE-001 | 命令注入 | 🔴 紧急 | POST /api/cmd | 🟢 已实战 | 9.45 |
| S-SQL-003 | SQL注入 | 🟠 高危 | GET /admin | 🟡 已分析 | 6.10 |
```

S-SQL-003 has `final_verdict: "suspected"` — it belongs in 05_未验证风险池.md, not here. Violates CR-1. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit result files found in exploits/ | Output zero-vulnerability template (Procedure D) |
| Exploit file missing `sink_id` field | Generate ID from filename: `UNKNOWN-{filename}` |
| Unknown `sink_type` value | Use `其他` as Chinese label |
| Unknown `severity` value | Default to `🟡 中危`; log warning |
| Missing `score` field | Display `N/A`; sort after scored entries of same severity |
| Count mismatch with exploit_summary.json | Use the actual count from scanned files; add footnote about discrepancy |
