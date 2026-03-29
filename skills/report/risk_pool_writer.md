> **Skill ID**: S-090f | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Input**: exploits/*.json
> **Output**: `$WORK_DIR/报告/05_未验证风险池.md`

# Risk Pool Writer

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-090f |
| Phase | Phase-5 (Report Generation) |
| Responsibility | Generate the unconfirmed/suspected findings table for manual review — entries that could not be fully confirmed but warrant attention |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| exploits/*.json | `$WORK_DIR/exploits/*.json` | ✅ | `sink_id`, `sink_type`, `route`, `final_verdict`, `downgrade_reason`, `suggested_action`, `severity` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | ONLY include entries where `final_verdict` is `"suspected"`, `"partial"`, or `"needs_manual_verification"` — NEVER include `"confirmed"` or `"not_vulnerable"` | Confirmed vulns belong in chapters 01/02; false positives must not appear here |
| CR-2 | Risk pool entries MUST NOT be deleted or omitted — even extremely low risk items MUST be listed with explanation | Missing entries violate audit completeness |
| CR-3 | Each entry MUST include a downgrade reason explaining why it was not confirmed | Entries without reasons are actionless |
| CR-4 | Each entry MUST include a suggested manual verification action | Risk pool without action items is useless |
| CR-5 | If risk pool is empty, output explicit confirmation that all findings were either confirmed or ruled out | Empty file is ambiguous |

| CR-DEG | Step 0 Degradation Check MUST be completed before any processing — empty table = QC FAIL | Degraded data treated as complete |
| CR-PRE | Pre-Submission Checklist MUST be completed before output — any ❌ MUST be fixed before submitting | Known-bad output wastes QC cycle |
## Fill-in Procedure

### Step 0 — Upstream Degradation Check (MANDATORY)

Per `shared/degradation_check.md`, fill the degradation status table before any data processing:

| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-2 | PHASE2_DEGRADED | {true/false/not_set} | {files consumed from this phase} |
| Phase-3 | PHASE3_DEGRADED | {true/false/not_set} | {files consumed from this phase} |
| Phase-4 | PHASE4_DEGRADED | {true/false/not_set} | {files consumed from this phase} |

IF any Value = true → apply Degradation Enforcement Rules (cap verdicts at "suspected", add [DEGRADED INPUT] prefix).

### Procedure A: Filter Unconfirmed Findings

1. Iterate all files in `$WORK_DIR/exploits/*.json`
2. For each file, check `final_verdict`
3. Select entries where `final_verdict` is one of:
   - `"suspected"` — likely vulnerable but insufficient proof
   - `"partial"` — some evidence but incomplete exploitation
   - `"needs_manual_verification"` — automated testing inconclusive

Extract:

| Field | Fill-in Value |
|-------|---------------|
| 编号 | Auto-generate: `RP-{sequential_number}` (e.g., `RP-001`) |
| 类型 | `sink_type` mapped to Chinese label |
| 路由 | `route` (HTTP method + path) |
| 原因 | `downgrade_reason` — why this was not confirmed |
| 建议操作 | `suggested_action` — recommended manual verification approach |

### Procedure B: Map Downgrade Reasons

If `downgrade_reason` is a code, map to Chinese:

| Code | Chinese Display |
|------|----------------|
| docker_unavailable | Docker 环境未启动，无法动态验证 |
| auth_required | 需要有效认证凭据，自动化测试无法获取 |
| waf_blocked | WAF 拦截了测试请求 |
| complex_prerequisite | 需要复杂前置条件（如特定数据库状态） |
| timeout | 测试超时未完成 |
| ambiguous_response | 响应模糊，无法判断是否成功 |
| rate_limited | 触发速率限制，测试中断 |
| (other) | ⚠️ UNRECOGNIZED CODE — map to `"原因未归类: {raw_value}"` and log warning. MUST NOT pass through raw free-text. |

### Procedure C: Map Suggested Actions

If `suggested_action` is a code, map to Chinese:

| Code | Chinese Display |
|------|----------------|
| manual_burp | 手工 Burp Suite 测试 |
| manual_code_review | 人工代码审查 |
| setup_docker | 搭建 Docker 环境后重新测试 |
| get_credentials | 获取有效凭据后重新测试 |
| disable_waf | 关闭 WAF 后测试（仅限测试环境） |
| time_based_test | 使用时间盲注等间接验证手段 |
| (other) | Use `suggested_action` value directly |

### Procedure D: Assemble Document

````markdown

<br/>

---

<br/>

## 待补证风险池

> 以下条目因证据不完整暂未确认，建议人工复验。
> ⚠️ 风险池条目不可删除，即使风险极低也须列出并注明原因。

| 编号 | 类型 | 路由 | 降级原因 | 建议复验方式 |
|------|------|------|----------|--------------|
| {编号} | {类型} | {路由} | {原因} | {建议操作} |
| ... | ... | ... | ... | ... |

> 共 **{risk_count}** 条待补证项目
````

### Procedure E: Empty Risk Pool

If no entries match the filter:

````markdown
# 待补证风险池

> ✅ **风险池为空**
>
> 所有发现的可疑点均已完成验证:
> - 已确认漏洞已列入 01_漏洞汇总表 和 02_漏洞详情
> - 已排除的误报不再列入
>
> 无需人工补充验证。
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
| 05_未验证风险池.md | `$WORK_DIR/报告/05_未验证风险池.md` | Table of unconfirmed/suspected findings for manual review | N/A (Markdown output) |

## Examples

### ✅ GOOD: Complete Risk Pool Table

```markdown
# 待补证风险池

> 以下条目因证据不完整暂未确认，建议人工复验。
> ⚠️ 风险池条目不可删除，即使风险极低也须列出并注明原因。

| 编号 | 类型 | 路由 | 降级原因 | 建议复验方式 |
|------|------|------|----------|--------------|
| RP-001 | SQL注入 | GET /user?id= | Docker 环境未启动，无法动态验证 | 手工 Burp Suite 测试 |
| RP-002 | 文件包含 | GET /page?tpl= | 响应模糊，无法判断是否成功 | 人工代码审查 |
| RP-003 | SSRF | POST /fetch | WAF 拦截了测试请求 | 关闭 WAF 后测试（仅限测试环境） |

> 共 **3** 条待补证项目
```

All entries have types, routes, reasons, and actions. ✅

### ❌ BAD: Mixing Confirmed and Suspected

```markdown
| RP-001 | SQL注入 | GET /user?id= | 已确认 | N/A |
| RP-002 | RCE | POST /cmd | 已实战验证 | N/A |
```

These are confirmed vulnerabilities — they belong in chapters 01/02, not here. Violates CR-1. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit result files found | Output empty risk pool (Procedure E) |
| Entry missing `downgrade_reason` | Use `"原因未记录"` and add to table |
| Entry missing `suggested_action` | Use `"建议人工代码审查"` as default |
| Unknown `final_verdict` value (not in expected set) | If not `"confirmed"` or `"not_vulnerable"`, include in risk pool as precaution |
| Duplicate sink_id across files | Deduplicate by sink_id; keep the entry with more detail |
