> **Skill ID**: S-090g | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Input**: exploits/*.json, attack_memory.db query results
> **Output**: `$WORK_DIR/经验沉淀/lessons_learned.md`

# Lessons Learned Writer

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-090g |
| Phase | Phase-5 (Report Generation) |
| Responsibility | Generate lessons learned document capturing framework security patterns, successful bypass techniques, failed approaches, and security recommendations |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| exploits/*.json | `$WORK_DIR/exploits/*.json` | ✅ | `sink_type`, `final_verdict`, `iterations[]`, `bypass_technique`, `failure_reason`, `severity` |
| attack_graph.json | `$WORK_DIR/attack_graph.json` | ❌ | `chains[]` (for cross-vuln pattern analysis) |
| environment_status.json | `$WORK_DIR/environment_status.json` | ❌ | `framework`, `framework_version`, `php_version` |
| attack_memory.db | `$WORK_DIR/audit_session.db` | ❌ | Query: successful payloads, failed attempts, technique effectiveness |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | All four sections (框架安全特征, 典型绕过手法, 踩坑记录, 安全建议) MUST be present — even if a section has no entries, include it with explicit "无" | Missing sections make lessons incomplete |
| CR-2 | Bypass techniques MUST include actual payloads or technique names from this audit — no generic textbook content | Generic content has no reuse value |
| CR-3 | Failed approaches MUST explain WHY they failed — not just what was tried | Failure reasons prevent repeating mistakes |
| CR-4 | Recommendations MUST be derived from actual findings — not boilerplate security advice | Boilerplate advice is ignored |
| CR-5 | Label each technique with effectiveness: `[实测高效]` or `[实测低效]` | Missing labels reduce future decision quality |

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

### Procedure A: Framework Security Patterns

Read `environment_status.json` for framework info, then scan all exploit results for patterns:

| Field | Fill-in Value |
|-------|---------------|
| framework_name | `environment_status.json → framework` |
| framework_version | `environment_status.json → framework_version` |
| security_features | List of security mechanisms observed during audit — use enum values: `{csrf_token, orm_parameterization, middleware_auth, input_validation, output_encoding, rate_limiting, session_management, file_upload_restriction, waf, csp_header, cors_policy, other: [specify]}` |
| bypass_susceptible | Which features were bypassed — format: `{feature_name}: {bypass_method}` per item. Example: `"csrf_token: token not validated on POST /api/delete"` |
| effective_protections | Which features successfully blocked attacks — format: `{feature_name}: blocked {attack_type}` per item |

### Procedure B: Successful Bypass Techniques

Iterate exploit results where `final_verdict == "confirmed"`:

| Field | Fill-in Value |
|-------|---------------|
| technique_name | `exploit → bypass_technique` or derived from `iterations[].strategy` |
| target_sink_type | `sink_type` |
| payload_example | Actual payload used (from `iterations[]` where `success == true`) |
| effectiveness_label | `[实测高效]` — confirmed working in this audit |
| context | Mandatory format: `"{technique_name} works on {framework} {version} when {precondition}, bypasses {filter_type}, requires {prerequisites}."` Example: `"Wide-byte injection works on ThinkPHP 5.x when MySQL charset=GBK, bypasses addslashes(), requires non-UTF8 database connection."` |

### Procedure C: Failed Approaches (踩坑记录)

Iterate exploit results where `final_verdict == "not_vulnerable"` or iterate `iterations[]` where `success == false`:

| Field | Fill-in Value |
|-------|---------------|
| approach_name | `iteration.strategy` or technique description |
| target | `sink_type` + `route` |
| failure_reason | `iteration.failure_reason` or `exploit → failure_reason` — must use structured format from exploit_result schema pattern |
| lesson | Mandatory format: `"{approach_name} fails on {framework/context} because {root_cause}. Alternative: {recommended_alternative}."` Example: `"Double encoding fails on Laravel 10 because middleware decodes before routing. Alternative: try Unicode normalization bypass."` |
| effectiveness_label | `[实测低效]` |

### Procedure D: Security Recommendations

Derive from confirmed vulnerabilities and coverage gaps:

| Field | Fill-in Value |
|-------|---------------|
| recommendation | Specific improvement action |
| based_on | Which finding(s) this recommendation addresses |
| priority | `高` / `中` / `低` based on associated vulnerability severity |

### Procedure E: Assemble Document

````markdown
# 审计经验总结

> 项目: {project_name} | 框架: {framework} {framework_version} | 日期: {audit_date}

---

## 一、框架安全特征

### {framework_name} {framework_version} 安全机制观察

| 安全机制 | 状态 | 说明 |
|----------|------|------|
| {feature_name} | ✅ 有效 / ⚠️ 部分有效 / ❌ 缺失 | {description} |
| ... | ... | ... |

### 有效防护

{List protections that successfully blocked attacks}

### 存在缺陷的防护

{List protections that were bypassed or had gaps}

---

## 二、典型绕过手法

> 以下技术在本次审计中实测验证

### {technique_name} {effectiveness_label}

- **目标类型**: {target_sink_type}
- **有效载荷**: `{payload_example}`
- **适用场景**: {context}

{Repeat for each confirmed bypass...}

{If none: "> 本次审计未发现成功的绕过手法"}

---

## 三、踩坑记录

> 以下方法在本次审计中测试但未成功，记录原因以避免重复

| 尝试方法 | 目标 | 失败原因 | 经验教训 |
|----------|------|----------|----------|
| {approach_name} | {target} | {failure_reason} | {lesson} |
| ... | ... | ... | ... |

{If none: "> 本次审计所有测试方法均有效，无失败记录"}

---

## 四、安全建议

> 基于本次审计实际发现，提出以下改进建议

| 优先级 | 建议 | 依据 |
|--------|------|------|
| {priority} | {recommendation} | {based_on} |
| ... | ... | ... |

---

*经验总结生成时间: {timestamp}*
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
| lessons_learned.md | `$WORK_DIR/经验沉淀/lessons_learned.md` | Audit lessons learned with framework patterns, bypasses, failures, and recommendations | N/A (Markdown output) |

## Examples

### ✅ GOOD: Complete Lessons with Real Data

```markdown
# 审计经验总结

> 项目: MyShop 电商系统 | 框架: Laravel 9.52 | 日期: 2025-01-15

---

## 一、框架安全特征

### Laravel 9.52 安全机制观察

| 安全机制 | 状态 | 说明 |
|----------|------|------|
| Eloquent ORM 参数化查询 | ✅ 有效 | 大部分查询使用 ORM，有效防止 SQL 注入 |
| CSRF Token 中间件 | ✅ 有效 | 所有 POST 路由均启用 |
| Blade 模板自动转义 | ⚠️ 部分有效 | 存在 {!! !!} 绕过点 |
| 文件上传校验 | ❌ 缺失 | 仅校验扩展名，未校验 MIME 类型 |

---

## 二、典型绕过手法

### Blade Raw Output 注入 [实测高效]

- **目标类型**: XSS
- **有效载荷**: `<img src=x onerror=alert(1)>`
- **适用场景**: 开发者使用 `{!! $var !!}` 输出用户内容时

---

## 三、踩坑记录

| 尝试方法 | 目标 | 失败原因 | 经验教训 |
|----------|------|----------|----------|
| 联合查询注入 | SQL注入 GET /user?id= | Eloquent 自动参数化 | Laravel ORM 查询无法通过常规注入绕过 |
| PHP 反序列化 | POST /import | 入口使用 json_decode 而非 unserialize | 确认反序列化入口函数后再测试 |

---

## 四、安全建议

| 优先级 | 建议 | 依据 |
|--------|------|------|
| 高 | 禁止在 Blade 模板中使用 `{!! !!}` 输出用户可控内容 | M-XSS-001 |
| 高 | 文件上传增加 MIME 类型校验和文件内容检查 | H-UPLOAD-001 |
| 中 | 为所有 API 端点添加速率限制 | 审计过程中未触发任何限制 |
```

All four sections present, real payloads, failure reasons explained, recommendations tied to findings. ✅

### ❌ BAD: Generic Boilerplate

```markdown
## 安全建议

1. 使用参数化查询
2. 对输入进行验证
3. 使用 HTTPS
4. 定期更新依赖
```

Generic textbook advice not tied to actual findings — violates CR-4. No bypass techniques, no failure records — violates CR-1. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit result files found | Generate skeleton with all four sections; note `"⚠️ 无审计数据可供总结"` |
| environment_status.json missing | Use `"未知框架"` for framework info |
| attack_memory.db unavailable | Skip DB queries; derive all data from exploit result files |
| No confirmed vulnerabilities (no bypass techniques) | Section 二 states `"本次审计未发现成功的绕过手法"` |
| No failed approaches | Section 三 states `"本次审计所有测试方法均有效，无失败记录"` |
| 经验沉淀/ directory doesn't exist | Create directory before writing |
