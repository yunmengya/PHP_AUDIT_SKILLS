> **Skill ID**: S-090e | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Input**: route_map.json, exploit_summary.json, checkpoint.json
> **Output**: `$WORK_DIR/报告/04_覆盖率统计.md`

# Coverage Statistics Writer

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-090e |
| Phase | Phase-5 (Report Generation) |
| Responsibility | Generate audit coverage statistics including route coverage, priority-level completion rates, and per-auditor execution status |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| route_map.json | `$WORK_DIR/route_map.json` | ✅ | `routes[]` (total count), `routes[].audited`, `routes[].priority` |
| exploit_summary.json | `$WORK_DIR/exploit_summary.json` | ✅ | `total_sinks`, `audited_sinks`, `per_auditor[]` |
| checkpoint.json | `$WORK_DIR/checkpoint.json` | ❌ | `completed[]`, `current`, `auditor_status[]` |
| priority_queue.json | `$WORK_DIR/priority_queue.json` | ❌ | `queue[].priority`, `queue[].status` (for priority breakdown) |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Coverage percentage MUST be calculated as `(audited / total) × 100` — no rounding tricks to inflate | Misleading coverage destroys report credibility |
| CR-2 | All four priority levels (P0/P1/P2/P3) MUST appear in the breakdown, even if count is 0 | Missing priority level suggests incomplete audit |
| CR-3 | Per-auditor status table MUST list every auditor that was spawned, including failed ones | Hiding failed auditors conceals coverage gaps |
| CR-4 | Skipped routes MUST be listed with skip reason | Unexplained skips raise quality questions |
| CR-5 | Percentages MUST use one decimal place (e.g., `85.7%`) | Inconsistent formatting looks unprofessional |

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

### Procedure A: Calculate Route Coverage

Read `route_map.json` and compute:

| Field | Fill-in Value |
|-------|---------------|
| total_routes | `len(routes[])` |
| audited_routes | Count of `routes[]` where `audited == true` |
| skipped_routes | `total_routes - audited_routes` |
| coverage_pct | `(audited_routes / total_routes) × 100`, formatted to 1 decimal |

### Procedure B: Calculate Priority Breakdown

Read `priority_queue.json` (or derive from `route_map.json → routes[].priority`):

| Field | Fill-in Value |
|-------|---------------|
| p0_total | Count of routes/sinks with `priority == "P0"` |
| p0_audited | Count of P0 items with `status == "completed"` or `audited == true` |
| p0_pct | `(p0_audited / p0_total) × 100` or `"N/A"` if p0_total == 0 |
| p1_total | Same for P1 |
| p1_audited | Same for P1 |
| p1_pct | Same for P1 |
| p2_total | Same for P2 |
| p2_audited | Same for P2 |
| p2_pct | Same for P2 |
| p3_total | Same for P3 |
| p3_audited | Same for P3 |
| p3_pct | Same for P3 |

### Procedure C: Collect Auditor Execution Status

Read `exploit_summary.json → per_auditor[]` or `checkpoint.json → auditor_status[]`:

| Field | Fill-in Value |
|-------|---------------|
| auditor_name | Auditor agent name (e.g., `rce_auditor`, `sqli_auditor`) |
| status | `"✅ 完成"` / `"⚠️ 部分完成"` / `"❌ 失败"` / `"⏭️ 跳过"` |
| sinks_audited | Number of sinks this auditor examined |
| vulns_found | Number of confirmed vulnerabilities from this auditor |

### Procedure D: Assemble Document

````markdown
# 审计覆盖率统计

## 路由覆盖率

| 统计项 | 数量 |
|--------|------|
| 路由总数 | {total_routes} |
| 已审计路由 | {audited_routes} |
| 跳过路由 | {skipped_routes} |
| **覆盖率** | **{coverage_pct}%** |

## 各优先级审计完成率

| 优先级 | 总数 | 已审计 | 完成率 |
|--------|------|--------|--------|
| 🔴 P0 (紧急) | {p0_total} | {p0_audited} | {p0_pct}% |
| 🟠 P1 (高) | {p1_total} | {p1_audited} | {p1_pct}% |
| 🟡 P2 (中) | {p2_total} | {p2_audited} | {p2_pct}% |
| 🔵 P3 (低) | {p3_total} | {p3_audited} | {p3_pct}% |

> P0/P1 应优先保证 100% 覆盖率

## 审计器执行状态

| 审计器 | 状态 | 审计 Sink 数 | 发现漏洞 |
|--------|------|-------------|----------|
| {auditor_name} | {status} | {sinks_audited} | {vulns_found} |
| ... | ... | ... | ... |

## 跳过路由清单

> 以下路由因特定原因未纳入本次审计

| 路由 | 跳过原因 |
|------|----------|
| {skipped_route} | {skip_reason} |
| ... | ... |

{If no skipped routes: "> ✅ 所有路由均已纳入审计范围"}
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

| Output File | Path | Description |
|-------------|------|-------------|
| 04_覆盖率统计.md | `$WORK_DIR/报告/04_覆盖率统计.md` | Audit coverage statistics with route, priority, and auditor breakdowns |

## Examples

### ✅ GOOD: Complete Coverage Report

```markdown
# 审计覆盖率统计

## 路由覆盖率

| 统计项 | 数量 |
|--------|------|
| 路由总数 | 47 |
| 已审计路由 | 42 |
| 跳过路由 | 5 |
| **覆盖率** | **89.4%** |

## 各优先级审计完成率

| 优先级 | 总数 | 已审计 | 完成率 |
|--------|------|--------|--------|
| 🔴 P0 (紧急) | 8 | 8 | 100.0% |
| 🟠 P1 (高) | 12 | 12 | 100.0% |
| 🟡 P2 (中) | 15 | 13 | 86.7% |
| 🔵 P3 (低) | 12 | 9 | 75.0% |

> P0/P1 应优先保证 100% 覆盖率

## 审计器执行状态

| 审计器 | 状态 | 审计 Sink 数 | 发现漏洞 |
|--------|------|-------------|----------|
| rce_auditor | ✅ 完成 | 3 | 1 |
| sqli_auditor | ✅ 完成 | 8 | 2 |
| xss_auditor | ✅ 完成 | 12 | 1 |
| file_upload_auditor | ✅ 完成 | 4 | 0 |
| ssrf_auditor | ⚠️ 部分完成 | 2 | 0 |

## 跳过路由清单

| 路由 | 跳过原因 |
|------|----------|
| GET /health | 健康检查端点，无用户输入 |
| GET /favicon.ico | 静态资源 |
| OPTIONS /* | CORS 预检请求 |
| GET /docs | 文档页面，无动态内容 |
| GET /metrics | 内部监控端点 |
```

All sections present, percentages to 1 decimal, all priorities listed, skipped routes explained. ✅

### ❌ BAD: Missing Priority Breakdown

```markdown
# 覆盖率

已审计 42/47 路由，覆盖率 89%。
```

Missing priority breakdown (CR-2), missing auditor table (CR-3), missing skipped routes (CR-4), percentage not to 1 decimal (CR-5). ❌

## Error Handling

| Error | Action |
|-------|--------|
| route_map.json missing | Use exploit_summary.json `total_sinks` / `audited_sinks` as fallback; note `"⚠️ 路由数据不可用，使用 Sink 级统计"` |
| priority_queue.json missing | Omit priority breakdown table; add note `"⚠️ 优先级数据不可用"` |
| Division by zero (total = 0) | Display `"N/A"` for percentage; note `"⚠️ 未发现可审计目标"` |
| Auditor status data missing | List known auditor types with `"❓ 状态未知"`; note data source unavailable |
| Skipped routes have no reason field | Use `"原因未记录"` as skip_reason |
