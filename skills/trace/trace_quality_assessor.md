## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037h |
| Phase | 3 |
| Responsibility | Assess trace quality and cross-validate against static Context Packs |

# Trace Quality Assessor

## Purpose

After a trace is extracted and filtered, assess its quality to determine whether
the result is usable for Phase 4 auditing or whether a retry, approach switch,
or static-analysis fallback is needed. Also cross-validate dynamic traces
against static Context Packs to establish confidence levels.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Filtered trace | Trace Filter S-037c (in-memory) | Yes | Filtered call chain, line count |
| HTTP response | Request Executor S-037b (in-memory) | Yes | HTTP status code |
| Dynamic bindings | Dynamic Binding Resolver S-037d (in-memory) | No | `dynamic_bindings` |
| Context Pack | `$WORK_DIR/context_packs/` | No | Static call path, key nodes |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST assess trace completeness against route count — quality score without coverage ratio is meaningless | FAIL — high quality score on incomplete trace data |

## Fill-in Procedure

### Step 1 — Quality Assessment Rules

| Field | Fill-in Value |
|-------|---------------|
| `trace_contains_sink` | {true / false — does trace contain target sink function call?} |
| `has_business_code` | {true / false — contains more than just framework bootstrap?} |
| `trace_line_count` | {number of lines in filtered trace} |
| `trace_is_empty` | {true / false — 0 lines or file missing?} |
| `has_fatal_error` | {true / false — Fatal Error or unhandled Exception before sink?} |
| `has_auth_redirect` | {true / false — HTTP 302 redirect to login page?} |
| `verdict` | {valid / route_missed / excessive / trace_failed / error_before_sink / auth_failed} |
| `action` | {proceed_to_phase4 / retry / auto_filter / switch_fallback / static_analysis / refresh_credentials} |

Evaluate the trace against the following conditions **in order** (first match wins):

| # | Condition | Verdict | Follow-up Action |
|---|-----------|---------|------------------|
| 1 | Trace contains the target sink function call | **Valid Trace** | Output normally; proceed to Phase 4 |
| 2 | Trace contains only framework bootstrap (`autoload`, `Kernel::handle`, `bootstrap`, `middleware pipeline`) — no business code | **Route Missed** | Verify URL / method / parameters are correct; retry or mark `route_missed` |
| 3 | Trace line count > 10 000 | **Excessive Trace** | Auto-filter with `trace_filter.php`; keep ≤ 500 lines upstream/downstream of sink |
| 4 | Trace line count = 0 (file empty or missing) | **Tracing Failed** | Switch to fallback approach (Tick / Middleware / strace via S-036f); mark `trace_empty` |
| 5 | Trace contains `Fatal Error` or unhandled `Exception` **before** the sink | **Execution Interrupted** | Mark `error_before_sink`; switch to context_pack static analysis |
| 6 | Trace contains HTTP 302 redirect to a login page | **Auth Failed** | Notify Auth-Simulator to refresh credentials; retry |

### Step 2 — Error-vs-Sink Position Analysis (for 500-status responses)

| Field | Fill-in Value |
|-------|---------------|
| `http_status` | {response status code} |
| `is_500_error` | {true / false} |
| `error_vs_sink` | {after_sink / before_sink — position of error relative to sink} |
| `error_point` | {function name where error occurred} |

When the HTTP response is a 500 error, determine whether the sink was reached:

| Position | Field Value | Implication |
|----------|-------------|-------------|
| Error **after** sink | `error_vs_sink: "after_sink"` | Sink was executed — potentially exploitable |
| Error **before** sink | `error_vs_sink: "before_sink"` | Sink not reached — requires context_pack analysis |

Record `error_point`: the function name where the error occurred.

### Step 3 — Trace and Context Pack Cross-Validation

| Field | Fill-in Value |
|-------|---------------|
| `context_pack_exists` | {true / false} |
| `path_consistency` | {match / divergent} |
| `dynamic_bindings_backfilled` | {true / false — resolved bindings added to Context Pack?} |
| `filters_confirmed` | {list of sanitisation functions confirmed in execution path} |
| `coverage_pct` | {percentage of Context Pack key nodes covered by trace} |
| `confidence` | {high / medium / low — based on coverage_pct} |

#### Path Consistency

Compare the trace's actual `call_chain` with the call path inferred by static
analysis in the Context Pack:
- **Both match** → High confidence.
- **Divergent** → Use trace as source of truth; retain Context Pack path as an alternative branch.

#### Dynamic Binding Supplementation

Traces resolve the actual targets of `call_user_func` / `$obj->$method()`.
Back-fill these resolutions into the Context Pack's `dynamic_bindings` field.

#### Filter Function Confirmation

Static analysis may miss filter functions in conditional branches. The trace
confirms whether the actual execution path passed through sanitisation functions:
- `htmlspecialchars`, `htmlentities`, `strip_tags`
- `intval`, `floatval`, `abs`
- Prepared statements (`->prepare()`, `bindParam`)
- `addslashes`, `mysqli_real_escape_string`

#### Coverage Assessment

| Trace Coverage of Context Pack Key Nodes | Confidence | Action |
|------------------------------------------|------------|--------|
| ≥ 80 % | `high` | No additional tracing needed |
| 50 – 79 % | `medium` | Acceptable; note gaps |
| < 50 % | `low` | Recommend supplementary tracing |

### Step 4 — Emit Quality Verdict

| Field | Fill-in Value |
|-------|---------------|
| `route_id` | {route identifier} |
| `verdict` | {valid / route_missed / excessive / trace_failed / error_before_sink / auth_failed} |
| `confidence` | {high / medium / low} |
| `error_vs_sink` | {after_sink / before_sink / null} |
| `error_point` | {function name or null} |
| `filters_confirmed` | {list of confirmed sanitisation functions} |
| `coverage_pct` | {integer percentage} |
| `action` | {proceed_to_phase4 / retry / switch_fallback / static_analysis / refresh_credentials} |

Produce a quality assessment object:

```json
{
  "route_id": "route_005",
  "verdict": "valid",
  "confidence": "high",
  "error_vs_sink": null,
  "error_point": null,
  "filters_confirmed": ["intval"],
  "coverage_pct": 85,
  "action": "proceed_to_phase4"
}
```

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Quality verdict | (in-memory) | Verdict + confidence + recommended action |
| Updated Context Pack | `$WORK_DIR/context_packs/` | Back-filled dynamic bindings and filter confirmations |
| Final trace record | `$WORK_DIR/traces/trace_NNN.json` | Complete trace conforming to `schemas/trace_record.schema.json` |

## Examples

### ✅ GOOD — Complete quality assessment

```json
{
  "route_id": "route_005",
  "verdict": "valid",
  "confidence": "high",
  "error_vs_sink": null,
  "error_point": null,
  "filters_confirmed": ["intval"],
  "coverage_pct": 85,
  "action": "proceed_to_phase4"
}
```

All fields present, verdict justified by trace content, confidence based on coverage.

### ❌ BAD — Missing assessment context

```json
{
  "verdict": "valid"
}
```

Problems: No `route_id`, no `confidence`, no `coverage_pct`, no `filters_confirmed`, no `action`.

## Error Handling

| Error | Action |
|-------|--------|
| No Context Pack for this route | Skip cross-validation; assess trace quality alone |
| Multiple verdicts apply | Use the first matching rule (highest priority) |
| Confidence cannot be computed (no key nodes in Context Pack) | Default to `medium` |
