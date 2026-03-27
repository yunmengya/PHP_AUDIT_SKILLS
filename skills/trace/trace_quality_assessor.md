> **Skill ID**: S-037h | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: Completed trace result
> **Output**: Quality verdict + confidence level + recommended follow-up action

# Trace Quality Assessor

## Purpose

After a trace is extracted and filtered, assess its quality to determine whether
the result is usable for Phase 4 auditing or whether a retry, approach switch,
or static-analysis fallback is needed. Also cross-validate dynamic traces
against static Context Packs to establish confidence levels.

## Procedure

### 1. Quality Assessment Rules

Evaluate the trace against the following conditions **in order** (first match
wins):

| # | Condition | Verdict | Follow-up Action |
|---|-----------|---------|------------------|
| 1 | Trace contains the target sink function call | **Valid Trace** | Output normally; proceed to Phase 4 |
| 2 | Trace contains only framework bootstrap (`autoload`, `Kernel::handle`, etc.) — no business code | **Route Missed** | Verify URL / method / parameters are correct; retry or mark `route_missed` |
| 3 | Trace line count > 10 000 | **Excessive Trace** | Auto-filter with `trace_filter.php`; keep ≤ 500 lines upstream/downstream of sink |
| 4 | Trace line count = 0 (file empty or missing) | **Tracing Failed** | Switch to fallback approach (Tick / Middleware / strace via S-036f); mark `trace_empty` |
| 5 | Trace contains `Fatal Error` or unhandled `Exception` **before** the sink | **Execution Interrupted** | Mark `error_before_sink`; switch to context_pack static analysis |
| 6 | Trace contains HTTP 302 redirect to a login page | **Auth Failed** | Notify Auth-Simulator to refresh credentials; retry |

### 2. Error-vs-Sink Position Analysis (for 500-status responses)

When the HTTP response is a 500 error, determine whether the sink was reached:

| Position | Field Value | Implication |
|----------|-------------|-------------|
| Error **after** sink | `error_vs_sink: "after_sink"` | Sink was executed — potentially exploitable |
| Error **before** sink | `error_vs_sink: "before_sink"` | Sink not reached — requires context_pack analysis |

Record `error_point`: the function name where the error occurred.

### 3. Trace and Context Pack Cross-Validation

When a corresponding Context Pack exists for the route, perform cross-checks:

#### Path Consistency

Compare the trace's actual `call_chain` with the call path inferred by static
analysis in the Context Pack:
- **Both match** → High confidence.
- **Divergent** → Use trace as source of truth; retain Context Pack path as an
  alternative branch.

#### Dynamic Binding Supplementation

Traces resolve the actual targets of `call_user_func` / `$obj->$method()`.
Back-fill these resolutions into the Context Pack's `dynamic_bindings` field.

#### Filter Function Confirmation

Static analysis may miss filter functions in conditional branches. The trace
confirms whether the actual execution path passed through sanitisation
functions:
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

### 4. Emit Quality Verdict

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

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Trace Filter (S-037c) | (in-memory) | Yes | Filtered call chain, line count |
| Request Executor (S-037b) | (in-memory) | Yes | HTTP status code |
| Dynamic Binding Resolver (S-037d) | (in-memory) | No | `dynamic_bindings` |
| Context Pack | `$WORK_DIR/context_packs/` | No | Static call path, key nodes |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Quality verdict | (in-memory) | Verdict + confidence + recommended action |
| Updated Context Pack | `$WORK_DIR/context_packs/` | Back-filled dynamic bindings and filter confirmations |
| Final trace record | `$WORK_DIR/traces/trace_NNN.json` | Complete trace conforming to `schemas/trace_record.schema.json` |

## Error Handling

| Error | Action |
|-------|--------|
| No Context Pack for this route | Skip cross-validation; assess trace quality alone |
| Multiple verdicts apply | Use the first matching rule (highest priority) |
| Confidence cannot be computed (no key nodes in Context Pack) | Default to `medium` |
