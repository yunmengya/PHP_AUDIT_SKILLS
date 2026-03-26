> **Skill ID**: S-082 | **Phase**: 3 (QC) | **Gate**: GATE_3
> **Input**: Phase 3 outputs
> **Output**: quality_report_phase3.json

# Phase-3 Quality Check — Dynamic Tracing

## Identity

Quality checker for Phase 3. Validates authentication simulation results and dynamic trace records before GATE_3 passage. Ensures traces have valid Source→Sink call chains, credentials are functional, and context_packs coverage meets the ≥ 80% threshold for priority routes.

## Input Contract

| Source | Path | Required | Validation |
|--------|------|----------|------------|
| Credentials | `$WORK_DIR/credentials.json` | YES | Valid JSON, passes `schemas/credentials.schema.json` |
| Trace records | `$WORK_DIR/traces/*.json` | YES | ≥1 file, each passes `schemas/trace_record.schema.json` |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | Used for coverage calculation (produced by Phase 2) |
| Context packs | `$WORK_DIR/context_packs/` | YES | Cross-validation reference (produced by Phase 2) |

## Check Procedure

### Check 1: Credential Validity
- [ ] `credentials.json` exists and is non-empty valid JSON
- [ ] Anonymous endpoints accessible without credentials (returns 200)
- [ ] Authenticated-level credential test: accessing a protected endpoint returns 200 (not 401/403)
- [ ] Admin-level credential test: accessing an admin endpoint returns 200 (not 401/403)
- [ ] Credential availability: at least **1 of 3** levels (anonymous/authenticated/admin) is valid

### Check 2: Trace Chain Structure
- [ ] `traces/` directory contains ≥1 JSON file
- [ ] Each trace record has required fields: `route_id`, `route_url`, `call_chain`, `filters_encountered`, `dynamic_bindings`, `raw_request`, `raw_response_status`
- [ ] Each `call_chain` is non-empty — no traces with zero-length chains
- [ ] Chain structure is valid: chain head = entry file/controller, chain tail = target sink function
- [ ] No unreasonable jumps — consecutive chain entries are in call-graph proximity (no impossible transitions)
- [ ] Spot-check 3 trace chains for logical consistency

### Check 3: Call Chain Completeness
- [ ] Call chain completeness rate: `complete chains (head-to-sink) / total chains × 100%` ≥ **70%**
- [ ] Broken chains have `error_point` annotated (explains where the chain broke)
- [ ] `error_vs_sink` properly annotated for broken chains: `before_sink` or `after_sink`
- [ ] Type B route handling: broken chains before sink are returned to context_pack for static analysis

### Check 4: Dynamic Bindings Resolution
- [ ] All `dynamic_bindings` entries have non-empty `resolved` field
- [ ] Binding types are valid: `call_user_func`, `variable_method`, or `dynamic_include`
- [ ] Resolved values reference actual functions/files in the codebase

### Check 5: Filter Function Annotations
- [ ] All `filters_encountered` entries have both `effective` (boolean) and `reason` (string) fields
- [ ] `reason` is descriptive (not empty or placeholder) — explains why filter is/isn't effective
- [ ] Filter assessments are reasonable: e.g. `htmlspecialchars` should be `effective: true` for XSS context

### Check 6: Cross-Validation with Context Packs
- [ ] Dynamic call chains compared with static call chains from `context_packs/`
- [ ] Differences between dynamic and static chains are recorded and explained
- [ ] Coverage of priority routes: `traced routes / priority_queue routes × 100%` ≥ **80%**
- [ ] P0/P1 sinks have ≥ 90% trace coverage

### Check 7: Schema Validation
- [ ] `credentials.json` passes `schemas/credentials.schema.json`
- [ ] Each `traces/*.json` file passes `schemas/trace_record.schema.json`
- [ ] No placeholder residue: `grep '【填写】\|TODO\|TBD\|PLACEHOLDER'` returns 0 hits
- [ ] All files UTF-8 encoded

## Verdict Rules

| Condition | Verdict |
|-----------|---------|
| All checks pass, chain completeness ≥ 70%, route coverage ≥ 80% | PASS |
| Credentials partially available (1–2 of 3 levels), coverage 60–79% | CONDITIONAL_PASS (annotate: uncovered auth levels tested as anonymous only) |
| All credential levels fail (0/3) | CONDITIONAL_PASS — degrade to static analysis mode; set `PHASE3_DEGRADED=true` flag |
| `credentials.json` missing entirely | FAIL — auth_simulator did not produce output |
| No trace files in `traces/` | FAIL — trace_dispatcher produced no output |
| Chain completeness < 50% | FAIL — trace quality too low for reliable exploitation |

**MUST-PASS items:** credentials.json exists, call chains non-empty (Checks 1-existence, 2-non-empty)
**MAY-WARN items:** credential validity per level, dynamic bindings, filter annotations, cross-validation

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase3.json` | Detailed check results with chain metrics |

**Output JSON structure:**
```json
{
  "qc_id": "qc-phase3-team3-{timestamp}",
  "phase": "3",
  "target_agent": "team3",
  "timestamp": "ISO-8601",
  "verdict": "pass|conditional_pass|fail",
  "checks": {
    "credentials": { "status": "pass|fail|warn", "valid_levels": 0, "total_levels": 3 },
    "trace_chains": { "status": "pass|fail", "trace_count": 0, "empty_chain_count": 0 },
    "chain_completeness": { "status": "pass|fail|warn", "completeness_pct": 0, "broken_count": 0 },
    "dynamic_bindings": { "status": "pass|warn", "unresolved_count": 0 },
    "filter_annotations": { "status": "pass|warn", "missing_count": 0 },
    "cross_validation": { "status": "pass|warn", "coverage_pct": 0, "difference_count": 0 },
    "schema_valid": { "status": "pass|fail", "errors": [] }
  },
  "metrics": {
    "credential_availability": "0/3",
    "chain_completeness_rate": "0%",
    "priority_route_coverage": "0%",
    "p0_p1_coverage": "0%"
  },
  "pass_count": 0,
  "total_count": 7,
  "failed_items": [],
  "degradation_flags": {
    "phase3_degraded": false,
    "degradation_reason": ""
  }
}
```

## Error Handling

| Error | Action |
|-------|--------|
| Missing `credentials.json` | FAIL — auth_simulator did not produce output |
| Missing `traces/` directory or empty | FAIL — trace_dispatcher did not execute |
| Malformed JSON in trace files | FAIL — data integrity issue; re-run trace workers |
| All credentials invalid (0/3 levels) | CONDITIONAL_PASS — set `PHASE3_DEGRADED=true`, downstream auditors tag findings `[NOT_VERIFIED]` |
| Chain completeness < 50% | FAIL — re-run trace_dispatcher with expanded timeout |
| Dynamic bindings all unresolved | WARN — may cause false negatives in Phase 4 |

## Redo Rules

| Attempt | Action |
|---------|--------|
| 1st failure | Re-run trace_dispatcher with failed items injected |
| 2nd failure | Mark degraded, fall back to static analysis mode (no dynamic traces) |
