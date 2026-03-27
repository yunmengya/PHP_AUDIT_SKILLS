# Phase-3 QC — Dynamic Tracing

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-082 |
| Category | QC |
| Responsibility | Validate authentication simulation and dynamic trace records before GATE_3 passage |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `credentials.json` | auth_simulator | YES | Credential entries per auth level (anonymous, authenticated, admin) |
| `traces/*.json` | trace_dispatcher | YES | `route_id`, `route_url`, `call_chain`, `filters_encountered`, `dynamic_bindings`, `raw_request`, `raw_response_status` |
| `priority_queue.json` | risk_classifier (Phase 2) | YES | Used for coverage calculation |
| `context_packs/` | context_extractor (Phase 2) | YES | Cross-validation reference for static vs dynamic chains |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | All 7 checks pass, chain completeness ≥ 70%, route coverage ≥ 80% | Verdict = PASS |
| CR-2 | `credentials.json` missing entirely | Verdict = FAIL — auth_simulator did not produce output |
| CR-3 | No trace files in `traces/` | Verdict = FAIL — trace_dispatcher produced no output |
| CR-4 | Chain completeness < 50% | Verdict = FAIL — trace quality too low for reliable exploitation |
| CR-5 | Credentials partially available (1–2 of 3 levels), coverage 60–79% | Verdict = CONDITIONAL_PASS — annotate: uncovered auth levels tested as anonymous only |
| CR-6 | All credential levels fail (0/3 valid) | Verdict = CONDITIONAL_PASS — degrade to static analysis mode; set `PHASE3_DEGRADED=true` flag |
| CR-7 | MUST-PASS items: credentials.json exists, call chains non-empty | Failure → immediate FAIL |
| CR-8 | MAY-WARN items: credential validity per level, dynamic bindings, filter annotations, cross-validation | Failure only degrades — does not block gate |
| CR-9b | P0/P1 sinks require ≥ 90% trace coverage | Shortfall triggers CONDITIONAL_PASS |

## Fill-in Procedure

### Procedure A: Credential Validity
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 1.1 | `credentials.json` exists and is non-empty valid JSON | file exists, valid JSON, non-empty | {fill-in: file existence and JSON validity} | {✅/❌} |
| 1.2 | Anonymous endpoints accessible without credentials (returns 200) | HTTP 200 on anonymous endpoints | {fill-in: HTTP status observed} | {✅/❌} |
| 1.3 | Authenticated-level credential test: protected endpoint returns 200 (not 401/403) | HTTP 200 (not 401/403) | {fill-in: HTTP status observed} | {✅/❌} |
| 1.4 | Admin-level credential test: admin endpoint returns 200 (not 401/403) | HTTP 200 (not 401/403) | {fill-in: HTTP status observed} | {✅/❌} |
| 1.5 | Credential availability: at least 1 of 3 levels (anonymous/authenticated/admin) is valid | ≥ 1/3 valid levels | {fill-in: valid levels count/3} | {✅/❌} |

### Procedure B: Trace Chain Structure
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 2.1 | `traces/` directory contains ≥1 JSON file | ≥ 1 JSON file in traces/ | {fill-in: file count found} | {✅/❌} |
| 2.2 | Each trace record has required fields: `route_id`, `route_url`, `call_chain`, `filters_encountered`, `dynamic_bindings`, `raw_request`, `raw_response_status` | all 7 required fields present per record | {fill-in: missing fields if any} | {✅/❌} |
| 2.3 | Each `call_chain` is non-empty — no traces with zero-length chains | 0 empty chains | {fill-in: empty chain count} | {✅/❌} |
| 2.4 | Chain structure valid: head = entry file/controller, tail = target sink function | head→sink structure in every chain | {fill-in: invalid chain count} | {✅/❌} |
| 2.5 | No unreasonable jumps — consecutive entries are in call-graph proximity | 0 suspicious jumps | {fill-in: suspicious jump count} | {✅/❌} |
| 2.6 | Spot-check 3 trace chains for logical consistency | 3/3 spot-checks logically consistent | {fill-in: format "trace_id(pass/fail), trace_id(pass/fail), trace_id(pass/fail)"} | {✅/❌} |

### Procedure C: Call Chain Completeness
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 3.1 | Call chain completeness rate: `complete chains (head-to-sink) / total chains × 100%` ≥ 70% | ≥ 70% | {fill-in: actual percentage} | {✅/❌} |
| 3.2 | Broken chains have `error_point` annotated | all broken chains annotated | {fill-in: unannotated count} | {✅/❌} |
| 3.3 | `error_vs_sink` properly annotated for broken chains: `before_sink` or `after_sink` | annotation present on all broken chains | {fill-in: missing annotation count} | {✅/❌} |
| 3.4 | Type B routes: broken chains before sink are returned to context_pack for static analysis | Type B broken chains returned to context_pack | {fill-in: Type B handling status} | {✅/❌} |

### Procedure D: Dynamic Bindings Resolution
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 4.1 | All `dynamic_bindings` entries have non-empty `resolved` field | 0 unresolved bindings | {fill-in: unresolved count} | {✅/❌} |
| 4.2 | Binding types are valid: `call_user_func`, `variable_method`, or `dynamic_include` | only valid binding types | {fill-in: invalid type count} | {✅/❌} |
| 4.3 | Resolved values reference actual functions/files in the codebase | all resolved values verified | {fill-in: unverified count} | {✅/❌} |

### Procedure E: Filter Function Annotations
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 5.1 | All `filters_encountered` entries have both `effective` (boolean) and `reason` (string) fields | both fields present on every entry | {fill-in: incomplete entry count} | {✅/❌} |
| 5.2 | `reason` is descriptive (not empty or placeholder) | 0 empty/placeholder reasons | {fill-in: empty reason count} | {✅/❌} |
| 5.3 | Filter assessments are reasonable (e.g. `htmlspecialchars` → `effective: true` for XSS) | assessments consistent with filter behavior | {fill-in: questionable assessment count} | {✅/❌} |

### Procedure F: Cross-Validation with Context Packs
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 6.1 | Dynamic call chains compared with static call chains from `context_packs/` | comparison completed | {fill-in: comparison status} | {✅/❌} |
| 6.2 | Differences between dynamic and static chains recorded and explained | all differences explained | {fill-in: unexplained difference count} | {✅/❌} |
| 6.3 | Coverage of priority routes: `traced routes / priority_queue routes × 100%` ≥ 80% | ≥ 80% | {fill-in: actual percentage} | {✅/❌} |
| 6.4 | P0/P1 sinks have ≥ 90% trace coverage | ≥ 90% | {fill-in: actual percentage} | {✅/❌} |

### Procedure G: Schema Validation
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 7.1 | `credentials.json` passes `schemas/credentials.schema.json` | passes schema validation | {fill-in: validation errors if any} | {✅/❌} |
| 7.2 | Each `traces/*.json` file passes `schemas/trace_record.schema.json` | all files pass schema validation | {fill-in: validation errors if any} | {✅/❌} |
| 7.3 | No placeholder residue: `grep 'TODO\|TBD\|PLACEHOLDER'` returns 0 hits | 0 hits | {fill-in: hit count} | {✅/❌} |
| 7.4 | All files UTF-8 encoded | all files UTF-8 | {fill-in: non-UTF8 file count} | {✅/❌} |

### Procedure H: Verdict Determination

| Field | Fill-in Value |
|-------|--------------|
| MUST-PASS items all pass? (credentials.json exists, call chains non-empty) | `{yes/no}` |
| Valid credential levels | `{N}/3` |
| Chain completeness rate | `{percentage}` |
| Priority route coverage | `{percentage}` |
| P0/P1 trace coverage | `{percentage}` |
| PHASE3_DEGRADED flag | `{true/false}` |
| Degradation reason (if degraded) | `{description}` |
| Final verdict | `{pass / conditional_pass / fail}` |
| pass_count | `{N}` / 7 |
| failed_items | `{list}` |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase3.json` | `schemas/quality_report_phase3.schema.json` | Per-check results with chain metrics and degradation flags |

## Examples

### ✅ GOOD: All checks pass with healthy trace coverage
```json
{
  "qc_id": "qc-phase3-team3-20250101T120000",
  "phase": "3",
  "target_agent": "team3",
  "timestamp": "2025-01-01T12:00:00Z",
  "basic_info": {
    "quality_checker": "S-082",
    "target": "Phase-3 output",
    "validated_files": ["{fill-in: actual file paths read}"]
  },
  "verdict": "pass",
  "checks": {
    "credentials": { "status": "pass", "valid_levels": 3, "total_levels": 3 },
    "trace_chains": { "status": "pass", "trace_count": 28, "empty_chain_count": 0 },
    "chain_completeness": { "status": "pass", "completeness_pct": 82, "broken_count": 5 },
    "dynamic_bindings": { "status": "pass", "unresolved_count": 0 },
    "filter_annotations": { "status": "pass", "missing_count": 0 },
    "cross_validation": { "status": "pass", "coverage_pct": 88, "difference_count": 3 },
    "schema_valid": { "status": "pass", "errors": [] }
  },
  "item_results": [
    {"id": "1.1", "check_item": "credentials.json exists and is non-empty valid JSON", "expected": "file exists, valid JSON, non-empty", "actual": "{fill-in}", "status": "✅"},
    {"id": "2.1", "check_item": "traces/ directory contains ≥1 JSON file", "expected": "≥ 1 JSON file", "actual": "{fill-in}", "status": "✅"},
    {"id": "3.1", "check_item": "Chain completeness ≥ 70%", "expected": "≥ 70%", "actual": "{fill-in}", "status": "✅"},
    {"id": "6.3", "check_item": "Priority route coverage ≥ 80%", "expected": "≥ 80%", "actual": "{fill-in}", "status": "✅"},
    {"id": "6.4", "check_item": "P0/P1 trace coverage ≥ 90%", "expected": "≥ 90%", "actual": "{fill-in}", "status": "✅"},
    {"id": "7.1", "check_item": "credentials.json passes schema", "expected": "passes credentials.schema.json", "actual": "{fill-in}", "status": "✅"},
    {"id": "7.3", "check_item": "No placeholder residue", "expected": "0 hits", "actual": "{fill-in}", "status": "✅"}
  ],
  "metrics": {
    "credential_availability": "3/3",
    "chain_completeness_rate": "82%",
    "priority_route_coverage": "88%",
    "p0_p1_coverage": "93%"
  },
  "final_verdict": {
    "status": "PASS",
    "passed": "7/7",
    "failed_items": []
  },
  "pass_count": 7,
  "total_count": 7,
  "failed_items": [],
  "degradation_flags": {
    "phase3_degraded": false,
    "degradation_reason": ""
  }
}
```
Explanation: All 7 checks pass — 3/3 credential levels valid, 28 traces with no empty chains, chain completeness 82% (≥70%), priority route coverage 88% (≥80%), P0/P1 coverage 93% (≥90%), schemas valid, no degradation needed. Verdict is PASS. ✅

### ❌ BAD: Zero credentials marked as pass instead of degraded
```json
{
  "qc_id": "qc-phase3-team3-20250101T120000",
  "phase": "3",
  "target_agent": "team3",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "credentials": { "status": "pass", "valid_levels": 0, "total_levels": 3 },
    "trace_chains": { "status": "pass", "trace_count": 15, "empty_chain_count": 0 },
    "chain_completeness": { "status": "pass", "completeness_pct": 75, "broken_count": 4 },
    "dynamic_bindings": { "status": "pass", "unresolved_count": 0 },
    "filter_annotations": { "status": "pass", "missing_count": 0 },
    "cross_validation": { "status": "pass", "coverage_pct": 80, "difference_count": 2 },
    "schema_valid": { "status": "pass", "errors": [] }
  },
  "metrics": {
    "credential_availability": "0/3",
    "chain_completeness_rate": "75%",
    "priority_route_coverage": "80%",
    "p0_p1_coverage": "90%"
  },
  "pass_count": 7,
  "total_count": 7,
  "failed_items": [],
  "degradation_flags": {
    "phase3_degraded": false,
    "degradation_reason": ""
  }
}
```
What's wrong: `valid_levels` is 0/3 (all credential levels failed) but verdict is "pass" and `phase3_degraded` is false. Violates CR-6 — when 0/3 credentials are valid, must set verdict = "conditional_pass" and `PHASE3_DEGRADED=true` to degrade to static analysis mode. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Missing `credentials.json` | FAIL — auth_simulator did not produce output |
| Missing `traces/` directory or empty | FAIL — trace_dispatcher did not execute |
| Malformed JSON in trace files | FAIL — data integrity issue; re-run trace workers |
| All credentials invalid (0/3 levels) | CONDITIONAL_PASS — set `PHASE3_DEGRADED=true`, downstream auditors tag findings `[NOT_VERIFIED]` |
| Chain completeness < 50% | FAIL — re-run trace_dispatcher with expanded timeout |
| Dynamic bindings all unresolved | WARN — may cause false negatives in Phase 4 |
| 1st redo attempt | Re-run trace_dispatcher with failed items injected |
| 2nd redo attempt | Mark degraded, fall back to static analysis mode (no dynamic traces) |
