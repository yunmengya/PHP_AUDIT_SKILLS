# Phase-2 QC — Static Reconnaissance

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-081 |
| Category | QC |
| Responsibility | Validate route mapping, auth matrix, priority queue, scanners, context packs, and dependency risk before GATE_2 passage |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `route_map.json` | route_mapper | YES | `routes[]` with `id`, `url`, `method`, `controller`, `file`, `line`, `params`, `param_sources`, `middleware`, `auth_level`, `route_type` |
| `auth_matrix.json` | auth_auditor | YES | `matrix[]` with `route_id`, `auth_level` |
| `ast_sinks.json` | tool_runner | YES | Sink entries with `file`, `line` |
| `priority_queue.json` | risk_classifier | YES | Entries with `id`, `priority`, `route_id`, `route_url`, `sink_function`, `sink_file`, `sink_line`, `auth_level`, `reason`, `source_count`, `sources` |
| `context_packs/` | context_extractor | YES | JSON files with `sink_id`, `sink_function`, `priority`, `trace_depth`, `layers`, `data_flow_summary`, `filters_in_path`, `global_filters` |
| `dep_risk.json` | dep_scanner | YES | Dependency risk assessment, CVE matches |
| `psalm_taint.json` | tool_runner | NO | Scanner output (existence check) |
| `progpilot.json` | tool_runner | NO | Scanner output (existence check) |
| `semgrep.json` | tool_runner | NO | Scanner output (existence check) |
| `phpstan.json` | tool_runner | NO | Scanner output (existence check) |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | All 7 checks pass and all coverage thresholds met | Verdict = PASS |
| CR-2 | `route_map.json` missing or empty | Verdict = FAIL — no routes to audit |
| CR-3 | `priority_queue.json` missing or empty | Verdict = FAIL — no sinks prioritized for attack |
| CR-4 | `ast_sinks.json` missing or empty | Verdict = FAIL — no sinks identified |
| CR-5 | Non-critical failures (auth_matrix coverage 60–79%, scanner partial failures, dep_risk incomplete) | Verdict = CONDITIONAL_PASS — list coverage gaps, annotate degraded coverage |
| CR-6 | MUST-PASS items: route_map exists, ast_sinks exists, priority_queue reasonable | Failure of any → immediate FAIL |
| CR-7 | MAY-WARN items: auth_matrix coverage, context_pack breakpoint rate, route coverage, scanner completeness | Failure only degrades — does not block gate |
| CR-8 | Auth matrix coverage < 60% | FAIL — auth_auditor requires redo |
| CR-9 | Auth matrix coverage threshold ≥ 80%, route coverage ≥ 90%, sink scan coverage ≥ 85% | Required for full PASS |

## Fill-in Procedure

### Procedure A: Route Map Completeness
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 1.1 | `route_map.json` exists and `routes` array length > 0 | `{pass/fail}` | `{route count}` |
| 1.2 | Each route has required fields: `id`, `url`, `method`, `controller`, `file`, `line`, `params`, `param_sources`, `middleware`, `auth_level`, `route_type` | `{pass/fail}` | `{missing fields list}` |
| 1.3 | Route IDs follow pattern `^route_(\d+\|synth_\d+)$` | `{pass/fail}` | `{invalid IDs}` |
| 1.4 | Spot-check 3 routes: `controller` file + `file:line` exists in source code | `{pass/fail}` | `{spot-check results}` |

### Procedure B: Auth Matrix Consistency
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 2.1 | `auth_matrix.json` exists and `matrix` array length > 0 | `{pass/fail}` | `{matrix entry count}` |
| 2.2 | Coverage rate: `matrix entries / route_map routes × 100%` ≥ 80% | `{pass/fail/warn}` | `{actual percentage}` |
| 2.3 | Each matrix entry `route_id` exists in `route_map.json` | `{pass/fail}` | `{orphan count}` |
| 2.4 | `auth_level` values are valid: `anonymous`, `authenticated`, or `admin` | `{pass/fail}` | `{invalid values}` |
| 2.5 | No orphan entries — every matrix `route_id` resolves to an actual route | `{pass/fail}` | `{orphan list}` |

### Procedure C: Priority Queue Validity
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 3.1 | `priority_queue.json` is non-empty array | `{pass/fail}` | `{entry count}` |
| 3.2 | P0 count: `0 < P0 ≤ 20` — reasonable number, no duplicates | `{pass/fail}` | `{P0 count, duplicate count}` |
| 3.3 | Each entry has required fields: `id`, `priority`, `route_id`, `route_url`, `sink_function`, `sink_file`, `sink_line`, `auth_level`, `reason`, `source_count`, `sources` | `{pass/fail}` | `{missing fields}` |
| 3.4 | Sink IDs follow pattern `^sink_\d+$` | `{pass/fail}` | `{invalid IDs}` |
| 3.5 | `route_id` references all exist in `route_map.json` | `{pass/fail}` | `{unresolved refs}` |

### Procedure D: Scanner Outputs
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 4.1 | At least 2 of 4 scanner outputs exist: `psalm_taint.json`, `progpilot.json`, `semgrep.json`, `phpstan.json` | `{pass/fail/warn}` | `{files found list}` |
| 4.2 | Existing scanner files are valid JSON (even with `status: "failed"`) | `{pass/fail}` | `{invalid files}` |
| 4.3 | `ast_sinks.json` exists with sink count > 0, each sink has `file` and `line` | `{pass/fail}` | `{sink count}` |
| 4.4 | Spot-check 3 sinks: confirm function call exists at source location | `{pass/fail}` | `{spot-check results}` |

### Procedure E: Context Packs Coverage
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 5.1 | `context_packs/` directory exists with ≥1 JSON file | `{pass/fail}` | `{pack count}` |
| 5.2 | Each context pack has required fields: `sink_id`, `sink_function`, `priority`, `trace_depth`, `layers`, `data_flow_summary`, `filters_in_path`, `global_filters` | `{pass/fail}` | `{missing fields}` |
| 5.3 | Each layer `code` field is non-empty (actual source code, not placeholders) | `{pass/fail}` | `{empty code count}` |
| 5.4 | Breakpoint rate: `packs with broken chains / total packs` ≤ 50% | `{pass/fail/warn}` | `{breakpoint rate percentage}` |
| 5.5 | Coverage: context packs cover ≥ 80% of priority_queue sinks | `{pass/fail/warn}` | `{coverage percentage}` |

### Procedure F: Dependency Risk & Coverage Rates
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 6.1 | `dep_risk.json` exists with dependency risk assessment | `{pass/fail}` | `{file status}` |
| 6.2 | External CVE sources were queried (CVE match count ≥ 0) | `{pass/fail/warn}` | `{CVE match count}` |
| 6.3 | Route coverage rate: `analyzed routes / total routes × 100%` ≥ 90% | `{pass/fail/warn}` | `{actual percentage}` |
| 6.4 | Sink scan coverage rate: `identified sink types / sink_definitions.md types` ≥ 85% | `{pass/fail/warn}` | `{actual percentage}` |

### Procedure G: Schema Validation
| # | Check Item | Result | Details |
|---|-----------|--------|---------|
| 7.1 | `route_map.json` passes `schemas/route_map.schema.json` | `{pass/fail}` | `{validation errors}` |
| 7.2 | `auth_matrix.json` passes `schemas/auth_matrix.schema.json` | `{pass/fail}` | `{validation errors}` |
| 7.3 | `priority_queue.json` passes `schemas/priority_queue.schema.json` | `{pass/fail}` | `{validation errors}` |
| 7.4 | Context pack files pass `schemas/context_pack.schema.json` | `{pass/fail}` | `{validation errors}` |
| 7.5 | No placeholder residue across all output files | `{pass/fail}` | `{hit count}` |

### Procedure H: Verdict Determination

| Field | Fill-in Value |
|-------|--------------|
| MUST-PASS items all pass? (route_map, ast_sinks, priority_queue) | `{yes/no}` |
| Auth matrix coverage | `{percentage}` |
| Route coverage rate | `{percentage}` |
| Sink scan coverage rate | `{percentage}` |
| Context pack coverage | `{percentage}` |
| Context pack breakpoint rate | `{percentage}` |
| Final verdict | `{pass / conditional_pass / fail}` |
| Coverage gaps (if conditional_pass) | `{description}` |
| pass_count | `{N}` / 7 |
| failed_items | `{list}` |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase2.json` | `schemas/quality_report_phase2.schema.json` | Per-check results with coverage metrics |

## Examples

### ✅ GOOD: All checks pass with high coverage
```json
{
  "qc_id": "qc-phase2-team2-20250101T120000",
  "phase": "2",
  "target_agent": "team2",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "route_map": { "status": "pass", "route_count": 47, "spot_check_results": ["ok", "ok", "ok"] },
    "auth_matrix": { "status": "pass", "coverage_pct": 92, "orphan_count": 0 },
    "priority_queue": { "status": "pass", "total": 35, "p0_count": 8, "duplicates": 0 },
    "scanners": { "status": "pass", "files_found": ["psalm_taint.json", "semgrep.json", "phpstan.json"], "ast_sink_count": 112 },
    "context_packs": { "status": "pass", "pack_count": 30, "breakpoint_rate_pct": 20, "coverage_pct": 86 },
    "dep_risk": { "status": "pass", "cve_matches": 3 },
    "schema_valid": { "status": "pass", "errors": [] }
  },
  "metrics": {
    "coverage_route": "95%",
    "coverage_auth": "92%",
    "coverage_sink": "88%",
    "context_pack_breakpoint_rate": "20%"
  },
  "pass_count": 7,
  "total_count": 7,
  "failed_items": []
}
```
Explanation: All 7 checks pass — route map has 47 routes, auth coverage 92% (≥80%), P0 count 8 (within 1–20), 3 scanners present, context packs cover 86% of sinks, breakpoint rate 20% (≤50%), schemas valid. Verdict is PASS. ✅

### ❌ BAD: Empty priority queue still marked as pass
```json
{
  "qc_id": "qc-phase2-team2-20250101T120000",
  "phase": "2",
  "target_agent": "team2",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "route_map": { "status": "pass", "route_count": 47, "spot_check_results": [] },
    "auth_matrix": { "status": "pass", "coverage_pct": 85, "orphan_count": 0 },
    "priority_queue": { "status": "fail", "total": 0, "p0_count": 0, "duplicates": 0 },
    "scanners": { "status": "pass", "files_found": ["semgrep.json", "phpstan.json"], "ast_sink_count": 50 },
    "context_packs": { "status": "pass", "pack_count": 10, "breakpoint_rate_pct": 30, "coverage_pct": 80 },
    "dep_risk": { "status": "pass", "cve_matches": 1 },
    "schema_valid": { "status": "pass", "errors": [] }
  },
  "metrics": {
    "coverage_route": "90%",
    "coverage_auth": "85%",
    "coverage_sink": "85%",
    "context_pack_breakpoint_rate": "30%"
  },
  "pass_count": 6,
  "total_count": 7,
  "failed_items": ["priority_queue"]
}
```
What's wrong: `priority_queue` total is 0 (empty) but verdict is "pass". Violates CR-3 — empty priority_queue must produce verdict = "fail" because no sinks are prioritized for attack. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Missing `route_map.json` | FAIL — route_mapper did not produce output |
| Missing `priority_queue.json` | FAIL — risk_classifier did not produce output |
| Missing `ast_sinks.json` | FAIL — tool_runner (AST scan) did not produce output |
| Malformed JSON in any output | FAIL — data integrity issue; identify responsible agent for redo |
| Auth matrix coverage < 60% | FAIL — auth_auditor requires redo |
| All scanner outputs missing | FAIL — tool_runner pipeline broken |
| Context pack `code` fields empty | WARN — context_extractor may need re-run |
| route_map redo needed | Responsible agent: route_mapper |
| auth_matrix redo needed | Responsible agent: auth_auditor |
| ast_sinks redo needed | Responsible agent: tool_runner (AST scan) |
| context_packs redo needed | Responsible agent: context_extractor |
| priority_queue redo needed | Responsible agent: risk_classifier |
| dep_risk redo needed | Responsible agent: dep_scanner |
