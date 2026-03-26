> **Skill ID**: S-081 | **Phase**: 2 (QC) | **Gate**: GATE_2
> **Input**: Phase 2 outputs
> **Output**: quality_report_phase2.json

# Phase-2 Quality Check — Static Reconnaissance

## Identity

Quality checker for Phase 2. Validates route mapping, authorization matrix, priority queue, scanner outputs, context packs, and dependency risk analysis before GATE_2 passage.

## Input Contract

| Source | Path | Required | Validation |
|--------|------|----------|------------|
| Route map | `$WORK_DIR/route_map.json` | YES | Non-empty, valid JSON, passes `schemas/route_map.schema.json` |
| Auth matrix | `$WORK_DIR/auth_matrix.json` | YES | Valid JSON, passes `schemas/auth_matrix.schema.json` |
| AST sinks | `$WORK_DIR/ast_sinks.json` | YES | Non-empty, each sink has file+line |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | Non-empty array, passes `schemas/priority_queue.schema.json` |
| Context packs | `$WORK_DIR/context_packs/` | YES | Directory exists, contains ≥1 JSON file |
| Dependency risk | `$WORK_DIR/dep_risk.json` | YES | Valid JSON, passes `schemas/dep_risk.schema.json` |
| Psalm results | `$WORK_DIR/psalm_taint.json` | NO | File existence check (status=failed allowed) |
| Progpilot results | `$WORK_DIR/progpilot.json` | NO | File existence check (status=failed allowed) |
| Semgrep results | `$WORK_DIR/semgrep.json` | NO | File existence check |
| PHPStan results | `$WORK_DIR/phpstan.json` | NO | File existence check |

## Check Procedure

### Check 1: Route Map Completeness
- [ ] `route_map.json` exists and `routes` array length > 0
- [ ] Each route has required fields: `id`, `url`, `method`, `controller`, `file`, `line`, `params`, `param_sources`, `middleware`, `auth_level`, `route_type`
- [ ] Route IDs follow pattern `^route_(\d+|synth_\d+)$`
- [ ] Spot-check 3 routes: `controller` file + `file:line` actually exists in source code

### Check 2: Auth Matrix Consistency
- [ ] `auth_matrix.json` exists and `matrix` array length > 0
- [ ] Coverage rate: `matrix entries / route_map routes × 100%` ≥ **80%**
- [ ] Each matrix entry's `route_id` exists in `route_map.json`
- [ ] `auth_level` values are valid: `anonymous`, `authenticated`, or `admin`
- [ ] No orphan entries — every matrix `route_id` resolves to an actual route

### Check 3: Priority Queue Validity
- [ ] `priority_queue.json` is non-empty array
- [ ] P0 count: `0 < P0 ≤ 20` — reasonable number, no duplicates
- [ ] Each entry has required fields: `id`, `priority`, `route_id`, `route_url`, `sink_function`, `sink_file`, `sink_line`, `auth_level`, `reason`, `source_count`, `sources`
- [ ] Sink IDs follow pattern `^sink_\d+$`
- [ ] `route_id` references in priority_queue all exist in `route_map.json`

### Check 4: Scanner Outputs
- [ ] At least 2 of the scanner output files exist: `psalm_taint.json`, `progpilot.json`, `semgrep.json`, `phpstan.json`
- [ ] Existing scanner files are valid JSON (even if they contain `status: "failed"`)
- [ ] `ast_sinks.json` exists with sink count > 0, each sink has `file` and `line`
- [ ] Spot-check 3 sinks from `ast_sinks.json`: confirm function call actually exists at source location

### Check 5: Context Packs Coverage
- [ ] `context_packs/` directory exists with ≥1 JSON file
- [ ] Each context pack has required fields: `sink_id`, `sink_function`, `priority`, `trace_depth`, `layers`, `data_flow_summary`, `filters_in_path`, `global_filters`
- [ ] Each layer's `code` field is non-empty (contains actual source code, not placeholders)
- [ ] Breakpoint rate: `packs with broken chains / total packs ≤ 50%`
- [ ] Coverage: context packs cover ≥ **80%** of priority_queue sinks

### Check 6: Dependency Risk & Coverage Rates
- [ ] `dep_risk.json` exists with dependency risk assessment
- [ ] External CVE sources were queried (CVE match count ≥ 0)
- [ ] Route coverage rate: `analyzed routes / total routes × 100%` ≥ **90%**
- [ ] Sink scan coverage rate: `identified sink types / sink_definitions.md types` ≥ **85%**

### Check 7: Schema Validation
- [ ] `route_map.json` passes `schemas/route_map.schema.json`
- [ ] `auth_matrix.json` passes `schemas/auth_matrix.schema.json`
- [ ] `priority_queue.json` passes `schemas/priority_queue.schema.json`
- [ ] Context pack files pass `schemas/context_pack.schema.json`
- [ ] No placeholder residue across all output files

## Verdict Rules

| Condition | Verdict |
|-----------|---------|
| All checks pass, coverage thresholds met | PASS |
| Non-critical failures: auth_matrix coverage 60–79%, scanner partial failures, dep_risk incomplete | CONDITIONAL_PASS (list coverage gaps, continue with degraded coverage annotation) |
| `route_map.json` missing or empty | FAIL — no routes to audit |
| `priority_queue.json` missing or empty | FAIL — no sinks prioritized for attack |
| `ast_sinks.json` missing or empty | FAIL — no sinks identified |

**MUST-PASS items:** route_map exists, ast_sinks exists, priority_queue reasonable (Checks 1, 3, 4-sinks)
**MAY-WARN items:** auth_matrix coverage, context_pack breakpoint rate, route coverage, scanner completeness

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase2.json` | Detailed check results with coverage metrics |

**Output JSON structure:**
```json
{
  "qc_id": "qc-phase2-team2-{timestamp}",
  "phase": "2",
  "target_agent": "team2",
  "timestamp": "ISO-8601",
  "verdict": "pass|conditional_pass|fail",
  "checks": {
    "route_map": { "status": "pass|fail", "route_count": 0, "spot_check_results": [] },
    "auth_matrix": { "status": "pass|fail|warn", "coverage_pct": 0, "orphan_count": 0 },
    "priority_queue": { "status": "pass|fail", "total": 0, "p0_count": 0, "duplicates": 0 },
    "scanners": { "status": "pass|fail|warn", "files_found": [], "ast_sink_count": 0 },
    "context_packs": { "status": "pass|fail|warn", "pack_count": 0, "breakpoint_rate_pct": 0, "coverage_pct": 0 },
    "dep_risk": { "status": "pass|fail|warn", "cve_matches": 0 },
    "schema_valid": { "status": "pass|fail", "errors": [] }
  },
  "metrics": {
    "coverage_route": "0%",
    "coverage_auth": "0%",
    "coverage_sink": "0%",
    "context_pack_breakpoint_rate": "0%"
  },
  "pass_count": 0,
  "total_count": 7,
  "failed_items": []
}
```

## Error Handling

| Error | Action |
|-------|--------|
| Missing `route_map.json` | FAIL — route_mapper did not produce output |
| Missing `priority_queue.json` | FAIL — risk_classifier did not produce output |
| Malformed JSON in any output | FAIL — data integrity issue; identify responsible agent for redo |
| Auth matrix coverage < 60% | FAIL — auth_auditor requires redo |
| All scanner outputs missing | FAIL — tool_runner pipeline broken |
| Context pack `code` fields empty | WARN — context_extractor may need re-run |

## Redo Responsibility Mapping

| Failed Item | Responsible Agent |
|-------------|-------------------|
| route_map related | route_mapper |
| auth_matrix related | auth_auditor |
| ast_sinks related | tool_runner (AST scan) |
| context_packs related | context_extractor |
| priority_queue related | risk_classifier |
| dep_risk related | dep_scanner |
