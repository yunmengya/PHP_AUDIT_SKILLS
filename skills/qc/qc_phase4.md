> **Skill ID**: S-083 | **Phase**: 4 (QC) | **Gate**: GATE_4
> **Input**: Phase 4 outputs
> **Output**: quality_report_phase4.json

# Phase-4 Quality Check — Exploit Verification

## Identity

Quality checker for Phase 4. Validates exploit results from all specialist auditors before GATE_4 passage. Ensures each `exploit_results/*.json` has a valid `final_verdict`, evidence is substantiated, severity scoring is consistent, PoC evidence exists, and prerequisite conditions are properly declared.

## Input Contract

| Source | Path | Required | Validation |
|--------|------|----------|------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | ≥1 file, each passes `schemas/exploit_result.schema.json` |
| Team progress | `$WORK_DIR/team4_progress.json` | YES | Valid JSON, passes `schemas/team4_progress.schema.json` |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | Cross-reference for sink coverage |
| Evidence contract | `$SKILL_DIR/shared/evidence_contract.md` | REF | EVID_* dictionary for evidence validation |
| Auth matrix | `$WORK_DIR/auth_matrix.json` | YES | Cross-reference for auth consistency |
| Context packs | `$WORK_DIR/context_packs/` | YES | Cross-reference for filter bypass validation |

## Check Procedure

### Check 1: Exploit File Integrity
- [ ] `exploits/` directory exists with ≥1 JSON file
- [ ] Each exploit file is valid JSON and passes `schemas/exploit_result.schema.json`
- [ ] Required fields present in each: `sink_id`, `route_url`, `sink_function`, `specialist`, `route_type`, `rounds_executed`, `rounds_skipped`, `results`, `final_verdict`, `confidence`, `severity`, `prerequisite_conditions`
- [ ] `sink_id` follows pattern `^sink_\d+$`

### Check 2: Final Verdict Validity
- [ ] `final_verdict` is one of: `confirmed`, `suspected`, `potential`, `not_vulnerable`
- [ ] `confirmed` verdicts have physical evidence: HTTP request/response with actual payload + observable outcome
- [ ] `confirmed` verdicts have `confidence: "high"` — no `confirmed` with low confidence
- [ ] `suspected` verdicts have at least code-level evidence or partial response anomaly
- [ ] All-8-rounds-failed sinks annotated as `potential` with failure reason documented

### Check 3: Evidence Completeness (EVID Chain)
- [ ] Each `confirmed` finding references all required EVID_* points per `shared/evidence_contract.md`
- [ ] EVID references contain actual data — not empty strings or placeholders
- [ ] Missing EVID points are annotated `EVID_XXX: [Not obtained: reason]` and verdict is auto-downgraded
- [ ] HTTP requests in Burp format: `METHOD URL HTTP/1.1` + Headers + Body — directly replayable
- [ ] HTTP responses include status code + key response body (evidence portion, not truncated)

### Check 4: Severity Scoring Consistency
- [ ] `severity` object contains all 10 required fields: `reachability`, `reachability_reason`, `impact`, `impact_reason`, `complexity`, `complexity_reason`, `score`, `cvss`, `level`, `vuln_id`
- [ ] R/I/C values are integers 0–3 with non-empty reason strings
- [ ] Weighted score formula correct: `score = R×0.40 + I×0.35 + C×0.25`
- [ ] CVSS estimate: `cvss = (score / 3.0) × 10.0`
- [ ] Level mapping correct: C=2.70–3.00, H=2.10–2.69, M=1.20–2.09, L=0.10–1.19
- [ ] `vuln_id` follows pattern `^[CHML]-[A-Z_]+-\d{3}$`
- [ ] Score ↔ evidence consistency: score ≥ 2.10 → evidence_score ≥ 7; 1.20–2.09 → 4–6; < 1.20 → 1–3

### Check 5: Prerequisite Conditions
- [ ] Each exploit has `prerequisite_conditions` with 4 sub-items: `auth_requirement`, `bypass_method`, `other_preconditions`, `exploitability_judgment`
- [ ] `auth_requirement` is one of: `anonymous`, `authenticated`, `admin`, `internal_network`
- [ ] `auth_requirement` matches the route's `auth_level` in `auth_matrix.json`
- [ ] `exploitability_judgment = "not_exploitable"` → `final_verdict` capped at `potential`, `confidence` capped at `low`
- [ ] `exploitability_judgment = "conditionally_exploitable"` → `severity.complexity` drops 1 level

### Check 6: Sink Coverage & Auditor Matrix
- [ ] Sink coverage: `audited sinks / priority_queue total sinks` ≥ **90%**
- [ ] `team4_progress.json` contains `total_findings` + per-level counts + findings array
- [ ] All 21 auditor types have a status (`executed`, `not_applicable`, `deferred`, `failed`)
- [ ] P0 sinks have **100%** coverage — every P0 sink has an exploit result
- [ ] `not_applicable` auditors have documented reason

### Check 7: Filter Bypass & False Positive Check
- [ ] For sinks with `effective=true` filters in context_pack, exploit records bypass method or `not_bypassable` annotation
- [ ] All `confirmed`/`suspected` findings compared against `shared/false_positive_patterns.md`
- [ ] Bypass strategies are reasonable — e.g. `htmlspecialchars` bypass not claimed via SQL comment technique
- [ ] Cross-validated with variant payloads for confirmed findings

## Verdict Rules

| Condition | Verdict |
|-----------|---------|
| All checks pass, P0 coverage 100%, sink coverage ≥ 90% | PASS |
| Minor issues: evidence_score inconsistencies ≤ 2, coverage 80–89% | CONDITIONAL_PASS (list exceptions, annotate gaps) |
| Any `confirmed` verdict without physical evidence | FAIL — evidence fabrication risk |
| Severity scoring contradictions > 2 | FAIL — scoring integrity compromised |
| P0 coverage < 100% without skip justification | FAIL — critical sinks unaudited |
| `team4_progress.json` missing | FAIL — team4 dispatcher did not produce summary |

**MUST-PASS items:** Exploit JSON exists, required fields complete, evidence matches type, severity scoring complete, prerequisites declared, exploitability compliant, EVID chain (Checks 1–5)
**MAY-WARN items:** HTTP format, evidence_score consistency, filter bypass records, auditor coverage

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase4.json` | Detailed per-auditor check results |

**Output JSON structure:**
```json
{
  "qc_id": "qc-phase4-team4-{timestamp}",
  "phase": "4",
  "target_agent": "team4",
  "timestamp": "ISO-8601",
  "verdict": "pass|conditional_pass|fail",
  "checks": {
    "exploit_integrity": { "status": "pass|fail", "file_count": 0, "schema_errors": [] },
    "verdict_validity": { "status": "pass|fail", "confirmed_without_evidence": 0 },
    "evidence_chain": { "status": "pass|fail", "missing_evid_count": 0, "empty_evid_count": 0 },
    "severity_scoring": { "status": "pass|fail", "contradictions": 0, "formula_errors": 0 },
    "prerequisites": { "status": "pass|fail", "missing_fields": 0, "auth_mismatches": 0 },
    "sink_coverage": { "status": "pass|fail|warn", "coverage_pct": 0, "p0_coverage_pct": 0 },
    "filter_bypass": { "status": "pass|warn", "unhandled_filters": 0, "false_positive_matches": 0 }
  },
  "metrics": {
    "sink_coverage": "0%",
    "p0_coverage": "0%",
    "confirmed_count": 0,
    "suspected_count": 0,
    "potential_count": 0,
    "not_vulnerable_count": 0
  },
  "pass_count": 0,
  "total_count": 7,
  "failed_items": []
}
```

## Error Handling

| Error | Action |
|-------|--------|
| Missing `exploits/` directory | FAIL — no exploit results produced |
| Malformed JSON in exploit files | FAIL — data integrity issue; identify responsible auditor |
| `confirmed` without HTTP evidence | FAIL — auditor must provide physical proof or downgrade to `suspected` |
| Severity formula miscalculation | FAIL — recalculate and resubmit |
| `team4_progress.json` missing | FAIL — team4 dispatcher must generate summary |
| auth_requirement ↔ auth_matrix mismatch | FAIL — auditor must align prerequisites with auth_matrix |

## Redo Rules

| Attempt | Action |
|---------|--------|
| 1st failure (individual auditor) | Return failed items to specific auditor for correction (max 2 per auditor) |
| 2nd failure (individual auditor) | Mark insufficient evidence, degrade confidence level |
| Comprehensive QC failure | Locate specific auditors to supplement based on failed items |
