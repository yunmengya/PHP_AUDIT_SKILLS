# Phase-4 Quality Check — Exploit Verification

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-083 |
| Category | QC |
| Responsibility | Validate exploit results from all specialist auditors before GATE_4 passage |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `exploits/*.json` | Phase-4 auditors | YES | ≥1 file; each passes `schemas/exploit_result.schema.json` |
| `team4_progress.json` | Team-4 dispatcher | YES | `total_findings`, per-level counts, findings array; passes `schemas/team4_progress.schema.json` |
| `priority_queue.json` | Phase-3 | YES | Sink list for coverage cross-reference |
| `shared/evidence_contract.md` | Skill directory | REF | EVID_* dictionary for evidence validation |
| `auth_matrix.json` | Phase-3 | YES | Auth levels for prerequisite consistency |
| `context_packs/` | Phase-3 | YES | Filter metadata for bypass validation |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every `confirmed` verdict MUST have physical HTTP evidence (request + response + payload + observable outcome) | FAIL — evidence fabrication risk |
| CR-2 | Severity scoring contradictions MUST NOT exceed 2 | FAIL — scoring integrity compromised |
| CR-3 | P0 sink coverage MUST be 100% (every P0 sink has an exploit result) | FAIL — critical sinks unaudited |
| CR-4 | `team4_progress.json` MUST exist | FAIL — team4 dispatcher did not produce summary |
| CR-5 | Overall sink coverage MUST be ≥ 90% (`audited / total` from priority_queue) | FAIL if < 80%; CONDITIONAL_PASS if 80–89% |
| CR-6 | `exploitability_judgment = "not_exploitable"` → `final_verdict` capped at `potential`, `confidence` capped at `low` | FAIL — exploitability/verdict mismatch |
| CR-7 | Severity score formula: `score = R×0.40 + I×0.35 + C×0.25`; CVSS = `(score / 3.0) × 10.0` | FAIL — recalculate and resubmit |
| CR-8 | MUST-PASS: Checks 1–5 (Exploit Integrity, Verdict Validity, EVID Chain, Severity Scoring, Prerequisites) | FAIL if any MUST-PASS check fails |
| CR-9 | MAY-WARN: HTTP format, evidence_score consistency, filter bypass records, auditor coverage | WARN only — does not block gate |

## Fill-in Procedure

### Procedure A: Exploit File Integrity
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | `exploits/` directory exists with ≥1 JSON file | {pass/fail} | {file count} |
| 2 | Each exploit file is valid JSON and passes `schemas/exploit_result.schema.json` | {pass/fail} | {schema errors if any} |
| 3 | Required fields present in each file: `sink_id`, `route_url`, `sink_function`, `specialist`, `route_type`, `rounds_executed`, `rounds_skipped`, `results`, `final_verdict`, `confidence`, `severity`, `prerequisite_conditions` | {pass/fail} | {missing fields list} |
| 4 | `sink_id` follows pattern `^sink_\d+$` | {pass/fail} | {invalid sink_ids} |

### Procedure B: Final Verdict Validity
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | `final_verdict` is one of: `confirmed`, `suspected`, `potential`, `not_vulnerable` | {pass/fail} | {invalid values} |
| 2 | `confirmed` verdicts have physical evidence: HTTP request/response with actual payload + observable outcome | {pass/fail} | {count of confirmed without evidence} |
| 3 | `confirmed` verdicts have `confidence: "high"` — no `confirmed` with low confidence | {pass/fail} | {mismatched entries} |
| 4 | `suspected` verdicts have at least code-level evidence or partial response anomaly | {pass/fail} | {count missing evidence} |
| 5 | All-8-rounds-failed sinks annotated as `potential` with failure reason documented | {pass/fail} | {undocumented failures} |

### Procedure C: Evidence Completeness (EVID Chain)
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Each `confirmed` finding references all required EVID_* points per `shared/evidence_contract.md` | {pass/fail} | {missing EVID references} |
| 2 | EVID references contain actual data — not empty strings or placeholders | {pass/fail} | {empty EVID count} |
| 3 | Missing EVID points annotated `EVID_XXX: [Not obtained: reason]` and verdict auto-downgraded | {pass/fail} | {unannotated missing EVIDs} |
| 4 | HTTP requests in Burp format: `METHOD URL HTTP/1.1` + Headers + Body — directly replayable | {pass/fail/warn} | {non-compliant requests} |
| 5 | HTTP responses include status code + key response body (evidence portion, not truncated) | {pass/fail/warn} | {incomplete responses} |

### Procedure D: Severity Scoring Consistency
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | `severity` object contains all 10 required fields: `reachability`, `reachability_reason`, `impact`, `impact_reason`, `complexity`, `complexity_reason`, `score`, `cvss`, `level`, `vuln_id` | {pass/fail} | {missing fields} |
| 2 | R/I/C values are integers 0–3 with non-empty reason strings | {pass/fail} | {invalid values} |
| 3 | Weighted score formula correct: `score = R×0.40 + I×0.35 + C×0.25` | {pass/fail} | {formula errors count} |
| 4 | CVSS estimate correct: `cvss = (score / 3.0) × 10.0` | {pass/fail} | {CVSS errors} |
| 5 | Level mapping correct: C=2.70–3.00, H=2.10–2.69, M=1.20–2.09, L=0.10–1.19 | {pass/fail} | {mismatched levels} |
| 6 | `vuln_id` follows pattern `^[CHML]-[A-Z_]+-\d{3}$` | {pass/fail} | {invalid vuln_ids} |
| 7 | Score ↔ evidence consistency: score ≥ 2.10 → evidence_score ≥ 7; 1.20–2.09 → 4–6; < 1.20 → 1–3 | {pass/fail/warn} | {inconsistencies count} |

### Procedure E: Prerequisite Conditions
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Each exploit has `prerequisite_conditions` with 4 sub-items: `auth_requirement`, `bypass_method`, `other_preconditions`, `exploitability_judgment` | {pass/fail} | {missing sub-items} |
| 2 | `auth_requirement` is one of: `anonymous`, `authenticated`, `admin`, `internal_network` | {pass/fail} | {invalid values} |
| 3 | `auth_requirement` matches the route's `auth_level` in `auth_matrix.json` | {pass/fail} | {mismatch count} |
| 4 | `exploitability_judgment = "not_exploitable"` → `final_verdict` capped at `potential`, `confidence` capped at `low` | {pass/fail} | {violations} |
| 5 | `exploitability_judgment = "conditionally_exploitable"` → `severity.complexity` drops 1 level | {pass/fail} | {uncapped entries} |

### Procedure F: Sink Coverage & Auditor Matrix
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Sink coverage: `audited sinks / priority_queue total sinks` ≥ 90% | {pass/fail/warn} | {coverage_pct}% |
| 2 | `team4_progress.json` contains `total_findings` + per-level counts + findings array | {pass/fail} | {missing fields} |
| 3 | All 21 auditor types have a status (`executed`, `not_applicable`, `deferred`, `failed`) | {pass/fail/warn} | {missing auditor statuses} |
| 4 | P0 sinks have 100% coverage — every P0 sink has an exploit result | {pass/fail} | {p0_coverage_pct}% |
| 5 | `not_applicable` auditors have documented reason | {pass/fail/warn} | {undocumented count} |

### Procedure G: Filter Bypass & False Positive Check
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | For sinks with `effective=true` filters in context_pack, exploit records bypass method or `not_bypassable` annotation | {pass/fail/warn} | {unhandled filters count} |
| 2 | All `confirmed`/`suspected` findings compared against `shared/false_positive_patterns.md` | {pass/fail/warn} | {false positive matches} |
| 3 | Bypass strategies are reasonable (e.g., `htmlspecialchars` bypass not claimed via SQL comment technique) | {pass/fail/warn} | {unreasonable strategies} |
| 4 | Cross-validated with variant payloads for confirmed findings | {pass/fail/warn} | {unvalidated findings} |

### Procedure H: Final Verdict Determination
| Field | Fill-in Value |
|-------|--------------|
| Total checks passed | {pass_count} / 7 |
| Sink coverage % | {coverage_pct}% |
| P0 coverage % | {p0_coverage_pct}% |
| Confirmed count | {confirmed_count} |
| Suspected count | {suspected_count} |
| Potential count | {potential_count} |
| Not-vulnerable count | {not_vulnerable_count} |
| Overall verdict | {PASS / CONDITIONAL_PASS / FAIL} |
| Verdict justification | {reason} |
| Failed items list | {failed_items} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase4.json` | See example below | Detailed per-auditor check results |

## Examples

### ✅ GOOD: All Checks Pass
```json
{
  "qc_id": "qc-phase4-team4-20250101T120000Z",
  "phase": "4",
  "target_agent": "team4",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "exploit_integrity": { "status": "pass", "file_count": 15, "schema_errors": [] },
    "verdict_validity": { "status": "pass", "confirmed_without_evidence": 0 },
    "evidence_chain": { "status": "pass", "missing_evid_count": 0, "empty_evid_count": 0 },
    "severity_scoring": { "status": "pass", "contradictions": 0, "formula_errors": 0 },
    "prerequisites": { "status": "pass", "missing_fields": 0, "auth_mismatches": 0 },
    "sink_coverage": { "status": "pass", "coverage_pct": 95, "p0_coverage_pct": 100 },
    "filter_bypass": { "status": "pass", "unhandled_filters": 0, "false_positive_matches": 0 }
  },
  "metrics": {
    "sink_coverage": "95%",
    "p0_coverage": "100%",
    "confirmed_count": 5,
    "suspected_count": 3,
    "potential_count": 2,
    "not_vulnerable_count": 5
  },
  "pass_count": 7,
  "total_count": 7,
  "failed_items": []
}
```
Explanation: All 7 checks pass. P0 coverage is 100%, overall sink coverage is 95% (≥90%). No evidence gaps, no scoring contradictions. ✅

### ❌ BAD: Confirmed Verdict Without Evidence
```json
{
  "qc_id": "qc-phase4-team4-20250101T120000Z",
  "phase": "4",
  "target_agent": "team4",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "fail",
  "checks": {
    "exploit_integrity": { "status": "pass", "file_count": 10, "schema_errors": [] },
    "verdict_validity": { "status": "fail", "confirmed_without_evidence": 3 },
    "evidence_chain": { "status": "fail", "missing_evid_count": 5, "empty_evid_count": 2 },
    "severity_scoring": { "status": "fail", "contradictions": 4, "formula_errors": 1 },
    "prerequisites": { "status": "pass", "missing_fields": 0, "auth_mismatches": 0 },
    "sink_coverage": { "status": "fail", "coverage_pct": 70, "p0_coverage_pct": 80 },
    "filter_bypass": { "status": "warn", "unhandled_filters": 2, "false_positive_matches": 1 }
  },
  "metrics": {
    "sink_coverage": "70%",
    "p0_coverage": "80%",
    "confirmed_count": 3,
    "suspected_count": 1,
    "potential_count": 0,
    "not_vulnerable_count": 6
  },
  "pass_count": 2,
  "total_count": 7,
  "failed_items": ["verdict_validity", "evidence_chain", "severity_scoring", "sink_coverage"]
}
```
What's wrong: 3 `confirmed` verdicts lack physical HTTP evidence (violates CR-1). Severity scoring has 4 contradictions (violates CR-2). P0 coverage is 80% (violates CR-3). Sink coverage is 70% (violates CR-5). ❌

## Error Handling
| Error | Action |
|-------|--------|
| Missing `exploits/` directory | FAIL — no exploit results produced |
| Malformed JSON in exploit files | FAIL — data integrity issue; identify responsible auditor |
| `confirmed` without HTTP evidence | FAIL — auditor must provide physical proof or downgrade to `suspected` |
| Severity formula miscalculation | FAIL — recalculate and resubmit |
| `team4_progress.json` missing | FAIL — team4 dispatcher must generate summary |
| `auth_requirement` ↔ `auth_matrix` mismatch | FAIL — auditor must align prerequisites with auth_matrix |
| 1st failure (individual auditor) | Return failed items to specific auditor for correction (max 2 per auditor) |
| 2nd failure (individual auditor) | Mark insufficient evidence, degrade confidence level |
| Comprehensive QC failure | Locate specific auditors to supplement based on failed items |
