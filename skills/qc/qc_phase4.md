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
| CR-9c | MAY-WARN: HTTP format, evidence_score consistency, filter bypass records, auditor coverage | WARN only — does not block gate |

## Fill-in Procedure

### Procedure A: Exploit File Integrity
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `exploits/` directory exists with ≥1 JSON file | ≥ 1 JSON file in exploits/ | {fill-in: file count found} | {✅/❌} |
| 2 | Each exploit file is valid JSON and passes `schemas/exploit_result.schema.json` | all files pass exploit_result.schema.json | {fill-in: schema errors if any} | {✅/❌} |
| 3 | Required fields present in each file: `sink_id`, `route_url`, `sink_function`, `specialist`, `route_type`, `rounds_executed`, `rounds_skipped`, `results`, `final_verdict`, `confidence`, `severity`, `prerequisite_conditions` | all 12 required fields present per file | {fill-in: missing fields list} | {✅/❌} |
| 4 | `sink_id` follows pattern `^sink_\d+$` | matches `^sink_\d+$` pattern | {fill-in: invalid sink_ids if any} | {✅/❌} |

### Procedure B: Final Verdict Validity
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `final_verdict` is one of: `confirmed`, `suspected`, `potential`, `not_vulnerable` | value ∈ {confirmed, suspected, potential, not_vulnerable} | {fill-in: invalid values if any} | {✅/❌} |
| 2 | `confirmed` verdicts have physical evidence: HTTP request/response with actual payload + observable outcome | every confirmed has HTTP evidence | {fill-in: count of confirmed without evidence} | {✅/❌} |
| 3 | `confirmed` verdicts have `confidence: "high"` — no `confirmed` with low confidence | all confirmed → confidence: "high" | {fill-in: mismatched entries} | {✅/❌} |
| 4 | `suspected` verdicts have at least code-level evidence or partial response anomaly | every suspected has partial evidence | {fill-in: count missing evidence} | {✅/❌} |
| 5 | All-8-rounds-failed sinks annotated as `potential` with failure reason documented | failed sinks → potential + documented reason | {fill-in: undocumented failure count} | {✅/❌} |

### Procedure C: Evidence Completeness (EVID Chain)
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | Each `confirmed` finding references all required EVID_* points per `shared/evidence_contract.md` | ≥ 1 EVID_* reference per confirmed finding | {fill-in: missing EVID references} | {✅/❌} |
| 2 | EVID references contain actual data — not empty strings or placeholders | 0 empty/placeholder EVID values | {fill-in: empty EVID count} | {✅/❌} |

**Evidence Data Validation Reference** (use when checking EVID field #2):

| EVID Field Type | Valid Example | Invalid Examples | Verification Method |
|-----------------|---------------|-----------------|---------------------|
| EVID_HTTP_REQUEST | `"POST /api/exec HTTP/1.1\nHost: target.local\nCookie: sess=abc\n\ncmd=id"` | `""`, `"request"`, `"[placeholder]"`, `"TODO"` | Length > 30 chars AND contains "HTTP/" |
| EVID_HTTP_RESPONSE | `"HTTP/1.1 200 OK\nContent-Type: text/html\n\nuid=33(www-data)"` | `""`, `"200"`, `"OK"`, `"[response]"` | Length > 20 chars AND contains "HTTP/1." or status code pattern |
| EVID_CODE_SNIPPET | `"$query = \"SELECT * FROM users WHERE id=\" . $_GET['id'];"` | `""`, `"vulnerable code"`, `"see source"` | Length > 10 chars AND contains at least one PHP/code token ($, ->, ::, function) |
| EVID_OBSERVABLE | `"alert(1) dialog appeared with title 'XSS PoC' in Chrome DevTools"` | `""`, `"XSS worked"`, `"vulnerable"` | Length > 20 chars AND describes specific observable behavior |
| EVID_FILE_LINE | `"app/Http/Controllers/UserController.php:42"` | `""`, `"some file"`, `"controller"` | Matches pattern `*.php:\d+` |
| EVID_TRACE | `"$_GET['id'] → UserController::show($id) → DB::raw($id) → mysql_query()"` | `""`, `"tainted"`, `"user input to sink"` | Contains → or -> indicating flow direction |
| 3 | Missing EVID points annotated `EVID_XXX: [Not obtained: reason]` and verdict auto-downgraded | all missing EVIDs annotated + verdict downgraded | {fill-in: unannotated missing EVID count} | {✅/❌} |
| 4 | HTTP requests in Burp format: `METHOD URL HTTP/1.1` + Headers + Body — directly replayable | Burp-compatible request format | {fill-in: non-compliant request count} | {✅/❌} |
| 5 | HTTP responses include status code + key response body (evidence portion, not truncated) | status code + evidence body present | {fill-in: incomplete response count} | {✅/❌} |

### Procedure D: Severity Scoring Consistency
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `severity` object contains all 10 required fields: `reachability`, `reachability_reason`, `impact`, `impact_reason`, `complexity`, `complexity_reason`, `score`, `cvss`, `level`, `vuln_id` | all 10 fields present | {fill-in: missing fields} | {✅/❌} |
| 2 | R/I/C values are integers 0–3 with non-empty reason strings | R, I, C ∈ {0,1,2,3} + non-empty reasons | {fill-in: invalid values} | {✅/❌} |
| 3 | Weighted score formula correct: `score = R×0.40 + I×0.35 + C×0.25` | score = R×0.40 + I×0.35 + C×0.25 | {fill-in: formula error count} | {✅/❌} |
| 4 | CVSS estimate correct: `cvss = (score / 3.0) × 10.0` | cvss = (score / 3.0) × 10.0 | {fill-in: CVSS error count} | {✅/❌} |
| 5 | Level mapping correct: C=2.70–3.00, H=2.10–2.69, M=1.20–2.09, L=0.10–1.19 | level matches score range | {fill-in: mismatched level count} | {✅/❌} |
| 6 | `vuln_id` follows pattern `^[CHML]-[A-Z_]+-\d{3}$` | matches `^[CHML]-[A-Z_]+-\d{3}$` | {fill-in: invalid vuln_id count} | {✅/❌} |
| 7 | Score ↔ evidence consistency: score ≥ 2.10 → evidence_score ≥ 7; 1.20–2.09 → 4–6; < 1.20 → 1–3 | score-evidence alignment per ranges | {fill-in: inconsistency count} | {✅/❌} |

### Procedure E: Prerequisite Conditions
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | Each exploit has `prerequisite_conditions` with 4 sub-items: `auth_requirement`, `bypass_method`, `other_preconditions`, `exploitability_judgment` | all 4 sub-items present per exploit | {fill-in: missing sub-item count} | {✅/❌} |
| 2 | `auth_requirement` is one of: `anonymous`, `authenticated`, `admin`, `internal_network` | value ∈ {anonymous, authenticated, admin, internal_network} | {fill-in: invalid values} | {✅/❌} |
| 3 | `auth_requirement` matches the route's `auth_level` in `auth_matrix.json` | auth_requirement = auth_matrix.auth_level | {fill-in: mismatch count} | {✅/❌} |
| 4 | `exploitability_judgment = "not_exploitable"` → `final_verdict` capped at `potential`, `confidence` capped at `low` | not_exploitable → potential + low confidence | {fill-in: violation count} | {✅/❌} |
| 5 | `exploitability_judgment = "conditionally_exploitable"` → `severity.complexity` drops 1 level | conditionally_exploitable → complexity -1 | {fill-in: uncapped entry count} | {✅/❌} |

### Procedure F: Sink Coverage & Auditor Matrix
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | Sink coverage: `audited sinks / priority_queue total sinks` ≥ 90% | ≥ 90% | {fill-in: coverage percentage} | {✅/❌} |
| 2 | `team4_progress.json` contains `total_findings` + per-level counts + findings array | all required fields present | {fill-in: missing fields} | {✅/❌} |
| 3 | All 21 auditor types have a status (`executed`, `not_applicable`, `deferred`, `failed`) | 21/21 auditors have status | {fill-in: missing auditor status count} | {✅/❌} |
| 4 | P0 sinks have 100% coverage — every P0 sink has an exploit result | 100% P0 coverage | {fill-in: P0 coverage percentage} | {✅/❌} |
| 5 | `not_applicable` auditors have documented reason | all not_applicable have reason | {fill-in: undocumented count} | {✅/❌} |

### Procedure G: Filter Bypass & False Positive Check
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | For sinks with `effective=true` filters in context_pack, exploit records bypass method or `not_bypassable` annotation | bypass method or not_bypassable for all filtered sinks | {fill-in: unhandled filter count} | {✅/❌} |
| 2 | All `confirmed`/`suspected` findings compared against `shared/false_positive_patterns.md` | comparison completed for all findings | {fill-in: false positive match count} | {✅/❌} |
| 3 | Bypass strategies are reasonable (e.g., `htmlspecialchars` bypass not claimed via SQL comment technique) | strategies consistent with filter type | {fill-in: unreasonable strategy count} | {✅/❌} |
| 4 | Cross-validated with variant payloads for confirmed findings | variant payload validation done | {fill-in: unvalidated finding count} | {✅/❌} |

### Procedure G2: Anti-Hallucination Verification (per `shared/anti_hallucination.md`)

For EACH `confirmed` or `suspected` exploit result, verify the following rules:

| # | Anti-Hallucination Rule | Check Method | Actual | Status |
|---|------------------------|--------------|--------|--------|
| 1 | No speculation — conclusions backed by code evidence | Every conclusion has `file:line` citation | {fill-in: unsupported conclusion count} | {✅/❌} |
| 2 | Source code snippets present | Each finding includes actual code snippet (not paraphrased) | {fill-in: missing snippet count} | {✅/❌} |
| 3 | Uncertain findings marked `[Needs Verification]` | Findings without full evidence chain marked | {fill-in: unmarked uncertain count} | {✅/❌} |
| 4 | Call chain evidence complete | Every link in call chain has code evidence | {fill-in: broken chain count} | {✅/❌} |
| 5 | Payload results from actual HTTP responses | `confirmed` has real response data, not fabricated | {fill-in: fabricated response count} | {✅/❌} |
| 6 | Response mismatch = not confirmed | If expected vs actual response differ → verdict ≠ confirmed | {fill-in: mismatch-but-confirmed count} | {✅/❌} |
| 7 | Code re-read, not from memory | Evidence references match actual file content — for EACH `file:line` citation, run `sed -n '{line}p' $TARGET_PATH/{file}` and compare with quoted code | {fill-in: stale reference count} | {✅/❌} |
| 8 | Non-vulnerability analysis present | Safe sinks documented with reason | {fill-in: undocumented safe count} | {✅/❌} |
| 9 | Multi-agent conflict resolved | Contradictory findings between auditors reconciled | {fill-in: unresolved conflict count} | {✅/❌} |
| 10 | Complete reproduction materials | PoC script + exact curl command + expected output | {fill-in: incomplete reproduction count} | {✅/❌} |
| 11 | Race condition statistical significance | Race findings have ≥3 successful reproductions | {fill-in: insufficient evidence count} | {✅/❌} |
| 12 | NoSQL/GraphQL semantics correct | NoSQL/GraphQL-specific syntax not confused with SQL | {fill-in: semantic error count} | {✅/❌} |
| 13 | Business logic context present | Business logic vulns have workflow context documented | {fill-in: missing context count} | {✅/❌} |
| 14 | Crypto exploitability verified | Crypto findings have practical exploit demonstration | {fill-in: theoretical-only crypto count} | {✅/❌} |
| 15 | WordPress core/plugin/theme distinction | WordPress findings correctly attribute component | {fill-in: misattribution count} | {✅/❌} |
| 16 | No fabrication on tool failure | If tool returned error, finding not fabricated from assumption | {fill-in: post-failure fabrication count} | {✅/❌} |
| 17 | Output size within limits | Each exploit JSON ≤ 50KB; total exploits/ ≤ 5MB | {fill-in: oversized file count} | {✅/❌} |

**Anti-hallucination verdict:**
- ANY of rules 1-6 has count > 0 for `confirmed` findings → FAIL (critical fabrication risk)
- Rules 7-17 with count > 0 → WARN (quality concern, does not block gate)

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
  "basic_info": {
    "quality_checker": "S-083",
    "target": "Phase-4 output",
    "validated_files": ["{fill-in: actual file paths read}"]
  },
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
  "item_results": [
    {"id": 1, "check_item": "exploits/ directory exists with ≥1 JSON file", "expected": "≥ 1 JSON file", "actual": "{fill-in}", "status": "✅"},
    {"id": 2, "check_item": "confirmed verdicts have physical evidence", "expected": "every confirmed has HTTP evidence", "actual": "{fill-in}", "status": "✅"},
    {"id": 3, "check_item": "EVID references present per confirmed finding", "expected": "≥ 1 EVID_* reference per confirmed finding", "actual": "{fill-in}", "status": "✅"},
    {"id": 4, "check_item": "Severity scoring formula correct", "expected": "score = R×0.40 + I×0.35 + C×0.25", "actual": "{fill-in}", "status": "✅"},
    {"id": 5, "check_item": "Prerequisites complete", "expected": "all 4 sub-items present", "actual": "{fill-in}", "status": "✅"},
    {"id": 6, "check_item": "Sink coverage ≥ 90%", "expected": "≥ 90%", "actual": "{fill-in}", "status": "✅"},
    {"id": 7, "check_item": "Filter bypass validation", "expected": "bypass method or not_bypassable", "actual": "{fill-in}", "status": "✅"}
  ],
  "metrics": {
    "sink_coverage": "95%",
    "p0_coverage": "100%",
    "confirmed_count": 5,
    "suspected_count": 3,
    "potential_count": 2,
    "not_vulnerable_count": 5
  },
  "final_verdict": {
    "status": "PASS",
    "passed": "7/7",
    "failed_items": []
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
