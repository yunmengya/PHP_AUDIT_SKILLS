# Phase-5 Quality Check — Report Generation

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-085 |
| Category | QC |
| Responsibility | Validate final report structure, deliverables, and file organization before declaring audit complete |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `报告/审计报告.md` | report_writer | YES | Markdown audit report; non-empty |
| `报告/audit_report.sarif.json` | sarif_exporter | YES | Valid JSON; SARIF v2.1.0 format |
| `PoC脚本/*.py` | poc_generator | YES | ≥1 file per confirmed finding |
| `PoC脚本/一键运行.sh` | poc_generator | YES | Runner script; executable |
| `修复补丁/` | remediation_generator | YES | ≥1 patch file |
| `经验沉淀/` | knowledge_base | NO | Optional lessons-learned export |
| `priority_queue.json` | Phase-3 | REF | Cross-reference for P0/P1 coverage |
| `exploits/*.json` | Phase-4 auditors | REF | Cross-reference for finding details |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | P0/P1 coverage MUST be 100% — every P0/P1 sink in `priority_queue.json` has a dedicated report section | FAIL — report_writer must add missing sections |
| CR-2 | Every `confirmed` finding MUST have complete HTTP evidence (Burp-format request + response + evidence description) | FAIL — evidence fabrication; downgrade or provide proof |
| CR-3 | SARIF export MUST be valid v2.1.0 JSON with result count matching report vulnerability count | FAIL — sarif_exporter must regenerate |
| CR-4 | Report MUST be written in Chinese (section headers, descriptions, analysis) | FAIL — report_writer must translate |
| CR-5 | PoC syntax pass rate MUST be 100% | FAIL — poc_generator must fix scripts |
| CR-6 | `报告/审计报告.md` MUST exist | FAIL — report_writer did not produce output |
| CR-7 | Confidence labels: ✅ = confirmed (has evidence), ⚠️ = suspected (code exploitable, no evidence), ⚡ = potential (static only) | FAIL — inconsistent labeling |
| CR-8 | MUST-PASS: P0/P1 coverage, evidence completeness, remediation specificity, agent coverage matrix, EVID chain | FAIL if any MUST-PASS fails |
| CR-9 | MAY-WARN: Markdown formatting, SARIF severity mapping, PoC URL consistency, file organization | WARN only — does not block gate |

## Fill-in Procedure

### Procedure A: Report Structure & Template Compliance
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | `报告/审计报告.md` exists and is non-empty | {pass/fail} | {file size} |
| 2 | Report contains mandatory sections: executive summary, vulnerability details, remediation recommendations, coverage statistics | {pass/fail} | {missing sections} |
| 3 | Each vulnerability section has: description, severity rating, affected endpoint, evidence, remediation | {pass/fail} | {incomplete vuln sections count} |
| 4 | Tables render correctly — no broken Markdown table syntax | {pass/fail/warn} | {broken tables count} |
| 5 | Code blocks have correct language syntax annotations | {pass/fail/warn} | {unannotated code blocks} |
| 6 | No broken internal links or references | {pass/fail/warn} | {broken links count} |

### Procedure B: P0/P1 Vulnerability Full Coverage
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Every P0 sink in `priority_queue.json` has a dedicated section in the report | {pass/fail} | {p0_covered / p0_total} |
| 2 | Every P1 sink in `priority_queue.json` has a dedicated section in the report | {pass/fail} | {p1_covered / p1_total} |
| 3 | P0/P1 coverage rate = 100% — no P0/P1 sink omitted | {pass/fail} | {coverage_pct}% |
| 4 | Untested P0 sinks have explicit skip reason (`not_applicable` + reason documented) | {pass/fail} | {undocumented skips} |
| 5 | Each vulnerability section references the correct `vuln_id` from exploit results | {pass/fail} | {mismatched vuln_ids} |

### Procedure C: Evidence Completeness for Confirmed Findings
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Each `confirmed` (✅) finding has: complete Burp-format HTTP request + HTTP response + evidence description | {pass/fail} | {confirmed_with_evidence / confirmed_total} |
| 2 | HTTP requests are complete: `METHOD URL HTTP/1.1` + Host + Cookie headers + Body | {pass/fail} | {incomplete requests count} |
| 3 | HTTP responses include Status Line + relevant Body excerpt (evidence portion) | {pass/fail} | {incomplete responses count} |
| 4 | All required EVID_* points for each vulnerability type referenced (per `shared/evidence_contract.md`) | {pass/fail} | {missing_evid count} |
| 5 | Evidence is not fabricated — response content matches described behavior | {pass/fail} | {suspicious evidence count} |
| 6 | `suspected` (⚠️) findings have code-level evidence explaining exploitability | {pass/fail} | {suspected without evidence} |
| 7 | `potential` (⚡) findings have static analysis reference only — correctly noted as unverified | {pass/fail} | {miscategorized potentials} |

### Procedure D: Remediation Quality
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Each vulnerability has specific before/after code comparison (not generic "fix the issue") | {pass/fail} | {generic fixes count} |
| 2 | Remediation uses framework-appropriate patterns (e.g., Laravel Eloquent for Laravel apps, not raw PDO) | {pass/fail} | {inappropriate patterns count} |
| 3 | Remediation count matches vulnerability count — no findings without fix guidance | {pass/fail} | {specific_fixes / total_vulns} |
| 4 | Patches in `修复补丁/` correspond to vulnerabilities in the report | {pass/fail} | {unmatched patches} |

### Procedure E: Chinese Output Verification
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Report is written in Chinese (section headers, descriptions, analysis) | {pass/fail} | {english_only_sections count} |
| 2 | Technical terms may remain in English where appropriate (CVE IDs, function names, HTTP headers) | {pass/fail} | {assessment} |
| 3 | No English-only sections (except code blocks and HTTP evidence) | {pass/fail} | {english-only sections list} |
| 4 | File encoding is UTF-8 | {pass/fail} | {detected encoding} |

### Procedure F: SARIF Export Validation
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | `报告/audit_report.sarif.json` is valid JSON | {pass/fail} | {validation result} |
| 2 | SARIF version is `2.1.0` | {pass/fail} | {detected version} |
| 3 | `results` count matches report vulnerability count | {pass/fail} | {sarif_results_count / report_count} |
| 4 | Severity mapping correct: `confirmed` → `error`, `suspected` → `warning`, `potential` → `note` | {pass/fail} | {severity_errors count} |
| 5 | Each result has `ruleId`, `message`, `locations` with file path and line number | {pass/fail} | {incomplete results count} |
| 6 | No duplicate results in SARIF output | {pass/fail} | {duplicate count} |

### Procedure G: PoC & Deliverable Validation
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | All `.py` PoC scripts pass Python syntax check: `python3 -c "compile(...)"` | {pass/fail} | {syntax_pass_count / script_count} |
| 2 | `PoC脚本/一键运行.sh` exists and contains execution commands for all PoC scripts | {pass/fail} | {runner_exists, scripts covered} |
| 3 | Target URLs in PoC scripts are consistent with report URLs | {pass/fail/warn} | {inconsistent URLs} |
| 4 | PoC script count ≥ confirmed vulnerability count | {pass/fail} | {script_count vs confirmed_count} |
| 5 | PoC pass rate = 100% (all must pass syntax check) | {pass/fail} | {syntax_pass_pct}% |

### Procedure H: File Organization
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | `报告/` — audit report + SARIF | {pass/fail/warn} | {files present} |
| 2 | `PoC脚本/` — PoC scripts + runner + summary | {pass/fail/warn} | {files present} |
| 3 | `修复补丁/` — patch files + summary | {pass/fail/warn} | {files present} |
| 4 | `经验沉淀/` — lessons learned (optional) | {pass/warn} | {exists or not} |
| 5 | `质量报告/` — QC reports | {pass/fail/warn} | {files present} |
| 6 | `原始数据/` — archived intermediate artifacts | {pass/fail/warn} | {files present} |
| 7 | No intermediate JSON files left in `$WORK_DIR` root (should be moved to `原始数据/`) | {pass/fail/warn} | {stray files list} |
| 8 | `audit_session.db` has been securely deleted (contains plaintext credentials) | {pass/fail} | {db_deleted} |
| 9 | Agent coverage matrix: all 21 Phase-4 auditors have a status entry | {pass/fail/warn} | {auditors with status / 21} |

### Procedure I: Cross-Phase Consistency
| # | Check Item | Result | Details |
|---|------------|--------|---------|
| 1 | Vulnerability deduplication: same `file:line:sink` appears only once in report | {pass/fail} | {duplicates count} |
| 2 | Coverage statistics: `audited routes + skipped routes = total routes` (math checks out) | {pass/fail/warn} | {coverage_math_ok} |
| 3 | Confidence labels consistent: ✅ = has evidence, ⚠️ = code exploitable no evidence, ⚡ = static only | {pass/fail} | {inconsistent labels count} |
| 4 | `auth_requirement` in exploits matches `auth_level` in `auth_matrix.json` for each route | {pass/fail/warn} | {auth_mismatches count} |

### Procedure J: Final Verdict Determination
| Field | Fill-in Value |
|-------|--------------|
| Total checks passed | {pass_count} / 9 |
| P0/P1 coverage % | {p0_p1_coverage_pct}% |
| PoC syntax pass rate | {poc_syntax_pass_pct}% |
| Evidence completeness rate | {evidence_completeness_pct}% |
| Confirmed count | {confirmed} |
| Suspected count | {suspected} |
| Potential count | {potential} |
| Total vulnerabilities | {total} |
| Overall verdict | {PASS / CONDITIONAL_PASS / FAIL} |
| Verdict justification | {reason} |
| Failed items list | {failed_items} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase5.json` | See example below | Final phase check results |
| Consolidated quality report | `$WORK_DIR/质量报告/质量报告.md` | Markdown | Consolidated quality report across all phases |

## Examples

### ✅ GOOD: All Checks Pass
```json
{
  "qc_id": "qc-phase5-team5-20250101T120000Z",
  "phase": "5",
  "target_agent": "team5",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "report_structure": { "status": "pass", "section_count": 12, "broken_links": 0 },
    "p0_p1_coverage": { "status": "pass", "p0_covered": 5, "p0_total": 5, "p1_covered": 8, "p1_total": 8 },
    "evidence_completeness": { "status": "pass", "confirmed_with_evidence": 6, "confirmed_total": 6, "missing_evid": 0 },
    "remediation_quality": { "status": "pass", "specific_fixes": 10, "total_vulns": 10 },
    "chinese_output": { "status": "pass", "english_only_sections": 0 },
    "sarif_valid": { "status": "pass", "version": "2.1.0", "results_count": 10, "report_count": 10, "severity_errors": 0 },
    "poc_deliverables": { "status": "pass", "script_count": 6, "syntax_pass_pct": 100, "runner_exists": true },
    "file_organization": { "status": "pass", "stray_files": [], "db_deleted": true },
    "cross_phase_consistency": { "status": "pass", "duplicates": 0, "coverage_math_ok": true, "auth_mismatches": 0 }
  },
  "metrics": {
    "p0_p1_coverage": "100%",
    "poc_syntax_pass_rate": "100%",
    "evidence_completeness_rate": "100%",
    "vulnerability_summary": {
      "confirmed": 6,
      "suspected": 3,
      "potential": 1,
      "total": 10
    }
  },
  "pass_count": 9,
  "total_count": 9,
  "failed_items": []
}
```
Explanation: All 9 checks pass. P0/P1 100% covered, PoC 100% syntax pass, evidence complete for all confirmed findings, report in Chinese, SARIF valid, files organized. ✅

### ❌ BAD: Missing P0 Coverage and Non-Chinese Report
```json
{
  "qc_id": "qc-phase5-team5-20250101T120000Z",
  "phase": "5",
  "target_agent": "team5",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "fail",
  "checks": {
    "report_structure": { "status": "pass", "section_count": 8, "broken_links": 0 },
    "p0_p1_coverage": { "status": "fail", "p0_covered": 3, "p0_total": 5, "p1_covered": 6, "p1_total": 8 },
    "evidence_completeness": { "status": "fail", "confirmed_with_evidence": 2, "confirmed_total": 4, "missing_evid": 4 },
    "remediation_quality": { "status": "fail", "specific_fixes": 5, "total_vulns": 8 },
    "chinese_output": { "status": "fail", "english_only_sections": 4 },
    "sarif_valid": { "status": "fail", "version": "2.1.0", "results_count": 6, "report_count": 8, "severity_errors": 2 },
    "poc_deliverables": { "status": "fail", "script_count": 3, "syntax_pass_pct": 67, "runner_exists": true },
    "file_organization": { "status": "warn", "stray_files": ["team4_progress.json", "priority_queue.json"], "db_deleted": false },
    "cross_phase_consistency": { "status": "warn", "duplicates": 1, "coverage_math_ok": false, "auth_mismatches": 2 }
  },
  "metrics": {
    "p0_p1_coverage": "64%",
    "poc_syntax_pass_rate": "67%",
    "evidence_completeness_rate": "50%",
    "vulnerability_summary": {
      "confirmed": 4,
      "suspected": 2,
      "potential": 2,
      "total": 8
    }
  },
  "pass_count": 1,
  "total_count": 9,
  "failed_items": ["p0_p1_coverage", "evidence_completeness", "remediation_quality", "chinese_output", "sarif_valid", "poc_deliverables"]
}
```
What's wrong: P0 coverage only 60% (3/5), P1 coverage 75% (6/8) — violates CR-1. 2 confirmed findings lack evidence (violates CR-2). SARIF results count mismatch 6 vs 8 (violates CR-3). 4 English-only sections in report (violates CR-4). PoC syntax pass rate 67% (violates CR-5). ❌

## Error Handling
| Error | Action |
|-------|--------|
| Missing `报告/审计报告.md` | FAIL — report_writer did not produce output |
| Missing `报告/audit_report.sarif.json` | FAIL — sarif_exporter did not produce output |
| Malformed SARIF JSON | FAIL — sarif_exporter must regenerate |
| P0/P1 vulnerability not in report | FAIL — report_writer must add missing vulnerability sections |
| `confirmed` without HTTP evidence | FAIL — must provide evidence or downgrade to `suspected` |
| Non-Chinese report content | FAIL — report_writer must output in Chinese |
| PoC syntax error | FAIL — poc_generator must fix script |
| Stray files in WORK_DIR root | WARN — file organization incomplete; move to `原始数据/` |
| 1st failure | Return specific failed items to report_writer for correction |
| 2nd failure | Force generate with available content, mark with WARN annotations |
| Maximum redo rounds: 2 | After 2 failures, output whatever is available |
