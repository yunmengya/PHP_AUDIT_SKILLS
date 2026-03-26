> **Skill ID**: S-085 | **Phase**: 5 (QC) | **Gate**: Final
> **Input**: Phase 5 outputs
> **Output**: quality_report_phase5.json

# Phase-5 Quality Check — Report Generation

## Identity

Quality checker for Phase 5. Validates final report structure, evidence completeness, and deliverable organization before declaring audit complete. Ensures report matches template structure, all confirmed vulnerabilities have PoC references, output is in Chinese, SARIF export is valid, and file organization follows the mandated directory structure.

## Input Contract

| Source | Path | Required | Validation |
|--------|------|----------|------------|
| Audit report | `$WORK_DIR/报告/审计报告.md` | YES | Markdown file exists, non-empty |
| SARIF export | `$WORK_DIR/报告/audit_report.sarif.json` | YES | Valid JSON, SARIF v2.1.0 format |
| PoC scripts | `$WORK_DIR/PoC脚本/*.py` | YES | ≥1 file per confirmed finding |
| PoC runner | `$WORK_DIR/PoC脚本/一键运行.sh` | YES | Exists, executable |
| Remediation patches | `$WORK_DIR/修复补丁/` | YES | ≥1 patch file |
| Lessons learned | `$WORK_DIR/经验沉淀/` | NO | Optional knowledge base export |
| Priority queue | `$WORK_DIR/priority_queue.json` | REF | Cross-reference for P0/P1 coverage |
| Exploits | `$WORK_DIR/exploits/*.json` | REF | Cross-reference for finding details |

## Check Procedure

### Check 1: Report Structure & Template Compliance
- [ ] `报告/审计报告.md` exists and is non-empty
- [ ] Report contains mandatory sections: executive summary, vulnerability details, remediation recommendations, coverage statistics
- [ ] Each vulnerability section has: description, severity rating, affected endpoint, evidence, remediation
- [ ] Tables render correctly — no broken Markdown table syntax
- [ ] Code blocks have correct language syntax annotations
- [ ] No broken internal links or references

### Check 2: P0/P1 Vulnerability Full Coverage
- [ ] Every P0 sink in `priority_queue.json` has a dedicated section in the report
- [ ] Every P1 sink in `priority_queue.json` has a dedicated section in the report
- [ ] P0/P1 coverage rate = **100%** — no P0/P1 sink omitted
- [ ] Untested P0 sinks have explicit skip reason (`not_applicable` + reason documented)
- [ ] Each vulnerability section references the correct `vuln_id` from exploit results

### Check 3: Evidence Completeness for Confirmed Findings
- [ ] Each `confirmed` (✅) finding has: complete Burp-format HTTP request + HTTP response + evidence description
- [ ] HTTP requests are complete: `METHOD URL HTTP/1.1` + Host + Cookie headers + Body
- [ ] HTTP responses include Status Line + relevant Body excerpt (evidence portion)
- [ ] All required EVID_* points for each vulnerability type are referenced (per `shared/evidence_contract.md`)
- [ ] Evidence is not fabricated — response content matches described behavior
- [ ] `suspected` (⚠️) findings have code-level evidence explaining exploitability
- [ ] `potential` (⚡) findings have static analysis reference only — correctly noted as unverified

### Check 4: Remediation Quality
- [ ] Each vulnerability has specific before/after code comparison (not generic "fix the issue")
- [ ] Remediation uses framework-appropriate patterns (e.g. Laravel Eloquent for Laravel apps, not raw PDO)
- [ ] Remediation count matches vulnerability count — no findings without fix guidance
- [ ] Patches in `修复补丁/` correspond to vulnerabilities in the report

### Check 5: Chinese Output Verification
- [ ] Report is written in Chinese (section headers, descriptions, analysis in 中文)
- [ ] Technical terms may remain in English where appropriate (CVE IDs, function names, HTTP headers)
- [ ] No English-only sections (except code blocks and HTTP evidence)
- [ ] File encoding is UTF-8

### Check 6: SARIF Export Validation
- [ ] `报告/audit_report.sarif.json` is valid JSON
- [ ] SARIF version is `2.1.0`
- [ ] `results` count matches report vulnerability count
- [ ] Severity mapping correct: `confirmed` → `error`, `suspected` → `warning`, `potential` → `note`
- [ ] Each result has `ruleId`, `message`, `locations` with file path and line number
- [ ] No duplicate results in SARIF output

### Check 7: PoC & Deliverable Validation
- [ ] All `.py` PoC scripts pass Python syntax check: `python3 -c "compile(...)"`
- [ ] `PoC脚本/一键运行.sh` exists and contains execution commands for all PoC scripts
- [ ] Target URLs in PoC scripts are consistent with report URLs
- [ ] PoC script count ≥ confirmed vulnerability count
- [ ] PoC pass rate = **100%** (all must pass syntax check)

### Check 8: File Organization
- [ ] Directory structure follows mandate:
  - `报告/` — audit report + SARIF
  - `PoC脚本/` — PoC scripts + runner + summary
  - `修复补丁/` — patch files + summary
  - `经验沉淀/` — lessons learned (optional)
  - `质量报告/` — QC reports
  - `原始数据/` — archived intermediate artifacts
- [ ] No intermediate JSON files left in `$WORK_DIR` root (should be moved to `原始数据/`)
- [ ] `audit_session.db` has been securely deleted (contains plaintext credentials)
- [ ] Agent coverage matrix: all 21 Phase-4 auditors have a status entry

### Check 9: Cross-Phase Consistency
- [ ] Vulnerability deduplication: same `file:line:sink` appears only once in report
- [ ] Coverage statistics: `audited routes + skipped routes = total routes` (math checks out)
- [ ] Confidence labels consistent: ✅ = has evidence, ⚠️ = code exploitable no evidence, ⚡ = static only
- [ ] `auth_requirement` in exploits matches `auth_level` in `auth_matrix.json` for each route

## Verdict Rules

| Condition | Verdict |
|-----------|---------|
| All checks pass, P0/P1 100% covered, PoC 100% syntax pass | PASS |
| Minor issues: ≤2 formatting issues, coverage stats off by 1–2 | CONDITIONAL_PASS (list exceptions) |
| P0/P1 coverage < 100% without justification | FAIL — report_writer must add missing sections |
| `confirmed` findings without evidence | FAIL — evidence fabrication; downgrade or provide proof |
| SARIF invalid or count mismatch | FAIL — sarif_exporter must regenerate |
| Report not in Chinese | FAIL — report_writer must translate |
| PoC syntax failures | FAIL — poc_generator must fix |
| `审计报告.md` missing | FAIL — report_writer did not produce output |

**MUST-PASS items:** P0/P1 coverage, evidence completeness, remediation specific, agent coverage matrix, EVID chain
**MAY-WARN items:** Markdown formatting, SARIF severity mapping, PoC URL consistency, file organization

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase5.json` | Final phase check results |
| Final quality report | `$WORK_DIR/质量报告/质量报告.md` | Consolidated quality report across all phases |

**Output JSON structure:**
```json
{
  "qc_id": "qc-phase5-team5-{timestamp}",
  "phase": "5",
  "target_agent": "team5",
  "timestamp": "ISO-8601",
  "verdict": "pass|conditional_pass|fail",
  "checks": {
    "report_structure": { "status": "pass|fail", "section_count": 0, "broken_links": 0 },
    "p0_p1_coverage": { "status": "pass|fail", "p0_covered": 0, "p0_total": 0, "p1_covered": 0, "p1_total": 0 },
    "evidence_completeness": { "status": "pass|fail", "confirmed_with_evidence": 0, "confirmed_total": 0, "missing_evid": 0 },
    "remediation_quality": { "status": "pass|fail", "specific_fixes": 0, "total_vulns": 0 },
    "chinese_output": { "status": "pass|fail", "english_only_sections": 0 },
    "sarif_valid": { "status": "pass|fail", "version": "", "results_count": 0, "report_count": 0, "severity_errors": 0 },
    "poc_deliverables": { "status": "pass|fail", "script_count": 0, "syntax_pass_pct": 0, "runner_exists": false },
    "file_organization": { "status": "pass|fail|warn", "stray_files": [], "db_deleted": false },
    "cross_phase_consistency": { "status": "pass|fail|warn", "duplicates": 0, "coverage_math_ok": false, "auth_mismatches": 0 }
  },
  "metrics": {
    "p0_p1_coverage": "0%",
    "poc_syntax_pass_rate": "0%",
    "evidence_completeness_rate": "0%",
    "vulnerability_summary": {
      "confirmed": 0,
      "suspected": 0,
      "potential": 0,
      "total": 0
    }
  },
  "pass_count": 0,
  "total_count": 9,
  "failed_items": []
}
```

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

## Redo Rules

| Attempt | Action |
|---------|--------|
| 1st failure | Return specific failed items to report_writer for correction |
| 2nd failure | Force generate with available content, mark with WARN annotations |
| Maximum redo rounds: 2 | After 2 failures, output whatever is available |
