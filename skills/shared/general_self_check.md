# General Pre-Submission Self-Check (G1-G8)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-108 |
| Category | Shared Protocol |
| Responsibility | Define the 8 universal self-check items every Phase-4 auditor MUST execute before submitting exploit JSON |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `$WORK_DIR/exploits/{sink_id}.json` | Current auditor's exploit output | Yes | `sink_id`, `vuln_type`, `specialist`, `status`, `confidence`, `evidence_score`, `severity`, `prerequisite_conditions`, `evidence`, `trace` |
| `shared/evidence_contract.md` | Shared protocol | Yes | EVID list for the auditor's vulnerability type |
| `shared/severity_rating.md` | Shared protocol | Yes | Score-to-severity mapping formula |
| Auth matrix | Phase-2 output | Yes | `auth_requirement` consistency reference |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | ALL 8 general checks (G1-G8) MUST pass ✅ before proceeding to specialized checks; any ❌ MUST be corrected and re-checked — MUST NOT skip | Non-compliant exploit JSON submitted, contract violation |
| CR-2 | After G1-G8 pass, execute auditor-specific specialized checks (S1-S3) before final submission | Auditor-type-specific validation missed |
| CR-3 | When `exploitability_judgment = "not_exploitable"`: cap `final_verdict` at `potential` and `confidence` at `low` | Over-reported vulnerability severity |
| CR-4 | When `exploitability_judgment = "conditionally_exploitable"`: drop `severity.complexity` by 1 level | Severity not adjusted for conditional exploitability |
| CR-5 | When any EVID has `[Not Obtained]` annotation: downgrade `status` from `confirmed` to `suspected` | Unsubstantiated confirmed status |
| CR-6 | When `evidence_score < 7`: `status` MUST NOT be `confirmed` | Confirmed status without sufficient evidence score |

## Fill-in Procedure

### Procedure A: Self-Check Workflow

Execute the following steps in order:

| Step | Action | Fill-in Value |
|------|--------|--------------|
| 1 | Execute all 8 general items (G1-G8) | {Mark each ✅ or ❌ — continue only after ALL pass} |
| 2 | Execute auditor-specific specialized checks (S1-S3) | {Defined in each auditor's own file — submit only after ALL pass} |
| 3 | Handle any ❌ item | {Correct the issue and re-check — MUST NOT skip} |

### Procedure B: G1-G8 Universal Check Items

For each check item, verify the pass criteria and fill in the result:

| # | Check Item | Check Method | Pass Criteria | Result |
|---|-----------|--------------|---------------|--------|
| G1 | File exists and path is correct | Run `ls $WORK_DIR/exploits/{sink_id}.json` | {File exists, size > 0} | {✅ / ❌} |
| G2 | JSON Schema compliant | Run `cat exploits/{sink_id}.json \| python3 -m json.tool` | {No JSON syntax errors} | {✅ / ❌} |
| G3 | Required fields complete | Verify: `sink_id`, `vuln_type`, `specialist`, `status`, `confidence`, `evidence_score`, `severity`, `prerequisite_conditions`, `evidence`, `trace` | {All present and non-empty} | {✅ / ❌} |
| G4 | EVID evidence chain complete | Cross-check against EVID list in `shared/evidence_contract.md` | {Each EVID has actual code snippet or `[Not Obtained: reason]` annotation} | {✅ / ❌} |
| G5 | evidence_score and severity consistent | Per `shared/severity_rating.md`: score ≥ 2.10 → evidence_score ≥ 7; 1.20-2.09 → 4-6; < 1.20 → 1-3 | {Numeric ranges match} | {✅ / ❌} |
| G6 | HTTP evidence format correct | Burp-style: complete Request (Host/Cookie headers) + Response (Status Line + Body excerpt) | {Not truncated, not fabricated, includes timestamp} | {✅ / ❌} |
| G7 | Severity 3D scoring complete | Check `severity` object: R/I/C values + reason fields + score + cvss + level + vuln_id | {All 10 fields filled, reason ≠ empty string} | {✅ / ❌} |
| G8 | Prerequisites declared | Check `prerequisite_conditions`: auth_requirement + bypass_method + other_preconditions + exploitability_judgment | {All 4 sub-items filled; auth_requirement consistent with auth_matrix} | {✅ / ❌} |

### Procedure C: Automatic Downgrade Rules

After completing G1-G8, check for the following conditions and apply downgrades:

| Condition | Downgrade Action | Verification Fill-in |
|-----------|-----------------|---------------------|
| `exploitability_judgment = "not_exploitable"` | Set `final_verdict` maximum `potential`, `confidence` maximum `low` | {Confirm status ≠ confirmed/suspected} |
| `exploitability_judgment = "conditionally_exploitable"` | Drop `severity.complexity` by 1 level | {Confirm C value has been downgraded} |
| EVID has `[Not Obtained]` annotation | Downgrade `status` from `confirmed` to `suspected` | {Confirm status ≠ confirmed} |
| `evidence_score < 7` | `status` MUST NOT be `confirmed` | {Confirm status ≠ confirmed} |

### Procedure D: Auditor File Integration Template

Each auditor's prompt SHOULD include this section at the end:

```markdown
## Pre-Submission Self-Check (MUST Execute)

After completing exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8), continue after all ✅
2. Execute the specialized checks below (S1-S3), submit after all ✅
3. Any item ❌ → Correct and re-check, MUST NOT skip

### Specialized Checks (Specific to This Auditor)
- [ ] S1: [customized by each auditor]
- [ ] S2: [customized by each auditor]
- [ ] S3: [customized by each auditor]
```

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Validated exploit JSON | `$WORK_DIR/exploits/{sink_id}.json` | JSON with all G1-G8 fields passing validation, downgrades applied | The auditor's exploit result after passing all universal checks |
| Self-check result | In-context (auditor's working memory) | G1-G8 pass/fail status + downgrade actions taken | Record of which checks passed/failed and what corrections were made |

## Examples

### ✅ GOOD: All Checks Pass with Proper Downgrade Applied

```json
{
  "sink_id": "SINK-042-001",
  "vuln_type": "sqli",
  "specialist": "S-042",
  "status": "suspected",
  "confidence": "medium",
  "evidence_score": 5,
  "severity": {
    "R": 3, "R_reason": "Database read access allows extraction of all user records",
    "I": 2, "I_reason": "Can modify query logic but limited to SELECT context",
    "C": 2, "C_reason": "Requires valid session token, conditionally exploitable",
    "score": 1.80, "cvss": 7.5, "level": "high", "vuln_id": "CWE-89"
  },
  "prerequisite_conditions": {
    "auth_requirement": "authenticated",
    "bypass_method": "none",
    "other_preconditions": "Requires valid user session",
    "exploitability_judgment": "conditionally_exploitable"
  },
  "evidence": [
    {"evid": "EVID-SQLI-01", "content": "$pdo->query(\"SELECT * FROM users WHERE id = '$id'\")"},
    {"evid": "EVID-SQLI-02", "content": "[Not Obtained: blind injection, no direct output]"}
  ],
  "trace": ["UserController.php:45 → query() → PDO::query()"]
}
```
Explanation ✅ G1-G8 all pass: file exists, valid JSON, all required fields present, EVID chain includes `[Not Obtained]` annotation with reason, evidence_score=5 matches severity score 1.80 (range 1.20-2.09 → 4-6), HTTP evidence not shown but assumed present, 3D scoring complete (all 10 fields filled), prerequisites declared. Downgrades correctly applied: EVID has `[Not Obtained]` → status is `suspected` (not `confirmed`); `conditionally_exploitable` → C dropped by 1 level.

### ❌ BAD: Multiple Check Failures and Missing Downgrade

```json
{
  "sink_id": "SINK-042-002",
  "vuln_type": "sqli",
  "specialist": "S-042",
  "status": "confirmed",
  "confidence": "high",
  "evidence_score": 5,
  "severity": {
    "R": 3, "R_reason": "",
    "I": 2, "I_reason": "Can modify queries",
    "C": 3, "C_reason": "No auth needed",
    "score": 1.80, "cvss": 7.5, "level": "high", "vuln_id": "CWE-89"
  },
  "prerequisite_conditions": {
    "auth_requirement": "authenticated",
    "bypass_method": "none",
    "other_preconditions": "",
    "exploitability_judgment": "not_exploitable"
  },
  "evidence": [
    {"evid": "EVID-SQLI-01", "content": "[Not Obtained: could not reproduce]"}
  ],
  "trace": []
}
```
What's wrong ❌ Violates **CR-6**: `evidence_score=5` (< 7) but `status` is `confirmed`. Violates **CR-5**: EVID has `[Not Obtained]` but `status` remains `confirmed` instead of `suspected`. Violates **CR-3**: `exploitability_judgment` is `not_exploitable` but `confidence` is `high` (should be max `low`) and `status` is `confirmed` (should be max `potential`). G7 fails: `R_reason` is empty string. G8 fails: `other_preconditions` is empty. `trace` is empty array — G3 fails.

## Error Handling
| Error | Action |
|-------|--------|
| Exploit JSON file does not exist (G1 fails) | Auditor must generate the exploit JSON before running self-check; cannot proceed |
| JSON syntax error (G2 fails) | Fix JSON syntax (missing commas, brackets, quotes); re-validate with `python3 -m json.tool` |
| Required field missing or empty (G3 fails) | Add missing field with correct value; if value is genuinely unknown, use appropriate placeholder with justification |
| EVID not found in `evidence_contract.md` (G4 fails) | Verify correct EVID identifiers for this vulnerability type; add missing EVIDs with code snippets or `[Not Obtained: reason]` |
| Score-severity mismatch (G5 fails) | Recalculate using `severity_rating.md` formula; adjust either `evidence_score` or `severity.score` to align |
| Multiple downgrade conditions triggered simultaneously | Apply ALL applicable downgrades — they are cumulative, not mutually exclusive |
| Specialized checks (S1-S3) not defined in auditor file | Auditor file is incomplete; add auditor-specific checks before submission |
