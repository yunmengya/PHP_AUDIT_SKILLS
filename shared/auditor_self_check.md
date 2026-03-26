# Auditor Pre-Submission Self-Check Checklist (8 Universal Items)

> Every Phase 4 Auditor **MUST** perform this item-by-item self-check before submitting exploit JSON.
> If self-check fails, correct and resubmit; MUST NOT skip.

---

## Universal Self-Check Items (Applicable to All Auditors)

| # | Check Item | Check Method | Pass Criteria |
|---|-----------|--------------|---------------|
| G1 | **File exists and path is correct** | Run `ls $WORK_DIR/exploits/{sink_id}.json` to confirm file is written | File exists, size > 0 |
| G2 | **JSON Schema compliant** | Validate syntax with `cat exploits/{sink_id}.json \| python3 -m json.tool` | No JSON syntax errors |
| G3 | **Required fields complete** | Verify each one: sink_id, vuln_type, specialist, status, confidence, evidence_score, severity, prerequisite_conditions, evidence, trace | All present and non-empty |
| G4 | **EVID evidence chain complete** | Cross-check against the EVID list for this vulnerability type in `shared/evidence_contract.md` | Each EVID has an actual code snippet or `[Not Obtained: reason]` annotation |
| G5 | **evidence_score and severity consistent** | Per `shared/severity_rating.md` formula: score ≥ 2.10 → evidence_score ≥ 7; 1.20-2.09 → 4-6; < 1.20 → 1-3 | Numeric ranges match |
| G6 | **HTTP evidence format correct** | Burp-style: includes complete Request (with Host/Cookie headers) and Response (with Status Line + Body excerpt) | Not truncated, not fabricated, includes timestamp |
| G7 | **severity tri-dimensional scoring complete** | Check severity object: R/I/C three values + three reason fields + score + cvss + level + vuln_id | All 10 fields filled, reason ≠ empty string |
| G8 | **Prerequisites declared** | Check prerequisite_conditions: auth_requirement + bypass_method + other_preconditions + exploitability_judgment | All 4 sub-items filled; auth_requirement consistent with auth_matrix |

---

## Downgrade Rule Self-Check

| Condition | Automatic Downgrade Action | Check Method |
|-----------|---------------------------|--------------|
| `exploitability_judgment = "not_exploitable"` | final_verdict maximum `potential`, confidence maximum `low` | Confirm status ≠ confirmed/suspected |
| `exploitability_judgment = "conditionally_exploitable"` | severity.complexity drops 1 level | Confirm C value has been downgraded |
| EVID has `[Not Obtained]` annotation | status downgrades from `confirmed` to `suspected` | Confirm status ≠ confirmed |
| evidence_score < 7 | status MUST NOT be `confirmed` | Confirm status ≠ confirmed |

---

## Usage

Each Auditor's prompt SHOULD reference this file at the end:

```
## Pre-Submission Self-Check (MUST Execute)

After completing exploit JSON writing, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute universal 8 items (G1-G8), continue only after all ✅
2. Execute specialized self-check items below (S1-S3), submit only after all ✅
3. Any item ❌ → correct and re-check, MUST NOT skip

### Specialized Self-Check (Specific to This Auditor)
- [ ] S1: [customized by each Auditor]
- [ ] S2: [customized by each Auditor]
- [ ] S3: [customized by each Auditor]
```
