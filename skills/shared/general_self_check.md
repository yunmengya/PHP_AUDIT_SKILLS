> **Skill ID**: S-108 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# General Pre-Submission Self-Check (G1-G8)

## Purpose

Define the 8 universal self-check items that every Phase-4 auditor MUST execute before submitting exploit JSON. Ensures consistent output quality and contract compliance across all 21 auditor types.

## Procedure

### Self-Check Workflow

1. Execute all 8 general items (G1-G8) below — continue only after all pass ✅
2. Execute the auditor-specific specialized checks (S1-S3, defined in each auditor's own file)
3. Any item ❌ → correct the issue and re-check; MUST NOT skip

### G1-G8 Universal Check Items

| # | Check Item | Check Method | Pass Criteria |
|---|-----------|--------------|---------------|
| G1 | **File exists and path is correct** | Run `ls $WORK_DIR/exploits/{sink_id}.json` to confirm file is written | File exists, size > 0 |
| G2 | **JSON Schema compliant** | Validate syntax with `cat exploits/{sink_id}.json \| python3 -m json.tool` | No JSON syntax errors |
| G3 | **Required fields complete** | Verify each one: `sink_id`, `vuln_type`, `specialist`, `status`, `confidence`, `evidence_score`, `severity`, `prerequisite_conditions`, `evidence`, `trace` | All present and non-empty |
| G4 | **EVID evidence chain complete** | Cross-check against the EVID list for this vulnerability type in `shared/evidence_contract.md` | Each EVID has an actual code snippet or `[Not Obtained: reason]` annotation |
| G5 | **evidence_score and severity consistent** | Per `shared/severity_rating.md` formula: score ≥ 2.10 → evidence_score ≥ 7; 1.20-2.09 → 4-6; < 1.20 → 1-3 | Numeric ranges match |
| G6 | **HTTP evidence format correct** | Burp-style format: includes complete Request (with Host/Cookie headers) and Response (with Status Line + Body excerpt) | Not truncated, not fabricated, includes timestamp |
| G7 | **Severity 3D scoring complete** | Check `severity` object: R/I/C three values + three reason fields + score + cvss + level + vuln_id | All 10 fields filled, reason ≠ empty string |
| G8 | **Prerequisites declared** | Check `prerequisite_conditions`: auth_requirement + bypass_method + other_preconditions + exploitability_judgment | All 4 sub-items filled; auth_requirement consistent with auth_matrix |

### Automatic Downgrade Rules

If self-check reveals any of the following conditions, apply the corresponding downgrade:

| Condition | Automatic Downgrade Action | Verification |
|-----------|---------------------------|--------------|
| `exploitability_judgment = "not_exploitable"` | `final_verdict` maximum `potential`, `confidence` maximum `low` | Confirm status ≠ confirmed/suspected |
| `exploitability_judgment = "conditionally_exploitable"` | `severity.complexity` drops 1 level | Confirm C value has been downgraded |
| EVID has `[Not Obtained]` annotation | `status` downgrades from `confirmed` to `suspected` | Confirm status ≠ confirmed |
| `evidence_score < 7` | `status` MUST NOT be `confirmed` | Confirm status ≠ confirmed |

### Usage in Auditor Files

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

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/general_self_check.md`
