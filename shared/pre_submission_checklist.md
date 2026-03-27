# Universal Pre-Submission Checklist

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-110 |
| Category | Shared Protocol |
| Responsibility | Mandatory self-check every agent MUST complete before submitting output — catch errors before QC |

> **Design philosophy**: Move validation LEFT — agent self-checks before submission, reducing wasted QC redo cycles.
> Phase-4 auditors use `shared/auditor_self_check.md` (G1-G8 + S1-S3) which is a superset of this checklist.
> All other agents (Phase-2 scanners, Phase-3 trace, Phase-4.5 correlation, Phase-5 report) use THIS checklist.

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-PRE-1 | ALL checklist items MUST be filled with ✅ or ❌ — blank cells = QC FAIL | Unchecked output submitted |
| CR-PRE-2 | ANY ❌ item MUST be fixed before submission — MUST NOT submit with ❌ | Known-bad output wastes QC cycle |
| CR-PRE-3 | This checklist MUST be the LAST step before output submission (after all Fill-in Procedures complete) | Premature submission before validation |

## Fill-in Procedure

### Pre-Submission Checklist (MANDATORY — fill BEFORE output)

| # | Check Item | Expected | Your Result | Pass |
|---|-----------|----------|-------------|------|
| P1 | **JSON syntax valid** | No trailing commas, proper brackets, valid UTF-8 | {describe: ran json.tool / manual check} | {✅/❌} |
| P2 | **All required fields present** | Per Output Contract — every required field filled | {list any missing fields, or "all present"} | {✅/❌} |
| P3 | **Zero placeholder text** | No `【填写】`, `TODO`, `TBD`, `PLACEHOLDER`, `XXX` | {count found, or "0 found"} | {✅/❌} |
| P4 | **File:line citations verified** | Every cited file exists; line numbers are accurate | {count verified / total citations} | {✅/❌} |
| P5 | **Output saved to correct path** | Path matches Output Contract exactly | {actual path written} | {✅/❌} |
| P6 | **Degradation check completed** | Step 0 table filled (per `shared/degradation_check.md`) | {done / N/A if Phase-1 agent} | {✅/❌} |
| P7 | **No fabricated data** | Every claim backed by source code or tool output | {describe evidence basis} | {✅/❌} |
| P8 | **Field value ranges valid** | Enums use allowed values; numbers in valid ranges | {describe: checked against schema} | {✅/❌} |

### On ❌ Failure

| Scenario | Action |
|----------|--------|
| P1 ❌ (invalid JSON) | Fix syntax error; re-validate with `python3 -m json.tool` |
| P2 ❌ (missing fields) | Add missing fields with correct values from source data |
| P3 ❌ (placeholders remain) | Replace every placeholder with actual computed value |
| P4 ❌ (bad citation) | Re-read the file; correct line number or mark `[Needs Verification]` |
| P5 ❌ (wrong path) | Move/rename output file to correct path per Output Contract |
| P6 ❌ (degradation unchecked) | Go back to Step 0; fill degradation table first |
| P7 ❌ (fabricated data) | Remove unsupported claims; add `[Not Obtained: reason]` annotation |
| P8 ❌ (invalid values) | Correct to valid enum/range values per schema definition |

## Integration Template

Each non-auditor agent MUST add the following section before their Output Contract:

```markdown
## Pre-Submission Checklist (MUST Execute)

Before submitting output, complete the self-check per `shared/pre_submission_checklist.md`:

| # | Check Item | Your Result | Pass |
|---|-----------|-------------|------|
| P1 | JSON syntax valid | {result} | {✅/❌} |
| P2 | All required fields present | {result} | {✅/❌} |
| P3 | Zero placeholder text | {result} | {✅/❌} |
| P4 | File:line citations verified | {result} | {✅/❌} |
| P5 | Output saved to correct path | {result} | {✅/❌} |
| P6 | Degradation check completed | {result} | {✅/❌} |
| P7 | No fabricated data | {result} | {✅/❌} |
| P8 | Field value ranges valid | {result} | {✅/❌} |

ANY ❌ → fix before submitting. MUST NOT submit with ❌.
```

## Examples

### ✅ GOOD: All Checks Pass

```
Pre-Submission Checklist:
| # | Check Item | Your Result | Pass |
| P1 | JSON syntax valid | Validated with python3 -m json.tool, no errors | ✅ |
| P2 | All required fields present | 12/12 required fields filled | ✅ |
| P3 | Zero placeholder text | grep found 0 matches | ✅ |
| P4 | File:line citations verified | 8/8 citations verified against source files | ✅ |
| P5 | Output saved to correct path | $WORK_DIR/route_map.json | ✅ |
| P6 | Degradation check completed | Step 0 done, no degradation detected | ✅ |
| P7 | No fabricated data | All routes extracted from actual source code | ✅ |
| P8 | Field value ranges valid | Methods: GET/POST (valid); auth_level: public/user/admin (valid) | ✅ |
```
All items pass, safe to submit ✅

### ❌ BAD: Submitting with Failures

```
Pre-Submission Checklist:
| # | Check Item | Your Result | Pass |
| P1 | JSON syntax valid | | |
| P2 | All required fields present | 10/12 filled | ❌ |
| P3 | Zero placeholder text | 2 TODO found | ❌ |
```
Violates CR-PRE-1 (P1 not filled), CR-PRE-2 (submitted with P2 and P3 as ❌) ❌
