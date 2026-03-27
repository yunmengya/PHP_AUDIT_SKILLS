# False Positive Filter

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-071 |
| Category | Correlation |
| Responsibility | Flag suspected false positives by comparing confirmed findings against known FP patterns, framework protections, and WAF/middleware configurations |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| False positive patterns | `${SKILL_DIR}/shared/false_positive_patterns.md` | YES | pattern definitions, framework protections |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT downgrade confirmed vulnerabilities — SHALL only flag false positive warnings for manual confirmation | Auto-downgrading removes real vulnerabilities from the report, causing missed findings |
| CR-2 | MUST NOT auto-remove or auto-reclassify any finding | Removing findings without human review violates audit integrity |
| CR-3 | Flagged findings retain their original severity until manual review | Premature severity changes corrupt the severity distribution in the final report |

| CR-DEG | Step 0 Degradation Check MUST be completed before any processing — empty table = QC FAIL | Degraded data treated as complete |
| CR-PRE | Pre-Submission Checklist MUST be completed before output — any ❌ MUST be fixed before submitting | Known-bad output wastes QC cycle |
## Fill-in Procedure

### Step 0 — Upstream Degradation Check (MANDATORY)

Per `shared/degradation_check.md`, fill the degradation status table before any data processing:

| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-2 | PHASE2_DEGRADED | {true/false/not_set} | {files consumed from this phase} |
| Phase-3 | PHASE3_DEGRADED | {true/false/not_set} | {files consumed from this phase} |
| Phase-4 | PHASE4_DEGRADED | {true/false/not_set} | {files consumed from this phase} |

IF any Value = true → apply Degradation Enforcement Rules (cap verdicts at "suspected", add [DEGRADED INPUT] prefix).

### Procedure A: Load Confirmed Findings

1. Load all exploit results from `$WORK_DIR/exploits/*.json`
2. Filter to findings with `final_verdict = "confirmed"`
3. Load the false positive pattern library from `shared/false_positive_patterns.md`

### Procedure B: Check Against Known False Positive Patterns

For each confirmed finding, compare the finding's characteristics against each pattern in `shared/false_positive_patterns.md`. If a match is found, fill in:

| Field | Fill-in Value |
|-------|--------------|
| `finding_id` | {ID of the confirmed finding} |
| `reason` | {Why this finding may be a false positive — reference the matched pattern} |
| `matched_pattern` | {Name of the matched false positive pattern from the pattern library} |

### Procedure C: Check Framework-Level Protections

Check whether built-in framework protections were overlooked by the auditor:

- Laravel: CSRF middleware globally enabled (`VerifyCsrfToken` in `$middlewareGroups`)
- Symfony: CSRF protection via form component
- CodeIgniter: Global XSS filtering enabled
- WordPress: Nonce verification patterns
- Other framework-specific global protections

If a finding contradicts an active framework protection, fill in:

| Field | Fill-in Value |
|-------|--------------|
| `finding_id` | {ID of the finding} |
| `reason` | {"Framework protection X is globally enabled, which should prevent this vulnerability"} |
| `matched_pattern` | {`framework_protection::<framework_name>::<protection_type>`} |

### Procedure D: Check Global WAF/Middleware Blocking

Check whether a global WAF or middleware has blocked the attack but the auditor did not account for it:

1. Look for evidence of WAF/middleware in the application configuration
2. If the exploit evidence shows the payload was blocked (HTTP 403, WAF error page, rate limit response, CAPTCHA challenge) but the finding is still marked `confirmed`, fill in:

| Field | Fill-in Value |
|-------|--------------|
| `finding_id` | {ID of the finding} |
| `reason` | {"Global WAF/middleware appears to block this attack vector"} |
| `matched_pattern` | {`waf_blocked::<waf_type>`} |

### Procedure E: Same Root Cause Deduplication

1. Group all confirmed findings by `(vuln_type, root_cause_file, root_cause_line)` or `(vuln_type, shared_function)`
2. If multiple findings share the same root cause (e.g., all pass through the same unsanitized function), flag duplicates:

| Field | Fill-in Value |
|-------|--------------|
| `finding_id` | {ID of the duplicate finding} |
| `reason` | {"Same root cause as finding X — shared vulnerable function/code path"} |
| `matched_pattern` | {`same_root_cause::<primary_finding_id>`} |

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

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | See schema below | Append `potential_false_positives` array entries |

### Output Schema (per false positive entry)

```json
{
  "finding_id": "string",
  "reason": "string",
  "matched_pattern": "string"
}
```

## Examples

### ✅ GOOD: Framework CSRF Protection Flags a CSRF Finding

```json
{
  "finding_id": "csrf-auditor-f-005",
  "reason": "Framework protection VerifyCsrfToken middleware is globally enabled in app/Http/Kernel.php $middlewareGroups['web'], which should prevent this CSRF vulnerability",
  "matched_pattern": "framework_protection::laravel::csrf_middleware"
}
```

Explanation: The finding is flagged (not removed or downgraded) with a clear reason referencing the specific framework protection. The original severity is preserved for manual review. Complies with CR-1 and CR-3. ✅

### ❌ BAD: Auto-Downgrading a Confirmed Finding

```json
{
  "finding_id": "xss-auditor-f-009",
  "reason": "CodeIgniter global XSS filtering is enabled",
  "matched_pattern": "framework_protection::codeigniter::xss_filter",
  "original_severity": "High",
  "adjusted_severity": "Info"
}
```

What's wrong: The output includes `adjusted_severity`, which auto-downgrades the finding from High to Info. CR-1 forbids downgrading confirmed vulnerabilities — this skill SHALL only flag warnings. The `adjusted_severity` field must not exist in the output. ❌

### ✅ GOOD: Same Root Cause Deduplication

```json
{
  "finding_id": "sqli-auditor-f-014",
  "reason": "Same root cause as finding sqli-auditor-f-002 — both pass through unsanitized function db_query() in app/Models/BaseModel.php:45",
  "matched_pattern": "same_root_cause::sqli-auditor-f-002"
}
```

Explanation: The duplicate is flagged with a clear reference to the primary finding and the shared root cause function. The finding is not removed, just flagged for manual review. ✅

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| false_positive_patterns.md not available | Skip pattern matching, only perform framework/WAF checks |
| No confirmed findings to check | Skip entirely, report zero false positive warnings |
