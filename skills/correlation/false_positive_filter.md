> **Skill ID**: S-073 | **Phase**: 4.5 | **Category**: Correlation Rule
> **Input**: exploit_results/*.json, priority_queue.json
> **Output**: correlation_findings.json (appended)

# False Positive Filter

## Identity

Correlation rule skill for filtering false positives. Part of the correlation engine (Phase 4.5).

These rules compare confirmed findings against known false positive patterns, framework-level protections, and global WAF/middleware configurations to flag suspected false positives for manual review. This skill MUST NOT auto-downgrade any confirmed vulnerability — it SHALL only flag warnings.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| False positive patterns | `${SKILL_DIR}/shared/false_positive_patterns.md` | YES | pattern definitions, framework protections |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |

## Fill-in Procedure

### Step 1: Load Confirmed Findings

1. Load all exploit results from `$WORK_DIR/exploits/*.json`
2. Filter to findings with `final_verdict = "confirmed"`
3. Load the false positive pattern library from `shared/false_positive_patterns.md`

### Step 2: Check Against Known False Positive Patterns

For each confirmed finding:

1. Compare the finding's characteristics against each pattern in `shared/false_positive_patterns.md`
2. If a match is found, create a false positive warning entry

| Field | Value |
|-------|-------|
| `finding_id` | ID of the confirmed finding |
| `reason` | Why this finding may be a false positive |
| `matched_pattern` | Name of the matched false positive pattern |

### Step 3: Check Framework-Level Protections

Check whether built-in framework protections were overlooked by the auditor:

- Laravel: CSRF middleware globally enabled (`VerifyCsrfToken` in `$middlewareGroups`)
- Symfony: CSRF protection via form component
- CodeIgniter: Global XSS filtering enabled
- WordPress: Nonce verification patterns
- Other framework-specific global protections

If a finding contradicts an active framework protection, flag it:

| Field | Value |
|-------|-------|
| `finding_id` | ID of the finding |
| `reason` | "Framework protection X is globally enabled, which should prevent this vulnerability" |
| `matched_pattern` | `framework_protection::<framework_name>::<protection_type>` |

### Step 4: Check Global WAF/Middleware Blocking

Check whether a global WAF or middleware has blocked the attack but the auditor did not account for it:

1. Look for evidence of WAF/middleware in the application configuration
2. If the exploit evidence shows the payload was blocked (HTTP 403, WAF error page, etc.) but the finding is still marked `confirmed`, flag it

| Field | Value |
|-------|-------|
| `finding_id` | ID of the finding |
| `reason` | "Global WAF/middleware appears to block this attack vector" |
| `matched_pattern` | `waf_blocked::<waf_type>` |

### Step 5: Same Root Cause Deduplication

1. Group all confirmed findings by `(vuln_type, root_cause_file, root_cause_line)` or `(vuln_type, shared_function)`
2. If multiple findings share the same root cause (e.g., all pass through the same unsanitized function), flag duplicates:

| Field | Value |
|-------|-------|
| `finding_id` | ID of the duplicate finding |
| `reason` | "Same root cause as finding X — shared vulnerable function/code path" |
| `matched_pattern` | `same_root_cause::<primary_finding_id>` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | Append `potential_false_positives` array entries |

### Output Schema (per false positive entry)

```json
{
  "finding_id": "string",
  "reason": "string",
  "matched_pattern": "string"
}
```

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| false_positive_patterns.md not available | Skip pattern matching, only perform framework/WAF checks |
| No confirmed findings to check | Skip entirely, report zero false positive warnings |

## Constraints

- MUST NOT downgrade confirmed vulnerabilities; SHALL only flag false positive warnings for manual confirmation
- MUST NOT auto-remove or auto-reclassify any finding
- Flagged findings retain their original severity until manual review
