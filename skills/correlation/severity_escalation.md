# Severity Escalation Rules

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-072 |
| Category | Correlation |
| Responsibility | Detect cases where individually low/medium-risk findings combine to produce a higher-severity impact and escalate accordingly |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Shared findings | `$WORK_DIR/audit_session.db → shared_findings` | YES | auditor_id, vuln_type, severity, endpoint |
| Auth matrix | `$WORK_DIR/auth_matrix.json` | NO | auth_level, roles |
| Attack memory graph | `$WORK_DIR/attack_memory.db` | NO | memory_nodes, memory_edges (enables, escalates_to) |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Escalated severity MUST be supported by clear combinatorial logic | Unjustified escalation produces inflated severity scores and erodes report credibility |
| CR-2 | MUST NOT downgrade confirmed vulnerabilities | Downgrading removes real risks from the report, causing missed findings |
| CR-3 | Graph edges with `speculative` confidence MUST NOT participate in escalation calculations | Speculative edges that escalate produce false critical alerts and noise |

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

### Procedure A: Build Vulnerability Index

1. Load all exploit results from `$WORK_DIR/exploits/*.json`
2. Build an index keyed by `(vuln_type, endpoint, severity)`
3. Load shared findings from the database grouped by `auditor_id`

### Procedure B: Evaluate Escalation Patterns

Iterate through each pattern in the table below. For each pattern, check whether **both** Condition A and Condition B are satisfied by existing findings:

| Pattern Name | Condition A | Condition B | Combined Impact | Escalated Severity |
|--------------|-------------|-------------|-----------------|-------------------|
| Mass Account Takeover | User enumeration (Info/Low) | No rate limiting + weak password policy (Low) | Can brute-force all users in bulk | High/Critical |
| Session Hijacking Chain | Reflected XSS (Medium) | No HttpOnly Cookie + no CSP (Low) | Cookie theft → session takeover | High |
| SSRF → Cloud Takeover | SSRF internal only (Medium) | Cloud environment (AWS/GCP/Azure) | Metadata → IAM → cloud resource takeover | Critical |
| Info→Credential→Full Control | Config leak (.env/phpinfo) (High) | Admin panel reachable + RCE Sink exists | .env keys→admin login→RCE | Critical |
| Read-only SQL→RCE | SQL injection (read-only permission) (High) | FILE privilege + web-writable directory | SQL write file→Webshell→RCE | Critical |
| Registration Privilege Escalation | Mass Assignment (Medium) | No email verification + no approval process | Self-register as admin | Critical |
| CSRF→Admin Operations | CSRF Token missing (Medium) | Admin can execute dangerous operations (Info) | Trick admin→arbitrary operations | High |
| Weak Crypto→Forgery | Predictable Token (Medium) | Token used for password reset (Info) | Predict reset Token→account takeover | Critical |
| Race Condition→Financial Loss | Race condition (Medium) | Payment/transfer functionality (Info) | Balance double spending | Critical |
| Second-Order Data Flow | Store point unfiltered (Low) | Use point unfiltered (Low) | Second-order injection | High/Critical |

For each matched pattern, fill in:

| Field | Fill-in Value |
|-------|--------------|
| `pattern_name` | {Pattern name from the table above} |
| `condition_a.finding_id` | {Finding ID satisfying Condition A} |
| `condition_a.vuln_type` | {Vulnerability type of Condition A} |
| `condition_a.original_severity` | {Original severity of Condition A} |
| `condition_b.finding_id` | {Finding ID satisfying Condition B} |
| `condition_b.vuln_type` | {Vulnerability type of Condition B} |
| `condition_b.original_severity` | {Original severity of Condition B} |
| `combined_severity` | {Escalated Severity from the pattern table — must be justified per CR-1} |
| `combined_impact` | {Combined Impact description from the pattern table} |
| `explanation` | {Use mandatory format below} |

**Explanation Mandatory Format** (CR-ESC):

The `explanation` field MUST follow this template — free-form paragraphs are QC FAIL:

```
"[Finding_A_ID] at [endpoint_A] provides [capability_A] (evidence: [EVID_ref_A]).
 [Finding_B_ID] at [endpoint_B] provides [capability_B] (evidence: [EVID_ref_B]).
 Combined: attacker can [step_1] → [step_2] → [final_outcome].
 Escalation justified because [neither finding alone achieves final_outcome]."
```

| Pattern Name | Explanation Template Example |
|-------------|----------------------------|
| Mass Account Takeover | "[F-001] at /api/users provides user list of {N} accounts. [F-002] at /login has no rate limit. Combined: attacker can enumerate → brute-force → takeover all {N} accounts. Escalation justified because enumeration alone is informational and no-rate-limit alone is low risk." |
| Session Hijacking Chain | "[F-003] at /search provides reflected XSS execution. [F-004] shows no HttpOnly flag on session cookie. Combined: attacker can inject script → steal cookie → hijack session. Escalation justified because XSS alone requires cookie access and missing HttpOnly alone has no direct exploit." |
| SSRF → Cloud Takeover | "[F-005] at /proxy provides SSRF to internal network. [F-006] confirms AWS environment. Combined: attacker can request 169.254.169.254 → get IAM credentials → control cloud resources. Escalation justified because SSRF to internal-only is medium and cloud env info is informational." |

### Procedure C: Graph-Based Escalation (if attack_memory.db available)

Consume graph data from `attack_memory.db` to discover additional escalation patterns:

1. **Prerequisite chains** — iterate `enables` edges:
   - If `source_node.status = "confirmed"` (prerequisite is satisfied)
   - Check whether `target_node` was marked as `not_exploitable` due to "prerequisite not met"
   - If so, reassess `target_node` exploitability as `"conditionally_exploitable"`
   - Output to `reassessment_candidates` array

2. **Combined severity** — iterate `escalates_to` edges (skip `speculative` confidence per CR-3):
   - Use the `combined_severity` field if already populated, or calculate:
     - High + Medium → Critical (if logical chain holds)
     - Medium + Medium → High
     - Medium + Low → Medium (flag only, do not escalate)
   - Append to the `escalations` array

### Procedure D: Calculate New Combined Severity

For each escalation record, set `combined_severity` using the Escalated Severity column. The escalated severity MUST be supported by clear combinatorial logic (CR-1).

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
| Correlation findings (escalations) | `$WORK_DIR/correlation_findings.json` | See schema below | Append `escalations` array entries for this rule category |
| Reassessment candidates | `$WORK_DIR/correlation_findings.json` | See schema below | Append `reassessment_candidates` array (from graph-based analysis) |

### Output Schema (per escalation entry)

```json
{
  "pattern_name": "string",
  "condition_a": {
    "finding_id": "string",
    "vuln_type": "string",
    "original_severity": "string"
  },
  "condition_b": {
    "finding_id": "string",
    "vuln_type": "string",
    "original_severity": "string"
  },
  "combined_severity": "string",
  "combined_impact": "string",
  "explanation": "string"
}
```

## Examples

### ✅ GOOD: SSRF → Cloud Takeover Escalation

```json
{
  "pattern_name": "SSRF → Cloud Takeover",
  "condition_a": {
    "finding_id": "ssrf-auditor-f-003",
    "vuln_type": "SSRF (internal only)",
    "original_severity": "Medium"
  },
  "condition_b": {
    "finding_id": "config-auditor-f-011",
    "vuln_type": "Cloud Environment Detected (AWS EC2)",
    "original_severity": "Info"
  },
  "combined_severity": "Critical",
  "combined_impact": "SSRF can reach AWS metadata endpoint 169.254.169.254 → retrieve IAM credentials → full cloud resource takeover",
  "explanation": "SSRF auditor confirmed /proxy?url= can request internal IPs. Config auditor identified AWS EC2 environment with IMDSv1 enabled (no token required). Combined: attacker uses SSRF to fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/ → obtains IAM role credentials → accesses S3, RDS, and other AWS services."
}
```

Explanation: Both conditions are confirmed findings. The escalation from Medium+Info to Critical is justified by the clear chain from SSRF → metadata → IAM → cloud takeover. The explanation provides step-by-step combinatorial logic per CR-1. ✅

### ❌ BAD: Escalation Without Combinatorial Logic

```json
{
  "pattern_name": "Session Hijacking Chain",
  "condition_a": {
    "finding_id": "xss-auditor-f-007",
    "vuln_type": "Reflected XSS",
    "original_severity": "Medium"
  },
  "condition_b": {
    "finding_id": "config-auditor-f-015",
    "vuln_type": "Missing HttpOnly Cookie Flag",
    "original_severity": "Low"
  },
  "combined_severity": "Critical",
  "combined_impact": "XSS + no HttpOnly = bad",
  "explanation": "Both vulnerabilities exist so severity is escalated"
}
```

What's wrong: (1) `combined_severity` is set to Critical, but the pattern table specifies High for this combination — violates CR-1. (2) The `explanation` provides no combinatorial logic ("both exist so escalated" is not reasoning). (3) The `combined_impact` is vague and unhelpful. A valid explanation must describe the attack chain: XSS executes JavaScript → reads document.cookie (no HttpOnly) → sends to attacker → session takeover. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| attack_memory.db not available | Skip Procedure C (graph-based escalation), proceed with pattern table only |
| Edges with `speculative` confidence | MUST NOT participate in escalation calculations; record in pattern_matches only |
