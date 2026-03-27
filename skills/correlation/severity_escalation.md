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

## Fill-in Procedure

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
| `explanation` | {Reasoning for why these findings combine to escalate} |

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
