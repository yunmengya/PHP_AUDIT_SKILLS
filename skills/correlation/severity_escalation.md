> **Skill ID**: S-070 | **Phase**: 4.5 | **Category**: Correlation Rule
> **Input**: exploit_results/*.json, priority_queue.json
> **Output**: correlation_findings.json (appended)

# Severity Escalation Rules

## Identity

Correlation rule skill for severity escalation patterns. Part of the correlation engine (Phase 4.5).

These rules detect cases where individually low/medium-risk findings combine to produce a higher-severity impact. The correlation engine orchestrator (S-069) dispatches this skill to scan all confirmed findings for escalation-eligible combinations.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Shared findings | `$WORK_DIR/audit_session.db → shared_findings` | YES | auditor_id, vuln_type, severity, endpoint |
| Auth matrix | `$WORK_DIR/auth_matrix.json` | NO | auth_level, roles |
| Attack memory graph | `$WORK_DIR/attack_memory.db` | NO | memory_nodes, memory_edges (enables, escalates_to) |

## Fill-in Procedure

### Step 1: Build Vulnerability Index

1. Load all exploit results from `$WORK_DIR/exploits/*.json`
2. Build an index keyed by `(vuln_type, endpoint, severity)`
3. Load shared findings from the database grouped by `auditor_id`

### Step 2: Evaluate Escalation Patterns

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

| Field | Value |
|-------|-------|
| `pattern_name` | Pattern name from table |
| `condition_a.finding_id` | Finding ID satisfying Condition A |
| `condition_a.vuln_type` | Vulnerability type of Condition A |
| `condition_a.original_severity` | Original severity of Condition A |
| `condition_b.finding_id` | Finding ID satisfying Condition B |
| `condition_b.vuln_type` | Vulnerability type of Condition B |
| `condition_b.original_severity` | Original severity of Condition B |
| `combined_severity` | Escalated Severity from table |
| `combined_impact` | Combined Impact from table |
| `explanation` | Reasoning for why these findings combine to escalate |

### Step 3: Graph-Based Escalation (if attack_memory.db available)

Consume graph data from `attack_memory.db` to discover additional escalation patterns:

1. **Prerequisite chains** — iterate `enables` edges:
   - If `source_node.status = "confirmed"` (prerequisite is satisfied)
   - Check whether `target_node` was marked as `not_exploitable` due to "prerequisite not met"
   - If so, reassess `target_node` exploitability as `"conditionally_exploitable"`
   - Output to `reassessment_candidates` array

2. **Combined severity** — iterate `escalates_to` edges:
   - Use the `combined_severity` field if already populated, or calculate:
     - High + Medium → Critical (if logical chain holds)
     - Medium + Medium → High
     - Medium + Low → Medium (flag only, do not escalate)
   - Append to the `escalations` array

### Step 4: Calculate New Combined Severity

For each escalation record, set `combined_severity` using the Escalated Severity column. The escalated severity MUST be supported by clear combinatorial logic.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | Append `escalations` array entries for this rule category |
| Reassessment candidates | `$WORK_DIR/correlation_findings.json` | Append `reassessment_candidates` array (from graph-based analysis) |

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

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| attack_memory.db not available | Skip Step 3 (graph-based escalation), proceed with pattern table only |
| Edges with `speculative` confidence | MUST NOT participate in escalation calculations; record in pattern_matches only |

## Constraints

- Escalated severity MUST be supported by clear combinatorial logic
- MUST NOT downgrade confirmed vulnerabilities
- Graph edges with `speculative` confidence MUST NOT participate in escalation calculations
