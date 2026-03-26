> **Skill ID**: S-074 | **Phase**: 4.5 | **Category**: Correlation Rule
> **Input**: exploit_results/*.json, priority_queue.json
> **Output**: correlation_findings.json (appended)

# Cross-Auditor Attack Chains

## Identity

Correlation rule skill for cross-auditor attack chains. Part of the correlation engine (Phase 4.5).

These rules handle cases where **independent findings from different auditors combine to form a complete attack chain**. Individual auditors can only see their own vulnerability types; this skill correlates across auditor boundaries to discover chains that no single auditor could identify alone.

Refer to `shared/attack_chains.md` for the complete attack chain pattern library and chain template definitions.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level, auditor_id |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Shared findings | `$WORK_DIR/audit_session.db → shared_findings` | YES | auditor_id, vuln_type, severity, endpoint |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Attack chain patterns | `${SKILL_DIR}/shared/attack_chains.md` | YES | chain templates, pattern definitions |

## Fill-in Procedure

### Step 1: Load and Group Findings by Auditor

1. Read all auditor findings from the shared findings store:
   ```bash
   bash tools/audit_db.sh finding-read "$WORK_DIR"
   ```
2. Group findings by `auditor_id`
3. Build a cross-reference index of all findings by `(vuln_type, endpoint, sink_type)`

### Step 2: Evaluate Known Cross-Auditor Chain Patterns

Check each of the following chain patterns against the grouped findings:

#### Chain 1: SQLi → SSTI (SQL Injection → Server-Side Template Injection)

- **Trigger**: SQLi auditor discovers SQL injection + XSS auditor discovers template rendering sink (Twig/Blade/Smarty raw output)
- **Correlation logic**: If SQLi can control database content, and that content is rendered unescaped by the template engine (`{{ var|raw }}`, `{!! $var !!}`), the attacker can write template payload via SQLi to trigger SSTI → RCE
- **Escalation**: Medium(SQLi read-only) + Low(template info) → **Critical (RCE)**
- **Example**:
  ```
  SQLi auditor: /api/profile?sort=name' UNION SELECT '{{7*7}}' --
  XSS auditor: /dashboard renders user.bio via Twig {{ bio|raw }}
  → Chain: SQLi writes bio='{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}' → SSTI RCE
  ```

#### Chain 2: SSRF → Docker RCE (SSRF + Docker Exposed Port)

- **Trigger**: SSRF auditor discovers SSRF reachable to internal network + Config auditor discovers Docker API port exposed (2375/2376 unauthenticated)
- **Correlation logic**: SSRF can access `http://172.17.0.1:2375`, Docker Remote API has no authentication → create privileged container → mount host / → host RCE
- **Escalation**: Medium(SSRF internal only) + Info(Docker port exposed) → **Critical (Host RCE)**
- **Example**:
  ```
  SSRF auditor: /fetch?url= can request internal network 172.17.0.0/16
  Config auditor: docker-compose.yml exposes port 2375, DOCKER_TLS_VERIFY not set
  → Chain: SSRF → http://172.17.0.1:2375/containers/create (privileged:true, Binds:["/:/host"])
           → /containers/{id}/start → chroot /host → full host control
  ```

#### Chain 3: LFI + Log Writable → Log Poisoning RCE

- **Trigger**: LFI auditor discovers file include vulnerability (`include($_GET['page'])` etc.) + RCE auditor discovers log file is writable and path is known
- **Correlation logic**: Attacker first injects PHP code into the log via User-Agent/Referer, then uses LFI to include the log file to trigger code execution
- **Escalation**: Medium(LFI limited) + Low(log path known) → **Critical (RCE)**
- **Example**:
  ```
  LFI auditor: /view?page=../../etc/passwd can read arbitrary files
  RCE auditor: access.log path /var/log/apache2/access.log, readable by www-data
  → Chain: curl -A '<?php system($_GET["c"]); ?>' http://target/
           → /view?page=../../var/log/apache2/access.log&c=id
           → RCE via log poisoning
  ```

For each matched chain, fill in:

| Field | Value |
|-------|-------|
| `pattern_name` | `cross_auditor_chain::<chain_name>` (e.g., `cross_auditor_chain::sqli_to_ssti`) |
| `condition_a.finding_id` | Finding ID from auditor A |
| `condition_a.vuln_type` | Vulnerability type from auditor A |
| `condition_a.original_severity` | Original severity from auditor A |
| `condition_b.finding_id` | Finding ID from auditor B |
| `condition_b.vuln_type` | Vulnerability type from auditor B |
| `condition_b.original_severity` | Original severity from auditor B |
| `combined_severity` | Escalated severity (typically Critical) |
| `combined_impact` | Description of the full attack chain impact |
| `explanation` | Step-by-step reasoning for the chain |

### Step 3: Sink-Source Bridging

Beyond the known patterns above, perform generic cross-auditor correlation:

1. Check whether auditor A's output/sink has a data flow relationship with auditor B's input/source
2. Use Config auditor's environment findings (ports, permissions, middleware configuration) as enabler conditions for chain feasibility

### Step 4: Chain Confidence Assessment

For each discovered chain, assign a confidence level:

| Confidence | Criteria | Action |
|-----------|----------|--------|
| `confirmed` | Both endpoint findings are confirmed AND data flow is verifiable | Escalate directly |
| `probable` | One end confirmed + one end potential, logical chain holds | Mark as high-priority candidate |
| `speculative` | Both ends are potential, or data flow requires additional conditions | Record only, do NOT escalate |

### Step 5: Deduplication

If the same chain is already covered by the severity escalation rules (S-070) — e.g., SSRF→Cloud Takeover — use the higher severity determination and do NOT record duplicates.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | Append to `escalations` array with `cross_auditor_chain::` prefix |

### Output Schema (per chain entry)

```json
{
  "pattern_name": "cross_auditor_chain::<chain_name>",
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
  "explanation": "string",
  "confidence": "confirmed | probable | speculative"
}
```

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| shared_findings table not accessible | Fall back to reading exploit result files directly |
| attack_chains.md not available | Use only the built-in chain patterns defined in this skill |

## Constraints

- MUST NOT downgrade confirmed vulnerabilities
- Escalated severity MUST be supported by clear combinatorial logic
- `speculative` confidence chains MUST NOT trigger severity escalation — record only
- If a chain duplicates a Rule Category 1 (S-070) pattern, use the higher severity and do NOT create duplicate entries
