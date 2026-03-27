# Cross-Auditor Attack Chains

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-070 |
| Category | Correlation |
| Responsibility | Correlate independent findings from different auditors to discover cross-auditor attack chains that no single auditor could identify alone |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level, auditor_id |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Shared findings | `$WORK_DIR/audit_session.db → shared_findings` | YES | auditor_id, vuln_type, severity, endpoint |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Attack chain patterns | `${SKILL_DIR}/shared/attack_chains.md` | YES | chain templates, pattern definitions |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT downgrade confirmed vulnerabilities | Existing confirmed severity is a floor, never a ceiling |
| CR-2 | Escalated severity MUST be supported by clear combinatorial logic | Unjustified escalation invalidates the entire chain finding |
| CR-3 | `speculative` confidence chains MUST NOT trigger severity escalation — record only | Speculative chains that escalate produce false critical alerts |
| CR-4 | If a chain duplicates a severity escalation rule (S-072) pattern, use the higher severity and do NOT create duplicate entries | Duplicate entries cause double-counting in the final report |

| CR-DEG | Step 0 Degradation Check MUST be completed before any processing — empty table = QC FAIL | Degraded data treated as complete |
| CR-REF | All cross-file ID references MUST be verified against source files before output — unverified references MUST be removed | Broken references cause downstream parse failures and phantom findings |
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

### Procedure A: Load and Group Findings by Auditor

1. Read all auditor findings from the shared findings store:
   ```bash
   bash tools/audit_db.sh finding-read "$WORK_DIR"
   ```
2. Group findings by `auditor_id`
3. Build a cross-reference index of all findings by `(vuln_type, endpoint, sink_type)`

### Procedure B: Evaluate Known Cross-Auditor Chain Patterns

Check each of the following chain patterns against the grouped findings:

#### Chain 1: SQLi → SSTI (SQL Injection → Server-Side Template Injection)

- **Trigger**: SQLi auditor discovers SQL injection + XSS auditor discovers template rendering sink (Twig/Blade/Smarty raw output)
- **Correlation logic**: If SQLi can control database content, and that content is rendered unescaped by the template engine (`{{ var|raw }}`, `{!! $var !!}`), the attacker can write template payload via SQLi to trigger SSTI → RCE
- **Escalation**: Medium(SQLi read-only) + Low(template info) → **Critical (RCE)**

#### Chain 2: SSRF → Docker RCE (SSRF + Docker Exposed Port)

- **Trigger**: SSRF auditor discovers SSRF reachable to internal network + Config auditor discovers Docker API port exposed (2375/2376 unauthenticated)
- **Correlation logic**: SSRF can access `http://172.17.0.1:2375`, Docker Remote API has no authentication → create privileged container → mount host / → host RCE
- **Escalation**: Medium(SSRF internal only) + Info(Docker port exposed) → **Critical (Host RCE)**

#### Chain 3: LFI + Log Writable → Log Poisoning RCE

- **Trigger**: LFI auditor discovers file include vulnerability (`include($_GET['page'])` and similar include/require with user input) + RCE auditor discovers log file is writable and path is known
- **Correlation logic**: Attacker first injects PHP code into the log via User-Agent/Referer, then uses LFI to include the log file to trigger code execution
- **Escalation**: Medium(LFI limited) + Low(log path known) → **Critical (RCE)**

For each matched chain, fill in:

| Field | Fill-in Value |
|-------|--------------|
| `pattern_name` | {`cross_auditor_chain::<chain_name>`, e.g. `cross_auditor_chain::sqli_to_ssti`} |
| `condition_a.finding_id` | {Finding ID from auditor A} |
| `condition_a.vuln_type` | {Vulnerability type from auditor A} |
| `condition_a.original_severity` | {Original severity from auditor A} |
| `condition_b.finding_id` | {Finding ID from auditor B} |
| `condition_b.vuln_type` | {Vulnerability type from auditor B} |
| `condition_b.original_severity` | {Original severity from auditor B} |
| `combined_severity` | {Escalated severity — typically Critical for RCE chains} |
| `combined_impact` | {Description of the full attack chain impact} |
| `explanation` | {Step-by-step reasoning for the chain} |
| `confidence` | {`confirmed` / `probable` / `speculative` per Procedure D} |

### Procedure C: Sink-Source Bridging

Beyond the known patterns above, perform generic cross-auditor correlation:

1. Check whether auditor A's output/sink has a data flow relationship with auditor B's input/source
2. Use Config auditor's environment findings (ports, permissions, middleware configuration) as enabler conditions for chain feasibility
3. For each discovered bridge, fill in the same fields as Procedure B

### Procedure D: Chain Confidence Assessment

For each discovered chain, assign a confidence level:

| Field | Fill-in Value |
|-------|--------------|
| `confidence` | {One of the levels below based on criteria} |

| Confidence | Criteria | Action |
|-----------|----------|--------|
| `confirmed` | Both endpoint findings are confirmed AND data flow is verifiable | Escalate directly |
| `probable` | One end confirmed + one end potential, logical chain holds | Mark as high-priority candidate |
| `speculative` | Both ends are potential, or data flow requires additional conditions | Record only, do NOT escalate (CR-3) |

### Procedure E: Deduplication

If the same chain is already covered by the severity escalation rules (S-072) — e.g., SSRF→Cloud Takeover — use the higher severity determination and do NOT record duplicates (CR-4).

## Reference Integrity Check (MUST Execute)

Per `shared/reference_integrity_check.md`, verify all cross-file references before output:

| # | My Output Field | Value | Source File | Verified | Evidence |
|---|----------------|-------|-------------|----------|----------|
| 1 | {field} | {id value} | {source file} | {✅/❌} | {jq query result or line content} |

CR-REF-1: Any ❌ → remove from output. MUST NOT include unverified references.

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
| Correlation findings | `$WORK_DIR/correlation_findings.json` | See schema below | Append to `escalations` array with `cross_auditor_chain::` prefix |

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

## Examples

### ✅ GOOD: SQLi → SSTI Chain with Confirmed Confidence

```json
{
  "pattern_name": "cross_auditor_chain::sqli_to_ssti",
  "condition_a": {
    "finding_id": "sqli-auditor-f-001",
    "vuln_type": "SQL Injection",
    "original_severity": "Medium"
  },
  "condition_b": {
    "finding_id": "xss-auditor-f-012",
    "vuln_type": "Template Injection Sink",
    "original_severity": "Low"
  },
  "combined_severity": "Critical",
  "combined_impact": "SQLi writes template payload to user.bio via UNION SELECT → Twig renders bio with |raw → SSTI achieves RCE",
  "explanation": "SQLi auditor confirmed /api/profile?sort= allows UNION SELECT to write arbitrary data to user.bio column. XSS auditor confirmed /dashboard renders user.bio via Twig {{ bio|raw }} without escaping. Combined: attacker writes SSTI payload via SQLi → Twig executes → RCE.",
  "confidence": "confirmed"
}
```

Explanation: Both findings are independently confirmed. The data flow (SQLi writes DB → template reads DB) is verifiable. Escalation from Medium+Low to Critical is justified by RCE impact. ✅

### ❌ BAD: Speculative Chain Incorrectly Escalated

```json
{
  "pattern_name": "cross_auditor_chain::ssrf_to_docker_rce",
  "condition_a": {
    "finding_id": "ssrf-auditor-f-003",
    "vuln_type": "SSRF",
    "original_severity": "Medium"
  },
  "condition_b": {
    "finding_id": "config-auditor-f-007",
    "vuln_type": "Docker Port Exposed",
    "original_severity": "Info"
  },
  "combined_severity": "Critical",
  "combined_impact": "SSRF reaches Docker API → host RCE",
  "explanation": "SSRF might reach internal network, Docker port might be exposed",
  "confidence": "speculative"
}
```

What's wrong: Confidence is `speculative` but `combined_severity` is set to `Critical`. CR-3 forbids severity escalation for speculative chains — they must be recorded only. The explanation uses hedging language ("might") confirming neither finding is verified. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| shared_findings table not accessible | Fall back to reading exploit result files directly |
| attack_chains.md not available | Use only the built-in chain patterns defined in this skill |
