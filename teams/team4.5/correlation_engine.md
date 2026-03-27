# Correlation-Engine (Cross-Auditor Correlation Engine)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-069 |
| Phase | Phase-4.5 |
| Responsibility | Orchestrate 5 correlation sub-skills (S-070\~S-074) to aggregate auditor findings, discover combined-risk patterns, and identify overlooked correlated vulnerabilities |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `.audit_state/team4_progress.json` | Phase-4 QA | Yes | QA verification results, auditor completion status |
| `exploits/*.json` | Phase-4 Auditors | Yes | All attack results (sink_id, vuln_type, severity, status) |
| `audit_session.db → shared_findings` | Phase-4 Auditors | Yes | Real-time shared findings grouped by `auditor_id` |
| `second_order/store_points.jsonl` | Phase-3 | Yes | Store points: `table`, `column`, `sanitization`, `endpoint` |
| `second_order/use_points.jsonl` | Phase-3 | Yes | Use points: `table`, `column`, `sanitization`, `endpoint`, `context` |
| `attack_graph.json` | Phase-4 (if exists) | No | Pre-built attack graph edges and nodes |
| `route_map.json` | Phase-2 | Yes | All application routes for coverage analysis |
| `auth_matrix.json` | Phase-2 | Yes | Authorization matrix with `auth_level` per route |
| `priority_queue.json` | Phase-3 | Yes | All prioritized sinks (P0-P4) for coverage check |
| `shared/anti_hallucination.md` | Shared (L2) | Yes | Anti-hallucination rules |
| `shared/data_contracts.md` | Shared (L2) | Yes | Data format contracts |
| `shared/false_positive_patterns.md` | Shared (L2) | Yes | Known false positive patterns |
| `shared/attack_chains.md` | Shared (L2) | Yes | Complete attack chain pattern library |
| `shared/attack_memory_graph.md` | Shared (L2) | Yes | Graph memory schema definition |
| `attack_memory.db` (memory_nodes + memory_edges) | Phase-4 Auditors | No | Relational graph data written by auditors |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT downgrade confirmed vulnerabilities — only flag false positive warnings for manual confirmation | Downgrading → confirmed vulns silently disappear from report |
| CR-2 | Escalated severity MUST be supported by clear combinatorial logic (both conditions satisfied) | Unsupported escalation → false critical findings, credibility loss |
| CR-3 | Second-order candidates are candidates only — MUST NOT mark as confirmed without actual testing | Premature confirmation → false positives in final report |
| CR-4 | Coverage gaps ≠ vulnerability discovery — serve only as supplementary audit reference | Treating gaps as vulns → inflated report, wasted remediation effort |
| CR-5 | MUST NOT modify `memory_nodes`/`memory_edges` — graph writes are Phase-4 Auditor responsibility | Writing to graph → data corruption, audit integrity violation |
| CR-6 | Edges with `speculative` confidence MUST NOT participate in escalation calculations | Speculative escalation → unreliable severity, audit credibility loss |
| CR-7 | Cross-project graph queries MUST only be used for pattern suggestions, NOT severity determination | Severity from other projects → misleading risk assessment |
| CR-8 | Deduplication required — if a chain is covered by Rule Cat 1, use higher severity and do NOT record duplicates | Duplicates → double-counted vulns, inflated report |

## Severity Escalation Reference Patterns

| Pattern Name | Condition A | Condition B | Combined Impact | Escalated Severity |
|--------------|-------------|-------------|-----------------|-------------------|
| Mass Account Takeover | User enumeration (Info/Low) | No rate limiting + weak password policy (Low) | Brute-force all users in bulk | High/Critical |
| Session Hijacking Chain | Reflected XSS (Medium) | No HttpOnly Cookie + no CSP (Low) | Cookie theft → session takeover | High |
| SSRF → Cloud Takeover | SSRF internal only (Medium) | Cloud environment (AWS/GCP/Azure) | Metadata → IAM → cloud resource takeover | Critical |
| Info→Credential→Full Control | Config leak (.env/phpinfo) (High) | Admin panel reachable + RCE Sink exists | .env keys→admin login→RCE | Critical |
| Read-only SQL→RCE | SQL injection read-only (High) | FILE privilege + web-writable directory | SQL write file→Webshell→RCE | Critical |
| Registration Privilege Escalation | Mass Assignment (Medium) | No email verification + no approval | Self-register as admin | Critical |
| CSRF→Admin Operations | CSRF Token missing (Medium) | Admin can execute dangerous ops (Info) | Trick admin→arbitrary operations | High |
| Weak Crypto→Forgery | Predictable Token (Medium) | Token used for password reset (Info) | Predict reset Token→account takeover | Critical |
| Race Condition→Financial Loss | Race condition (Medium) | Payment/transfer functionality (Info) | Balance double spending | Critical |
| Second-Order Data Flow | Store point unfiltered (Low) | Use point unfiltered (Low) | Second-order injection | High/Critical |

## Cross-Auditor Attack Chain Reference

| Chain Name | Auditor A Finding | Auditor B Finding | Combined Result | Escalated Severity |
|------------|-------------------|-------------------|-----------------|-------------------|
| SQLi → SSTI | SQLi can control DB content (Medium) | Template renders DB field unescaped via Twig/Blade `raw` (Low) | SQLi writes template payload → SSTI → RCE | Critical |
| SSRF → Docker RCE | SSRF reaches internal network (Medium) | Docker API port 2375 exposed unauthenticated (Info) | SSRF → Docker API → privileged container → host RCE | Critical |
| LFI + Log Poisoning | LFI can include arbitrary files (Medium) | Log file writable + path known (Low) | Inject PHP into log via User-Agent → LFI includes log → RCE | Critical |

## Fill-in Procedure

### Procedure A: Data Aggregation

| Field | Fill-in Value |
|-------|--------------|
| all_findings | {Array of all findings loaded from `exploits/*.json` and `audit_session.db → shared_findings`} |
| vuln_index | {Index of findings grouped by `vuln_type` → array of finding objects} |
| endpoint_index | {Index of findings grouped by `endpoint` → array of finding objects} |
| severity_index | {Index of findings grouped by `severity` → array of finding objects} |
| total_findings_count | {Integer count of all loaded findings} |

### Procedure B: Severity Escalation Scan (dispatches S-070)

For each pattern in the Severity Escalation Reference table, check if both conditions are satisfied:

| Field | Fill-in Value |
|-------|--------------|
| pattern_name | {Name from the reference table, e.g., "Mass Account Takeover"} |
| condition_a_match | {Finding object matching Condition A, or `null` if not found} |
| condition_b_match | {Finding object matching Condition B, or `null` if not found} |
| both_satisfied | {`true` if both condition_a_match and condition_b_match are non-null} |
| combined_severity | {Escalated severity from reference table — only fill if `both_satisfied = true`} |
| combined_impact | {Combined impact description from reference table} |
| explanation | {Clear combinatorial logic explaining WHY escalation is justified — required per CR-2} |

→ Repeat this table for each matched pattern. Append all matched records to `escalations` array.

### Procedure C: Second-Order Correlation (dispatches S-071)

| Field | Fill-in Value |
|-------|--------------|
| store_use_pairs | {Array of matched `(table, column)` pairs between `store_points.jsonl` and `use_points.jsonl`} |

Per matched pair:

| Field | Fill-in Value |
|-------|--------------|
| table | {Matched table name} |
| column | {Matched column name} |
| store_sanitization | {Sanitization applied at store point: function name or `none`} |
| use_sanitization | {Sanitization applied at use point: function name or `none`} |
| sanitization_match | {`safe` \| `possibly_safe` \| `high_risk` — see decision matrix below} |
| sanitization_type_mismatch | {`true` if store uses HTML encoding but use expects SQL escaping (or similar cross-type mismatch)} |
| vuln_type | {`second_order_sqli` \| `stored_xss` \| `second_order_cmdi` \| etc.} |
| risk_level | {`high` \| `medium` \| `low`} |
| sanitization_gap | {Description of what sanitization is missing or mismatched} |

**Sanitization Decision Matrix:**
- Sanitized at store + sanitized at use = `safe`
- Sanitized at store + unsanitized at use = `possibly_safe`
- Unsanitized at store + sanitized at use = `possibly_safe`
- Unsanitized at store + unsanitized at use = `high_risk`

**Type Mismatch Rules:**
- `htmlspecialchars` at store + SQL concatenation at use = vulnerability
- `addslashes` at store + `system()` at use = vulnerability

### Procedure D: Coverage Gap Analysis (dispatches S-072)

| Field | Fill-in Value |
|-------|--------------|
| untested_admin_endpoints | {Array of routes where `auth_level=admin` in `auth_matrix.json` but no corresponding exploit result exists} |
| uncovered_sinks | {Array of sinks from `priority_queue.json` with no corresponding `exploits/*.json` result} |
| static_only_high_priority | {Array of P0/P1 sinks with only `potential_risk` annotation and no actual exploit testing} |
| cross_endpoint_flows | {Array of endpoint pairs where endpoint A's output feeds unsafely into endpoint B's input} |

Per gap:

| Field | Fill-in Value |
|-------|--------------|
| area | {Description of the uncovered area} |
| risk_level | {`critical` \| `high` \| `medium` \| `low`} |
| recommendation | {Specific recommendation for supplementary audit} |

### Procedure E: False Positive Detection (dispatches S-073)

| Field | Fill-in Value |
|-------|--------------|
| fp_pattern_matches | {Array of confirmed findings that match patterns in `shared/false_positive_patterns.md`} |

Per suspected false positive:

| Field | Fill-in Value |
|-------|--------------|
| finding_id | {ID of the confirmed finding suspected as false positive} |
| reason | {Why this finding may be a false positive} |
| matched_pattern | {Which pattern from `false_positive_patterns.md` it matches} |
| framework_protection | {Built-in framework protection that may have been overlooked, e.g., "Laravel CSRF middleware globally enabled"} |
| waf_blocked | {`true` if a global WAF/middleware blocked the attack but auditor did not account for it} |

⚠️ Per CR-1: Do NOT auto-downgrade. Flag with warning for manual confirmation only.

### Procedure F: Graph Memory Consumption (dispatches S-074 — executes after E, before G)

| Field | Fill-in Value |
|-------|--------------|
| graph_export_cmd | `bash tools/audit_db.sh graph-export "$WORK_DIR"` |
| graph_data | {Complete graph structure exported for the current project} |

#### F1: Data Flow Chain Discovery (`data_flows_to` edges)

| Field | Fill-in Value |
|-------|--------------|
| edge_relation | `data_flows_to` |
| source_node | {Node where `status = "confirmed"`} |
| target_node | {Node where `status ∈ {"confirmed", "suspected", "potential"}`} |
| chain_description | {e.g., "SQLi writes to users.bio (confirmed) → XSS renders users.bio (potential) → Stored XSS"} |
| escalated_priority | {New priority for target_node based on confirmed source} |

#### F2: Prerequisite Chain Discovery (`enables` edges)

| Field | Fill-in Value |
|-------|--------------|
| edge_relation | `enables` |
| source_node | {Confirmed prerequisite node} |
| target_node | {Node previously marked `not_exploitable` due to "prerequisite not met"} |
| reassessment | {`conditionally_exploitable` — recommend orchestrator retry this sink} |

#### F3: Combined Severity Calculation (`escalates_to` edges)

| Field | Fill-in Value |
|-------|--------------|
| edge_relation | `escalates_to` |
| node_a_severity | {Severity of source node} |
| node_b_severity | {Severity of target node} |
| combined_severity | {Calculated: High+Medium→Critical, Medium+Medium→High, Medium+Low→Medium (flag only)} |
| edge_confidence | {MUST be non-`speculative` per CR-6 to participate in escalation} |

#### F4: High-Value Data Object Discovery (`shares_data_object` edges)

| Field | Fill-in Value |
|-------|--------------|
| data_object | {Shared data object name, e.g., "users"} |
| vuln_count | {Number of vulnerability nodes sharing this data object (must be ≥ 3)} |
| vuln_types | {Array of distinct vuln types, e.g., `["sqli", "xss", "idor", "mass_assignment"]`} |
| max_severity | {Highest severity among associated nodes} |
| recommendation | {e.g., "The users table is a core attack surface; centralized verification of all CRUD paths is recommended"} |

#### F5: Cross-Project Pattern Matching

| Field | Fill-in Value |
|-------|--------------|
| framework | {Framework of current project} |
| matched_historical_chains | {Historical projects with same `framework + vuln_type` combinations that had successful attack chains} |
| missing_edges | {Edges present in historical projects but absent in current project → potentially overlooked correlations} |
| confidence_note | {Per CR-7: "Pattern suggestion only — not used for severity determination"} |

### Procedure G: Cross-Auditor Attack Chain Discovery

Read all findings from shared findings store grouped by `auditor_id`:
```bash
bash tools/audit_db.sh finding-read "$WORK_DIR"
```

Per chain from Cross-Auditor Attack Chain Reference:

| Field | Fill-in Value |
|-------|--------------|
| chain_name | {e.g., `cross_auditor_chain::sqli_to_ssti`} |
| auditor_a_finding | {Finding from auditor A that matches the chain's first condition} |
| auditor_b_finding | {Finding from auditor B that matches the chain's second condition} |
| data_flow_verified | {`true` if auditor A's output/sink has data flow to auditor B's input/source} |
| environment_conditions | {Config auditor's environment findings that enable/disable the chain} |
| chain_confidence | {`confirmed` = both confirmed + data flow verified; `probable` = one confirmed + one potential; `speculative` = both potential} |
| escalation_action | {`confirmed` → escalate directly; `probable` → mark high-priority candidate; `speculative` → record only, do NOT escalate} |
| deduplicated | {`true` if already covered by Procedure B — per CR-8, use higher severity, do not duplicate} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Correlation report | `$WORK_DIR/原始数据/correlation_report.json` | See output schema below | Full correlation results: escalations, second-order, gaps, FP, graph, chains |
| Second-order correlations | `$WORK_DIR/原始数据/second_order/correlations.json` | Subset of correlation_report | Second-order vulnerability candidate pairs |

### Output Schema: `correlation_report.json`

```json
{
  "generated_at": "ISO-8601",
  "escalations": [{
    "pattern_name": "string",
    "condition_a": { "finding_id": "string", "vuln_type": "string", "original_severity": "string" },
    "condition_b": { "finding_id": "string", "vuln_type": "string", "original_severity": "string" },
    "combined_severity": "string",
    "combined_impact": "string",
    "explanation": "string"
  }],
  "second_order_candidates": [{
    "store_point": "object",
    "use_point": "object",
    "vuln_type": "string",
    "risk_level": "string",
    "sanitization_gap": "string"
  }],
  "coverage_gaps": [{
    "area": "string",
    "risk_level": "string",
    "recommendation": "string"
  }],
  "potential_false_positives": [{
    "finding_id": "string",
    "reason": "string",
    "matched_pattern": "string"
  }],
  "graph_correlations": {
    "data_flow_chains": [],
    "reassessment_candidates": [],
    "escalations_from_graph": [],
    "high_value_targets": [],
    "historical_pattern_matches": []
  }
}
```

## Examples

### ✅ GOOD: Severity Escalation with Clear Combinatorial Logic
```json
{
  "generated_at": "2024-01-15T14:00:00Z",
  "escalations": [
    {
      "pattern_name": "Session Hijacking Chain",
      "condition_a": {
        "finding_id": "xss-reflected-007",
        "vuln_type": "reflected_xss",
        "original_severity": "medium"
      },
      "condition_b": {
        "finding_id": "config-cookie-001",
        "vuln_type": "missing_httponly",
        "original_severity": "low"
      },
      "combined_severity": "high",
      "combined_impact": "Cookie theft via XSS → session takeover; HttpOnly not set allows JavaScript access to session cookie",
      "explanation": "Reflected XSS on /search endpoint (xss-reflected-007) can execute arbitrary JS. Session cookie lacks HttpOnly flag (config-cookie-001) and no CSP is deployed. Combined: attacker injects XSS payload that reads document.cookie and exfiltrates session token → full session hijacking."
    }
  ],
  "second_order_candidates": [],
  "coverage_gaps": [],
  "potential_false_positives": [],
  "graph_correlations": {
    "data_flow_chains": [],
    "reassessment_candidates": [],
    "escalations_from_graph": [],
    "high_value_targets": [],
    "historical_pattern_matches": []
  }
}
```
Explanation: ✅ Both conditions clearly identified with finding IDs. `explanation` provides clear combinatorial logic (CR-2). No confirmed vulns downgraded (CR-1). Escalation from Medium+Low → High is supported by the reference pattern.

### ❌ BAD: Unsupported Escalation and Downgraded Finding
```json
{
  "generated_at": "2024-01-15T14:00:00Z",
  "escalations": [
    {
      "pattern_name": "SSRF → Cloud Takeover",
      "condition_a": {
        "finding_id": "ssrf-001",
        "vuln_type": "ssrf",
        "original_severity": "medium"
      },
      "condition_b": {
        "finding_id": null,
        "vuln_type": "cloud_environment",
        "original_severity": "info"
      },
      "combined_severity": "critical",
      "combined_impact": "SSRF to cloud takeover",
      "explanation": "Might be exploitable"
    }
  ],
  "potential_false_positives": [
    {
      "finding_id": "sqli-confirmed-003",
      "reason": "Probably a false positive",
      "matched_pattern": ""
    }
  ]
}
```
What's wrong: ❌ `condition_b.finding_id` is null — no actual finding supports the cloud environment condition, so escalation has no combinatorial basis → violates **CR-2**. `explanation` is "Might be exploitable" — no clear logic → violates **CR-2**. `sqli-confirmed-003` is flagged as FP with empty `matched_pattern` and vague reason — this effectively downgrades a confirmed vuln → violates **CR-1**.

## Error Handling
| Error | Action |
|-------|--------|
| `exploits/*.json` directory empty | Log warning; skip Procedure B/G (no findings to correlate); produce report with empty arrays |
| `second_order/store_points.jsonl` missing | Skip Procedure C; note in report that second-order correlation was not possible |
| `auth_matrix.json` missing | Skip untested admin endpoint check in Procedure D; proceed with other gap checks |
| `attack_memory.db` missing or empty | Skip Procedure F entirely; note graph correlations unavailable |
| `graph-export` command fails | Skip Procedure F; log error; continue with remaining procedures |
| Finding references invalid sink_id | Skip that finding in correlation; log warning with the invalid ID |
| Sub-skill (S-070\~S-074) times out | Use partial results from that sub-skill; note incomplete analysis in report |
| Duplicate chain detected (CR-8) | Keep the entry with higher severity; discard the duplicate |
| `shared/false_positive_patterns.md` missing | Skip Procedure E; note FP detection was not possible |
