# Second-Order Attack Chains

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-074 |
| Category | Correlation |
| Responsibility | Correlate store points and use points across the application to identify second-order vulnerability candidates |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Store points | `$WORK_DIR/second_order/store_points.jsonl` | YES | table, column, sanitization, endpoint |
| Use points | `$WORK_DIR/second_order/use_points.jsonl` | YES | table, column, sanitization, endpoint, context |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Attack memory graph | `$WORK_DIR/attack_memory.db` | NO | memory_nodes, memory_edges (data_flows_to) |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Second-order vulnerability candidates require subsequent actual testing for confirmation; this step SHALL only mark candidates | Treating candidates as confirmed vulnerabilities produces false positives and misleads remediation |
| CR-2 | Graph edges with `speculative` confidence MUST NOT participate in escalation calculations; they SHALL only be recorded in pattern_matches | Including speculative edges in escalation inflates priority and wastes testing resources |
| CR-3 | Sanitization type MUST be validated against the use context, not just presence/absence | A store point with `htmlspecialchars` feeding a SQL concatenation use point is still vulnerable despite sanitization existing |
| CR-4 | Both `store_point` and `use_point` MUST be fully populated with all fields in each candidate entry | Incomplete entries prevent downstream auditors from locating and testing the candidate |

## Fill-in Procedure

### Procedure A: Load Store and Use Points

1. Read `$WORK_DIR/second_order/store_points.jsonl` — each line is a JSON object describing where user input is stored
2. Read `$WORK_DIR/second_order/use_points.jsonl` — each line is a JSON object describing where stored data is consumed

### Procedure B: Match Store → Use by (table, column)

For each store point, find all use points that share the same `(table, column)` pair. This creates candidate second-order data flows.

### Procedure C: Check Sanitization Chain Completeness

For each matched pair, evaluate the sanitization status:

| Store Sanitization | Use Sanitization | Assessment |
|-------------------|-----------------|------------|
| Sanitized | Sanitized | Safe |
| Sanitized | Unsanitized | Possibly safe (depends on sanitization type — proceed to Procedure D) |
| Unsanitized | Sanitized | Possibly safe (depends on sanitization type — proceed to Procedure D) |
| Unsanitized | Unsanitized | **High-risk second-order vulnerability** |

### Procedure D: Check Sanitization Type Matching

Even when sanitization exists, verify the sanitization type is appropriate for the use context (see CR-3). Mismatched sanitization = vulnerability:

| Store Sanitization | Use Context | Result |
|-------------------|-------------|--------|
| `htmlspecialchars` (HTML encoding) | SQL concatenation at use | **Vulnerability** — HTML encoding ≠ SQL escaping |
| `addslashes` (SQL escaping) | `system()` call at use | **Vulnerability** — SQL escaping ≠ command escaping |
| `htmlspecialchars` | HTML output | Safe |
| `mysqli_real_escape_string` | SQL parameterized query | Safe |

Fill in for each candidate (all fields required — see CR-4):

| Field | Fill-in Value |
|-------|--------------|
| `store_point` | {full store point object with table, column, endpoint, sanitization} |
| `use_point` | {full use point object with table, column, endpoint, context, sanitization} |
| `vuln_type` | {`"second_order_sqli"` / `"stored_xss"` / `"second_order_cmdi"` / "second_order_lfi" / "second_order_ssrf", based on use context} |
| `risk_level` | {`"high"` if both unsanitized or sanitization mismatched; `"medium"` if partially sanitized; `"low"` if minor mismatch} |
| `sanitization_gap` | {description of the sanitization mismatch or absence, e.g. `"Store uses htmlspecialchars but use context is SQL concatenation"`} |

### Procedure E: Graph-Based Data Flow Discovery (if attack_memory.db available)

Consume graph data from `attack_memory.db` to discover additional second-order chains:

1. Iterate all edges where `relation = "data_flows_to"`
2. If `source_node.status = "confirmed"` and `target_node.status ∈ {"confirmed", "suspected", "potential"}`
3. Mark as **data flow attack chain candidate**, escalate `target_node` priority
4. **Do NOT escalate based on `speculative` confidence edges** (CR-2) — record in `pattern_matches` only
5. Example: SQLi writes to `users.bio` (confirmed) → XSS renders `users.bio` (potential) → escalate to Stored XSS (probable)

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | `second_order_candidates[]` | Append second-order candidate entries from Procedures C–D |
| Second-order correlations | `$WORK_DIR/second_order/correlations.json` | `candidates[]`, `graph_chains[]` | Detailed second-order correlation results including graph-based discoveries |

## Examples

### ✅ GOOD: Unsanitized store → unsanitized SQL use

```json
{
  "second_order_candidates": [
    {
      "store_point": {
        "table": "users",
        "column": "bio",
        "endpoint": "POST /profile/update",
        "sanitization": null
      },
      "use_point": {
        "table": "users",
        "column": "bio",
        "endpoint": "GET /admin/user-report",
        "context": "SQL concatenation",
        "sanitization": null
      },
      "vuln_type": "second_order_sqli",
      "risk_level": "high",
      "sanitization_gap": "No sanitization at store or use point; user-controlled bio value is concatenated into SQL query"
    }
  ]
}
```

Explanation ✅ Both store and use points are fully populated (CR-4). Neither side has sanitization → correctly flagged as `high`. The `vuln_type` matches the use context (SQL concatenation → `second_order_sqli`). The entry is a candidate, not a confirmed finding (CR-1 compliant).

### ✅ GOOD: Sanitization type mismatch detected

```json
{
  "second_order_candidates": [
    {
      "store_point": {
        "table": "comments",
        "column": "body",
        "endpoint": "POST /comments",
        "sanitization": "htmlspecialchars"
      },
      "use_point": {
        "table": "comments",
        "column": "body",
        "endpoint": "GET /export/csv",
        "context": "system() shell command",
        "sanitization": null
      },
      "vuln_type": "second_order_cmdi",
      "risk_level": "high",
      "sanitization_gap": "Store uses htmlspecialchars (HTML encoding) but use context is shell command execution — HTML encoding does not prevent command injection"
    }
  ]
}
```

Explanation ✅ Sanitization exists at the store point but is wrong for the use context (CR-3). `htmlspecialchars` does not protect against command injection. Correctly identified as a sanitization type mismatch with a clear gap description.

### ❌ BAD: Candidate treated as confirmed vulnerability

```json
{
  "second_order_candidates": [
    {
      "store_point": {
        "table": "users",
        "column": "bio",
        "endpoint": "POST /profile/update",
        "sanitization": null
      },
      "use_point": {
        "table": "users",
        "column": "bio",
        "endpoint": "GET /admin/user-report",
        "context": "SQL concatenation",
        "sanitization": null
      },
      "vuln_type": "second_order_sqli",
      "risk_level": "critical",
      "sanitization_gap": "CONFIRMED second-order SQL injection — immediate remediation required"
    }
  ]
}
```

What's wrong: Violates CR-1. This step SHALL only mark candidates, not confirm vulnerabilities. The `sanitization_gap` falsely claims "CONFIRMED" and the `risk_level` is inflated to `"critical"` without actual exploit testing. Should be `"high"` with candidate-level language. ❌

### ❌ BAD: Missing use_point fields

```json
{
  "second_order_candidates": [
    {
      "store_point": {
        "table": "users",
        "column": "bio",
        "endpoint": "POST /profile/update",
        "sanitization": null
      },
      "use_point": {
        "table": "users",
        "column": "bio"
      },
      "vuln_type": "stored_xss",
      "risk_level": "high",
      "sanitization_gap": "No sanitization"
    }
  ]
}
```

What's wrong: Violates CR-4. The `use_point` is missing `endpoint`, `context`, and `sanitization` fields. Without `context`, downstream auditors cannot determine whether the sanitization gap assessment is correct. Without `endpoint`, they cannot locate the code to test. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| store_points.jsonl or use_points.jsonl missing | Skip second-order correlation, log warning |
| No matching (table, column) pairs | Report zero candidates, no error |
| attack_memory.db not available | Skip Procedure E (graph-based discovery), proceed with file-based matching only |
