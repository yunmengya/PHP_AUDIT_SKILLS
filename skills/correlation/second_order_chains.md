> **Skill ID**: S-071 | **Phase**: 4.5 | **Category**: Correlation Rule
> **Input**: exploit_results/*.json, priority_queue.json
> **Output**: correlation_findings.json (appended)

# Second-Order Attack Chains

## Identity

Correlation rule skill for second-order/stored attack chains. Part of the correlation engine (Phase 4.5).

These rules correlate store points and use points across the application to identify second-order vulnerabilities where data is stored in one context (e.g., database write) and consumed unsafely in another (e.g., template rendering, SQL query).

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Store points | `$WORK_DIR/second_order/store_points.jsonl` | YES | table, column, sanitization, endpoint |
| Use points | `$WORK_DIR/second_order/use_points.jsonl` | YES | table, column, sanitization, endpoint, context |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Attack memory graph | `$WORK_DIR/attack_memory.db` | NO | memory_nodes, memory_edges (data_flows_to) |

## Fill-in Procedure

### Step 1: Load Store and Use Points

1. Read `$WORK_DIR/second_order/store_points.jsonl` — each line is a JSON object describing where user input is stored
2. Read `$WORK_DIR/second_order/use_points.jsonl` — each line is a JSON object describing where stored data is consumed

### Step 2: Match Store → Use by (table, column)

For each store point, find all use points that share the same `(table, column)` pair. This creates candidate second-order data flows.

### Step 3: Check Sanitization Chain Completeness

For each matched pair, evaluate the sanitization status:

| Store Sanitization | Use Sanitization | Assessment |
|-------------------|-----------------|------------|
| Sanitized | Sanitized | Safe |
| Sanitized | Unsanitized | Possibly safe (depends on sanitization type) |
| Unsanitized | Sanitized | Possibly safe (depends on sanitization type) |
| Unsanitized | Unsanitized | **High-risk second-order vulnerability** |

### Step 4: Check Sanitization Type Matching

Even when sanitization exists, verify the sanitization type is appropriate for the use context. Mismatched sanitization = vulnerability:

| Store Sanitization | Use Context | Result |
|-------------------|-------------|--------|
| `htmlspecialchars` (HTML encoding) | SQL concatenation at use | **Vulnerability** — HTML encoding ≠ SQL escaping |
| `addslashes` (SQL escaping) | `system()` call at use | **Vulnerability** — SQL escaping ≠ command escaping |
| `htmlspecialchars` | HTML output | Safe |
| `mysqli_real_escape_string` | SQL parameterized query | Safe |

Fill in for each candidate:

| Field | Value |
|-------|-------|
| `store_point` | Full store point object |
| `use_point` | Full use point object |
| `vuln_type` | `second_order_sqli` / `stored_xss` / `second_order_cmdi` / etc. |
| `risk_level` | `high` / `medium` / `low` |
| `sanitization_gap` | Description of the sanitization mismatch or absence |

### Step 5: Graph-Based Data Flow Discovery (if attack_memory.db available)

Consume graph data from `attack_memory.db` to discover additional second-order chains:

1. Iterate all edges where `relation = "data_flows_to"`
2. If `source_node.status = "confirmed"` and `target_node.status ∈ {"confirmed", "suspected", "potential"}`
3. Mark as **data flow attack chain candidate**, escalate `target_node` priority
4. Example: SQLi writes to `users.bio` (confirmed) → XSS renders `users.bio` (potential) → escalate to Stored XSS (probable)

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | Append `second_order_candidates` array entries |
| Second-order correlations | `$WORK_DIR/second_order/correlations.json` | Detailed second-order correlation results |

### Output Schema (per candidate entry)

```json
{
  "store_point": {
    "table": "string",
    "column": "string",
    "endpoint": "string",
    "sanitization": "string|null"
  },
  "use_point": {
    "table": "string",
    "column": "string",
    "endpoint": "string",
    "context": "string",
    "sanitization": "string|null"
  },
  "vuln_type": "string",
  "risk_level": "string",
  "sanitization_gap": "string"
}
```

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| store_points.jsonl or use_points.jsonl missing | Skip second-order correlation, log warning |
| No matching (table, column) pairs | Report zero candidates, no error |
| attack_memory.db not available | Skip Step 5 (graph-based discovery), proceed with file-based matching only |

## Constraints

- Second-order vulnerability candidates require subsequent actual testing for confirmation; this step SHALL only mark candidates
- Graph edges with `speculative` confidence MUST NOT participate in escalation calculations; they SHALL only be recorded in pattern_matches
