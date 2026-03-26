> **Skill ID**: S-072 | **Phase**: 4.5 | **Category**: Correlation Rule
> **Input**: exploit_results/*.json, priority_queue.json
> **Output**: correlation_findings.json (appended)

# Coverage Gap Analysis

## Identity

Correlation rule skill for identifying untested sink combinations and missing coverage. Part of the correlation engine (Phase 4.5).

These rules compare the planned attack surface (route map, priority queue, auth matrix) against actual exploit results to flag high-risk areas that were never tested or only received static analysis annotations.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Route map | `$WORK_DIR/route_map.json` | YES | routes, endpoints, methods |
| Auth matrix | `$WORK_DIR/auth_matrix.json` | YES | auth_level, roles, endpoints |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Attack memory graph | `$WORK_DIR/attack_memory.db` | NO | memory_nodes, memory_edges (shares_data_object) |

## Fill-in Procedure

### Step 1: Load Attack Surface Data

1. Load `route_map.json` to get the complete list of endpoints
2. Load `auth_matrix.json` to identify admin and privileged endpoints
3. Load `priority_queue.json` to get all prioritized sinks
4. Load all exploit results from `$WORK_DIR/exploits/*.json`

### Step 2: Check Untested Admin Endpoints

1. Extract all routes with `auth_level=admin` from `auth_matrix.json`
2. Check whether each admin route has been tested by the authz-auditor (look for matching entries in exploit results)
3. Flag any untested admin endpoints

| Field | Value |
|-------|-------|
| `area` | Description of the untested admin endpoint |
| `risk_level` | `high` (admin endpoints are always high-risk if untested) |
| `recommendation` | "Test this admin endpoint for authorization bypass and privilege escalation" |

### Step 3: Check Uncovered Sinks

1. Extract all sinks from `priority_queue.json`
2. Check whether each sink has a corresponding exploit result
3. Flag sinks with no exploit results

| Field | Value |
|-------|-------|
| `area` | Sink type + endpoint with no exploit result |
| `risk_level` | Based on original priority (P0/P1 = `critical`, P2 = `high`, P3 = `medium`) |
| `recommendation` | "This sink was prioritized but never tested — run the appropriate auditor" |

### Step 4: Check Static-Analysis-Only High-Priority Sinks

1. Identify P0/P1 sinks that have only a `potential_risk` annotation and no actual exploit testing
2. Flag these as requiring active testing

| Field | Value |
|-------|-------|
| `area` | P0/P1 sink with static analysis only |
| `risk_level` | `high` |
| `recommendation` | "High-priority sink has only static analysis annotation — requires active exploit testing" |

### Step 5: Check Cross-Endpoint Data Flows

1. Identify cases where endpoint A's output is consumed by endpoint B (API chained calls)
2. Check whether the data flow between A→B has been tested for injection or manipulation
3. Flag untested cross-endpoint data flows

### Step 6: Graph-Based Coverage Analysis (if attack_memory.db available)

Consume graph data from `attack_memory.db` for additional coverage insights:

1. **Attack surface aggregation** — iterate `shares_data_object` edges:
   - Group all vulnerability nodes by `data_object`
   - If the same data_object has ≥ 3 vulnerability nodes → mark as **high-value data object**
   - Output to `high_value_targets` array:
     ```json
     {
       "data_object": "users",
       "vuln_count": 4,
       "vuln_types": ["sqli", "xss", "idor", "mass_assignment"],
       "max_severity": "high",
       "recommendation": "The users table is a core attack surface; centralized verification of all CRUD paths is recommended"
     }
     ```

2. **Cross-project pattern matching** — query historical projects:
   - Find successful attack chains with the same `framework + vuln_type` combinations in past projects
   - If the current project has similar node combinations but missing edges → mark as **potentially overlooked correlation**
   - Output to `historical_pattern_matches` array

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Correlation findings | `$WORK_DIR/correlation_findings.json` | Append `coverage_gaps` array entries |
| High-value targets | `$WORK_DIR/correlation_findings.json` | Append `high_value_targets` array (from graph analysis) |
| Historical matches | `$WORK_DIR/correlation_findings.json` | Append `historical_pattern_matches` array (from graph analysis) |

### Output Schema (per coverage gap entry)

```json
{
  "area": "string",
  "risk_level": "string",
  "recommendation": "string"
}
```

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| route_map.json missing | Skip admin endpoint check, log warning |
| auth_matrix.json missing | Skip admin endpoint check, log warning |
| attack_memory.db not available | Skip Step 6 (graph-based analysis), proceed with file-based checks only |

## Constraints

- Coverage gap analysis does NOT equal vulnerability discovery; it serves only as supplementary audit reference
- Cross-project queries MUST only be used for pattern suggestions, NOT for severity determination
