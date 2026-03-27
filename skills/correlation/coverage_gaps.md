# Coverage Gap Analysis

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-073 |
| Category | Correlation |
| Responsibility | Detect untested sinks and missing coverage by comparing planned attack surface against actual exploit results |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Exploit results | `$WORK_DIR/exploits/*.json` | YES | final_verdict, evidence, sink_type, auth_level |
| Priority queue | `$WORK_DIR/priority_queue.json` | YES | sink_type, priority, routes |
| Route map | `$WORK_DIR/route_map.json` | YES | routes, endpoints, methods |
| Auth matrix | `$WORK_DIR/auth_matrix.json` | YES | auth_level, roles, endpoints |
| Attack plans | `$WORK_DIR/attack_plans/*.json` | NO | planned_vectors, filter_analysis |
| Attack memory graph | `$WORK_DIR/attack_memory.db` | NO | memory_nodes, memory_edges (shares_data_object) |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Coverage gap analysis does NOT equal vulnerability discovery; it serves only as supplementary audit reference | Treating gaps as confirmed vulnerabilities inflates severity and misleads remediation |
| CR-2 | Cross-project queries MUST only be used for pattern suggestions, NOT for severity determination | Using historical matches to set severity produces unreliable risk ratings |
| CR-3 | Admin endpoints without exploit results MUST always be flagged as `high` risk | Missing an untested admin endpoint leaves the highest-privilege attack surface unverified |
| CR-4 | P0/P1 sinks with only `potential_risk` annotation MUST be flagged for active testing | Static analysis annotations alone are insufficient for high-priority sinks |
| CR-5 | Coverage gap entries MUST be marked with `"confidence": "gap_only"` and MUST NOT appear in severity-ordered vulnerability lists without human review | Prevents unverified gaps from being treated as confirmed vulnerabilities |

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

### Procedure A: Load Attack Surface Data

1. Load `route_map.json` to get the complete list of endpoints
2. Load `auth_matrix.json` to identify admin and privileged endpoints
3. Load `priority_queue.json` to get all prioritized sinks
4. Load all exploit results from `$WORK_DIR/exploits/*.json`

### Procedure B: Check Untested Admin Endpoints

1. Extract all routes with `auth_level=admin` from `auth_matrix.json`
2. Check whether each admin route has been tested by the authz-auditor (look for matching entries in exploit results)
3. Flag any untested admin endpoints

| Field | Fill-in Value |
|-------|--------------|
| `area` | {description of the untested admin endpoint, e.g. `"POST /admin/users — no authz-auditor result"`} |
| `risk_level` | `"high"` (admin endpoints are always high-risk if untested — see CR-3) |
| `recommendation` | `"Test this admin endpoint for authorization bypass and privilege escalation"` |

### Procedure C: Check Uncovered Sinks

1. Extract all sinks from `priority_queue.json`
2. Check whether each sink has a corresponding exploit result
3. Flag sinks with no exploit results

| Field | Fill-in Value |
|-------|--------------|
| `area` | {sink type + endpoint with no exploit result, e.g. `"sqli sink at /api/search — no exploit result"`} |
| `risk_level` | {based on original priority: P0/P1 = `"critical"`, P2 = `"high"`, P3 = `"medium"`} |
| `recommendation` | `"This sink was prioritized but never tested — run the appropriate auditor"` |

### Procedure D: Check Static-Analysis-Only High-Priority Sinks

1. Identify P0/P1 sinks that have only a `potential_risk` annotation and no actual exploit testing
2. Flag these as requiring active testing (see CR-4)

| Field | Fill-in Value |
|-------|--------------|
| `area` | {P0/P1 sink with static analysis only, e.g. `"P0 sqli sink at /admin/query — static annotation only"`} |
| `risk_level` | `"high"` |
| `recommendation` | `"High-priority sink has only static analysis annotation — requires active exploit testing"` |

### Procedure E: Check Cross-Endpoint Data Flows

1. Identify cases where endpoint A's output is consumed by endpoint B (API chained calls)
2. Check whether the data flow between A→B has been tested for injection or manipulation
3. Flag untested cross-endpoint data flows

| Field | Fill-in Value |
|-------|--------------|
| `area` | {description of untested A→B data flow, e.g. `"GET /api/profile → POST /api/export — untested data flow"`} |
| `risk_level` | `"medium"` or `"high"` depending on sink context |
| `recommendation` | `"Cross-endpoint data flow has not been tested for injection or manipulation"` |

### Procedure F: Graph-Based Coverage Analysis (if attack_memory.db available)

Consume graph data from `attack_memory.db` for additional coverage insights:

1. **Attack surface aggregation** — iterate `shares_data_object` edges:
   - Group all vulnerability nodes by `data_object`
   - If the same data_object has ≥ 3 vulnerability nodes → mark as **high-value data object**
   - Output to `high_value_targets` array

| Field | Fill-in Value |
|-------|--------------|
| `data_object` | {table or object name, e.g. `"users"`} |
| `vuln_count` | {number of vulnerability nodes sharing this data object} |
| `vuln_types` | {array of distinct vulnerability types, e.g. `["sqli", "xss", "idor"]`} |
| `max_severity` | {highest severity among associated vulnerabilities} |
| `recommendation` | {centralized verification suggestion for this data object} |

2. **Cross-project pattern matching** — query historical projects (pattern suggestions only — see CR-2):
   - Find successful attack chains with the same `framework + vuln_type` combinations in past projects
   - If the current project has similar node combinations but missing edges → mark as **potentially overlooked correlation**
   - Output to `historical_pattern_matches` array

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
| Correlation findings | `$WORK_DIR/correlation_findings.json` | `coverage_gaps[]` | Append coverage gap entries from Procedures B–E |
| High-value targets | `$WORK_DIR/correlation_findings.json` | `high_value_targets[]` | Append high-value data object entries from Procedure F |
| Historical matches | `$WORK_DIR/correlation_findings.json` | `historical_pattern_matches[]` | Append historical pattern match entries from Procedure F |

## Examples

### ✅ GOOD: Untested admin endpoint correctly flagged

```json
{
  "coverage_gaps": [
    {
      "area": "POST /admin/users/delete — no authz-auditor result found",
      "risk_level": "high",
      "recommendation": "Test this admin endpoint for authorization bypass and privilege escalation"
    }
  ]
}
```

Explanation ✅ Admin endpoint has no matching exploit result → flagged as `high` per CR-3. The `area` clearly identifies the endpoint and the gap. The recommendation directs to the correct next action.

### ✅ GOOD: Graph-based high-value target

```json
{
  "high_value_targets": [
    {
      "data_object": "users",
      "vuln_count": 4,
      "vuln_types": ["sqli", "xss", "idor", "mass_assignment"],
      "max_severity": "high",
      "recommendation": "The users table is a core attack surface; centralized verification of all CRUD paths is recommended"
    }
  ]
}
```

Explanation ✅ The `users` table has ≥ 3 vulnerability nodes sharing it via `shares_data_object` edges. Aggregation correctly identifies it as a high-value data object. Recommendation is a pattern suggestion, not a severity determination (CR-2 compliant).

### ❌ BAD: Coverage gap treated as confirmed vulnerability

```json
{
  "coverage_gaps": [
    {
      "area": "POST /admin/config — CONFIRMED authorization bypass vulnerability",
      "risk_level": "critical",
      "recommendation": "Immediately patch this critical authorization bypass"
    }
  ]
}
```

What's wrong: Violates CR-1. Coverage gap analysis identifies *untested areas*, not confirmed vulnerabilities. The `area` falsely claims a "CONFIRMED" vulnerability. The `risk_level` should be `"high"` (untested admin), not `"critical"` (which implies confirmed exploit). ❌

### ❌ BAD: Historical match used to set severity

```json
{
  "coverage_gaps": [
    {
      "area": "sqli sink at /api/search",
      "risk_level": "critical",
      "recommendation": "Historical data shows 90% exploit rate — treat as critical"
    }
  ]
}
```

What's wrong: Violates CR-2. Cross-project historical matches MUST only be used for pattern suggestions, never for severity determination. The `risk_level` was inflated to `"critical"` based on historical data instead of the sink's own priority. ❌

## Error Handling

| Error | Action |
|-------|--------|
| No exploit results found | Skip this rule category, log warning |
| Missing fields in exploit JSON | Use defaults, mark finding as "low_confidence" |
| route_map.json missing | Skip admin endpoint check, log warning |
| auth_matrix.json missing | Skip admin endpoint check, log warning |
| attack_memory.db not available | Skip Procedure F (graph-based analysis), proceed with file-based checks only |
