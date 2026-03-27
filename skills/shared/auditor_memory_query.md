# Historical Attack Memory Query Protocol

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-100 |
| Category | Shared Protocol |
| Responsibility | Query attack memory store before starting attacks to optimize round ordering |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `~/.php_audit/attack_memory.db` | System memory store | ✅ | `sink_type`, `framework`, `php_version`, `strategy`, `result` |
| Current auditor context | Invoking auditor (S-040 ~ S-060) | ✅ | `sink_type`, `target_framework`, `target_php_version` |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Memory query MUST be executed before any attack round begins | Skipping query wastes rounds on previously failed strategies |
| CR-2 | Confirmed records MUST be prioritized to R1 | Failing to reorder misses known-successful strategies |
| CR-3 | Failed records MUST be excluded from round planning | Re-attempting known-failed strategies wastes attack rounds |
| CR-4 | PHP version matching uses Major.Minor only (e.g., 8.1.x matches 8.1.y) | Using exact patch version causes false negatives in memory lookup |
| CR-5 | Query results MUST be recorded in `{sink_id}_plan.json` under `memory_hits` | Missing record breaks audit traceability |

## Fill-in Procedure

### Procedure A: Query Memory Store
| Field | Fill-in Value |
|-------|--------------|
| sink_type | {exact match with current auditor's sink type, e.g., "sql_injection", "rce"} |
| framework | {exact match with target framework, e.g., "Laravel", "ThinkPHP"} |
| php_version | {Major.Minor version of target, e.g., "8.1"} |
| query_target | {path to memory DB: `~/.php_audit/attack_memory.db`} |

### Procedure B: Apply Query Results
| Field | Fill-in Value |
|-------|--------------|
| confirmed_strategies | {list of strategies from confirmed records to prioritize to R1} |
| excluded_strategies | {list of strategies from failed records to skip} |
| round_order | {reordered round sequence, or default R1→R2→...→R8 if no matches} |

### Procedure C: Record Query in Plan
| Field | Fill-in Value |
|-------|--------------|
| plan_file | {path: `{sink_id}_plan.json`} |
| confirmed_hits | {array of `{"strategy": "...", "round": "N"}` from confirmed matches} |
| failed_hits | {array of `{"strategy": "...", "excluded_reason": "..."}` from failed matches} |
| total_matches | {integer count of all matching records} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Memory hits record | `{sink_id}_plan.json` → `memory_hits` field | See example below | Query results appended to the attack plan file |

## Examples

### ✅ GOOD: Memory query with confirmed and failed hits
```json
{
  "memory_hits": {
    "confirmed": [
      {"strategy": "double_url_encoding", "round": "3"},
      {"strategy": "header_injection", "round": "5"}
    ],
    "failed": [
      {"strategy": "basic_cmd_injection", "excluded_reason": "escapeshellarg() blocks all shell metacharacters"},
      {"strategy": "null_byte_injection", "excluded_reason": "PHP 8.x removes null bytes from input"}
    ],
    "total_matches": 4
  }
}
```
Explanation ✅ Confirmed strategies will be prioritized to R1/R2. Failed strategies are excluded with specific defense reasons. Total matches is accurate.

### ✅ GOOD: No matches found
```json
{
  "memory_hits": {
    "confirmed": [],
    "failed": [],
    "total_matches": 0
  }
}
```
Explanation ✅ No matches — auditor proceeds with default round order R1→R2→...→R8. Empty arrays and zero count correctly recorded.

### ❌ BAD: Missing memory_hits in plan
```json
{
  "sink_id": "sqli_001",
  "rounds": ["R1", "R2", "R3"]
}
```
What's wrong: `memory_hits` field is completely absent. Violates CR-5 — query results must be recorded for audit traceability. ❌

### ❌ BAD: Failed strategy not excluded
```json
{
  "memory_hits": {
    "confirmed": [],
    "failed": [
      {"strategy": "basic_cmd_injection", "excluded_reason": "escapeshellarg() blocks all metacharacters"}
    ],
    "total_matches": 1
  },
  "round_plan": [
    {"round": 1, "strategy": "basic_cmd_injection"}
  ]
}
```
What's wrong: `basic_cmd_injection` appears in failed records but is still scheduled in round plan. Violates CR-3 — failed records must be excluded from round planning. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Memory DB file not found (`attack_memory.db` missing) | Treat as zero matches; proceed with default round order; log warning in plan |
| DB query fails (corruption, permission error) | Treat as zero matches; proceed with default round order; record error in `memory_hits` |
| Auditor context missing `sink_type` | HALT — sink type is required for query; cannot proceed without it |
| PHP version not determinable | Query with `sink_type` and `framework` only; omit version filter; note in plan |
| Partial match (only framework matches, no sink_type match) | Return zero matches — `sink_type` exact match is mandatory |
