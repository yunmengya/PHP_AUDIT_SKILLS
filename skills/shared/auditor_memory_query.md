> **Skill ID**: S-100 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Historical Attack Memory Query Protocol

## Purpose

Before starting attacks, query the attack memory store for records matching the current context to optimize attack round ordering.

## Procedure

### Step 1: Query Memory Store

Query `~/.php_audit/attack_memory.db` with these filter conditions:

| Field | Match Criteria |
|-------|---------------|
| sink_type | Exact match with current auditor's sink type |
| framework | Exact match with target framework |
| php_version | Major.Minor version match (e.g., 8.1.x matches 8.1.y) |

### Step 2: Apply Results

| Query Result | Action |
|-------------|--------|
| Has confirmed records | Prioritize their successful strategies to R1 |
| Has failed records | Skip their excluded strategies |
| No matches | Execute in default round order (R1→R2→...→R8) |

### Step 3: Record Query in Plan

Add `memory_hits` field to `{sink_id}_plan.json`:

```json
{
  "memory_hits": {
    "confirmed": [{"strategy": "...", "round": "N"}],
    "failed": [{"strategy": "...", "excluded_reason": "..."}],
    "total_matches": "N"
  }
}
```

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/auditor_memory_query.md`
