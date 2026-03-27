> **Skill ID**: S-106 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Real-Time Sharing and Second-Order Tracking

## Purpose

Enable cross-auditor intelligence sharing and track second-order vulnerability patterns where user input is stored in one location and later used unsafely in another.

## Procedure

### Part 1: Shared Intelligence Reading

Before starting the attack phase, read the shared findings store to leverage intelligence from other auditors:

```bash
# Read shared findings store
cat $WORK_DIR/audit_session.db
```

Types of intelligence to look for:

| Finding Type | Value |
|-------------|-------|
| WAF bypass methods | Reuse techniques that worked against the same WAF |
| Leaked credentials/keys | May unlock authenticated attack surfaces |
| Configuration values | PHP settings, framework config, database type |
| Related sink discoveries | Other auditors may have found paths to the same sink |

### Part 2: Second-Order Store Points

Record all locations where user-controllable input is written to persistent storage (database, files, cache).

**Output file**: `$WORK_DIR/second_order/store_points.jsonl`

Each line is a JSON object:

```json
{
  "store_id": "SP-001",
  "sink_type": "sqli",
  "source_param": "POST username",
  "storage_type": "database",
  "storage_location": "users.username",
  "write_function": "PDO::execute()",
  "write_file": "app/Controllers/UserController.php",
  "write_line": 45,
  "is_sanitized_on_write": true,
  "sanitize_method": "PDO prepared statement",
  "raw_value_stored": true,
  "notes": "Original user input stored without modification despite safe write"
}
```

### Part 3: Second-Order Use Points

Record all locations where data retrieved from persistent storage is passed into a dangerous sink without proper sanitization.

**Output file**: `$WORK_DIR/second_order/use_points.jsonl`

Each line is a JSON object:

```json
{
  "use_id": "UP-001",
  "related_store_id": "SP-001",
  "sink_type": "sqli",
  "retrieval_function": "PDO::fetch()",
  "retrieval_file": "app/Controllers/AdminController.php",
  "retrieval_line": 88,
  "sink_function": "PDO::query()",
  "sink_file": "app/Controllers/AdminController.php",
  "sink_line": 92,
  "is_sanitized_on_use": false,
  "concatenation_pattern": "$pdo->query(\"SELECT * FROM orders WHERE customer = '$username'\")",
  "exploitability": "high",
  "notes": "DB-fetched username directly concatenated into SQL without escaping"
}
```

### Part 4: Cross-Linking Store and Use Points

When both a store point and a use point are identified for the same data flow:

1. Link them via `store_id` ↔ `related_store_id`
2. This constitutes a **second-order vulnerability** — escalate priority
3. Include both points in the final exploit result's evidence chain

### File Management Rules

- Use JSONL format (one JSON object per line, newline-delimited)
- Append to existing files — do not overwrite other auditors' entries
- Create the `second_order/` directory if it does not exist:
  ```bash
  mkdir -p $WORK_DIR/second_order
  ```

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/second_order_tracking.md`
