# Real-Time Sharing and Second-Order Tracking

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-106 |
| Category | Shared Protocol |
| Responsibility | Enable cross-auditor intelligence sharing and track second-order vulnerability patterns where user input is stored in one location and used unsafely in another |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `$WORK_DIR/audit_session.db` | Shared findings store (all auditors) | Yes | WAF bypass methods, leaked credentials/keys, configuration values, related sink discoveries |
| Source code files | Auditor's assigned scope | Yes | User input write locations, persistent storage read locations, sink functions |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Read `audit_session.db` BEFORE starting attack phase to leverage intelligence from other auditors | Missing reusable bypass techniques, leaked credentials, or related sink discoveries |
| CR-2 | Use JSONL format (one JSON object per line, newline-delimited) for all output files | Output files become unparseable by downstream consumers |
| CR-3 | APPEND to existing files — NEVER overwrite other auditors' entries | Loss of other auditors' second-order tracking data |
| CR-4 | Link store points and use points via `store_id` ↔ `related_store_id` when both exist for the same data flow | Second-order vulnerability goes undetected |
| CR-5 | Create `second_order/` directory before writing if it does not exist (`mkdir -p $WORK_DIR/second_order`) | File write fails |
| CR-6 | When a store–use link is confirmed, escalate priority and include both points in the exploit evidence chain | Critical second-order vulnerability reported without full tracing evidence |

## Fill-in Procedure

### Procedure A: Shared Intelligence Reading

Before starting the attack phase, read the shared findings store:

```bash
cat $WORK_DIR/audit_session.db
```

Scan for the following intelligence types:

| Intelligence Type | Fill-in Value |
|-------------------|--------------|
| WAF bypass methods | {Reusable techniques that worked against the same WAF} |
| Leaked credentials/keys | {Credentials that may unlock authenticated attack surfaces} |
| Configuration values | {PHP settings, framework config, database type} |
| Related sink discoveries | {Paths to the same sink found by other auditors} |

### Procedure B: Record Second-Order Store Points

For each location where user-controllable input is written to persistent storage (database, files, cache), append one JSON line to `$WORK_DIR/second_order/store_points.jsonl`:

| Field | Fill-in Value |
|-------|--------------|
| store_id | {Unique ID, format: `SP-NNN`} |
| sink_type | {Vulnerability type, e.g. `sqli`, `xss`, `rce`} |
| source_param | {HTTP parameter carrying user input, e.g. `POST username`} |
| storage_type | {`database` / `file` / `cache` / `session`} |
| storage_location | {Table.column or file path where data is stored, e.g. `users.username`} |
| write_function | {PHP function performing the write, e.g. `PDO::execute()`} |
| write_file | {File path containing the write operation} |
| write_line | {Line number of the write call} |
| is_sanitized_on_write | {`true` / `false` — whether input is sanitized before storage} |
| sanitize_method | {Sanitization method used on write, or `none`} |
| raw_value_stored | {`true` / `false` — whether the original raw input value is stored} |
| notes | {Additional context about the store point} |

### Procedure C: Record Second-Order Use Points

For each location where data retrieved from persistent storage is passed into a dangerous sink without proper sanitization, append one JSON line to `$WORK_DIR/second_order/use_points.jsonl`:

| Field | Fill-in Value |
|-------|--------------|
| use_id | {Unique ID, format: `UP-NNN`} |
| related_store_id | {Corresponding `store_id` from store_points.jsonl, e.g. `SP-001`} |
| sink_type | {Vulnerability type, e.g. `sqli`, `xss`, `rce`} |
| retrieval_function | {PHP function reading from storage, e.g. `PDO::fetch()`} |
| retrieval_file | {File path containing the retrieval operation} |
| retrieval_line | {Line number of the retrieval call} |
| sink_function | {Dangerous function the data flows into, e.g. `PDO::query()`} |
| sink_file | {File path containing the sink function} |
| sink_line | {Line number of the sink call} |
| is_sanitized_on_use | {`true` / `false` — whether data is sanitized between retrieval and sink} |
| concatenation_pattern | {Exact code pattern showing unsafe usage, e.g. `$pdo->query("... '$var' ...")`} |
| exploitability | {`high` / `medium` / `low`} |
| notes | {Additional context about the use point} |

### Procedure D: Cross-Link Store and Use Points

When both a store point and a use point exist for the same data flow:

| Step | Action |
|------|--------|
| 1 | Verify `store_id` in store_points.jsonl matches `related_store_id` in use_points.jsonl |
| 2 | Classify as a **second-order vulnerability** — escalate priority |
| 3 | Include BOTH the store point and use point in the final exploit result's `evidence` / `trace` chain |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Store Points | `$WORK_DIR/second_order/store_points.jsonl` | JSONL — one JSON object per line with fields from Procedure B | All identified locations where user input is written to persistent storage |
| Use Points | `$WORK_DIR/second_order/use_points.jsonl` | JSONL — one JSON object per line with fields from Procedure C | All identified locations where stored data is used unsafely in a sink |

## Examples

### ✅ GOOD: Complete Store-Use Link for Second-Order SQLi

**store_points.jsonl** entry:
```json
{"store_id":"SP-001","sink_type":"sqli","source_param":"POST username","storage_type":"database","storage_location":"users.username","write_function":"PDO::execute()","write_file":"app/Controllers/UserController.php","write_line":45,"is_sanitized_on_write":true,"sanitize_method":"PDO prepared statement","raw_value_stored":true,"notes":"Original user input stored without modification despite safe write"}
```

**use_points.jsonl** entry:
```json
{"use_id":"UP-001","related_store_id":"SP-001","sink_type":"sqli","retrieval_function":"PDO::fetch()","retrieval_file":"app/Controllers/AdminController.php","retrieval_line":88,"sink_function":"PDO::query()","sink_file":"app/Controllers/AdminController.php","sink_line":92,"is_sanitized_on_use":false,"concatenation_pattern":"$pdo->query(\"SELECT * FROM orders WHERE customer = '$username'\")","exploitability":"high","notes":"DB-fetched username directly concatenated into SQL without escaping"}
```
Explanation ✅ Store and use points are correctly linked via `SP-001`. All fields filled. JSONL format (one line each). The store point shows safe write but raw value stored; the use point shows unsafe retrieval-to-sink flow with exact code pattern.

### ❌ BAD: Missing Link and Multi-Line JSON

**store_points.jsonl** entry:
```json
{
  "store_id": "SP-002",
  "sink_type": "sqli",
  "source_param": "POST email"
}
```

**use_points.jsonl** entry:
```json
{"use_id":"UP-002","related_store_id":"","sink_type":"sqli","retrieval_function":"mysql_query()","retrieval_file":"admin.php","retrieval_line":50,"sink_function":"mysql_query()","sink_file":"admin.php","sink_line":50,"is_sanitized_on_use":false,"concatenation_pattern":"","exploitability":"high","notes":""}
```
What's wrong ❌ Violates **CR-2**: store point uses multi-line JSON instead of single-line JSONL. Violates **CR-4**: `related_store_id` is empty — store and use points are not linked. Store point is missing required fields (`storage_type`, `storage_location`, `write_function`, `write_file`, `write_line`, etc.). Use point has empty `concatenation_pattern` — no evidence of how the data is unsafely used.

## Error Handling
| Error | Action |
|-------|--------|
| `audit_session.db` does not exist or is empty | Proceed without shared intelligence; log warning that no cross-auditor data is available |
| `second_order/` directory does not exist | Run `mkdir -p $WORK_DIR/second_order` before writing any output files |
| Cannot determine `related_store_id` for a use point | Set `related_store_id` to `""` and add a note explaining the gap; revisit after other auditors complete |
| Store point identified but no corresponding use point found | Record the store point anyway — another auditor may discover the use point later |
| Duplicate `store_id` or `use_id` detected | Append a suffix (e.g. `SP-001-b`) to avoid collision; never overwrite existing entries (CR-3) |
| JSONL write fails due to permissions | Verify `$WORK_DIR` path and permissions; do not silently skip — report the error |
