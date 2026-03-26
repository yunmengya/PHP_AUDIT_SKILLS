# Attack Memory System

Cross-audit experience reuse mechanism for Phase-4 expert Agents. By structurally recording success/failure experiences from each attack, subsequent audits can reuse historical knowledge, improve first-round hit rate, and reduce ineffective attempts.

---

## Design Principles

Inspired by PentAGI's Smart Memory System approach, uses SQLite database for ACID transactions and indexed queries (zero installation; built into macOS/PHP/Python):

- **Write timing**: After each Phase-4 expert completes an attack, experience is written to the memory store
- **Read timing**: Before Phase-4 expert starts the attack phase, matching historical memories are queried
- **Matching dimensions**: `sink_type + framework + PHP version segment + WAF type`
- **Storage location**: `${HOME}/.php_audit/attack_memory.db` (SQLite, persistent across projects)
- **Tool script**: `tools/audit_db.sh` (encapsulates all database operations)

## Initialization

Automatically initialized before the first audit (idempotent operation):

```bash
bash tools/audit_db.sh init-memory
```

Creates the `attack_memory` table with indexes `(sink_type, framework, status)` and `(sink_type, php_version)`.

## Memory Data Structure

Schema is defined in `schemas/attack_memory_entry.schema.json`; SQLite table fields correspond one-to-one:

| Field | Type | Description |
|-------|------|-------------|
| sink_type | TEXT | rce/sqli/xss/ssrf/lfi/... |
| sink_function | TEXT | system/eval/query/... |
| framework | TEXT | Laravel/ThinkPHP/WordPress/... |
| php_version | TEXT | 8.1.27 |
| waf_type | TEXT | none/ModSecurity/Cloudflare |
| status | TEXT | confirmed/failed/partial |
| rounds_used | INTEGER | Actual rounds used |
| successful_round | INTEGER | Successful round (confirmed only) |
| successful_payload_type | TEXT | Strategy type |
| bypass_technique | TEXT | Bypass technique |
| eliminated_strategies | TEXT | JSON array of eliminated strategies |
| failure_reason | TEXT | Failure reason classification |

## Write Protocol (After Attack Completion)

Each Phase-4 expert **MUST** execute the following write flow after completing all attack rounds:

### 1. Write Memory

Build JSON from attack results and environment information and write:

```bash
# Write using audit_db.sh (built-in transaction protection, no flock needed)
bash tools/audit_db.sh memory-write '{
  "sink_type":"rce",
  "sink_function":"system",
  "framework":"Laravel",
  "php_version":"8.1.27",
  "waf_type":"none",
  "status":"confirmed",
  "rounds_used":3,
  "successful_round":3,
  "successful_payload_type":"IFS_substitution",
  "successful_payload_summary":"$IFS substitution bypasses parameter filtering by replacing spaces",
  "bypass_technique":"IFS_substitution",
  "eliminated_strategies":["basic_separators","url_encoding"]
}'
```

### 2. Write Conditions

| Attack Result | Recorded Content | Purpose |
|---------------|-----------------|---------|
| ✅ confirmed | Successful payload type + bypass technique + successful round | Prioritize next time |
| ❌ failed (max_rounds) | All eliminated strategies + failure reason | Skip directly next time |
| ⚠️ partial | Partially successful strategies + blocking reason | Reference for adjustment next time |
| ❌ failed (< 3 rounds) | **Not recorded** | Insufficient data, not reference-worthy |

### 3. Sanitization Requirements

- Replace specific URLs, paths, and IPs in payloads with placeholders
- MUST NOT record credential information from credentials.json
- MUST NOT record specific project names or business data

## Read Protocol (Before Attack Starts)

Phase-4 experts query historical memory using the following flow when starting **Phase 2 (Attack Phase)**:

### 1. Matching Query

```bash
# Exact query: sink_type + framework + PHP major version + WAF
bash tools/audit_db.sh memory-query rce Laravel 8 none

# Relaxed query: sink_type + framework only
bash tools/audit_db.sh memory-query rce Laravel

# Most relaxed: sink_type only
bash tools/audit_db.sh memory-query rce
```

Returns a JSON array sorted by confirmed → partial → failed, maximum 20 entries.

### 2. Match Priority

| Match Level | Conditions | Weight |
|-------------|-----------|--------|
| Exact match | sink_type + framework + PHP version segment + WAF type all match | ⭐⭐⭐ |
| High match | sink_type + framework + PHP version segment match | ⭐⭐ |
| Partial match | sink_type + PHP version segment match | ⭐ |
| No match | Only sink_type matches | Reference only |

### 3. Application Strategy

Adjust the attack plan based on matched historical records:

**Has confirmed records**:
```
Historical match: Laravel + RCE + PHP8.x → R3 used $IFS substitution successfully
Adjustment: Move $IFS strategy from R3 to R1, skip basic separator tests
Expected: First-round hit, saving 2 rounds
```

**Has failed records**:
```
Historical match: Laravel + SQLi + PHP8.x + ModSecurity → All 8 rounds failed, reason=framework_filter
Adjustment: Eliminated strategies [union, boolean_blind, error_based, ...] will not be reattempted
            Start R1 directly with unconventional paths (second_order / JSON injection / subquery)
Expected: Avoid wasting 5+ rounds on repeated attempts
```

**No matching records**:
```
No historical data, execute in default round order
```

### 4. Memory Injection Format

Format for injecting query results into the expert Agent prompt:

```
## Historical Attack Memory (Auto-Retrieved)

Matched {n} relevant records:

✅ Success records (prioritize):
- [Laravel+RCE+PHP8.x] R3 used IFS_substitution successfully, bypass technique: $IFS substitution for spaces
- [Laravel+RCE+PHP7.4] R5 used LD_PRELOAD+mail() successfully

❌ Failure records (avoid repeating):
- [Laravel+SQLi+PHP8.x+ModSecurity] All 8 rounds failed, eliminated: union/boolean_blind/error_based/stacked/time_blind
  Failure reason: Eloquent ORM parameter binding cannot be bypassed

Suggested adjustments:
- R1 prioritize: IFS_substitution (historical success rate 100%)
- Skip strategies: basic_separators, url_encoding (historical success rate 0%)
```

## Memory Maintenance

### Capacity Control

```bash
# Auto-maintenance: when exceeding 1000 entries, keep confirmed + most recent 500
bash tools/audit_db.sh memory-maintain
```

### Statistics Overview

```bash
# View memory store statistics
bash tools/audit_db.sh memory-stats
```

### Initialization

On the first audit, the memory store does not exist; `init-memory` creates it automatically. All experts execute in default round order. The memory system **starts with zero configuration** and accumulates automatically with use.

### Migration from JSONL

If historical JSONL memory files exist, one-command migration is available:

```bash
bash tools/audit_db.sh migrate-memory
# Default reads ~/.php_audit/attack_memory.jsonl → writes to attack_memory.db
```

## Relationship with Other Systems

| System | Relationship |
|--------|-------------|
| `lessons_learned.md` | Human-readable experience summaries (text); the memory system is machine-readable structured data (SQLite) |
| `context_compression.md` | Context management within a single audit; the memory system is cross-audit experience reuse |
| `audit_session.db` → `shared_findings` | Real-time finding sharing within a single audit (also SQLite); the memory system persists across projects |
| `payload_templates.md` | Static payload library; the memory system records which payloads are effective/ineffective under what conditions |

---

## Relational Memory Extension (Graph Layer)

> See `shared/attack_memory_graph.md` for the complete entity-relationship graph model definition.

On top of the flat memory (`attack_memory` table) described above, two graph tables (`memory_nodes` + `memory_edges`) are added to the same `attack_memory.db` file to record semantic relationships between vulnerabilities.

### Extended Write Rules

Each Phase-4 expert **MUST simultaneously** execute the following relational writes when performing the **write protocol**:

#### Rule GW-1: Write Node After Attack Completion

When writing to the `attack_memory` table (flat record), simultaneously write to the `memory_nodes` table:

```bash
# Flat memory write (existing flow, unchanged)
bash tools/audit_db.sh memory-write '{...}'

# Relational memory write (new, MUST immediately follow flat write)
bash tools/audit_db.sh graph-node-write '{
  "node_id": "{project_hash}_{sink_id}",
  "vuln_type": "{sink_type}",
  "sink_id": "{sink_id}",
  "route": "{attacked route path}",
  "severity": "{level after tri-dimensional scoring}",
  "status": "{confirmed/failed/partial}",
  "framework": "{framework}",
  "data_object": "{involved data object, e.g., users table/session/cookie}",
  "summary": "{one-line attack result summary}"
}'
```

**data_object Identification Rules**:
- SQL vulnerabilities → involved table name (e.g., `users`, `orders`)
- File vulnerabilities → involved file path pattern (e.g., `/uploads/*`, `/config/.env`)
- Session vulnerabilities → `session`
- Authentication vulnerabilities → `auth_token` or `credentials`
- Configuration vulnerabilities → `config`

#### Rule GW-2: Write Edge When Cross-Sink Relationships Are Discovered

When the Auditor discovers associations with other Sinks during analysis or attack, write to the `memory_edges` table:

**Trigger conditions** (write edge if ANY condition is met):
1. Current Sink's output data can serve as input for another Sink → `data_flows_to`
2. Current Sink's exploitation requires another vulnerability to succeed first → `enables` (write in reverse)
3. Current Sink and another Sink operate on the same data table/file → `shares_data_object`
4. Current Sink and another Sink share the same entry route → `same_entry_point`
5. A confirmed related vulnerability is found in the `shared_findings` table → evaluate whether it constitutes `escalates_to`

```bash
bash tools/audit_db.sh graph-edge-write '{
  "source_node": "{project_hash}_{current_sink_id}",
  "target_node": "{project_hash}_{related_sink_id}",
  "relation": "{relation type}",
  "confidence": "{confirmed/probable/speculative}",
  "evidence": "{relationship evidence: specific description of how data flows/why it constitutes escalation}"
}'
```

**confidence Determination Criteria**:
- `confirmed`: Relationship verified through PoC (e.g., injected data actually rendered at another endpoint)
- `probable`: Code analysis confirms data flow exists, but not actually verified
- `speculative`: Based on pattern inference (e.g., same table operations but specific field association unconfirmed)

#### Rule GW-3: No-Write Conditions

The following situations **MUST NOT** be written to relational memory (consistent with flat memory no-write conditions):
- Attack failed in < 3 rounds (insufficient data)
- Only `speculative` with no code-level evidence
- data_object cannot be determined (MUST NOT guess)

### Extended Read Rules

Phase-4 experts **additionally** query the relationship graph when starting Attack Phase 2, in addition to querying flat memory:

```bash
# Flat memory query (existing flow, unchanged)
bash tools/audit_db.sh memory-query {sink_type} {framework}

# Relationship graph query (new) — query complete attack surface for the current Sink's data object
bash tools/audit_db.sh graph-by-data-object "{data_object}"
```

**Injection format** (appended after existing "Historical Attack Memory"):

```
## Related Vulnerability Intelligence (Graph Memory)

Known vulnerabilities involving data object "{data_object}":
- [SQLi → users table] sink_023: ORDER BY injection (confirmed) — can read arbitrary fields
- [XSS → users table] sink_045: template renders users.bio (suspected) — unescaped output

Relationship chains:
- sink_023 --[data_flows_to]--> sink_045: SQLi writes to bio field → XSS renders bio field
  → Combined exploitation can escalate to Stored XSS (High)

Suggestion: Prioritize verifying data_flows_to relationship chains; if source is confirmed, target success rate increases significantly.
```
