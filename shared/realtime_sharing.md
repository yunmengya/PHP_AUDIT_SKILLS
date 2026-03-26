# Realtime Finding Sharing Protocol

This document defines the realtime information sharing specification between Phase-4 auditors. All auditors MUST write to the shared findings database when they discover critical information that other auditors can leverage.

---

## Shared Database

`$WORK_DIR/audit_session.db` → `shared_findings` table (SQLite, WAL mode, supports concurrent reads/writes).

Initialization (automatically executed at Phase-4 startup, idempotent operation):
```bash
bash tools/audit_db.sh init-session "$WORK_DIR"
```

## Write Rules

### When to Write

Auditors **MUST** write shared findings in the following situations:

1. **Valid credentials discovered**: Database passwords, API keys, JWT Secret, Tokens, Session Cookies
2. **Internal addresses discovered**: Internal IPs, internal API endpoints, service ports
3. **Key material discovered**: APP_KEY, encryption keys, HMAC Secret, private keys
4. **Exploitable endpoints discovered**: Unauthenticated admin endpoints, debug endpoints, file upload endpoints
5. **Bypass methods confirmed**: WAF bypass techniques, encoding methods, HTTP method bypasses

### Write Command

```bash
bash tools/audit_db.sh finding-write "$WORK_DIR" '{
  "source_agent": "infoleak-auditor",
  "finding_type": "secret_key",
  "priority": "critical",
  "data": {
    "key": "JWT_SECRET",
    "value": "super_secret_key_123",
    "context": "Obtained from .env file leak",
    "source_location": "GET /.env"
  },
  "target_agents": ["authz-auditor", "crypto-auditor"]
}'
```

**Advantage**: Built-in UNIQUE constraint provides automatic deduplication (identical source_agent + finding_type + data_key + data_value will not be inserted again); no manual dedup needed.

### Write Format

| Field | Type | Description |
|------|------|------|
| source_agent | TEXT | Name of the writing agent |
| finding_type | TEXT | credential/internal_url/secret_key/endpoint/bypass_method/config_value |
| priority | TEXT | critical/high/medium |
| data.key | TEXT | Name/identifier of the finding |
| data.value | TEXT | Value of the finding |
| data.context | TEXT | Contextual description |
| data.source_location | TEXT | Source: file:line or HTTP endpoint |
| target_agents | JSON array | Suggested consumer agent names |

## Read Rules

### When to Read

Auditors SHOULD read shared findings at the following times:

1. **Before starting the attack phase**: Check whether other auditors have provided credentials/keys that can be directly leveraged
2. **After each failed attack round**: Check whether new bypass methods or internal endpoints are available to try
3. **During combination chain construction (R8)**: Retrieve all cross-auditor findings for chained exploitation

### Read Commands

```bash
# Read all findings (sorted by critical → high → medium)
bash tools/audit_db.sh finding-read "$WORK_DIR"

# Read only a specific type
bash tools/audit_db.sh finding-read "$WORK_DIR" credential

# Read only findings not yet consumed by this agent
bash tools/audit_db.sh finding-read "$WORK_DIR" "" sqli-auditor
```

Returns a JSON array that can be parsed directly with `jq`:

```bash
# Example: extract all unconsumed credentials
bash tools/audit_db.sh finding-read "$WORK_DIR" credential sqli-auditor \
  | jq -r '.[] | "\(.data_key)=\(.data_value)"'
```

### Consumption Marking

After the consumer reads a finding, mark it as consumed:

```bash
bash tools/audit_db.sh finding-consume "$WORK_DIR" 1 authz-auditor
# Arguments: WORK_DIR, finding_id, agent_name
```

### Consumer Behavior

| finding_type | Consumer | Behavior |
|---|---|---|
| credential (DB password) | sqli-auditor | Attempt direct database connection verification |
| credential (API key) | infoleak-auditor | Verify whether the key is active and its permission scope |
| secret_key (JWT_SECRET) | authz-auditor | Use for JWT Token forgery (R5) |
| secret_key (APP_KEY) | config-auditor | Use for Cookie decryption / signed URL forgery (R8) |
| internal_url | ssrf-auditor | Add to SSRF target list |
| internal_url (Redis) | nosql-auditor | Attempt Redis command injection |
| endpoint (admin) | authz-auditor | Add to privilege escalation test endpoint list |
| bypass_method | All auditors | Apply bypass techniques in failed rounds |
| config_value | crypto-auditor | Use for cryptographic analysis |

## Concurrency Safety

SQLite WAL mode natively supports concurrency:
- **Multiple readers reading simultaneously**: No locks needed, non-blocking
- **Single writer does not block readers**: WAL provides snapshot isolation
- **Write conflicts**: SQLite auto-retries (5-second timeout), fully sufficient for audit scenarios
- **ACID transactions**: Each write is atomic; no partial writes occur

No `flock` file locks needed.

## Statistics

```bash
# View finding statistics for the current audit
bash tools/audit_db.sh finding-stats "$WORK_DIR"
```

Example output:
```
=== 共享发现统计 ===
总发现: 12
  critical: 3
  high: 5
  medium: 4
---
按类型:
  credential: 4
  secret_key: 3
  internal_url: 3
  bypass_method: 2
---
按来源:
  infoleak-auditor: 5
  config-auditor: 3
  ssrf-auditor: 2
  sqli-auditor: 2
---
未消费: 4
```

## Migrating from JSONL

If existing JSONL data needs to be migrated during the audit:

```bash
bash tools/audit_db.sh migrate-findings "$WORK_DIR"
```

## Graph Memory Node Bridging

When an auditor writes a high-confidence graph node (`status = "confirmed"`), it SHOULD **also** write a shared finding so that other auditors can perceive related vulnerabilities via realtime sharing:

```bash
# After writing a graph node, synchronously write a shared finding
bash tools/audit_db.sh finding-write "$WORK_DIR" '{
  "source_agent": "{current auditor name}",
  "finding_type": "endpoint",
  "priority": "high",
  "data_key": "graph_node_{sink_id}",
  "data_value": "{vuln_type}: {summary}",
  "data_context": "Relational graph node confirmed — data_object={data_object}, severity={severity}",
  "source_location": "{route}",
  "target_agents": ["correlation_engine", "related auditor"]
}'
```

**Bridging conditions** (all MUST be met to bridge):
- Graph node `status = "confirmed"` (do not bridge suspected/speculative)
- Graph node `data_object` is non-empty (has a definite data object association)
- The data_object has not already been reported by another auditor in shared_findings

**Purpose**: Ensure bidirectional interoperability between the relational graph memory (globally persisted `attack_memory.db`) and session-level realtime sharing (`audit_session.db`), eliminating information silos.

## Constraints

- Written values MUST be **actually obtained data**; speculation is MUST NOT be used
- Sensitive credentials MUST be redacted in reports (originals are retained only in audit_session.db for audit use)
- audit_session.db is securely deleted by env-cleaner during Phase-5 cleanup (`shred` or `dd` overwrite followed by `rm`)
