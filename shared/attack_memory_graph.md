# Relational Attack Memory (Attack Memory Graph)

On top of the flat records in `attack_memory.md`, a relational memory layer is added to record **semantic relationships** between vulnerabilities, enabling correlation_engine and subsequent audits to discover cross-Sink attack chains.

---

## Design Principles

Inspired by PentAGI's Graphiti knowledge graph approach, uses SQLite relational tables to simulate graph structures (zero dependencies, no Neo4j required):

- **Node**: Each discovered vulnerability/weakness/configuration issue
- **Edge**: Exploitation relationships between vulnerabilities (data flow, privilege escalation, combined attacks)
- **Property**: Metadata for nodes and edges (severity, reachability, prerequisites)

## Data Structure

### Node Table: `memory_nodes`

```sql
CREATE TABLE IF NOT EXISTS memory_nodes (
    node_id     TEXT PRIMARY KEY,     -- Format: {project_hash}_{sink_id}
    vuln_type   TEXT NOT NULL,        -- sqli/rce/xss/ssrf/lfi/authz/config/...
    sink_id     TEXT NOT NULL,        -- Corresponding sink_id
    route       TEXT,                 -- Associated route path
    severity    TEXT,                 -- critical/high/medium/low/info
    status      TEXT,                 -- confirmed/suspected/potential
    framework   TEXT,                 -- Laravel/ThinkPHP/...
    data_object TEXT,                 -- Involved data object (e.g., users table, session cookie)
    summary     TEXT,                 -- One-line description
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_nodes_type ON memory_nodes(vuln_type);
CREATE INDEX idx_nodes_data ON memory_nodes(data_object);
```

### Edge Table: `memory_edges`

```sql
CREATE TABLE IF NOT EXISTS memory_edges (
    edge_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node TEXT NOT NULL REFERENCES memory_nodes(node_id),
    target_node TEXT NOT NULL REFERENCES memory_nodes(node_id),
    relation    TEXT NOT NULL,         -- Relation type (see enumeration below)
    direction   TEXT DEFAULT 'forward', -- forward/bidirectional
    confidence  TEXT DEFAULT 'probable', -- confirmed/probable/speculative
    evidence    TEXT,                  -- Relationship evidence description
    combined_severity TEXT,           -- Combined severity after escalation
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(source_node, target_node, relation)
);
CREATE INDEX idx_edges_relation ON memory_edges(relation);
CREATE INDEX idx_edges_source ON memory_edges(source_node);
```

### Relation Type Enumeration

| relation Value | Meaning | Example |
|----------------|---------|---------|
| `data_flows_to` | A's output data flows into B's input | SQLi writes to DB → Stored XSS reads from DB |
| `enables` | Exploiting A is a prerequisite for B | Config leaks .env → obtain key → forge Token |
| `escalates_to` | A + B combined escalates severity | SSRF(Medium) + Docker API(Info) → Host RCE(Critical) |
| `shares_data_object` | A and B operate on the same data object | Registration Mass Assignment + Export IDOR share users table |
| `same_entry_point` | A and B share the same entry route | Same endpoint has both SQLi and XSS |
| `auth_chain` | A's auth bypass makes B reachable | Auth Bypass → access admin panel → RCE |
| `pivot_from` | After A fails, pivot to B | RCE disable_functions → Deserialization RCE |

## Write Protocol

### Timing 1: After Phase-4 Auditor Attack Completion

Each Auditor writes a node when writing to `attack_memory.db`:

```bash
bash tools/audit_db.sh graph-node-write '{
  "node_id": "a1b2c3_sink_012",
  "vuln_type": "sqli",
  "sink_id": "sink_012",
  "route": "/api/users?sort=",
  "severity": "high",
  "status": "confirmed",
  "framework": "Laravel",
  "data_object": "users",
  "summary": "ORDER BY injection, can UNION SELECT to read arbitrary tables"
}'
```

### Timing 2: When Phase-4 Auditor Discovers Cross-Sink Relationships

When an Auditor discovers associations with other Sinks during analysis or attack, write an edge:

```bash
bash tools/audit_db.sh graph-edge-write '{
  "source_node": "a1b2c3_sink_012",
  "target_node": "a1b2c3_sink_045",
  "relation": "data_flows_to",
  "confidence": "probable",
  "evidence": "sink_012 SQLi can write to users.bio field; sink_045 template rendering reads users.bio without escaping"
}'
```

### Timing 3: After Phase-4.5 Correlation Engine Completes Association Analysis

The Correlation Engine writes discovered attack chains when performing cross-auditor correlation:

```bash
bash tools/audit_db.sh graph-edge-write '{
  "source_node": "a1b2c3_sink_012",
  "target_node": "a1b2c3_sink_045",
  "relation": "escalates_to",
  "confidence": "confirmed",
  "evidence": "SQLi(High) + SSTI(Medium) combined → RCE(Critical), verified through PoC",
  "combined_severity": "critical"
}'
```

## Read Protocol

### Query 1: Get All Associations for a Node (For Auditor Reference)

```bash
# Query all nodes and edges associated with sink_012
bash tools/audit_db.sh graph-neighbors "a1b2c3_sink_012"
```

Returns: all incoming and outgoing edges for that node + associated node summaries

### Query 2: Get Complete Attack Surface for a Data Object (For Correlation Engine)

```bash
# Query all vulnerability nodes operating on the users table
bash tools/audit_db.sh graph-by-data-object "users"
```

Returns: all nodes with `data_object = "users"` + edges between them

### Query 3: Get Complete Attack Graph (For Report Writer)

```bash
# Export complete graph structure as JSON
bash tools/audit_db.sh graph-export "$WORK_DIR"
```

Returns: all nodes + all edges as JSON, for generating attack graph visualization

## Integration with Existing Systems

| System | Integration Method |
|--------|-------------------|
| `attack_memory.md` (flat memory) | Graph nodes are extensions of flat records; each confirmed/failed record simultaneously generates a node |
| `correlation_engine.md` | After Step 2/3 execution, writes escalations and second_order results as graph edges |
| `attack_graph_builder.md` | Reads `escalates_to` and `auth_chain` edges from the graph; directly used for attack graph construction |
| `shared_findings` (SQLite) | Real-time sharing within a single audit; graph memory is persistent cross-audit relationships |
| `report_writer.md` | Reads graph-export to generate the "Vulnerability Relationship Graph" section |

## Constraints

- Node IDs MUST include project hash prefix to avoid cross-project conflicts
- Edge confidence MUST have evidence support; relationships MUST NOT be speculated without basis
- `combined_severity` SHALL only be filled for `escalates_to` relationships
- Graph memory coexists with flat memory (attack_memory table) in the same SQLite file `attack_memory.db`
- Capacity control: when nodes exceed 5000, the oldest speculative nodes are cleaned up by created_at
