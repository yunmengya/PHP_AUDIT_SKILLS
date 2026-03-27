# Attack-Graph-Builder

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-067 |
| Phase | Phase-4.5 |
| Responsibility | Identify chained exploitation paths and build attack graphs with Mermaid visualizations |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| exploits/*.json | `$WORK_DIR/exploits/*.json` | ✅ | Attack results from all auditors |
| team4_progress.json | `$WORK_DIR/.audit_state/team4_progress.json` | ✅ | Findings summary after QA verification |
| route_map.json | `$WORK_DIR/route_map.json` | ⚠️ Optional | Route map |
| auth_matrix.json | `$WORK_DIR/auth_matrix.json` | ⚠️ Optional | Authorization matrix |
| audit_session.db | `$WORK_DIR/audit_session.db` (shared_findings table) | ⚠️ Optional | Real-time shared findings |
| shared/attack_chains.md | Shared resource (L2) | ✅ | 10 known PHP attack chain patterns — MUST read before construction |
| shared/anti_hallucination.md | Shared resource (L2) | ✅ | Anti-hallucination rules |
| shared/data_contracts.md | Shared resource (L2) | ✅ | Data format contracts |
| WORK_DIR | Orchestrator parameter | ✅ | Working directory path |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST only build graph from discovered vulnerabilities; MUST NOT assume unverified vulns exist | Fabricated nodes → misleading attack paths |
| CR-2 | Every step in an attack path MUST reference a specific vulnerability ID and evidence | Unsubstantiated paths → hallucinated chains |
| CR-3 | Mermaid graph MUST NOT exceed 30 nodes (if exceeded, show only Top path nodes) | Oversized graph → unreadable visualization |
| CR-4 | Attack narratives MUST be understandable by non-technical personnel | Technical jargon → stakeholder confusion |
| CR-5 | MUST read `shared/attack_chains.md` BEFORE beginning graph construction | Missing known chain patterns → incomplete analysis |
| CR-6 | known_attack_path chains MUST have remediation_priority elevated by one level (P2→P1, P1→P0) | Under-prioritized known attack patterns |

## Fill-in Procedure

### Procedure A: Vulnerability Node Collection
| Field | Fill-in Value |
|-------|--------------|
| sources | {Collect all `confirmed` and `highly_suspected` vulns from `exploits/*.json` + `team4_progress.json`} |
| node_fields | {`node_id` (V-NNN), `vuln_type`, `sub_type`, `endpoint`, `confidence`, `output_data` (data/capability produced), `required_access`, `grants_access`, `severity`} |

### Procedure B: Attack Edge Construction
| Field | Fill-in Value |
|-------|--------------|
| edge_rule | {When vuln A's `output_data` can serve as vuln B's `input_requirement` → create directed edge A→B} |
| edge_fields | {`from`, `to`, `relationship` (credential_reuse/token_forge/privilege_escalation/data_extraction/lateral_movement), `description`} |

#### Standard Chain Pattern Library

| Chain Pattern | Entry | Intermediate | End |
|---------------|-------|--------------|-----|
| Info→Credential→Privilege Escalation | Info leak (keys/passwords) | Credential forging/acquisition | Vertical/horizontal privilege escalation |
| Config→Injection→RCE | Config leak (APP_KEY/JWT_SECRET) | Token forging/Cookie decryption | Admin RCE |
| Enumeration→Brute Force→Takeover | User enumeration | Weak password/no rate limiting | Account takeover |
| Injection→File Read→More Injections | SQL injection (file read) | Source code acquisition | Discover more injection points |
| SSRF→Internal Network→Data | SSRF | Internal service discovery | Database/cache/API access |
| XSS→CSRF→Privilege Escalation | Stored XSS | CSRF to admin operations | Privilege escalation |
| File Upload→Include→RCE | File write (Webshell) | LFI include | Remote code execution |
| Deserialization→RCE→Persistence | Deserialization | Code execution | Webshell/backdoor |
| Race Condition→Duplicate Op→Funds | Race condition | Double spending/balance overflow | Financial loss |
| Weak Crypto→Forgery→Impersonation | Crypto weakness (predictable token) | Token prediction/forgery | Identity impersonation |

### Procedure C: Known Attack Chain Pattern Matching (BEFORE Path Discovery)
| Field | Fill-in Value |
|-------|--------------|
| prerequisite | {MUST first read `shared/attack_chains.md` — contains 10 known PHP attack chain patterns} |
| vuln_type_set | {Extract `vuln_type` + `sub_type` combinations from all nodes → form `V_set`} |
| pattern_scan | {Iterate 10 chain patterns from `shared/attack_chains.md`, subset-match each chain's Sink Type sequence against `V_set`} |
| full_match | {All chain steps have corresponding Sink Types in `V_set` → `known_attack_path` → auto-elevate priority (P2→P1, P1→P0)} |
| partial_match | {≥60% steps matched → `potential_known_path` → indicate missing steps in report} |
| no_match | {<60% matched → skip this chain pattern} |
| output_field | {Add `matched_chain` field to path (e.g., `"chain_3_ssrf_internal_rce"`); append to narrative: "This path matches known attack chain pattern [Chain X: name]"} |

### Procedure D: Path Discovery (DFS)
| Field | Fill-in Value |
|-------|--------------|
| algorithm | {Depth-First Search from low-privilege entry points to high-impact end goals} |
| entry_conditions | {`required_access`="anonymous"; `required_access`="authenticated" with default/weak credentials; publicly accessible info leaks} |
| end_goals | {RCE, full DB access, admin account takeover, mass user data leak, significant financial/business logic loss} |
| path_scoring | {`path_score = Σ(node_severity) × chain_length_bonus × confidence_factor`; node_severity: confirmed=10, highly_suspected=6, potential_risk=3; chain_length_bonus: 1-step=1.0, 2-step=1.5, 3-step=2.0, 4+-step=2.5; confidence_factor: all_confirmed=1.0, has_suspected=0.7, has_potential=0.4} |

### Procedure E: Impact Escalation Analysis
| Field | Fill-in Value |
|-------|--------------|
| pattern_check | {Identify "individually low-risk but combined high-risk" patterns:} |
| escalation_1 | {Info Leak + Weak Auth → individually Medium, combined Critical (account takeover)} |
| escalation_2 | {SSRF + Cloud Environment → individually Medium, combined Critical (IAM credential acquisition)} |
| escalation_3 | {XSS + No CSP + Session Cookie → individually Medium, combined High (session hijacking)} |
| escalation_4 | {SQLi (read-only) + File Write → individually High, combined Critical (RCE)} |
| escalation_5 | {User Enumeration + No Rate Limiting + Weak Password → individually Low/Info each, combined High} |

### Procedure F: Chain Exploitation Feasibility Scoring
| Field | Fill-in Value |
|-------|--------------|
| scope | {Score each matched attack chain (both `known_attack_path` and `potential_known_path`)} |

**Feasibility Checklist:**

| Check Dimension | Check Content | Weight |
|-----------------|---------------|--------|
| Docker Environment | Target runs in Docker container (affects SSRF→Docker API path) | 0.15 |
| Internal Service Reachability | Redis/Memcached/internal APIs reachable via SSRF or direct access | 0.20 |
| Filesystem Permissions | Web process read/write on log dirs, upload dirs, session dirs | 0.15 |
| PHP Configuration | `allow_url_include`, `disable_functions`, `open_basedir` restrictions | 0.15 |
| Framework & Dependency Versions | Laravel/Symfony/Yii version matches known POP gadget chains | 0.10 |
| WAF/Filtering Mechanisms | WAF, input filtering, CSP existence and bypass feasibility | 0.10 |
| Network Isolation | Internal network segmentation, inter-service restrictions | 0.10 |
| Authentication Requirements | Chain entry requires auth, default/weak credentials available | 0.05 |

**Scoring Formula:**
```
feasibility_score = Σ(check_item_score × weight) × 100
  check_item_score: confirmed=1.0, suspected=0.5, unknown=0.0, explicitly_not_met=-0.3
```

**Score Levels:**

| Score Range | Level | Handling |
|-------------|-------|---------|
| 80-100 | High Feasibility | Critical path, P0 priority, detail exploitation steps |
| 50-79 | Medium Feasibility | Retain in graph, note prerequisites needing verification |
| 20-49 | Low Feasibility | Dashed lines in graph, explain blocking reasons |
| <20 | Infeasible | Remove from main graph, record as "theoretical path" in appendix |

### Procedure G: Mermaid Graph Generation
| Field | Fill-in Value |
|-------|--------------|
| format | {`graph TD` with node labels: `V001[Vuln Type: description<br/>confidence ✅/⚠️]`} |
| color_coding | {Red (#ff4444): confirmed + Critical/High; Orange (#ffaa00): highly_suspected or Medium; Yellow (#ffdd00): potential_risk or Low} |
| edge_thickness | {Indicates path confidence level} |
| node_limit | {Max 30 nodes; if exceeded, show only nodes related to Top paths} |

### Procedure H: Attack Narrative Generation
| Field | Fill-in Value |
|-------|--------------|
| scope | {Top-3 attack paths by score} |
| format | {Numbered steps: `[Access Level] Action description (confidence)`; ending with `→ Impact:` and `→ Remediation Priority:`} |
| language | {Natural language understandable by non-technical personnel} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| attack_graph.json | `$WORK_DIR/原始数据/attack_graph.json` | JSON | Complete attack graph: nodes[], edges[], paths[], escalation_patterns[], chain_matches[], mermaid_diagram |

### attack_graph.json Schema
```json
{
  "generated_at": "ISO-8601",
  "total_nodes": "number",
  "total_edges": "number",
  "total_paths": "number",
  "nodes": [{
    "node_id": "V-001",
    "vuln_type": "string",
    "sub_type": "string",
    "endpoint": "string",
    "confidence": "string",
    "output_data": "string",
    "required_access": "string",
    "grants_access": "string",
    "severity": "string"
  }],
  "edges": [{
    "from": "V-001",
    "to": "V-005",
    "relationship": "string",
    "description": "string"
  }],
  "paths": [{
    "path_id": "P-001",
    "score": "number",
    "confidence": "string",
    "nodes": ["V-001", "V-005", "V-008"],
    "entry_point": "string",
    "final_impact": "string",
    "narrative": "string",
    "remediation_priority": "string",
    "matched_chain": "string (if matched known pattern)",
    "feasibility": {
      "score": "number",
      "level": "string",
      "checks": {}
    }
  }],
  "escalation_patterns": [{
    "pattern_name": "string",
    "involved_vulns": ["V-001", "V-002"],
    "individual_severity": "string",
    "combined_severity": "string",
    "explanation": "string"
  }],
  "chain_matches": [{
    "chain_id": "string",
    "chain_name": "string",
    "match_type": "string",
    "matched_vulns": ["string"],
    "missing_steps": ["string"],
    "priority_elevation": "string"
  }],
  "mermaid_diagram": "string"
}
```

## Examples

### ✅ GOOD: Multi-Step Attack Path
```json
{
  "generated_at": "2024-01-15T12:00:00Z",
  "total_nodes": 5,
  "total_edges": 4,
  "total_paths": 2,
  "nodes": [
    {"node_id": "V-001", "vuln_type": "InfoLeak", "sub_type": "env_exposure", "endpoint": "/.env", "confidence": "confirmed", "output_data": "APP_KEY, DB_PASSWORD", "required_access": "anonymous", "grants_access": "config_secrets", "severity": "High"},
    {"node_id": "V-002", "vuln_type": "SessionForgery", "sub_type": "cookie_decrypt", "endpoint": "/admin", "confidence": "confirmed", "output_data": "admin session", "required_access": "config_secrets", "grants_access": "admin_access", "severity": "Critical"},
    {"node_id": "V-003", "vuln_type": "RCE", "sub_type": "command_injection", "endpoint": "/admin/system/exec", "confidence": "confirmed", "output_data": "shell access", "required_access": "admin_access", "grants_access": "full_server", "severity": "Critical"}
  ],
  "edges": [
    {"from": "V-001", "to": "V-002", "relationship": "token_forge", "description": "APP_KEY enables Laravel cookie decryption and admin session forging"},
    {"from": "V-002", "to": "V-003", "relationship": "privilege_escalation", "description": "Admin session grants access to command execution endpoint"}
  ],
  "paths": [{
    "path_id": "P-001",
    "score": 47.5,
    "confidence": "high",
    "nodes": ["V-001", "V-002", "V-003"],
    "entry_point": "Anonymous access to /.env",
    "final_impact": "Full server control via RCE",
    "narrative": "1. [Anonymous] Access /.env to obtain APP_KEY and DB_PASSWORD (confirmed)\n2. [Anonymous] Use APP_KEY to decrypt Laravel Cookie, forge admin Session (confirmed)\n3. [Admin] Access /admin/system/exec to execute arbitrary commands (confirmed)\n→ Impact: 3-step chain from anonymous to full server control\n→ Remediation Priority: P0 Urgent",
    "remediation_priority": "P0",
    "matched_chain": "chain_5_info_leak_token_forge",
    "feasibility": {"score": 92, "level": "high", "checks": {"docker_env": {"status": "confirmed"}, "auth_requirements": {"status": "confirmed", "evidence": "Entry point is anonymous"}}}
  }],
  "chain_matches": [{
    "chain_id": "chain_5_info_leak_token_forge",
    "chain_name": "Info Leak -> Token Forgery -> Privilege Escalation",
    "match_type": "full_match",
    "matched_vulns": ["V-001", "V-002", "V-003"],
    "missing_steps": [],
    "priority_elevation": "P1 → P0"
  }],
  "mermaid_diagram": "graph TD\n    V001[Info Leak: .env exposure<br/>confirmed ✅] -->|APP_KEY extraction| V002[Session Forgery<br/>confirmed ✅]\n    V002 -->|Admin identity| V003[Admin RCE<br/>confirmed ✅]\n    style V001 fill:#ff4444,stroke:#333\n    style V002 fill:#ff4444,stroke:#333\n    style V003 fill:#ff4444,stroke:#333"
}
```
Explanation ✅ Every node references specific vulnerability evidence. Chain matches known pattern (chain_5). Feasibility scored. Narrative is non-technical. Mermaid graph under 30 nodes.

### ❌ BAD: Assumed Vulnerabilities
```json
{
  "nodes": [
    {"node_id": "V-001", "vuln_type": "SQLi", "confidence": "confirmed"},
    {"node_id": "V-099", "vuln_type": "RCE", "confidence": "assumed", "endpoint": "/admin/exec"}
  ],
  "paths": [{
    "nodes": ["V-001", "V-099"],
    "narrative": "SQL injection probably leads to RCE through some admin panel"
  }]
}
```
What's wrong ❌ V-099 has confidence "assumed" — not a discovered vulnerability (CR-1 violated). No evidence referenced (CR-2 violated). Narrative uses vague "probably" and "some" — not specific. No scoring, no feasibility check, no chain matching.

## Error Handling
| Error | Action |
|-------|--------|
| No confirmed vulnerabilities found | Generate empty attack_graph.json with total_nodes=0, log info |
| Only single isolated vulnerabilities (no chains possible) | Generate graph with nodes only, no edges/paths, note "no chained paths identified" |
| `shared/attack_chains.md` not found | Skip known chain matching (Procedure C), log warning, proceed with organic path discovery |
| Mermaid graph exceeds 30 nodes | Filter to Top-3 path nodes only, note truncation in output |
| route_map.json or auth_matrix.json not found | Proceed without them, note reduced analysis scope |
| Circular dependency in attack edges | Break cycle, log warning, mark path as "contains cycle" |
