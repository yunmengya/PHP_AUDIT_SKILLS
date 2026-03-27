# Cross-File Reference Integrity Check

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-111 |
| Category | Shared Protocol |
| Responsibility | Verify that all cross-file ID references (sink_id, route_id, finding_id) actually exist in their source files |

> **Problem solved**: Without this check, an agent can hallucinate a `sink_id` that does not exist in `ast_sinks.json`.
> The fabricated ID enters the pipeline, triggers downstream auditors/reporters to analyze a non-existent vulnerability.

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-REF-1 | Every ID referenced in output MUST exist in the declared source file — fabricated IDs violate anti-hallucination Rule 1 | Phantom vulnerability enters pipeline |
| CR-REF-2 | The Reference Integrity Table MUST be filled for ALL cross-file references — empty = QC FAIL | Unverified references slip through |
| CR-REF-3 | If source file is unavailable (degraded), mark `N/A — degraded` and use verdict `suspected` | Agent guesses IDs instead of verifying |
| CR-REF-4 | If a referenced ID does NOT exist in source → MUST NOT include it in output — remove or report as error | Orphaned reference propagates downstream |

## Reference Relationship Map

The following cross-file reference relationships MUST be verified:

| Agent Type | Output Field | Source File | Source Field | Relationship |
|-----------|-------------|-------------|-------------|-------------|
| Risk Classifier (S-033) | `priority_queue[].sink_id` | `ast_sinks.json` | `sink_id` | Each sink in queue MUST exist in AST scan |
| Risk Classifier (S-033) | `priority_queue[].route_id` | `route_map.json` | `route_id` | Each route reference MUST exist in route map |
| Task Packager (S-039) | `task_packages[].route_id` | `route_map.json` | `route_id` | Task route MUST exist in route map |
| Task Packager (S-039) | `task_packages[].sink_id` | `priority_queue.json` | `sink_id` | Task sink MUST exist in priority queue |
| All Auditors (Phase-4) | `exploits/{sink_id}.json` filename | `priority_queue.json` | `sink_id` | Audited sink MUST be from priority queue |
| All Auditors (Phase-4) | `evidence[].trace` file:line refs | Source code files | Actual lines | Code references MUST exist on disk |
| Correlation (S-070~074) | `finding_id` references | `exploits/*.json` | `sink_id` | Correlated finding MUST reference real exploit |
| Coverage Gaps (S-073) | `uncovered_routes[]` | `route_map.json` | `route_id` | Uncovered route MUST exist in route map |
| Report Writers (Phase-5) | `sink_id` in detail pages | `exploits/*.json` | `sink_id` | Reported vulnerability MUST have exploit result |

## Fill-in Procedure

### Reference Integrity Verification Table (MANDATORY)

For each cross-file reference in your output, fill one row:

| # | My Output Field | Value Used | Source File | Verified Exists | Evidence |
|---|----------------|-----------|-------------|-----------------|----------|
| 1 | {field name} | {actual ID value, e.g., sink_001} | {source file path} | {✅ / ❌ / N/A-degraded} | {line # in source, or jq query result} |
| 2 | {field name} | {actual ID value} | {source file path} | {✅ / ❌ / N/A-degraded} | {evidence of existence} |
| ... | ... | ... | ... | ... | ... |

### Verification Commands

Use the following commands to verify references:

```bash
# Verify sink_id exists in ast_sinks.json
jq -e '.[] | select(.sink_id == "SINK_ID_HERE")' "$WORK_DIR/ast_sinks.json"

# Verify route_id exists in route_map.json
jq -e '.routes[] | select(.route_id == "ROUTE_ID_HERE")' "$WORK_DIR/route_map.json"

# Verify sink_id exists in priority_queue.json
jq -e '.[] | select(.sink_id == "SINK_ID_HERE")' "$WORK_DIR/priority_queue.json"

# Verify exploit result exists
ls "$WORK_DIR/exploits/SINK_ID_HERE.json"

# Verify source code file:line exists
sed -n 'LINE_NUMp' "SOURCE_FILE_PATH"
```

### On Verification Failure

| Scenario | Action |
|----------|--------|
| Referenced ID not found in source file | REMOVE the reference from your output — do NOT fabricate |
| Source file does not exist | Check if upstream phase is degraded; if yes, mark `N/A — degraded` |
| Source file exists but is empty | Treat as degraded; mark all references as `suspected` |
| Multiple IDs fail verification | Re-read source files; if genuinely missing, reduce output scope |

## Integration Template

Agents producing cross-file references MUST add:

```markdown
## Reference Integrity Check (MUST Execute)

Per `shared/reference_integrity_check.md`, verify all cross-file references:

| # | My Output Field | Value | Source File | Verified | Evidence |
|---|----------------|-------|-------------|----------|----------|
| 1 | {field} | {id} | {source} | {✅/❌} | {proof} |

CR-REF-1: Any ❌ → remove from output. MUST NOT include unverified references.
```

## Examples

### ✅ GOOD: All References Verified

```
Reference Integrity Check:
| # | My Output Field | Value | Source File | Verified | Evidence |
| 1 | sink_id | sink_042 | ast_sinks.json | ✅ | jq found: {"sink_id":"sink_042","function":"query","file":"UserController.php","line":45} |
| 2 | route_id | route_007 | route_map.json | ✅ | jq found: {"route_id":"route_007","url":"/api/users","method":"GET"} |
| 3 | trace ref | UserController.php:45 | Source code | ✅ | sed -n '45p': "$pdo->query("SELECT * FROM users WHERE id='$id'")" |
```
All references verified against source files ✅

### ❌ BAD: Unverified References Submitted

```
Reference Integrity Check:
| # | My Output Field | Value | Source File | Verified | Evidence |
| 1 | sink_id | sink_099 | ast_sinks.json | ❌ | jq returned empty — ID not found |

Output still contains: "sink_id": "sink_099" → SUBMITTED
```
Violates CR-REF-4: unverified ID not removed from output. Phantom vulnerability enters pipeline ❌
