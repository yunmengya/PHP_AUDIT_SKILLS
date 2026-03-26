> **Skill ID**: S-084 | **Phase**: 4.5 (QC) | **Gate**: GATE_4_5
> **Input**: Phase 4.5 outputs
> **Output**: quality_report_phase45.json

# Phase-4.5 Quality Check — Correlation Analysis

## Identity

Quality checker for Phase 4.5. Validates correlation analysis outputs before GATE_4_5 passage. Ensures `correlation_report.json` is non-empty, attack chains contain no duplicate vulnerability references, severity escalations are justified by actual chain relationships, PoC scripts are generated and executable, and remediation patches are applicable.

## Input Contract

| Source | Path | Required | Validation |
|--------|------|----------|------------|
| Attack graph | `$WORK_DIR/attack_graph.json` | YES | Valid JSON, passes `schemas/attack_graph.schema.json` |
| Correlation report | `$WORK_DIR/correlation_report.json` | YES | Valid JSON, passes `schemas/correlation_report.schema.json` |
| PoC scripts | `$WORK_DIR/PoC脚本/*.py` | YES | ≥1 Python file, syntax valid |
| PoC runner | `$WORK_DIR/PoC脚本/一键运行.sh` | YES | Exists, references all PoC scripts |
| PoC summary | `$WORK_DIR/PoC脚本/poc_summary.json` | YES | Valid JSON, passes `schemas/poc_summary.schema.json` |
| Remediation patches | `$WORK_DIR/修复补丁/*.patch` | YES | ≥1 patch for each confirmed vuln |
| Remediation summary | `$WORK_DIR/修复补丁/remediation_summary.json` | YES | Valid JSON |
| Team4 progress | `$WORK_DIR/team4_progress.json` | REF | Cross-reference for finding ID validation |
| Exploits | `$WORK_DIR/exploits/*.json` | REF | Cross-reference for vulnerability details |

## Check Procedure

### Check 1: Correlation Report Completeness
- [ ] `correlation_report.json` exists and is non-empty
- [ ] Required fields present: `generated_at`, `total_findings`, `false_positives_removed`, `chains`, `summary`
- [ ] `total_findings` > 0 (at least one finding was analyzed)
- [ ] `chains` array contains ≥0 entries (empty is valid if no chains found)
- [ ] `summary` is non-empty descriptive text (not placeholder)

### Check 2: No Duplicate Chains
- [ ] No duplicate `chain_id` values in `chains` array
- [ ] No duplicate vulnerability reference pairs within a single chain — each `vulns` entry is unique within its chain
- [ ] No identical chain compositions — two chains must not contain the exact same set of `vulns`
- [ ] Each `chain_id` follows a consistent naming pattern

### Check 3: Severity Escalation Justification
- [ ] Each chain with `combined_impact` has a justified escalation reason
- [ ] Escalated severity is strictly higher than individual vulnerability severities — no gratuitous escalation
- [ ] `confidence` for chains is one of: `high`, `medium`, `low`
- [ ] High-confidence chains require ≥2 confirmed individual vulnerabilities
- [ ] If `graph_correlations.escalations_from_graph` exists, each entry has `original_severities` and `combined_severity` with supporting chain evidence

### Check 4: Attack Graph Validity
- [ ] `attack_graph.json` exists with `nodes` and `edges`
- [ ] Graph nodes reference valid finding IDs from `exploits/*.json`
- [ ] Graph edges represent actual exploitable paths (not hypothetical connections)
- [ ] `data_flow_chains` (if present) have `source_node`, `target_node`, `relation` fields
- [ ] No orphan nodes — every node has at least one edge connection or is explicitly isolated

### Check 5: Finding ID Cross-Reference
- [ ] All vulnerability IDs referenced in `correlation_report.json` exist in `team4_progress.json` or `exploits/*.json`
- [ ] No references to non-existent findings (zero invalid references)
- [ ] `false_positives_removed` count is plausible relative to `total_findings`
- [ ] Removed false positives match patterns from `shared/false_positive_patterns.md`

### Check 6: PoC Scripts Validation
- [ ] `PoC脚本/` directory contains ≥1 `.py` file
- [ ] All `.py` files pass Python syntax check: `python3 -c "compile(open('file').read(), 'file', 'exec')"`
- [ ] `一键运行.sh` exists and contains execution commands for all PoC scripts
- [ ] `poc_summary.json` exists with valid JSON
- [ ] Target URLs in PoC scripts are consistent (use parameterized base URL, not hardcoded)

### Check 7: Remediation Patches
- [ ] `修复补丁/` directory contains ≥1 `.patch` file
- [ ] Each confirmed vulnerability has a corresponding patch file
- [ ] Each patch passes `patch --dry-run` verification against source
- [ ] `remediation_summary.json` exists with patch-to-vulnerability mapping
- [ ] Patches contain specific code changes (before/after), not generic advice

## Verdict Rules

| Condition | Verdict |
|-----------|---------|
| All checks pass, no duplicates, escalations justified | PASS |
| Minor issues: 1–2 patches fail dry-run, PoC URLs slightly inconsistent | CONDITIONAL_PASS (list exceptions) |
| `correlation_report.json` missing or empty | FAIL — correlation_engine did not produce output |
| Duplicate chains detected | FAIL — deduplication logic broken |
| Invalid finding ID references (> 0) | FAIL — referential integrity violation |
| No PoC scripts generated | FAIL — poc_generator must produce output |
| Severity escalation without chain evidence | FAIL — unjustified escalation |

**MUST-PASS items:** Correlation report exists, no duplicates, finding IDs valid, PoC scripts exist and pass syntax
**MAY-WARN items:** Patch dry-run failures, graph edge completeness, escalation confidence levels

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase45.json` | Detailed check results with chain analysis |

**Output JSON structure:**
```json
{
  "qc_id": "qc-phase45-team45-{timestamp}",
  "phase": "4.5",
  "target_agent": "team4.5",
  "timestamp": "ISO-8601",
  "verdict": "pass|conditional_pass|fail",
  "checks": {
    "correlation_report": { "status": "pass|fail", "total_findings": 0, "chain_count": 0, "fp_removed": 0 },
    "deduplication": { "status": "pass|fail", "duplicate_chain_ids": [], "duplicate_vuln_pairs": [] },
    "severity_escalation": { "status": "pass|fail", "unjustified_escalations": 0, "high_confidence_chains": 0 },
    "attack_graph": { "status": "pass|fail", "node_count": 0, "edge_count": 0, "orphan_nodes": 0 },
    "finding_references": { "status": "pass|fail", "invalid_references": 0 },
    "poc_scripts": { "status": "pass|fail", "script_count": 0, "syntax_pass_count": 0, "runner_exists": false },
    "remediation_patches": { "status": "pass|fail|warn", "patch_count": 0, "dry_run_pass": 0, "confirmed_without_patch": 0 }
  },
  "pass_count": 0,
  "total_count": 7,
  "failed_items": []
}
```

## Error Handling

| Error | Action |
|-------|--------|
| Missing `correlation_report.json` | FAIL — correlation_engine did not produce output |
| Missing `attack_graph.json` | FAIL — attack_graph_builder did not produce output |
| Malformed JSON in any output | FAIL — data integrity issue |
| No PoC scripts in `PoC脚本/` | FAIL — poc_generator must be re-run |
| PoC syntax errors | FAIL — poc_generator must fix Python syntax |
| Patch `--dry-run` failure | WARN — patch may be against wrong code version; log but don't block |
| All finding IDs invalid | FAIL — correlation ran against stale data; re-run after Phase 4 |

## Redo Rules

| Attempt | Action |
|---------|--------|
| 1st failure | Re-run failing agent (correlation_engine / attack_graph_builder / poc_generator / remediation_generator) |
| Continued failure | Use `team4_progress.json` directly; proceed to Phase 5 with partial correlation (degraded) |
