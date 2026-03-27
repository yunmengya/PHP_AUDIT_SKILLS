# Phase-4.5 Quality Check — Correlation Analysis

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-084 |
| Category | QC |
| Responsibility | Validate correlation analysis outputs before GATE_4_5 passage |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `attack_graph.json` | attack_graph_builder | YES | `nodes`, `edges`; passes `schemas/attack_graph.schema.json` |
| `correlation_report.json` | correlation_engine | YES | `generated_at`, `total_findings`, `false_positives_removed`, `chains`, `summary`; passes `schemas/correlation_report.schema.json` |
| `PoC脚本/*.py` | poc_generator | YES | ≥1 Python file, syntax valid |
| `PoC脚本/一键运行.sh` | poc_generator | YES | Runner script referencing all PoC scripts |
| `PoC脚本/poc_summary.json` | poc_generator | YES | Valid JSON; passes `schemas/poc_summary.schema.json` |
| `修复补丁/*.patch` | remediation_generator | YES | ≥1 patch per confirmed vulnerability |
| `修复补丁/remediation_summary.json` | remediation_generator | YES | Valid JSON; patch-to-vulnerability mapping |
| `team4_progress.json` | Team-4 dispatcher | REF | Cross-reference for finding ID validation |
| `exploits/*.json` | Phase-4 auditors | REF | Cross-reference for vulnerability details |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | `correlation_report.json` MUST exist and be non-empty | FAIL — correlation_engine did not produce output |
| CR-2 | No duplicate `chain_id` values or identical chain compositions allowed | FAIL — deduplication logic broken |
| CR-3 | All vulnerability IDs referenced MUST exist in `team4_progress.json` or `exploits/*.json` | FAIL — referential integrity violation |
| CR-4 | `PoC脚本/` MUST contain ≥1 `.py` file that passes Python syntax check | FAIL — poc_generator must produce output |
| CR-5 | Severity escalation MUST be justified by actual chain relationships — no gratuitous escalation | FAIL — unjustified escalation |
| CR-6 | MUST-PASS: Checks 1–2, 5–6 (correlation report exists, no duplicates, finding IDs valid, PoC scripts pass syntax) | FAIL if any MUST-PASS check fails |
| CR-7 | MAY-WARN: Patch dry-run failures, graph edge completeness, escalation confidence levels | WARN only — does not block gate |

## Fill-in Procedure

### Procedure A: Correlation Report Completeness
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `correlation_report.json` exists and is non-empty | File exists, size > 0 bytes | {fill-in: file existence and size} | {✅/❌} |
| 2 | Required fields present: `generated_at`, `total_findings`, `false_positives_removed`, `chains`, `summary` | All 5 fields present | {fill-in: missing fields if any} | {✅/❌} |
| 3 | `total_findings` > 0 (at least one finding analyzed) | total_findings ≥ 1 | {fill-in: total_findings value} | {✅/❌} |
| 4 | `chains` array contains ≥0 entries (empty is valid if no chains found) | chains is a valid array | {fill-in: chain count} | {✅/❌} |
| 5 | `summary` is non-empty descriptive text (not placeholder) | summary.length > 0, not placeholder | {fill-in: summary length and content check} | {✅/❌} |

### Procedure B: No Duplicate Chains
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | No duplicate `chain_id` values in `chains` array | 0 duplicate chain_ids | {fill-in: duplicate chain_ids found} | {✅/❌} |
| 2 | No duplicate vulnerability reference pairs within a single chain — each `vulns` entry unique within its chain | 0 duplicate vuln pairs per chain | {fill-in: duplicate vuln pairs found} | {✅/❌} |
| 3 | No identical chain compositions — two chains must not contain the exact same set of `vulns` | 0 identical compositions | {fill-in: identical compositions found} | {✅/❌} |
| 4 | Each `chain_id` follows a consistent naming pattern | All chain_ids match naming convention | {fill-in: invalid chain_ids found} | {✅/❌} |

### Procedure C: Severity Escalation Justification
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | Each chain with `combined_impact` has a justified escalation reason | 0 unjustified escalations | {fill-in: unjustified escalations count} | {✅/❌} |
| 2 | Escalated severity is strictly higher than individual vulnerability severities — no gratuitous escalation | 0 gratuitous escalations | {fill-in: gratuitous escalations found} | {✅/❌} |
| 3 | `confidence` for chains is one of: `high`, `medium`, `low` | All confidence values in {high, medium, low} | {fill-in: invalid confidence values} | {✅/❌} |
| 4 | High-confidence chains require ≥2 confirmed individual vulnerabilities | Each high-confidence chain has ≥ 2 confirmed vulns | {fill-in: non-compliant high-confidence chains} | {✅/❌} |
| 5 | If `graph_correlations.escalations_from_graph` exists, each entry has `original_severities` and `combined_severity` with supporting chain evidence | All escalation entries have required fields | {fill-in: missing fields in escalations} | {✅/❌} |

### Procedure D: Attack Graph Validity
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `attack_graph.json` exists with `nodes` and `edges` | File exists with nodes and edges arrays | {fill-in: node_count, edge_count} | {✅/❌} |
| 2 | Graph nodes reference valid finding IDs from `exploits/*.json` | 0 invalid node references | {fill-in: invalid node references found} | {✅/❌} |
| 3 | Graph edges represent actual exploitable paths (not hypothetical connections) | 0 hypothetical-only edges | {fill-in: hypothetical edges count} | {✅/❌} |
| 4 | `data_flow_chains` (if present) have `source_node`, `target_node`, `relation` fields | All data_flow_chains have required fields | {fill-in: incomplete data_flow_chains} | {✅/❌} |
| 5 | No orphan nodes — every node has at least one edge connection or is explicitly isolated | 0 orphan nodes | {fill-in: orphan nodes count} | {✅/❌} |

### Procedure E: Finding ID Cross-Reference
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | All vulnerability IDs in `correlation_report.json` exist in `team4_progress.json` or `exploits/*.json` | 0 invalid references | {fill-in: invalid references count} | {✅/❌} |
| 2 | No references to non-existent findings (zero invalid references) | 0 invalid IDs | {fill-in: invalid IDs list} | {✅/❌} |
| 3 | `false_positives_removed` count is plausible relative to `total_findings` | fp_removed / total_findings ≤ 0.5 (plausible ratio) | {fill-in: fp ratio} | {✅/❌} |
| 4 | Removed false positives match patterns from `shared/false_positive_patterns.md` | All removals match known FP patterns | {fill-in: unmatched removals} | {✅/❌} |

### Procedure F: PoC Scripts Validation
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `PoC脚本/` directory contains ≥1 `.py` file | script_count ≥ 1 | {fill-in: script count} | {✅/❌} |
| 2 | All `.py` files pass Python syntax check: `python3 -c "compile(open('file').read(), 'file', 'exec')"` | syntax_pass_count = script_count | {fill-in: syntax_pass_count / script_count} | {✅/❌} |
| 3 | `一键运行.sh` exists and contains execution commands for all PoC scripts | Runner exists, covers all scripts | {fill-in: runner_exists, scripts covered} | {✅/❌} |
| 4 | `poc_summary.json` exists with valid JSON | Valid JSON, schema-compliant | {fill-in: validation result} | {✅/❌} |
| 5 | Target URLs in PoC scripts are consistent (use parameterized base URL, not hardcoded) | 0 hardcoded URLs | {fill-in: hardcoded URLs found} | {✅/❌} |

### Procedure G: Remediation Patches
| # | Check Item | Expected | Actual | Status |
|---|------------|----------|--------|--------|
| 1 | `修复补丁/` directory contains ≥1 `.patch` file | patch_count ≥ 1 | {fill-in: patch count} | {✅/❌} |
| 2 | Each confirmed vulnerability has a corresponding patch file | 0 confirmed vulns without patch | {fill-in: confirmed_without_patch count} | {✅/❌} |
| 3 | Each patch passes `patch --dry-run` verification against source | dry_run_pass = patch_count | {fill-in: dry_run_pass / patch_count} | {✅/❌} |
| 4 | `remediation_summary.json` exists with patch-to-vulnerability mapping | Valid JSON with complete mapping | {fill-in: validation result} | {✅/❌} |
| 5 | Patches contain specific code changes (before/after), not generic advice | 0 generic patches | {fill-in: generic patches count} | {✅/❌} |

### Procedure H: Final Verdict Determination
| Field | Fill-in Value |
|-------|--------------|
| Total checks passed | {pass_count} / 7 |
| Total findings analyzed | {total_findings} |
| Chain count | {chain_count} |
| False positives removed | {fp_removed} |
| PoC script count | {script_count} |
| PoC syntax pass rate | {syntax_pass_count / script_count} |
| Patch count | {patch_count} |
| Overall verdict | {PASS / CONDITIONAL_PASS / FAIL} |
| Verdict justification | {reason} |
| Failed items list | {failed_items} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase45.json` | See example below | Detailed check results with chain analysis |

## Examples

### ✅ GOOD: All Checks Pass
```json
{
  "qc_id": "qc-phase45-team45-20250101T120000Z",
  "phase": "4.5",
  "target_agent": "team4.5",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "basic_info": {
    "quality_checker": "S-084",
    "target": "Phase-4.5 output",
    "validated_files": ["{fill-in: actual file paths read}"]
  },
  "checks": {
    "correlation_report": { "status": "pass", "total_findings": 12, "chain_count": 3, "fp_removed": 2 },
    "deduplication": { "status": "pass", "duplicate_chain_ids": [], "duplicate_vuln_pairs": [] },
    "severity_escalation": { "status": "pass", "unjustified_escalations": 0, "high_confidence_chains": 2 },
    "attack_graph": { "status": "pass", "node_count": 10, "edge_count": 8, "orphan_nodes": 0 },
    "finding_references": { "status": "pass", "invalid_references": 0 },
    "poc_scripts": { "status": "pass", "script_count": 5, "syntax_pass_count": 5, "runner_exists": true },
    "remediation_patches": { "status": "pass", "patch_count": 5, "dry_run_pass": 5, "confirmed_without_patch": 0 }
  },
  "item_results": [
    {"id": 1, "check_item": "correlation_report exists", "expected": "File exists, size > 0", "actual": "{fill-in}", "status": "✅"},
    {"id": 2, "check_item": "no duplicate chains", "expected": "0 duplicates", "actual": "{fill-in}", "status": "✅"},
    {"id": 3, "check_item": "severity escalation justified", "expected": "0 unjustified", "actual": "{fill-in}", "status": "✅"},
    {"id": 4, "check_item": "attack graph valid", "expected": "nodes and edges present", "actual": "{fill-in}", "status": "✅"},
    {"id": 5, "check_item": "finding IDs valid", "expected": "0 invalid references", "actual": "{fill-in}", "status": "✅"},
    {"id": 6, "check_item": "PoC scripts pass syntax", "expected": "syntax_pass_count = script_count", "actual": "{fill-in}", "status": "✅"},
    {"id": 7, "check_item": "remediation patches valid", "expected": "0 confirmed without patch", "actual": "{fill-in}", "status": "✅"}
  ],
  "final_verdict": {
    "status": "PASS",
    "passed": "7/7",
    "failed_items": []
  },
  "pass_count": 7,
  "total_count": 7,
  "failed_items": []
}
```
Explanation: All 7 checks pass. No duplicate chains, all finding IDs valid, PoC scripts pass syntax, all patches pass dry-run. ✅

### ❌ BAD: Duplicate Chains and Invalid References
```json
{
  "qc_id": "qc-phase45-team45-20250101T120000Z",
  "phase": "4.5",
  "target_agent": "team4.5",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "fail",
  "checks": {
    "correlation_report": { "status": "pass", "total_findings": 8, "chain_count": 4, "fp_removed": 1 },
    "deduplication": { "status": "fail", "duplicate_chain_ids": ["chain-sqli-rce-01"], "duplicate_vuln_pairs": [["sink_01", "sink_02"]] },
    "severity_escalation": { "status": "fail", "unjustified_escalations": 2, "high_confidence_chains": 0 },
    "attack_graph": { "status": "pass", "node_count": 6, "edge_count": 4, "orphan_nodes": 0 },
    "finding_references": { "status": "fail", "invalid_references": 3 },
    "poc_scripts": { "status": "pass", "script_count": 3, "syntax_pass_count": 3, "runner_exists": true },
    "remediation_patches": { "status": "warn", "patch_count": 3, "dry_run_pass": 1, "confirmed_without_patch": 2 }
  },
  "pass_count": 3,
  "total_count": 7,
  "failed_items": ["deduplication", "severity_escalation", "finding_references"]
}
```
What's wrong: Duplicate chain ID `chain-sqli-rce-01` detected (violates CR-2). 3 invalid finding ID references (violates CR-3). 2 unjustified severity escalations without chain evidence (violates CR-5). ❌

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
| 1st failure | Re-run failing agent (correlation_engine / attack_graph_builder / poc_generator / remediation_generator) |
| Continued failure | Use `team4_progress.json` directly; proceed to Phase 5 with partial correlation (degraded) |
