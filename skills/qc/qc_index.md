# QC Skills — Master Index

> Phase-specific quality check skills for the PHP security audit pipeline. Each QC skill validates outputs from its corresponding phase before gate passage.

## Skill Registry

| Skill ID | File | Phase | Gate | Key Checks |
|----------|------|-------|------|------------|
| S-080 | qc_phase1.md | 1 | GATE_1 | Docker containers running, PHP version detected, framework identified, composer parsed, Xdebug trace mode |
| S-081 | qc_phase2.md | 2 | GATE_2 | route_map.json completeness, auth_matrix coverage ≥ 80%, priority_queue valid (0 < P0 ≤ 20), scanner outputs exist, context_packs coverage |
| S-082 | qc_phase3.md | 3 | GATE_3 | credentials.json valid, traces have Source→Sink call chains, chain completeness ≥ 70%, context_packs coverage ≥ 80% of priority routes |
| S-083 | qc_phase4.md | 4 | GATE_4 | exploits have valid final_verdict, EVID evidence chains complete, severity scoring consistent, prerequisites declared, sink coverage ≥ 90% |
| S-084 | qc_phase45.md | 4.5 | GATE_4_5 | correlation_report non-empty, no duplicate chains, severity escalations justified, PoC scripts executable, patches applicable |
| S-085 | qc_phase5.md | 5 | Final | Report structure matches template, P0/P1 100% coverage, confirmed vulns have PoC + evidence, Chinese output, SARIF valid, file organization correct |

## Gate Flow

```
Phase 1 → [S-080: Environment QC] → GATE_1 ────→ Phase 2
Phase 2 → [S-081: Recon QC]        → GATE_2 ────→ Phase 3
Phase 3 → [S-082: Trace QC]        → GATE_3 ────→ Phase 4
Phase 4 → [S-083: Exploit QC]      → GATE_4 ────→ Phase 4.5
Phase 4.5 → [S-084: Correlation QC] → GATE_4_5 ──→ Phase 5
Phase 5 → [S-085: Report QC]       → Final Gate → Audit Complete
```

## Shared Dependencies

All QC skills reference:
- `teams/qc/quality_checker.md` — Generic quality checker agent behavior
- `teams/qc/qc_dispatcher.md` — Dispatch logic and redo policies
- `references/quality_check_templates.md` — Phase-specific verification checklists
- `shared/output_standard.md` — 6 iron rules and output constraints
- `shared/data_contracts.md` — Data format contracts
- `shared/evidence_contract.md` — EVID_* evidence point dictionary (Phase 4+)

## Verdict Semantics

| Verdict | Meaning | Gate Action |
|---------|---------|-------------|
| `PASS` | All checks pass, thresholds met | Gate opens, proceed to next phase |
| `CONDITIONAL_PASS` | Non-critical failures only | Gate opens with degradation flags; downstream phases adjust |
| `FAIL` | Critical check failure | Gate blocked; responsible agent must redo (subject to redo limits) |

## Redo Limits Per Phase

| Phase | Max Redo | Over-Limit Action |
|-------|:--------:|-------------------|
| Phase 1 (S-080) | 3 | Halt for user intervention (cannot degrade) |
| Phase 2 (S-081) | 2 | Mark degraded, continue with available data |
| Phase 3 (S-082) | 2 | Degrade to static analysis mode (`PHASE3_DEGRADED=true`) |
| Phase 4 (S-083) | 2 per auditor | Mark insufficient evidence, degrade confidence |
| Phase 4.5 (S-084) | 1 | Skip correlation, proceed directly to report |
| Phase 5 (S-085) | 2 | Force generate with WARN annotations |

## Output Locations

All QC reports are written to `$WORK_DIR/质量报告/`:

| File | Producer |
|------|----------|
| `quality_report_phase1.json` | S-080 |
| `quality_report_phase2.json` | S-081 |
| `quality_report_phase3.json` | S-082 |
| `quality_report_phase4.json` | S-083 |
| `quality_report_phase45.json` | S-084 |
| `quality_report_phase5.json` | S-085 |
| `质量报告.md` | Final QC consolidation (generated after S-085 passes) |
