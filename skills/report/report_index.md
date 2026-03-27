> **Skill ID**: S-090-INDEX | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Purpose**: Master index of all report chapter skills — assembly order and parallel execution guide

# Report Chapter Index

## Overview

The Phase-5 report is composed of 7 chapter skills (S-090a ~ S-090g), each responsible for generating one section of the final audit report. Chapters can be executed **in parallel** since they read from shared input files without write conflicts. After all chapters complete, they are assembled in sequential order into the final report.

## Chapter Skills Registry

| Order | Skill ID | Skill File | Output File | Description |
|-------|----------|------------|-------------|-------------|
| 00 | S-090a | `cover_page_writer.md` | `$WORK_DIR/报告/00_封面.md` | Cover page with project metadata and vulnerability statistics |
| 01 | S-090b | `vuln_summary_writer.md` | `$WORK_DIR/报告/01_漏洞汇总表.md` | Summary table of all confirmed vulnerabilities |
| 02 | S-090c | `vuln_detail_writer.md` | `$WORK_DIR/报告/02_漏洞详情_{sink_id}.md` | One detail page per confirmed vulnerability (multiple files) |
| 03 | S-090d | `attack_chain_writer.md` | `$WORK_DIR/报告/03_攻击链分析.md` | Attack chain Mermaid diagrams and step tables |
| 04 | S-090e | `coverage_stats_writer.md` | `$WORK_DIR/报告/04_覆盖率统计.md` | Route coverage, priority breakdown, auditor status |
| 05 | S-090f | `risk_pool_writer.md` | `$WORK_DIR/报告/05_未验证风险池.md` | Unconfirmed/suspected findings for manual review |
| 经验 | S-090g | `lessons_writer.md` | `$WORK_DIR/经验沉淀/lessons_learned.md` | Lessons learned: patterns, bypasses, failures, recommendations |

## Execution Model

### Parallel Execution (All 7 chapters)

All chapter skills read from shared Phase-4 output files and do NOT write to each other's output paths. They can safely run in parallel:

```
┌─────────────────────────────────────────────────────────┐
│                   Phase-5 Report Generation              │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ S-090a   │ │ S-090b   │ │ S-090c   │ │ S-090d   │   │
│  │ 封面     │ │ 汇总表   │ │ 漏洞详情 │ │ 攻击链   │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │
│       │            │            │            │          │
│  ┌────┴─────┐ ┌────┴─────┐ ┌────┴─────┐               │
│  │ S-090e   │ │ S-090f   │ │ S-090g   │               │
│  │ 覆盖率   │ │ 风险池   │ │ 经验沉淀 │               │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘               │
│       │            │            │                       │
│       └────────────┼────────────┘                       │
│                    ▼                                     │
│          Sequential Assembly                             │
│    00_封面 → 01_汇总表 → 02_详情*                        │
│    → 03_攻击链 → 04_覆盖率 → 05_风险池                   │
│    + 经验沉淀/lessons_learned.md                         │
└─────────────────────────────────────────────────────────┘
```

### Sequential Assembly Order

After all chapter writers complete, assemble the final report:

1. `00_封面.md` — Report cover page
2. `01_漏洞汇总表.md` — Vulnerability summary table
3. `02_漏洞详情_{sink_id}.md` — Detail pages (sorted by severity: Critical → Low)
4. `03_攻击链分析.md` — Attack chain analysis
5. `04_覆盖率统计.md` — Coverage statistics
6. `05_未验证风险池.md` — Unverified risk pool

Separately (not part of main report):
- `经验沉淀/lessons_learned.md` — Lessons learned (retained for future audits)

### Assembly Notes

- Chapter 02 produces **multiple files** (one per confirmed vulnerability) — sort them by severity when assembling
- If no confirmed vulnerabilities exist, chapter 02 produces no files; chapter 01 outputs the zero-vuln notice
- The assembled report is saved to: `$WORK_DIR/报告/审计报告.md`
- Individual chapter files are retained alongside the assembled report for reference

## Input/Output Dependency Map

```
environment_status.json ──→ S-090a (封面), S-090g (经验)
exploit_summary.json ───→ S-090a (封面), S-090e (覆盖率)
exploits/*.json ────────→ S-090b (汇总), S-090c (详情), S-090f (风险池), S-090g (经验)
traces/*.json ──────────→ S-090c (详情)
修复补丁/*.diff ────────→ S-090c (详情)
attack_graph.json ──────→ S-090d (攻击链), S-090g (经验)
correlation_report.json ─→ S-090d (攻击链)
route_map.json ─────────→ S-090e (覆盖率)
checkpoint.json ────────→ S-090e (覆盖率)
priority_queue.json ────→ S-090e (覆盖率)
attack_memory.db ───────→ S-090g (经验)
```

## Quality Checklist

Before marking report generation complete, verify:

- [ ] All 7 chapter outputs exist (or appropriate zero-vuln alternatives)
- [ ] Vulnerability counts in 00_封面 match 01_汇总表 row count
- [ ] Every confirmed vuln in 01_汇总表 has a corresponding 02_漏洞详情 file
- [ ] Every 02_漏洞详情 file has a Burp PoC template
- [ ] Attack chains in 03 reference only valid sink_ids
- [ ] Coverage percentages in 04 are mathematically correct
- [ ] Risk pool in 05 contains NO `final_verdict: "confirmed"` entries
- [ ] Lessons in 经验沉淀 reference actual audit data, not boilerplate
