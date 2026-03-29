> **Skill ID**: S-090-INDEX | **Phase**: 5 | **Parent**: S-090 (report_writer)
> **Purpose**: Master index of all report chapter skills — assembly order and parallel execution guide
> **Output**: Single file `$WORK_DIR/报告/审计报告.md` containing ALL chapters

# Report Chapter Index

## Overview

The Phase-5 report is composed of 7 chapter skills (S-090a ~ S-090g). All chapters are assembled into **ONE single `审计报告.md`** file — the user only reads this one file.

## Chapter Skills Registry

| Order | Skill ID | Skill File | Section Title | Description |
|-------|----------|------------|---------------|-------------|
| 00 | S-090a | `cover_page_writer.md` | 封面 + 目录 + 执行摘要 | Cover page with metadata, TOC, executive summary, CVSS visual bars |
| 01 | S-090b | `vuln_summary_writer.md` | 漏洞汇总表 | Summary table with CVSS visual bars |
| 02 | S-090c | `vuln_detail_writer.md` | 漏洞详情 | Per-vuln detail with context pack, Burp, Mermaid, fix comparison |
| 03 | S-090d | `attack_chain_writer.md` | 联合攻击链分析 | Multi-vuln Mermaid chain diagrams |
| 04 | S-090e | `coverage_stats_writer.md` | 审计覆盖率统计 | Route coverage, priority breakdown, auditor status |
| 05 | S-090f | `risk_pool_writer.md` | 待补证风险池 | Unconfirmed findings for manual review |
| 06 | S-090g | `lessons_writer.md` | 审计经验总结 | Lessons learned (also saved separately for reuse) |

## Assembly Structure (Single-File Output)

The final `审计报告.md` has this exact structure:

```
┌─────────────────────────────────────────────┐
│  # PHP 代码安全审计报告                      │ ← S-090a
│  封面 (项目元数据 + CVSS可视化)              │
│  ─────────────────────────                   │
│  📖 目录 (锚点导航)                          │ ← S-090a
│  ─────────────────────────                   │
│  执行摘要 (风险等级 + 关键发现 + 范围概要)    │ ← S-090a
│  ─────────────────────────                   │
│  漏洞汇总表 (CVSS进度条)                     │ ← S-090b
│  ─────────────────────────                   │
│  漏洞详情 ×N                                 │ ← S-090c
│  ├─ 🔖 信息卡                               │
│  ├─ 📦 上下文包 (调用链+过滤器+认证)         │ ← NEW
│  ├─ 🔗 Mermaid 攻击链                       │
│  ├─ 📊 数据流追踪                            │
│  ├─ 🔫 Burp 复现模板                        │
│  ├─ ⚔️ 攻击迭代记录                          │
│  └─ 🔧 修复方案 (❌前 vs ✅后)               │
│  ─────────────────────────                   │
│  联合攻击链分析 (Mermaid + 步骤表)           │ ← S-090d
│  ─────────────────────────                   │
│  审计覆盖率统计                              │ ← S-090e
│  ─────────────────────────                   │
│  待补证风险池                                │ ← S-090f
│  ─────────────────────────                   │
│  审计经验总结 (框架特征+绕过+踩坑+建议)      │ ← S-090g
│  ─────────────────────────                   │
│  📋 报告页脚 (版本+时间+工具)                │
└─────────────────────────────────────────────┘
```

## Execution Model

### Parallel Execution (All 7 chapters)

All chapter skills read from shared Phase-4 output files and do NOT write to each other's output paths. They can safely run in parallel:

```
┌─────────────────────────────────────────────────────────┐
│                   Phase-5 Report Generation              │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ S-090a   │ │ S-090b   │ │ S-090c   │ │ S-090d   │   │
│  │ 封面+摘要│ │ 汇总表   │ │ 漏洞详情 │ │ 攻击链   │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │
│       │            │            │            │          │
│  ┌────┴─────┐ ┌────┴─────┐ ┌────┴─────┐               │
│  │ S-090e   │ │ S-090f   │ │ S-090g   │               │
│  │ 覆盖率   │ │ 风险池   │ │ 经验总结 │               │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘               │
│       └────────────┼────────────┘                       │
│                    ▼                                     │
│      Sequential Assembly into ONE FILE:                  │
│   封面+目录+摘要 → 汇总表 → 详情* → 攻击链              │
│   → 覆盖率 → 风险池 → 经验总结 → 页脚                   │
│                    ▼                                     │
│       $WORK_DIR/报告/审计报告.md  (SINGLE FILE)          │
└─────────────────────────────────────────────────────────┘
```

### Assembly Notes

- **Single file output** — All chapters are concatenated into `$WORK_DIR/报告/审计报告.md`
- Individual chapter files are NOT retained — the assembled report IS the only output
- Chapter 02 produces **multiple sections** (one per confirmed vulnerability) — sort by severity
- Use `<br/>\n\n---\n\n<br/>` as separator between major chapters
- If no confirmed vulnerabilities, chapter 02 is omitted; chapter 01 shows zero-vuln notice

## Input/Output Dependency Map

```
environment_status.json ──→ S-090a (封面+摘要), S-090g (经验)
exploit_summary.json ───→ S-090a (封面+摘要), S-090e (覆盖率)
exploits/*.json ────────→ S-090b (汇总), S-090c (详情), S-090f (风险池), S-090g (经验)
traces/*.json ──────────→ S-090c (详情)
context_packs/*.json ───→ S-090c (详情) [NEW: call chain, middleware, filters]
修复补丁/*.diff ────────→ S-090c (详情)
attack_graph.json ──────→ S-090d (攻击链), S-090g (经验)
correlation_report.json ─→ S-090d (攻击链)
route_map.json ─────────→ S-090a (摘要), S-090e (覆盖率)
checkpoint.json ────────→ S-090e (覆盖率)
priority_queue.json ────→ S-090c (详情), S-090e (覆盖率)
attack_memory.db ───────→ S-090g (经验)
```

## Quality Checklist

Before marking report generation complete, verify:

- [ ] All 7 chapter sections present in assembled `审计报告.md`
- [ ] Vulnerability counts in 封面 match 汇总表 row count
- [ ] Every confirmed vuln has: 信息卡 + 上下文包 + Mermaid + 数据流 + Burp + 修复方案
- [ ] Every vuln detail has context pack data (or ⚠️ warning if unavailable)
- [ ] Attack chains in 联合攻击链 reference only valid sink_ids
- [ ] Coverage percentages are mathematically correct
- [ ] Risk pool contains NO `final_verdict: "confirmed"` entries
- [ ] 经验总结 references actual audit data, not boilerplate
- [ ] TOC anchor links work correctly
- [ ] Section dividers (`---`) between all major chapters
- [ ] CVSS visual bars present in 汇总表
- [ ] 执行摘要 risk level matches actual vulnerability counts
