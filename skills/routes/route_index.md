> **Parent Skill**: S-030 (route_mapper) | **Phase**: 2 — Static Asset Reconnaissance
> **Source**: `teams/team2/route_mapper.md`

# Route Sub-Skills Index

## Overview

The monolithic Route-Mapper skill (S-030) is decomposed into 8 fine-grained sub-skills, each responsible for a distinct procedure in the route discovery and mapping pipeline.

## Sub-Skill Registry

| ID | File | Title | Procedure |
|----|------|-------|-----------|
| S-030a | `framework_route_parser.md` | Framework Route Parser | A (Determine Framework) + B (Parse Registered Routes) |
| S-030b | `route_command_executor.md` | Route Command Executor | CR-2 (CLI route:list / debug:router execution + cross-validation) |
| S-030c | `parameter_source_extractor.md` | Parameter Source Extractor | C (Parameter Source Identification) |
| S-030d | `hidden_endpoint_discoverer.md` | Hidden Endpoint Discoverer | D (Hidden Endpoint Discovery) |
| S-030e | `cli_entry_scanner.md` | CLI Entry Scanner | E.1 (CLI Command Entry Points) |
| S-030f | `cron_queue_scanner.md` | CRON / Queue / Hook Scanner | E.2 + E.3 + E.4 (CRON + Queue + Hook entry points) |
| S-030g | `auth_gap_analyzer.md` | Auth Gap Analyzer | F (Auth Gap Analysis) |
| S-030h | `route_map_assembler.md` | Route Map Assembler | G (Output Assembly + CR-1~CR-6 validation) |

## Dependency Chain

```
S-030a ──→ S-030b ──→ S-030c ──┐
                                │
S-030d (parallel) ──────────────┤
                                ├──→ S-030g ──→ S-030h
S-030e (parallel) ──────────────┤
                                │
S-030f (parallel) ──────────────┘
```

### Execution Order

| Phase | Sub-Skills | Mode | Description |
|-------|-----------|------|-------------|
| 1 | **S-030a** | Sequential | Parse all framework routes from source code |
| 2 | **S-030b** | Sequential (depends on S-030a) | Execute CLI route commands, cross-validate |
| 3 | **S-030c**, **S-030d**, **S-030e**, **S-030f** | **Parallel** | Parameter extraction, hidden endpoints, CLI entries, CRON/Queue/Hook entries |
| 4 | **S-030g** | Sequential (depends on S-030b~f) | Auth gap analysis across all route types |
| 5 | **S-030h** | Sequential (depends on all above) | Final assembly, CR validation, output generation |

## Data Flow

```
environment_status.json ──→ [S-030a] ──→ raw_routes.json
                                              │
                                              ▼
                            [S-030b] ──→ validated_routes.json
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
              [S-030c]                  [S-030d]                  [S-030e]
           route_params.json       hidden_routes.json        cli_entries.json
                    │                         │                         │
                    │                         │              [S-030f]   │
                    │                         │         background_     │
                    │                         │         entries.json    │
                    │                         │              │          │
                    └─────────┬───────────────┴──────────────┴──────────┘
                              ▼
                        [S-030g] ──→ auth_gap_report.json
                              │
                              ▼
                        [S-030h] ──→ route_map.json (FINAL)
                                     auth_gap_report.json (FINAL)
```

## Intermediate Files

| File | Producer | Consumer(s) |
|------|----------|-------------|
| `raw_routes.json` | S-030a | S-030b |
| `validated_routes.json` | S-030b | S-030c, S-030d, S-030g, S-030h |
| `route_params.json` | S-030c | S-030h |
| `hidden_routes.json` | S-030d | S-030g, S-030h |
| `cli_entries.json` | S-030e | S-030g, S-030h |
| `background_entries.json` | S-030f | S-030g, S-030h |
| `auth_gap_report.json` | S-030g | S-030h |

## Final Outputs

| File | Path | Schema | Consumed By |
|------|------|--------|-------------|
| `route_map.json` | `$WORK_DIR/route_map.json` | `schemas/route_map.schema.json` | context_extractor (S-040), risk_classifier (S-050), Phase-3 agents |
| `auth_gap_report.json` | `$WORK_DIR/auth_gap_report.json` | `schemas/auth_gap_report.schema.json` | auth_auditor (S-031), Phase-3 deep analysis |

## Critical Rules Coverage

| Rule | Enforced By |
|------|------------|
| CR-1 (No fabricated routes) | S-030a (parse), S-030h (final validation) |
| CR-2 (Must run CLI route commands) | S-030b (execution) |
| CR-3 (Controller methods must exist) | S-030a (verification), S-030h (final validation) |
| CR-4 (Parameter sources from code) | S-030c (extraction), S-030h (final validation) |
| CR-5 (Resource routes fully expanded) | S-030a (expansion), S-030h (final validation) |
| CR-6 (Hidden endpoints annotate source) | S-030d (discovery), S-030h (final validation) |
