# Cumulative Pipeline View Template

After each Phase completes, print the **complete pipeline view** once. Completed phases MUST be populated with data from results; incomplete phases SHALL be expanded to show all subtasks and dependency relationships.

## Status Marker Rules

- `✅` = completed and passed
- `⚠️` = completed but degraded / partially passed
- `❌` = failed
- `⚙️` = running
- `⏳` = waiting (not yet started)
- `🔄` = skipped (degraded mode)

## Rendering Rules

1. **Header**: MUST always display project name + progress bar + completed task count / total + total elapsed time
2. **Phase header**: `Phase-N  phase_name` with phase status icon + completion count `x/y` + phase elapsed time on the right
3. **Task row**: Completed tasks display `→ {summary}`, running tasks display `⚙️ running`, waiting tasks display `⏳` + dependency `← #x,#y`
4. **Phase connector**: Connect phases with a centered `↓`
5. **Uncreated phases**: Display `⏳ pending creation`, do NOT expand subtasks
6. **Progress bar**: Render with `▓` (completed) and `░` (incomplete), 20 cells total

## View Template

```
╔══════════════════════════════════════════════════════════╗
║  PHP 安全审计  ·  {PROJECT_NAME}                         ║
║  {▓▓▓▓░░░░░░░░░░░░░░░░}  {done}/{total} ({pct}%)  ⏱ {total_elapsed}  ║
╚══════════════════════════════════════════════════════════╝

Phase-1  Intelligent Environment Detection & Build     {✅/⚠️/⚙️/⏳} {done}/{total}  ⏱ {elapsed}
  ├─ #1  Env Detective          {✅}  → {framework} {version}
  ├─ #2  Schema Rebuild         {✅}  → {n} tables
  ├─ #3  Docker Build           {✅}  → PHP {php_version} + {db_type}
  └─ #4  QC: Env Build          {✅}  → routes: {A}A/{B}B/{C}C
                              ↓
Phase-2  Static Asset Reconnaissance                   {✅/⚠️/⚙️/⏳} {done}/{total}  ⏱ {elapsed}
  ├─ #5  Tool Scan              {✅}  → Psalm + Progpilot
  ├─ #6  Route Mapping          {✅}  → {n} routes
  ├─ #7  Auth Audit             {✅}  → {n} rules
  ├─ #8  Component Scan         {✅}  → {n} vulnerable components
  ├─ #9  Context Extraction     {✅}  → {n} Sinks
  ├─ #10 Priority Rating        {✅}  → P0:{n} P1:{n} P2:{n} P3:{n}
  └─ #11 QC: Static Recon      {✅}  → coverage {n}%
                              ↓
Phase-3  Authentication Simulation & Dynamic Tracing    {✅/⚠️/⚙️/🔄/⏳} {done}/{total}  ⏱ {elapsed}
  ├─ #12 Auth Simulation        {✅}  → {anonymous ✅ | auth ✅ | admin ❌}
  ├─ #13 Trace Dispatch & Exec  {✅}  → {succeeded}/{total} traces
  └─ #14 QC: Dynamic Tracing   {✅}  → broken chains {n}
                              ↓
Phase-4   Deep Adversarial Audit                       {✅/⚠️/⚙️/⏳} {done}/{total}  ⏱ {elapsed}
  ├─ #15 {sink_type} Expert     {✅}  → confirmed {n}
  ├─ ... (dynamically generated)
  └─ #N  QC: Physical Evidence  {✅}  → {n} evidence items
                              ↓
Phase-4.5 Post-Exploitation Intelligent Analysis       {✅/⚠️/⚙️/⏳} {done}/{total}  ⏱ {elapsed}
  ├─ #M   Attack Graph Build   {✅}  → {n} attack paths
  ├─ #M+1 Correlation Analysis {✅}  → escalated {n}, 2nd-order {n}, gaps {n}
  ├─ #M+2 Remediation Patch    {✅}  → {n} Patches
  └─ #M+3 PoC Scripts          {✅}  → {n} PoCs
                              ↓
Phase-5   Cleanup and Reporting                        {✅/⏳} {done}/{total}  ⏱ {elapsed}
  ├─ #N+1 Env Cleanup          {✅}
  ├─ #N+2 Report Writing       {✅}  → {path}
  └─ #N+3 QC: Final Report     {✅}

══════════════════════════════════════════════════════════
 Vulnerabilities: confirmed {n} · suspected {n} · potential {n}  |  Total elapsed: {total_elapsed}
══════════════════════════════════════════════════════════
```

## Task Row Rendering Examples by Status

```
Completed: ├─ #1  Env Detective          ✅  → Laravel 10.x
Running:   ├─ #6  Route Mapping          ⚙️ running
Waiting:   ├─ #9  Context Extraction     ⏳  ← #5~#8
Degraded:  ├─ #7  Auth Audit             ⚠️  → partial rules missing
Failed:    ├─ #3  Docker Build           ❌  → port conflict
Skipped:   ├─ #12 Auth Simulation        🔄  skipped (no Docker)
```

## Rendering of Uncreated Phases

Tasks for Phase-4/4.5/5 are dynamically created only after Phase-2 completes. Before creation, display:

```
Phase-4   Deep Adversarial Audit                       ⏳ pending creation
                              ↓
Phase-4.5 Post-Exploitation Intelligent Analysis       ⏳ pending creation
                              ↓
Phase-5   Cleanup and Reporting                        ⏳ pending creation
```

## Progress Bar Rendering Rules

20 cells wide, filled proportionally by `completed task count / total task count`:

```
 0%:  ░░░░░░░░░░░░░░░░░░░░
25%:  ▓▓▓▓▓░░░░░░░░░░░░░░░
50%:  ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░
75%:  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░
100%: ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
```

## Real-Time Guarantees

- **Between phases**: MUST print the updated complete view immediately after all Agents in each Phase complete
- **Within a phase**: Claude Code native Task UI renders automatically (based on Agent TaskUpdate state changes + activeForm spinner indicator)
- Two-layer coordination: Task UI displays fine-grained progress for the current phase; pipeline view displays global phase progress
