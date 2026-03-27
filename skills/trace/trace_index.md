# Trace Sub-Skills Index

> **Phase**: 3 — Authentication Simulation & Dynamic Tracing
> **Directory**: `skills/trace/`

This index lists all 14 fine-grained trace sub-skills, grouped by parent skill.

---

## S-036 — Trace-Dispatcher Sub-Skills

Parent file: `teams/team3/trace_dispatcher.md`

| Skill ID | File | Title | Purpose |
|----------|------|-------|---------|
| S-036a | `task_priority_sorter.md` | Task Priority Sorter | Sort routes by P0→P3, secondary by `source_count` descending |
| S-036b | `resource_downsampler.md` | Resource Downsampler | Downsample lower-priority routes when total count exceeds budget |
| S-036c | `sink_grouper.md` | Sink Grouper | Group routes by sink type for batch dispatch to Phase 4 auditors |
| S-036d | `concurrency_tuner.md` | Concurrency Tuner | Check container CPU/Memory, decide worker count (1/2/3) |
| S-036e | `task_packager.md` | Task Packager | Create `task_NNN.json` per route with full execution context |
| S-036f | `fallback_strategy_selector.md` | Fallback Strategy Selector | Choose tracing approach when Xdebug is unavailable |

### Dispatcher Pipeline Flow

```
priority_queue.json
       │
       ▼
  S-036a  Task Priority Sorter
       │
       ▼
  S-036b  Resource Downsampler
       │
       ▼
  S-036c  Sink Grouper
       │
       ├──────────────────┐
       ▼                  ▼
  S-036d  Concurrency   S-036e  Task Packager
          Tuner                    │
       │                          ▼
       └──────────► Dispatch to Trace-Workers
                         │
                    (S-036f consulted if Xdebug unavailable)
```

---

## S-037 — Trace-Worker Sub-Skills

Parent file: `teams/team3/trace_worker.md`

| Skill ID | File | Title | Purpose |
|----------|------|-------|---------|
| S-037a | `request_constructor.md` | Request Constructor | Build HTTP request from route params + credentials |
| S-037b | `request_executor.md` | Request Executor | Send request with XDEBUG_TRIGGER, collect response + trace |
| S-037c | `trace_filter.md` | Trace Filter | Filter raw trace to ≤500 sink-relevant lines |
| S-037d | `dynamic_binding_resolver.md` | Dynamic Binding Resolver | Resolve `call_user_func`, `$obj->$method`, `include $var` |
| S-037e | `async_job_tracer.md` | Async Job Tracer | Trace queued jobs synchronously, append to route trace |
| S-037f | `websocket_graphql_tracer.md` | WebSocket & GraphQL Tracer | Construct WS/GraphQL requests, trace handlers/resolvers |
| S-037g | `file_upload_tracer.md` | File Upload Tracer | Send multipart request, trace `$_FILES` → `move_uploaded_file()` |
| S-037h | `trace_quality_assessor.md` | Trace Quality Assessor | Assess trace quality, cross-validate with Context Packs |

### Worker Pipeline Flow

```
task_NNN.json (from S-036e)
       │
       ▼
  S-037a  Request Constructor
       │
       ▼
  S-037b  Request Executor ──────────┐
       │                             │ (if WS/GraphQL)
       │                             ▼
       │                        S-037f  WebSocket & GraphQL Tracer
       │                             │ (if file upload)
       │                             ▼
       │                        S-037g  File Upload Tracer
       │
       ▼
  S-037c  Trace Filter
       │
       ▼
  S-037d  Dynamic Binding Resolver
       │
       ├─── (if dispatch() found) ──► S-037e  Async Job Tracer
       │                                  │
       ◄──────────────────────────────────┘
       │
       ▼
  S-037h  Trace Quality Assessor
       │
       ▼
  traces/trace_NNN.json
```

---

## Cross-References

- **Phase 3 orchestration**: `phases/phase3-trace.md`
- **Dispatcher parent**: `teams/team3/trace_dispatcher.md`
- **Worker parent**: `teams/team3/trace_worker.md`
- **Trace record schema**: `schemas/trace_record.schema.json`
- **Fallback tracing tools**: `tools/trace_filter.php`, `tick_tracer.php`
