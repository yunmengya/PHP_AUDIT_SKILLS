## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-036e |
| Phase | 3 |
| Responsibility | Create self-contained JSON task packages for each route to be traced |

# Task Packager

## Purpose

Create a self-contained JSON task package for every route that needs tracing.
Each package carries all information a Trace-Worker requires so that workers are
stateless and can execute independently.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Grouped batches | Sink Grouper S-036c (in-memory) | Yes | Grouped and batched task list |
| `route_map.json` | `$WORK_DIR/route_map.json` | Yes | `route_url`, `method`, `auth_level`, `params` |
| `priority_queue.json` | `$WORK_DIR/priority_queue.json` | Yes | `sink_id`, `route_id`, `sink_function` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST include route metadata (method, URL, parameters, auth requirements) in each task package — auditors cannot operate without context | FAIL — auditor receives empty context, wastes all 8 rounds |

## Fill-in Procedure

### Step 1 — Iterate Over Grouped Batches

| Field | Fill-in Value |
|-------|---------------|
| `batch_source` | {sink-grouped batches from S-036c} |
| `numbering_scheme` | {sequential: task_001, task_002, …} |

For each task in the sink-grouped batches produced by S-036c, generate a
sequentially numbered task file.

### Step 2 — Assemble Task Package Fields

| Field | Fill-in Value |
|-------|---------------|
| `task_id` | {auto-generated: trace_001, trace_002, …} |
| `sink_id` | {sink identifier from priority_queue.json} |
| `route_id` | {route identifier from priority_queue.json} |
| `route_url` | {URL path from route_map.json, e.g., /api/user/update} |
| `method` | {HTTP method from route_map.json: GET / POST / PUT / DELETE} |
| `sink_function` | {target function name from priority_queue.json, e.g., DB::raw} |
| `auth_level` | {anonymous / authenticated / admin from route_map.json} |
| `params` | {array of parameter names from route_map.json} |
| `status` | {constant: "pending"} |

Source mapping:

| Field | Source | Description |
|-------|--------|-------------|
| `task_id` | Auto-generated | `trace_001`, `trace_002`, … |
| `sink_id` | `priority_queue.json` | Identifier of the target sink |
| `route_id` | `priority_queue.json` | Identifier of the route |
| `route_url` | `route_map.json` | URL path (e.g., `/api/user/update`) |
| `method` | `route_map.json` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`) |
| `sink_function` | `priority_queue.json` | Target function name (e.g., `DB::raw`) |
| `auth_level` | `route_map.json` | `anonymous`, `authenticated`, or `admin` |
| `params` | `route_map.json` | Array of parameter names |
| `status` | Constant | Initial value: `pending` |

### Step 3 — Task Package JSON Schema

| Field | Fill-in Value |
|-------|---------------|
| `schema_format` | {JSON object with all fields from Step 2} |

```json
{
  "task_id": "trace_001",
  "sink_id": "sink_001",
  "route_id": "route_005",
  "route_url": "/api/user/update",
  "method": "POST",
  "sink_function": "DB::raw",
  "auth_level": "authenticated",
  "params": ["name", "email"],
  "status": "pending"
}
```

### Step 4 — Write Task Files

| Field | Fill-in Value |
|-------|---------------|
| `output_dir` | {$WORK_DIR/tasks/} |
| `filename_pattern` | {task_NNN.json} |
| `create_dir_if_missing` | {true} |

Write each package to `$WORK_DIR/tasks/task_NNN.json` (create the `tasks/` directory if it does not exist).

### Step 5 — Build Dispatch Manifest

| Field | Fill-in Value |
|-------|---------------|
| `manifest_path` | {$WORK_DIR/tasks/manifest.json} |
| `manifest_fields` | {task file list, batch assignment, sink category, initial status} |

Create `$WORK_DIR/tasks/manifest.json` listing all task files, their assigned
batch, sink category, and initial status. The Dispatcher uses this manifest to
track progress.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Task packages | `$WORK_DIR/tasks/task_NNN.json` | One file per route |
| Dispatch manifest | `$WORK_DIR/tasks/manifest.json` | Index of all tasks with batch assignments |

## Examples

### ✅ GOOD — Complete task package

```json
{
  "task_id": "trace_001",
  "sink_id": "sink_001",
  "route_id": "route_005",
  "route_url": "/api/user/update",
  "method": "POST",
  "sink_function": "DB::raw",
  "auth_level": "authenticated",
  "params": ["name", "email"],
  "status": "pending"
}
```

All fields present, values sourced from correct files.

### ❌ BAD — Incomplete task package

```json
{
  "task_id": "trace_001",
  "route_url": "/api/user/update",
  "status": "pending"
}
```

Problems: Missing `sink_id`, `route_id`, `method`, `sink_function`, `auth_level`, `params`.

## Error Handling

| Error | Action |
|-------|--------|
| `route_map.json` missing or unreadable | Abort packaging with `missing_route_map` error |
| Route referenced in queue not found in route map | Skip the task, mark `status: "skipped"`, log warning |
| Disk write failure | Retry once; if still failing, abort with `io_error` |
