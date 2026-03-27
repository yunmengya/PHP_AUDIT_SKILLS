> **Skill ID**: S-036e | **Phase**: 3 | **Parent**: S-036 (Trace-Dispatcher)
> **Input**: Final grouped tasks, route_map.json, credentials.json
> **Output**: `task_NNN.json` files — one per route with full execution context

# Task Packager

## Purpose

Create a self-contained JSON task package for every route that needs tracing.
Each package carries all information a Trace-Worker requires so that workers are
stateless and can execute independently.

## Procedure

### 1. Iterate Over Grouped Batches

For each task in the sink-grouped batches produced by S-036c, generate a
sequentially numbered task file.

### 2. Assemble Task Package Fields

| Field | Source | Description |
|-------|--------|-------------|
| `task_id` | Auto-generated | `trace_001`, `trace_002`, … |
| `sink_id` | `priority_queue.json` | Identifier of the target sink |
| `route_id` | `priority_queue.json` | Identifier of the route |
| `route_url` | `route_map.json` | URL path (e.g., `/api/user/update`) |
| `method` | `route_map.json` | HTTP method (`GET`, `POST`, etc.) |
| `sink_function` | `priority_queue.json` | Target function name (e.g., `DB::raw`) |
| `auth_level` | `route_map.json` | `anonymous`, `authenticated`, or `admin` |
| `params` | `route_map.json` | Array of parameter names |
| `status` | Constant | Initial value: `pending` |

### 3. Task Package JSON Schema

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

### 4. Write Task Files

Write each package to `$WORK_DIR/tasks/task_NNN.json` (create the `tasks/`
directory if it does not exist).

### 5. Build Dispatch Manifest

Create `$WORK_DIR/tasks/manifest.json` listing all task files, their assigned
batch, sink category, and initial status. The Dispatcher uses this manifest to
track progress.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Sink Grouper (S-036c) | (in-memory) | Yes | Grouped and batched task list |
| Route map | `$WORK_DIR/route_map.json` | Yes | `route_url`, `method`, `auth_level`, `params` |
| Priority queue | `$WORK_DIR/priority_queue.json` | Yes | `sink_id`, `route_id`, `sink_function` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Task packages | `$WORK_DIR/tasks/task_NNN.json` | One file per route |
| Dispatch manifest | `$WORK_DIR/tasks/manifest.json` | Index of all tasks with batch assignments |

## Error Handling

| Error | Action |
|-------|--------|
| `route_map.json` missing or unreadable | Abort packaging with `missing_route_map` error |
| Route referenced in queue not found in route map | Skip the task, mark `status: "skipped"`, log warning |
| Disk write failure | Retry once; if still failing, abort with `io_error` |
