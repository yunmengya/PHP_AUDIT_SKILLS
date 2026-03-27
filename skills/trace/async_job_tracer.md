## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037e |
| Phase | 3 |
| Responsibility | Trace async job call chains dispatched from HTTP request flow |

# Async Job Tracer

## Purpose

Some sink calls occur not in the synchronous HTTP request flow but inside
background jobs dispatched to a queue. This sub-skill identifies async dispatch
points in the trace, synchronously executes the queued jobs inside Docker, and
appends the job's call chain to the original route trace so that Phase 4
auditors see the complete taint path.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Filtered trace | Trace Filter S-037c (in-memory) | Yes | Call chain containing `dispatch()` or equivalent |
| Original request | Request Executor S-037b (in-memory) | Yes | Original request details for re-triggering |

## Fill-in Procedure

### Step 1 — Identify Async Dispatch Points

| Field | Fill-in Value |
|-------|---------------|
| `dispatch_function` | {dispatch() / Queue::push() / Bus::dispatch() / ->dispatch() / MessageBusInterface::dispatch() / $queue->enqueue()} |
| `job_class` | {fully qualified class name from dispatch arguments} |
| `framework` | {Laravel / Symfony / Generic} |

Scan the route's trace for calls that dispatch work to a queue:

| Framework | Dispatch Functions |
|-----------|--------------------|
| Laravel | `dispatch()`, `Queue::push()`, `Bus::dispatch()`, `->dispatch()` |
| Symfony | `MessageBusInterface::dispatch()` |
| Generic | `Queue::push()`, `$queue->enqueue()` |

Record the **Job class name** from the dispatch arguments.

### Step 2 — Execute Job Synchronously

| Field | Fill-in Value |
|-------|---------------|
| `execution_method` | {queue:work --once / direct re-trigger} |
| `xdebug_config` | {mode=trace start_with_request=trigger} |
| `timeout` | {30 seconds} |
| `max_tries` | {1} |

Bypass the queue and run the job directly with Xdebug tracing:

```bash
docker exec php sh -c 'export XDEBUG_CONFIG="mode=trace start_with_request=trigger" && \
  XDEBUG_TRIGGER=1 php artisan queue:work --once --tries=1 --timeout=30'
```

Alternatively, if the dispatch happened during the traced request, the job may already be in the queue. Execute it within 30 seconds:

```bash
docker exec php rm -f /tmp/xdebug_traces/trace.*
docker exec -d php sh -c 'XDEBUG_TRIGGER=1 php artisan queue:work --once --timeout=30'
docker exec php curl -s -X POST http://nginx:80$ROUTE_URL \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -d "$BODY"
sleep 5
docker exec php ls -la /tmp/xdebug_traces/
```

### Step 3 — Handle Job Chains

| Field | Fill-in Value |
|-------|---------------|
| `chain_depth` | {number of chained jobs detected, max 3} |
| `execution_iterations` | {number of --once runs needed} |

If Job A dispatches Job B, run `--once` multiple times until the queue is empty:

```bash
for i in 1 2 3; do
  docker exec php sh -c 'XDEBUG_TRIGGER=1 php artisan queue:work --once --timeout=15'
done
```

### Step 4 — Collect and Merge Job Trace

| Field | Fill-in Value |
|-------|---------------|
| `job_trace_file` | {Xdebug trace file from job execution} |
| `filter_rules` | {same as S-037c Trace Filter} |
| `merge_strategy` | {append job call chain to original route trace} |
| `async_jobs_array` | {list of {class, traced} objects} |

1. Extract the job's Xdebug trace file.
2. Filter it using the same rules as S-037c (Trace Filter).
3. Append the job's call chain to the original route trace.
4. Mark the trace record:

```json
{
  "async_jobs": [
    { "class": "App\\Jobs\\ProcessData", "traced": true },
    { "class": "App\\Jobs\\SendNotification", "traced": true }
  ]
}
```

### Step 5 — WordPress Cron Tracing

| Field | Fill-in Value |
|-------|---------------|
| `is_wordpress` | {true / false} |
| `cron_trigger_url` | {http://nginx:80/wp-cron.php?doing_wp_cron=1} |

For WordPress targets, cron tasks are triggered via HTTP:

```bash
docker exec php curl -s http://nginx:80/wp-cron.php?doing_wp_cron=1 \
  -H "Cookie: XDEBUG_TRIGGER=1"
```

### Step 6 — Generic Event/Listener Tracing

| Field | Fill-in Value |
|-------|---------------|
| `event_system` | {Event::listen / EventDispatcher / ->on(} |
| `listener_method` | {handle() method of the listener class} |
| `tracing_approach` | {tick tracer injection into listener handle()} |

For event-driven architectures where sinks reside in listeners:

1. Identify the event system (`Event::listen`, `EventDispatcher`, `->on(`).
2. Inject tick tracer into the listener's `handle()` method.
3. Trigger the event via HTTP and collect the listener trace.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Extended trace | (in-memory) | Original trace + appended job call chain(s) |
| `async_jobs` field | Embedded in trace record | List of traced jobs with `class` and `traced` flag |

## Examples

### ✅ GOOD — Complete async job trace

```json
{
  "route_id": "route_010",
  "async_jobs": [
    { "class": "App\\Jobs\\ProcessData", "traced": true },
    { "class": "App\\Jobs\\SendNotification", "traced": true }
  ],
  "job_call_chains": [
    {
      "class": "App\\Jobs\\ProcessData",
      "call_chain": [
        "App\\Jobs\\ProcessData::handle",
        "App\\Services\\DataProcessor::process",
        "Illuminate\\Support\\Facades\\DB::raw"
      ]
    }
  ]
}
```

Jobs identified, traced successfully, call chains merged.

### ❌ BAD — Incomplete job tracing

```json
{
  "async_jobs": [
    { "class": "App\\Jobs\\ProcessData" }
  ]
}
```

Problems: Missing `traced` flag, no `job_call_chains`, no `route_id`.

## Error Handling

| Error | Action |
|-------|--------|
| No job appears in queue within 30 s | Mark job as `async_jobs: [{class: "...", traced: false}]`; log timeout |
| Job fails during execution | Capture error trace; mark `traced: true` with `job_error: true` |
| Queue driver not supported (e.g., SQS) | Mark as `traced: false`; recommend static analysis of job class |
| Job chain depth > 3 | Stop recursive tracing; log warning |
