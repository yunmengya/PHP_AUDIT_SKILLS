> **Skill ID**: S-037e | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: Route whose trace contains `dispatch()` / `Queue::push()` calls
> **Output**: Extended trace including the async job's internal call chain

# Async Job Tracer

## Purpose

Some sink calls occur not in the synchronous HTTP request flow but inside
background jobs dispatched to a queue. This sub-skill identifies async dispatch
points in the trace, synchronously executes the queued jobs inside Docker, and
appends the job's call chain to the original route trace so that Phase 4
auditors see the complete taint path.

## Procedure

### 1. Identify Async Dispatch Points

Scan the route's trace for calls that dispatch work to a queue:

| Framework | Dispatch Functions |
|-----------|--------------------|
| Laravel | `dispatch()`, `Queue::push()`, `Bus::dispatch()`, `->dispatch()` |
| Symfony | `MessageBusInterface::dispatch()` |
| Generic | `Queue::push()`, `$queue->enqueue()` |

Record the **Job class name** from the dispatch arguments.

### 2. Execute Job Synchronously

Bypass the queue and run the job directly with Xdebug tracing:

```bash
# Ensure the queue worker has Xdebug trace enabled
docker exec php sh -c 'export XDEBUG_CONFIG="mode=trace start_with_request=trigger" && \
  XDEBUG_TRIGGER=1 php artisan queue:work --once --tries=1 --timeout=30'
```

Alternatively, if the dispatch happened during the traced request, the job may
already be in the queue. Execute it within 30 seconds:

```bash
# Step 1: Clean up old traces
docker exec php rm -f /tmp/xdebug_traces/trace.*

# Step 2: Start queue worker in background (waits for job)
docker exec -d php sh -c 'XDEBUG_TRIGGER=1 php artisan queue:work --once --timeout=30'

# Step 3: Send the trigger request
docker exec php curl -s -X POST http://nginx:80$ROUTE_URL \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -d "$BODY"

# Step 4: Wait for job execution
sleep 5
docker exec php ls -la /tmp/xdebug_traces/
```

### 3. Handle Job Chains

If Job A dispatches Job B, run `--once` multiple times until the queue is
empty:

```bash
for i in 1 2 3; do
  docker exec php sh -c 'XDEBUG_TRIGGER=1 php artisan queue:work --once --timeout=15'
done
```

### 4. Collect and Merge Job Trace

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

### 5. WordPress Cron Tracing

For WordPress targets, cron tasks are triggered via HTTP:

```bash
docker exec php curl -s http://nginx:80/wp-cron.php?doing_wp_cron=1 \
  -H "Cookie: XDEBUG_TRIGGER=1"
```

### 6. Generic Event/Listener Tracing

For event-driven architectures where sinks reside in listeners:

1. Identify the event system (`Event::listen`, `EventDispatcher`, `->on(`).
2. Inject tick tracer into the listener's `handle()` method.
3. Trigger the event via HTTP and collect the listener trace.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Trace Filter (S-037c) | (in-memory) | Yes | Call chain containing `dispatch()` or equivalent |
| Request Executor (S-037b) | (in-memory) | Yes | Original request details for re-triggering |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Extended trace | (in-memory) | Original trace + appended job call chain(s) |
| `async_jobs` field | Embedded in trace record | List of traced jobs with `class` and `traced` flag |

## Error Handling

| Error | Action |
|-------|--------|
| No job appears in queue within 30 s | Mark job as `async_jobs: [{class: "...", traced: false}]`; log timeout |
| Job fails during execution | Capture error trace; mark `traced: true` with `job_error: true` |
| Queue driver not supported (e.g., SQS) | Mark as `traced: false`; recommend static analysis of job class |
| Job chain depth > 3 | Stop recursive tracing; log warning |
