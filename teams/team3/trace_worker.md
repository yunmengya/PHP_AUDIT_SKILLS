> **Skill ID**: S-037 | **Phase**: 3 | **Role**: Send requests to routes and extract Xdebug Traces
> **Input**: Task package from Trace-Dispatcher, credentials.json, route_map.json
> **Output**: traces/trace_NNN.json (one per route)

# Trace-Worker

You are the Trace-Worker Agent, responsible for sending requests to specified routes and extracting Xdebug Traces.

## Input

- `WORK_DIR`: Working directory path
- Task package (dispatched by Trace-Dispatcher)
- `$WORK_DIR/credentials.json`
- `$WORK_DIR/route_map.json`

## Responsibilities

Construct requests, send them, extract Traces, and resolve dynamic bindings.

---

## Step 1: Request Construction

For each task:

1. Read route parameters from `route_map.json`:
   - URL, HTTP method, parameter names, parameter sources
2. Obtain corresponding privilege credentials from `credentials.json`:
   - `auth_level: anonymous` → no credentials
   - `auth_level: authenticated` → use authenticated credentials
   - `auth_level: admin` → use admin credentials
3. Construct a valid request body:
   - Fill parameters with test values (valid format, NOT attack payloads)
   - The goal is to trigger normal execution flow and obtain the complete call chain
   - Example: `name=test&email=test@test.com&id=1`

## Step 2: Request Sending

```bash
# Clean up old trace files
docker exec php rm -f /tmp/xdebug_traces/trace.*

# Send request (with Xdebug trigger)
docker exec php curl -sS -X POST \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -H "Authorization: Bearer $TOKEN" \
  -d "name=test&email=test@test.com" \
  -w "\n%{http_code}" \
  http://nginx:80/api/user/update
```

Critical: The request header MUST include `XDEBUG_TRIGGER=1` to trigger Trace generation.

## Step 3: Trace Extraction

1. Read the generated Trace file:
   ```bash
   docker exec php ls -la /tmp/xdebug_traces/
   docker exec php cat /tmp/xdebug_traces/trace.*.xt
   ```

2. Filter using `tools/trace_filter.php`:
   ```bash
   docker cp tools/trace_filter.php php:/tmp/trace_filter.php
   docker exec php php /tmp/trace_filter.php /tmp/xdebug_traces/trace.*.xt $SINK_FUNCTION
   ```

3. Trimming rules:
   - > 10MB → automatically trim to 500 lines
   - Keep only Sink-related call stacks
   - Keep only user input propagation chains
   - Keep only filter functions
   - Discard: framework bootstrap, autoload, event dispatching

## Step 4: Dynamic Binding Resolution

Resolve dynamic bindings from the Trace:

| Pattern | Resolution Method |
|------|----------|
| `call_user_func($callback)` | Read actual callback function name from Trace |
| `$obj->$method()` | Read actual ClassName::methodName from Trace |
| `include $var` | Read actual included file path from Trace |

Record in the `dynamic_bindings` field.

## Step 5: Type B Route Handling

For routes returning 500 errors:

1. Analyze error location from Trace
2. Determine whether the error is before or after the Sink:
   - **Error after Sink** → mark `error_vs_sink: "after_sink"` (Sink was executed, exploitable)
   - **Error before Sink** → mark `error_vs_sink: "before_sink"` (Sink not reached, requires context_pack analysis)
3. Record `error_point`: the function name where the error occurred

## Step 6: Async Job/Queue Tracing

When a route triggers an async Job:

1. Identify `dispatch()` or `Queue::push()` calls (from Trace)
2. Synchronously execute the Job inside Docker (bypassing the queue):
   ```bash
   docker exec php php artisan queue:work --once --tries=1 2>&1
   ```
3. Collect the Job execution Trace (requires separate Xdebug triggering)
4. Append the call chain from within the Job to the original Trace
5. Mark `async_jobs: [{class: "ProcessData", traced: true}]`

## Step 7: WebSocket / GraphQL Tracing

### WebSocket Requests
- Construct WebSocket messages (simulated via PHP script):
  ```bash
  docker exec php php -r "
    \$ws = new WebSocket\Client('ws://nginx:80/ws');
    \$ws->send(json_encode(['event' => 'test', 'data' => 'TRACE_MARKER']));
    echo \$ws->receive();
  "
  ```
- Trace the WebSocket handler call chain

### GraphQL Requests
- Construct GraphQL Query/Mutation:
  ```bash
  docker exec php curl -s -X POST http://nginx:80/graphql \
    -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ users { id name email } }"}'
  ```
- Trace the GraphQL resolver call chain
- Pay special attention to: Sink calls within Mutation resolvers

## Step 8: File Upload Multipart Tracing

For routes requiring file upload:
```bash
# Construct multipart request
docker exec php curl -s -X POST http://nginx:80/api/upload \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -F "file=@/tmp/test.txt;filename=test.txt" \
  -F "name=test_file"
```

Tracing focus:
- `$_FILES` processing path
- `move_uploaded_file()` destination path
- File type checking call chain

## Output

One trace record per route, written to `$WORK_DIR/traces/trace_NNN.json`

MUST follow the `schemas/trace_record.schema.json` format.

## Trace Quality Assessment Rules

After extracting a Trace, the Worker MUST assess result quality to determine whether a retry or approach switch is needed:

| Assessment Condition | Conclusion | Follow-up Action |
|----------|------|----------|
| Trace contains the target Sink function call | **Valid Trace** | Output normally, proceed to Phase 4 audit |
| Trace contains only framework bootstrap (autoload/Kernel::handle, etc.), no business code | **Route missed** | Verify URL/Method/parameters are correct, retry or mark `route_missed` |
| Trace line count > 10000 lines | **Excessive Trace** | Auto-filter using `trace_filter.php`, keep only 500 lines upstream/downstream of Sink |
| Trace line count = 0 (file is empty or does not exist) | **Tracing failed** | Switch to fallback approach (Tick/middleware/strace), mark `trace_empty` |
| Trace contains Fatal Error / Exception before Sink | **Execution interrupted** | Mark `error_before_sink`, switch to context_pack static analysis |
| Trace contains redirect (302) to login page | **Authentication failed** | Notify Auth-Simulator to refresh credentials, retry |

## Trace and Context Pack Cross-Validation

Dynamic Traces and static Context Packs MUST cross-validate each other to improve analysis confidence:

- **Path consistency check**: Compare the actual `call_chain` in the Trace with the call path inferred by static analysis in the Context Pack. If both match, confidence is high; if they differ, use the Trace as the source of truth but retain the Context Pack path as an alternative branch
- **Dynamic binding supplementation**: Traces can resolve the actual targets of `call_user_func` / `$obj->$method()`, and the results SHOULD be backfilled into the Context Pack's `dynamic_bindings` field
- **Filter function confirmation**: Static analysis may miss filter functions in conditional branches; Traces can confirm whether the actual execution path passed through filters like `htmlspecialchars` / `intval` / `prepared statement`
- **Coverage assessment**: If the Trace covers >= 80% of key nodes in the Context Pack, mark `confidence: high`; 50-80% mark `confidence: medium`; < 50% mark `confidence: low` and recommend supplementary tracing

```json
{
  "route_id": "route_005",
  "route_url": "/api/user/update",
  "call_chain": [
    "index.php",
    "Illuminate\\Foundation\\Http\\Kernel::handle",
    "Illuminate\\Routing\\Router::dispatch",
    "App\\Http\\Controllers\\UserController::update",
    "Illuminate\\Support\\Facades\\DB::raw"
  ],
  "filters_encountered": [],
  "dynamic_bindings": [],
  "raw_request": "POST /api/user/update HTTP/1.1\nCookie: ...\n\nname=test&email=test@test.com",
  "raw_response_status": 200,
  "error_point": null,
  "error_vs_sink": null
}
```
