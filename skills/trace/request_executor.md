> **Skill ID**: S-037b | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: Constructed HTTP request (from S-037a)
> **Output**: HTTP response (status + body) + Xdebug trace file path

# Request Executor

## Purpose

Execute the constructed HTTP request inside the Docker environment, ensure
Xdebug trace generation is triggered, and collect both the HTTP response and
the resulting trace file for downstream processing.

## Procedure

### 1. Clean Up Old Trace Files

```bash
docker exec php rm -f /tmp/xdebug_traces/trace.*
```

### 2. Send the Request

Use `curl` inside the container with the `XDEBUG_TRIGGER` cookie:

```bash
docker exec php curl -sS -X $METHOD \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: $CONTENT_TYPE" \
  -d "$BODY" \
  -w "\n%{http_code}" \
  http://nginx:80$ROUTE_URL
```

**Critical**: The request MUST include `XDEBUG_TRIGGER=1` in the Cookie header
to trigger Xdebug trace generation.

### 3. Capture Response

Parse the `curl` output:
- Last line = HTTP status code (from `-w "\n%{http_code}"`).
- Everything before the last line = response body.

### 4. Locate Trace File

```bash
docker exec php ls -la /tmp/xdebug_traces/
```

Identify the newly created `.xt` file. If multiple files exist, use the one
with the most recent modification time.

### 5. Handle Type B Routes (500 Errors)

If the HTTP status code is `500`:

1. The trace may still be valid — the Sink may have been reached before the
   error.
2. Pass the trace to downstream steps; the Trace Quality Assessor (S-037h)
   will determine whether the error occurred before or after the Sink.

### 6. Record Raw Request/Response

Store the raw request and response metadata for inclusion in the final trace
record:

| Field | Value |
|-------|-------|
| `raw_request` | Full request line + headers + body |
| `raw_response_status` | HTTP status code |

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Request Constructor (S-037a) | (in-memory) | Yes | `url`, `method`, `headers`, `body` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| HTTP response | (in-memory) | Status code + response body |
| Xdebug trace path | Container: `/tmp/xdebug_traces/trace.*.xt` | Raw trace file for extraction |

## Error Handling

| Error | Action |
|-------|--------|
| `curl` timeout (> 30 s) | Mark task `failed` with reason `timeout` |
| Connection refused | Verify container is running; retry once; then mark `failed` with `container_error` |
| No trace file generated | Mark `trace_empty`; trigger fallback strategy (S-036f) |
| Trace file > 50 MB | Truncate and mark `truncated` |
