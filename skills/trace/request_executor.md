## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037b |
| Phase | 3 |
| Responsibility | Execute HTTP requests inside Docker and collect Xdebug trace files |

# Request Executor

## Purpose

Execute the constructed HTTP request inside the Docker environment, ensure
Xdebug trace generation is triggered, and collect both the HTTP response and
the resulting trace file for downstream processing.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Constructed request | Request Constructor S-037a (in-memory) | Yes | `url`, `method`, `headers`, `body` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST record actual HTTP response (status + headers + body) for each request — timeout or connection failure MUST be logged, not silently skipped | FAIL — failed requests invisible to downstream analysis |

## Fill-in Procedure

### Step 1 — Clean Up Old Trace Files

| Field | Fill-in Value |
|-------|---------------|
| `trace_dir` | {/tmp/xdebug_traces/} |
| `cleanup_command` | {docker exec php rm -f /tmp/xdebug_traces/trace.*} |

```bash
docker exec php rm -f /tmp/xdebug_traces/trace.*
```

### Step 2 — Send the Request

| Field | Fill-in Value |
|-------|---------------|
| `method` | {GET / POST / PUT / DELETE from constructed request} |
| `cookie_header` | {XDEBUG_TRIGGER=1; + session cookie} |
| `auth_header` | {Bearer token or empty} |
| `content_type` | {application/x-www-form-urlencoded or application/json} |
| `body` | {URL-encoded or JSON body from constructed request} |
| `route_url` | {target route path} |

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

**Critical**: The request MUST include `XDEBUG_TRIGGER=1` in the Cookie header to trigger Xdebug trace generation.

### Step 3 — Capture Response

| Field | Fill-in Value |
|-------|---------------|
| `http_status` | {last line of curl output — numeric status code} |
| `response_body` | {everything before the last line of curl output} |

Parse the `curl` output:
- Last line = HTTP status code (from `-w "\n%{http_code}"`).
- Everything before the last line = response body.

### Step 4 — Locate Trace File

| Field | Fill-in Value |
|-------|---------------|
| `trace_file_path` | {/tmp/xdebug_traces/trace.*.xt — most recently modified} |

```bash
docker exec php ls -la /tmp/xdebug_traces/
```

Identify the newly created `.xt` file. If multiple files exist, use the one with the most recent modification time.

### Step 5 — Handle Type B Routes (500 Errors)

| Field | Fill-in Value |
|-------|---------------|
| `is_500_error` | {true / false} |
| `trace_still_valid` | {true — sink may have been reached before the error} |
| `quality_assessor` | {S-037h will determine error position relative to sink} |

If the HTTP status code is `500`:
1. The trace may still be valid — the Sink may have been reached before the error.
2. Pass the trace to downstream steps; the Trace Quality Assessor (S-037h) will determine whether the error occurred before or after the Sink.

### Step 6 — Record Raw Request/Response

| Field | Fill-in Value |
|-------|---------------|
| `raw_request` | {full request line + headers + body} |
| `raw_response_status` | {HTTP status code} |

Store the raw request and response metadata for inclusion in the final trace record.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| HTTP response | (in-memory) | Status code + response body |
| Xdebug trace path | Container: `/tmp/xdebug_traces/trace.*.xt` | Raw trace file for extraction |

## Examples

### ✅ GOOD — Complete execution record

```json
{
  "raw_request": "POST /api/user/update HTTP/1.1\nCookie: XDEBUG_TRIGGER=1; session=abc\nContent-Type: application/x-www-form-urlencoded\n\nname=test&email=test@test.com",
  "raw_response_status": 200,
  "response_body": "{\"success\": true}",
  "trace_file": "/tmp/xdebug_traces/trace.1234567890.xt"
}
```

Request sent with XDEBUG_TRIGGER, response captured, trace file located.

### ❌ BAD — Missing trace file info

```json
{
  "raw_response_status": 200
}
```

Problems: No `raw_request`, no `response_body`, no `trace_file` path.

## Error Handling

| Error | Action |
|-------|--------|
| `curl` timeout (> 30 s) | Mark task `failed` with reason `timeout` |
| Connection refused | Verify container is running; retry once; then mark `failed` with `container_error` |
| No trace file generated | Mark `trace_empty`; trigger fallback strategy (S-036f) |
| Trace file > 50 MB | Truncate and mark `truncated` |
