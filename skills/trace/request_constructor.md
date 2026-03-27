> **Skill ID**: S-037a | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: `route_map.json` entry, `credentials.json`
> **Output**: Fully constructed HTTP request (URL, method, headers, body)

# Request Constructor

## Purpose

Build a complete, valid HTTP request for a single route so that the request
triggers normal application execution and produces a meaningful Xdebug trace.
Requests use benign test values — **not** attack payloads — because the goal is
to capture the real call chain, not to exploit.

## Procedure

### 1. Read Route Parameters

From the task package (`route_map.json` entry for the target `route_id`),
extract:

| Field | Description |
|-------|-------------|
| `route_url` | URL path (e.g., `/api/user/update`) |
| `method` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, etc.) |
| `params` | Array of parameter names |
| `param_sources` | Where parameters come from (`query`, `body`, `path`, `header`) |
| `auth_level` | `anonymous`, `authenticated`, or `admin` |

### 2. Select Credentials

Look up the appropriate credential set from `$WORK_DIR/credentials.json`:

| `auth_level` | Credential Action |
|--------------|-------------------|
| `anonymous` | No credentials attached |
| `authenticated` | Use `authenticated` credential set (Cookie / Bearer token) |
| `admin` | Use `admin` credential set |

Store the resulting auth headers / cookies for injection into the request.

### 3. Fill Test Values

For each parameter, generate a type-appropriate benign test value:

| Parameter Pattern | Example Value |
|-------------------|---------------|
| `name`, `username` | `test` |
| `email` | `test@test.com` |
| `id`, `user_id` | `1` |
| `page`, `limit` | `1`, `10` |
| `url`, `link` | `http://example.com` |
| `file` | (handled by File Upload Tracer S-037g) |
| Unknown | `testvalue` |

### 4. Assemble Request Object

Produce a request specification containing:

```
{
  "url":     "http://nginx:80/api/user/update",
  "method":  "POST",
  "headers": {
    "Cookie": "XDEBUG_TRIGGER=1; <session_cookie>",
    "Authorization": "Bearer <token>",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "body": "name=test&email=test@test.com"
}
```

> **Critical**: The `Cookie` header MUST always include `XDEBUG_TRIGGER=1` to
> activate trace generation.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Route map | `$WORK_DIR/route_map.json` | Yes | `route_url`, `method`, `params`, `param_sources`, `auth_level` |
| Credentials | `$WORK_DIR/credentials.json` | Yes (unless `anonymous`) | Cookie / token per auth level |
| Task package | (from S-036e) | Yes | `route_id`, `sink_function` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Constructed request | (in-memory / piped to S-037b) | Complete HTTP request spec ready for execution |

## Error Handling

| Error | Action |
|-------|--------|
| Route not found in `route_map.json` | Mark task `failed` with reason `route_not_found` |
| Required `auth_level` credentials missing | Mark task `failed` with reason `missing_credentials`; notify Auth-Simulator |
| Unknown parameter source type | Default to `body` for POST, `query` for GET |
