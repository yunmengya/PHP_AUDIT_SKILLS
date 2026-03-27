## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037a |
| Phase | 3 |
| Responsibility | Build complete HTTP requests with benign test values for trace generation |

# Request Constructor

## Purpose

Build a complete, valid HTTP request for a single route so that the request
triggers normal application execution and produces a meaningful Xdebug trace.
Requests use benign test values — **not** attack payloads — because the goal is
to capture the real call chain, not to exploit.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `route_map.json` | `$WORK_DIR/route_map.json` | Yes | `route_url`, `method`, `params`, `param_sources`, `auth_level` |
| `credentials.json` | `$WORK_DIR/credentials.json` | Yes (unless `anonymous`) | Cookie / token per auth level |
| Task package | From S-036e (in-memory) | Yes | `route_id`, `sink_function` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST include all required parameters discovered from route analysis — missing parameters cause HTTP 400/422 in trace execution | FAIL — incomplete requests produce unusable traces |

## Fill-in Procedure

### Step 1 — Read Route Parameters

| Field | Fill-in Value |
|-------|---------------|
| `route_url` | {route path from route_map, e.g., /api/user/update} |
| `method` | {GET / POST / PUT / DELETE from route_map} |
| `params` | {array of parameter names from route_map} |
| `param_sources` | {query / body / path / header — where each param comes from} |
| `auth_level` | {anonymous / authenticated / admin from route_map} |

From the task package (`route_map.json` entry for the target `route_id`), extract:

| Field | Description |
|-------|-------------|
| `route_url` | URL path (e.g., `/api/user/update`) |
| `method` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, etc.) |
| `params` | Array of parameter names |
| `param_sources` | Where parameters come from (`query`, `body`, `path`, `header`) |
| `auth_level` | `anonymous`, `authenticated`, or `admin` |

### Step 2 — Select Credentials

| Field | Fill-in Value |
|-------|---------------|
| `auth_level` | {anonymous / authenticated / admin} |
| `credential_type` | {none / Cookie / Bearer token} |
| `credential_value` | {session cookie or JWT token from credentials.json} |

Look up the appropriate credential set from `$WORK_DIR/credentials.json`:

| `auth_level` | Credential Action |
|--------------|-------------------|
| `anonymous` | No credentials attached |
| `authenticated` | Use `authenticated` credential set (Cookie / Bearer token) |
| `admin` | Use `admin` credential set |

Store the resulting auth headers / cookies for injection into the request.

### Step 3 — Fill Test Values

| Field | Fill-in Value |
|-------|---------------|
| `param_name` | {each parameter name from params array} |
| `test_value` | {type-appropriate benign value from mapping table below} |

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

### Step 4 — Assemble Request Object

| Field | Fill-in Value |
|-------|---------------|
| `url` | {http://nginx:80 + route_url} |
| `method` | {GET / POST / PUT / DELETE} |
| `headers` | {auth headers from credentials + XDEBUG_TRIGGER=1 cookie + Content-Type} |
| `body` | {URL-encoded or JSON-encoded parameter values} |

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

> **Critical**: The `Cookie` header MUST always include `XDEBUG_TRIGGER=1` to activate trace generation.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Constructed request | (in-memory / piped to S-037b) | Complete HTTP request spec ready for execution |

## Examples

### ✅ GOOD — Complete request with all fields

```json
{
  "url": "http://nginx:80/api/user/update",
  "method": "POST",
  "headers": {
    "Cookie": "XDEBUG_TRIGGER=1; session=abc123",
    "Authorization": "Bearer eyJhbGciOi...",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "body": "name=test&email=test@test.com"
}
```

All fields present, XDEBUG_TRIGGER cookie included, benign test values used.

### ❌ BAD — Missing critical fields

```json
{
  "url": "/api/user/update",
  "method": "POST"
}
```

Problems: No base URL (missing `http://nginx:80`), no headers (missing XDEBUG_TRIGGER), no body, no Content-Type.

## Error Handling

| Error | Action |
|-------|--------|
| Route not found in `route_map.json` | Mark task `failed` with reason `route_not_found` |
| Required `auth_level` credentials missing | Mark task `failed` with reason `missing_credentials`; notify Auth-Simulator |
| Unknown parameter source type | Default to `body` for POST, `query` for GET |
