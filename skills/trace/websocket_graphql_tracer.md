> **Skill ID**: S-037f | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: WebSocket or GraphQL route entry
> **Output**: Handler/resolver call-chain trace

# WebSocket & GraphQL Tracer

## Purpose

Standard HTTP curl requests cannot exercise WebSocket handlers or GraphQL
resolvers in the same way as REST endpoints. This sub-skill constructs the
appropriate protocol-specific requests and traces the resulting handler or
resolver call chains.

## Procedure

### 1. WebSocket Request Construction

Construct and send a WebSocket message via a PHP script inside the container:

```bash
docker exec php php -r "
  \$ws = new WebSocket\Client('ws://nginx:80/ws');
  \$ws->send(json_encode(['event' => 'test', 'data' => 'TRACE_MARKER']));
  echo \$ws->receive();
"
```

#### Tracing the Handler

1. Ensure Xdebug is configured to trace the WebSocket handler process
   (may require `auto_prepend_file` or a tick tracer if the handler runs in a
   separate worker).
2. Collect the trace file from the handler process.
3. Filter using the same rules as S-037c.

#### Common WebSocket Sink Patterns

| Pattern | Risk |
|---------|------|
| Message body passed to `eval()` / `exec()` | RCE |
| Message body used in SQL query | SQLi |
| Message body written to file | File write |

### 2. GraphQL Request Construction

Send a GraphQL query or mutation via `curl`:

```bash
# Query example
docker exec php curl -s -X POST http://nginx:80/graphql \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name email } }"}'

# Mutation example
docker exec php curl -s -X POST http://nginx:80/graphql \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUser(id: 1, name: \"test\") { id } }"}'
```

#### Tracing the Resolver

1. The Xdebug trace captures the resolver function called for each field.
2. Pay special attention to **Mutation resolvers** — they are more likely to
   contain sinks (writes, deletes, external calls).
3. For nested resolvers, trace the full resolver chain.

#### Common GraphQL Sink Patterns

| Pattern | Risk |
|---------|------|
| Mutation resolver passes args directly to `DB::raw()` | SQLi |
| Resolver constructs shell command from args | RCE |
| File upload mutation with unvalidated type | File upload |

### 3. Construct Protocol-Specific Test Values

| Protocol | Field | Test Value |
|----------|-------|------------|
| WebSocket | `event` | `test` |
| WebSocket | `data` | `TRACE_MARKER` |
| GraphQL Query | `query` | Introspection or simple field query |
| GraphQL Mutation | `query` | Minimal mutation with benign test values |

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Task package (S-036e) | (in-memory) | Yes | `route_url`, `method`, `route_type` (ws/graphql) |
| Credentials (S-037a) | (in-memory) | Yes | Auth headers/cookies |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Handler/resolver trace | (in-memory / piped to S-037c) | Filtered call chain from the handler or resolver |

## Error Handling

| Error | Action |
|-------|--------|
| WebSocket connection refused | Mark `failed` with `ws_connection_refused`; try HTTP fallback |
| WebSocket library not installed in container | Install `textalk/websocket` via Composer or use raw socket PHP script |
| GraphQL introspection disabled | Construct query from route_map parameter hints |
| GraphQL query returns validation errors | Adjust query schema and retry once |
