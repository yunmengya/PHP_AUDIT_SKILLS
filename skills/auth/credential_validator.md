> **Skill ID**: S-038i | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: credentials (from S-038b–S-038h), test endpoint(s)
> **Output**: validity check results per credential

# Credential Validation

## Purpose

After credentials are obtained by upstream sub-skills (S-038b through S-038h), validate that each credential actually grants the expected access level. This prevents downstream audit phases from operating with invalid or expired credentials.

## Procedure

### Step 1 — Select Test Endpoints

Choose endpoints that require authentication at each level:

| Level | Test Endpoint | Expected Response |
|-------|---------------|-------------------|
| Authenticated | `/api/user` or `/dashboard` | HTTP 200 with user data |
| Admin | `/admin` or `/api/admin/users` | HTTP 200 with admin content |
| Per-role | Role-specific endpoint from route_map | HTTP 200 |

### Step 2 — Test Bearer Token Credentials

```bash
# Authenticated credential test
docker exec php curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" http://nginx:80/api/user

# Admin credential test
docker exec php curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ADMIN_TOKEN" http://nginx:80/admin
```

### Step 3 — Test Cookie-Based Credentials

```bash
# Cookie-based authenticated test
docker exec php curl -s -o /dev/null -w "%{http_code}" \
  -b "session_cookie=xxx" http://nginx:80/dashboard

# Cookie-based admin test
docker exec php curl -s -o /dev/null -w "%{http_code}" \
  -b "session_cookie=yyy" http://nginx:80/admin
```

### Step 4 — Test API Key Credentials

```bash
# Header-based API key
docker exec php curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: $KEY" http://nginx:80/api/data

# Query parameter API key
docker exec php curl -s -o /dev/null -w "%{http_code}" \
  "http://nginx:80/api/data?api_key=$KEY"
```

### Step 5 — Interpret Results

| HTTP Status | Interpretation | Action |
|-------------|----------------|--------|
| `200` | ✅ Valid | Mark credential as valid |
| `401` | ❌ Invalid / expired | Retry with different strategy; mark as invalid |
| `403` | ❌ Insufficient permissions | Credential works but lacks required role; note the actual permission level |
| `302` (redirect to login) | ❌ Invalid | Session expired or cookie rejected; re-acquire |
| `500` | ⚠️ Server error | Investigate; credential may still be valid but endpoint has a bug |

### Step 6 — Record Validation Results

For each credential, record:
- Credential type (bearer / cookie / api_key)
- Target endpoint tested
- HTTP status code received
- Validity determination (valid / invalid / partial)
- Timestamp of validation

### Step 7 — Retry Failed Credentials

If a credential fails validation:
1. Check if the account exists in the database
2. Re-login to get a fresh token/cookie
3. Try an alternate test endpoint
4. If still failing, mark as invalid with reason and trigger the next fallback strategy

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Credentials | `$WORK_DIR/credentials.json` | ✅ | All credential sections (authenticated, admin, roles, oauth_tokens, api_keys, tenants) |
| Route map | `$WORK_DIR/route_map.json` | Optional | Endpoint URLs for validation targets |
| Docker env | Running containers (`php`, `nginx`) | ✅ | Curl execution context |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Validation results | `$WORK_DIR/credential_validation.json` | Per-credential validity status |
| Updated credentials | `$WORK_DIR/credentials.json` | Invalid credentials set to `null` with reason in notes |

Example validation output:
```json
{
  "validation_results": [
    {
      "credential_type": "bearer",
      "level": "authenticated",
      "endpoint_tested": "/api/user",
      "http_status": 200,
      "valid": true,
      "timestamp": "2025-01-15T10:30:00Z"
    },
    {
      "credential_type": "bearer",
      "level": "admin",
      "endpoint_tested": "/admin",
      "http_status": 200,
      "valid": true,
      "timestamp": "2025-01-15T10:30:01Z"
    },
    {
      "credential_type": "cookie",
      "level": "authenticated",
      "endpoint_tested": "/dashboard",
      "http_status": 302,
      "valid": false,
      "reason": "Redirected to login page; session expired",
      "timestamp": "2025-01-15T10:30:02Z"
    }
  ],
  "summary": {
    "total": 3,
    "valid": 2,
    "invalid": 1
  }
}
```

## Error Handling

| Error | Action |
|-------|--------|
| All credentials fail validation | Re-run acquisition sub-skills (S-038b–S-038h); if still failing, mark Phase-3 as degraded |
| Test endpoint returns 404 | Choose a different endpoint from route_map; try `/` as last resort |
| Network/connection errors | Verify Docker containers are running; check nginx proxy config |
| Mixed results (200 on some endpoints, 401 on others) | Credential is valid but has limited scope; document accessible vs restricted endpoints |
| Credential is valid but response body is empty | Mark as valid; the endpoint may return empty for test accounts with no data |
