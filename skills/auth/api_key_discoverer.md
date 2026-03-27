# API Key Extraction & Discovery

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038f |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | Locate API keys stored in the database, configuration files, or source code. Construct authenticated requests using the discovered keys. Covers both dedicated API key tables and hard-coded keys in config. |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Database | Docker `db` container | ✅ | API key tables (varies) |
| Config files | `$TARGET_PATH/.env`, `$TARGET_PATH/config/` | ✅ | Hard-coded or env-based keys |
| Source code | `$TARGET_PATH/app/` | Optional | Key extraction middleware logic |
| Docker env | Running containers (`php`, `db`) | ✅ | Query + request execution |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT use hardcoded credentials — only use credentials discovered from source code analysis or `$WORK_DIR/credentials.json` | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to `$WORK_DIR/auth/` directory conforming to output contract schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST search source code, config files, `.env`, AND common API key locations — single-source search creates coverage gaps | FAIL — valid API keys missed from unsearched locations |

---

## Fill-in Procedure

### Step 1 — Search Database for API Key Tables

```bash
# Find tables related to API keys
docker exec db mysql -e "SHOW TABLES;" | grep -i "api\|key\|token"

# Query discovered tables
docker exec db mysql -e "SELECT * FROM api_keys LIMIT 5;"
```

Check common table names:
- `api_keys`, `api_tokens`, `access_keys`
- `tokens`, `auth_tokens`
- `personal_access_tokens` (if not OAuth2)

### Step 2 — Search Configuration Files for API Keys

```bash
grep -rn "api_key\|apikey\|API_KEY" $TARGET_PATH/ --include="*.php" --include="*.env*"
```

Also check:
- `$TARGET_PATH/.env` — environment variables
- `$TARGET_PATH/config/*.php` — framework config files
- `$TARGET_PATH/storage/` — cached config

### Step 3 — Identify Key Usage Pattern

Determine how the application expects the API key to be sent:

| Delivery Method | Example |
|-----------------|---------|
| Header | `X-API-Key: $KEY` or `Authorization: Bearer $KEY` |
| Query parameter | `?api_key=$KEY` or `?apikey=$KEY` |
| POST body | `api_key=$KEY` |

Search middleware or request handling code for the key extraction logic.

### Step 4 — Fill in Discovered API Keys

**Fill in the API key discovery table — one row per key found:**

| Source | Location | Key Value | Valid |
|--------|----------|-----------|-------|
| `___` (e.g. `database`) | `___` (e.g. `api_keys table, row id=1`) | `___` (e.g. `ak_live_abc123`) | `___` (✅ / ❌ / untested) |
| `___` (e.g. `.env file`) | `___` (e.g. `API_KEY=xxx on line 42`) | `___` (e.g. `sk_test_def456`) | `___` (✅ / ❌ / untested) |
| `___` (e.g. `source code`) | `___` (e.g. `app/Services/PaymentService.php:15`) | `___` (e.g. `hardcoded_key_789`) | `___` (✅ / ❌ / untested) |

### Step 5 — Construct Test Requests

```bash
# Header-based
docker exec php curl -H "X-API-Key: $KEY" http://nginx:80/api/data

# Query parameter-based
docker exec php curl "http://nginx:80/api/data?api_key=$KEY"
```

### Step 6 — Categorize Keys by Privilege Level

If multiple keys are found, test each one to determine its permission scope:

| Key Source | Likely Level |
|------------|-------------|
| Admin user's API key | Admin |
| Regular user's API key | Authenticated |
| Service/system key in `.env` | System-level |

### Step 7 — Save to Credentials

Write discovered keys into the `api_keys` section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/输出结果/credentials.json` → `api_keys` section | Keys labeled by privilege level |

Example output fragment:
```json
{
  "api_keys": {
    "user_key": "ak_xxx",
    "admin_key": "ak_yyy",
    "system_key": "sk_zzz"
  }
}
```

---

## Examples

### ✅ GOOD — All keys discovered, validated, and categorized

| Source | Location | Key Value | Valid |
|--------|----------|-----------|-------|
| database | `api_keys` table, row id=1, user_id=1 (admin) | `ak_live_Xk9mP2` | ✅ (200 on `/api/admin/users`) |
| database | `api_keys` table, row id=5, user_id=10 (user) | `ak_live_Rn3qW7` | ✅ (200 on `/api/user`, 403 on `/api/admin`) |
| `.env` file | `INTERNAL_API_KEY=xxx` on line 58 | `sk_internal_abc123` | ✅ (200 on `/api/system/health`) |

### ❌ BAD — Keys found but not tested

| Source | Location | Key Value | Valid |
|--------|----------|-----------|-------|
| database | `api_keys` table | (multiple rows) | untested |
| `.env` file | `API_KEY=` | `some_key` | untested |

> Keys discovered but never validated against actual endpoints. Cannot determine privilege level or usability.

---

## Error Handling

| Error | Action |
|-------|--------|
| No API key tables found in database | Search config files and source code only |
| Keys in database are hashed | Check if plain-text version exists in related columns or logs; if not, generate a new key and insert it |
| API key is IP-restricted | Note the restriction in output; test from within the Docker network |
| Key format is unknown (UUID, hex, etc.) | Inspect existing keys in DB to determine format; generate matching format if inserting new ones |
| No key extraction pattern found in code | Try common header names (`X-API-Key`, `Authorization`, `X-Auth-Token`) by brute-force testing |
