> **Skill ID**: S-038f | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: database tables, configuration files, source code
> **Output**: discovered API keys ready for use in requests

# API Key Extraction & Discovery

## Purpose

Locate API keys stored in the database, configuration files, or source code. Construct authenticated requests using the discovered keys. This covers both dedicated API key tables and hard-coded keys in config.

## Procedure

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

### Step 4 — Construct Test Requests

```bash
# Header-based
docker exec php curl -H "X-API-Key: $KEY" http://nginx:80/api/data

# Query parameter-based
docker exec php curl "http://nginx:80/api/data?api_key=$KEY"
```

### Step 5 — Categorize Keys by Privilege Level

If multiple keys are found, test each one to determine its permission scope:

| Key Source | Likely Level |
|------------|-------------|
| Admin user's API key | Admin |
| Regular user's API key | Authenticated |
| Service/system key in `.env` | System-level |

### Step 6 — Save to Credentials

Write discovered keys into the `api_keys` section of `credentials.json`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Database | Docker `db` container | ✅ | API key tables (varies) |
| Config files | `$TARGET_PATH/.env`, `$TARGET_PATH/config/` | ✅ | Hard-coded or env-based keys |
| Source code | `$TARGET_PATH/app/` | Optional | Key extraction middleware logic |
| Docker env | Running containers (`php`, `db`) | ✅ | Query + request execution |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Credentials | `$WORK_DIR/credentials.json` → `api_keys` section | Keys labeled by privilege level |

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

## Error Handling

| Error | Action |
|-------|--------|
| No API key tables found in database | Search config files and source code only |
| Keys in database are hashed | Check if plain-text version exists in related columns or logs; if not, generate a new key and insert it |
| API key is IP-restricted | Note the restriction in output; test from within the Docker network |
| Key format is unknown (UUID, hex, etc.) | Inspect existing keys in DB to determine format; generate matching format if inserting new ones |
| No key extraction pattern found in code | Try common header names (`X-API-Key`, `Authorization`, `X-Auth-Token`) by brute-force testing |
