> **Skill ID**: S-038g | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: tenant schema (database structure with tenant isolation)
> **Output**: per-tenant credentials for cross-tenant testing

# Multi-Tenant Credential Isolation

## Purpose

When the target is a multi-tenant application, create test accounts in separate tenants and obtain independent, tenant-scoped credentials. This enables cross-tenant access testing (IDOR, tenant isolation bypass) in later audit phases.

## Procedure

### Step 1 — Detect Multi-Tenancy Model

Identify how the application implements tenant isolation:

| Model | Detection Pattern |
|-------|-------------------|
| Column-based | `tenant_id`, `org_id`, `company_id` column in most tables |
| Database-per-tenant | Separate database per tenant; `tenants` table with DB connection info |
| Schema-per-tenant | PostgreSQL schemas; `tenants` table with schema name |
| Domain-based | `domains` or `tenants` table with `domain` / `subdomain` column |
| Package-based | `stancl/tenancy`, `hyn/multi-tenant` in `composer.json` |

```bash
# Search for tenancy packages
grep -i "tenancy\|multi-tenant\|stancl\|hyn" $TARGET_PATH/composer.json

# Search for tenant_id columns
grep -rn "tenant_id\|org_id\|company_id" $TARGET_PATH/database/migrations/ --include="*.php" | head -20

# Query tenants table
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SHOW TABLES LIKE '%tenant%';"
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SELECT * FROM tenants LIMIT 5;" 2>/dev/null
```

### Step 2 — Create Test Accounts for Different Tenants

For each tenant (or create new tenants if possible):

```bash
# Identify existing tenants
TENANTS=$(docker exec db mysql -uroot -paudit_root_pass audit_db -sN -e "SELECT id FROM tenants LIMIT 3;")

# Create a test user in each tenant
for TENANT_ID in $TENANTS; do
  HASH=$(docker exec php php -r "echo password_hash('AuditTenant123!', PASSWORD_BCRYPT);")
  docker exec db mysql -uroot -paudit_root_pass audit_db -e \
    "INSERT INTO users (name, email, password, tenant_id, created_at) \
     VALUES ('audit_tenant_${TENANT_ID}', 'tenant${TENANT_ID}@audit.test', '${HASH}', ${TENANT_ID}, NOW());"
  echo "[CREATED] User for tenant ${TENANT_ID}"
done
```

### Step 3 — Obtain Tenant-Scoped Credentials

Login as each tenant user and extract credentials. The login may require:
- Tenant-specific subdomain (e.g., `tenant1.app.local`)
- Tenant ID in header (e.g., `X-Tenant-ID: 1`)
- Tenant selection in login payload

### Step 4 — Record Tenant Metadata

For each credential, record:
- `tenant_id` / `org_id`
- Tenant domain/subdomain (if applicable)
- Tenant-specific database (if DB-per-tenant)

### Step 5 — Save to Credentials

Write per-tenant credentials into the `tenants` section of `credentials.json`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Database | Docker `db` container → `tenants`, `users` tables | ✅ | Tenant IDs, user-tenant mapping |
| Source code | `$TARGET_PATH/` | ✅ | Tenancy middleware, tenant resolution logic |
| Migrations | `$TARGET_PATH/database/migrations/` | Optional | `tenant_id` column definitions |
| Docker env | Running containers (`php`, `nginx`, `db`) | ✅ | User creation + login execution |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Credentials | `$WORK_DIR/credentials.json` → `tenants` section | Per-tenant tokens/cookies with tenant metadata |

Example output fragment:
```json
{
  "tenants": {
    "tenant_a": {
      "token": "eyJ...",
      "tenant_id": 1,
      "domain": "tenant-a.app.local",
      "user_id": 10,
      "username": "audit_tenant_1"
    },
    "tenant_b": {
      "token": "eyJ...",
      "tenant_id": 2,
      "domain": "tenant-b.app.local",
      "user_id": 11,
      "username": "audit_tenant_2"
    }
  }
}
```

## Error Handling

| Error | Action |
|-------|--------|
| No multi-tenancy detected | Skip this strategy; not applicable |
| Cannot create new tenants | Use existing tenants only; create users within them |
| Tenant isolation at database level | May need to connect to each tenant database separately |
| Login requires tenant-specific subdomain | Configure Docker network aliases or use `Host` header in curl |
| Tenant creation requires billing/subscription | Insert minimal tenant record directly into DB, bypassing business logic |
