# Multi-Tenant Credential Isolation

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038g |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | When the target is a multi-tenant application, create test accounts in separate tenants and obtain independent, tenant-scoped credentials. Enables cross-tenant access testing (IDOR, tenant isolation bypass) in later audit phases. |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Database | Docker `db` → `tenants`, `users` tables | ✅ | Tenant IDs, user-tenant mapping |
| Source code | `$TARGET_PATH/` | ✅ | Tenancy middleware, tenant resolution logic |
| Migrations | `$TARGET_PATH/database/migrations/` | Optional | `tenant_id` column definitions |
| Docker env | Running containers (`php`, `nginx`, `db`) | ✅ | User creation + login execution |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate credentials for existing accounts — only use credentials discovered from source code analysis, `$WORK_DIR/credentials.json`, or test accounts created by this procedure | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to `$WORK_DIR/auth/` directory conforming to output contract schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST verify tenant isolation by confirming cross-tenant data access is blocked | FAIL — tenant created but isolation not verified |

---

## Fill-in Procedure

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

### Step 2 — Fill in Tenant Provisioning Table

**Fill in the tenant provisioning table — one row per tenant:**

| Tenant ID | Domain | Account | Credentials |
|-----------|--------|---------|-------------|
| `___` (e.g. `1`) | `___` (e.g. `tenant-a.app.local`) | `___` (e.g. `audit_tenant_1 / tenant1@audit.test`) | `___` (e.g. `Bearer eyJ...` or `Cookie: session=xxx`) |
| `___` (e.g. `2`) | `___` (e.g. `tenant-b.app.local`) | `___` (e.g. `audit_tenant_2 / tenant2@audit.test`) | `___` (e.g. `Bearer eyJ...` or `Cookie: session=yyy`) |
| `___` (e.g. `3`) | `___` (e.g. `tenant-c.app.local`) | `___` (e.g. `audit_tenant_3 / tenant3@audit.test`) | `___` (e.g. `Bearer eyJ...` or `Cookie: session=zzz`) |

### Step 3 — Create Test Accounts for Different Tenants

For each tenant (or create new tenants as needed):

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

### Step 4 — Obtain Tenant-Scoped Credentials

Login as each tenant user and extract credentials. The login may require:
- Tenant-specific subdomain (e.g., `tenant1.app.local`)
- Tenant ID in header (e.g., `X-Tenant-ID: 1`)
- Tenant selection in login payload

### Step 5 — Record Tenant Metadata

For each credential, record:
- `tenant_id` / `org_id`
- Tenant domain/subdomain (if applicable)
- Tenant-specific database (if DB-per-tenant)

### Step 6 — Save to Credentials

Write per-tenant credentials into the `tenants` section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/输出结果/credentials.json` → `tenants` section | Per-tenant tokens/cookies with tenant metadata |

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

---

## Examples

### ✅ GOOD — Complete tenant provisioning with credentials verified

| Tenant ID | Domain | Account | Credentials |
|-----------|--------|---------|-------------|
| `1` | `tenant-a.app.local` | `audit_tenant_1 / tenant1@audit.test` | `Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEwfQ...` (verified: 200 on `/api/user`) |
| `2` | `tenant-b.app.local` | `audit_tenant_2 / tenant2@audit.test` | `Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjExfQ...` (verified: 200 on `/api/user`) |
| `3` | `tenant-c.app.local` | `audit_tenant_3 / tenant3@audit.test` | `Cookie: session=abc789` (verified: 200 on `/dashboard`) |

### ❌ BAD — Tenants listed but no accounts created

| Tenant ID | Domain | Account | Credentials |
|-----------|--------|---------|-------------|
| `1` | `tenant-a.app.local` | (not created) | (none) |
| `2` | (unknown) | (not created) | (none) |

> No test accounts provisioned. Cross-tenant isolation testing impossible without per-tenant credentials.

---

## Error Handling

| Error | Action |
|-------|--------|
| No multi-tenancy detected | Skip this strategy; not applicable |
| Cannot create new tenants | Use existing tenants only; create users within them |
| Tenant isolation at database level | May need to connect to each tenant database separately |
| Login requires tenant-specific subdomain | Configure Docker network aliases or use `Host` header in curl |
| Tenant creation requires billing/subscription | Insert minimal tenant record directly into DB, bypassing business logic |
