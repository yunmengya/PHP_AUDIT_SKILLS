# Compatibility Self-Healing Strategy Mapping Table

This file is used by the `@docker-builder` Agent during **Phase B (Compatibility Fix)**.

After Phase A (Standard Self-Healing ×5) fails, Phase B is entered. Phase B has 3 rounds, each corresponding to a category of fix strategies.

---

## Round B-1: Helper / Missing Function Fix

Extract `Call to undefined function` function names from container error logs and fix according to the mapping table.

| Error Pattern | Fix Command |
|--------------|-------------|
| `Call to undefined function str_slug` | `composer require laravel/helpers` |
| `Call to undefined function str_*` (any str_ helper) | `composer require laravel/helpers` |
| `Call to undefined function array_*` (signature mismatch) | Check PHP version compatibility, try `composer require symfony/polyfill-phpXX` |
| `Call to undefined function collect` | `composer require illuminate/collections` |
| `Call to undefined function env` | `composer require vlucas/phpdotenv` |
| `Call to undefined function dd` / `dump` | `composer require symfony/var-dumper` |
| `Call to undefined function {other}` | Infer package name from function name → `composer search {func}` → `composer require {package}` |

**Execution Flow**:
1. `docker compose logs --tail=100 php 2>&1 | grep "undefined function"` to extract all missing functions
2. Match each against the table above, execute `docker exec php composer require {package} --no-interaction`
3. Restart PHP container: `docker compose restart php`
4. Verify: `docker exec php curl -sS -o /dev/null -w "%{http_code}" http://nginx:80/`
5. If new undefined functions remain → repeat (maximum 5 packages per round)

---

## Round B-2: ServiceProvider / Middleware Fix

Extract Provider or middleware errors from container error logs, comment out non-core components.

| Error Pattern | Fix Command |
|--------------|-------------|
| `Class "XXXServiceProvider" not found` | Comment out that Provider in the `providers` array in `config/app.php` |
| `Target class [xxx] does not exist` (middleware) | Comment out that middleware in `app/Http/Kernel.php` |
| `Class "XXX" not found` (Facade) | Comment out that Facade in the `aliases` array in `config/app.php` |
| `ReflectionException: Class xxx does not exist` | Same as above — locate the reference and comment it out |

**Protection List** — The following components MUST NOT be commented out (they affect core audit functionality):
- `AuthServiceProvider` / `auth` middleware
- `RouteServiceProvider`
- `SessionServiceProvider` / `StartSession` middleware
- `EncryptCookies` middleware
- Database-related Providers

**Execution Flow**:
1. `docker compose logs --tail=100 php 2>&1 | grep -E "not found|does not exist"` to extract errors
2. Confirm the target is not in the protection list
3. Use `docker exec php sed -i` to comment out the corresponding line (add `//` at the beginning)
4. If Laravel: `docker exec php php artisan config:clear && docker exec php php artisan cache:clear`
5. Restart: `docker compose restart php`
6. Verify

---

## Round B-3: PHP Version Switch

When B-1 + B-2 still fail, try switching PHP version and rebuilding the container.

**Strategy**:

| Current PHP Version | Try Switching To | Rationale |
|--------------------|-----------------|-----------|
| 8.0+ | 7.4 | Legacy projects MAY depend on PHP 7.x features |
| 7.x | 8.1 | Newer dependency packages MAY require PHP 8+ |
| 7.4 already tried | 7.2 | Last attempt for very old projects |

**Execution Flow**:
1. Modify `FROM php:X.X-fpm` in `$WORK_DIR/docker/Dockerfile` to the target version
2. `docker compose build --no-cache php`
3. `docker compose up -d php`
4. Re-execute `composer install --no-interaction`
5. Verify

---

## Phase B Failure → Pause and Wait for User Intervention

After all 3 rounds fail:
- Notify the user via AskUserQuestion: "环境构建失败（已尝试标准修复 5 轮 + 兼容性修复 3 轮）。请检查以下错误日志并手动修复环境问题，修复完成后我将重新尝试构建。"
- Attach a summary of the most recent container error logs
- After user confirms the fix, restart the self-healing cycle from Phase A until the environment builds successfully
- **MUST NOT downgrade to static-only mode; the Docker environment MUST build successfully before proceeding**
