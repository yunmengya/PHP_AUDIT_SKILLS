# 兼容性自愈策略映射表

本文件供 `@docker-builder` Agent 在 **Phase B（兼容性修复）** 阶段使用。

Phase A（标准自愈 ×5）失败后进入 Phase B，Phase B 共 3 轮，每轮对应一类修复策略。

---

## Round B-1: Helper / 函数缺失修复

从容器错误日志中提取 `Call to undefined function` 的函数名，按映射表修复。

| 错误特征 | 修复命令 |
|----------|----------|
| `Call to undefined function str_slug` | `composer require laravel/helpers` |
| `Call to undefined function str_*` (任意 str_ helper) | `composer require laravel/helpers` |
| `Call to undefined function array_*` (签名不匹配) | 检查 PHP 版本兼容性，尝试 `composer require symfony/polyfill-phpXX` |
| `Call to undefined function collect` | `composer require illuminate/collections` |
| `Call to undefined function env` | `composer require vlucas/phpdotenv` |
| `Call to undefined function dd` / `dump` | `composer require symfony/var-dumper` |
| `Call to undefined function {其他}` | 从函数名推断包名 → `composer search {func}` → `composer require {package}` |

**执行流程**:
1. `docker compose logs --tail=100 php 2>&1 | grep "undefined function"` 提取所有缺失函数
2. 逐一匹配上表，执行 `docker exec php composer require {package} --no-interaction`
3. 重启 PHP 容器: `docker compose restart php`
4. 验证: `docker exec php curl -sS -o /dev/null -w "%{http_code}" http://nginx:80/`
5. 仍有新的 undefined function → 重复（本轮内最多修 5 个包）

---

## Round B-2: ServiceProvider / 中间件修复

从容器错误日志中提取 Provider 或中间件报错，注释掉非核心组件。

| 错误特征 | 修复命令 |
|----------|----------|
| `Class "XXXServiceProvider" not found` | 在 `config/app.php` 的 `providers` 数组中注释该 Provider |
| `Target class [xxx] does not exist` (中间件) | 在 `app/Http/Kernel.php` 中注释该中间件 |
| `Class "XXX" not found` (Facade) | 在 `config/app.php` 的 `aliases` 数组中注释该 Facade |
| `ReflectionException: Class xxx does not exist` | 同上，定位引用位置并注释 |

**保护清单** — 以下组件 **禁止注释**（影响审计核心功能）:
- `AuthServiceProvider` / `auth` 中间件
- `RouteServiceProvider`
- `SessionServiceProvider` / `StartSession` 中间件
- `EncryptCookies` 中间件
- 数据库相关 Provider

**执行流程**:
1. `docker compose logs --tail=100 php 2>&1 | grep -E "not found|does not exist"` 提取报错
2. 确认目标不在保护清单中
3. 用 `docker exec php sed -i` 注释对应行（在行首加 `//`）
4. 如果是 Laravel: `docker exec php php artisan config:clear && docker exec php php artisan cache:clear`
5. 重启: `docker compose restart php`
6. 验证

---

## Round B-3: PHP 版本切换

B-1 + B-2 仍失败时，尝试切换 PHP 版本重建容器。

**策略**:

| 当前 PHP 版本 | 尝试切换到 | 理由 |
|---------------|-----------|------|
| 8.0+ | 7.4 | 旧项目可能依赖 PHP 7.x 特性 |
| 7.x | 8.1 | 新依赖包可能要求 PHP 8+ |
| 7.4 已尝试 | 7.2 | 极老项目最后尝试 |

**执行流程**:
1. 修改 `$WORK_DIR/docker/Dockerfile` 中的 `FROM php:X.X-fpm` 为目标版本
2. `docker compose build --no-cache php`
3. `docker compose up -d php`
4. 重新执行 `composer install --no-interaction`
5. 验证

---

## Phase B 失败 → 正式降级

3 轮全部失败后:
- 设置 `DEGRADED_MODE=static-only`
- 通知用户: "环境构建失败（已尝试标准修复 5 轮 + 兼容性修复 3 轮），将以纯静态模式继续审计。Phase-3 动态追踪将跳过，Phase-4 退回 context_pack 静态分析。报告可信度降级。"
