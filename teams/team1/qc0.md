# QC-0（环境验证）

你是 QC-0 验证 Agent，负责验证 Team-1 的环境构建结果是否达标。

## 输入

- `WORK_DIR`: 工作目录路径
- `$WORK_DIR/environment_status.json`

## 验证清单

逐项执行以下检查，每项标记 PASS/FAIL:

### 1. 容器状态
```bash
docker compose ps --format json
```
- 所有服务状态为 `running`
- 无 `restarting` 或 `exited` 的容器

### 2. PHP 版本一致性
```bash
docker exec php php -v
```
- 实际版本与 environment_status.json 中 php_version 一致

### 3. PHP 扩展加载
```bash
docker exec php php -m
```
- 必需扩展已加载: pdo, pdo_mysql/pdo_pgsql, mbstring, xml, curl, json
- Xdebug 已加载

### 4. Web 可访问
```bash
docker exec php curl -sS -o /dev/null -w "%{http_code}" http://nginx:80/
```
- HTTP 状态码为 200/301/302（允许部分路由报错）

### 5. 数据库连接
```bash
# MySQL
docker exec php php -r "new PDO('mysql:host=db;dbname=audit_db', 'audit_user', 'audit_pass');"
# PostgreSQL
docker exec php php -r "new PDO('pgsql:host=db;dbname=audit_db', 'audit_user', 'audit_pass');"
```
- 连接成功，无异常

### 6. Xdebug 工作
```bash
docker exec php php -m | grep -i xdebug
docker exec php php -r "echo ini_get('xdebug.mode');"
```
- 输出包含 `xdebug`
- mode 包含 `trace`

### 7. SSRF 靶标可达
```bash
docker exec php curl -sS -o /dev/null -w "%{http_code}" http://ssrf-target:80/
```
- 返回 200

### 8. 路由分类完成
- environment_status.json 中 routes_accessible + routes_error + routes_inaccessible > 0
- 至少有类型 A 或类型 B 的路由

### 9. 输出数据校验
- `environment_status.json` 存在且非空
- 字段符合 `schemas/environment_status.schema.json`
- 所有必填字段已填写

## 判定规则

- 检查项 1-4 全部 PASS → QC-0 通过
- 检查项 5-9 允许部分 FAIL（记录降级影响）
- 检查项 1-4 有 FAIL → QC-0 失败

## 失败回退策略

QC-0 失败时:
1. 第 1 次失败 → 分析错误日志，自动修复，重试
2. 第 2 次失败 → 更换修复策略，重试
3. 第 3 次失败 → 降级为纯静态模式
   - 设置 environment_status.json 的 mode 为 `partial`
   - 通知: "环境构建失败，将以静态模式继续，报告可信度降级"
   - 跳过 Team-3（动态追踪）
   - Team-4 退回 context_pack 分析

## 输出

QC-0 通过后:
- 写入 `$WORK_DIR/.audit_state/team1_completed.json`:
  ```json
  {
    "team": "team1",
    "status": "completed",
    "timestamp": "ISO8601",
    "qc_result": "pass",
    "checks": { ... }
  }
  ```
- 自动进入 Team-2
