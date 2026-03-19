# PHP 代码审计 - 主调度器

触发命令: /php-audit $ARGUMENTS

你是 PHP 代码审计主调度器。接收目标源码路径，按固定 Phase 顺序调度审计流程。
每个 Phase 的具体指令在 phases/ 目录下的独立文件中，你必须逐个读取并严格执行。

## 输入参数

- `$ARGUMENTS`: 目标 PHP 项目源码的绝对路径

---

## Step 0: 确定 SKILL_DIR

运行以下命令确定 skill 项目根目录（包含 teams/、shared/、phases/ 的目录）:

```bash
SKILL_DIR=$(dirname "$(dirname "$(find /Users -maxdepth 6 -path '*/.claude/commands/php-audit.md' -type f 2>/dev/null | head -1)")")
echo "SKILL_DIR=$SKILL_DIR"
ls "$SKILL_DIR/teams" "$SKILL_DIR/shared" "$SKILL_DIR/phases"
```

记录 SKILL_DIR 的值，后续所有文件读取都使用此值作为前缀。

## Step 1: 环境前置检查

```bash
docker --version
docker compose version
df -h /tmp
```

- docker 未安装 → 提示用户安装
- docker compose 未安装 → 提示安装
- 磁盘空间 < 5GB → 警告

如果用户未在 tmux 中运行，提示建议在 tmux 中运行。

## Step 2: 目标路径检查

- 检查 `$ARGUMENTS` 路径是否存在
- 检查路径下是否包含 `.php` 文件（排除 vendor/）
- 不存在或无 .php 文件 → 终止

## Step 3: 创建工作目录

```bash
PROJECT_NAME=$(basename "$ARGUMENTS")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR="/tmp/${PROJECT_NAME}/${TIMESTAMP}"
mkdir -p "$WORK_DIR"
```

设置 TARGET_PATH=$ARGUMENTS

## Step 4: 断点续审检测

检查 `/tmp/${PROJECT_NAME}/` 下最近的目录是否存在 `checkpoint.json`:
- 存在 → 询问用户是否从断点继续
- 不存在 → 全新开始

## Step 4.5: 增量审计模式

检查目标项目是否为 Git 仓库且之前有完整审计记录:
- 非 Git 仓库 → 全量审计
- 变更文件 < 10 个 → 询问用户是否增量审计
- 变更文件 >= 10 个 → 全量审计

## Step 5: 加载共享资源

使用 Read 工具读取以下 3 个核心共享文件，将内容存为 SHARED_RESOURCES:

1. `${SKILL_DIR}/shared/anti_hallucination.md`
2. `${SKILL_DIR}/shared/sink_definitions.md`
3. `${SKILL_DIR}/shared/data_contracts.md`

---

## Step 6: Team + Task 模式调度

### Step 6.0: 创建团队

```
TeamCreate(team_name="php-audit", description="PHP 代码审计 - 目标: {PROJECT_NAME}")
```

如果返回 "Already leading team" 错误: 先 TeamDelete()，再重新 TeamCreate。

### Step 6.1: 创建静态任务（Task #1 ~ #14）

一次性创建以下 14 个任务，通过 TaskUpdate 设置 blockedBy 依赖:

```
#1  "环境侦探 - 框架指纹识别"    activeForm="分析项目环境"       (无依赖)
#2  "表结构重建"                 activeForm="重建数据库表结构"    (无依赖)
#3  "Docker 环境构建"            activeForm="构建 Docker 环境"   (blockedBy: [1, 2])
#4  "QC-0 环境验证"             activeForm="验证环境完整性"      (blockedBy: [3])
#5  "工具扫描 Psalm/Progpilot"   activeForm="运行静态分析"       (blockedBy: [4])
#6  "路由映射"                   activeForm="解析路由表"         (blockedBy: [4])
#7  "鉴权审计"                   activeForm="分析鉴权机制"       (blockedBy: [4])
#8  "组件扫描"                   activeForm="扫描第三方组件"      (blockedBy: [4])
#9  "上下文抽取"                 activeForm="抽取 Sink 上下文"   (blockedBy: [5,6,7,8])
#10 "优先级定级"                 activeForm="漏洞严重度定级"     (blockedBy: [9])
#11 "QC-1 侦察完整性"           activeForm="验证侦察完整性"      (blockedBy: [10])
#12 "鉴权模拟"                   activeForm="模拟鉴权获取凭证"    (blockedBy: [11])
#13 "追踪调度与执行"             activeForm="动态追踪中"         (blockedBy: [12])
#14 "QC-2 调用链验证"           activeForm="验证调用链"         (blockedBy: [13])
```

断点续审: 如果 checkpoint.json 显示已完成某些 Phase，将对应 Task 标记为 completed。

---

### Step 6.2: 执行 Phase 1 — 环境智能识别与构建

1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase1-env.md`
2. 按照文件中的指令，逐步执行所有步骤
3. 完成后验证 GATE-1:
```bash
test -f "$WORK_DIR/environment_status.json" && echo "GATE-1 PASS" || echo "GATE-1 FAIL"
```
4. GATE-1 PASS → 写入 checkpoint: `{"completed": ["env"], "current": "scan"}`
5. GATE-1 FAIL → 检查 Agent 是否正常执行
6. 打印流水线视图（Phase-1 显示数据，Phase-2~5 显示等待中）

---

### Step 6.3: 执行 Phase 2 — 静态资产侦察

1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase2-recon.md`
2. 按照文件中的指令，逐步执行所有步骤
3. 完成后验证 GATE-2:
```bash
test -f "$WORK_DIR/priority_queue.json" && test -d "$WORK_DIR/context_packs" && echo "GATE-2 PASS" || echo "GATE-2 FAIL"
```
4. GATE-2 PASS → 写入 checkpoint: `{"completed": ["env", "scan"], "current": "trace"}`
5. GATE-2 FAIL → 不写入 checkpoint，检查 Agent 是否正常执行
6. 打印流水线视图

---

### Step 6.3.1: 动态创建 Phase 4/5 任务

1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase2-tasks-dynamic.md`
2. 按照文件中的指令，创建所有动态任务

---

### Step 6.4: 执行 Phase 3 — 鉴权模拟与动态追踪

**如果 MODE=static-only**:
- 将 Task #12~#14 标记 completed（降级跳过）
- 打印流水线视图（Phase-3 标记为跳过）
- 直接跳到 Step 6.5

**否则**:
1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase3-trace.md`
2. 按照文件中的指令，逐步执行所有步骤
3. 完成后验证 GATE-3（MODE=full 时）:
```bash
test -f "$WORK_DIR/credentials.json" && echo "GATE-3 PASS" || echo "GATE-3 FAIL"
```
4. 写入 checkpoint: `{"completed": ["env", "scan", "trace"], "current": "exploit"}`
5. 打印流水线视图

---

### Step 6.5: 执行 Phase 4 — 深度对抗审计

**绝对不可跳过此 Phase。**

1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase4-exploit.md`
2. 按照文件中的指令，逐步执行所有步骤
3. 完成后验证 GATE-4:
```bash
test -d "$WORK_DIR/exploits" && ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 && echo "GATE-4 PASS" || echo "GATE-4 FAIL"
```
4. GATE-4 PASS → 写入 checkpoint: `{"completed": ["env", "scan", "trace", "exploit"], "current": "post_exploit"}`
5. GATE-4 FAIL → **不写入 checkpoint**。检查专家 Agent 是否实际被 spawn。如果未 spawn，立即回到 Step 1 执行。
6. 打印流水线视图

---

### Step 6.6: 执行 Phase 4.5 — 后渗透智能分析

**绝对不可跳过此 Phase。**

1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase45-post.md`
2. 按照文件中的指令，逐步执行所有步骤
3. 完成后验证 GATE-4.5:
```bash
test -d "$WORK_DIR/poc" && ls "$WORK_DIR/poc/"*.py >/dev/null 2>&1 && echo "GATE-4.5 PASS" || echo "GATE-4.5 FAIL"
test -d "$WORK_DIR/patches" && echo "PATCHES PASS" || echo "PATCHES FAIL"
```
4. GATE-4.5 PASS → 写入 checkpoint: `{"completed": ["env", "scan", "trace", "exploit", "post_exploit"], "current": "report"}`
5. 打印流水线视图

---

### Step 6.7: 执行 Phase 5 — 清理与报告

1. 使用 Read 工具读取: `${SKILL_DIR}/phases/phase5-report.md`
2. 按照文件中的指令，逐步执行所有步骤
3. 完成后写入 checkpoint: `{"completed": ["env", "scan", "trace", "exploit", "post_exploit", "report"], "current": "done"}`
4. 打印最终流水线视图

---

### Step 6.8: Agent 关闭与团队清理

**关闭所有 Agent**:
```
遍历所有仍活跃的 teammate:
  SendMessage(to="{agent-name}", message={type: "shutdown_request", reason: "任务完成"})
  等待 shutdown_response（最多 30 秒）
```

**团队清理**:
```
TeamDelete()
```

**tmux 保底清理**:
```bash
CURRENT_PANE=$(tmux display-message -p '#{pane_id}' 2>/dev/null)
if [ -n "$CURRENT_PANE" ]; then
  tmux list-panes -F '#{pane_id}' 2>/dev/null | while read pane; do
    [ "$pane" != "$CURRENT_PANE" ] && tmux kill-pane -t "$pane" 2>/dev/null
  done
fi
```

**告知用户**: "审计完成！报告文件: $WORK_DIR/audit_report.md"

---

## 流水线视图模板

每个 Phase 完成后打印一次完整视图。状态标记: ✅=通过 ⚠️=降级 ❌=失败 ⏳=等待 🔄=跳过

```
━━━ 审计流水线状态 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

阶段 1: 环境智能识别与构建 {状态}
  ├─ #1  环境侦探          → {framework} {version}
  ├─ #2  表结构重建         → {n} 张表
  ├─ #3  Docker 构建        → PHP {php_version} + {db_type}
  └─ #4  QC-0 环境验证      → routes: {A}A/{B}B/{C}C
  ↓
阶段 2: 静态资产侦察 {状态}
  ├─ #5  工具扫描           → Psalm + Progpilot
  ├─ #6  路由映射           → {n} 条路由
  ├─ #7  鉴权审计           → {n} 条规则
  ├─ #8  组件扫描           → {n} 个漏洞组件
  ├─ #9  上下文抽取         → {n} 处 Sink
  ├─ #10 优先级定级         → P0:{n} P1:{n} P2:{n} P3:{n}
  └─ #11 QC-1 侦察完整性    → 覆盖率 {n}%
  ↓
阶段 3: 鉴权模拟与动态追踪 {状态}
  ├─ #12 鉴权模拟           → {角色列表}
  ├─ #13 追踪调度           → {成功}/{总数} 条
  └─ #14 QC-2 调用链验证    → 断链 {n} 条
  ↓
阶段 4: 深度对抗审计 {状态}
  ├─ 专家列表 (动态)
  └─ QC-3 物理取证          → {n} 条物证
  ↓
阶段 4.5: 后渗透智能分析 {状态}
  ├─ 攻击图谱构建           → {n} 条攻击路径
  ├─ 关联分析               → 升级 {n}, 二阶 {n}
  ├─ 修复 Patch             → {n} 个 Patch
  └─ PoC 脚本               → {n} 个 PoC
  ↓
阶段 5: 清理与报告 {状态}
  ├─ 环境清理
  ├─ 报告撰写               → {path}
  └─ QC-Final

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
漏洞总计: 确认 {n} + 疑似 {n} + 潜在 {n}  |  总耗时: {total}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## QC 失败回退策略

- QC-0 失败 → 降级为纯静态模式，跳过 Phase-3
- QC-1 失败 → 用已有部分继续，报告中注明覆盖率
- QC-2 失败 → 断链路由退回静态分析
- QC-3 失败 → 降级标注，不阻塞报告生成

## 超时控制

总计审计时间上限 2.5 小时。超时后:
- 保存当前进度到 checkpoint.json
- 生成已完成部分的报告
- TeamDelete()
- 提示用户可使用断点续审继续

## 输出文件

- `$WORK_DIR/audit_report.md` — 主报告
- `$WORK_DIR/audit_report.sarif.json` — SARIF 2.1.0
- `$WORK_DIR/exploits/*.json` — 攻击结果
- `$WORK_DIR/attack_graph.json` — 攻击图谱
- `$WORK_DIR/correlation_report.json` — 关联分析
- `$WORK_DIR/patches/*.patch` — 修复 Patch
- `$WORK_DIR/poc/poc_*.py` — PoC 脚本
- `$WORK_DIR/poc/run_all.sh` — 批量 PoC 执行
- `$WORK_DIR/checkpoint.json` — 断点续审检查点
