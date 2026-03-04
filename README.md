# PHP_AUDIT_SKILLS

面向 PHP 项目的安全审计技能集。  
默认工作模式为 Docker-Only，支持静态审计、动态调试、AI 深入验证、中文报告交付。

---

## 1. 目标与定位

PHP_AUDIT_SKILLS 的目标：

- 给出可复核、可追溯、可复现的审计结论
- 将静态结果与动态证据强绑定，避免“只重复静态”
- 输出网安人员可读、研发可执行的中文报告

---

## 2. 核心能力（已包含新增小功能）

- 路由发现、参数建模、调用链追踪与污点传播
- 多漏洞模块并行分析（SQL/RCE/File/SSRF/XXE/XSS/SSTI/CSRF/反序列化/变量覆盖/鉴权）
- 动态调试验证（切片 + Docker 实际请求 + 逐轮过程记录）
- AI 深入验证（聚焦目标状态，AI-only 绕过循环）
- 阶段门禁（phase_0~7）+ 同一 Verifier Agent 持续验收
- 证据校验阻断分级：硬阻断（BLOCK）与质量预警（WARN）
- `skip_reason` 分类（`precheck_skip/runtime_skip/timeout/auth_required`）

---

## 3. 审计流程（默认全链路）

1. 阶段0：预检与编排  
2. 阶段1：信息收集（路由/鉴权/依赖）  
3. 阶段2：调用链追踪  
4. 阶段3：交叉分析与风险收敛  
5. 阶段4：静态漏洞分析（按 sink 类型）  
6. 阶段5：动态验证与漏洞确认  
7. 阶段6：AI 深入审计（报告驱动 + 源码定位 + Docker 严格验证）  
8. 阶段7：报告汇总与证据校验  

---

## 4. 动态与 AI 深验策略

### 4.1 动态阶段（阶段5）

- 框架项目：先健康检查，通过后再做动态验证
- 无框架项目：先抽取 PHP 切片，再执行动态调试
- 默认记录完整证据：过程、结果、函数追踪、PoC、Burp 模板
- `skipped` 必须带 `skip_reason`，用于区分预检跳过与运行时跳过

### 4.2 AI 深审阶段（阶段6）

- 默认目标状态：`conditional`（可配置）
- 默认模式：AI-only 绕过（不走字典）
- 默认目标：尽量将可疑 case 从 `conditional` 推进到 `confirmed`
- 深审必须在 Docker 内真实执行并落证据

---

## 5. 输出契约（中文优先）

默认输出目录格式：

`{output_base_dir}/{project_name}/{timestamp}`

其中 `timestamp` 格式：`YYYYmmdd_HHMMSS`。

外层仅保留三份主报告（中文）：

1. `最终静态审计结果.md`
2. `动态debug审计报告.md`
3. `AI深入验证最终报告.md`

其余产物归档：

- `归档/阶段报告/`
- `归档/调试证据/`
- `归档/Burp模板/`
- `归档/质量门禁/`
- `归档/结论绑定/`

---

## 6. 门禁与阻断规则（重点）

### 6.1 阶段验收

- 必须按阶段0~7顺序执行
- 每阶段结束后必须运行同一 `agent-verifier` 验收
- 阶段验收文件必须存在：`phase_0_verifier.md` ~ `phase_7_verifier.md`

### 6.2 阻断分级

- 默认：质量类噪声（例如跳过比例预警）记为 WARN，不直接阻断交付
- 严格模式：可将对应规则提升为 BLOCK
- Phase 7 的硬阻断聚焦：
  - Docker 真实性未满足
  - 高危覆盖/深审目标覆盖不满足
  - 证据缺失或不可追溯

### 6.3 跳过率口径

- 跳过率默认按“可执行范围”统计，而非全量 case
- 仅 `runtime_skip` 计入跳过率质量指标
- `precheck_skip/auth_required/timeout` 不计入运行时跳过率

---

## 7. 报告风格约定

主报告要求：

- 全中文表达
- 人话优先，避免机器 JSON 直出
- 每条漏洞给出明确修复动作与复测标准

AI 深验报告要求：

- 漏洞“项目/结论”两列表
- “动态调试过程（逐轮）”表
- Burp 复现模板（`http` 代码块）
- 结论对照（静态 / 动态 / AI）使用中文状态
- 验证过程默认只展开 `已确认 / 有条件成立`，其余状态做汇总

中文状态枚举：

- 已确认
- 有条件成立
- 已排除
- 已跳过

---

## 8. Claude 脱敏提示词模板（推荐）

> 以下模板已去除本地路径、账号目录等敏感信息，可直接放入公开文档。

```text
使用 agent team 模式执行 PHP_AUDIT_SKILLS 审计。

【固定输入】
- 项目路径：{PROJECT_PATH}
- SKILLS 路径：{SKILLS_PATH}
- 输出根目录：{OUTPUT_BASE_DIR}
- 子任务 team 成员模型：全部 {MODEL_NAME}（主控同模型）

【必须遵守】
1) 先读取 {SKILLS_PATH}/SKILL.md，并先输出将执行的硬约束清单（5-10条），再开始执行。
2) 必须通过 {SKILLS_PATH}/docker/run_audit.sh 执行，不允许绕过 Docker，不允许手工拼装静态流程代替。
3) 输出目录必须是：{OUTPUT_BASE_DIR}/{project_name}/{timestamp}，timestamp 格式 YYYYmmdd_HHMMSS。
4) 必须按阶段0~7顺序执行；每个阶段结束后必须运行同一个质检 agent（agent-verifier）验收。
5) 每阶段验收文件必须存在且为 PASS：
   归档/质量门禁/步骤门禁/phase_0_verifier.md ... phase_7_verifier.md
6) 动态阶段与AI深入阶段必须证明在 Docker 中真实执行（不是文字说明）：
   - debug_verify/动态运行元信息.json
   - ai_deep_audit/ai_deep_audit_summary.json
7) 若任一阶段或验收 BLOCK：立即停止，输出失败阶段、失败原因、对应 verifier 报告绝对路径、可复跑命令。
8) 不允许只输出静态总结报告后结束。

【完成时输出】
- 先输出阶段验收汇总（phase_0~7 PASS/BLOCK）
- 再输出三份主报告绝对路径：
  1. 最终静态审计结果.md
  2. 动态debug审计报告.md
  3. AI深入验证最终报告.md
- 最后一行必须是 AI深入验证最终报告.md 的绝对路径
如果没有按上述硬约束执行，直接判定本次任务失败，不要输出“已完成”。
```

### 8.1 占位符说明（脱敏）

- `{PROJECT_PATH}`：待审计项目路径
- `{SKILLS_PATH}`：本技能目录路径
- `{OUTPUT_BASE_DIR}`：输出根目录（建议临时目录）
- `{MODEL_NAME}`：Team 全员模型名（如 `glm-5`）

---

## 9. 常见问题（Claude 场景）

- AI 实时补全失败：流程允许降级继续，但会保留证据状态
- 动态验证偏弱：优先确认目标可请求、路由可达、认证条件满足
- 报告太技术化：主文保持人话，技术细节放归档附录
- 结果“像静态重复”：检查动态绑定、逐轮调试、AI 深审是否实际执行

---

## 10. 版本说明

该 README 面向 Claude 编排执行场景，不强调手工命令。  
如需 CLI 手工运行说明，可另维护 `README.cli.md`。
