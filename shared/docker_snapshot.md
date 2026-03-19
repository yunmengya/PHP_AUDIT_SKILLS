# Docker 快照管理共享指令

本文件供所有 Phase-4 **攻击专家 Agent** 共用。每轮攻击前创建容器快照，攻击后回滚，确保干净环境。

---

## 快照操作流程

### 攻击前: 创建快照

```bash
# 在每轮攻击开始前执行
SNAPSHOT_NAME="php_snapshot_${SINK_ID}_round_${ROUND}"
docker commit php "$SNAPSHOT_NAME"
```

### 攻击后: 回滚到快照

```bash
# 每轮攻击结束后（无论成功/失败）执行回滚
docker stop php
docker rm php

# 从快照重建容器，保持网络和挂载不变
docker run -d \
  --name php \
  --network audit_net \
  -v "$(docker inspect php_snapshot_${SINK_ID}_round_1 --format='{{range .Mounts}}{{.Source}}{{end}}')":/var/www/html \
  "$SNAPSHOT_NAME"

# 等待容器就绪
sleep 2
docker exec php php -v > /dev/null 2>&1
```

### 清理快照（本 Sink 所有轮次结束后）

```bash
# 删除本 Sink 的所有快照镜像，释放磁盘空间
docker images --filter "reference=php_snapshot_${SINK_ID}_*" -q | xargs -r docker rmi
```

---

## 竞态条件测试

对 **状态变更类接口**（POST/PUT/DELETE 且涉及余额、库存、权限变更）执行并发测试:

```bash
# 构造合法请求，并发发送 5-10 个相同请求
for i in $(seq 1 10); do
  docker exec php curl -s -X POST http://nginx:80/${ROUTE_PATH} \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "${PAYLOAD}" &
done
wait

# 检查结果: 余额/库存是否出现异常
# 记录到攻击结果的 race_condition_results 字段
```

---

## 两阶段执行模式

Phase-4 采用"并行分析 + 串行攻击"模式，避免多个专家同时操作 Docker 容器的冲突:

- **阶段 1（分析）**: 所有专家并行执行，只读取文件（context_packs、traces、源码），不操作容器。生成 `{sink_id}_plan.json` 攻击计划。
- **阶段 2（攻击）**: 主调度器按优先级逐个 spawn 专家，每个专家独占容器执行攻击。上一个完成后下一个才开始。

**你在阶段 1 时**: 禁止执行任何 `docker exec`、`curl`、`docker commit` 等容器操作命令。
**你在阶段 2 时**: 可以自由操作容器，执行快照/回滚/发送请求。

## 注意事项

- 每个专家 Agent 独立管理自己负责的 Sink 的快照，不要操作其他专家的快照
- 阶段 2 是串行的，同一时间只有一个专家操作容器，无冲突风险
- 磁盘空间不足时（`df -h` 剩余 < 2GB），跳过快照，直接在当前容器测试
