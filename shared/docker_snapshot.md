# Docker Snapshot Management Shared Instructions

This file is shared by all Phase-4 **attack expert Agents**. A container snapshot MUST be created before each attack round and rolled back after, to ensure a clean environment.

---

## Snapshot Operation Flow

### Pre-Attack: Create Snapshot

```bash
# Execute before each attack round begins
SNAPSHOT_NAME="php_snapshot_${SINK_ID}_round_${ROUND}"
docker commit php "$SNAPSHOT_NAME"
```

### Post-Attack: Rollback to Snapshot

```bash
# Execute rollback after each attack round (regardless of success/failure)
# Save mount path first (cannot inspect after container is removed)
SOURCE_PATH=$(docker inspect php --format='{{range .Mounts}}{{if eq .Destination "/var/www/html"}}{{.Source}}{{end}}{{end}}')
docker stop php
docker rm php

# Rebuild container from snapshot, keeping network and mounts unchanged
docker run -d \
  --name php \
  --network audit_net \
  -v "${SOURCE_PATH}":/var/www/html \
  "$SNAPSHOT_NAME"

# Wait for container readiness
sleep 2
docker exec php php -v > /dev/null 2>&1
```

### Clean Up Snapshots (After All Rounds for This Sink Are Complete)

```bash
# Delete all snapshot images for this Sink to free disk space
docker images --filter "reference=php_snapshot_${SINK_ID}_*" -q | xargs -r docker rmi
```

---

## Race Condition Testing

Perform concurrency testing on **state-changing endpoints** (POST/PUT/DELETE involving balance, inventory, or permission changes):

```bash
# Construct a legitimate request and send 5-10 identical requests concurrently
for i in $(seq 1 10); do
  docker exec php curl -s -X POST http://nginx:80/${ROUTE_PATH} \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "${PAYLOAD}" &
done
wait

# Check results: whether balance/inventory shows anomalies
# Record in the race_condition_results field of the attack results
```

---

## Two-Phase Execution Mode

Phase-4 uses a "parallel analysis + serial attack" mode to avoid conflicts from multiple experts operating the Docker container simultaneously:

- **Phase 1 (Analysis)**: All experts execute in parallel, only reading files (context_packs, traces, source code) without operating the container. Produces `{sink_id}_plan.json` attack plans.
- **Phase 2 (Attack)**: The main orchestrator spawns experts one by one in priority order, each expert exclusively operates the container for attacks. The next one starts only after the previous one completes.

**During Phase 1**: You MUST NOT execute any container operation commands such as `docker exec`, `curl`, or `docker commit`.
**During Phase 2**: You MAY freely operate the container — performing snapshots/rollbacks/sending requests.

## Notes

- Each expert Agent independently manages snapshots for its assigned Sink; MUST NOT operate on other experts' snapshots
- Phase 2 is serial — only one expert operates the container at a time, so there is no conflict risk
- When disk space is insufficient (`df -h` remaining < 2GB), skip snapshots and test directly on the current container
