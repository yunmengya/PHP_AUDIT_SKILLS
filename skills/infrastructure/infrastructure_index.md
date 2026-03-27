# Infrastructure Skills — Index

> **Phase**: Cross-phase infrastructure support
> **Directory**: `skills/infrastructure/`

This index lists all 4 infrastructure skills that provide workspace, checkpoint, recovery, and timeout management.

| Skill ID | File | Responsibility |
|----------|------|----------------|
| S-002 | `workspace_init.md` | Create working directory tree, generate gate/transition scripts, initialize databases and state machine |
| S-003 | `checkpoint_manager.md` | Manage checkpoint.json lifecycle with atomic read/write, validation, resume detection, and incremental audit tracking |
| S-005 | `failure_recovery.md` | Define and execute 3-level gate failure recovery strategy and QC failure recovery with degradation propagation |
| S-007 | `timeout_handler.md` | Monitor and enforce tiered timeout limits for agents, phases, and global audit duration with graceful shutdown |
