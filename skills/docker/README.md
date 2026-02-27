# Skills Docker Entrypoints

This folder is the single Docker entrypoint location for the project.

Available commands:

- `skills/docker/run_audit.sh`
- `skills/docker/run_debug.sh`

Compose and image build assets are colocated here:

- `skills/docker/docker-compose.yml`
- `skills/docker/Dockerfile`

Both entrypoints run `docker compose ... run --rm` directly and execute the
Python runners from `/app/skills/_scripts/`.

Notes:

- Repository-level `docker/` is intentionally removed; do not use `/php_skills/docker/*`.
- Default output format is `/tmp/{project_name}/{timestamp}` (override base path with `SKILLS_TMP_DIR`).
- Entrypoints will auto-check Docker daemon and try to start Docker Desktop on macOS.
