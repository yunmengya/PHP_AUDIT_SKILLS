#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="$ROOT_DIR/assets/third_party"

mkdir -p "$DEST_DIR"

clone_or_pull() {
  local name="$1"
  local url="$2"
  local path="$DEST_DIR/$name"

  if [ -d "$path/.git" ]; then
    git -C "$path" pull --ff-only
  else
    git clone "$url" "$path"
  fi
}

clone_or_pull "semgrep-rules" "https://github.com/semgrep/semgrep-rules.git"
clone_or_pull "trailofbits-semgrep-rules" "https://github.com/trailofbits/semgrep-rules.git"
clone_or_pull "apiiro-malicious-code-ruleset" "https://github.com/apiiro/malicious-code-ruleset.git"

echo "Rules synced to: $DEST_DIR"
