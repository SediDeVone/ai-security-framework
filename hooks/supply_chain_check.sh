#!/usr/bin/env bash
# SessionStart supply-chain check. Cached daily so sessions start fast.
# Scans: MCP server configs + tool descriptions (poisoning/shadowing/rug pulls),
# skills, and Claude Code config files.
set -u
STAMP="$HOME/.claude/.supply-scan-stamp"
LOG="$HOME/.claude/.supply-scan.log"

# run at most once per day
if [ -f "$STAMP" ] && [ "$(find "$STAMP" -mtime -1 2>/dev/null)" ]; then
  exit 0
fi
touch "$STAMP"

{
  echo "=== supply-chain scan $(date -Iseconds) ==="

  # MCP servers + skills: Snyk agent-scan (successor of Invariant mcp-scan)
  if command -v uvx >/dev/null; then
    uvx mcp-scan@latest scan --json 2>&1 | tail -50
  fi

  # Config tampering: settings.json, CLAUDE.md, hook definitions
  if command -v sketchy >/dev/null; then
    sketchy scan ~/.claude "$PWD/.claude" "$PWD/CLAUDE.md" 2>&1 | tail -30
  fi

  # Secrets already sitting in the repo
  if command -v gitleaks >/dev/null && [ -d "$PWD/.git" ]; then
    gitleaks detect --source "$PWD" --no-banner --exit-code 0 2>&1 | tail -20
  fi
} >> "$LOG" 2>&1 &

# Non-blocking: findings land in the log; alert on CRITICAL from last run
if grep -q "CRITICAL\|tool poisoning\|shadowing" "$LOG" 2>/dev/null; then
  echo "[security] Supply-chain scanner flagged issues — review $LOG"
fi
exit 0
