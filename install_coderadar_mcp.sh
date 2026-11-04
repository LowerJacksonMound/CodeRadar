#!/usr/bin/env bash
# install_coderadar_mcp.sh — register CodeRadar's MCP server with Claude Code ONCE (R1, path-first).
#
#   bash install_coderadar_mcp.sh            # register (user scope: every project sees it)
#   bash install_coderadar_mcp.sh --print    # print the command, change nothing
#
# After this, open Claude Code in any repo and type  /mcp__coderadar__scan <path>  (or just
# "scan <path>"). The server starts with NO target; cr_watch names it. Nothing is written into
# any target repo (no .mcp.json there).
#
# The long tool timeout: cr_watch blocks until every gate passes (1.5-40 min). Claude Code
# 2.1.284 honours a per-server "timeout" (milliseconds) in the server's config entry — it
# overrides MCP_TOOL_TIMEOUT for this server only (verified 2026-09-28, run 177: a 12 s tool
# under "timeout": 3000 was cut off at 3 s; the same tool with no timeout returned). `claude mcp
# add` has no flag for it, so the entry goes in through `claude mcp add-json`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENTRY="$ROOT/coderadar-mcp.sh"
NAME="coderadar"
TIMEOUT_MS=3000000   # 50 min, above cr_watch's 40-min ceiling

if [ ! -x "$ENTRY" ]; then
  echo "install_coderadar_mcp.sh: $ENTRY is missing or not executable" >&2
  exit 1
fi
if [ ! -x "$ROOT/.venv_new/bin/coderadar-mcp" ]; then
  echo "install_coderadar_mcp.sh: $ROOT/.venv_new/bin/coderadar-mcp is missing — build the venv first" >&2
  exit 1
fi

JSON=$(printf '{"type":"stdio","command":"%s","args":[],"timeout":%s}' "$ENTRY" "$TIMEOUT_MS")

if [ "${1:-}" = "--print" ]; then
  printf "claude mcp add-json --scope user %s '%s'\n" "$NAME" "$JSON"
  exit 0
fi

if ! command -v claude >/dev/null 2>&1; then
  echo "install_coderadar_mcp.sh: the claude CLI is not on PATH. Register by hand with:" >&2
  printf "  claude mcp add-json --scope user %s '%s'\n" "$NAME" "$JSON" >&2
  exit 1
fi

if claude mcp get "$NAME" >/dev/null 2>&1; then
  echo "install_coderadar_mcp.sh: an MCP server named '$NAME' is already registered — replacing it"
  claude mcp remove --scope user "$NAME" >/dev/null 2>&1 || true
fi

claude mcp add-json --scope user "$NAME" "$JSON"
echo
echo "Registered '$NAME' -> $ENTRY (tool timeout ${TIMEOUT_MS} ms, this server only)."
echo "Open Claude Code in any directory and type:  /mcp__coderadar__scan <repo path>"
echo "If your Claude Code ignores the per-server timeout (older than 2.1.284), launch it with:"
echo "  MCP_TOOL_TIMEOUT=$TIMEOUT_MS claude"
