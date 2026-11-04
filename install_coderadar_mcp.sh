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
# A fresh clone has no venv. Build it here, once, from pyproject.toml (2026-11-04: the stranger-facing path; before
# this the script refused and said "build the venv first" without saying how). Every other script in the tree
# (launch.sh, coderadar-mcp.sh, replay_gates.sh) expects exactly this path, so the name is not a choice.
if [ ! -x "$ROOT/.venv_new/bin/coderadar-mcp" ]; then
  PY="${PYTHON:-python3}"
  if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    echo "install_coderadar_mcp.sh: CodeRadar needs Python 3.12 or newer; '$PY' is $("$PY" --version 2>&1). Set PYTHON=/path/to/python3.13 and run again." >&2
    exit 1
  fi
  if [ "${1:-}" = "--print" ]; then
    echo "# the venv $ROOT/.venv_new does not exist yet; without --print this script builds it with:" >&2
    echo "#   $PY -m venv $ROOT/.venv_new && $ROOT/.venv_new/bin/pip install -e '$ROOT[lane]'" >&2
  else
    echo "install_coderadar_mcp.sh: building $ROOT/.venv_new with $("$PY" --version 2>&1) (a minute or two; dash, plotly and mypy are the big ones)"
    "$PY" -m venv "$ROOT/.venv_new"
    "$ROOT/.venv_new/bin/pip" install --quiet --upgrade pip
    "$ROOT/.venv_new/bin/pip" install --quiet -e "$ROOT[lane]"
    [ -x "$ROOT/.venv_new/bin/coderadar-mcp" ] || { echo "install_coderadar_mcp.sh: the venv built but $ROOT/.venv_new/bin/coderadar-mcp is still missing" >&2; exit 1; }
    echo "install_coderadar_mcp.sh: venv built; self-test next"
    (cd "$ROOT" && PYTHONDONTWRITEBYTECODE=1 "$ROOT/.venv_new/bin/python" system_scripts/health_check.py >/dev/null 2>&1) \
      && echo "install_coderadar_mcp.sh: self-test passed" \
      || echo "install_coderadar_mcp.sh: self-test reported issues (the first cr_watch runs it again and shows each step)"
  fi
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
