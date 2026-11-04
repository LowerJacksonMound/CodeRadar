#!/usr/bin/env bash
# coderadar-mcp.sh — the launcher a client runs (Q1, session 6, 2026-09-20).
#
# The console script `coderadar-mcp` lives only in this tree's venv (`[project.scripts]`
# in pyproject.toml → .venv_new/bin/coderadar-mcp); it is NOT on PATH, so a client
# outside the venv cannot resolve the bare name. Nothing is installed outside the tree
# the gates check — a `pipx install -e .` would put the engine's dependencies where
# health step 20 cannot see them. This wrapper is the whole of the packaging.
#
# Named by ABSOLUTE PATH in the client's config; it resolves the tree from its own
# location, so it works from any cwd. Every argument is passed through untouched
# (R1, 2026-09-28: normally NO arguments — the server starts path-first and cr_watch names
# the target; an optional `--target`, `--state-dir`, `--tree` and `--print-tools` ride here).
#
# PYTHONPATH is the tree root, and it is NOT redundant (measured, run 152): this venv's
# editable-install hook `__editable__.noai_validator-8.0.0.pth` carries the macOS UF_HIDDEN
# flag, and Python 3.14's `site.addpackage` SKIPS a hidden .pth file — so the finder that
# maps `coderadar_mcp`, `no_aivalidator`, `system_scripts`, `utils`, … to this tree never
# installs. Every process to date has run with cwd == the tree root, where `''` on sys.path
# covered it; a MOUNTED client starts the server from the TARGET's directory, where nothing
# does. The variable names exactly the directories the editable finder's MAPPING names.
#
# stdout IS the MCP transport — this script must print nothing to it.
#
# C3 (f) / B10 (Q-H1-1, 2026-10-01): the same three exports launch.sh makes, so the server and
# everything it spawns (cr_watch's launch.sh inherits and re-exports its own) write no .pyc into
# the tree and keep mypy's cache in the engine-owned system_scripts/.cr_pycache/ that launch.sh's
# pre-flight sweeps (gate 18 fails a run on bytecode or .mypy_cache in the tree). One prefix per
# server start, `mcp_<ts>`, beside launch.sh's `launch_<ts>`; nothing is created until Python
# writes to it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX="$ROOT/system_scripts/.cr_pycache/mcp_$(date +%Y%m%d_%H%M%S)"
export MYPY_CACHE_DIR="$PYTHONPYCACHEPREFIX/mypy"
exec "$ROOT/.venv_new/bin/coderadar-mcp" "$@"
