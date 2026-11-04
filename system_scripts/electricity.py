#!/usr/bin/env python3
"""
electricity.py -- On-demand "script electricity" status check.

The screenshot principle made terminal-sized: LOOK at the live circuit.
Reads circuit_state.json — the raw state the circuit daemon writes every
frame — plus running.json (kernel/process-scan proven running scripts)
and poll_config.json (target + frame interval).

Usage:
    python3 electricity.py              # one-shot check
    python3 electricity.py --watch 5    # refresh every 5s
    python3 electricity.py --json       # machine-readable output

Exit codes:
    0 - Scripts running (daemon data is fresh)
    1 - Config error (repo not found)
    2 - No scripts running (daemon data is fresh)
    3 - Daemon never started (no state file or health endpoint)
    4 - Daemon data stale (but health endpoint alive)
    5 - Daemon crashed (stale state, no health endpoint)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import fcntl
from pathlib import Path

from engine_utils import read_json, _DEFAULT_HEALTH_PORT

SCRIPT_DIR = Path(__file__).resolve().parent
POLL_CONFIG_FILE = SCRIPT_DIR / "poll_config.json"
# The daemon's single source of truth — written fresh every scan frame.
CIRCUIT_STATE_FILE = SCRIPT_DIR / "circuit_state.json"
# Process table of detected running monitored scripts (daemon-written).
RUNNING_STATE_FILE = SCRIPT_DIR / "running.json"
PROJECT_ROOT = SCRIPT_DIR.parent


def _read_poll_config() -> Dict[str, Any]:
    """Read poll_config.json with shared lock (daemon-compatible)."""
    try:
        if POLL_CONFIG_FILE.exists():
            with open(POLL_CONFIG_FILE) as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    config = json.load(f)
                    if isinstance(config, dict):
                        return config
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    return {}


def _get_repo_path() -> Path:
    """Read target repo from poll_config.json, matching circuit_daemon logic."""
    default = Path(os.getenv('TARGET_REPO', str(PROJECT_ROOT)))
    repo_path = _read_poll_config().get('target_repo')
    return Path(repo_path) if repo_path else default


def _get_frame_interval() -> float:
    """Daemon frame interval in seconds (poll_config interval_ms, default 2.5s)."""
    try:
        ms = float(_read_poll_config().get('interval_ms', 2500))
        return max(ms / 1000.0, 0.1)
    except (TypeError, ValueError):
        return 2.5

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

_USE_COLOR = (
    sys.stdout.isatty()
    and os.getenv("TERM") != "dumb"
    and os.getenv("NO_COLOR") is None
)

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _USE_COLOR else text


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Liveness = state-file mtime fresh within ~2x the daemon frame interval
# (floored: a cycle that includes a slow mypy pass can stretch past 2x on
# tiny intervals, and a slow frame is not a dead daemon).
_STALE_FLOOR_SECONDS = 10.0


def _frame_cycle_s(state) -> Optional[float]:
    """I-90: the larger of the frame's own measured cycle (`cycle_s`) and the recent window max
    (`cycle_max_s`) circuit_daemon publishes; None when neither is there."""
    vals = [v for v in ((state or {}).get('cycle_s'), (state or {}).get('cycle_max_s'))
            if isinstance(v, (int, float))]
    return max(vals) if vals else None


def stale_threshold_s(interval_s: float, cycle_s: Optional[float] = None) -> float:
    """I-90 / Q1 (MCP-working packet 2026-09-28): the ONE frame-stale threshold.
    max(2 * interval, floor, 2 * (interval + the MEASURED cycle)) — the next frame is due one sleep
    plus one cycle after the last, so the floor scales with the circuit's own measured cycle
    (`cycle_s` in circuit_state.json) and has NO cap: a large viewed directory is a slow frame,
    not a dead daemon. No measurement (None / unreadable) = the old rule."""
    base = max(2.0 * interval_s, _STALE_FLOOR_SECONDS)
    try:
        c = float(cycle_s) if cycle_s is not None else None
    except (TypeError, ValueError):
        c = None
    if c is None or c < 0:
        return base
    return max(base, 2.0 * (interval_s + c))

# Exit codes
EXIT_RUNNING = 0
EXIT_CONFIG_ERROR = 1
EXIT_NO_SCRIPTS = 2
EXIT_DAEMON_NEVER_STARTED = 3
EXIT_DAEMON_STALE = 4
EXIT_DAEMON_CRASHED = 5


# ---------------------------------------------------------------------------
# Age / formatting helpers
# ---------------------------------------------------------------------------


def _age_from_iso(stamp: str) -> Optional[float]:
    """Seconds since an ISO timestamp. Handles naive (local) and aware stamps."""
    try:
        ts = datetime.fromisoformat(stamp)
    except (ValueError, TypeError):
        return None
    if ts.tzinfo is None:
        # Daemon writes naive local timestamps (datetime.now().isoformat())
        return (datetime.now() - ts).total_seconds()
    return (datetime.now(timezone.utc) - ts).total_seconds()


def _fmt_age(seconds: Optional[float]) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60}s"
    h, m = divmod(s, 3600)
    return f"{h}h{m // 60}m"


# ---------------------------------------------------------------------------
# Daemon health check (synchronous, non-critical)
# ---------------------------------------------------------------------------


def _fetch_daemon_health(port: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Ping daemon health endpoint. Returns None if daemon unreachable."""
    if port is None:
        port = _DEFAULT_HEALTH_PORT
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/health")
        _MAX_HEALTH_RESPONSE = 1 * 1024 * 1024  # 1MB
        with urllib.request.urlopen(req, timeout=2) as resp:
            raw = resp.read(_MAX_HEALTH_RESPONSE + 1)
            if len(raw) > _MAX_HEALTH_RESPONSE:
                return None
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return None
            # Validate expected schema keys from daemon health endpoint
            if "status" not in data and "uptime" not in data:
                return None
            return data
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Core gather (reads live circuit_state.json written by the daemon)
# ---------------------------------------------------------------------------


def gather_electricity() -> Dict[str, Any]:
    """Gather live circuit data from the daemon's state files.

    circuit_state.json is rewritten every daemon frame (fresh AST scan each
    cycle — live scans only). Field mapping from the old trace_state schema:
    poll_timestamp -> scan_timestamp, kernel_running -> daemon liveness via
    state-file mtime (fresh within ~2x frame interval) + running.json,
    discovered_count -> len(nodes).
    """
    repo = _get_repo_path()
    if not repo.exists():
        return {"error": f"Repo not found: {repo}"}

    state = read_json(CIRCUIT_STATE_FILE)

    # Daemon liveness: state-file mtime fresh within ~2x the frame interval
    interval = _get_frame_interval()
    stale_threshold = stale_threshold_s(interval, _frame_cycle_s(state))   # I-90
    daemon_age: Optional[float] = None
    if CIRCUIT_STATE_FILE.exists():
        try:
            daemon_age = time.time() - CIRCUIT_STATE_FILE.stat().st_mtime
        except OSError:
            pass
    is_stale = daemon_age is None or daemon_age > stale_threshold

    # Scan freshness (the frame timestamp inside the state itself)
    scan_timestamp = state.get("scan_timestamp", "") if state else ""
    scan_age = _age_from_iso(scan_timestamp) if scan_timestamp else None

    # Nodes / connections (discovered_count -> len(nodes))
    nodes: List[Dict[str, Any]] = state.get("nodes", []) if state else []
    connected = sum(1 for n in nodes if n.get("connected"))
    broken = [
        {"file": n.get("relative_path", n.get("name", "?")),
         "error": (n.get("import_error") or "").strip().splitlines()[-1]
         if n.get("import_error") else ""}
        for n in nodes if not n.get("connected")
    ]

    # Running monitored scripts (daemon process-table scan -> running.json)
    running: Dict[str, Dict[str, Any]] = {}
    seen_ages: Dict[int, Optional[float]] = {}
    for pid_str, info in (read_json(RUNNING_STATE_FILE) or {}).items():
        name = info.get("script", "")
        pid = info.get("pid", 0)
        if name and pid:
            running[name] = {
                "pid": pid,
                "source": info.get("source", "?"),
                "detected_at": info.get("detected_at", ""),
            }
            if info.get("detected_at"):
                seen_ages[pid] = _age_from_iso(info["detected_at"])

    # Kernel-traced dataflows (eslogger or lsof fallback), straight from state
    dataflows = state.get("dataflows", []) if state else []

    # Daemon health endpoint (observability, non-critical)
    daemon_health = _fetch_daemon_health()

    return {
        "repo": str(repo),
        "target_repo": state.get("target_repo", str(repo)) if state else str(repo),
        "daemon_phase": state.get("daemon_phase", "") if state else "",
        "node_count": len(nodes),
        "connected": connected,
        "broken": broken,
        "cycles": state.get("cycles", []) if state else [],
        "running": running,
        "seen_ages": seen_ages,
        "dataflows": dataflows,
        "daemon_state": state or None,
        "scan_timestamp": scan_timestamp,
        "scan_age_seconds": round(scan_age, 1) if scan_age is not None else None,
        "daemon_age_seconds": round(daemon_age, 1) if daemon_age is not None else None,
        "stale_threshold_seconds": round(stale_threshold, 1),
        "frame_interval_seconds": interval,
        "daemon_health": daemon_health,
        "is_stale": is_stale,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def print_electricity(data: Dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        output = {
            "repo": data["repo"],
            "target_repo": data["target_repo"],
            "daemon_phase": data["daemon_phase"],
            "node_count": data["node_count"],
            "connected": data["connected"],
            "broken": data["broken"],
            "cycles": data["cycles"],
            "running": {
                name: {
                    "pid": info["pid"],
                    "source": info.get("source", "?"),
                    "seen_seconds_ago": data["seen_ages"].get(info["pid"]),
                }
                for name, info in data["running"].items()
            },
            "dataflows": data["dataflows"],
            "scan_timestamp": data["scan_timestamp"],
            "scan_age_seconds": data["scan_age_seconds"],
            "daemon_age_seconds": data["daemon_age_seconds"],
            "stale_threshold_seconds": data["stale_threshold_seconds"],
            # Liveness = fresh state-file mtime; the :8051 health endpoint is
            # optional corroboration, not the liveness signal.
            "daemon_live": not data.get("is_stale", True),
            "health_endpoint_alive": data["daemon_health"] is not None,
            "is_stale": data.get("is_stale", True),
        }
        print(json.dumps(output, indent=2, default=str))
        return

    BAR = "═" * 51
    print()
    print(f"  {BAR}")
    print(f"    {_c(BOLD, 'SCRIPT ELECTRICITY')} — Live Circuit Status")
    print(f"  {BAR}")

    # Staleness warning (liveness = state-file mtime within ~2x frame interval)
    is_stale = data.get("is_stale", True)
    daemon_age = data.get("daemon_age_seconds")
    if is_stale:
        if daemon_age is not None:
            threshold = data.get("stale_threshold_seconds", "?")
            msg = (f"⚠ State is {_fmt_age(daemon_age)} old "
                   f"(daemon may be stopped; fresh = <{threshold}s)")
            print(f"  {_c(YELLOW, msg)}")
        else:
            print(f"  {_c(YELLOW, '⚠ No daemon data available — start the circuit daemon')}")
    print()

    # --- CIRCUIT (the live graph, terminal-sized) ---
    node_count = data["node_count"]
    connected = data["connected"]
    broken = data["broken"]
    phase = data["daemon_phase"] or "?"
    scan_age = data.get("scan_age_seconds")

    print(f"  {_c(BOLD, 'CIRCUIT')} ({node_count} node{'s' if node_count != 1 else ''}, "
          f"phase {phase})")
    print(f"    target: {data['target_repo']}")
    if node_count:
        color = GREEN if connected == node_count else RED
        print(f"    {_c(color, f'{connected}/{node_count} connected')}"
              f"  (frame scanned {_fmt_age(scan_age)} ago)")
        for b in broken:
            err = f"  {b['error']}" if b.get('error') else ""
            print(f"    {_c(RED, '✗')} {b['file']}{err}")
        for cycle in data.get("cycles", []):
            print(f"    {_c(YELLOW, '↺ cycle:')} {' → '.join(cycle)}")
    else:
        print(f"    {_c(YELLOW, 'No nodes in circuit state')}")
    print()

    # --- RUNNING ---
    running = data["running"]
    seen_ages = data["seen_ages"]

    if running:
        print(
            f"  {_c(BOLD, 'RUNNING')} ({len(running)} script{'s' if len(running) != 1 else ''})"
        )
        for name, info in sorted(running.items()):
            pid = info["pid"]
            seen = seen_ages.get(pid)
            seen_str = f"  seen {_fmt_age(seen)} ago" if seen is not None else ""
            print(
                f"    {_c(GREEN, '✓')} {name}  PID {pid}  [{info.get('source', '?')}]{seen_str}"
            )
    else:
        print(f"  {_c(BOLD, 'RUNNING')} (none)")
        if is_stale:
            print(f"    {_c(YELLOW, 'Daemon data stale or unavailable')}")
        else:
            print(f"    {_c(YELLOW, 'No monitored scripts detected running')}")
    print()

    # --- DATAFLOWS ---
    dataflows = data["dataflows"]
    if dataflows:
        print(f"  {_c(BOLD, 'DATAFLOWS')} ({len(dataflows)} active)")
        for df in dataflows:
            print(f"    {df.get('src', '?')} → {df.get('dst', '?')}")
            print(f"      channel: {df.get('channel', '?')}")
            print(f"      proof: {df.get('proof', '?')}")
    else:
        print(f"  {_c(BOLD, 'DATAFLOWS')} (none)")
        if len(running) < 2:
            print(f"    {_c(YELLOW, 'Need 2+ running scripts for dataflow detection')}")
        elif is_stale:
            print(f"    {_c(YELLOW, 'Daemon data stale or unavailable')}")
        else:
            print(
                f"    {_c(YELLOW, 'No shared files or sockets detected')}"
            )
    print()

    # --- DAEMON ---
    daemon_state = data["daemon_state"]
    daemon_health = data["daemon_health"]

    if daemon_state and daemon_age is not None:
        freshness = _c(GREEN, "fresh") if not is_stale else _c(RED, "STALE")
        print(f"  {_c(BOLD, 'DAEMON')} (state written {_fmt_age(daemon_age)} ago — {freshness})")
        print(f"    frame interval: {data['frame_interval_seconds']}s  "
              f"(stale beyond {data['stale_threshold_seconds']}s)")
        if daemon_health:
            uptime = daemon_health.get("uptime_seconds", daemon_health.get("uptime", 0))
            print(f"    health endpoint: {_c(GREEN, 'alive')}  uptime {_fmt_age(uptime)}")
        else:
            print(f"    health endpoint: {_c(YELLOW, 'unreachable')} (non-critical)")
    elif daemon_health:
        uptime = daemon_health.get("uptime_seconds", daemon_health.get("uptime", 0))
        print(f"  {_c(BOLD, 'DAEMON')} (alive, uptime {_fmt_age(uptime)})")
        print(f"    {_c(YELLOW, 'No circuit_state.json yet (daemon still initializing?)')}")
    else:
        print(f"  {_c(BOLD, 'DAEMON')} {_c(YELLOW, '(not detected)')}")
        print("    No circuit_state.json or health endpoint found")

    print()


# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------


_MAX_WATCH_ITERATIONS = 100_000  # Safety cap (~27 hours at 1s interval)


async def watch_loop(interval: int) -> None:
    """Repeat gather + print every *interval* seconds.

    Runs gather_electricity() in a thread to avoid blocking the event
    loop during the urllib HTTP call inside _fetch_daemon_health().

    Uses a guard flag to skip the current iteration if the previous
    gather is still in-flight (prevents thread pool accumulation when
    the daemon is slow to respond).

    Capped at _MAX_WATCH_ITERATIONS to prevent unbounded loops.
    """
    _gathering = False

    for _iteration in range(_MAX_WATCH_ITERATIONS):
        if _gathering:
            # Previous gather still running — skip this tick
            await asyncio.sleep(interval)
            continue

        _gathering = True
        try:
            data = await asyncio.to_thread(gather_electricity)
            sys.stdout.write("\033[2J\033[H")  # ANSI clear + cursor home
            if "error" in data:
                print(f"Error: {data['error']}", file=sys.stderr)
            else:
                print_electricity(data)
        finally:
            _gathering = False

        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="On-demand script electricity check (live circuit_state.json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON",
    )
    parser.add_argument(
        "--watch",
        type=int,
        metavar="N",
        default=0,
        help="Repeat every N seconds (0 = run once)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    args = parser.parse_args()

    global _USE_COLOR
    if args.no_color:
        _USE_COLOR = False

    if args.watch > 0:
        try:
            asyncio.run(watch_loop(args.watch))
        except KeyboardInterrupt:
            print("\nStopped.")
            sys.exit(0)
    else:
        data = gather_electricity()  # synchronous now
        if "error" in data:
            print(f"Error: {data['error']}", file=sys.stderr)
            sys.exit(EXIT_CONFIG_ERROR)

        print_electricity(data, as_json=args.json)

        is_stale = data.get("is_stale", True)
        daemon_health = data.get("daemon_health")
        daemon_state = data.get("daemon_state")

        # Categorize daemon state for precise exit codes
        if not daemon_state and not daemon_health:
            sys.exit(EXIT_DAEMON_NEVER_STARTED)
        if is_stale and not daemon_health:
            sys.exit(EXIT_DAEMON_CRASHED)
        if is_stale and daemon_health:
            sys.exit(EXIT_DAEMON_STALE)

        if not data["running"]:
            sys.exit(EXIT_NO_SCRIPTS)


if __name__ == "__main__":
    main()
