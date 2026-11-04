#!/usr/bin/env python3
"""
circuit_daemon.py - Monitor circuit wiring integrity

Uses ast_scanner.CircuitScanner for all AST-based dependency analysis.
Scanner runs on daemon start, then re-scans whenever a monitored file changes.
Logs status for dashboard polling.

"""

import ast
import asyncio
import re
import shutil
import subprocess
import threading
import time
import sys
import signal
import json
import os
import tempfile
import logging
import hashlib
import fcntl
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure system_scripts dir is on sys.path for sibling imports
_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

# Import the shared AST scanner
from ast_scanner import CircuitScanner
from path_hack_detector import scan_repo_for_path_hacks, PathHack
# Naming-drift data type tracker (PLAN_NAMING_DRIFT_TRACKER_2026-09-29, lane ND1 2026-10-01): permanent, the way
# the sys.path tracker is — no launch token chooses it. Its names ride on the circuit scanner's own parse (ast_scanner
# `ScriptNode.names`); this module only builds the baseline, watches changed files and publishes the §D block.
# A detector that cannot be imported is a tracker that measured nothing (NOT MEASURED, reason kept), never 0.
try:
    from naming_drift_detector import NamingDriftTracker, not_measured_block as _naming_not_measured_block
    _NAMING_DRIFT_IMPORT_ERROR: str | None = None
except Exception as _naming_import_exc:
    NamingDriftTracker = None  # type: ignore[assignment,misc]
    _naming_not_measured_block = None  # type: ignore[assignment]
    _NAMING_DRIFT_IMPORT_ERROR = f"naming_drift_detector unavailable: {_naming_import_exc!r}"
# P3 / A4 (2026-09-29): scan_scope.is_whitelisted is the ONE whitelist matcher (exact path, directory
# prefix, glob) — the same one the validator and discovery use, so the three agree on every whitelist row.
import scan_scope
# B5 (2026-10-01, Q-H2-2 / Q-H0-1): the ONE type-error / annotation-note split, shared with the
# dashboard's mypy tile and cr_data_types — formerly the `_is_note` closure inside run_mypy_scan.
import mypy_partition
# Item 10 (2026-09-15): pytest + unittest as permanent data type trackers beside path hacks
from test_runner_tracker import (scan_test_runner_presence, list_python_processes, collect_runner_executions,
                                 runner_coverage as _runner_coverage, runner_dataflows as _runner_dataflows,
                                 test_files_in as _runner_test_files, read_json as _read_json_plain,
                                 not_run_block as _test_runners_not_run, proc_cwd as _proc_cwd)

# Dataflow detection types (from system_scripts/engine_utils.py; renamed from utils.py in G1a to de-collide with the top-level utils package)
import importlib.util as _ilu
_ss_utils_spec: Any = _ilu.spec_from_file_location(
    "system_scripts_utils",
    Path(__file__).resolve().parent / "engine_utils.py",
)
_ss_utils = _ilu.module_from_spec(_ss_utils_spec)
sys.modules["system_scripts_utils"] = _ss_utils  # register before exec so @dataclass works
_ss_utils_spec.loader.exec_module(_ss_utils)
DataflowDict = _ss_utils.DataflowDict
PROOF_KERNEL = _ss_utils.PROOF_KERNEL

# Kernel tracer for dataflow detection (requires sudo/root). Item 7 (2026-09-10): the
# backend is CHOSEN at launch (--tracer eslogger|lsof) and read from the launch control
# block; tracer.select_kernel_backend (dead, referenced a nonexistent Config) is archived.
_ESLOGGER_AVAILABLE = False
try:
    from tracer import EsloggerMonitor
    _ESLOGGER_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).warning(
        "tracer import failed — kernel dataflow detection disabled "
        "(EsloggerMonitor unavailable): %s", e)
    EsloggerMonitor = None

# Observability — health/metrics HTTP endpoint
_OBSERVABILITY_AVAILABLE = False
try:
    from observability import Observability
    _OBSERVABILITY_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).warning(
        "observability import failed — health/metrics endpoint disabled: %s", e)
    Observability = None

# Import from mypy_n_contracts_watcher (lives inside system_scripts)
# Import individual modules directly to avoid __init__.py pulling in optional deps (rich, watchdog)
_harness_dir = Path(__file__).parent / "mypy_n_contracts_watcher"
_HARNESS_ERROR = ""   # R4: why the harness did not load (set in the except below)
try:
    import importlib.util
    def _load_harness_module(name):
        spec = importlib.util.spec_from_file_location(name, _harness_dir / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    _crc_mod = _load_harness_module("crc_engine")
    _mypy_mod = _load_harness_module("mypy_validator")
    _io_tracker_mod = _load_harness_module("io_tracker")
    # contracts scanning still disabled — panel kept for visual continuity
    # _contracts_mod = _load_harness_module("contracts")

    CRCEngine = _crc_mod.CRCEngine
    MypyEngine = _mypy_mod.MypyEngine
    # scan_io_functions loaded from harness but overridden below with custom AST visitor
    _harness_scan_io = _io_tracker_mod.scan_io_functions
    get_recent_violations = None
    ContractViolation = None
    scan_contract_decorators = None
    HARNESS_AVAILABLE = True
except Exception as e:
    HARNESS_AVAILABLE = False
    _HARNESS_ERROR = f"{type(e).__name__}: {e}"   # R4: published as CRC's NOT MEASURED reason
    CRCEngine = None
    MypyEngine = None
    get_recent_violations = None
    ContractViolation = None
    scan_contract_decorators = None
    _harness_scan_io = None
    print(f"HARNESS LOAD FAILED: {e}")
    import traceback
    traceback.print_exc()

_shutdown_requested = False
# B8 / Q-H1-4 (2026-10-01): the tool subprocess running right now (mypy / vulture), so a shutdown signal
# can stop it with the daemon — a flag-only handler left a running mypy alive after the daemon was gone.
_ACTIVE_TOOL: Optional[subprocess.Popen] = None


def _run_tool(cmd: List[str], *, timeout: float, cwd: Optional[str] = None,
              env: Optional[Dict[str, str]] = None, capture_output: bool = True,
              text: bool = True) -> subprocess.CompletedProcess:
    """subprocess.run for the tool scans, with the handle kept in _ACTIVE_TOOL while it runs so
    signal_handler can terminate it (same result and the same TimeoutExpired as subprocess.run)."""
    global _ACTIVE_TOOL
    pipe = subprocess.PIPE if capture_output else None
    proc = subprocess.Popen(cmd, stdout=pipe, stderr=pipe, text=text, cwd=cwd, env=env)
    _ACTIVE_TOOL = proc
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        _ACTIVE_TOOL = None
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _stop_active_tool() -> None:
    """Terminate the running tool subprocess, if any — called from signal_handler."""
    proc = _ACTIVE_TOOL
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        logging.info(f"tool subprocess pid {proc.pid} terminated with the daemon")
    except OSError as e:
        logging.warning(f"tool subprocess pid {proc.pid} not terminated: {e}")


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully via flag (no sys.exit from signal context)."""
    global _shutdown_requested
    logging.info(f"Received signal {signum}. Shutting down daemon...")
    _shutdown_requested = True
    _stop_active_tool()   # B8 / Q-H1-4: a running mypy / vulture stops with the daemon
    # Start a watchdog: if main loop doesn't exit within 8s, run cleanup then force-exit
    def _force_exit():
        time.sleep(8)
        if _shutdown_requested:
            logging.warning("Shutdown watchdog: main loop stuck — running cleanup and forcing exit")
            try:
                cleanup_running_state()
            except Exception:
                pass
            proc = _ACTIVE_TOOL   # B8 / Q-H1-4: a tool that ignored SIGTERM does not outlive the forced exit
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            os._exit(0)
    t = threading.Thread(target=_force_exit, daemon=True)
    t.start()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def _interruptible_sleep(seconds: float) -> None:
    """Sleep for `seconds` but check _shutdown_requested every 0.25s so signals are responsive."""
    end = time.time() + seconds
    while time.time() < end and not _shutdown_requested:
        time.sleep(min(0.25, end - time.time()))

def _rate_aware_sleep() -> float:
    """The poll loop's wait, re-reading the slider's rate about once a second (owner 2026-09-28: the rate
    now goes up to 10 min, so a wait fixed at its start would hold a move back to 2.5s for up to 10 min).
    Returns the seconds actually slept."""
    start = time.time()
    while not _shutdown_requested:
        left = float(get_ping_interval()) - (time.time() - start)
        if left <= 0:
            break
        time.sleep(min(1.0, left))
    return time.time() - start


SCRIPT_DIR = Path(__file__).parent
DAEMON_LOG_DIR = SCRIPT_DIR / "daemon_log"
DAEMON_LOG_DIR.mkdir(exist_ok=True)
DAEMON_LOG = DAEMON_LOG_DIR / "daemon_log.txt"

# Project root (parent of system_scripts)
PROJECT_ROOT = SCRIPT_DIR.parent

POLL_CONFIG_FILE = SCRIPT_DIR / "poll_config.json"
CIRCUIT_STATE_FILE = SCRIPT_DIR / "circuit_state.json"  # Shared state for dashboard
RUNNING_STATE_FILE = SCRIPT_DIR / "running.json"
RUNNING_LOCK_FILE = SCRIPT_DIR / "running.lock"
RUNTIME_COVERAGE_FILE = SCRIPT_DIR / "runtime_coverage.json"  # Track which modules have been imported at runtime
ENTRY_POINT_INFO_FILE = SCRIPT_DIR / "entry_point_info.json"  # Written by entry_point_wrapper.py at execution (plan item 8)
RUNNER_INFO_FILE = SCRIPT_DIR / "runner_info.json"  # Item 10: the test RUNNER's own record (the wrapper writes it for -m pytest / -m unittest) — never entry_point_info.json
# Item 10: the tracker's published block + the runner's hash-verified coverage (module state, refreshed every frame)
_TEST_RUNNERS: Dict[str, Any] = _test_runners_not_run()
_CYCLE_CLOCK: Dict[str, float] = {}
# owner 2026-09-29: the whole-repo trackers run once (the first pass), then only on a changed file
_FIRST_PASS_DONE: Dict[str, bool] = {}   # I-90: the poll loop's cycle start, read by write_circuit_state
# I-90: the last CYCLE_WINDOW measured cycles — a slow cycle (a cadence-period re-read) can follow a
# fast one, so the frame also carries the window's max (`cycle_max_s`); the dash keys on the larger.
CYCLE_WINDOW = 64
_CYCLE_HISTORY: List[float] = []
_RUNNER_COVERAGE: set = set()
# M-48 / C (owner 2026-10-06): this frame's target runs seen in the process table — started by hand, an IDE,
# `-m pkg.mod`, a path relative to the process's own cwd — NOT through the wrapper. Published as
# `outside_runs` so the dash names them; a sighting, never proof of what ran (running.json stays wrapper-only).
_OUTSIDE_RUNS: List[Dict[str, Any]] = []
_CWD_CACHE: Dict[Tuple[int, str], Optional[str]] = {}   # (pid, command) -> cwd, one lsof per process
# A (owner 2026-10-06): load_recorder.py's output (eslogger, started by launch.sh) and its summary for the dash
LOAD_PROOF_FILE = SCRIPT_DIR / "load_proof.json"
_LOAD_PROOF_STATE: Dict[str, Any] = {'status': 'not run', 'reason': 'not read yet', 'runs': [], 'verified': 0}

from datetime import datetime

# owner 2026-10-07 05:20: PMC and the sudo system monitor that rode on its switch are removed —
# neither ever ran live, and a whole-machine CPU counter could not say which script ran.

def get_target_repo_from_config() -> Optional[Path]:
    """Read TARGET_REPO from the shared config file (poll_config.json `target_repo`).

    T-12: None when the config names no target — the daemon then refuses (run_daemon). It never
    falls back: not to PROJECT_ROOT (CodeRadar scanning its own tree is a wrong target, not a
    default), and not to an inherited TARGET_REPO environment variable (a second source that can
    disagree with the launch's record). The gearbox writes the config before it starts the daemon."""
    try:
        if POLL_CONFIG_FILE.exists():
            with open(POLL_CONFIG_FILE) as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    config = json.load(f)
                    repo_path = config.get('target_repo')
                    if repo_path:
                        return Path(repo_path)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logging.warning(f"TARGET: poll_config.json unreadable ({type(e).__name__}: {e})")
    return None

def get_repo_id(repo_path: Path) -> str:
    """Generate a unique ID for a repo path (short hash for log identification)."""
    return hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:12]


# =============================================================================
# MONITOR-SIDE WHITELIST (the "virtual stripper")
# =============================================================================
# One persisted whitelist artifact per target lives OUTSIDE the dev's CB:
#   system_scripts/whitelist_<repoid>.json
#   repoid = sha256(str(Path(target).resolve()))[:12]  (== get_repo_id)
#   schema: {target, generated_at, entries: [{path, reason}], functions: [...]}
# Whitelisted files virtually do not exist on the scan surface: no node,
# no change tag, no mirror infraction. Read fresh on every call (live reads,
# no caching — same doctrine as live scans; the file is tiny).

def load_whitelist(target: Path) -> frozenset:
    """Load whitelisted repo-relative file/dir paths for *target*.

    Missing or corrupt artifact ⇒ the bytecode rows alone (scan surface unchanged).

    I-156 (2026-09-22, run 175): ONE TABLE. This loader used to re-read the artifact with its
    own copy of the reader, so it was the one reader of the whitelist that never saw I-153 (a)'s
    bytecode rows — `__pycache__/` and `*.pyc` — which `scan_scope.load_whitelist` unions in for
    everybody else. It now READS THROUGH scan_scope, so the daemon's whitelist and the engine's
    are the same set by construction rather than by agreement, and launch.sh writes the same two
    rows into the artifact on disk (the other half of I-156). The private reader below is the
    fallback for the case where scan_scope cannot be imported at all; it keeps the old answer.
    """
    wl_file = SCRIPT_DIR / f"whitelist_{get_repo_id(target)}.json"
    wl: frozenset = frozenset()
    try:
        import scan_scope
        wl = frozenset(scan_scope.load_whitelist(target))
    except Exception as e:
        logging.warning(f"WHITELIST: scan_scope table unavailable ({e}); reading {wl_file.name} directly")
        if wl_file.exists():
            try:
                data = json.loads(wl_file.read_text())
                wl = frozenset(
                    str(e['path']) for e in data.get('entries', [])
                    if isinstance(e, dict) and e.get('path')
                )
            except Exception as e:
                logging.warning(f"WHITELIST: failed to read {wl_file.name}: {e}")
                wl = frozenset()
    # F-CIRC-WALK (2026-09-05, evening): ONE scan surface — publish the whitelist
    # to scan_scope so every parameterless walker (path hacks, CRC, I/O,
    # contracts, harness) consumes the same list the graph walker does.
    try:
        import scan_scope
        scan_scope.set_scope(target, wl)
    except Exception as e:
        logging.warning(f"WHITELIST: scan_scope not published: {e}")
    return wl


# P3 / A4 (2026-09-29): the daemon's own `_is_whitelisted` (exact + dir prefix, no glob) is gone — every
# consult below goes through scan_scope.is_whitelisted, so a glob row (`*.pyc`, a launch.sh pattern row)
# means the same thing here as in the validator and discovery. `unreachable_by_import` is never a
# whitelist row (load_whitelist reads `entries` only): such a module is scanned like every other .py.

# Target repo to monitor - read from config or env var
# T-12: no target named → an empty Path here and a refusal in run_daemon (never PROJECT_ROOT)
TARGET_REPO: Path = get_target_repo_from_config() or Path()

DEFAULT_PING_INTERVAL = 2.5  # seconds
DEFAULT_SYNTAX_TIMEOUT = 10  # seconds
DEFAULT_IMPORT_TIMEOUT = 30  # seconds (increased for large deps)

# FIX_46 (owner Q6, 2026-09-15): every period and phase this daemon polls on comes from THE ONE
# CADENCE TABLE in gearbox.py. Before this, crc / io / mypy / vulture all carried "% 8 == 0" — four
# blades stacked on one angle, a quadruple burst every 20 s. They are now four teeth of one blade.
try:
    import gearbox as _cadence          # same directory (system_scripts/)
except Exception:                       # a tree without the coordinator still runs
    _cadence = None


def _due(duty_name: str, n_cycles: int, fallback_period: int, fallback_phase: int) -> bool:
    """This duty's tooth passes on cycle n, per the cadence table (one fallback site, never a literal
    scattered through the loop)."""
    if _cadence is not None:
        return bool(_cadence.due('circuit', duty_name, n_cycles))
    return (int(n_cycles) % fallback_period) == fallback_phase


# CRC / mypy / IO integration (contracts still disabled)
CRC_SCAN_INTERVAL = 8           # FIX_46: the table's row; kept as the fallback period
CRC_BASELINE_PATH = Path(__file__).parent / "mypy_n_contracts_watcher" / "baseline.json"

# mypy configs
MYPY_SCAN_INTERVAL = 8          # FIX_46: the table's row (phase 4)
MYPY_FULL_SCAN_TIMEOUT = 120    # Full repo scan timeout (seconds)
MYPY_CACHE_DIR = DAEMON_LOG_DIR / ".mypy_cache"
# Mypy error categories suppressed from actionable counts (shown in dashboard but not in mirror)
MYPY_SUPPRESS = {'[import-not-found]', '[import-untyped]',
                 'Duplicate module named "__main__"',
                 'No parent module -- cannot perform relative import'}

# IO configs
IO_SCAN_INTERVAL = 8            # Run IO scan every 8 cycles (~20s)

# Vulture dead code detection configs
ENABLE_VULTURE = False          # Item 7 (2026-09-10): True iff 'vulture' is in the launch control's trackers
# Item 7: the pluggable data type trackers a launch may choose (--trackers a,b,c); absent = none run.
_TRACKER_TOKENS = ('io', 'mypy', 'crc', 'vulture')
_TRACKERS: frozenset = frozenset()   # set in run_daemon from the launch control block
_NOT_RUN = "not run — nothing measured"
_NOT_MEASURED = "NOT MEASURED"   # R4: chosen at launch, but its tool is missing or failed
# ND1: the permanent trackers — always listed under `trackers.chosen`, never `not_run` (plan §D); each publishes
# NOT MEASURED with its reason until it has measured.
_PERMANENT_TRACKERS = ('naming_drift', 'pytest')   # owner 2026-10-07: pytest reads the last test run
_NAMING_DRIFT = None                  # NamingDriftTracker for the current target, built on the loop's first pass
_NAMING_DRIFT_WHY: str | None = 'launch scan has not completed'   # why it measured nothing, None once it has
# Item 7: the facts every circuit_state write republishes (set by run_daemon once the block is read)
_LAUNCH_CONTROL: dict | None = None
_TRACER_STATE: dict = {'backend': None, 'alive': False, 'chosen_at': None, 'reason': 'launch control not read yet'}
VULTURE_SCAN_INTERVAL = 8       # Run vulture every 8 cycles (~20s) — pure AST, very fast
VULTURE_SCAN_TIMEOUT = 60       # Timeout for vulture subprocess (seconds)
VULTURE_MIN_CONFIDENCE = 0     # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was 60 — vulture's confidence is published, not used as a floor


# =============================================================================
# SYNC-BY-DESIGN CLASSIFIER
# =============================================================================

def _is_sync_by_design(node: ast.FunctionDef, file_tree: ast.Module, filepath: str = '') -> tuple:
    """Classify whether a sync function is intentionally sync (not a conversion candidate).

    Heuristics (ordered by specificity):
        1. Dunder methods (__init__, __call__, etc.)
        2. @property / @x.setter decorated
        3. Logger module — all sync functions in a logging utility are by design
        4. Called via asyncio.to_thread() in the same file
        5. Contains asyncio.run() or sys.exit() — CLI entry/exit point
        6. Decorator factory — defines and returns an inner function
        7. Validation/check helper — _validate_*, _check_*, validate_* prefixed
        8. Trivial body (≤3 stmts: assigns, return, pass, docstring, logger calls)

    Print-only I/O and no-IO fallback are handled by the caller since they
    depend on io_types computed separately.

    Returns:
        (is_exempt: bool, reason: str) — reason is '' if not exempt.
    """
    name = node.name
    body = node.body

    # ── 1. Dunder methods ──
    if name.startswith('__') and name.endswith('__'):
        return True, 'dunder_method'

    # ── 2. @property decorated ──
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id == 'property':
            return True, 'property'
        if isinstance(dec, ast.Attribute) and dec.attr in ('setter', 'getter', 'deleter'):
            return True, 'property'

    # ── 3. Logger module — sync logging wrappers are by design ──
    if filepath:
        fname = Path(filepath).stem
        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `fname in ('logger', 'logging_config', 'log_utils', 'log_setup')` removed
            return True, 'logger_module'

    # ── 4. to_thread target — file-wide scan for asyncio.to_thread(NAME) ──
    for file_node in ast.walk(file_tree):
        if not isinstance(file_node, ast.Call):
            continue
        func = file_node.func
        if (isinstance(func, ast.Attribute) and func.attr == 'to_thread'
                and isinstance(func.value, ast.Name) and func.value.id == 'asyncio'):
            if file_node.args:
                arg = file_node.args[0]
                if isinstance(arg, ast.Name) and arg.id == name:
                    return True, 'to_thread_target'

    # ── 5. Contains asyncio.run() or sys.exit() — CLI entry/exit point ──
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Call):
            func = subnode.func
            if (isinstance(func, ast.Attribute) and func.attr == 'run'
                    and isinstance(func.value, ast.Name) and func.value.id == 'asyncio'):
                return True, 'event_loop_entry'
            if (isinstance(func, ast.Attribute) and func.attr == 'exit'
                    and isinstance(func.value, ast.Name) and func.value.id == 'sys'):
                return True, 'sys_exit'

    # ── 6. Decorator factory — defines and returns an inner function ──
    has_inner_def = any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) for s in body)
    has_return = any(isinstance(s, ast.Return) and s.value is not None for s in body)
    if has_inner_def and has_return:
        return True, 'decorator_factory'

    # ── 7. Validation/check helper — sync guards by convention ──
    if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `name.startswith('_validate') or name.startswith('validate_') or name.s` removed
            # (excised condition continued) or name.startswith('_check_') or name.startswith('check_')):
        return True, 'validation_helper'

    # ── 8. Trivial body (≤3 statements, all safe) ──
    if len(body) <= 3:
        trivial_types = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return, ast.Pass)
        all_trivial = True
        for stmt in body:
            if isinstance(stmt, trivial_types):
                continue
            # Docstring or Ellipsis: Expr(Constant)
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue
            # logger.debug/info/warning/error(...)
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                cf = stmt.value.func
                if (isinstance(cf, ast.Attribute)
                        and cf.attr in ('debug', 'info', 'warning', 'error')
                        and isinstance(cf.value, ast.Name)
                        and cf.value.id == 'logger'):
                    continue
            # if-guard + return: if cond: return ...
            if isinstance(stmt, ast.If) and len(stmt.body) == 1 and isinstance(stmt.body[0], ast.Return):
                continue
            # try/except wrapping a single call (e.g. callback notification)
            if isinstance(stmt, ast.Try):
                if (len(stmt.body) == 1 and isinstance(stmt.body[0], ast.Expr)
                        and isinstance(stmt.body[0].value, ast.Call)):
                    continue
            all_trivial = False
            break
        if all_trivial:
            return True, 'trivial_body'

    return False, ''


# =============================================================================
# CUSTOM I/O SCANNER (AST-based, recursive, strict definitions)
# =============================================================================

def scan_io_functions(repo_path: Path, files: Optional[List[Path]] = None) -> dict:
    """Scan repo for ALL functions and detect I/O operations via AST visitor.

    Classifies each function as async/sync. ALL functions are counted and
    listed in the results. Functions with detected I/O patterns are tagged
    with their io_types; others get an empty list.

    Detects: file ops, stdio (stdin/stdout/stderr), logging setup,
    subprocess, queue pipelines, network, database, aiofiles, etc.
    Recurses into all .py files, deduplicates by (file, line, name).
    """
    # Explicit reset — fresh results every scan, no carryover from prior runs
    results: Dict[str, Any] = {
        'totals': {'total_functions': 0, 'async_count': 0, 'sync_count': 0, 'io_functions': 0, 'sync_exempt_count': 0},
        'files': {},
        'details': [],
    }
    seen: Set[tuple] = set()  # Reset dedupe

    class IOVisitor(ast.NodeVisitor):
        def __init__(self, rel_path: str, file_tree: ast.Module):
            self.current_file = rel_path
            self.file_tree = file_tree

        def visit_FunctionDef(self, node):
            self._process_function(node, is_async=False)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node):
            self._process_function(node, is_async=True)
            self.generic_visit(node)

        def _process_function(self, node, is_async):
            key = (self.current_file, node.lineno, node.name)
            if key in seen:
                return
            seen.add(key)

            results['totals']['total_functions'] += 1
            io_types = self._detect_io_types(node)

            # Always count and list ALL functions (async and sync)
            detail = {
                'file': self.current_file,
                'line': node.lineno,
                'name': node.name,
                'async': is_async,
                'io_types': io_types,
            }

            # Build per-file structure for dashboard compatibility
            file_entry = results['files'].setdefault(self.current_file, {
                'async_functions': [], 'sync_functions': [],
            })
            fn_info = {'name': node.name, 'lineno': node.lineno, 'io_types': io_types}
            if is_async:
                file_entry['async_functions'].append(fn_info)
                results['totals']['async_count'] += 1
            else:
                # Classify whether this sync function is intentionally sync
                exempt, reason = _is_sync_by_design(node, self.file_tree, self.current_file)
                if not exempt and io_types and all(t == 'print' for t in io_types):
                    exempt, reason = True, 'print_only'
                if not exempt and not io_types:
                    exempt, reason = True, 'no_io_pure_cpu'
                fn_info['sync_exempt'] = exempt
                fn_info['exempt_reason'] = reason
                detail['sync_exempt'] = exempt
                detail['exempt_reason'] = reason
                if exempt:
                    results['totals']['sync_exempt_count'] += 1
                file_entry['sync_functions'].append(fn_info)
                results['totals']['sync_count'] += 1

            results['details'].append(detail)

            if io_types:
                results['totals']['io_functions'] += 1

        def _detect_io_types(self, node):
            """Detect true I/O patterns in a function body.

            Expanded detection covers:
            - File I/O: open, read/write, pathlib methods
            - Filesystem: exists, mkdir, unlink, stat, glob, etc.
            - stdio: sys.stdin/stdout/stderr .read/.write/.readline
            - Subprocess: run, Popen, check_output, communicate, etc.
            - Async I/O: asyncio.create_subprocess_*, aiofiles
            - Queue: get, put, get_nowait, put_nowait
            - Logging: basicConfig, addHandler, FileHandler, StreamHandler
            - Network: socket ops, requests/httpx/aiohttp/urllib
            - Database: sqlite3/psycopg2/sqlalchemy/pymongo connect/execute
            - System: os.environ, sys.exit, os.getenv, os.system, os.popen
            """
            io_types: Set[str] = set()
            for subnode in ast.walk(node):
                if not isinstance(subnode, ast.Call):
                    continue
                func = subnode.func
                # Direct name calls: open(), print(), input(), exit(), etc.
                if isinstance(func, ast.Name):
                    if func.id == 'open':
                        io_types.add('file_open')
                    elif func.id == 'print':
                        io_types.add('print')
                    elif func.id == 'input':
                        io_types.add('stdin_input')
                    elif func.id in ('exit', 'quit'):
                        io_types.add('sys_exit')
                # Attribute calls: path.open(), subprocess.run(), etc.
                elif isinstance(func, ast.Attribute):
                    attr = func.attr
                    val_dump = ast.dump(func.value) if func.value else ''
                    # File I/O
                    if attr in ('open', 'read', 'write', 'readline', 'readlines',
                                'writelines', 'flush', 'close') and (
                                'Path' in val_dump or 'open' in val_dump or 'self' in val_dump):
                        io_types.add(f'file_{attr}')
                    elif attr in ('read_text', 'write_text', 'read_bytes', 'write_bytes'):
                        io_types.add(f'file_{attr}')
                    # pathlib existence checks (filesystem I/O)
                    elif attr in ('exists', 'is_file', 'is_dir', 'stat', 'mkdir',
                                  'unlink', 'rename', 'rglob', 'glob', 'iterdir',
                                  'rmdir', 'symlink_to', 'touch', 'chmod'):
                        io_types.add(f'fs_{attr}')
                    # stdin/stdout/stderr via sys module
                    elif attr in ('read', 'write', 'readline', 'readlines', 'flush') and (
                            'stdin' in val_dump or 'stdout' in val_dump or 'stderr' in val_dump):
                        io_types.add(f'stdio_{attr}')
                    # sys.exit
                    elif attr == 'exit' and 'sys' in val_dump:
                        io_types.add('sys_exit')
                    # Subprocess
                    elif attr in ('run', 'call', 'check_output', 'check_call', 'Popen') and 'subprocess' in val_dump:
                        io_types.add(f'subprocess_{attr}')
                    elif attr == 'communicate':
                        io_types.add('subprocess_communicate')
                    # Async I/O
                    elif attr in ('create_subprocess_exec', 'create_subprocess_shell') and 'asyncio' in val_dump:
                        io_types.add(f'asyncio_{attr}')
                    elif 'aiofiles' in val_dump:
                        io_types.add(f'aiofiles_{attr}')
                    # Queue operations (pipeline I/O)
                    elif attr in ('get', 'put', 'get_nowait', 'put_nowait') and (
                            'queue' in val_dump.lower() or 'Queue' in val_dump):
                        io_types.add(f'queue_{attr}')
                    # Logging setup (expanded: basicConfig, addHandler, FileHandler, StreamHandler)
                    elif attr == 'basicConfig' and 'logging' in val_dump:
                        io_types.add('logging_setup')
                    elif attr == 'addHandler' and ('logging' in val_dump or 'logger' in val_dump.lower()):
                        io_types.add('logging_handler')
                    elif attr in ('FileHandler', 'StreamHandler', 'RotatingFileHandler',
                                  'TimedRotatingFileHandler') and 'logging' in val_dump:
                        io_types.add('logging_handler')
                    # Network: socket
                    elif attr in ('send', 'recv', 'connect', 'bind', 'listen', 'accept',
                                  'sendto', 'recvfrom', 'sendall') and 'socket' in val_dump:
                        io_types.add(f'socket_{attr}')
                    # Network: HTTP clients (requests, httpx, aiohttp, urllib)
                    elif attr in ('get', 'post', 'put', 'delete', 'patch', 'request', 'head', 'options') and (
                            'requests' in val_dump or 'httpx' in val_dump or 'aiohttp' in val_dump):
                        io_types.add(f'http_{attr}')
                    elif attr in ('urlopen', 'urlretrieve') and ('urllib' in val_dump):
                        io_types.add(f'http_{attr}')
                    # Database: sqlite3, psycopg2, sqlalchemy, pymongo
                    elif attr == 'connect' and any(db in val_dump for db in
                                                   ('sqlite3', 'psycopg2', 'psycopg', 'pymysql',
                                                    'pymongo', 'redis', 'cx_Oracle')):
                        io_types.add('db_connect')
                    elif attr in ('execute', 'executemany', 'fetchone', 'fetchall', 'fetchmany',
                                  'commit', 'rollback') and (
                            'cursor' in val_dump.lower() or 'conn' in val_dump.lower()
                            or 'db' in val_dump.lower() or 'session' in val_dump.lower()):
                        io_types.add(f'db_{attr}')
                    elif attr == 'create_engine' and 'sqlalchemy' in val_dump:
                        io_types.add('db_connect')
                    # os module I/O: os.system, os.popen, os.environ, os.getenv
                    elif attr in ('system', 'popen', 'exec', 'execvp', 'execv') and 'os' in val_dump:
                        io_types.add(f'os_{attr}')
                    elif attr in ('getenv', 'putenv', 'unsetenv') and 'os' in val_dump:
                        io_types.add('os_environ')
                    elif attr in ('listdir', 'scandir', 'walk', 'makedirs', 'remove',
                                  'removedirs', 'rmdir') and 'os' in val_dump:
                        io_types.add(f'os_fs_{attr}')
                    # shutil I/O
                    elif attr in ('copy', 'copy2', 'copytree', 'move', 'rmtree',
                                  'disk_usage') and 'shutil' in val_dump:
                        io_types.add(f'shutil_{attr}')
                    # json/yaml file ops (load/dump with file handles)
                    elif attr in ('load', 'dump') and ('json' in val_dump or 'yaml' in val_dump
                                                       or 'toml' in val_dump):
                        io_types.add(f'serialization_{attr}')
            return list(io_types)

    for py_file in (_live_py(repo_path) if files is None else files):   # FIX_15: the one contained walk
        rel_path = str(py_file.relative_to(repo_path))
        try:
            code = py_file.read_text(encoding='utf-8', errors='replace')
            tree = ast.parse(code)
            visitor = IOVisitor(rel_path, tree)
            visitor.visit(tree)
        except Exception as e:
            logging.warning(f"IO SCAN ERROR: {rel_path} - {e}")

    return results


_IO_FILE_CACHE: Dict[tuple, dict] = {}


def scan_io_incremental(repo_path: Path) -> dict:
    """owner 2026-09-29: after the first full pass only CHANGED files are re-read — the rest of the repo
    has already been measured. Each file's result is kept under (path, mtime_ns, size); a file whose key
    is unchanged is reused, a new or edited file is parsed alone, a deleted file drops out. The merged
    result has the same shape as scan_io_functions' whole-repo scan."""
    merged: Dict[str, Any] = {
        'totals': {'total_functions': 0, 'async_count': 0, 'sync_count': 0, 'io_functions': 0, 'sync_exempt_count': 0},
        'files': {},
        'details': [],
    }
    kept: Dict[tuple, dict] = {}
    parsed = 0
    for py_file in _live_py(repo_path):
        try:
            st = py_file.stat()
        except OSError as e:   # deleted between the walk and the stat — it drops out, and the log says so
            logging.info(f"IO TRACKER: {py_file} gone mid-scan ({e}); left out of this pass")
            continue
        key = (str(py_file), st.st_mtime_ns, st.st_size)
        part = _IO_FILE_CACHE.get(key)
        if part is None:
            part = scan_io_functions(repo_path, [py_file])
            parsed += 1
        kept[key] = part
        for k, v in part['totals'].items():
            merged['totals'][k] += v
        merged['files'].update(part['files'])
        merged['details'].extend(part['details'])
    _IO_FILE_CACHE.clear()
    _IO_FILE_CACHE.update(kept)
    merged['files_parsed'] = parsed
    return merged


# =============================================================================
# MYPY TYPE CHECK SCANNER
# =============================================================================

def _project_mypy_config(repo: Path):
    """The project's own mypy config file, or None (F-MYPY-CFG)."""
    try:
        for name in ("mypy.ini", ".mypy.ini"):
            p = repo / name
            if p.is_file():
                return p
        pp = repo / "pyproject.toml"
        if pp.is_file() and "[tool.mypy]" in pp.read_text(encoding="utf-8", errors="replace"):
            return pp
        sc = repo / "setup.cfg"
        if sc.is_file() and re.search(r"^\[mypy", sc.read_text(encoding="utf-8", errors="replace"), re.M):
            return sc
    except Exception:
        pass
    return None


def _is_syntax_fixture(rel: str) -> bool:
    """FIX_53: consult the ONE scan-surface module (rule 15) for "does this repo-relative path name a
    file the target ships in order to be unparsable". A consult that cannot run means NO fixtures —
    every break is genuine, today's behaviour — and says so."""
    try:
        import scan_scope
        return bool(scan_scope.syntax_fixture(str(rel).replace('\\', '/')))
    except Exception as _e:
        logging.warning("circuit: scan_scope unavailable for the syntax-fixture consult (%r) — "
                        "every break is genuine", _e)
        return False


def _scope_excluded(path) -> bool:
    """F-CIRC-WALK: whitelist consult through scan_scope (no scope => nothing excluded)."""
    try:
        import scan_scope
        return bool(scan_scope.excluded(path))
    except Exception:
        return False


def _live_py(root: Path) -> list:
    """FIX_15 (2026-09-10): the ONE contained walk — whitelist, engine hard-skips, never through a
    symlink, nothing outside the root. Found live on run 100 launch A: the I/O scan, the mypy and
    vulture counts and the CRC disk list were bare rglobs with name tests (the FIX_15 inventory had
    them as "guarded"), and mypy / vulture were handed the DIRECTORY — mypy followed the symlinked
    dir (`colorama/linked_dir/` in errors-by-dir) and the CRC list read the symlinked file
    (`+ colorama/outside.py`). Every one consumes this list now; the subprocesses get the files."""
    import scan_scope
    return list(scan_scope.iter_live_py(Path(root)))


def run_mypy_scan():
    """Run mypy full scan on TARGET_REPO.

    Uses strict flags. Parses summary line for accurate file counts.
    Returns dict with files_checked, passed, failed, errors, recent_checks.
    """
    # Find a working python with mypy — ENGINE interpreter only (slot 16, H22, reworded for
    # B2 / R2 2026-09-28): never probe or execute a binary the TARGET supplies (its own .venv,
    # a PATH lookup) — that is untrusted input and non-deterministic. The one other interpreter
    # CR runs is the one CR BUILT itself in its own tree (target_env.py, from the launch
    # snapshot); mypy stays the engine's and reads that env only via --python-executable.
    candidates = [sys.executable]
    mypy_python = None
    for py in candidates:
        try:
            r = subprocess.run([py, "-m", "mypy", "--version"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                mypy_python = py
                break
        except Exception:
            continue

    if not mypy_python:
        logging.debug("measured nothing (%s): %s", 'run_mypy_scan', 'not mypy_python')  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → reported
        logging.warning("MYPY: No working python+mypy found")
        # C5: no scan happened — never publish a clean zero for it
        return {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0, 'total_errors': 0,
                'errors': [], 'errors_by_dir': {}, 'recent_checks': [], 'last_scan': None,
                'mypy_rc': None, 'mypy_ran': False,
                # R4: the reason the tracker reads NOT MEASURED (_tracker_status publishes it)
                'not_measured_reason': _tool_missing_reason('mypy', candidates)}

    scan_target = '.'
    timeout = MYPY_FULL_SCAN_TIMEOUT

    # Clear cache for fresh start each time (no stale errors)
    import shutil
    if MYPY_CACHE_DIR.exists():
        try:
            shutil.rmtree(MYPY_CACHE_DIR)
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.warning("reported, not swallowed (cut 3): %s: %r", 'run_mypy_scan', _e)
            pass
    MYPY_CACHE_DIR.mkdir(exist_ok=True)

    # F-MYPY-CFG (2026-09-05, evening): measure the PROJECT's own type
    # contract when it states one (pyproject [tool.mypy] / mypy.ini / .mypy.ini /
    # setup.cfg [mypy]); only a project with no config gets the engine default
    # (--strict). The policy in force is published as mypy_config.
    mypy_cfg = _project_mypy_config(TARGET_REPO)
    if mypy_cfg:
        policy = ["--config-file", str(mypy_cfg)]
        mypy_policy = f"project:{mypy_cfg.relative_to(TARGET_REPO).as_posix()}"
    else:
        policy = ["--strict", "--config-file", "/dev/null"]
        mypy_policy = "engine-default:--strict (project states no mypy config)"
    # I-128 / Q2 (session 8, 2026-09-21, owner default: force the version, keep the rest):
    # the RUNNING interpreter's version is forced on EVERY invocation. The target's own
    # `[tool.mypy]` keeps its excludes and the extensions it names — the target's own knowledge —
    # but it never sets the version mypy checks against, because the stubs mypy resolves are
    # the ENGINE's (the engine venv's `numpy/__init__.pyi` is written with a `type` statement
    # and needs 3.12 or greater). A target pinning an older `python_version` — click pins
    # "3.10" — makes mypy abort with rc 2, 0 files checked, and `finished`'s second input then
    # reads NOT MEASURED for the whole run, silently. The version was the literal "3.13" here,
    # which is not the engine's interpreter and drifts the moment the engine's interpreter moves.
    forced_python_version = f"{sys.version_info[0]}.{sys.version_info[1]}"
    cmd = [mypy_python, "-m", "mypy",
           *policy,
           "--python-version", forced_python_version,
           "--exclude", "site-packages",
           "--no-incremental",
           "--explicit-package-bases",
           "--cache-dir", str(MYPY_CACHE_DIR),
           "--show-error-codes"]
    # Whitelist insertion point ③: whitelisted files are removed from the mypy
    # target set entirely (virtual stripper — they don't exist to the scan).
    for _wl in sorted(load_whitelist(TARGET_REPO)):
        cmd += ["--exclude", "^" + re.escape(_wl.rstrip('/')) + ("/" if _wl.endswith('/') else "$")]
    # FIX_15 (2026-09-10): mypy is handed the live FILES (repo-relative, cwd = the target), never
    # the directory — handed the directory it walked through a symlinked dir on run 100 launch A.
    _mypy_files = [str(p.relative_to(TARGET_REPO)) for p in _live_py(TARGET_REPO)]
    cmd += _mypy_files if _mypy_files else [scan_target]

    # I-128, SECOND cause — measured on run 161, not in the pinned row: the LAUNCH's `PYTHONPATH`
    # reaches mypy and decides its package bases. A src-layout target needs
    # `PYTHONPATH=<target>/src` for the RUNNER (I-134, run 155 fact 10), and with it set mypy finds
    # `src/click/shell_completion.py` twice — once as `click.shell_completion` down that path and
    # once as `src.click.shell_completion` down the cwd base `--explicit-package-bases` gives it.
    # "Source file found twice under different module names" is a BLOCKING error: rc 2, 0 files
    # checked, the gate NOT MEASURED for the whole run — the same silence I-128 pinned, from the
    # other end. Measured on this target: with the variable, rc 2 / 0 files; without it, rc 1 /
    # 65 files / 1329 errors. mypy's package bases are the target's config's business and the
    # flag's, never the runner's environment, so the variable is dropped from THIS subprocess
    # and from nowhere else — `cr_run_module` still passes it to the runner untouched.
    mypy_env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
    # B2 / R2 + B3 (2026-09-28): third-party imports resolve against the target's PRIVATE env
    # (CR-built, target_env.py) via --python-executable — mypy itself stays the engine's — and a
    # src layout puts <target>/src on MYPYPATH, a mypy package base (not the runner's PYTHONPATH,
    # so the I-128 "found twice" above cannot recur). Q5: no usable env → the engine
    # interpreter's site-packages, and the result SAYS so in `target_env` / `import_resolution`.
    import target_env as _target_env
    _tenv = _target_env.read(TARGET_REPO)
    if _tenv.get("python"):
        cmd[3:3] = ["--python-executable", _tenv["python"]]
        _import_resolution = f"target env ({_tenv['python']})"
    else:
        _import_resolution = f"engine interpreter — target env {_target_env.describe(_tenv)} (degraded, Q5)"
    if _tenv.get("layout") == "src" and _tenv.get("src_path"):
        mypy_env["MYPYPATH"] = os.pathsep.join(
            [_tenv["src_path"]] + ([mypy_env["MYPYPATH"]] if mypy_env.get("MYPYPATH") else []))
    try:
        result = _run_tool(cmd, capture_output=True, text=True,   # B8: stops with the daemon's SIGTERM
                           timeout=timeout, cwd=str(TARGET_REPO), env=mypy_env)
        output = result.stdout + result.stderr
        # C5: the returncode is the scan-integrity signal — 0/1 mean mypy ran
        # to completion (verdict real, clean or dirty); anything else means a
        # process ran but performed no valid check.
        mypy_rc = result.returncode
        logging.info(f"MYPY RAW CMD: {' '.join(cmd)}")
        logging.info(f"MYPY RAW OUT: rc={mypy_rc} {output[:500]}...")

        # Parse summary line: "Found N errors in M files (checked K source files)"
        # or "Success: no issues found in K source files"
        summary_match = re.search(
            r'(?:Found (\d+) errors? in (\d+) files? \(checked (\d+) source files?\))|'
            r'(?:Success: no issues found in (\d+) source files?)',
            output)
        if summary_match:
            if summary_match.group(4):  # Success case
                files_checked = int(summary_match.group(4))
                total_errors = 0
                failed_files = 0
            else:
                total_errors = int(summary_match.group(1))
                failed_files = int(summary_match.group(2))
                files_checked = int(summary_match.group(3))
        else:
            if mypy_rc not in (0, 1):
                # C5 rule: trust the counts iff rc in {0, 1}. rc 2 = usage/
                # config error — a process ran but performed no valid check.
                # Do not synthesise a count; return the not-scanned state.
                logging.warning(f"MYPY SCAN: rc={mypy_rc} with no summary line — "
                                f"scan did not run; withholding counts")
                return {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0,
                        'total_errors': 0, 'errors': [], 'errors_by_dir': {},
                        'recent_checks': [], 'last_scan': None,
                        'mypy_rc': mypy_rc, 'mypy_ran': False,
                        'not_measured_reason': f"mypy exited rc={mypy_rc} with no summary line "
                                               f"(no valid check) in {mypy_python}"}
            # Fallback: count from output (rc in {0, 1}: mypy ran to
            # completion, only the summary formatting drifted)
            all_py = _live_py(TARGET_REPO)   # FIX_15: the one contained walk
            files_checked = len(all_py)
            total_errors = output.count(': error:')
            failed_files = len({line.split(':')[0] for line in output.splitlines()
                               if ': error:' in line})

        passed_files = max(0, files_checked - failed_files)

        # Independent dir count — enumerate .py files to count unique parent dirs
        all_py_for_dirs = _live_py(TARGET_REPO)   # FIX_15: the one contained walk
        dirs_checked = len({f.parent for f in all_py_for_dirs})

        # Parse errors from current output ONLY (no carryover from previous scans)
        now_iso = datetime.now().isoformat()
        error_lines = [line.strip() for line in output.splitlines() if ': error:' in line]

        # Plan item 11 (2026-09-05): annotation noise is not "failed". Under
        # --strict, mypy reports missing annotations / untyped calls / Any
        # returns as errors; those are NOTES here. A file "failed" only when it
        # carries a real type error. Both counts are published; nothing is hidden.
        # B5 (2026-10-01): the rule is `mypy_partition.is_note` — the SAME one the dashboard's
        # drill-down and cr_data_types apply to the published lines, so every count below and
        # every count they show comes from one split of one list.
        type_error_lines, _note_lines = mypy_partition.partition(error_lines)
        annotation_notes = len(_note_lines)
        failed_files = len({l.split(': error:', 1)[0].rsplit(':', 1)[0] for l in type_error_lines})
        passed_files = max(0, files_checked - failed_files)

        # Group by file for structured output
        file_errors: Dict[str, list] = {}
        for line in error_lines:
            parts = line.split(': error:', 1)
            file_loc = parts[0]
            file_part = file_loc.rsplit(':', 1)[0]
            line_num = file_loc.rsplit(':', 1)[1] if ':' in file_loc else '?'
            err_msg = parts[1].strip()
            try:
                rel = str(Path(file_part).relative_to(TARGET_REPO))
            except ValueError:
                rel = file_part
            file_errors.setdefault(rel, []).append(f"{rel}:{line_num}: {err_msg}")

        # Build errors list from current output only (empty if resolved)
        errors = [{'file': k, 'message': "; ".join(v),
                   'error_count': len(v),
                   'timestamp': now_iso} for k, v in file_errors.items()]

        # Group errors by directory for dashboard drill-down.
        # B5 (Q-H2-2): each directory publishes the SAME split as the badge — `type_errors` /
        # `annotation_notes` by `mypy_partition` over its own lines, and `files_with_type_errors`
        # — so the drill-down's per-directory numbers sum to `type_errors` above. `error_count`
        # and `file_count` keep their old meaning (every line / every file with a line).
        dir_errors: Dict[str, Dict[str, Any]] = {}
        for rel_path, errs in file_errors.items():
            parent = str(Path(rel_path).parent) if '/' in rel_path else '.'
            de = dir_errors.setdefault(parent, {'files': {}, 'error_count': 0, 'file_count': 0,
                                                'type_errors': 0, 'annotation_notes': 0,
                                                'files_with_type_errors': 0})
            _f_errs, _f_notes = mypy_partition.partition(errs)
            de['files'][rel_path] = errs
            de['error_count'] += len(errs)
            de['file_count'] += 1
            de['type_errors'] += len(_f_errs)
            de['annotation_notes'] += len(_f_notes)
            de['files_with_type_errors'] += 1 if _f_errs else 0
        errors_by_dir = {d: {'files': v['files'], 'error_count': v['error_count'],
                             'file_count': v['file_count'],
                             'type_errors': v['type_errors'],
                             'annotation_notes': v['annotation_notes'],
                             'files_with_type_errors': v['files_with_type_errors']}
                         for d, v in sorted(dir_errors.items())}

        # Build recent_checks from current output only (empty if no errors)
        checks = []
        for rel_path, errs in sorted(file_errors.items()):
            checks.append({
                'file': rel_path,
                'passed': False,
                'errors_list': errs,
                'error_count': len(errs),
                'timestamp': now_iso,
            })
        if passed_files > 0:
            checks.insert(0, {
                'file': f'{passed_files} files',
                'passed': True,
                'message': 'type check passed',
                'timestamp': now_iso,
            })
        recent_checks = checks

        scan_result = {
            'files_checked': files_checked,
            'dirs_checked': dirs_checked,
            'passed': passed_files,
            'failed': failed_files,
            'total_errors': len(type_error_lines),  # real type errors only (plan item 11)
            'type_errors': len(type_error_lines),
            'annotation_notes': annotation_notes,
            'errors': errors,
            'errors_by_dir': errors_by_dir,
            'recent_checks': recent_checks,
            'last_scan': now_iso,
            'mypy_rc': mypy_rc,
            # C5: counts above are trustworthy iff mypy_ran — rc in {0, 1}
            'mypy_ran': mypy_rc in (0, 1),
            'mypy_config': mypy_policy,   # F-MYPY-CFG: the policy in force
            'target_env': _target_env.describe(_tenv),   # B2 / Q5: built|reused|failed: <reason>
            'import_resolution': _import_resolution,
            'layout': _tenv.get('layout'),               # B3: src|flat
            'import_errors': len(re.findall(r"\[import-(?:not-found|untyped)\]", output)),  # B2: what the env resolves
            # Q2: the version that was FORCED, beside the policy it was forced over.
            'mypy_python_version': forced_python_version,
        }
        logging.info(f"MYPY FULL SCAN: "
                     f"{files_checked} files in {dirs_checked} dirs, "
                     f"{passed_files} passed, {failed_files} failed, "
                     f"{len(error_lines)} total errors (rc={mypy_rc})")
        return scan_result

    except subprocess.TimeoutExpired:
        logging.warning(f"MYPY SCAN: Timeout ({timeout}s)")
        _now = datetime.now().isoformat()
        # C5: timeout blocks ALL CLEAR twice over — mypy_ran is False (no
        # returncode exists), and the synthetic infraction ships via
        # recent_checks so it reaches the mirror's actionable list (the
        # pre-C5 errors-only entry never did: the mirror reads recent_checks).
        return {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0, 'total_errors': 1,
                'errors': [{'file': 'timeout', 'message': f'mypy timeout ({timeout}s)',
                            'timestamp': _now}],
                'errors_by_dir': {},
                'recent_checks': [{'file': 'timeout', 'passed': False,
                                   'errors_list': [f'timeout: mypy timeout ({timeout}s)'],
                                   'error_count': 1, 'timestamp': _now}],
                'last_scan': _now,
                'mypy_rc': None, 'mypy_ran': False,
                'not_measured_reason': f"mypy timed out after {timeout}s in {mypy_python}"}
    except Exception as e:
        logging.error(f"MYPY SCAN ERROR: {e}")
        # C5: no scan happened — never publish a clean zero for it
        return {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0, 'total_errors': 0,
                'errors': [], 'errors_by_dir': {}, 'recent_checks': [], 'last_scan': None,
                'mypy_rc': None, 'mypy_ran': False,
                'not_measured_reason': f"mypy scan crashed: {type(e).__name__}: {e}"}


def _vulture_zero_dict():
    """Return the clean pre-scan vulture results dict. R4: nothing has been measured yet, so
    the counts are null, never 0 — a scan's result replaces them (run_vulture_scan)."""
    return {
        'files_scanned': None,
        'files_with_dead_code': None,
        'total_items': None,
        'items_by_category': {},
        'items': [],
        'last_scan': None,
    }


def _tool_missing_reason(tool: str, pythons) -> str:
    """R4: the NOT MEASURED reason for a tracker tool that no engine interpreter can run —
    names the interpreter(s) probed, so the owner knows which environment lacks it."""
    return f"{tool} not installed in {', '.join(str(p) for p in pythons) or 'no interpreter'}"


def _vulture_not_measured(reason: str) -> dict:
    """R4: the vulture shape for a scan that measured nothing — every count null (never 0)
    and the reason carried as `not_measured_reason` (published as the tracker's status)."""
    return {
        'files_scanned': None,
        'files_with_dead_code': None,
        'total_items': None,
        'items_by_category': {},
        'items': [],
        'last_scan': datetime.now().isoformat(),
        'not_measured_reason': reason,
    }


def run_vulture_scan():
    """Run vulture dead code scan on TARGET_REPO.

    Uses --min-confidence from VULTURE_MIN_CONFIDENCE.
    Parses text output: 'path/file.py:42: unused function 'foo' (60% confidence)'
    Returns dict with files_scanned, total_items, items_by_category, items, last_scan.
    """
    # Find a working python with vulture — ENGINE interpreter only (slot 16, H22, reworded for
    # B2 / R2): never probe or execute a binary the TARGET supplies (its own .venv, a PATH
    # lookup); the only other interpreter CR runs is the env CR built itself (target_env.py).
    candidates = [sys.executable]
    vulture_python = None
    for py in candidates:
        try:
            r = subprocess.run([py, "-m", "vulture", "--version"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                vulture_python = py
                break
        except Exception:
            continue

    if not vulture_python:
        logging.debug("measured nothing (%s): %s", 'run_vulture_scan', 'not vulture_python')  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → reported
        logging.warning("VULTURE: No working python+vulture found")
        # R4: a missing tool is NOT MEASURED, never "0 dead code" — counts null, reason published
        return _vulture_not_measured(_tool_missing_reason('vulture', candidates))

    # FIX_15 (2026-09-10): vulture is handed the live FILES (repo-relative), never the directory
    _vulture_files = [str(p.relative_to(TARGET_REPO)) for p in _live_py(TARGET_REPO)] or [str(TARGET_REPO)]
    cmd = [vulture_python, "-m", "vulture",
           *_vulture_files,
           "--min-confidence", str(VULTURE_MIN_CONFIDENCE),
           "--exclude",
           ",".join([
               "*/__pycache__/*", "*/.venv/*", "*/venv/*",
               "*/.git/*", "*/site-packages/*", "*/.mypy_cache/*",
               "*/.ruff_cache/*", "*/.pytest_cache/*",
               "*/node_modules/*", "*/.atomic_backups/*",
               "*/build/*", "*/dist/*",
           ])]

    try:
        result = _run_tool(cmd, capture_output=True, text=True,   # B8: stops with the daemon's SIGTERM
                           timeout=VULTURE_SCAN_TIMEOUT, cwd=str(TARGET_REPO))
        output = result.stdout
        logging.info(f"VULTURE RAW CMD: {' '.join(cmd)}")
        logging.info(f"VULTURE RAW OUT: {output[:500]}...")

        # Parse output lines
        # Format 1: "path/file.py:42: unused function 'foo' (60% confidence)"
        # Format 2: "path/file.py:42: unreachable code after 'return' (100% confidence)"
        pattern = re.compile(
            r"^(.+?):(\d+): (unused \w+) '([^']+)' \((\d+)% confidence\)$"
        )
        pattern_unreachable = re.compile(
            r"^(.+?):(\d+): (unreachable code) after '([^']*)' \((\d+)% confidence\)$"
        )

        items = []
        files_seen = set()
        category_counts = {}
        now_iso = datetime.now().isoformat()
        # Whitelist insertion point ④: whitelisted files are outside the
        # vulture target set (virtual stripper — dropped before results form).
        whitelist = load_whitelist(TARGET_REPO)

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = pattern.match(line) or pattern_unreachable.match(line)
            if not m:
                continue

            file_path_raw, line_num, category, name, confidence = m.groups()
            try:
                rel_path = str(Path(file_path_raw).relative_to(TARGET_REPO))
            except ValueError:
                rel_path = file_path_raw
            if scan_scope.is_whitelisted(rel_path, whitelist):
                continue

            files_seen.add(rel_path)
            cat_key = category.replace(' ', '_')
            category_counts[cat_key] = category_counts.get(cat_key, 0) + 1

            items.append({
                'file': rel_path,
                'line': int(line_num),
                'category': cat_key,
                'name': name,
                'confidence': int(confidence),
                'raw': line,
            })

        # R4: vulture's exit codes are 0 (none found), 3 (dead code found) and 1 (some input
        # did not parse — the other files are still reported). rc 2 (bad arguments), or any
        # other rc with nothing parsed, is a run that measured nothing: say so, never "0".
        if result.returncode == 2 or (result.returncode not in (0, 1, 3) and not items):
            _err = (result.stderr or '').strip().splitlines()
            return _vulture_not_measured(
                f"vulture exited rc={result.returncode} in {vulture_python}"
                + (f": {_err[-1][:200]}" if _err else ''))

        # Count total .py files for context
        all_py = _live_py(TARGET_REPO)   # FIX_15: the one contained walk
        files_scanned = len(all_py)

        scan_result = {
            'files_scanned': files_scanned,
            'files_with_dead_code': len(files_seen),
            'total_items': len(items),
            'items_by_category': category_counts,
            'items': items,
            'last_scan': now_iso,
        }
        logging.info(f"VULTURE SCAN: {files_scanned} files, "
                     f"{len(items)} dead code items in {len(files_seen)} files "
                     f"(categories: {category_counts})")
        return scan_result

    except subprocess.TimeoutExpired:
        logging.warning(f"VULTURE SCAN: Timeout ({VULTURE_SCAN_TIMEOUT}s)")
        return _vulture_not_measured(f"vulture timed out after {VULTURE_SCAN_TIMEOUT}s in {vulture_python}")
    except Exception as e:
        logging.error(f"VULTURE SCAN ERROR: {e}")
        return _vulture_not_measured(f"vulture scan crashed: {type(e).__name__}: {e}")


SYNTAX_BROKEN_FILES: list = []   # F-CRC1: files present on disk that do not parse (published, never "removed")
# FIX_53 (owner Q5 / I-47, 2026-09-17): files that do not parse BY DESIGN — a lexer / parser test
# corpus the target ships, matched BY PATTERN through scan_scope.syntax_fixture. Split out of
# SYNTAX_BROKEN_FILES so that list carries only genuine breakage; both stay in the disk list (F-CRC1).
SYNTAX_FIXTURE_FILES: list = []


def count_disk_py_files(repo_path: Path, crc_engine=None) -> list:
    """Ground truth: .py files on disk that have functions (matches baseline criteria).

    F-CRC1 (2026-09-05): a file that fails to PARSE is still on disk — it is
    recorded in SYNTAX_BROKEN_FILES and kept in the disk list so the CRC panel
    never reports it as "gone from disk". Whitelisted files are outside the
    scan surface (scan_scope).

    FIX_53 (2026-09-17): the parse reads BYTES, not `errors='replace'` text — bytes are what the
    interpreter reads, a `# -*- coding:` line is honoured, and a file that is not valid UTF-8 is
    reported as the error it is instead of being silently patched with U+FFFD. A file that does not
    parse AND matches a shipped syntax-fixture pattern goes to SYNTAX_FIXTURE_FILES instead.
    """
    files = []
    SYNTAX_BROKEN_FILES.clear()
    SYNTAX_FIXTURE_FILES.clear()
    for py_file in _live_py(repo_path):   # FIX_15: the one contained walk (the CRC list read a symlinked file on launch A)
        rel = str(py_file.relative_to(repo_path))
        if crc_engine:
            try:
                ast.parse(py_file.read_bytes(), filename=str(py_file))
            except SyntaxError as e:
                _row = {'file': rel, 'error': f"line {e.lineno}: {e.msg}"}
                (SYNTAX_FIXTURE_FILES if _is_syntax_fixture(rel) else SYNTAX_BROKEN_FILES).append(_row)
                files.append(rel)   # present on disk, unparsable — not removed
                continue
            except Exception as _pe:
                if _is_syntax_fixture(rel):
                    SYNTAX_FIXTURE_FILES.append({'file': rel, 'error': f"{type(_pe).__name__}: {_pe}"})
                files.append(rel)
                continue
            funcs = crc_engine._extract_functions(py_file)
            if funcs:
                files.append(rel)
        else:
            files.append(rel)
    return sorted(files)


def detect_removed_files(baseline_functions: dict, disk_files: set, target_repo: Path) -> list:
    """Find files in baseline that no longer exist on disk."""
    removed = []
    for file_key in baseline_functions:
        try:
            rel = str(Path(file_key).relative_to(target_repo))
        except ValueError:
            rel = file_key
        if rel not in disk_files:
            removed.append({'file': rel, 'functions': len(baseline_functions[file_key])})
    return removed


def write_file_locked(filepath: Path, data: dict):
    """Write JSON atomically via temp file + rename (no truncate-before-lock race)."""
    filepath.parent.mkdir(exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=filepath.parent,
        prefix=f".{filepath.stem}_{os.getpid()}_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
        Path(tmp_path).rename(filepath)  # atomic on same filesystem
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def _distribute_mirror(repo: Path, filename: str, data: dict, whitelist=None) -> None:
    """Write a mirror file to every directory in the repo (root + all subdirs).

    Whitelist insertion point ⑥ (distribution half): mirrors are never written
    into whitelisted/detritus directories — those dirs virtually don't exist,
    so CodeRadar leaves no work-files inside them.
    """
    if not repo.is_dir():
        return
    dirs: set[Path] = {repo}
    # FIX_13 / FIX_15 (2026-09-10): the fan-out walks only CONTAINED directories (never through a
    # symlink, never outside the target) and skips exactly what the scan surface skips — the engine
    # hard-skips and the whitelist. A dot-dir is in scope unless the whitelist names it; the old
    # '/.' / node_modules name tests are gone (`.git` / `__pycache__` stay hard-skipped in scan_scope).
    import scan_scope
    # FIX_35 e (2026-09-15, run 111 launch A): the whitelist names FILES, so a venv-by-size / detritus-only
    # directory (its every file whitelisted, the directory itself never an entry) still received a mirror —
    # 7 mirrors under a 15 MB `venv_shape/`. A mirror is for whoever works in a LIVE directory: it is written
    # only into directories that hold a live .py, or lie on the path from the root down to one.
    live_dirs: set[Path] = set()
    for py in scan_scope.iter_live_py(repo, whitelist if whitelist is not None else frozenset()):
        d = py.parent
        while d != repo and d not in live_dirs:
            live_dirs.add(d)
            d = d.parent
    for item in scan_scope.iter_contained(repo, '*'):
        if item.is_dir():
            if scan_scope.excluded(item):
                continue
            rel = item.relative_to(repo).as_posix()
            if scan_scope.is_whitelisted(rel, whitelist):
                continue
            if item not in live_dirs:
                continue
            dirs.add(item)
    for d in dirs:
        try:
            # owner ruling 2026-09-28: into <target>/.coderadar/<rel>/, never the code folder itself
            write_file_locked(scan_scope.mirror_path(repo, d, filename, create=True), data)
        except Exception:
            pass  # best-effort, don't break the daemon


# ── FIX_49 / FIX_50 (2026-09-17, owner Q9 / Q10) — path-hack dispositions ────────────────────────
# The disposition of a path hack is DATA (rule_dispositions.json `path_hacks`), resolved per
# (type, CONTEXT) by engine_utils and STAMPED here, where the facts live. The detector never decides
# it (step 17 keeps policy out of detectors) and no whitelist is touched: a `context` hack stays on
# the scan surface, is published with its warning, and is not counted as an infraction.

def _entry_relpath() -> str:
    """The ENTRY SCRIPT — the one entry_point_wrapper.py ran — as a path relative to TARGET_REPO.

    The fact FIX_50's context row reads (`role: entry`). Empty when the target was never run through
    the wrapper: no entry point measured, so nothing is exempted (NOT MEASURED by construction)."""
    try:
        proof = read_file_locked(ENTRY_POINT_INFO_FILE) if ENTRY_POINT_INFO_FILE.exists() else {}
        abspath = (proof or {}).get("entry_point_abspath")
        if not abspath:
            return ""
        return Path(abspath).resolve().relative_to(TARGET_REPO.resolve()).as_posix()
    except Exception:
        return ""


def _stamp_hack_dispositions(path_hacks) -> None:
    """Stamp `disposition` / `warning` on every hack of this scan, in place."""
    if not path_hacks:
        return
    try:
        from engine_utils import path_hack_disposition
    except Exception as e:            # a broken table is a broken install; never a silent default
        logging.warning(f"PATH HACK DISPOSITIONS: reader unavailable ({type(e).__name__}: {e})")
        return
    entry = _entry_relpath()
    for file, hacks in path_hacks.items():
        role = "entry" if entry and file == entry else ""
        for hack in hacks:
            try:
                disp, warning = path_hack_disposition(hack.type, {"role": role})
            except Exception as e:
                logging.warning(f"PATH HACK DISPOSITIONS: {hack.type}: {type(e).__name__}: {e}")
                continue
            hack.disposition = disp
            hack.warning = warning


# ── The FINISHED state (packet Q5 / B7-5, owner-ruled 2026-09-17) ────────────
# The finished state is `monitor.summary.finished`. ONE named set of gates so another domain can
# swap it without touching the arithmetic below; the default is the owner's formula:
#
#     counterfeit mirror summary.failed == 0
#     AND monitor.summary.mypy_errors   == 0
#     AND monitor.summary.severed_links == 0
#
# What is deliberately NOT here (owner 2026-09-17): the I/O tracker is a CENSUS of I/O functions —
# everything async in this project — so it can never legitimately be zero and cannot gate. crc,
# vulture, io and contract_violations are REPORTED (cr_data_types) and never gate. Withheld rows
# never count: `summary.failed` is repairs + no_vetted_fix, and `withheld` is a disjoint list.
# A gate whose input was NOT MEASURED (the counterfeit mirror not yet published; a mypy scan that
# never ran, C5) is not a zero — the state is unfinished and `finished_reason` says which input.
#
# Session 8 (2026-09-21), the two inputs the owner ruled on:
#   * `mypy_errors`   (I-128 / Q2) is MEASURED only when mypy ran (rc in {0, 1}) AND checked at
#     least one source file. The version is forced to the engine interpreter's at the invocation.
#   * `severed_links` (I-127 / Q1) counts the red edges a LEASED repair does NOT explain.
#     `severed_by_repair` carries the rest, published beside it.
# `cr_status` reads `finished` as `"not measured"` — never `true`, never `false` — while any one
# of the three is NOT MEASURED; the tri-state is made at that boundary, from `finished_inputs`.
FINISHED_GATES: tuple = ('counterfeit_failed', 'mypy_errors', 'severed_links')

NOAI_MIRROR_FILE = SCRIPT_DIR / '.noai_state.json'   # the counterfeit-code mirror, engine-side copy


def _naming_drift_not_measured() -> str | None:
    """ND1 / R4: why the naming-drift tracker measured nothing (`trackers.not_measured` reading), None once it has.
    The import failure, then the loop's own failure or 'launch scan has not completed', then the tracker's."""
    if _NAMING_DRIFT_IMPORT_ERROR:
        return _NAMING_DRIFT_IMPORT_ERROR
    if _NAMING_DRIFT is None:
        return _NAMING_DRIFT_WHY or 'launch scan has not completed'
    return _NAMING_DRIFT_WHY or _NAMING_DRIFT.not_measured_reason()


def _naming_drift_block() -> dict:
    """ND1: the mirror's `naming_drift` block (plan §D, frozen shape). `ran: false` and null counts until the
    launch pass built the baseline — NOT MEASURED, never 0."""
    why = _naming_drift_not_measured()
    if why is None and _NAMING_DRIFT is not None:
        return _NAMING_DRIFT.report()
    if _naming_not_measured_block is not None:
        return _naming_not_measured_block(why or 'launch scan has not completed')
    return {"groups": None, "pre_existing": None, "new": None, "by_tier": None, "accepted": None, "ran": False,
            "scanned_files": None, "baseline_at": None, "rows": [], "status": f"{_NOT_MEASURED} — {why}"}


def _pytest_block() -> dict:
    """owner 2026-10-07 ~06:45: the pytest data-type tracker — the LAST pytest run CodeRadar started (the wrapper's
    cr_pytest_results plugin writes system_scripts/pytest_results.json). No run yet = NOT MEASURED with the reason,
    never a zero. Rows: every failed / error test with file:line and the reason; counts for all outcomes."""
    doc = read_file_locked(SCRIPT_DIR / 'pytest_results.json')
    if not doc or 'counts' not in doc:
        return {'ran': False, 'status': _NOT_MEASURED,
                'reason': 'no pytest run yet this launch — run it through cr_run_module (path "pytest")'}
    counts = doc.get('counts') or {}
    bad = [t for t in doc.get('tests') or [] if t.get('outcome') in ('failed', 'error')]
    return {'ran': True, 'finished_at': doc.get('finished_at'), 'duration_s': doc.get('duration_s'),
            'exit_status': doc.get('exit_status'), 'args': doc.get('args'), 'collected': doc.get('collected'),
            'counts': counts, 'failed': counts.get('failed', 0), 'errors': counts.get('error', 0),
            'passed': counts.get('passed', 0), 'rows': bad}


def write_repo_mirror(graph, path_hacks, mypy_results, io_tracker_results, vulture_results,
                      severed_links=None):
    """Write a curated JSON mirror into the watched repo root.

    This file lets AI agents working in the repo see dashboard errors
    (imports, path hacks, mypy, dead code, functions) without manual copy-paste.
    Only writes when data has actually changed.

    FIX_45 (owner Q3, 2026-09-15): every broken/red connection is relayed here — the DASH mirror
    (`.monitor_state.json`, the data-type mirror) — and leaves it the moment the connection is green
    again. `severed_links` is the daemon's own set for this frame (None = the module state, which the
    frame loop has already updated); `compute_severed_links` stays the ONE source, as Item 11 ruled.
    """
    nodes = graph.nodes

    # Whitelist insertion point ⑥ (content half): whitelisted files' infractions
    # are excluded from every mirror section (virtual stripper).
    whitelist = load_whitelist(TARGET_REPO)

    broken = [{'file': n.relative_path, 'error': n.import_error}
              for n in nodes
              if not n.connected and not scan_scope.is_whitelisted(n.relative_path, whitelist)]

    # Build sections. Mirror mypy errors are formatted "rel/path.py:line: msg"
    # — whitelisted files are dropped from the mirror's mypy universe entirely.
    all_mypy = [
        err
        for chk in (mypy_results or {}).get('recent_checks', [])
        if not chk.get('passed')
        for err in chk.get('errors_list', [])
        if not scan_scope.is_whitelisted(err.split(':', 1)[0], whitelist)
    ]
    # Only actionable type errors count toward ALL CLEAR (external imports and
    # known quirks suppressed) — but suppression is DISPLAY metadata, never data
    # loss: the filtered error strings ship in the recoverable `suppressed` list.
    mypy_actionable = [e for e in all_mypy if not any(s in e for s in MYPY_SUPPRESS)]
    mypy_suppressed = [e for e in all_mypy if any(s in e for s in MYPY_SUPPRESS)]

    # Path hacks split for the mirror: _MIRROR_HACK_TYPES are the actionable set;
    # any type outside it ships under `other` (recoverable, not silently dropped).
    _MIRROR_HACK_TYPES = {'sys_path_insert', 'sys_path_append', 'sys_path_extend',
                          'pythonpath_access', 'pythonpath_read', 'pythonpath_config',
                          'shadowed_stdlib', 'broken_import', 'unguarded_external',
                          'circular_import', 'relative_import',
                          'file_traversal', 'relative_path'}
    # FIX_49 / FIX_50 (2026-09-17): a hack the disposition table calls `context` is INFORMATIONAL —
    # published under `other` (recoverable, never dropped) and never counted, whatever its type.
    # The stamp is `_stamp_hack_dispositions`'s; a hack with no stamp behaves exactly as before.
    critical_hacks = {}
    other_hacks = {}
    for file, hacks in (path_hacks or {}).items():
        if scan_scope.is_whitelisted(file, whitelist):
            continue
        critical = [h for h in hacks
                    if h.type in _MIRROR_HACK_TYPES and getattr(h, 'disposition', 'deciding') != 'context']
        other = [h for h in hacks
                 if h.type not in _MIRROR_HACK_TYPES or getattr(h, 'disposition', 'deciding') == 'context']
        if critical:
            critical_hacks[file] = critical
        if other:
            other_hacks[file] = other
    hack_total = sum(len(hacks) for hacks in critical_hacks.values())

    # Only non-exempt sync functions are actionable
    sync_needs_review = [
        d for d in (io_tracker_results or {}).get('details', [])
        if not d.get('async', False) and not d.get('sync_exempt', False)
        and not scan_scope.is_whitelisted(d.get('file', ''), whitelist)
    ]

    # Dead code: unused_import (ruff/mypy handle those) and unused_attribute
    # (dataclass/namedtuple fields accessed via constructors — false positives)
    # are suppressed from the actionable list but ship recoverably in
    # `suppressed_items`, never dropped.
    _VULTURE_SUPPRESS = {'unused_import', 'unused_attribute'}
    _vulture_all = [
        i for i in (vulture_results or {}).get('items', [])
        if not scan_scope.is_whitelisted(i.get('file', ''), whitelist)
    ]
    dead_code_items = [
        i for i in _vulture_all
        if i.get('category') not in _VULTURE_SUPPRESS
    ]
    dead_code_suppressed = [
        i for i in _vulture_all
        if i.get('category') in _VULTURE_SUPPRESS
    ]
    # Only high-confidence items affect ALL CLEAR status
    dead_code_actionable = [i for i in dead_code_items if i.get('confidence', 0) >= 80]

    # R4 / T-05: a count is published only when its tracker MEASURED it. A tracker the launch
    # did not choose (`not_run`), or whose tool is missing or failed (`not_measured`), publishes
    # null counts and leaves `zero_signal` and ALL CLEAR — never a silent 0 that reads as clean.
    def _unmeasured_why(token, results):
        if token not in _TRACKERS:
            return _NOT_RUN
        return _tracker_not_measured(token, results)
    io_why = _unmeasured_why('io', io_tracker_results)
    vulture_why = _unmeasured_why('vulture', vulture_results)
    if vulture_why is None and not isinstance((vulture_results or {}).get('files_scanned'), int):
        vulture_why = 'no vulture scan has completed yet'
    io_measured = io_why is None
    vulture_measured = vulture_why is None
    # ND1: the naming-drift block and its headline (`new` drift, T1+T2) — null until the baseline exists.
    naming_drift = _naming_drift_block()
    naming_measured = bool(naming_drift.get('ran'))
    naming_new = naming_drift.get('new') if naming_measured else None

    # Monitor writes its own mirror — no shared file with noai

    # C5: a mypy scan that never ran must not read as clean. mypy_ran is True
    # only when the scan subprocess completed with rc in {0, 1}; an absent key
    # (old state, scan never attempted) defaults to not-measured.
    mypy_ran = bool((mypy_results or {}).get('mypy_ran', False))
    # I-128 / Q2 (session 8): the scan's own verdict, published beside the count it vouches for
    # — `mypy_rc 2` with `mypy_files_checked 0` is the silent failure run 155 carried for a whole
    # run, and it is now LOUD. A scan that checked NOTHING measured nothing, whatever its rc, so
    # it is not a zero either: `mypy_errors` below reads NOT MEASURED unless both hold.
    mypy_rc = (mypy_results or {}).get('mypy_rc')
    mypy_files_checked = int((mypy_results or {}).get('files_checked') or 0)
    mypy_measured = mypy_ran and mypy_files_checked > 0

    # FIX_45: the severed set of THIS frame, from the one source (`compute_severed_links` on the
    # module state, which the frame loop updated before this call).
    # I-83 (owner-ruled 2026-09-17, Q5/B7-5): `zero_signal` and `circuit_clear` now DO carry
    # `severed_links` — FIX_45 left the extension for the owner's P4 call and the call was made.
    # Purely additive: every other name in the predicate keeps the meaning it had.
    _sev = _SEVERED_LINKS if severed_links is None else severed_links
    _sev_pairs = sorted(_sev)
    _sev_since = dict(_sev) if isinstance(_sev, dict) else {}
    # I-127 / Q1 (session 8): the red set, split by WHO cut it. A repair-severed edge is still
    # red on the wiring and still counted — under its own name — but it is not the release's
    # unfinished business, so it is out of `severed_links` and out of `finished`'s third input.
    _sev_repair = classify_severed_by_repair(_sev_since, {n.name: n.relative_path for n in nodes})
    _sev_open = [p for p in _sev_pairs if p not in _sev_repair]
    _sev_repair_pairs = [p for p in _sev_pairs if p in _sev_repair]

    circuit_clear = (not broken and mypy_measured and not mypy_actionable and hack_total == 0
                     and not (io_measured and sync_needs_review)
                     and not (vulture_measured and dead_code_actionable)
                     and not _sev_open
                     # ND1 (plan §D, "the way path_hacks sits in zero_signal"): NEW naming drift since the
                     # launch baseline (T1+T2) is the seventh name; pre-existing rows and T3 never gate.
                     and not (naming_measured and naming_new))

    # Q5: the counterfeit mirror's own failure count — the ONE input to `finished` the dash mirror
    # never published. None when the Builder has not written the mirror yet (NOT MEASURED, never a
    # zero); read through the same shared lock every other state read uses.
    counterfeit_failed = None
    try:
        _cf_summary = (read_file_locked(NOAI_MIRROR_FILE) or {}).get('summary') or {}
        if 'failed' in _cf_summary:
            counterfeit_failed = int(_cf_summary['failed'])
    except Exception as e:
        logging.warning(f"MIRROR: counterfeit mirror unreadable for the finished state: {e}")

    # The three inputs, by the ONE gate set. A gate is satisfied when its input is MEASURED and zero.
    finished_inputs = {
        'counterfeit_failed': counterfeit_failed,
        # C5 + Q2: an unrun scan is not a zero, and neither is a scan that checked no files.
        'mypy_errors': len(mypy_actionable) if mypy_measured else None,
        # Q1: the severed input is the edges NOT cut by a leased repair.
        'severed_links': len(_sev_open),
    }
    _unmeasured = [g for g in FINISHED_GATES if finished_inputs.get(g) is None]
    _outstanding = [g for g in FINISHED_GATES if finished_inputs.get(g)]
    finished = not _unmeasured and not _outstanding
    if finished:
        finished_reason = 'finished: ' + ', '.join(f'{g}=0' for g in FINISHED_GATES)
    else:
        _parts = [f'{g}=NOT MEASURED' for g in _unmeasured]
        # M-20 (run 187, six: status panel 516 vs tracker 77): `mypy_errors` is every mypy
        # `: error:` line INCLUDING the --strict annotation notes, less the suppressed ones — not
        # the circuit's `total_errors` (real type errors only). Say which, where it is published.
        _scope = {'mypy_errors': ' (mypy error lines incl. annotation notes, less suppressed)'}
        _plain = {'counterfeit_failed': 'counterfeit code infractions', 'mypy_errors': 'mypy error lines',
                  'severed_links': 'broken import links'}
        _parts += [f'{finished_inputs[g]} {_plain.get(g, g)} ({g}={finished_inputs[g]}){_scope.get(g, "")}'
                   for g in _outstanding]
        finished_reason = 'not finished: ' + ', '.join(_parts)

    mirror = {
        # ── LEFT PANEL: Circuit Monitor ──
        'monitor': {
            # T-13: whose run this mirror records — the MCP's _wrong_target guard checks it
            'target_repo': str(TARGET_REPO),
            'status': 'ALL CLEAR' if circuit_clear else 'ISSUES FOUND',
            'summary': {
                'broken_imports': len(broken),
                'path_hacks': hack_total,
                'mypy_errors': len(mypy_actionable),
                # C5: distinguishes "0 errors" (measured) from "not measured"
                'mypy_ran': mypy_ran,
                # Q2 / I-128 (session 8): the two facts that make a silent mypy failure loud —
                # the process's own returncode and how many source files it actually checked.
                'mypy_rc': mypy_rc,
                'mypy_files_checked': mypy_files_checked,
                'sync_needs_review': len(sync_needs_review) if io_measured else None,
                'dead_code_items': len(dead_code_items) if vulture_measured else None,
                'dead_code_actionable': len(dead_code_actionable) if vulture_measured else None,
                # FIX_45 (owner Q3): the number of connections currently RED. I-83 puts it in
                # zero_signal and circuit_clear as well (the B7-5 call, made 2026-09-17).
                'severed_links': len(_sev_open),
                # Q1 / I-127 (session 8): the red edges a LEASED repair explains — published
                # with their own count, and deliberately NOT in `severed_links` or `zero_signal`.
                # `severed_links + severed_by_repair` is every red edge on the wiring.
                'severed_by_repair': len(_sev_repair_pairs),
                # ND1: new naming drift since the launch baseline (T1+T2 rows of kind `new`); null until the
                # baseline exists. The full block is `naming_drift` beside `path_hacks` below.
                'naming_drift': naming_new,
                # ── Q5, the FINISHED state ──────────────────────────────────
                # `finished` is NOT `circuit_clear`: ALL CLEAR is the six-name zero_signal below,
                # the finished state is FINISHED_GATES — three gates, I/O among the names that
                # report but never gate. The three inputs ride beside it so a reader can see why.
                'finished': finished,
                'finished_reason': finished_reason,
                'finished_gates': list(FINISHED_GATES),
                'finished_inputs': finished_inputs,
                # The counterfeit mirror's own count, republished here so `finished` can be
                # re-derived from `monitor.summary` alone (it was in neither mirror before).
                'counterfeit_failed': counterfeit_failed,
            },
            # Zero-signal contract: ALL CLEAR ⇔ every one of THESE summary
            # counts is zero AND mypy_ran is true — a mypy scan that did not
            # run disqualifies ALL CLEAR (C5): a zero is only a measurement
            # when mypy_ran vouches for it. (dead_code_items may be non-zero
            # on ALL CLEAR: only confidence>=80 items — dead_code_actionable
            # — gate status.)
            # I-83 (2026-09-17): `severed_links` is the SIXTH name — a red connection now
            # disqualifies ALL CLEAR, exactly as FIX_45's plan said it would once ruled.
            # Q1 (session 8): the name keeps its place; what changed is what it counts — a red
            # edge a leased repair explains rides under `severed_by_repair` and gates nothing.
            # R4 / T-05: a name whose tracker measured nothing is left out (its count is null);
            # `trackers.not_measured` / `trackers.not_run` say which and why.
            'zero_signal': [n for n in ('broken_imports', 'path_hacks', 'mypy_errors',
                                        'sync_needs_review', 'dead_code_actionable', 'severed_links',
                                        'naming_drift')
                            if not (n == 'sync_needs_review' and not io_measured)
                            and not (n == 'dead_code_actionable' and not vulture_measured)
                            and not (n == 'naming_drift' and not naming_measured)],
            # R4: the launch's tracker choice and, per chosen tracker that measured nothing, why.
            # (crc publishes nothing in this mirror; its reading is circuit_state.crc_results.)
            'trackers': {
                # ND1: the permanent trackers are always chosen (plan §D) — never in `not_run`.
                'chosen': sorted(_TRACKERS) + list(_PERMANENT_TRACKERS),
                'not_run': [t for t in _TRACKER_TOKENS if t not in _TRACKERS],
                'not_measured': {t: r for t, r in (
                    ('io', _tracker_not_measured('io', io_tracker_results)),
                    ('mypy', _tracker_not_measured('mypy', mypy_results)),
                    ('vulture', vulture_why if 'vulture' in _TRACKERS else None),
                    ('naming_drift', _naming_drift_not_measured()),
                    ('pytest', _pytest_block().get('reason')),
                ) if r},
            },
            # Files virtually stripped from the scan surface for this target
            # (whitelist_<repoid>.json) — disclosed so agents can see what the
            # monitor is NOT looking at.
            'whitelisted_files': sorted(whitelist),
            'recommended_order': [
                {'step': 1, 'category': 'path_hacks',
                 'reason': 'Clean imports are the foundation. Fixing sys.path hacks and relative imports changes what mypy can resolve — some suppressed import-not-found errors are caused by path hacks.',
                 'resolution': 'Replace sys.path.insert hacks with proper package installs (pip install -e .) or __init__.py wiring. Convert relative imports to absolute where the package structure supports it. Guard external imports with try/except for optional dependencies.'},
                {'step': 2, 'category': 'mypy',
                 'reason': 'Once imports are clean, mypy sees the real picture. Adding type annotations makes the I/O review safer because you can verify signatures after async conversion.',
                 'resolution': 'Add return type annotations to untyped functions. Add parameter type annotations where missing. Replace bare generic types (dict, list, tuple) with parameterized versions (dict[str, Any], list[int]). Fix incompatible defaults by using Optional (e.g. content: str | None = None).'},
                {'step': 3, 'category': 'sync_needs_review',
                 'reason': 'Converting sync I/O to async is the most invasive change. It ripples through callers. Clean imports (real call graph) and proper types (verified signatures) make this much safer.',
                 'resolution': 'For each sync function doing I/O: if an async sibling already exists, remove the sync version and update callers. If no async version exists, convert to async (file_open -> aiofiles, subprocess_run -> asyncio.create_subprocess_exec, fs_exists/rglob -> asyncio.to_thread). Update all callers to await the converted function.'},
                # ND1: the permanent naming-drift tracker, last — a rename is cheap once the wiring, the types and
                # the I/O shape are settled, and the ranker (not the rule) judges which rows are false positives.
                {'step': 4, 'category': 'naming_drift',
                 'reason': 'One concept spelled several ways (user_id / userId / usr_id) is drift the repo cannot keep up with by hand; every row names the canonical spelling, its variant and the sites. New drift since the launch baseline is the headline; pre-existing drift is reported once; T3 (one typo apart) is reported, never counted.',
                 'resolution': 'Rename the variant sites to the canonical spelling — the developer does it, CodeRadar never edits. A spelling that is a legitimate variant is accepted from the dash (accepted_<repoid>.json); a spelling that should be the canonical is made canonical there, and the old canonical becomes the variant.'},
            ],
            'imports': {
                'total_scripts': len(nodes),
                'connected': sum(1 for n in nodes if n.connected),
                'broken': broken,
                'cycles': graph.cycles,
            },
            # FIX_45 (owner Q3, 2026-09-15): every RED connection, relayed here as the two node
            # names and nothing else, and gone the frame the connection is green again. The dash
            # mirror repeats the daemon; it never computes a severed link of its own.
            'wiring': {
                'severed': [list(p) for p in _sev_pairs],
                'severed_since': {f'{p[0]}->{p[1]}': _sev_since[p] for p in _sev_pairs if p in _sev_since},
                # Q1: the same pairs, named. Every edge here is also in `severed` above — the
                # wiring still draws it red; the split is about what `finished` counts.
                'severed_by_repair': [list(p) for p in _sev_repair_pairs],
                'drawn': 'red',
            },
            'path_hacks': {
                'total': hack_total,
                'hacks': {
                    file: [{'line': h.line, 'type': h.type, 'details': h.details,
                            'disposition': getattr(h, 'disposition', 'deciding'),
                            'warning': getattr(h, 'warning', '')}
                           for h in hacks]
                    for file, hacks in critical_hacks.items()
                },
                # Hack types outside _MIRROR_HACK_TYPES, and every hack the disposition table calls
                # `context` (FIX_49 / FIX_50) — not actionable here, but recoverable (nothing
                # silently dropped from the mirror).
                'other': {
                    file: [{'line': h.line, 'type': h.type, 'details': h.details,
                            'disposition': getattr(h, 'disposition', 'deciding'),
                            'warning': getattr(h, 'warning', '')}
                           for h in hacks]
                    for file, hacks in other_hacks.items()
                },
            },
            'mypy': {
                # C5: False ⇒ the counts below are not a measurement
                'mypy_ran': (mypy_results or {}).get('mypy_ran', False),
                'mypy_rc': (mypy_results or {}).get('mypy_rc'),
                'files_checked': (mypy_results or {}).get('files_checked', 0),
                'passed': (mypy_results or {}).get('passed', 0),
                'failed': (mypy_results or {}).get('failed', 0),
                # T-06: `total_errors` / `type_errors` / `annotation_notes` are circuit_state's
                # (run_mypy_scan) — real type errors, the --strict annotation notes kept apart —
                # null unless mypy measured. `error_lines` is this mirror's own count: every
                # `: error:` line less the suppressed ones (= summary.mypy_errors, M-20).
                'total_errors': (mypy_results or {}).get('total_errors') if mypy_measured else None,
                'type_errors': (mypy_results or {}).get('type_errors') if mypy_measured else None,
                'annotation_notes': (mypy_results or {}).get('annotation_notes') if mypy_measured else None,
                'error_lines': len(mypy_actionable),
                'total_errors_unfiltered': len(all_mypy),
                'suppressed_errors': len(mypy_suppressed),
                'errors': mypy_actionable,
                # The MYPY_SUPPRESS-filtered error strings themselves —
                # suppression is display metadata, the content stays recoverable.
                'suppressed': mypy_suppressed,
                # B2 / B3 (2026-09-28): whose site-packages the imports resolved against, and how many did not
                'target_env': (mypy_results or {}).get('target_env'),
                'import_resolution': (mypy_results or {}).get('import_resolution'),
                'layout': (mypy_results or {}).get('layout'),
                'import_errors': (mypy_results or {}).get('import_errors'),
            },
            'dead_code': {
                # R4: "measured", or why not (not_run / NOT MEASURED — <reason>); counts null unless measured
                'status': 'measured' if vulture_measured else (
                    vulture_why if vulture_why == _NOT_RUN else f"{_NOT_MEASURED} — {vulture_why}"),
                'files_scanned': (vulture_results or {}).get('files_scanned') if vulture_measured else None,
                'files_with_dead_code': ((vulture_results or {}).get('files_with_dead_code')
                                         if vulture_measured else None),
                'total_items': len(dead_code_items) if vulture_measured else None,
                'items_by_category': {
                    cat: sum(1 for i in dead_code_items if i.get('category') == cat)
                    for cat in {i.get('category') for i in dead_code_items}
                },
                'items': [
                    {'file': i['file'], 'line': i['line'], 'category': i['category'],
                     'name': i['name'], 'confidence': i['confidence']}
                    for i in dead_code_items
                ],
                # Items in _VULTURE_SUPPRESS categories (unused_import /
                # unused_attribute) — recoverable, not silently dropped.
                'suppressed_items': [
                    {'file': i['file'], 'line': i['line'], 'category': i['category'],
                     'name': i['name'], 'confidence': i['confidence']}
                    for i in dead_code_suppressed
                ],
            },
            # ND1 (plan §D, FROZEN shape): the naming-drift tracker's block — groups / pre_existing / new /
            # by_tier / accepted / ran / scanned_files / baseline_at / rows (+ `status`, the tracker idiom).
            'naming_drift': naming_drift,
            'pytest': _pytest_block(),
            'functions': {
                # R4: the io tracker's counts, null unless it measured (status says why)
                'status': 'measured' if io_measured else (
                    io_why if io_why == _NOT_RUN else f"{_NOT_MEASURED} — {io_why}"),
                'total': (io_tracker_results or {}).get('totals', {}).get('total_functions', 0) if io_measured else None,
                'async': (io_tracker_results or {}).get('totals', {}).get('async_count', 0) if io_measured else None,
                'sync': (io_tracker_results or {}).get('totals', {}).get('sync_count', 0) if io_measured else None,
                'io_functions': (io_tracker_results or {}).get('totals', {}).get('io_functions', 0) if io_measured else None,
                'sync_needs_review': sync_needs_review,
            },
        },
    }
    try:
        # Write to system_scripts/
        write_file_locked(SCRIPT_DIR / '.monitor_state.json', mirror)
        # Write to every dir in TARGET_REPO (skipping whitelisted/detritus dirs)
        _distribute_mirror(TARGET_REPO, '.monitor_state.json', mirror, whitelist)
    except Exception as e:
        logging.warning(f"MIRROR: Failed to write monitor mirror: {e}")


def read_file_locked(filepath: Path) -> dict:
    """Read JSON data from file with shared lock."""
    if not filepath.exists():
        return {}
    try:
        with open(filepath, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        return {}

# =============================================================================
# DATAFLOW DETECTION (kernel-traced IPC + TCP sockets)
# =============================================================================


class _AsyncBridge:
    """Runs an asyncio event loop in a background daemon thread.

    Allows synchronous code to call async EsloggerMonitor methods.
    """

    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        """Start the background event loop."""
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="eslogger-loop",
            daemon=True,
        )
        self._thread.start()

    def run(self, coro):
        """Run an async coroutine from synchronous code. Blocks until done."""
        if self._loop is None:
            raise RuntimeError("AsyncBridge not started")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=10)

    def stop(self):
        """Stop the background event loop."""
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)


def detect_dataflows_kernel(
    ipc_data: Dict[int, Set[str]],
    pid_to_node: Dict[int, str],
) -> List[Dict[str, Any]]:
    """Detect dataflows from kernel-traced IPC file access.

    If PID A and PID B both accessed the same IPC file,
    that's a kernel-proven dataflow.
    """
    file_to_pids: Dict[str, Set[int]] = {}
    for pid, files in ipc_data.items():
        if pid not in pid_to_node:
            continue
        for fpath in files:
            file_to_pids.setdefault(fpath, set()).add(pid)

    seen: Set[Tuple[str, str, str]] = set()
    flows: List[Dict[str, Any]] = []
    for fpath, pids in file_to_pids.items():
        if len(pids) < 2:
            continue
        pid_list = sorted(pids)
        for i in range(len(pid_list)):
            for j in range(i + 1, len(pid_list)):
                src, dst = sorted([pid_to_node[pid_list[i]], pid_to_node[pid_list[j]]])
                channel = f"file:{fpath}"
                key = (src, dst, channel)
                if key not in seen:
                    seen.add(key)
                    flows.append(DataflowDict(src=src, dst=dst, channel=channel, proof=PROOF_KERNEL))
    return flows


async def _gather_dataflows_async(
    monitor: 'EsloggerMonitor',
    running: dict,
) -> List[Dict[str, Any]]:
    """Collect dataflows from kernel traces (IPC files + sockets).

    Async function called via _AsyncBridge.run().
    """
    dataflows: List[Dict[str, Any]] = []
    if not monitor or not monitor.is_running:
        return dataflows

    # Kernel-native IPC file detection
    ipc_data = await monitor.get_ipc_files()
    pid_to_node: Dict[int, str] = {}
    for pid_str, info in running.items():
        pid = info.get('pid')
        script = info.get('script', '').replace('.py', '')
        if pid and script:
            pid_to_node[pid] = script

    dataflows = detect_dataflows_kernel(ipc_data, pid_to_node)

    # Kernel-native TCP socket detection
    socket_flows = monitor.get_socket_flows()
    existing_keys = {(f.get("src"), f.get("dst"), f.get("channel")) for f in dataflows}
    for sf in socket_flows:
        if (sf.get("src"), sf.get("dst"), sf.get("channel")) not in existing_keys:
            dataflows.append(sf)

    return dataflows


def detect_dataflows_lsof(running: dict) -> List[Dict[str, Any]]:
    """Fallback dataflow detection using lsof when kernel tracer lacks TCP support.

    Finds pairs of running scripts that share a TCP port (one LISTEN, one ESTABLISHED)
    and returns them as dataflows.
    """
    if len(running) < 2:
        return []

    pid_to_script = {}
    pids = []
    for pid_str, info in running.items():
        pid = info.get('pid')
        # M-74 (2026-10-07): the flow's ends are the node PATH ('pkg/sub/file'), not the bare stem — the dash
        # folds a path into the folder box it sits under; a bare stem matched no drawn node, so no blue drew
        script = (info.get('node') or info.get('script', '')).replace('.py', '')
        if pid and script:
            pid_to_script[pid] = script
            pids.append(str(pid))

    if len(pids) < 2:
        return []

    try:
        result = subprocess.run(
            ['lsof', '-i', 'TCP', '-n', '-P', '-a'] +
            [item for pid in pids for item in ['-p', pid]],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            # lsof -a with multiple -p flags: try per-pid
            lines = []
            for pid in pids:
                r = subprocess.run(
                    ['lsof', '-i', 'TCP', '-n', '-P', '-p', pid],
                    capture_output=True, text=True, timeout=5
                )
                lines.extend(r.stdout.strip().splitlines())
        else:
            lines = result.stdout.strip().splitlines()
    except Exception as _e:
        logging.warning("probe failed (reported, not swallowed): %s", _e)  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous)
        return []

    # Parse lsof output: find port→pid mappings
    port_listeners = {}   # port -> script (LISTEN)
    port_connectors = {}  # port -> script (ESTABLISHED/connect)
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            pid = int(parts[1])
        except (ValueError, IndexError):
            continue
        if pid not in pid_to_script:
            continue
        script = pid_to_script[pid]
        name_col = parts[8]  # NAME column: e.g. 127.0.0.1:9821
        state = parts[9] if len(parts) > 9 else ''
        # Extract port from address
        if ':' in name_col:
            port = name_col.rsplit(':', 1)[-1]
            if state == '(LISTEN)':
                port_listeners[port] = script
            elif state in ('(ESTABLISHED)', '(CLOSE_WAIT)', '(CLOSED)'):
                port_connectors[port] = script

    # Match: script A listens on port, script B connects to same port
    flows = []
    for port, listener in port_listeners.items():
        connector = port_connectors.get(port)
        if connector and connector != listener:
            flows.append(DataflowDict(
                src=connector, dst=listener,
                channel=f'tcp://127.0.0.1:{port}', proof='lsof'
            ))
    return flows + _pipe_flows_lsof(pid_to_script)


def _pipe_flows_lsof(pid_to_script: Dict[int, str]) -> List[Dict[str, Any]]:
    """owner 2026-09-29 (dataflow_scripts): OS pipes between running scripts — `a.py | b.py`, or
    subprocess stdout wired into another's stdin. lsof lists each pipe end as (device, peer device);
    the WRITE end (access `w`, or fd 1/2) of one script whose peer is the READ end (access `r`, or fd 0)
    of another is a flow writer -> reader."""
    try:
        r = subprocess.run(['lsof', '-a', '-p', ','.join(str(p) for p in pid_to_script), '-F', 'pfatdn'],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as e:
        logging.warning(f"DATAFLOW: pipe probe failed (reported, not swallowed): {e}")
        return []
    ends: Dict[str, tuple] = {}         # device -> (script, 'w'|'r', peer device)
    pid = fd = acc = typ = dev = peer = None
    for line in r.stdout.splitlines() + ['p']:
        tag, val = line[:1], line[1:]
        if tag in ('p', 'f') and typ == 'PIPE' and dev and pid in pid_to_script:
            direction = 'w' if acc == 'w' or fd in ('1', '2') else ('r' if acc == 'r' or fd == '0' else '')
            # M-74 (2026-10-07): a parent's end of a subprocess pipe sits on fd 3+ with no access flag (lsof
            # prints `a ` for pipes), so its direction is unknown here — kept, and set from its peer below
            ends[dev] = (pid_to_script[pid], direction, peer)
        if tag == 'p':
            pid = int(val) if val.isdigit() else None
            fd = acc = typ = dev = peer = None
        elif tag == 'f':
            fd, acc, typ, dev, peer = val, None, None, None, None
        elif tag == 'a':
            acc = val.strip()
        elif tag == 't':
            typ = val
        elif tag == 'd':
            dev = val
        elif tag == 'n':
            peer = val[2:] if val.startswith('->') else None
    pairs: Dict[tuple, str] = {}        # (writer, reader) -> the pipe's device; one flow per pair
    for dev, (script, direction, peer_dev) in ends.items():
        other = ends.get(peer_dev or '')
        if not other or other[0] == script:
            continue
        # an end with no known direction is the opposite of its peer's (one pipe = one writer, one reader)
        mine = direction or {'r': 'w', 'w': 'r'}.get(other[1], '')
        theirs = other[1] or {'r': 'w', 'w': 'r'}.get(direction, '')
        if mine == 'w' and theirs == 'r':
            pairs.setdefault((script, other[0]), dev)
    return [DataflowDict(src=w, dst=rd, channel=f'pipe:{d}', proof='lsof') for (w, rd), d in pairs.items()]


# =============================================================================
# =============================================================================
# LIVE PROCESS DETECTION
# =============================================================================

# System script filenames to exclude from process scanning
_SYSTEM_SCRIPTS = {
    'circuit_daemon.py', 'proof_dashboard.py',
    'ast_scanner.py', 'integration_dashboard.py', 'kernel_trace_daemon.py',
    'electricity.py',
}


def is_pid_alive(pid: int) -> bool:
    """Check if a process with given PID exists via signal 0."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user
    except OSError:
        return False


def _cached_proc_cwd(pid: int, cmd: str) -> Optional[str]:
    """M-48: a process's cwd, read once per (pid, command) — a reused pid with a new command reads again."""
    key = (pid, cmd)
    if key not in _CWD_CACHE:
        if len(_CWD_CACHE) > 512:
            _CWD_CACHE.clear()
        _CWD_CACHE[key] = _proc_cwd(pid)
    return _CWD_CACHE[key]


def _module_token(tokens: List[str]) -> Optional[str]:
    """M-48 (2026-10-06): the module a `python … -m pkg.mod …` command runs — `-m pkg.mod` or the joined
    `-mpkg.mod` form — or None. Only the first `-m` counts: what follows it is the module's own argv."""
    for i, tok in enumerate(tokens):
        if tok == '-m':
            return tokens[i + 1] if i + 1 < len(tokens) else None
        if tok.startswith('-m') and len(tok) > 2 and not tok.startswith('--'):
            return tok[2:]
    return None


def _resolve_run_target(rel: str, bases: List[Path], repo_path: Path, module: bool) -> Optional[Path]:
    """M-48: the file under `repo_path` that `rel` names when read from each base in turn (the process's
    cwd first, then the repo root). A module resolves to `pkg/mod.py`, else to `pkg/mod/__main__.py`
    (what `python -m pkg` runs). None when no base gives an existing file inside the repo."""
    if module:
        parts = Path(*rel.split('.'))
        rels = [parts.with_suffix('.py'), parts / '__main__.py']
    else:
        rels = [Path(rel)]
    for base in bases:
        for r in rels:
            cand = (base / r).resolve()
            if cand.is_file():
                try:
                    cand.relative_to(repo_path)
                except ValueError:
                    continue
                return cand
    return None


def scan_running_processes(monitored_scripts: list, repo_path: Path, ps_lines=None, cwd_of=None) -> dict:
    """Scan process table for Python processes running monitored scripts.

    Args:
        monitored_scripts: Script stem names (e.g. ['script_A', 'script_B'])
        repo_path: Resolved path to the monitored repository
        ps_lines: Item 10 — the frame's ONE `ps` snapshot [(pid, command)] from
            test_runner_tracker.list_python_processes(); None = take one here.
        cwd_of: M-48 — pid -> the process's cwd (str) or None; None = test_runner_tracker.proc_cwd.
            Read only for a command with `-m` or a relative `.py` path, once per (pid, command).

    Returns:
        Dict keyed by PID string with running script info. M-48 (2026-10-06): `how` says what matched —
        'path' (a `.py` argument, absolute or relative to the process's cwd), 'module' (`-m pkg.mod`),
        'stem' (a bare name only matched by stem, the pre-M-48 fallback) — with `node`, `cmd` and `cwd`.
    """
    running: Dict[str, Dict[str, Any]] = {}
    own_pid = os.getpid()
    monitored_set = set(monitored_scripts)
    # Also build stem-only lookup for matching subdir-prefixed names like "tests/receiving"
    stem_to_full: Dict[str, str] = {}
    for name in monitored_scripts:
        bare = name.rsplit('/', 1)[-1] if '/' in name else name
        stem_to_full[bare] = name
    candidates_seen = 0

    try:
        # Item 10: one `ps` per frame, shared with the test-runner scan (the block that took it here
        # is test_runner_tracker.list_python_processes now).
        if ps_lines is None:
            ps_lines = list_python_processes(own_pid)

        for pid, cmd in ps_lines:
            if pid == own_pid:
                continue

            candidates_seen += 1

            # Skip system scripts
            if any(ss in cmd for ss in _SYSTEM_SCRIPTS):
                logging.debug(f"Process scan: skipping system script pid={pid} cmd={cmd[:120]}")
                continue

            tokens = cmd.split()
            matched = False

            # M-48 (owner 2026-10-06: "should be detecting connections no matter how it's looked for"):
            # `-m pkg.mod` and a `.py` path relative to the process's OWN cwd — the old loop below only
            # took `.py` tokens resolved against the repo root, so `python3 -m charlie_work.x` (the only
            # way a package-entry target runs) and `cd sub && python ../x.py` were invisible.
            module = _module_token(tokens)
            rel_py = [t for t in tokens if t.endswith('.py') and not Path(t).is_absolute()]
            if module or rel_py:
                cwd = cwd_of(pid) if cwd_of is not None else _cached_proc_cwd(pid, cmd)
                bases =([Path(cwd)] if cwd else []) + [repo_path]
                hit, how = None, None
                if module:
                    hit, how = _resolve_run_target(module, bases, repo_path, module=True), 'module'
                for t in ([] if hit else rel_py):
                    hit, how = _resolve_run_target(t, bases, repo_path, module=False), 'path'
                    if hit:
                        break
                if hit:
                    node = hit.relative_to(repo_path).with_suffix('').as_posix()
                    if node in monitored_set:
                        running[str(pid)] = {
                            'script': hit.name, 'node': node, 'pid': pid, 'how': how,
                            'cmd': cmd[:200], 'cwd': cwd,
                            'detected_at': datetime.now().isoformat(), 'source': 'daemon',
                        }
                        continue
                    logging.debug(f"Process scan: pid={pid} resolved {node} ({how}) but it is not a graph node")
                elif module:
                    logging.debug(f"Process scan: pid={pid} -m {module} is not a module in the repo (cwd={cwd})")

            # Check each token for a .py file in the monitored repo
            for token in tokens:
                if not token.endswith('.py'):
                    continue
                try:
                    token_path = Path(token)
                    stem = token_path.stem

                    if token_path.is_absolute():
                        # Absolute path: verify it's under the repo
                        try:
                            token_path.relative_to(repo_path)
                        except ValueError:
                            logging.debug(f"Process scan: pid={pid} {stem}.py not under repo "
                                          f"({token_path} vs {repo_path})")
                            continue
                    else:
                        # Bare filename (e.g. "dataflow_sender.py") — resolve
                        # against repo first, fall back to stem match
                        repo_candidate = repo_path / token
                        if repo_candidate.exists():
                            token_path = repo_candidate
                        elif stem not in monitored_set and stem not in stem_to_full:
                            logging.debug(f"Process scan: pid={pid} {stem}.py not in monitored set")
                            continue

                    # Match against full names (e.g. "tests/receiving") or bare stems
                    matched_name = None
                    if stem in monitored_set:
                        matched_name = stem
                    elif stem in stem_to_full:
                        matched_name = stem_to_full[stem]

                    if matched_name:
                        running[str(pid)] = {
                            'script': f'{stem}.py',
                            'node': matched_name,
                            'pid': pid,
                            # an absolute path checked under the repo, else only a stem match (M-48)
                            'how': 'path' if token_path.is_absolute() else 'stem',
                            'cmd': cmd[:200], 'cwd': None,
                            'detected_at': datetime.now().isoformat(),
                            'source': 'daemon',
                        }
                        matched = True
                        break
                    else:
                        logging.debug(f"Process scan: pid={pid} stem={stem} not in monitored "
                                      f"({', '.join(list(monitored_set)[:5])}...)")
                except Exception:
                    continue

            if not matched and candidates_seen <= 3:
                logging.debug(f"Process scan: unmatched python process pid={pid} cmd={cmd[:120]}")

        if not running and candidates_seen > 0:
            logging.info(f"Process scan: {candidates_seen} python processes seen, "
                         f"none matched monitored set ({len(monitored_set)} scripts, "
                         f"repo={repo_path})")

    except Exception as e:
        logging.warning(f"Process scan error: {e}")

    return running


def runner_proof_summary() -> dict:
    """Item 10: what the last RUNNER execution proved (runner_info.json — the runner's own record, the
    app's entry_point_info.json untouched): runner, what it was pointed at, when, the test files it
    imported, files verified / stale by hash. NOT MEASURED when no runner has run."""
    proof = _read_json_plain(RUNNER_INFO_FILE) if RUNNER_INFO_FILE.exists() else {}
    if not proof:
        return {"status": "NOT MEASURED — no runner execution recorded (run pytest / unittest through entry_point_wrapper.py -m …)"}
    cov, verified, stale = _runner_coverage(proof, TARGET_REPO)
    return {
        "status": "MEASURED",
        "runner": proof.get("runner"),
        "test_path": proof.get("test_path"),
        "executed_at": proof.get("executed_at") or proof.get("capture_timestamp"),
        "exit_code": proof.get("exit_code"),
        "imported_files": len(proof.get("imported_files") or []),
        "test_files": _runner_test_files(proof, TARGET_REPO),
        "verified": verified,
        "stale": stale,
    }


def update_running_state(detected: dict) -> None:
    """Merge detected running processes into running.json.

    Read-merge-write with file locking. Preserves wrapper entries,
    adds/updates daemon entries, prunes stale PIDs from all sources.
    """
    with open(RUNNING_LOCK_FILE, 'w') as lock_f:
        fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
        try:
            # Read existing state
            existing = {}
            if RUNNING_STATE_FILE.exists():
                try:
                    with open(RUNNING_STATE_FILE, 'r') as f:
                        content = f.read().strip()
                        if content:
                            existing = json.loads(content)
                            # Handle legacy single-script format
                            if isinstance(existing, dict) and 'script' in existing and 'pid' in existing:
                                existing = {str(existing['pid']): existing}
                except Exception:
                    existing = {}

            # Prune stale PIDs and remove old daemon entries not re-detected
            merged = {}
            for pid_str, info in existing.items():
                try:
                    pid = int(info.get('pid', pid_str))
                except (ValueError, TypeError):
                    continue
                if not is_pid_alive(pid):
                    continue
                source = info.get('source', 'wrapper')
                if source == 'daemon':
                    # Only keep if re-detected this cycle
                    if pid_str in detected:
                        merged[pid_str] = detected[pid_str]
                else:
                    # Preserve wrapper entries that are still alive
                    merged[pid_str] = info

            # Add newly detected daemon entries
            for pid_str, info in detected.items():
                if pid_str not in merged:
                    merged[pid_str] = info

            # Write or delete
            if merged:
                with open(RUNNING_STATE_FILE, 'w') as f:
                    json.dump(merged, f)
            elif RUNNING_STATE_FILE.exists():
                RUNNING_STATE_FILE.unlink()
        finally:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)


def load_proof_summary(lp: dict, verified: int) -> dict:
    """A: what the dash says about the eslogger load proof — recording or not (and why), the target runs it
    saw, how many modules it proved (hash still current). An absent file = the launch did not turn it on."""
    if not lp:
        return {'status': 'not run', 'reason': 'load proof off for this launch', 'runs': [], 'verified': 0}
    rec = lp.get('recorder') or {}
    runs = [{k: r.get(k) for k in ('pid', 'node', 'via', 'exited')} for r in (lp.get('runs') or [])]
    status = 'recording' if rec.get('alive') else 'NOT MEASURED'
    return {'status': status, 'reason': None if rec.get('alive') else (rec.get('reason') or 'recorder stopped'),
            'runs': runs, 'verified': verified, 'loaded': len(lp.get('loaded') or {}),
            'started_at': rec.get('started_at')}


def update_runtime_coverage(running_scripts: list, import_map: dict) -> set:
    """Plan item 8 (2026-09-05): "exercised" = recorded at EXECUTION by
    entry_point_wrapper.py — the entry point plus every target module actually
    imported, SHA256 at execution. A module counts only while its current bytes
    still equal the recorded hash: a stale proof is not a proof. The old
    inference (a running script ⇒ all of its STATIC imports "loaded") is gone;
    running_scripts / import_map stay in the signature and are ignored.
    """
    proof = read_file_locked(ENTRY_POINT_INFO_FILE) if ENTRY_POINT_INFO_FILE.exists() else {}
    coverage: set = set()
    verified = stale = outside = 0
    if proof:
        for abspath, recorded in (proof.get("file_hashes") or {}).items():
            p = Path(abspath)
            try:
                current = f"sha256:{hashlib.sha256(p.read_bytes()).hexdigest()}"
            except OSError:
                stale += 1
                continue
            if current == recorded:
                # Run 19 (2026-09-05): coverage is keyed by RELATIVE PATH, never
                # by stem — `__init__` matched every package marker and painted
                # colorama/tests/__init__.py green without a single import.
                try:
                    coverage.add(p.resolve().relative_to(TARGET_REPO.resolve()).as_posix())
                except ValueError:
                    # T-18: one shape — repo-relative paths only. A file outside the target is
                    # not a target module; it is counted (`outside`), never added as a bare stem.
                    outside += 1
                    continue
                verified += 1
            else:
                stale += 1
    # A (owner 2026-10-06, narrow amendment): the eslogger LOAD PROOF — a target run, however it was started,
    # opened these target modules; each hash taken at that open must still match (same stale rule as above).
    lp = read_file_locked(LOAD_PROOF_FILE) if LOAD_PROOF_FILE.exists() else {}
    lp_verified = 0
    if lp and Path(lp.get('target') or '').resolve() == TARGET_REPO.resolve():
        for rel, rec in (lp.get('loaded') or {}).items():
            try:
                current = f"sha256:{hashlib.sha256((TARGET_REPO / rel).read_bytes()).hexdigest()}"
            except OSError:
                stale += 1
                continue
            if current == (rec or {}).get('sha256'):
                coverage.add(rel)
                lp_verified += 1
            else:
                stale += 1
    _LOAD_PROOF_STATE.clear()
    _LOAD_PROOF_STATE.update(load_proof_summary(lp, lp_verified))
    sources = [s for s, on in (('entry_point_wrapper (executed proof)', bool(proof)),
                               ('eslogger load proof', bool(lp_verified))) if on]
    try:
        write_file_locked(RUNTIME_COVERAGE_FILE, {
            'loaded_modules': sorted(coverage),
            'source': ' + '.join(sources) if sources else 'NOT MEASURED — no execution recorded',
            'load_proof_verified': lp_verified,
            'entry_point': proof.get('entry_point'),
            'executed_at': proof.get('executed_at') or proof.get('capture_timestamp'),
            'exit_code': proof.get('exit_code'),
            'verified': verified,
            'stale': stale,
            'outside_target': outside,
            'last_update': datetime.now().isoformat(),
        })
    except Exception as e:
        logging.warning(f"Failed to write runtime coverage: {e}")
    return coverage


# ITEM 11 (2026-09-15, P-1 as ruled B8 / P3): SEVERED LINKS — the daemon is the ONE source of truth.
# A link is LIVE when an import edge's two ends both carry executed proof (hash-verified coverage) or a
# dataflow was seen between them. A link that was live and is not any more is SEVERED and stays severed
# until it is sensed live again or one of its nodes is gone (the owner's transition, 2026-09-10; the
# 2026-09-08 one-frame rule is the choice the owner may flip). The dash draws and names what is published
# here; the Builder copies it into the counterfeit-code mirror as text.
#
# FIX_45 / I-54 (owner Q3, 2026-09-15): "a runner FINISHING is none of these — its flow simply ends;
# only a broken import severs." So the pairs that MAY sever are the IMPORT-live ones; a pair that was
# live only through a sensed dataflow leaves `live` silently when the flow ends.
_PREV_LIVE_LINKS: set = set()
_PREV_IMPORT_LIVE: set = set()   # FIX_45: last frame's SEVERABLE pairs (import edges, both ends proven)
_SEVERED_LINKS: dict = {}   # (src, dst) -> ISO timestamp the pair was first seen severed


def live_links(graph, runtime_coverage, dataflows) -> set:
    """Pairs (src, dst) of daemon names that are LIVE this frame."""
    cov = set(runtime_coverage or ())
    rel = {n.name: n.relative_path for n in graph.nodes}

    def _live(name):
        return name in cov or rel.get(name) in cov

    live = set()
    for src, dst in (graph.edges or []):
        if _live(src) and _live(dst):
            live.add((src, dst))
    names = set(rel)
    for f in dataflows or []:
        src, dst = f.get('src'), f.get('dst')
        if src in names and dst in names and src != dst:
            live.add((src, dst))
    return live


def import_live_links(graph, runtime_coverage) -> set:
    """FIX_45 / I-54 (owner Q3, 2026-09-15): the SEVERABLE pairs — an IMPORT edge whose two ends both
    carry executed proof. A pair that is live only because a dataflow was sensed is NOT severable: a
    test runner's flow ending is not a broken import. One reading of "live", with the dataflow half
    removed, so the two can never drift."""
    return live_links(graph, runtime_coverage, [])


def compute_severed_links(prev_live, current_live, severed, node_names, now=None, severable=None) -> dict:
    """The transition, pure: held = every severed pair still not live with both nodes present;
    new = every pair live last frame and not this frame; a pair leaves the set the frame it is
    live again or a node is gone. Returns {(src, dst): since}.

    FIX_45 / I-54: `severable` (when given) is the set of pairs a NEW sever may come from — the
    import-live pairs of the frame the pair was last green. A pair that drops out of `live` and is
    not in `severable` simply stops being live (its flow ended); it never turns red. HELD pairs keep
    Item 11's rule unchanged, so a pair stays red while its broken side is unparseable and the import
    edge itself has vanished from the graph (ITEM_11 §9's recorded risk)."""
    now = now or datetime.now().isoformat()
    out = {}
    for pair, since in (severed or {}).items():
        if pair not in current_live and pair[0] in node_names and pair[1] in node_names:
            out[pair] = since
    for pair in (prev_live or set()):
        if severable is not None and pair not in severable:
            continue   # I-54: the flow ended; only a broken import severs
        if pair not in current_live and pair not in out and pair[0] in node_names and pair[1] in node_names:
            out[pair] = now
    return out


# ── I-127 / Q1 — SEVERED BY REPAIR (session 8, 2026-09-21) ───────────────────
# Every import edge incident on a file goes red the moment the file's bytes change, and
# re-promotion needs the flow evidence only a re-run gives. Until now every such edge counted
# against `finished`, so a client that repaired anything moved the release's own completion
# signal further away BY repairing it (run 155: `severed_links` 0 → 16 in three bursts, each
# burst dated to the moment the client rewrote one file).
#
# The owner's default: an edge severed AFTER a lease record for one of its two files, where
# the lease's after-text is what that file reads NOW, is `severed_by_repair` — its own count,
# published, still red on the wiring, and OUT of `finished`'s severed input. An edge severed by
# an edit the server never handed out (no lease) stays `severed` and stays in `finished`.
# Re-promotion proper is unchanged: the next entry run re-measures the file by the existing path.
#
# The lease is READ through the server's own reader (`gearbox.read_apply_lease`); nothing here
# re-implements it.

#: Bytes the window search may hash for ONE lease record before it gives up. The first anchor
#: — the lease's own span — costs one pass of the file and answers the ordinary case; the budget
#: only bounds the fallback slide. Over budget the answer is "not proven", which leaves the edge
#: `severed`: the conservative side, and the side it was on before this existed.
_LEASE_SCAN_BUDGET = 8_000_000

_LEASE_SPAN_RE = re.compile(r":L(\d+)-L(\d+)$")


def _span_lines(span: str):
    """`src/click/_compat.py:L120-L134` → `(120, 134)`; anything else → None."""
    m = _LEASE_SPAN_RE.search(str(span or ""))
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    return (a, b) if 0 < a <= b else None


def _as_instant(stamp):
    """One comparable instant from either clock. The lease is stamped
    `datetime.now(timezone.utc)` (AWARE, `+00:00`); `severed_since` is stamped `datetime.now()`
    (NAIVE, this machine's local clock). Compared raw, every sever would read as older than
    every lease by the UTC offset and the classifier would never fire. `astimezone()` reads a
    naive stamp as local and converts an aware one, so both sides end up on one clock."""
    try:
        return datetime.fromisoformat(str(stamp)).astimezone()
    except (TypeError, ValueError):
        return None


def _windows_from(lines, anchor: int, want: str, budget: int):
    """`(found, bytes hashed)` over every window of `lines` that STARTS at `anchor` — height 1,
    then 2, then 3. The height is unknown on purpose: `after_sha256` hashes the text the edit
    PUT THERE, while the lease's span is the height it REPLACED, and a repair is rarely the same
    number of lines as the code it repairs. sha256 does not roll, so each height's digest is
    taken from a copy of the running state and the whole sweep is one pass of the file."""
    running = hashlib.sha256()
    used = 0
    for i in range(anchor, len(lines)):
        chunk = lines[i].encode("utf-8")
        running.update(chunk)
        used += len(chunk)
        if running.copy().hexdigest() == want:
            return True, used
        if used >= budget:
            break
    return False, used


def _lease_after_text_stands(path: Path, record: dict) -> bool:
    """The lease's after-text is what this file reads now.

    `after_sha256` hashes the SPAN the edit replaced it with, not the whole file
    (`coderadar_mcp.write_tools._lease_record`), and the text itself was never recorded — so
    this is hash-only. The lease's own live span is the FIRST anchor and answers the ordinary
    case (rows applied in ascending order never move each other's spans); a later edit ABOVE the
    leased text moves it, and the bounded slide finds it where that edit left it."""
    want = str(record.get("after_sha256") or "")
    if not want:
        return False
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return False
    span = _span_lines(str(record.get("replace_span_live") or record.get("replace_span") or ""))
    first = (span[0] - 1) if span else 0
    budget = _LEASE_SCAN_BUDGET
    for anchor in [first] + [a for a in range(len(lines)) if a != first]:
        if budget <= 0:
            break
        if not 0 <= anchor < len(lines):
            continue
        found, used = _windows_from(lines, anchor, want, budget)
        if found:
            return True
        budget -= used
    return False


def read_target_lease(repo=None) -> dict:
    """The apply lease beside THIS target's return channel, as `{row_key: record}` — the
    server's own reader, on the server's own naming rule (`system_scripts/return_channel_<repo
    id>.jsonl` → `apply_lease_<repo id>.jsonl`). A tree without the coordinator, or a target
    whose channel was never published, leases nothing and the classifier fires on nothing."""
    if _cadence is None:
        return {}
    try:
        repo_path = Path(repo or TARGET_REPO)
        channel = SCRIPT_DIR / f"return_channel_{get_repo_id(repo_path)}.jsonl"
        return _cadence.read_apply_lease(_cadence.apply_lease_path(channel))
    except Exception as e:
        logging.warning(f"SEVERED BY REPAIR: the lease is unreadable ({type(e).__name__}: {e}) — "
                        f"every severed edge stays severed")
        return {}


#: I-146 (owner ruling 2026-09-21): the pairs whose `SEVERED BY REPAIR` line has already been
#: logged for the sever event they are in — the classifier's own `_SEVERED_LINKS`, so the line is
#: written once per bucketed edge and not once per classification pass (the mirror writer classifies
#: every frame). Cleared and refilled from the bucket at the end of every pass.
_SEVERED_BY_REPAIR_LOGGED: set = set()


def classify_severed_by_repair(severed_since, node_files, repo=None, lease=None) -> set:
    """The pairs of `severed_since` a LEASED edit explains. Q1's rule, both halves and no others:

      (a) TIME     — the pair's `severed_since` is at or after the lease record's own timestamp
                     (the sever falls AFTER the server handed that file's bytes out), and
      (b) IDENTITY — that lease record's `after_sha256` is what the file reads now.

    The file is either end of the edge — the sever is the edit's, whichever side of the import
    moved. `node_files` maps a graph node's name to its repo-relative path. Nothing is inferred
    from a file's mtime and nothing from the shape of the edit: no lease, no bucket."""
    repo_path = Path(repo or TARGET_REPO)
    records = read_target_lease(repo_path) if lease is None else lease
    if not records:
        _SEVERED_BY_REPAIR_LOGGED.clear()   # no lease, no bucket: the next one is a new sever event
        return set()
    by_file: dict = {}
    for rec in records.values():
        rel = str(rec.get("file") or "")
        if rel:
            by_file.setdefault(Path(rel).as_posix(), []).append(rec)
    out = set()
    why: dict = {}          # pair -> (rel, lease timestamp, severed_since) for the line below
    for pair, since in (severed_since or {}).items():
        t_sev = _as_instant(since)
        if t_sev is None or len(pair) != 2:
            continue
        for end in pair:
            rel = Path(str(node_files.get(end) or end)).as_posix()
            for rec in by_file.get(rel, ()):
                t_lease = _as_instant(rec.get("timestamp"))
                if t_lease is None or t_sev < t_lease:
                    continue
                if _lease_after_text_stands(repo_path / str(rec.get("file") or ""), rec):
                    out.add(pair)
                    why[pair] = (rel, str(rec.get("timestamp") or ""), str(since))
                    break
            if pair in out:
                break
    # I-146 (2026-09-21, deduped by the owner's ruling of the same day): one line per bucketed EDGE
    # PER SEVER EVENT, in the shape `SEVERED LINK` / `LINK RESTORED` already use — the transition is
    # logged, never the frame (the mirror writer classifies every frame). Run 162 left no line at all:
    # both archived frames fell outside the window and nothing named the classifier.
    for pair in sorted(out - _SEVERED_BY_REPAIR_LOGGED):
        rel, stamp, since = why[pair]
        logging.info(f"SEVERED BY REPAIR: {pair[0]} -> {pair[1]} — severed {since}, at or after the "
                     f"apply lease for {rel} ({stamp}), whose after-text is what the file reads now; "
                     f"still red on the wiring and out of `finished`'s severed input")
    # The dedupe state, kept the way `_SEVERED_LINKS` is kept: what is in the bucket NOW. An edge
    # that leaves the bucket and is bucketed again later is a new sever event and logs again.
    _SEVERED_BY_REPAIR_LOGGED.clear()
    _SEVERED_BY_REPAIR_LOGGED.update(out)
    return out


def update_severed_links(graph, runtime_coverage, dataflows) -> dict:
    """One frame of the transition on the module state; logs each change."""
    current = live_links(graph, runtime_coverage, dataflows)
    current_imports = import_live_links(graph, runtime_coverage)
    names = {n.name for n in graph.nodes}
    # FIX_45 / I-54: a new sever may only come from a pair that was import-live LAST frame — the frame
    # the pair was last green through a hash-verified import on both sides.
    new = compute_severed_links(_PREV_LIVE_LINKS, current, _SEVERED_LINKS, names,
                                severable=_PREV_IMPORT_LIVE)
    for pair in new:
        if pair not in _SEVERED_LINKS:
            logging.warning(f"SEVERED LINK: {pair[0]} -> {pair[1]} (was live; a side is broken or the flow stopped)")
    for pair in _SEVERED_LINKS:
        if pair not in new:
            logging.info(f"LINK RESTORED: {pair[0]} -> {pair[1]}")
    # I-54 made visible rather than silent: a pair that was live, is not any more, and was never
    # import-live — a runner's (or any) dataflow that simply ended. Never red, always logged.
    for pair in _PREV_LIVE_LINKS:
        if pair not in current and pair not in new and pair not in _PREV_IMPORT_LIVE:
            logging.info(f"FLOW ENDED: {pair[0]} -> {pair[1]} (a sensed flow stopped; not a severed link — owner Q3, I-54)")
    _SEVERED_LINKS.clear(); _SEVERED_LINKS.update(new)
    _PREV_LIVE_LINKS.clear(); _PREV_LIVE_LINKS.update(current)
    _PREV_IMPORT_LIVE.clear(); _PREV_IMPORT_LIVE.update(current_imports)
    return new


_TB_FRAME_RE = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>.+)$')


def execution_proof_summary() -> dict:
    """What the last wrapper execution proved, for circuit_state (plan item 8):
    entry point, when, exit code, files exercised (verified / stale), and the
    exception with its traceback frames inside the target — the origin
    tracer's feed."""
    proof = read_file_locked(ENTRY_POINT_INFO_FILE) if ENTRY_POINT_INFO_FILE.exists() else {}
    if not proof:
        logging.debug("measured nothing (%s): %s", 'execution_proof_summary', 'not proof')  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → reported
        return {"status": "NOT MEASURED — no execution recorded (run the target through entry_point_wrapper.py)"}
    cov = read_file_locked(RUNTIME_COVERAGE_FILE) if RUNTIME_COVERAGE_FILE.exists() else {}
    root = str(proof.get("target_root") or "")
    exc = proof.get("exception_info") or None
    frames = []
    if exc:
        # format_exception() entries carry the source line after a newline —
        # match frame headers line by line.
        for entry in exc.get("traceback_lines") or []:
            for line in str(entry).split("\n"):
                m = _TB_FRAME_RE.match(line)
                if m and (not root or m.group("file").startswith(root)):
                    frames.append({"file": m.group("file"), "line": int(m.group("line")), "function": m.group("func")})
    return {
        "status": "MEASURED",
        "entry_point": proof.get("entry_point"),
        "entry_point_abspath": proof.get("entry_point_abspath"),
        "executed_at": proof.get("executed_at") or proof.get("capture_timestamp"),
        "captured_at": proof.get("capture_timestamp"),
        "exit_code": proof.get("exit_code"),
        "imported_files": len(proof.get("imported_files") or []),
        "verified": cov.get("verified"),
        "stale": cov.get("stale"),
        "exception": ({"type": exc.get("type"), "message": exc.get("message"), "frames": frames} if exc else None),
    }


def cleanup_running_state() -> None:
    """Remove all daemon-detected entries from running.json on shutdown."""
    try:
        with open(RUNNING_LOCK_FILE, 'w') as lock_f:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
            try:
                if not RUNNING_STATE_FILE.exists():
                    return
                with open(RUNNING_STATE_FILE, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        return
                    state = json.loads(content)

                # Keep only non-daemon entries that are still alive
                kept = {}
                for pid_str, info in state.items():
                    source = info.get('source', 'wrapper')
                    if source != 'daemon':
                        try:
                            pid = int(info.get('pid', pid_str))
                            if is_pid_alive(pid):
                                kept[pid_str] = info
                        except (ValueError, TypeError):
                            continue

                if kept:
                    with open(RUNNING_STATE_FILE, 'w') as f:
                        json.dump(kept, f)
                elif RUNNING_STATE_FILE.exists():
                    RUNNING_STATE_FILE.unlink()
            finally:
                fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass


# Configure logging
def setup_logging():
    """Configure logging with rotation and proper formatting."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    logger.handlers = []

    # File handler with rotation (10MB max, keep 5 backups)
    file_handler = RotatingFileHandler(
        DAEMON_LOG,
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(console_handler)


def get_config():
    """Read all configuration from poll_config.json."""
    defaults = {
        'interval_ms': DEFAULT_PING_INTERVAL * 1000,
        'syntax_timeout': DEFAULT_SYNTAX_TIMEOUT,
        'import_timeout': DEFAULT_IMPORT_TIMEOUT,
        # FIX_35 p (2026-09-15): the dead `max_depth: 4` default deleted — the scanner is forced to None every cycle ("Scan depth: unlimited")
    }
    try:
        if POLL_CONFIG_FILE.exists():
            with open(POLL_CONFIG_FILE) as f:
                config = json.load(f)
                return {**defaults, **config}
    except Exception:
        pass
    return defaults


def get_ping_interval():
    """Read ping interval from shared config file, or use default."""
    config = get_config()
    return config['interval_ms'] / 1000.0


def read_launch_control() -> dict:
    """Item 7 (2026-09-10): the launch control block launch.sh wrote into poll_config.json —
    `{tracer: "eslogger"|"lsof", trackers: [str], chosen_at: iso}` — shape-validated.
    Returns {"ok": True, "control": block, "reason": ""} or {"ok": False, "control": None,
    "reason": <why>}. Never a default: an absent or malformed block is a refusal to run
    (run_daemon publishes daemon_phase ERROR and exits 2). The health check calls this offline
    with no launch in flight and reads the dict, not the block."""
    try:
        if not POLL_CONFIG_FILE.exists():
            return {"ok": False, "control": None,
                    "reason": "launch_control absent — no poll_config.json; launch through launch.sh --tracer …"}
        with open(POLL_CONFIG_FILE) as f:
            cfg = json.load(f)
    except Exception as e:
        return {"ok": False, "control": None, "reason": f"poll_config.json unreadable: {type(e).__name__}: {e}"}
    block = cfg.get("launch_control") if isinstance(cfg, dict) else None
    if not isinstance(block, dict):
        return {"ok": False, "control": None,
                "reason": "launch_control absent — launch through launch.sh --tracer eslogger|lsof"}
    tracer = block.get("tracer")
    if tracer not in ("eslogger", "lsof"):
        return {"ok": False, "control": None, "reason": f"launch_control.tracer must be eslogger|lsof, got {tracer!r}"}
    trackers = block.get("trackers")
    if not isinstance(trackers, list) or any(not isinstance(t, str) for t in trackers):
        return {"ok": False, "control": None, "reason": "launch_control.trackers must be a list of strings"}
    bad = [t for t in trackers if t not in _TRACKER_TOKENS]
    if bad:
        return {"ok": False, "control": None,
                "reason": f"launch_control.trackers has unknown token(s) {bad} — allowed: {list(_TRACKER_TOKENS)}"}
    chosen_at = block.get("chosen_at")
    if not isinstance(chosen_at, str) or not chosen_at:
        return {"ok": False, "control": None, "reason": "launch_control.chosen_at missing"}
    return {"ok": True,
            "control": {"tracer": tracer, "trackers": list(trackers), "chosen_at": chosen_at},
            "reason": ""}


def _tracker_status(results, token: str, ran_key: str | None = None):
    """Item 7: stamp a tracker's published shape with its `status` — "measured" when the launch
    chose it, "not run — nothing measured" when it did not (an empty shape, never a silent zero).
    R4: a chosen tracker whose tool is missing or failed carries `not_measured_reason`; its
    status is then "NOT MEASURED — <reason>", never "measured"."""
    d = dict(results) if isinstance(results, dict) else {}
    if token not in _TRACKERS:
        d['status'] = _NOT_RUN
    elif d.get('not_measured_reason'):
        d['status'] = f"{_NOT_MEASURED} — {d['not_measured_reason']}"
    else:
        d['status'] = 'measured'
    return d


def _tracker_not_measured(token: str, results) -> str | None:
    """R4: the reason a CHOSEN tracker measured nothing, or None (it measured, or was not
    chosen — that is `not_run`). One reading for the circuit state, the mirror and the MCP."""
    if token not in _TRACKERS:
        return None
    return (results or {}).get('not_measured_reason') or None


def _cycle_s_now():
    """I-90: seconds from this poll's start to now (the frame write); remembered as the cycle's length."""
    t0 = _CYCLE_CLOCK.get('t0')
    if not t0:
        return None
    c = round(time.monotonic() - t0, 3)
    if _CYCLE_CLOCK.get('last_t0') != t0:        # first write of this poll
        _CYCLE_CLOCK['last_t0'] = t0
        _CYCLE_CLOCK['last'] = c
    else:                                        # a later write of the same poll
        _CYCLE_CLOCK['last'] = max(c, _CYCLE_CLOCK.get('last', 0.0))
    return c


def write_circuit_state(graph, repo_id: str, runtime_coverage=None,
                        path_hacks=None,
                        crc_results=None, mypy_results=None, contract_violations=None,
                        contract_decorators=None, io_tracker_results=None,
                        dataflows=None, vulture_results=None,
                        daemon_phase: str = "RUNNING",
                        launch_control=None, tracer=None, trackers=None,
                        error_reason=None, test_runners=None, runner_coverage=None,
                        severed_links=None, scan_cadence=None):
    """Write circuit graph state to JSON file for dashboard consumption.

    This is the SINGLE SOURCE OF TRUTH that the dashboard reads.
    The dashboard should NOT parse log files.

    Args:
        graph: CircuitGraph from ast_scanner
        repo_id: Current repo identifier
        runtime_coverage: Set of modules that have been loaded at runtime
        path_hacks: Dict of detected path manipulation hacks
        crc_results: CRC frozen function check results
        mypy_results: mypy type check results
        contract_violations: Contract violation data
        daemon_phase: Lifecycle phase — INIT → READY → RUNNING (ERROR: refused to run)
        launch_control: Item 7 — the block launch.sh wrote (echoed here, read-only for the dash)
        tracer: Item 7 — {backend, alive, chosen_at, reason}
        trackers: Item 7 — {chosen[], not_run[]}
        error_reason: Item 7 — only with daemon_phase ERROR
    """
    nodes = graph.nodes
    _rc = set(runner_coverage if runner_coverage is not None else _RUNNER_COVERAGE)
    _tr = test_runners if test_runners is not None else _TEST_RUNNERS

    def _loaded_via(n):
        # Item 10: how a node earned its green — the app's proof, a runner's (a warning), both, or none
        app = (n.relative_path in (runtime_coverage or set())) or (n.name in (runtime_coverage or set()))
        run = (n.relative_path in _rc) or (n.name in _rc)
        return "app+runner" if app and run else ("app" if app else ("runner" if run else None))

    state = {
        'daemon_phase': daemon_phase,
        # Item 7: every write carries the launch control and the tracer / trackers facts
        # (module state set by run_daemon; an explicit argument wins).
        'launch_control': launch_control if launch_control is not None else _LAUNCH_CONTROL,
        'tracer': tracer if tracer is not None else dict(_TRACER_STATE),
        # M-48 / C: target runs seen in the process table this frame — a sighting, not proof of what ran
        'outside_runs': list(_OUTSIDE_RUNS),
        'load_proof': dict(_LOAD_PROOF_STATE),   # A: eslogger load proof — recording?, runs seen, modules proven
        'trackers': trackers or {'chosen': sorted(_TRACKERS) + list(_PERMANENT_TRACKERS),   # ND1: permanent, always chosen
                                 'not_run': [t for t in _TRACKER_TOKENS if t not in _TRACKERS],
                                 # R4: chosen, but the tool is missing or failed — token → reason
                                 'not_measured': {t: r for t, r in (
                                     ('io', _tracker_not_measured('io', io_tracker_results)),
                                     ('mypy', _tracker_not_measured('mypy', mypy_results)),
                                     ('crc', _tracker_not_measured('crc', crc_results)),
                                     ('vulture', _tracker_not_measured('vulture', vulture_results)),
                                     ('naming_drift', _naming_drift_not_measured()),
                                     ('pytest', _pytest_block().get('reason')),
                                 ) if r}},
        'repo_id': repo_id,
        'target_repo': str(TARGET_REPO),
        'scan_timestamp': graph.scan_timestamp,
        # FIX_39 (owner Q1): the per-directory scan cadence — files, period, phase, viewed — the dash
        # prints it in the band. Absent (None) before the first cadence plan; never an empty dict
        # standing in for "no cadence".
        'scan_cadence': scan_cadence,
        # I-90 / Q1: this frame's MEASURED cycle (poll start -> this write), seconds — the dash's
        # frame-stale threshold scales with it (electricity.stale_threshold_s), no cap.
        'cycle_s': _cycle_s_now(),
        'cycle_max_s': (round(max(_CYCLE_HISTORY + [_CYCLE_CLOCK.get('last', 0.0)]), 3)
                        if _CYCLE_CLOCK.get('t0') else None),
        'sys_path': sys.path[:10],  # First 10 entries
        'nodes': [
            {
                'name': n.name,
                'relative_path': n.relative_path,
                'connected': n.connected,
                'imports': list(n.imports),
                'syntax_valid': n.syntax_valid,
                # FIX_53 (2026-09-17): unparsable BY DESIGN (a shipped lexer/parser fixture, by
                # pattern) — connected stays True and the WIRING gate reads this field.
                'syntax_fixture': getattr(n, 'syntax_fixture', False),
                'import_error': n.import_error,
                'content_hash': n.content_hash,
                'subdir': n.subdir,
                'change_tags': [
                    {'lines': tag.lines, 'timestamp': tag.timestamp}
                    for tag in (n.change_tags or [])
                ],
                'runtime_loaded': (n.relative_path in (runtime_coverage or set())) or (n.name in (runtime_coverage or set())),
                'runtime_loaded_via': _loaded_via(n),   # Item 10: "app" | "runner" | "app+runner" | None
            }
            for n in nodes
        ],
        'edges': graph.edges,
        'cycles': graph.cycles,
        'all_connected': all(n.connected for n in nodes),
        # ITEM 11: the severed set, computed here every frame (update_severed_links) — one source of truth
        'severed_links': [list(p) for p in sorted((severed_links if severed_links is not None else _SEVERED_LINKS))],
        'severed_since': {f'{p[0]}->{p[1]}': t for p, t in sorted((severed_links if isinstance(severed_links, dict) else _SEVERED_LINKS).items())},
        'runtime_coverage': sorted(runtime_coverage) if runtime_coverage else [],   # repo-relative paths
        'execution_proof': {**execution_proof_summary(),   # plan item 8: what was EXECUTED, hash-verified
                            'via_runner': runner_proof_summary()},   # Item 10: the runner's own record, beside it — never over it
        'runner_coverage': sorted(_rc),          # Item 10: files a runner's record proves imported (hash-verified) — a warning, never a pass
        'test_runners': _tr,                     # Item 10: presence (imports / fixtures / marks / conftest / TestCase / config) + execution (wrapper / ps / kernel)
        'path_hacks': {
            file: [
                {
                    'line': hack.line,
                    'type': hack.type,
                    'details': hack.details,
                    # FIX_49 / FIX_50 (2026-09-17): the disposition is DATA (rule_dispositions.json
                    # `path_hacks`, resolved per (type, context) — e.g. role: entry). 'context' =
                    # informational: published with its warning, never counted as an infraction.
                    'disposition': getattr(hack, 'disposition', 'deciding'),
                    'warning': getattr(hack, 'warning', ''),
                }
                for hack in hacks
            ]
            for file, hacks in (path_hacks or {}).items()
        },
        'crc_results': _tracker_status(crc_results or {}, 'crc'),
        'mypy_results': _tracker_status(mypy_results or {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0, 'total_errors': 0, 'errors': [], 'errors_by_dir': {}, 'recent_checks': [], 'last_scan': None, 'mypy_rc': None, 'mypy_ran': False}, 'mypy'),
        'contract_violations': contract_violations or {'total': 0, 'violations': [], 'disabled': True},
        'contract_decorators': contract_decorators or [],
        'io_tracker_results': _tracker_status(io_tracker_results or {'totals': {'total_functions': 0, 'async_count': 0, 'sync_count': 0, 'io_functions': 0, 'sync_exempt_count': 0}, 'details': []}, 'io'),
        'dataflows': dataflows or [],
        'vulture_results': _tracker_status(vulture_results or _vulture_zero_dict(), 'vulture'),
    }
    if error_reason is not None:
        state['error_reason'] = error_reason   # Item 7: only with daemon_phase ERROR

    write_file_locked(CIRCUIT_STATE_FILE, state)


def write_refusal_state(reason: str) -> None:
    """C2 / Q-H0-7 (2026-10-01): the ERROR record for a refusal BEFORE any graph exists (T-12: no target in
    poll_config). write_circuit_state needs a graph and a repo id; this writes the same `daemon_phase` /
    `error_reason` the dash's launch-control chip reads ("circuit daemon REFUSED: …") with no graph and no
    target — the state says why, instead of the file being absent. Never raises: a refusal is already
    on its way to exit 2, and a record that cannot be written is logged."""
    state = {
        'daemon_phase': 'ERROR',
        'error_reason': reason,
        'launch_control': None,
        'tracer': dict(_TRACER_STATE),
        'trackers': {'chosen': list(_PERMANENT_TRACKERS), 'not_run': list(_TRACKER_TOKENS),
                     'not_measured': {'naming_drift': 'launch refused before the scan ran',
                                      'pytest': 'launch refused before the scan ran'}},
        'repo_id': None,
        'target_repo': None,
        'scan_timestamp': None,
        'refused_at': datetime.now().isoformat(),
    }
    try:
        write_file_locked(CIRCUIT_STATE_FILE, state)
        logging.error(f"TARGET: refusal recorded in {CIRCUIT_STATE_FILE.name} (daemon_phase ERROR)")
    except Exception as e:
        logging.error(f"TARGET: refusal NOT recorded in {CIRCUIT_STATE_FILE.name} ({type(e).__name__}: {e})")


def log_graph_status(graph):
    """Log circuit status from a CircuitGraph in the format the dashboard expects.

    Args:
        graph: CircuitGraph from ast_scanner
    """
    nodes = graph.nodes

    if not nodes:
        logging.info("NO SCRIPTS: No Python scripts found in target repo")
        return False

    all_connected = True

    for node in nodes:
        imports_str = ','.join(sorted(node.imports)) if node.imports else ''

        if node.connected:
            logging.info(f"CONNECTED {node.relative_path}: OK IMPORTS[{imports_str}]")
        else:
            error = node.import_error or 'Unknown'
            if 'NameError' in error:
                logging.info(f"BROKEN {node.relative_path}: Missing import/reference")
            elif 'ImportError' in error or 'ModuleNotFoundError' in error:
                if node.imports:
                    logging.info(f"BROKEN {node.relative_path}: Import failed EXPECTED[{imports_str}]")
                else:
                    logging.info(f"BROKEN {node.relative_path}: Import failed")
            elif 'Missing local modules' in error:
                logging.info(f"BROKEN {node.relative_path}: {error}")
            else:
                err_lines = error.split('\n') if error else []
                err_msg = err_lines[-2] if len(err_lines) >= 2 else (err_lines[-1] if err_lines else 'Unknown')
                logging.info(f"BROKEN {node.relative_path}: {err_msg}")
            all_connected = False

    return all_connected


def _clear_stale_session_data():
    """Clear daemon log if TARGET_REPO changed.

    Reads the last 'REPO_ID:' line from the existing daemon log. If it
    doesn't match current TARGET_REPO's ID, all session
    artifacts are wiped so stale results never bleed across targets.

    MUST be called BEFORE setup_logging() to avoid file handle conflicts.
    """
    current_repo_id = get_repo_id(TARGET_REPO)
    previous_repo_id = None

    if DAEMON_LOG.exists():
        try:
            with open(DAEMON_LOG, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    for line in f:
                        if 'REPO_ID:' in line:
                            # F28 (slot 12): daemon_log.txt appends across runs —
                            # keep the LAST match (most recent run), not the first,
                            # so an A->B->A boot sequence still purges B's state.
                            previous_repo_id = line.split('REPO_ID:')[-1].strip()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

    if previous_repo_id and previous_repo_id != current_repo_id:
        print(f"Target changed: repo ID {previous_repo_id} -> {current_repo_id}")
        print("Clearing stale session data from previous target")

        if DAEMON_LOG.exists():
            try:
                DAEMON_LOG.unlink()
            except Exception:
                pass

        # Clear circuit state JSON (dashboard reads this)
        if CIRCUIT_STATE_FILE.exists():
            try:
                CIRCUIT_STATE_FILE.unlink()
            except Exception:
                pass

        _purge_circuit_state_files()

        return True
    return False


def _purge_circuit_state_files():
    """Delete circuit_daemon-owned state files (except protected caches)."""
    for f in (
        SCRIPT_DIR / '.monitor_state.json',
        RUNNING_STATE_FILE,
        RUNTIME_COVERAGE_FILE,
        DAEMON_LOG_DIR / "change_tag_overflow.log",
    ):
        if f.exists():
            try:
                f.unlink()
            except Exception:
                pass


def run_daemon():
    """Main daemon loop with AST-based circuit scanning."""
    global TARGET_REPO

    # Clear stale data BEFORE setting up logging (avoids file handle conflicts)
    _clear_stale_session_data()

    setup_logging()

    if get_target_repo_from_config() is None:
        # T-12: refuse — the daemon never falls back to scanning CodeRadar itself
        reason = "poll_config.json names no target_repo (CodeRadar is never its own default target)"
        logging.error(f"TARGET: refusing to start — {reason} (phase ERROR, exit 2)")
        write_refusal_state(reason)   # C2 / Q-H0-7: the dash reads WHY, not "circuit state absent"
        sys.exit(2)

    repo_id = get_repo_id(TARGET_REPO)
    config = get_config()

    # Load the per-target whitelist artifact (virtual stripper — insertion point ①)
    whitelist_files = load_whitelist(TARGET_REPO)
    if whitelist_files:
        logging.info(f"WHITELIST: {len(whitelist_files)} entries loaded for "
                     f"{get_repo_id(TARGET_REPO)}: {', '.join(sorted(whitelist_files))}")
    else:
        logging.info("WHITELIST: no whitelist artifact for this target (scan surface unfiltered)")

    # Create the shared AST scanner
    scanner = CircuitScanner(
        repo_path=str(TARGET_REPO),
        project_root=str(PROJECT_ROOT),
        syntax_timeout=config.get('syntax_timeout', DEFAULT_SYNTAX_TIMEOUT),
        import_timeout=config.get('import_timeout', DEFAULT_IMPORT_TIMEOUT),
        exclude_relpaths=whitelist_files,
    )

    # Start observability endpoint (health/metrics)
    _obs = None
    if _OBSERVABILITY_AVAILABLE:
        try:
            # Copy setup (2026-09-10): the health port comes from copy_ports.json so a
            # copy never binds — or reads — the original's endpoint (8051 in the original).
            from engine_utils import _DEFAULT_HEALTH_PORT as _health_port
            _obs = Observability(port=_health_port)
            logging.info(f"Observability endpoint started on :{_health_port}")
        except Exception as e:
            logging.warning(f"Observability unavailable: {e}")

    logging.info("=" * 40)
    logging.info("Circuit Daemon Started")
    logging.info(f"REPO_ID: {repo_id}")
    logging.info(f"Monitoring: {TARGET_REPO}")
    logging.info(f"Mode: AST SCANNER (ast_scanner.CircuitScanner)")

    logging.info(f"Ping interval: {get_ping_interval()}s (dynamic from dashboard)")
    logging.info(f"Syntax timeout: {config.get('syntax_timeout', DEFAULT_SYNTAX_TIMEOUT)}s")
    logging.info(f"Import timeout: {config.get('import_timeout', DEFAULT_IMPORT_TIMEOUT)}s")

    # Item 7 (2026-09-10): the dataflow backend / the trackers are all
    # decided by the launch control block — read below, right after the INIT write. Nothing
    # here reads an environment switch or the effective uid to pick a backend any more.

    logging.info("Press Ctrl+C to stop")
    logging.info("=" * 40)

    # Initialize before first write_circuit_state call
    dataflows = []  # Active kernel-traced data flows

    # Initial AST scan
    logging.info("AST SCAN: Initial scan starting...")
    graph = scanner.get_full_graph(force_refresh=True)
    logging.info(f"AST SCAN: Complete - {len(graph.nodes)} scripts, {len(graph.edges)} edges")
    if graph.cycles:
        for cycle in graph.cycles:
            logging.info(f"AST SCAN: Circular dependency: {' -> '.join(cycle)}")

    # Write initial state to JSON (dashboard reads this, not the log)
    write_circuit_state(graph, repo_id, dataflows=[], daemon_phase="INIT")
    logging.info(f"Circuit state written to: {CIRCUIT_STATE_FILE}")

    # --- Item 7: the launch control — REQUIRED; absent or invalid = refuse to run ---
    global ENABLE_VULTURE, _TRACKERS, _LAUNCH_CONTROL, _TRACER_STATE, _NAMING_DRIFT, _NAMING_DRIFT_WHY
    lc_read = read_launch_control()
    if not lc_read["ok"]:
        logging.error(f"LAUNCH CONTROL: {lc_read['reason']} — daemon refuses to run (phase ERROR, exit 2)")
        write_circuit_state(graph, repo_id, dataflows=[], daemon_phase="ERROR",
                            error_reason=lc_read["reason"])
        if _obs:
            try:
                _obs.stop()
            except Exception:
                pass
        sys.exit(2)
    lc = lc_read["control"]
    _LAUNCH_CONTROL = lc
    _TRACKERS = frozenset(lc["trackers"])
    ENABLE_VULTURE = 'vulture' in _TRACKERS
    logging.info(f"LAUNCH CONTROL: tracer={lc['tracer']} "
                 f"trackers={','.join(sorted(_TRACKERS)) or 'none'} chosen_at={lc['chosen_at']}")
    for _tok in _TRACKER_TOKENS:
        logging.info(f"TRACKER {_tok}: {'chosen' if _tok in _TRACKERS else _NOT_RUN}")

    # --- Item 7: the dataflow backend, exactly the one chosen — no fallback in either direction ---
    eslogger_monitor = None
    async_bridge = None
    backend = lc["tracer"]
    _TRACER_STATE = {'backend': backend, 'alive': False, 'chosen_at': lc['chosen_at'], 'reason': ''}

    def _refuse(reason: str):
        logging.error(f"DATAFLOW: {reason} — daemon refuses to run (phase ERROR, exit 2)")
        _TRACER_STATE.update({'alive': False, 'reason': reason})
        write_circuit_state(graph, repo_id, dataflows=[], daemon_phase="ERROR", error_reason=reason)
        if _obs:
            try:
                _obs.stop()
            except Exception:
                pass
        sys.exit(2)

    if backend == "eslogger":
        if os.geteuid() != 0:
            _refuse(f"tracer eslogger chosen but euid={os.geteuid()} (eslogger needs root: sudo ./launch.sh … --tracer eslogger)")
        if not _ESLOGGER_AVAILABLE:
            _refuse("tracer eslogger chosen but tracer.py / EsloggerMonitor is not importable")
        logging.info(f"DATAFLOW: backend=eslogger (chosen at launch), euid={os.geteuid()}, starting...")
        try:
            async_bridge = _AsyncBridge()
            async_bridge.start()
            # Try full events first, retry without TCP socket events if it fails
            eslogger_monitor = EsloggerMonitor(repo=TARGET_REPO)
            started = async_bridge.run(eslogger_monitor.start())
            if not started:
                # Retry without TCP socket events (not on all macOS versions)
                _TCP_EVENTS = {"bind", "connect", "listen", "accept"}
                from tracer import _ESLOGGER_EVENTS
                core_events = [e for e in _ESLOGGER_EVENTS if e not in _TCP_EVENTS]
                logging.info("DATAFLOW: Retrying without TCP socket events...")
                eslogger_monitor = EsloggerMonitor(
                    repo=TARGET_REPO,
                    event_config={"events": core_events}
                )
                started = async_bridge.run(eslogger_monitor.start())
        except Exception as e:
            started = False
            logging.warning(f"DATAFLOW: EsloggerMonitor init error: {e}")
        if not started:
            _refuse("tracer eslogger chosen but EsloggerMonitor failed to start (no fallback to lsof by design)")
        _TRACER_STATE.update({'alive': True, 'reason': 'EsloggerMonitor started'})
        logging.info("DATAFLOW: EsloggerMonitor started")
    else:  # lsof
        if not shutil.which('lsof'):
            _refuse("tracer lsof chosen but no lsof on PATH")
        _TRACER_STATE.update({'alive': True, 'reason': f"lsof at {shutil.which('lsof')}"})
        logging.info(f"DATAFLOW: backend=lsof (chosen at launch) — {shutil.which('lsof')}")

    # --- CRC Engine ---
    logging.info(f"HARNESS_AVAILABLE = {HARNESS_AVAILABLE}")
    crc_engine = None
    crc_results = {}
    if 'crc' not in _TRACKERS:
        logging.info(f"CRC: {_NOT_RUN} (not in --trackers at launch)")
    elif HARNESS_AVAILABLE and CRCEngine:
        crc_engine = CRCEngine()
        # Single *usable baseline* determination (fix #1): a baseline is usable
        # iff the file exists AND loads AND has non-empty functions. Anything
        # else (missing / unreadable / empty) falls through to create_baseline
        # — an exists-but-empty legacy file can no longer deadlock the create
        # path, and a failed load recreates instead of disabling CRC.
        loaded = CRC_BASELINE_PATH.exists() and crc_engine.load_baseline(CRC_BASELINE_PATH)
        if loaded and crc_engine.baseline.functions:
            # Check if baseline belongs to current target repo
            # If no file paths match the target, it's stale — recreate
            target_str = str(TARGET_REPO)
            baseline_matches = any(
                f.startswith(target_str) or (TARGET_REPO / f).exists()
                for f in crc_engine.baseline.functions
            )
            if not baseline_matches and crc_engine.baseline.functions:
                logging.info(f"CRC: Baseline is from a different target, recreating for {TARGET_REPO}")
                crc_engine.create_baseline([TARGET_REPO], CRC_BASELINE_PATH)
            elif crc_engine.baseline.frozen:
                # Purge frozen entries that belong to a different target
                stale_frozen = {
                    entry for entry in crc_engine.baseline.frozen
                    if not entry.split("::")[0].startswith(target_str)
                }
                if stale_frozen:
                    logging.info(f"CRC: Removing {len(stale_frozen)} frozen entries from other targets")
                    crc_engine.baseline.frozen -= stale_frozen
                    crc_engine._save_baseline(crc_engine.baseline, CRC_BASELINE_PATH)

            total_funcs = sum(len(funcs) for funcs in crc_engine.baseline.functions.values())
            frozen_count = len(crc_engine.baseline.frozen)
            logging.info(f"Baseline loaded: {total_funcs} functions, {frozen_count} frozen")
        else:
            if not CRC_BASELINE_PATH.exists():
                cause = "missing"
            elif not loaded:
                cause = "unreadable"
            else:
                cause = "empty"
            logging.warning(f"CRC: Baseline {cause} — creating from {TARGET_REPO}")
            try:
                crc_engine.create_baseline([TARGET_REPO], CRC_BASELINE_PATH)
                logging.info(f"CRC: Baseline created at {CRC_BASELINE_PATH}")
            except Exception as e:
                # R4: a crashed baseline build is NOT MEASURED with its reason — not a daemon crash
                logging.error(f"CRC: baseline build failed: {e}")
                crc_engine = None
                crc_results = {'not_measured_reason': f"CRC baseline build crashed: {type(e).__name__}: {e}"}
    else:
        logging.info("CRC: mypy_n_contracts_watcher not available, CRC disabled")
        # R4: chosen but unrunnable is NOT MEASURED with its reason — never an empty "measured"
        crc_results = {'not_measured_reason': f"CRC engine not available "
                                              f"(mypy_n_contracts_watcher failed to load: {_HARNESS_ERROR})"}

    # --- Contracts still disabled (panel kept for visual continuity) ---
    contract_decorator_list = []
    contract_data = {'total': 0, 'recent_count': 0, 'violations': [], 'disabled': True}
    logging.info("CONTRACTS: Disabled (scanning logic removed)")

    # --- Initial mypy scan on startup ---
    mypy_results = {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0, 'total_errors': 0,
                    'errors': [], 'errors_by_dir': {}, 'recent_checks': [], 'last_scan': None,
                    'mypy_rc': None, 'mypy_ran': False}
    if 'mypy' in _TRACKERS:
        logging.info("MYPY: Running initial full scan on startup...")
        scan = run_mypy_scan()
        # T-18: this IS the first pass — the poll loop must not run mypy again in the same second
        _FIRST_PASS_DONE['mypy'] = True
        if scan:
            mypy_results.update(scan)   # R4: a not-measured scan keeps its reason (never dropped)
        if scan and scan.get('not_measured_reason'):
            logging.warning(f"MYPY: NOT MEASURED — {scan['not_measured_reason']}")
        elif scan and scan.get('files_checked'):
            logging.info(f"MYPY: Initial - {scan['files_checked']} files, "
                         f"{scan['passed']} passed, {scan['failed']} failed")
        else:
            logging.warning("MYPY: Initial scan returned no results")
    else:
        logging.info(f"MYPY: {_NOT_RUN} (not in --trackers at launch)")
    mypy_pending_files: Set[str] = set()

    # --- Initial I/O tracker scan on startup ---
    io_tracker_results: Dict[str, Any] = {}
    if 'io' in _TRACKERS:
        logging.info("IO TRACKER: Running initial scan on startup...")
        try:
            io_tracker_results = scan_io_functions(TARGET_REPO)
            totals = io_tracker_results.get('totals', {})
            logging.info(
                f"IO TRACKER: {totals.get('total_functions', 0)} functions "
                f"({totals.get('async_count', 0)} async, {totals.get('sync_count', 0)} sync), "
                f"{totals.get('io_functions', 0)} with I/O patterns"
            )
        except Exception as e:
            logging.warning(f"IO TRACKER: Initial scan error: {e}")
            io_tracker_results = {'not_measured_reason': f"io scan crashed: {type(e).__name__}: {e}"}
    else:
        logging.info(f"IO TRACKER: {_NOT_RUN} (not in --trackers at launch)")

    # --- Initial vulture dead code scan on startup ---
    vulture_results = _vulture_zero_dict()
    vulture_pending_files: Set[str] = set()
    if ENABLE_VULTURE:
        logging.info("VULTURE: Running initial dead code scan on startup...")
        vscan = run_vulture_scan()
        _FIRST_PASS_DONE['vulture'] = True   # T-18: the startup scan is the first pass (no rerun)
        if vscan:
            vulture_results.update(vscan)
        if vscan and vscan.get('not_measured_reason'):
            logging.warning(f"VULTURE: NOT MEASURED — {vscan['not_measured_reason']}")
        elif vscan and vscan.get('files_scanned'):
            logging.info(f"VULTURE: Initial - {vscan['files_scanned']} files, "
                         f"{vscan['total_items']} dead code items")
        else:
            logging.warning("VULTURE: Initial scan returned no results")
    else:
        logging.info(f"VULTURE: {_NOT_RUN} (not in --trackers at launch)")

    # Write state with initial scan results
    write_circuit_state(graph, repo_id, crc_results=crc_results,
                        mypy_results=mypy_results,
                        contract_violations=contract_data,
                        io_tracker_results=io_tracker_results, dataflows=[],
                        vulture_results=vulture_results,
                        daemon_phase="INIT")
    write_repo_mirror(graph, {}, mypy_results, io_tracker_results, vulture_results)

    # --- Initial CRC scan on startup (don't wait 20 cycles) ---
    if crc_engine and crc_engine.baseline:
        logging.info("CRC SCAN: Running initial scan on startup...")
        crc_engine._baseline_mtime = CRC_BASELINE_PATH.stat().st_mtime
        crc_violations = []
        total_checked = 0
        current_total_funcs = 0

        # Ground truth: actual files on disk right now
        disk_files_list = count_disk_py_files(TARGET_REPO, crc_engine)
        disk_files_set = set(disk_files_list)
        files_on_disk = len(disk_files_list)
        logging.info(f"CRC SCAN: Ground truth - {files_on_disk} .py files on disk")

        for file_key in crc_engine.baseline.functions:
            file_path = Path(file_key)
            if not file_path.exists():
                file_path = TARGET_REPO / file_key
            if file_path.exists():
                total_checked += 1
                passed, msg = crc_engine.check_file(file_path)
                if not passed:
                    crc_violations.append({'file': file_path.name, 'message': msg})
                    logging.warning(f"CRC VIOLATION: {file_path.name} - {msg}")
                current_funcs = crc_engine._extract_functions(file_path)
                current_total_funcs += len(current_funcs)

        # Detect new files (on disk but not in baseline)
        new_files = []
        baseline_rel_paths = set()
        for k in crc_engine.baseline.functions:
            try:
                baseline_rel_paths.add(str(Path(k).relative_to(TARGET_REPO)))
            except ValueError:
                baseline_rel_paths.add(Path(k).name)
        for rel_path in disk_files_list:
            if rel_path not in baseline_rel_paths:
                py_file = TARGET_REPO / rel_path
                funcs = crc_engine._extract_functions(py_file)
                current_total_funcs += len(funcs)
                if funcs:
                    new_files.append({'file': rel_path, 'functions': len(funcs)})

        # Detect removed files (in baseline but gone from disk)
        removed_files = detect_removed_files(
            crc_engine.baseline.functions, disk_files_set, TARGET_REPO)
        if removed_files:
            logging.info(f"CRC SCAN: {len(removed_files)} files removed from disk:")
            for rf in removed_files[:5]:
                logging.info(f"  - {rf['file']} ({rf['functions']} funcs)")

        baseline_funcs = sum(len(f) for f in crc_engine.baseline.functions.values())
        frozen_count = len(crc_engine.baseline.frozen)
        crc_results = {
            'total_functions': baseline_funcs,
            'current_functions': current_total_funcs,
            'frozen_count': frozen_count,
            'files_in_baseline': len(crc_engine.baseline.functions),
            'files_on_disk': files_on_disk,
            'files_checked': total_checked,
            'new_files': new_files,
            'new_file_count': len(new_files),
            'removed_files': removed_files,
            'removed_file_count': len(removed_files),
            'violation_count': len(crc_violations),
            'violations': crc_violations[:10],
            'last_scan': datetime.now().isoformat(),
        }
        logging.info(f"CRC SCAN: Initial - {frozen_count} frozen, {current_total_funcs} funcs, "
                     f"{len(new_files)} new files, {len(crc_violations)} violations")
        # Write state immediately so dashboard sees CRC on first poll
        write_circuit_state(graph, repo_id, crc_results=crc_results, dataflows=[],
                            daemon_phase="READY")
    else:
        # No CRC — signal READY now (all other init scans are already written)
        write_circuit_state(graph, repo_id, crc_results=crc_results,
                            mypy_results=mypy_results,
                            contract_violations=contract_data,
                            io_tracker_results=io_tracker_results, dataflows=[],
                            vulture_results=vulture_results,
                            daemon_phase="READY")

    logging.info("Circuit daemon initialization COMPLETE — phase: READY")

    backoff = 1
    max_backoff = 60
    path_hacks = {}  # Detected path manipulation hacks
    n_intervals = 0  # Cycle counter for periodic checks

    while not _shutdown_requested:
        try:
            _cycle_t0 = time.monotonic()   # Item 7: the poll's elapsed time reaches /health via record_poll
            if _CYCLE_CLOCK.get('t0'):     # I-90: the previous poll's full cycle (start to start, less its sleep)
                _CYCLE_HISTORY.append(max(0.0, _cycle_t0 - _CYCLE_CLOCK['t0'] - _CYCLE_CLOCK.get('sleep', 0.0)))
                del _CYCLE_HISTORY[:-CYCLE_WINDOW]
            _CYCLE_CLOCK['t0'] = _cycle_t0  # I-90: the frame carries its measured cycle (`cycle_s`)
            # Re-read target repo from config each cycle (hot-reload on config change)
            new_target = get_target_repo_from_config()
            if new_target is None:
                # T-12: the config lost its target — keep the current one, never PROJECT_ROOT
                logging.warning(f"TARGET: poll_config.json names no target — staying on {TARGET_REPO}")
            elif new_target != TARGET_REPO:
                logging.info(f"TARGET CHANGED: {TARGET_REPO} → {new_target}")
                TARGET_REPO = new_target
                repo_id = get_repo_id(TARGET_REPO)

                # 1. Delete owned state files in system_scripts/
                _purge_circuit_state_files()

                # 2. Delete circuit_state.json (rewritten immediately below)
                if CIRCUIT_STATE_FILE.exists():
                    try:
                        CIRCUIT_STATE_FILE.unlink()
                    except Exception:
                        pass

                _FIRST_PASS_DONE.clear()      # a new target gets its own first pass (owner 2026-09-29)
                _IO_FILE_CACHE.clear()
                _NAMING_DRIFT = None          # ND1: the new target gets its own baseline on its first pass
                _NAMING_DRIFT_WHY = 'launch scan has not completed'
                # 3. Recreate scanner → all in-memory caches start fresh
                #    (whitelist reloaded for the NEW target's repoid)
                scanner = CircuitScanner(
                    repo_path=str(TARGET_REPO),
                    project_root=str(PROJECT_ROOT),
                    syntax_timeout=config.get('syntax_timeout', DEFAULT_SYNTAX_TIMEOUT),
                    import_timeout=config.get('import_timeout', DEFAULT_IMPORT_TIMEOUT),
                    exclude_relpaths=load_whitelist(TARGET_REPO),
                )
                logging.info(f"TARGET CHANGED: Scanner recreated for {TARGET_REPO}")

                # 4. Reset ancillary state
                mypy_pending_files.clear()
                if ENABLE_VULTURE:
                    vulture_pending_files.clear()
                path_hacks = {}
                mypy_results = {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0, 'total_errors': 0,
                                'errors': [], 'error_counts': {},
                                'mypy_rc': None, 'mypy_ran': False}
                io_tracker_results = {}
                vulture_results = _vulture_zero_dict()

                continue  # restart loop cycle with fresh state

            # Apply depth changes from dashboard slider
            # EXCISED cut 3 batch 2 (2026-09-06, agreed) (F-DEPTH1-ZERO / F-DEPTH-EXPAND1): the slider's max_depth governed the SCAN — the circuit
            # published 0 nodes at depth 1. The scanner now always scans every depth; the slider only shapes the VIEW (circuit_views).
            if scanner.max_depth is not None:
                scanner.max_depth = None
                logging.info("Scan depth: unlimited (the dashboard slider filters the view, never the scan)")

            # Hot-reload the whitelist every cycle (live read — the artifact can
            # be regenerated between cycles; a whitelisted file must vanish from
            # the very next frame, an un-whitelisted one must reappear).
            scanner.exclude_relpaths = set(load_whitelist(TARGET_REPO))

            # FIX_39 (owner Q1, 2026-09-15): the directory the user is viewing, read the same way
            # and on the same cycle as the whitelist. The viewed directory is re-read at full rate;
            # every other directory on the period its live .py count earns (FIX_46's table).
            try:
                _viewed = read_file_locked(POLL_CONFIG_FILE).get('viewed_dirs') or []
            except Exception:
                _viewed = []
            scanner.set_view(_viewed)

            # Check for file changes and re-scan if needed
            graph = scanner.get_full_graph()

            if scanner.rescan_triggered:
                if scanner.changed_files:
                    mypy_pending_files.update(scanner.changed_files)
                    if ENABLE_VULTURE:
                        vulture_pending_files.update(scanner.changed_files)
                    logging.info(f"AST RESCAN: Change detected in: {', '.join(scanner.changed_files)}")
                else:
                    # S1: rescan_triggered with no changed files is only the launch pass now
                    logging.info("AST RESCAN: launch pass (every file read)")
                logging.info(f"AST RESCAN: {len(graph.nodes)} scripts, {len(graph.edges)} edges")
                if graph.cycles:
                    for cycle in graph.cycles:
                        logging.info(f"AST RESCAN: Circular dependency: {' -> '.join(cycle)}")
                
                # Log new change tags
                for node in graph.nodes:
                    if node.change_tags:
                        latest_tag = node.change_tags[-1]
                        logging.info(f"CODE CHANGE: {node.name} {latest_tag.lines}")
            
            # Log any evicted tags (overflow)
            overflow = scanner.get_overflow_log()
            if overflow:
                for evicted in overflow[-5:]:  # Log last 5 evictions max per cycle
                    logging.info(f"CHANGE LOG: {evicted['script']} {evicted['lines']} @ {evicted['timestamp']}")

            # Detect running scripts via process table scan
            monitored_names = [n.name for n in graph.nodes]
            running_script_names = []
            detected = {}
            _ps_lines = []
            try:
                _ps_lines = list_python_processes()   # Item 10: ONE ps per frame, shared
                detected = scan_running_processes(monitored_names, TARGET_REPO.resolve(), _ps_lines)
                # Plan item 8 (2026-09-05): running.json carries WRAPPER-recorded
                # executions only — the triangle means executed. Process-table
                # pins are kept for dataflow tracing, never written as "running".
                update_running_state({})
                _OUTSIDE_RUNS[:] = [{k: info.get(k) for k in ('node', 'script', 'pid', 'how', 'cmd', 'cwd')}
                                    for info in detected.values()]
                if detected:
                    logging.info("PROCESS PINS (dataflow only; outside CodeRadar): " + ', '.join(
                        f"{info.get('node') or info['script']} pid {info['pid']} [{info.get('how')}]"
                        for info in detected.values()))
            except Exception as e:
                _OUTSIDE_RUNS.clear()   # a failed scan names no run — never last frame's
                logging.warning(f"Process scan error: {e}")

            # ---- Item 10: test runners — presence (every 10th frame / on change) + execution (every frame) ----
            try:
                if _TEST_RUNNERS.get('presence') is None or n_intervals % 10 == 0 or (scanner.rescan_triggered and scanner.changed_files):
                    _TEST_RUNNERS['presence'] = scan_test_runner_presence(graph.nodes, TARGET_REPO)
                    _TEST_RUNNERS['status'] = 'MEASURED'
                    _pp = _TEST_RUNNERS['presence']
                    logging.info(f"TEST RUNNER PRESENCE: pytest in {len(_pp['pytest']['files'])} file(s), unittest in "
                                 f"{len(_pp['unittest']['files'])} file(s), config {[c['file'] for c in _pp['config']]}")
                _running_json = read_file_locked(RUNNING_STATE_FILE) if RUNNING_STATE_FILE.exists() else {}
                _kernel_pytest = None
                if backend == "eslogger" and eslogger_monitor is not None and hasattr(eslogger_monitor, 'get_kernel_pytest'):
                    _kernel_pytest = eslogger_monitor.get_kernel_pytest()
                _runner_entries = collect_runner_executions(_running_json if isinstance(_running_json, dict) else {},
                                                            _ps_lines, _kernel_pytest, TARGET_REPO.resolve())
                _TEST_RUNNERS['execution'] = {
                    'entries': _runner_entries,
                    'sources': {'wrapper': 'MEASURED', 'ps': 'MEASURED',
                                'kernel': 'MEASURED' if backend == "eslogger" else 'not run — tracer is lsof'},
                }
                if _runner_entries:
                    logging.info("TEST RUNNER: " + ", ".join(
                        f"{e['runner']} pid {e['pid']} → {e['test_path'] or '(cwd)'} [{e['proof']}]" for e in _runner_entries))
                # the runner's own record: hash-verified coverage (a warning on the graph, never a pass)
                _rproof = _read_json_plain(RUNNER_INFO_FILE) if RUNNER_INFO_FILE.exists() else {}
                _RUNNER_COVERAGE.clear()
                if _rproof:
                    _rc_set, _rv, _rs = _runner_coverage(_rproof, TARGET_REPO)
                    _RUNNER_COVERAGE.update(_rc_set)
            except Exception as e:
                logging.warning(f"Test runner tracker error: {e}")
                _rproof = {}

            # Item 7: dataflows through the ONE backend chosen at launch. eslogger → the kernel
            # tracer; lsof → the TCP-pair detector. No branch runs the other backend, ever.
            dataflows = []
            if backend == "eslogger" and eslogger_monitor and async_bridge:
                try:
                    # Pin ALL detected PIDs first, THEN begin accepting
                    needs_accept = not eslogger_monitor._accepting
                    for pid_str, info in detected.items():
                        pid = info.get('pid')
                        if pid:
                            eslogger_monitor._pinned_pids.add(pid)
                    if needs_accept:
                        async_bridge.run(eslogger_monitor.begin_accepting())

                    dataflows = async_bridge.run(
                        _gather_dataflows_async(eslogger_monitor, detected)
                    )
                    # Diagnostic: show what eslogger IPC queue has
                    if not dataflows and len(detected) >= 2:
                        ipc_diag = async_bridge.run(eslogger_monitor.get_ipc_files())
                        logging.info(f"DATAFLOW DIAG: eslogger ipc_data={dict((k, list(v)) for k, v in ipc_diag.items())}, "
                                     f"pinned={sorted(eslogger_monitor._pinned_pids)}, "
                                     f"accepting={eslogger_monitor._accepting}, "
                                     f"health={eslogger_monitor.health}")
                except Exception as e:
                    logging.warning(f"DATAFLOW: eslogger error: {e}")
            elif backend == "lsof" and len(detected) >= 2:
                dataflows = detect_dataflows_lsof(detected)

            # Item 7: the tracer's liveness, refreshed every frame from the backend itself
            if backend == "eslogger":
                _es_health = eslogger_monitor.health if eslogger_monitor else {}
                _TRACER_STATE.update({'alive': bool(_es_health.get('alive')),
                                      'reason': 'EsloggerMonitor running' if _es_health.get('alive') else 'EsloggerMonitor not running'})
            else:
                _lsof_path = shutil.which('lsof')
                _es_health = {}
                _TRACER_STATE.update({'alive': _lsof_path is not None,
                                      'reason': f"lsof at {_lsof_path}" if _lsof_path else 'lsof gone from PATH'})

            # Item 10 (T2): while a WRAPPER-recorded runner is alive, the runner's import flows test → source
            # join the frame's dataflows (proof "runner", drawn amber) — the graph shows where pytest runs.
            try:
                if _rproof and any(e.get('proof') == 'wrapper' and is_pid_alive(int(e['pid'])) for e in _TEST_RUNNERS['execution']['entries']):
                    _seen = {(f.get('src'), f.get('dst'), f.get('channel')) for f in dataflows}
                    for _rf in _runner_dataflows(_rproof, graph.import_map, TARGET_REPO):
                        if (_rf['src'], _rf['dst'], _rf['channel']) not in _seen:
                            dataflows.append(_rf); _seen.add((_rf['src'], _rf['dst'], _rf['channel']))
            except Exception as e:
                logging.warning(f"Runner dataflow error: {e}")

            if not dataflows and detected and len(detected) >= 2:
                logging.debug("DATAFLOW: No flows detected this cycle "
                             f"(pids={[info.get('pid') for info in detected.values()]})")
            if dataflows:
                flow_pairs = [(f['src'], f['dst']) for f in dataflows]
                logging.info(f"DATAFLOW: {len(dataflows)} active flow(s): "
                             f"{', '.join(f'{s}->{d}' for s, d in flow_pairs[:5])}")

            # Update runtime coverage based on running scripts
            runtime_coverage = update_runtime_coverage(running_script_names, graph.import_map)
            if runtime_coverage:
                coverage_count = len(runtime_coverage)
                total_count = len(graph.nodes)
                logging.info(f"RUNTIME COVERAGE: {coverage_count}/{total_count} modules loaded")

            # Log status in dashboard-compatible format
            all_ok = log_graph_status(graph)

            # Check for path hacks (periodic + on file change so resolved hacks clear immediately)
            # owner 2026-09-29: first pass, then only when a file changed (was also every 10 cycles)
            should_scan_hacks = (
                not _FIRST_PASS_DONE.get('hacks') or
                (scanner.rescan_triggered and scanner.changed_files)  # Re-scan when files change
            )
            if should_scan_hacks:
                if scanner.rescan_triggered and scanner.changed_files:
                    # S1: the AST RESCAN line above already names every changed file; count them here
                    logging.info(f"PATH HACK SCAN: Re-checking after {len(scanner.changed_files)} file change(s)")
                else:
                    logging.info("PATH HACK SCAN: Checking for path manipulation...")
                path_hacks = scan_repo_for_path_hacks(TARGET_REPO)
                _stamp_hack_dispositions(path_hacks)
                _FIRST_PASS_DONE['hacks'] = True

            # ND1: the naming-drift tracker — unconditional (permanent), first pass builds the baseline from the
            # launch graph's own names, afterwards only the changed files are re-read from their nodes; the
            # owner's rulings are re-read whenever the dash touched the reload flag or the accepted file.
            # A failure is a reason in the mirror (NOT MEASURED), never an empty baseline that reads as clean.
            try:
                if NamingDriftTracker is None:
                    _NAMING_DRIFT_WHY = _NAMING_DRIFT_IMPORT_ERROR
                elif _NAMING_DRIFT is None or not _FIRST_PASS_DONE.get('naming_drift'):
                    _NAMING_DRIFT = NamingDriftTracker(repo_id)
                    _NAMING_DRIFT.baseline(graph.nodes)
                    _FIRST_PASS_DONE['naming_drift'] = True
                    _NAMING_DRIFT_WHY = None
                    _nd = _NAMING_DRIFT.report()
                    logging.info(f"NAMING DRIFT: baseline — {_nd.get('scanned_files')} files, "
                                 f"{_nd.get('groups')} group(s), pre-existing {_nd.get('pre_existing')}, "
                                 f"new {_nd.get('new')}, by tier {_nd.get('by_tier')}, accepted {_nd.get('accepted')}")
                else:
                    if scanner.rescan_triggered and scanner.changed_files:
                        _moved = _NAMING_DRIFT.watch(graph.nodes, scanner.changed_files)
                        _nd = _NAMING_DRIFT.report()
                        logging.info(f"NAMING DRIFT: {_moved} file(s) re-read — new {_nd.get('new')}, "
                                     f"pre-existing {_nd.get('pre_existing')}, by tier {_nd.get('by_tier')}")
                    if _NAMING_DRIFT.reload_accepted():
                        logging.info(f"NAMING DRIFT: accepted rulings reloaded from {_NAMING_DRIFT.accepted_file.name} "
                                     f"({len(_NAMING_DRIFT.accepted)} entr{'y' if len(_NAMING_DRIFT.accepted) == 1 else 'ies'})")
            except Exception as _nd_exc:
                _NAMING_DRIFT_WHY = f"{type(_nd_exc).__name__}: {_nd_exc}"
                logging.warning(f"NAMING DRIFT: {_NOT_MEASURED} — {_NAMING_DRIFT_WHY}")

                if path_hacks:
                    for file, hacks in path_hacks.items():
                        for hack in hacks:
                            # FIX_49 / FIX_50: a hack the table calls `context` is INFORMATIONAL — it is
                            # published with its warning and logged as such, never as an infraction.
                            if getattr(hack, 'disposition', 'deciding') == 'context':
                                logging.info(
                                    f"PATH HACK (informational): {file}:{hack.line} - {hack.type} - "
                                    f"{hack.details}{' — ' + hack.warning if hack.warning else ''}"
                                )
                            else:
                                logging.warning(
                                    f"PATH HACK: {file}:{hack.line} - {hack.type} - {hack.details}"
                                )
                else:
                    logging.info("PATH HACK SCAN: No path manipulation detected")

            # ---- CRC Frozen Function Check ----
            # FIX_46: period + phase from the cadence table (circuit/crc = 8 cycles, phase 0)
            # owner 2026-09-29: first pass, then only when a file changed (was every 8 cycles)
            crc_turn = not _FIRST_PASS_DONE.get('crc') or bool(scanner.changed_files)
            if crc_turn:
                if crc_engine and crc_engine.baseline:
                    _FIRST_PASS_DONE['crc'] = True
                    # Reload baseline if it was updated (e.g. by dashboard Accept button)
                    try:
                        _bl_mtime = CRC_BASELINE_PATH.stat().st_mtime
                        if not hasattr(crc_engine, '_baseline_mtime') or _bl_mtime != crc_engine._baseline_mtime:
                            crc_engine.load_baseline(CRC_BASELINE_PATH)
                            crc_engine._baseline_mtime = _bl_mtime
                            logging.info("CRC: Baseline reloaded from disk")
                    except Exception:
                        pass
                    logging.info("CRC SCAN: Checking frozen functions...")
                    crc_violations = []
                    total_checked = 0
                    current_total_funcs = 0

                    # Ground truth: actual files on disk right now
                    disk_files_list = count_disk_py_files(TARGET_REPO, crc_engine)
                    disk_files_set = set(disk_files_list)
                    files_on_disk = len(disk_files_list)

                    # Check baseline files for frozen function changes
                    for file_key in crc_engine.baseline.functions:
                        file_path = Path(file_key)
                        if not file_path.exists():
                            file_path = TARGET_REPO / file_key
                        if file_path.exists():
                            total_checked += 1
                            passed, msg = crc_engine.check_file(file_path)
                            if not passed:
                                crc_violations.append({
                                    'file': file_path.name,
                                    'message': msg,
                                })
                                logging.warning(f"CRC VIOLATION: {file_path.name} - {msg}")
                            current_funcs = crc_engine._extract_functions(file_path)
                            current_total_funcs += len(current_funcs)

                    # Detect new files (on disk but not in baseline)
                    new_files = []
                    baseline_rel_paths = set()
                    for k in crc_engine.baseline.functions:
                        try:
                            baseline_rel_paths.add(str(Path(k).relative_to(TARGET_REPO)))
                        except ValueError:
                            baseline_rel_paths.add(Path(k).name)
                    for rel_path in disk_files_list:
                        if rel_path not in baseline_rel_paths:
                            py_file = TARGET_REPO / rel_path
                            funcs = crc_engine._extract_functions(py_file)
                            current_total_funcs += len(funcs)
                            if funcs:
                                new_files.append({
                                    'file': rel_path,
                                    'functions': len(funcs),
                                })

                    # Detect removed files (in baseline but gone from disk)
                    removed_files = detect_removed_files(
                        crc_engine.baseline.functions, disk_files_set, TARGET_REPO)

                    baseline_funcs = sum(len(f) for f in crc_engine.baseline.functions.values())
                    frozen_count = len(crc_engine.baseline.frozen)
                    crc_results = {
                        'total_functions': baseline_funcs,
                        'current_functions': current_total_funcs,
                        'frozen_count': frozen_count,
                        'files_in_baseline': len(crc_engine.baseline.functions),
                        'files_on_disk': files_on_disk,
                        'files_checked': total_checked,
                        'new_files': new_files,
                        'new_file_count': len(new_files),
                        'removed_files': removed_files,
                        'removed_file_count': len(removed_files),
                        'violation_count': len(crc_violations),
                        'violations': crc_violations[:10],
                        'last_scan': datetime.now().isoformat(),
                    }
                    if new_files:
                        logging.info(f"CRC SCAN: {len(new_files)} new files not in baseline:")
                        for nf in new_files[:5]:
                            logging.info(f"  + {nf['file']} ({nf['functions']} funcs)")
                        if len(new_files) > 5:
                            logging.info(f"  ... and {len(new_files) - 5} more")
                    if removed_files:
                        logging.info(f"CRC SCAN: {len(removed_files)} files removed from disk:")
                        for rf in removed_files[:5]:
                            logging.info(f"  - {rf['file']} ({rf['functions']} funcs)")
                    if not crc_violations:
                        logging.info(f"CRC SCAN: OK - {frozen_count} frozen, {files_on_disk} on disk")

            # ---- Async/Sync I/O Function Tracker ----
            # FIX_46: circuit/io = 8 cycles, phase 2 — off the CRC angle
            # owner 2026-09-29: every tick, but only new/edited files are parsed (scan_io_incremental)
            if 'io' in _TRACKERS:
                try:
                    io_tracker_results = scan_io_incremental(TARGET_REPO)
                    _iot = io_tracker_results.get('totals', {})
                    if io_tracker_results.get('files_parsed'):
                        logging.info(
                            f"IO TRACKER: parsed {io_tracker_results['files_parsed']} changed file(s); "
                            f"{_iot.get('total_functions', 0)} functions "
                            f"({_iot.get('async_count', 0)} async, {_iot.get('sync_count', 0)} sync), "
                            f"{_iot.get('io_functions', 0)} with I/O patterns"
                        )
                except Exception as e:
                    logging.warning(f"IO TRACKER: Scan error: {e}")
                    # R4: a crashed scan is NOT MEASURED — never the last good frame, never a zero
                    io_tracker_results = {'not_measured_reason': f"io scan crashed: {type(e).__name__}: {e}"}

            # ---- mypy Type Check ----
            # FIX_46: circuit/mypy = 8 cycles, phase 4
            # owner 2026-09-29: first pass, then only when a file changed (was also every 8 cycles)
            if 'mypy' in _TRACKERS and (mypy_pending_files or not _FIRST_PASS_DONE.get('mypy')):
                _FIRST_PASS_DONE['mypy'] = True
                logging.info("MYPY: Starting full repository scan (clean slate)...")
                # Total clear before fresh scan — no merging, no stale data
                mypy_results = {'files_checked': 0, 'dirs_checked': 0, 'passed': 0, 'failed': 0,
                                'total_errors': 0, 'errors': [], 'errors_by_dir': {},
                                'recent_checks': [], 'last_scan': None,
                                'mypy_rc': None, 'mypy_ran': False}
                scan = run_mypy_scan()
                if scan:
                    mypy_results.update(scan)
                mypy_pending_files.clear()

            # ---- Vulture Dead Code Check ----
            if ENABLE_VULTURE:
                # FIX_46: circuit/vulture = 8 cycles, phase 6
                if vulture_pending_files or not _FIRST_PASS_DONE.get('vulture'):
                    _FIRST_PASS_DONE['vulture'] = True
                    logging.info("VULTURE: Starting dead code scan (clean slate)...")
                    vulture_results = _vulture_zero_dict()
                    vscan = run_vulture_scan()
                    if vscan:
                        vulture_results.update(vscan)
                    vulture_pending_files.clear()

            # ITEM 11: the severed-link transition for this frame (edges x executed proof + dataflows)
            try:
                update_severed_links(graph, runtime_coverage, dataflows)
            except Exception as e:
                logging.warning(f"Severed-link transition error: {e}")

            # Write circuit state to JSON (SINGLE SOURCE OF TRUTH for dashboard)
            write_circuit_state(graph, repo_id, runtime_coverage=runtime_coverage,
                                path_hacks=path_hacks,
                                crc_results=crc_results, mypy_results=mypy_results,
                                contract_violations=contract_data,
                                contract_decorators=contract_decorator_list,
                                io_tracker_results=io_tracker_results,
                                dataflows=dataflows,
                                vulture_results=vulture_results,
                                scan_cadence=getattr(scanner, 'scan_cadence', None),   # FIX_39
                                test_runners=_TEST_RUNNERS, runner_coverage=_RUNNER_COVERAGE)   # Item 10
            # FIX_45: the dash mirror carries this frame's severed set, from the same module state
            # `update_severed_links` just wrote — one computation, two mirrors.
            write_repo_mirror(graph, path_hacks, mypy_results, io_tracker_results, vulture_results,
                              severed_links=dict(_SEVERED_LINKS))
            # owner 2026-10-07 ~05:50: the dash mirrors of every VIEWED folder (root included), visible JSONL
            # in the folder itself — written from the frame's own state, never into an unviewed folder
            try:
                import view_mirrors
                _vm_viewed = set(read_file_locked(POLL_CONFIG_FILE).get('viewed_dirs_seen') or [])
                view_mirrors.write(TARGET_REPO, _vm_viewed | {''},
                                   read_file_locked(CIRCUIT_STATE_FILE),
                                   (read_file_locked(SCRIPT_DIR / '.monitor_state.json').get('monitor') or {}),
                                   read_file_locked(SCRIPT_DIR / '.noai_state.json'))
            except Exception as _vm_e:
                logging.warning(f"VIEW MIRRORS: write failed (reported, not swallowed): {_vm_e}")

            # Item 7: the observability endpoint learns about every poll and the tracer's
            # liveness — the site FIX_19 needed (record_poll / record_kernel_tracer were never
            # called, so /health was always 503).
            if _obs:
                try:
                    _obs.record_poll(
                        n_intervals, (time.monotonic() - _cycle_t0) * 1000.0,
                        sum(1 for _n in graph.nodes if _n.connected), len(graph.nodes),
                        running=len(detected), dataflows=len(dataflows), interval=get_ping_interval())
                    _obs.record_kernel_tracer(
                        backend, bool(_TRACER_STATE.get('alive')),
                        int(_es_health.get('events_total', 0)), int(_es_health.get('tracked_pids', len(detected))),
                        parse_ok=int(_es_health.get('parse_ok', 0)), parse_fail=int(_es_health.get('parse_fail', 0)),
                        parse_skip=int(_es_health.get('parse_skip', 0)), queue_drops=int(_es_health.get('queue_drops', 0)))
                except Exception as e:
                    logging.warning(f"OBSERVABILITY: record failed: {e}")

            if all_ok:
                logging.info("CIRCUIT STATUS: ALL CONNECTED")
            else:
                logging.info("CIRCUIT STATUS: BREAKS DETECTED")
            logging.info("-" * 40)

            n_intervals += 1
            backoff = 1
            _CYCLE_CLOCK['sleep'] = _rate_aware_sleep()   # I-90: subtracted from the start-to-start cycle

        except KeyboardInterrupt:
            logging.info("Daemon stopped by user (KeyboardInterrupt)")
            break
        except Exception as e:
            logging.error(f"Ping failed with error: {e}")
            logging.info(f"Retrying in {backoff}s (exponential backoff)")
            _interruptible_sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    # Post-loop cleanup (runs whether exited via signal flag, KeyboardInterrupt, or error)
    logging.info("Daemon shutting down — cleaning up...")
    if eslogger_monitor and async_bridge:
        try:
            async_bridge.run(eslogger_monitor.stop())
        except Exception:
            pass
        async_bridge.stop()
        logging.info("DATAFLOW: EsloggerMonitor stopped")
    # F14 (slot 10): stop the observability HTTP server and join its thread —
    # it was never stopped anywhere, so the non-daemon obs-health thread pinned
    # the process at exit (the twice-logged SIGTERM -> SIGKILL-after-grace).
    if _obs:
        try:
            _obs.stop()
        except Exception:
            pass
    try:
        cleanup_running_state()
    except Exception:
        pass
    logging.info("Daemon stopped.")


if __name__ == '__main__':
    import argparse as _argparse

    _parser = _argparse.ArgumentParser(description='Circuit Daemon')
    _parser.add_argument('repo', nargs='?', help='Target repo path (overrides config)')
    # FIX_22 (2026-09-15): the per-repo state-file suffix flag is gone — ONE circuit state file
    # (CIRCUIT_STATE_FILE, the module constant); the gearbox never passed the flag. The removed
    # block is quoted in .archive/archived_20260915/NOTES.md ("circuit_daemon state-file suffix flag").
    _args = _parser.parse_args()

    if _args.repo:
        TARGET_REPO = Path(_args.repo)
        print(f"Monitoring custom repo: {TARGET_REPO}")
        # Save to config so single-repo dashboard stays in sync
        try:
            config = read_file_locked(POLL_CONFIG_FILE)
            config['target_repo'] = str(TARGET_REPO.resolve())
            write_file_locked(POLL_CONFIG_FILE, config)
        except Exception as e:
            print(f"Warning: Could not save repo to config: {e}")

    run_daemon()
