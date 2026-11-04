#!/usr/bin/env python3
"""
tracer.py — Kernel event tracer (EsloggerMonitor).

Provides ESF-based kernel event tracing via macOS Endpoint Security
Framework (eslogger).

Terminology:
  - **Daemon**: the main process (kernel_trace_daemon.py)
  - **Tracer**: the kernel event capture backend (this module)
  - **Supervisor**: persistent module script runner (supervisor.py)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# (Item 7, 2026-09-10: the `Config = None` placeholder and the dead `select_kernel_backend` that
#  referenced it are archived at .archive/archived_20260910/tracer_select_kernel_backend_ITEM07.py;
#  the backend is chosen at launch and started by circuit_daemon.run_daemon.)
from engine_utils import PROOF_KERNEL, KernelProcessInfo, ProcessEvents, now_iso


# ---------------------------------------------------------------------------
# Constants (kernel event configuration)
# ---------------------------------------------------------------------------

IPC_FILE_EXTENSIONS: FrozenSet[str] = frozenset({
    ".json", ".jsonl", ".queue", ".pipe", ".sock", ".db", ".sqlite",
})

# Kernel event strength ranking — shared by both backends.
# Higher = stronger evidence that the process actually loaded the file.
# Strength 3 = definite interaction, 2 = metadata/indirect, 1 = permission only.
_EVENT_STRENGTH: Dict[str, int] = {
    # File operations — module .py detection
    "open": 3, "mmap": 3, "read": 3,       # definite file load
    "stat": 2, "stat64": 2, "lookup": 2,   # file metadata check
    "access": 1, "getattrlist": 1,          # permission check only
    # File lifecycle — kernel-based file discovery
    "write": 3, "close": 2, "create": 3,
    "unlink": 3, "rename": 3,              # file deletion/move
    # Unix domain socket IPC
    "uipc_bind": 3, "uipc_connect": 3,
    # TCP/IP socket lifecycle
    "bind": 3, "connect": 3, "listen": 3, "accept": 3,
    # Process lifecycle
    "fork": 3, "exec": 3, "exit": 3, "signal": 2,
}

# Minimum strength to count as a "connection" (filters out weak events).
_MIN_CONNECTION_STRENGTH: int = 0  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 2 — event strength is published, not used as a floor

# Queue and buffer sizing
EVENT_QUEUE_SIZE: int = 10_000       # Max burst events before backpressure
PENDING_BUFFER_SIZE: int = 50_000    # Max raw lines buffered before accepting PIDs
EVENT_SEQUENCE_MAX: int = 500        # Max events per PID for temporal analysis
EVENT_SEQUENCE_KEEP: int = 250       # Keep this many when pruning (half of max)
RECURSIVE_PATH_MAX_DEPTH: int = 6    # Max depth for recursive path search in ESF JSON
DIAG_SAMPLE_PIDS: int = 20          # Max PIDs to sample in buffer diagnostics
DIAG_NEARBY_LIMIT: int = 3          # Max nearby-PID log entries during begin_accepting
DIAG_PID_RANGE_BELOW: int = 5       # PID range window below pinned set for diagnostics
DIAG_PID_RANGE_ABOVE: int = 10      # PID range window above pinned set for diagnostics
DIAG_PINNED_SKIP_SAMPLES: int = 5   # Max pinned-PID skip samples logged in _parse_event
ESLOGGER_STOP_TIMEOUT: float = 3.0  # Seconds to wait for eslogger process to exit
MAX_RELAUNCH_BACKOFF: float = 60.0   # Max seconds between eslogger relaunch attempts
DIAG_RAW_EVENT_TRUNCATE: int = 500  # Max chars for diagnostic raw event samples
COMMAND_TRUNCATE: int = 300          # Max chars for command string in kernel_running
COMMAND_MAX_ARGS: int = 10           # Max args included in command string
_MAX_DICT_KEYS_RECURSIVE: int = 100  # Abort recursive path search if dict too large
_ARG_MAX_LEN: int = 200             # Max chars per arg before truncation in command string
_MAX_EVENT_LINE_BYTES: int = 1_000_000  # 1MB per eslogger line — skip oversized events

# Auto-pruning limits (prevent unbounded memory growth)
MAX_DISCOVERED_FILES: int = 5_000    # Max tracked discovered files (prune oldest)
MAX_DELETED_FILES: int = 2_000       # Max tracked deleted files
MAX_SOCKET_BINDINGS: int = 1_000     # Max tracked socket bindings
SOCKET_BINDING_TTL: float = 300.0    # Seconds before a socket binding is stale (5 min)
MAX_PROCESS_EVENTS: int = 10_000     # Max tracked PIDs in _process_events
READER_PRUNE_INTERVAL: float = 60.0  # Seconds between auto-prune in reader loop
READER_PRUNE_EVENT_THRESHOLD: int = 1_000  # Events between auto-prune checks
QUEUE_PUT_TIMEOUT: float = 5.0       # Seconds to wait before dropping an event
QUEUE_DROP_ALERT_INTERVAL: int = 10  # Log warning every N drops
QUEUE_DROP_CIRCUIT_BREAKER: int = 1_000  # Drops in window to trigger critical alert
QUEUE_DROP_CIRCUIT_WINDOW: float = 60.0  # Window in seconds for circuit breaker
HEALTH_CHECK_WARMUP: float = 60.0    # Seconds before health check kicks in
HEALTH_CHECK_STALL_WINDOW: float = 30.0  # No events in this window = stalled
PARSE_FAIL_CIRCUIT_MIN: int = 1_000  # Min failures before circuit breaker check
PARSE_FAIL_RATIO_THRESHOLD: float = 0.5  # Failure ratio that triggers shutdown

# Valid eslogger (ESF) event types — subset of _EVENT_STRENGTH keys that
# correspond to Endpoint Security Framework notify events.
_ESLOGGER_EVENTS: Tuple[str, ...] = (
    # File observation
    "open", "mmap", "stat", "access",
    # File lifecycle (kernel-based discovery)
    "write", "close", "create", "unlink", "rename",
    # Unix domain sockets
    "uipc_bind", "uipc_connect",
    # TCP/IP sockets
    "bind", "connect", "listen", "accept",
    # Process lifecycle
    "fork", "exec", "exit", "signal",
)
_ESLOGGER_EVENTS_SET: FrozenSet[str] = frozenset(_ESLOGGER_EVENTS)

# Python process identification — used by eslogger backend.
_PYTHON_INDICATORS: FrozenSet[str] = frozenset({
    "python", "python3", "Python.framework",
    "pyenv", "conda", "virtualenv",
})

# Auto-discovery patterns for critical nodes when none configured.
_AUTO_CRITICAL_PATTERNS: Tuple[str, ...] = (
    "__init__", "main", "core", "api", "setup",
)


# BIG 3 #1 — CONNECTION (kernel: real-time filesystem event tracing)
#
# EsloggerMonitor — ESF kernel event monitor (macOS 13+, structured JSON)
# ===================================================================


class EsloggerMonitor:
    """ESF-based kernel event monitor. Structured JSON — no regex parsing.

    eslogger uses macOS Endpoint Security Framework (kernel-level).
    Available on macOS 13+ (Ventura). Requires root. Supports multiple
    concurrent clients.

    Expected JSON shape per line (ES_EVENT_TYPE_NOTIFY_OPEN example):
        {
          "event_type": "ES_EVENT_TYPE_NOTIFY_OPEN",
          "process": {
            "executable": {"path": "/usr/bin/python3"},
            "audit_token": {"pid": 12345},
            "signing_id": "com.apple.python3"
          },
          "event": {
            "open": {"file": {"path": "/path/to/file.py"}}
          }
        }
    """

    def __init__(
        self,
        repo: Path,
        event_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.repo: Path = repo.resolve()
        # Ensure trailing slash to prevent /foo/bar_backup matching /foo/bar
        self.repo_str: str = str(self.repo).rstrip("/") + "/"
        # Alternative non-resolved path (handles symlink differences)
        self._repo_str_alt: str = str(repo).rstrip("/") + "/"
        self._backend_name: str = "eslogger"
        self._process: Optional[asyncio.subprocess.Process] = None
        # Consolidated per-PID event storage:
        # pid → {"modules": {node_name: best_event}, "ipc_files": {path: best_event}, "sequence": [(ts, name)]}
        self._process_events: Dict[int, ProcessEvents] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._running: bool = False
        self._event_count: int = 0
        self._parse_ok: int = 0
        self._parse_fail: int = 0
        self._queue_drops: int = 0
        # Diagnostic skip counters — per-filter-point
        self._skip_not_python: int = 0
        self._skip_no_path: int = 0
        self._skip_not_relevant_ext: int = 0
        self._skip_outside_repo: int = 0
        self._pinned_skip_samples: int = 0  # for diagnostic logging
        self._pinned_events_seen: int = 0  # events from pinned PIDs (any stage)
        self._diag_sample_raw: Optional[str] = None  # first raw event from pinned PID
        self.__relaunch_backoff: float = 1.0
        self._last_relaunch_attempt: float = 0.0
        self._start_time: float = 0.0
        self._event_queue: asyncio.Queue[Tuple[int, str, str, float]] = asyncio.Queue(maxsize=EVENT_QUEUE_SIZE)
        # (event_sequence and ipc_files consolidated into _process_events above)
        self._ipc_event_queue: asyncio.Queue[Tuple[int, str, str, float]] = asyncio.Queue(maxsize=EVENT_QUEUE_SIZE)
        # Pinned PIDs: preserved across cleanup cycles (e.g. persistent orchestrator)
        self._pinned_pids: Set[int] = set()
        # Buffering gate: hold raw eslogger lines until PIDs are pinned
        self._accepting: bool = False
        self._pending_lines: deque = deque(maxlen=PENDING_BUFFER_SIZE)
        # Kernel-proven running processes (via exec/exit events)
        self._kernel_running: Dict[int, KernelProcessInfo] = {}  # pid → process info
        
        # Kernel-proven pytest detection (via exec events)
        self._kernel_pytest: Optional[Dict[str, Any]] = None  # {pid, command, test_path, started_at}
        
        # Kernel-based file discovery (via create/unlink/rename events)
        self._discovered_files: Dict[str, float] = {}  # node_name → discovery_timestamp
        self._deleted_files: Set[str] = set()  # node names that were deleted
        # Queue for file lifecycle events (reader loop → main loop under lock)
        self._file_lifecycle_queue: deque[Tuple[str, str, float]] = deque(maxlen=EVENT_QUEUE_SIZE)  # (action, node_name, ts)
        
        # Kernel-based socket tracking (via bind/connect/listen/accept)
        self._socket_bindings: Dict[Tuple[str, int], Tuple[int, float]] = {}  # (addr, port) → (PID, timestamp)
        self._socket_connections: Dict[int, Set[Tuple[str, int]]] = {}  # PID → set of (addr, port) connected to
        self._socket_listens: Dict[int, Set[Tuple[str, int]]] = {}  # PID → set of (addr, port) listening on

        # Health check: timestamp of last successfully parsed event
        self._last_event_time: float = 0.0

        # Queue drop circuit breaker tracking
        self._queue_drop_window_start: float = 0.0
        self._queue_drops_in_window: int = 0

        # Reader loop auto-prune tracking
        self._last_prune_time: float = 0.0
        self._events_since_prune: int = 0

        # Cache: event_type → tuple of dict keys leading to "path"
        # Avoids repeated recursive search for the same event structure
        # Bounded to prevent unbounded memory growth from novel event types
        self._path_key_cache: Dict[str, Optional[Tuple[str, ...]]] = {}
        self._PATH_KEY_CACHE_MAX: int = 256

        # Configurable events and strength from trace_config.json
        self._event_strength: Dict[str, int] = dict(_EVENT_STRENGTH)
        if event_config:
            custom_events = event_config.get("events")
            self._events: List[str] = custom_events if custom_events else list(_ESLOGGER_EVENTS)
            custom = event_config.get("strength", {})
            self._event_strength.update(custom)
        else:
            self._events = list(_ESLOGGER_EVENTS)

        # Configurable health check and test runner settings
        self._health_check_warmup: float = event_config.get(
            "health_check_warmup_seconds", HEALTH_CHECK_WARMUP,
        ) if event_config else HEALTH_CHECK_WARMUP
        self._health_check_stall_window: float = event_config.get(
            "health_check_stall_window_seconds", HEALTH_CHECK_STALL_WINDOW,
        ) if event_config else HEALTH_CHECK_STALL_WINDOW
        # Item 10 (2026-09-15): unittest is a runner too
        self._test_runner_patterns: List[str] = event_config.get(
            "test_runner_patterns", ["pytest", "-m pytest", "unittest", "-m unittest"],
        ) if event_config else ["pytest", "-m pytest", "unittest", "-m unittest"]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        """Launch ``eslogger`` with filesystem event subscriptions."""
        try:
            self._process = await asyncio.create_subprocess_exec(
                "eslogger", *self._events,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(self._process.wait(), timeout=0.5)
                # Process exited within 0.5s — failed to start
                err = ""
                if self._process.stderr:
                    try:
                        raw = await asyncio.wait_for(self._process.stderr.read(), timeout=0.5)
                        err = raw.decode(errors="replace")[:200]
                    except (asyncio.TimeoutError, Exception):
                        err = "(stderr unavailable)"
                logging.warning("eslogger failed to start: %s", err)
                return False
            except asyncio.TimeoutError:
                # Still running after 0.5s — good!
                pass
            self._running = True
            self._start_time = time.monotonic()
            self._reader_task = asyncio.create_task(self._read_loop())
            logging.info(
                "eslogger kernel tracer started (PID %d), events: %s",
                self._process.pid, self._events,
            )
            return True
        except FileNotFoundError:
            logging.info("eslogger not found (requires macOS 13+)")
            return False
        except Exception as exc:
            logging.warning("eslogger start error: %s", exc, exc_info=True)
            return False

    async def stop(self) -> None:
        """Terminate the eslogger subprocess."""
        self._running = False
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=ESLOGGER_STOP_TIMEOUT)
            except asyncio.TimeoutError:
                self._process.kill()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    logging.warning("eslogger process did not exit after SIGKILL")
            self._process = None
        logging.info("eslogger stopped (%d events captured)", self._event_count)

    # ------------------------------------------------------------------
    # JSON parsing — no regex needed
    # ------------------------------------------------------------------

    def _is_python_process(self, process: Dict[str, Any]) -> bool:
        """Check if process is a Python interpreter.

        Null-safe: handles executable being None, a string (macOS 26 may
        flatten), or a dict with ``path`` key.
        """
        executable = process.get("executable") or {}
        if isinstance(executable, str):
            path = executable  # macOS 26 may flatten to string
        elif isinstance(executable, dict):
            path = executable.get("path", "") or ""
        else:
            path = ""
        if any(ind in path for ind in _PYTHON_INDICATORS):
            return True
        signing_id = process.get("signing_id", "") or ""
        if "python" in signing_id.lower():
            return True
        return False

    def _cache_path_key(self, event_type: str, key_path: Tuple[str, ...]) -> None:
        """Store a path key in the cache, evicting oldest entries if full."""
        if len(self._path_key_cache) >= self._PATH_KEY_CACHE_MAX:
            # Evict first quarter of entries (FIFO approximation via dict order)
            evict_count = self._PATH_KEY_CACHE_MAX // 4
            for _ in range(evict_count):
                try:
                    self._path_key_cache.pop(next(iter(self._path_key_cache)))
                except (StopIteration, RuntimeError):
                    break
        self._path_key_cache[event_type] = key_path

    def _extract_path(self, event_data: Dict[str, Any], event_type: str) -> Optional[str]:
        """Extract file path from eslogger event data.

        Strategy:
          0) Cache hit: use previously discovered key path for this event_type
          1) Direct lookup: event_data[event_type][file/target/source]["path"]
          2) Event-key scan: iterate event_data values looking for nested path
          3) Recursive fallback: deep search for any "path" key starting with "/"
        """
        # --- Strategy 0: cached key path for this event_type ---
        cached = self._path_key_cache.get(event_type)
        if cached is not None:
            try:
                obj = event_data
                for k in cached:
                    obj = obj[k]
                if isinstance(obj, str) and obj.startswith("/"):
                    return obj
            except (KeyError, TypeError):
                pass  # Cache miss for this particular event — fall through

        # --- Strategy 1: direct event_type lookup (works when event_type is correct name) ---
        specific = event_data.get(event_type, {})
        if isinstance(specific, dict):
            for key in ("file", "target", "source"):
                obj = specific.get(key)  # type: ignore[assignment]  # FIX_54 ast-pos
                if isinstance(obj, dict) and "path" in obj:
                    self._cache_path_key(event_type, (event_type, key, "path"))
                    return obj["path"]

        # --- Strategy 2: scan all event_data values (handles wrong/unknown event_type) ---
        for evt_key, evt_val in event_data.items():
            if not isinstance(evt_val, dict):
                continue
            for fkey in ("file", "target", "source", "executable"):
                obj = evt_val.get(fkey)  # type: ignore[assignment]  # FIX_54 ast-pos
                if isinstance(obj, dict) and "path" in obj:
                    self._cache_path_key(event_type, (evt_key, fkey, "path"))
                    return obj["path"]

        # --- Strategy 3: recursive fallback (future-proofing for Apple restructuring) ---
        result = self._recursive_find_path(event_data, max_depth=6)
        if result:
            return result

        # Unix socket events: path from dir + filename
        try:
            for sock_key in ("uipc_bind", "uipc_connect"):
                sock_data = event_data.get(sock_key, {})
                if isinstance(sock_data, dict):
                    dir_obj = sock_data.get("dir", {})
                    dir_path = dir_obj.get("path", "") if isinstance(dir_obj, dict) else ""
                    filename = sock_data.get("filename", "")
                    if dir_path and filename:
                        return str(Path(dir_path) / filename)
        except (TypeError, ValueError) as exc:
            logging.debug("Socket event parse failed: %s", exc)

        return None

    def _recursive_find_path(
        self, data: Any, max_depth: int = RECURSIVE_PATH_MAX_DEPTH, _depth: int = 0,
    ) -> Optional[str]:
        """Recursively search for a 'path' key with an absolute path value.

        Bounded to max_depth to prevent runaway on large payloads.
        Skips stat blocks and other non-file-path containers.
        """
        if _depth >= max_depth or not isinstance(data, dict):
            return None
        if len(data) > _MAX_DICT_KEYS_RECURSIVE:
            logging.debug("Recursive path search: dict too large (%d keys), aborting", len(data))
            return None
        for key, val in data.items():
            if key == "path" and isinstance(val, str) and val.startswith("/"):
                return val
            if isinstance(val, dict) and key not in ("stat", "action", "result"):
                result = self._recursive_find_path(val, max_depth, _depth + 1)
                if result:
                    return result
        return None

    def _parse_event(self, line: str) -> Optional[Tuple[int, str, str, bool]]:
        """Extract event data from eslogger JSON line (string wrapper).

        Parses the line and delegates to _parse_event_obj.
        Used by begin_accepting for backward-compat with string buffers.
        """
        if len(line) > _MAX_EVENT_LINE_BYTES:
            self._parse_fail += 1
            logging.warning("Oversized event line in _parse_event (%d bytes), skipping", len(line))
            return None
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self._parse_fail += 1
            logging.debug("eslogger JSON decode failed: %.100s", line.strip())
            return None
        if not isinstance(event, dict):
            self._parse_fail += 1
            return None
        # Validate required event schema keys before full parse
        if "event_type" not in event:
            self._parse_fail += 1
            return None
        return self._parse_event_obj(event)

    def _parse_event_obj(self, event: Dict[str, Any]) -> Optional[Tuple[int, str, str, bool]]:
        """Extract event data from a pre-parsed eslogger event dict.

        Returns (pid, name_or_path, event_type, is_ipc):
          - is_ipc=False: name is a node name (relative .py path without extension)
          - is_ipc=True: name is an absolute IPC file path
        Returns None if event is not relevant (wrong process, wrong path).
        """
        # Process filtering — extract PID first for pinned fast-path
        process = event.get("process", {})

        # PID extraction (null-safe: audit_token may be None on macOS 26)
        audit_token = process.get("audit_token") or {}
        pid = audit_token.get("pid", 0) if isinstance(audit_token, dict) else 0
        if not pid:
            pid = process.get("pid", 0)
        if not pid:
            self._parse_fail += 1
            return None

        # Pinned PID fast-path: known to be Python (registered by ScriptSupervisor)
        is_pinned = pid in self._pinned_pids
        if is_pinned:
            self._pinned_events_seen += 1
            if self._diag_sample_raw is None:
                self._diag_sample_raw = json.dumps(event, default=str)[:DIAG_RAW_EVENT_TRUNCATE]
                logging.debug(
                    "eslogger DIAG: first event from pinned PID %d: %s",
                    pid, self._diag_sample_raw,
                )
        if not is_pinned and not self._is_python_process(process):
            self._skip_not_python += 1
            return None

        # Event type: resolve to canonical name
        event_type_raw = event.get("event_type", "")
        if isinstance(event_type_raw, int):
            # macOS 26+: event_type is integer — infer name from event data keys
            event_data_keys = set(event.get("event", {}).keys())
            matched = event_data_keys & _ESLOGGER_EVENTS_SET
            event_type = matched.pop() if len(matched) == 1 else str(event_type_raw)
        else:
            event_type = str(event_type_raw).replace("ES_EVENT_TYPE_NOTIFY_", "").lower()

        # File path extraction
        event_data = event.get("event", {})
        fpath = self._extract_path(event_data, event_type)
        if not fpath:
            self._skip_no_path += 1
            # Log first few skipped events from pinned PIDs for diagnostics
            if is_pinned and self._pinned_skip_samples < DIAG_PINNED_SKIP_SAMPLES:
                self._pinned_skip_samples += 1
                logging.debug(
                    "eslogger: pinned PID %d event skipped (no_path), event_type=%s: %.200s",
                    pid, event_type, json.dumps(event, default=str),
                )
            return None

        # Map __pycache__/*.pyc → source .py
        if "__pycache__" in fpath and fpath.endswith(".pyc"):
            parent_dir = Path(fpath).parent.parent
            mod_stem = Path(fpath).stem.split(".")[0]
            fpath = str(parent_dir / f"{mod_stem}.py")

        # --- IPC file branch ---
        if not fpath.endswith(".py"):
            ext = Path(fpath).suffix
            if ext in IPC_FILE_EXTENSIONS:
                # Socket/pipe files and temp-dir IPC files may live outside repo
                # — only require repo locality for data files not in /tmp
                is_socket = ext in (".sock", ".pipe")
                in_tmp = fpath.startswith("/tmp/") or fpath.startswith("/var/folders/")
                in_repo = fpath.startswith(self.repo_str) or fpath.startswith(self._repo_str_alt)
                if is_socket or in_tmp or in_repo:
                    self._parse_ok += 1
                    return (pid, fpath, event_type, True)
            self._skip_not_relevant_ext += 1
            if is_pinned and self._pinned_skip_samples < 5:
                self._pinned_skip_samples += 1
                logging.debug(
                    "eslogger: pinned PID %d event skipped (not_relevant_ext), path=%s",
                    pid, fpath[:200],
                )
            return None

        # --- .py module branch (existing behavior) ---
        if not fpath.startswith(self.repo_str) and not fpath.startswith(self._repo_str_alt):
            self._skip_outside_repo += 1
            if is_pinned and self._pinned_skip_samples < 5:
                self._pinned_skip_samples += 1
                logging.debug(
                    "eslogger: pinned PID %d event skipped (outside_repo), path=%s repo=%s",
                    pid, fpath[:200], self.repo_str,
                )
            return None

        try:
            rel = Path(fpath).relative_to(self.repo)
            self._parse_ok += 1
            return (pid, str(rel.with_suffix("")), event_type, False)
        except ValueError:
            self._parse_fail += 1
            return None

    # ------------------------------------------------------------------
    # Reader loop (bounded queue for burst protection)
    # ------------------------------------------------------------------

    async def _read_loop(self) -> None:
        """Consume eslogger JSON stdout, queue events for main loop."""
        assert self._process is not None and self._process.stdout is not None
        self._last_prune_time = time.monotonic()
        self._events_since_prune = 0
        while self._running:
            try:
                raw = await self._process.stdout.readline()
                if not raw:
                    break
                if len(raw) > _MAX_EVENT_LINE_BYTES:
                    self._parse_fail += 1
                    logging.warning("Oversized event line (%d bytes), skipping", len(raw))
                    continue
                line = raw.decode("utf-8", errors="replace")

                # Parse JSON once — reused by all handlers below
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    self._parse_fail += 1
                    continue
                if not isinstance(event, dict):
                    self._parse_fail += 1
                    continue
                # Validate required event schema key
                if "event_type" not in event:
                    self._parse_fail += 1
                    continue

                self._last_event_time = time.monotonic()

                # Always process lifecycle events (exec/exit) even before accepting
                try:
                    self._handle_lifecycle_event(event)
                except Exception as exc:
                    logging.error("Lifecycle handler error: %s", exc, exc_info=True)
                    self._parse_fail += 1
                if not self._accepting:
                    self._pending_lines.append(event)
                    continue
                # DIAG: check for any events from pinned PIDs at raw JSON level
                if self._pinned_pids and self._pinned_events_seen < 1:
                    try:
                        _proc = event.get("process", {})
                        _at = _proc.get("audit_token") or {}
                        _pid = _at.get("pid", 0) if isinstance(_at, dict) else 0
                        if _pid in self._pinned_pids:
                            logging.warning(
                                "LIVE DIAG: event from pinned PID %d (first seen in live stream): "
                                "executable=%s event_type=%s",
                                _pid, _proc.get("executable", {}).get("path", "?")
                                if isinstance(_proc.get("executable"), dict) else _proc.get("executable"),
                                event.get("event_type"),
                            )
                    except Exception as exc:
                        logging.debug("Event line parse failed: %s", exc)
                # Handle file lifecycle events (create/unlink/rename) for kernel file discovery
                try:
                    self._handle_file_lifecycle_from_event(event)
                except Exception as exc:
                    logging.error("File lifecycle handler error: %s", exc, exc_info=True)
                # Handle socket events (bind/connect/listen/accept) for kernel socket tracking
                try:
                    self._handle_socket_event_from_event(event)
                except Exception as exc:
                    logging.error("Socket handler error: %s", exc, exc_info=True)
                result = self._parse_event_obj(event)
                if result:
                    pid, name_or_path, evt, is_ipc = result
                    target_q = self._ipc_event_queue if is_ipc else self._event_queue
                    try:
                        await asyncio.wait_for(
                            target_q.put((pid, name_or_path, evt, time.monotonic())),
                            timeout=QUEUE_PUT_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        self._queue_drops += 1
                        # Circuit breaker: track drops within time window
                        now_cb = time.monotonic()
                        if now_cb - self._queue_drop_window_start > QUEUE_DROP_CIRCUIT_WINDOW:
                            self._queue_drop_window_start = now_cb
                            self._queue_drops_in_window = 0
                        self._queue_drops_in_window += 1
                        if self._queue_drops_in_window >= QUEUE_DROP_CIRCUIT_BREAKER:
                            logging.critical(
                                "Event queue circuit breaker: %d drops in %.0fs — "
                                "STOPPING TRACER (total drops=%d)",
                                self._queue_drops_in_window,
                                QUEUE_DROP_CIRCUIT_WINDOW,
                                self._queue_drops,
                            )
                            self._running = False
                            break
                        elif self._queue_drops == 1 or self._queue_drops % QUEUE_DROP_ALERT_INTERVAL == 0:
                            logging.warning(
                                "Event queue backpressure — dropped %d events "
                                "(queue_size=%d).",
                                self._queue_drops, EVENT_QUEUE_SIZE,
                            )
                # Periodic auto-prune to bound memory between poll cycles
                self._events_since_prune += 1
                now = time.monotonic()
                if (self._events_since_prune >= READER_PRUNE_EVENT_THRESHOLD
                        and now - self._last_prune_time > READER_PRUNE_INTERVAL):
                    async with self._lock:
                        self._auto_prune_unlocked()
                    self._events_since_prune = 0
                    self._last_prune_time = now
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._parse_fail += 1
                if self._parse_fail <= 5:
                    logging.warning("eslogger read loop error: %s", exc, exc_info=True)
                # Circuit breaker: stop if parse failures dominate
                total = self._parse_ok + self._parse_fail
                if (self._parse_fail >= PARSE_FAIL_CIRCUIT_MIN
                        and total > 0
                        and self._parse_fail / total > PARSE_FAIL_RATIO_THRESHOLD):
                    logging.error(
                        "Parse failure circuit breaker: %d failures / %d total (%.0f%%) — "
                        "stopping tracer (eslogger format mismatch?)",
                        self._parse_fail, total,
                        100.0 * self._parse_fail / total,
                    )
                    self._running = False
                    break
                continue

    def _ensure_process_entry(self, pid: int) -> ProcessEvents:
        """Get or create a _process_events entry for pid."""
        entry = self._process_events.get(pid)
        if entry is None:
            entry: ProcessEvents = {"modules": {}, "ipc_files": {}, "sequence": []}  # type: ignore[no-redef]  # FIX_54 ast-pos
            self._process_events[pid] = entry
        return entry

    @staticmethod
    def _prune_sequence(seq: List[Tuple[float, str]]) -> List[Tuple[float, str]]:
        """Prune event sequence preserving temporal locality.

        Keeps the first 50 events (entry behavior) and the most recent
        (EVENT_SEQUENCE_KEEP - 50) events so that _infer_temporal_edges
        has chronological coverage of both early and late activity.
        """
        if len(seq) <= EVENT_SEQUENCE_MAX:
            return seq
        head = 50
        tail_keep = EVENT_SEQUENCE_KEEP - head
        return seq[:head] + seq[-tail_keep:]

    async def _drain_queue(self) -> None:
        """Drain queued events into _process_events. Called from main poll loop."""
        async with self._lock:
            while not self._event_queue.empty():
                try:
                    pid, node_name, event_type, ts = self._event_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                entry = self._ensure_process_entry(pid)
                modules = entry["modules"]
                old_s = self._event_strength.get(modules.get(node_name, ""), 0)
                new_s = self._event_strength.get(event_type, 0)
                if new_s > old_s:
                    modules[node_name] = event_type
                # Track event sequence for temporal edge inference
                seq = entry["sequence"]
                seq.append((ts, node_name))
                if len(seq) > EVENT_SEQUENCE_MAX:
                    entry["sequence"] = self._prune_sequence(seq)
                self._event_count += 1

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    async def get_connected_modules(
        self, min_strength: int = _MIN_CONNECTION_STRENGTH,
    ) -> Dict[int, Set[str]]:
        """PID → set of node names with kernel events at or above min_strength."""
        await self._drain_queue()
        async with self._lock:
            result: Dict[int, Set[str]] = {}
            for pid, entry in self._process_events.items():
                strong = {
                    name for name, evt in entry["modules"].items()
                    if self._event_strength.get(evt, 0) >= min_strength
                }
                if strong:
                    result[pid] = strong
            return result

    async def get_all_events(self) -> Dict[int, Dict[str, str]]:
        """Full PID → {node: event_type} including weak events. For metrics."""
        await self._drain_queue()
        async with self._lock:
            return {pid: dict(entry["modules"]) for pid, entry in self._process_events.items()}

    async def get_event_sequence(self) -> Dict[int, List[Tuple[float, str]]]:
        """PID → [(monotonic_time, node_name)] for temporal edge inference."""
        await self._drain_queue()
        async with self._lock:
            return {pid: list(entry["sequence"]) for pid, entry in self._process_events.items()}

    async def _drain_ipc_queue(self) -> None:
        """Drain IPC file events into _process_events."""
        async with self._lock:
            while not self._ipc_event_queue.empty():
                try:
                    pid, fpath, event_type, ts = self._ipc_event_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                entry = self._ensure_process_entry(pid)
                ipc = entry["ipc_files"]
                old_s = self._event_strength.get(ipc.get(fpath, ""), 0)
                new_s = self._event_strength.get(event_type, 0)
                if new_s > old_s:
                    ipc[fpath] = event_type
                # Prune event sequence (same as _drain_queue)
                seq = entry["sequence"]
                seq.append((ts, fpath))
                if len(seq) > EVENT_SEQUENCE_MAX:
                    entry["sequence"] = self._prune_sequence(seq)

    async def get_ipc_files(
        self, min_strength: int = _MIN_CONNECTION_STRENGTH,
    ) -> Dict[int, Set[str]]:
        """PID → set of IPC file paths with sufficient event strength."""
        await self._drain_ipc_queue()
        async with self._lock:
            result: Dict[int, Set[str]] = {}
            for pid, entry in self._process_events.items():
                strong = {
                    path for path, evt in entry["ipc_files"].items()
                    if self._event_strength.get(evt, 0) >= min_strength
                }
                if strong:
                    result[pid] = strong
            return result

    def _handle_lifecycle_event(self, event: Dict[str, Any]) -> None:
        """Handle exec/exit events for kernel-proven process tracking.

        Called synchronously from _read_loop for every pre-parsed event.
        Updates _kernel_running dict directly (no queue — lifecycle events are rare).
        """
        event_type_raw = event.get("event_type", "")
        if isinstance(event_type_raw, int):
            event_data_keys = set(event.get("event", {}).keys())
            if "exec" in event_data_keys:
                event_type = "exec"
            elif "exit" in event_data_keys:
                event_type = "exit"
            else:
                return
        else:
            event_type = str(event_type_raw).replace("ES_EVENT_TYPE_NOTIFY_", "").lower()

        if event_type not in ("exec", "exit"):
            return

        # Extract PID
        process = event.get("process", {})
        audit_token = process.get("audit_token") or {}
        pid = audit_token.get("pid", 0) if isinstance(audit_token, dict) else 0
        if not pid:
            pid = process.get("pid", 0)
        if not pid:
            return

        if event_type == "exit":
            self._kernel_running.pop(pid, None)
            if self._kernel_pytest and self._kernel_pytest.get("pid") == pid:
                self._kernel_pytest = None
            return

        self._handle_exec_event(event, pid)

    def _handle_exec_event(self, event: Dict[str, Any], pid: int) -> None:
        """Process an exec event — detect Python scripts and pytest in our repo."""
        event_data = event.get("event", {})
        exec_data = event_data.get("exec", {})

        # Get the target executable
        target = exec_data.get("target", {})
        target_exe = target.get("executable", {})
        exe_path = target_exe.get("path", "") if isinstance(target_exe, dict) else ""

        if not any(ind in exe_path.lower() for ind in ("python", "Python")):
            return

        # Normalize args across eslogger versions
        args = exec_data.get("args", [])
        if isinstance(args, dict):
            args = args.get("args", [])
        if not isinstance(args, list):
            args = []

        command = " ".join(str(a)[:_ARG_MAX_LEN] for a in args[:COMMAND_MAX_ARGS])[:COMMAND_TRUNCATE] if args else exe_path

        # Pytest detection (kernel-proven)
        self._detect_pytest_in_args(pid, args, command)

        # Script path resolution and recording
        script_path = self._resolve_script_path(args)
        if not script_path:
            return

        if not script_path.startswith(self.repo_str) and not script_path.startswith(self._repo_str_alt):
            return

        try:
            rel = Path(script_path).relative_to(self.repo)
            node_name = str(rel.with_suffix(""))
        except ValueError:
            return

        self._kernel_running[pid] = {
            "name": node_name,
            "script_path": script_path,
            "started_at": now_iso(),
            "command": command,
            "proof": PROOF_KERNEL,
        }

    def _detect_pytest_in_args(self, pid: int, args: List, command: str) -> None:
        """Check if exec args indicate a test runner in our repo."""
        args_str = " ".join(str(a) for a in args)
        if not any(p in args_str for p in self._test_runner_patterns):
            return

        repo_in_args = self.repo_str in args_str or self._repo_str_alt in args_str
        test_path = ""
        for arg in args:
            if isinstance(arg, str):
                if arg.endswith(".py") or "test" in arg.lower():
                    test_path = arg
                    if arg.startswith(self.repo_str) or arg.startswith(self._repo_str_alt):
                        repo_in_args = True
                    break

        if repo_in_args:
            self._kernel_pytest = {
                "pid": pid,
                "command": command,
                "runner": "unittest" if "unittest" in args_str else "pytest",   # Item 10
                "test_path": test_path,
                "started_at": now_iso(),
                "proof": PROOF_KERNEL,
            }

    def _resolve_script_path(self, args: List) -> Optional[str]:
        """Extract script path from exec args (direct .py or -m module.name).

        Resolves relative paths and symlinks so the result always starts
        with the repo prefix for reliable ``startswith()`` checks.
        """
        script_path = None
        module_run = None

        for i, arg in enumerate(args):
            if isinstance(arg, str):
                if arg.endswith(".py"):
                    # Resolve relative paths and symlinks
                    try:
                        script_path = str(Path(arg).resolve())
                    except (OSError, ValueError):
                        script_path = arg
                    break
                elif arg == "-m" and i + 1 < len(args):
                    module_run = args[i + 1]

        # Convert -m module.name to filesystem path
        if not script_path and module_run and isinstance(module_run, str):
            parts = module_run.replace(".", "/")
            potential_path = str(self.repo / f"{parts}.py")
            if Path(potential_path).exists():
                script_path = potential_path
            else:
                potential_main = str(self.repo / parts / "__main__.py")
                if Path(potential_main).exists():
                    script_path = potential_main

        return script_path

    def get_kernel_running(self) -> Dict[int, KernelProcessInfo]:
        """Return kernel-proven running processes (from exec/exit events).

        Returns:
            Dict mapping PID to process info with keys:
                name: Node name (relative path without .py)
                script_path: Absolute path to script
                started_at: ISO timestamp when exec was observed
                command: Truncated command line
                proof: Always "kernel"
        """
        return dict(self._kernel_running)

    def get_kernel_pytest(self) -> Optional[Dict[str, Any]]:
        """Return kernel-proven pytest info (from exec events).

        Returns:
            Dict with keys: pid, command, test_path, started_at, proof
            or None if no pytest detected.
        """
        if self._kernel_pytest is None:
            return None
        # Expire stale pytest info if exit event was missed (e.g., queue overflow)
        started = self._kernel_pytest.get("started_at", "")
        if started:
            try:
                from datetime import datetime, timezone
                started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - started_dt).total_seconds()
                if age > 300.0:  # 5 minute TTL
                    self._kernel_pytest = None
                    return None
            except (ValueError, TypeError):
                pass
        return dict(self._kernel_pytest)  # type: ignore[arg-type]  # FIX_54 ast-pos

    def _handle_file_lifecycle_event(self, event: Dict[str, Any], event_type: str) -> None:
        """Handle create/unlink/rename events for kernel-based file discovery.

        Called synchronously from _read_loop for file lifecycle events.
        Enqueues events for deferred processing under lock (avoids race
        with main loop reading _discovered_files/_deleted_files).
        """
        event_data = event.get("event", {})
        now = time.monotonic()

        # Extract file path based on event type
        if event_type == "create":
            target = event_data.get("create", {}).get("destination", {})
            fpath = target.get("path", "") if isinstance(target, dict) else ""
        elif event_type == "unlink":
            target = event_data.get("unlink", {}).get("target", {})
            fpath = target.get("path", "") if isinstance(target, dict) else ""
        elif event_type == "rename":
            # For rename, enqueue both source (delete) and destination (create)
            source = event_data.get("rename", {}).get("source", {})
            dest = event_data.get("rename", {}).get("destination", {})
            old_path = source.get("path", "") if isinstance(source, dict) else ""
            new_path = dest.get("path", "") if isinstance(dest, dict) else ""

            if old_path.endswith(".py"):
                if old_path.startswith(self.repo_str) or old_path.startswith(self._repo_str_alt):
                    try:
                        rel = Path(old_path).relative_to(self.repo)
                        node_name = str(rel.with_suffix(""))
                        self._file_lifecycle_queue.append(("delete", node_name, now))
                    except ValueError:
                        pass

            if new_path.endswith(".py"):
                if new_path.startswith(self.repo_str) or new_path.startswith(self._repo_str_alt):
                    try:
                        rel = Path(new_path).relative_to(self.repo)
                        node_name = str(rel.with_suffix(""))
                        self._file_lifecycle_queue.append(("create", node_name, now))
                    except ValueError:
                        pass
            return
        else:
            return

        # For create/unlink, process single path
        if not fpath.endswith(".py"):
            return

        if not fpath.startswith(self.repo_str) and not fpath.startswith(self._repo_str_alt):
            return

        try:
            rel = Path(fpath).relative_to(self.repo)
            node_name = str(rel.with_suffix(""))
        except ValueError:
            return

        if event_type == "create":
            self._file_lifecycle_queue.append(("create", node_name, now))
        elif event_type == "unlink":
            self._file_lifecycle_queue.append(("delete", node_name, now))

    def _drain_file_lifecycle_queue(self) -> None:
        """Apply queued file lifecycle events to _discovered_files/_deleted_files.

        Must be called under self._lock.
        """
        while self._file_lifecycle_queue:
            action, node_name, ts = self._file_lifecycle_queue.popleft()
            if action == "create":
                self._discovered_files[node_name] = ts
                self._deleted_files.discard(node_name)
            elif action == "delete":
                self._discovered_files.pop(node_name, None)
                self._deleted_files.add(node_name)

    def get_discovered_files(self) -> Set[str]:
        """Return set of node names discovered via kernel create events."""
        self._drain_file_lifecycle_queue()
        return set(self._discovered_files.keys())

    def get_deleted_files(self) -> Set[str]:
        """Return set of node names deleted via kernel unlink events."""
        self._drain_file_lifecycle_queue()
        return set(self._deleted_files)

    def _handle_socket_event(self, event: Dict[str, Any], event_type: str, pid: int) -> None:
        """Handle bind/connect/listen/accept events for kernel-based socket tracking.

        Detect TCP dataflows between processes via kernel socket events.
        """
        try:
            event_data = event.get("event", {})

            # Extract socket address info
            sock_info = event_data.get(event_type, {})
            if not sock_info:
                return

            # Try to extract address and port from socket info
            # eslogger socket events contain socket address details
            sock_addr = sock_info.get("socket", {}) or sock_info.get("addr", {}) or sock_info

            # Different event types have different structures
            addr = ""
            port = 0

            if isinstance(sock_addr, dict):
                # Try common field names
                addr = sock_addr.get("address", "") or sock_addr.get("ip", "") or sock_addr.get("host", "")
                port = sock_addr.get("port", 0)

                # Nested in tcp/inet structure
                if not addr:
                    inet = sock_addr.get("inet", {}) or sock_addr.get("tcp", {})
                    if isinstance(inet, dict):
                        addr = inet.get("address", "") or inet.get("ip", "")
                        port = inet.get("port", 0)

            if not port:
                return  # Can't track without port info

            # Normalize localhost addresses
            if addr in ("127.0.0.1", "::1", "localhost", ""):
                addr = "localhost"

            if event_type == "bind":
                self._socket_bindings[(addr, port)] = (pid, time.time())
                self._socket_listens.setdefault(pid, set()).add((addr, port))
            elif event_type == "listen":
                self._socket_listens.setdefault(pid, set()).add((addr, port))
            elif event_type == "connect":
                self._socket_connections.setdefault(pid, set()).add((addr, port))
            elif event_type == "accept":
                # Accept means another process connected to our bound port
                # The binding info is more important than the accept
                pass
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            logging.debug("Socket event parse failed (pid=%d): %s", pid, exc)
            self._parse_fail += 1

    def get_socket_flows(self) -> List[Dict[str, Any]]:
        """Detect TCP dataflows from kernel socket events.

        Cross-references bind/listen PIDs with connect PIDs to find
        processes communicating over TCP.

        Note: This is intentionally synchronous (not async). It only reads
        in-memory dicts populated by the async event processor, so it is
        safe to call from both sync and async contexts without await.

        Returns:
            List of dataflow dicts with keys: src, dst, channel, proof
        """
        flows: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str]] = set()
        
        # For each connecting process, check if destination is bound by another process
        for connect_pid, destinations in self._socket_connections.items():
            # Need PID → node name mapping
            connect_name = None
            if connect_pid in self._kernel_running:
                connect_name = self._kernel_running[connect_pid].get("name")
            
            if not connect_name:
                continue
            
            for addr, port in destinations:
                # Check if any other process is listening on this addr:port
                for bind_pid, bindings in self._socket_listens.items():
                    if bind_pid == connect_pid:
                        continue
                    
                    # Check for matching bind
                    if (addr, port) in bindings or ("localhost", port) in bindings or ("", port) in bindings:
                        bind_name = None
                        if bind_pid in self._kernel_running:
                            bind_name = self._kernel_running[bind_pid].get("name")
                        
                        if bind_name:
                            src, dst = sorted([connect_name, bind_name])
                            channel = f"tcp:{addr}:{port}" if addr else f"tcp:localhost:{port}"
                            key = (src, dst, channel)
                            if key not in seen:
                                seen.add(key)
                                flows.append({
                                    "src": src,
                                    "dst": dst,
                                    "channel": channel,
                                    "proof": PROOF_KERNEL,
                                })
        
        return flows

    def _handle_file_lifecycle_from_event(self, event: Dict[str, Any]) -> None:
        """Dispatch pre-parsed event to _handle_file_lifecycle_event."""
        # Get event type
        event_type_raw = event.get("event_type", "")
        if isinstance(event_type_raw, int):
            event_data_keys = set(event.get("event", {}).keys())
            if "create" in event_data_keys:
                event_type = "create"
            elif "unlink" in event_data_keys:
                event_type = "unlink"
            elif "rename" in event_data_keys:
                event_type = "rename"
            else:
                return
        else:
            event_type = str(event_type_raw).replace("ES_EVENT_TYPE_NOTIFY_", "").lower()
        
        if event_type in ("create", "unlink", "rename"):
            self._handle_file_lifecycle_event(event, event_type)

    def _handle_socket_event_from_event(self, event: Dict[str, Any]) -> None:
        """Handle socket events from a pre-parsed event dict."""
        # Get event type
        event_type_raw = event.get("event_type", "")
        if isinstance(event_type_raw, int):
            event_data_keys = set(event.get("event", {}).keys())
            socket_types = {"bind", "connect", "listen", "accept"}
            matched = event_data_keys & socket_types
            if matched:
                event_type = matched.pop()
            else:
                return
        else:
            event_type = str(event_type_raw).replace("ES_EVENT_TYPE_NOTIFY_", "").lower()
        
        if event_type not in ("bind", "connect", "listen", "accept"):
            return
        
        # Extract PID
        process = event.get("process", {})
        audit_token = process.get("audit_token") or {}
        pid = audit_token.get("pid", 0) if isinstance(audit_token, dict) else 0
        if not pid:
            pid = process.get("pid", 0)
        if not pid:
            return
        
        self._handle_socket_event(event, event_type, pid)

    def _auto_prune_unlocked(self) -> None:
        """Prune unbounded data structures to prevent memory leaks.

        Caller must hold self._lock.
        """
        # Drain pending file lifecycle events before pruning those dicts
        self._drain_file_lifecycle_queue()

        # Prune _process_events (evict PIDs with fewest modules, keep pinned)
        if len(self._process_events) > MAX_PROCESS_EVENTS:
            candidates = [
                (pid, len(entry["modules"]))
                for pid, entry in self._process_events.items()
                if pid not in self._pinned_pids
            ]
            candidates.sort(key=lambda x: x[1])
            excess = len(self._process_events) - MAX_PROCESS_EVENTS
            for pid, _ in candidates[:excess]:
                del self._process_events[pid]
            logging.debug("auto_prune: trimmed %d process_events entries", min(excess, len(candidates)))

        # Prune _discovered_files (keep newest by timestamp)
        if len(self._discovered_files) > MAX_DISCOVERED_FILES:
            sorted_items = sorted(
                self._discovered_files.items(), key=lambda x: x[1],
            )
            excess = len(self._discovered_files) - MAX_DISCOVERED_FILES
            for name, _ in sorted_items[:excess]:
                del self._discovered_files[name]
            logging.debug("auto_prune: trimmed %d discovered_files", excess)

        # Prune _deleted_files (no timestamp — evict arbitrary entries)
        if len(self._deleted_files) > MAX_DELETED_FILES:
            excess = len(self._deleted_files) - MAX_DELETED_FILES
            to_remove = list(self._deleted_files)[:excess]
            self._deleted_files -= set(to_remove)
            logging.debug("auto_prune: trimmed %d deleted_files", excess)

        # Cap _socket_bindings count (TTL expiry done in cleanup_dead_pids)
        if len(self._socket_bindings) > MAX_SOCKET_BINDINGS:
            sorted_bindings = sorted(
                self._socket_bindings.items(), key=lambda x: x[1][1],
            )
            excess = len(self._socket_bindings) - MAX_SOCKET_BINDINGS
            for k, _ in sorted_bindings[:excess]:
                del self._socket_bindings[k]
            logging.debug("auto_prune: trimmed %d socket_bindings", excess)

    async def cleanup_dead_pids(self, alive_pids: Optional[Set[int]] = None) -> int:
        """Prune PIDs no longer alive. Returns count removed.

        Pinned PIDs (registered via :meth:`register_pid`) are always
        preserved regardless of liveness.
        """
        async with self._lock:
            dead: List[int] = []
            for p in self._process_events:
                if alive_pids and p in alive_pids:
                    continue
                if p in self._pinned_pids:
                    continue
                try:
                    os.kill(p, 0)
                except PermissionError:
                    pass  # still alive, just can't signal
                except (ProcessLookupError, OSError, SystemError, ValueError):
                    dead.append(p)
            for p in dead:
                del self._process_events[p]
                self._kernel_running.pop(p, None)
                # Clean up socket tracking for dead PIDs
                self._socket_connections.pop(p, None)
                self._socket_listens.pop(p, None)
                # Remove from socket_bindings any entries for this PID
                bindings_to_remove = [k for k, (bp, _ts) in self._socket_bindings.items() if bp == p]
                for k in bindings_to_remove:
                    del self._socket_bindings[k]

            # Expire stale bindings
            now = time.time()
            stale = [
                k for k, (bp, ts) in self._socket_bindings.items()
                if now - ts > SOCKET_BINDING_TTL and bp not in self._socket_listens
            ]
            for k in stale:
                del self._socket_bindings[k]

            # Auto-prune unbounded structures
            self._auto_prune_unlocked()

            return len(dead)

    # ------------------------------------------------------------------
    # PID Registry (pinning for persistent / verification subprocesses)
    # ------------------------------------------------------------------

    async def register_pid(self, pid: int, tag: str = "") -> None:
        """Pin PID for cleanup preservation. Tag is optional (for logging).

        IMPORTANT: Caller must ensure all PIDs are registered BEFORE calling
        begin_accepting(). Concurrent calls are safe but order matters.
        """
        async with self._lock:
            self._pinned_pids.add(pid)
            if tag:
                logging.info("Pinned PID %d (%s)", pid, tag)

    async def unregister_pid(self, pid: int) -> None:
        """Unpin a PID so normal cleanup resumes."""
        async with self._lock:
            self._pinned_pids.discard(pid)

    async def get_pinned_pids(self) -> Set[int]:
        """Return a snapshot of all pinned PIDs."""
        async with self._lock:
            return set(self._pinned_pids)

    async def begin_accepting(self) -> None:
        """Open the event gate and stream buffered eslogger events.

        Call after all supervised PIDs are pinned so buffered events
        pass the pinned-PID check in ``_parse_event_obj``.

        Processes in batches of 100 with ``asyncio.sleep(0)`` yields
        to prevent blocking the event loop when buffer is large.
        """
        self._accepting = True
        n_buffered = len(self._pending_lines)
        logging.info("begin_accepting: pinned_pids=%s, buffered=%d",
                     sorted(self._pinned_pids), n_buffered)
        # Reset skip counters to measure only the buffer drain
        skip_before = self._skip_not_python
        streamed = 0
        batch_count = 0
        batch_size = 100
        sample_pids: Set[int] = set()
        pinned_set = set(self._pinned_pids)
        nearby_logged = 0
        while self._pending_lines:
            event = self._pending_lines.popleft()
            # Peek at PID in the pre-parsed event for diagnostics
            if len(sample_pids) < DIAG_SAMPLE_PIDS or nearby_logged < DIAG_NEARBY_LIMIT:
                try:
                    proc = event.get("process", {})
                    at = proc.get("audit_token", {})
                    pid = at.get("pid", 0) if isinstance(at, dict) else 0
                    if pid:
                        sample_pids.add(pid)
                    # Log process info for PIDs near the pinned range
                    if pid and nearby_logged < DIAG_NEARBY_LIMIT and pinned_set:
                        min_pinned = min(pinned_set)
                        max_pinned = max(pinned_set)
                        if min_pinned - DIAG_PID_RANGE_BELOW <= pid <= max_pinned + DIAG_PID_RANGE_ABOVE:
                            nearby_logged += 1
                            logging.info(
                                "begin_accepting DIAG: pid=%d executable=%s "
                                "signing_id=%s is_pinned=%s ppid=%s",
                                pid,
                                proc.get("executable"),
                                proc.get("signing_id"),
                                pid in pinned_set,
                                proc.get("parent_audit_token", {}).get("pid")
                                if isinstance(proc.get("parent_audit_token"), dict) else
                                proc.get("ppid"),
                            )
                except Exception as exc:
                    logging.debug("Buffered event inspect failed: %s", exc)
            result = self._parse_event_obj(event)
            if result:
                pid, name_or_path, evt, is_ipc = result
                target_q = self._ipc_event_queue if is_ipc else self._event_queue
                try:
                    target_q.put_nowait((pid, name_or_path, evt, time.monotonic()))
                    streamed += 1
                except asyncio.QueueFull:
                    self._queue_drops += 1
                    if self._queue_drops % 500 == 0:
                        logging.warning(
                            "begin_accepting: queue full, dropped %d buffered events",
                            self._queue_drops,
                        )
            # Yield control every batch_size events to avoid starving event loop
            batch_count += 1
            if batch_count >= batch_size:
                batch_count = 0
                await asyncio.sleep(0)
        skip_during = self._skip_not_python - skip_before
        logging.info("begin_accepting: streamed %d, skipped_not_python=%d, "
                     "sample_pids_in_buffer=%s",
                     streamed, skip_during, sorted(sample_pids)[:DIAG_SAMPLE_PIDS])

    async def get_events_for_pid(self, pid: int) -> Dict[str, str]:
        """Return kernel events recorded for a specific PID.

        Returns:
            Dict mapping node_name → best_event_type for the given PID.
            Empty dict if no events recorded.
        """
        async with self._lock:
            entry = self._process_events.get(pid)
            return dict(entry["modules"]) if entry else {}

    async def ensure_running(self) -> bool:
        """Relaunch eslogger if it died or appears hung. Returns True if running."""
        if self.is_running:
            # Health check: detect hung tracer (alive but no events)
            uptime = time.monotonic() - self._start_time
            if uptime > self._health_check_warmup and self._last_event_time > 0:
                stall_duration = time.monotonic() - self._last_event_time
                if stall_duration > self._health_check_stall_window:
                    logging.warning(
                        "Tracer appears stalled (no events for %.0fs) — restarting",
                        stall_duration,
                    )
                    await self.stop()
                    return await self.start()
            self._relaunch_backoff = 1.0
            return True
        if time.monotonic() - self._last_relaunch_attempt < self._relaunch_backoff:
            return False
        logging.warning(
            "%s died — relaunching (backoff=%.1fs)",
            self._backend_name, self._relaunch_backoff,
        )
        self._last_relaunch_attempt = time.monotonic()
        ok = await self.start()
        if not ok:
            self._relaunch_backoff = min(self._relaunch_backoff * 2, MAX_RELAUNCH_BACKOFF)
        return ok

    @property
    def _relaunch_backoff(self) -> float:
        return self.__relaunch_backoff

    @_relaunch_backoff.setter
    def _relaunch_backoff(self, value: float) -> None:
        self.__relaunch_backoff = min(value, MAX_RELAUNCH_BACKOFF)

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def is_running(self) -> bool:
        return (
            self._running
            and self._process is not None
            and self._process.returncode is None
        )

    @property
    def health(self) -> Dict[str, Any]:
        parse_skip = (
            self._skip_not_python + self._skip_no_path
            + self._skip_not_relevant_ext + self._skip_outside_repo
        )
        return {
            "backend": self._backend_name,
            "alive": self.is_running,
            "pid": self._process.pid if self._process else None,
            "events_total": self._event_count,
            "tracked_pids": len(self._process_events),
            "parse_ok": self._parse_ok,
            "parse_skip": parse_skip,
            "parse_fail": self._parse_fail,
            "queue_drops": self._queue_drops,
            "uptime_seconds": round(time.monotonic() - self._start_time) if self._start_time else 0,
            "skip_not_python": self._skip_not_python,
            "skip_no_path": self._skip_no_path,
            "skip_not_relevant_ext": self._skip_not_relevant_ext,
            "skip_outside_repo": self._skip_outside_repo,
            "pinned_pids": sorted(self._pinned_pids),
            "pinned_events_seen": self._pinned_events_seen,
        }




# Item 7 (2026-09-10): `select_kernel_backend` archived — never called, referenced a nonexistent
# Config; the launch chooses the backend (--tracer) and circuit_daemon.run_daemon starts it.
