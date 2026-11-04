#!/usr/bin/env python3
"""
engine_utils.py — Shared utilities for the circuit monitor system.

Provides:
  - Subprocess execution with timeout + error handling
  - JSON I/O with atomic writes
  - File hashing
  - Legacy config helpers (prefer config.py / load_config() for new code)

State Model Definitions (canonical reference)
=============================================

NODE STATES (mutually compatible):
  - discovered: Node found via import analysis (always True if in nodes list)
  - connected: Kernel proof of import obtained (L1: kernel_imports check passed).
                This means the import statement was traced by eslogger, NOT that
                the module actually resolves or executes code.
  - running: Process currently active (PID exists, kernel-verified)
  - has_dataflow: Participating in active data flow

INTEGRATION STATES (linear progression):
  - candidate: In targets list, not yet current
  - active: Current integration target (current_index points here)
  - integrated: Integration verified (L2+ requirement met), added to integrated list

VERIFICATION LEVELS (0-4, must advance sequentially):
  L0: not_started (discovered but not connected)
  L1: kernel_imports (kernel proof of import edges) → SETS connected=True
  L2: resolve + critical (all critical nodes connected) → INTEGRATION THRESHOLD
  L3: runtime (output equivalence passed) → CONFIDENCE CHECK
  L4: execute (code coverage passed) → FULL VERIFICATION

PROCESS STATES:
  - alive: Process running (PID valid, may not be traced)
  - traced: Kernel events captured for this PID
  - kernel_verified: Running status proven via kernel trace (not inferred)
"""

from __future__ import annotations

import asyncio
import fcntl
import functools
import hashlib
import json
import logging
import operator
import os
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar, Union, overload

from typing_extensions import NotRequired, TypedDict

T = TypeVar("T")

_UTC = timezone.utc


# ---------------------------------------------------------------------------
# Canonical proof types (single source of truth)
# ---------------------------------------------------------------------------


class ProofType(str, Enum):
    """Provenance proof for connections, running status, and verification.

    - KERNEL: Proven by kernel events (eslogger/ESF)
    - SUBPROCESS: Captured from subprocess execution
    - TRACE: Traced execution (import hooks, sys.settrace)
    - INFERRED: Deduced from runtime state (ps)
    - NONE: No proof available

    Inherits from str for JSON round-trip compatibility. Values serialize
    as plain strings and comparisons work with both enum and string forms::

        proof = ProofType.KERNEL
        proof == "kernel"           # True
        json.dumps({"p": proof})    # '{"p": "kernel"}'

    After JSON deserialization, values are plain ``str``, not ``ProofType``.
    Use ``==`` comparison (not ``isinstance()``) and avoid calling enum
    methods like ``.display()`` on deserialized values without converting
    first via ``ProofType(value)``.
    """
    KERNEL = "kernel"
    SUBPROCESS = "subprocess"
    INFERRED = "inferred"
    TRACE = "trace"
    RUNNER = "runner"     # Item 10 (2026-09-15): reached through a test runner — a warning, never a pass
    NONE = "none"

    def display(self) -> str:
        """Human-readable label for dashboard display."""
        return _PROOF_DISPLAY.get(self, self.value)


_PROOF_DISPLAY = {
    ProofType.KERNEL: "kernel \u2713",
    ProofType.SUBPROCESS: "subprocess \u2713",
    ProofType.TRACE: "trace \u2713",
    ProofType.INFERRED: "inferred",
    ProofType.RUNNER: "via runner \u26a0",
    ProofType.NONE: "\u2014",
}

# Constants for backward compatibility
PROOF_KERNEL = ProofType.KERNEL.value
PROOF_SUBPROCESS = ProofType.SUBPROCESS.value
PROOF_TRACE = ProofType.TRACE.value
PROOF_INFERRED = ProofType.INFERRED.value
PROOF_NONE = ProofType.NONE.value


# ---------------------------------------------------------------------------
# Typed data structures (JSON-compatible, shared by daemon + dashboard)
# ---------------------------------------------------------------------------


class NodeDict(TypedDict, total=False):
    """A tracked .py file in the repository."""
    name: str
    path: str
    relative_path: str
    module: str
    connected: bool
    imports: List[str]
    syntax_ok: bool
    import_error: Optional[str]
    content_hash: str
    proof: ProofType
    running: bool
    pid: Optional[int]
    running_proof: ProofType
    has_dataflow: bool
    runtime_loaded_via: Optional[str]   # Item 10: "app" | "runner" | "app+runner" | None


class DataflowDict(TypedDict):
    """Kernel-proven IPC between two nodes."""
    src: str
    dst: str
    channel: str
    proof: ProofType


class RunningDict(TypedDict):
    """A detected running process."""
    pid: int
    command: str
    detected_at: str
    proof: ProofType


class PytestKernelDict(TypedDict, total=False):
    """Test runner process detected by the kernel tracer (Item 10: the tracer writes `started_at`,
    never `detected_at` — the name the tracer has always set; `runner` = pytest | unittest)."""
    pid: int
    command: str
    runner: str
    test_path: str
    started_at: str
    proof: ProofType


class IntegrationStatusDict(TypedDict):
    """Canonical integration state for agent consumption."""
    current_target: str
    current_level: int
    targets_integrated: List[str]
    targets_remaining: List[str]
    all_integrated: bool


class VerificationCheckDict(TypedDict, total=False):
    """A single verification check result."""
    check_type: str
    passed: bool
    proof: str
    details: Dict[str, Any]


class IntegrationVerificationDict(TypedDict, total=False):
    """Composite integration verification block."""
    source_module: str
    target_module: str
    fully_verified: bool
    integration_level: int
    raw_integration_level: int
    timestamp: str
    checks: Dict[str, VerificationCheckDict]
    critical_nodes: Dict[str, Any]
    output_equivalence: Optional[Dict[str, Any]]
    code_coverage: Optional[Dict[str, Any]]


class KernelProcessInfo(TypedDict):
    """A running Python process detected by the kernel tracer (exec event)."""
    name: str
    script_path: str
    started_at: str
    command: str
    proof: ProofType


class ProcessEvents(TypedDict):
    """Kernel events recorded for a single process (PID)."""
    modules: Dict[str, str]   # node_name → best event_type
    ipc_files: Dict[str, str]  # path → event_type
    sequence: List[Tuple[float, str]]  # (timestamp, node_name)


class KernelTracerMetrics(TypedDict, total=False):
    """Kernel tracer health metrics."""
    backend: str
    alive: bool
    pid: int
    events_total: int
    tracked_pids: int
    parse_ok: int
    parse_skip: int
    parse_fail: int
    queue_drops: int
    uptime_seconds: float
    pinned_pids: List[int]
    pinned_events_seen: int


# ---------------------------------------------------------------------------
# Paths (all relative to this file's directory)
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
LOG_DIR = Path(os.getenv("MONITOR_LOG_DIR", SCRIPT_DIR / "daemon_log"))

def copy_ports() -> dict:
    """Copy setup (express plan, 2026-09-10): the ports of THIS tree, read from
    system_scripts/copy_ports.json — the only file that differs between the original
    and an app copy (original: dashboard 8080, health 8051). Missing file = the original's."""
    try:
        with open(SCRIPT_DIR / "copy_ports.json", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}

# Default health port (matches defaults.py DAEMON.HEALTH_PORT in the original; a copy's from copy_ports.json)
_DEFAULT_HEALTH_PORT = int(copy_ports().get("health", 8051))


# ---------------------------------------------------------------------------
# Subprocess Wrapper
# ---------------------------------------------------------------------------


def run_cmd(
    args: Sequence[Union[str, Path]],
    *,
    timeout: int = 10,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command with timeout and consistent error handling.

    Args:
        args: Command and arguments.
        timeout: Seconds before TimeoutExpired is raised.
        cwd: Working directory for the child process.
        env: Environment variables (inherits parent if None).
        capture: If True, capture stdout/stderr; otherwise inherit.

    Returns:
        CompletedProcess with text stdout/stderr.

    Raises:
        subprocess.TimeoutExpired: If the command exceeds *timeout*.
        FileNotFoundError: If the executable is not found.
    """
    str_args = [str(a) for a in args]
    return subprocess.run(
        str_args,
        capture_output=capture,
        text=True,
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
        env=env,
    )


def run_cmd_safe(
    args: Sequence[Union[str, Path]],
    *,
    timeout: int = 10,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    default_stdout: str = "",
    default_stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Like run_cmd but swallows exceptions, returning a synthetic result.

    Use for non-critical checks (ps) where failure is not fatal.

    Returns:
        CompletedProcess — on error, returncode=-1 and stdout/stderr are defaults.
    """
    try:
        return run_cmd(args, timeout=timeout, cwd=cwd, env=env)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logging.debug("run_cmd_safe failed: %s %s", str_args_short(args), exc)
        return subprocess.CompletedProcess(
            args=[str(a) for a in args],
            returncode=-1,
            stdout=default_stdout,
            stderr=str(exc) if default_stderr == "" else default_stderr,
        )


def str_args_short(args: Sequence[Union[str, Path]], max_len: int = 60) -> str:
    """Truncated repr of command args for logging."""
    s = " ".join(str(a) for a in args)
    return s if len(s) <= max_len else s[:max_len] + "…"


# ---------------------------------------------------------------------------
# Async Subprocess Wrappers
# ---------------------------------------------------------------------------

# Shared result type for both sync and async paths
@dataclass
class CmdResult:
    """Lightweight result from a subprocess call."""
    returncode: int
    stdout: str
    stderr: str

    @classmethod
    def from_completed(cls, cp: subprocess.CompletedProcess[str]) -> CmdResult:
        return cls(returncode=cp.returncode, stdout=cp.stdout or "", stderr=cp.stderr or "")

    @classmethod
    def failure(cls, error: str) -> CmdResult:
        return cls(returncode=-1, stdout="", stderr=error)


# Global semaphore — limits concurrent subprocess spawns.
# Prevents fork-bombing when scanning 200+ files in parallel.
# Set via configure_concurrency(); default 12 is safe for M2 iMac.
#
# The semaphore is lazily created inside the event loop (by _get_semaphore)
# rather than eagerly in configure_concurrency(), because asyncio.Semaphore
# must be instantiated within a running event loop context.

_subprocess_semaphore: Optional[asyncio.Semaphore] = None
_max_concurrency: int = 12
_concurrency_configured: bool = False
_semaphore_lock: Optional[asyncio.Lock] = None
_semaphore_init_lock = threading.Lock()  # Thread-safe for asyncio.Lock creation


def configure_concurrency(max_concurrent: int = 12) -> None:
    """Set the maximum number of concurrent async subprocesses.

    Call once before the event loop starts (or early in run_daemon).
    Subsequent calls log a warning and are ignored.
    Does NOT create the semaphore — that is deferred to _get_semaphore()
    so it is always instantiated inside the running event loop.
    """
    global _max_concurrency, _concurrency_configured
    if _concurrency_configured:
        logging.warning("configure_concurrency called again (max=%d), ignoring", max_concurrent)
        return
    _max_concurrency = max_concurrent
    _concurrency_configured = True


async def _get_semaphore() -> asyncio.Semaphore:
    """Get or create the subprocess semaphore (event-loop safe)."""
    global _subprocess_semaphore, _semaphore_lock

    # Thread-safe lock creation
    with _semaphore_init_lock:
        if _semaphore_lock is None:
            _semaphore_lock = asyncio.Lock()

    # Async-safe semaphore creation
    if _subprocess_semaphore is None:
        async with _semaphore_lock:
            if _subprocess_semaphore is None:
                _subprocess_semaphore = asyncio.Semaphore(_max_concurrency)
    return _subprocess_semaphore


async def run_cmd_async(
    args: Sequence[Union[str, Path]],
    *,
    timeout: int = 10,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
) -> CmdResult:
    """Async subprocess execution with timeout and semaphore.

    Raises:
        asyncio.TimeoutError: if command exceeds *timeout*.
    """
    str_args = [str(a) for a in args]
    sem = await _get_semaphore()

    async with sem:
        proc = await asyncio.create_subprocess_exec(
            *str_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

    return CmdResult(
        returncode=proc.returncode or 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else "",
        stderr=stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else "",
    )


async def run_cmd_safe_async(
    args: Sequence[Union[str, Path]],
    *,
    timeout: int = 10,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
) -> CmdResult:
    """Async equivalent of run_cmd_safe — swallows exceptions."""
    try:
        return await run_cmd_async(args, timeout=timeout, cwd=cwd, env=env)
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as exc:
        logging.debug("run_cmd_safe_async failed: %s %s", str_args_short(args), exc)
        return CmdResult.failure(str(exc))


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------


@contextmanager
def locked_file_read(path: Path, timeout: float = 1.0):
    """Context manager for locked file reading.

    Acquires shared lock to prevent reading during writes.
    Uses os.fdopen with closefd=True to guarantee fd cleanup.

    WARNING: Caller must handle interrupted reads (EINTR). If a signal
    arrives during f.read(), partial data may be returned and the lock
    will be released when the context manager exits.
    """
    fd = os.open(str(path), os.O_RDONLY)
    try:
        deadline = time.time() + timeout
        max_attempts = int(timeout / 0.01) + 100  # Safety bound against clock issues
        for _attempt in range(max_attempts):
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    raise TimeoutError(f"Could not acquire read lock on {path}")
                time.sleep(0.01)
        else:
            raise TimeoutError(f"Could not acquire read lock on {path} (max attempts)")

        with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as f:
            fd = None  # type: ignore[assignment]  # FIX_54 ast-pos; prevent double close, fdopen owns the fd now
            yield f
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError as e:
                logging.warning("Failed to unlock fd %d: %s", fd, e)
            try:
                os.close(fd)
            except OSError as e:
                logging.error("Failed to close fd %d: %s", fd, e)


@contextmanager
def locked_file_write(path: Path, timeout: float = 1.0):
    """Context manager for locked file writing.

    Acquires exclusive lock to prevent concurrent writes/reads.
    Uses os.fdopen with closefd=True to guarantee fd cleanup.

    The file is truncated only after the caller's block completes
    successfully (via flush + ftruncate to written size), so a caller
    exception leaves the original file content intact.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        deadline = time.time() + timeout
        max_attempts = int(timeout / 0.01) + 100  # Safety bound against clock issues
        for _attempt in range(max_attempts):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    raise TimeoutError(f"Could not acquire write lock on {path}")
                time.sleep(0.01)
        else:
            raise TimeoutError(f"Could not acquire write lock on {path} (max attempts)")

        # Truncate and seek AFTER acquiring lock, but wrap in try so
        # a caller exception after truncation is at least logged.
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)

        with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as f:
            fd = None  # type: ignore[assignment]  # FIX_54 ast-pos; prevent double close, fdopen owns the fd now
            yield f
            f.flush()
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError as e:
                logging.warning("Failed to unlock fd %d: %s", fd, e)
            try:
                os.close(fd)
            except OSError as e:
                logging.error("Failed to close fd %d: %s", fd, e)


class StateFileCorrupted(Exception):
    """Raised when a state file contains invalid JSON or unexpected type."""


_MAX_JSON_FILE_SIZE = 50 * 1024 * 1024  # 50MB — reject unreasonably large JSON files


def _backup_corrupt_file(filepath: Path) -> None:
    """Save a .corrupt backup of a corrupt state file for post-mortem analysis."""
    try:
        backup = filepath.with_suffix(".corrupt")
        import shutil
        shutil.copy2(str(filepath), str(backup))
        logging.warning("Backed up corrupt file to %s", backup)
    except OSError as exc:
        logging.warning("Failed to backup corrupt file %s: %s", filepath, exc)


def read_json(
    filepath: Path,
    *,
    raise_on_corrupt: bool = False,
    schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Read a JSON file with locking, returning empty dict on any failure.

    Uses shared file locking to prevent reading during writes.

    Args:
        filepath: Path to JSON file.
        raise_on_corrupt: If True, raise StateFileCorrupted instead of
            returning ``{}`` on parse errors. Callers that need to
            distinguish "no data" from "corrupted data" should set this.
        schema: Optional JSON schema dict. If provided, the validator is called
            on the loaded data before returning — see the I-73 note below: no
            caller passes it today and the validator module does not exist, so
            that branch is GUARDED, never taken silently.
    """
    if not filepath.exists():
        return {}
    try:
        file_size = filepath.stat().st_size
        if file_size > _MAX_JSON_FILE_SIZE:
            logging.error(
                "read_json(%s): file too large (%d MB), skipping",
                filepath.name, file_size // (1024 * 1024),
            )
            return {}
        with locked_file_read(filepath, timeout=1.0) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            err = f"expected dict, got {type(data).__name__}"
            _backup_corrupt_file(filepath)
            if raise_on_corrupt:
                raise StateFileCorrupted(f"read_json({filepath.name}): {err}")
            logging.error("read_json(%s): %s", filepath.name, err)
            return {}
        if schema is not None:
            # I-73 (2026-09-21, lane tr1_L4L8): a DEAD import on a branch no caller takes. The
            # traced callers of read_json are electricity.gather_electricity and
            # nai094_entry_proof._build / .refreeze (16 caller edges, 5 modules, every one of them
            # in the .archive copies of the same two files) and NONE of them passes `schema=`; the
            # module it imports exists nowhere in the tree. Guarded rather than dropped so the
            # signature stays and the day a caller does pass a schema the read returns its data and
            # says the validation was skipped, instead of raising ModuleNotFoundError here.
            try:
                from schemas import validate_or_warn
            except ImportError:
                logging.warning(
                    "read_json(%s): schema= was passed but no schema validator module is present "
                    "— the data is returned UNVALIDATED (I-73)", filepath.name,
                )
            else:
                validate_or_warn(filepath.name, schema, data)
        return data
    except json.JSONDecodeError as exc:
        _backup_corrupt_file(filepath)
        if raise_on_corrupt:
            raise StateFileCorrupted(f"read_json({filepath.name}): corrupt JSON — {exc}") from exc
        logging.error("read_json(%s): corrupt JSON — %s", filepath.name, exc)
        return {}
    except TimeoutError as exc:
        logging.warning("read_json(%s): lock timeout — %s", filepath.name, exc)
        return {}
    except (OSError, ValueError) as exc:
        logging.warning("read_json(%s): %s", filepath.name, exc)
        return {}


_STALE_LOCK_AGE_S: float = 60.0  # Force-break locks older than this


@contextmanager
def atomic_file_lock(filepath: Path, *, timeout: float = 5.0, is_lockfile: bool = False):
    """Advisory file lock using fcntl.flock().

    Creates a .lock sidecar file alongside the target path.
    Uses non-blocking attempts with a timeout to avoid deadlocks.
    If the lock file is older than _STALE_LOCK_AGE_S, it is removed
    before retrying (protects against crash-orphaned locks).

    If *is_lockfile* is True, *filepath* is used directly as the lock
    file instead of creating a sidecar (for dedicated lock files like
    ``config.lock``).
    """
    lock_path = filepath if is_lockfile else filepath.with_suffix(filepath.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)

    # Proactive stale lock check — try non-blocking acquire first.
    # Only attempt stale removal inside the spin loop where we can
    # safely close/reopen the fd (avoids TOCTOU race on unlink).

    acquired = False
    try:
        start = time.monotonic()
        last_stale_check = start
        max_attempts = int(timeout / 0.05) + 200  # Safety bound against clock issues
        for _attempt in range(max_attempts):
            if time.monotonic() - start >= timeout:
                break
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                now = time.monotonic()
                # Periodic stale lock check (every 1s during spin)
                if now - last_stale_check >= 1.0:
                    last_stale_check = now
                    try:
                        lock_age = time.time() - lock_path.stat().st_mtime
                        if lock_age > _STALE_LOCK_AGE_S:
                            logging.warning(
                                "Breaking stale lock %s (age=%.0fs)", lock_path, lock_age,
                            )
                            # Mark fd as invalid before closing to prevent double-close in finally
                            old_fd = fd
                            fd = -1
                            try:
                                fcntl.flock(old_fd, fcntl.LOCK_UN)
                            except OSError:
                                pass
                            os.close(old_fd)
                            lock_path.unlink(missing_ok=True)
                            lock_path.touch(exist_ok=True)
                            fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
                            continue  # Retry immediately with fresh fd
                    except (OSError, BlockingIOError):
                        pass
                time.sleep(0.05)

        if not acquired:
            raise TimeoutError(
                f"Could not acquire lock on {lock_path} within {timeout}s"
            )

        # Touch lock file so staleness detection works for future callers
        os.utime(fd)
        yield fd
    finally:
        if fd >= 0:
            if acquired:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(fd)
            except OSError as exc:
                logging.error("Failed to close lock fd %d: %s", fd, exc)


def _atomic_write_json_impl(filepath: Path, data: Dict[str, Any]) -> None:
    """Internal: atomic write via temp file + rename.

    Checks for minimum free disk space before writing and cleans up
    the temp file on failure to prevent orphaned partial writes.
    """
    import shutil

    filepath.parent.mkdir(parents=True, exist_ok=True)

    stat = shutil.disk_usage(filepath.parent)
    if stat.free < 100 * 1024 * 1024:
        raise IOError(f"Insufficient disk space: {stat.free / 1024 / 1024:.1f} MB free")

    tmp = filepath.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.rename(filepath)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def write_json(
    filepath: Path,
    data: Dict[str, Any],
    *,
    atomic: bool = True,
    locked: bool = True,
) -> None:
    """Write JSON with optional atomicity and locking (defaults: both enabled).

    Args:
        filepath: Target file path.
        data: Dict to serialize as JSON.
        atomic: Use temp file + rename to prevent partial reads (default True).
        locked: Use advisory file lock to prevent concurrent writes (default True).
    """
    if not atomic:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        try:
            import shutil as _shutil
            free_mb = _shutil.disk_usage(filepath.parent).free / (1024 * 1024)
            if free_mb < 100:
                logging.warning("Disk space critically low (%d MB free), skipping write to %s",
                                int(free_mb), filepath.name)
                return
        except OSError:
            pass
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return

    if locked:
        with atomic_file_lock(filepath):
            _atomic_write_json_impl(filepath, data)
    else:
        _atomic_write_json_impl(filepath, data)


def atomic_write_json(filepath: Path, data: Dict[str, Any]) -> None:
    """Write JSON atomically (no lock). Alias for write_json(locked=False)."""
    write_json(filepath, data, locked=False)


def atomic_write_json_locked(filepath: Path, data: Dict[str, Any]) -> None:
    """Write JSON atomically with lock. Alias for write_json()."""
    write_json(filepath, data)


# ---------------------------------------------------------------------------
# Safe Access & Retry
# ---------------------------------------------------------------------------


@overload
def safe_get(
    data: Optional[Dict[str, Any]],
    *keys: str,
    default: T,
    validator: Optional[Callable[[Any], bool]] = None,
) -> T: ...


@overload
def safe_get(
    data: Optional[Dict[str, Any]],
    *keys: str,
    validator: Optional[Callable[[Any], bool]] = None,
) -> Optional[Any]: ...


def safe_get(
    data: Optional[Dict[str, Any]],
    *keys: str,
    default: T = None,  # type: ignore[assignment]
    validator: Optional[Callable[[Any], bool]] = None,
) -> Optional[T]:
    """Safely traverse nested dicts with optional validation.

    Args:
        data: Source dict (None-safe).
        *keys: Sequence of keys to traverse.
        default: Value if any key is missing or validation fails.
        validator: Optional callable; if it returns False, return default.

    Returns:
        The nested value, or *default*.
    """
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default  # type: ignore[return-value]
        current = current.get(key)
        if current is None:
            return default  # type: ignore[return-value]
    if validator is not None and not validator(current):
        logging.debug("safe_get: validation failed for key path %s, using default", keys)
        return default  # type: ignore[return-value]
    return current


def retry_on_failure(
    max_retries: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 10.0,
    exceptions: Tuple[type, ...] = (OSError, json.JSONDecodeError),
) -> Callable:
    """Decorator: retry with exponential backoff on specified exceptions.

    Usage::

        @retry_on_failure(max_retries=3)
        def fragile_io():
            ...
    """
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            delay = base_delay
            for attempt in range(max_retries + 1):
                try:
                    return fn(*args, **kwargs)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except exceptions as exc:  # type: ignore[misc]  # FIX_54 ast-pos
                    if attempt == max_retries:
                        raise
                    logging.debug(
                        "retry_on_failure(%s): attempt %d/%d failed: %s",
                        fn.__name__, attempt + 1, max_retries, exc,
                    )
                    time.sleep(min(delay, max_delay))
                    delay *= 2
            raise RuntimeError("unreachable")  # satisfy type checker
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


_MAX_HASH_FILE_SIZE = 100 * 1024 * 1024  # 100MB


def content_hash(filepath: Path) -> str:
    """SHA-256 of file content, truncated to 16 hex chars. Empty str on error.

    Files larger than 100MB are hashed using only the first 100MB to
    prevent excessive memory usage from accidentally committed large files.
    """
    try:
        size = filepath.stat().st_size
        if size > _MAX_HASH_FILE_SIZE:
            logging.warning(
                "File too large for full hash (%d MB): %s",
                size // (1024 * 1024), filepath,
            )
            with open(filepath, "rb") as f:
                data = f.read(_MAX_HASH_FILE_SIZE)
            return hashlib.sha256(data).hexdigest()[:16]
        return hashlib.sha256(filepath.read_bytes()).hexdigest()[:16]
    except (OSError, ValueError) as exc:
        logging.debug("content_hash(%s): %s", filepath.name, exc)
        return ""


def make_repo_id(repo_path: Path) -> str:
    """Deterministic 12-char hex ID for a repository path."""
    return hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:12]




# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Current UTC ISO timestamp (timezone-aware)."""
    return datetime.now(tz=_UTC).isoformat()


# ---------------------------------------------------------------------------
# Path-hack dispositions — FIX_49 / FIX_50 (owner Q9 / Q10, 2026-09-15)
# ---------------------------------------------------------------------------
# A path hack's disposition is DATA, exactly as a rule's is: one row per hack TYPE in the
# `path_hacks` section of system_scripts/rule_dispositions.json, beside `families` (never inside
# it — a hack type is not a rule id, so step 18's family rules and step 19's "every deciding id has
# a registry row" are untouched). Per the owner's 2026-09-10 ruling the row keeps ONE default
# disposition and may carry `contexts` — an ordered list of {"when": {fact: condition}, "disposition"}
# rows over DISCRETE FACTS the route already measures, never prose. The first row whose every
# condition holds wins; none → the default. A type with NO row is 'deciding' — nothing is inferred,
# and the dashboard's own literal sets then classify it exactly as they did before this fix.
#
#   deciding → an infraction, counted, as today
#   context  → INFORMATIONAL: published with its `warning`, never counted (D24 / FIX_35 c's shape)

_PATH_HACK_TABLE: dict | None = None            # loaded ONCE per process
PATH_HACK_CONTEXT_FACTS: tuple = ("role", "species", "magnitude")
_PATH_HACK_OPS: dict = {
    ">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt,
    "==": operator.eq, "!=": operator.ne,
    "in": lambda a, b: a in b, "not_in": lambda a, b: a not in b,
}
RULE_DISPOSITIONS_FILE = Path(__file__).resolve().parent / "rule_dispositions.json"


def path_hack_dispositions(path: Path | None = None) -> dict:
    """The `path_hacks` section, loaded and VALIDATED once per process.

    A bad row is a broken table, not a silent default: unknown disposition, unknown fact or unknown
    op raises RuntimeError (the same contract `knowledge_base._load_dispositions` keeps for rules).
    An absent section is an empty table — every type then behaves as it did before FIX_49."""
    global _PATH_HACK_TABLE
    if _PATH_HACK_TABLE is not None and path is None:
        return _PATH_HACK_TABLE
    src = path or RULE_DISPOSITIONS_FILE
    try:
        with open(src, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise RuntimeError(
            f"rule_dispositions.json is missing at {src} — a broken install; "
            f"run system_scripts/disposition_check.py --seed, then the health check (step 18)")
    table: dict = {}
    for htype, row in (data.get("path_hacks") or {}).items():
        if htype.startswith("_"):          # `_policy` and friends are prose, not rows
            continue
        default = (row or {}).get("disposition")
        if default not in ("deciding", "context"):
            raise RuntimeError(f"rule_dispositions.json path_hacks: {htype} has disposition "
                               f"{default!r}; only deciding|context are dispositions")
        ctxs = (row or {}).get("contexts") or []
        if not isinstance(ctxs, list):
            raise RuntimeError(f"rule_dispositions.json path_hacks: {htype} contexts is not a list")
        parsed: list = []
        for c in ctxs:
            cd = (c or {}).get("disposition")
            when = (c or {}).get("when") or {}
            if cd not in ("deciding", "context"):
                raise RuntimeError(f"rule_dispositions.json path_hacks: {htype} context row has "
                                   f"disposition {cd!r}")
            unknown = sorted(k for k in when if k not in PATH_HACK_CONTEXT_FACTS)
            if not when or unknown:
                raise RuntimeError(f"rule_dispositions.json path_hacks: {htype} context row uses "
                                   f"unknown facts {unknown} (facts: {PATH_HACK_CONTEXT_FACTS})")
            for k, cond in when.items():
                if isinstance(cond, dict) and any(op not in _PATH_HACK_OPS for op in cond):
                    raise RuntimeError(f"rule_dispositions.json path_hacks: {htype} context row on "
                                       f"{k!r} uses an unknown op (ops: {sorted(_PATH_HACK_OPS)})")
            parsed.append((dict(when), cd, str((c or {}).get("warning") or "")))
        table[htype] = {"default": default,
                        "warning": str((row or {}).get("warning") or ""),
                        "contexts": parsed}
    if path is None:
        _PATH_HACK_TABLE = table
    return table


def _path_hack_condition_holds(fact, cond) -> bool:
    """One table condition against one measured fact. A missing fact NEVER holds — so a target that
    was never run through the wrapper has no `role` and nothing is exempted."""
    if fact is None or fact == "":
        return False
    try:
        if isinstance(cond, dict):
            return all(_PATH_HACK_OPS[op](fact, value) for op, value in cond.items())
        return fact == cond
    except TypeError:
        return False


def path_hack_disposition(htype: str, facts: dict | None = None) -> tuple:
    """('deciding' | 'context', warning) for one hack type under `facts`.

    The first context row whose conditions all hold, else the type's default. A type with no row is
    ('deciding', '')."""
    table = path_hack_dispositions()
    row = table.get(str(htype or ""))
    if not row:
        return ("deciding", "")
    if facts:
        for when, disp, warning in row["contexts"]:
            if all(_path_hack_condition_holds(facts.get(k), cond) for k, cond in when.items()):
                return (disp, warning or row["warning"])
    return (row["default"], row["warning"])
