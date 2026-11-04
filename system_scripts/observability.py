#!/usr/bin/env python3
"""
observability.py — Minimal observability package for the kernel trace daemon.

Provides:
  - Metrics: Thread-safe counters and gauges (Prometheus-compatible export)
  - HealthHandler: HTTP handler for /health, /metrics, / endpoints
  - JSONLogWriter: Rotating structured JSON log writer
  - Observability: Facade tying metrics, health endpoint, and structured logging together

Usage in kernel_trace_daemon.py:
    from observability import Observability
    obs = Observability(port=8051)
    obs.log("poll_complete", nodes_connected=12, poll_ms=45)
    obs.metrics.inc("polls_total")
    obs.stop()

Endpoints (default port 8051):
    GET /health  → {"status": "ok", "uptime_seconds": ..., "metrics": {...}}
    GET /metrics → Prometheus text format (text/plain)
    GET /        → redirect to /health
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine_utils import LOG_DIR, now_iso


# ===================================================================
# METRICS — thread-safe counters and gauges
# ===================================================================


@dataclass
class Metrics:
    """Thread-safe counters and gauges with Prometheus-compatible export.

    Counters only go up. Gauges can be set to any value.
    All operations are O(1) and lock-protected.
    """

    _counters: Dict[str, int] = field(default_factory=dict)
    _gauges: Dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, name: str, value: int = 1) -> None:
        """Increment a counter by value (default 1)."""
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge to an absolute value."""
        with self._lock:
            self._gauges[name] = value

    def get(self, name: str) -> float:
        """Get a counter or gauge value (counter checked first)."""
        with self._lock:
            if name in self._counters:
                return self._counters[name]
            return self._gauges.get(name, 0.0)

    def snapshot(self) -> Dict[str, float]:
        """Return a copy of all metrics (counters + gauges)."""
        with self._lock:
            result: Dict[str, float] = {}
            result.update(self._counters)
            result.update(self._gauges)
            return result

    @staticmethod
    def _sanitize_metric_name(name: str) -> str:
        """Sanitize metric name to Prometheus-safe characters [a-zA-Z0-9_:]."""
        import re
        return re.sub(r'[^a-zA-Z0-9_:]', '_', name)

    def prometheus(self) -> str:
        """Export all metrics in Prometheus text exposition format.

        Counters get TYPE counter, gauges get TYPE gauge.
        """
        lines: List[str] = []
        with self._lock:
            for name, value in sorted(self._counters.items()):
                safe = self._sanitize_metric_name(name)
                lines.append(f"# TYPE {safe} counter")
                lines.append(f"{safe} {value}")
            for name, value in sorted(self._gauges.items()):  # type: ignore[assignment]  # FIX_54 ast-pos
                safe = self._sanitize_metric_name(name)
                lines.append(f"# TYPE {safe} gauge")
                lines.append(f"{safe} {value}")
        return "\n".join(lines) + "\n"


# ===================================================================
# TRIGGERS — thread-safe flags for on-demand test triggers
# ===================================================================


class Triggers:
    """Thread-safe trigger flags for on-demand test runs.

    Replaces fragile file-based triggers with in-process flags
    that can be set via HTTP POST and polled from the async event loop.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._equivalence: bool = False
        self._coverage: bool = False

    def set_equivalence(self) -> None:
        with self._lock:
            self._equivalence = True

    def set_coverage(self) -> None:
        with self._lock:
            self._coverage = True

    def poll_equivalence(self) -> bool:
        """Return True and reset if equivalence was triggered."""
        with self._lock:
            if self._equivalence:
                self._equivalence = False
                return True
            return False

    def poll_coverage(self) -> bool:
        """Return True and reset if coverage was triggered."""
        with self._lock:
            if self._coverage:
                self._coverage = False
                return True
            return False

    def equivalence_pending(self) -> bool:
        """Check if equivalence trigger is pending (without consuming)."""
        with self._lock:
            return self._equivalence

    def coverage_pending(self) -> bool:
        """Check if coverage trigger is pending (without consuming)."""
        with self._lock:
            return self._coverage


# ===================================================================
# HEALTH HTTP HANDLER
# ===================================================================


class HealthHandler(BaseHTTPRequestHandler):
    """HTTP request handler for /health, /metrics, /trigger/* endpoints.

    Attributes on the server instance (set by Observability):
        server.metrics: Metrics instance
        server.start_time: float (monotonic)
        server.triggers: Triggers instance
    """

    def do_GET(self) -> None:
        if self.path == "/health":
            self._serve_health()
        elif self.path == "/metrics":
            self._serve_metrics()
        elif self.path == "/":
            self._redirect("/health")
        else:
            self._send_text(404, "Not Found\n")

    def do_POST(self) -> None:
        triggers: Triggers = self.server.triggers  # type: ignore[attr-defined]
        if self.path == "/trigger/equivalence":
            triggers.set_equivalence()
            self._send_json(200, {"status": "triggered", "test": "equivalence"})
        elif self.path == "/trigger/coverage":
            triggers.set_coverage()
            self._send_json(200, {"status": "triggered", "test": "coverage"})
        else:
            self._send_text(404, "Not Found\n")

    def _serve_health(self) -> None:
        uptime = time.monotonic() - self.server.start_time  # type: ignore[attr-defined]
        metrics: Metrics = self.server.metrics  # type: ignore[attr-defined]
        triggers: Triggers = self.server.triggers  # type: ignore[attr-defined]
        snap = metrics.snapshot()

        # Evaluate health conditions
        last_poll_ts = snap.get("last_poll_timestamp", 0)
        last_poll_age = time.time() - last_poll_ts if last_poll_ts else float("inf")
        tracer_alive = snap.get("tracer_alive", 0)

        if last_poll_age > 60:
            status = "degraded"
            code = 503
        elif tracer_alive < 1:
            status = "degraded"
            code = 503
        else:
            status = "ok"
            code = 200

        body = json.dumps({
            "status": status,
            "uptime_seconds": round(uptime, 1),
            "pid": os.getpid(),
            "checks": {
                "polls": "ok" if last_poll_age < 60 else "stale",
                "tracer": "ok" if tracer_alive else "down",
            },
            "metrics": snap,
            "triggers": {
                "equivalence_pending": triggers.equivalence_pending(),
                "coverage_pending": triggers.coverage_pending(),
            },
        }, indent=2) + "\n"
        self._send_text(code, body, content_type="application/json")

    def _serve_metrics(self) -> None:
        body = self.server.metrics.prometheus()  # type: ignore[attr-defined]
        self._send_text(200, body, content_type="text/plain; version=0.0.4; charset=utf-8")

    def _redirect(self, location: str) -> None:
        self.send_response(301)
        self.send_header("Location", location)
        self.end_headers()

    def _send_text(self, code: int, body: str, content_type: str = "text/plain") -> None:
        encoded = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Client disconnected mid-response

    def _send_json(self, code: int, data: Dict[str, Any]) -> None:
        self._send_text(code, json.dumps(data) + "\n", content_type="application/json")

    def log_message(self, format: str, *args: Any) -> None:
        """Route HTTP request logs through stdlib logging instead of stderr."""
        logging.debug("[http] %s", format % args)


# ===================================================================
# JSON LOG WRITER — rotating structured JSON logs
# ===================================================================


class JSONLogWriter:
    """Rotating JSON log writer for structured daemon events.

    Each log entry is a single JSON line with timestamp, event name,
    and arbitrary key-value data. Rotates when file exceeds max_bytes.
    """

    def __init__(
        self,
        path: Path,
        max_bytes: int = 5_000_000,
        backup_count: int = 3,
    ) -> None:
        self._path = path
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **kwargs: Any) -> None:
        """Write a structured JSON log line.

        Rotation check runs outside the write lock to avoid blocking
        all log writes during file I/O (rename, stat).  A brief lock
        is taken only to check the size, then rotation happens unlocked,
        and finally the write itself takes the lock for minimal time.
        """
        entry = {
            "ts": now_iso(),
            "event": event,
            **kwargs,
        }
        line = json.dumps(entry, default=str) + "\n"

        # Check rotation need with minimal lock time
        needs_rotation = self._needs_rotation()

        # Rotate outside lock (file renames are atomic on POSIX)
        if needs_rotation:
            self._rotate()

        # Disk space check before write
        try:
            import shutil
            free_mb = shutil.disk_usage(self._path.parent).free / (1024 * 1024)
            if free_mb < 50:
                return  # Skip log write — disk critically low
        except OSError:
            pass  # disk_usage failed; proceed with write attempt

        # Write with minimal lock hold time
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)

    def _needs_rotation(self) -> bool:
        """Check if log file exceeds max_bytes (lock-free)."""
        try:
            if not self._path.exists():
                return False
            return self._path.stat().st_size >= self._max_bytes
        except OSError:
            # stat() failed — use os.path.getsize as fallback.
            # Emergency truncate only if file is suspiciously large (>50MB).
            try:
                size = os.path.getsize(self._path)
                if size > 50_000_000:
                    logging.warning(
                        "Emergency truncate of large log %s (%d bytes)", self._path, size,
                    )
                    with open(self._path, "w", encoding="utf-8") as f:
                        f.write(json.dumps({
                            "ts": now_iso(),
                            "event": "log_emergency_truncate",
                            "reason": "stat_failed_size_exceeded",
                        }) + "\n")
            except OSError:
                pass  # Cannot determine size at all
            return False

    def _rotate(self) -> None:
        """Rotate log file outside the write lock.

        Uses self._lock only briefly to prevent concurrent rotations.
        File renames are atomic on POSIX so concurrent writes see
        either the old or new file, never a partial state.
        """
        with self._lock:
            # Re-check under lock to prevent double rotation
            try:
                if not self._path.exists():
                    return
                size = self._path.stat().st_size
            except OSError:
                return
            if size < self._max_bytes:
                return

            # Shift existing backups (with error recovery)
            for i in range(self._backup_count - 1, 0, -1):
                src = self._path.with_suffix(f".{i}")
                dst = self._path.with_suffix(f".{i + 1}")
                if src.exists():
                    try:
                        src.rename(dst)
                    except OSError as exc:
                        logging.warning("Failed to rotate %s -> %s: %s", src, dst, exc)

            # Rotate current to .1
            backup = self._path.with_suffix(".1")
            try:
                self._path.rename(backup)
            except OSError as exc:
                logging.error("Failed to rotate current log %s: %s", self._path, exc)
                # Emergency truncate if file is 2x over threshold
                if size > self._max_bytes * 2:
                    try:
                        logging.warning("Emergency truncate of log file %s", self._path)
                        with open(self._path, "w", encoding="utf-8") as f:
                            f.write(json.dumps({
                                "ts": now_iso(),
                                "event": "log_emergency_truncate",
                                "reason": "rotation_failed",
                                "error": str(exc),
                            }) + "\n")
                    except OSError:
                        pass  # Nothing more we can do


# ===================================================================
# OBSERVABILITY FACADE
# ===================================================================


class Observability:
    """Facade tying metrics, health endpoint, and structured logging together.

    Usage:
        obs = Observability(port=8051)
        obs.log("daemon_start", backend="eslogger")
        obs.metrics.inc("polls_total")
        obs.metrics.set_gauge("nodes_connected", 42)
        obs.record_poll(poll_count=1, elapsed_ms=45, connected=12, total=100)
        obs.stop()
    """

    def __init__(
        self,
        port: int = 8051,
        log_path: Optional[Path] = None,
        enable_http: bool = True,
    ) -> None:
        self.metrics = Metrics()
        self.triggers = Triggers()
        self._start_time = time.monotonic()
        self._log_writer = JSONLogWriter(
            log_path or LOG_DIR / "daemon_structured.jsonl",
        )
        self._http_enabled = False
        self._server: Optional[HTTPServer] = None          # FIX_31: declared once (was re-annotated below)
        self._thread: Optional[threading.Thread] = None

        if not enable_http:
            logging.info("Observability HTTP endpoint disabled")
            return

        # Start HTTP health server in background thread

        for attempt in range(3):
            try:
                self._server = HTTPServer(("127.0.0.1", port), HealthHandler)
                self._server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server.metrics = self.metrics  # type: ignore[attr-defined]
                self._server.start_time = self._start_time  # type: ignore[attr-defined]
                self._server.triggers = self.triggers  # type: ignore[attr-defined]
                self._thread = threading.Thread(
                    target=self._server.serve_forever,
                    daemon=True,  # F14 belt: never pin the process at exit; stop() still drains in-flight requests
                    name="obs-health",
                )
                self._thread.start()
                self._http_enabled = True
                logging.info("Observability health endpoint: http://127.0.0.1:%d/health", port)
                break
            except OSError as exc:
                if attempt < 2:
                    logging.warning("HTTP server start attempt %d failed: %s (retrying)", attempt + 1, exc)
                    time.sleep(0.5 * (2 ** attempt))
                else:
                    logging.error("Observability HTTP server failed after 3 attempts: %s", exc)
                    logging.error("Metrics and logging will continue, but HTTP endpoint unavailable")
                    self._server = None
                    self._thread = None

    def is_http_available(self) -> bool:
        """Check if HTTP endpoint is running."""
        return self._http_enabled and self._server is not None

    def log(self, event: str, **kwargs: Any) -> None:
        """Write a structured log entry and also emit to stdlib logging."""
        self._log_writer.write(event, **kwargs)
        # Also log to stdlib for console/file visibility
        if kwargs:
            detail = " ".join(f"{k}={v}" for k, v in kwargs.items())
            logging.info("[obs] %s: %s", event, detail)
        else:
            logging.info("[obs] %s", event)

    def record_poll(
        self,
        poll_count: int,
        elapsed_ms: float,
        connected: int,
        total: int,
        running: int = 0,
        dataflows: int = 0,
        interval: float = 0.0,
    ) -> None:
        """Record metrics for a completed poll cycle."""
        self.metrics.inc("polls_total")
        self.metrics.set_gauge("last_poll_timestamp", time.time())
        self.metrics.set_gauge("poll_elapsed_ms", elapsed_ms)
        self.metrics.set_gauge("poll_count", poll_count)
        self.metrics.set_gauge("nodes_connected", connected)
        self.metrics.set_gauge("nodes_total", total)
        self.metrics.set_gauge("nodes_running", running)
        self.metrics.set_gauge("dataflows_active", dataflows)
        self.metrics.set_gauge("poll_interval_seconds", interval)

    def record_kernel_tracer(
        self,
        backend: str,
        alive: bool,
        events_total: int,
        tracked_pids: int,
        parse_ok: int = 0,
        parse_fail: int = 0,
        parse_skip: int = 0,
        queue_drops: int = 0,
    ) -> None:
        """Record kernel tracer health metrics."""
        self.metrics.set_gauge("tracer_alive", 1.0 if alive else 0.0)
        self.metrics.set_gauge("tracer_events_total", events_total)
        self.metrics.set_gauge("tracer_tracked_pids", tracked_pids)
        self.metrics.set_gauge("tracer_parse_ok", parse_ok)
        self.metrics.set_gauge("tracer_parse_fail", parse_fail)
        self.metrics.set_gauge("tracer_parse_skip", parse_skip)
        self.metrics.set_gauge("tracer_queue_drops", queue_drops)

    def record_execution_scheduler(
        self,
        alive: bool,
        pid: Optional[int] = None,
        restart_count: int = 0,
        uptime_seconds: float = 0.0,
        orchestrator_module: str = "",
    ) -> None:
        """Record execution scheduler (persistent orchestrator) metrics."""
        self.metrics.set_gauge("orchestrator_alive", 1.0 if alive else 0.0)
        self.metrics.set_gauge("orchestrator_pid", float(pid) if pid else 0.0)
        self.metrics.set_gauge("orchestrator_restart_count", restart_count)
        self.metrics.set_gauge("orchestrator_uptime_seconds", uptime_seconds)

    def record_poll_provenance(
        self,
        nodes_kernel_proof: int,
        nodes_inferred: int,
        nodes_no_proof: int,
    ) -> None:
        """Record proof provenance breakdown for the current poll cycle."""
        self.metrics.set_gauge("nodes_kernel_proof", nodes_kernel_proof)
        self.metrics.set_gauge("nodes_inferred", nodes_inferred)
        self.metrics.set_gauge("nodes_no_proof", nodes_no_proof)

    def record_macos_version(self, major: int, minor: int) -> None:
        """Record macOS version as a gauge."""
        self.metrics.set_gauge("macos_major", major)
        self.metrics.set_gauge("macos_minor", minor)

    def stop(self) -> None:
        """Shut down the health endpoint server.

        Signals serve_forever to exit, then waits up to 5s for the
        thread to finish (allowing in-flight HTTP requests to complete).
        """
        if self._server:
            try:
                self._server.shutdown()  # Signals serve_forever loop to exit
                logging.info("Observability HTTP server stopped")
            except Exception as exc:
                logging.warning("Error shutting down HTTP server: %s", exc, exc_info=True)
            finally:
                try:
                    self._server.server_close()
                except Exception:
                    pass
                self._server = None

        if self._thread:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                logging.error("HTTP server thread did not stop after 5s, proceeding with shutdown")
            self._thread = None

        self.log("observability_stopped")
