"""
RCA - Session-Scoped State Management
Production-hardened isolation for concurrent GRANULARIZE missions.

Key Features:
- Cache hit rate tracking with health monitoring
- Automatic session expiry (prevents memory leaks)
- Resource limits (MAX_CACHE_SIZE, MAX_SESSIONS)
- Context manager for safe session lifecycle
- Graceful shutdown support

IMPORTANT: Use cache_get/cache_set methods for automatic hit tracking.
Direct cache access (e.g., session.calculator_cache[key]) bypasses tracking.
"""

from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import TracebackType
from typing import Callable, Dict, Optional, Set, Any, TypeVar, TYPE_CHECKING

from rca_main.constants import (
    MAX_CACHE_SIZE,
    MAX_SESSIONS,
    SESSION_TIMEOUT_HOURS,
    CACHE_HIT_RATE_WARNING_THRESHOLD,
    CACHE_HIT_RATE_CRITICAL_THRESHOLD,
)

if TYPE_CHECKING:
    from rca_main.context_calculator import ContextLinesCalculator

logger = logging.getLogger(__name__)

# Flow tracing integration
_F = TypeVar('_F', bound=Callable[..., Any])
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False


@dataclass
class CacheMetrics:
    """
    Granular cache performance tracking.

    Monitor hit_rate to tune MAX_CACHE_SIZE:
    - hit_rate < 10%: Cache too small or keys too unique
    - hit_rate < 30%: Consider increasing MAX_CACHE_SIZE
    - hit_rate > 70%: Cache working well
    """
    hits: int = 0
    misses: int = 0
    evictions: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate (0.0 to 1.0)."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    @property
    def total_requests(self) -> int:
        """Total cache requests (hits + misses)."""
        return self.hits + self.misses

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metrics to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "total_requests": self.total_requests,
            "hit_rate": f"{self.hit_rate:.2%}"
        }

    def check_health(self, session_id: str = "") -> str:
        """
        Check cache health and log warnings if needed.

        Returns:
            Health status: "healthy", "warning", or "critical"
        """
        if self.total_requests < 10:
            return "insufficient_data"

        rate = self.hit_rate
        prefix = f"Session {session_id}: " if session_id else ""

        if rate < CACHE_HIT_RATE_CRITICAL_THRESHOLD:
            logger.error(
                f"{prefix}CRITICAL cache hit rate ({rate:.1%}). "
                f"Consider increasing MAX_CACHE_SIZE or reviewing cache key strategy."
            )
            return "critical"
        elif rate < CACHE_HIT_RATE_WARNING_THRESHOLD:
            logger.warning(
                f"{prefix}Low cache hit rate ({rate:.1%}). "
                f"Cache may be undersized for workload."
            )
            return "warning"
        else:
            return "healthy"


@dataclass
class RootCauseSessionState:
    """
    Isolated rca state with production-grade lifecycle management.

    IMPORTANT: Use cache_get() and cache_set() methods for automatic
    hit/miss tracking and LRU eviction. Direct cache access bypasses these.
    """
    session_id: str
    repo_path: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Session-local caches
    calculator_cache: Dict[str, Any] = field(default_factory=dict)
    whitelist: Set[str] = field(default_factory=set)

    # Progress Metrics
    files_analyzed: int = 0
    candidates_found: int = 0
    files_failed: int = 0
    failed_paths: list[str] = field(default_factory=list)

    # Cache Performance
    cache_metrics: CacheMetrics = field(default_factory=CacheMetrics)

    def __post_init__(self) -> None:
        """Validate session initialization."""
        if not self.session_id or not self.session_id.strip():
            raise ValueError("session_id cannot be empty")

        repo = Path(self.repo_path)
        if not repo.exists():
            raise ValueError(f"repo_path does not exist: {self.repo_path}")
        if not repo.is_dir():
            raise ValueError(f"repo_path is not a directory: {self.repo_path}")

    async def touch(self) -> None:
        """Update last access time (for expiry tracking)."""
        self.last_accessed = datetime.now(timezone.utc)

    def is_expired(self, timeout_hours: int = SESSION_TIMEOUT_HOURS) -> bool:
        """Check if session has exceeded idle timeout."""
        age = datetime.now(timezone.utc) - self.last_accessed
        return age > timedelta(hours=timeout_hours)

    @trace
    async def cache_get(self, cache_name: str, key: str) -> Optional[Any]:
        """
        Tracked cache retrieval with hit/miss recording.

        Args:
            cache_name: Name of cache attribute (e.g., "calculator_cache")
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        logger.debug("cache_get: %s[%s]", cache_name, key)
        cache = getattr(self, cache_name, None)
        if cache is None:
            logger.warning(f"Unknown cache: {cache_name}")
            return None

        if key in cache:
            self.cache_metrics.hits += 1
            await self.touch()
            return cache[key]
        else:
            self.cache_metrics.misses += 1
            return None

    @trace
    async def cache_set(self, cache_name: str, key: str, value: Any) -> None:
        """
        Tracked cache insertion with size limit enforcement.

        Uses FIFO eviction when cache is full.

        Args:
            cache_name: Name of cache attribute
            key: Cache key
            value: Value to cache
        """
        logger.debug("cache_set: %s[%s]", cache_name, key)
        cache = getattr(self, cache_name, None)
        if cache is None:
            logger.warning(f"Unknown cache: {cache_name}")
            return

        # Enforce cache size limit (FIFO eviction)
        if len(cache) >= MAX_CACHE_SIZE and key not in cache:
            oldest_key = next(iter(cache))
            cache.pop(oldest_key)
            self.cache_metrics.evictions += 1
            logger.debug(f"Cache eviction in {cache_name}: {oldest_key}")

        cache[key] = value
        await self.touch()

    def cache_delete(self, cache_name: str, key: str) -> bool:
        """
        Remove a specific key from cache.

        Returns:
            True if key was found and removed
        """
        cache = getattr(self, cache_name, None)
        if cache is None:
            return False

        if key in cache:
            del cache[key]
            return True
        return False

    async def record_failure(self, file_path: str, error: str) -> None:
        """Log a failed analysis attempt without crashing the mission."""
        self.files_failed += 1
        # Limit stored failures to prevent memory bloat
        if len(self.failed_paths) < 100:
            self.failed_paths.append(f"{file_path}: {error}")
        await self.touch()

    def check_cache_health(self) -> str:
        """
        Check and log cache health status.

        Returns:
            Health status string
        """
        return self.cache_metrics.check_health(self.session_id)

    def get_metrics(self) -> Dict[str, Any]:
        """Comprehensive session performance snapshot."""
        now = datetime.now(timezone.utc)
        return {
            "session_id": self.session_id,
            "repo_path": self.repo_path,
            "runtime_seconds": (now - self.created_at).total_seconds(),
            "idle_seconds": (now - self.last_accessed).total_seconds(),
            "files_analyzed": self.files_analyzed,
            "files_failed": self.files_failed,
            "candidates_found": self.candidates_found,
            "whitelist_size": len(self.whitelist),
            "caches": {
                "calculator": len(self.calculator_cache),
            },
            "cache_performance": self.cache_metrics.to_dict(),
            "cache_health": self.cache_metrics.check_health()
        }

    def clear(self) -> None:
        """Explicit cache teardown for GC assistance."""
        self.calculator_cache.clear()
        self.whitelist.clear()
        self.failed_paths.clear()
        logger.debug(f"Session {self.session_id} caches cleared")


class RootCauseSessionManager:
    """
    Production singleton lifecycle manager with resource limits and auto-cleanup.

    Features:
    - Thread-safe async singleton
    - Automatic expired session cleanup
    - LRU eviction when MAX_SESSIONS reached
    - Graceful shutdown support
    """
    _instance: Optional['RootCauseSessionManager'] = None
    _lock = asyncio.Lock()

    def __init__(self) -> None:
        self._sessions: Dict[str, RootCauseSessionState] = {}
        self._access_lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    @classmethod
    async def get_instance(cls) -> 'RootCauseSessionManager':
        """Thread-safe async singleton with proper double-check."""
        if cls._instance is None:
            async with cls._lock:
                # Double-check after acquiring lock
                if cls._instance is None:
                    instance = cls()
                    await instance._start_background_cleanup()
                    cls._instance = instance
        return cls._instance

    async def _start_background_cleanup(self) -> None:
        """Launch periodic cleanup task for expired sessions."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Background session cleanup task started")

    async def _cleanup_loop(self) -> None:
        """Periodic sweeper for expired sessions (runs every hour)."""
        try:
            while True:
                await asyncio.sleep(3600)  # 1 hour
                await self._cleanup_expired_sessions()
        except asyncio.CancelledError:
            logger.info("Cleanup loop cancelled")
        except Exception as e:
            logger.error(f"Cleanup loop error: {e}", exc_info=True)

    @trace
    async def _cleanup_expired_sessions(self) -> None:
        """Remove sessions that have exceeded idle timeout."""
        logger.debug("_cleanup_expired_sessions: checking %d sessions", len(self._sessions))
        async with self._access_lock:
            expired = [
                sid for sid, session in self._sessions.items()
                if session.is_expired()
            ]

            for session_id in expired:
                session = self._sessions.pop(session_id)
                # Log cache health before cleanup
                session.check_cache_health()
                session.clear()
                logger.info(f"Auto-cleaned expired session: {session_id}")

            if expired:
                logger.info(f"Expired {len(expired)} session(s), {len(self._sessions)} remain")

    @trace
    async def get_session(
        self,
        session_id: str,
        repo_path: str,
        whitelist: Optional[Set[str]] = None
    ) -> RootCauseSessionState:
        """
        Retrieves an existing session or initializes a new one.
        Enforces MAX_SESSIONS limit via LRU eviction.
        """
        logger.debug("get_session: %s for %s", session_id, repo_path)
        async with self._access_lock:
            # Return existing session
            if session_id in self._sessions:
                session = self._sessions[session_id]
                await session.touch()
                return session

            # Enforce session limit
            if len(self._sessions) >= MAX_SESSIONS:
                # Evict oldest session (by last_accessed)
                oldest_id = min(
                    self._sessions.keys(),
                    key=lambda sid: self._sessions[sid].last_accessed
                )
                evicted = self._sessions.pop(oldest_id)
                # Log metrics before eviction
                metrics = evicted.get_metrics()
                evicted.clear()
                logger.warning(
                    f"Session limit reached. Evicted {oldest_id} "
                    f"(idle {metrics['idle_seconds']:.0f}s, "
                    f"hit_rate={metrics['cache_performance']['hit_rate']})"
                )

            # Create new session
            try:
                session = RootCauseSessionState(
                    session_id=session_id,
                    repo_path=repo_path,
                    whitelist=whitelist or set()
                )
                self._sessions[session_id] = session
                logger.info(
                    f"Session {session_id} created for {repo_path} "
                    f"({len(self._sessions)}/{MAX_SESSIONS})"
                )
                return session
            except ValueError as e:
                logger.error(f"Failed to create session {session_id}: {e}")
                raise

    @trace
    async def cleanup_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Finalizes a session and reclaims memory."""
        logger.debug("cleanup_session: %s", session_id)
        async with self._access_lock:
            session = self._sessions.pop(session_id, None)
            if session:
                metrics = session.get_metrics()
                # Log cache health on cleanup
                health = session.check_cache_health()
                session.clear()
                logger.info(
                    f"Session {session_id} finalized. "
                    f"Hit rate: {metrics['cache_performance']['hit_rate']}, "
                    f"Health: {health}, "
                    f"Analyzed: {metrics['files_analyzed']} files"
                )
                return metrics
            else:
                logger.warning(f"Attempted to cleanup non-existent session: {session_id}")
                return None

    async def get_all_metrics(self) -> Dict[str, Any]:
        """System-wide rca session statistics."""
        async with self._access_lock:
            return {
                "active_sessions": len(self._sessions),
                "max_sessions": MAX_SESSIONS,
                "sessions": {
                    sid: session.get_metrics()
                    for sid, session in self._sessions.items()
                }
            }

    async def check_all_cache_health(self) -> Dict[str, str]:
        """Check cache health for all active sessions."""
        async with self._access_lock:
            return {
                sid: session.check_cache_health()
                for sid, session in self._sessions.items()
            }

    @trace
    async def shutdown(self) -> None:
        """Graceful shutdown: cleanup all sessions and stop background tasks."""
        logger.debug("shutdown: cleaning up %d active sessions", len(self._sessions))
        logger.info("RootCauseSessionManager shutting down...")

        # Cancel cleanup task
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Cleanup all sessions
        async with self._access_lock:
            for session_id in list(self._sessions.keys()):
                session = self._sessions.pop(session_id)
                metrics = session.get_metrics()
                session.clear()
                logger.info(
                    f"Shutdown cleanup: {session_id} "
                    f"(hit_rate={metrics['cache_performance']['hit_rate']})"
                )

        logger.info("RootCauseSessionManager shutdown complete")

    @classmethod
    async def reset_instance(cls) -> None:
        """Force reset singleton (use only in tests)."""
        async with cls._lock:
            if cls._instance:
                await cls._instance.shutdown()
                cls._instance = None


class RootCauseSession:
    """
    Context manager for safe session lifecycle.

    Usage:
        async with RootCauseSession(session_id, repo_path) as session:
            # Use cache_get/cache_set for tracked caching
            cached = await session.cache_get("calculator_cache", "file.py")
            if cached is None:
                result = await calculate_context("file.py")
                await session.cache_set("calculator_cache", "file.py", result)

            session.files_analyzed += 1
        # Auto-cleanup and metrics logging on exit
    """

    def __init__(
        self,
        session_id: str,
        repo_path: str,
        whitelist: Optional[Set[str]] = None,
        auto_cleanup: bool = True
    ):
        """
        Initialize session context.

        Args:
            session_id: Unique session identifier
            repo_path: Path to repository being analyzed
            whitelist: Optional set of protected file paths
            auto_cleanup: If True, cleanup session on exit
        """
        self.session_id = session_id
        self.repo_path = repo_path
        self.whitelist = whitelist
        self.auto_cleanup = auto_cleanup
        self.session: Optional[RootCauseSessionState] = None
        self.manager: Optional[RootCauseSessionManager] = None

    async def __aenter__(self) -> RootCauseSessionState:
        self.manager = await RootCauseSessionManager.get_instance()
        self.session = await self.manager.get_session(
            self.session_id,
            self.repo_path,
            self.whitelist
        )
        return self.session

    async def __aexit__(self, exc_type: Optional[type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]) -> None:
        if self.auto_cleanup and self.manager and self.session:
            await self.manager.cleanup_session(self.session_id)
        elif self.session:
            # Just check health without cleanup
            self.session.check_cache_health()
