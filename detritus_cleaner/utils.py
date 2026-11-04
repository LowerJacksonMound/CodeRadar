"""Utility functions for detritus cleaner."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sys
from pathlib import Path
from typing import Callable, Optional, Coroutine, Any, TypeVar, TYPE_CHECKING


# =============================================================================
# Logging Setup
# =============================================================================

async def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure logger with proper formatting."""
    def _setup() -> logging.Logger:
        _logger = logging.getLogger("DetritusCleaner")
        _logger.setLevel(level)

        if not _logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(level)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            _logger.addHandler(handler)

        return _logger

    return await asyncio.to_thread(_setup)


logger = logging.getLogger("DetritusCleaner")


# =============================================================================
# Optional Integrations
# =============================================================================

_F = TypeVar('_F', bound=Callable[..., Any])

if TYPE_CHECKING:
    def trace(func: _F) -> _F: ...
    def emit_trace(*args: Any, **kwargs: Any) -> None: ...
    def set_workflow(*args: Any, **kwargs: Any) -> None: ...
    TRACING_ENABLED: bool
else:
    try:
        from flow_tracer import trace, emit_trace, set_workflow
        TRACING_ENABLED = True
    except ImportError:
        TRACING_ENABLED = False
        def trace(func):
            return func
        def emit_trace(*args, **kwargs):
            pass
        def set_workflow(*args, **kwargs):
            pass


try:
    import tomli  # Use tomli for Python < 3.11, tomllib for 3.11+
except ImportError:
    try:
        import tomllib as tomli  # type: ignore
    except ImportError:
        tomli = None  # type: ignore


# =============================================================================
# File Operations
# =============================================================================

async def compute_file_checksum(file_path: Path) -> Optional[str]:
    """Compute SHA256 checksum of a file. Returns None on failure."""
    logger.debug(f"compute_file_checksum: {file_path}")

    def _compute() -> Optional[str]:
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            digest = sha256.hexdigest()
            logger.debug(f"compute_file_checksum: {file_path} -> {digest[:16]}...")
            return digest
        except OSError as e:
            logger.warning(f"Failed to compute checksum for {file_path}: {e}")
            return None

    return await asyncio.to_thread(_compute)


def is_safe_path(base_path: Path, target_path: Path) -> bool:
    """Verify target path doesn't escape base directory."""
    try:
        target_path.resolve().relative_to(base_path.resolve())
        return True
    except ValueError:
        logger.debug(f"is_safe_path: REJECTED {target_path} (escapes {base_path})")
        return False


# =============================================================================
# Async Helpers
# =============================================================================

T = TypeVar('T')


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """
    Run async coroutine from synchronous context.
    
    This function is intended to be called from synchronous code only.
    If you're already in an async context, simply await the coroutine directly.
    
    Args:
        coro: The coroutine to run
        
    Returns:
        The result of the coroutine
        
    Raises:
        RuntimeError: If called from within an async context (running event loop)
    """
    logger.debug(f"run_async: executing coroutine {coro.__qualname__ if hasattr(coro, '__qualname__') else type(coro).__name__}")
    try:
        loop = asyncio.get_running_loop()
        # We're in an async context - this is likely a mistake
        raise RuntimeError(
            "run_async() cannot be called from an async context. "
            "Use 'await coro' directly instead."
        )
    except RuntimeError as e:
        if "no running event loop" not in str(e).lower():
            raise
        # No running loop - safe to create one
        logger.debug("run_async: no running event loop, creating new one")
        if sys.version_info >= (3, 11):
            with asyncio.Runner() as runner:
                return runner.run(coro)
        else:
            return asyncio.run(coro)


# Export commonly used symbols
__all__ = [
    'setup_logging',
    'logger',
    'trace',
    'emit_trace',
    'set_workflow',
    'TRACING_ENABLED',
    'tomli',
    'compute_file_checksum',
    'is_safe_path',
    'run_async',
]
