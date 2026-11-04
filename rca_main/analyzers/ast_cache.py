"""
AST Cache - Memoized AST parsing with auto-invalidation
"""

import ast
import asyncio
import hashlib
import logging
import os
from typing import Any, Callable, Optional, Dict, TypeVar
from dataclasses import dataclass
from threading import Lock
from functools import lru_cache
import aiofiles
import aiofiles.os

_F = TypeVar('_F', bound=Callable[..., Any])

# Flow tracing integration
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False

logger = logging.getLogger("ASTCache")


@dataclass
class CacheEntry:
    tree: ast.AST
    content_hash: str
    mtime: float
    size: int


class ASTCache:
    """Caches parsed AST trees with automatic invalidation."""

    def __init__(self, max_size: int = 100, check_mtime: bool = True):
        self._cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.check_mtime = check_mtime  # Check file modification time
        self._lock = Lock()  # For sync methods
        self._async_lock: Optional[asyncio.Lock] = None  # Lazy init for async methods

        # Stats
        self.hits = 0
        self.misses = 0
        self.invalidations = 0

    def _get_async_lock(self) -> asyncio.Lock:
        """Get or create async lock (lazy init for event loop safety)."""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _hash_content(self, content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()

    async def _get_file_info_async(self, file_path: str) -> tuple[float, int]:
        """Get mtime and size for a file (async)."""
        try:
            # FIX: Use aiofiles.os for async stat
            stat = await aiofiles.os.stat(file_path)
            return stat.st_mtime, stat.st_size
        except OSError:
            return 0, 0

    async def _is_stale_async(self, file_path: str, entry: CacheEntry) -> bool:
        """Check if cache entry is stale (async)."""
        if not self.check_mtime:
            return False

        mtime, size = await self._get_file_info_async(file_path)

        # Quick check: size or mtime changed
        if size != entry.size or mtime > entry.mtime:
            return True

        return False

    @trace
    async def get(self, file_path: str, content: Optional[str] = None) -> Optional[ast.AST]:
        """
        Get cached AST or parse and cache (async).

        Uses aiofiles for async file I/O operations.
        """
        logger.debug("get: %s (content_provided=%s)", file_path, content is not None)
        async with self._get_async_lock():
            if file_path in self._cache:
                entry = self._cache[file_path]

                # Validate cache freshness asynchronously
                is_stale = await self._is_stale_async(file_path, entry)

                if not is_stale:
                    # If content provided, verify hash matches
                    if content is not None:
                        content_hash = self._hash_content(content)
                        if content_hash == entry.content_hash:
                            self.hits += 1
                            return entry.tree
                    else:
                        self.hits += 1
                        return entry.tree

                # Stale - remove
                self.invalidations += 1
                del self._cache[file_path]

            self.misses += 1

            # Read content if not provided
            if content is None:
                try:
                    async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                        content = await f.read()
                except Exception as e:
                    logger.debug(f"Cannot read {file_path}: {e}")
                    return None

            # Parse
            try:
                tree = ast.parse(content)
            except SyntaxError as e:
                logger.debug(f"Syntax error in {file_path}: {e}")
                return None

            # Cache
            mtime, size = await self._get_file_info_async(file_path)

            entry = CacheEntry(
                tree=tree,
                content_hash=self._hash_content(content),
                mtime=mtime,
                size=size
            )

            # Evict if over limit (LRU-ish: just remove first)
            if len(self._cache) >= self.max_size:
                oldest = next(iter(self._cache))
                del self._cache[oldest]

            self._cache[file_path] = entry
            return tree

    @trace
    async def get_async(self, file_path: str, content: Optional[str] = None) -> Optional[ast.AST]:
        """
        Get cached AST or parse and cache (async).

        Args:
            file_path: Path to file
            content: Optional content (if already read)

        Returns:
            Parsed AST or None on error
        """
        logger.debug("get_async: %s (content_provided=%s)", file_path, content is not None)
        async with self._get_async_lock():
            # Check existing cache
            if file_path in self._cache:
                entry = self._cache[file_path]

                # Validate cache freshness
                is_stale = await self._is_stale_async(file_path, entry)
                if not is_stale:
                    # If content provided, verify hash matches
                    if content is not None:
                        content_hash = self._hash_content(content)
                        if content_hash == entry.content_hash:
                            self.hits += 1
                            return entry.tree
                    else:
                        self.hits += 1
                        return entry.tree

                # Stale - remove
                self.invalidations += 1
                del self._cache[file_path]

            self.misses += 1

            # Read content if not provided
            if content is None:
                try:
                    # Use aiofiles for async file reading
                    async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                        content = await f.read()
                except Exception as e:
                    logger.debug(f"Cannot read {file_path}: {e}")
                    return None

            # Parse
            try:
                tree = ast.parse(content)
            except SyntaxError as e:
                logger.debug(f"Syntax error in {file_path}: {e}")
                return None

            # Cache
            mtime, size = await self._get_file_info_async(file_path)
            entry = CacheEntry(
                tree=tree,
                content_hash=self._hash_content(content),
                mtime=mtime,
                size=size
            )

            # Evict if over limit (LRU-ish: just remove first)
            if len(self._cache) >= self.max_size:
                oldest = next(iter(self._cache))
                del self._cache[oldest]

            self._cache[file_path] = entry
            return tree

    @trace
    def invalidate(self, file_path: str) -> None:
        """Manually invalidate a cache entry."""
        logger.debug("invalidate: %s", file_path)
        with self._lock:
            if file_path in self._cache:
                del self._cache[file_path]
                self.invalidations += 1
                logger.debug(f"Invalidated cache for {file_path}")

    def invalidate_pattern(self, pattern: str) -> None:
        """Invalidate all entries matching a glob pattern."""
        import fnmatch
        with self._lock:
            to_remove = [k for k in self._cache if fnmatch.fnmatch(k, pattern)]
            for k in to_remove:
                del self._cache[k]
                self.invalidations += 1

    @trace
    def clear(self) -> None:
        """Clear entire cache."""
        logger.debug("clear: clearing %d cached ASTs", len(self._cache))
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            logger.info(f"Cleared {count} cached ASTs")

    def notify_file_changed(self, file_path: str) -> None:
        """Called when a file is modified (e.g., after fix applied)."""
        self.invalidate(file_path)

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "invalidations": self.invalidations,
            "hit_rate": round(self.hits / total * 100, 1) if total else 0,
            "cached_files": len(self._cache),
            "max_size": self.max_size
        }


# Global instance
ast_cache = ASTCache()


def invalidate_on_write(file_path: str) -> None:
    """Decorator helper: invalidate cache when file is written."""
    ast_cache.notify_file_changed(file_path)


@lru_cache(maxsize=200)
def parse_cached(content: str) -> Optional[ast.AST]:
    """Standalone cached parse function."""
    try:
        return ast.parse(content)
    except SyntaxError:
        return None