"""find_spec cache — the one helper the daemon still used from the retired always-pass repair validation (cut 3 round 1, 2026-09-06).
Extracted verbatim from the retired always-pass module; that module (always-pass repair verdict, 'atomic' era) is LOST by owner ruling.
"""
from __future__ import annotations
import importlib.util
from typing import Optional   # FIX_31 (2026-09-15): was used, never imported

IMPORT_CACHE_SIZE = 1024

try:
    from functools import lru_cache
    
    @lru_cache(maxsize=IMPORT_CACHE_SIZE)
    def _cached_find_spec(module_name: str) -> Optional[str]:
        """Cached import spec lookup."""
        try:
            spec = importlib.util.find_spec(module_name)
            return "found" if spec else None
        except Exception:
            return None
    
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    _cached_find_spec = None  # type: ignore[assignment]
