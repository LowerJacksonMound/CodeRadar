"""
RCA - Centralized constants and configuration.
Eliminates magic numbers and provides tunable parameters.
"""

import logging
from pathlib import Path
from typing import FrozenSet

logger = logging.getLogger(__name__)

# ============================================================================
# THE ONE WALK (FIX_14, 2026-09-10) — replaces EXCLUDED_PATH_PATTERNS / should_exclude_path
# (archived: .archive/archived_20260910/rca_main/rca_constants_excluded.py.txt). A substring
# test on a path was a name-based exclusion; ONE whitelist is the ONE discovery (cut 3 batch 5),
# reachability by content never by path (rule 16). Every rca_main walk that is not handed a
# files= list falls back to scan_scope.iter_live_py — never a private rglob + name test.
# ============================================================================

def _scan_scope():
    """system_scripts/scan_scope.py — the same module object the daemons published the whitelist
    into (it is imported by name, never loaded a second time by file location)."""
    import sys
    try:
        import scan_scope
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "system_scripts"))
        import scan_scope
    return scan_scope


def live_py_files(root, files=None) -> list:
    """The .py files an rca_main walk may see: the handed-over list when the caller has one
    (the validator's whitelist-filtered discovery, plan item 6), else scan_scope.iter_live_py(root)
    — whitelist, engine hard-skips, containment (FIX_15). Sorted, as Paths."""
    if files is not None:
        return [Path(f) for f in files]
    return list(_scan_scope().iter_live_py(Path(root)))

# ============================================================================
# CACHING CONFIGURATION
# ============================================================================

# Calculator cache TTL (seconds)
CACHE_TTL_SECONDS: int = 300  # 5 minutes

# Number of files to sample for content hash
CACHE_SAMPLE_SIZE: int = 20

# Session-level cache limits
MAX_CACHE_SIZE: int = 10_000  # Per-session cache limit
MAX_SESSIONS: int = 100  # Total concurrent sessions
SESSION_TIMEOUT_HOURS: int = 24  # Auto-cleanup stale sessions

# Cache health thresholds
CACHE_HIT_RATE_WARNING_THRESHOLD: float = 0.3  # Warn if below 30%
CACHE_HIT_RATE_CRITICAL_THRESHOLD: float = 0.1  # Critical if below 10%


# ============================================================================
# SCORING WEIGHTS (must sum to 1.0)
# ============================================================================

WEIGHT_IMPORT_COUPLING: float = 0.35
WEIGHT_CALLER_COUPLING: float = 0.35
WEIGHT_COMPLEXITY: float = 0.30

# Validate weights sum to 1.0
_total_weight = (
    WEIGHT_IMPORT_COUPLING +
    WEIGHT_CALLER_COUPLING +
    WEIGHT_COMPLEXITY
)
assert abs(_total_weight - 1.0) < 0.001, f"Scoring weights must sum to 1.0, got {_total_weight}"


# ============================================================================
# CONTEXT LINES CONFIGURATION
# ============================================================================

MIN_CONTEXT_LINES: int = 10
DEFAULT_CONTEXT_LINES: int = 30
MAX_CONTEXT_LINES: int = 100


# ============================================================================
# COMPLEXITY THRESHOLDS
# ============================================================================

# Import coupling thresholds (low, high)
IMPORT_COUPLING_LOW: int = 10
IMPORT_COUPLING_HIGH: int = 25

# Caller coupling thresholds (low, high)
CALLER_COUPLING_LOW: int = 5
CALLER_COUPLING_HIGH: int = 15

# Function size thresholds (lines)
FUNCTION_SIZE_SMALL: int = 20
FUNCTION_SIZE_LARGE: int = 50


# ============================================================================
# RESOURCE LIMITS
# ============================================================================

# EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): MAX_FILES_TO_ANALYZE (1000) and MAX_FILE_SIZE_BYTES (1 MB) deleted — unreferenced budgets that invited silence
ANALYSIS_TIMEOUT_SECONDS: int = 300  # 5 minute timeout for full analysis
MAX_CONCURRENT_FILE_READS: int = 50  # Limit concurrent file reads to prevent fd exhaustion
