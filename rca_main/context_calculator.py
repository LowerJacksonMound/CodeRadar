"""
PRE-SCAN RCA - Context Lines Calculator
Calculates optimal context_lines based on file coupling and function complexity.

ENTIRE APP IS ASYNC: Provides rca-lite context analysis.

UPGRADES APPLIED:
- #4: Thread-Safe Calculator Cache (simplified with threading.Lock)
- #4b: Content-Aware Cache with File Hashing (fixed blocking I/O)
- #7: Resource Limits & Timeouts
- #10: Centralized exclude patterns
- #11: Session-aware caching with automatic hit tracking

SESSION CACHING:
When a RootCauseSessionState is provided, caching uses session.cache_get()
and session.cache_set() for automatic hit rate tracking. This enables
monitoring cache performance and tuning MAX_CACHE_SIZE.

Usage with session:
    async with RootCauseSession(session_id, repo_path) as session:
        calc = ContextLinesCalculator(repo_path, session=session)
        rec = calc.recommend_for_file(file_path)
        # Cache hits/misses automatically tracked in session.cache_metrics
"""

import asyncio
import hashlib
import threading
import time as _time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Dict, List, Tuple, TYPE_CHECKING, TypeVar

import aiofiles
import aiofiles.os

# Flow tracing integration
_F = TypeVar('_F', bound=Callable[..., Any])
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass
def set_workflow(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace, set_workflow  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False

import logging

from rca_main.import_graph import ImportGraphBuilder
from rca_main.caller_map import CallerMapBuilder
from rca_main.constants import (
    live_py_files,
    CACHE_TTL_SECONDS,
    CACHE_SAMPLE_SIZE,
    WEIGHT_IMPORT_COUPLING,
    WEIGHT_CALLER_COUPLING,
    WEIGHT_COMPLEXITY,
    MIN_CONTEXT_LINES,
    DEFAULT_CONTEXT_LINES,
    MAX_CONTEXT_LINES,
)

if TYPE_CHECKING:
    from executor import WorkflowContext
    from rca_main.session_state import RootCauseSessionState

logger = logging.getLogger(__name__)


@dataclass
class ContextRecommendation:
    """Recommended context_lines with reasoning"""
    context_lines: int
    confidence: str  # "high", "medium", "low"
    reasoning: List[str]

    # Component scores
    import_score: float
    caller_score: float
    complexity_score: float

    # File info
    file_path: Optional[Path] = None
    function_name: Optional[str] = None


@dataclass
class RepoStats:
    """Repository statistics for dynamic threshold scaling"""
    total_files: int = 0
    total_functions: int = 0
    avg_imports_per_file: float = 0.0
    avg_calls_per_function: float = 0.0

    @property
    def size_category(self) -> str:
        """Categorize repo size"""
        if self.total_files < 20:
            return "small"
        elif self.total_files < 100:
            return "medium"
        else:
            return "large"


class ContextLinesCalculator:
    """
    Calculates optimal context_lines for a file or function.

    Factors considered:
    1. Import coupling - how many files import/are imported by this file
    2. Caller coupling - how many functions call/are called by this function
    3. Function complexity - lines of code, number of internal calls

    Usage:
        calc = ContextLinesCalculator(project_root)
        calc.scan()

        rec = calc.recommend_for_file(Path("orchestrator/scanner.py"))
        print(f"Recommended: {rec.context_lines} lines")

        rec = calc.recommend_for_function("repair_pipeline._execute_repairs")
        print(f"Recommended: {rec.context_lines} lines")
    """

    # Context line ranges (from constants)
    MIN_CONTEXT = MIN_CONTEXT_LINES
    DEFAULT_CONTEXT = DEFAULT_CONTEXT_LINES
    MAX_CONTEXT = MAX_CONTEXT_LINES

    def __init__(
        self,
        project_root: Path,
        session: Optional['RootCauseSessionState'] = None,
        files=None,
    ):
        """
        Initialize context lines calculator.

        Args:
            project_root: Root directory of the project to analyze
            session: Optional RootCauseSessionState for tracked caching.
                     When provided, caching uses session.cache_get/cache_set
                     for automatic hit rate tracking.
            files: the caller's whitelist-filtered file list (FIX_14) — the graph and the
                   caller map are built from exactly these; None = the ONE walk
                   (scan_scope.iter_live_py), never a private rglob.
        """
        self.project_root = project_root.resolve()
        self.files = [Path(f) for f in files] if files is not None else None
        self.import_graph = ImportGraphBuilder(project_root, files=files)
        self.caller_map = CallerMapBuilder(project_root, files=files)
        self._scanned = False

        # Session for tracked caching (optional)
        self._session: Optional['RootCauseSessionState'] = session

        # Dynamic thresholds
        self.repo_stats: Optional[RepoStats] = None

    async def scan(self) -> None:
        """Scan project to build import graph and caller map"""
        logger.info("Building import graph...")
        await self.import_graph.scan()

        logger.info("Building caller map...")
        await self.caller_map.scan()

        # Calculate repo stats for dynamic thresholds
        await self._calculate_repo_stats()

        self._scanned = True
        if self.repo_stats is not None:
            logger.info(f"Context calculator ready (repo size: {self.repo_stats.size_category})")

    async def scan_async(self) -> None:
        """Async version: Scan project to build import graph and caller map."""
        logger.info("Building import graph (async)...")
        await self.import_graph.scan_async()

        logger.info("Building caller map (async)...")
        await self.caller_map.scan_async()

        # Calculate repo stats (now natively async)
        await self._calculate_repo_stats()

        self._scanned = True
        if self.repo_stats is not None:
            logger.info(f"Context calculator ready (repo size: {self.repo_stats.size_category})")

    async def _calculate_repo_stats(self) -> None:
        """Calculate repository statistics for dynamic threshold scaling"""
        total_files = len(set(f.file_path for f in self.caller_map.functions.values()))
        total_functions = len(self.caller_map.functions)

        # Calculate average imports per file — the handed-over list, else the ONE walk (FIX_14)
        py_files = await asyncio.to_thread(live_py_files, self.project_root, self.files)
        import_counts = []
        for py_file in py_files:
            importers = len(self.import_graph.get_importers(py_file))
            imports = len(self.import_graph.get_imports(py_file))
            import_counts.append(importers + imports)

        avg_imports = sum(import_counts) / len(import_counts) if import_counts else 0

        # Calculate average calls per function
        call_counts = []
        for func_def in self.caller_map.functions.values():
            callers = len(self.caller_map.get_callers(func_def.qualified_name, cross_file_only=True))
            callees = len(func_def.calls)
            call_counts.append(callers + callees)

        avg_calls = sum(call_counts) / len(call_counts) if call_counts else 0

        self.repo_stats = RepoStats(
            total_files=total_files,
            total_functions=total_functions,
            avg_imports_per_file=avg_imports,
            avg_calls_per_function=avg_calls
        )

        logger.debug(f"Repo stats: {self.repo_stats}")

    # EXCISED cut 3 batch 3 (2026-09-06): _get_import_thresholds / _get_caller_thresholds (repo-size-scaled tier thresholds, a percentile-style gate) retired

    async def _ensure_scanned(self) -> None:
        if not self._scanned:
            await self.scan()

    async def recommend_for_file(self, file_path: Path) -> ContextRecommendation:
        """Calculate recommended context_lines for a file."""
        await self._ensure_scanned()

        file_path = file_path.resolve()
        reasoning = []

        # Get dynamic thresholds
        # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): repo-size-scaled thresholds (a percentile-style gate) no longer consulted

        # Get import coupling score
        importers = len(self.import_graph.get_importers(file_path))
        imports = len(self.import_graph.get_imports(file_path))
        import_total = importers + imports

        # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): import-coupling tiers 0.2/0.5/0.9 against repo-size-scaled thresholds were a score before the ranker; the count is the measurement
        import_score = float(import_total)
        reasoning.append(f"Import coupling: {import_total} connections")

        # Get average caller coupling for functions in this file
        caller_scores = []
        for qualified, func_def in self.caller_map.functions.items():
            if func_def.file_path == file_path:
                callers = len(self.caller_map.get_callers(qualified, cross_file_only=True))
                callees = len(func_def.calls)
                caller_scores.append(callers + callees)

        if caller_scores:
            avg_calls = sum(caller_scores) / len(caller_scores)
            # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): caller-coupling tiers 0.2/0.5/0.9 replaced by the raw average
            caller_score = float(avg_calls)
            reasoning.append(f"Function coupling: avg {avg_calls:.1f} calls")
        else:
            caller_score = 0.0   # K2 (owner 2026-09-07): no invented default — nothing measured is 0
            reasoning.append("No functions found in file")

        # Complexity: based on file having high-coupling functions
        max_call_score = max(caller_scores) if caller_scores else 0
        # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): complexity tiers 0.2/0.5/0.9 replaced by the raw maximum
        complexity_score = float(max_call_score)
        reasoning.append(f"Max function coupling: {max_call_score} connections")

        # Inheritance coupling bonus
        inheritance_coupling = self.caller_map.get_class_coupling(file_path)
        if inheritance_coupling > 0:
            reasoning.append(f"Class inheritance coupling ({inheritance_coupling} cross-file bases)")   # K2: the count is the fact; no bonus

        # Calculate final context_lines with configurable weights
        # K2 (owner 2026-09-07): the weighted score + exponent that TRIMMED the context the Ranker sees was a
        # ranking before the Ranker — excised; the consumer sees the whole context, as on the per-function path
        context_lines = self.MAX_CONTEXT

        # Confidence based on data quality
        if len(caller_scores) > 3 and import_total > 0:
            confidence = "high"
        elif len(caller_scores) > 0 or import_total > 0:
            confidence = "medium"
        else:
            confidence = "low"
            reasoning.append("Limited data for this file")

        return ContextRecommendation(
            context_lines=context_lines,
            confidence=confidence,
            reasoning=reasoning,
            import_score=import_score,
            caller_score=caller_score,
            complexity_score=complexity_score,
            file_path=file_path
        )

    async def recommend_for_function(self, function_name: str) -> ContextRecommendation:
        """Calculate recommended context_lines for a specific function."""
        await self._ensure_scanned()

        reasoning = []

        # Find the function
        func_def = None
        for qualified, fd in self.caller_map.functions.items():
            if qualified == function_name or qualified.endswith('.' + function_name):
                func_def = fd
                function_name = qualified
                break

        if not func_def:
            return ContextRecommendation(
                context_lines=self.DEFAULT_CONTEXT,
                confidence="low",
                reasoning=["Function not found in project"],
                import_score=0.5,
                caller_score=0.5,
                complexity_score=0.5,
                function_name=function_name
            )

        file_path = func_def.file_path

        # Caller coupling
        callers = self.caller_map.get_callers(function_name, cross_file_only=True)
        num_callers = len(callers)

        # EXCISED cut 3 batch 3 (2026-09-06): caller tier ladder (0.2/0.5/0.9 against halved repo-scaled thresholds) → the raw count
        caller_score = float(num_callers)
        reasoning.append(f"Caller coupling: {num_callers} external callers")

        # Callee coupling
        num_callees = len(func_def.calls)
        # EXCISED cut 3 batch 3 (2026-09-06): callee tier ladder (3 / 8) → the raw count
        callee_score = float(num_callees)
        reasoning.append(f"Callee coupling: {num_callees} calls")

        # File-level import coupling
        importers = len(self.import_graph.get_importers(file_path))
        imports = len(self.import_graph.get_imports(file_path))
        import_total = importers + imports
        # EXCISED cut 3 batch 3 (2026-09-06): file import tier ladder → the raw count
        import_score = float(import_total)
        reasoning.append(f"File import coupling: {import_total} connections")

        # Complexity from function size
        func_lines = func_def.end_lineno - func_def.lineno
        # EXCISED cut 3 batch 3 (2026-09-06): size tier ladder (20 / 50) → the raw line count
        complexity_score = float(func_lines)
        reasoning.append(f"Function size: {func_lines} lines")

        # Calculate weighted score
        # EXCISED cut 3 batch 3 (2026-09-06): the weighted score (fixed coefficients, exponent 1.5) that TRIMMED context lines was a ranking; context is not trimmed —
        # the raw measurements above are published and the consumer sees the whole context
        context_lines = self.MAX_CONTEXT

        # Confidence
        if num_callers > 0 or num_callees > 3:
            confidence = "high"
        elif import_total > 0:
            confidence = "medium"
        else:
            confidence = "low"

        return ContextRecommendation(
            context_lines=context_lines,
            confidence=confidence,
            reasoning=reasoning,
            import_score=import_score,
            caller_score=(caller_score + callee_score) / 2,
            complexity_score=complexity_score,
            file_path=file_path,
            function_name=function_name
        )

    async def recommend_for_error(self, file_path: Path, line_number: int) -> ContextRecommendation:
        """
        Calculate recommended context_lines for an error at a specific location.

        Combines file-level and function-level analysis.
        """
        await self._ensure_scanned()

        # Start with file recommendation
        file_rec = await self.recommend_for_file(file_path)

        # Try to find function at this line
        for qualified, func_def in self.caller_map.functions.items():
            if (func_def.file_path == file_path and
                func_def.lineno <= line_number <= func_def.end_lineno):
                func_rec = await self.recommend_for_function(qualified)
                # Return whichever recommends more context
                if func_rec.context_lines > file_rec.context_lines:
                    return func_rec
                break

        return file_rec

    async def recommend_for_file_async(self, file_path: Path) -> ContextRecommendation:
        """
        Async version: Calculate recommended context_lines for a file.

        Now delegates to recommend_for_file which is natively async.
        Kept for backward compatibility with existing callers.
        """
        return await self.recommend_for_file(file_path)

    async def recommend_for_error_async(self, file_path: Path, line_number: int) -> ContextRecommendation:
        """
        Async version: Calculate recommended context_lines for an error.

        Now delegates to recommend_for_error which is natively async.
        Kept for backward compatibility with existing callers.
        """
        return await self.recommend_for_error(file_path, line_number)


# =============================================================================
# UPGRADE #4b: Content-Aware Cache with File Hashing (Fixed)
# =============================================================================

@dataclass
class CacheEntry:
    """Cache entry with content hash for change detection."""
    calculator: ContextLinesCalculator
    created_at: float
    content_hash: str


# Module-level cache with thread safety
_calculator_cache: Dict[str, CacheEntry] = {}
_cache_lock = threading.Lock()


async def _compute_repo_hash(repo_path: Path) -> str:
    """
    Compute hash of sample Python files for change detection.

    Upgrade #4b fix: Uses async I/O, deterministic sampling.

    Args:
        repo_path: Path to repository

    Returns:
        MD5 hash string of file metadata
    """
    hasher = hashlib.md5(usedforsecurity=False)

    # Include directory mtime for structural changes
    try:
        dir_stat = await aiofiles.os.stat(str(repo_path))
        hasher.update(str(dir_stat.st_mtime).encode())
    except OSError:
        pass

    # The ONE walk (FIX_14), in a thread (sync metadata)
    py_files = await asyncio.to_thread(live_py_files, repo_path)

    # Deterministic sampling: first N sorted + largest N
    half_sample = CACHE_SAMPLE_SIZE // 2
    sample = sorted(py_files)[:half_sample]

    try:
        sizes = []
        for p in py_files:
            try:
                s = await aiofiles.os.stat(str(p))
                sizes.append((p, s.st_size))
            except OSError:
                pass
        sizes.sort(key=lambda x: x[1], reverse=True)
        sample.extend(p for p, _ in sizes[:half_sample])
    except OSError:
        pass

    for py_file in sorted(set(sample)):
        try:
            stat = await aiofiles.os.stat(str(py_file))
            hasher.update(f"{py_file}:{stat.st_mtime}:{stat.st_size}".encode())
        except OSError:
            continue

    return hasher.hexdigest()


async def _is_cache_valid(repo_path: str) -> bool:
    """
    Check if cache entry is still valid (not expired and content unchanged).

    Upgrade #4b: Adds content hash validation.
    """
    if repo_path not in _calculator_cache:
        return False

    entry = _calculator_cache[repo_path]
    age = _time.time() - entry.created_at

    if age >= CACHE_TTL_SECONDS:
        return False

    # Check content hash (only if within TTL)
    current_hash = await _compute_repo_hash(Path(repo_path))
    return entry.content_hash == current_hash


async def _get_or_create_calculator(
    repo_path: str,
    session: Optional['RootCauseSessionState'] = None
) -> ContextLinesCalculator:
    """
    Thread-safe calculator retrieval with TTL and content-aware caching.

    Args:
        repo_path: Path to repository
        session: Optional RootCauseSessionState for tracked caching

    Returns:
        ContextLinesCalculator instance (cached or new)
    """
    # Check cache under lock (fast path)
    # Note: _is_cache_valid is async, so we check outside the lock
    if await _is_cache_valid(repo_path):
        with _cache_lock:
            if repo_path in _calculator_cache:
                calc = _calculator_cache[repo_path].calculator
                # Update session reference if provided
                if session:
                    calc._session = session
                return calc

    # Scan OUTSIDE the lock to avoid blocking other threads during I/O
    calc = ContextLinesCalculator(
        Path(repo_path),
        session=session
    )
    await calc.scan()

    # Store result under lock (short critical section)
    content_hash = await _compute_repo_hash(Path(repo_path))
    # Double-check: another thread may have populated the cache while we scanned
    if await _is_cache_valid(repo_path):
        with _cache_lock:
            if repo_path in _calculator_cache:
                existing = _calculator_cache[repo_path].calculator
                if session:
                    existing._session = session
                return existing

    with _cache_lock:
        _calculator_cache[repo_path] = CacheEntry(
            calculator=calc,
            created_at=_time.time(),
            content_hash=content_hash
        )

        return calc


async def _compute_repo_hash_async(repo_path: Path) -> str:
    """
    Async version: Compute hash of sample Python files for change detection.

    Now delegates to _compute_repo_hash which is natively async.
    Kept for backward compatibility with existing callers.
    """
    return await _compute_repo_hash(repo_path)


async def _get_or_create_calculator_async(
    repo_path: str,
    session: Optional['RootCauseSessionState'] = None
) -> ContextLinesCalculator:
    """
    Async version: Thread-safe calculator retrieval with TTL and content-aware caching.

    Now delegates to _get_or_create_calculator which is natively async.
    Kept for backward compatibility with existing callers.
    """
    return await _get_or_create_calculator(repo_path, session)


def clear_calculator_cache(repo_path: str | None = None) -> None:
    """
    Clear the calculator cache to force re-scanning.

    Args:
        repo_path: If provided, only clear cache for this repo.
                   If None, clears all cached calculators.
    """
    with _cache_lock:
        if repo_path:
            _calculator_cache.pop(repo_path, None)
        else:
            _calculator_cache.clear()


# =============================================================================
# WORKFLOW HANDLER (executor.py integration)
# =============================================================================

def _emit_rca_lite_trace(name: str, success: bool, elapsed: float = 0.0, error: str | None = None) -> None:
    """Helper to emit RootCause Lite traces."""
    if _TRACING_ENABLED:
        emit_trace(
            name=f"rca_lite_{name}",
            success=success,
            elapsed=elapsed,
            error=error,
            layer='RootCause',
            module='context_calculator.py'
        )


@trace
async def rca_lite_handler(context: 'WorkflowContext') -> 'WorkflowContext':
    """
    Workflow handler for Step 19: RootCause Lite.

    Calculates optimal context_lines for each job based on file coupling
    and function complexity. This runs AFTER granulation but BEFORE fix execution.

    Reads: context.jobs, context.repo_path
    Writes: context.jobs[].context_lines (updated with calculated values)
    """
    set_workflow('phase1_rca_lite')

    _start_total = _time.perf_counter()
    _emit_rca_lite_trace('start', success=True, elapsed=0)

    _start = _time.perf_counter()
    if not context.jobs:
        _emit_rca_lite_trace('check_jobs', success=True, elapsed=_time.perf_counter() - _start)
        _emit_rca_lite_trace('no_jobs', success=True, elapsed=0)
        logger.info("RootCause Lite: No jobs to process")
        context.step_results['rca_lite'] = {
            'jobs_processed': 0,
            'note': 'No jobs to process'
        }
        _emit_rca_lite_trace('complete', success=True, elapsed=_time.perf_counter() - _start_total)
        return context
    _emit_rca_lite_trace('check_jobs', success=True, elapsed=_time.perf_counter() - _start)

    repo_path = Path(context.repo_path)

    _start = _time.perf_counter()

    # Check cache status before getting calculator
    cache_will_hit = await _is_cache_valid(str(context.repo_path))

    calc = await _get_or_create_calculator_async(str(context.repo_path))

    if cache_will_hit:
        _emit_rca_lite_trace('cache_hit', success=True, elapsed=_time.perf_counter() - _start)
    else:
        logger.info(f"RootCause Lite: Built analysis graphs for {repo_path}")
        _emit_rca_lite_trace('init_calculator', success=True, elapsed=_time.perf_counter() - _start)

    _start = _time.perf_counter()
    jobs_processed = 0
    for job in context.jobs:
        file_path = job.get('file_path', '')
        line_number = job.get('line_number', 1)

        if not file_path:
            continue

        full_path = repo_path / file_path
        if not full_path.exists():
            continue

        rec = await calc.recommend_for_error_async(full_path, line_number)

        half_context = rec.context_lines // 2
        start_line = max(1, line_number - half_context)
        end_line = line_number + half_context

        job['context_lines'] = (start_line, end_line)
        job['rca_confidence'] = rec.confidence
        job['rca_reasoning'] = rec.reasoning
        jobs_processed += 1

        logger.debug(
            f"RootCause Lite: {file_path}:{line_number} -> "
            f"context_lines=({start_line}, {end_line}) [{rec.confidence}]"
        )
    _emit_rca_lite_trace('process_jobs', success=True, elapsed=_time.perf_counter() - _start)

    _start = _time.perf_counter()
    context.step_results['rca_lite'] = {
        'jobs_processed': jobs_processed,
        'jobs_total': len(context.jobs),
        'cache_used': cache_will_hit,
        'repo_size': calc.repo_stats.size_category if calc.repo_stats else 'unknown',
    }
    _emit_rca_lite_trace('store_results', success=True, elapsed=_time.perf_counter() - _start)

    _emit_rca_lite_trace('complete', success=True, elapsed=_time.perf_counter() - _start_total)

    logger.info(f"RootCause Lite: Processed {jobs_processed} jobs")
    return context


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys

    async def _cli_main() -> None:
        if len(sys.argv) < 2:
            print("Usage: python context_calculator.py <project_root> [file_or_function]")
            sys.exit(1)

        project_root = Path(sys.argv[1])

        print(f"Scanning {project_root}...")
        calc = ContextLinesCalculator(project_root)
        await calc.scan()

        print(f"\nRepo stats:")
        if calc.repo_stats is not None:
            print(f"  Size category: {calc.repo_stats.size_category}")
            print(f"  Total files: {calc.repo_stats.total_files}")
            print(f"  Total functions: {calc.repo_stats.total_functions}")
        else:
            print("  Repo stats not available")

        args = sys.argv[2:]

        if len(args) > 0:
            if args[0] == "--function":
                func_name = args[1]
                rec = await calc.recommend_for_function(func_name)
                print(f"\n{'='*50}")
                print(f"Function: {func_name}")
            else:
                file_path = Path(args[0])
                if not file_path.is_absolute():
                    file_path = project_root / file_path
                rec = await calc.recommend_for_file(file_path)
                print(f"\n{'='*50}")
                print(f"File: {file_path.name}")

            print(f"{'='*50}")
            print(f"\nRecommended context_lines: {rec.context_lines}")
            print(f"Confidence: {rec.confidence}")
            print(f"\nScores:")
            print(f"  Import coupling:  {rec.import_score:.2f}")
            print(f"  Caller coupling:  {rec.caller_score:.2f}")
            print(f"  Complexity:       {rec.complexity_score:.2f}")
            print(f"\nReasoning:")
            for r in rec.reasoning:
                print(f"  - {r}")

        else:
            print(f"\n{'='*60}")
            print("Context line recommendations by file:")
            print(f"{'='*60}")

            recs = []
            for py_file in live_py_files(project_root):  # FIX_14: the ONE walk (CLI, no live caller)
                rec = await calc.recommend_for_file(py_file)
                recs.append((py_file, rec))

            recs.sort(key=lambda x: x[1].context_lines, reverse=True)

            for fp, rec in recs[:20]:
                rel = fp.relative_to(project_root)
                print(f"  {rec.context_lines:3d} lines [{rec.confidence:6s}]  {rel}")

    asyncio.run(_cli_main())
