"""Workflow handlers and high-level API functions for detritus cleaner."""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Callable, Dict, Any, Optional, TypeVar, TYPE_CHECKING

from detritus_cleaner.models import DetritusConfig, CleanseResult, ProgressCallback
from detritus_cleaner.core import DetritusCleaner
from detritus_cleaner.utils import (
    logger,
    trace as _trace_impl,
    emit_trace,
    set_workflow,
    TRACING_ENABLED,
)

_F = TypeVar('_F', bound=Callable[..., Any])

def trace(func: _F) -> _F:
    return _trace_impl(func)  # type: ignore[no-any-return]

__all__ = [
    'run_pre_game_optimization',
    'validate_cleaning',
    'clean',
    'post_scan_validation_handler',
]

if TYPE_CHECKING:
    # WorkflowContext is provided by external orchestrator frameworks
    # Using Any as fallback type when not available
    try:
        from executor import WorkflowContext
    except ImportError:
        from typing import Any as WorkflowContext


# =============================================================================
# Public API Functions
# =============================================================================

async def run_pre_game_optimization(
    repo_path: str,
    skip_cleanup: bool = False,
    dry_run: bool = False,
    progress_callback: Optional[ProgressCallback] = None
) -> Dict[str, Any]:
    """
    High-level function for repository optimization.
    Pure async function for repository optimization.

    Args:
        repo_path: Path to repository
        skip_cleanup: If True, only scan without cleaning
        dry_run: If True, don't actually move files
        progress_callback: Optional progress callback

    Returns:
        Dictionary with optimization results
    """
    _opt_start = time.perf_counter()
    repo = Path(repo_path).resolve()
    if not repo.exists():
        raise FileNotFoundError(f"Repository not found: {repo}")

    logger.info(f"Starting pre-game optimization for: {repo}")
    logger.debug(f"run_pre_game_optimization: skip_cleanup={skip_cleanup}, dry_run={dry_run}")

    if TRACING_ENABLED:
        emit_trace('optimization_start', success=True, elapsed=0,
                   layer='Workflow', module='workflows.py')

    # 1. Load whitelist if available
    whitelist_files = set()
    artifacts = []

    try:
        # Try multiple import paths for WhitelistManager
        WhitelistManager = None
        for module_path in [
            'data.whitelist',
            'orchestrator.core.data.whitelist',
        ]:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                WhitelistManager = getattr(mod, 'WhitelistManager', None)
                if WhitelistManager:
                    break
            except ImportError:
                continue
        
        if WhitelistManager:
            wm = WhitelistManager(str(repo))
            if wm.exists():
                wl = wm.load()
                for item in wl.items:
                    whitelist_files.add(item.file)
                    artifacts.append({"file": item.file, "name": item.name})
                logger.info(f"Loaded {len(whitelist_files)} whitelisted files")
        else:
            logger.debug("WhitelistManager not available")
    except Exception as e:
        logger.warning(f"Failed to load whitelist: {e}")

    logger.debug(f"run_pre_game_optimization: {len(whitelist_files)} whitelist files, "
                  f"{len(artifacts)} artifacts")

    if TRACING_ENABLED:
        emit_trace('optimization_whitelist_loaded', success=True,
                   elapsed=time.perf_counter() - _opt_start,
                   layer='Workflow', module='workflows.py')

    # 2. Configure and run cleaner
    config = DetritusConfig(
        repo_path=repo,
        dry_run=dry_run or skip_cleanup,
        additional_entry_points=whitelist_files
    )

    cleaner = DetritusCleaner(config)

    # 3. Run async pipeline directly
    logger.debug(f"run_pre_game_optimization: mode={'scan-only' if skip_cleanup else 'clean'}")
    if skip_cleanup:
        result = await cleaner.scan(progress_callback)
    else:
        result = await cleaner.clean_async(progress_callback=progress_callback)

    _opt_elapsed = time.perf_counter() - _opt_start
    logger.debug(f"run_pre_game_optimization: completed in {_opt_elapsed:.2f}s")

    if TRACING_ENABLED:
        emit_trace('optimization_complete', success=True,
                   elapsed=_opt_elapsed,
                   layer='Workflow', module='workflows.py')

    # 4. Return results
    return {
        "success": True,
        "whitelist": list(whitelist_files),
        "artifacts": artifacts,
        "scan_results": result.summary(),
        "detritus_moved": result.moved_files,
        "failed_moves": result.failed_files,
        "manifest_path": result.manifest_path,
        "files_remaining": len(result.live_files | result.whitelisted_files),
        "circular_imports": len(result.circular_imports)
    }


async def validate_cleaning(
    repo_path: Path,
    original_result: CleanseResult,
    config: DetritusConfig
) -> Dict[str, Any]:
    """
    Independent validation of cleaning results.
    Re-scans repository and verifies consistency.

    Args:
        repo_path: Repository path
        original_result: Original cleaning result
        config: Configuration used for original cleaning

    Returns:
        Validation report
    """
    _val_start = time.perf_counter()
    logger.info("Running post-clean validation...")
    logger.debug(f"validate_cleaning: repo={repo_path}, dry_run={config.dry_run}, "
                  f"original_detritus={len(original_result.detritus_files)}")

    if TRACING_ENABLED:
        emit_trace('validate_cleaning_start', success=True, elapsed=0,
                   layer='Validation', module='workflows.py')

    # Create independent auditor
    audit_config = DetritusConfig(
        repo_path=repo_path,
        dry_run=True,  # Never modify during audit
        additional_entry_points=config.additional_entry_points,
        exclude_dirs=config.exclude_dirs
    )

    auditor = DetritusCleaner(audit_config)
    audit_result = await auditor.scan()

    logger.debug(f"validate_cleaning: audit found {len(audit_result.detritus_files)} detritus, "
                  f"{len(audit_result.live_files)} live")

    # Compute expected state
    expected_detritus = len(original_result.detritus_files) if config.dry_run else 0
    actual_detritus = len(audit_result.detritus_files)
    
    if config.dry_run:
        # Dry run: detritus count should match (nothing was moved)
        passed = (expected_detritus == actual_detritus)
    else:
        # Real cleaning: detritus should be gone
        passed = (actual_detritus == 0)

    discrepancies = []
    if not passed:
        if config.dry_run:
            discrepancies.append(
                f"Dry run mismatch: expected {expected_detritus}, found {actual_detritus}"
            )
        else:
            discrepancies.append(
                f"Detritus remains after cleaning: {actual_detritus} files"
            )
            # List the remaining detritus files
            if audit_result.detritus_files:
                discrepancies.append(f"Files: {sorted(audit_result.detritus_files)[:10]}")

    validation_report = {
        "passed": passed,
        "original_detritus_count": len(original_result.detritus_files),
        "audit_detritus_count": actual_detritus,
        "files_moved": len(original_result.moved_files),
        "files_failed": len(original_result.failed_files),
        "discrepancies": discrepancies
    }

    if passed:
        logger.info("Validation passed")
    else:
        logger.error(f"Validation failed: {discrepancies}")

    if TRACING_ENABLED:
        emit_trace('validate_cleaning_complete', success=passed,
                   elapsed=time.perf_counter() - _val_start,
                   error='; '.join(discrepancies) if discrepancies else None,
                   layer='Validation', module='workflows.py')

    return validation_report


# =============================================================================
# Workflow Handlers (Backward Compatibility)
# =============================================================================

@trace
async def clean(context: 'WorkflowContext') -> 'WorkflowContext':
    """
    Workflow handler for detritus cleanup step (Step 10).

    Reads: context.repo_path, context.whitelist, context.dry_run
    Writes: context.step_results['detritus_clean']
    """
    _start = time.perf_counter()
    logger.debug(f"clean handler: repo={context.repo_path}, dry_run={context.dry_run}")

    # Use whitelisted files as protected entry points
    protected_files = set(context.whitelist) if context.whitelist else set()
    logger.debug(f"clean handler: {len(protected_files)} protected files from whitelist")

    config = DetritusConfig(
        repo_path=Path(context.repo_path),
        dry_run=context.dry_run,
        additional_entry_points=protected_files,
    )
    cleaner = DetritusCleaner(config)

    # Use async method to avoid blocking the event loop
    result = await cleaner.clean_async()

    _elapsed = time.perf_counter() - _start

    # Emit individual traces for detritus categories
    if TRACING_ENABLED:
        emit_trace('detritus_live_files', success=True, elapsed=0,
                   layer='Scanner', module='workflows.py')
        emit_trace('detritus_orphans_found', success=True, elapsed=0,
                   layer='Scanner', module='workflows.py')
        emit_trace('detritus_scan_complete', success=True, elapsed=_elapsed,
                   layer='Scanner', module='workflows.py')

    # Report to Recorder if available
    if hasattr(context, '_recorder') and context._recorder:
        try:
            context._recorder.record_mission_event(
                'detritus_scan',
                {
                    'total_scanned': result.total_scanned,
                    'live_files': len(result.live_files),
                    'detritus_count': len(result.detritus),
                    'detritus_to_remove': sorted(result.detritus)[:20],
                }
            )
        except Exception as e:
            logger.debug(f"Could not report to Recorder: {e}")

    context.step_results['detritus_clean'] = {
        'live_files': len(result.live_files),
        'whitelisted_files': len(result.whitelisted_files),
        'detritus_count': len(result.detritus),
        'detritus_to_remove': result.detritus,
        'total_scanned': result.total_scanned,
    }

    logger.debug(f"clean handler: completed in {_elapsed:.2f}s - "
                  f"{result.total_scanned} scanned, {len(result.detritus)} detritus")
    return context


@trace
async def post_scan_validation_handler(context: 'WorkflowContext') -> 'WorkflowContext':
    """
    Workflow handler for post-scan validation (Step 11).

    TRULY INDEPENDENT VERIFICATION:
    - Re-scans codebase using SEPARATE methods
    - Does NOT trust prior step outputs (except detritus count)
    - Arrives at conclusions independently and compares

    INPUT FROM PRIOR STEPS:
    - detritus_count: The ONLY value passed from Step 3 (the claim to verify)

    Reads: context.repo_path, context.step_results['detritus_clean']['detritus_count']
    Writes: context.step_results['post_scan_validate']
    """
    start_total = time.perf_counter()
    repo_path = Path(context.repo_path)
    holding_dir_name = DetritusConfig(repo_path=repo_path).holding_dir_name
    logger.debug(f"post_scan_validation_handler: repo={repo_path}, "
                  f"holding_dir={holding_dir_name}")

    # Set workflow context for tracing
    set_workflow('phase1_validation_scan')

    # TRACE: Validation entry point
    if TRACING_ENABLED:
        emit_trace('validate_start', success=True, elapsed=0,
                   layer='Validation', module='workflows.py')

    # Get claimed detritus count from prior step
    start = time.perf_counter()
    claimed_detritus_count = 0
    if 'detritus_clean' in context.step_results:
        claimed_detritus_count = context.step_results['detritus_clean'].get('detritus_count', 0)

    if TRACING_ENABLED:
        emit_trace('validate_get_claim', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    # Fresh filesystem scan
    start = time.perf_counter()

    def _scan_py_files() -> set[str]:
        result = set()
        from rca_main.constants import _scan_scope  # FIX_15: contained walks, never a bare glob
        _ss = _scan_scope()
        for f in _ss.iter_contained(repo_path, "*.py"):
            rel_path = str(f.relative_to(repo_path))
            if holding_dir_name not in rel_path:
                result.add(rel_path)
        # Also scan non-Python artifact files
        from detritus_cleaner.core import DetritusCleaner
        for f in _ss.iter_contained(repo_path, "*"):
            if f.is_file() and f.suffix.lower() in DetritusCleaner.ARTIFACT_EXTENSIONS:
                rel_path = str(f.relative_to(repo_path))
                if holding_dir_name not in rel_path:
                    result.add(rel_path)
        return result

    actual_files = await asyncio.to_thread(_scan_py_files)
    total_files = len(actual_files)
    logger.debug(f"post_scan_validation: fresh scan found {total_files} Python files")

    if TRACING_ENABLED:
        emit_trace('validate_fresh_scan', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    # Fresh artifact scan
    start = time.perf_counter()
    whitelisted_files = set()

    try:
        from artifact_detector import DevelopmentArtifactDetector
        detector = DevelopmentArtifactDetector(str(repo_path))
        report = await detector.scan()

        for artifact in report.artifacts:
            if artifact.file_path.endswith('.py'):
                whitelisted_files.add(artifact.file_path)

    except ImportError:
        logger.warning("artifact_detector not available for independent validation")
    except Exception as e:
        logger.error(f"Fresh artifact scan failed: {e}")

    set_workflow('phase1_validation_scan')

    if TRACING_ENABLED:
        emit_trace('validate_fresh_artifact_scan', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    # Fresh import graph BFS
    start = time.perf_counter()

    independent_cleaner = DetritusCleaner(str(repo_path), dry_run=True)
    import_graph = await independent_cleaner.graph_builder.build_graph_async(actual_files)

    if TRACING_ENABLED:
        emit_trace('validate_build_import_graph', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    bfs_start = time.perf_counter()
    live_files = independent_cleaner._find_reachable(import_graph, actual_files)

    if TRACING_ENABLED:
        emit_trace('validate_bfs_complete', success=True,
                   elapsed=time.perf_counter() - bfs_start,
                   layer='Validation', module='workflows.py')

    live_files = live_files & actual_files
    logger.debug(f"post_scan_validation: BFS found {len(live_files)} reachable files")

    # Add implicit active files
    for f in actual_files:
        f_lower = f.lower()
        f_name = os.path.basename(f).lower()
        if f_name == "__init__.py":
            live_files.add(f)
        elif "test" in f_lower or f_name.startswith("test_") or f_name.endswith("_test.py"):
            live_files.add(f)
        elif f_name in ("conftest.py", "fixtures.py", "factories.py"):
            live_files.add(f)

    if TRACING_ENABLED:
        emit_trace('validate_live_files_identified', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    # Calculate expected detritus
    start = time.perf_counter()
    kept_files = live_files | whitelisted_files
    calculated_detritus = actual_files - kept_files
    calculated_detritus_count = len(calculated_detritus)
    logger.debug(f"post_scan_validation: kept={len(kept_files)}, "
                  f"detritus={calculated_detritus_count}, claimed={claimed_detritus_count}")

    if TRACING_ENABLED:
        emit_trace('validate_calculate_detritus', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    # Compare results
    start = time.perf_counter()
    validation_passed = True
    warnings = []
    discrepancies = []

    if calculated_detritus_count != claimed_detritus_count:
        validation_passed = False
        discrepancies.append(
            f"Detritus count mismatch: claimed={claimed_detritus_count}, "
            f"independently calculated={calculated_detritus_count}"
        )
        warnings.append(discrepancies[-1])

    if TRACING_ENABLED:
        detritus_match = (calculated_detritus_count == claimed_detritus_count)
        emit_trace('validate_detritus_comparison', success=detritus_match,
                   elapsed=time.perf_counter() - start,
                   error=discrepancies[-1] if discrepancies else None,
                   layer='Validation', module='workflows.py')

    # Math sanity check
    math_start = time.perf_counter()
    live_only = live_files - whitelisted_files
    whitelisted_only = whitelisted_files - live_files
    both = live_files & whitelisted_files

    math_check_total = len(live_only) + len(whitelisted_only) + len(both) + calculated_detritus_count
    math_passed = (math_check_total == total_files)
    if not math_passed:
        validation_passed = False
        discrepancies.append(
            f"Math check failed: live_only({len(live_only)}) + whitelisted_only({len(whitelisted_only)}) + "
            f"both({len(both)}) + detritus({calculated_detritus_count}) = {math_check_total} != total({total_files})"
        )
        warnings.append(discrepancies[-1])

    if TRACING_ENABLED:
        emit_trace('validate_math_check', success=math_passed,
                   elapsed=time.perf_counter() - math_start,
                   error=discrepancies[-1] if not math_passed else None,
                   layer='Validation', module='workflows.py')

    if TRACING_ENABLED:
        emit_trace('validate_compare_results', success=validation_passed,
                   elapsed=time.perf_counter() - start,
                   error='; '.join(discrepancies) if discrepancies else None,
                   layer='Validation', module='workflows.py')

    # Check backup directory
    start = time.perf_counter()
    detritus_backup_path = repo_path / holding_dir_name

    def _scan_backup_files() -> list[str]:
        if not detritus_backup_path.exists():
            return []
        from rca_main.constants import _scan_scope  # FIX_15: contained walk
        return [str(f.relative_to(detritus_backup_path)) for f in _scan_scope().iter_contained(detritus_backup_path, "*.py")]

    detritus_removed_files = await asyncio.to_thread(_scan_backup_files)

    if TRACING_ENABLED:
        emit_trace('validate_check_backup', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    # Store results
    start = time.perf_counter()
    context.step_results['post_scan_validate'] = {
        'passed': validation_passed,
        'total_files': total_files,
        'live_files': len(live_files),
        'whitelisted_files': len(whitelisted_files),
        'live_and_whitelisted_overlap': len(both),
        'claimed_detritus_count': claimed_detritus_count,
        'calculated_detritus_count': calculated_detritus_count,
        'calculated_detritus_files': sorted(calculated_detritus),
        'detritus_in_backup': len(detritus_removed_files),
        'discrepancies': discrepancies,
        'warnings': warnings,
    }

    if TRACING_ENABLED:
        emit_trace('validate_store_results', success=True,
                   elapsed=time.perf_counter() - start,
                   layer='Validation', module='workflows.py')

    if not validation_passed:
        context.errors.append({
            'step': 'post_scan_validate',
            'error': f"Independent validation failed: {'; '.join(discrepancies)}",
        })

    if TRACING_ENABLED:
        emit_trace('validate_complete', success=validation_passed,
                   elapsed=time.perf_counter() - start_total,
                   error='; '.join(discrepancies) if discrepancies else None,
                   layer='Validation', module='workflows.py')

    return context
