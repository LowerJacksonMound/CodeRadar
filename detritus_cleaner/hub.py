"""
DetritusHub — Single-wire aggregation point for all detritus cleaner I/O.

The orchestrator creates ONE hub, registers ONE event callback, and calls
operations. Every operation returns a uniform HubResult envelope.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, TYPE_CHECKING

from detritus_cleaner.models import (
    DetritusConfig,
    CleanseResult,
    DetritusCleanerError,
    ValidationError,
    ProgressCallback,
)
from detritus_cleaner.core import DetritusCleaner
from detritus_cleaner.workflows import run_pre_game_optimization, validate_cleaning
from detritus_cleaner.utils import logger, TRACING_ENABLED, emit_trace, set_workflow

if TYPE_CHECKING:
    try:
        from executor import WorkflowContext
    except ImportError:
        from typing import Any as WorkflowContext


__all__ = [
    'DetritusHub',
    'HubResult',
    'HubEvent',
    'HubEventType',
    'HubOperation',
    'HubEventCallback',
]


# =============================================================================
# Enums
# =============================================================================

class HubOperation(Enum):
    """All operations the hub exposes."""
    SCAN = "scan"
    CLEAN = "clean"
    RESTORE = "restore"
    VALIDATE = "validate"
    OPTIMIZE = "optimize"
    LIST_HELD = "list_held"
    GET_GRAPH = "get_graph"
    GET_CIRCULAR_IMPORTS = "get_circular_imports"


class HubEventType(Enum):
    """Event types the hub emits."""
    PROGRESS = "progress"
    OPERATION_START = "op_start"
    OPERATION_END = "op_end"
    WARNING = "warning"
    ERROR = "error"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class HubEvent:
    """Single event emitted by the hub to the orchestrator."""
    event_type: HubEventType
    operation: HubOperation
    timestamp: float = field(default_factory=time.time)
    current: int = 0
    total: int = 0
    message: str = ""
    data: Optional[Dict[str, Any]] = None


class HubEventCallback(Protocol):
    """The SINGLE callback the orchestrator registers for all events."""
    def __call__(self, event: HubEvent) -> None: ...


@dataclass
class HubResult:
    """Uniform envelope for ALL hub operation results."""
    operation: HubOperation
    success: bool
    duration_seconds: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    cleanse_result: Optional[CleanseResult] = None


# =============================================================================
# Hub
# =============================================================================

class DetritusHub:
    """
    Single aggregation point for all detritus cleaner operations.

    Usage::

        hub = DetritusHub("/path/to/repo", dry_run=True)
        hub.set_event_callback(my_callback)

        result = await hub.scan()
        result = await hub.clean()
        result = await hub.validate()
    """

    def __init__(
        self,
        repo_path: str | Path,
        *,
        dry_run: bool = False,
        config: Optional[DetritusConfig] = None,
        event_callback: Optional[HubEventCallback] = None,
    ):
        if config is not None:
            self._config = config
        else:
            self._config = DetritusConfig(
                repo_path=Path(repo_path).resolve(),
                dry_run=dry_run,
            )

        self._event_callback = event_callback
        self._cleaner = DetritusCleaner(self._config)
        self._last_scan_result: Optional[CleanseResult] = None

    # ----- Single connection point -----

    def set_event_callback(self, callback: HubEventCallback) -> None:
        """Register (or replace) the single event callback."""
        self._event_callback = callback

    # ----- Properties -----

    @property
    def config(self) -> DetritusConfig:
        return self._config

    @property
    def last_scan_result(self) -> Optional[CleanseResult]:
        return self._last_scan_result

    @property
    def repo_path(self) -> Path:
        return Path(self._config.repo_path)

    # ----- Internal plumbing -----

    def _emit(self, event: HubEvent) -> None:
        if self._event_callback is not None:
            self._event_callback(event)

    def _make_progress_callback(self, operation: HubOperation) -> ProgressCallback:
        """Wrap the hub's single event callback into the ProgressCallback
        protocol that internal modules expect."""
        def _progress(current: int, total: int, message: str) -> None:
            self._emit(HubEvent(
                event_type=HubEventType.PROGRESS,
                operation=operation,
                current=current,
                total=total,
                message=message,
            ))
        return _progress

    async def _execute(
        self,
        operation: HubOperation,
        coro_factory: Callable[..., Any],
    ) -> HubResult:
        """Standard execution wrapper: emit start, run, emit end, catch errors,
        return uniform HubResult."""
        start = time.time()

        self._emit(HubEvent(
            event_type=HubEventType.OPERATION_START,
            operation=operation,
        ))

        if TRACING_ENABLED:
            set_workflow(f'hub_{operation.value}')
            emit_trace(f'hub_{operation.value}_start', success=True, elapsed=0,
                       layer='Hub', module='hub.py')

        progress_cb = self._make_progress_callback(operation)
        result = HubResult(operation=operation, success=False)

        try:
            data, cleanse_result = await coro_factory(progress_cb)
            result.success = True
            result.data = data
            result.cleanse_result = cleanse_result
        except asyncio.CancelledError:
            # Allow cancellation to propagate - don't swallow it
            result.errors.append("Operation cancelled")
            self._emit(HubEvent(
                event_type=HubEventType.ERROR,
                operation=operation,
                message="Operation cancelled",
            ))
            raise
        except DetritusCleanerError as e:
            result.errors.append(f"{type(e).__name__}: {e}")
            self._emit(HubEvent(
                event_type=HubEventType.ERROR,
                operation=operation,
                message=str(e),
            ))
        except (FileNotFoundError, PermissionError) as e:
            result.errors.append(f"{type(e).__name__}: {e}")
            self._emit(HubEvent(
                event_type=HubEventType.ERROR,
                operation=operation,
                message=str(e),
            ))
        except Exception as e:
            result.errors.append(f"Unexpected {type(e).__name__}: {e}")
            self._emit(HubEvent(
                event_type=HubEventType.ERROR,
                operation=operation,
                message=str(e),
            ))
        finally:
            result.duration_seconds = time.time() - start

            if TRACING_ENABLED:
                emit_trace(
                    f'hub_{operation.value}_complete',
                    success=result.success,
                    elapsed=result.duration_seconds,
                    error='; '.join(result.errors) if result.errors else None,
                    layer='Hub', module='hub.py',
                )

            self._emit(HubEvent(
                event_type=HubEventType.OPERATION_END,
                operation=operation,
                data={"success": result.success, "duration": result.duration_seconds},
            ))

        return result

    # =====================================================================
    # Public operations — all async, all return HubResult
    # =====================================================================

    async def scan(self) -> HubResult:
        """Analyze repository — identify live vs detritus files."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            cr = await self._cleaner.scan(progress_callback=progress_cb)
            self._last_scan_result = cr
            return cr.summary(), cr

        return await self._execute(HubOperation.SCAN, _run)

    async def clean(self, rescan: bool = False) -> HubResult:
        """Scan (if needed) and holding detritus files.
        Uses cached scan result unless rescan=True."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            scan_input = None if rescan else self._last_scan_result
            cr = await self._cleaner.clean_async(
                result=scan_input,
                progress_callback=progress_cb,
            )
            self._last_scan_result = cr
            return cr.summary(), cr

        return await self._execute(HubOperation.CLEAN, _run)

    async def restore(self) -> HubResult:
        """Restore all holdingd files."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            restored, failed = await self._cleaner.restore_held(
                progress_callback=progress_cb,
            )
            data = {
                "restored_count": len(restored),
                "restored_files": restored,
                "failed_count": len(failed),
                "failed_files": [{"path": p, "reason": r} for p, r in failed],
            }
            return data, None

        return await self._execute(HubOperation.RESTORE, _run)

    async def validate(self) -> HubResult:
        """Run independent validation of the last cleaning result.
        Requires a prior scan() or clean() call."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            if self._last_scan_result is None:
                raise ValidationError(
                    "No prior scan/clean result to validate against. "
                    "Run scan() or clean() first."
                )
            report = await validate_cleaning(
                self._config.repo_path,
                self._last_scan_result,
                self._config,
            )
            return report, None

        return await self._execute(HubOperation.VALIDATE, _run)

    async def optimize(self, skip_cleanup: bool = False) -> HubResult:
        """High-level optimization workflow (wraps run_pre_game_optimization)."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            report = await run_pre_game_optimization(
                str(self._config.repo_path),
                skip_cleanup=skip_cleanup,
                dry_run=self._config.dry_run,
                progress_callback=progress_cb,
            )
            return report, None

        return await self._execute(HubOperation.OPTIMIZE, _run)

    async def list_held(self) -> HubResult:
        """List all files currently in holding."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            items = await self._cleaner.holding_mgr.list_held()
            data = {
                "holdingd_count": len(items),
                "files": items,
            }
            return data, None

        return await self._execute(HubOperation.LIST_HELD, _run)

    async def get_import_graph(self) -> HubResult:
        """Build and return the import dependency graph."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            py_files = await self._cleaner._discover_python_files()
            graph = await self._cleaner.graph_builder.build_graph_async(
                py_files,
                self._config.max_concurrent_tasks,
                progress_cb,
            )
            serializable = {k: sorted(v) for k, v in graph.items()}
            data = {
                "node_count": len(serializable),
                "edge_count": sum(len(v) for v in graph.values()),
                "graph": serializable,
            }
            return data, None

        return await self._execute(HubOperation.GET_GRAPH, _run)

    async def get_circular_imports(self) -> HubResult:
        """Return detected circular imports.
        Requires get_import_graph() or scan() to have been run first."""
        async def _run(progress_cb: ProgressCallback) -> Tuple[Dict[str, Any], Optional[CleanseResult]]:
            cycles = self._cleaner.graph_builder.get_circular_imports()
            data = {
                "cycle_count": len(cycles),
                "cycles": [list(c) for c in cycles],
            }
            return data, None

        return await self._execute(HubOperation.GET_CIRCULAR_IMPORTS, _run)

    # =====================================================================
    # WorkflowContext bridge
    # =====================================================================

    async def execute_workflow_step(
        self,
        step_name: str,
        context: 'WorkflowContext',
    ) -> 'WorkflowContext':
        """Bridge for orchestrators that use WorkflowContext.
        Routes to the appropriate workflow handler by step_name."""
        from detritus_cleaner.workflows import clean as wf_clean, post_scan_validation_handler

        handlers = {
            'detritus_clean': wf_clean,
            'post_scan_validate': post_scan_validation_handler,
        }
        handler = handlers.get(step_name)
        if handler is None:
            raise ValueError(f"Unknown workflow step: {step_name}")

        op = HubOperation.CLEAN if step_name == 'detritus_clean' else HubOperation.VALIDATE

        self._emit(HubEvent(
            event_type=HubEventType.OPERATION_START,
            operation=op,
            message=f"workflow_step:{step_name}",
        ))

        start = time.time()
        try:
            result_context = await handler(context)
        finally:
            self._emit(HubEvent(
                event_type=HubEventType.OPERATION_END,
                operation=op,
                data={
                    "step": step_name,
                    "duration": time.time() - start,
                    "result": context.step_results.get(step_name, {}),
                },
            ))

        return result_context
