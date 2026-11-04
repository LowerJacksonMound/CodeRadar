"""
OriginTracer - Runtime Error Tracing with Natural Walls

Implements the "Attribute to Caller" algorithm for root cause analysis.
Instead of artificial depth limits, traces stop at Natural Walls:

1. Logical Wall: Function crashes without calling dependencies
   → This function IS the root cause

2. Permission Wall: Hits vendor/stdlib code we can't modify
   → Attribution reverts to caller (for sending bad data)

3. Cyclic Wall: Circular dependency detected
   → The architecture itself is the error

The tracer captures:
- Full call stack at crash time
- Input arguments to each function
- The exact exception and location
- Which function is the "Root Cause"
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

import aiofiles
import aiofiles.os

logger = logging.getLogger(__name__)

_F = TypeVar('_F', bound=Callable[..., Any])

# Flow tracing integration
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class StackFrame:
    """A single frame in the attribution trace."""
    function_name: str
    qualified_name: str          # module.class.method
    file_path: str
    line_number: int
    arguments: Dict[str, Any]    # Captured args (serializable subset)
    local_vars: Dict[str, Any]   # Local vars at crash (serializable subset)
    is_vendor: bool = False      # True if stdlib/third-party
    is_entry: bool = False       # True if this was the entry point

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function": self.function_name,
            "qualified_name": self.qualified_name,
            "file": self.file_path,
            "line": self.line_number,
            "args": self._safe_serialize(self.arguments),
            "locals": self._safe_serialize(self.local_vars),
            "is_vendor": self.is_vendor,
            "is_entry": self.is_entry,
        }

    def _safe_serialize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Safely serialize data for JSON."""
        result = {}
        for k, v in data.items():
            try:
                json.dumps(v)  # Test if serializable
                result[k] = v
            except (TypeError, ValueError):
                result[k] = repr(v)[:200]  # Truncate repr
        return result


@dataclass
class CrashArtifact:
    """
    Complete crash artifact for repair agent consumption.

    Contains everything needed to understand and fix the crash.
    """
    # Timing
    timestamp: str = ""

    # The root cause
    root_cause_function: str = ""
    root_cause_file: str = ""
    root_cause_line: int = 0
    wall_type: str = ""              # "logical", "permission", "cyclic"

    # The error
    exception_type: str = ""
    exception_message: str = ""
    exception_traceback: str = ""

    # The attribution chain
    origin_chain: List[StackFrame] = field(default_factory=list)

    # Input that caused the crash
    failing_input: Dict[str, Any] = field(default_factory=dict)

    # Related pieces (for cross-referencing with BreakpointScanner)
    piece_id: str = ""               # Matched LogicalPiece ID
    upstream_pieces: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "root_cause": {
                "function": self.root_cause_function,
                "file": self.root_cause_file,
                "line": self.root_cause_line,
                "wall_type": self.wall_type,
            },
            "exception": {
                "type": self.exception_type,
                "message": self.exception_message,
                "traceback": self.exception_traceback,
            },
            "origin_chain": [f.to_dict() for f in self.origin_chain],
            "failing_input": self.failing_input,
            "piece_id": self.piece_id,
            "upstream_pieces": self.upstream_pieces,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# =============================================================================
# TRACE CONTEXT
# =============================================================================

class TraceContext:
    """
    Manages the trace state during execution.

    Implements the "Attribute to Caller" algorithm:
    - Tracks the call stack
    - Detects cycles
    - Identifies root cause on crash
    """

    # Standard library modules (Permission Wall)
    VENDOR_PREFIXES = {
        'builtins', 'os', 'sys', 'json', 're', 'io', 'time', 'datetime',
        'collections', 'itertools', 'functools', 'typing', 'pathlib',
        'logging', 'unittest', 'asyncio', 'threading', 'subprocess',
        'shutil', 'tempfile', 'hashlib', 'base64', 'random', 'uuid',
        'copy', 'pickle', 'csv', 'configparser', 'abc', 'contextlib',
        'dataclasses', 'enum', 'traceback', 'math', 'statistics',
        'numpy', 'pandas', 'requests', 'flask', 'django', 'fastapi',
        'sqlalchemy', 'pydantic', 'pytest', 'sklearn', 'tensorflow',
        'torch', 'scipy', 'matplotlib',
    }

    def __init__(self) -> None:
        self.stack: List[StackFrame] = []
        self.root_cause_found = False
        self.crash_artifact: Optional[CrashArtifact] = None
        self._seen_functions: Set[str] = set()

    def reset(self) -> None:
        """Reset the context for a new trace."""
        self.stack = []
        self.root_cause_found = False
        self.crash_artifact = None
        self._seen_functions = set()

    @trace
    def enter(
        self,
        func_name: str,
        qualified_name: str,
        file_path: str,
        args: Dict[str, Any]
    ) -> None:
        """Record entering a function."""
        # Check for Cyclic Wall
        if qualified_name in self._seen_functions:
            # Cycle detected - but we still allow entry for now
            logger.debug(f"Potential cycle at {qualified_name}")

        self._seen_functions.add(qualified_name)

        # Determine if this is vendor code
        is_vendor = self._is_vendor_code(file_path, qualified_name)

        frame = StackFrame(
            function_name=func_name,
            qualified_name=qualified_name,
            file_path=file_path,
            line_number=0,  # Updated on exit/crash
            arguments=args,
            local_vars={},
            is_vendor=is_vendor,
            is_entry=len(self.stack) == 0,
        )

        self.stack.append(frame)
        logger.debug(f" -> Entering {qualified_name}")

    def exit(self, func_name: str, result: Any) -> None:
        """Record exiting a function normally."""
        if self.stack and self.stack[-1].function_name == func_name:
            frame = self.stack.pop()
            self._seen_functions.discard(frame.qualified_name)
            logger.debug(f" <- Exiting {func_name}")

    @trace
    def report_crash(
        self,
        func_name: str,
        exception: Exception,
        line_number: int,
        local_vars: Dict[str, Any]
    ) -> CrashArtifact:
        """
        Report a crash and determine root cause.

        Implements the Natural Wall detection logic.
        """
        logger.debug(f" !! CRASH in {func_name}: {exception}")

        # Update the current frame with crash info
        if self.stack:
            self.stack[-1].line_number = line_number
            self.stack[-1].local_vars = local_vars

        # Determine wall type
        wall_type = self._determine_wall_type(func_name, exception)

        # Find root cause
        root_frame = self._find_root_cause(wall_type)

        # Build crash artifact
        self.crash_artifact = CrashArtifact(
            timestamp=datetime.now().isoformat(),
            root_cause_function=root_frame.function_name if root_frame else func_name,
            root_cause_file=root_frame.file_path if root_frame else "",
            root_cause_line=root_frame.line_number if root_frame else line_number,
            wall_type=wall_type,
            exception_type=type(exception).__name__,
            exception_message=str(exception),
            exception_traceback=traceback.format_exc(),
            origin_chain=list(self.stack),
            failing_input=self.stack[0].arguments if self.stack else {},
        )

        self.root_cause_found = True
        logger.info(f" *** ROOT CAUSE: {self.crash_artifact.root_cause_function} ({wall_type} wall) ***")

        return self.crash_artifact

    def _is_vendor_code(self, file_path: str, qualified_name: str) -> bool:
        """Check if code is vendor/stdlib (Permission Wall)."""
        # Check file path
        if 'site-packages' in file_path:
            return True
        if file_path.startswith('/usr/lib') or file_path.startswith('/lib'):
            return True

        # Check module name
        module_root = qualified_name.split('.')[0] if qualified_name else ""
        if module_root in self.VENDOR_PREFIXES:
            return True

        return False

    def _determine_wall_type(self, func_name: str, exception: Exception) -> str:
        """Determine which Natural Wall was hit."""
        if not self.stack:
            return "logical"

        current_frame = self.stack[-1]

        # Check for Cyclic Wall (use qualified_name to avoid false positives)
        qualified_names = [f.qualified_name for f in self.stack]
        current_qualified = self.stack[-1].qualified_name
        occurrences = sum(1 for qn in qualified_names if qn == current_qualified)
        if occurrences > 1:
            return "cyclic"

        # Check for Permission Wall
        if current_frame.is_vendor:
            return "permission"

        # Check if exception came from a vendor call
        tb = traceback.extract_tb(sys.exc_info()[2])
        for frame in tb:
            if 'site-packages' in frame.filename:
                return "permission"

        # Default: Logical Wall
        return "logical"

    def _find_root_cause(self, wall_type: str) -> Optional[StackFrame]:
        """Find the root cause frame based on wall type."""
        if not self.stack:
            return None

        if wall_type == "logical":
            # Logical Wall: The current function IS the root cause
            return self.stack[-1]

        elif wall_type == "permission":
            # Permission Wall: Attribution reverts to the last non-vendor frame
            for frame in reversed(self.stack):
                if not frame.is_vendor:
                    return frame
            return self.stack[-1]

        elif wall_type == "cyclic":
            # Cyclic Wall: The first occurrence of the cycle is the root
            seen = set()
            for frame in self.stack:
                if frame.qualified_name in seen:
                    return frame
                seen.add(frame.qualified_name)
            return self.stack[-1]

        return self.stack[-1]


# =============================================================================
# TRACE DECORATOR
# =============================================================================

# Global tracer instance
_tracer = TraceContext()


def get_tracer() -> TraceContext:
    """Get the global tracer instance."""
    return _tracer


def reset_tracer() -> None:
    """Reset the global tracer."""
    _tracer.reset()


def trace_me(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to trace function execution for origin analysis.

    Wraps a function to:
    1. Record entry with arguments
    2. Record exit with result
    3. Capture crash state on exception
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Build qualified name
        module = func.__module__ or ""
        qual_name = func.__qualname__ or func.__name__
        qualified_name = f"{module}.{qual_name}" if module else qual_name

        # Get file path
        try:
            file_path = func.__code__.co_filename
        except AttributeError:
            file_path = "<unknown>"

        # Capture arguments
        arg_names = func.__code__.co_varnames[:func.__code__.co_argcount]
        captured_args = {}
        for i, name in enumerate(arg_names):
            if i < len(args):
                captured_args[name] = args[i]
        captured_args.update(kwargs)

        # Enter trace
        _tracer.enter(func.__name__, qualified_name, file_path, captured_args)

        try:
            result = func(*args, **kwargs)
            _tracer.exit(func.__name__, result)
            return result

        except Exception as e:
            # Capture local vars (best effort)
            local_vars = {}
            frame = sys._getframe(0)
            if frame:
                local_vars = {
                    k: v for k, v in frame.f_locals.items()
                    if not k.startswith('_')
                }

            # Get line number from traceback
            tb = sys.exc_info()[2]
            line_number = tb.tb_lineno if tb else 0

            # Report crash
            _tracer.report_crash(func.__name__, e, line_number, local_vars)

            # Re-raise to let caller handle
            raise

    return wrapper


def trace_class(cls: type) -> type:
    """
    Class decorator to trace all methods.

    Applies @trace_me to all non-dunder methods.
    """
    for name, method in cls.__dict__.items():
        if callable(method) and not name.startswith('_'):
            setattr(cls, name, trace_me(method))
    return cls


# =============================================================================
# CRASH ARTIFACT PERSISTENCE
# =============================================================================

class CrashArtifactStore:
    """
    Persists crash artifacts for later analysis.

    Stores as JSON files for easy consumption by repair agents.
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @trace
    async def save(self, artifact: CrashArtifact) -> str:
        """
        Save a crash artifact to disk.

        Returns:
            Path to the saved artifact file
        """
        logger.debug("save: saving crash artifact for %s", artifact.root_cause_function)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"crash_{timestamp}.json"
        filepath = self.output_dir / filename

        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            await f.write(artifact.to_json())

        logger.info(f"Saved crash artifact to {filepath}")
        return str(filepath)

    @trace
    async def load(self, filepath: str) -> CrashArtifact:
        """Load a crash artifact from disk."""
        logger.debug("load: loading crash artifact from %s", filepath)
        async with aiofiles.open(filepath, 'r', encoding='utf-8') as f:
            content = await f.read()
        data = json.loads(content)

        # Reconstruct the artifact
        artifact = CrashArtifact(
            timestamp=data.get('timestamp', ''),
            root_cause_function=data.get('root_cause', {}).get('function', ''),
            root_cause_file=data.get('root_cause', {}).get('file', ''),
            root_cause_line=data.get('root_cause', {}).get('line', 0),
            wall_type=data.get('root_cause', {}).get('wall_type', ''),
            exception_type=data.get('exception', {}).get('type', ''),
            exception_message=data.get('exception', {}).get('message', ''),
            exception_traceback=data.get('exception', {}).get('traceback', ''),
            failing_input=data.get('failing_input', {}),
            piece_id=data.get('piece_id', ''),
            upstream_pieces=data.get('upstream_pieces', []),
        )

        # Reconstruct attribution chain
        for frame_data in data.get('origin_chain', []):
            artifact.origin_chain.append(StackFrame(
                function_name=frame_data.get('function', ''),
                qualified_name=frame_data.get('qualified_name', ''),
                file_path=frame_data.get('file', ''),
                line_number=frame_data.get('line', 0),
                arguments=frame_data.get('args', {}),
                local_vars=frame_data.get('locals', {}),
                is_vendor=frame_data.get('is_vendor', False),
                is_entry=frame_data.get('is_entry', False),
            ))

        return artifact

    def get_recent_crashes(self, limit: int = 10) -> List[str]:
        """Get paths to recent crash artifacts (sync)."""
        artifacts = sorted(
            self.output_dir.glob("crash_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        return [str(p) for p in artifacts[:limit]]

    @trace
    async def get_recent_crashes_async(self, limit: int = 10) -> List[str]:
        """Async version: Get paths to recent crash artifacts."""
        logger.debug("get_recent_crashes_async: fetching up to %d recent crashes", limit)
        # Wrap sync glob + stat in to_thread
        def _get_sorted() -> List[Path]:
            return sorted(
                self.output_dir.glob("crash_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )

        artifacts = await asyncio.to_thread(_get_sorted)
        return [str(p) for p in artifacts[:limit]]


# =============================================================================
# INTEGRATION WITH BREAKPOINT SCANNER
# =============================================================================

def match_crash_to_piece(
    artifact: CrashArtifact,
    pieces: List[Any]  # LogicalPiece instances from breakpoint_scanner
) -> Optional[str]:
    """
    Match a crash artifact to a LogicalPiece.

    Returns the piece_id of the matching piece, or None.
    """
    # Try to find by file path and line number
    for piece in pieces:
        if piece.file_path == artifact.root_cause_file:
            if piece.line_start <= artifact.root_cause_line <= piece.line_end:
                artifact.piece_id = str(piece.get_id())
                return str(piece.get_id())

    # Try to find by function name
    for piece in pieces:
        if piece.name == artifact.root_cause_function:
            artifact.piece_id = str(piece.get_id())
            return str(piece.get_id())

    return None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_with_tracing(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Tuple[Any, Optional[CrashArtifact]]:
    """
    Run a function with tracing enabled.

    Returns:
        Tuple of (result or None, CrashArtifact or None)
    """
    reset_tracer()
    traced_func = trace_me(func)

    try:
        result = traced_func(*args, **kwargs)
        return result, None
    except Exception:
        return None, _tracer.crash_artifact


async def trace_and_save(
    func: Callable[..., Any],
    output_dir: str,
    *args: Any,
    **kwargs: Any
) -> Tuple[Any, Optional[str]]:
    """
    Run a function with tracing and save any crash artifact.

    Returns:
        Tuple of (result or None, artifact_path or None)
    """
    result, artifact = run_with_tracing(func, *args, **kwargs)

    if artifact:
        store = CrashArtifactStore(output_dir)
        artifact_path = await store.save(artifact)
        return None, artifact_path

    return result, None
