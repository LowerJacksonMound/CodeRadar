"""
PRE-SCAN RCA - Caller Map Builder
Builds a map of which functions call which other functions.
More granular than import graph - used for precise context_lines.
"""

import ast
import asyncio
import logging
import sys
import builtins
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

import aiofiles
import aiofiles.os

from rca_main.constants import live_py_files

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

# === FIX 1: Filter stdlib calls ===
# Common stdlib modules and builtins to filter out
STDLIB_MODULES = frozenset({
    # Builtins
    'print', 'len', 'range', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set',
    'tuple', 'type', 'isinstance', 'issubclass', 'hasattr', 'getattr', 'setattr',
    'delattr', 'callable', 'iter', 'next', 'enumerate', 'zip', 'map', 'filter',
    'sorted', 'reversed', 'min', 'max', 'sum', 'abs', 'round', 'pow', 'divmod',
    'all', 'any', 'open', 'input', 'repr', 'hash', 'id', 'dir', 'vars', 'globals',
    'locals', 'exec', 'eval', 'compile', 'format', 'ord', 'chr', 'bin', 'hex', 'oct',
    'super', 'property', 'staticmethod', 'classmethod', 'object', 'slice',
    'memoryview', 'bytearray', 'bytes', 'frozenset', 'complex',
    # Common stdlib functions/classes
    'Path', 'join', 'exists', 'read', 'write', 'append', 'extend', 'pop', 'remove',
    'insert', 'clear', 'copy', 'update', 'keys', 'values', 'items', 'get',
    'split', 'strip', 'replace', 'lower', 'upper', 'startswith', 'endswith',
    'find', 'index', 'count', 'encode', 'decode', 'format', 'join',
    # Logging
    'debug', 'info', 'warning', 'error', 'critical', 'exception',
    # Common patterns
    'resolve', 'relative_to', 'rglob', 'glob', 'mkdir', 'makedirs', 'rmdir',
    'read_text', 'read_bytes', 'write_text', 'write_bytes',
    # Exception handling
    'raise', 'Exception', 'ValueError', 'TypeError', 'KeyError', 'AttributeError',
    'IndexError', 'RuntimeError', 'IOError', 'OSError', 'FileNotFoundError',
    # Dataclass/typing
    'field', 'dataclass', 'Optional', 'List', 'Dict', 'Set', 'Tuple', 'Union',
    'Any', 'Callable', 'TypeVar', 'Generic', 'cast',
    # Async
    'sleep', 'gather', 'create_task', 'wait', 'wait_for',
})

# Add all actual builtins
STDLIB_MODULES = STDLIB_MODULES | set(dir(builtins))

# Prefixes that indicate stdlib/third-party module calls
STDLIB_PREFIXES = frozenset({
    'os.', 'sys.', 'json.', 'logging.', 'pathlib.', 'asyncio.',
    're.', 'time.', 'datetime.', 'collections.', 'itertools.',
    'functools.', 'typing.', 'dataclasses.', 'ast.', 'inspect.',
    'subprocess.', 'shutil.', 'tempfile.', 'io.', 'threading.',
    'multiprocessing.', 'concurrent.', 'urllib.', 'http.',
    'self.', 'cls.',  # instance/class method calls on self
})


@dataclass
class FunctionDef:
    """Information about a function definition"""
    name: str
    qualified_name: str  # module.class.function
    file_path: Path
    lineno: int
    end_lineno: int
    calls: list[str] = field(default_factory=list)  # Functions this calls
    is_method: bool = False
    class_name: Optional[str] = None
    # === FIX 4: Class inheritance tracking ===
    base_classes: list[str] = field(default_factory=list)  # For methods, what classes are inherited


@dataclass
class CallerInfo:
    """Who calls a function and from where"""
    caller: str  # qualified name of caller
    file_path: Path
    lineno: int
    is_cross_file: bool = False  # === FIX 3: Cross-file detection ===


class CallVisitor(ast.NodeVisitor):
    """AST visitor to extract function calls"""

    def __init__(self, filter_stdlib: bool = True):
        self.calls: list[str] = []
        self.filter_stdlib = filter_stdlib

    def _should_include(self, name: str, full_path: str | None = None) -> bool:
        """FIX 1: Filter out stdlib/builtin calls"""
        if not self.filter_stdlib:
            return True
        # Check simple name
        simple_name = name.split('.')[-1] if '.' in name else name
        if simple_name in STDLIB_MODULES:
            return False
        # Check full path against stdlib prefixes
        if full_path:
            for prefix in STDLIB_PREFIXES:
                if full_path.startswith(prefix):
                    return False
        return True

    def visit_Call(self, node: ast.Call) -> None:
        # Extract the function name being called
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if self._should_include(name):
                self.calls.append(name)
        elif isinstance(node.func, ast.Attribute):
            # Build full path first for better filtering
            parts: list[str] = []
            n: ast.expr = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)

            full_path = None
            if parts:
                parts.reverse()
                full_path = '.'.join(parts)

            # FIX: Only record ONE entry per call to avoid double-counting
            # Prefer full_path (obj.method) for better resolution, fallback to attr_name
            attr_name = node.func.attr
            if full_path and self._should_include(full_path, full_path):
                self.calls.append(full_path)
            elif self._should_include(attr_name, full_path):
                self.calls.append(attr_name)

        self.generic_visit(node)


class CallerMapBuilder:
    """
    Builds a map of function call relationships.

    Usage:
        builder = CallerMapBuilder(project_root)
        await builder.scan()

        # Who calls this function?
        callers = builder.get_callers("mission_tracker.record_event")

        # What does this function call?
        callees = builder.get_callees("repair_pipeline._execute_repairs")
    """

    def __init__(self, project_root: Path, filter_stdlib: bool = True, files=None):
        self.project_root = project_root.resolve()
        self.filter_stdlib = filter_stdlib
        # Owner 2026-09-05: when the caller hands over the whitelist-filtered file
        # list, the caller map is built from exactly those files — no own walk.
        self.files = list(files) if files is not None else None

        # qualified_name -> FunctionDef
        self.functions: dict[str, FunctionDef] = {}

        # function_name -> list of CallerInfo (reverse index)
        self.called_by: dict[str, list[CallerInfo]] = {}

        # Simple name -> list of qualified names (for resolution)
        self.name_to_qualified: dict[str, list[str]] = {}

        # === FIX 4: Class inheritance map ===
        # class_name -> list of base class names
        self.class_inheritance: dict[str, list[str]] = {}

    def _get_module_name(self, file_path: Path) -> str:
        """Convert file path to module name"""
        try:
            rel_path = file_path.relative_to(self.project_root)
            parts = list(rel_path.parts)
            if parts[-1].endswith('.py'):
                parts[-1] = parts[-1][:-3]
            if parts[-1] == '__init__':
                parts = parts[:-1]
            return '.'.join(parts) if parts else ''
        except ValueError:
            return file_path.stem

    def _extract_base_classes(self, node: ast.ClassDef) -> list[str]:
        """FIX 4: Extract base class names from a class definition"""
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                # module.Class -> just get "Class" or full path
                parts: list[str] = []
                n: ast.expr = base
                while isinstance(n, ast.Attribute):
                    parts.append(n.attr)
                    n = n.value
                if isinstance(n, ast.Name):
                    parts.append(n.id)
                parts.reverse()
                bases.append('.'.join(parts))
        return bases

    async def _extract_functions(self, file_path: Path) -> list[FunctionDef]:
        """Extract all function definitions from a file (async I/O)."""
        functions: list[FunctionDef] = []

        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source = await f.read()
            tree = ast.parse(source)
        except Exception as e:
            logger.debug(f"Could not parse {file_path}: {e}")
            return functions

        module_name = self._get_module_name(file_path)

        # FIX: Only iterate top-level nodes to avoid nested function double-counting
        # ast.walk() visits ALL nodes including nested functions - use tree.body instead
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name

                # === FIX 4: Track inheritance ===
                base_classes = self._extract_base_classes(node)
                qualified_class = f"{module_name}.{class_name}" if module_name else class_name
                self.class_inheritance[qualified_class] = base_classes

                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qualified = f"{module_name}.{class_name}.{item.name}" if module_name else f"{class_name}.{item.name}"

                        # Extract calls within this function (with stdlib filter)
                        visitor = CallVisitor(filter_stdlib=self.filter_stdlib)
                        visitor.visit(item)

                        func_def = FunctionDef(
                            name=item.name,
                            qualified_name=qualified,
                            file_path=file_path,
                            lineno=item.lineno,
                            end_lineno=item.end_lineno or item.lineno,
                            calls=visitor.calls,
                            is_method=True,
                            class_name=class_name,
                            base_classes=base_classes  # FIX 4
                        )
                        functions.append(func_def)

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Top-level function (not in a class)
                qualified = f"{module_name}.{node.name}" if module_name else node.name

                visitor = CallVisitor(filter_stdlib=self.filter_stdlib)
                visitor.visit(node)

                func_def = FunctionDef(
                    name=node.name,
                    qualified_name=qualified,
                    file_path=file_path,
                    lineno=node.lineno,
                    end_lineno=node.end_lineno or node.lineno,
                    calls=visitor.calls,
                    is_method=False
                )
                functions.append(func_def)

        return functions

    async def _extract_functions_async(self, file_path: Path) -> list[FunctionDef]:
        """Extract all function definitions from a file (async I/O).

        Delegates to _extract_functions which is now fully async.
        """
        return await self._extract_functions(file_path)

    @trace
    async def scan(self) -> int:
        """
        Scan all Python files and build caller map (async I/O).
        Returns number of functions found.
        """
        logger.debug("scan: starting caller map build for %s", self.project_root)
        # Collect files: the handed-over list, else the ONE walk (FIX_14; sync metadata, in a thread)
        py_files = await asyncio.to_thread(live_py_files, self.project_root, self.files)

        count = 0
        batch_size = 30
        for i in range(0, len(py_files), batch_size):
            batch = py_files[i:i + batch_size]
            results = await asyncio.gather(
                *[self._extract_functions(f) for f in batch],
                return_exceptions=True
            )
            for result in results:
                if isinstance(result, BaseException):
                    logger.debug(f"Error extracting functions: {result}")
                    continue
                for func in result:
                    self.functions[func.qualified_name] = func
                    if func.name not in self.name_to_qualified:
                        self.name_to_qualified[func.name] = []
                    self.name_to_qualified[func.name].append(func.qualified_name)
                    count += 1

        # Build reverse index (called_by)
        self._build_reverse_index()

        logger.info(f"Scanned {count} functions")
        return count

    @trace
    async def scan_async(self) -> int:
        """
        Async version: Scan all Python files and build caller map.

        Delegates to scan() which is now fully async.
        Returns number of functions found.
        """
        return await self.scan()

    def _build_reverse_index(self) -> None:
        """Build called_by reverse index - FIX 3: Only count cross-file calls"""
        self.called_by.clear()

        for qualified_name, func_def in self.functions.items():
            caller_file = func_def.file_path

            for called in func_def.calls:
                # Try to resolve the called function
                resolved_targets = []

                # First try exact match
                if called in self.functions:
                    resolved_targets.append(called)
                # Try simple name match
                elif called in self.name_to_qualified:
                    resolved_targets.extend(self.name_to_qualified[called])

                for resolved in resolved_targets:
                    target_func = self.functions.get(resolved)
                    if not target_func:
                        continue

                    # === FIX 3: Determine if cross-file ===
                    is_cross_file = target_func.file_path != caller_file

                    if resolved not in self.called_by:
                        self.called_by[resolved] = []

                    self.called_by[resolved].append(CallerInfo(
                        caller=qualified_name,
                        file_path=func_def.file_path,
                        lineno=func_def.lineno,
                        is_cross_file=is_cross_file
                    ))

    @trace
    def get_callers(self, function_name: str, cross_file_only: bool = False) -> list[CallerInfo]:
        """
        Get list of functions that call this function.

        Args:
            function_name: Name of function to look up
            cross_file_only: If True, only return cross-file callers (FIX 3)
        """
        logger.debug("get_callers: %s (cross_file_only=%s)", function_name, cross_file_only)
        callers = []

        # Try exact match
        if function_name in self.called_by:
            callers = self.called_by[function_name]
        else:
            # Try partial match
            for qualified, c in self.called_by.items():
                if qualified.endswith('.' + function_name) or qualified.endswith(function_name):
                    callers = c
                    break

        # === FIX 3: Filter to cross-file only if requested ===
        if cross_file_only:
            callers = [c for c in callers if c.is_cross_file]

        return callers

    def get_cross_file_caller_count(self, function_name: str) -> int:
        """FIX 3: Get count of unique cross-file callers"""
        callers = self.get_callers(function_name, cross_file_only=True)
        unique_files = set(c.file_path for c in callers)
        return len(unique_files)

    def get_callees(self, function_name: str) -> list[str]:
        """Get list of functions that this function calls"""
        # Try exact match
        if function_name in self.functions:
            return self.functions[function_name].calls

        # Try partial match
        for qualified, func_def in self.functions.items():
            if qualified.endswith('.' + function_name) or qualified.endswith(function_name):
                return func_def.calls

        return []

    @trace
    def get_call_depth(self, function_name: str, max_depth: Optional[int] = None) -> int:  # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): was 5 (a clamp)
        """
        Calculate call depth - how many unique callers.
        More callers = more "core" = needs more context.
        """
        logger.debug("get_call_depth: %s (max_depth=%d)", function_name, max_depth)
        callers = self.get_callers(function_name)
        unique_callers = set(c.caller for c in callers)
        return len(unique_callers) if max_depth is None else min(len(unique_callers), max_depth)

    def get_inherited_methods(self, class_name: str) -> list[str]:
        """FIX 4: Get methods that might be inherited from base classes"""
        inherited: list[str] = []

        # Find the class
        bases = None
        for qname, base_list in self.class_inheritance.items():
            if qname == class_name or qname.endswith('.' + class_name):
                bases = base_list
                break

        if not bases:
            return inherited

        # Find methods from base classes
        for base in bases:
            for qname, func_def in self.functions.items():
                if func_def.is_method and func_def.class_name:
                    if base == func_def.class_name or qname.startswith(base + '.'):
                        inherited.append(qname)

        return inherited

    def get_class_coupling(self, file_path: Path) -> int:
        """
        Get class coupling score for a file based on inheritance.
        Returns count of cross-file inheritance relationships.

        This measures how many classes in this file inherit from classes
        defined in OTHER files - indicating tight coupling.
        """
        coupling = 0
        file_path = file_path.resolve()

        # Build a map of class name -> file path for resolution
        class_files: dict[str, Path] = {}
        for qname, bases in self.class_inheritance.items():
            # Find the file for this class from any method
            for func_qname, func_def in self.functions.items():
                if func_def.is_method and func_qname.startswith(qname + '.'):
                    class_files[qname] = func_def.file_path
                    break

        # Check each class in the target file
        for qname, bases in self.class_inheritance.items():
            if qname not in class_files or class_files[qname] != file_path:
                continue

            # Check each base class
            for base in bases:
                # Try to find the base class file
                base_file = None
                # Exact match
                if base in class_files:
                    base_file = class_files[base]
                else:
                    # Partial match
                    for cname, cfile in class_files.items():
                        if cname.endswith('.' + base) or cname == base:
                            base_file = cfile
                            break

                # Count if base is in a different file
                if base_file and base_file != file_path:
                    coupling += 1

        return coupling

    @trace
    def get_function_complexity(self, function_name: str) -> dict[str, Any]:
        """
        Get complexity metrics for a function.
        Used to calculate context_lines.
        """
        logger.debug("get_function_complexity: %s", function_name)
        # Find the function
        func_def = None
        for qualified, fd in self.functions.items():
            if qualified == function_name or qualified.endswith('.' + function_name):
                func_def = fd
                break

        if not func_def:
            return {"callers": 0, "callees": 0, "lines": 0, "complexity": "unknown"}

        callers = self.get_callers(function_name)
        cross_file_callers = self.get_callers(function_name, cross_file_only=True)

        return {
            "callers": len(callers),
            "cross_file_callers": len(cross_file_callers),  # FIX 3
            "callees": len(func_def.calls),
            "lines": func_def.end_lineno - func_def.lineno + 1,
            "is_method": func_def.is_method,
            "base_classes": func_def.base_classes,  # FIX 4
            "complexity": self._calc_complexity(len(cross_file_callers), len(func_def.calls))
        }

    def _calc_complexity(self, callers: int, callees: int) -> str:
        """Simple complexity rating"""
        total = callers + callees
        if total < 3:
            return "low"
        elif total < 8:
            return "medium"
        else:
            return "high"


# === CLI ===

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 2:
        print("Usage: python caller_map.py /path/to/project [function_name]")
        sys.exit(1)

    async def _cli_main() -> None:
        project_root = Path(sys.argv[1]).resolve()

        builder = CallerMapBuilder(project_root)
        count = await builder.scan()

        print(f"\nProject: {project_root}")
        print(f"Functions found: {count}")

        if len(sys.argv) > 2:
            func_name = sys.argv[2]
            print(f"\n{'='*50}")
            print(f"Function: {func_name}")
            print(f"{'='*50}")

            callers = builder.get_callers(func_name)
            cross_file = builder.get_callers(func_name, cross_file_only=True)
            print(f"\nCalled by ({len(callers)} total, {len(cross_file)} cross-file):")
            for c in callers[:10]:
                marker = "[X]" if c.is_cross_file else "[S]"
                print(f"  {marker} ← {c.caller} (line {c.lineno})")

            callees = builder.get_callees(func_name)
            print(f"\nCalls ({len(callees)}):")
            for callee in callees[:10]:
                print(f"  → {callee}")

            complexity = builder.get_function_complexity(func_name)
            print(f"\nComplexity: {complexity}")

        else:
            # Show most called functions (cross-file only for accuracy)
            print(f"\n{'='*50}")
            print("Most called functions (cross-file calls only):")
            print(f"{'='*50}")

            sorted_funcs = sorted(
                builder.called_by.items(),
                key=lambda x: len([c for c in x[1] if c.is_cross_file]),
                reverse=True
            )

            for fn_name, fn_callers in sorted_funcs[:15]:
                num_cross_file = len([ci for ci in fn_callers if ci.is_cross_file])
                total = len(fn_callers)
                print(f"  {num_cross_file:3d}/{total:3d} calls  {fn_name}")

    asyncio.run(_cli_main())
