"""Import graph builder for dependency analysis."""

from __future__ import annotations

import ast
import asyncio
import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, Set, List, Tuple, Optional

from detritus_cleaner.models import ProgressCallback
from detritus_cleaner.utils import logger, TRACING_ENABLED, emit_trace


__all__ = ['ImportGraphBuilder']


class ImportGraphBuilder:
    """
    Builds dependency graph by parsing Python imports.
    Handles relative imports, package structures, and detects circular imports.
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.module_to_file: Dict[str, str] = {}
        self.import_graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_graph: Dict[str, Set[str]] = defaultdict(set)
        self._circular_imports: List[Tuple[str, ...]] = []

    def build_module_map(self, py_files: Set[str]) -> None:
        """
        Map Python module names (dot notation) to file paths.
        Handles __init__.py packages and common src/ layouts.
        """
        logger.debug(f"build_module_map: processing {len(py_files)} files")
        for rel_path in py_files:
            # Handle __init__.py packages
            if rel_path.endswith("__init__.py"):
                parent = Path(rel_path).parent
                if str(parent) == ".":
                    # Root __init__.py has no valid module name - skip
                    continue
                module_name = str(parent).replace(os.sep, ".")
            else:
                module_name = str(Path(rel_path).with_suffix("")).replace(os.sep, ".")

            self.module_to_file[module_name] = rel_path

            # Heuristics for src/ and lib/ layouts
            if module_name.startswith("src."):
                self.module_to_file[module_name[4:]] = rel_path
                logger.debug(f"build_module_map: aliased src-stripped {module_name[4:]} -> {rel_path}")
            elif module_name.startswith("lib."):
                self.module_to_file[module_name[4:]] = rel_path
                logger.debug(f"build_module_map: aliased lib-stripped {module_name[4:]} -> {rel_path}")

        # 2026-09-29 (flowapp2): a repo whose ROOT is itself a package (root __init__.py) imports its own
        # modules by the root folder's name — `from flowapp2.core.flow import Flow`, with the parent dir on
        # sys.path. Every module is also mapped under that qualified name, and the bare name to the root
        # marker; before this those imports resolved to nothing and every real module read unreachable.
        if "__init__.py" in py_files:
            root_pkg = Path(self.repo_path).name
            if root_pkg.isidentifier():
                for mod, rel in list(self.module_to_file.items()):
                    self.module_to_file.setdefault(f"{root_pkg}.{mod}", rel)
                self.module_to_file.setdefault(root_pkg, "__init__.py")

        logger.debug(f"build_module_map: {len(self.module_to_file)} module entries created")

    def _register_sys_path_dirs(self, py_files: Set[str]) -> None:
        """
        Scan files for sys.path.insert/append/extend calls and register
        the targeted directories' modules in module_to_file.

        This allows the import graph to resolve imports that depend on
        runtime sys.path manipulation (e.g., sys.path.insert(0, "subdir")).
        """
        for rel_path in py_files:
            file_path = self.repo_path / rel_path
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if "sys.path" not in content:
                continue

            try:
                tree = ast.parse(content, filename=str(file_path))
            except SyntaxError:
                continue

            importer_dir = (self.repo_path / rel_path).parent

            for node in ast.walk(tree):
                # Match: sys.path.insert(0, X), sys.path.append(X), sys.path.extend([X])
                if not isinstance(node, ast.Expr):
                    continue
                call = node.value
                if not isinstance(call, ast.Call):
                    continue
                func = call.func
                if not (isinstance(func, ast.Attribute)
                        and func.attr in ("insert", "append", "extend")
                        and isinstance(func.value, ast.Attribute)
                        and func.value.attr == "path"
                        and isinstance(func.value.value, ast.Name)
                        and func.value.value.id == "sys"):
                    continue

                # Extract the directory argument
                dir_str = self._extract_sys_path_dir(call, func.attr, importer_dir)
                if not dir_str:
                    continue

                # Resolve relative to the repo root
                target = Path(dir_str)
                if not target.is_absolute():
                    target = importer_dir / target
                target = target.resolve()

                if not target.is_dir():
                    continue

                # Register Python files in that directory under their basename module name
                try:
                    for child in target.iterdir():
                        if child.is_symlink():
                            continue  # FIX_15: never through a symlink
                        if child.suffix == ".py" and child.is_file():
                            try:
                                child_rel = str(child.resolve().relative_to(self.repo_path))
                            except ValueError:
                                continue  # Outside repo
                            base_name = child.stem
                            if base_name == "__init__":
                                pkg_name = target.name
                                if pkg_name not in self.module_to_file:
                                    self.module_to_file[pkg_name] = child_rel
                                    logger.debug(f"sys.path register: {pkg_name} -> {child_rel}")
                            else:
                                if base_name not in self.module_to_file:
                                    self.module_to_file[base_name] = child_rel
                                    logger.debug(f"sys.path register: {base_name} -> {child_rel}")
                        elif child.is_dir() and (child / "__init__.py").exists():
                            # Register sub-packages
                            pkg_name = child.name
                            init_rel = str((child / "__init__.py").resolve().relative_to(self.repo_path))
                            if pkg_name not in self.module_to_file:
                                self.module_to_file[pkg_name] = init_rel
                                logger.debug(f"sys.path register pkg: {pkg_name} -> {init_rel}")
                except OSError:
                    continue

            logger.debug(f"sys.path scan: {len(self.module_to_file)} module entries after {rel_path}")

    @staticmethod
    def _extract_sys_path_dir(
        call: ast.Call, method: str, importer_dir: Path
    ) -> Optional[str]:
        """Extract the directory string from a sys.path manipulation call."""
        # Determine which arg holds the path
        if method == "insert" and len(call.args) >= 2:
            path_arg = call.args[1]
        elif method == "append" and len(call.args) >= 1:
            path_arg = call.args[0]
        elif method == "extend" and len(call.args) >= 1:
            # sys.path.extend([dir1, dir2]) — take the list elements
            if isinstance(call.args[0], ast.List) and call.args[0].elts:
                path_arg = call.args[0].elts[0]
            else:
                return None
        else:
            return None

        # Case 1: String literal — sys.path.insert(0, "/some/path")
        if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str):
            return path_arg.value

        # Case 2: os.path.join(base, "subdir") — very common pattern
        if (isinstance(path_arg, ast.Call)
                and isinstance(path_arg.func, ast.Attribute)
                and path_arg.func.attr == "join"
                and isinstance(path_arg.func.value, ast.Attribute)
                and path_arg.func.value.attr == "path"
                and isinstance(path_arg.func.value.value, ast.Name)
                and path_arg.func.value.value.id == "os"):
            # Try to resolve: os.path.join(base, "literal", ...)
            # We can only resolve if all args after the first are string literals
            # and the first arg is a "base dir" pattern we can infer
            string_parts = []
            for i, arg in enumerate(path_arg.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    string_parts.append(arg.value)
                elif i == 0:
                    # First arg is likely a variable like `base` — assume importer dir
                    string_parts.append(str(importer_dir))
                else:
                    return None  # Non-literal arg in the middle, can't resolve
            if string_parts:
                return os.path.join(*string_parts)

        # Case 3: bare variable (e.g., sys.path.insert(0, base)) — assume importer dir
        if isinstance(path_arg, ast.Name):
            return str(importer_dir)

        return None

    async def build_graph_async(
        self,
        py_files: Set[str],
        max_concurrent: int = 50,
        progress_callback: Optional[ProgressCallback] = None
    ) -> Dict[str, Set[str]]:
        """
        Build the import graph asynchronously with controlled concurrency.

        Args:
            py_files: Set of relative paths to Python files
            max_concurrent: Maximum concurrent file parsing operations
            progress_callback: Optional callback for progress updates

        Returns:
            Import graph mapping each file to its direct dependencies
        """
        import time as _time
        _graph_start = _time.perf_counter()

        logger.debug(f"build_graph_async: starting with {len(py_files)} files, "
                      f"max_concurrent={max_concurrent}")
        self.build_module_map(py_files)
        self._register_sys_path_dirs(py_files)

        sem = asyncio.Semaphore(max_concurrent)
        completed = 0
        total = len(py_files)

        async def process_file(rel_path: str) -> Tuple[str, Set[str]]:
            nonlocal completed
            async with sem:
                imports = await self._extract_imports_async(rel_path)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, f"Analyzing {rel_path}")
                return rel_path, imports

        tasks = [process_file(f) for f in py_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        _error_count = 0
        for result in results:
            if isinstance(result, BaseException):
                logger.error(f"Task failed: {result}")
                _error_count += 1
                continue
            rel_path, imports = result
            self.import_graph[rel_path] = imports
            # Build reverse graph for cycle detection
            for imported in imports:
                self.reverse_graph[imported].add(rel_path)

        _edge_count = sum(len(v) for v in self.import_graph.values())
        logger.debug(f"build_graph_async: graph has {len(self.import_graph)} nodes, "
                      f"{_edge_count} edges, {_error_count} errors")

        if TRACING_ENABLED:
            emit_trace('graph_build_complete', success=(_error_count == 0),
                       elapsed=_time.perf_counter() - _graph_start,
                       layer='Graph', module='graph.py')

        # Detect circular imports
        _cycle_start = _time.perf_counter()
        self._detect_circular_imports()

        if TRACING_ENABLED:
            emit_trace('graph_cycle_detection', success=True,
                       elapsed=_time.perf_counter() - _cycle_start,
                       layer='Graph', module='graph.py')

        return self.import_graph

    async def _extract_imports_async(self, rel_path: str) -> Set[str]:
        """Parse a single file and extract its imports."""
        file_path = self.repo_path / rel_path
        resolved_imports = set()

        try:
            # Read file
            content = await asyncio.to_thread(
                file_path.read_text,
                encoding="utf-8",
                errors="ignore"
            )

            # Quick optimization: skip parsing if no imports
            if "import" not in content:
                return set()

            # Parse AST
            tree = await asyncio.to_thread(ast.parse, content, filename=str(file_path))

            # Determine package context for relative imports
            importer_package = '.'.join(Path(rel_path).parts[:-1])

            # Extract imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        resolved_imports.update(
                            self._resolve_import(alias.name, importer_package, 0)
                        )
                        # Also resolve intermediate parent packages (e.g. "import a.b.c" -> a, a.b)
                        parts = alias.name.split('.')
                        for i in range(1, len(parts)):
                            parent_module = '.'.join(parts[:i])
                            resolved_imports.update(
                                self._resolve_import(parent_module, importer_package, 0)
                            )
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    resolved_imports.update(
                        self._resolve_import(module, importer_package, node.level)
                    )

        except SyntaxError as e:
            logger.debug(f"Syntax error in {rel_path}: {e}")
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as e:
            logger.debug(f"Failed to parse {rel_path}: {e}")

        if resolved_imports:
            logger.debug(f"_extract_imports_async({rel_path}): resolved {len(resolved_imports)} imports")

        return resolved_imports

    def _resolve_import(self, module: str, package: str, level: int) -> Set[str]:
        """
        Resolve import string to file path(s).

        Args:
            module: The imported module name
            package: The package context of the importing file
            level: Relative import level (0 for absolute)

        Returns:
            Set of resolved file paths
        """
        candidates = set()

        # Handle relative imports
        if level > 0:
            if not package:
                return set()

            parts = package.split('.')
            if len(parts) < level - 1:
                return set()

            # Navigate up the package hierarchy
            if level == 1:
                base = package
            else:
                base = '.'.join(parts[:-(level-1)])

            full_name = f"{base}.{module}" if module else base
        else:
            full_name = module

        # Build list of names to check (original + src/lib stripped variants)
        names_to_check = [full_name]
        if full_name.startswith("src."):
            names_to_check.append(full_name[4:])
        elif full_name.startswith("lib."):
            names_to_check.append(full_name[4:])

        for name in names_to_check:
            # Exact module match
            if name in self.module_to_file:
                candidates.add(self.module_to_file[name])

            # Package __init__.py match
            init_key = f"{name}.__init__" if name else "__init__"
            if init_key in self.module_to_file:
                candidates.add(self.module_to_file[init_key])

            # Submodule wildcard match (for package imports)
            prefix = f"{name}."
            for mod, path in self.module_to_file.items():
                if mod.startswith(prefix):
                    candidates.add(path)

        return candidates

    def _detect_circular_imports(self) -> None:
        """Detect circular import chains using iterative DFS to avoid stack overflow."""
        logger.debug(f"_detect_circular_imports: checking {len(self.import_graph)} nodes")
        visited = set()

        for start_node in self.import_graph:
            if start_node in visited:
                continue
            
            # Iterative DFS using explicit stack
            # Stack contains (node, iterator over neighbors, path)
            stack = [(start_node, iter(self.import_graph.get(start_node, set())), [start_node])]
            path_set = {start_node}  # For O(1) cycle detection
            
            while stack:
                node, neighbors, path = stack[-1]
                
                try:
                    neighbor = next(neighbors)
                    
                    if neighbor in path_set:
                        # Found cycle
                        try:
                            cycle_start = path.index(neighbor)
                        except ValueError:
                            continue
                        cycle = tuple(path[cycle_start:] + [neighbor])
                        if cycle not in self._circular_imports:
                            self._circular_imports.append(cycle)
                    elif neighbor not in visited:
                        # Continue DFS
                        stack.append((neighbor, iter(self.import_graph.get(neighbor, set())), path + [neighbor]))
                        path_set.add(neighbor)
                        
                except StopIteration:
                    # Done with this node
                    stack.pop()
                    if path:
                        path_set.discard(path[-1])
                    visited.add(node)

        if self._circular_imports:
            logger.warning(f"Detected {len(self._circular_imports)} circular import chain(s)")
            for cycle in self._circular_imports:
                logger.debug(f"Circular import: {' -> '.join(cycle)}")
        else:
            logger.debug("_detect_circular_imports: no cycles found")

    def get_circular_imports(self) -> List[Tuple[str, ...]]:
        """Return detected circular imports."""
        return self._circular_imports.copy()
