"""
Module-Level & Nested Handling Analysis.
Handles imports, module structure, nested classes/functions, and scoping issues.
"""

import ast
import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ModuleIssue:
    file: str
    line: int
    code: str
    message: str
    context: str = ""


class ModuleAnalyzer(ast.NodeVisitor):
    """Analyze module structure and nesting."""

    def __init__(self, filename: str):
        self.filename = filename
        self.issues: list[ModuleIssue] = []

        # Tracking state
        self._imports: list[tuple[str, int, bool]] = []  # (name, line, is_from)
        self._late_imports: list[tuple[str, int]] = []
        self._nesting_depth = 0
        self._function_stack: list[str] = []
        self._class_stack: list[str] = []
        self._in_try_except = False
        self._conditional_imports: list[tuple[str, int]] = []
        logger.debug("TRACE: ModuleAnalyzer initialized for %s", filename)

    def _add(self, line: int, code: str, message: str, context: str = ""):
        self.issues.append(ModuleIssue(
            file=self.filename,
            line=line,
            code=code,
            message=message,
            context=context
        ))

    def _current_context(self) -> str:
        """Get current context string."""
        parts = []
        for cls in self._class_stack:
            parts.append(f"class {cls}")
        for func in self._function_stack:
            parts.append(f"def {func}")
        return " > ".join(parts) if parts else "module"

    def visit_Module(self, node: ast.Module):
        self.generic_visit(node)
        self._post_analysis()

    def _post_analysis(self):
        """Post-processing analysis after visiting all nodes."""
        # Check import ordering
        stdlib_imports = []
        third_party_imports = []
        local_imports = []
        
        # Simplified import categorization
        stdlib_modules = {
            "os", "sys", "re", "json", "typing", "collections", "itertools",
            "functools", "pathlib", "abc", "ast", "io", "time", "datetime",
            "math", "random", "copy", "dataclasses", "enum", "contextlib",
            "unittest", "logging", "argparse", "subprocess", "threading",
            "multiprocessing", "asyncio", "socket", "http", "urllib",
        }
        
        for name, line, is_from in self._imports:
            root_module = name.split(".")[0]
            if root_module in stdlib_modules:
                stdlib_imports.append((name, line))
            elif name.startswith("."):
                local_imports.append((name, line))
            else:
                third_party_imports.append((name, line))
        
        # Check if imports are grouped (simplified check)
        if stdlib_imports and third_party_imports:
            last_stdlib = max(line for _, line in stdlib_imports)
            first_third = min(line for _, line in third_party_imports)
            if last_stdlib > first_third:
                self._add(first_third, "MOD010",
                          "Import order: stdlib imports should come before third-party")

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._handle_import(alias.name, node.lineno, False)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        if node.level > 0:
            module = "." * node.level + module
        self._handle_import(module, node.lineno, True)
        self.generic_visit(node)

    def _handle_import(self, name: str, line: int, is_from: bool):
        """Process an import statement."""
        self._imports.append((name, line, is_from))
        
        # Check for late imports (not at module level)
        if self._function_stack or self._class_stack:
            if not self._in_try_except:
                self._late_imports.append((name, line))
                # Not necessarily an error - could be intentional lazy import
                self._add(line, "MOD001",
                          f"Import '{name}' inside {self._current_context()} (lazy import)",
                          context=self._current_context())
        
        # Check for conditional imports
        # (handled by visit_If)

    def visit_If(self, node: ast.If):
        # Check for conditional imports
        old_depth = self._nesting_depth
        
        # Detect TYPE_CHECKING guard
        is_type_checking = False
        if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            is_type_checking = True
        elif isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING":
            is_type_checking = True
        
        if not is_type_checking:
            # Check for imports in conditional (not type checking)
            for stmt in node.body + node.orelse:
                if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    self._conditional_imports.append(
                        (self._get_import_name(stmt), stmt.lineno)
                    )
        
        self._nesting_depth += 1
        self.generic_visit(node)
        self._nesting_depth = old_depth

    def _get_import_name(self, node: ast.Import | ast.ImportFrom) -> str:
        if isinstance(node, ast.Import):
            return node.names[0].name
        else:
            return node.module or ""

    def visit_Try(self, node: ast.Try):
        old_in_try = self._in_try_except
        self._in_try_except = True
        
        # Check for import error handling
        for handler in node.handlers:
            if handler.type:
                if isinstance(handler.type, ast.Name):
                    if handler.type.id in ("ImportError", "ModuleNotFoundError"):
                        # This is a valid pattern for optional dependencies
                        pass
        
        self.generic_visit(node)
        self._in_try_except = old_in_try

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._function_stack.append(node.name)
        old_depth = self._nesting_depth
        self._nesting_depth += 1
        
        # Check for deeply nested functions
        if len(self._function_stack) > 0:  # EXCISED cut 2 (2026-09-05): was `len(self._function_stack) > 2` — EXCISION_LIST class A
            self._add(node.lineno, "MOD020",
                      f"Deeply nested function '{node.name}' (depth {len(self._function_stack)})",
                      context=self._current_context())
        
        # Check for closure issues
        self._check_closure_issues(node)
        
        self.generic_visit(node)
        
        self._nesting_depth = old_depth
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef):
        self._class_stack.append(node.name)
        old_depth = self._nesting_depth
        self._nesting_depth += 1
        
        # Check for nested classes
        if len(self._class_stack) > 0:  # EXCISED cut 2 (2026-09-05): was `len(self._class_stack) > 1` — EXCISION_LIST class A
            # Nested classes can be valid, but note them
            if len(self._class_stack) > 0:  # EXCISED cut 2 (2026-09-05): was `len(self._class_stack) > 2` — EXCISION_LIST class A
                self._add(node.lineno, "MOD030",
                          f"Deeply nested class '{node.name}' (depth {len(self._class_stack)})",
                          context=self._current_context())
        
        # Check for class inside function
        if self._function_stack:
            self._add(node.lineno, "MOD031",
                      f"Class '{node.name}' defined inside function (creates new class each call)",
                      context=self._current_context())
        
        self.generic_visit(node)
        
        self._nesting_depth = old_depth
        self._class_stack.pop()

    def _check_closure_issues(self, _node: ast.FunctionDef):
        """Check for common closure issues.
        
        TODO: Implement proper closure issue detection including:
        - Loop variable capture in lambdas/closures
        - Late binding issues
        This requires proper parent tracking which is not yet implemented.
        """
        # Placeholder for future implementation
        pass

    def visit_Lambda(self, node: ast.Lambda):
        # Check for lambda in loop (potential late binding issue)
        # Would need parent context to detect this properly
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global):
        if self._function_stack:
            for name in node.names:
                self._add(node.lineno, "MOD040",
                          f"Global '{name}' in {self._current_context()}",
                          context=self._current_context())
        self.generic_visit(node)

    def visit_Nonlocal(self, node: ast.Nonlocal):
        if len(self._function_stack) < 2:
            self._add(node.lineno, "MOD041",
                      "Nonlocal statement outside nested function",
                      context=self._current_context())
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # Check for __all__ definition
        if node.id == "__all__" and isinstance(node.ctx, ast.Store):
            if self._function_stack or self._class_stack:
                self._add(node.lineno, "MOD050",
                          "__all__ should be defined at module level",
                          context=self._current_context())
        self.generic_visit(node)


class CircularImportDetector:
    """Detect potential circular import issues."""
    
    def __init__(self):
        self.imports: dict[str, set[str]] = {}  # module -> imports
    
    def add_module(self, module_path: Path, tree: ast.AST):
        """Add a module's imports."""
        module_name = module_path.stem
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        
        self.imports[module_name] = imports
    
    def find_cycles(self) -> list[list[str]]:
        """Find circular import chains."""
        cycles = []
        visited = set()
        
        def dfs(module: str, path: list[str]):
            if module in path:
                cycle_start = path.index(module)
                cycles.append(path[cycle_start:] + [module])
                return
            if module in visited:
                return
            visited.add(module)
            
            for imported in self.imports.get(module, []):
                if imported in self.imports:  # Only check known modules
                    dfs(imported, path + [module])
        
        for module in self.imports:
            dfs(module, [])
        
        return cycles


def _analyze_tree(filepath: Path, tree: ast.AST) -> list[ModuleIssue]:
    """Analyze a pre-parsed AST for module structure issues."""
    logger.debug("TRACE: _analyze_tree called for %s", filepath)
    analyzer = ModuleAnalyzer(str(filepath))
    analyzer.visit(tree)
    return analyzer.issues


async def analyze_file(filepath: Path) -> list[ModuleIssue]:
    """Analyze module structure in a file."""
    logger.debug("analyze_file called: %s", filepath)
    try:
        source = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError) as e:
        return [ModuleIssue(str(filepath), 0, "MOD000", f"Parse error: {e}")]

    result = _analyze_tree(filepath, tree)
    logger.debug("analyze_file done: %s — %d issues", filepath, len(result))
    return result


async def analyze_directory(directory: Path, pattern: str = "**/*.py",
                            files: list[Path] | None = None) -> list[ModuleIssue]:
    """Analyze all Python files in directory.

    files: optional pre-filtered file list (e.g. whitelist-filtered discovery
    output from the validator daemon). None = legacy full-glob behavior.
    """
    logger.debug("analyze_directory called: %s pattern=%s files=%s",
                 directory, pattern, "None" if files is None else len(files))
    detector = CircularImportDetector()
    all_issues = []

    if files is None:
        from semantic_analysis._scope import contained_glob  # FIX_15: contained, never a bare glob
        files = await asyncio.to_thread(contained_glob, directory, pattern)
    for filepath in files:
        try:
            source = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
            tree = ast.parse(source, filename=str(filepath))
        except (SyntaxError, UnicodeDecodeError) as e:
            all_issues.append(ModuleIssue(str(filepath), 0, "MOD000", f"Parse error: {e}"))
            continue

        all_issues.extend(_analyze_tree(filepath, tree))
        detector.add_module(filepath, tree)

    # Check for circular imports
    logger.debug("TRACE: checking circular imports across %d files", len(all_issues))
    cycles = detector.find_cycles()
    for cycle in cycles:
        cycle_str = " -> ".join(cycle)
        all_issues.append(ModuleIssue(
            file=str(directory),
            line=0,
            code="MOD060",
            message=f"Potential circular import: {cycle_str}"
        ))

    return all_issues


if __name__ == "__main__":
    import sys

    async def _main():
        target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
        if target.is_file():
            issues = await analyze_file(target)
        else:
            issues = await analyze_directory(target)
        for issue in issues:
            ctx = f" [{issue.context}]" if issue.context else ""
            print(f"{issue.file}:{issue.line}: [{issue.code}]{ctx} {issue.message}")
        print(f"\nTotal: {len(issues)} module issues")

    asyncio.run(_main())
