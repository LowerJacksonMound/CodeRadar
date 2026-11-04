"""
Parameter Usage Analysis.
Detects unused parameters, shadowed parameters, and parameter misuse patterns.
"""

import ast
import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ParamIssue:
    file: str
    line: int
    function: str
    param: str
    code: str
    message: str


class ParameterAnalyzer(ast.NodeVisitor):
    """Analyze parameter usage in functions."""

    def __init__(self, filename: str):
        self.filename = filename
        self.issues: list[ParamIssue] = []
        logger.debug("TRACE: ParameterAnalyzer initialized for %s", filename)

    def _add(self, node: ast.AST, func_name: str, param: str, code: str, message: str):
        self.issues.append(ParamIssue(
            file=self.filename,
            line=getattr(node, "lineno", 0),
            function=func_name,
            param=param,
            code=code,
            message=message
        ))

    def _get_all_params(self, node: ast.FunctionDef) -> dict[str, ast.arg]:
        """Extract all parameter names from function definition."""
        params = {}
        for arg in node.args.posonlyargs:
            params[arg.arg] = arg
        for arg in node.args.args:
            params[arg.arg] = arg
        for arg in node.args.kwonlyargs:
            params[arg.arg] = arg
        if node.args.vararg:
            params[node.args.vararg.arg] = node.args.vararg
        if node.args.kwarg:
            params[node.args.kwarg.arg] = node.args.kwarg
        return params

    def _collect_used_names(self, node: ast.AST, exclude: set | None = None) -> set[str]:
        """Collect all Name nodes used (loaded) in a subtree."""
        exclude_nodes = exclude or set()
        used = set()
        
        for child in ast.walk(node):
            if child in exclude_nodes:
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                used.add(child.id)
            # Also check attribute access (self.x uses 'self')
            elif isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                used.add(child.value.id)
        return used

    def _collect_assigned_names(self, node: ast.AST) -> set[str]:
        """Collect all names that are assigned within a scope."""
        assigned = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                assigned.add(child.id)
            elif isinstance(child, ast.NamedExpr):  # walrus operator
                assigned.add(child.target.id)
        return assigned

    def _is_abstract_or_protocol(self, node: ast.FunctionDef) -> bool:
        """Check if function is abstract or part of protocol (unused params expected)."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in ("abstractmethod", "abstractproperty"):
                    return True
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr in ("abstractmethod", "abstractproperty"):
                    return True
        
        # Check for NotImplementedError raise
        for child in ast.walk(node):
            if isinstance(child, ast.Raise):
                if isinstance(child.exc, ast.Call):
                    if isinstance(child.exc.func, ast.Name):
                        if child.exc.func.id == "NotImplementedError":
                            return True
        return False

    def _is_callback_or_handler(self, node: ast.FunctionDef) -> bool:
        """Heuristic: callbacks/handlers may not use all params."""
        callback_patterns = ("_callback", "_handler", "on_", "_event", "_hook")
        return any(node.name.endswith(p) or node.name.startswith(p) for p in callback_patterns)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        params = self._get_all_params(node)
        
        # Skip self/cls
        params.pop("self", None)
        params.pop("cls", None)
        
        if not params:
            self.generic_visit(node)
            return

        # Skip abstract methods and protocols
        if self._is_abstract_or_protocol(node):
            self.generic_visit(node)
            return

        # Collect names used in function body
        used_names = self._collect_used_names(node)
        assigned_names = self._collect_assigned_names(node)

        # Check each parameter
        for param_name, param_node in params.items():
            # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous) — owner ruling: the `_` prefix is a LEXICAL PRIOR, not intent evidence; the skip goes, the fact rides on the message
            _underscore = param_name.startswith("_")

            # Check for unused parameter
            if param_name not in used_names:
                # More lenient for callbacks
                if self._is_callback_or_handler(node):
                    self._add(param_node, node.name, param_name, "PUA002",
                              f"Unused parameter '{param_name}' (callback/handler - consider underscore prefix)")
                else:
                    self._add(param_node, node.name, param_name, "PUA001",
                              f"Unused parameter '{param_name}'" + (" (underscore-prefixed: declared unused by convention — a lexical prior)" if _underscore else ""))

            # Check for parameter shadowing
            elif param_name in assigned_names:
                # Find the assignment
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id == param_name:
                        if isinstance(child.ctx, ast.Store):
                            self._add(child, node.name, param_name, "PUA010",
                                      f"Parameter '{param_name}' is reassigned (shadows parameter)")
                            break

        # Check for mutable default arguments
        for i, default in enumerate(node.args.defaults):
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                # Map back to parameter
                num_no_default = len(node.args.args) - len(node.args.defaults)
                param_idx = num_no_default + i
                if param_idx < len(node.args.args):
                    param_name = node.args.args[param_idx].arg
                    self._add(default, node.name, param_name, "PUA020",
                              f"Mutable default argument for '{param_name}'")

        for kw_default in node.args.kw_defaults:
            if kw_default is not None and isinstance(kw_default, (ast.List, ast.Dict, ast.Set)):
                self._add(kw_default, node.name, "kwarg", "PUA020",
                          "Mutable default argument for keyword-only parameter")

        # Check for **kwargs used but not unpacked (might indicate missing params)
        if node.args.kwarg:
            kwarg_name = node.args.kwarg.arg
            kwarg_accesses = []
            for child in ast.walk(node):
                if isinstance(child, ast.Subscript):
                    if isinstance(child.value, ast.Name) and child.value.id == kwarg_name:
                        if isinstance(child.slice, ast.Constant):
                            kwarg_accesses.append(child.slice.value)
            
            if len(kwarg_accesses) > 0:  # EXCISED cut 2 (2026-09-05): was `len(kwarg_accesses) > 3` — EXCISION_LIST class A
                self._add(node.args.kwarg, node.name, kwarg_name, "PUA030",
                          f"**{kwarg_name} accesses {len(kwarg_accesses)} keys; consider explicit parameters")

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]


async def analyze_file(filepath: Path) -> list[ParamIssue]:
    """Analyze parameter usage in a file."""
    logger.debug("analyze_file called: %s", filepath)
    try:
        source = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError) as e:
        return [ParamIssue(str(filepath), 0, "", "", "PUA000", f"Parse error: {e}")]

    analyzer = ParameterAnalyzer(str(filepath))
    analyzer.visit(tree)
    logger.debug("analyze_file done: %s — %d issues", filepath, len(analyzer.issues))
    return analyzer.issues


async def analyze_directory(directory: Path, pattern: str = "**/*.py",
                            files: list[Path] | None = None) -> list[ParamIssue]:
    """Analyze all Python files in directory.

    files: optional pre-filtered file list (e.g. whitelist-filtered discovery
    output from the validator daemon). None = legacy full-glob behavior.
    """
    logger.debug("analyze_directory called: %s pattern=%s files=%s",
                 directory, pattern, "None" if files is None else len(files))
    if files is None:
        from semantic_analysis._scope import contained_glob  # FIX_15: contained, never a bare glob
        files = await asyncio.to_thread(contained_glob, directory, pattern)
    results: list[ParamIssue] = []
    for filepath in files:
        results.extend(await analyze_file(filepath))
    return results


if __name__ == "__main__":
    import sys

    async def _main():
        target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
        if target.is_file():
            issues = await analyze_file(target)
        else:
            issues = await analyze_directory(target)
        for issue in issues:
            print(f"{issue.file}:{issue.line}: [{issue.code}] {issue.function}({issue.param}): {issue.message}")
        print(f"\nTotal: {len(issues)} parameter issues")

    asyncio.run(_main())
