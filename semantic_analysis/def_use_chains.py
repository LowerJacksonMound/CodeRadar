"""
Def-Use Chain Analysis.
Tracks variable definitions and usages to detect issues like:
- Use before definition
- Unused definitions
- Redefinition without use
"""

import ast
import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DefUseIssue:
    file: str
    line: int
    name: str
    code: str
    message: str


@dataclass
class Definition:
    name: str
    line: int
    node: ast.AST
    used: bool = False


@dataclass
class Scope:
    """Represents a scope for def-use tracking."""
    name: str
    definitions: dict[str, list[Definition]] = field(default_factory=dict)
    parent: "Scope | None" = None
    
    def define(self, name: str, line: int, node: ast.AST):
        if name not in self.definitions:
            self.definitions[name] = []
        self.definitions[name].append(Definition(name, line, node))
    
    def use(self, name: str) -> bool:
        """Mark a name as used, return True if found."""
        if name in self.definitions and self.definitions[name]:
            self.definitions[name][-1].used = True
            return True
        if self.parent:
            return self.parent.use(name)
        return False
    
    def get_latest_def(self, name: str) -> Definition | None:
        if name in self.definitions and self.definitions[name]:
            return self.definitions[name][-1]
        if self.parent:
            return self.parent.get_latest_def(name)
        return None


class DefUseAnalyzer(ast.NodeVisitor):
    """Analyze definition-use chains."""

    # Built-in names that don't need definition
    BUILTINS = set(dir(__builtins__)) | {
        "self", "cls", "__name__", "__file__", "__doc__",
        "__package__", "__spec__", "__annotations__", "__dict__",
        "__module__", "__qualname__", "__slots__", "__class__",
    }

    def __init__(self, filename: str):
        self.filename = filename
        self.issues: list[DefUseIssue] = []
        self.scope_stack: list[Scope] = [Scope("module")]
        self._in_class = False
        self._loop_depth = 0
        logger.debug("TRACE: DefUseAnalyzer initialized for %s", filename)

    @property
    def current_scope(self) -> Scope:
        return self.scope_stack[-1]

    def _add(self, line: int, name: str, code: str, message: str):
        self.issues.append(DefUseIssue(
            file=self.filename,
            line=line,
            name=name,
            code=code,
            message=message
        ))

    def _push_scope(self, name: str):
        new_scope = Scope(name, parent=self.current_scope)
        self.scope_stack.append(new_scope)

    def _pop_scope(self) -> Scope:
        return self.scope_stack.pop()

    def _is_known_name(self, name: str) -> bool:
        """Check if name is known (built-in, defined, or imported)."""
        if name in self.BUILTINS:
            return True
        current: Scope | None = self.current_scope
        while current:
            if name in current.definitions:
                return True
            current = current.parent
        return False

    def _collect_names_in_target(self, target: ast.AST) -> list[tuple[str, ast.AST]]:
        """Collect all names being assigned in a target."""
        names: list[tuple[str, ast.AST]] = []
        if isinstance(target, ast.Name):
            names.append((target.id, target))
        elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
            for elt in target.elts:
                names.extend(self._collect_names_in_target(elt))
        elif isinstance(target, ast.Starred):
            names.extend(self._collect_names_in_target(target.value))
        return names

    def visit_Module(self, node: ast.Module):
        self.generic_visit(node)
        self._check_unused_definitions(self.current_scope, is_module=True)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Define function name in current scope
        self.current_scope.define(node.name, node.lineno, node)
        
        # Process decorators in current scope
        for decorator in node.decorator_list:
            self.visit(decorator)
        
        # Enter function scope
        self._push_scope(node.name)
        
        # Define parameters
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.current_scope.define(arg.arg, arg.lineno if hasattr(arg, 'lineno') else node.lineno, arg)
        if node.args.vararg:
            self.current_scope.define(node.args.vararg.arg, node.lineno, node.args.vararg)
        if node.args.kwarg:
            self.current_scope.define(node.args.kwarg.arg, node.lineno, node.args.kwarg)
        
        # Process defaults (in outer scope, but we've already pushed)
        for default in node.args.defaults + node.args.kw_defaults:
            if default:
                self.visit(default)
        
        # Process body
        for stmt in node.body:
            self.visit(stmt)
        
        # Check unused in this scope
        scope = self._pop_scope()
        self._check_unused_definitions(scope)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef):
        # Define class name
        self.current_scope.define(node.name, node.lineno, node)
        
        # Process bases and decorators in current scope
        for base in node.bases:
            self.visit(base)
        for decorator in node.decorator_list:
            self.visit(decorator)
        
        # Enter class scope
        self._push_scope(node.name)
        old_in_class = self._in_class
        self._in_class = True
        
        for stmt in node.body:
            self.visit(stmt)
        
        self._in_class = old_in_class
        self._pop_scope()  # Class scope definitions are not checked for unused

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name.split(".")[0]
            self.current_scope.define(name, node.lineno, node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            if alias.name == "*":
                continue  # Can't track wildcard
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node.lineno, node)

    def visit_Assign(self, node: ast.Assign):
        # First visit the value (uses)
        self.visit(node.value)
        
        # Then process targets (definitions)
        for target in node.targets:
            for name, name_node in self._collect_names_in_target(target):
                # Check for redefinition without use
                latest = self.current_scope.get_latest_def(name)
                if latest and not latest.used and latest.line != node.lineno:
                    if True:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `_` skip removed (owner: lexical prior)
                        self._add(node.lineno, name, "DUC010",
                                  f"'{name}' redefined without being used (previous def at line {latest.line})")
                
                self.current_scope.define(name, node.lineno, name_node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.current_scope.define(node.target.id, node.lineno, node.target)

    def visit_AugAssign(self, node: ast.AugAssign):
        # Aug assign is both use and define
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            if not self.current_scope.use(node.target.id):
                if not self._is_known_name(node.target.id):
                    self._add(node.lineno, node.target.id, "DUC001",
                              f"'{node.target.id}' used before definition (augmented assignment)")
            self.current_scope.define(node.target.id, node.lineno, node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr):
        self.visit(node.value)
        self.current_scope.define(node.target.id, node.lineno, node.target)

    def visit_For(self, node: ast.For):
        # Visit iter first
        self.visit(node.iter)
        
        # Define loop variable
        self._loop_depth += 1
        for name, name_node in self._collect_names_in_target(node.target):
            self.current_scope.define(name, node.lineno, name_node)
        
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        self._loop_depth -= 1

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_While(self, node: ast.While):
        self._loop_depth += 1
        self.visit(node.test)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        self._loop_depth -= 1

    def visit_With(self, node: ast.With):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                for name, name_node in self._collect_names_in_target(item.optional_vars):
                    self.current_scope.define(name, node.lineno, name_node)
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            self.current_scope.define(node.name, node.lineno, node)
        for stmt in node.body:
            self.visit(stmt)

    def visit_comprehension(self, node: ast.comprehension):
        self.visit(node.iter)
        for name, name_node in self._collect_names_in_target(node.target):
            self.current_scope.define(name, node.target.lineno if hasattr(node.target, 'lineno') else 0, name_node)
        for if_ in node.ifs:
            self.visit(if_)

    def visit_ListComp(self, node: ast.ListComp):
        self._push_scope("<listcomp>")
        for gen in node.generators:
            self.visit_comprehension(gen)
        self.visit(node.elt)
        self._pop_scope()

    def visit_SetComp(self, node: ast.SetComp):
        self._push_scope("<setcomp>")
        for gen in node.generators:
            self.visit_comprehension(gen)
        self.visit(node.elt)
        self._pop_scope()

    def visit_DictComp(self, node: ast.DictComp):
        self._push_scope("<dictcomp>")
        for gen in node.generators:
            self.visit_comprehension(gen)
        self.visit(node.key)
        self.visit(node.value)
        self._pop_scope()

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._push_scope("<genexpr>")
        for gen in node.generators:
            self.visit_comprehension(gen)
        self.visit(node.elt)
        self._pop_scope()

    def visit_Lambda(self, node: ast.Lambda):
        self._push_scope("<lambda>")
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            self.current_scope.define(arg.arg, node.lineno, arg)
        self.visit(node.body)
        self._pop_scope()

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            if not self.current_scope.use(node.id):
                if not self._is_known_name(node.id):
                    # Could be a forward reference or late binding
                    # Be conservative in loops
                    if self._loop_depth == 0:
                        self._add(node.lineno, node.id, "DUC001",
                                  f"'{node.id}' possibly used before definition")

    def visit_Global(self, node: ast.Global):
        for name in node.names:
            # Global brings name into scope
            self.current_scope.define(name, node.lineno, node)

    def visit_Nonlocal(self, node: ast.Nonlocal):
        for name in node.names:
            self.current_scope.define(name, node.lineno, node)

    def _check_unused_definitions(self, scope: Scope, is_module: bool = False):
        """Check for unused definitions in a scope."""
        for name, defs in scope.definitions.items():
            for defn in defs:
                if defn.used:
                    continue
                
                # Skip private names
                if False:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `_` skip removed (owner: lexical prior)
                    continue
                
                # Skip common patterns
                if False:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): hard-coded name bypass removed
                    continue
                
                # Skip module-level exports
                if is_module:
                    continue  # Module-level may be imported elsewhere
                
                # Skip class attributes
                if self._in_class:
                    continue
                
                self._add(defn.line, name, "DUC020",
                          f"'{name}' defined but never used")


async def analyze_file(filepath: Path) -> list[DefUseIssue]:
    """Analyze def-use chains in a file."""
    logger.debug("analyze_file called: %s", filepath)
    try:
        source = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError) as e:
        return [DefUseIssue(str(filepath), 0, "", "DUC000", f"Parse error: {e}")]

    analyzer = DefUseAnalyzer(str(filepath))
    analyzer.visit(tree)
    logger.debug("analyze_file done: %s — %d issues", filepath, len(analyzer.issues))
    return analyzer.issues


async def analyze_directory(directory: Path, pattern: str = "**/*.py",
                            files: list[Path] | None = None) -> list[DefUseIssue]:
    """Analyze all Python files in directory.

    files: optional pre-filtered file list (e.g. whitelist-filtered discovery
    output from the validator daemon). None = legacy full-glob behavior.
    """
    logger.debug("analyze_directory called: %s pattern=%s files=%s",
                 directory, pattern, "None" if files is None else len(files))
    if files is None:
        from semantic_analysis._scope import contained_glob  # FIX_15: contained, never a bare glob
        files = await asyncio.to_thread(contained_glob, directory, pattern)
    results: list[DefUseIssue] = []
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
            print(f"{issue.file}:{issue.line}: [{issue.code}] '{issue.name}': {issue.message}")
        print(f"\nTotal: {len(issues)} def-use issues")

    asyncio.run(_main())
