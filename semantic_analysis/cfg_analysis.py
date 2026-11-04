"""
CFG (Control Flow Graph) Analysis.
Detects unreachable code, infinite loops, missing returns, and control flow issues.
"""

import ast
import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

logger = logging.getLogger(__name__)


class FlowState(Enum):
    NORMAL = auto()
    RETURNS = auto()
    RAISES = auto()
    BREAKS = auto()
    CONTINUES = auto()


@dataclass
class CFGIssue:
    file: str
    line: int
    code: str
    message: str


class CFGAnalyzer(ast.NodeVisitor):
    """Analyze control flow patterns."""

    def __init__(self, filename: str):
        self.filename = filename
        self.issues: list[CFGIssue] = []
        self._current_function: str = ""
        logger.debug("TRACE: CFGAnalyzer initialized for %s", filename)

    def _add(self, node: ast.AST, code: str, message: str):
        self.issues.append(CFGIssue(
            file=self.filename,
            line=getattr(node, "lineno", 0),
            code=code,
            message=message
        ))

    def _analyze_block_flow(self, stmts: list[ast.stmt]) -> FlowState:
        """
        Analyze a block of statements and return flow state.
        Also detects unreachable code.
        """
        for i, stmt in enumerate(stmts):
            state = self._stmt_flow(stmt)
            
            if state != FlowState.NORMAL and i < len(stmts) - 1:
                # Code after terminal statement
                next_stmt = stmts[i + 1]
                self._add(next_stmt, "CFG001", "Unreachable code after terminal statement")
                return state
            
            if state != FlowState.NORMAL:
                return state
        
        return FlowState.NORMAL

    def _stmt_flow(self, stmt: ast.stmt) -> FlowState:
        """Determine the flow state after a statement."""
        if isinstance(stmt, ast.Return):
            return FlowState.RETURNS
        
        elif isinstance(stmt, ast.Raise):
            return FlowState.RAISES
        
        elif isinstance(stmt, ast.Break):
            return FlowState.BREAKS
        
        elif isinstance(stmt, ast.Continue):
            return FlowState.CONTINUES
        
        elif isinstance(stmt, ast.If):
            then_state = self._analyze_block_flow(stmt.body)
            else_state = self._analyze_block_flow(stmt.orelse) if stmt.orelse else FlowState.NORMAL
            
            # Both branches terminate
            if then_state in (FlowState.RETURNS, FlowState.RAISES) and \
               else_state in (FlowState.RETURNS, FlowState.RAISES):
                return FlowState.RETURNS  # Conservative
            return FlowState.NORMAL
        
        elif isinstance(stmt, ast.While):
            # Check for while True without break
            if isinstance(stmt.test, ast.Constant) and stmt.test.value is True:
                if not self._has_direct_break(stmt):
                    self._add(stmt, "CFG010", "Infinite loop: 'while True' without break")
                    return FlowState.RAISES  # Effectively never returns
            return FlowState.NORMAL
        
        elif isinstance(stmt, ast.For):
            # Check for break in else clause
            if stmt.orelse:
                for else_stmt in stmt.orelse:
                    if isinstance(else_stmt, ast.Break):
                        self._add(else_stmt, "CFG011", "Break in for-else has no effect")
            return FlowState.NORMAL
        
        elif isinstance(stmt, ast.Try):
            self._analyze_block_flow(stmt.body)

            # Check if all handlers return/raise
            for h in stmt.handlers:
                self._analyze_block_flow(h.body)
            finally_state = self._analyze_block_flow(stmt.finalbody) if stmt.finalbody else FlowState.NORMAL
            
            # Finally always runs
            if finally_state in (FlowState.RETURNS, FlowState.RAISES):
                return finally_state
            
            return FlowState.NORMAL
        
        elif isinstance(stmt, ast.With):
            return self._analyze_block_flow(stmt.body)
        
        elif isinstance(stmt, ast.Match):
            # All cases must terminate for match to terminate
            case_states = [self._analyze_block_flow(c.body) for c in stmt.cases]
            if all(s in (FlowState.RETURNS, FlowState.RAISES) for s in case_states):
                return FlowState.RETURNS
            return FlowState.NORMAL
        
        return FlowState.NORMAL

    @staticmethod
    def _has_direct_break(loop_node: ast.For | ast.While) -> bool:
        """Check if a loop contains a break at its own level (not inside a nested loop)."""
        def _search(stmts: list[ast.stmt]) -> bool:
            for stmt in stmts:
                if isinstance(stmt, ast.Break):
                    return True
                if isinstance(stmt, (ast.For, ast.While)):
                    continue  # Breaks inside nested loops don't belong to us
                for attr in ("body", "orelse", "finalbody"):
                    if hasattr(stmt, attr) and _search(getattr(stmt, attr)):
                        return True
                if hasattr(stmt, "handlers"):
                    for handler in stmt.handlers:
                        if _search(handler.body):
                            return True
            return False
        return _search(loop_node.body)

    def _check_missing_return(self, node: ast.FunctionDef):
        """Check if function might not return a value when it should."""
        # Skip if no return annotation
        if node.returns is None:
            return
        
        # Skip if annotated as None
        if isinstance(node.returns, ast.Constant) and node.returns.value is None:
            return
        if isinstance(node.returns, ast.Name) and node.returns.id == "None":
            return
        
        # Skip generators
        for child in ast.walk(node):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return
        
        # Check if all paths return
        state = self._analyze_block_flow(node.body)
        
        if state == FlowState.NORMAL:
            # Function can fall through without return
            self._add(node, "CFG020", 
                      f"Function '{node.name}' may not return a value on all paths")

    def _check_unreachable_after_loop_break(self, node: ast.For | ast.While):
        """Check for code after loop that always breaks."""
        # This is a simplified check - full analysis would need proper CFG
        for stmt in node.body:
            if isinstance(stmt, ast.Break):
                # Unconditional break at start of loop body
                idx = node.body.index(stmt)
                if idx < len(node.body) - 1:
                    self._add(node.body[idx + 1], "CFG002", 
                              "Unreachable code after unconditional break")
                break

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        self._current_function = node.name
        
        self._check_missing_return(node)
        self._analyze_block_flow(node.body)
        
        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_While(self, node: ast.While):
        self._check_unreachable_after_loop_break(node)
        
        # Check for suspicious while conditions
        if isinstance(node.test, ast.NamedExpr):
            self._add(node, "CFG030", 
                      "Walrus operator in while condition (ensure it updates)")
        
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self._check_unreachable_after_loop_break(node)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        # Check for side effects in assert (will be stripped in -O mode)
        for child in ast.walk(node.test):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id not in ("isinstance", "hasattr", "callable", "len", "bool"):
                        self._add(node, "CFG040", 
                                  f"Function call '{child.func.id}()' in assert may be stripped with -O")
                        break
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # Check for redundant else after return
        if node.body and isinstance(node.body[-1], ast.Return):
            if node.orelse and len(node.orelse) == 1:
                if isinstance(node.orelse[0], ast.If):
                    pass  # elif chain, okay
                else:
                    # Could simplify by removing else
                    pass  # Not an error, just style
        
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        # Check for empty except body
        for handler in node.handlers:
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                # Already caught by fast_static_filters, skip
                pass
        
        # Check for return in finally
        for stmt in node.finalbody:
            if isinstance(stmt, ast.Return):
                self._add(stmt, "CFG050", 
                          "Return in finally block may suppress exceptions")
        
        self.generic_visit(node)


async def analyze_file(filepath: Path) -> list[CFGIssue]:
    """Analyze control flow in a file."""
    logger.debug("analyze_file called: %s", filepath)
    try:
        source = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError) as e:
        return [CFGIssue(str(filepath), 0, "CFG000", f"Parse error: {e}")]

    analyzer = CFGAnalyzer(str(filepath))
    analyzer.visit(tree)
    logger.debug("analyze_file done: %s — %d issues", filepath, len(analyzer.issues))
    return analyzer.issues


async def analyze_directory(directory: Path, pattern: str = "**/*.py",
                            files: list[Path] | None = None) -> list[CFGIssue]:
    """Analyze all Python files in directory.

    files: optional pre-filtered file list (e.g. whitelist-filtered discovery
    output from the validator daemon). None = legacy full-glob behavior.
    """
    logger.debug("analyze_directory called: %s pattern=%s files=%s",
                 directory, pattern, "None" if files is None else len(files))
    if files is None:
        from semantic_analysis._scope import contained_glob  # FIX_15: contained, never a bare glob
        files = await asyncio.to_thread(contained_glob, directory, pattern)
    results: list[CFGIssue] = []
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
            print(f"{issue.file}:{issue.line}: [{issue.code}] {issue.message}")
        print(f"\nTotal: {len(issues)} control flow issues")

    asyncio.run(_main())
