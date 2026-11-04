"""
Metrics extraction from Python AST nodes.

Extracts function metrics used for classification and validation.
"""

import ast
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional, Set, TypeVar

from .core import FunctionMetrics

logger = logging.getLogger(__name__)

__all__ = ["MetricsExtractor"]

# Flow tracer integration (optional)
_F = TypeVar("_F", bound=Callable[..., Any])

try:
    from flow_tracer import trace as _flow_trace, emit_trace, set_workflow
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False
    def _flow_trace(func: _F) -> _F: return func
    def emit_trace(*args: Any, **kwargs: Any) -> None: pass
    def set_workflow(*args: Any, **kwargs: Any) -> None: pass

def trace(func: _F) -> _F:
    return _flow_trace(func)  # type: ignore[no-any-return]


class MetricsExtractor:
    """
    Extracts metrics from a function AST node.
    
    Metrics include parameter count, return count, branches, loops,
    complexity, and other structural characteristics.
    """
    
    def __init__(
        self,
        node: ast.FunctionDef,
        class_context: bool = False,
        source: Optional[str] = None
    ) -> None:
        self.node = node
        self.class_context = class_context
        self.source = source
        self._metrics: Optional[FunctionMetrics] = None
    
    @property
    def metrics(self) -> FunctionMetrics:
        """Get extracted metrics (computes on first access)."""
        if self._metrics is None:
            self._extract_sync()
        assert self._metrics is not None
        return self._metrics
    
    @trace
    def extract(self) -> FunctionMetrics:
        """Extract all metrics from the function."""
        return self._extract_sync()

    def _extract_sync(self) -> FunctionMetrics:
        """Internal extraction implementation."""
        if self._metrics is not None:
            return self._metrics

        logger.debug("Extracting metrics for: %s", self.node.name)
        node = self.node
        
        # Count parameters (excluding self/cls for methods)
        params = len(node.args.args)
        if self.class_context and params > 0:
            first_arg = node.args.args[0].arg
            if first_arg in ('self', 'cls'):
                params -= 1
        
        # Add *args and **kwargs
        if node.args.vararg:
            params += 1
        if node.args.kwarg:
            params += 1
        
        # Count returns and yields
        returns = 0
        yields = 0
        branches = 0
        loops = 0
        calls = 0
        assigns = 0
        comparisons = 0
        comprehensions = 0
        has_side_effects = False
        
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                returns += 1
            elif isinstance(child, (ast.Yield, ast.YieldFrom)):
                yields += 1
            elif isinstance(child, (ast.If, ast.IfExp)):
                branches += 1
            elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                loops += 1
            elif isinstance(child, ast.Call):
                calls += 1
                # Check for side effect calls
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in ('write', 'send', 'post', 'put', 'delete', 'append', 'extend', 'update'):
                        has_side_effects = True
                elif isinstance(child.func, ast.Name):
                    if child.func.id in ('print', 'open', 'write'):
                        has_side_effects = True
            elif isinstance(child, ast.Delete):
                has_side_effects = True   # IG-11: `del self[key]` / `del obj.attr` is an effect
            elif isinstance(child, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                assigns += 1
            elif isinstance(child, ast.Compare):
                comparisons += 1
            elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                comprehensions += 1
        
        # Calculate cyclomatic complexity
        complexity = 1 + branches + loops
        
        # Count lines
        lines = 0
        if hasattr(node, 'end_lineno') and hasattr(node, 'lineno') and node.end_lineno is not None and node.lineno is not None:
            lines = node.end_lineno - node.lineno + 1
        
        # Count docstring lines
        docstring_lines = 0
        body_start = 0
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
            docstring = node.body[0].value.value
            if isinstance(docstring, str):
                docstring_lines = len(docstring.split('\n'))
                body_start = 1
        
        # Check body patterns
        body_is_pass = False
        body_is_ellipsis = False
        returns_literal_only = False
        returns_input_unchanged = False
        
        body_stmts = node.body[body_start:]  # Skip docstring if present
        
        body_is_raise_not_implemented = False
        if len(body_stmts) == 1:
            stmt = body_stmts[0]
            if isinstance(stmt, ast.Pass):
                body_is_pass = True
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if stmt.value.value is ...:
                    body_is_ellipsis = True
            elif isinstance(stmt, ast.Raise):
                # F-ABS1 (2026-09-05): `raise NotImplementedError(...)` (docstring
                # allowed above) is an ABSTRACT body — pylint W0223 treats it so.
                exc = stmt.exc
                if isinstance(exc, ast.Call):
                    exc = exc.func
                if isinstance(exc, ast.Name) and exc.id == 'NotImplementedError':
                    body_is_raise_not_implemented = True
                elif isinstance(exc, ast.Attribute) and exc.attr == 'NotImplementedError':
                    body_is_raise_not_implemented = True
            elif isinstance(stmt, ast.Return):
                if stmt.value is None:
                    pass
                elif isinstance(stmt.value, ast.Constant):
                    returns_literal_only = True
                elif isinstance(stmt.value, ast.Name):
                    # Check if returning an input parameter
                    param_names = {arg.arg for arg in node.args.args}
                    if stmt.value.id in param_names:
                        returns_input_unchanged = True
        
        # Extract params_used: which declared params are actually read in the body
        declared_params: set[str] = set()
        for arg in node.args.args:
            if not (self.class_context and arg is node.args.args[0] and arg.arg in ('self', 'cls')):
                declared_params.add(arg.arg)
        for arg in node.args.posonlyargs:
            declared_params.add(arg.arg)
        for arg in node.args.kwonlyargs:
            declared_params.add(arg.arg)
        if node.args.vararg:
            declared_params.add(node.args.vararg.arg)
        if node.args.kwarg:
            declared_params.add(node.args.kwarg.arg)

        read_names: set[str] = set()
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                read_names.add(child.id)

        params_used = declared_params & read_names

        logger.debug("Extracted %s: complexity=%d, params=%d, returns=%d", node.name, complexity, params, returns)

        self._metrics = FunctionMetrics(
            name=node.name,
            params=params,
            returns=returns,
            yields=yields,
            branches=branches,
            loops=loops,
            calls=calls,
            assigns=assigns,
            comparisons=comparisons,
            complexity=complexity,
            comprehensions=comprehensions,
            has_side_effects=has_side_effects,
            lines=lines,
            docstring_lines=docstring_lines,
            comment_lines=0,  # Would need source analysis
            body_is_pass=body_is_pass,
            body_is_ellipsis=body_is_ellipsis,
            body_is_raise_not_implemented=body_is_raise_not_implemented,
            is_method=bool(self.class_context),
            is_async=isinstance(node, ast.AsyncFunctionDef),   # I-02 (run 117, 2026-09-15): NAI-018 / NAI-204 read the flag; it was never set
            returns_literal_only=returns_literal_only,
            returns_input_unchanged=returns_input_unchanged,
            params_used=params_used,
            params_declared=declared_params,
        )

        return self._metrics