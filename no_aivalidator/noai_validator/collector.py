"""
Function collector for AST traversal.

Collects information about functions, lambdas, and comprehensions
during AST traversal.
"""

import ast
import logging
from typing import Any, Callable, Dict, List, Set, TypeVar, Union

from .models import FunctionInfo, LambdaMetrics, ComprehensionInfo

logger = logging.getLogger(__name__)

__all__ = ["FunctionCollector"]

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


class FunctionCollector(ast.NodeVisitor):
    """
    Collects function information from an AST.
    
    Traverses the AST and collects:
    - Function definitions (including methods)
    - Lambda expressions
    - Comprehensions
    - Import statements
    - Symbol definitions and references
    """
    
    def __init__(self, source: str) -> None:
        self.source = source
        self.source_lines = source.split('\n')
        
        # Collected items
        self.functions: List[FunctionInfo] = []
        self.lambdas: List[LambdaMetrics] = []
        self.comprehensions: List[ComprehensionInfo] = []
        
        # Symbol tracking
        self.defined_symbols: Set[str] = set()
        self.referenced_symbols: Set[str] = set()
        self.imports: Set[str] = set()
        self.imported_names: Dict[str, str] = {}  # name -> source module
        
        # Call graph
        self.call_graph: Dict[str, Set[str]] = {}
        
        # Context tracking
        self._current_class: str = ""
        self._current_class_bases: List[str] = []
        self._current_function: str = ""
        self._nesting_depth: int = 0
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition."""
        self.defined_symbols.add(node.name)
        old_class = self._current_class
        old_bases = self._current_class_bases
        self._current_class = node.name
        self._current_class_bases = [
            (b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute)
             else (b.value.id if isinstance(b, ast.Subscript) and isinstance(b.value, ast.Name)
                   else b.value.attr if isinstance(b, ast.Subscript) and isinstance(b.value, ast.Attribute)
                   else ''))
            for b in node.bases
        ]
        self.generic_visit(node)
        self._current_class = old_class
        self._current_class_bases = old_bases
    
    @trace
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function definition."""
        self._visit_function(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function definition."""
        self._visit_function(node)
    
    def _visit_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        """Common function visit logic."""
        logger.debug("Collecting function: %s", node.name)
        self.defined_symbols.add(node.name)
        
        # Get decorators
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(dec.attr)
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decorators.append(dec.func.attr)
        
        # Get source segment
        source_segment = None
        if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
            try:
                source_segment = '\n'.join(
                    self.source_lines[node.lineno - 1:node.end_lineno]
                )
            except IndexError:
                pass
        
        # Create function info
        info = FunctionInfo(
            node=node,  # type: ignore[arg-type]  # AsyncFunctionDef is structurally compatible
            class_context=bool(self._current_class),
            decorators=decorators,
            source_segment=source_segment,
            nesting_depth=self._nesting_depth,
            parent_class=self._current_class if self._current_class else None,
            parent_bases=list(self._current_class_bases),
        )
        self.functions.append(info)
        
        # Initialize call graph entry
        func_key = f"{self._current_class}.{node.name}" if self._current_class else node.name
        self.call_graph[func_key] = set()
        
        # Track nesting
        old_function = self._current_function
        old_depth = self._nesting_depth
        self._current_function = func_key
        self._nesting_depth += 1
        
        self.generic_visit(node)
        
        self._current_function = old_function
        self._nesting_depth = old_depth
    
    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Visit a lambda expression."""
        logger.debug("Collecting lambda at line %s", getattr(node, 'lineno', '?'))
        # Count arguments
        arg_count = len(node.args.args)
        if node.args.vararg:
            arg_count += 1
        if node.args.kwarg:
            arg_count += 1
        
        # Check for identity lambda: lambda x: x
        is_identity = False
        if len(node.args.args) == 1 and isinstance(node.body, ast.Name):
            if node.body.id == node.args.args[0].arg:
                is_identity = True
        
        # Check for constant lambda
        is_constant = isinstance(node.body, ast.Constant)
        
        metrics = LambdaMetrics(
            node=node,
            arg_count=arg_count,
            body_complexity=1,
            is_identity=is_identity,
            is_constant=is_constant,
        )
        self.lambdas.append(metrics)
        
        self.generic_visit(node)
    
    def visit_ListComp(self, node: ast.ListComp) -> None:
        """Visit a list comprehension."""
        self._visit_comprehension(node)
    
    def visit_SetComp(self, node: ast.SetComp) -> None:
        """Visit a set comprehension."""
        self._visit_comprehension(node)
    
    def visit_DictComp(self, node: ast.DictComp) -> None:
        """Visit a dict comprehension."""
        self._visit_comprehension(node)
    
    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        """Visit a generator expression."""
        self._visit_comprehension(node)
    
    def _visit_comprehension(self, node: Union[ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp]) -> None:
        """Common comprehension visit logic."""
        generators = getattr(node, 'generators', [])
        filter_count = sum(len(gen.ifs) for gen in generators)
        
        # Calculate nesting level
        nesting_level = 0
        for gen in generators:
            if isinstance(gen.iter, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                nesting_level += 1
        
        info = ComprehensionInfo(
            node=node,
            nesting_level=nesting_level,
            filter_count=filter_count,
            generator_count=len(generators),
        )
        self.comprehensions.append(info)
        
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import) -> None:
        """Visit an import statement."""
        for alias in node.names:
            module = alias.name.split('.')[0]
            self.imports.add(module)
            name = alias.asname or alias.name
            self.defined_symbols.add(name)
            self.imported_names[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit a from-import statement."""
        if node.module:
            module = node.module.split('.')[0]
            self.imports.add(module)
        for alias in node.names:
            name = alias.asname or alias.name
            if name != '*':
                self.defined_symbols.add(name)
                self.imported_names[name] = node.module or ''
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Module-level bindings — including those inside try/if/with blocks
        (`try: _GetStdHandle = windll.kernel32.GetStdHandle`) — are defined
        symbols (run 19, 2026-09-05: NAI-050 / NAI-097 called them undefined)."""
        if not self._current_function:
            for tgt in node.targets:
                for sub in ast.walk(tgt):
                    if isinstance(sub, ast.Name):
                        self.defined_symbols.add(sub.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if not self._current_function and isinstance(node.target, ast.Name):
            self.defined_symbols.add(node.target.id)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        """Visit a name reference."""
        if isinstance(node.ctx, ast.Load):
            self.referenced_symbols.add(node.id)
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Visit a function call."""
        # Track in call graph
        if self._current_function:
            if isinstance(node.func, ast.Name):
                self.call_graph[self._current_function].add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                self.call_graph[self._current_function].add(node.func.attr)
        
        self.generic_visit(node)
