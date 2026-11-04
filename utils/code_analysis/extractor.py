"""
AST metrics extraction.

Provides the MetricsExtractor class for extracting function metrics from AST nodes.
"""

import ast
import logging
from typing import Union

from utils.code_analysis.core import DataFlowEdge, FunctionMetrics

# Builtins that copy/wrap without transforming the data
COPY_CONSTRUCTORS = frozenset({
    "list", "dict", "set", "tuple", "frozenset", "bytearray", "bytes",
})
COPY_METHODS = frozenset({"copy", "deepcopy"})

logger = logging.getLogger(__name__)


class MetricsExtractor:
    """
    Extract metrics from a function AST node.

    Walks the AST to count structural elements and track variable usage.
    """

    def __init__(
        self,
        func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        class_context: bool = False,
    ):
        """
        Initialize the extractor with a function node.

        Args:
            func_node: The function AST node to analyze
            class_context: Whether the function is a method in a class
        """
        self.func_node = func_node
        self.class_context = class_context
        self.metrics = FunctionMetrics(name=func_node.name)
        self._current_depth = 0
        self._max_depth = 0
        logger.debug("MetricsExtractor: extracting %s (class_context=%s)", func_node.name, class_context)
        self._extract()
        logger.debug(
            "MetricsExtractor: %s -> params=%d returns=%d branches=%d loops=%d calls=%d depth=%d",
            func_node.name, self.metrics.params, self.metrics.returns,
            self.metrics.branches, self.metrics.loops, self.metrics.calls,
            self.metrics.nested_depth,
        )

    def _extract(self) -> None:
        """Extract all metrics from the function node."""
        # Basic properties
        self.metrics.is_async = isinstance(self.func_node, ast.AsyncFunctionDef)
        self._extract_params()
        self._walk_body(self.func_node.body)
        self.metrics.nested_depth = self._max_depth

    def _extract_params(self) -> None:
        """Extract parameter count and names."""
        args = self.func_node.args

        # Count all parameter types
        param_count = len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)

        # Add vararg and kwarg if present
        if args.vararg:
            param_count += 1
            self.metrics.params_declared.add(args.vararg.arg)
        if args.kwarg:
            param_count += 1
            self.metrics.params_declared.add(args.kwarg.arg)

        # Skip 'self' or 'cls' in class context
        if self.class_context and args.args:
            first_arg = args.args[0].arg
            if first_arg in ("self", "cls"):
                param_count -= 1
            else:
                self.metrics.params_declared.add(first_arg)
            # Add remaining args
            for arg in args.args[1:]:
                self.metrics.params_declared.add(arg.arg)
        else:
            for arg in args.args:
                self.metrics.params_declared.add(arg.arg)

        # Add positional-only and keyword-only args
        for arg in args.posonlyargs:
            self.metrics.params_declared.add(arg.arg)
        for arg in args.kwonlyargs:
            self.metrics.params_declared.add(arg.arg)

        self.metrics.params = param_count

    def _walk_body(self, body: list[ast.stmt], depth: int = 0) -> None:
        """
        Walk a list of statements and extract metrics.

        Args:
            body: List of AST statement nodes
            depth: Current nesting depth
        """
        self._current_depth = depth
        self._max_depth = max(self._max_depth, depth)

        for node in body:
            self._process_node(node, depth)

    def _process_node(self, node: ast.AST, depth: int) -> None:
        """
        Process a single AST node and update metrics.

        Args:
            node: The AST node to process
            depth: Current nesting depth
        """
        # Return statements
        if isinstance(node, ast.Return):
            self.metrics.returns += 1
            if node.value:
                self._extract_uses(node.value)
                # Track which vars feed the return value
                self._collect_names(node.value, self.metrics.return_sources)

        # Yield statements (generator)
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            self.metrics.is_generator = True
            if isinstance(node, ast.Yield) and node.value:
                self._extract_uses(node.value)
            elif isinstance(node, ast.YieldFrom) and node.value:
                self._extract_uses(node.value)

        # If statements
        elif isinstance(node, ast.If):
            self.metrics.branches += 1
            self._extract_uses(node.test)
            self._walk_body(node.body, depth + 1)
            if node.orelse:
                # Count elif as additional branch
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    self._process_node(node.orelse[0], depth)
                else:
                    self._walk_body(node.orelse, depth + 1)

        # For loops
        elif isinstance(node, ast.For):
            self.metrics.loops += 1
            self._extract_assigns_from_target(node.target)
            self._extract_uses(node.iter)
            self._walk_body(node.body, depth + 1)
            if node.orelse:
                self._walk_body(node.orelse, depth + 1)

        # Async for loops
        elif isinstance(node, ast.AsyncFor):
            self.metrics.loops += 1
            self._extract_assigns_from_target(node.target)
            self._extract_uses(node.iter)
            self._walk_body(node.body, depth + 1)
            if node.orelse:
                self._walk_body(node.orelse, depth + 1)

        # While loops
        elif isinstance(node, ast.While):
            self.metrics.loops += 1
            self._extract_uses(node.test)
            self._walk_body(node.body, depth + 1)
            if node.orelse:
                self._walk_body(node.orelse, depth + 1)

        # With statements
        elif isinstance(node, ast.With):
            for item in node.items:
                self._extract_uses(item.context_expr)
                if item.optional_vars:
                    self._extract_assigns_from_target(item.optional_vars)
            self._walk_body(node.body, depth + 1)

        # Async with statements
        elif isinstance(node, ast.AsyncWith):
            for item in node.items:
                self._extract_uses(item.context_expr)
                if item.optional_vars:
                    self._extract_assigns_from_target(item.optional_vars)
            self._walk_body(node.body, depth + 1)

        # Try/except
        elif isinstance(node, ast.Try):
            self._walk_body(node.body, depth + 1)
            for handler in node.handlers:
                if handler.name:
                    self.metrics.vars_assigned.add(handler.name)
                self._walk_body(handler.body, depth + 1)
            if node.orelse:
                self._walk_body(node.orelse, depth + 1)
            if node.finalbody:
                self._walk_body(node.finalbody, depth + 1)

        # Try/except* (Python 3.11+)
        elif hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
            self._walk_body(node.body, depth + 1)
            for handler in node.handlers:
                if handler.name:
                    self.metrics.vars_assigned.add(handler.name)
                self._walk_body(handler.body, depth + 1)
            if node.orelse:
                self._walk_body(node.orelse, depth + 1)
            if node.finalbody:
                self._walk_body(node.finalbody, depth + 1)

        # Assignments
        elif isinstance(node, ast.Assign):
            self.metrics.assigns += 1
            for target in node.targets:
                self._extract_assigns_from_target(target)
                # Record data flow edges with operation classification
                if isinstance(target, ast.Name):
                    sources, operation, detail = self._classify_rhs(node.value)
                    for src in sources:
                        self.metrics.data_flow_edges.append(DataFlowEdge(
                            source=src, target=target.id,
                            operation=operation, detail=detail,
                        ))
            self._extract_uses(node.value)

        # Annotated assignments
        elif isinstance(node, ast.AnnAssign):
            if node.value:
                self.metrics.assigns += 1
                self._extract_uses(node.value)
            if node.target:
                self._extract_assigns_from_target(node.target)

        # Augmented assignments (+=, -=, etc.)
        elif isinstance(node, ast.AugAssign):
            self.metrics.assigns += 1
            self._extract_assigns_from_target(node.target)
            self._extract_uses(node.target)
            self._extract_uses(node.value)

        # Named expressions (walrus operator :=)
        elif isinstance(node, ast.NamedExpr):
            self.metrics.assigns += 1
            self._extract_assigns_from_target(node.target)
            self._extract_uses(node.value)

        # Expression statements (including function calls)
        elif isinstance(node, ast.Expr):
            self._extract_uses(node.value)
            if isinstance(node.value, ast.Call):
                self.metrics.calls += 1
                # Detect in-place method mutations: var.method(args)
                # These transform the object without an explicit assignment
                call = node.value
                if (isinstance(call.func, ast.Attribute)
                        and isinstance(call.func.value, ast.Name)):
                    mutated_var = call.func.value.id
                    method = call.func.attr
                    self.metrics.data_flow_edges.append(DataFlowEdge(
                        source=mutated_var, target=mutated_var,
                        operation="transform",
                        detail=f"method_call:{method}",
                    ))

        # Comprehensions
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            self.metrics.comprehensions += 1
            self._extract_comprehension(node)

        elif isinstance(node, ast.DictComp):
            self.metrics.comprehensions += 1
            self._extract_dict_comprehension(node)

        # Match statements (Python 3.10+)
        elif hasattr(ast, "Match") and isinstance(node, ast.Match):
            self._extract_uses(node.subject)
            for case in node.cases:
                self.metrics.branches += 1
                self._walk_body(case.body, depth + 1)

        # Global / nonlocal declarations — track so dead-variable checks can skip them
        elif isinstance(node, ast.Global):
            self.metrics.global_vars.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            self.metrics.nonlocal_vars.update(node.names)

        # Nested function definitions (don't recurse into them for metrics)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Just note that there's a nested function, don't extract its metrics
            pass

        # Class definitions (don't recurse)
        elif isinstance(node, ast.ClassDef):
            pass

    def _extract_uses(self, node: ast.AST) -> None:
        """
        Extract variable uses from an expression.

        Args:
            node: The expression AST node
        """
        if node is None:
            return

        if isinstance(node, ast.Name):
            # Only track loads (reads), not stores
            if isinstance(node.ctx, ast.Load):
                self.metrics.vars_used.add(node.id)

        elif isinstance(node, ast.Call):
            self.metrics.calls += 1
            self._extract_uses(node.func)
            for arg in node.args:
                self._extract_uses(arg)
            for keyword in node.keywords:
                self._extract_uses(keyword.value)

        elif isinstance(node, ast.BinOp):
            self._extract_uses(node.left)
            self._extract_uses(node.right)

        elif isinstance(node, ast.UnaryOp):
            self._extract_uses(node.operand)

        elif isinstance(node, ast.Compare):
            self._extract_uses(node.left)
            for comparator in node.comparators:
                self._extract_uses(comparator)

        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                self._extract_uses(value)

        elif isinstance(node, ast.Subscript):
            self._extract_uses(node.value)
            self._extract_uses(node.slice)

        elif isinstance(node, ast.Attribute):
            self._extract_uses(node.value)

        elif isinstance(node, ast.Tuple) or isinstance(node, ast.List):
            for elt in node.elts:
                self._extract_uses(elt)

        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if key:
                    self._extract_uses(key)
            for value in node.values:
                self._extract_uses(value)

        elif isinstance(node, ast.Set):
            for elt in node.elts:
                self._extract_uses(elt)

        elif isinstance(node, ast.IfExp):
            self._extract_uses(node.test)
            self._extract_uses(node.body)
            self._extract_uses(node.orelse)

        elif isinstance(node, ast.Lambda):
            self._extract_uses(node.body)

        elif isinstance(node, ast.Starred):
            self._extract_uses(node.value)

        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            self.metrics.comprehensions += 1
            self._extract_comprehension(node)

        elif isinstance(node, ast.DictComp):
            self.metrics.comprehensions += 1
            self._extract_dict_comprehension(node)

        elif isinstance(node, ast.Await):
            self._extract_uses(node.value)

        elif isinstance(node, ast.Yield):
            self.metrics.is_generator = True
            if node.value:
                self._extract_uses(node.value)

        elif isinstance(node, ast.YieldFrom):
            self.metrics.is_generator = True
            self._extract_uses(node.value)

        elif isinstance(node, ast.FormattedValue):
            self._extract_uses(node.value)

        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                self._extract_uses(value)

        elif isinstance(node, ast.NamedExpr):
            self.metrics.assigns += 1
            self._extract_assigns_from_target(node.target)
            self._extract_uses(node.value)

        elif isinstance(node, ast.Slice):
            if node.lower:
                self._extract_uses(node.lower)
            if node.upper:
                self._extract_uses(node.upper)
            if node.step:
                self._extract_uses(node.step)

    def _classify_rhs(self, value: ast.AST) -> tuple[set[str], str, str]:
        """Classify an assignment RHS as identity-preserving or transforming.

        Returns: (source_vars, operation, detail)
        """
        # Direct name: x = y
        if isinstance(value, ast.Name):
            return ({value.id}, "identity", "direct_assign")

        # Call: might be copy constructor
        if isinstance(value, ast.Call):
            # list(y), dict(y), tuple(y), etc. — single arg, no kwargs
            if (isinstance(value.func, ast.Name)
                    and value.func.id in COPY_CONSTRUCTORS
                    and len(value.args) == 1
                    and isinstance(value.args[0], ast.Name)
                    and not value.keywords):
                return ({value.args[0].id}, "identity",
                        f"copy_constructor:{value.func.id}")

            # y.copy()
            if (isinstance(value.func, ast.Attribute)
                    and value.func.attr in COPY_METHODS
                    and isinstance(value.func.value, ast.Name)
                    and not value.args and not value.keywords):
                return ({value.func.value.id}, "identity",
                        f"copy_method:{value.func.attr}")

            # copy.copy(y), copy.deepcopy(y)
            if (isinstance(value.func, ast.Attribute)
                    and isinstance(value.func.value, ast.Name)
                    and value.func.value.id == "copy"
                    and value.func.attr in COPY_METHODS
                    and len(value.args) == 1
                    and isinstance(value.args[0], ast.Name)):
                return ({value.args[0].id}, "identity",
                        f"copy_module:{value.func.attr}")

            # General function call — transform
            sources: set[str] = set()
            func_name = ""
            if isinstance(value.func, ast.Name):
                func_name = value.func.id
            elif isinstance(value.func, ast.Attribute):
                func_name = value.func.attr
            for arg in value.args:
                self._collect_names(arg, sources)
            for kw in value.keywords:
                self._collect_names(kw.value, sources)
            return (sources, "transform", f"call:{func_name}")

        # Subscript: might be full-slice copy y[:]
        if isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Name):
                if (isinstance(value.slice, ast.Slice)
                        and value.slice.lower is None
                        and value.slice.upper is None
                        and value.slice.step is None):
                    return ({value.value.id}, "identity", "slice_copy")
                # Specific index/key — extracting a subset, that's a transform
                return ({value.value.id}, "transform", "subscript")
            sources = set()
            self._collect_names(value, sources)
            return (sources, "transform", "subscript")

        # BinOp: arithmetic/string ops — always transform
        if isinstance(value, ast.BinOp):
            sources = set()
            self._collect_names(value, sources)
            return (sources, "transform", f"binop:{type(value.op).__name__}")

        # UnaryOp
        if isinstance(value, ast.UnaryOp):
            sources = set()
            self._collect_names(value, sources)
            return (sources, "transform", f"unaryop:{type(value.op).__name__}")

        # Constant/literal: new data, no source vars
        if isinstance(value, ast.Constant):
            return (set(), "transform", "constant")

        # Collection literals (Dict, List, Set, Tuple)
        if isinstance(value, (ast.Dict, ast.List, ast.Set, ast.Tuple)):
            sources = set()
            self._collect_names(value, sources)
            type_name = type(value).__name__
            return (sources, "transform", f"literal:{type_name}")

        # Attribute access: x.attr — selecting sub-part
        if isinstance(value, ast.Attribute):
            sources = set()
            self._collect_names(value, sources)
            return (sources, "transform", f"attr:{value.attr}")

        # IfExp (ternary): conditional selection — transform
        if isinstance(value, ast.IfExp):
            sources = set()
            self._collect_names(value, sources)
            return (sources, "transform", "conditional")

        # Comprehensions — always transform
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            sources = set()
            self._collect_names(value, sources)
            return (sources, "transform", "comprehension")

        # Fallback: collect all names, classify as transform
        sources = set()
        self._collect_names(value, sources)
        return (sources, "transform", "other")

    def _collect_names(self, node: ast.AST, result: set[str]) -> None:
        """Walk an expression and collect all Name nodes (Load context)."""
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            result.add(node.id)
        for child in ast.iter_child_nodes(node):
            self._collect_names(child, result)

    def _extract_assigns_from_target(self, target: ast.AST) -> None:
        """
        Extract variable names from an assignment target.

        Args:
            target: The assignment target AST node
        """
        if isinstance(target, ast.Name):
            self.metrics.vars_assigned.add(target.id)
        elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
            for elt in target.elts:
                self._extract_assigns_from_target(elt)
        elif isinstance(target, ast.Starred):
            self._extract_assigns_from_target(target.value)
        # For attribute and subscript targets, we don't track as simple variable assigns

    def _extract_comprehension(
        self, node: Union[ast.ListComp, ast.SetComp, ast.GeneratorExp]
    ) -> None:
        """
        Extract variable uses from a comprehension.

        Args:
            node: The comprehension AST node
        """
        self._extract_uses(node.elt)
        for generator in node.generators:
            self._extract_assigns_from_target(generator.target)
            self._extract_uses(generator.iter)
            for if_clause in generator.ifs:
                self._extract_uses(if_clause)

    def _extract_dict_comprehension(self, node: ast.DictComp) -> None:
        """
        Extract variable uses from a dict comprehension.

        Args:
            node: The dict comprehension AST node
        """
        self._extract_uses(node.key)
        self._extract_uses(node.value)
        for generator in node.generators:
            self._extract_assigns_from_target(generator.target)
            self._extract_uses(generator.iter)
            for if_clause in generator.ifs:
                self._extract_uses(if_clause)


def collect_method_ids(tree: ast.AST) -> set[int]:
    """
    Collect the object ids of function nodes that are direct children of a class.

    Single O(n) pass over the AST.

    Args:
        tree: The root AST node to walk.

    Returns:
        Set of ``id()`` values for function/async-function nodes that are
        immediate children of a class body.
    """
    method_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_ids.add(id(item))
    logger.debug("collect_method_ids: found %d methods", len(method_ids))
    return method_ids


if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    # Enable logging for CLI
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Extract function metrics from a Python file."
    )
    parser.add_argument("file", type=Path, help="Python file to analyze")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed metrics for each function"
    )
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    source = args.file.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: Syntax error in {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    method_ids = collect_method_ids(tree)
    func_count = 0

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_method = id(node) in method_ids
            ext = MetricsExtractor(node, class_context=is_method)
            m = ext.metrics
            func_count += 1

            if args.verbose:
                print(f"\n{m.name}():")
                print(f"  params: {m.params}, returns: {m.returns}")
                print(f"  branches: {m.branches}, loops: {m.loops}")
                print(f"  calls: {m.calls}, assigns: {m.assigns}")
                print(f"  nested_depth: {m.nested_depth}")
                print(f"  vars_assigned: {m.vars_assigned}")
                print(f"  vars_used: {m.vars_used}")
                if m.data_flow_edges:
                    print(f"  data_flow_edges: {len(m.data_flow_edges)}")
            else:
                print(f"{m.name}: params={m.params} returns={m.returns} branches={m.branches} depth={m.nested_depth}")

    print(f"\n✓ Extracted metrics from {func_count} functions in {args.file}")
