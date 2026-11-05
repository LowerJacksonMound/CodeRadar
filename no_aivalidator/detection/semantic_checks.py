"""
Semantic Analysis Checks Mixin (NAI-100 to NAI-119).

Integrates the New_Semantic_Analysis_Module to catch semantic fakes that
slip through structural analysis:

- NAI-100: Parameter not used in return path (fake calculation)
- NAI-101: Magic number return (ignores input)
- NAI-102: Function name/docstring mismatch (says X, does Y)
- NAI-103: Boolean logic inversion (is_valid returns True for invalid)
- NAI-104: Extra arithmetic not justified (a+b+1 when should be a+b)
- NAI-105: Data flow disconnect (input->output with no transform)
- NAI-106: Missing string normalization in comparison (case-sensitive trap)
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, Set, List, Optional, Iterator, TYPE_CHECKING
import asyncio
import logging

_log = logging.getLogger(__name__)


# Patterns that indicate potential user/external input
INPUT_PATTERNS = [
    r'^user_', r'^input_', r'^args\.', r'^request\.',
    r'^param_', r'^query_', r'^form_', r'^data_',
    r'_input$', r'_query$', r'_param$',
]

# For validation functions, ANY string comparison without normalization is risky
# These patterns indicate the comparison target could be user-supplied
VALIDATION_INPUT_HEURISTIC = True  # In validate_* functions, assume params are inputs

# Verbs that imply specific operations
VERB_OPERATIONS: dict[str, set[type]] = {
    # Math verbs -> expect arithmetic
    "add": {ast.Add, ast.BinOp},
    "subtract": {ast.Sub, ast.BinOp},
    "multiply": {ast.Mult, ast.BinOp},
    "divide": {ast.Div, ast.FloorDiv, ast.BinOp},
    "calculate": {ast.BinOp, ast.AugAssign},
    "compute": {ast.BinOp, ast.AugAssign},
    "sum": {ast.Add, ast.BinOp},
    "average": {ast.Div, ast.BinOp},
    "mean": {ast.Div, ast.BinOp},

    # Filter verbs -> expect conditionals
    "filter": {ast.If, ast.IfExp, ast.Compare},
    "select": {ast.If, ast.IfExp, ast.Compare},
    "find": {ast.If, ast.IfExp, ast.Compare},

    # Transform verbs -> expect modification
    "transform": {ast.BinOp, ast.Call, ast.Subscript},
    "convert": {ast.Call, ast.BinOp},
    "format": {ast.Call, ast.JoinedStr},
    "parse": {ast.Call},

    # Validation verbs -> expect bool return
    "validate": {ast.Compare, ast.BoolOp},
    "check": {ast.Compare, ast.BoolOp, ast.If},
    "is_": {ast.Compare, ast.BoolOp},  # prefix
    "has_": {ast.Compare, ast.BoolOp},  # prefix

    # Sort verbs -> expect ordering
    "sort": {ast.Call, ast.Compare},
    "order": {ast.Call, ast.Compare},
}

# Magic numbers that indicate fake returns
SUSPICIOUS_MAGIC_NUMBERS = {
    42, 42.0,  # The answer to everything
    0, 0.0,    # When non-zero expected
    1, 1.0,    # When more expected
    -1,        # Common placeholder
    100, 100.0,
    999, 9999,
    123, 1234,
}


class SemanticChecksMixin:
    """Mixin for semantic fake detection checks."""
    if TYPE_CHECKING:  # FIX_31 (2026-09-15): what the composed AIFakeDetector supplies to every check mixin — typing only, no runtime effect
        imported_names: Dict[str, str]
        module_level_names: Set[str]
        module_attr_names: Set[str]
        enclosing_names: Set[str]
        class_bases: Optional[List[str]]
        @staticmethod
        def _own_scope(root: ast.AST) -> Iterator[ast.AST]: ...
        def _has_decorator(self, *names: str) -> bool: ...
        def _class_is_protocol(self) -> bool: ...

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    def _get_param_names(self) -> set[str]:
        """Get all parameter names (excluding self/cls)."""
        params: set[str] = set()
        args = self.func.args
        for arg in args.posonlyargs + args.args + args.kwonlyargs:
            if arg.arg not in ("self", "cls"):
                params.add(arg.arg)
        if args.vararg:
            params.add(args.vararg.arg)
        if args.kwarg:
            params.add(args.kwarg.arg)
        return params

    def _get_return_values(self) -> list[ast.expr]:
        """Get all return value nodes."""
        returns: list[ast.expr] = []
        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value is not None:
                returns.append(node.value)
        return returns

    def _names_in_expr(self, node: ast.AST) -> set[str]:
        """Get all Name references in an expression."""
        names: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                names.add(child.id)
        return names

    def _check_param_return_disconnect(self) -> None:
        """
        NAI-100: Parameter not used in return data flow.

        Detects: calculate_average(numbers) that ignores numbers in return.
        """
        params = self._get_param_names()
        if not params:
            self.observations.append({"tag": 'NAI-100', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not params'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        returns = self._get_return_values()
        if not returns:
            self.observations.append({"tag": 'NAI-100', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not returns'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        # For each return, check if params flow to it
        for ret in returns:
            # Skip if return is just a literal or a dict/list of constants
            # (these are guard-clause early returns, not the real computation)
            if isinstance(ret, ast.Constant):
                continue
            names_used = self._names_in_expr(ret)
            if not names_used:
                # Return has no variable references (e.g. {"mean": 0, "median": 0})
                continue

            # Get names used in return expression
            names_in_return = self._names_in_expr(ret)

            # Check if any param is NOT in the return flow
            # but the function name suggests it should process all inputs
            func_name_lower = self.func.name.lower()

            # For "calculate_X" functions, all numeric params should be used
            if func_name_lower.startswith(("calculate", "compute", "sum", "add")):
                for param in params:
                    if param not in names_in_return:
                        # Check if param is used anywhere to derive the return
                        # by tracing through variable assignments
                        if not self._param_flows_to_return(param, ret):
                            self.observations.append({
                                "tag": "NAI-100",
                                "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                                "unused_param": param,
                                "func_name": self.func.name,
                            })
                            _log.debug("NAI-100 observed: param '%s' not in return of '%s'", param, self.func.name)

    def _param_flows_to_return(self, param: str, ret_node: ast.AST) -> bool:
        """Check if a parameter eventually flows to the return value."""
        # Build a simple data flow graph
        # var -> set of vars it depends on
        dependencies: dict[str, set[str]] = {}

        def _base(t: ast.AST) -> str | None:
            while isinstance(t, (ast.Subscript, ast.Attribute)):
                t = t.value
            return t.id if isinstance(t, ast.Name) else None

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        dependencies[target.id] = self._names_in_expr(node.value)
                    elif isinstance(target, (ast.Subscript, ast.Attribute)) and _base(target):
                        # M-146: a container write (`rollup[cat] = … val`) makes the container depend on key and value
                        deps = dependencies.setdefault(_base(target), set())   # type: ignore[arg-type]
                        deps |= self._names_in_expr(node.value) | self._names_in_expr(target)
                    elif isinstance(target, ast.Tuple):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                dependencies[elt.id] = self._names_in_expr(node.value)
            elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                  and isinstance(node.value.func, ast.Attribute) and _base(node.value.func.value)):
                # M-146: a mutating call (`out.append(x)`, `seen.update(y)`) makes the receiver depend on its arguments
                deps = dependencies.setdefault(_base(node.value.func.value), set())   # type: ignore[arg-type]
                for arg in [*node.value.args, *(k.value for k in node.value.keywords)]:
                    deps |= self._names_in_expr(arg)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    var = node.target.id
                    deps = dependencies.get(var, set())
                    deps |= self._names_in_expr(node.value)
                    deps.add(var)  # x += y depends on x
                    dependencies[var] = deps
            # Handle for loops — loop variable depends on iterable
            elif isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    loop_var = node.target.id
                    dependencies[loop_var] = self._names_in_expr(node.iter)
                elif isinstance(node.target, ast.Tuple):
                    iter_names = self._names_in_expr(node.iter)
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            dependencies[elt.id] = iter_names

        # Get names in return
        return_names = self._names_in_expr(ret_node)

        # Transitively check if param flows to any return name
        def reaches(source: str, target_set: set[str], visited: set[str] | None = None) -> bool:
            if visited is None:
                visited = set()
            if source in target_set:
                return True
            if source in visited:
                return False
            visited.add(source)

            # Check if source flows to any var that reaches target
            for var, deps in dependencies.items():
                if source in deps:
                    if var in target_set or reaches(var, target_set, visited):
                        return True
            return False

        return reaches(param, return_names)

    def _check_magic_number_return(self) -> None:
        """
        NAI-101: Magic number return ignores input.

        Detects: calculate_average(numbers) -> return 42.0

        Exception: returning 0 as edge case (empty input) is valid if there's
        another return path that uses the input.
        """
        params = self._get_param_names()
        if not params:
            self.observations.append({"tag": 'NAI-101', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not params'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return  # No params, magic number might be valid

        returns = self._get_return_values()
        if not returns:
            self.observations.append({"tag": 'NAI-101', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not returns'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        # Separate zero returns from other magic numbers
        zero_returns: list[ast.expr] = []
        magic_returns: list[ast.expr] = []
        param_using_returns: list[ast.expr] = []

        for ret in returns:
            if isinstance(ret, ast.Constant) and isinstance(ret.value, (int, float)):
                if ret.value in (0, 0.0):
                    zero_returns.append(ret)
                elif ret.value in SUSPICIOUS_MAGIC_NUMBERS:
                    magic_returns.append(ret)
            else:
                # Check if this return uses any parameters (transitively)
                for param in params:
                    if self._param_flows_to_return(param, ret):
                        param_using_returns.append(ret)
                        break  # Only need one param to flow

        # Check if function name implies calculation
        name_lower = self.func.name.lower()
        calc_prefixes = ("calculate", "compute", "get_", "find_", "sum", "average", "count")
        is_calc_func = any(name_lower.startswith(p) for p in calc_prefixes)

        if not is_calc_func:
            return

        # M-146: constants SELECTED by the input (`if occupancy > target: return 1.20 … return 1.0`) are a band table,
        # not an ignored input — the rule's own premise ("magic number return ignores input") does not hold when a
        # branch test reads a parameter.
        _tests = [n.test for n in ast.walk(self.func) if isinstance(n, (ast.If, ast.IfExp, ast.While))]
        if any(set(params) & self._names_in_expr(t) for t in _tests):
            return

        # Flag non-zero magic numbers always
        for ret in magic_returns:
            if isinstance(ret, ast.Constant):
                self.observations.append({
                    "tag": "NAI-101",
                    "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                    "magic_value": ret.value,
                    "func_name": self.func.name,
                    "param_count": len(params),
                })
                _log.debug("NAI-101 observed: magic number %s in '%s'", ret.value, self.func.name)

        # Flag zero returns ONLY if there's no other return path that uses params
        # (i.e., 0 is the only return, not an edge case)
        if zero_returns and not param_using_returns and not magic_returns:
            # All returns are just 0 - definitely a fake
            for ret in zero_returns:
                if isinstance(ret, ast.Constant):
                    self.observations.append({
                        "tag": "NAI-101",
                        "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                        "magic_value": ret.value,
                        "func_name": self.func.name,
                        "param_count": len(params),
                        "zero_only": True,
                    })
                    _log.debug("NAI-101 observed: zero-only return in '%s'", self.func.name)

    def _docstring_claims_vs_body(self, doc: str, doc_lower: str) -> None:
        """owner 2026-10-07 (blind tree 1 L5, M-90): three claims a docstring can make that the body can contradict, each
        named by the claim's own words so the twin (whose body agrees) stays quiet:
          * direction — the docstring says the value is ADDED / increases, the only return SUBTRACTS (or the reverse);
          * range     — the docstring names a range `A..B` / `A to B`, a chained compare in the body bounds the same
                        variable from A to a different upper bound (or the same B from a different lower bound);
          * extent    — the docstring says ANY / anywhere / every, the only return is a single `==` test."""
        import re as _re
        returns = [n for n in ast.walk(self.func) if isinstance(n, ast.Return) and n.value is not None]
        # the function's ONE return (a structural fact: a second return means the claim may hold on another path)
        for ret in [r.value for r in returns if not any(o is not r for o in returns)]:
            says_add = bool(_re.search(r"\b(add|adds|added|increase|increases|plus|grows?)\b", doc_lower))
            says_sub = bool(_re.search(r"\b(subtract|subtracts|decrease|decreases|minus|goes down|reduce|reduces)\b",
                                       doc_lower))
            if isinstance(ret, ast.BinOp) and says_add != says_sub:
                if says_add and isinstance(ret.op, ast.Sub) or says_sub and isinstance(ret.op, ast.Add):
                    self.observations.append({
                        "tag": "NAI-102", "line": ret.lineno, "func_name": self.func.name,
                        "docstring_claim": "adds" if says_add else "subtracts",
                        "body_does": "subtracts" if isinstance(ret.op, ast.Sub) else "adds",
                    })
            if (_re.search(r"\b(any|anywhere|every|all|whole|full)\b", doc_lower)
                    and isinstance(ret, ast.Compare) and [type(o) for o in ret.ops] == [ast.Eq]):
                self.observations.append({
                    "tag": "NAI-102", "line": ret.lineno, "func_name": self.func.name,
                    "docstring_claim": "any / every case", "body_does": "matches one exact value (==)",
                })
        m = _re.search(r"(-?\d+(?:\.\d+)?)\s*(?:\.\.|to|–|-)\s*(-?\d+(?:\.\d+)?)", doc)
        if m:
            lo, hi = float(m.group(1)), float(m.group(2))
            for n in ast.walk(self.func):
                # a chained two-sided bound `A <= x <= B` (shape, not a count)
                if (isinstance(n, ast.Compare) and [type(o) in (ast.LtE, ast.Lt) for o in n.ops] == [True, True]
                        and isinstance(n.left, ast.Constant) and isinstance(n.comparators[1], ast.Constant)
                        and isinstance(n.left.value, (int, float)) and isinstance(n.comparators[1].value, (int, float))):
                    blo, bhi = float(n.left.value), float(n.comparators[1].value)
                    if (blo == lo) != (bhi == hi):   # one end agrees with the docstring, the other does not
                        self.observations.append({
                            "tag": "NAI-102", "line": n.lineno, "func_name": self.func.name,
                            "docstring_claim": f"range {m.group(1)}..{m.group(2)}",
                            "body_does": f"counts only {n.left.value}..{n.comparators[1].value}",
                        })

    def _check_docstring_code_mismatch(self) -> None:
        """
        NAI-102: Docstring claims don't match code behavior.

        Detects: "Add two numbers" but returns a+b+1
        """
        docstring = ast.get_docstring(self.func)
        if not docstring:
            self.observations.append({"tag": 'NAI-102', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not docstring'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        docstring_lower = docstring.lower()
        self._docstring_claims_vs_body(docstring, docstring_lower)
        # owner 2026-10-07 ~09:10: the stated intent, read once (intent_claims) and checked against the body —
        # by probe when the body is pure arithmetic, by shape otherwise; a claim that cannot be checked stays silent
        _ic: Any
        try:
            from no_aivalidator.noai_validator import intent_claims as _ic
        except ImportError:
            try:
                from noai_validator import intent_claims as _ic  # type: ignore
            except ImportError:
                _ic = None
        if _ic is not None:
            for _b in _ic.check(self.func):
                self.observations.append({
                    "tag": "NAI-102", "line": _b.get("line") or self.func.lineno, "func_name": self.func.name,
                    "docstring_claim": _b["says"], "body_does": f"gives {_b['got']} (expected {_b['expected']})",
                    "probe": _b["probe"], "lines": _b.get("lines") or [],
                })

        # Check for "add" claim
        if "add" in docstring_lower and "two" in docstring_lower:
            # Look for extra operations on the addition result
            for node in ast.walk(self.func):
                if isinstance(node, ast.Return) and node.value:
                    ret = node.value
                    # Pattern: a + b + 1 (extra constant)
                    if isinstance(ret, ast.BinOp) and isinstance(ret.op, ast.Add):
                        if isinstance(ret.right, ast.Constant) and isinstance(ret.right.value, (int, float)):
                            if ret.right.value not in (0, 0.0):
                                self.observations.append({
                                    "tag": "NAI-102",
                                    "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                                    "func_name": self.func.name,
                                    "extra_constant": ret.right.value,
                                    "docstring_claim": "add two numbers",
                                })
                                _log.debug("NAI-102 observed: extra +%s in return at line %d", ret.right.value, ret.lineno)
                        elif isinstance(ret.left, ast.BinOp):
                            # Nested: (a + b) + 1
                            if isinstance(ret.right, ast.Constant) and ret.right.value not in (0, 0.0):
                                self.observations.append({
                                    "tag": "NAI-102",
                                    "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                                    "func_name": self.func.name,
                                    "extra_constant": ret.right.value,
                                    "docstring_claim": "add",
                                })
                                _log.debug("NAI-102 observed: nested extra constant in return at line %d", ret.lineno)

    def _check_boolean_logic_inversion(self) -> None:
        """
        NAI-103: Boolean return logic is inverted from what name/docstring implies.

        Detects: is_valid(x) returns True when x is invalid
        """
        name_lower = self.func.name.lower()

        # Check for is_valid, is_positive, has_X patterns
        positive_prefixes = ("is_valid", "is_positive", "is_active", "is_enabled",
                            "has_", "can_", "should_")

        matched_prefix: str | None = None
        for prefix in positive_prefixes:
            if name_lower.startswith(prefix):
                matched_prefix = prefix
                break

        if not matched_prefix:
            return

        # Look for inverted logic patterns
        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                # Pattern: if x <= 0: return True (for is_valid or is_positive)
                if isinstance(node.test, ast.Compare):
                    # Check if condition is "negative" but returns True
                    ops = node.test.ops
                    if any(isinstance(op, (ast.LtE, ast.Lt)) for op in ops):
                        # Check if comparing to 0
                        for comp in node.test.comparators:
                            if isinstance(comp, ast.Constant) and comp.value == 0:
                                # Check what's returned in the body
                                for stmt in node.body:
                                    if isinstance(stmt, ast.Return):
                                        if isinstance(stmt.value, ast.Constant):
                                            if stmt.value.value is True:
                                                self.observations.append({
                                                    "tag": "NAI-103",
                                                    "line": stmt.lineno if hasattr(stmt, 'lineno') else self.func.lineno,
                                                    "func_name": self.func.name,
                                                    "matched_prefix": matched_prefix,
                                                    "returns_true_for": "negative/zero",
                                                })
                                                _log.debug("NAI-103 observed: inverted boolean in '%s' at line %d", self.func.name, stmt.lineno)

    def _check_name_operation_mismatch(self) -> None:
        """
        NAI-104: Function name implies operation not found in code.

        Detects: multiply_values() with no multiplication operator
        """
        name_lower = self.func.name.lower()

        # body-shape fact: a body carrying NO operation evidence at all is never
        # judged, regardless of verb — an overload/abstract stub (`...`), a no-op
        # stub (`pass`), a bare `raise SomeError` (a Name, not a Call — no message,
        # no args), or a bare getter/delegate return (`return x`, `return self.x`,
        # `return not self.x` — a Name/Attribute, optionally negated once, with no
        # Compare/BoolOp/BinOp/Call around it).
        def _is_bare_stored_value(value: ast.expr) -> bool:
            if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
                value = value.operand
            return isinstance(value, (ast.Name, ast.Attribute))

        body = self.func.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            body = body[1:]  # drop the docstring before judging "the whole body is..."

        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
                return  # typing.overload / protocol stub
            if isinstance(stmt, ast.Pass):
                return  # documented no-op hook
            if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Name) and stmt.cause is None:
                return  # abstract-method marker (raise NotImplementedError, no call)
            if isinstance(stmt, ast.Return) and stmt.value is not None and _is_bare_stored_value(stmt.value):
                return  # trivial getter / subclass-delegate

        # a Subscript-target Assign (`container[key] = value`) is itself a
        # mutating operation, the same standing as a Call/BinOp.
        has_subscript_store = any(
            isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) for t in n.targets)
            for n in ast.walk(self.func)
        )

        # Extract verb from name
        for verb, expected_ops in VERB_OPERATIONS.items():
            if verb in name_lower or name_lower.startswith(verb):
                # Check if expected operations exist
                found_expected = has_subscript_store
                for node in ast.walk(self.func):
                    if type(node) in expected_ops:
                        found_expected = True
                        break
                    # Also check operator types within BinOp
                    if isinstance(node, ast.BinOp):
                        if type(node.op) in expected_ops:
                            found_expected = True
                            break

                # Hardened 2026-09-05 (F-055 family): `add()` that appends,
                # `compute()` that delegates — a body that CALLS anything may
                # perform the implied operation elsewhere; only a call-free
                # body that lacks the operator is judged.
                if not found_expected and self.metrics.calls == 0:  # EXCISED cut 3 batch 5 (2026-09-06, line read): `verb not in ("is_", "has_")` name mute removed — implied_verb is on the observation; the ranker decides
                    self.observations.append({
                        "tag": "NAI-104",
                        "line": self.func.lineno,
                        "func_name": self.func.name,
                        "implied_verb": verb,
                        "expected_ops": sorted(t.__name__ for t in expected_ops),  # F-NONDET-104: deterministic order (cut 2)
                    })
                    _log.debug("NAI-104 observed: '%s' implies '%s' but op not found", self.func.name, verb)
                break  # Only check first matching verb

    def _check_no_transform_passthrough(self) -> None:
        """
        NAI-105: Input passes through with no meaningful transformation.

        More sophisticated than simple identity check - catches:
        - Copy to temp var, return temp
        - Iterate and collect unchanged
        """
        params = self._get_param_names()
        if not params:
            self.observations.append({"tag": 'NAI-105', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not params'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        returns = self._get_return_values()
        if not returns:
            self.observations.append({"tag": 'NAI-105', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not returns'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        # Check for "transform", "process", "convert" in name
        name_lower = self.func.name.lower()
        transform_words = ("transform", "process", "convert", "modify", "update")

        if not any(w in name_lower for w in transform_words):
            return

        # Look for patterns like:
        # result = items; for x in items: result.append(x); return result
        for node in ast.walk(self.func):
            if isinstance(node, ast.For):
                # Check if loop body just appends without modification
                for stmt in node.body:
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        call = stmt.value
                        if isinstance(call.func, ast.Attribute):
                            if call.func.attr == "append" and len(call.args) == 1:
                                # Check if appending the loop variable unchanged
                                if isinstance(call.args[0], ast.Name):
                                    if isinstance(node.target, ast.Name):
                                        if call.args[0].id == node.target.id:
                                            self.observations.append({
                                                "tag": "NAI-105",
                                                "line": stmt.lineno if hasattr(stmt, 'lineno') else self.func.lineno,
                                                "func_name": self.func.name,
                                                "loop_var": node.target.id,
                                            })
                                            _log.debug("NAI-105 observed: passthrough copy in '%s' at line %d", self.func.name, stmt.lineno)

    def _check_missing_normalization(self) -> None:
        """
        NAI-106: Missing string normalization in comparison.

        Detects: if user_input == "expected"  (missing .lower())

        This is the Level 4 "String Comparison Trap" - looks correct but
        fails for case variations like "EXPECTED" or "Expected".
        """
        name_lower = self.func.name.lower()

        # cut 3 batch 5 (2026-09-06, line read): the validation-name prefix was a MUTE on a measurement that stands on
        # its own (an `==` against an un-normalised input); the name is now a published fact on the observation.
        validation_prefixes = ("validate", "check", "is_", "has_", "verify", "match")
        name_implies_validation = any(name_lower.startswith(p) for p in validation_prefixes)
        # EXCISED cut 3 batch 5 (2026-09-06, line read): `if not any(name_lower.startswith(p) for p in validation_prefixes): return` removed

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                # Only check == comparisons
                if not any(isinstance(op, ast.Eq) for op in node.ops):
                    continue

                # Check left side and each comparator
                sides: list[ast.expr] = [node.left] + list(node.comparators)

                for i, side in enumerate(sides):
                    other_sides = sides[:i] + sides[i+1:]

                    # Check if this side is a string literal
                    if isinstance(side, ast.Constant) and isinstance(side.value, str):
                        str_literal = side.value

                        # If literal has uppercase, might be intentional case-sensitive
                        if any(c.isupper() for c in str_literal):
                            continue

                        # Check other sides for potential input without normalization
                        for other in other_sides:
                            if self._is_potential_input(other) and not self._has_normalization(other):
                                other_name = ast.unparse(other) if hasattr(ast, 'unparse') else "?"
                                self.observations.append({
                                    "tag": "NAI-106",
                                    "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                                    "func_name": self.func.name,
                                    "compared_literal": str_literal,
                                    "input_expr": other_name,
                                    "name_implies_validation": name_implies_validation,
                                })
                                _log.debug("NAI-106 observed: unnormalized compare in '%s' at line %d", self.func.name, node.lineno)

    def _is_potential_input(self, node: ast.AST) -> bool:
        """Check if a node looks like user/external input based on naming."""
        # First check explicit input patterns
        if isinstance(node, ast.Name):
            name = node.id
            # Check explicit input patterns
            if any(re.match(pat, name) for pat in INPUT_PATTERNS):
                return True
            # In validation functions, function parameters are likely inputs
            if VALIDATION_INPUT_HEURISTIC:
                func_name = self.func.name.lower()
                if any(func_name.startswith(p) for p in ("validate", "check", "is_", "has_", "verify", "match")):
                    # Check if this name is a function parameter
                    param_names = {arg.arg for arg in self.func.args.args + self.func.args.posonlyargs + self.func.args.kwonlyargs}
                    param_names.discard("self")
                    param_names.discard("cls")
                    if name in param_names:
                        return True
            return False
        elif isinstance(node, ast.Attribute):
            # Get full attribute string like "request.form"
            try:
                attr_str = ast.unparse(node)
                return any(re.search(pat, attr_str) for pat in INPUT_PATTERNS)
            except Exception:
                return False
        elif isinstance(node, ast.Subscript):
            # Check if it's like args["key"] or request.form["key"]
            if isinstance(node.value, (ast.Name, ast.Attribute)):
                return self._is_potential_input(node.value)
        return False

    def _has_normalization(self, node: ast.AST) -> bool:
        """Check if node or its subtree has string normalization calls."""
        normalizers = {'lower', 'upper', 'casefold', 'strip', 'lstrip', 'rstrip'}

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in normalizers:
                        return True
                    # Check for unicodedata.normalize
                    if child.func.attr == 'normalize':
                        try:
                            if 'unicodedata' in ast.unparse(child.func.value):
                                return True
                        except Exception:
                            pass
        return False

    # -----------------------------------------------------------------
    # NAI-108, 109, 115-118: Additional semantic checks
    # -----------------------------------------------------------------

    def _check_return_type_name_mismatch(self) -> None:
        """
        NAI-108: Return type doesn't match function name convention.

        Detects: get_count() returning a string, get_name() returning int.
        """
        name_lower = self.func.name.lower()
        # cr_trials round three, step 5 (2026-11-04): `reset_count`, `clear_total` name an ACTION on the noun; what
        # comes back is a status or message, not the noun's type. `get_count` / `word_count` still promise the noun.
        if any(name_lower.startswith(v) for v in ("reset_", "clear_", "set_", "update_", "apply_", "record_", "add_",
                                                   "remove_", "save_", "write_", "delete_", "drop_", "mark_")):
            return

        # Map name suffixes/prefixes to expected return types
        type_hints: list[tuple[list[str], set[type]]] = [
            (['_count', '_total', '_sum', '_size', '_length', '_num'],
             {int, float}),
            (['_name', '_label', '_title', '_text', '_message', '_path'],
             {str}),
            (['_list', '_items', '_entries', '_records'],
             {list}),
            (['_dict', '_map', '_mapping'],
             {dict}),
        ]

        matched_types: set[type] | None = None
        for suffixes, expected in type_hints:
            if any(name_lower.endswith(s) for s in suffixes):
                matched_types = expected
                break

        if matched_types is None:
            return

        returns = self._get_return_values()
        for ret in returns:
            if isinstance(ret, ast.Constant) and ret.value is not None:
                if type(ret.value) not in matched_types:
                    self.observations.append({
                        "tag": "NAI-108",
                        "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                        "func_name": self.func.name,
                        "actual_type": type(ret.value).__name__,
                        "expected_types": [t.__name__ for t in matched_types],
                    })
                    _log.debug("NAI-108 observed: type mismatch in '%s' at line %d", self.func.name, ret.lineno)
                    return

    def _check_opposite_operation(self) -> None:
        """
        NAI-109: Function does opposite of what name suggests.

        Detects: remove_item() that appends, add_item() that removes.
        """
        name_lower = self.func.name.lower()

        # Opposite verb pairs
        opposites: dict[str, set[str]] = {
            'add': {'remove', 'pop', 'discard', 'delete', 'del'},
            'remove': {'append', 'add', 'insert', 'extend', 'push'},
            'delete': {'append', 'add', 'insert', 'create', 'new'},
            'create': {'remove', 'delete', 'destroy', 'drop'},
            'open': {'close'},
            'close': {'open'},
            'start': {'stop', 'end', 'finish'},
            'stop': {'start', 'begin', 'launch'},
            'enable': {'disable'},
            'disable': {'enable'},
            'increment': {'decrement'},
            'decrement': {'increment'},
        }

        matched_verb: str | None = None
        bad_methods: set[str] = set()
        for verb, opposite_methods in opposites.items():
            if verb in name_lower:
                matched_verb = verb
                bad_methods = opposite_methods
                break

        if matched_verb is None:
            return

        # Body-shape fact: an opposite-named call only counts as the
        # function's real action when (a) it sits at the body's top level,
        # unconditional -- not tucked inside try/except/finally/if/for/while
        # as cleanup (close-in-finally, pop-under-if, append-in-a-loop) --
        # and (b) its receiver is a bare local name that a later top-level
        # `return` goes on to hand back, directly or folded into the
        # returned expression, i.e. the mutated object IS the result.
        # Honest rows fail (a) (nested cleanup) or (b) (receiver never
        # becomes what the function returns); the plant does both.
        nested_types = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
                        ast.With, ast.AsyncWith, ast.ExceptHandler)

        top_level_calls: list[tuple[int, ast.Call]] = []
        for idx, stmt in enumerate(self.func.body):
            if isinstance(stmt, nested_types):
                continue
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                        and sub.func.attr in bad_methods:
                    top_level_calls.append((idx, sub))

        for idx, node in top_level_calls:
            receiver = node.func.value  # type: ignore[attr-defined]  # FIX_54 ast-pos
            if not isinstance(receiver, ast.Name):
                continue  # not a bare local, e.g. self._context_stack.close()
            receiver_name = receiver.id

            flows_to_return = False
            for later in self.func.body[idx + 1:]:
                if isinstance(later, ast.Return) and later.value is not None:
                    if any(isinstance(n, ast.Name) and n.id == receiver_name
                           for n in ast.walk(later.value)):
                        flows_to_return = True
                        break
            if not flows_to_return:
                continue

            self.observations.append({
                "tag": "NAI-109",
                "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                "func_name": self.func.name,
                "implied_verb": matched_verb,
                "opposite_method": node.func.attr,  # type: ignore[attr-defined]  # FIX_54 ast-pos
            })
            _log.debug("NAI-109 observed: '%s' calls opposite '.%s()' at line %d", self.func.name, node.func.attr, node.lineno)  # type: ignore[attr-defined]  # FIX_54 ast-pos
            return

    def _check_hardcoded_collection_return(self) -> None:
        """
        NAI-115: Function returns hardcoded collection when name implies dynamic.

        Detects: get_users() returning ["alice", "bob"]
        """
        name_lower = self.func.name.lower()
        dynamic_prefixes = ("get_", "fetch_", "load_", "query_", "find_", "search_",
                            "list_", "read_", "retrieve_")

        if not any(name_lower.startswith(p) for p in dynamic_prefixes):
            return

        params = self._get_param_names()
        returns = self._get_return_values()

        for ret in returns:
            # Hardcoded list/dict with literals
            if isinstance(ret, ast.List) and len(ret.elts) > 0:
                if all(isinstance(e, ast.Constant) for e in ret.elts):
                    self.observations.append({
                        "tag": "NAI-115",
                        "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                        "func_name": self.func.name,
                        "collection_type": "list",
                        "element_count": len(ret.elts),
                    })
                    _log.debug("NAI-115 observed: hardcoded list in '%s' at line %d", self.func.name, ret.lineno)
                    return
            if isinstance(ret, ast.Dict) and len(ret.keys) > 0:
                if all(isinstance(k, ast.Constant) for k in ret.keys if k) and \
                   all(isinstance(v, ast.Constant) for v in ret.values):
                    self.observations.append({
                        "tag": "NAI-115",
                        "line": ret.lineno if hasattr(ret, 'lineno') else self.func.lineno,
                        "func_name": self.func.name,
                        "collection_type": "dict",
                        "key_count": len(ret.keys),
                    })
                    _log.debug("NAI-115 observed: hardcoded dict in '%s' at line %d", self.func.name, ret.lineno)
                    return

    def _check_string_concat_in_loop(self) -> None:
        """
        NAI-116: String concatenation inside loop (performance anti-pattern).

        Pattern: for x in items: result += str(x)
        Should use: ''.join() or list append + join.
        """
        def _is_freshly_rebound_in_loop(loop_node: ast.AST, target_name: str) -> bool:
            """Body-shape fact: True when `target_name` is unconditionally rebound
            somewhere else within this SAME loop -- either by being (part of) the
            loop's own iteration variable, or by a plain (non-augmented) assignment
            to that bare name anywhere in the loop's body. Either shape means each
            pass starts the name from a fresh value rather than carrying an
            ever-growing accumulation forward across iterations -- e.g. a per-part
            tokenizer buffer that gets reset to "" once a part is emitted, or a
            for-loop's own unpacked target reused as scratch space within the pass
            it was just bound in."""
            if isinstance(loop_node, ast.For):
                for n in ast.walk(loop_node.target):
                    if isinstance(n, ast.Name) and n.id == target_name:
                        return True
            for n in ast.walk(loop_node):
                if isinstance(n, ast.Assign) and len(n.targets) == 1:
                    t = n.targets[0]
                    if isinstance(t, ast.Name) and t.id == target_name:
                        return True
            return False

        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                for stmt in ast.walk(node):
                    if isinstance(stmt, ast.AugAssign):
                        if isinstance(stmt.op, ast.Add):
                            target_name = stmt.target.id if isinstance(stmt.target, ast.Name) else "?"
                            if target_name != "?" and _is_freshly_rebound_in_loop(node, target_name):
                                continue
                            # Check if target is being string-concatenated
                            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                                self.observations.append({
                                    "tag": "NAI-116",
                                    "line": stmt.lineno if hasattr(stmt, 'lineno') else self.func.lineno,
                                    "func_name": self.func.name,
                                    "target_var": target_name,
                                    "concat_kind": "literal",
                                })
                                _log.debug("NAI-116 observed: string concat in loop in '%s' at line %d", self.func.name, stmt.lineno)
                                return
                            # += str(x) pattern
                            if isinstance(stmt.value, ast.Call):
                                if isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == 'str':
                                    self.observations.append({
                                        "tag": "NAI-116",
                                        "line": stmt.lineno if hasattr(stmt, 'lineno') else self.func.lineno,
                                        "func_name": self.func.name,
                                        "target_var": target_name,
                                        "concat_kind": "str_call",
                                    })
                                    _log.debug("NAI-116 observed: str() concat in loop in '%s' at line %d", self.func.name, stmt.lineno)
                                    return

    def _check_inconsistent_naming(self) -> None:
        """
        NAI-117: Mixed naming conventions within function (camelCase + snake_case).

        Indicates AI-generated code mixing style conventions.
        """
        import re as _re

        local_names: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if len(name) > 1:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `_` prefix skip removed (owner: lexical prior)
                            local_names.add(name)

        if len(local_names) < 1:  # EXCISED cut 2 (2026-09-05): was `len(local_names) < 3` — EXCISION_LIST class A
            return

        camel_count = 0
        snake_count = 0
        camel_pat = _re.compile(r'^[a-z]+[A-Z][a-zA-Z]*$')
        snake_pat = _re.compile(r'^[a-z]+(_[a-z]+)+$')

        for name in local_names:
            if camel_pat.match(name):
                camel_count += 1
            elif snake_pat.match(name):
                snake_count += 1

        if camel_count >= 1 and snake_count >= 1:  # EXCISED cut 2 (2026-09-05): was `camel_count >= 2 and snake_count >= 2` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-117",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "camel_count": camel_count,
                "snake_count": snake_count,
                "total_locals": len(local_names),
            })
            _log.debug("NAI-117 observed: mixed naming in '%s' (%d camel, %d snake)", self.func.name, camel_count, snake_count)

    def _check_validation_missing_error(self) -> None:
        """
        NAI-118: Validation function with no error/raise path.

        Detects: validate_X() that returns True/False but never raises or reports error.
        """
        name_lower = self.func.name.lower()
        if not name_lower.startswith(('validate', 'verify', 'check_')):
            return

        has_raise = False
        has_error_call = False
        return_count = 0

        for node in ast.walk(self.func):
            if isinstance(node, ast.Raise):
                has_raise = True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('error', 'warning', 'critical', 'exception'):
                        has_error_call = True
                if isinstance(node.func, ast.Name):
                    if node.func.id in ('raise', 'warn', 'warnings'):
                        has_error_call = True
            if isinstance(node, ast.Return):
                return_count += 1

        # If it only returns booleans and never raises/logs errors
        if not has_raise and not has_error_call and return_count > 0:
            returns = self._get_return_values()
            all_bool = all(
                isinstance(r, ast.Constant) and isinstance(r.value, bool)
                for r in returns
            )
            if all_bool and len(returns) >= 2:
                self.observations.append({
                    "tag": "NAI-118",
                    "line": self.func.lineno,
                    "func_name": self.func.name,
                    "return_count": return_count,
                    "has_raise": has_raise,
                    "has_error_call": has_error_call,
                })
                _log.debug("NAI-118 observed: validation '%s' only returns bool, no error path", self.func.name)

    # -----------------------------------------------------------------
    # NAI-110, 111, 112, 119: AI fingerprint / hallucination checks
    # -----------------------------------------------------------------

    def _check_cross_language_confusion(self) -> None:
        """
        NAI-110: Cross-language method calls leaked into Python.

        Detects JS/Java/Ruby syntax: .push(), .length, .equals(), .forEach(),
        .toString(), .indexOf(), .charAt(), .substring(), .toUpperCase(), etc.
        """
        # Map of non-Python methods → (language, Python equivalent)
        CROSS_LANG_METHODS: dict[str, tuple[str, str]] = {
            # JavaScript / Java
            'push': ('JS', '.append()'),
            'forEach': ('JS', 'for loop'),
            'indexOf': ('JS/Java', '.index()'),
            'charAt': ('JS/Java', '[]'),
            'substring': ('JS/Java', '[start:end]'),
            'toString': ('JS/Java', 'str()'),
            'toUpperCase': ('JS', '.upper()'),
            'toLowerCase': ('JS', '.lower()'),
            'parseInt': ('JS', 'int()'),
            'parseFloat': ('JS', 'float()'),
            'equals': ('Java', '=='),
            'compareTo': ('Java', '< > =='),
            'isEmpty': ('Java', 'not x or len(x)==0'),
            'contains': ('Java', 'in operator'),
            'size': ('Java', 'len()'),
            'toArray': ('Java', 'list()'),
            'addAll': ('Java', '.extend()'),
            'putAll': ('Java', '.update()'),
            'keySet': ('Java', '.keys()'),
            'entrySet': ('Java', '.items()'),
            # Ruby
            'each': ('Ruby', 'for loop'),
            'map!': ('Ruby', 'list comprehension'),
            'select': ('Ruby', 'filter()'),
            'reject': ('Ruby', 'filterfalse()'),
            'include?': ('Ruby', 'in operator'),
            'nil?': ('Ruby', 'is None'),
            'to_s': ('Ruby', 'str()'),
            'to_i': ('Ruby', 'int()'),
            'to_f': ('Ruby', 'float()'),
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method = node.func.attr
                # IG-10 (2026-09-06): defined in this module (`self.push`, `ETags.contains`, `snapshot.size`), a stdlib method
                # (`select.select`), or a call on an imported module — a fact, not a leak from another language.
                from .base import STDLIB_METHOD_NAMES
                if method in self.module_attr_names or method in STDLIB_METHOD_NAMES or (
                        isinstance(node.func.value, ast.Name) and node.func.value.id in self.imported_names):
                    continue
                if method in CROSS_LANG_METHODS:
                    lang, python_equiv = CROSS_LANG_METHODS[method]
                    self.observations.append({
                        "tag": "NAI-110",
                        "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                        "func_name": self.func.name,
                        "foreign_method": method,
                        "source_lang": lang,
                        "python_equiv": python_equiv,
                    })
                    _log.debug("NAI-110 observed: '.%s()' (%s) in '%s' at line %d", method, lang, self.func.name, node.lineno)
                    return
            # Also check .length property access (JS/Java)
            if isinstance(node, ast.Attribute) and not isinstance(node.ctx, ast.Store):
                if node.attr == 'length' and 'length' not in self.module_attr_names:   # IG-10: `self.length = …` anywhere in the module is an attribute
                    # Skip if on a known object that actually has .length (e.g., numpy)
                    self.observations.append({
                        "tag": "NAI-110",
                        "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                        "func_name": self.func.name,
                        "foreign_method": "length",
                        "source_lang": "JS/Java",
                        "python_equiv": "len()",
                    })
                    _log.debug("NAI-110 observed: '.length' in '%s' at line %d", self.func.name, node.lineno)
                    return

    def _check_phantom_api_methods(self) -> None:
        """
        NAI-111: Calls to methods that don't exist on known libraries.

        Detects: pd.optimize(), np.autograd(), os.execute(), json.stringify(),
        requests.fetch(), etc.
        """
        # Map of module/alias → set of commonly hallucinated methods
        PHANTOM_METHODS: dict[str, set[str]] = {
            'pd': {'optimize', 'autofit', 'auto_clean', 'smart_merge', 'to_database',
                   'from_api', 'visualize', 'plot_auto', 'clean_data', 'normalize_all'},
            'pandas': {'optimize', 'autofit', 'auto_clean', 'smart_merge', 'to_database'},
            'np': {'autograd', 'auto_reshape', 'smart_array', 'to_tensor',
                   'normalize', 'standardize', 'auto_fill', 'smart_sort'},
            'numpy': {'autograd', 'auto_reshape', 'smart_array', 'to_tensor'},
            'os': {'execute', 'run_command', 'create_file', 'delete_file',
                   'read_file', 'write_file', 'copy_file'},
            'json': {'stringify', 'parse', 'to_string', 'from_string',
                     'encode', 'decode', 'serialize', 'deserialize'},
            'requests': {'fetch', 'download', 'upload', 'send_json',
                         'get_json', 'post_json', 'async_get'},
            'sys': {'execute', 'run', 'get_input', 'read_line'},
            'math': {'round_up', 'round_down', 'clamp', 'lerp',
                     'normalize', 'sigmoid', 'relu'},
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    obj = node.func.value.id
                    method = node.func.attr
                    if obj in PHANTOM_METHODS and method in PHANTOM_METHODS[obj]:
                        self.observations.append({
                            "tag": "NAI-111",
                            "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                            "func_name": self.func.name,
                            "object": obj,
                            "phantom_method": method,
                        })
                        _log.debug("NAI-111 observed: '%s.%s()' in '%s' at line %d", obj, method, self.func.name, node.lineno)
                        return

    def _check_hallucinated_packages(self) -> None:
        """
        NAI-112: Import of packages that don't exist in PyPI/stdlib.

        Detects slopsquatting vectors and AI-invented packages like
        'dataprocessor', 'fileutils', 'stringhelper', etc.
        """
        # Common AI-hallucinated package names (not in PyPI or stdlib)
        FAKE_PACKAGES: set[str] = {
            'dataprocessor', 'data_processor', 'datahelper', 'data_helper',
            'fileutils', 'file_utils', 'filehelper', 'file_helper',
            'stringhelper', 'string_helper', 'stringutils', 'string_utils',
            'mathutils', 'math_utils', 'mathhelper', 'math_helper',
            'dbhelper', 'db_helper', 'dbutils', 'db_utils',
            'apihelper', 'api_helper', 'apiutils', 'api_utils',
            'errorhandler', 'error_handler', 'errorutils', 'error_utils',
            'configmanager', 'config_manager', 'confighelper',
            'loghelper', 'log_helper', 'logutils', 'log_utils',
            'networkutils', 'network_utils', 'nethelper', 'net_helper',
            'webutils', 'web_utils', 'webhelper', 'web_helper',
            'testutils', 'test_utils', 'testhelper', 'test_helper',
            'cachemanager', 'cache_manager', 'cacheutils',
            'securityutils', 'security_utils', 'authhelper', 'auth_helper',
            'validationutils', 'validation_utils',
            'transformutils', 'transform_utils',
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg = alias.name.split('.')[0].lower()
                    if pkg in FAKE_PACKAGES:
                        self.observations.append({
                            "tag": "NAI-112",
                            "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                            "func_name": self.func.name,
                            "package_name": alias.name,
                            "import_style": "import",
                        })
                        _log.debug("NAI-112 observed: hallucinated package '%s' in '%s' at line %d", alias.name, self.func.name, node.lineno)
                        return
            elif isinstance(node, ast.ImportFrom) and node.module:
                pkg = node.module.split('.')[0].lower()
                if pkg in FAKE_PACKAGES:
                    self.observations.append({
                        "tag": "NAI-112",
                        "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                        "func_name": self.func.name,
                        "package_name": node.module,
                        "import_style": "from",
                    })
                    _log.debug("NAI-112 observed: hallucinated package '%s' in '%s' at line %d", node.module, self.func.name, node.lineno)
                    return

    def _check_hedging_comments(self) -> None:
        """
        NAI-119: Hedging language in docstrings/string constants.

        Detects: "hopefully", "should work", "might", "maybe", "probably",
        "I think", "not sure" — AI uncertainty signals.
        """
        HEDGING_PHRASES = [
            'hopefully', 'should work', 'might not', 'maybe',
            'probably', 'i think', 'not sure', 'not certain',
            'could potentially', 'may or may not', 'try to',
            'attempt to', 'best effort', 'workaround',
            'hack', 'kludge', 'band-aid', 'quick fix',
            'this should', 'fingers crossed',
        ]

        # Check docstring
        docstring = ast.get_docstring(self.func)
        if docstring:
            doc_lower = docstring.lower()
            for phrase in HEDGING_PHRASES:
                if phrase in doc_lower:
                    self.observations.append({
                        "tag": "NAI-119",
                        "line": self.func.lineno,
                        "func_name": self.func.name,
                        "hedging_phrase": phrase,
                        "location": "docstring",
                    })
                    _log.debug("NAI-119 observed: hedging '%s' in docstring of '%s'", phrase, self.func.name)
                    return

        # Check inline string constants (comment-like strings)
        for node in ast.walk(self.func):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str) and len(node.value.value) > 0:  # EXCISED cut 2 (2026-09-05): was `isinstance(node.value.value, str) and len(node.value.value) > 10` — EXCISION_LIST class A
                    s_lower = node.value.value.lower()
                    for phrase in HEDGING_PHRASES:
                        if phrase in s_lower:
                            self.observations.append({
                                "tag": "NAI-119",
                                "line": node.lineno if hasattr(node, 'lineno') else self.func.lineno,
                                "func_name": self.func.name,
                                "hedging_phrase": phrase,
                                "location": "inline_string",
                            })
                            _log.debug("NAI-119 observed: hedging '%s' in inline string of '%s'", phrase, self.func.name)
                            return

    async def run_semantic_checks(self) -> list[dict[str, Any]]:
        """Run all semantic analysis checks."""
        self._check_param_return_disconnect()
        await asyncio.sleep(0)  # Yield control

        self._check_magic_number_return()
        self._check_docstring_code_mismatch()
        self._check_boolean_logic_inversion()
        await asyncio.sleep(0)  # Yield control

        self._check_name_operation_mismatch()
        self._check_no_transform_passthrough()
        self._check_missing_normalization()

        await asyncio.sleep(0)  # Yield control

        # Additional semantic checks
        self._check_return_type_name_mismatch()
        self._check_opposite_operation()
        self._check_hardcoded_collection_return()
        self._check_string_concat_in_loop()
        self._check_inconsistent_naming()
        self._check_validation_missing_error()

        await asyncio.sleep(0)  # Yield control

        # AI fingerprint / hallucination checks
        self._check_cross_language_confusion()
        self._check_phantom_api_methods()
        self._check_hallucinated_packages()
        self._check_hedging_comments()

        return self.observations
