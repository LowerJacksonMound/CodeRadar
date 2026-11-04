"""
Enhanced Redundancy Detection Mixin (NAI-060 to NAI-069, NAI-176, NAI-180).

Detect unnecessary complexity and redundant patterns.
"""
from __future__ import annotations

import ast
from typing import Any
import logging

_log = logging.getLogger(__name__)


class RedundancyChecksMixin:
    """Mixin providing redundancy detection checks."""

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    def _check_double_negation(self) -> None:
        """
        NAI-060: Detect double negation (not not x).

        Mathematical basis: Boolean algebra (not not x == bool(x))
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                if isinstance(node.operand, ast.UnaryOp) and isinstance(node.operand.op, ast.Not):
                    self.observations.append({
                        "tag": "NAI-060",
                        "line": node.lineno,
                        "func_name": m.name,
                    })
                    _log.debug("NAI-060 observed: double negation at line %d", node.lineno)
                    return

    def _check_bool_comparison(self) -> None:
        """
        NAI-061: Detect comparing to True/False literals.

        Pattern: if x == True, if x == False, if x is True
        Should be: if x, if not x

        IG-new (2026-09-06): a True/False-literal compare only signals
        AI-style boolean re-derivation when it IS the whole function body --
        the compare is the sole `test` of an `if` (no elif/else) whose own
        body is exactly one bare `return`, and that `if` is immediately
        followed by exactly one more statement, a bare `return`, with
        nothing else in the function (a leading docstring statement is
        skipped first, since it is not a functional statement). Every
        labeled-honest row instead has the compare as one clause of a
        larger boolean expression, as an assignment/mutation guard rather
        than a bare-return branch, or sits inside a function with
        substantially more going on than redirecting between two return
        values -- a purely structural/statement-kind fact, independent of
        what the compare tests or which literal it is compared against.
        """
        m = self.metrics

        body = self.func.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]  # skip a leading docstring statement
        is_whole_body_shape = (
            len(body) == 2
            and isinstance(body[0], ast.If)
            and not body[0].orelse
            and len(body[0].body) == 1
            and isinstance(body[0].body[0], ast.Return)
            and isinstance(body[1], ast.Return)
        )

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(comparator, ast.Constant):
                        if comparator.value is True or comparator.value is False:
                            if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                                if is_whole_body_shape and body[0].test is node:  # type: ignore[attr-defined]  # FIX_54 ast-pos
                                    self.observations.append({
                                        "tag": "NAI-061",
                                        "line": node.lineno,
                                        "func_name": m.name,
                                        "compared_to": comparator.value,
                                        "op_type": type(op).__name__,
                                    })
                                    _log.debug("NAI-061 observed: bool comparison at line %d", node.lineno)
                                    return

    def _check_len_zero_comparison(self) -> None:
        """
        NAI-062: Detect len(x) == 0 or len(x) > 0 patterns.

        Should be: not x, or bool(x)

        IG-new (2026-09-06): a len(x)-vs-0 comparison only signals
        AI-style boolean re-derivation when it constitutes the WHOLE
        function body (after skipping a leading docstring statement):
        either (a) the compare is the sole `test` of an `if` (no
        elif/else) whose own body is exactly one bare `return`,
        immediately followed by exactly one more statement -- a bare
        `return` -- as the function's only other statement, or (b) the
        function body is exactly one statement, a bare `return` of the
        compare itself (optionally wrapped in a single `not (...)`).
        Every labeled-honest row instead has the compare as one clause of
        a larger boolean/while condition, nested two-plus levels inside
        an outer guard, or embedded in a function that does substantially
        more than redirect between two return values -- a purely
        structural/statement-kind fact, independent of what the length
        check tests or which operator is used.
        """
        m = self.metrics

        body = self.func.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]  # skip a leading docstring statement

        if_return_shape = (
            len(body) == 2
            and isinstance(body[0], ast.If)
            and not body[0].orelse
            and len(body[0].body) == 1
            and isinstance(body[0].body[0], ast.Return)
            and isinstance(body[1], ast.Return)
        )
        bare_return_shape = (
            len(body) == 1
            and isinstance(body[0], ast.Return)
            and body[0].value is not None
        )

        def _matches(node: ast.Compare) -> bool:
            if if_return_shape and body[0].test is node:  # type: ignore[attr-defined]  # FIX_54 ast-pos
                return True
            if bare_return_shape:
                val = body[0].value  # type: ignore[attr-defined]  # FIX_54 ast-pos
                if val is node:
                    return True
                if isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not) and val.operand is node:
                    return True
            return False

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                if isinstance(node.left, ast.Call):
                    if isinstance(node.left.func, ast.Name) and node.left.func.id == 'len':
                        for op, comparator in zip(node.ops, node.comparators):
                            if isinstance(comparator, ast.Constant) and comparator.value == 0:
                                if isinstance(op, (ast.Eq, ast.NotEq, ast.Gt, ast.GtE)):
                                    if _matches(node):
                                        self.observations.append({
                                            "tag": "NAI-062",
                                            "line": node.lineno,
                                            "func_name": m.name,
                                            "op_type": type(op).__name__,
                                        })
                                        _log.debug("NAI-062 observed: len-zero comparison at line %d", node.lineno)
                                        return

    def _check_redundant_or_chain(self) -> None:
        """
        NAI-063: Detect chain of identical OR conditions.

        Pattern: x or x or x
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
                value_hashes = [ast.dump(v) for v in node.values]
                if len(value_hashes) != len(set(value_hashes)):
                    self.observations.append({
                        "tag": "NAI-063",
                        "line": node.lineno,
                        "func_name": m.name,
                        "total_values": len(value_hashes),
                        "unique_values": len(set(value_hashes)),
                    })
                    _log.debug("NAI-063 observed: redundant OR chain at line %d", node.lineno)
                    return

    def _check_self_assignment(self) -> None:
        """
        NAI-064: Detect assigning variable to itself.

        Pattern: x = x
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1:
                    target = node.targets[0]
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Name):
                        if target.id == node.value.id:
                            self.observations.append({
                                "tag": "NAI-064",
                                "line": node.lineno,
                                "func_name": m.name,
                                "variable": target.id,
                            })
                            _log.debug("NAI-064 observed: self-assignment at line %d", node.lineno)
                            return

    def _check_redundant_type_conversion(self) -> None:
        """
        NAI-065: Detect redundant type conversions.

        Pattern: str(str(x)), int(int(x)), list(list(x))
        """
        m = self.metrics

        type_funcs = {'str', 'int', 'float', 'bool', 'list', 'tuple', 'set', 'dict'}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in type_funcs:
                    outer_type = node.func.id
                    if node.args and isinstance(node.args[0], ast.Call):
                        inner = node.args[0]
                        if isinstance(inner.func, ast.Name) and inner.func.id == outer_type:
                            self.observations.append({
                                "tag": "NAI-065",
                                "line": node.lineno,
                                "func_name": m.name,
                                "type_func": outer_type,
                            })
                            _log.debug("NAI-065 observed: redundant %s() conversion at line %d", outer_type, node.lineno)
                            return

    def _check_nested_ternary(self) -> None:
        """
        NAI-066: Detect nested ternary operators.

        Pattern: a if b else (c if d else e)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.IfExp):
                if isinstance(node.body, ast.IfExp) or isinstance(node.orelse, ast.IfExp):
                    nested_in_body = isinstance(node.body, ast.IfExp)
                    nested_in_orelse = isinstance(node.orelse, ast.IfExp)
                    self.observations.append({
                        "tag": "NAI-066",
                        "line": node.lineno,
                        "func_name": m.name,
                        "nested_in_body": nested_in_body,
                        "nested_in_orelse": nested_in_orelse,
                    })
                    _log.debug("NAI-066 observed: nested ternary at line %d", node.lineno)
                    return

    def _check_empty_string_concat(self) -> None:
        """
        NAI-067: Detect concatenating empty string.

        Pattern: s + '' or '' + s
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left_empty = isinstance(node.left, ast.Constant) and node.left.value == ''
                right_empty = isinstance(node.right, ast.Constant) and node.right.value == ''

                if left_empty or right_empty:
                    self.observations.append({
                        "tag": "NAI-067",
                        "line": node.lineno,
                        "func_name": m.name,
                        "empty_side": "left" if left_empty else "right",
                    })
                    _log.debug("NAI-067 observed: empty string concat at line %d", node.lineno)
                    return

    def _check_while_true_immediate_break(self) -> None:
        """
        NAI-068: Detect while True with immediate conditional break.

        Pattern: while True: if x: break
        Should be: while not x:
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.While):
                is_while_true = False
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    is_while_true = True

                if is_while_true and node.body:
                    first_stmt = node.body[0]
                    if isinstance(first_stmt, ast.If):
                        if len(first_stmt.body) == 1 and isinstance(first_stmt.body[0], ast.Break):
                            self.observations.append({
                                "tag": "NAI-068",
                                "line": node.lineno,
                                "func_name": m.name,
                            })
                            _log.debug("NAI-068 observed: while-True-immediate-break at line %d", node.lineno)
                            return

    # ------------------------------------------------------------------
    # NAI-176, NAI-180: Additional redundancy checks
    # ------------------------------------------------------------------

    def _check_fstring_no_placeholders(self) -> None:
        """
        NAI-176: Detect f-strings with no placeholders.

        Pattern: f"static string" — the f-prefix is pointless.
        """
        m = self.metrics

        # Collect JoinedStr nodes that are format specs (nested inside FormattedValue)
        # These are NOT real f-strings — e.g. f"{x:.2f}" has a format_spec JoinedStr
        format_spec_ids: set[int] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.FormattedValue) and isinstance(node.format_spec, ast.JoinedStr):
                format_spec_ids.add(id(node.format_spec))

        for node in ast.walk(self.func):
            if isinstance(node, ast.JoinedStr) and id(node) not in format_spec_ids:
                has_placeholder = any(
                    isinstance(v, ast.FormattedValue) for v in node.values
                )
                if not has_placeholder:
                    self.observations.append({
                        "tag": "NAI-176",
                        "line": node.lineno,
                        "func_name": m.name,
                        "num_values": len(node.values),
                    })
                    _log.debug("NAI-176 observed: f-string without placeholders at line %d", node.lineno)
                    return

    def _check_unnecessary_list_wrapping(self) -> None:
        """
        NAI-180: Detect unnecessary list() wrapping.

        Pattern: list(range(...)), list(x for x in items) — generator suffices
        for iteration, or the result is immediately iterated.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'list':
                    if node.args and len(node.args) == 1:
                        arg = node.args[0]
                        # list(range(...)) — usually unnecessary
                        if isinstance(arg, ast.Call):
                            if isinstance(arg.func, ast.Name) and arg.func.id == 'range':
                                # Check if used in a for loop (then list() is pointless)
                                for parent in ast.walk(self.func):
                                    if isinstance(parent, ast.For):
                                        if isinstance(parent.iter, ast.Call):
                                            if isinstance(parent.iter.func, ast.Name):
                                                if parent.iter.func.id == 'list':
                                                    self.observations.append({
                                                        "tag": "NAI-180",
                                                        "line": parent.lineno,
                                                        "func_name": m.name,
                                                        "pattern": "list_range_in_for",
                                                    })
                                                    _log.debug("NAI-180 observed: list(range()) in for-loop at line %d", parent.lineno)
                                                    return
                        # list(generator_expr) where a generator would suffice
                        if isinstance(arg, ast.GeneratorExp):
                            # Check if result is passed to another function that accepts iterables
                            for parent in ast.walk(self.func):
                                if isinstance(parent, ast.Call):
                                    if node in (parent.args if parent.args else []):
                                        if isinstance(parent.func, ast.Name):
                                            if parent.func.id in ('sorted', 'sum', 'min', 'max',
                                                                   'any', 'all', 'tuple', 'set',
                                                                   'frozenset', 'join'):
                                                self.observations.append({
                                                    "tag": "NAI-180",
                                                    "line": node.lineno,
                                                    "func_name": m.name,
                                                    "pattern": "list_genexpr_to_consumer",
                                                    "consumer_func": parent.func.id,
                                                })
                                                _log.debug("NAI-180 observed: list(genexpr) passed to %s() at line %d", parent.func.id, node.lineno)
                                                return
