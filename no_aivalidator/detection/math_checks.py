"""
Mathematical Detection Mixin (NAI-030 to NAI-039).

Graph theory, set operations, symbolic equality - NO thresholds.
Uses mathematical proofs rather than heuristics.
"""
from __future__ import annotations

import ast
from typing import Any
import logging

from .evidence_lines import dead_value_lines, unused_param_lines

_log = logging.getLogger(__name__)


class MathChecksMixin:
    """Mixin providing mathematical AI fake detection checks."""

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    def _check_data_flow_disconnect(self) -> None:
        """
        NAI-030: Graph-based data flow analysis.

        Build a dependency graph where nodes are variables, edges are data flow.
        Check if every input parameter reaches at least one output.

        Mathematical basis: Graph reachability (DFS) + Set intersection
        """
        m = self.metrics

        effective_params = m.params_declared - {'self', 'cls'}
        if not effective_params:
            return

        if m.name in ('__init__', '__new__', '__del__', '__exit__', '__enter__'):
            return
        if m.name.startswith('__') and m.name.endswith('__'):
            return

        flows_to: dict[str, set[str]] = {p: set() for p in effective_params}
        output_sources: set[str] = set()

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_name = target.id
                        for sub in ast.walk(node.value):
                            if isinstance(sub, ast.Name):
                                source = sub.id
                                if source not in flows_to:
                                    flows_to[source] = set()
                                flows_to[source].add(target_name)

            if isinstance(node, ast.Return) and node.value:
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Name):
                        output_sources.add(sub.id)

            if isinstance(node, ast.Yield) and node.value:
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Name):
                        output_sources.add(sub.id)

        reachable = set(output_sources)
        changed = True
        while changed:
            changed = False
            for var, targets in flows_to.items():
                if targets & reachable:
                    if var not in reachable:
                        reachable.add(var)
                        changed = True

        disconnected = effective_params - reachable - m.params_used
        # Hardened 2026-09-05: `_x` / `ignored_x` / `unused_x` are declared-unused
        # by convention (pylint ignored-argument-names, ruff dummy-variable-rgx).
        disconnected = {p for p in disconnected
                        if not (p.startswith('_') or p.startswith('ignored_') or p.startswith('unused_'))}

        if disconnected and m.returns > 0:
            call_args: set[str] = set()
            for node in ast.walk(self.func):
                if isinstance(node, ast.Call):
                    for arg in node.args:
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Name):
                                call_args.add(sub.id)

            truly_disconnected = disconnected - call_args
            if truly_disconnected:
                # Calibration 2026-10-08 (owner): explicitly `del`-ed params are variant "deleted" (context by table).
                deleted = {t.id for n in ast.walk(self.func) if isinstance(n, ast.Delete)
                           for t in n.targets if isinstance(t, ast.Name)}
                obs = {
                    "tag": "NAI-030",
                    "line": self.func.lineno,
                    "func_name": m.name,
                    "disconnected_params": sorted(truly_disconnected),
                    "lines": unused_param_lines(self.func, truly_disconnected),
                    "total_params": sorted(effective_params),
                }
                if truly_disconnected <= deleted:
                    obs["variant"] = "deleted"
                self.observations.append(obs)
                _log.debug("NAI-030 observed: data flow disconnect for params %s at line %d", sorted(truly_disconnected), self.func.lineno)

    def _check_variable_liveness(self) -> None:
        """
        NAI-031: Variable liveness analysis for dead stores.

        Mathematical basis: Set operations (gen/kill sets)
        A variable is dead if assigned but never read afterward.
        """
        m = self.metrics

        assignments: list[tuple[str, ast.AST]] = []
        reads: set[str] = set()

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments.append((target.id, node))
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    assignments.append((node.target.id, node))
                    reads.add(node.target.id)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                reads.add(node.id)

        assigned_vars = {name for name, _ in assignments}
        dead_stores = assigned_vars - reads - m.params_declared
        dead_stores -= {'_', '__'}
        dead_stores -= {v for v in dead_stores if v.startswith('_unused')}

        # Exclude global/nonlocal declarations — these write to outer scope intentionally
        for node in ast.walk(self.func):
            if isinstance(node, ast.Global):
                dead_stores -= set(node.names)
            elif isinstance(node, ast.Nonlocal):
                dead_stores -= set(node.names)

        if dead_stores:
            self.observations.append({
                "tag": "NAI-031",
                "line": self.func.lineno,
                "func_name": m.name,
                "dead_vars": sorted(dead_stores),
                "lines": dead_value_lines(self.func, dead_stores),
                "assigned_vars": sorted(assigned_vars),
                "read_vars": sorted(reads & assigned_vars),
            })
            _log.debug("NAI-031 observed: dead stores %s at line %d", sorted(dead_stores), self.func.lineno)

    def _check_algebraic_identity(self) -> None:
        """
        NAI-032: Detect algebraic expressions that simplify to identity.

        Mathematical basis: Symbolic normalization + equality
        Patterns: x + 0, x * 1, x / 1, x - 0
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.BinOp):
                if isinstance(node.op, ast.Add):
                    if self._is_zero(node.left) or self._is_zero(node.right):
                        self.observations.append({
                            "tag": "NAI-032",
                            "line": node.lineno,
                            "identity_type": "add_zero",
                        })
                        _log.debug("NAI-032 observed: algebraic identity (add zero) at line %d", node.lineno)
                        return

                if isinstance(node.op, ast.Sub):
                    if self._is_zero(node.right):
                        self.observations.append({
                            "tag": "NAI-032",
                            "line": node.lineno,
                            "identity_type": "sub_zero",
                        })
                        _log.debug("NAI-032 observed: algebraic identity (sub zero) at line %d", node.lineno)
                        return

                if isinstance(node.op, ast.Mult):
                    if self._is_one(node.left) or self._is_one(node.right):
                        self.observations.append({
                            "tag": "NAI-032",
                            "line": node.lineno,
                            "identity_type": "mul_one",
                        })
                        _log.debug("NAI-032 observed: algebraic identity (mul one) at line %d", node.lineno)
                        return

                if isinstance(node.op, ast.Div):
                    if self._is_one(node.right):
                        self.observations.append({
                            "tag": "NAI-032",
                            "line": node.lineno,
                            "identity_type": "div_one",
                        })
                        _log.debug("NAI-032 observed: algebraic identity (div one) at line %d", node.lineno)
                        return

    def _is_zero(self, node: ast.AST) -> bool:
        """Check if node is literal zero."""
        if isinstance(node, ast.Constant):
            return node.value == 0
        if hasattr(ast, 'Num') and isinstance(node, ast.Num):
            return node.n == 0
        return False

    def _is_one(self, node: ast.AST) -> bool:
        """Check if node is literal one."""
        if isinstance(node, ast.Constant):
            return node.value == 1
        if hasattr(ast, 'Num') and isinstance(node, ast.Num):
            return node.n == 1
        return False

    def _check_comprehension_identity(self) -> None:
        """
        NAI-033: Detect identity comprehensions.

        Patterns: [x for x in lst], {x for x in s}
        Mathematical basis: Exact AST equality (element == loop var)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.ListComp):
                if len(node.generators) == 1:
                    gen = node.generators[0]
                    if isinstance(gen.target, ast.Name) and isinstance(node.elt, ast.Name):
                        if gen.target.id == node.elt.id and not gen.ifs:
                            self.observations.append({
                                "tag": "NAI-033",
                                "line": node.lineno,
                                "comp_type": "list",
                                "loop_var": gen.target.id,
                            })
                            _log.debug("NAI-033 observed: identity list comprehension at line %d", node.lineno)
                            return

            if isinstance(node, ast.SetComp):
                if len(node.generators) == 1:
                    gen = node.generators[0]
                    if isinstance(gen.target, ast.Name) and isinstance(node.elt, ast.Name):
                        if gen.target.id == node.elt.id and not gen.ifs:
                            self.observations.append({
                                "tag": "NAI-033",
                                "line": node.lineno,
                                "comp_type": "set",
                                "loop_var": gen.target.id,
                            })
                            _log.debug("NAI-033 observed: identity set comprehension at line %d", node.lineno)
                            return

    def _check_docstring_only_body(self) -> None:
        """
        NAI-034: Detect functions with only a docstring.

        Mathematical basis: Exact count (body == 1 docstring)
        """
        m = self.metrics
        body = self.func.body

        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, ast.Expr):
                if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                    self.observations.append({
                        "tag": "NAI-034",
                        "line": self.func.lineno,
                        "func_name": m.name,
                        "body_len": 1,
                    })
                    _log.debug("NAI-034 observed: docstring-only body in '%s' at line %d", m.name, self.func.lineno)

    def _check_dunder_fakes(self) -> None:
        """
        NAI-035: Detect fake dunder implementations.

        Patterns: __eq__ always True, __hash__ constant, __len__ constant
        Mathematical basis: Exact AST matching
        """
        m = self.metrics

        if not m.name.startswith('__') or not m.name.endswith('__'):
            return

        returns_literal = None
        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Constant):
                    returns_literal = node.value.value
                    break

        if returns_literal is None:
            return

        if m.name == '__eq__' and returns_literal is True:
            self.observations.append({
                "tag": "NAI-035",
                "line": self.func.lineno,
                "dunder": "__eq__",
                "constant_value": True,
            })
            _log.debug("NAI-035 observed: fake __eq__ (always True) at line %d", self.func.lineno)

        if m.name == '__hash__' and isinstance(returns_literal, int):
            self.observations.append({
                "tag": "NAI-035",
                "line": self.func.lineno,
                "dunder": "__hash__",
                "constant_value": returns_literal,
            })
            _log.debug("NAI-035 observed: fake __hash__ (constant %d) at line %d", returns_literal, self.func.lineno)

        if m.name == '__bool__' and isinstance(returns_literal, bool):
            if m.comparisons == 0 and m.branches == 0:
                self.observations.append({
                    "tag": "NAI-035",
                    "line": self.func.lineno,
                    "dunder": "__bool__",
                    "constant_value": returns_literal,
                })
                _log.debug("NAI-035 observed: fake __bool__ (always %s) at line %d", returns_literal, self.func.lineno)

        if m.name == '__len__' and isinstance(returns_literal, int):
            self.observations.append({
                "tag": "NAI-035",
                "line": self.func.lineno,
                "dunder": "__len__",
                "constant_value": returns_literal,
            })
            _log.debug("NAI-035 observed: fake __len__ (constant %d) at line %d", returns_literal, self.func.lineno)

    def _check_redundant_comparisons(self) -> None:
        """
        NAI-036: Detect tautological comparisons.

        Patterns: x == x (always True), x != x (always False)
        Mathematical basis: Exact AST equality via dump
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                left_dump = ast.dump(node.left)
                for op, comparator in zip(node.ops, node.comparators):
                    right_dump = ast.dump(comparator)
                    if left_dump == right_dump:
                        if isinstance(op, ast.Eq):
                            self.observations.append({
                                "tag": "NAI-036",
                                "line": node.lineno,
                                "op": "eq",
                                "expr_dump": left_dump,
                            })
                            _log.debug("NAI-036 observed: tautology (x == x) at line %d", node.lineno)
                            return
                        elif isinstance(op, ast.NotEq):
                            self.observations.append({
                                "tag": "NAI-036",
                                "line": node.lineno,
                                "op": "ne",
                                "expr_dump": left_dump,
                            })
                            _log.debug("NAI-036 observed: tautology (x != x) at line %d", node.lineno)
                            return
        # owner 2026-10-07 (blind tree 1 L2, M-90): `x or not x` is always True and `x and not x` always False — the
        # test a constant fake hides behind (`return 85 if computed or not computed else …`)
        for node in ast.walk(self.func):
            if isinstance(node, ast.BoolOp):
                plain = {ast.dump(v) for v in node.values if not (isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not))}
                negated = {ast.dump(v.operand) for v in node.values
                           if isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not)}
                # `True or x` is always True, `False and x` always False — a literal that decides the whole test
                lit = [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, bool)]
                if (isinstance(node.op, ast.Or) and True in lit) or (isinstance(node.op, ast.And) and False in lit):
                    self.observations.append({
                        "tag": "NAI-036", "line": node.lineno,
                        "op": "or_not" if isinstance(node.op, ast.Or) else "and_not",
                        "expr_dump": "literal " + ("True or" if isinstance(node.op, ast.Or) else "False and"),
                    })
                    return
                if plain & negated:
                    always = isinstance(node.op, ast.Or)
                    self.observations.append({
                        "tag": "NAI-036",
                        "line": node.lineno,
                        "op": "or_not" if always else "and_not",
                        "expr_dump": sorted(plain & negated)[0],
                    })
                    _log.debug("NAI-036 observed: tautology (x %s not x) at line %d",
                               "or" if always else "and", node.lineno)
                    return

    def _check_loop_overwrite_pattern(self) -> None:
        """
        NAI-037: Detect loops that overwrite without accumulation.

        Pattern: for x in items: result = x
        Mathematical basis: Set tracking (no cumulative modification)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                loop_assigns: dict[str, int] = {}
                loop_aug_assigns: set[str] = set()
                loop_methods: set[str] = set()
                # body-shape fact (NAI-037): the counterfeit assigns the variable
                # UNCONDITIONALLY at the loop body's own top level (a direct
                # statement of node.body, not nested in an If/Try/With/except/
                # nested loop). Honest "any-flag" / "last-match" idioms assign the
                # same variable NESTED under a conditional; a variable with even
                # one nested (non-top-level) assign is excluded from this pass.
                top_level_ids = {id(s) for s in node.body}
                assign_all_top_level: dict[str, bool] = {}

                has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
                if has_break:
                    continue

                # Track all variable reads (Load context) inside the loop
                loop_reads: set[str] = set()

                for stmt in ast.walk(node):
                    if isinstance(stmt, ast.Assign):
                        is_top_level = id(stmt) in top_level_ids
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                loop_assigns[target.id] = loop_assigns.get(target.id, 0) + 1
                                prior = assign_all_top_level.get(target.id, True)
                                assign_all_top_level[target.id] = prior and is_top_level
                        # Track variable reads in assignment value and targets
                        # (e.g., `ngrams[gram] = ...` reads `gram` as subscript)
                        for read_node in ast.walk(stmt):
                            if isinstance(read_node, ast.Name) and isinstance(read_node.ctx, ast.Load):
                                loop_reads.add(read_node.id)

                    elif isinstance(stmt, ast.AugAssign):
                        if isinstance(stmt.target, ast.Name):
                            loop_aug_assigns.add(stmt.target.id)

                    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        if isinstance(stmt.value.func, ast.Attribute):
                            if isinstance(stmt.value.func.value, ast.Name):
                                loop_methods.add(stmt.value.func.value.id)

                    # Track reads in all other expressions (function args, conditions, etc.)
                    if isinstance(stmt, ast.Name) and isinstance(stmt.ctx, ast.Load):
                        loop_reads.add(stmt.id)

                for var in loop_assigns:
                    if (var not in loop_aug_assigns and var not in loop_methods
                            and var not in loop_reads and assign_all_top_level.get(var, False)):
                        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                            if var == node.target.id:
                                continue
                        if var.startswith('_'):
                            continue

                        self.observations.append({
                            "tag": "NAI-037",
                            "line": node.lineno,
                            "func_name": m.name,
                            "overwritten_var": var,
                            "loop_type": "for" if isinstance(node, ast.For) else "while",
                        })
                        _log.debug("NAI-037 observed: loop overwrite of '%s' at line %d", var, node.lineno)
                        return

    def _check_constant_conditional(self) -> None:
        """
        NAI-038: Constant conditional expression.

        Pattern: if True:, if False:, if 1:, if 0:
        Mathematical basis: Boolean constant folding — condition is statically known.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Constant):
                    if isinstance(test.value, (bool, int)):
                        val = bool(test.value)
                        self.observations.append({
                            "tag": "NAI-038",
                            "line": node.lineno,
                            "func_name": m.name,
                            "literal_value": test.value,
                            "bool_result": val,
                        })
                        _log.debug("NAI-038 observed: constant conditional (if %s) at line %d", test.value, node.lineno)
                        return
