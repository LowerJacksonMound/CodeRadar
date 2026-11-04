"""
Structural Checks Mixin (NAI-026 to NAI-029, NAI-171).

Detects structural patterns that indicate AI-generated counterfeit code:
- Identical branches
- Mutation theater
- Unreachable code
- Constant conditions
- Inverse operations
- Loop else without break
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any
import logging

_log = logging.getLogger(__name__)


class StructuralChecksMixin:
    """Mixin providing structural AI fake detection checks."""

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    def _check_identical_branches(self) -> None:
        """
        NAI-026: If/else branches with identical code.

        Invariant: Branches should lead to different outcomes.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.If) and node.orelse:
                # Skip elif chains
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    continue

                try:
                    if_hash = hashlib.md5(ast.dump(ast.Module(body=node.body, type_ignores=[])).encode()).hexdigest()
                    else_hash = hashlib.md5(ast.dump(ast.Module(body=node.orelse, type_ignores=[])).encode()).hexdigest()

                    if if_hash == else_hash:
                        self.observations.append({
                            "tag": "NAI-026",
                            "line": node.lineno,
                            "variant": "identical_branches",
                            "branch_hash": if_hash,
                        })
                        _log.debug("NAI-026 observed: identical branches at line %d", node.lineno)
                        return
                except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                    _log.warning("reported, not swallowed (cut 3): %s: %r", '_check_identical_branches', _e)
                    pass

    def _check_mutation_theater(self) -> None:
        """
        NAI-027: Functions that mutate local copies, not the input.

        Invariant: Mutations should affect returned/referenced data.
        """
        m = self.metrics

        local_empties: set[str] = set()

        for node in self.func.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node.value, ast.List) and len(node.value.elts) == 0:
                            local_empties.add(target.id)
                        elif isinstance(node.value, ast.Dict) and len(node.value.keys) == 0:
                            local_empties.add(target.id)
                        elif isinstance(node.value, ast.Set) and len(node.value.elts) == 0:
                            local_empties.add(target.id)
                        elif isinstance(node.value, ast.Call):
                            if isinstance(node.value.func, ast.Name):
                                if node.value.func.id in ('list', 'dict', 'set') and not node.value.args:
                                    local_empties.add(target.id)

        if local_empties:
            param_names = {arg.arg for arg in self.func.args.args if arg.arg not in ('self', 'cls')}

            for node in self.func.body:
                if isinstance(node, ast.Return) and node.value:
                    if isinstance(node.value, ast.Name):
                        if node.value.id in param_names:
                            for child in ast.walk(self.func):
                                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                                    if child.func.attr in ('append', 'extend', 'add', 'update'):
                                        if isinstance(child.func.value, ast.Name):
                                            if child.func.value.id in local_empties:
                                                self.observations.append({
                                                    "tag": "NAI-027",
                                                    "line": child.lineno,
                                                    "mutated_local": child.func.value.id,
                                                    "mutation_method": child.func.attr,
                                                    "returned_param": node.value.id,
                                                })
                                                _log.debug("NAI-027 observed: mutation theater at line %d", child.lineno)
                                                return

    def _check_unreachable_code(self) -> None:
        """
        NAI-028: Code after unconditional return/raise.

        Invariant: All code should be reachable.
        """
        m = self.metrics

        for i, node in enumerate(self.func.body):
            if isinstance(node, (ast.Return, ast.Raise)) and not isinstance(node, ast.If):
                if i < len(self.func.body) - 1:
                    remaining = self.func.body[i + 1:]
                    meaningful = [s for s in remaining if not (
                        isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                    )]
                    if meaningful:
                        self.observations.append({
                            "tag": "NAI-028",
                            "line": node.lineno,
                            "terminal_type": type(node).__name__,
                            "unreachable_count": len(meaningful),
                        })
                        _log.debug("NAI-028 observed: unreachable code after line %d", node.lineno)
                        return

    def _check_constant_conditions(self) -> None:
        """
        NAI-029: Conditions that are always true or false.

        Invariant: Conditions should be dynamic.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Constant):
                    if node.test.value is True:
                        self.observations.append({
                            "tag": "NAI-029",
                            "line": node.lineno,
                            "constant_value": True,
                        })
                        _log.debug("NAI-029 observed: constant True condition at line %d", node.lineno)
                    elif node.test.value is False:
                        self.observations.append({
                            "tag": "NAI-029",
                            "line": node.lineno,
                            "constant_value": False,
                        })
                        _log.debug("NAI-029 observed: constant False condition at line %d", node.lineno)

    def _check_inverse_operations(self) -> None:
        """
        NAI-026: Detect operations that cancel each other out.

        Patterns detected:
        - x = a * b; x = x / b
        - x += y; x -= y
        - self.x += y; self.x -= y
        """
        m = self.metrics

        def get_target_name(target: ast.AST) -> str | None:
            """Get a canonical name for assignment target."""
            if isinstance(target, ast.Name):
                return target.id
            elif isinstance(target, ast.Attribute):
                if isinstance(target.value, ast.Name):
                    return f"{target.value.id}.{target.attr}"
            return None

        var_operations: dict[str, list[tuple[str, str]]] = {}

        for node in ast.walk(self.func):
            if isinstance(node, ast.AugAssign):
                var_name = get_target_name(node.target)
                if var_name:
                    value_repr = ast.dump(node.value)

                    if isinstance(node.op, ast.Add):
                        op = '+'
                    elif isinstance(node.op, ast.Sub):
                        op = '-'
                    elif isinstance(node.op, ast.Mult):
                        op = '*'
                    elif isinstance(node.op, ast.Div):
                        op = '/'
                    else:
                        continue

                    if var_name not in var_operations:
                        var_operations[var_name] = []
                    var_operations[var_name].append((op, value_repr))

            elif isinstance(node, ast.Assign):
                if len(node.targets) == 1:
                    var_name = get_target_name(node.targets[0])
                    if not var_name:
                        continue

                    if isinstance(node.value, ast.BinOp):
                        left_name: str | None = None
                        if isinstance(node.value.left, ast.Name):
                            left_name = node.value.left.id
                        elif isinstance(node.value.left, ast.Attribute):
                            if isinstance(node.value.left.value, ast.Name):
                                left_name = f"{node.value.left.value.id}.{node.value.left.attr}"

                        if left_name == var_name:
                            value_repr = ast.dump(node.value.right)

                            if isinstance(node.value.op, ast.Add):
                                op = '+'
                            elif isinstance(node.value.op, ast.Sub):
                                op = '-'
                            elif isinstance(node.value.op, ast.Mult):
                                op = '*'
                            elif isinstance(node.value.op, ast.Div):
                                op = '/'
                            else:
                                continue

                            if var_name not in var_operations:
                                var_operations[var_name] = []
                            var_operations[var_name].append((op, value_repr))

        inverse_pairs = {
            ('+', '-'): 'add then subtract',
            ('-', '+'): 'subtract then add',
            ('*', '/'): 'multiply then divide',
            ('/', '*'): 'divide then multiply',
        }

        for var_name, ops in var_operations.items():
            if len(ops) >= 2:
                for i in range(len(ops) - 1):
                    op1, val1 = ops[i]
                    op2, val2 = ops[i + 1]

                    if val1 == val2:
                        pair = (op1, op2)
                        if pair in inverse_pairs:
                            self.observations.append({
                                "tag": "NAI-026",
                                "line": getattr(self.func, 'lineno', 0),
                                "variant": "inverse_same_value",
                                "var_name": var_name,
                                "op_pair": pair,
                                "description": inverse_pairs[pair],
                            })
                            _log.debug("NAI-026 observed: inverse ops on %s", var_name)
                            return

                for i in range(len(ops) - 1):
                    op1, _ = ops[i]
                    op2, _ = ops[i + 1]
                    pair = (op1, op2)

                    if pair in inverse_pairs and '.' in var_name:
                        self.observations.append({
                            "tag": "NAI-026",
                            "line": getattr(self.func, 'lineno', 0),
                            "variant": "inverse_attribute",
                            "var_name": var_name,
                            "op_pair": pair,
                            "description": inverse_pairs[pair],
                        })
                        _log.debug("NAI-026 observed: inverse attribute ops on %s", var_name)
                        return

    # ------------------------------------------------------------------
    # NAI-171: Loop else without break
    # ------------------------------------------------------------------

    def _check_loop_else_without_break(self) -> None:
        """
        NAI-171: Detect loop else without break in loop body.

        The else clause on a for/while loop only executes if the loop completes
        without hitting break. If there's no break, the else always executes,
        defeating its purpose.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                if node.orelse:
                    has_break = any(
                        isinstance(child, ast.Break)
                        for child in ast.walk(ast.Module(body=node.body, type_ignores=[]))
                    )
                    if not has_break:
                        loop_type = "for" if isinstance(node, ast.For) else "while"
                        self.observations.append({
                            "tag": "NAI-171",
                            "line": node.lineno,
                            "loop_type": loop_type,
                            "has_break": False,
                        })
                        _log.debug("NAI-171 observed: %s-else without break at line %d", loop_type, node.lineno)
                        return
