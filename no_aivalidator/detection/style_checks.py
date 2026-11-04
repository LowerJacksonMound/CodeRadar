"""
Style/Structure Analysis Mixin (NAI-080 to NAI-095).

Detect generic naming, structural smells, inefficiency, uniformity.
"""
from __future__ import annotations

import ast
import re
from typing import Any
import logging

_log = logging.getLogger(__name__)


def _stmt_references_name(node: ast.AST, name: str) -> bool:
    """True if `name` appears as a Name node anywhere inside `node`."""
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _contains_break_or_return(stmts: list) -> bool:
    """True if any statement in `stmts` contains a `break` or `return` (at any nesting)."""
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, (ast.Break, ast.Return)):
                return True
    return False


def _is_break_guarded(later_stmts: list, target_name: str) -> bool:
    """NAI-087 body-shape helper: True when some later top-level `if` in the
    same loop body tests `target_name` and its body/orelse breaks or returns --
    the 'read until falsy, then stop' idiom, where the call result IS the
    loop's own continuation check, not an inert invariant byproduct."""
    for later in later_stmts:
        if isinstance(later, ast.If) and _stmt_references_name(later.test, target_name):
            if _contains_break_or_return(later.body) or _contains_break_or_return(later.orelse):
                return True
    return False


class StyleChecksMixin:
    """Mixin providing style and structure detection checks."""

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    def _check_generic_naming(self) -> None:
        """
        NAI-080: Detect functions where all variables use generic names.

        Generic names: Only truly vague placeholder names that indicate no thought.
        Real code usually has domain-specific names, but math/science code legitimately
        uses single letters like x, y, z, r, t, etc.
        """
        m = self.metrics

        # FIX: Reduced to only truly vague names - not domain-common like data/result/value
        generic_names = {'temp', 'tmp', 'var', 'val', 'obj', 'foo', 'bar', 'baz',
                        'thing', 'stuff', 'dummy', 'placeholder', 'res', 'ret', 'inp'}

        assigned_vars: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned_vars.add(target.id.lower())

        if not assigned_vars:
            self.observations.append({"tag": 'NAI-080', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not assigned_vars'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        # FIX: Math-safe single letter vars - common in math/physics/graphics code
        math_safe = {'x', 'y', 'z', 'w', 'h', 'r', 't', 'a', 'b', 'c', 'v', 'u', 'm', 'n', 'd'}
        non_generic = assigned_vars - generic_names - {'_', 'i', 'j', 'k'} - math_safe

        if len(assigned_vars) >= 1 and (not non_generic):  # EXCISED cut 2 (2026-09-05): was `len(assigned_vars) >= 3 and not non_generic` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-080",
                "line": self.func.lineno,
                "var_count": len(assigned_vars),
                "generic_vars": sorted(assigned_vars),
            })
            _log.debug("NAI-080 observed: %d generic vars at line %d", len(assigned_vars), self.func.lineno)

    def _check_numbered_variables(self) -> None:
        """
        NAI-081: Detect numbered variable sequences.

        Pattern: var1, var2, var3 (should use a list)
        """
        m = self.metrics

        numbered_pattern = re.compile(r'^([a-zA-Z_]+)(\d+)$')

        var_bases: dict[str, list[int]] = {}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Name):
                match = numbered_pattern.match(node.id)
                if match:
                    base, num = match.groups()
                    if base not in var_bases:
                        var_bases[base] = []
                    var_bases[base].append(int(num))

        for base, nums in var_bases.items():
            unique_nums = sorted(set(nums))
            if len(unique_nums) >= 1:  # EXCISED cut 2 (2026-09-05): was `len(unique_nums) >= 3` — EXCISION_LIST class A
                if unique_nums[-1] - unique_nums[0] <= len(unique_nums) + 1:
                    self.observations.append({
                        "tag": "NAI-081",
                        "line": self.func.lineno,
                        "base_name": base,
                        "count": len(unique_nums),
                    })
                    _log.debug("NAI-081 observed: numbered var '%s' (%d instances) at line %d", base, len(unique_nums), self.func.lineno)
                    return

    def _check_excessive_params(self) -> None:
        """
        NAI-082: Detect functions with too many parameters.

        More than 7 params suggests need for refactoring (object, config, etc.)
        """
        m = self.metrics

        effective_params = m.params - (1 if m.is_method else 0)

        if effective_params > 0:  # EXCISED cut 2 (2026-09-05): was `effective_params > 7` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-082",
                "line": self.func.lineno,
                "param_count": effective_params,
            })
            _log.debug("NAI-082 observed: %d params at line %d", effective_params, self.func.lineno)

    def _check_deep_nesting(self) -> None:
        """
        NAI-083: Detect excessively deep nesting.

        More than 4 levels of nesting is hard to read.
        """
        m = self.metrics

        def get_depth(node: ast.AST, current: int = 0) -> int:
            max_depth = current
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    child_depth = get_depth(child, current + 1)
                    max_depth = max(max_depth, child_depth)
                else:
                    child_depth = get_depth(child, current)
                    max_depth = max(max_depth, child_depth)
            return max_depth

        depth = get_depth(self.func)

        if depth > 0:  # EXCISED cut 2 (2026-09-05): was `depth > 4` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-083",
                "line": self.func.lineno,
                "depth": depth,
            })
            _log.debug("NAI-083 observed: nesting depth %d at line %d", depth, self.func.lineno)

    def _check_function_length(self) -> None:
        """
        NAI-084: Detect excessively long functions.

        More than 50 statements suggests need to split.
        """
        m = self.metrics

        stmt_count = 0
        for node in ast.walk(self.func):
            if isinstance(node, ast.stmt) and node != self.func:
                stmt_count += 1

        if stmt_count > 0:  # EXCISED cut 2 (2026-09-05): was `stmt_count > 50` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-084",
                "line": self.func.lineno,
                "stmt_count": stmt_count,
            })
            _log.debug("NAI-084 observed: %d statements at line %d", stmt_count, self.func.lineno)

    def _check_flag_argument(self) -> None:
        """
        NAI-085: Detect boolean flag arguments that switch behavior.

        Pattern: def f(x, flag=False): if flag: ... else: ...
        Should be two separate functions.
        """
        m = self.metrics

        bool_params: set[str] = set()

        for arg, default in zip(
            self.func.args.args[-len(self.func.args.defaults):] if self.func.args.defaults else [],
            self.func.args.defaults
        ):
            if isinstance(default, ast.Constant) and isinstance(default.value, bool):
                bool_params.add(arg.arg)

        if not bool_params:
            self.observations.append({"tag": 'NAI-085', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not bool_params'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Name):
                    if node.test.id in bool_params:
                        self.observations.append({
                            "tag": "NAI-085",
                            "line": node.lineno,
                            "flag_param": node.test.id,
                        })
                        _log.debug("NAI-085 observed: flag param '%s' at line %d", node.test.id, node.lineno)
                        return

    def _check_repeated_attribute_access(self) -> None:
        """
        NAI-086: Detect repeated attribute chain access.

        Pattern: self.config.settings.value used 3+ times (cache it)
        """
        m = self.metrics

        attr_chains: dict[str, int] = {}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Attribute):
                chain_parts: list[str] = []
                current: ast.expr = node
                while isinstance(current, ast.Attribute):
                    chain_parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    chain_parts.append(current.id)

                if len(chain_parts) >= 2:
                    chain = '.'.join(reversed(chain_parts))
                    attr_chains[chain] = attr_chains.get(chain, 0) + 1

        for chain, count in attr_chains.items():
            if count >= 1 and chain.count('.') >= 1:  # EXCISED cut 2 (2026-09-05): was `count >= 3 and chain.count('.') >= 2` — EXCISION_LIST class A
                self.observations.append({
                    "tag": "NAI-086",
                    "line": self.func.lineno,
                    "chain": chain,
                    "access_count": count,
                })
                _log.debug("NAI-086 observed: chain '%s' accessed %dx at line %d", chain, count, self.func.lineno)
                return

    def _check_loop_invariant(self) -> None:
        """
        NAI-087: Detect constant computations inside loops.

        Pattern: for x in items: y = expensive_constant(); use(y)
        Move constant computation outside loop.
        """
        m = self.metrics

        for node in self._own_scope(self.func):   # type: ignore[attr-defined]  # FIX_54 ast-pos; IG-9b: a nested def's loops are the nested def's own row
            if isinstance(node, (ast.For, ast.While)):
                # Start with direct loop variables
                loop_dependent: set[str] = set()
                if isinstance(node, ast.For):
                    if isinstance(node.target, ast.Name):
                        loop_dependent.add(node.target.id)
                    elif isinstance(node.target, ast.Tuple):
                        for elt in node.target.elts:
                            if isinstance(elt, ast.Name):
                                loop_dependent.add(elt.id)

                # IG-11 (2026-09-06): every name BOUND anywhere in the loop body is loop-dependent — tuple unpack, aug-assign,
                # walrus, a later reassignment, with / except names; one forward pass over plain Assigns saw none of them.
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                        loop_dependent.add(sub.id)
                    elif isinstance(sub, ast.NamedExpr):
                        loop_dependent.add(sub.target.id)
                    elif isinstance(sub, ast.ExceptHandler) and sub.name:
                        loop_dependent.add(sub.name)
                for idx, stmt in enumerate(node.body):
                    if isinstance(stmt, ast.Assign):
                        if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                            target_name = stmt.targets[0].id
                            # Check if RHS uses any loop-dependent variable
                            uses_loop_dep = False
                            for sub in ast.walk(stmt.value):
                                if isinstance(sub, ast.Name) and sub.id in loop_dependent:
                                    uses_loop_dep = True
                                    break

                            if uses_loop_dep:
                                # This variable now also depends on loop (transitively)
                                loop_dependent.add(target_name)
                            else:
                                # Potential loop invariant — only flag if it's a call
                                if isinstance(stmt.value, ast.Call):
                                    # Body-shape fact: a call whose assigned result is
                                    # later tested by a same-body `if` that breaks/returns
                                    # the loop IS the loop's own continuation check (the
                                    # classic "read until empty" idiom) — not an inert
                                    # invariant byproduct. Only flag when no later
                                    # top-level statement guards the loop on this name.
                                    if _is_break_guarded(node.body[idx + 1:], target_name):
                                        continue
                                    self.observations.append({
                                        "tag": "NAI-087",
                                        "line": stmt.lineno,
                                        "target_var": target_name,
                                    })
                                    _log.debug("NAI-087 observed: loop-invariant call assigned to '%s' at line %d", target_name, stmt.lineno)
                                    return

    def _check_string_concat_loop(self) -> None:
        """
        NAI-088: Detect string concatenation in loop.

        Pattern: for x in items: s = s + x or s += x
        Should use ''.join() or list.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                for stmt in ast.walk(node):
                    if isinstance(stmt, ast.AugAssign):
                        if isinstance(stmt.op, ast.Add):
                            if isinstance(stmt.target, ast.Name):
                                value = stmt.value
                                # String evidence must be REAL (measured false hit,
                                # runs 1-4, 2026-09-05: `total += v` over a float
                                # accumulator was called a string concat):
                                #   - the added value is a str literal, an f-string,
                                #     or a str()/repr()/format() call, or
                                #   - the accumulator was initialised to a string
                                #     in this function (s = "" ... s += name).
                                # A bare name with no string evidence is arithmetic.
                                is_string_op = False
                                if isinstance(value, ast.JoinedStr):
                                    is_string_op = True
                                elif isinstance(value, ast.Constant):
                                    is_string_op = isinstance(value.value, str)
                                elif isinstance(value, ast.Call):
                                    if isinstance(value.func, ast.Name):
                                        if value.func.id in ('str', 'repr', 'format'):
                                            is_string_op = True
                                if not is_string_op and isinstance(value, ast.Name):
                                    is_string_op = self._initialised_as_string(
                                        stmt.target.id, stmt.lineno)

                                if is_string_op:
                                    self.observations.append({
                                        "tag": "NAI-088",
                                        "line": stmt.lineno,
                                        "target_var": stmt.target.id,
                                    })
                                    _log.debug("NAI-088 observed: string concat on '%s' in loop at line %d", stmt.target.id, stmt.lineno)
                                    return

    def _initialised_as_string(self, name: str, before_line: int) -> bool:
        """True iff the LAST assignment to `name` before `before_line` in this
        function binds a string: str literal, f-string, str()/repr()/format() call
        or a ''.join(...) call. A numeric or unknown initialiser returns False."""
        last: tuple[int, bool] | None = None
        for node in ast.walk(self.func):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.lineno < before_line:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
                    continue
                v = node.value
                is_str = False
                if isinstance(v, ast.JoinedStr):
                    is_str = True
                elif isinstance(v, ast.Constant):
                    is_str = isinstance(v.value, str)
                elif isinstance(v, ast.Call):
                    f = v.func
                    if isinstance(f, ast.Name) and f.id in ('str', 'repr', 'format'):
                        is_str = True
                    elif isinstance(f, ast.Attribute) and f.attr == 'join':
                        is_str = True
                if last is None or node.lineno >= last[0]:
                    last = (node.lineno, is_str)
        return bool(last and last[1])

    def _check_append_loop_to_comprehension(self) -> None:
        """
        NAI-089: Detect the IDENTITY append loop.

        Pattern: for x in items: result.append(x)   — this is list(items) dressed
        as processing: no transformation of the loop variable, fake work.
        A projection (result.append(x.attr) / result.append(x["k"])) is honest
        work and is NOT flagged (measured false hit, runs 1-4, 2026-09-05).
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.For):
                if len(node.body) == 1:
                    stmt = node.body[0]
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        call = stmt.value
                        if isinstance(call.func, ast.Attribute):
                            _loop_var = node.target.id if isinstance(node.target, ast.Name) else None
                            _identity = (len(call.args) == 1 and not call.keywords
                                         and isinstance(call.args[0], ast.Name)
                                         and _loop_var is not None
                                         and call.args[0].id == _loop_var)
                            if call.func.attr == 'append' and _identity:
                                self.observations.append({
                                    "tag": "NAI-089",
                                    "line": node.lineno,
                                })
                                _log.debug("NAI-089 observed: append loop at line %d", node.lineno)
                                return

    def _check_single_letter_vars(self) -> None:
        """
        NAI-090: Detect excessive single-letter variables outside loops.

        i, j, k in loops are fine. Math-safe letters (x, y, z, r, t, etc.) are
        also acceptable as they're common in math/physics/graphics code.
        """
        m = self.metrics

        loop_vars: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    loop_vars.add(node.target.id)
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for gen in node.generators:
                    if isinstance(gen.target, ast.Name):
                        loop_vars.add(gen.target.id)

        single_letter: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if len(target.id) == 1 and target.id.isalpha():
                            if target.id not in loop_vars:
                                single_letter.add(target.id)

        # FIX: Math-safe single letter vars - common in math/physics/graphics code
        math_safe = {'x', 'y', 'z', 'w', 'h', 'r', 't', 'a', 'b', 'c', 'v', 'u', 'm', 'n', 'd'}
        acceptable = {'_', 'f', 'e', 'i', 'j', 'k'} | math_safe
        single_letter -= acceptable

        if len(single_letter) >= 1:  # EXCISED cut 2 (2026-09-05): was `len(single_letter) >= 3` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-090",
                "line": self.func.lineno,
                "count": len(single_letter),
                "vars": sorted(single_letter),
            })
            _log.debug("NAI-090 observed: %d single-letter vars at line %d", len(single_letter), self.func.lineno)

    def _check_comment_code_ratio(self) -> None:
        """
        NAI-113: Comment-to-code ratio anomaly — over-documented obvious code.

        AI-generated code has comment density >0.4 vs human <0.25.
        Detects excessive docstrings and inline string constants used as comments.
        """
        m = self.metrics

        # Count docstring + inline string constants (AI uses these as inline docs)
        doc_lines = 0
        code_lines = 0

        # Function span in lines
        if hasattr(self.func, 'end_lineno') and self.func.end_lineno:
            total_lines = self.func.end_lineno - self.func.lineno + 1
        else:
            total_lines = sum(1 for _ in ast.walk(self.func))

        # Count string-constant expressions (docstrings, inline comments)
        for node in ast.walk(self.func):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    doc_lines += max(1, node.value.value.count('\n') + 1)
            if isinstance(node, ast.stmt) and not isinstance(node, ast.Expr):
                code_lines += 1

        if code_lines < 1:  # EXCISED cut 2 (2026-09-05): was `code_lines < 5` — EXCISION_LIST class A
            return

        ratio = doc_lines / max(code_lines, 1)
        if doc_lines >= 1:  # EXCISED cut 2 (2026-09-05): was `ratio > 0.5 and doc_lines >= 5` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-113",
                "line": self.func.lineno,
                "doc_lines": doc_lines,
                "code_lines": code_lines,
                "ratio": round(ratio, 2),
            })
            _log.debug("NAI-113 observed: doc/code ratio %.2f at line %d", ratio, self.func.lineno)

    def _check_hyper_descriptive_naming(self) -> None:
        """
        NAI-114: Hyper-descriptive variable/function naming — AI fingerprint.

        AI tends to use avg identifier length >>15 chars with no abbreviations:
        'active_registered_user_quantity', 'current_temperature_reading_celsius'.
        Human code uses abbreviations and shorter names.
        """
        m = self.metrics

        long_names: list[str] = []
        all_names: list[str] = []

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if not name.startswith('_'):
                            all_names.append(name)
                            if len(name) > 0:  # EXCISED cut 2 (2026-09-05): was `len(name) > 25` — EXCISION_LIST class A
                                long_names.append(name)

        if len(all_names) < 1:  # EXCISED cut 2 (2026-09-05): was `len(all_names) < 3` — EXCISION_LIST class A
            return

        avg_len = sum(len(n) for n in all_names) / len(all_names)

        # Flag if average identifier length > 20 or 3+ names > 25 chars
        if avg_len > 0 and len(all_names) >= 1:  # EXCISED cut 2 (2026-09-05): was `avg_len > 20 and len(all_names) >= 3` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-114",
                "line": self.func.lineno,
                "avg_identifier_len": round(avg_len, 1),
                "name_count": len(all_names),
                "long_name_count": len(long_names),
            })
            _log.debug("NAI-114 observed: avg identifier len %.1f at line %d", avg_len, self.func.lineno)
        elif len(long_names) >= 1:  # EXCISED cut 2 (2026-09-05): was `len(long_names) >= 3` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-114",
                "line": self.func.lineno,
                "avg_identifier_len": round(avg_len, 1),
                "name_count": len(all_names),
                "long_name_count": len(long_names),
            })
            _log.debug("NAI-114 observed: %d long identifiers at line %d", len(long_names), self.func.lineno)

    # ------------------------------------------------------------------
    # NAI-178, NAI-179, NAI-181, NAI-183-186: Extended style checks
    # ------------------------------------------------------------------

    def _check_repeated_lookups_in_loop(self) -> None:
        """
        NAI-178: Detect repeated dict/attribute lookups inside loops.

        Pattern: for x in items: ... obj.attr ... obj.attr ... (3+ times)
        Should cache the lookup result outside the loop body.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                attr_counts: dict[str, int] = {}
                for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(child, ast.Subscript):
                        if isinstance(child.value, ast.Name) and isinstance(child.slice, ast.Constant):
                            key = f"{child.value.id}[{child.slice.value!r}]"
                            attr_counts[key] = attr_counts.get(key, 0) + 1
                    if isinstance(child, ast.Attribute):
                        if isinstance(child.value, ast.Name):
                            key = f"{child.value.id}.{child.attr}"
                            attr_counts[key] = attr_counts.get(key, 0) + 1

                for key, count in attr_counts.items():
                    if count >= 1:  # EXCISED cut 2 (2026-09-05): was `count >= 3` — EXCISION_LIST class A
                        self.observations.append({
                            "tag": "NAI-178",
                            "line": node.lineno,
                            "lookup_key": key,
                            "access_count": count,
                        })
                        _log.debug("NAI-178 observed: '%s' accessed %dx in loop at line %d", key, count, node.lineno)
                        return

    def _check_concat_in_loop_extended(self) -> None:
        """
        NAI-179: Detect s = s + x concatenation pattern in loops (extends NAI-088).

        NAI-088 catches s += x but misses s = s + x with regular assignment.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(child, ast.Assign):
                        if len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                            target = child.targets[0].id
                            if isinstance(child.value, ast.BinOp) and isinstance(child.value.op, ast.Add):
                                if isinstance(child.value.left, ast.Name) and child.value.left.id == target:
                                    self.observations.append({
                                        "tag": "NAI-179",
                                        "line": child.lineno,
                                        "target_var": target,
                                    })
                                    _log.debug("NAI-179 observed: concat on '%s' in loop at line %d", target, child.lineno)
                                    return

    def _check_commented_out_code(self) -> None:
        """
        NAI-181: Detect string constants that look like commented-out code.

        AI often leaves dead code as string constants instead of deleting it.
        Checks non-docstring string expressions that parse as valid Python.
        """
        m = self.metrics

        # Skip the first statement if it's the docstring
        body = self.func.body
        start_idx = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                start_idx = 1

        for stmt in body[start_idx:]:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if isinstance(stmt.value.value, str):
                    text = stmt.value.value.strip()
                    if not text or True:  # EXCISED cut 2 (2026-09-05): was `not text or len(text) < 10` — EXCISION_LIST class A
                        continue
                    # Check if it looks like code
                    code_indicators = ['def ', 'class ', 'import ', 'from ', 'return ',
                                       'if ', 'for ', 'while ', 'try:', 'except ',
                                       ' = ', '()', '[]', '{}']
                    indicator_count = sum(1 for ind in code_indicators if ind in text)
                    if indicator_count >= 1:  # EXCISED cut 2 (2026-09-05): was `indicator_count >= 2` — EXCISION_LIST class A
                        try:
                            ast.parse(text)
                            self.observations.append({
                                "tag": "NAI-181",
                                "line": stmt.lineno,
                                "indicator_count": indicator_count,
                                "text_len": len(text),
                            })
                            _log.debug("NAI-181 observed: dead-code string (%d indicators) at line %d", indicator_count, stmt.lineno)
                            return
                        except SyntaxError:
                            pass

    def _check_god_class_method(self) -> None:
        """
        NAI-183: Detect methods that access too many distinct self attributes.

        If a single method touches 10+ distinct self.xxx attributes, the class
        likely has too many responsibilities (God class smell).
        """
        m = self.metrics

        if not m.is_method:
            self.observations.append({"tag": 'NAI-183', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not m.is_method'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        self_attrs: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id == 'self':
                    self_attrs.add(node.attr)

        if len(self_attrs) >= 1:  # EXCISED cut 2 (2026-09-05): was `len(self_attrs) >= 10` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-183",
                "line": self.func.lineno,
                "attr_count": len(self_attrs),
            })
            _log.debug("NAI-183 observed: %d self attrs at line %d", len(self_attrs), self.func.lineno)

    def _check_feature_envy(self) -> None:
        """
        NAI-184: Detect methods that use another object's data more than self.

        If a method accesses other_obj.xxx more than self.xxx, the method
        may belong in the other class (Feature Envy smell).
        """
        m = self.metrics

        if not m.is_method:
            self.observations.append({"tag": 'NAI-184', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not m.is_method'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        self_count = 0
        other_counts: dict[str, int] = {}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    obj = node.value.id
                    if obj == 'self':
                        self_count += 1
                    elif obj not in ('cls', 'super'):
                        other_counts[obj] = other_counts.get(obj, 0) + 1

        for obj, count in other_counts.items():
            if count > self_count and count >= 1:  # EXCISED cut 2 (2026-09-05): was `count > self_count and count >= 4` — EXCISION_LIST class A
                self.observations.append({
                    "tag": "NAI-184",
                    "line": self.func.lineno,
                    "other_obj": obj,
                    "other_access_count": count,
                    "self_access_count": self_count,
                })
                _log.debug("NAI-184 observed: '%s' accessed %dx vs self %dx at line %d", obj, count, self_count, self.func.lineno)
                return

    def _check_cyclomatic_complexity(self) -> None:
        """
        NAI-185: Detect functions with excessive cyclomatic complexity.

        Counts decision points (if, elif, for, while, except, and, or, ternary).
        Complexity > 10 indicates too many execution paths.
        """
        m = self.metrics

        complexity = 1  # Base path

        for node in ast.walk(self.func):
            if isinstance(node, (ast.If, ast.IfExp)):
                complexity += 1
            elif isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                # Each 'and'/'or' adds a path
                complexity += len(node.values) - 1
            elif isinstance(node, ast.Assert):
                complexity += 1

        if complexity > 0:  # EXCISED cut 2 (2026-09-05): was `complexity > 10` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-185",
                "line": self.func.lineno,
                "complexity": complexity,
            })
            _log.debug("NAI-185 observed: cyclomatic complexity %d at line %d", complexity, self.func.lineno)

    # ------------------------------------------------------------------
    # NAI-151, NAI-153, NAI-154, NAI-168, NAI-169, NAI-182
    # ------------------------------------------------------------------

    def _check_comment_to_code_ratio_source(self) -> None:
        """
        NAI-151: Comment-to-code ratio anomaly (>0.4 = AI fingerprint).

        Uses actual source lines (# comments) rather than string-constant
        heuristics (NAI-113).  AI-generated code averages >0.4 comment-to-code
        ratio; human code is typically <0.25.
        """
        m = self.metrics

        # Use metrics if available; otherwise skip
        if m.comment_lines == 0 and m.lines == 0:
            return

        code_lines = m.lines - m.comment_lines - m.docstring_lines
        if code_lines < 1:  # EXCISED cut 2 (2026-09-05): was `code_lines < 5` — EXCISION_LIST class A
            return

        ratio = m.comment_lines / code_lines
        if m.comment_lines >= 1:  # EXCISED cut 2 (2026-09-05): was `ratio > 0.4 and m.comment_lines >= 4` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-151",
                "line": self.func.lineno,
                "comment_lines": m.comment_lines,
                "code_lines": code_lines,
                "ratio": round(ratio, 2),
            })
            _log.debug("NAI-151 observed: comment/code ratio %.2f at line %d", ratio, self.func.lineno)

    def _check_membership_test_on_list(self) -> None:
        """
        NAI-153: Membership test on list literal instead of set.

        Pattern: if x in [1, 2, 3]  — O(n) scan every time.
        Should be: if x in {1, 2, 3}  — O(1) hash lookup.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.In, ast.NotIn)):
                        if isinstance(comparator, ast.List) and len(comparator.elts) >= 1:  # EXCISED cut 2 (2026-09-05): was `isinstance(comparator, ast.List) and len(comparator.elts) >= 3` — EXCISION_LIST class A
                            # All elements must be hashable constants for set to work
                            all_const = all(
                                isinstance(e, ast.Constant) for e in comparator.elts
                            )
                            if all_const:
                                self.observations.append({
                                    "tag": "NAI-153",
                                    "line": node.lineno,
                                    "element_count": len(comparator.elts),
                                })
                                _log.debug("NAI-153 observed: list membership test with %d elements at line %d", len(comparator.elts), node.lineno)
                                return

    def _check_noqa_type_ignore_overuse(self) -> None:
        """
        NAI-154: Overuse of # noqa / # type: ignore lint suppression comments.

        AI-generated code often sprinkles suppressions to silence linters rather
        than fixing the underlying issue.  >=3 suppressions in a single function
        is suspicious.
        """
        m = self.metrics

        # We need source lines for this check — derive from func line range
        # Since we don't have raw source, walk string constants and comments
        # from metrics.  Use comment_lines as a proxy if the source isn't available.
        # Best-effort: count suppression patterns in string constants
        suppress_count = 0

        # Walk the AST looking for inline string comments that contain noqa/type:ignore
        # This is a heuristic — real detection requires source text.
        # Use the function's line range to scan source if available.
        for node in ast.walk(self.func):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if '# noqa' in text or '# type: ignore' in text:
                    suppress_count += text.count('# noqa') + text.count('# type: ignore')

        # Also check decorator expressions for pragma patterns
        # Note: Real source-line scanning would be more accurate, but we work
        # with what the AST gives us.  The metric comment_lines is already counted.
        # For a more robust approach, the validator could pass source lines.

        if suppress_count >= 1:  # EXCISED cut 2 (2026-09-05): was `suppress_count >= 3` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-154",
                "line": self.func.lineno,
                "suppress_count": suppress_count,
            })
            _log.debug("NAI-154 observed: %d lint suppressions at line %d", suppress_count, self.func.lineno)

    def _check_structural_over_engineering(self) -> None:
        """
        NAI-168: Structural over-engineering — 3.2x more try/except than needed.

        AI-generated code wraps nearly every operation in try/except blocks,
        creating deeply nested error handling for operations that rarely fail.
        Threshold: >3 try blocks in a function with <20 statements.
        """
        m = self.metrics

        try_count = 0
        stmt_count = 0

        for node in ast.walk(self.func):
            if isinstance(node, ast.stmt) and node is not self.func:
                stmt_count += 1
            if isinstance(node, ast.Try):
                try_count += 1

        if stmt_count < 1 or try_count == 0:  # EXCISED cut 2 (2026-09-05): was `stmt_count < 5 or try_count == 0` — EXCISION_LIST class A
            return

        ratio = try_count / max(stmt_count, 1)
        # 3.2x more than expected: for typical code ~1 try per 15 stmts
        # so ratio > 0.2 is suspicious (1/5 of all stmts are try blocks)
        if try_count >= 1:  # EXCISED cut 2 (2026-09-05): was `try_count >= 3 and ratio > 0.2` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-168",
                "line": self.func.lineno,
                "try_count": try_count,
                "stmt_count": stmt_count,
                "ratio": round(ratio, 2),
            })
            _log.debug("NAI-168 observed: %d try blocks in %d stmts at line %d", try_count, stmt_count, self.func.lineno)

    def _check_compulsive_modularization(self) -> None:
        """
        NAI-169: Compulsive modularization — excessive tiny nested functions.

        AI-generated code often creates many small helper functions inside a
        parent function, each doing trivial work.  >=4 nested function defs
        where the average body is <=3 statements is a strong AI signal.
        """
        m = self.metrics

        nested_funcs: list[ast.FunctionDef] = []
        for node in ast.walk(self.func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not self.func:
                nested_funcs.append(node)  # type: ignore[arg-type]  # FIX_54 ast-pos

        if len(nested_funcs) < 1:  # EXCISED cut 2 (2026-09-05): was `len(nested_funcs) < 4` — EXCISION_LIST class A
            return

        # Average body size of nested functions
        total_stmts = 0
        for nf in nested_funcs:
            body_stmts = sum(1 for n in ast.walk(nf) if isinstance(n, ast.stmt) and n is not nf)
            total_stmts += body_stmts

        avg_body = total_stmts / len(nested_funcs) if nested_funcs else 0

        if True:  # EXCISED cut 2 (2026-09-05): was `avg_body <= 3` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-169",
                "line": self.func.lineno,
                "nested_func_count": len(nested_funcs),
                "avg_body_stmts": round(avg_body, 1),
            })
            _log.debug("NAI-169 observed: %d nested funcs (avg %.1f stmts) at line %d", len(nested_funcs), avg_body, self.func.lineno)

    def _check_commented_out_code_blocks(self) -> None:
        """
        NAI-182: Commented-out code blocks (extends NAI-181 string-based).

        NAI-181 catches dead code left as string constants.  NAI-182 extends
        this by detecting patterns in the AST that suggest code was mechanically
        disabled: sequences of string-constant expressions that together form
        a parseable block, or multiple consecutive string statements.
        """
        m = self.metrics

        body = self.func.body
        # Skip docstring
        start_idx = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                start_idx = 1

        # Count consecutive string-constant expressions (non-docstring)
        consecutive_strings = 0
        max_consecutive = 0
        string_code_blocks = 0

        for stmt in body[start_idx:]:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if isinstance(stmt.value.value, str):
                    text = stmt.value.value.strip()
                    if len(text) >= 1:  # EXCISED cut 2 (2026-09-05): was `len(text) >= 5` — EXCISION_LIST class A
                        consecutive_strings += 1
                        max_consecutive = max(max_consecutive, consecutive_strings)
                        # Check if it looks like code
                        code_keywords = ('def ', 'class ', 'import ', 'return ', 'if ',
                                         'for ', 'while ', ' = ', '()', '.', 'self.')
                        if sum((1 for kw in code_keywords if kw in text)) >= 1:  # EXCISED cut 2 (2026-09-05): was `sum(1 for kw in code_keywords if kw in text) >= 2` — EXCISION_LIST class A
                            string_code_blocks += 1
                        continue
            consecutive_strings = 0

        if string_code_blocks >= 1 or max_consecutive >= 1:  # EXCISED cut 2 (2026-09-05): was `string_code_blocks >= 2 or max_consecutive >= 3` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-182",
                "line": self.func.lineno,
                "string_code_blocks": string_code_blocks,
                "max_consecutive": max_consecutive,
            })
            _log.debug("NAI-182 observed: %d code-like string blocks at line %d", string_code_blocks, self.func.lineno)

    def _check_cognitive_complexity(self) -> None:
        """
        NAI-186: Detect functions with high cognitive complexity.

        Unlike cyclomatic complexity, cognitive complexity penalizes nesting depth.
        Each nested control structure adds its nesting level to the score.
        """
        m = self.metrics

        def _calc_cognitive(node: ast.AST, nesting: int = 0) -> int:
            score = 0
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if child is not self.func:
                        score += nesting + 1
                        score += _calc_cognitive(child, nesting + 1)
                        continue
                if isinstance(child, (ast.If, ast.IfExp)):
                    score += 1 + nesting
                    score += _calc_cognitive(child, nesting + 1)
                elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                    score += 1 + nesting
                    score += _calc_cognitive(child, nesting + 1)
                elif isinstance(child, ast.ExceptHandler):
                    score += 1 + nesting
                    score += _calc_cognitive(child, nesting + 1)
                elif isinstance(child, ast.BoolOp):
                    score += len(child.values) - 1
                    score += _calc_cognitive(child, nesting)
                elif isinstance(child, ast.Break) or isinstance(child, ast.Continue):
                    score += 1
                else:
                    score += _calc_cognitive(child, nesting)
            return score

        score = _calc_cognitive(self.func)

        if score > 0:  # EXCISED cut 2 (2026-09-05): was `score > 15` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-186",
                "line": self.func.lineno,
                "cognitive_complexity": score,
            })
            _log.debug("NAI-186 observed: cognitive complexity %d at line %d", score, self.func.lineno)
