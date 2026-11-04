"""
Advanced Detection Mixin (NAI-040 to NAI-049).

Additional triangulation methods for 20/20 fake detection vision.
"""
from __future__ import annotations

import ast
import re
import hashlib
from typing import Any, Dict, Set, List, Optional, Iterator, TYPE_CHECKING
import logging

_log = logging.getLogger(__name__)


class AdvancedChecksMixin:
    """Mixin providing advanced AI fake detection checks."""
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
    _definitions: Any

    def _check_subtree_duplication(self) -> None:
        """
        NAI-040: Hash-based detection of duplicate subtrees.

        AI often generates repeated patterns for "balance."
        Mathematical basis: Cryptographic hash equality of AST dumps

        FIX: Uses include_attributes=False to ignore line numbers/offsets
        so identical logic at different locations is correctly matched.

        IG-new (2026-09-06): a duplicate body/orelse is only the "appearance
        of a branch" when the two copies are lexically ADJACENT — the same
        If's own body vs its own orelse (an if/else that does the same thing
        either way), or two sibling If statements back-to-back in the same
        statement list with nothing between them. Real libraries repeat the
        same small block across separate, non-adjacent guards (sequential
        early-exit checks with code in between, parallel branches of
        unrelated if/elif chains, a re-check nested inside a different
        block such as `with lock:`) — that is convergent handling of
        distinct cases, not copy-paste padding, and is left alone.
        """
        m = self.metrics

        # Safe dump helper for different python versions
        def get_clean_hash(nodes: list[ast.stmt]) -> str:
            try:
                # Python 3.9+: use include_attributes=False to ignore line numbers
                dump = ast.dump(ast.Module(body=nodes, type_ignores=[]), include_attributes=False)
            except TypeError:
                # Fallback for older python (less accurate, but functional)
                dump = ast.dump(ast.Module(body=nodes, type_ignores=[]))
            return hashlib.md5(dump.encode()).hexdigest()[:8]

        # Map id(if_node) -> (id(containing statement list), index within it),
        # so two different If statements can be tested for "back-to-back in
        # the same block" without any name/type/threshold reasoning.
        position: dict[int, tuple[int, int]] = {}

        def index_lists(node: ast.AST) -> None:
            for field in ('body', 'orelse', 'finalbody'):
                stmts = getattr(node, field, None)
                if isinstance(stmts, list):
                    for idx, stmt in enumerate(stmts):
                        if isinstance(stmt, ast.If):
                            position[id(stmt)] = (id(stmts), idx)
                        index_lists(stmt)
            for handler in getattr(node, 'handlers', None) or []:
                index_lists(handler)

        index_lists(self.func)

        subtree_hashes: dict[str, list[tuple[ast.If, str]]] = {}
        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                if len(node.body) > 1:
                    subtree_hashes.setdefault(get_clean_hash(node.body), []).append((node, 'if_body'))
                if node.orelse and len(node.orelse) > 1:
                    subtree_hashes.setdefault(get_clean_hash(node.orelse), []).append((node, 'else_body'))

        for hash_val, locations in subtree_hashes.items():
            if len(locations) < 2:
                continue

            adjacent = False
            for i in range(len(locations)):
                node_i, _ = locations[i]
                for j in range(i + 1, len(locations)):
                    node_j, _ = locations[j]
                    if node_i is node_j:
                        # The same If's own body and its own orelse collide:
                        # an if/else that does the same thing regardless.
                        adjacent = True
                    else:
                        pos_i = position.get(id(node_i))
                        pos_j = position.get(id(node_j))
                        if (
                            pos_i is not None
                            and pos_j is not None
                            and pos_i[0] == pos_j[0]
                            and abs(pos_i[1] - pos_j[1]) == 1
                        ):
                            # Two sibling If statements, back-to-back in the
                            # same statement list, nothing between them.
                            adjacent = True
                    if adjacent:
                        break
                if adjacent:
                    break

            if adjacent:
                self.observations.append({
                    "tag": "NAI-040",
                    "line": self.func.lineno,
                    "duplicate_count": len(locations),
                    "hash": hash_val,
                    "block_types": [loc[1] for loc in locations],
                })
                _log.debug("NAI-040 observed: %d duplicate subtrees at line %d", len(locations), self.func.lineno)
                return

    @staticmethod
    def _leaf_stmt_map_for_shadow(func: ast.AST) -> dict:
        """NAI-041 helper: map id(Name node) -> its nearest enclosing
        statement, without descending into nested function/class scopes
        (mirrors base._own_scope's IG-9 rule). Used to test whether a
        parameter's first write is a direct top-level statement of the
        function body or nested inside a compound block."""
        mapping: dict = {}

        def walk(node: ast.AST, current: ast.stmt) -> None:
            if node is not func and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                return
            nxt = node if isinstance(node, ast.stmt) else current
            if isinstance(node, ast.Name):
                mapping[id(node)] = current
            for child in ast.iter_child_nodes(node):
                walk(child, nxt)

        for top_stmt in getattr(func, 'body', []):
            walk(top_stmt, top_stmt)
        return mapping

    def _check_param_shadow(self) -> None:
        """
        NAI-041: Detect parameters immediately overwritten.

        Pattern: def f(x): x = 5  # x never used before reassignment
        Mathematical basis: First use tracking

        IG-new (2026-09-06): a parameter's first write only counts as a
        shadow when it is an UNCONDITIONAL statement at the direct top
        level of the function body (the plant's literal first statement,
        e.g. `factor = 1`). A first write nested inside any compound block
        (if/elif/else, for, while, try, with) is a deliberate conditional
        override, not a shadow — e.g. click's
        `if isinstance(show_default, str): default = ...`, numpy's
        `if axis is not None: axisa, axisb, axisc = (axis,) * 3`, attrs'
        `if unsafe_hash is not None: hash = unsafe_hash`. This is a purely
        lexical/scope fact (statement nesting), independent of what the
        guard condition tests.
        """
        m = self.metrics

        effective_params = m.params_declared - {'self', 'cls'}
        if not effective_params:
            self.observations.append({"tag": 'NAI-041', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not effective_params'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        # Run 19 (2026-09-05): first use by SOURCE ORDER, not ast.walk order —
        # `text = self.convert(text)` READS text before it stores it (the RHS
        # evaluates first), so a Store is positioned at the END of its
        # statement and Loads in the RHS come first.
        events: list[tuple[int, int, str, str, ast.AST | None]] = []
        for stmt in self._own_scope(self.func):   # IG-9: a nested def's assignments are its own, not the outer parameter's shadow
            if not isinstance(stmt, ast.stmt):
                continue
            if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id in effective_params:
                events.append((stmt.lineno, stmt.col_offset, stmt.target.id, 'read', None))   # IG-11: `x += …` reads x before it writes
            end = (getattr(stmt, 'end_lineno', stmt.lineno) or stmt.lineno,
                   getattr(stmt, 'end_col_offset', 0) or 0)
            for node in self._own_scope(stmt):
                if isinstance(node, ast.Name) and node.id in effective_params:
                    if isinstance(node.ctx, ast.Store):
                        events.append((end[0], end[1] + 1, node.id, 'write', node))
                    elif isinstance(node.ctx, ast.Load):
                        events.append((node.lineno, node.col_offset, node.id, 'read', None))
        first_use: dict[str, tuple[str, ast.AST | None]] = {}
        for _l, _c, pname, kind, node_ref in sorted(events, key=lambda e: (e[0], e[1])):
            first_use.setdefault(pname, (kind, node_ref))

        top_level_ids = {id(s) for s in self.func.body}
        leaf_stmt_map = self._leaf_stmt_map_for_shadow(self.func)

        shadowed = []
        for p, (use, node_ref) in first_use.items():
            if use != 'write':
                continue
            leaf = leaf_stmt_map.get(id(node_ref)) if node_ref is not None else None
            if leaf is not None and id(leaf) not in top_level_ids:
                continue  # conditional/nested override, not a shadow
            shadowed.append(p)

        if shadowed:
            self.observations.append({
                "tag": "NAI-041",
                "line": self.func.lineno,
                "shadowed_params": list(shadowed),
                "func_name": m.name,
            })
            _log.debug("NAI-041 observed: param shadow at line %d", self.func.lineno)

    def _check_exception_alias_unused(self) -> None:
        """
        NAI-042: Detect exception alias that is never used.

        Pattern: except Exception as e: pass  # e never referenced
        Mathematical basis: Set membership (alias in used names)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.ExceptHandler):
                if node.name:
                    alias_used = False
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Name) and sub.id == node.name:
                            if isinstance(sub.ctx, ast.Load):
                                alias_used = True
                                break

                    if not alias_used:
                        self.observations.append({
                            "tag": "NAI-042",
                            "line": node.lineno,
                            "alias": node.name,
                            "func_name": m.name,
                        })
                        _log.debug("NAI-042 observed: unused exception alias '%s' at line %d", node.name, node.lineno)
                        return

    def _check_placeholder_strings(self) -> None:
        """
        NAI-043: Detect placeholder strings in code.

        Patterns: "TODO", "FIXME", "implement", "placeholder"
        Uses dynamic definitions if available.

        FIX: Correctly checks if string is a docstring by inspecting the parent Expr.
        The first statement is an ast.Expr containing an ast.Constant, not a direct Constant.
        """
        m = self.metrics

        # Check if first statement is a docstring - get the actual Constant node
        docstring_node: ast.Constant | None = None
        if (self.func.body and
            isinstance(self.func.body[0], ast.Expr) and
            isinstance(self.func.body[0].value, ast.Constant) and
            isinstance(self.func.body[0].value.value, str)):
            docstring_node = self.func.body[0].value

        defs = self._definitions
        if defs and defs.patterns.stub_comments:
            stub_regex = defs.get_stub_regex()
            for node in ast.walk(self.func):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    # Skip if this is the docstring constant
                    if node is docstring_node:
                        continue
                    if stub_regex.search(node.value):
                        self.observations.append({
                            "tag": "NAI-043",
                            "line": node.lineno,
                            "matched_value": node.value,  # EXCISED cut 2 (2026-09-05): truncation `[:80]` removed — EXCISION_LIST class R
                            "source": "stub_regex",
                            "func_name": m.name,
                        })
                        _log.debug("NAI-043 observed: placeholder string at line %d", node.lineno)
                        return
        else:
            placeholder_patterns = ['todo', 'fixme', 'implement', 'placeholder', 'stub', 'hack', 'xxx']

            for node in ast.walk(self.func):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    # Skip if this is the docstring constant
                    if node is docstring_node:
                        continue
                    lower_val = node.value.lower()
                    # IG-10 (2026-09-06): a placeholder WORD, on word boundaries — `implementation` is not `implement`
                    _m = re.search(r'\b(' + '|'.join(placeholder_patterns) + r')\b', lower_val)
                    for pattern in ([_m.group(1)] if _m else []):
                        if True:
                            self.observations.append({
                                "tag": "NAI-043",
                                "line": node.lineno,
                                "matched_value": node.value,  # EXCISED cut 2 (2026-09-05): truncation `[:80]` removed — EXCISION_LIST class R
                                "matched_pattern": pattern,
                                "source": "builtin_patterns",
                                "func_name": m.name,
                            })
                            _log.debug("NAI-043 observed: placeholder string at line %d", node.lineno)
                            return

    def _check_infinite_loop_patterns(self) -> None:
        """
        NAI-044: Detect infinite loops without exit.

        Pattern: while True: ... (no break, return, or raise)
        Mathematical basis: Boolean completeness (exit path exists)

        IG-new (2026-09-06): a `while True` loop also counts as having a
        designed exit -- without hiding a loop that genuinely has none --
        when either of two further statement-kind facts holds, in addition
        to the pre-existing break/return/raise scan:
          (a) the loop's own subtree contains a `yield`/`yield from` --
              the loop is an intentionally-unbounded generator, and the
              caller simply not requesting the next value IS the exit;
          (b) the `while` is the SOLE statement in the body of its
              immediately-enclosing `try` (which has at least one
              `except` handler), or the SOLE statement in the body of its
              immediately-enclosing `with`/`async with` whose one context
              manager is a call to `suppress(...)` -- an exception
              escaping the loop is then the loop's designed exit, caught
              just outside it.
        Every labeled-honest/instrument-gap row not already covered by the
        break/return/raise scan matches (a) or (b) -- both are purely
        structural (scope/lexical/statement-kind) properties of the loop
        and what directly contains it, independent of what the loop does.
        One honest row (werkzeug `_reloader.Reloader.run`) has neither --
        its exit is a `sys.exit(3)` call buried inside an overridden
        `run_step()` method on a different call frame, invisible in this
        function's own body -- and is left firing; no body-shape fact of
        this function can see into a method it merely calls.
        """
        m = self.metrics

        def _is_suppress_call(expr: ast.expr) -> bool:
            if not isinstance(expr, ast.Call):
                return False
            f = expr.func
            return (isinstance(f, ast.Name) and f.id == "suppress") or (
                isinstance(f, ast.Attribute) and f.attr == "suppress"
            )

        # Whiles that are the sole body statement of an enclosing
        # try/except or with-suppress(...) -- their exit is the caught
        # exception, not visible via break/return/raise inside the loop.
        exception_exit_whiles: set[int] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Try) and node.handlers:
                if len(node.body) == 1 and isinstance(node.body[0], ast.While):
                    exception_exit_whiles.add(id(node.body[0]))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                if len(node.items) == 1 and _is_suppress_call(node.items[0].context_expr):
                    if len(node.body) == 1 and isinstance(node.body[0], ast.While):
                        exception_exit_whiles.add(id(node.body[0]))

        for node in ast.walk(self.func):
            if isinstance(node, ast.While):
                is_infinite = False
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    is_infinite = True

                if is_infinite:
                    has_exit = False
                    for sub in ast.walk(node):
                        if isinstance(sub, (ast.Break, ast.Return, ast.Raise, ast.Yield, ast.YieldFrom)):
                            has_exit = True
                            break

                    if not has_exit and id(node) in exception_exit_whiles:
                        has_exit = True

                    if not has_exit:
                        self.observations.append({
                            "tag": "NAI-044",
                            "line": node.lineno,
                            "loop_type": "while_true",
                            "exit_statements_found": False,
                            "func_name": m.name,
                        })
                        _log.debug("NAI-044 observed: infinite loop at line %d", node.lineno)
                        return

    def _check_return_type_inconsistency(self) -> None:
        """
        NAI-045: Detect inconsistent return types across branches.

        Pattern: return "string" in one branch, return 42 in another
        Mathematical basis: Type set cardinality (should be 1 or compatible)
        """
        m = self.metrics

        return_types: set[str] = set()

        for node in ast.walk(self.func):
            if isinstance(node, ast.Return):
                if node.value is None:
                    return_types.add('None')
                elif isinstance(node.value, ast.Constant):
                    return_types.add(type(node.value.value).__name__)
                elif isinstance(node.value, ast.List):
                    return_types.add('list')
                elif isinstance(node.value, ast.Dict):
                    return_types.add('dict')
                elif isinstance(node.value, ast.Set):
                    return_types.add('set')
                elif isinstance(node.value, ast.Tuple):
                    return_types.add('tuple')

        incompatible = return_types - {'None'}
        if len(incompatible) > 1:
            if 'str' in incompatible and ('int' in incompatible or 'float' in incompatible):
                self.observations.append({
                    "tag": "NAI-045",
                    "line": self.func.lineno,
                    "return_types": sorted(return_types),
                    "incompatible_types": sorted(incompatible),
                    "func_name": m.name,
                })
                _log.debug("NAI-045 observed: inconsistent return types at line %d", self.func.lineno)

    def _check_closure_no_capture(self) -> None:
        """
        NAI-046: Detect nested functions that capture nothing.

        Pattern: def outer(): def inner(): return 1  # inner doesn't use outer's scope
        Mathematical basis: Set intersection (inner's free vars intersection outer's scope)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.FunctionDef) and node != self.func:
                inner_names: set[str] = set()
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                        inner_names.add(sub.id)

                outer_names: set[str] = set()
                for sub in ast.walk(self.func):
                    if sub == node:
                        continue
                    if isinstance(sub, ast.Name):
                        outer_names.add(sub.id)
                    if isinstance(sub, ast.Assign):
                        for target in sub.targets:
                            if isinstance(target, ast.Name):
                                outer_names.add(target.id)

                outer_names |= m.params_declared

                captured = inner_names & outer_names
                builtins = {'print', 'len', 'range', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'True', 'False', 'None'}
                captured -= builtins

                if not captured and len(node.body) > 1:
                    self.observations.append({
                        "tag": "NAI-046",
                        "line": node.lineno,
                        "inner_func_name": node.name,
                        "outer_func_name": m.name,
                        "inner_body_stmts": len(node.body),
                    })
                    _log.debug("NAI-046 observed: closure '%s' captures nothing at line %d", node.name, node.lineno)
                    return

    def _check_assert_side_effects(self) -> None:
        """
        NAI-047: Detect assertions with side effects.

        Pattern: assert func_with_side_effect()
        Mathematical basis: Call presence in assert (calls may have side effects)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assert):
                for sub in ast.walk(node.test):
                    if isinstance(sub, ast.Call):
                        func_name = ""
                        if isinstance(sub.func, ast.Name):
                            func_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            func_name = sub.func.attr

                        # Hardened 2026-09-05 (F-047): the builtin and str/
                        # container methods whose only product is a value are
                        # pure — `assert x.splitlines() == [...]` has no side
                        # effect. Shares NAI-022's allowlist.
                        pure_funcs = (set(getattr(self, '_PURE_BUILTINS', ()))
                                      | set(getattr(self, '_PURE_METHODS', ()))
                                      | {'len', 'isinstance', 'issubclass', 'hasattr', 'callable', 'type',
                                         'id', 'hash', 'abs', 'all', 'any', 'min', 'max', 'sum'})
                        if func_name not in pure_funcs and not self.metrics.name.startswith('test_'):
                            self.observations.append({
                                "tag": "NAI-047",
                                "line": node.lineno,
                                "called_func": func_name,
                                "func_name": m.name,
                            })
                            _log.debug("NAI-047 observed: assert calls '%s' at line %d", func_name, node.lineno)
                            return

    def _check_identical_method_bodies(self) -> None:
        """
        NAI-048: Multiple methods/nested functions with identical bodies.

        AI often generates copy-paste methods that do the same thing.
        Mathematical basis: Hash equality of function body AST dumps.
        """
        m = self.metrics

        # Only check if the function contains nested function defs
        nested_funcs: list[ast.FunctionDef] = []
        for node in ast.walk(self.func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not self.func:
                nested_funcs.append(node)  # type: ignore[arg-type]  # FIX_54 ast-pos

        if len(nested_funcs) < 2:
            return

        body_hashes: dict[str, list[str]] = {}
        for func in nested_funcs:
            try:
                body_dump = ast.dump(ast.Module(body=func.body, type_ignores=[]),
                                    include_attributes=False)
            except TypeError:
                body_dump = ast.dump(ast.Module(body=func.body, type_ignores=[]))
            h = hashlib.md5(body_dump.encode()).hexdigest()[:10]
            if h not in body_hashes:
                body_hashes[h] = []
            body_hashes[h].append(func.name)

        for h, names in body_hashes.items():
            if len(names) > 1:
                self.observations.append({
                    "tag": "NAI-048",
                    "line": self.func.lineno,
                    "identical_funcs": list(names),
                    "identical_count": len(names),
                    "body_hash": h,
                    "func_name": m.name,
                })
                _log.debug("NAI-048 observed: %d identical method bodies at line %d", len(names), self.func.lineno)
                return
