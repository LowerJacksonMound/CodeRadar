"""
Core Checks Mixin (NAI-001 to NAI-025, NAI-170, NAI-174, NAI-175).

Fundamental AI fake pattern detection based on mathematical invariants:
1. Inputs must influence outputs
2. Computation must be captured
3. Iteration must accumulate
4. Functions must have returns OR side effects
"""
from __future__ import annotations

import ast
import re
from typing import Any, TYPE_CHECKING, Dict, Set, List, Optional, Iterator

# FIX_54 (2026-09-17): the optional-import pattern, typed. The name is bound either to the class
# or to None, so it is declared Any once and the try/except keeps its exact runtime behaviour.
try:
    from no_aivalidator.noai_validator.identifier import VariableTracker as _VariableTracker
except ImportError:
    _VariableTracker = None   # type: ignore[assignment,misc]
VariableTracker: Any = _VariableTracker

import logging

from .evidence_lines import dead_value_lines, return_lines, unused_param_lines

_log = logging.getLogger(__name__)


def _variable_tracker():
    """I-01 (2026-09-15, run 116): NAI-010's tracker, bound LAZILY.

    When this module is the FIRST of the package imported in a process (the health check's step 8 imports
    `detection.core_checks` before anything else), the module-top import above fails on the package cycle
    (identifier -> noai_validator/__init__ -> validator -> detection.base -> core_checks, partially initialised)
    and `VariableTracker` stayed None for the life of that process: NAI-010 silently never decided there, and the
    recall guard's by-id count ran exactly one short on every run (204 caught / 203 by id). Resolved at first use,
    after every module has finished importing; a real ImportError is reported once, never swallowed."""
    global VariableTracker
    if VariableTracker is None:
        try:
            from no_aivalidator.noai_validator.identifier import VariableTracker as _vt
        except ImportError as _e:
            _log.warning("reported, not swallowed: NAI-010 cannot bind VariableTracker: %r", _e)
            return None
        VariableTracker = _vt
    return VariableTracker



def _container_elements(node: ast.AST) -> list:
    """Direct elements of a literal container (dict -> its values)."""
    if isinstance(node, ast.Dict):
        return list(node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    return []


def _literal_tree(node: ast.AST) -> bool:
    """True when every leaf is a constant and every branch a literal container
    (no names, calls, comprehensions or `**`/`*` unpacking anywhere)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Dict):
        return all(k is not None and _literal_tree(k) for k in node.keys) and \
            all(_literal_tree(v) for v in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_literal_tree(e) for e in node.elts)
    return False

_STR_METHOD_NAMES: frozenset = frozenset(n for n in dir(str) if not n.startswith('__'))   # IG-10: str's own methods


def _non_docstring_body(func: ast.AST) -> list:
    """A function's body statements with a single leading docstring Expr stripped.

    body_is_pass / body_is_ellipsis / body_is_raise_not_implemented (extractor.py) only
    classify a stub when EXACTLY one statement remains after the docstring; a body that
    reduces to NOTHING (docstring-only) falls through every one of those flags."""
    body = list(getattr(func, "body", []) or [])
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


def _stmts_after(func: ast.AST, target: ast.AST) -> list:
    """The statements that come after `target` in whichever statement list (body/
    orelse/finalbody) of `func` directly contains it. Used by NAI-024 to tell a
    degenerate for/while-return (nothing real follows) from a real fallback."""
    for node in ast.walk(func):
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(node, field, None)
            if isinstance(stmts, list):
                for i, s in enumerate(stmts):
                    if s is target:
                        return stmts[i + 1:]
    return []


def _is_trivial_tail(stmts: list) -> bool:
    """True when `stmts` is empty, or a single bare `pass`/`return`/`return None` —
    i.e. no real fallback logic. Used by NAI-024's immediate_return variant."""
    if not stmts:
        return True
    if len(stmts) == 1:
        s = stmts[0]
        if isinstance(s, ast.Pass):
            return True
        if isinstance(s, ast.Return):
            if s.value is None:
                return True
            if isinstance(s.value, ast.Constant) and s.value.value is None:
                return True
    return False


def _name_read_in(tree: ast.AST, name: str) -> bool:
    """True if `name` is read (Load context) anywhere in `tree`. Used by NAI-024's
    overwrite variant to tell a real cursor/accumulator (its old value consumed
    before the overwrite, or the new value used right after, inside the SAME loop)
    from a blind overwrite whose only other reference is the trailing return that
    every accumulator -- honest or fake -- has after the loop."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load):
            return True
    return False


def _mutates_attr_or_subscript_of(own_scope_nodes, names) -> bool:
    """IG-15: True if an Assign/AugAssign target anywhere in `own_scope_nodes` (this
    function's OWN scope -- see _own_scope) is an Attribute or Subscript whose innermost
    base Name is the literal 'self' or one of `names` (this function's own parameters) --
    e.g. `method.__doc__ = ...` or `self.view_functions[endpoint] = f`. extractor.py's
    has_side_effects only recognizes a side effect via specific method CALLS (write/
    append/...); an assignment INTO an attribute or subscript of the object being mutated
    is invisible to it, so a function that mutates its own argument (or the enclosing
    instance) and then returns that argument unchanged reads as a pure passthrough."""
    for node in own_scope_nodes:
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tgt in targets:
                if not isinstance(tgt, (ast.Attribute, ast.Subscript)):
                    continue
                base = tgt
                while isinstance(base, (ast.Attribute, ast.Subscript)):
                    base = base.value  # type: ignore[assignment]  # FIX_54 ast-pos
                if isinstance(base, ast.Name) and (base.id == 'self' or base.id in names):
                    return True
    return False


def _dead_names_exempt_by_binding_shape(func, dead_names) -> set:
    """IG-17: A name VariableTracker reports dead (assigned via Store, never read) is
    not a genuine forgotten computation when EVERY Store-binding of that name in this
    function fits one of two binding shapes Python's own syntax forces regardless of
    whether the value is read:
      (a) the target of a `for` / `async for` loop -- a bare Name or a nested Tuple/
          List -- whether a statement-level loop or a comprehension / generator-
          expression `for` clause (iterating at all requires binding some name per
          element, even when the loop exists purely to count / exhaust / filter /
          repeat -- numpy Arrayterator.__init__'s `[0 for dim in var.shape]`,
          more_itertools all_equal's `for first in iterator: for second in iterator`,
          rich get_line_length's `for text, style, control in line`); or
      (b) one slot of a Tuple/List destructuring Assign/AnnAssign (2+ names) that has
          at least one SIBLING name in that same destructure referenced elsewhere in
          the function -- discarding one fixed-arity slot while using the others is
          the standard idiom for "this call/iterable has a fixed shape and I only
          need part of it" (urllib3 create_connection's `canonname` from
          `af, socktype, proto, canonname, sa = res`; werkzeug encode_multipart's
          `length` from `stream, length, boundary = stream_encode_multipart(...)`).
    A name that has ANY OTHER binding -- a bare Assign/AnnAssign/AugAssign to a lone
    Name, or a destructure with no used sibling -- is never exempt: a plain computed-
    and-stored value that is never read remains the real dead computation the check's
    own docstring describes."""
    referenced = {
        node.id for node in ast.walk(func)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Load, ast.Del))
    }
    exempt: set = set()
    suspect: set = set()

    def handle_target(tgt, in_loop, siblings_used):
        if isinstance(tgt, ast.Name):
            if tgt.id not in dead_names:
                return
            if in_loop or siblings_used:
                exempt.add(tgt.id)
            else:
                suspect.add(tgt.id)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for elt in tgt.elts:
                handle_target(elt, in_loop, siblings_used)
        # Attribute/Subscript/Starred targets are not bare-name dead-var candidates.

    for node in ast.walk(func):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            handle_target(node.target, True, False)
        elif isinstance(node, ast.comprehension):
            handle_target(node.target, True, False)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tgt in targets:
                if isinstance(tgt, (ast.Tuple, ast.List)):
                    sibling_names = [e.id for e in tgt.elts if isinstance(e, ast.Name)]
                    any_used = any(n in referenced for n in sibling_names)
                    handle_target(tgt, False, any_used)
                elif isinstance(tgt, ast.Name):
                    handle_target(tgt, False, False)

    return exempt - suspect


class CoreChecksMixin:
    """Mixin providing core AI fake detection checks."""
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
        def _class_has_bases(self) -> bool: ...

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    # -----------------------------------------------------------------
    # NAI-002 to NAI-008: Additional core fake patterns
    # -----------------------------------------------------------------

    def _check_unreachable_after_return(self) -> None:
        """
        NAI-002: Code after return/raise that can never execute.

        Invariant: Every statement must be reachable.
        """
        for node in ast.walk(self.func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not self.func:
                continue  # Don't check nested functions
            body: list[ast.stmt] | None = None
            if isinstance(node, (ast.If, ast.For, ast.While, ast.AsyncFor)):
                body = node.body
            elif isinstance(node, ast.ExceptHandler):
                body = node.body
            elif isinstance(node, ast.With):
                body = node.body
            elif node is self.func:
                body = node.body

            if body is None:
                continue

            for i, stmt in enumerate(body):
                if isinstance(stmt, (ast.Return, ast.Raise)) and i < len(body) - 1:
                    # Next statement is unreachable
                    next_stmt = body[i + 1]
                    # Skip if it's a nested function/class def (valid pattern)
                    if isinstance(next_stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    self.observations.append({
                        "tag": "NAI-002",
                        "line": next_stmt.lineno,
                        "func_name": self.metrics.name,
                        "terminal_type": type(stmt).__name__,
                    })
                    _log.debug("NAI-002 observed: unreachable code at line %d", next_stmt.lineno)
                    return

    def _check_unused_parameters(self) -> None:
        """
        NAI-003: Parameters declared but never referenced in the function body.

        Invariant: Every declared parameter should be used.
        """
        m = self.metrics

        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name.startswith('__')` removed
            return
        if m.is_property:
            return
        if m.body_is_pass or m.body_is_ellipsis or m.body_is_raise_not_implemented:
            return
        # Rules hardening 2026-09-05 (sources: ruff ARG001/ARG002 docs — exempts
        # @override, dummy-variable-rgx `_`-prefixed names, LSP rationale; pylint
        # unused-argument ignored-argument-names `_.*|^ignored_|^unused_`;
        # mypy overload docs — variant bodies are placeholders):
        #   * @overload / @override / @abstractmethod bodies are never judged;
        #   * dummy-named params (_x, ignored_x, unused_x) and *args/**kwargs
        #     catch-alls are declared-unused by convention;
        #   * a method on a class that HAS a base class conforms to an imposed
        #     signature (Liskov) — an unused param there is interface
        #     conformance unless the body ignores EVERY input (the counterfeit
        #     signal, also caught by NAI-009S/022S).
        if self._has_decorator('overload', 'override', 'abstractmethod'):
            return
        vararg_names = set()
        if self.func.args.vararg:
            vararg_names.add(self.func.args.vararg.arg)
        if self.func.args.kwarg:
            vararg_names.add(self.func.args.kwarg.arg)
        effective_params = {p for p in m.params_declared - {'self', 'cls'} - vararg_names
                            if not (p.startswith('_') or p.startswith('ignored_') or p.startswith('unused_'))}
        if not effective_params:
            self.observations.append({"tag": 'NAI-003', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not effective_params'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        unused = effective_params - m.params_used
        if unused:
            # Skip callback/handler patterns where unused params are protocol-required
            if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `any((p in m.name.lower() for p in ('callback', 'handler', 'hook', 'sig` removed
                return
            all_ignored = unused == effective_params
            if m.is_method and self._class_has_bases() and not all_ignored:
                return
            if m.is_method and self._class_is_protocol():
                return
            # Calibration 2026-10-08 (owner): `del start, end` is the developer saying "ignored on purpose" —
            # measured as variant "deleted"; the disposition table makes that context, the rule stays silent on it.
            deleted = {t.id for n in ast.walk(self.func) if isinstance(n, ast.Delete)
                       for t in n.targets if isinstance(t, ast.Name)}
            obs = {
                "tag": "NAI-003",
                "line": self.func.lineno,
                "func_name": m.name,
                "unused_params": sorted(unused),
                "lines": unused_param_lines(self.func, unused),   # M-142: where the fix goes, not the def line
                "total_effective_params": len(effective_params),
                "all_params_ignored": all_ignored,
            }
            if unused <= deleted:
                obs["variant"] = "deleted"
            self.observations.append(obs)
            _log.debug("NAI-003 observed: unused params in %s at line %d", m.name, self.func.lineno)

    def _check_pass_only_function(self) -> None:
        """
        NAI-004: Non-abstract function with only pass/ellipsis as body.

        Invariant: Functions should have implementation.
        """
        m = self.metrics

        # Skip abstract methods
        is_abstract = any(
            (isinstance(d, ast.Name) and d.id == 'abstractmethod') or
            (isinstance(d, ast.Attribute) and d.attr == 'abstractmethod')
            for d in self.func.decorator_list
        )
        if is_abstract:
            return

        # Skip protocol stubs (__init__, __enter__, etc.)
        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name.startswith('__') and m.name.endswith('__')` removed
            return
        # Rules hardening 2026-09-05 — F-OVL1: a typing.overload VARIANT is a
        # signature declaration whose body is a placeholder by convention (mypy
        # "More types": "the more common convention is to instead use the
        # ellipsis"); the implementation follows it. A method of a
        # typing.Protocol class is likewise a declaration. Neither is a stub.
        if self._has_decorator('overload'):
            return
        if m.is_method and self._class_is_protocol():
            return

        if m.body_is_pass or m.body_is_ellipsis:
            self.observations.append({
                "tag": "NAI-004",
                "line": self.func.lineno,
                "func_name": m.name,
                "body_type": "pass" if m.body_is_pass else "ellipsis",
            })
            _log.debug("NAI-004 observed: empty function %s at line %d", m.name, self.func.lineno)

    def _check_canned_return(self) -> None:
        """
        NAI-212: canned_return — the body is a single `return` of a literal
        container holding structured rows (dicts / lists / tuples of literals):
        hardcoded sample data shaped like real output (SPECIES_DICT
        stubs.canned_return; plan item 4, 2026-09-05). A scalar constant is NOT
        this species (NAI-009S when parameters are ignored; honest when there
        are none, e.g. version()), and a flat literal dict/list is not either —
        the signal is the nested rows.
        """
        m = self.metrics
        body = [s for s in self.func.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                        and isinstance(s.value.value, str))]
        if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
            return
        val = body[0].value
        if not isinstance(val, (ast.List, ast.Tuple, ast.Dict, ast.Set)) or not _literal_tree(val):
            return
        rows = [e for e in _container_elements(val) if isinstance(e, (ast.Dict, ast.List, ast.Tuple))]
        if not rows:
            self.observations.append({"tag": 'NAI-212', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not rows'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return
        self.observations.append({
            "tag": "NAI-212",
            "line": self.func.lineno,
            "func_name": m.name,
            "shape": f"{type(val).__name__.lower()} of {len(rows)} literal row(s)",
        })
        _log.debug("NAI-212 observed: canned return in %s at line %d", m.name, self.func.lineno)

    def _check_redundant_else_after_return(self) -> None:
        """
        NAI-005: Redundant else after if-return.

        Pattern: if cond: return x \\n else: y  → should be: if cond: return x \\n y
        Not a bug but indicates AI-generated style.
        """
        for node in self._own_scope(self.func):   # IG-9: a nested def's branches are its own row
            if isinstance(node, ast.If) and node.orelse:
                # Check if all paths in the if body return/raise
                body_terminals = all(
                    isinstance(stmt, (ast.Return, ast.Raise))
                    for stmt in node.body[-1:]
                )
                if body_terminals and len(node.orelse) > 0:
                    # Check it's a simple else (not elif)
                    if not (len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If)):
                        # FACT (2026-09-06, body-shape stage): "non-trivial" (>= 2 statements)
                        # over-fired on real branching logic whose else does DIFFERENT work
                        # than the if (a loop, a nested if/try, several assigns, a return of
                        # something other than what it just built) — jinja2 do_filesizeformat,
                        # packaging _compare_equal/_get_payload, pathspec check_match_file,
                        # urllib3 create_urllib3_context/_get_next_buffer, werkzeug write_binary,
                        # more_itertools _len/intersperse, numpy flatten_descr/round, rich
                        # color.parse/Text.__getitem__. The plant's else is a value computed
                        # then handed back UNCHANGED — exactly two statements, an Assign to one
                        # Name immediately followed by a Return of that same Name — which is
                        # mechanically identical to returning the expression directly (the
                        # dedent the docstring describes). Only that exact shape is redundant;
                        # anything richer is real logic and must not fire.
                        orelse = node.orelse
                        is_redundant_value_passthrough = (
                            len(orelse) == 2
                            and isinstance(orelse[0], ast.Assign)
                            and len(orelse[0].targets) == 1
                            and isinstance(orelse[0].targets[0], ast.Name)
                            and isinstance(orelse[1], ast.Return)
                            and isinstance(orelse[1].value, ast.Name)
                            and orelse[1].value.id == orelse[0].targets[0].id
                        )
                        if is_redundant_value_passthrough:
                            self.observations.append({
                                "tag": "NAI-005",
                                "line": node.lineno,
                                "func_name": self.metrics.name,
                                "else_body_length": len(node.orelse),
                            })
                            _log.debug("NAI-005 observed: redundant else at line %d", node.lineno)
                            return

    def _check_variable_immediate_overwrite(self) -> None:
        """
        NAI-006: Variable assigned then immediately overwritten without use.

        Pattern: x = compute(); x = other()  — first assignment wasted.
        """
        body = self.func.body
        if len(body) < 2:
            return

        prev_assigns: dict[str, int] = {}  # var_name -> line index

        for i, stmt in enumerate(body):
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name):
                    name = target.id
                    if name in prev_assigns and prev_assigns[name] == i - 1 and not any(
                            isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
                            for n in ast.walk(stmt.value)):   # IG-11: `x = f(x)` READS x — the first value is consumed
                        # Consecutive assignments to same var
                        self.observations.append({
                            "tag": "NAI-006",
                            "line": stmt.lineno,
                            "func_name": self.metrics.name,
                            "variable": name,
                            "first_assign_index": prev_assigns[name],
                            "overwrite_index": i,
                        })
                        _log.debug("NAI-006 observed: variable %s overwritten at line %d", name, stmt.lineno)
                        return
                    prev_assigns[name] = i
            else:
                prev_assigns.clear()

    def _check_nested_function_never_called(self) -> None:
        """
        NAI-007: Nested function defined but never called or returned.

        Invariant: Defined functions must be used.
        """
        nested_defs: list[str] = []
        for node in self.func.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested_defs.append(node.name)

        if not nested_defs:
            self.observations.append({"tag": 'NAI-007', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not nested_defs'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # Collect all Name references (Load context)
        used_names: set[str] = set()
        for node in ast.walk(self.func):  # type: ignore[assignment]  # FIX_54 ast-pos
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used_names.add(node.id)
            # Also check return values
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name):
                    used_names.add(node.value.id)

        for name in nested_defs:
            if name not in used_names:
                self.observations.append({
                    "tag": "NAI-007",
                    "line": self.func.lineno,
                    "func_name": self.metrics.name,
                    "nested_func_name": name,
                })
                _log.debug("NAI-007 observed: unused nested function %s at line %d", name, self.func.lineno)
                return

    def _check_reimport_inside_function(self) -> None:
        """
        NAI-008: Import statement inside function body.

        Pattern: def f(): import os. Exception: conditional imports (try/except ImportError) are legitimate.
        Variant `plain` — context (owner 2026-10-08, option B): a lazy import is usually a style choice. The `cycle`
        variant (an import that dodges an import cycle) is a project fact: noai_validator/import_cycles.py.
        """
        for node in self.func.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.observations.append({
                    "tag": "NAI-008",
                    "line": node.lineno,
                    "func_name": self.metrics.name,
                    "import_type": type(node).__name__,
                    "variant": "plain",
                })
                _log.debug("NAI-008 observed: import inside function at line %d", node.lineno)
                return

    # -----------------------------------------------------------------
    # NAI-009+: Original core checks
    # -----------------------------------------------------------------

    def _check_input_output_disconnect(self) -> None:
        """
        NAI-009: Functions that take args but return constants, ignoring inputs.

        Invariant: Inputs must influence outputs.
        """
        m = self.metrics

        # Skip if no params or no returns
        if m.params == 0 or m.returns == 0:
            return

        # Skip special cases
        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name in ('__init__', '__new__', '__del__', '__exit__', '__aexit__')` removed
            return
        if m.is_property:
            return

        # Context managers (__exit__) legitimately return False to not suppress exceptions
        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name.endswith('_exit__')` removed
            return

        # __missing__ is a protocol method that may legitimately return constants
        if m.name == '__missing__':
            return

        # FIX: Only allow 'is_' stubs if they don't take parameters (property-like).
        # If they take params and return constant, it's likely a fake validator.
        if m.returns_literal_only:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name clause `startswith('is_')` dropped — a lexical prior
            effective_params = m.params - (1 if m.is_method else 0)
            if effective_params == 0:
                return

        # Check: has params but returns literal without using any
        if m.returns_literal_only and len(m.params_used) == 0:
            effective_params = m.params - (1 if m.is_method else 0)
            if effective_params > 0:
                self.observations.append({
                    "tag": "NAI-009",
                    "line": self.func.lineno,
                    "variant": "returns_constant_ignores_params",
                    "lines": return_lines(self.func),
                    "func_name": m.name,
                    "effective_params": effective_params,
                    "params_used_count": 0,
                })
                _log.debug("NAI-009 observed: constant return ignoring params at line %d", self.func.lineno)

        # Check for empty collection returns
        effective_params = m.params - (1 if m.is_method else 0)
        if effective_params > 0 and len(m.params_used) == 0:
            for node in ast.walk(self.func):
                if isinstance(node, ast.Return) and node.value:
                    if isinstance(node.value, ast.List) and len(node.value.elts) == 0:
                        self.observations.append({
                            "tag": "NAI-009",
                            "line": node.lineno,
                            "variant": "returns_empty_collection",
                            "func_name": m.name,
                            "collection_type": "list",
                            "effective_params": effective_params,
                        })
                        _log.debug("NAI-009 observed: empty list return at line %d", node.lineno)
                    elif isinstance(node.value, ast.Dict) and len(node.value.keys) == 0:
                        self.observations.append({
                            "tag": "NAI-009",
                            "line": node.lineno,
                            "variant": "returns_empty_collection",
                            "func_name": m.name,
                            "collection_type": "dict",
                            "effective_params": effective_params,
                        })
                        _log.debug("NAI-009 observed: empty dict return at line %d", node.lineno)
                    elif isinstance(node.value, ast.Call):
                        if isinstance(node.value.func, ast.Name):
                            if node.value.func.id in ('list', 'dict', 'set') and not node.value.args:
                                self.observations.append({
                                    "tag": "NAI-009",
                                    "line": node.lineno,
                                    "variant": "returns_empty_collection",
                                    "func_name": m.name,
                                    "collection_type": node.value.func.id,
                                    "effective_params": effective_params,
                                })
                                _log.debug("NAI-009 observed: empty %s return at line %d", node.value.func.id, node.lineno)

    _FILL_METHODS = frozenset({"append", "extend", "add", "update", "insert", "setdefault", "appendleft"})

    def _check_discarded_collection(self) -> None:
        """NAI-009 variant `discards_built_collection` (M-142, 2026-10-08): a local collection is filled (append / add /
        update / item assignment) but never read, while the function returns a literal — the work is done and thrown
        away (`upcoming.append(...)` … `return []`). Measured on this function's own statements only."""
        own = [n for n in ast.walk(self.func) if not (n is not self.func and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)))]
        rets = [n for n in own if isinstance(n, ast.Return)]
        if not rets or not all(isinstance(r.value, (ast.Constant, ast.List, ast.Dict, ast.Set, ast.Tuple))
                               and not any(isinstance(x, ast.Name) for x in ast.walk(r.value)) for r in rets if r.value is not None):
            return
        filled: Set[str] = set()
        fill_nodes: Set[int] = set()
        for n in own:
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in self._FILL_METHODS
                    and isinstance(n.func.value, ast.Name)):
                filled.add(n.func.value.id); fill_nodes.add(id(n.func.value))
            elif isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store) and isinstance(n.value, ast.Name):
                filled.add(n.value.id); fill_nodes.add(id(n.value))
        bound = {t.id for n in own if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)
                 and isinstance(n.value, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp, ast.Call))}
        read = {n.id for n in own if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and id(n) not in fill_nodes}
        discarded = sorted((filled & bound) - read)
        if discarded:
            self.observations.append({
                "tag": "NAI-009",
                "line": rets[0].lineno,
                "lines": dead_value_lines(self.func, discarded),
                "variant": "discards_built_collection",
                "func_name": self.metrics.name,
                "discarded": discarded,
                "description": f"`{', '.join(discarded)}` is filled but never read; the function returns a literal "
                               f"instead — return the built value",
            })
            _log.debug("NAI-009 observed: built collection %s discarded in %s", discarded, self.metrics.name)

    def _check_dead_computation(self) -> None:
        """
        NAI-010: Variables assigned but never used.

        Invariant: Computation must be captured.
        """
        _tracker_cls = _variable_tracker()   # I-01: bound at first use, not at import time
        if _tracker_cls is None:
            return
        tracker = _tracker_cls(self.func)
        dead_vars = tracker.get_dead_variables()

        # FACT (2026-09-06, body-shape stage, IG-17): a dead name whose every binding
        # is a for/comprehension loop target, or one discarded slot of a tuple/list
        # destructure with a used sibling, is not a forgotten computation -- see
        # _dead_names_exempt_by_binding_shape. Computed before the existing name-list
        # filters below so it can only REMOVE names from consideration, never add.
        dead_vars = dead_vars - _dead_names_exempt_by_binding_shape(self.func, dead_vars)

        # FIX: Added '_' and standard loop/unpacking variables to acceptable list
        acceptable = {'result', 'output', 'ret', 'rv', 'response', 'data',
                      'dummy', 'placeholder', 'unused', '_',
                      'exc_type', 'exc_val', 'exc_tb', 'exc_info',
                      'exception_type', 'exception_value', 'traceback',
                      'e', 'ex', 'err', 'exc', 'exctype', 'exctb', 'excinst',
                      'excinfo', 't', 'v', 'tb', 'exc_value',
                      'wrapper', 'inner', 'wrapped', 'decorator', 'new_func',
                      'decorated', 'func_wrapper', 'method_wrapper',
                      'cache', 'memo', 'sentinel', 'MISSING', 'lock',
                      'hits', 'misses', 'full', 'currsize', 'maxsize',
                      'cls', 'klass', 'base', 'bases', 'mcs', 'dct', 'type',
                      'owner', 'objtype', 'name',
                      'kwargs', 'args', 'kw', 'pat', 'key', '_key',
                      'oldresult', 'oldkey', 'is_dir', 'scandir', 'exists',
                      'target_is_directory',
                      'mode', 'pathobj', 'target', 'a', 'b', 'iterable',
                      'parts', 'path', 'filename', 'dirname',
                      'i', 'j', 'k', 'n', 'm', 'x', 'y', 'z', 'p', 'q', 'r', 's', 't', 'v', 'w'}

        # FIX: Filter out private/ignored variables starting with _
        really_dead: set[str] = set()
        for var in dead_vars:
            if var not in acceptable and not var.startswith('_'):
                really_dead.add(var)

        if really_dead:
            self.observations.append({
                "tag": "NAI-010",
                "line": self.func.lineno,
                "func_name": self.metrics.name,
                "dead_variables": sorted(really_dead),
                "lines": dead_value_lines(self.func, really_dead),
                "dead_count": len(really_dead),
            })
            _log.debug("NAI-010 observed: %d dead variables at line %d", len(really_dead), self.func.lineno)

    def _check_side_effect_free(self) -> None:
        """
        NAI-011: Functions with no return AND no side effects.

        Invariant: A function must do one or the other.
        """
        m = self.metrics

        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name.startswith('__')` removed
            return
        if m.is_property:
            return
        if m.body_is_pass or m.body_is_ellipsis or m.body_is_raise_not_implemented:
            return

        # FACT (2026-09-06, body-shape stage): a body that reduces to NOTHING after its
        # docstring (an interface hook / abstractmethod default with no other statement —
        # click ParamType.get_metavar, jinja2 NodeVisitor.visit_Block, packaging
        # BaseSpecifier.__str__/__hash__/filter/prereleases-setter, urllib3 close/
        # _validate_conn, watchdog on_modified/on_thread_stop, werkzeug connection_dropped),
        # or whose one remaining statement is a bare `return` with no value (watchdog
        # dirsnapshot.path), or a lone `raise` of ANYTHING — not just NotImplementedError
        # (flask's deferred re-raise `raise err from None`) — is a documented no-op stub /
        # control-transfer, the same class body_is_pass/ellipsis/raise_not_implemented
        # already exempt, just too narrow (those only fire when exactly one statement
        # follows the docstring). Neither NAI-011 plant (a bare attribute/subscript read,
        # no docstring, no return, no raise) matches any of these shapes.
        # NARROWED by the orchestrator (2026-09-06, same sitting): the docstring-only and bare-`return`
        # exemptions hold for METHODS only (first parameter `self` / `cls` — the interface-hook scope).
        # A module-level docstring-only function is the NAI-034 / NAI-120 counterfeit shape
        # (`rotate_logs`, `save_report`, `part_of_me`) that NAI-011 catches IN SUBSTANCE — the
        # slice-3 ruling NAI-034 -> context rests on that catch; exempting it lost 3 archived plants.
        # The lone-`raise` exemption stays for any scope (no plant raises).
        rest = _non_docstring_body(self.func)
        _pos = list(self.func.args.posonlyargs) + list(self.func.args.args)
        _is_method = bool(_pos) and _pos[0].arg in ("self", "cls")
        if _is_method and not rest:
            return
        if len(rest) == 1:
            only = rest[0]
            if _is_method and isinstance(only, ast.Return) and only.value is None:
                return
            if isinstance(only, ast.Raise):
                return

        if m.returns == 0 and m.yields == 0 and not m.has_side_effects:
            if m.calls == 0 and m.assigns == 0:
                self.observations.append({
                    "tag": "NAI-011",
                    "line": self.func.lineno,
                    "func_name": m.name,
                    "returns": m.returns,
                    "yields": m.yields,
                    "calls": m.calls,
                    "assigns": m.assigns,
                })
                _log.debug("NAI-011 observed: side-effect-free function at line %d", self.func.lineno)

    def _check_meaningless_operations(self) -> None:
        """
        NAI-014: x = x, comparisons as statements, discarded computations.

        Invariant: Operations must have purpose.
        """
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1:
                    target = node.targets[0]
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Name):
                        if target.id == node.value.id:
                            self.observations.append({
                                "tag": "NAI-014",
                                "line": node.lineno,
                                "variant": "self_assignment",
                                "func_name": self.metrics.name,
                                "variable": target.id,
                            })
                            _log.debug("NAI-014 observed: self-assignment of %s at line %d", target.id, node.lineno)

            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Compare):
                    self.observations.append({
                        "tag": "NAI-014",
                        "line": node.lineno,
                        "variant": "comparison_as_statement",
                        "func_name": self.metrics.name,
                    })
                    _log.debug("NAI-014 observed: comparison as statement at line %d", node.lineno)

                if isinstance(node.value, ast.BinOp):
                    self.observations.append({
                        "tag": "NAI-014",
                        "line": node.lineno,
                        "variant": "discarded_computation",
                        "func_name": self.metrics.name,
                        "op_type": type(node.value.op).__name__,
                    })
                    _log.debug("NAI-014 observed: discarded computation at line %d", node.lineno)

    def _check_fake_iteration(self) -> None:
        """
        NAI-015: Loops that iterate but do nothing meaningful.

        Invariant: Iteration must accumulate.
        """
        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                if len(node.body) == 1:
                    stmt = node.body[0]
                    if isinstance(stmt, ast.Pass):
                        self.observations.append({
                            "tag": "NAI-015",
                            "line": node.lineno,
                            "variant": "empty_loop_pass",
                            "func_name": self.metrics.name,
                            "loop_type": type(node).__name__,
                        })
                        _log.debug("NAI-015 observed: empty loop (pass) at line %d", node.lineno)
                        continue
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                        if stmt.value.value is ...:
                            self.observations.append({
                                "tag": "NAI-015",
                                "line": node.lineno,
                                "variant": "ellipsis_loop",
                                "func_name": self.metrics.name,
                                "loop_type": type(node).__name__,
                            })
                            _log.debug("NAI-015 observed: ellipsis loop at line %d", node.lineno)
                            continue

                if all(isinstance(s, ast.Continue) for s in node.body):
                    self.observations.append({
                        "tag": "NAI-015",
                        "line": node.lineno,
                        "variant": "continue_only_loop",
                        "func_name": self.metrics.name,
                        "loop_type": type(node).__name__,
                        "body_length": len(node.body),
                    })
                    _log.debug("NAI-015 observed: continue-only loop at line %d", node.lineno)
                    continue

                self._check_loop_accumulation(node)

    def _check_loop_accumulation(self, loop_node: ast.AST) -> None:
        """Check if a loop accumulates/modifies anything."""
        # IG-8 (2026-09-06): a loop that CALLS anything has an effect — `param.add_to_parser(parser, ctx)`,
        # `self.add_command(...)`, `setattr(self, name, arg)`, `queue_events(...)` are what the loop is for. The
        # "iterates but does nothing" shape is a body with no assignment, no call, no del, no yield, no return, no
        # raise. The old method-name tables (append/extend/…, print/write/…) were name guesses and are gone.
        has_accumulation = False
        for node in ast.walk(loop_node):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete, ast.Call, ast.Await,
                                 ast.Yield, ast.YieldFrom, ast.Raise)):
                has_accumulation = True
                break
            if isinstance(node, ast.Return) and node.value:
                has_accumulation = True
                break

        if not has_accumulation:
            self.observations.append({
                "tag": "NAI-015",
                "line": loop_node.lineno,  # type: ignore[attr-defined]  # FIX_54 ast-pos
                "variant": "no_accumulation",
                "func_name": self.metrics.name,
                "loop_type": type(loop_node).__name__,
            })
            _log.debug("NAI-015 observed: non-accumulating loop at line %d", loop_node.lineno)  # type: ignore[attr-defined]  # FIX_54 ast-pos

    def _check_return_input_unchanged(self) -> None:
        """
        NAI-016: Identity functions - def f(x): return x

        Invariant: Functions should transform, not pass-through.
        Also detects identity chains through copy operations:
          temp = list(param); processed = temp[:]; return processed
        """
        m = self.metrics

        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name in ('identity', '__copy__', '__deepcopy__', 'noop', '__enter__'` removed
                      # (excised condition continued) 'casefold', 'casefold_parts', 'make_uri'):
            return
        if 'identity' in m.name.lower() or 'passthrough' in m.name.lower():
            return
        if 'casefold' in m.name.lower():
            return

        if m.has_side_effects:
            return

        if m.returns_input_unchanged:
            self.observations.append({
                "tag": "NAI-016",
                "line": self.func.lineno,
                "variant": "returns_input_unchanged",
                "func_name": m.name,
            })
            _log.debug("NAI-016 observed: identity function at line %d", self.func.lineno)
            return

        param_names: set[str] = set()
        for arg in self.func.args.args + self.func.args.posonlyargs + self.func.args.kwonlyargs:
            if arg.arg not in ('self', 'cls'):
                param_names.add(arg.arg)

        if not param_names:
            self.observations.append({"tag": 'NAI-016', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not param_names'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # --- Simple alias tracing (original: var = param) ---
        var_to_param: dict[str, str] = {}
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                    if isinstance(node.value, ast.Name) and node.value.id in param_names:
                        var_to_param[var_name] = node.value.id

        # IG-15 (2026-09-06, body-shape stage): has_side_effects (extractor.py) only
        # recognizes an effect via specific method CALLS (write/append/...) -- an
        # Assign/AugAssign INTO an attribute or subscript of 'self' or one of this
        # function's own parameters (attrs `method.__module__ = ...; return method`,
        # flask `self.view_functions[endpoint] = f; return f`, jinja2
        # `self[key] = default; return default`) is a real effect that metric misses.
        # Scoped to this function's OWN scope (_own_scope) so a nested def's mutation
        # of an outer variable of the same name doesn't count.
        mutates_self_or_param = _mutates_attr_or_subscript_of(
            self._own_scope(self.func), param_names)

        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name):
                    name = node.value.id
                    if name in param_names or name in var_to_param:
                        if m.branches == 0 and m.loops == 0 and m.comprehensions == 0:
                            if m.calls <= 0 and (not m.has_side_effects) and (not mutates_self_or_param):  # EXCISED cut 2 (2026-09-05): was `m.calls <= 0 and m.assigns <= 1 and not m.has_side_effects` — EXCISION_LIST class A
                                self.observations.append({
                                    "tag": "NAI-016",
                                    "line": node.lineno,
                                    "variant": "returns_param_via_variable",
                                    "func_name": m.name,
                                    "returned_name": name,
                                    "is_alias": name in var_to_param,
                                })
                                _log.debug("NAI-016 observed: param passthrough via variable at line %d", node.lineno)
                                return

        # --- Extended chain tracing through copy operations ---
        # Catches patterns like: temp = list(p); x = temp[:]; y = x; return y
        if m.branches > 0 or m.loops > 0 or m.comprehensions > 0:
            return

        # Copy-constructor builtins that preserve data unchanged
        _COPY_BUILTINS = frozenset({"list", "dict", "set", "tuple", "frozenset",
                                     "sorted", "bytes", "bytearray"})
        # Methods that return a copy
        _COPY_METHODS = frozenset({"copy"})

        # Build chain: var -> source_param (following through copies)
        chain: dict[str, str] = {}  # var_name -> originating param

        # Walk the function body in statement order
        for node in ast.iter_child_nodes(self.func):
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            var_name = node.targets[0].id
            val = node.value
            source: str | None = None

            # Pattern 1: var = param  (direct alias)
            if isinstance(val, ast.Name):
                if val.id in param_names:
                    source = val.id
                elif val.id in chain:
                    source = chain[val.id]

            # Pattern 2: var = list(param) / dict(chain_var) etc.
            elif isinstance(val, ast.Call) and isinstance(val.func, ast.Name):
                if val.func.id in _COPY_BUILTINS and len(val.args) == 1:
                    arg = val.args[0]  # type: ignore[assignment]  # FIX_54 ast-pos
                    if isinstance(arg, ast.Name):
                        if arg.id in param_names:
                            source = arg.id
                        elif arg.id in chain:
                            source = chain[arg.id]

            # Pattern 3: var = other_var[:] (full slice copy)
            elif isinstance(val, ast.Subscript):
                if isinstance(val.slice, ast.Slice):
                    sl = val.slice
                    if sl.lower is None and sl.upper is None and sl.step is None:
                        if isinstance(val.value, ast.Name):
                            if val.value.id in param_names:
                                source = val.value.id
                            elif val.value.id in chain:
                                source = chain[val.value.id]

            # Pattern 4: var = other_var.copy()
            elif (isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute)
                  and val.func.attr in _COPY_METHODS and not val.args):
                if isinstance(val.func.value, ast.Name):
                    if val.func.value.id in param_names:
                        source = val.func.value.id
                    elif val.func.value.id in chain:
                        source = chain[val.func.value.id]

            if source is not None:
                chain[var_name] = source

        # Check if the return value traces back to a param through the chain
        if chain:
            for node in ast.walk(self.func):
                if isinstance(node, ast.Return) and node.value:
                    if isinstance(node.value, ast.Name) and node.value.id in chain:
                        self.observations.append({
                            "tag": "NAI-016",
                            "line": node.lineno,
                            "variant": "identity_chain_through_copy",
                            "func_name": m.name,
                            "returned_name": node.value.id,
                            "source_param": chain[node.value.id],
                        })
                        _log.debug("NAI-016 observed: identity chain at line %d", node.lineno)
                        return

    def _check_exception_swallow(self) -> None:
        """
        NAI-017: Exception handlers that swallow exceptions silently.

        Invariant: Exceptions should be handled meaningfully or propagated.
        """
        EAFP_EXCEPTIONS = {
            'AttributeError', 'KeyError', 'IndexError', 'TypeError',
            'ValueError', 'LookupError', 'StopIteration', 'OSError',
            'IOError', 'FileNotFoundError', 'PermissionError',
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.ExceptHandler):
                if node.type is not None:
                    exc_name = None
                    if isinstance(node.type, ast.Name):
                        exc_name = node.type.id
                    elif isinstance(node.type, ast.Tuple):
                        exc_names = [e.id for e in node.type.elts if isinstance(e, ast.Name)]
                        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `all((n in EAFP_EXCEPTIONS for n in exc_names))` removed
                            continue

                    if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `exc_name in EAFP_EXCEPTIONS` removed
                        continue

                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    if node.type is None:
                        self.observations.append({
                            "tag": "NAI-017",
                            "line": node.lineno,
                            "variant": "bare_except_pass",
                            "func_name": self.metrics.name,
                        })
                        _log.debug("NAI-017 observed: bare except with pass at line %d", node.lineno)
                    else:
                        # owner 2026-10-07 (blind tree 1 L1, M-90): `except Exception: pass` swallows exactly what a bare
                        # except does — the common form, which slipped through. Named narrow types (KeyError …) stay
                        # out: catching one expected error is EAFP, not swallowing.
                        _caught = ([node.type] if not isinstance(node.type, ast.Tuple) else list(node.type.elts))
                        _names = {c.id if isinstance(c, ast.Name) else getattr(c, 'attr', '') for c in _caught}
                        if _names & {'Exception', 'BaseException'}:
                            self.observations.append({
                                "tag": "NAI-017",
                                "line": node.lineno,
                                "variant": "broad_except_pass",
                                "func_name": self.metrics.name,
                            })
                            _log.debug("NAI-017 observed: broad except with pass at line %d", node.lineno)

        # Detect contextlib.suppress(Exception) / suppress(BaseException)
        broad_exceptions = {'Exception', 'BaseException'}
        for node in ast.walk(self.func):
            if isinstance(node, ast.With):
                for item in node.items:
                    ctx = item.context_expr
                    if not isinstance(ctx, ast.Call):
                        continue
                    # Match suppress(...) or contextlib.suppress(...)
                    is_suppress = False
                    if isinstance(ctx.func, ast.Name) and ctx.func.id == 'suppress':
                        is_suppress = True
                    elif isinstance(ctx.func, ast.Attribute) and ctx.func.attr == 'suppress':
                        is_suppress = True
                    if not is_suppress:
                        self.observations.append({"tag": 'NAI-017', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not is_suppress'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
                        continue
                    # Check arguments for broad exception types
                    for arg in ctx.args:
                        if isinstance(arg, ast.Name) and arg.id in broad_exceptions:
                            self.observations.append({
                                "tag": "NAI-017",
                                "line": node.lineno,
                                "variant": "suppress_broad_exception",
                                "func_name": self.metrics.name,
                                "suppressed_type": arg.id,
                            })
                            _log.debug("NAI-017 observed: suppress(%s) at line %d", arg.id, node.lineno)
                            return

    def _check_async_no_await(self) -> None:
        """
        NAI-018: Async functions that never await anything.

        Invariant: Async functions should use async operations.
        """
        if not self.metrics.is_async:
            self.observations.append({"tag": 'NAI-018', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not self.metrics.is_async'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `self.metrics.name in ('__aenter__', '__aexit__')` removed
            return

        has_await = False
        for node in ast.walk(self.func):
            if isinstance(node, ast.Await):
                has_await = True
                break

        if not has_await:
            self.observations.append({
                "tag": "NAI-018",
                "line": self.func.lineno,
                "func_name": self.metrics.name,
            })
            _log.debug("NAI-018 observed: async without await at line %d", self.func.lineno)

    def _check_constant_returns(self) -> None:
        """
        NAI-019: Functions that return constants regardless of branching.

        Invariant: Branches should lead to different outcomes.
        """
        m = self.metrics

        if m.branches == 0:
            return

        constant_returns: list[str] = []
        has_non_constant_return = False

        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Constant):
                    constant_returns.append(repr(node.value.value))
                elif isinstance(node.value, ast.Name):
                    has_non_constant_return = True
                else:
                    has_non_constant_return = True

        if (not has_non_constant_return and
            len(constant_returns) >= 2 and
            len(set(constant_returns)) == 1):
            self.observations.append({
                "tag": "NAI-019",
                "line": self.func.lineno,
                "func_name": m.name,
                "constant_value": constant_returns[0],
                "branch_count": len(constant_returns),
            })
            _log.debug("NAI-019 observed: all branches return same value at line %d", self.func.lineno)

    def _check_test_fakes(self) -> None:
        """
        NAI-020: Test functions that don't actually test anything.

        Invariant: Tests must have assertions.
        """
        m = self.metrics

        if not m.name.startswith('test_'):  # RESTORED cut 3 batch 4 (2026-09-06): the `test_` prefix is the RUNNER's collection convention (pytest collects by it) — a fact about how the function is executed, not the author's claim; removing it produced 280 false verdicts on two honest repos
            return

        has_assertion = False
        has_trivial_assertion = False

        # Rules hardening 2026-09-05 (source: pytest "How to write and report
        # assertions" — `pytest.raises` IS an assertion about exceptions; the
        # unittest `self.assert*` family and mock `assert_called*` are
        # assertions too; `pytest.fail/skip/xfail` end the case deliberately).
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                cname = node.func.attr if isinstance(node.func, ast.Attribute) else (
                    node.func.id if isinstance(node.func, ast.Name) else '')
                if (cname.startswith('assert') or cname in ('raises', 'warns', 'deprecated_call',
                                                            'fail', 'skip', 'xfail', 'approx',
                                                            'assertRaises', 'assertRaisesRegex')):
                    has_assertion = True
            if isinstance(node, ast.With):
                for item in node.items:
                    ce = item.context_expr
                    if isinstance(ce, ast.Call):
                        cn = ce.func.attr if isinstance(ce.func, ast.Attribute) else (
                            ce.func.id if isinstance(ce.func, ast.Name) else '')
                        if cn in ('raises', 'warns', 'assertRaises', 'assertRaisesRegex',
                                  'assertWarns', 'assertLogs', 'deprecated_call'):
                            has_assertion = True
            if isinstance(node, ast.Assert):
                has_assertion = True
                test = node.test
                if isinstance(test, ast.Constant) and test.value is True:
                    has_trivial_assertion = True
                elif isinstance(test, ast.Compare):
                    if len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
                        left = test.left
                        right = test.comparators[0]
                        if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                            if left.id == right.id:
                                has_trivial_assertion = True
                        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
                            if left.value == right.value:
                                has_trivial_assertion = True

        # owner 2026-10-07 (tests judged like any file): an UNCONDITIONAL skip — `@pytest.mark.skip`, `@unittest.skip`,
        # or `pytest.skip(...)` as the first statement — means the test never runs; recorded as a fact (variant).
        _skip_deco = any(re.fullmatch(r"(?:pytest\.mark\.skip|unittest\.skip|skip)(?:\(.*\))?", ast.unparse(d), re.S)
                         for d in self.func.decorator_list)
        _first = next((b for b in self.func.body if not (isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None),
                                                                                                  ast.Constant))), None)
        _skip_first = isinstance(_first, ast.Expr) and isinstance(_first.value, ast.Call) and \
            ast.unparse(_first.value.func) in ("pytest.skip", "self.skipTest")
        if _skip_deco or _skip_first:
            self.observations.append({"tag": "NAI-020", "line": self.func.lineno, "variant": "skipped_unconditionally",
                                      "func_name": m.name})
            return
        if not has_assertion:
            # owner 2026-10-07 (tests are judged): the test's NAME may say what it checks — "doesn't raise" tests
            # assert by not raising. Recorded as a fact (variant); the disposition table decides what it means.
            _says_no_raise = bool(re.search(r"(?:not|no|nt|never|without|wont|cant)_?(?:raise|raising|throw|crash|fail|error)"
                                            r"|(?:does|should|must|will)(?:nt|_not)_?(?:raise|throw|crash|fail|error)"
                                            r"|_ok$|_smoke|_runs?$|_no_error|_safe$", m.name.lower()))
            self.observations.append({
                "tag": "NAI-020",
                "line": self.func.lineno,
                "variant": "no_assertions_named_no_raise" if _says_no_raise else "no_assertions",
                "func_name": m.name,
            })
            _log.debug("NAI-020 observed: test with no assertions at line %d", self.func.lineno)
        elif has_trivial_assertion:
            self.observations.append({
                "tag": "NAI-020",
                "line": self.func.lineno,
                "variant": "trivial_assertions",
                "func_name": m.name,
            })
            _log.debug("NAI-020 observed: trivial assertions at line %d", self.func.lineno)

    def _check_logging_only(self) -> None:
        """
        NAI-021: Functions that only log/print without real logic.

        Invariant: Functions should do more than just log.
        """
        m = self.metrics

        print_calls = 0
        other_calls = 0

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'print':
                        print_calls += 1
                    else:
                        other_calls += 1
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('info', 'debug', 'warning', 'error', 'log', 'critical'):
                        print_calls += 1
                    else:
                        other_calls += 1

        if print_calls > 0 and other_calls == 0:
            for node in self.func.body:
                if isinstance(node, ast.Return) and node.value:
                    if isinstance(node.value, ast.Name):
                        param_names = {arg.arg for arg in self.func.args.args
                                      if arg.arg not in ('self', 'cls')}
                        if node.value.id in param_names:
                            self.observations.append({
                                "tag": "NAI-021",
                                "line": self.func.lineno,
                                "variant": "log_and_return_input",
                                "func_name": m.name,
                                "print_calls": print_calls,
                            })
                            _log.debug("NAI-021 observed: log-only function at line %d", self.func.lineno)
                            return

        if m.loops > 0 and print_calls > 0 and other_calls == 0:
            if True:  # EXCISED cut 2 (2026-09-05): was `m.assigns <= 1` — EXCISION_LIST class A
                self.observations.append({
                    "tag": "NAI-021",
                    "line": self.func.lineno,
                    "variant": "loop_only_logs",
                    "func_name": m.name,
                    "print_calls": print_calls,
                    "assigns": m.assigns,
                })
                _log.debug("NAI-021 observed: loop only logs at line %d", self.func.lineno)

    # Callees whose ONLY product is their return value: discarding it is
    # meaningless work (the counterfeit signal). Everything else is presumed a
    # side-effect call — rules hardening 2026-09-05, sources: pylint W0106
    # expression-not-assigned ("an expression that is not a function call"),
    # ruff B018 useless-expression ("ignores ... function calls"), pyright
    # reportUnusedCallResult (off by default). The industry default is: a bare
    # call statement is NOT a infraction; only a known-pure callee is.
    _PURE_BUILTINS = frozenset({
        'sorted', 'reversed', 'len', 'str', 'int', 'float', 'bool', 'bytes', 'list', 'dict',
        'set', 'frozenset', 'tuple', 'map', 'filter', 'zip', 'enumerate', 'range', 'abs',
        'round', 'min', 'max', 'sum', 'any', 'all', 'repr', 'format', 'hash', 'isinstance',
        'issubclass', 'getattr', 'hasattr', 'type', 'id', 'divmod', 'pow', 'ord', 'chr',
        'bin', 'hex', 'oct', 'ascii', 'callable', 'iter', 'slice', 'complex',
    })
    _PURE_METHODS = frozenset({
        # str / bytes
        'strip', 'lstrip', 'rstrip', 'upper', 'lower', 'title', 'capitalize', 'casefold',
        'swapcase', 'replace', 'split', 'rsplit', 'splitlines', 'join', 'format', 'format_map',
        'startswith', 'endswith', 'encode', 'decode', 'find', 'rfind', 'index', 'rindex',
        'count', 'partition', 'rpartition', 'zfill', 'center', 'ljust', 'rjust', 'expandtabs',
        'isdigit', 'isalpha', 'isalnum', 'isspace', 'isupper', 'islower', 'istitle',
        'isnumeric', 'isdecimal', 'isidentifier', 'isprintable', 'removeprefix', 'removesuffix',
        'translate', 'maketrans',
        # containers (non-mutating)
        'copy', 'keys', 'values', 'items', 'get', 'union', 'intersection', 'difference',
        'symmetric_difference', 'issubset', 'issuperset', 'isdisjoint',
        # numbers / misc
        'is_integer', 'as_integer_ratio', 'bit_length', 'conjugate', 'hex', 'to_bytes',
        # pathlib pure
        'with_suffix', 'with_name', 'with_stem', 'relative_to', 'joinpath', 'as_posix',
        'as_uri', 'is_absolute', 'is_relative_to', 'exists', 'is_file', 'is_dir',
    })

    def _receiver_is_str(self, expr: ast.AST, before: int) -> bool:
        """IG-10 (2026-09-06): the receiver is a string by a visible fact — a literal, an f-string, str()/repr()/format(),
        a string-method chain, or a name last bound to one of those in this function before the call."""
        def is_str(e: ast.AST) -> bool:
            if isinstance(e, ast.Constant):
                return isinstance(e.value, str)
            if isinstance(e, ast.JoinedStr):
                return True
            if isinstance(e, ast.Call):
                f = e.func
                return (isinstance(f, ast.Name) and f.id in ('str', 'repr', 'format')) or \
                       (isinstance(f, ast.Attribute) and f.attr in _STR_METHOD_NAMES and is_str(f.value))
            if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
                return is_str(e.left)
            return False
        if is_str(expr):
            return True
        if isinstance(expr, ast.Name):
            last = None
            for n in self._own_scope(self.func):
                if isinstance(n, ast.Assign) and n.lineno < before and any(isinstance(t, ast.Name) and t.id == expr.id for t in n.targets):
                    if last is None or n.lineno > last.lineno:
                        last = n
            return last is not None and is_str(last.value)
        return False

    def _check_discarded_calls(self) -> None:
        """
        NAI-022: Function calls whose return values are ignored.

        Invariant: Function results should be used.

        Hardened 2026-09-05 (F-022): only a call to a KNOWN-PURE callee — a
        builtin or method whose only product is its return value — is a
        discarded result. A bare call to anything else is a side-effect call
        by the industry default (pylint W0106 / ruff B018 exclude calls;
        pyright's reportUnusedCallResult is off by default).
        """
        m = self.metrics

        discarded_calls: list[str] = []
        for node in self.func.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Name):
                    if call.func.id in self._PURE_BUILTINS:
                        discarded_calls.append(call.func.id)
                elif isinstance(call.func, ast.Attribute):
                    # IG-10 (2026-09-06): a pure STRING method (join / replace / strip …) needs a string receiver by a visible
                    # fact — `os.replace(a, b)` and `thread.join()` share the name, not the purity.
                    if call.func.attr in self._PURE_METHODS and (call.func.attr not in _STR_METHOD_NAMES or self._receiver_is_str(call.func.value, node.lineno)):
                        discarded_calls.append(call.func.attr)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Await):
                continue  # awaited coroutine — the await is the effect

        if discarded_calls:
            self.observations.append({
                "tag": "NAI-022",
                "line": self.func.lineno,
                "func_name": m.name,
                "discarded_calls": discarded_calls,
                "discarded_count": len(discarded_calls),
            })
            _log.debug("NAI-022 observed: %d discarded pure results at line %d", len(discarded_calls), self.func.lineno)

    def _check_self_comparisons(self) -> None:
        """
        NAI-023: Comparisons of a value to itself.

        Invariant: Comparisons should be between different values.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                left = node.left
                for right in node.comparators:
                    if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                        if left.id == right.id:
                            self.observations.append({
                                "tag": "NAI-023",
                                "line": node.lineno,
                                "func_name": m.name,
                                "variable": left.id,
                                "op_type": type(node.ops[0]).__name__,
                            })
                            _log.debug("NAI-023 observed: self-comparison of %s at line %d", left.id, node.lineno)
                            return

    def _check_loop_patterns(self) -> None:
        """
        NAI-024: Additional loop fake patterns.
        """
        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While)):
                if len(node.body) >= 1:
                    first_stmt = node.body[0]
                    if isinstance(first_stmt, ast.Return):
                        # FACT (2026-09-06, body-shape stage): "for/while whose first
                        # statement is Return" is ALSO the correct, idiomatic shape of
                        # "get the first item of an iterable" (more_itertools.first:
                        # `for item in iterable: return item`) — mechanically identical
                        # to the plants (scan_values / drain_queue). The plants' loop is
                        # followed by NOTHING but a bare `return None`; the honest row is
                        # followed by real fallback logic (a raise, or a return of an
                        # actual parameter/computed value). "Trivial tail after the loop"
                        # (empty, or a single bare `return`/`return None`/`pass`) is the
                        # fact; real logic after the loop means it isn't degenerate.
                        tail = _stmts_after(self.func, node)
                        if not _is_trivial_tail(tail):
                            continue
                        self.observations.append({
                            "tag": "NAI-024",
                            "line": node.lineno,
                            "variant": "immediate_return",
                            "func_name": self.metrics.name,
                            "loop_type": type(node).__name__,
                        })
                        _log.debug("NAI-024 observed: loop returns immediately at line %d", node.lineno)
                        continue

                self._check_loop_overwrite(node)

    def _check_loop_overwrite(self, loop_node: ast.AST) -> None:
        """Check if loop overwrites instead of accumulates."""
        loop_var = None
        if isinstance(loop_node, ast.For):
            if isinstance(loop_node.target, ast.Name):
                loop_var = loop_node.target.id

        has_break = any(isinstance(n, ast.Break) for n in ast.walk(loop_node))
        if has_break:
            return

        for node in ast.walk(loop_node):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    target_name = node.targets[0].id
                    if isinstance(node.value, ast.Name):
                        if node.value.id == loop_var:
                            # FACT (2026-09-06, body-shape stage): every labeled honest
                            # row (click _parse_decls, idna intranges_from_list, jinja2
                            # visit_FromImport/rewrite_traceback_stack, packaging
                            # canonicalize_license_expression, werkzeug best_match, numpy
                            # get_masked_subclass/atleast_2d, rich Traceback.__init__/
                            # Segment.simplify, more_itertools mark_ends) either (a)
                            # assigns under a nested if/elif/else — a guarded reassignment,
                            # not a blind unconditional overwrite (click, jinja2 alias
                            # default, packaging final_token, werkzeug best-so-far, numpy
                            # rcls/result, rich path) — or (b) is a top-level,
                            # unconditional assign whose target is still READ again
                            # (Load) somewhere else INSIDE the very same loop body — the
                            # classic cursor/reverse-link idiom that consumes the OLD
                            # value before overwriting it, or uses the new value right
                            # after (idna last_write, jinja2 tb_next, rich prior-segment
                            # yield, more_itertools mark_ends a/b lookahead). A true blind
                            # overwrite (`total = 0` then `for x: total = x`) is neither
                            # nested NOR read again inside the loop — only discarded and
                            # picked up again after the loop via the final return, which
                            # every accumulator (honest or fake) does, so that doesn't
                            # count as "read".
                            is_top_level = any(node is s for s in loop_node.body)  # type: ignore[attr-defined]  # FIX_54 ast-pos
                            if is_top_level and not _name_read_in(loop_node, target_name):
                                self.observations.append({
                                    "tag": "NAI-024",
                                    "line": node.lineno,
                                    "variant": "overwrite_instead_of_accumulate",
                                    "func_name": self.metrics.name,
                                    "target_variable": target_name,
                                    "loop_variable": loop_var,
                                })
                                _log.debug("NAI-024 observed: loop overwrites at line %d", node.lineno)
                                return

    def _check_noop_operations(self) -> None:
        """
        NAI-025: No-op operations like x = x + 0, x = x * 1.

        Invariant: Operations should have effect.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    target = node.targets[0].id
                    value = node.value

                    if isinstance(value, ast.BinOp):
                        if isinstance(value.left, ast.Name) and value.left.id == target:
                            if isinstance(value.right, ast.Constant):
                                if isinstance(value.op, (ast.Add, ast.Sub)) and value.right.value == 0:
                                    self.observations.append({
                                        "tag": "NAI-025",
                                        "line": node.lineno,
                                        "func_name": m.name,
                                        "variable": target,
                                        "op": type(value.op).__name__,
                                        "identity_value": 0,
                                    })
                                    _log.debug("NAI-025 observed: noop +/- 0 at line %d", node.lineno)
                                elif isinstance(value.op, (ast.Mult, ast.Div)) and value.right.value == 1:  # noqa: E501
                                    self.observations.append({
                                        "tag": "NAI-025",
                                        "line": node.lineno,
                                        "func_name": m.name,
                                        "variable": target,
                                        "op": type(value.op).__name__,
                                        "identity_value": 1,
                                    })
                                    _log.debug("NAI-025 observed: noop */div 1 at line %d", node.lineno)

    # ------------------------------------------------------------------
    # NAI-170, NAI-174, NAI-175: Additional core checks
    # ------------------------------------------------------------------

    def _check_pre_increment_decrement(self) -> None:
        """
        NAI-170: Detect pre-increment/decrement misuse (++x or --x).

        In Python, ++x is UnaryOp(UAdd, UnaryOp(UAdd, x)) — a no-op.
        --x is UnaryOp(USub, UnaryOp(USub, x)) — also a no-op (double negation for ints).
        These are C/Java habits that do nothing in Python.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.UnaryOp):
                if isinstance(node.op, ast.UAdd) and isinstance(node.operand, ast.UnaryOp):
                    if isinstance(node.operand.op, ast.UAdd):
                        self.observations.append({
                            "tag": "NAI-170",
                            "line": node.lineno,
                            "variant": "pre_increment",
                            "func_name": m.name,
                        })
                        _log.debug("NAI-170 observed: pre-increment at line %d", node.lineno)
                        return
                if isinstance(node.op, ast.USub) and isinstance(node.operand, ast.UnaryOp):
                    if isinstance(node.operand.op, ast.USub):
                        if isinstance(node.operand.operand, ast.Name):
                            self.observations.append({
                                "tag": "NAI-170",
                                "line": node.lineno,
                                "variant": "pre_decrement",
                                "func_name": m.name,
                                "operand_name": node.operand.operand.id,
                            })
                            _log.debug("NAI-170 observed: pre-decrement at line %d", node.lineno)
                            return

    def _check_shadowing_builtins(self) -> None:
        """
        NAI-174: Detect variable names that shadow Python builtins.

        Pattern: list = [...], dict = {...}, type = ..., id = ...
        Shadows the builtin, causing hard-to-debug errors later.
        """
        m = self.metrics

        dangerous_builtins = {
            'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool',
            'type', 'id', 'input', 'range', 'len', 'map', 'filter', 'zip',
            'max', 'min', 'sum', 'sorted', 'reversed', 'enumerate',
            'open', 'print', 'format', 'hash', 'next', 'iter', 'object',
        }

        # FACT (2026-09-06, body-shape stage): shadowing one of these names is only the
        # invariant's actual harm ("hard-to-debug errors LATER") when this SAME function's
        # OWN scope also CALLS that name as a builtin -- i.e. still needs its real
        # behavior after rebinding it. Real code very commonly reuses a builtin word as a
        # plain local/parameter that mirrors a public API kwarg or an attribute of the
        # same name (click `min = self.min`, jinja2 `hash = sha1(...)`, attrs
        # `hash = unsafe_hash` for its own `hash=` kwarg, numpy `next = previous + 1`) and
        # never calls the builtin again in that scope -- nothing is actually broken.
        # Scoped to _own_scope (both the assign search and the call search) so a nested
        # def's own use doesn't count against, or get counted for, the outer function
        # that merely defines the name.
        called_names = {
            node.func.id
            for node in self._own_scope(self.func)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

        for node in self._own_scope(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in dangerous_builtins:
                        if target.id not in called_names:
                            continue
                        self.observations.append({
                            "tag": "NAI-174",
                            "line": node.lineno,
                            "func_name": m.name,
                            "shadowed_builtin": target.id,
                        })
                        _log.debug("NAI-174 observed: shadowing builtin %s at line %d", target.id, node.lineno)
                        return

    def _check_duplicate_dict_keys(self) -> None:
        """
        NAI-175: Detect duplicate keys in dict literals.

        Pattern: {'a': 1, 'b': 2, 'a': 3} — second 'a' silently overwrites first.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Dict):
                seen_keys: list[str] = []
                for key in node.keys:
                    if key is None:
                        continue
                    key_repr = ast.dump(key)
                    if key_repr in seen_keys:
                        key_str = ""
                        if isinstance(key, ast.Constant):
                            key_str = repr(key.value)
                        self.observations.append({
                            "tag": "NAI-175",
                            "line": node.lineno,
                            "func_name": m.name,
                            "duplicate_key": key_str,
                            "key_repr": key_repr,
                        })
                        _log.debug("NAI-175 observed: duplicate dict key at line %d", node.lineno)
                        return
                    seen_keys.append(key_repr)

    def _check_duplicate_dict_keys_semantic(self) -> None:
        """
        NAI-177: Duplicate dict keys in literals (semantic equivalence).

        Extends NAI-175 (AST-identical keys) to catch semantically equivalent
        keys that Python treats as equal: True/1, False/0, 1/1.0, etc.

        Pattern: {True: 'a', 1: 'b'}  — 1 overwrites True silently.
                 {0: 'x', False: 'y'} — False overwrites 0 silently.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Dict):
                seen_values: list[object] = []
                seen_reprs: list[str] = []
                for key in node.keys:
                    if key is None:
                        continue
                    if isinstance(key, ast.Constant):
                        val = key.value
                        # Check semantic equality (True == 1, False == 0, 1 == 1.0)
                        for i, prev_val in enumerate(seen_values):
                            if val == prev_val and type(val) is not type(prev_val):
                                self.observations.append({
                                    "tag": "NAI-177",
                                    "line": node.lineno,
                                    "func_name": m.name,
                                    "current_key_value": repr(val),
                                    "current_key_type": type(val).__name__,
                                    "collides_with_value": seen_reprs[i],
                                    "collides_with_type": type(prev_val).__name__,
                                })
                                _log.debug("NAI-177 observed: semantic key collision at line %d", node.lineno)
                        seen_values.append(val)
                        seen_reprs.append(repr(val))
