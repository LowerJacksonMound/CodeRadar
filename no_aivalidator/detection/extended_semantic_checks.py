"""
Extended Semantic Analysis Integration (NAI-120 to NAI-150).

Integrates the full semantic_analysis submodule capabilities:

Fast Static Filters (FSF):
- NAI-120: Empty function body (FSF001)
- NAI-121: Too many parameters (FSF002)
- NAI-122: Bare except clause (FSF010)
- NAI-123: Assert with tuple always true (FSF020)
- NAI-124: Comparison to None with == (FSF030)
- NAI-125: __init__ returns value (FSF050)
- NAI-126: Wildcard import (FSF070)
- NAI-127: eval/exec usage (FSF080)

Prefix Pattern Checks (PPC):
- NAI-130: Getter without return (PPC011)
- NAI-131: Setter returns value (PPC012)
- NAI-132: Boolean prefix wrong return type (PPC010)

CFG Analysis:
- NAI-140: Unreachable code after terminal (CFG001)
- NAI-141: Infinite loop without break (CFG010)
- NAI-142: Missing return on some paths (CFG020)
- NAI-143: Return in finally block (CFG050)

Def-Use Chains:
- NAI-145: Use before definition (DUC001)
- NAI-146: Redefinition without use (DUC010)
- NAI-147: Unused local variable (DUC020)
"""
from __future__ import annotations

import ast
import re as _re
_re_const = _re.compile(r"Constant\(value=[^)]*\)")
from typing import Any, Dict, Set, List, Optional, Iterator, TYPE_CHECKING
from enum import Enum, auto
import logging

from .evidence_lines import dead_value_lines

_log = logging.getLogger(__name__)


# =============================================================================
# FLOW STATE FOR CFG ANALYSIS
# =============================================================================

class FlowState(Enum):
    NORMAL = auto()
    RETURNS = auto()
    RAISES = auto()
    BREAKS = auto()
    CONTINUES = auto()


# =============================================================================
# NAI-131 APPLICABILITY — FIX_59 (2026-09-17)
# =============================================================================

def _is_real_setter(func: Any) -> bool:
    """NAI-131 fact (FIX_59, owner ruling on packet §A row #21): a `set_` PREFIX IS NOT A SETTER.

    A real setter STORES on `self.<attr>`, and what it returns is an ECHO of what it stored —
    `self.width = width` then `return width` (or `return self.width`, or `return self`). A
    `set_`-named function that stores nothing on the instance, or returns a computed PRODUCT, is a
    builder and out of NAI-131's scope: colorama's `ansi.py::set_title` returns
    `OSC + '2;' + title + BEL`, the escape string its callers write to the terminal, and dropping
    that return would silently hand every caller None.

    Read by the check itself, by the NAI-131 rewriter (`repair_generators/extended_semantic.py::
    fix_setter_return`) and by G0's predicate, so detector, rewriter and gate agree on one sentence.
    """
    echoes: Set[str] = set()
    stores = False
    for node in [n for n in ast.walk(func) if isinstance(n, ast.Assign)]:
        for target in node.targets:
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                stores = True
                echoes.add(target.attr)
                if isinstance(node.value, ast.Name):
                    echoes.add(node.value.id)
    returned = [n.value for n in ast.walk(func) if isinstance(n, ast.Return) and n.value is not None]
    # stores on the instance AND every return is an echo of what it stored (`width`, `self.width`,
    # `self`) — a computed product anywhere means the return is the API, not a leaked assignment.
    return stores and all(_is_echo(value, echoes) for value in returned)


def _is_echo(value: Any, echoes: Set[str]) -> bool:
    """The value a real setter is allowed to hand back: the name it stored, the attribute it stored
    it in, or the receiver itself (`return self`, which NAI-131 has always allowed)."""
    if isinstance(value, ast.Name):
        return value.id in echoes or value.id == "self"
    return isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == "self"


# =============================================================================
# EXTENDED CHECKS MIXIN
# =============================================================================

class ExtendedSemanticChecksMixin:
    """
    Extended semantic checks from noai_validator.semantic_analysis.

    Expects self.func (AST node), self.observations (list), and self.source (optional).
    """
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
        def _class_has_bases(self) -> bool: ...   # FIX_68 (I-150, 2026-09-21): the override reading needs the enclosing class's bases

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]

    # -------------------------------------------------------------------------
    # FAST STATIC FILTERS (FSF) - NAI-120 to NAI-129
    # -------------------------------------------------------------------------

    # FIX_68 (I-150, owner ruling R1 2026-09-21): the release hooks whose DOCUMENTED no-op override is
    # itself the implementation — the subclass declares "this object does not own the resource, so the
    # inherited teardown must not run". Closed set, resource-release only: a `close` / `flush` that does
    # nothing suppresses the base's teardown, `__del__` / `__exit__` the finalizer and the with-exit.
    # Anything else (a getter, a computation, a hook that must produce a value) keeps firing.
    _NOOP_OVERRIDE_HOOKS = ('close', 'flush', '__del__', '__exit__')

    def _is_documented_noop_override(self) -> bool:
        """FIX_68 (I-150, run 163, owner ruling R1 2026-09-21) — F-NOP1, the fifth DECLARATION shape.

        `click/testing.py::_NamedTextIOWrapper.close::184` is the case: a docstring-only `close` that
        overrides `io.TextIOWrapper.close` precisely so the inherited `__del__` will NOT close a buffer
        the object does not own. The empty body IS the implementation — `tests/test_stream_lifecycle.py
        ::test_wrapper_close_does_not_close_underlying_buffer` asserts it ("Calling ``close()`` on the
        wrapper must leave the buffer open"), and NAI-120's prescription (`raise NotImplementedError`)
        reddens 1166 of that suite's 1990 passing tests. The fire was a FALSE POSITIVE on a real
        lifecycle close (R1 (iii)); this is the predicate that recognises the shape.

        FOUR conjuncts, never the name alone (the reading NAI-011 already carries at
        `core_checks.py:_check_side_effect_free` — "a body that reduces to NOTHING after its docstring …
        is a documented no-op stub", narrowed there to METHODS by the orchestrator 2026-09-06 — plus the
        two facts that reading leaves open for NAI-120):
          1. a METHOD of a class with a REAL base (`_class_has_bases`): there is an inherited behaviour
             for the empty body to suppress. A class with no base, or a module-level def, has nothing to
             override and stays a fire — that is the unimplemented shape NAI-120 exists for.
          2. the name is one of `_NOOP_OVERRIDE_HOOKS`: doing nothing is a meaningful override there.
          3. the return annotation is exactly `-> None`: the method PROMISES no value, so an empty body
             is behaviour-complete. `-> int` on an empty body is still a broken promise and still fires.
          4. the body is EXACTLY the docstring — no `pass`, no `...`, nothing else. The docstring is the
             declaration; a bare `pass` with nothing written declares nothing and still fires.
        """
        m = self.metrics
        if not (m.is_method and self._class_has_bases()):
            return False
        if self.func.name not in self._NOOP_OVERRIDE_HOOKS:
            return False
        ann = self.func.returns
        if not (isinstance(ann, ast.Constant) and ann.value is None):
            return False
        body = self.func.body
        return (len(body) == 1 and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str))

    def _check_empty_function_body(self) -> None:
        """NAI-120: Empty function body (just pass or docstring)."""
        body = self.func.body
        m = self.metrics

        # Rules hardening 2026-09-05 (F-OVL1 / F-ABS1 / F-LBL1): a DECLARATION
        # body is not an empty implementation — @overload variants (mypy: the
        # ellipsis is the convention), @abstractmethod, typing.Protocol
        # members, `raise NotImplementedError` (pylint W0223: abstract).
        # FIX_68 (F-NOP1, I-150 / R1 2026-09-21): and a DOCUMENTED NO-OP OVERRIDE of an inherited
        # release hook — see `_is_documented_noop_override`.
        if (self._has_decorator('overload', 'abstractmethod')
                or (m.is_method and self._class_is_protocol())
                or m.body_is_raise_not_implemented
                or self._is_documented_noop_override()):
            return

        # Filter out a real docstring (a str constant) — `...` is NOT a docstring
        real_body: list[ast.stmt] = []
        for i, stmt in enumerate(body):
            if (i == 0 and isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)):
                continue  # Skip docstring
            real_body.append(stmt)

        if len(real_body) == 0:
            self._add_observation({
                "tag": "NAI-120",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "variant": "docstring_only",
            })
        elif len(real_body) == 1 and isinstance(real_body[0], ast.Pass):
            self._add_observation({
                "tag": "NAI-120",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "variant": "pass_only",
            })
        elif (len(real_body) == 1 and isinstance(real_body[0], ast.Expr)
              and isinstance(real_body[0].value, ast.Constant) and real_body[0].value.value is ...):
            self._add_observation({
                "tag": "NAI-120",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "variant": "ellipsis",   # F-LBL1: labelled for what it is
            })

    def _check_excessive_parameters(self) -> None:
        """NAI-121: Too many parameters (>7)."""
        args = self.func.args
        total = len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)

        # Exclude self/cls
        if args.args and args.args[0].arg in ("self", "cls"):
            total -= 1

        if total > 0:  # EXCISED cut 2 (2026-09-05): was `total > 7` — EXCISION_LIST class A
            self._add_observation({
                "tag": "NAI-121",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "param_count": total,
            })

    def _check_assert_tuple(self) -> None:
        """NAI-123: Assert with tuple is always True."""
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assert):
                if isinstance(node.test, ast.Tuple):
                    self._add_observation({
                        "tag": "NAI-123",
                        "line": node.lineno,
                        "func_name": self.func.name,
                        "tuple_length": len(node.test.elts),
                    })

    def _check_none_comparison(self) -> None:
        """NAI-124: Comparison to None with == instead of 'is'."""
        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(comparator, ast.Constant) and comparator.value is None:
                        if isinstance(op, (ast.Eq, ast.NotEq)):
                            self._add_observation({
                                "tag": "NAI-124",
                                "line": node.lineno,
                                "op": "==" if isinstance(op, ast.Eq) else "!=",
                            })

    def _check_init_return(self) -> None:
        """NAI-125: __init__ should not return a value."""
        if self.func.name != "__init__":
            return

        for node in self._own_scope(self.func):   # IG-9: a return inside a nested helper is the helper's, not __init__'s
            if isinstance(node, ast.Return) and node.value is not None:
                # Allow return None explicitly
                if not (isinstance(node.value, ast.Constant) and node.value.value is None):
                    self._add_observation({
                        "tag": "NAI-125",
                        "line": node.lineno,
                        "return_node_type": type(node.value).__name__,
                    })

    def _check_eval_exec(self) -> None:
        """NAI-127: eval/exec usage is dangerous."""
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    self._add_observation({
                        "tag": "NAI-127",
                        "line": node.lineno,
                        "callee": node.func.id,
                    })

    def _check_bare_except(self) -> None:
        """NAI-122: Bare except clause catches everything including SystemExit/KeyboardInterrupt."""
        for node in ast.walk(self.func):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                self._add_observation({
                    "tag": "NAI-122",
                    "line": node.lineno,
                    "func_name": self.func.name,
                })

    def _check_wildcard_import(self) -> None:
        """NAI-126: Wildcard import ('from X import *') pollutes the namespace."""
        for node in ast.walk(self.func):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        self._add_observation({
                            "tag": "NAI-126",
                            "line": node.lineno,
                            "module": node.module or "<unknown>",
                            "func_name": self.func.name,
                        })

    # -------------------------------------------------------------------------
    # PREFIX PATTERN CHECKS (PPC) - NAI-130 to NAI-139
    # -------------------------------------------------------------------------

    def _check_getter_return(self) -> None:
        """NAI-130: Getter functions (get_*) should return a value."""
        name = self.func.name.lower()
        if not name.startswith("get_"):
            return

        # Check for return with value
        has_value_return = False
        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value is not None:
                has_value_return = True
                break

        # IG-12 (2026-09-06, body-shape): a generator hands a value to its caller through `yield` /
        # `yield from`, not `return` — a statement-kind fact. Scoped to the function's OWN body (a
        # nested def's yield belongs to a different generator entirely) and symmetric with the
        # `node.value is not None` requirement above (a bare, valueless `yield` returns nothing either).
        if not has_value_return:
            for node in self._own_scope(self.func):
                if isinstance(node, ast.Yield) and node.value is not None:
                    has_value_return = True
                    break
                if isinstance(node, ast.YieldFrom):
                    has_value_return = True
                    break

        if not has_value_return:
            self._add_observation({
                "tag": "NAI-130",
                "line": self.func.lineno,
                "func_name": self.func.name,
            })

    def _check_setter_return(self) -> None:
        """NAI-131: Setter functions (set_*) should not return a value.

        FIX_59 (2026-09-17, owner ruling on packet §A row #21): a `set_` PREFIX is not a setter. The
        check used to fire on the name alone, so colorama's `ansi.py::set_title` — a public
        escape-string builder that returns `OSC + '2;' + title + BEL` — was reported as a setter
        leaking its value, and the rewriter dropped the return. That is a DETECTOR false positive
        first: the row must not exist. `_is_real_setter` is the applicability — stores on `self.<attr>`
        and returns only an echo of what it stored — the same reading G0's NAI-131 predicate uses
        (`repair_generators/gate.py::_nai131_real_setter`, narrowing 3) and the rewriter's own
        (`repair_generators/extended_semantic.py::fix_setter_return`).
        """
        name = self.func.name.lower()
        if not name.startswith("set_"):
            return
        if not _is_real_setter(self.func):
            return

        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value is not None:
                # Allow returning self for chaining
                if isinstance(node.value, ast.Name) and node.value.id == "self":
                    continue
                self._add_observation({
                    "tag": "NAI-131",
                    "line": node.lineno,
                    "func_name": self.func.name,
                    "return_node_type": type(node.value).__name__,
                })
                break

    def _check_boolean_prefix_return(self) -> None:
        """NAI-132: Boolean prefix functions (is_*, has_*, can_*) should return bool."""
        name = self.func.name.lower()
        bool_prefixes = ("is_", "has_", "can_", "should_", "will_", "did_")

        if not any(name.startswith(p) for p in bool_prefixes):
            return

        # Check return type annotation
        if self.func.returns:
            if isinstance(self.func.returns, ast.Name):
                if self.func.returns.id != "bool":
                    self._add_observation({
                        "tag": "NAI-132",
                        "line": self.func.lineno,
                        "func_name": self.func.name,
                        "annotated_return": self.func.returns.id,
                    })

    # -------------------------------------------------------------------------
    # CFG ANALYSIS - NAI-140 to NAI-144
    # -------------------------------------------------------------------------

    def _analyze_flow(self, stmts: list[ast.stmt], suppress_stopiteration: bool = False) -> FlowState:
        """Analyze control flow of a statement list."""
        for i, stmt in enumerate(stmts):
            state = self._stmt_flow_state(stmt, suppress_stopiteration)

            if state != FlowState.NORMAL and i < len(stmts) - 1:
                # Code after terminal statement
                self._add_observation({
                    "tag": "NAI-140",
                    "line": stmts[i + 1].lineno,
                    "func_name": self.func.name,
                    "terminal_type": type(stmt).__name__,
                    "terminal_line": stmt.lineno,
                })
                return state

            if state != FlowState.NORMAL:
                return state

        return FlowState.NORMAL

    # IG-6 (2026-09-06): a function annotated NoReturn / Never owes no return path, and a call to one terminates.
    _NORETURN_ANNOTATIONS = ("NoReturn", "Never")
    _STDLIB_NORETURN = {("sys", "exit"), ("os", "_exit"), ("os", "abort"), (None, "exit"), (None, "quit")}

    def _annotation_is_noreturn(self, ann) -> bool:
        if isinstance(ann, ast.Name):
            return ann.id in self._NORETURN_ANNOTATIONS
        if isinstance(ann, ast.Attribute):
            return ann.attr in self._NORETURN_ANNOTATIONS
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            return ann.value.rsplit(".", 1)[-1] in self._NORETURN_ANNOTATIONS
        return False

    def _call_never_returns(self, call: ast.Call) -> bool:
        """A call to a NEVER-RETURNING callee: a stdlib NoReturn (sys.exit …) or a def in THIS module annotated NoReturn
        (the validator hands the module's NoReturn-annotated names over — a lexical fact, never a name guess)."""
        f = call.func
        if isinstance(f, ast.Name):
            return (None, f.id) in self._STDLIB_NORETURN or f.id in getattr(self, "noreturn_names", set())
        if isinstance(f, ast.Attribute):
            root = f.value.id if isinstance(f.value, ast.Name) else None
            return (root, f.attr) in self._STDLIB_NORETURN or f.attr in getattr(self, "noreturn_names", set())
        return False

    @staticmethod
    def _withitems_suppress_stopiteration(items: list[ast.withitem]) -> bool:
        """IG-14 (2026-09-06, body-shape): True when a `with` item's context manager is
        `suppress(...)` / `contextlib.suppress(...)` naming StopIteration among its excepted types."""
        for item in items:
            ctx = item.context_expr
            if not isinstance(ctx, ast.Call):
                continue
            f = ctx.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name != "suppress":
                continue
            for a in ctx.args:
                if isinstance(a, ast.Name) and a.id == "StopIteration":
                    return True
                if isinstance(a, ast.Attribute) and a.attr == "StopIteration":
                    return True
        return False

    def _stmt_flow_state(self, stmt: ast.stmt, suppress_stopiteration: bool = False) -> FlowState:
        """Determine flow state after a statement."""
        if isinstance(stmt, ast.Return):
            return FlowState.RETURNS
        elif isinstance(stmt, ast.Raise):
            return FlowState.RAISES
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and self._call_never_returns(stmt.value):
            return FlowState.RAISES   # IG-6: a never-returning call terminates the path
        elif isinstance(stmt, ast.Break):
            return FlowState.BREAKS
        elif isinstance(stmt, ast.Continue):
            return FlowState.CONTINUES
        elif isinstance(stmt, ast.If):
            then_state = self._analyze_flow(stmt.body, suppress_stopiteration)
            else_state = self._analyze_flow(stmt.orelse, suppress_stopiteration) if stmt.orelse else FlowState.NORMAL
            if then_state in (FlowState.RETURNS, FlowState.RAISES) and \
               else_state in (FlowState.RETURNS, FlowState.RAISES):
                return FlowState.RETURNS
            return FlowState.NORMAL
        elif isinstance(stmt, ast.While):
            if isinstance(stmt.test, ast.Constant) and stmt.test.value is True:
                has_break = any(isinstance(n, (ast.Break, ast.Return, ast.Raise)) or
                                (isinstance(n, ast.Call) and self._call_never_returns(n))
                                for n in self._own_scope(stmt))   # IG-11: return / raise / a never-returning call exit `while True` too
                # IG-14 (2026-09-06, body-shape): inside a `with suppress(StopIteration):`, any call in the loop
                # body may raise StopIteration — the suppress swallows it, ending the with-block (and the loop
                # with it) from the outside; the loop itself needs no internal break/return/raise.
                if not has_break and suppress_stopiteration:
                    has_break = any(isinstance(n, ast.Call) for n in self._own_scope(stmt))
                if not has_break:
                    self._add_observation({
                        "tag": "NAI-141",
                        "line": stmt.lineno,
                        "func_name": self.func.name,
                    })
            return FlowState.NORMAL
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            # IG-2 (calibrator slice 1, 2026-09-06): a `with` block's body IS the path — `with open(p) as fh: return fh.read()`
            # returns on every path; before, every With was NORMAL and NAI-142 fired on it.
            nested_suppress = suppress_stopiteration or self._withitems_suppress_stopiteration(stmt.items)
            return self._analyze_flow(stmt.body, nested_suppress)
        elif isinstance(stmt, ast.Try):
            # Check for return in finally
            finally_returns = False
            for final_stmt in stmt.finalbody:
                if isinstance(final_stmt, ast.Return):
                    finally_returns = True
                    self._add_observation({
                        "tag": "NAI-143",
                        "line": final_stmt.lineno,
                        "func_name": self.func.name,
                    })
            if finally_returns:
                return FlowState.RETURNS
            # IG-2 (calibrator slice 1, 2026-09-06): every path through a Try returns when (the body returns / raises, or
            # the body completes and the else returns / raises) AND every handler returns / raises. Before, every Try was
            # NORMAL, so `try: return int(x) / except ValueError: return 0` was reported as "may not return".
            terminal = (FlowState.RETURNS, FlowState.RAISES)
            body_state = self._analyze_flow(stmt.body, suppress_stopiteration)
            else_state = self._analyze_flow(stmt.orelse, suppress_stopiteration) if stmt.orelse else FlowState.NORMAL
            handler_states = [self._analyze_flow(h.body, suppress_stopiteration) for h in stmt.handlers]
            main_terminal = body_state in terminal or else_state in terminal
            if main_terminal and all(hs in terminal for hs in handler_states):
                return FlowState.RETURNS
            return FlowState.NORMAL
        return FlowState.NORMAL

    def _check_missing_return_paths(self) -> None:
        """NAI-142: Function may not return a value on all paths."""
        # Skip if no return annotation or annotated as None
        if self.func.returns is None:
            return
        if isinstance(self.func.returns, ast.Constant) and self.func.returns.value is None:
            return
        if isinstance(self.func.returns, ast.Name) and self.func.returns.id == "None":
            return
        if self._annotation_is_noreturn(self.func.returns):
            return   # IG-6: NoReturn / Never owes no return path

        # Skip generators
        for node in ast.walk(self.func):
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                return
        # Rules hardening 2026-09-05 (F-OVL1 / F-ABS1): a declaration body —
        # @overload variant, Protocol / abstract method, `...`, `pass`,
        # `raise NotImplementedError` — has no return path BY DESIGN.
        m = self.metrics
        if (m.body_is_ellipsis or m.body_is_pass or m.body_is_raise_not_implemented
                or self._has_decorator('overload', 'abstractmethod')
                or (m.is_method and self._class_is_protocol())):
            return

        # Check flow
        state = self._analyze_flow(self.func.body)
        if state == FlowState.NORMAL:
            self._add_observation({
                "tag": "NAI-142",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "return_annotation": ast.dump(self.func.returns) if self.func.returns else None,
            })

    def _check_cfg_issues(self) -> None:
        """Run all CFG checks."""
        self._analyze_flow(self.func.body)
        self._check_missing_return_paths()

    # -------------------------------------------------------------------------
    # DEF-USE CHAIN ANALYSIS - NAI-145 to NAI-149
    # -------------------------------------------------------------------------

    def _build_def_use_info(self) -> tuple[set[str], set[str], set[str]]:
        """
        Build definition and use information for the function.
        Returns: (defined_names, used_names, params)
        """
        params: set[str] = set()
        for arg in self.func.args.args + self.func.args.posonlyargs + self.func.args.kwonlyargs:
            if arg.arg not in ("self", "cls"):
                params.add(arg.arg)

        defined = set(params)  # Params are defined at function entry
        used: set[str] = set()

        # IG-9 / IG-11 (2026-09-06): this function's OWN scope; `del x` is a use; a comprehension's targets are the
        # comprehension's own names (Python 3), never this function's locals.
        comp_targets: set[str] = set()
        # IG-17 (2026-09-06, body-shape): a `for` loop's target binds a name because the ITERATION mechanism needs
        # somewhere to put each item, not because the body captured a computation — more_itertools `for k, g in
        # groupby(...): yield ...g...` (k unused) and `for first in it: ... return` (the value is never read, only
        # the iteration/exhaustion matters) are the honest idiom; a for-target is never a dead store. Separately, a
        # name that is one element of a multi-name Assign target (tuple/list unpack of 2+ names) is an intentional
        # discard of an unwanted sibling when at least one OTHER element of that SAME unpack is read elsewhere —
        # the multi-return-discard idiom (urllib3 `(version, code, message) = ...` keeps code/message, drops
        # version; werkzeug `stream, length, boundary = ...` keeps stream/boundary, drops length). A tuple-unpack
        # where NO element is ever read is still a genuinely dead computation and keeps firing.
        loop_targets: set[str] = set()
        tuple_groups: list[set[str]] = []
        # IG-9b (2026-09-06, round 2): a READ anywhere inside this function — a nested def's body, a lambda, a nested class,
        # a nested def's decorator or default expression — is a use of this function's local (a closure reads it).
        # DEFINITIONS stay own-scope: a nested def's own assignments are not this function's locals.
        for node in ast.walk(self.func):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Load, ast.Del)):
                used.add(node.id)
        for node in self._own_scope(self.func):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    defined.add(node.id)
            elif isinstance(node, ast.NamedExpr):
                defined.add(node.target.id)
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for gen in node.generators:
                    comp_targets |= {n.id for n in ast.walk(gen.target) if isinstance(n, ast.Name)}
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                loop_targets |= {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)}
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, (ast.Tuple, ast.List)) and len(tgt.elts) > 1:
                        names = {e.id for e in tgt.elts if isinstance(e, ast.Name)}
                        if len(names) > 1:
                            tuple_groups.append(names)
        defined -= (comp_targets - params)
        defined -= (loop_targets - params)
        for group in tuple_groups:
            if group & used:  # at least one sibling of this unpack is read elsewhere
                defined -= (group - used - params)  # the unread siblings are discards, not dead stores

        return defined, used, params

    def _check_use_before_def(self) -> None:
        """NAI-145: Variable used before definition."""
        # This is complex to do properly - simplified version
        # Track first use vs first definition line numbers

        first_def: dict[str, int] = {}
        first_use: dict[str, int] = {}

        # IG-7 (2026-09-06): this function's OWN scope only — a nested def / lambda / class is another scope; a
        # comprehension's targets belong to the comprehension (Python 3) and never read "before definition".
        def own_scope(root):
            stack = list(ast.iter_child_nodes(root))
            while stack:
                n = stack.pop()
                yield n
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                    continue
                stack.extend(ast.iter_child_nodes(n))
        comp_targets: set[str] = set()
        for n in own_scope(self.func):
            if isinstance(n, ast.comprehension):
                comp_targets.update(t.id for t in ast.walk(n.target) if isinstance(t, ast.Name))

        # IG-1 (calibrator slice 1, 2026-09-06): ast.walk is breadth-first, so "first" used to mean SHALLOWEST, not
        # earliest — a read nested in a branch before a later bare `return name` was never seen (the bare return, one
        # level up, claimed the first use). First use / first definition are the MINIMUM line, as the words say.
        for node in own_scope(self.func):
            if isinstance(node, ast.Name) and node.id not in comp_targets:
                name = node.id
                if name in ("self", "cls"):
                    continue

                if isinstance(node.ctx, ast.Store):
                    if name not in first_def or node.lineno < first_def[name]:
                        first_def[name] = node.lineno
                elif isinstance(node.ctx, ast.Load):
                    if name not in first_use or node.lineno < first_use[name]:
                        first_use[name] = node.lineno

        # Get params (always defined at line 0 conceptually)
        params = {arg.arg for arg in self.func.args.args + self.func.args.posonlyargs + self.func.args.kwonlyargs}
        for va in (self.func.args.vararg, self.func.args.kwarg):   # IG-7: *args / **kwargs are parameters too
            if va is not None:
                params.add(va.arg)

        # Builtins
        builtins_set: set[str] = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))

        declared_outside: set[str] = set()
        for _n in ast.walk(self.func):
            if isinstance(_n, (ast.Global, ast.Nonlocal)):
                declared_outside.update(_n.names)

        for name, use_line in first_use.items():
            if name in params or name in builtins_set or name in declared_outside:
                continue  # run 19 (2026-09-05): a `global` is defined by its module
            if name not in first_def:
                # Used but never defined in this function - might be closure or global
                continue
            if first_use[name] < first_def[name]:
                self._add_observation({
                    "tag": "NAI-145",
                    "line": use_line,
                    "variable": name,
                    "use_line": use_line,
                    "def_line": first_def[name],
                })

    def _check_redefinition_without_use(self) -> None:
        """NAI-146: Variable redefined before its previous value was used."""
        # Walk statements in order, tracking last-defined-line per name.
        # If a name is assigned again before any Load reference, the first
        # assignment was wasted.
        last_def: dict[str, int] = {}
        used_since_def: set[str] = set()

        params = {arg.arg for arg in (
            self.func.args.args + self.func.args.posonlyargs + self.func.args.kwonlyargs
        )}

        for node in ast.walk(self.func):
            if not hasattr(node, "lineno"):
                continue
            if isinstance(node, ast.Name):
                name = node.id
                if name.startswith("_") or name in ("self", "cls") or name in params:
                    continue
                if isinstance(node.ctx, ast.Load):
                    used_since_def.add(name)
                elif isinstance(node.ctx, ast.Store):
                    if name in last_def and name not in used_since_def:
                        self._add_observation({
                            "tag": "NAI-146",
                            "line": node.lineno,
                            "variable": name,
                            "prev_def_line": last_def[name],
                        })
                    last_def[name] = node.lineno
                    used_since_def.discard(name)

    def _check_unused_variables(self) -> None:
        """NAI-147: Local variable defined but never used."""
        # IG-17 (2026-09-06, body-shape): a bare call to locals()/vars() anywhere in the body reflects every local
        # by name (rich scope.py `test()`: `render_scope(locals(), ...)`) — the call IS the use of every local, so
        # the dead-store check does not apply to a function that introspects its own namespace this way.
        for node in ast.walk(self.func):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in ("locals", "vars") and not node.args and not node.keywords):
                return

        defined, used, params = self._build_def_use_info()

        # Collect global/nonlocal declarations — these write to outer scope intentionally
        outer_scope: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Global):
                outer_scope.update(node.names)
            elif isinstance(node, ast.Nonlocal):
                outer_scope.update(node.names)

        # Find defined but not used (excluding params and global/nonlocal)
        unused = defined - used - params - outer_scope

        # Filter out private names (underscore prefix)
        for name in unused:
            if name.startswith("_"):
                continue
            self._add_observation({
                "tag": "NAI-147",
                "line": self.func.lineno,
                "variable": name,
                "lines": dead_value_lines(self.func, [name]),
                "func_name": self.func.name,
            })

    # -------------------------------------------------------------------------
    # ADDITIONAL FSF - NAI-128
    # -------------------------------------------------------------------------

    def _check_mutable_default_nested(self) -> None:
        """NAI-128: Mutable default argument in nested function definition."""
        for node in ast.walk(self.func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not self.func:
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        self._add_observation({
                            "tag": "NAI-128",
                            "line": node.lineno,
                            "nested_func": node.name,
                            "outer_func": self.func.name,
                            "mutable_type": type(default).__name__,
                        })
                        return

    # -------------------------------------------------------------------------
    # ADDITIONAL PPC - NAI-133 to NAI-138
    # -------------------------------------------------------------------------

    def _check_process_without_iteration(self) -> None:
        """NAI-133: process_*/transform_* function without any loop or comprehension."""
        name = self.func.name.lower()
        if not any(name.startswith(p) for p in ("process_", "transform_", "batch_")):
            return

        has_loop = False
        for node in ast.walk(self.func):
            if isinstance(node, (ast.For, ast.While, ast.AsyncFor,
                                 ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                has_loop = True
                break

        if not has_loop:
            # Check if it delegates to another function (acceptable)
            call_count = sum(1 for n in ast.walk(self.func) if isinstance(n, ast.Call))
            if call_count == 0:
                self._add_observation({
                    "tag": "NAI-133",
                    "line": self.func.lineno,
                    "func_name": self.func.name,
                })

    def _check_filter_without_conditional(self) -> None:
        """NAI-134: filter_* function without any conditional logic."""
        name = self.func.name.lower()
        if not any(name.startswith(p) for p in ("filter_", "exclude_", "select_")):
            return

        has_conditional = False
        for node in ast.walk(self.func):
            if isinstance(node, (ast.If, ast.IfExp, ast.Compare)):
                has_conditional = True
                break
            # Comprehension with if clause
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                for gen in node.generators:
                    if gen.ifs:
                        has_conditional = True
                        break

        if not has_conditional:
            self._add_observation({
                "tag": "NAI-134",
                "line": self.func.lineno,
                "func_name": self.func.name,
            })

    def _is_key_callable(self) -> bool:
        """I-132 / Q4 (session 8, run 160): is this function a `key=` CALLABLE rather than a
        function that sorts?

        NAI-135 reads `sort_*` as verb + object ("sort the users"). `sort_key` is the opposite
        parse — noun phrase, "the sort KEY" — and a key callable is BUILT not to sort: it takes one
        item and returns the value the sort is ordered by. `click.core.sort_key` (the closure passed
        to `sorted(declaration_order, key=sort_key)`) was failed by NAI-135 on the shakedown target,
        a category error, not a finding. The test is structural, not a name list: one parameter, and
        every value it returns is DERIVED from that parameter (an attribute, a subscript, a call, a
        tuple of them) rather than the parameter itself or a constant.
        """
        name = self.func.name.lower()
        if not (name.endswith("key") or name.endswith("keyfunc") or name.endswith("key_func")):
            return False
        args = [a.arg for a in self.func.args.args if a.arg not in ("self", "cls")]
        if len(args) != 1 or self.func.args.vararg or self.func.args.kwarg:
            return False
        item = args[0]
        returns = [n for n in self._own_scope(self.func)
                   if isinstance(n, ast.Return) and n.value is not None]
        if not returns:
            return False
        for r in returns:
            if isinstance(r.value, ast.Name) and r.value.id == item:
                return False   # returns the item unchanged — a no-op, not a key projection
            reads = {n.id for n in ast.walk(r.value)   # type: ignore[arg-type]
                     if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            if item not in reads and not (reads & self.enclosing_names):
                return False   # a return that reads neither the item nor the closure's own names
        return True

    def _check_sort_without_comparison(self) -> None:
        """NAI-135: sort_*/order_* function without sort/comparison.

        Q4 (session 8): a `key=` callable is exempt — it produces the ordering value, it does not
        order anything, so "no sort call in the body" is its correct shape, not a deficit.
        """
        name = self.func.name.lower()
        if not any(name.startswith(p) for p in ("sort_", "order_", "rank_")):
            return
        if self._is_key_callable():
            return

        has_sort = False
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'sorted':
                    has_sort = True
                    break
                if isinstance(node.func, ast.Attribute) and node.func.attr in ('sort', 'sorted'):
                    has_sort = True
                    break
            if isinstance(node, ast.Compare):
                has_sort = True
                break

        if not has_sort:
            self._add_observation({
                "tag": "NAI-135",
                "line": self.func.lineno,
                "func_name": self.func.name,
            })

    def _check_count_without_accumulator(self) -> None:
        """NAI-136: count_* function without counter/accumulator."""
        name = self.func.name.lower()
        if not any(name.startswith(p) for p in ("count_", "tally_", "total_")):
            return

        has_accumulator = False
        for node in ast.walk(self.func):
            # cr_trials round three (2026-11-04): `-=` (a count-down), `x = x + 1` and `d[k] = d.get(k, 0) + 1` are
            # accumulation too; the test saw only `+=` and flagged three honest counters (counter.count_down,
            # wordfreq.count_words, the plant's count_up_to). A body that never adds or subtracts is still flagged.
            if isinstance(node, ast.AugAssign) and isinstance(node.op, (ast.Add, ast.Sub)):
                has_accumulator = True
                break
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Sub)):
                has_accumulator = True
                break
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ('len', 'sum', 'count'):
                    has_accumulator = True
                    break
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'count':
                    has_accumulator = True
                    break

        if not has_accumulator:
            self._add_observation({
                "tag": "NAI-136",
                "line": self.func.lineno,
                "func_name": self.func.name,
            })

    def _check_answer_table(self) -> None:
        """NAI-260: an answer table. A ladder of `if <input> == <constant>` branches that each replay the same
        statements with different constants, and no branch that computes from the input (cr_trials round four,
        2026-11-04; the T4 claim species: right only for the inputs its tests use). A pure lookup ladder (branches
        that only `return` a constant) is a table by design and is not this; a branch that does real work is not this."""
        def strip_constants(node):
            return ast.dump(node).replace("Constant(value=", "Constant(").__class__ and _re_const.sub("Constant(value=~)", ast.dump(node))

        def is_key_test(test):
            if not (isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) and all(isinstance(op, ast.Eq) for op in test.ops)):
                return None
            sides = [test.left] + list(test.comparators)
            consts = [x for x in sides if isinstance(x, ast.Constant)]
            others = [x for x in sides if not isinstance(x, ast.Constant)]
            if consts and others and not others[1:]:
                return ast.dump(others[0])
            return None

        branches = []
        for stmt in self.func.body:
            if isinstance(stmt, ast.If) and not stmt.orelse:
                keyed = is_key_test(stmt.test)
                if keyed:
                    branches.append((keyed, stmt))
        if not branches[1:]:
            return
        keyed_on = branches[0][0]
        if any(k != keyed_on for k, _ in branches):
            return
        shapes = set()
        for _, stmt in branches:
            body = [n for n in stmt.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
            if not body[1:]:
                return  # a lone statement per branch: a lookup, not a replayed recipe
            if any(not isinstance(n, ast.Return) and any(isinstance(c, ast.Call) for c in ast.walk(n) if c is not n) and
                   not all(isinstance(a, ast.Constant) for c in ast.walk(n) if isinstance(c, ast.Call) for a in c.args) for n in body):
                return  # a branch that computes with non-constant arguments is doing work
            shapes.add("|".join(strip_constants(n) for n in body))
        _one_shape, *other_shapes = shapes
        if other_shapes:
            return
        self._add_observation({
            "tag": "NAI-260",
            "line": self.func.lineno,
            "func_name": self.func.name,
            "keyed_on": keyed_on,
            "branches": len(branches),
        })

    def _check_search_without_comparison(self) -> None:
        """NAI-137: search_*/find_* function without any comparison."""
        name = self.func.name.lower()
        if not any(name.startswith(p) for p in ("search_", "find_", "lookup_", "locate_")):
            return

        has_comparison = False
        for node in ast.walk(self.func):
            if isinstance(node, (ast.Compare, ast.IfExp)):
                has_comparison = True
                break
            if isinstance(node, ast.If):
                has_comparison = True
                break
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('find', 'index', 'search', 'match', 'get'):
                        has_comparison = True
                        break
                if isinstance(node.func, ast.Name):
                    if node.func.id in ('filter', 'next'):
                        has_comparison = True
                        break

        if not has_comparison:
            self._add_observation({
                "tag": "NAI-137",
                "line": self.func.lineno,
                "func_name": self.func.name,
            })

    def _check_build_without_return(self) -> None:
        """NAI-138: build_*/create_* function without return statement."""
        name = self.func.name.lower()
        if not any(name.startswith(p) for p in ("build_", "create_", "make_", "generate_", "construct_")):
            return

        has_return = False
        for node in ast.walk(self.func):
            if isinstance(node, ast.Return) and node.value is not None:
                has_return = True
                break
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                has_return = True
                break

        if not has_return:
            self._add_observation({
                "tag": "NAI-138",
                "line": self.func.lineno,
                "func_name": self.func.name,
            })

    # -------------------------------------------------------------------------
    # ADDITIONAL DUC - NAI-148
    # -------------------------------------------------------------------------

    def _check_import_reassignment(self) -> None:
        """NAI-148: Imported name reassigned to something else."""
        # Get names imported at the top of the function
        imported: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)

        if not imported:
            self._add_observation({"tag": 'NAI-148', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not imported'})  # EXCISED cut 3 batch 5 (2026-09-06, line read): silence → measured-nothing context
            return

        # Check if any imported name is reassigned
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in imported:
                        self._add_observation({
                            "tag": "NAI-148",
                            "line": node.lineno,
                            "variable": target.id,
                            "func_name": self.func.name,
                        })
                        return

    # -------------------------------------------------------------------------
    # TEST QUALITY CHECKS - NAI-129, NAI-139, NAI-149, NAI-150
    # -------------------------------------------------------------------------

    def _check_mock_everything_test(self) -> None:
        """NAI-129: Test that mocks all real dependencies — fake integration test."""
        if not self.func.name.startswith('test_'):
            return

        mock_count = 0
        call_count = 0

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                call_count += 1
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('patch', 'mock', 'Mock', 'MagicMock',
                                          'create_autospec', 'PropertyMock'):
                        mock_count += 1
                elif isinstance(node.func, ast.Name):
                    if node.func.id in ('patch', 'mock', 'Mock', 'MagicMock',
                                        'create_autospec', 'mocker'):
                        mock_count += 1

        # Also count @patch decorators
        for decorator in self.func.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute) and decorator.func.attr == 'patch':
                    mock_count += 1
                elif isinstance(decorator.func, ast.Name) and decorator.func.id == 'patch':
                    mock_count += 1
            elif isinstance(decorator, ast.Attribute) and decorator.attr == 'patch':
                mock_count += 1

        _mock_only = bool(mock_count) and self._asserts_only_mocks()   # a fact about the asserts, whatever the ratio
        if mock_count >= 1 and call_count > 0:  # EXCISED cut 2 (2026-09-05): was `mock_count >= 3 and call_count > 0` — EXCISION_LIST class A
            real_calls = call_count - mock_count
            if real_calls <= mock_count or _mock_only:
                # owner 2026-10-07 (tests judged like any file): WHAT the asserts check, as a fact — `mock_only_asserts`
                # when every assert touches only mock objects (it passes whatever the real code does),
                # `real_asserts` when some assert checks a real value. The disposition table reads `variant`.
                self._add_observation({
                    "tag": "NAI-129",
                    "line": self.func.lineno,
                    "func_name": self.func.name,
                    "mock_count": mock_count,
                    "real_call_count": real_calls,
                    "total_call_count": call_count,
                    "variant": "mock_only_asserts" if _mock_only else "real_asserts",
                })

    def _asserts_only_mocks(self) -> bool:
        """Every assertion in the test reads only mock objects: names bound from Mock()/MagicMock()/patch(…)/mocker,
        `@patch` arguments, or a mock's own assert_called*/assert_* method. No assertion at all is not this fact."""
        mock_ctor = ('Mock', 'MagicMock', 'AsyncMock', 'PropertyMock', 'NonCallableMock', 'create_autospec', 'patch')
        mocks = set()
        for node in ast.walk(self.func):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.withitem)):
                val = node.value if not isinstance(node, ast.withitem) else node.context_expr
                tgts = (node.targets if isinstance(node, ast.Assign) else
                        [node.target] if isinstance(node, ast.AnnAssign) else [node.optional_vars] if node.optional_vars else [])
                is_mock = isinstance(val, ast.Call) and any(
                    (isinstance(x, ast.Name) and x.id in mock_ctor) or (isinstance(x, ast.Attribute) and x.attr in mock_ctor)
                    for x in ast.walk(val.func))
                if is_mock:
                    mocks |= {t.id for tgt in tgts for t in ast.walk(tgt) if isinstance(t, ast.Name)}
        n_patch = sum(1 for d in self.func.decorator_list if 'patch' in ast.unparse(d))
        args = [a.arg for a in self.func.args.args if a.arg not in ('self', 'cls')]
        mocks |= set(args[len(args) - n_patch:]) if n_patch else set()
        mocks |= {a for a in args if a.startswith('mock') or a == 'mocker'}
        checks = []
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assert):
                checks.append(node.test)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr.startswith('assert'):
                base = node.func.value
                if isinstance(base, ast.Name) and base.id == 'self':
                    checks.extend(node.args)                       # self.assertEqual(a, b): its arguments are checked
                else:
                    checks.append(base)                            # mock.assert_called_once(): the mock itself
        if not checks:
            return False
        for c in checks:
            names = {x.id for x in ast.walk(c) if isinstance(x, ast.Name)}
            consts_only = not names
            if consts_only or not (names & mocks) or (names - mocks - {'self', 'len', 'call', 'ANY'}):
                return False
        return True

    def _check_tautological_test(self) -> None:
        """NAI-139: Test that mirrors implementation logic rather than validating behavior."""
        if not self.func.name.startswith('test_'):
            return

        # Pattern: test that computes the expected value the same way as the code under test
        # Detect: result = func(x); assert result == x * 2  (when func does x * 2)
        # Simplified: flag tests where assert compares call result to an inline computation
        # that uses the same args

        # cr_trials round three, step 3 (2026-11-04): the old test ("a BinOp in the comparator") caught neither rigged
        # test and flagged a property test (len(x) == len(a) + len(b)). A test mirrors the implementation when the
        # EXPECTED side is built by calling the same callee as the result side, directly or through a local name
        # assigned from such a call (stress case 10: expected = tally.reset_count(...); assert tally.reset_count(s) == expected).
        import builtins as _bi

        def callee(node):
            # a builtin (len, str, sum) on both sides is a property, not a mirror of the code under test
            if isinstance(node, ast.Call) and not (isinstance(node.func, ast.Name) and hasattr(_bi, node.func.id)):
                return ast.dump(node.func)
            return None

        def callees_in(node, env):
            out = set()
            for n in ast.walk(node):
                c = callee(n)
                if c:
                    out.add(c)
                if isinstance(n, ast.Name) and n.id in env:
                    out |= env[n.id]
            return out

        env: Dict[str, Set[str]] = {}
        node: ast.AST
        for node in self.func.body:
            if isinstance(node, ast.Assign):
                first, *rest = node.targets
                if not rest and isinstance(first, ast.Name):
                    env[first.id] = callees_in(node.value, env)

        assert_count = 0
        recompute_count = 0
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare):
                assert_count += 1
                left = callees_in(node.test.left, env)
                right = set()
                for comp in node.test.comparators:
                    right |= callees_in(comp, env)
                if left and right and (left & right):
                    recompute_count += 1

        if assert_count > 0 and recompute_count == assert_count:
            self._add_observation({
                "tag": "NAI-139",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "assert_count": assert_count,
                "recompute_count": recompute_count,
            })

    def _check_happy_path_only_test(self) -> None:
        """NAI-149: Test with zero negative/edge/error test cases."""
        if not self.func.name.startswith('test_'):
            return
        if self._has_decorator('parametrize', 'raises', 'xfail'):
            return  # hardened 2026-09-05: the cases live in the decorator, not the body

        # Check for any error/edge case testing patterns
        has_error_test = False

        for node in ast.walk(self.func):
            # pytest.raises / self.assertRaises
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('raises', 'assertRaises', 'assertRaisesRegex',
                                          'assertWarns', 'assertLogs'):
                        has_error_test = True
                        break
                elif isinstance(node.func, ast.Name):
                    if node.func.id == 'raises':
                        has_error_test = True
                        break

            # Negative assertions: assertFalse, assertIsNone, assertNotEqual
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ('assertFalse', 'assertIsNone', 'assertNotEqual',
                                      'assertNotIn', 'assertNotIsInstance', 'assertIsNot'):
                    has_error_test = True
                    break

            # assert ... is None / assert not ...
            if isinstance(node, ast.Assert):
                test = node.test
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    has_error_test = True
                    break
                if isinstance(test, ast.Compare):
                    for comp in test.comparators:
                        if isinstance(comp, ast.Constant) and comp.value is None:
                            has_error_test = True
                            break
                        if isinstance(comp, ast.Constant) and comp.value is False:
                            has_error_test = True
                            break

            # try/except in test (testing for exceptions)
            if isinstance(node, ast.ExceptHandler):
                has_error_test = True
                break

        # Only flag if the test has assertions but no negative testing
        has_assertions = any(isinstance(n, ast.Assert) for n in ast.walk(self.func))
        has_assert_calls = any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr.startswith('assert')
            for n in ast.walk(self.func)
        )

        if (has_assertions or has_assert_calls) and not has_error_test:
            # Count positive assertions to make sure it's a real test
            assert_count = sum(1 for n in ast.walk(self.func) if isinstance(n, ast.Assert))
            if assert_count >= 1:  # EXCISED cut 2 (2026-09-05): was `assert_count >= 2` — EXCISION_LIST class A
                self._add_observation({
                    "tag": "NAI-149",
                    "line": self.func.lineno,
                    "func_name": self.func.name,
                    "assert_count": assert_count,
                })

    def _check_assertion_free_test_with_calls(self) -> None:
        """NAI-150: Test that calls code but never asserts anything."""
        if not self.func.name.startswith('test_'):
            return

        # Count calls and assertions
        call_count = 0
        has_assertion = False

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                call_count += 1
                # Check for assertion method calls (self.assertEqual, etc.)
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr.startswith('assert'):
                        has_assertion = True
                        break
            if isinstance(node, ast.Assert):
                has_assertion = True
                break

        # Wave 3 (owner 2026-10-08, frontier list #3): asserts that cannot tell a right answer from a wrong one —
        # `is not None`, `isinstance`, `hasattr`, `callable` and nothing else. Measured as variant "weak_asserts_only".
        asserts = [n.test for n in ast.walk(self.func) if isinstance(n, ast.Assert)]

        def _weak(t: ast.AST) -> bool:
            if isinstance(t, ast.Compare) and isinstance(t.comparators[-1], ast.Constant) \
                    and t.comparators[-1].value is None and all(isinstance(o, ast.IsNot) for o in t.ops):
                return True
            return isinstance(t, ast.Call) and getattr(t.func, "id", "") in ("isinstance", "hasattr", "callable")

        if asserts and all(_weak(t) for t in asserts) and not any(
                isinstance(n, ast.Call) and getattr(n.func, "attr", "").startswith("assert") for n in ast.walk(self.func)):
            self._add_observation({
                "tag": "NAI-150",
                "line": asserts[0].lineno if hasattr(asserts[0], "lineno") else self.func.lineno,
                "func_name": self.func.name,
                "variant": "weak_asserts_only",
                "weak_asserts": [ast.unparse(t) for t in asserts],
            })
            return

        # Test has calls but no assertions — it runs code without verifying
        if call_count >= 1 and (not has_assertion):  # EXCISED cut 2 (2026-09-05): was `call_count >= 2 and not has_assertion` — EXCISION_LIST class A
            self._add_observation({
                "tag": "NAI-150",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "call_count": call_count,
            })

    # -------------------------------------------------------------------------
    # EXTENDED TEST QUALITY CHECKS - NAI-155, NAI-156, NAI-157
    # -------------------------------------------------------------------------

    def _check_copy_paste_test_proliferation(self) -> None:
        """
        NAI-155: Copy-paste test proliferation (>73% structural duplication).

        Detects test functions whose body is structurally near-identical to a
        template: all test methods in the function share the same AST shape
        (same sequence of statement types).  This catches AI-generated tests
        that are copy-pasted with only literal values changed.
        """
        if not self.func.name.startswith('test_'):
            return

        # Collect structural fingerprints of top-level statements
        def stmt_fingerprint(stmt: ast.stmt) -> str:
            """Reduce a statement to its structural type signature."""
            parts: list[str] = []
            for node in ast.walk(stmt):
                if isinstance(node, ast.stmt):
                    parts.append(type(node).__name__)
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        parts.append(f"call.{node.func.attr}")
                    elif isinstance(node.func, ast.Name):
                        parts.append(f"call.{node.func.id}")
            return '|'.join(parts)

        body = self.func.body
        # Skip docstring
        start = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            start = 1

        stmts = body[start:]
        if len(stmts) < 1:  # EXCISED cut 2 (2026-09-05): was `len(stmts) < 4` — EXCISION_LIST class A
            return

        fingerprints = [stmt_fingerprint(s) for s in stmts]

        # Check how many fingerprints are identical to the most common one
        from collections import Counter
        counts = Counter(fingerprints)
        if not counts:
            return

        most_common_count = counts.most_common(1)[0][1]
        duplication_ratio = most_common_count / len(fingerprints)

        if most_common_count >= 1:  # EXCISED cut 2 (2026-09-05): was `duplication_ratio > 0.73 and most_common_count >= 3` — EXCISION_LIST class A
            self._add_observation({
                "tag": "NAI-155",
                "line": self.func.lineno,
                "func_name": self.func.name,
                "total_stmts": len(fingerprints),
                "duplication_ratio": round(duplication_ratio, 3),
                "fingerprint_counts": dict(counts),
            })

    def _check_boundary_value_blindness(self) -> None:
        """
        NAI-156: Boundary value blindness in tests — no edge values tested.

        AI-generated tests typically use "happy middle" values (e.g., 5, 10, 42)
        but never test boundary values: 0, 1, -1, empty string, None, max int,
        empty list, etc.  Real test suites include edge cases.
        """
        if not self.func.name.startswith('test_'):
            return
        if self._has_decorator('parametrize'):
            return  # hardened 2026-09-05: values come from the decorator

        boundary_values = {0, 1, -1, '', None, True, False}
        boundary_collections = (ast.List, ast.Dict, ast.Set, ast.Tuple)

        has_boundary = False
        has_any_value = False

        for node in ast.walk(self.func):
            if isinstance(node, ast.Constant):
                has_any_value = True
                if node.value in boundary_values:
                    has_boundary = True
                    break
                # Large integers as boundary
                if isinstance(node.value, int):  # EXCISED cut 3 batch 2 (2026-09-06): was `and abs(node.value) > 2**30` — every int literal is a candidate boundary value
                    has_boundary = True
                    break
            # Empty collection literals: [], {}, ()
            if isinstance(node, boundary_collections):
                has_any_value = True
                if hasattr(node, 'elts') and len(node.elts) == 0:
                    has_boundary = True
                    break
                if isinstance(node, ast.Dict) and len(node.keys) == 0:
                    has_boundary = True
                    break

        if has_any_value and not has_boundary:
            # Only flag if there are multiple test values (a real test)
            value_count = sum(1 for n in ast.walk(self.func) if isinstance(n, ast.Constant))
            if value_count >= 1:  # EXCISED cut 2 (2026-09-05): was `value_count >= 3` — EXCISION_LIST class A
                self._add_observation({
                    "tag": "NAI-156",
                    "line": self.func.lineno,
                    "func_name": self.func.name,
                    "value_count": value_count,
                })

    def _check_silent_error_suppression_in_test(self) -> None:
        """
        NAI-157: Silent error suppression in tests (empty catch / only logging).

        Detects test functions with try/except blocks that catch exceptions
        and either do nothing (pass) or only log/print instead of failing
        the test.  This hides real failures.
        """
        if not self.func.name.startswith('test_'):
            return

        for node in ast.walk(self.func):
            if isinstance(node, ast.ExceptHandler):
                body = node.body
                if not body:
                    continue

                # Check for empty handler (just pass)
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    self._add_observation({
                        "tag": "NAI-157",
                        "line": node.lineno,
                        "func_name": self.func.name,
                        "variant": "empty_except_pass",
                    })
                    return

                # Check for handler that only logs/prints
                all_logging = True
                for stmt in body:
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        call = stmt.value
                        is_log = False
                        if isinstance(call.func, ast.Name):
                            if call.func.id in ('print', 'log'):
                                is_log = True
                        if isinstance(call.func, ast.Attribute):
                            if call.func.attr in ('info', 'debug', 'warning', 'error',
                                                    'warn', 'log', 'Log', 'print',
                                                    'Logf', 'Println'):
                                is_log = True
                        if not is_log:
                            all_logging = False
                            break
                    elif isinstance(stmt, ast.Pass):
                        continue
                    else:
                        all_logging = False
                        break

                if all_logging and len(body) >= 1:
                    self._add_observation({
                        "tag": "NAI-157",
                        "line": node.lineno,
                        "func_name": self.func.name,
                        "variant": "log_only_except",
                        "handler_stmt_count": len(body),
                    })
                    return

    # -------------------------------------------------------------------------
    # HELPER
    # -------------------------------------------------------------------------

    def _add_observation(self, obs: dict[str, Any]) -> None:
        """Append a raw AST observation."""
        self.observations.append(obs)
        _log.debug("observed %s at line %s", obs.get("tag"), obs.get("line"))

    # -------------------------------------------------------------------------
    # MAIN ENTRY POINT
    # -------------------------------------------------------------------------

    async def run_extended_semantic_checks(self) -> list[dict[str, Any]]:
        """Run all extended semantic checks."""
        import asyncio

        # Fast static filters
        self._check_empty_function_body()
        self._check_excessive_parameters()
        self._check_bare_except()
        self._check_assert_tuple()
        self._check_none_comparison()
        self._check_init_return()
        self._check_wildcard_import()
        self._check_eval_exec()
        self._check_mutable_default_nested()

        await asyncio.sleep(0)  # Yield control

        # Prefix pattern checks
        self._check_getter_return()
        self._check_setter_return()
        self._check_boolean_prefix_return()
        self._check_process_without_iteration()
        self._check_filter_without_conditional()
        self._check_sort_without_comparison()
        self._check_count_without_accumulator()
        self._check_answer_table()
        self._check_search_without_comparison()
        self._check_build_without_return()

        await asyncio.sleep(0)  # Yield control

        # CFG analysis
        self._check_cfg_issues()

        # Def-use chains
        self._check_use_before_def()
        self._check_redefinition_without_use()
        self._check_unused_variables()
        self._check_import_reassignment()

        await asyncio.sleep(0)  # Yield control

        # Test quality checks
        self._check_mock_everything_test()
        self._check_tautological_test()
        self._check_happy_path_only_test()
        self._check_assertion_free_test_with_calls()

        return self.observations
