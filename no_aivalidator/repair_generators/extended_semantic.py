"""Extended-semantic family (no_aivalidator/detection/extended_semantic_checks.py) — item 4, 2026-09-08.

Every row is `unbuilt` (the honest placeholder) until this family is worked.
Set 4b-13 (2026-09-10, portion B of ITEM_04B): NAI-124 rewriter `none_identity_fix` (`<x> == None` →
`<x> is None`, `<x> != None` → `<x> is not None`, the detector's own "should be"); NAI-122 an ALIAS rewriter
row of NAI-070's `bare_except_fix` with no plant of its own — the id is UNREACHABLE on the daemon route
(`AIFakeDetector.run_all_checks` calls `_check_bare_except` once, base.py:274, and the mixin order resolves it
to SafetyChecksMixin's, which tags NAI-070; the same order stands in the reference tree, so the collision is
as old as the integration) — step 19 accepts the row through NAI-070's plant and asserts NAI-122 absent from
its tags at every launch; NAI-120 (what an empty function should do), NAI-125 (what the value returned from
__init__ was meant to become) no-fix-by-design; NAI-126 never decides a row (`_check_wildcard_import` is not
called by `run_all_checks`, and its only caller `run_extended_semantic_checks` is called by nothing) — declared
with the fact. Facts: NAI-120 excludes declarations (@overload, @abstractmethod, Protocol members, `raise
NotImplementedError`) and labels the variant (docstring_only / pass_only / ellipsis); NAI-124 observes None on
the RIGHT of `==` / `!=` only (`None == x` stays quiet) and walks nested defs too; NAI-125 reads __init__'s own
scope (a return in a nested helper is the helper's) and allows an explicit `return None`.
Set 4b-14 (2026-09-10): NAI-127 (what eval / exec should become), NAI-130 (what a getter should return), NAI-131
(whether a caller reads the setter's value), NAI-132 (the name or the annotation) no-fix-by-design; NAI-128
no-fix-by-design with the fact that the nested def is a row of its own carrying NAI-071, rewritten there by
`mutable_default_fix` — a solution on the enclosing row would double the edit on overlapping lines. Facts: all
five are called from `run_all_checks` (base.py:383-389); NAI-127 fires per call, NAI-128 once per enclosing
function at the nested def's line; NAI-130 counts a valued `yield` / `yield from` in the function's own scope as
a return; NAI-131 allows `return self`; NAI-132 reads only a Name annotation.
Set 4b-15 (2026-09-10): NAI-133 / 134 / 135 / 136 / 137 no-fix-by-design — the prefix-pattern rules: a body that
lacks the construct its name promises (a loop, a condition, a sort or compare, an accumulator, a comparison or
lookup call); what the body should do is the dev's in every case. Facts: all five are called from
`run_all_checks` (base.py:390-394) and observe on the def line; NAI-133 stays quiet when the body makes any
call (delegation accepted); NAI-135 and NAI-137 count a compare anywhere as the construct.
Set 4b-16 (2026-09-10): NAI-138 (what a builder should return), NAI-140 (the terminal or the code after it),
NAI-141 (what ends a `while True`), NAI-142 (what to return on the missing path) no-fix-by-design; NAI-139
no-fix-by-design with the fact that it never decides a row: it fires only on a `test_*` def that ASSERTS, and
that is exactly what makes the file the test species (content rule, `_file_species` IG-5: an unittest / pytest
import or an asserting top-level `test_*` def), whose rows carry every id as context.
Set 4b-18 (2026-09-10): NAI-157 no-fix-by-design (what a test should do when the exception it swallows
arrives); it DOES decide a row when the test never asserts — a non-asserting `test_*` def does not make the
file the test species (probed 2026-09-10: NAI-020 + NAI-078 + NAI-157 deciding, species ''). Facts: the CFG walk runs once from `_check_cfg_issues` (base.py:398)
and again inside `_check_missing_return_paths` on an annotated def, so NAI-140 / 141 are observed twice there —
the row's ids are unique, so the id appears once; NAI-142's `meaning_source` is `_check_missing_return_paths`
(the catalogue's `_stmt_flow_state` is the helper, corrected in the row).
Set 4b-17 (2026-09-10): NAI-143 (the finally's value or the exception), NAI-145 (what a name holds at its first
read), NAI-147 (whether an unused local was meant to be used), NAI-148 (which name was meant) no-fix-by-design;
NAI-146 no-fix-by-design with the fact that it is never emitted (uncalled). Facts: 143 comes from the CFG walk
(base.py:398) and always sits with NAI-173; 145 / 147 / 148 are called from `run_all_checks` (base.py:401-403);
a 148 row always carries NAI-008 too (the import must be inside the def for 148 to see it), and the hoist
rewriter declines exactly that shape (a bound-elsewhere name), so the row publishes as declined.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Optional

from . import no_fix, prescribed, rewriter, unbuilt
from ._ast_edit import func_node, replace_cols, snippet_pad
from .safety import fix_bare_except

_NONE_OP = re.compile(r"\s*(==|!=)\s*")


# ── NAI-124 (set 4b-13, 2026-09-10) ──────────────────────────────────────────

def fix_none_compare(broken_code: str) -> tuple[str, str]:
    """NAI-124: every `<x> == None` / `<x> != None` the detector observes (None the right operand,
    `==` or `!=` the operator, nested defs included — the detector walks them too) → `<x> is None` /
    `<x> is not None`, the detector's own "should be". Structural preconditions per compare (decline
    the whole snippet otherwise): one operator and one comparator (a chained compare is another
    expression), the left operand's end and None on one line, nothing but the operator between them.
    Nothing else on the line moves; the operand text is untouched. Behaviour that changes, by the
    rule's meaning: an object whose __eq__ answers None is no longer mistaken for None — identity is
    the test the rule calls for; on the normal path (None itself, or an ordinary object) the result is
    the same."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int, str, str, str]] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Compare):
            continue
        hits = [op for op, c in zip(node.ops, node.comparators)
                if isinstance(c, ast.Constant) and c.value is None and isinstance(op, (ast.Eq, ast.NotEq))]
        if not hits:
            continue
        if len(node.ops) != 1:
            return "", ""  # chained compare: another expression, not the detector's shape
        left, right = node.left, node.comparators[0]
        if left.end_lineno != right.lineno:
            return "", ""
        row = right.lineno - 1
        if row >= len(lines):
            return "", ""
        s, e = pad + left.end_col_offset, pad + right.col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        m = _NONE_OP.fullmatch(lines[row], s, e)
        if m is None:
            return "", ""
        text = "is" if m.group(1) == "==" else "is not"
        a, b = pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        old = lines[row][a:b]
        new = lines[row][a:m.start(1)] + text + lines[row][m.end(1):b]
        edits.append((row, m.start(1), m.end(1), text, old, new))
    if not edits:
        return "", ""
    for row, s, e, text, _old, _new in sorted(edits, key=lambda t: (t[0], t[1]), reverse=True):
        replace_cols(lines, row, s, e, text)
    what = "; ".join(f"`{old}` (snippet line {row + 1}) → `{new}`"
                     for row, _s, _e, _t, old, new in sorted(edits, key=lambda t: (t[0], t[1])))
    return "\n".join(lines), what


# ---------------------------------------------------------------------------------------------------------
# FIX_43 (b) — finite-set rewriters (owner rulings 2026-09-15/16); the line-level helpers live in core.py.
# ---------------------------------------------------------------------------------------------------------
from .core import _Variants, _blocks, _delete_stmts, _indent, _rows, _terminal_variants, dead_local_variants


def _first_param_is_self(func) -> bool:
    return bool(func.args.args) and func.args.args[0].arg == "self"


def fix_init_return(broken_code: str) -> _Variants:
    """NAI-125 finite set for `return <value>` in __init__'s own scope: `drop_value` (a bare `return` — the
    caller gets the instance), `store_attribute` (the value kept on the instance as `self.<name>` when it is a
    plain name, then `return`)."""
    func = func_node(broken_code)
    if not func or func.name != "__init__":
        return []
    from .core import _own_scope
    rets = [n for n in _own_scope(func) if isinstance(n, ast.Return) and n.value is not None
            and not (isinstance(n.value, ast.Constant) and n.value.value is None)]
    if not rets:
        return []
    lines0 = broken_code.splitlines()
    pad = snippet_pad(broken_code)
    out: _Variants = []
    lines = list(lines0)
    for r in sorted(rets, key=lambda r: r.lineno, reverse=True):
        a, b = _rows(r)
        replace_cols(lines, a, pad + r.col_offset, len(lines[a]) if a != b else pad + r.end_col_offset, "return")  # type: ignore[operator]  # FIX_54 ast-pos
        del lines[a + 1:b + 1]
    out.append(("drop_value", "\n".join(lines), "; ".join(f"`return {ast.unparse(r.value)}` (snippet line {r.lineno}) → `return` — __init__ returns nothing" for r in rets)))  # type: ignore[arg-type]  # FIX_54 ast-pos
    if _first_param_is_self(func) and all(isinstance(r.value, ast.Name) for r in rets):
        lines = list(lines0)
        for r in sorted(rets, key=lambda r: r.lineno, reverse=True):
            a, b = _rows(r)
            ind = _indent(lines[a])
            lines[a:b + 1] = [f"{ind}self.{r.value.id} = {r.value.id}", f"{ind}return"]  # type: ignore[union-attr]  # FIX_54 ast-pos
        out.append(("store_attribute", "\n".join(lines), "; ".join(f"`return {r.value.id}` (snippet line {r.lineno}) → `self.{r.value.id} = {r.value.id}` then `return` — the value kept on the instance" for r in rets)))  # type: ignore[union-attr]  # FIX_54 ast-pos
    return out


def fix_setter_return(broken_code: str) -> _Variants:
    """NAI-131 finite set for a REAL setter returning a value other than self: `drop_value` (bare
    `return`), `return_self` (chaining — when the first parameter is self).

    FIX_59 (2026-09-17, owner ruling on packet §A row #21): the `set_` prefix alone is not enough. The
    detector's own applicability (`_is_real_setter`: stores on `self.<attr>`, returns only an echo of
    what it stored) decides here too, so a `set_`-named builder — colorama's `ansi.py::set_title`,
    whose return IS its product — is never offered a rewrite even if some other route reaches this
    function. The detector no longer files the row at all; this is the rewriter's half of the same
    sentence, and `_nai131_real_setter` (below) is G0's."""
    from ..detection.extended_semantic_checks import _is_real_setter   # the detector's own setter reading
    func = func_node(broken_code)
    if not func or not func.name.lower().startswith("set_"):
        return []
    if not _is_real_setter(func):
        return []
    rets = [n for n in ast.walk(func) if isinstance(n, ast.Return) and n.value is not None
            and not (isinstance(n.value, ast.Name) and n.value.id == "self")]
    if not rets:
        return []
    lines0 = broken_code.splitlines()
    pad = snippet_pad(broken_code)
    out: _Variants = []
    for variant, text, why in (("drop_value", "return", "the setter returns nothing"), ("return_self", "return self", "the setter returns self for chaining")):
        if variant == "return_self" and not _first_param_is_self(func):
            continue
        lines = list(lines0)
        for r in sorted(rets, key=lambda r: r.lineno, reverse=True):
            a, b = _rows(r)
            replace_cols(lines, a, pad + r.col_offset, len(lines[a]) if a != b else pad + r.end_col_offset, text)  # type: ignore[operator]  # FIX_54 ast-pos
            del lines[a + 1:b + 1]
        out.append((variant, "\n".join(lines), "; ".join(f"`return {ast.unparse(r.value)}` (snippet line {r.lineno}) → `{text}` — {why}" for r in rets)))  # type: ignore[arg-type]  # FIX_54 ast-pos
    return out


def _nai131_real_setter(rw: Any, before: Any, after: Any) -> Optional[str]:
    """FIX_59's G0 predicate for BOTH NAI-131 variants (lane contract 1).

    G0 shipped the `drop_value` reading with S5-1; this is that reading FIRST — nothing it withholds
    is let through — then the source's own applicability (`_is_real_setter`), and it is registered for
    `return_self` as well: `return self` destroys a builder's product exactly as a bare `return` does.
    The detector no longer files the row, so this is the backstop, not the fix."""
    from ..detection.extended_semantic_checks import _is_real_setter
    reason = _G0_NAI131_DROP_VALUE(rw, before, after)
    if reason:
        return reason
    func = next((n for n in ast.walk(before) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if func is not None and not _is_real_setter(func):
        return (f"gate: `{func.name}` is not a setter — it stores nothing on `self`, or what it returns is a "
                f"computed product rather than an echo of what it stored; the `set_` prefix alone never makes "
                f"a return droppable.")
    return None


def _register_nai131_predicates() -> None:
    """FIX_59: declared beside the variant, as the lane contract asks."""
    from . import gate
    gate.PREDICATES[("NAI-131", "drop_value")] = _nai131_real_setter
    gate.PREDICATES[("NAI-131", "return_self")] = _nai131_real_setter


def _g0_nai131_drop_value() -> Any:
    from . import gate
    return gate.PREDICATES[("NAI-131", "drop_value")]


_G0_NAI131_DROP_VALUE = _g0_nai131_drop_value()   # S5-1's reading, captured before FIX_59 wraps it
_register_nai131_predicates()


def fix_after_terminal(broken_code: str) -> _Variants:
    """NAI-140 finite set (the flow reading: return / raise / break / continue, an if whose both branches end,
    a with whose body ends, a try whose finally returns): `drop_dead` / `terminal_last` (the latter only for a
    simple terminal)."""
    return _terminal_variants(broken_code, simple_only=False)


def fix_return_in_finally(broken_code: str) -> _Variants:
    """NAI-143 finite set for a `return` in a finally block: `drop_finally_return` (the try's own result or
    exception wins; an emptied finally gets `pass`), `move_after_try` (the return runs after the try block, so it
    is reached only when nothing in the try returned or raised)."""
    func = func_node(broken_code)
    if not func:
        return []
    from .core import _own_scope
    tries = [(n, [f for f in n.finalbody if isinstance(f, ast.Return)]) for n in _own_scope(func) if isinstance(n, ast.Try)]
    tries = [(t, rs) for t, rs in tries if rs]
    if not tries:
        return []
    lines0 = broken_code.splitlines()
    out: _Variants = []
    for variant in ("drop_finally_return", "move_after_try"):
        lines = list(lines0)
        for t, rs in sorted(tries, key=lambda x: x[0].lineno, reverse=True):
            moved = [lines[a:b + 1] for a, b in (_rows(r) for r in rs)]
            _delete_stmts(lines, rs, t.finalbody)
            if variant == "move_after_try":
                end = _rows(t)[1] - sum(b - a + 1 for a, b in (_rows(r) for r in rs)) + (1 if len(t.finalbody) == len(rs) else 0)
                ind = _indent(lines[_rows(t)[0]])
                block = [ind + ln.lstrip() if i == 0 else ind + ln[len(_indent(moved[0][0])):] for m in moved for i, ln in enumerate(m)]
                lines[end + 1:end + 1] = block
        what = "; ".join(f"`{ast.unparse(r)}` in the finally at snippet line {r.lineno} " + ("deleted — the try's own result or exception comes out" if variant == "drop_finally_return" else "moved after the try — reached only when nothing in the try returned or raised") for _, rs in tries for r in rs)
        out.append((variant, "\n".join(lines), what))
    return out


def fix_unused_local(broken_code: str) -> _Variants:
    """NAI-147 finite set (own-scope def/use, no name table): `drop_assignment` / `keep_call_effect`."""
    return dead_local_variants(broken_code, frozenset())


_SRC = "no_aivalidator/detection/extended_semantic_checks.py"

GENERATORS = [
    prescribed('NAI-120', f"{_SRC}:_check_empty_function_body", "Implement the body: compute and return what the name and the intent's expected output promise; a declared-but-unimplemented member (a reserved hook whose only meaning is 'not yet') raises NotImplementedError naming the missing piece — give the function an effect without inventing one (the owner\'s form, hand check #17, 2026-09-16).",
               'def <name>(<params>):\n    """<existing docstring>"""\n    raise NotImplementedError("<name>: not implemented")'),
    rewriter("NAI-122", f"{_SRC}:_check_bare_except", "bare_except_fix", fix_bare_except,
             "ALIAS of NAI-070 (same function object, same role): the extended-semantic integration's re-emission of the construct NAI-070 observes. UNREACHABLE on the daemon route — `run_all_checks` calls `_check_bare_except` once and the mixin order resolves it to SafetyChecksMixin's, which tags NAI-070; the reference tree has the same order. No plant of its own: step 19 accepts the row through NAI-070's plant and asserts NAI-122 absent from that plant's tags at every launch (set 4b-13, 2026-09-10)",
             "2026-09-10", "set 4b-13 (2026-09-10)"),
    rewriter("NAI-124", f"{_SRC}:_check_none_comparison", "none_identity_fix", fix_none_compare,
             "`<x> == None` → `<x> is None`, `<x> != None` → `<x> is not None` in place — the detector's own 'should be'; the operand is untouched, nothing else on the line moves; declines a chained compare, a compare split over lines, or anything but the operator between the operand and None. By the rule's meaning an object whose __eq__ answers None is no longer mistaken for None; on the normal path the result is the same (set 4b-13, 2026-09-10)",
             "2026-09-10", "set 4b-13 (2026-09-10)"),
    rewriter("NAI-125", f"{_SRC}:_check_init_return", "init_return_fix", fix_init_return,
             "FINITE SET (1–2 candidates) for `return <value>` in __init__'s own scope: `drop_value` (a bare `return`), `store_attribute` (`self.<name> = <name>` then `return`, when the value is a plain name and the first parameter is self). A factory's result has no finite form here. The Ranker decides (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-126', f"{_SRC}:_check_wildcard_import", 'Import the names used explicitly at module top (from X import a, b); no star import inside a function body.',
               'from <module> import <a>, <b>   # module level'),
    prescribed('NAI-127', f"{_SRC}:_check_eval_exec", 'Replace eval / exec with the safe form of what it computes: ast.literal_eval for literals, a dict dispatch for names to callables, json / a real parser for structured text, getattr for attribute names.',
               'value = ast.literal_eval(<text>)   # or: HANDLERS[<name>](<args>) / json.loads(<text>) / getattr(<obj>, <attr>)'),
    prescribed('NAI-128', f"{_SRC}:_check_mutable_default_nested", "On the nested def, replace the mutable default with None and create the container inside the body (the repair NAI-071's rewriter applies on the nested def's own row).",
               'def <inner>(<p>=None):\n    if <p> is None:\n        <p> = []'),
    prescribed('NAI-130', f"{_SRC}:_check_getter_return", 'Return the value the getter is named for: read it from self / the source and return it; a getter that only sets or prints is renamed to what it does.',
               'def get_<thing>(self):\n    return self._<thing>'),
    rewriter("NAI-131", f"{_SRC}:_check_setter_return", "setter_return_fix", fix_setter_return,
             "FINITE SET (1–2 candidates) for a `set_*` function returning a value other than self: `drop_value` (bare `return`), `return_self` (chaining, when the first parameter is self). Whether a caller read the old value is the callers'; the Ranker decides (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-132', f"{_SRC}:_check_boolean_prefix_return", 'Annotate the function -> bool and return a bool (the predicate the name asks), or rename the function to what it actually returns.',
               'def is_<what>(...) -> bool:\n    return <predicate>'),
    prescribed('NAI-133', f"{_SRC}:_check_process_without_iteration", 'Process the input: iterate its items (or call the transformer) and return the processed value the name promises; a delegating call to the real worker is fine.',
               'def process_<what>(items):\n    return [<transform(item)> for item in items]'),
    prescribed('NAI-134', f"{_SRC}:_check_filter_without_conditional", 'Filter by the condition the name promises: keep the items for which the predicate from the intent holds and return them.',
               'def filter_<what>(items):\n    return [item for item in items if <condition(item)>]'),
    prescribed('NAI-135', f"{_SRC}:_check_sort_without_comparison", 'Sort by the key and direction the name promises: sorted(items, key=<key>, reverse=<bool>).',
               'def sort_<what>(items):\n    return sorted(items, key=lambda item: <key>, reverse=<bool>)'),
    prescribed('NAI-136', f"{_SRC}:_check_count_without_accumulator", 'Count the thing the name promises — sum(1 for item in items if <condition>) or len(...) — and return the number.',
               'def count_<what>(items):\n    return sum(1 for item in items if <condition(item)>)'),
    prescribed('NAI-260', f"{_SRC}:_check_answer_table", 'Replace the ladder of per-input cases with one computation over the input that the cases were standing in for; the tests must pass for inputs they never mention.',
               'def <name>(<input>):\n    <general computation over the input>\n    return <value computed from the input>'),
    prescribed('NAI-137', f"{_SRC}:_check_search_without_comparison", 'Search for the target the name promises: compare each item to it (or use find / index / next with a predicate) and return the match or the documented not-found value.',
               'def find_<what>(items, target):\n    return next((item for item in items if <item matches target>), None)'),
    prescribed('NAI-138', f"{_SRC}:_check_build_without_return", 'Return the object the build_* / create_* / make_* name promises: construct it and hand it back (or yield it when it is a stream).',
               'def build_<what>(...):\n    obj = <construct>\n    return obj'),
    prescribed('NAI-139', f"{_SRC}:_check_tautological_test", 'Assert against an independent expected value (a literal from the spec, a fixture) rather than recomputing the same expression; the test must be able to fail.',
               'assert <unit>(<input>) == <expected literal>'),
    rewriter("NAI-140", f"{_SRC}:_analyze_flow", "after_terminal_fix", fix_after_terminal,
             "FINITE SET (1–2 candidates) for statements after a terminal in the flow reading (return / raise / break / continue, an if whose both branches end, a with whose body ends, a try whose finally returns): `drop_dead`, `terminal_last` (only for a simple terminal). The Ranker decides; NAI-002's candidates on the same row read the same (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-141', f"{_SRC}:_stmt_flow_state", 'Give the loop its exit: break / return when the condition the intent describes is met, or bound it with a maximum number of iterations.',
               'while True:\n    <work>\n    if <done condition>:\n        break'),
    prescribed('NAI-142', f"{_SRC}:_check_missing_return_paths", 'Return on every path: give the missing branch / fall-through the value the annotation promises or raise the documented error; a function that may return nothing is annotated Optional and returns None explicitly.',
               'if <cond>:\n    return <value>\nreturn <value for the other case>   # or raise <Error>'),
    rewriter("NAI-143", f"{_SRC}:_stmt_flow_state", "finally_return_fix", fix_return_in_finally,
             "FINITE SET (2 candidates) for a `return` in a finally block: `drop_finally_return` (the try's own result or exception comes out; an emptied finally gets `pass`), `move_after_try` (the return runs after the try block — reached only when nothing in the try returned or raised). The row also carries NAI-173 (safety). The Ranker decides (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-145', f"{_SRC}:_check_use_before_def", 'Assign the name before its first read: move the assignment above the read when the same value was meant, or initialise it (None / empty / the parameter) at the top of the function.',
               '<name> = <initial value>\n... <first read of <name>> ...'),
    prescribed('NAI-146', f"{_SRC}:_check_redefinition_without_use", 'Delete the first definition (or use it before the second) so a name is defined once per meaning.',
               '<name> = <value>   # once; the earlier definition removed'),
    rewriter("NAI-147", f"{_SRC}:_check_unused_variables", "unused_local_fix", fix_unused_local,
             "FINITE SET (1–2 candidates) for a local assigned and never read (own-scope def/use, `_`-names excluded): `drop_assignment` (an emptied block gets `pass`), `keep_call_effect` (when every right side is a call). The Ranker decides; NAI-010 on the same row reads the same (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-148', f"{_SRC}:_check_import_reassignment", 'Give the value its own name and keep the imported name for the module: rename the assignment target — or, when the in-function import has no other use, drop the import and keep the value under its own name (the owner\'s form, hand check #10, 2026-09-16) — so no name means two things.',
               "def <name>(<params>):\n    <mod>_value = <expr>   # the in-function `import <mod>` dropped when nothing else used it; else keep it and rename the value"),
    prescribed('NAI-157', f"{_SRC}:_check_silent_error_suppression_in_test", 'Make the test react to the exception: assert it with pytest.raises(<Error>) when it is expected, or let it propagate (delete the try) so the test fails when it happens.',
               'with pytest.raises(<Error>):\n    <call>'),
]
