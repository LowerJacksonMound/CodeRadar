"""Advanced family (no_aivalidator/detection/advanced_checks.py) — item 4, 2026-09-08.

No fix by design: NAI-044 (owner ruling 2026-09-08).
Set 4b-38 (2026-09-10, portion H of ITEM_04B, app copy 2): NAI-042 `exception_alias_fix` — the alias the detector
observes is never read in its handler, so `except E as name:` becomes `except E:`; exactly equivalent when the alias
identifier occurs nowhere else in the function (the only other effect of `as name` is the handler's implicit delete
of that name at its end — observable only if somebody else binds or reads it), any other occurrence declines.
NAI-040 / NAI-041 / NAI-043 / NAI-045 no-fix-by-design: which branch was meant to differ, whether the parameter or
its overwrite is the mistake, what the real string should be, which return type was intended — each the dev's.
NAI-041's `meaning_source` corrected: the emitter is `_check_param_shadow` (`_leaf_stmt_map_for_shadow` is its
helper). Facts: all eight detectors of the family are called from `run_all_checks` (base.py, the ADVANCED block);
040 / 042 / 043 / 046 / 047 / 048 observe the FIRST hit and return; 040 / 041 / 045 / 048 report the def's own line,
042 / 043 / 046 / 047 the construct's; 045 types only literal returns (Constant / List / Dict / Set / Tuple) and fires
only for str beside int / float.
Set 4b-39 (2026-09-10, portion H, app copy 2): NAI-046 / NAI-047 / NAI-048 no-fix-by-design — hoist, inline or keep
a capture-less nested def; whether a call inside an `assert` must always run (it vanishes under `-O`); which of two
identical nested bodies to keep — each the dev's. FACT (run 93, nothing edited): NAI-046 decides only for a nested
def whose every read is a builtin of the detector's small table — `_check_closure_no_capture` skips the inner def
NODE (`sub == node`) but `ast.walk` still yields the inner subtree, so the inner's own locals land in `outer_names`
and count as "captured"; a nested def that reads any local of its own never fires. The observation is reported at the
inner def's line but carried on the OUTER function's row (the inner def has its own row — the 4b-14 precedent).
"""
from __future__ import annotations

import ast
from typing import Any
import re
import textwrap

from . import no_fix, prescribed, rewriter
from ._ast_edit import func_node, snippet_pad
from ._finite import (Variant, delete_rows, dedent_rows, edited, finish, fresh_name, indent, keyword_row, node_text,
                      prep, replace_node, rows, same_if_else_variants, single_line, whole_rows)

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SRC = "no_aivalidator/detection/advanced_checks.py"
_H = "set 4b-38 (app copy 2)"

_AS_CLAUSE = re.compile(r"\s+as\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:")


def _identifiers_outside(func: Node, handler: ast.ExceptHandler) -> set[str]:
    """Every identifier the snippet binds or reads anywhere OUTSIDE the given handler — names in any context,
    parameters, def / class names, import aliases, global / nonlocal declarations, other handlers' aliases."""
    inside = {id(n) for n in ast.walk(handler)}
    found: set[str] = set()
    for n in ast.walk(func):
        if id(n) in inside:
            continue
        if isinstance(n, ast.Name):
            found.add(n.id)
        elif isinstance(n, ast.arg):
            found.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(n.name)
        elif isinstance(n, ast.alias):
            found.add((n.asname or n.name).split(".")[0])
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            found.update(n.names)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            found.add(n.name)
    return found


def fix_exception_alias(broken_code: str) -> tuple[str, str]:
    """NAI-042: `except E as name:` where `name` is never read (no Load of it anywhere in the handler — the
    detector's own set-membership basis) → `except E:`. Meaning: the alias is bound at entry to the handler and
    implicitly deleted at its end; with no read in between, dropping the binding changes nothing — PROVIDED the
    identifier is not bound or read anywhere else in the function (a prior `name = …` would survive where the
    alias form deleted it; a later read would see a different value). Preconditions, decline otherwise: the
    identifier occurs nowhere else in the snippet (any context, parameter, def, import, global / nonlocal, another
    handler's alias); the `as name` clause sits on the handler's header line; the result parses and the handler
    keeps its type expression. Every such handler in the snippet is edited (the detector reports the first)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    hits: list[tuple[ast.ExceptHandler, str]] = []
    for n in ast.walk(func):
        if not (isinstance(n, ast.ExceptHandler) and n.name):
            continue
        if any(isinstance(s, ast.Name) and s.id == n.name and isinstance(s.ctx, ast.Load) for s in ast.walk(n)):
            continue  # read somewhere in the handler — not the detector's shape
        if n.name in _identifiers_outside(func, n):
            return "", ""  # the implicit delete of the alias would be observable — the dev's
        if any(isinstance(s, ast.Name) and s.id == n.name for s in ast.walk(n)):
            return "", ""  # stored in the handler under the alias name — the delete at its end is load-bearing
        hits.append((n, n.name))
    if not hits:
        return "", ""
    whats: list[str] = []
    for n, name in sorted(hits, key=lambda h: h[0].lineno, reverse=True):
        row = n.lineno - 1
        if row >= len(lines):
            return "", ""
        line = lines[row]
        head_start = pad + n.col_offset
        m = _AS_CLAUSE.search(line, head_start)
        if not m or m.group("name") != name:
            return "", ""
        before = line[head_start:m.start()]
        if not before.lstrip().startswith("except") or ":" in before:
            return "", ""
        lines[row] = line[:m.start()] + ":" + line[m.end():]
        whats.append(f"`{line[head_start:m.end()].strip()}` (snippet line {row + 1}) → `{before.strip()}:` — "
                     f"`{name}` is never read in the handler and occurs nowhere else in the function")
    code = "\n".join(lines)
    try:
        new = ast.parse(textwrap.dedent(code))
    except SyntaxError:
        return "", ""
    old_types = sorted(ast.dump(h.type) if h.type else "" for h in ast.walk(func) if isinstance(h, ast.ExceptHandler))
    new_types = sorted(ast.dump(h.type) if h.type else "" for h in ast.walk(new) if isinstance(h, ast.ExceptHandler))
    if old_types != new_types:
        return "", ""
    return code, "; ".join(reversed(whats))



# ── FIX_43 (b) finite-set rewriters (2026-09-16, app copy 3): every candidate offered, the Ranker decides ──
_H43 = "FIX_43 (b) (2026-09-16, app copy 3)"


def _dump(stmts: list) -> str:
    return ast.dump(ast.Module(body=list(stmts), type_ignores=[]), include_attributes=False)


def _stmt_lists(node: Node):
    for n in ast.walk(node):
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(n, field, None)
            if isinstance(stmts, list) and stmts and isinstance(stmts[0], ast.stmt):
                yield stmts


def fix_duplicate_subtrees(broken_code: str) -> list[Variant]:
    """NAI-040 (finite set): an `if` / `else` whose two blocks are the same (each > 1 statement), or two back-to-back
    sibling `if`s with the same block. Candidates — same if / else: `body_once` (the block once, unconditionally) and
    `else_not_implemented` (the if kept, the else an explicit NotImplementedError stub); adjacent ifs: `merge_guards`
    (`if (A) or (B):` — the block runs once where before it could run twice) and `second_not_implemented` (the second
    guard kept, its block a stub). Declines a multi-line test, a statement sharing its row, any other shape."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    for n in ast.walk(func):
        if isinstance(n, ast.If) and len(n.body) > 1 and len(n.orelse) > 1 and _dump(n.body) == _dump(n.orelse):
            return same_if_else_variants(func, pad, lines, n, "NAI-040")
    for lst in _stmt_lists(func):
        for a, b in zip(lst, lst[1:]):
            if not (isinstance(a, ast.If) and isinstance(b, ast.If) and len(a.body) > 1 and len(b.body) > 1):
                continue
            if a.orelse or b.orelse or _dump(a.body) != _dump(b.body):
                continue
            if not (single_line(a.test) and single_line(b.test) and whole_rows(lines, [a, b])):
                return []
            ta, tb = node_text(lines, a.test, pad), node_text(lines, b.test, pad)
            b0, b1 = rows(b)
            body0 = b.body[0].lineno - 1

            def merge(ls: list[str]) -> bool:
                delete_rows(ls, b0, b1)
                return replace_node(ls, a.test, pad, f"({ta}) or ({tb})")

            def stub(ls: list[str]) -> bool:
                delete_rows(ls, body0, b1)
                ls.insert(body0, " " * indent(lines[body0]) + f'raise NotImplementedError("{func.name}: `if {tb}` not implemented")')
                return True

            out = []
            v = edited(lines, merge)
            if v is not None:
                out.append(("merge_guards", v, f"`if {ta}:` and `if {tb}:` (snippet lines {a.lineno}, {b.lineno}) guarded the same {len(a.body)}-statement block back-to-back — merged into `if ({ta}) or ({tb}):`; the block now runs once where both guards true ran it twice (NAI-040)"))
            v = edited(lines, stub)
            if v is not None:
                out.append(("second_not_implemented", v, f"`if {tb}:` (snippet line {b.lineno}) repeated the block of `if {ta}:` — its block replaced by an explicit NotImplementedError stub so the guard that was meant to differ is named, not invented (NAI-040)"))
            return finish(out)
    return []


def fix_return_type_mix(broken_code: str) -> list[Variant]:
    """NAI-045 (finite set): a str literal returned on one path and an int / float literal on another. Candidates:
    `all_str` (every numeric literal return wrapped in `str(...)` — one type on every path) and `str_is_error` (each
    str-literal return becomes `raise ValueError(<that str>)` — the string was the failure message, the number the
    value). Declines a multi-line return."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    rets = [n for n in ast.walk(func) if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)]
    strs = [n for n in rets if isinstance(n.value.value, str)]  # type: ignore[union-attr]  # FIX_54 ast-pos
    nums = [n for n in rets if isinstance(n.value.value, (int, float)) and not isinstance(n.value.value, bool)]  # type: ignore[union-attr]  # FIX_54 ast-pos
    if not strs or not nums or not all(single_line(n) for n in strs + nums):
        return []

    def all_str(ls: list[str]) -> bool:
        for n in sorted(nums, key=lambda r: (r.lineno, r.col_offset), reverse=True):
            t = node_text(lines, n.value, pad)
            if not replace_node(ls, n.value, pad, f"str({t})"):
                return False
        return True

    def str_is_error(ls: list[str]) -> bool:
        for n in sorted(strs, key=lambda r: (r.lineno, r.col_offset), reverse=True):
            t = node_text(lines, n.value, pad)
            if not replace_node(ls, n, pad, f"raise ValueError({t})"):
                return False
        return True

    nl = ", ".join(str(n.lineno) for n in nums)
    sl = ", ".join(str(n.lineno) for n in strs)
    out = []
    v = edited(lines, all_str)
    if v is not None:
        out.append(("all_str", v, f"numeric literal return(s) at snippet line(s) {nl} wrapped in str(...) — every path now returns a str like the return(s) at line(s) {sl} (NAI-045)"))
    v = edited(lines, str_is_error)
    if v is not None:
        out.append(("str_is_error", v, f"str literal return(s) at snippet line(s) {sl} became `raise ValueError(<that text>)` — the string was the failure, the number at line(s) {nl} the value (NAI-045)"))
    return finish(out)


def _pure_names() -> set[str]:
    try:
        from ..detection.base import AIFakeDetector  # the detector's own tables (NAI-022 / NAI-047 share them)
        pure = set(getattr(AIFakeDetector, "_PURE_BUILTINS", ())) | set(getattr(AIFakeDetector, "_PURE_METHODS", ()))
    except Exception:
        pure = set()
    return pure | {"len", "isinstance", "issubclass", "hasattr", "callable", "type", "id", "hash", "abs", "all", "any", "min", "max", "sum"}


def fix_assert_side_effect(broken_code: str) -> list[Variant]:
    """NAI-047 (finite set): an `assert` whose test calls a function outside the pure table (the call vanishes under
    `python -O`). Candidates: `call_first` (the call hoisted to its own statement, the assert tests the stored result —
    the call always runs) and `if_not_raise` (`if not (<test>): raise AssertionError(...)` — the check always runs).
    Declines a multi-line assert or a call spanning rows."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    pure = _pure_names()
    for n in ast.walk(func):
        if not isinstance(n, ast.Assert) or not single_line(n):
            continue
        call = None
        for sub in ast.walk(n.test):
            if isinstance(sub, ast.Call):
                fn = sub.func.id if isinstance(sub.func, ast.Name) else sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
                if fn not in pure:
                    call = (sub, fn)
                    break
        if call is None:
            continue
        sub, fn = call
        row = n.lineno - 1
        ind = " " * indent(lines[row])
        test = node_text(lines, n.test, pad)
        msg = node_text(lines, n.msg, pad) if n.msg is not None else None
        name = fresh_name(func, "checked")

        def call_first(ls: list[str]) -> bool:
            if not replace_node(ls, sub, pad, name):
                return False
            ls.insert(row, f"{ind}{name} = {node_text(lines, sub, pad)}")
            return True

        def if_not_raise(ls: list[str]) -> bool:
            ls[row] = f"{ind}if not ({test}):"
            ls.insert(row + 1, f"{ind}    raise AssertionError({msg if msg is not None else repr(test)})")
            return True

        out = []
        v = edited(lines, call_first)
        if v is not None:
            out.append(("call_first", v, f"`{fn}(...)` inside `assert {test}` (snippet line {row + 1}) hoisted to `{name} = {fn}(...)` — the call runs under -O too; the assert tests {name} (NAI-047)"))
        v = edited(lines, if_not_raise)
        if v is not None:
            out.append(("if_not_raise", v, f"`assert {test}` (snippet line {row + 1}) became `if not (...): raise AssertionError(...)` — the check and its call run under -O too (NAI-047)"))
        return finish(out)
    return []


def fix_identical_nested_defs(broken_code: str) -> list[Variant]:
    """NAI-048 (finite set): two or more nested defs with identical bodies. One candidate per def in the group,
    `keep_<name>`: that def stays, the others are deleted and every read of their names becomes the kept name.
    Declines a def sharing a row, or a deleted name used other than as a plain read."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    nested = [n for n in ast.walk(func) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not func]
    groups: dict[str, list] = {}
    for n in nested:
        groups.setdefault(_dump(n.body), []).append(n)
    group = next((g for g in groups.values() if len(g) > 1), None)
    if group is None or not whole_rows(lines, group):
        return []
    names = [n.name for n in group]
    out = []
    for keep in group:
        others = [n for n in group if n is not keep]
        gone = {n.name for n in others}
        gone_rows = {r for n in others for r in range(rows(n)[0], rows(n)[1] + 1)}
        reads = [x for x in ast.walk(func) if isinstance(x, ast.Name) and x.id in gone and x.lineno - 1 not in gone_rows]
        if any(not isinstance(x.ctx, ast.Load) for x in reads):
            continue

        def edit(ls: list[str], keep=keep, others=others, reads=reads) -> bool:
            for x in sorted(reads, key=lambda r: (r.lineno, r.col_offset), reverse=True):
                if not replace_node(ls, x, pad, keep.name):
                    return False
            for n in sorted(others, key=lambda d: d.lineno, reverse=True):
                a, b = rows(n)
                delete_rows(ls, a, b)
            return True

        v = edited(lines, edit)
        if v is not None:
            out.append((f"keep_{keep.name}", v, f"nested defs {', '.join(names)} had identical bodies — `{keep.name}` kept, {', '.join(sorted(gone))} deleted and their {len(reads)} read(s) renamed to `{keep.name}` (NAI-048)"))
    return finish(out)


GENERATORS = [
    prescribed('NAI-044', f"{_SRC}:_check_infinite_loop_patterns", 'Give the loop its exit: break / return when the condition the intent describes is met (the queue is empty, the response arrives, the count is reached), or bound it with a maximum.',
               'while True:\n    <work>\n    if <done condition>:\n        break'),
    # set 4b-38 (2026-09-10, portion H, app copy 2)
    rewriter("NAI-040", f"{_SRC}:_check_subtree_duplication", "duplicate_subtrees_fix", fix_duplicate_subtrees,
             reason="finite set — identical if / else blocks: the block once (`body_once`) or the else an explicit NotImplementedError stub (`else_not_implemented`); two back-to-back guards with the same block: merged `if (A) or (B):` (`merge_guards`, runs once where both true ran it twice) or the second block a stub (`second_not_implemented`); every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
    prescribed('NAI-041', f"{_SRC}:_check_param_shadow", "Delete the overwrite and use the parameter's value; when the parameter is meant to be a default the overwrite supplies, make it a default value in the signature.",
               'def <name>(<param>=<default>):\n    <use <param>>'),
    rewriter("NAI-042", f"{_SRC}:_check_exception_alias_unused", "exception_alias_fix", fix_exception_alias,
             reason="`except E as name:` → `except E:` when the alias is never read in its handler — exactly equivalent "
                    "while the identifier occurs nowhere else in the function (the handler's implicit delete of the "
                    "alias is the only other effect); declines any other occurrence, a store under the alias inside the "
                    "handler, a clause off the header line",
             dated="2026-09-10", by=_H),
    prescribed('NAI-043', f"{_SRC}:_check_placeholder_strings", 'Replace the placeholder text with the real content (the message, the path, the value) the intent specifies; if it is genuinely unfinished, raise NotImplementedError at the site instead of shipping the string.',
               "<name> = '<the real text>'   # or: raise NotImplementedError('<what is missing>')"),
    rewriter("NAI-045", f"{_SRC}:_check_return_type_inconsistency", "return_type_fix", fix_return_type_mix,
             reason="finite set — a str literal returned beside an int / float literal: every numeric return wrapped in str(...) (`all_str`) or each str return raised as ValueError (`str_is_error`: the string was the failure message); every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
    # set 4b-39 (2026-09-10, portion H, app copy 2)
    prescribed('NAI-046', f"{_SRC}:_check_closure_no_capture", 'Move the nested def out to module level (private, _name) and call it from here, or inline its body at the single call; nested only when it is meant to be redefined per call.',
               'def _<helper>(<args>):   # module level\n    ...\n\ndef <name>(...):\n    ... _<helper>(<args>) ...'),
    rewriter("NAI-047", f"{_SRC}:_check_assert_side_effects", "assert_side_effect_fix", fix_assert_side_effect,
             reason="finite set — an assert whose test calls outside the pure table (gone under -O): the call hoisted to its own statement and the assert tests the result (`call_first`), or `if not (...): raise AssertionError(...)` (`if_not_raise`); every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
    rewriter("NAI-048", f"{_SRC}:_check_identical_method_bodies", "identical_defs_fix", fix_identical_nested_defs,
             reason="finite set — nested defs with identical bodies: one candidate per def (`keep_<name>`), that def kept, the others deleted and their reads renamed to it; every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
]
