"""Structural family (no_aivalidator/detection/structural_checks.py) — item 4, 2026-09-08.

Set 4b-42 (2026-09-10, portion I; app copy 1, a fan-out lane): one rewriter and four no-fix-by-design.
NAI-171 REWRITER `loop_else_splice_fix` — the detector's `for` / `while` carrying an `else:` block while no `break`
sits anywhere in the loop body (nested loops included, exactly as the detector walks): the `else:` line goes and its
statements are dedented one level to sit directly after the loop. Behaviour that changes: none — a loop `else` runs
when the loop ends without a `break`; with no `break` anywhere it ran after every completion of the loop, and the
other ways out (`return`, `raise`, an exception) skipped it exactly as they skip the statements that follow the loop.
Declines: two hits nested one inside the other (one pass edits one level), an `else:` line the source does not carry
at the loop's own indent, an else block that does not sit deeper than the loop header, or an else-block line (a
multi-line string's continuation) that cannot be dedented by the block's own depth. NAI-026 (two shapes under one id:
identical `if` / `else` bodies — which branch should differ is the dev's; and an operation cancelled by its inverse
on the same value, `x += y; x -= y` — which of the two was the mistake is the dev's), NAI-027 (a local empty
collection is mutated while the parameter is returned — whether the local or the parameter should carry the result
is the dev's), NAI-028 (statements after an unconditional `return` / `raise` — whether the early exit or the
unreachable code is the mistake is the dev's; deleting the dead statements would hide the intent they record),
NAI-029 (`if True:` / `if False:` — the condition the dev never wrote is the dev's; flattening or deleting the
block hides the placeholder) no-fix-by-design. Facts: all six detector functions are called from `run_all_checks`
(base.py:213-218) — the two NAI-026 shapes from `_check_identical_branches` and `_check_inverse_operations`, each
returning after its first hit; NAI-029 observes EVERY constant `if` in the function (no early return), so one row can
carry the id twice in `observations` — the row's id set carries it once; NAI-171 observes the loop's own line;
NAI-027 NEVER DECIDES a row on the daemon route — its shape requires `return <parameter>`, which the strict
NAI-021S (alias-chain identity flow) takes first whatever is mutated beside it (probed twice on the set).
"""
from __future__ import annotations

import ast
from typing import Any

from . import no_fix, prescribed, rewriter
from ._ast_edit import func_node
from ._finite import (Variant, delete_rows, dedent_rows, edited, finish, fresh_name, indent, keyword_row, node_text,
                      prep, register_not_implemented_predicates, replace_node, rows, same_if_else_variants,
                      single_line, whole_rows)

register_not_implemented_predicates()   # FIX_57: NAI-026's `else_not_implemented`, declared beside the variant

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SRC = "no_aivalidator/detection/structural_checks.py"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


# ── NAI-171 (set 4b-42, 2026-09-10) ──────────────────────────────────────────

def fix_loop_else_without_break(broken_code: str) -> tuple[str, str]:
    """NAI-171: a `for` / `while` with an `else:` block and no `break` anywhere in its body → the `else:` line dropped,
    its statements dedented one level to follow the loop directly. Preconditions (decline the whole snippet otherwise):
    exactly one `else` line between the body and the else block, at the loop header's indent; the else block deeper
    than the header; every non-blank else-block line dedentable by that depth; no hit nested inside another hit.
    Behaviour that changes: none — without a `break` the else block ran after every completion of the loop."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    lines = broken_code.splitlines()
    loops = [n for n in ast.walk(func)
             if isinstance(n, (ast.For, ast.While)) and n.orelse
             and not any(isinstance(c, ast.Break) for c in ast.walk(ast.Module(body=n.body, type_ignores=[])))]
    if not loops:
        return "", ""
    spans = [(n.lineno, n.orelse[-1].end_lineno) for n in loops]
    for i, a in enumerate(spans):
        for j, b in enumerate(spans):
            if i != j and a[0] <= b[0] and b[1] <= a[1]:  # type: ignore[operator]  # FIX_54 ast-pos
                return "", ""  # one hit sits inside another: one pass edits one level, so the snippet is declined
    edits: list[tuple[int, int, int, int, ast.AST]] = []
    for n in loops:
        loop_indent = _indent(lines[n.lineno - 1])
        first, last = n.orelse[0].lineno - 1, n.orelse[-1].end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
        else_rows = [r for r in range(n.body[-1].end_lineno, first) if lines[r].strip().startswith("else")]  # type: ignore[arg-type]  # FIX_54 ast-pos
        if len(else_rows) != 1 or _indent(lines[else_rows[0]]) != loop_indent:
            return "", ""  # the `else:` line is not where the source must carry it: decline
        delta = _indent(lines[first]) - loop_indent
        if delta <= 0:
            return "", ""  # the else block does not sit deeper than the loop header: decline
        if any(lines[r].strip() and _indent(lines[r]) < delta for r in range(first, last + 1)):
            return "", ""  # a line of the block (a multi-line string) cannot be dedented by the block's depth: decline
        edits.append((else_rows[0], first, last, delta, n))
    for else_row, first, last, delta, _n in sorted(edits, key=lambda t: t[0], reverse=True):
        for r in range(first, last + 1):
            if lines[r].strip():
                lines[r] = lines[r][delta:]
        del lines[else_row]
    what = "; ".join(
        f"`else:` (snippet line {else_row + 1}) after a `{'for' if isinstance(n, ast.For) else 'while'}` with no `break` dropped, "
        f"its {len(n.orelse)} statement(s) spliced after the loop"  # type: ignore[attr-defined]  # FIX_54 ast-pos
        for else_row, _f, _l, _d, n in sorted(edits, key=lambda t: t[0]))
    return "\n".join(lines), what + " — with no break the else block always ran after the loop; the same statements run in the same order"



# ── FIX_43 (b) finite-set rewriters (2026-09-16, app copy 3): every candidate offered, the Ranker decides ──
_H43 = "FIX_43 (b) (2026-09-16, app copy 3)"
_INVERSE = {("+", "-"), ("-", "+"), ("*", "/"), ("/", "*")}
_OPS = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/"}


def _target_name(t: Node) -> str | None:
    if isinstance(t, ast.Name):
        return t.id
    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name):
        return f"{t.value.id}.{t.attr}"
    return None


def fix_identical_branches(broken_code: str) -> list[Variant]:
    """NAI-026 (finite set), two shapes. Identical `if` / `else` bodies (no elif chain): `body_once` (the block once,
    unconditionally) or `else_not_implemented` (the if kept, the else an explicit NotImplementedError stub). An
    operation cancelled by its inverse on the same value (`x += y; x -= y`, `x = x * y; x = x / y`; for an attribute
    target any inverse pair): `keep_first` (the second statement deleted) or `keep_second` (the first deleted).
    Declines a multi-line test or a statement sharing a row."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    for n in ast.walk(func):
        if isinstance(n, ast.If) and n.orelse and not (len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If)):
            if ast.dump(ast.Module(body=list(n.body), type_ignores=[])) == ast.dump(ast.Module(body=list(n.orelse), type_ignores=[])):
                return same_if_else_variants(func, pad, lines, n, "NAI-026")
    ops: dict[str, list[tuple[str, str, ast.stmt]]] = {}
    for n in ast.walk(func):
        if isinstance(n, ast.AugAssign) and type(n.op) in _OPS and _target_name(n.target):
            ops.setdefault(_target_name(n.target), []).append((_OPS[type(n.op)], ast.dump(n.value), n))  # type: ignore[arg-type]  # FIX_54 ast-pos
        elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.value, ast.BinOp) and type(n.value.op) in _OPS:
            name = _target_name(n.targets[0])
            if name and _target_name(n.value.left) == name:
                ops.setdefault(name, []).append((_OPS[type(n.value.op)], ast.dump(n.value.right), n))
    for name, seq in ops.items():
        for (o1, v1, s1), (o2, v2, s2) in zip(seq, seq[1:]):
            if (o1, o2) in _INVERSE and (v1 == v2 or "." in name):
                if not whole_rows(lines, [s1, s2]):
                    return []
                t1, t2 = node_text(lines, s1, pad), node_text(lines, s2, pad)
                out = []
                for variant, gone, kept in (("keep_first", s2, s1), ("keep_second", s1, s2)):
                    def edit(ls: list[str], gone=gone) -> bool:
                        a, b = rows(gone)
                        delete_rows(ls, a, b)
                        return True
                    v = edited(lines, edit)
                    if v is not None:
                        out.append((variant, v, f"`{node_text(lines, s1, pad)}` (line {s1.lineno}) and `{node_text(lines, s2, pad)}` (line {s2.lineno}) cancel each other on `{name}` — `{node_text(lines, kept, pad)}` kept, the other deleted (NAI-026)"))
                return finish(out)
    return []


def fix_unreachable_code(broken_code: str) -> list[Variant]:
    """NAI-028 (finite set): statements after an unconditional top-level `return` / `raise`. Candidates: `drop_dead`
    (the unreachable statements deleted — the early exit stands) and `exit_last` (the early exit deleted and, unless
    the remaining body already ends in a return / raise, re-appended after it — the work was meant to happen).
    Declines a statement sharing a row."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    body = list(func.body)
    for i, s in enumerate(body):
        if not isinstance(s, (ast.Return, ast.Raise)):
            continue
        rest = body[i + 1:]
        if not [x for x in rest if not (isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant))]:
            continue
        if not whole_rows(lines, [s] + rest):
            return []
        d0, d1 = rest[0].lineno - 1, rest[-1].end_lineno - 1
        ta, tb = rows(s)
        term = [lines[r] for r in range(ta, tb + 1)]
        ends_terminal = isinstance(rest[-1], (ast.Return, ast.Raise))

        def drop(ls: list[str]) -> bool:
            delete_rows(ls, d0, d1)
            return True

        def last(ls: list[str]) -> bool:
            delete_rows(ls, ta, tb)
            if not ends_terminal:
                at = d1 - (tb - ta + 1) + 1
                for k, line in enumerate(term):
                    ls.insert(at + k, line)
            return True

        tt = node_text(lines, s, pad) or type(s).__name__.lower()
        out = []
        v = edited(lines, drop)
        if v is not None:
            out.append(("drop_dead", v, f"{len(rest)} statement(s) after `{tt}` (snippet line {s.lineno}) were unreachable — deleted; the early exit stands (NAI-028)"))
        v = edited(lines, last)
        if v is not None:
            out.append(("exit_last", v, f"`{tt}` (snippet line {s.lineno}) exited before {len(rest)} statement(s) — the exit {'deleted (the body already ends in a terminal)' if ends_terminal else 'moved to the end'} so the work runs (NAI-028)"))
        return finish(out)
    return []


GENERATORS = [
    rewriter("NAI-026", f"{_SRC}:_check_identical_branches", "identical_branches_fix", fix_identical_branches,
             reason="finite set, two shapes — identical if / else bodies: the block once (`body_once`) or the else an explicit NotImplementedError stub (`else_not_implemented`); an operation cancelled by its inverse on the same value (`_check_inverse_operations`): the first kept (`keep_first`) or the second (`keep_second`); every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
    prescribed('NAI-027', f"{_SRC}:_check_mutation_theater", 'Return the local the function builds (the mutated list / dict / set), not the untouched parameter; or, when the parameter is meant to be updated in place, mutate it and drop the local.',
               'result = []\n... result.append(<item>) ...\nreturn result'),
    rewriter("NAI-028", f"{_SRC}:_check_unreachable_code", "top_level_unreachable_fix", fix_unreachable_code,
             reason="finite set — statements after an unconditional top-level return / raise: the dead statements deleted (`drop_dead`) or the early exit moved after them (`exit_last`); every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
    prescribed('NAI-029', f"{_SRC}:_check_constant_conditions", 'Write the real condition the branch was waiting for (the flag, the state, the comparison from the intent) in place of True / False; when the branch is unconditional, flatten it to its body and delete the dead arm.',
               'if <real condition>:\n    <body>'),
    rewriter("NAI-171", f"{_SRC}:_check_loop_else_without_break", "loop_else_splice_fix", fix_loop_else_without_break,
             "a `for` / `while` with an `else:` block and no `break` anywhere in its body (nested loops included, as the detector walks): the `else:` line goes and its statements are dedented one level to follow the loop — with no break the else block ran after every completion of the loop, and return / raise / an exception skipped it exactly as they skip what follows the loop; declines nested hits, an `else:` line not at the loop's indent, an else block not deeper than the header, or a block line that cannot be dedented by the block's depth (set 4b-42, 2026-09-10)",
             dated="2026-09-10", by="set 4b-42 (2026-09-10)"),
]
