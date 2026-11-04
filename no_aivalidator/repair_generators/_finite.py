"""Shared line-edit helpers for the FIX_43 (b) finite-set rewriters (2026-09-16, app copy 3).

A finite-set rewriter returns EVERY candidate of a "which one's right" row as a list of
(variant, after_code, what_changed) — the Builder offers each, the Ranker decides, nothing here
ranks (owner rulings 2026-09-15/16: no rule-outs, no candidate unpickable). The edits are made on
the ORIGINAL snippet lines by row and column (formatting and comments survive; dedent is used
only to parse), the same discipline as `_ast_edit.py`."""
from __future__ import annotations

import ast
import textwrap
from typing import Any, Callable, List, Optional, Tuple

from ._ast_edit import func_node, snippet_pad

Variant = Tuple[str, str, str]

# FIX_54 (2026-09-17): "an AST node that carries a source position" — every helper below reads
# .lineno / .end_lineno / .col_offset / .end_col_offset off whatever node it is handed, and those
# attributes live on the concrete classes, not on ast.AST, while end_lineno/end_col_offset are typed
# Optional even where the parser always fills them. Annotating the intent is honest and changes no
# runtime behaviour; narrowing every call site would add isinstance early-outs the hunter counts.
Positioned = Any


def prep(code: str) -> Optional[Tuple[Positioned, int, List[str]]]:
    """(function node, column pad, original lines) or None when the snippet has no def."""
    func = func_node(code)
    if func is None:
        return None
    return func, snippet_pad(code), code.splitlines()


def rows(node: Positioned) -> Tuple[int, int]:
    """0-based inclusive row span of a node (decorators included for a def)."""
    first = node.lineno
    for d in getattr(node, "decorator_list", None) or []:
        first = min(first, d.lineno)
    return first - 1, node.end_lineno - 1


def indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def single_line(node: Positioned) -> bool:
    return node.lineno == node.end_lineno


def whole_rows(lines: List[str], stmts: List[Positioned]) -> bool:
    """True when no two statements of the list share a row with anything else on it — the row edits below
    delete or replace whole lines, so a `a; b` line declines."""
    for s in stmts:
        a, b = rows(s)
        if a < 0 or b >= len(lines):
            return False
        for r in (a, b):
            if ";" in lines[r].split("#")[0]:
                return False
    return True


def node_text(lines: List[str], node: Positioned, pad: int) -> Optional[str]:
    """The original text of a single-line node, or None."""
    if not single_line(node):
        return None
    line = lines[node.lineno - 1]
    return line[pad + node.col_offset:pad + node.end_col_offset]


def replace_node(lines: List[str], node: Positioned, pad: int, text: str) -> bool:
    """Replace a single-line node's columns with text (in place). False when the node spans rows."""
    if not single_line(node):
        return False
    r = node.lineno - 1
    lines[r] = lines[r][:pad + node.col_offset] + text + lines[r][pad + node.end_col_offset:]
    return True


def delete_rows(lines: List[str], a: int, b: int) -> None:
    del lines[a:b + 1]


def dedent_rows(lines: List[str], a: int, b: int, delta: int) -> bool:
    """Dedent rows a..b by delta columns; False when a non-blank row cannot give that much."""
    if delta <= 0:
        return True
    for r in range(a, b + 1):
        if lines[r].strip() and indent(lines[r]) < delta:
            return False
    for r in range(a, b + 1):
        if lines[r].strip():
            lines[r] = lines[r][delta:]
    return True


def keyword_row(lines: List[str], after_row: int, before_row: int, word: str) -> Optional[int]:
    """The one row strictly between after_row and before_row whose code starts with `word` (the `else:` /
    `finally:` line of a compound statement); None when there is not exactly one."""
    hits = [r for r in range(after_row + 1, before_row) if lines[r].split("#")[0].strip().startswith(word)]
    return hits[0] if len(hits) == 1 else None


def fresh_name(func: Positioned, base: str) -> str:
    """`base` unless the function already binds or reads it, then base_2, base_3 …"""
    used = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)} | {a.arg for a in ast.walk(func) if isinstance(a, ast.arg)}
    name, k = base, 1
    while name in used:
        k += 1
        name = f"{base}_{k}"
    return name


def finish(variants: List[Tuple[str, List[str], str]]) -> List[Variant]:
    """Keep the variants whose text parses; each becomes (variant, after_code, what_changed)."""
    out: List[Variant] = []
    for variant, lines, what in variants:
        code = "\n".join(lines)
        try:
            ast.parse(textwrap.dedent(code))
        except SyntaxError:
            continue
        out.append((variant, code, what))
    return out


def edited(lines: List[str], edit: Callable[[List[str]], bool]) -> Optional[List[str]]:
    """Apply an edit to a copy of the lines; None when the edit declined."""
    copy = list(lines)
    return copy if edit(copy) else None


# ── FIX_57 (2026-09-17): the NAI-120 shape, read once for every `*_not_implemented` variant ──────

def declared_only_body(body: List[Positioned]) -> bool:
    """FIX_57 (owner ruling 2, packet §A rows #61 #70): EMPTY or DECLARED-ONLY — `pass`, `...`, a
    reserved (docstring) stub, `raise NotImplemented[Error]`, or nothing at all. Only such an arm may
    be rewritten into an explicit `NotImplementedError` stub. A value-returning or value-producing arm
    is out of scope: identical-branch detection licenses COLLAPSING (`body_once` / `merge_conditions`),
    not raising, and a raise in place of an arm that does work is a new behaviour, not a repair.
    The same reading as G0's `gate._is_stub_body` — the source and the gate must agree."""
    for st in body:
        if isinstance(st, ast.Pass):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
            if st.value.value is Ellipsis or isinstance(st.value.value, str):
                continue
            return False
        if isinstance(st, ast.Raise) and _raises_not_implemented(st):
            continue
        return False
    return True


def _raises_not_implemented(st: Positioned) -> bool:
    raised = st.exc if isinstance(st, ast.Raise) else None
    called = raised.func if isinstance(raised, ast.Call) else raised
    name = called.attr if isinstance(called, ast.Attribute) else getattr(called, "id", "")
    return name in ("NotImplemented", "NotImplementedError")


def _not_implemented_predicate(rw: Any, before: Any, after: Any) -> Optional[str]:
    """FIX_57's G0 predicate for `else_not_implemented` / `later_not_implemented` (lane contract 1).

    G0 already ships the family reading under `("*", "<variant>")` — "withhold when any branch of the
    span still does work". This is that reading FIRST (so nothing G0 withholds is let through), then
    the tightening the SOURCE knows: the arm that BECAME the `NotImplementedError` stub is paired with
    the arm it replaced, and the rewrite is withheld unless THAT arm was empty / declared-only. An
    exact (rule_id, variant) key wins over the `"*"` one, so registering this replaces nothing and
    loses nothing."""
    from . import gate
    reason = gate.PREDICATES[("*", "else_not_implemented")](rw, before, after)
    if reason:
        return reason
    # G0's own arm reading, not a second one — the stub variants keep the branch structure, so the
    # two lists pair arm with arm and the tightening is "the arm it REPLACED was declared-only".
    for was, now in zip(gate._branch_bodies(before), gate._branch_bodies(after)):
        if any(_raises_not_implemented(st) for st in now) and not declared_only_body(was):
            return ("gate: the arm this would stub out already does work — `NotImplementedError` in "
                    "place of a value-producing branch changes what the function returns; only an "
                    "empty or declared-only body (`pass`, `...`, a reserved stub) qualifies, and the "
                    "duplicate is answered by collapsing the branches, not by raising.")
    return None


def register_not_implemented_predicates() -> None:
    """Called from the rewriter modules that own the variants (`structural`, `hallucination`,
    `advanced` through `same_if_else_variants`) so G0 and the source carry ONE reading of FIX_57."""
    from . import gate
    for key in (("NAI-026", "else_not_implemented"), ("NAI-040", "else_not_implemented"),
                ("NAI-053", "later_not_implemented")):
        gate.PREDICATES[key] = _not_implemented_predicate


def same_if_else_variants(func: Positioned, pad: int, lines: List[str], n: ast.If, tag: str) -> List[Variant]:
    """The two answers to an `if` / `else` whose blocks are identical: the block once (unconditionally), or the
    `if` kept and the `else` made distinct as an explicit NotImplementedError stub. Shared by NAI-040 and NAI-026.

    FIX_57 (2026-09-17, owner ruling 2 on row #61): the stub is offered ONLY when the else arm is empty /
    declared-only (`declared_only_body` — the NAI-120 shape). A value-returning duplicate arm gets the
    collapse and nothing else: identical-branch detection licenses collapsing, not raising."""
    if not single_line(n.test) or not whole_rows(lines, list(n.body) + list(n.orelse)):
        return []
    head = n.lineno - 1
    b0, b1 = n.body[0].lineno - 1, n.body[-1].end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
    e0, e1 = n.orelse[0].lineno - 1, n.orelse[-1].end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
    else_row = keyword_row(lines, b1, e0, "else")
    if else_row is None:
        return []
    head_indent, body_indent = indent(lines[head]), indent(lines[b0])
    test = node_text(lines, n.test, pad) or ""
    fname = getattr(func, "name", "f")

    def once(ls: List[str]) -> bool:
        delete_rows(ls, else_row, e1)
        if not dedent_rows(ls, b0, b1, body_indent - head_indent):
            return False
        delete_rows(ls, head, head)
        return True

    def stub(ls: List[str]) -> bool:
        delete_rows(ls, e0, e1)
        ls.insert(e0, " " * indent(lines[e0]) + f'raise NotImplementedError("{fname}: else of `if {test}` not implemented")')
        return True

    k = len(n.body)
    out: List[Tuple[str, List[str], str]] = []
    v = edited(lines, once)
    if v is not None:
        out.append(("body_once", v, f"`if {test}:` (snippet line {head + 1}) had identical if / else blocks ({k} statement(s) each) — the block kept once, unconditionally; the test no longer decides anything ({tag})"))
    if declared_only_body(list(n.orelse)):   # FIX_57: an empty / declared-only arm, never a working one
        v = edited(lines, stub)
        if v is not None:
            out.append(("else_not_implemented", v, f"`if {test}:` (snippet line {head + 1}) had identical if / else blocks, both empty / declared-only — the if block kept, the else block replaced by an explicit NotImplementedError stub so the branch that was meant to differ is named, not invented ({tag})"))
    return finish(out)
