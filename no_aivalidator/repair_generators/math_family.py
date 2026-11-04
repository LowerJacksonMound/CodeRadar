"""Math family (no_aivalidator/detection/math_checks.py) — module named math_family so it can never shadow the stdlib `math` — item 4, 2026-09-08.

Every row is `unbuilt` (the honest placeholder) until this family is worked.
Set 4b-32 (2026-09-10, portion G's first; app copy 3): NAI-032 rewriter `algebraic_identity_fix` (`<x> + 0`,
`0 + <x>`, `<x> - 0`, `<x> * 1`, `1 * <x>` → `<x>`, the detector's own reading; a `/ 1` declines the snippet —
`4 / 1` is `4.0`, the plan's "partial"); NAI-033 rewriter `identity_comprehension_fix` (`[x for x in it]` →
`list(it)`, `{x for x in it}` → `set(it)`, equal by construction); NAI-030 (which parameter should reach the
result), NAI-031 (whether a dead store was meant to be read), NAI-034 (what a docstring-only function should do)
no-fix-by-design. Facts: all five are called from `run_all_checks` (base.py:221-225); NAI-030 / 031 / 034 observe
on the def line, NAI-032 / 033 on the expression's line and stop at the first hit (the rewriters take every hit);
NAI-034's `meaning_source` corrected — the catalogue named `core_checks.py:_check_side_effect_free`, which is
NAI-011's emitter (its comment names NAI-034 only as the shape NAI-011 catches in substance); the emitter is
`_check_docstring_only_body`. A NAI-030 row always also carries NAI-003 (an unread parameter is disconnected by
construction); a NAI-031 row carries NAI-147; a NAI-034 row carries NAI-120 and, module-level, NAI-011.
Set 4b-33 (2026-09-10, app copy 3): NAI-035 (what a dunder should compute), NAI-036 (which operand was meant —
and `x != x` is the NaN idiom), NAI-037 (accumulate or keep the last item), NAI-038 (which arm of a constant
switch survives) no-fix-by-design — FAMILY `math_family` CLOSED: 2 rewriters + 7 no-fix-by-design. Facts: all four
called from `run_all_checks` (base.py:226-229); 035 observes on the def line and reads the FIRST literal return
`ast.walk` meets, so a dunder whose first return is honest stays quiet; 036 / 038 stop at their first hit; 037's
top-level-assign rule (the body-shape fact in the detector) keeps the any-flag / last-match idioms quiet; a
dunder that is only `return <literal>` is NAI-009S's row (strict, body of one statement) — the plant carries a
statement beside the return.
"""
from __future__ import annotations

import ast
import textwrap
from typing import Any, Optional

from . import no_fix, prescribed, rewriter, unbuilt
from ._ast_edit import func_node, replace_cols, snippet_pad
from .core import _impure_callees, _nai010_pure_callee_only   # FIX_64: FIX_60's purity evidence and its gate word
from .gate import PREDICATES as _GATE_PREDICATES
from ._finite import (Variant, delete_rows, dedent_rows, edited, finish, fresh_name, indent, keyword_row, node_text,
                      prep, replace_node, rows, same_if_else_variants, single_line, whole_rows)

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SRC = "no_aivalidator/detection/math_checks.py"
_ATOMS = (ast.Name, ast.Constant, ast.Attribute, ast.Subscript, ast.Call)


# ── NAI-032 (set 4b-32, 2026-09-10) ──────────────────────────────────────────

def _literal(node: Node, value: int) -> bool:
    """The detector's `_is_zero` / `_is_one` narrowed to a real number: a bool literal (`False == 0`) is
    declined — dropping it would change the operand's type on the normal path."""
    return isinstance(node, ast.Constant) and type(node.value) in (int, float) and node.value == value


def _kept_operand(node: ast.BinOp):
    """The operand the identity reduces to, or None when the BinOp is not one of the detector's shapes."""
    if isinstance(node.op, ast.Add):
        if _literal(node.right, 0):
            return node.left
        if _literal(node.left, 0):
            return node.right
    elif isinstance(node.op, ast.Sub):
        if _literal(node.right, 0):
            return node.left
    elif isinstance(node.op, ast.Mult):
        if _literal(node.right, 1):
            return node.left
        if _literal(node.left, 1):
            return node.right
    return None


def _bool_operand(node: ast.BinOp) -> bool:
    return any(isinstance(side, ast.Constant) and isinstance(side.value, bool) for side in (node.left, node.right))


def _statement_has_effect(stmt: Node) -> bool:
    """FIX_62: the statement may not be deleted when evaluating it does anything but read and store a
    plain local — a call / await / yield / walrus anywhere in it, or a target whose assignment itself
    runs code (`obj.attr = …` can be a property or `__setattr__`, `d[k] = …` is `__setitem__`)."""
    if any(isinstance(n, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr)) for n in ast.walk(stmt)):
        return True
    return not all(isinstance(t, ast.Name) for t in getattr(stmt, "targets", []))


def _self_targets(stmt: Node) -> tuple[set, set]:
    """(every target of an `<t> = <identity>` statement, the ones the identity reduces its right side
    to). When the two sets are equal the statement the in-place rewrite would emit is `<t> = <t>` — a
    self-assignment, NAI-064's own shape, and FIX_62's whole subject. When only SOME target is that one
    (a chained `a = x = x + 0`, which still stores into `a`) the caller withholds: half a deletion is
    not a repair."""
    if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.BinOp)):
        return set(), set()
    kept = _kept_operand(stmt.value)
    if kept is None:
        return set(), set()
    texts = {ast.unparse(t) for t in stmt.targets}
    return texts, texts & {ast.unparse(kept)}


def fix_algebraic_identity(broken_code: str) -> tuple[str, str]:
    """NAI-032: every `<x> + 0` / `0 + <x>` / `<x> - 0` / `<x> * 1` / `1 * <x>` in the snippet → `<x>`, in
    place. The operand's own text is untouched and its own parentheses are kept; a non-atomic operand
    (anything but a name, literal, attribute, subscript or call) is parenthesized so the precedence around
    it cannot change. Structural preconditions (decline the whole snippet otherwise): no `<x> / 1` anywhere
    (the detector's div_one — `4 / 1` is `4.0`, a value-type change on the normal path), every identity on
    one line, no two identities overlapping, no bool literal as an operand of the identity.

    FIX_62 (2026-09-17, owner ruling on packet §A row #53): when the identity reduces a whole assignment
    to `<t> = <t>` — `total = total + 0` — the in-place rewrite USED TO EMIT the self-assignment, and the
    repair's own output tripped NAI-064. The repair is to DELETE the statement (it does nothing), and to
    WITHHOLD the whole snippet (`"", ""`) when deleting it would take an effect with it: a call, await,
    yield or walrus on the right side, a target that is an attribute or a subscript (a property /
    `__setitem__` runs on assignment), a statement that does not own its rows, or the only statement of
    its block. G0's `output_trips_rule` stays the backstop; `_nai032_identity` below is the predicate."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int, str, str]] = []
    deletions: list[tuple[int, int, str, str]] = []
    reduced: set[int] = set()
    walked: list[Node] = list(ast.walk(func))                      # FIX_54 ast-pos: positions live on the
    for stmt in walked:                                            # concrete node — FIX_62's pre-pass
        targets, selfish = _self_targets(stmt)
        if selfish:
            if targets != selfish or _statement_has_effect(stmt):
                return "", ""
            row, end = stmt.lineno - 1, stmt.end_lineno - 1
            if row != end or row >= len(lines):
                return "", ""
            before_col, after_col = pad + stmt.col_offset, pad + stmt.end_col_offset
            if lines[row][:before_col].strip() or lines[row][after_col:].strip():
                return "", ""                                      # shares its row: not ours to delete
            deletions.append((row, end, lines[row].strip(), ast.unparse(stmt.targets[0])))
            reduced.add(id(stmt.value))
    for node in ast.walk(func):
        if not isinstance(node, ast.BinOp):
            continue
        if id(node) in reduced:                                    # FIX_62: its statement goes instead
            continue
        if isinstance(node.op, ast.Div) and isinstance(node.right, ast.Constant) and node.right.value == 1:
            return "", ""  # div_one: not an identity on the normal path
        if isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)) and _bool_operand(node):
            return "", ""  # a bool literal: the detector's shape, not the rewrite's
        kept = _kept_operand(node)
        if kept is None:
            continue
        if node.lineno != node.end_lineno:
            return "", ""
        row = node.lineno - 1
        if row >= len(lines):
            return "", ""
        line = lines[row]
        bs, be = pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        ks, ke = pad + kept.col_offset, pad + kept.end_col_offset
        # keep the operand's own parentheses (they lie inside the BinOp's span)
        while True:
            left_of = line[bs:ks].rstrip()
            right_of = line[ke:be].lstrip()
            if left_of.endswith("(") and right_of.startswith(")"):
                ks = bs + len(left_of) - 1
                ke = be - len(right_of) + 1
                continue
            break
        text = line[ks:ke]
        if not isinstance(kept, _ATOMS) and not text.startswith("("):
            text = f"({text})"
        edits.append((row, bs, be, line[bs:be], text))
    if not edits and not deletions:
        return "", ""
    spans = sorted((r, s, e) for r, s, e, _o, _n in edits)
    for (r1, s1, e1), (r2, s2, e2) in zip(spans, spans[1:]):
        if r1 == r2 and s2 < e1:
            return "", ""  # nested identities: the columns of one move under the other
    dead = {r for r, _e, _t, _n in deletions}
    if any(row in dead for row, _s, _e, _o, _n in edits):
        return "", ""      # an identity on a row that goes: the columns would move under the deletion
    for row, s, e, _old, new in sorted(edits, key=lambda t: (t[0], t[1]), reverse=True):
        replace_cols(lines, row, s, e, new)
    for row, end, _text, _name in sorted(deletions, reverse=True):   # FIX_62: the no-op statement goes
        del lines[row:end + 1]
    if deletions:
        try:                        # a deletion that empties a block would not parse — withhold instead
            ast.parse(textwrap.dedent("\n".join(lines)))
        except SyntaxError:
            return "", ""
    what = "; ".join(
        [f"`{old}` (snippet line {row + 1}) → `{new}`"
         for row, _s, _e, old, new in sorted(edits, key=lambda t: (t[0], t[1]))]
        + [f"`{text}` (snippet line {row + 1}) reduces to `{name} = {name}` — the statement does nothing, "
           f"so it is DELETED, not rewritten as a self-assignment (FIX_62)"
           for row, _end, text, name in sorted(deletions)])
    return "\n".join(lines), what


def _nai032_identity(rw: Any, before: Any, after: Any) -> Optional[str]:
    """FIX_62's G0 predicate for `algebraic_identity_fix` (lane contract 1; the role is single-candidate,
    so the variant is the empty string).

    G0's generic `output_trips_rule` is the backstop the packet names for row #53 and it speaks first —
    a rewrite that ships `total = total` is a new NAI-064 infraction. Beside it the variant says its own
    word: an identity that reduces a statement to `<t> = <t>` is answered by DELETING the statement, and
    no deletion may take an effect with it — if a call the before-span made is gone from the after-span,
    the repair is withheld, not the effect."""
    from . import gate
    reason = gate.output_trips_rule(rw, before, after)
    if reason:
        return reason
    was = {ast.unparse(n) for n in ast.walk(before) if isinstance(n, ast.Call)}
    now = {ast.unparse(n) for n in ast.walk(after) if isinstance(n, ast.Call)}
    lost = sorted(was - now)
    if lost:
        return (f"gate: simplifying the identity would take `{lost[0]}` with it — the statement reduces to "
                f"`x = x`, but its right side has an effect; the repair is withheld, the effect kept.")
    return None


def _register_nai032_predicate() -> None:
    from . import gate
    gate.PREDICATES[("NAI-032", "")] = _nai032_identity


_register_nai032_predicate()   # FIX_62: declared beside the variant, as the lane contract asks


# ── NAI-033 (set 4b-32, 2026-09-10) ──────────────────────────────────────────

def fix_identity_comprehension(broken_code: str) -> tuple[str, str]:
    """NAI-033: every `[<x> for <x> in <it>]` → `list(<it>)` and `{<x> for <x> in <it>}` → `set(<it>)` in
    the snippet, in place — exactly the detector's shape (one generator, the element the loop variable, no
    condition). The iterable's text is untouched. Equal by construction for every iterable: a new list /
    set, the iterable consumed once, the comprehension's variable never leaked. Structural preconditions
    (decline the whole snippet otherwise): no `async for`, the comprehension on one line."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int, str, str]] = []
    for node in ast.walk(func):
        if not isinstance(node, (ast.ListComp, ast.SetComp)):
            continue
        if len(node.generators) != 1:
            continue
        gen = node.generators[0]
        if not (isinstance(gen.target, ast.Name) and isinstance(node.elt, ast.Name)):
            continue
        if gen.target.id != node.elt.id or gen.ifs:
            continue
        if gen.is_async:
            return "", ""
        if node.lineno != node.end_lineno:
            return "", ""
        row = node.lineno - 1
        if row >= len(lines):
            return "", ""
        line = lines[row]
        bs, be = pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        it = line[pad + gen.iter.col_offset:pad + gen.iter.end_col_offset]  # type: ignore[operator]  # FIX_54 ast-pos
        ctor = "list" if isinstance(node, ast.ListComp) else "set"
        edits.append((row, bs, be, line[bs:be], f"{ctor}({it})"))
    if not edits:
        return "", ""
    for row, s, e, _old, new in sorted(edits, key=lambda t: (t[0], t[1]), reverse=True):
        replace_cols(lines, row, s, e, new)
    what = "; ".join(f"`{old}` (snippet line {row + 1}) → `{new}`"
                     for row, _s, _e, old, new in sorted(edits, key=lambda t: (t[0], t[1])))
    return "\n".join(lines), what



# ── FIX_43 (b) finite-set rewriter (2026-09-16, app copy 3): every candidate offered, the Ranker decides ──
_H43 = "FIX_43 (b) (2026-09-16, app copy 3)"


def fix_dead_store(broken_code: str) -> list[Variant]:
    """NAI-031 (finite set): a local assigned and read nowhere in the function (the detector's order-blind gen / kill
    sets; `_`, `__`, `_unused*`, parameters, global / nonlocal names excluded). Candidates: `drop_store` (each dead
    assignment deleted — its right side no longer runs) and, when a dead right side contains a call, `keep_effect`
    (the target dropped, the right side kept as a bare expression statement — whatever it does still happens).
    Declines a dead name stored by tuple unpacking, augmented assignment, or a statement sharing a row.

    FIX_64 (2026-09-17, I-116; FIX_60's rule on the third helper): `drop_store` is minted only when every call
    a dead right side makes is pure by the module's own evidence (`core._pure_call` — the NAI-022 detector's
    tables and a local def with no side-effect statements). Otherwise the result was discarded but the CALL
    was not (rows #73 #74's class — `_GetConsoleScreenBufferInfo`, seen live on run 149 through this id): the
    delete is not offered and `keep_effect` stands alone. Fails CLOSED — unseen is not pure. G0 says the same
    at the gate, `PREDICATES[("NAI-031", "drop_store")]` = core's `_nai010_pure_callee_only`, so a
    `drop_store` minted anywhere else meets the same test."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    stores: dict[str, list[Node]] = {}
    reads: set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    stores.setdefault(t.id, []).append(n)
                else:
                    for x in ast.walk(t):
                        if isinstance(x, ast.Name):
                            stores.setdefault(x.id, []).append(n)
        elif isinstance(n, ast.AugAssign):
            if isinstance(n.target, ast.Name):
                stores.setdefault(n.target.id, []).append(n)
                reads.add(n.target.id)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            reads.add(n.id)
    params = {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}
    declared = {x for n in ast.walk(func) if isinstance(n, (ast.Global, ast.Nonlocal)) for x in n.names}
    dead = sorted(k for k in stores if k not in reads and k not in params and k not in declared
                  and k not in ("_", "__") and not k.startswith("_unused"))
    if not dead:
        return []
    stmts: list[ast.Assign] = []
    for k in dead:
        for s in stores[k]:
            if not (isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name)):
                return []
            if s not in stmts:
                stmts.append(s)
    if not whole_rows(lines, stmts):
        return []
    effectful = [s for s in stmts if any(isinstance(x, ast.Call) for x in ast.walk(s.value))]
    impure = [c for s in stmts for c in _impure_callees(s.value, func)]   # FIX_64: what the delete would silence

    def drop(ls: list[str]) -> bool:
        for s in sorted(stmts, key=lambda x: x.lineno, reverse=True):
            a, b = rows(s)
            delete_rows(ls, a, b)
        return True

    def keep(ls: list[str]) -> bool:
        for s in sorted(stmts, key=lambda x: x.lineno, reverse=True):
            r = s.lineno - 1
            if s.value.lineno != s.lineno:
                return False
            ls[r] = ls[r][:pad + s.col_offset] + ls[r][pad + s.value.col_offset:]
        return True

    where = ", ".join(f"`{s.targets[0].id}` (line {s.lineno})" for s in stmts)  # type: ignore[attr-defined]  # FIX_54 ast-pos
    out = []
    if not impure:
        v = edited(lines, drop)
        if v is not None:
            out.append(("drop_store", v, f"dead store(s) {where} deleted — the name was never read; its right side no longer runs, and every call it made is pure by the module's own evidence (NAI-031)"))
    if effectful:
        v = edited(lines, keep)
        if v is not None:
            why = (f" — `{impure[0]}` is not pure by the module's own evidence, so the delete is not offered (FIX_64)" if impure else "")
            out.append(("keep_effect", v, f"dead store(s) {where}: the target dropped, the right side kept as a statement — the call(s) it makes still run{why} (NAI-031)"))
    return finish(out)


# THE LANE CONTRACT (S5-1 §1): the predicate beside the variant, registered in G0's table by exact key.
# NAI-031's `drop_store` deletes a statement whose right side may call — the same test FIX_60 gave NAI-010 /
# NAI-147's `drop_assignment`, so the same predicate is its word (FIX_64, I-116).
_GATE_PREDICATES[("NAI-031", "drop_store")] = _nai010_pure_callee_only


GENERATORS = [
        prescribed("NAI-030", f"{_SRC}:_check_data_flow_disconnect",
               "Route the disconnected parameter into the result: use it in the computation the function's name and the intent promise, or remove it from the signature when every caller agrees it is unused.",
               "def f(a, b):\n    return <compute using a AND b>"),
    rewriter("NAI-031", f"{_SRC}:_check_variable_liveness", "dead_store_fix", fix_dead_store,
             reason="finite set — a local assigned and never read: the store deleted (`drop_store`) ONLY when every call its right side makes is pure by the module's own evidence (FIX_64, 2026-09-17 — FIX_60's rule on this helper; fail closed), and, when its right side calls something, the right side kept as a bare statement (`keep_effect`), which stands alone when a callee is not provably pure; the Ranker decides between what is offered (the row carries NAI-147 too)",
             dated="2026-09-16", by=_H43 + "; FIX_64 2026-09-17"),
    rewriter("NAI-032", f"{_SRC}:_check_algebraic_identity", "algebraic_identity_fix", fix_algebraic_identity,
             "`<x> + 0`, `0 + <x>`, `<x> - 0`, `<x> * 1`, `1 * <x>` → `<x>` in place — the detector's own reading (the expression simplifies to its operand); the operand's text is untouched, its own parentheses kept, a non-atomic operand parenthesized so the precedence around it cannot change; every identity in the snippet is rewritten (the detector stops at its first). Declines a `<x> / 1` anywhere in the snippet (`4 / 1` is `4.0` — a value-type change on the normal path; the plan's 'partial'), a bool literal as an operand, an identity split over lines, or two identities nested. By the rule's meaning a sequence is no longer copied by `* 1` — identity is what the rule calls for; on the normal path (a number) the value is the same (set 4b-32, 2026-09-10)",
             "2026-09-10", "set 4b-32 (2026-09-10)"),
    rewriter("NAI-033", f"{_SRC}:_check_comprehension_identity", "identity_comprehension_fix", fix_identity_comprehension,
             "`[<x> for <x> in <it>]` → `list(<it>)`, `{<x> for <x> in <it>}` → `set(<it>)` in place — exactly the detector's shape (one generator, the element the loop variable, no condition); the iterable's text is untouched. Equal by construction for every iterable: a new list / set, the iterable consumed once, the comprehension's variable never leaked. Declines an `async for` or a comprehension split over lines (set 4b-32, 2026-09-10)",
             "2026-09-10", "set 4b-32 (2026-09-10)"),
        # 4b fact (kept, FIX_41): a body that is exactly one docstring — what the function should do is the dev's implementation (NAI-120's reading; the row carries NAI-120 and, for a module-level def, NAI-011 too). `meaning_source` corrected: the catalogue named `core_checks.py:_check_side_effect_free`, which is NAI-011's emitter and names NAI-034 only as the shape NAI-011 catches in substance (set 4b-32, 2026-09-10)
    prescribed("NAI-034", f"{_SRC}:_check_docstring_only_body",
               "Write the body the docstring describes: implement what the docstring promises, reading the parameters and returning the promised value.",
               "def f(a):\n    \"\"\"<existing docstring>\"\"\"\n    <implementation per the docstring>\n    return <value>"),
        prescribed("NAI-035", f"{_SRC}:_check_dunder_fakes",
               "Write the dunder's real contract: `__eq__` compares the attributes that define identity, `__hash__` hashes those same attributes, `__len__` / `__bool__` measure the object's contents.",
               "def __eq__(self, other):\n    return isinstance(other, type(self)) and (self.<key>,) == (other.<key>,)\n\ndef __hash__(self):\n    return hash((self.<key>,))"),
        prescribed("NAI-036", f"{_SRC}:_check_redundant_comparisons",
               "Replace the self-comparison with the comparison against the operand the dev meant (another name or value); if it is the NaN idiom, write `math.isnan(x)` so the intent is explicit.",
               "if x == <other>:  # or: math.isnan(x)\n    ..."),
        prescribed("NAI-037", f"{_SRC}:_check_loop_overwrite_pattern",
               "Turn the per-iteration overwrite into the accumulation the loop was written for (`+=`, `.append`, a max / min), or move the assignment after the loop when only the last item is wanted.",
               "acc = <init>\nfor item in items:\n    acc += item   # or acc.append(item) / acc = max(acc, item)\nreturn acc"),
        prescribed("NAI-038", f"{_SRC}:_check_constant_conditional",
               "Remove the constant switch: keep the arm the intent needs, delete the other and dedent the kept arm; a toggle that must stay becomes a named flag read from config.",
               "<the kept arm, dedented>"),
]
