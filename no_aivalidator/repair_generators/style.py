"""Style family (no_aivalidator/detection/style_checks.py) — item 4, 2026-09-08.

Set 4b-43 (2026-09-10, portion I's last — the LAST 4b set; app copy 1, a fan-out lane): three rewriters and two
no-fix-by-design. NAI-088 and NAI-179 are ALIASES of NAI-116's join role (`semantic.fix_string_concat_loop`, the one
function object, role `join_fix`): NAI-088 reads the detector's `acc += "<literal>"` / `acc += str(…)` / `acc += f"…"`
(with an accumulator initialised to a string) and NAI-179 the plain-assignment spelling `acc = acc + <value>` that
NAI-088's detector misses — the join role was widened on this set to read that spelling with the same preconditions
(`acc = "<str>"` directly above, the loop's only statement, a literal / `str()` / f-string value, the loop target read
nowhere else). Each alias carries its own plant: NAI-116's plant fires NAI-088 too (two detectors, one `+=` shape), so
the plant-less alias acceptance (NAI-122's) does not apply; the Builder dedupes by role, so a row carrying 088 + 116
sees ONE candidate. FACT on NAI-179: its detector carries no string evidence at all — `total = total + v` over a
number fires the same — the join role's literal-init precondition is the evidence, so the numeric shape declines.
NAI-089 REWRITER `append_loop_extend_fix` — the detector's identity append loop, `for <x> in <iter>: <out>.append(<x>)`
as the loop's only statement, becomes `<out>.extend(<iter>)` ONLY when `<out>` is a bare name the function itself
binds to a list (a list literal / `list(…)` / a list comprehension, or a parameter with such a default — the
receiver evidence of `cross_language_fix`); `list.extend` walks the same iterable once and appends each item in the
same order. Declines: no list evidence for the receiver, the receiver or the loop target read in the iterable, a loop
with `else`, a multi-line header, a loop-target name read anywhere outside its loop (the for's binding would be lost).
NAI-085 no-fix-by-design with the fact that it NEVER DECIDES today: `_check_flag_argument` was STRUCK from
`run_all_checks` at run 19 (2026-09-05, base.py:323 — "a design smell, not counterfeit") and is called from nowhere;
whether a boolean flag argument should be two functions is the dev's in any case. NAI-087 no-fix-by-design: a call
assigned inside a loop that reads no loop-bound name — hoisting it changes when and how often it runs (side effects,
a loop of zero iterations), which is the dev's; `meaning_source` corrected from the plan's `_is_break_guarded`
(the helper that mutes the read-until-falsy idiom) to `_check_loop_invariant`, the emitting function. Facts: 087,
088, 089 and 179 are called from `run_all_checks` (base.py:325-332); each observes its first hit and returns; 088
requires real string evidence (a literal / f-string / `str()` / `repr()` / `format()` value, or an accumulator last
initialised to a string), 089 requires the append argument to BE the loop target (a projection is honest work).
"""
from __future__ import annotations

import ast
import textwrap

from . import no_fix, prescribed, rewriter
from ._ast_edit import func_node
from .semantic import _names, _receiver_evidence, fix_string_concat_loop

_SRC = "no_aivalidator/detection/style_checks.py"


# ── NAI-089 (set 4b-43, 2026-09-10) ──────────────────────────────────────────

def fix_append_loop_extend(broken_code: str) -> tuple[str, str]:
    """NAI-089: `for <x> in <iter>: <out>.append(<x>)` (the loop's only statement) → `<out>.extend(<iter>)`, two lines
    become one at the loop's indent. Preconditions (decline the whole snippet otherwise): `<out>` a bare name the
    function binds to a list; neither `<out>` nor `<x>` read in `<iter>`; no `else`; the header and the statement each
    on one line, adjacent; no loop-target name read outside its loop. Behaviour that changes: none — `list.extend`
    walks the same iterable once and appends each item in the same order."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    dedented = textwrap.dedent(broken_code)
    lines = broken_code.splitlines()
    kinds = _receiver_evidence(func)
    hits: list[tuple[ast.For, str]] = []
    for n in ast.walk(func):
        if not (isinstance(n, ast.For) and not n.orelse and len(n.body) == 1 and isinstance(n.target, ast.Name)):
            continue
        stmt = n.body[0]
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
            continue
        call = stmt.value
        if not (isinstance(call.func, ast.Attribute) and call.func.attr == "append" and isinstance(call.func.value, ast.Name)
                and len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Name)
                and call.args[0].id == n.target.id):
            continue
        recv = call.func.value.id
        if kinds.get(recv) != "list":
            return "", ""  # the receiver is not a name the function binds to a list: no evidence, decline
        if recv in _names(n.iter) or n.target.id in _names(n.iter):
            return "", ""  # the receiver or the target is read in the iterable: not the extend
        if n.lineno != n.iter.end_lineno or stmt.lineno != n.lineno + 1 or stmt.lineno != stmt.end_lineno:
            return "", ""  # multi-line shapes are not edited
        hits.append((n, recv))
    if not hits:
        return "", ""
    for n, _recv in hits:
        inside = {id(x) for x in ast.walk(n)}
        for x in ast.walk(func):
            if isinstance(x, ast.Name) and x.id == n.target.id and id(x) not in inside:  # type: ignore[attr-defined]  # FIX_54 ast-pos
                return "", ""  # the loop-target name is read after (or before) the loop: the for's binding is relied on
    edits: list[tuple[int, int, str, str]] = []
    for n, recv in hits:
        row0, row1 = n.lineno - 1, n.body[0].end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
        indent = lines[row0][:len(lines[row0]) - len(lines[row0].lstrip())]
        iter_src = ast.get_source_segment(dedented, n.iter) or ""
        edits.append((row0, row1, f"{indent}{recv}.extend({iter_src})", f"`{lines[row0].strip()} {lines[row1].strip()}`"))
    for row0, row1, new_line, _old in sorted(edits, key=lambda t: t[0], reverse=True):
        lines[row0:row1 + 1] = [new_line]
    what = "; ".join(f"{old} (snippet lines {row0 + 1}-{row1 + 1}) → `{new_line.strip()}`" for row0, row1, new_line, old in sorted(edits, key=lambda t: t[0]))
    return "\n".join(lines), what + " — the receiver is a list the function binds; extend appends the same items in the same order"


GENERATORS = [
        # 4b fact (kept, FIX_41): a boolean-default parameter switching an `if` — whether the flag should be two functions is the dev's; and the detector NEVER DECIDES today: `_check_flag_argument` was struck from `run_all_checks` at run 19 (2026-09-05, base.py:323, 'a design smell, not counterfeit') and is called from nowhere (set 4b-43, 2026-09-10)
    prescribed("NAI-085", f"{_SRC}:_check_flag_argument",
               "Split the flag-switched function into two functions, one per arm, each named for what it does; callers pass no boolean.",
               "def do_a(x):\n    ...\n\ndef do_b(x):\n    ..."),
        prescribed("NAI-087", f"{_SRC}:_check_loop_invariant",
               "Hoist the loop-invariant call above the loop into a local and read the local inside the loop; a call whose side effect is meant to repeat stays, with a comment saying so.",
               "value = call()\nfor item in items:\n    use(value, item)"),
    rewriter("NAI-088", f"{_SRC}:_check_string_concat_loop", "join_fix", fix_string_concat_loop,
             "ALIAS of NAI-116's join role (the same function object, the same role): the detector's `acc += <str literal / f-string / str(…)>` as a `for` loop's only statement with `acc = \"<str>\"` directly above becomes `acc = \"\".join(…)`; every other string-evidenced shape the detector reads (`repr()` / `format()`, a bare name over a string-initialised accumulator, a `while` loop) declines. Its own plant: NAI-116's plant fires NAI-088 too, so the plant-less alias acceptance does not apply (set 4b-43, 2026-09-10)",
             dated="2026-09-10", by="set 4b-43 (2026-09-10)"),
    rewriter("NAI-089", f"{_SRC}:_check_append_loop_to_comprehension", "append_loop_extend_fix", fix_append_loop_extend,
             "the identity append loop `for <x> in <iter>: <out>.append(<x>)` (the loop's only statement) becomes `<out>.extend(<iter>)` ONLY when `<out>` is a bare name the function itself binds to a list — `list.extend` walks the same iterable once and appends each item in the same order; declines a receiver without list evidence, a receiver or target read in the iterable, a loop with else, a multi-line header, or a loop-target name read outside its loop (set 4b-43, 2026-09-10)",
             dated="2026-09-10", by="set 4b-43 (2026-09-10)"),
    rewriter("NAI-179", f"{_SRC}:_check_concat_in_loop_extended", "join_fix", fix_string_concat_loop,
             "ALIAS of NAI-116's join role (the same function object, the same role), widened on this set for the detector's plain-assignment spelling `acc = acc + <value>`: with `acc = \"<str>\"` directly above and a literal / f-string / `str(…)` value it becomes `acc = \"\".join(…)`; the detector itself carries NO string evidence (`total = total + v` over a number fires the same), so the literal init directly above is the evidence and every other shape declines. Its own plant (the `=` spelling) (set 4b-43, 2026-09-10)",
             dated="2026-09-10", by="set 4b-43 (2026-09-10)"),
]
