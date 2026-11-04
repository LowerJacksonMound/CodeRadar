"""Hallucination family (no_aivalidator/detection/hallucination_checks.py) — item 4, 2026-09-08.

No fix by design: NAI-050, NAI-055 (owner ruling 2026-09-08).
Set 4b-36 (2026-09-10, portion H's first; app copy 1, a fan-out lane): three rewriters and two no-fix-by-design.
NAI-051 REWRITER `misspelled_builtin_fix` — the detector's misspelled builtin name (`lenght(` / `pritn(` / `rnage(` …,
the `MISSPELLED_BUILTINS` table it reads, whose `correction` it carries) is respelled to the builtin it names, at every
Load-context occurrence in the function. Declines the whole snippet when the misspelled name is BOUND anywhere in the
function (a parameter, an assignment, a def, an import, an except-as — then it is the dev's own name, not a typo),
when the corrected name is itself bound in the function (the respelling would resolve to that local), or when the
table's correction is not a builtin (`retrun` → `return` is a keyword, not a name). Behaviour that changes, by the
rule's meaning: the misspelling raises NameError at the first call; the respelling is the one reading under which the
function runs. NAI-052 REWRITER `redundant_nesting_fix` — the detector's two shapes: (a) `if C:` whose FIRST statement
is `if C:` with the same condition — the inner `if` header goes, its body is dedented one level into the outer, its
`else` (dead: the same condition was just true) goes with it; (b) `if C: … elif C: …` — the `elif` branch is dead and
is removed, whatever follows it (`elif` / `else`) stays. Only a PURE condition is rewritten — names, constants,
attributes, comparisons, `and` / `or` / `not`, arithmetic; a call, a subscript, a walrus, an await / yield, a
conditional expression, a comprehension, a lambda or an f-string in the condition declines the snippet (a second
evaluation could observe something; the rule's claim of redundancy needs the condition to be the same VALUE, not just
the same text). Multi-line headers or bodies that cannot be dedented cleanly decline. Behaviour that changes: none —
every reachable statement runs in the same order; only the second evaluation of the same pure expression goes.
NAI-056 REWRITER `misspelled_module_fix` — the detector's misspelled top-level module (`import colelctions` /
`from pathilb import Path`, the `MISSPELLED_MODULES` table, `correction` carried) is respelled in the import statement
and — for a plain `import x` with no `as` — at every `x.…` reference in the function, since the bound name changes
with the spelling. Declines: a relative import, a misspelled name bound anywhere else in the function, the corrected
name already bound or referenced in the function (a collision), a multi-line import header. Behaviour that changes,
by the rule's meaning: the misspelling raises ModuleNotFoundError; the respelling is the module the dev reached for.
NAI-053 (identical bodies across branches — which branch is wrong, or whether the conditions should be merged, is the
dev's) and NAI-054 (consecutive identical statements — whether the second is a copy-paste slip or an intended
repeat of an effectful call is the dev's) no-fix-by-design. Facts: all five are called from `run_all_checks`
(base.py:247-252); every one observes its first hit and returns; NAI-051's Name path fires on Store context too (a
local NAMED `lenght` is its row — the rewriter declines exactly that shape); NAI-052's `elif` loop walks `node.orelse`
as a list, so an `else:` block whose first statement is `if <same C>:` also reads as `identical_elif` (the rewriter
edits only a real `elif` line); NAI-053's sentinel-only bodies never count (`_is_sentinel_only_branch_body`).
Set 4b-37 (2026-09-10, portion H's second, run 91): NAI-057 (an import of a commonly hallucinated module name — the module the
dev meant is unknown), NAI-058 (a dunder-shaped method name Python never calls — what the hook should be named,
or whether the project's protocol wants it, is the dev's; a name defined or referenced twice in the file's
directory subtree is a project fact and never fires), NAI-059 (`module.STATUS_ACTIVE`-style constants from the
detector's own table on a non-self receiver — the real constant, if any, is unknown) no-fix-by-design. Facts: all
three are called from `run_all_checks` (base.py:253-255); NAI-058 observes on the def line of the dunder itself and
is gated by `is_fake_dunder` plus `_dunder_occurrence_counts` of the file's directory; NAI-059's table is local to
the detector (twenty names) and `self` / `cls` receivers are skipped.
"""
from __future__ import annotations

import ast
from typing import Any
import builtins
import re

from . import no_fix, prescribed, rewriter, unbuilt
from ._ast_edit import func_node, replace_cols, snippet_pad
from ._finite import (Variant, declared_only_body, delete_rows, dedent_rows, edited, finish, fresh_name, indent,
                      keyword_row, node_text, prep, register_not_implemented_predicates, replace_node, rows,
                      same_if_else_variants, single_line, whole_rows)

register_not_implemented_predicates()   # FIX_57: G0 and the source carry ONE reading of the stub variants

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SRC = "no_aivalidator/detection/hallucination_checks.py"

try:
    from signature_engine.hallucinations import MISSPELLED_BUILTINS, MISSPELLED_MODULES
except ImportError:  # the detector refuses to run without the registries; the rewriters simply decline
    MISSPELLED_BUILTINS, MISSPELLED_MODULES = {}, {}


def _bound_names(func: Node) -> set[str]:
    """Every name the function binds: parameters, Store / Del targets, nested defs and classes, imports, except-as,
    global / nonlocal declarations. A misspelling that is bound is the dev's own name — never respelled."""
    names: set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.arg):
            names.add(n.arg)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not func:
            names.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                names.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            names.update(n.names)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
    return names


# ── NAI-051 (set 4b-36, 2026-09-10) ──────────────────────────────────────────

def fix_misspelled_builtin(broken_code: str) -> tuple[str, str]:
    """NAI-051: every Load-context name in the function that the detector's MISSPELLED_BUILTINS table lists is respelled
    to the table's correction, in place by column. Declines the whole snippet if the misspelled name is bound in the
    function, if the correction is bound in the function, or if the correction is not a builtin."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    bound = _bound_names(func)
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int, str, str]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id in MISSPELLED_BUILTINS:
            correct = MISSPELLED_BUILTINS[node.id]
            if node.id in bound or correct in bound or not hasattr(builtins, correct):
                return "", ""
            if not isinstance(node.ctx, ast.Load) or node.lineno != node.end_lineno:
                return "", ""
            row, a, b = node.lineno - 1, pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
            if lines[row][a:b] != node.id:
                return "", ""
            edits.append((row, a, b, correct, node.id))
    if not edits:
        return "", ""
    for row, a, b, text, _old in sorted(edits, reverse=True):
        replace_cols(lines, row, a, b, text)
    what = "; ".join(f"`{old}` (snippet line {row + 1}) → `{new}`" for row, _a, _b, new, old in sorted(edits))
    return "\n".join(lines), what + " — the builtin the misspelling names, unbound in the function"


# ── NAI-052 (set 4b-36, 2026-09-10) ──────────────────────────────────────────

_PURE = (ast.Name, ast.Constant, ast.Attribute, ast.Compare, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Tuple,
         ast.boolop, ast.cmpop, ast.unaryop, ast.operator, ast.expr_context)


def _pure(test: Node) -> bool:
    return all(isinstance(n, _PURE) for n in ast.walk(test))


def _dedent_block(lines: list[str], first: int, last: int, delta: int) -> list[str] | None:
    out = []
    for row in range(first, last + 1):
        line = lines[row]
        if not line.strip():
            out.append("")
        elif line[:delta].strip():
            return None  # a line shallower than the block (a string continuation) — cannot dedent cleanly
        else:
            out.append(line[delta:])
    return out


def fix_redundant_nesting(broken_code: str) -> tuple[str, str]:
    """NAI-052: (a) an `if C:` whose first statement is `if C:` — the inner header and its dead `else` go, the inner
    body is dedented into the outer; (b) an `elif C:` repeating its own chain's `if C:` — the dead branch goes. Pure
    conditions only; any impure hit, a same-line body, an uncleanly dedentable block or overlapping edits decline."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    # (first row, last row, replacement lines, what)
    edits: list[tuple[int, int, list[str], str]] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        outer = ast.dump(node.test)
        if node.body and isinstance(node.body[0], ast.If) and ast.dump(node.body[0].test) == outer:
            inner = node.body[0]
            if not _pure(node.test):
                return "", ""
            if inner.body[0].lineno <= inner.test.end_lineno:  # type: ignore[operator]  # FIX_54 ast-pos
                return "", ""  # body on the header line
            first, last = inner.body[0].lineno - 1, inner.body[-1].end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
            delta = inner.body[0].col_offset - inner.col_offset
            block = _dedent_block(lines, first, last, delta)
            if block is None or delta <= 0:
                return "", ""
            header = lines[inner.lineno - 1].strip()
            dead = f", its dead `else` ({len(inner.orelse)} statement(s)) with it" if inner.orelse else ""
            edits.append((inner.lineno - 1, inner.end_lineno - 1, block,  # type: ignore[operator]  # FIX_54 ast-pos
                          f"the inner `{header}` (snippet line {inner.lineno}) under the same `{lines[node.lineno - 1].strip()}` goes, its body dedented into the outer{dead}"))
        for elif_node in node.orelse:
            if isinstance(elif_node, ast.If) and ast.dump(elif_node.test) == outer:
                if not _pure(node.test):
                    return "", ""
                row = elif_node.lineno - 1
                if not re.match(r"\s*elif\b", lines[row]) or pad + elif_node.col_offset != len(lines[row]) - len(lines[row].lstrip()):
                    return "", ""  # not a real `elif` line (an `if` inside an `else:` block): not this shape
                if elif_node.body[0].lineno <= elif_node.test.end_lineno:  # type: ignore[operator]  # FIX_54 ast-pos
                    return "", ""
                edits.append((row, elif_node.body[-1].end_lineno - 1, [],  # type: ignore[operator]  # FIX_54 ast-pos
                              f"the dead `{lines[row].strip()}` branch (snippet line {elif_node.lineno}) repeating `{lines[node.lineno - 1].strip()}` goes"))
    if not edits:
        return "", ""
    edits.sort(key=lambda t: t[0])
    for (_, last_a, _, _), (first_b, _, _, _) in zip(edits, edits[1:]):
        if first_b <= last_a:
            return "", ""  # overlapping shapes: decline rather than edit inside an edit
    for first, last, block, _what in reversed(edits):
        lines[first:last + 1] = block
    return "\n".join(lines), "; ".join(w for _f, _l, _b, w in edits) + " — the same pure condition was just evaluated true; every reachable statement runs as before"


# ── NAI-056 (set 4b-36, 2026-09-10) ──────────────────────────────────────────

def fix_misspelled_module(broken_code: str) -> tuple[str, str]:
    """NAI-056: the misspelled top-level module of an `import` / `from … import` in the function is respelled to the
    detector's correction; a plain `import x` (no `as`) also respells every `x` reference in the function, since the
    bound name changes. Declines a relative import, a misspelled name bound elsewhere, a corrected name already bound
    or referenced in the function, or a multi-line header."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    referenced = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
    bound = _bound_names(func)
    edits: list[tuple[int, int, int, str, str, str]] = []  # row, a, b, new, old text, new text
    renames: dict[str, str] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in MISSPELLED_MODULES:
                    continue
                correct = MISSPELLED_MODULES[top]
                if alias.lineno != alias.end_lineno or correct in bound or correct in referenced:
                    return "", ""
                row, a = alias.lineno - 1, pad + alias.col_offset
                if lines[row][a:a + len(top)] != top:
                    return "", ""
                edits.append((row, a, a + len(top), correct, f"import {alias.name}", f"import {correct}{alias.name[len(top):]}"))
                if alias.asname is None:
                    if any(isinstance(n, ast.Name) and n.id == top and not isinstance(n.ctx, ast.Load) for n in ast.walk(func)):
                        return "", ""  # the misspelled name is also assigned in the function: the dev's own name
                    renames[top] = correct
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top not in MISSPELLED_MODULES:
                continue
            correct = MISSPELLED_MODULES[top]
            if node.level or node.lineno != node.names[0].lineno:
                return "", ""
            row = node.lineno - 1
            m = re.match(r"(\s*from\s+)(" + re.escape(top) + r")\b", lines[row])
            if not m:
                return "", ""
            edits.append((row, m.start(2), m.end(2), correct, f"from {node.module}", f"from {correct}{node.module[len(top):]}"))
    if not edits:
        return "", ""
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id in renames and isinstance(node.ctx, ast.Load):
            row, a, b = node.lineno - 1, pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
            if lines[row][a:b] != node.id:
                return "", ""
            edits.append((row, a, b, renames[node.id], node.id, renames[node.id]))
    for row, a, b, text, _o, _n in sorted(edits, reverse=True):
        replace_cols(lines, row, a, b, text)
    what = "; ".join(f"`{old}` (snippet line {row + 1}) → `{new}`" for row, _a, _b, _t, old, new in sorted(edits))
    return "\n".join(lines), what + " — the module the misspelling names"



# ── FIX_43 (b) finite-set rewriter (2026-09-16, app copy 3): every candidate offered, the Ranker decides ──
_H43 = "FIX_43 (b) (2026-09-16, app copy 3)"


def _chain(n: ast.If) -> list[tuple[ast.If | None, ast.expr | None, list]]:
    """The branches of an if / elif / else chain as (node, test, body); the else has node None."""
    out: list = [(n, n.test, n.body)]
    cur = n
    while cur.orelse:
        if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
            cur = cur.orelse[0]
            out.append((cur, cur.test, cur.body))
        else:
            out.append((None, None, cur.orelse))
            break
    return out


def fix_repetitive_branches(broken_code: str) -> list[Variant]:
    """NAI-053 (finite set): an if / elif / else chain with two or more identical non-sentinel bodies. Candidates:
    `merge_conditions` (the later duplicates' tests joined to the first with `or`, their branches deleted — only when
    every duplicate has a test) and `later_not_implemented` (the first kept, each later duplicate's body an explicit
    NotImplementedError stub naming its test). Declines a multi-line test or a statement sharing a row.

    FIX_57 (2026-09-17, owner ruling 2 on row #70): `later_not_implemented` is offered ONLY when EVERY later
    duplicate arm is empty / declared-only (`declared_only_body` — the NAI-120 shape). A copied-constant arm
    (`code == 2 → "one"`) is answered by the collapse, never by a raise: the duplicate is a shape question,
    and a raise where a value was returned is a new behaviour, not a repair."""
    from ..detection.hallucination_checks import _is_sentinel_only_branch_body  # the detector's own sentinel reading
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    for n in ast.walk(func):
        if not isinstance(n, ast.If):
            continue
        chain = _chain(n)
        seen: dict[str, list[int]] = {}
        for i, (_node, _test, body) in enumerate(chain):
            if _is_sentinel_only_branch_body(body):
                continue
            seen.setdefault(ast.dump(ast.Module(body=list(body), type_ignores=[])), []).append(i)
        dup = next((ix for ix in seen.values() if len(ix) > 1), None)
        if dup is None:
            continue
        first, later = chain[dup[0]], [chain[i] for i in dup[1:]]
        if any(t is not None and not single_line(t) for _n, t, _b in chain) or not whole_rows(lines, [s for _n, _t, b in chain for s in b]):
            return []
        f_test = node_text(lines, first[1], pad) if first[1] is not None else None

        def branch_rows(i: int) -> tuple[int, int]:
            node, _t, body = chain[i]
            if node is not None:
                return node.lineno - 1, body[-1].end_lineno - 1
            prev_body = chain[i - 1][2]
            r = keyword_row(lines, prev_body[-1].end_lineno - 1, body[0].lineno - 1, "else")
            return (r if r is not None else body[0].lineno - 1), body[-1].end_lineno - 1

        def merge(ls: list[str]) -> bool:
            if first[1] is None or any(t is None for _n, t, _b in later):
                return False
            tests = [f_test] + [node_text(lines, t, pad) for _n, t, _b in later]
            for i in sorted(dup[1:], reverse=True):
                a, b = branch_rows(i)
                delete_rows(ls, a, b)
            return replace_node(ls, first[1], pad, " or ".join(f"({t})" for t in tests))

        def stubs(ls: list[str]) -> bool:
            for i in sorted(dup[1:], reverse=True):
                node, t, body = chain[i]
                b0, b1 = body[0].lineno - 1, body[-1].end_lineno - 1
                label = f"`elif {node_text(lines, t, pad)}`" if t is not None else "the else branch"
                delete_rows(ls, b0, b1)
                ls.insert(b0, " " * indent(lines[b0]) + f'raise NotImplementedError("{func.name}: {label} not implemented")')
            return True

        labels = ", ".join(f"line {chain[i][0].lineno}" if chain[i][0] is not None else "else" for i in dup[1:])  # type: ignore[union-attr]  # FIX_54 ast-pos
        out = []
        v = edited(lines, merge)
        if v is not None:
            out.append(("merge_conditions", v, f"branch(es) at snippet {labels} repeated the body of `if {f_test}` (line {n.lineno}) — their tests joined to the first with `or`, the repeats deleted (NAI-053)"))
        if all(declared_only_body(list(b)) for _n, _t, b in later):   # FIX_57: empty / declared-only arms only
            v = edited(lines, stubs)
            if v is not None:
                out.append(("later_not_implemented", v, f"branch(es) at snippet {labels} repeated the empty / declared-only body of the branch at line {n.lineno} — each repeat's body an explicit NotImplementedError stub naming its test, so the branch meant to differ is named, not invented (NAI-053)"))
        return finish(out)
    return []


GENERATORS = [
    prescribed('NAI-050', f"{_SRC}:_check_undefined_calls", "Call the function that exists for this job: import or define it under the name used, or change the call to the real name in this module / the intent's external systems; no undefined name stays.",
               'from <module> import <real_name>\n...\n<real_name>(<args>)'),
    prescribed('NAI-055', f"{_SRC}:_check_hallucinated_function_calls", "Replace the call with the library's real API (its documentation names the method that does what this name suggests) and match the arguments to its signature.",
               "<obj>.<real_method>(<args per the library's signature>)"),
    rewriter("NAI-051", f"{_SRC}:_check_misspelled_builtins", "misspelled_builtin_fix", fix_misspelled_builtin,
             "the misspelled builtin name (the detector's MISSPELLED_BUILTINS table, correction carried) is respelled at every Load-context occurrence in the function; declines when the misspelling or the correction is bound in the function, or the correction is not a builtin (set 4b-36, 2026-09-10)",
             dated="2026-09-10", by="set 4b-36 (2026-09-10)"),
    rewriter("NAI-052", f"{_SRC}:_check_redundant_nesting", "redundant_nesting_fix", fix_redundant_nesting,
             "an `if C:` whose first statement is `if C:` loses the inner header (its body dedented, its dead else dropped); an `elif C:` repeating its chain's `if C:` is removed; pure conditions only (a call, subscript, walrus, await, comprehension, lambda or f-string in C declines), same-line bodies and uncleanly dedentable blocks decline (set 4b-36, 2026-09-10)",
             dated="2026-09-10", by="set 4b-36 (2026-09-10)"),
    rewriter("NAI-053", f"{_SRC}:_check_repetitive_branches", "repetitive_branches_fix", fix_repetitive_branches,
             reason="finite set — an if / elif / else chain with identical non-sentinel bodies: the repeats' tests joined to the first with `or` (`merge_conditions`) or each repeat's body an explicit NotImplementedError stub (`later_not_implemented`); every candidate offered, the Ranker decides",
             dated="2026-09-16", by=_H43),
    prescribed('NAI-054', f"{_SRC}:_check_duplicate_statements", 'Delete the second copy; when the call is meant to run twice, loop it with the count named so the repetition reads as intended.',
               '<statement>   # once\n# or\nfor _ in range(<n>):\n    <statement>'),
    rewriter("NAI-056", f"{_SRC}:_check_misspelled_module_imports", "misspelled_module_fix", fix_misspelled_module,
             "the misspelled top-level module (the detector's MISSPELLED_MODULES table, correction carried) is respelled in the import and, for a plain `import x`, at every `x` reference in the function; declines a relative import, a bound misspelling, a corrected name already bound or referenced, or a multi-line header (set 4b-36, 2026-09-10)",
             dated="2026-09-10", by="set 4b-36 (2026-09-10)"),
    prescribed('NAI-057', f"{_SRC}:_check_hallucinated_module_imports", "Import the module that actually holds the names used — the project's own module by its real path, or the installed package the intent's dependencies list; delete the import when nothing from it is used.",
               'from <real.package.module> import <names actually used>'),
    prescribed('NAI-058', f"{_SRC}:_check_fake_dunder_methods", 'Rename the method to a plain name (serialize, validate) and call it explicitly, or implement the real protocol hook Python calls (__repr__, __iter__, __eq__ …) when that is what was meant.',
               'def <plain_name>(self, ...):   # was __<name>__\n    ...\nobj.<plain_name>()'),
    prescribed('NAI-059', f"{_SRC}:_check_invented_constants", 'Use the constant the module actually defines (or define it once at module level with its real value) and reference that name; never an attribute that does not exist.',
               '<CONSTANT> = <real value>   # module level\n...\n<receiver>.<existing attribute>  /  <CONSTANT>'),
]
