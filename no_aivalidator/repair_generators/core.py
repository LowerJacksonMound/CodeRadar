"""Core family (no_aivalidator/detection/core_checks.py) — item 4, 2026-09-08.

Rewriter: NAI-008 (new). No fix by design: NAI-004, NAI-015 (owner ruling 2026-09-08).
Set 4b-19 (2026-09-10, portion C of ITEM_04B): NAI-005 rewriter `redundant_else_fix` — the `else:` after an
if whose body ends in return / raise is dropped and its two statements (`name = <expr>; return name`, the only
shape the detector fires on) dedented to the if's level; NAI-002 (which is the mistake, the terminal or the
code after it — the NAI-140 reading), NAI-003 (what the parameter was for; removing it changes the signature),
NAI-006 (which of two consecutive values was meant; the first assignment's right side has effects), NAI-007
(call it, return it or delete it) no-fix-by-design. Facts: all five are called from `run_all_checks`
(base.py:180-186); NAI-002 observes the first unreachable statement's line and returns; NAI-003 exempts
dummy-named / catch-all params, @overload / @override / @abstractmethod bodies and a method on a class with
bases unless every param is ignored; NAI-005 reads the function's own scope and excludes `elif`; NAI-006
reads consecutive top-level assigns only and `x = f(x)` counts as a use; NAI-007 reads top-level nested defs.
Set 4b-20 (2026-09-10): NAI-009 (what to compute from the inputs), NAI-010 (whether a dead local was meant to be
used), NAI-011 (return something or act on something), NAI-014 (three bundled shapes; a self-assignment deletion
changes scope, a discarded expression may have effects) no-fix-by-design; NAI-016 no-fix-by-design with the fact
that its row is always a strict row's on the daemon route — a bare `return param` is NAI-016S's, a return through
an alias NAI-021S's (probed 2026-09-10) — what the function should transform is the dev's anyway. Facts: all
five called from `run_all_checks` (base.py:188-193); NAI-009's literal variant is likewise NAI-009S's row, its
empty-collection variant reaches a row as NAI-009.
Set 4b-21 (2026-09-10): NAI-017 (what happens on the swallowed exception), NAI-019 (which branch returns
what), NAI-020 (what the test should assert), NAI-021 (what to do besides logging) no-fix-by-design; NAI-018
no-fix-by-design with the fact that it never decides (the extractor never sets `is_async`). `meaning_source`
corrected for 017 and 018 (both emitted from core_checks.py, not safety_checks.py). Facts: all five called from
`run_all_checks` (base.py:194-199); a bare `except: pass` row also carries NAI-070 (rewritten) and NAI-078; the
`suppress(Exception)` form carries NAI-017 alone; NAI-020's trivial-assert variant is withheld with its file
(test species by content); NAI-021's return-input variant is a strict row's.Set 4b-22 (2026-09-10): NAI-022 (keep the result or drop the line), NAI-023 (which operand), NAI-024 (what the
loop does with its other items), NAI-025 (which value), NAI-170 (`x += 1` or nothing) no-fix-by-design; NAI-024's
`meaning_source` corrected (`_check_loop_patterns`, not the helper). Facts: all five called from `run_all_checks`
(base.py:200-204); 022 fires only for a known-pure callee; 024 mutes itself when a real fallback follows the
loop; 025 / 170 / 022 rows become NAI-021S's when the no-op is the function's only data flow.Set 4b-23 (2026-09-10, portion C's last): NAI-174 (which name), NAI-175 / NAI-177 (which value or key), NAI-212
(where the real data comes from) no-fix-by-design. Facts: all four called from `run_all_checks` (base.py:183,
205-207); 174 fires only when the shadowed builtin is also called in the same function; 212 needs nested literal
rows — a flat literal container is not the species. FAMILY `core` CLOSED: 2 rewriters (NAI-008, NAI-005) + 27
no-fix-by-design; 017 / 018 / 024 `meaning_source` corrected; 018 never decides today (`is_async` never set).
"""
from __future__ import annotations

import ast
import contextlib
import contextvars
import functools
from typing import Any, Iterator
import re
import sys

from . import no_fix, prescribed, rewriter, unbuilt
from ._ast_edit import body_after_docstring, func_node, replace_cols, snippet_pad
from .gate import PREDICATES as _GATE_PREDICATES      # FIX_60: this lane registers its variant's predicate

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_ELSE_LINE = re.compile(r"^(\s*)else:\s*(#.*)?$")


def _own_scope(func: "ast.FunctionDef | ast.AsyncFunctionDef"):
    """The function's OWN statements — a nested def / lambda / class is another row (the detector's IG-9)."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(n))


def fix_redundant_else(broken_code: str) -> tuple[str, str]:
    """NAI-005: every `if` of the function's own scope whose body ends in return / raise and whose
    else is exactly `name = <expr>` then `return name` (the ONLY shape the detector fires on, the
    2026-09-06 fact) — the `else:` line is dropped and the two statements are dedented to the if's
    level. The else is reached only when the if body did not terminate, and it never terminates
    otherwise, so the statements run under the same condition as before: nothing on any path
    changes. Structural preconditions, decline the whole snippet otherwise: one `else:` line (a
    trailing comment allowed) at the if's own column between the body and the else statements;
    both else statements on single lines, indented deeper than the if; no `elif`."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    hits: list[tuple[int, int, int, int, str]] = []   # (else_row, first_row, last_row, delta, name)
    for node in _own_scope(func):
        if not (isinstance(node, ast.If) and node.orelse and isinstance(node.body[-1], (ast.Return, ast.Raise))):
            continue
        orelse = node.orelse
        if len(orelse) == 1 and isinstance(orelse[0], ast.If):
            continue   # elif: not the detector's shape
        shape = (len(orelse) == 2 and isinstance(orelse[0], ast.Assign) and len(orelse[0].targets) == 1
                 and isinstance(orelse[0].targets[0], ast.Name) and isinstance(orelse[1], ast.Return)
                 and isinstance(orelse[1].value, ast.Name) and orelse[1].value.id == orelse[0].targets[0].id)
        if not shape:
            continue
        if any(st.lineno != st.end_lineno for st in orelse):
            return "", ""
        if_col = pad + node.col_offset
        else_rows = [r for r in range(node.body[-1].end_lineno, orelse[0].lineno - 1)  # type: ignore[arg-type]  # FIX_54 ast-pos
                     if r < len(lines) and (m := _ELSE_LINE.match(lines[r])) and len(m.group(1)) == if_col]
        if len(else_rows) != 1:
            return "", ""
        delta = orelse[0].col_offset - node.col_offset
        if delta <= 0:
            return "", ""
        first, last = orelse[0].lineno - 1, orelse[-1].lineno - 1
        if last >= len(lines) or any(lines[r].strip() and not lines[r].startswith(" " * delta) for r in range(first, last + 1)):
            return "", ""
        hits.append((else_rows[0], first, last, delta, orelse[0].targets[0].id))  # type: ignore[attr-defined]  # FIX_54 ast-pos
    if not hits:
        return "", ""
    what_parts = []
    for else_row, first, last, delta, name in sorted(hits, reverse=True):
        for r in range(first, last + 1):
            if lines[r].strip():
                replace_cols(lines, r, 0, delta, "")
        what_parts.append(f"`else:` (snippet line {else_row + 1}) dropped — `{name} = …; return {name}` dedented to the if's level")
        del lines[else_row]
    return "\n".join(lines), "; ".join(reversed(what_parts))

_STDLIB = frozenset(sys.stdlib_module_names)


def _bound_names(imp: "ast.Import | ast.ImportFrom") -> list[str]:
    out = []
    for a in imp.names:
        out.append(a.asname or a.name.split(".")[0])
    return out


def _names_bound_in_function(func: "ast.FunctionDef | ast.AsyncFunctionDef", imports: list) -> set[str]:
    """Every name the function binds OTHER than through the imports being hoisted: parameters,
    Store / Del targets, global / nonlocal declarations, nested def / class names."""
    skip = set(map(id, imports))
    names: set[str] = set()
    a = func.args
    for arg in a.posonlyargs + a.args + a.kwonlyargs + ([a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else []):
        names.add(arg.arg)
    for n in ast.walk(func):
        if id(n) in skip:
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            names.update(n.names)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not func:
            names.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names.update(_bound_names(n))
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
        elif isinstance(n, ast.arg):
            names.add(n.arg)
    return names


def fix_import_in_function(broken_code: str) -> tuple[str, str]:
    """NAI-008: every import that is a DIRECT statement of the function body (the construct the
    detector observes; a try/except-wrapped import is not a direct statement and never fires)
    is hoisted out of the body to module scope, immediately above the def (above its
    decorators when the snippet carries them). Structural preconditions — each a fact of the
    snippet's own AST, decline otherwise:
      * the def is at module level (snippet indent 0): hoisting from a method or nested def
        would land in class / enclosing scope, which is not module scope;
      * every direct-body import is single-line, absolute (level 0 — a relative import inside a
        function is the circular-import idiom), and of a stdlib top-level module
        (sys.stdlib_module_names — a third-party or optional dependency imported lazily is the
        dev's choice; hoisting it would make the module fail to import when it is absent);
      * no name the import binds is bound anywhere else in the function (parameter, assignment,
        global / nonlocal, nested def), so the body's references resolve to the same object as
        module globals;
      * the body keeps at least one statement after the hoist.
    All direct-body imports are hoisted together (so the rule goes quiet) or none are."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    if snippet_pad(broken_code) != 0:
        return "", ""
    lines = broken_code.splitlines()
    body = body_after_docstring(func)
    imports = [n for n in body if isinstance(n, (ast.Import, ast.ImportFrom))]
    if not imports or len(body) == len(imports):
        return "", ""
    for imp in imports:
        if imp.lineno != imp.end_lineno:
            return "", ""
        if isinstance(imp, ast.ImportFrom):
            if imp.level or not imp.module or imp.module == "__future__":
                return "", ""
            tops = [imp.module.split(".")[0]]
        else:
            tops = [a.name.split(".")[0] for a in imp.names]
        if any(t not in _STDLIB for t in tops):
            return "", ""
    bound_elsewhere = _names_bound_in_function(func, imports)
    hoisted_names = [n for imp in imports for n in _bound_names(imp)]
    if any(n in bound_elsewhere for n in hoisted_names) or len(set(hoisted_names)) != len(hoisted_names):
        return "", ""
    rows = sorted(imp.lineno - 1 for imp in imports)
    if any(r >= len(lines) for r in rows):
        return "", ""
    hoisted = [lines[r].strip() for r in rows]
    for r in reversed(rows):
        del lines[r]
    out = hoisted + [""] + lines
    what = "; ".join(f"`{text}` (body line {r + 1}) hoisted to module scope above `def {func.name}`"
                     for r, text in zip(rows, hoisted))
    return "\n".join(out), what


# ---------------------------------------------------------------------------------------------------------
# FIX_43 (b) — finite-set rewriters (owner rulings 2026-09-15/16: a "which one's right" row emits EVERY candidate
# and the Ranker decides; nothing here ranks, no candidate is unpickable). Each fn returns a list of
# (variant, after_code, what_changed); [] declines. Shared line-level helpers first (a statement's rows are its
# lineno..end_lineno; dedent keeps line numbers, so rows are the original's; columns need snippet_pad).
# ---------------------------------------------------------------------------------------------------------
_Variants = list[tuple[str, str, str]]


def _rows(st: Node) -> tuple[int, int]:
    return st.lineno - 1, st.end_lineno - 1


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _delete_stmts(lines: list[str], stmts: list[Node], block: list[Node]) -> None:
    """Delete the statements' rows (bottom-up); an emptied block gets `pass` at the first deleted row's indent."""
    if not stmts:
        return
    keep = [s for s in block if s not in stmts]
    first_row = min(_rows(s)[0] for s in stmts)
    pad = _indent(lines[first_row])
    for s in sorted(stmts, key=lambda s: s.lineno, reverse=True):
        a, b = _rows(s)
        del lines[a:b + 1]
    if not keep:
        lines.insert(first_row, pad + "pass")


def _blocks(func) -> list[list[Node]]:
    """Every statement list of the function's OWN scope (the body and each nested block), outermost first."""
    out: list[list[Node]] = []
    stack: list[list[Node]] = [func.body]
    while stack:
        block = stack.pop(0)
        out.append(block)
        for st in block:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for field in ("body", "orelse", "finalbody"):
                sub = getattr(st, field, None)
                if isinstance(sub, list) and sub and all(isinstance(x, ast.stmt) for x in sub):
                    stack.append(sub)
            for h in getattr(st, "handlers", []) or []:
                stack.append(h.body)
    return out


def _dedent_rows(lines: list[str], a: int, b: int, n: int) -> None:
    for r in range(a, b + 1):
        if lines[r].strip() and lines[r].startswith(" " * n):
            lines[r] = lines[r][n:]


def _remove_dict_entries(lines: list[str], node: ast.Dict, drop: list[int], pad: int) -> None:
    """Remove the given key:value entries (indices into node.keys) from the dict literal's text, with their
    separating comma; entries are removed bottom-up so earlier offsets stay valid."""
    text = "\n".join(lines)
    starts = [0]
    for ln in lines[:-1]:
        starts.append(starts[-1] + len(ln) + 1)
    def off(line: int, col: int) -> int:
        return starts[line - 1] + col + pad
    for i in sorted(drop, reverse=True):
        k, v = node.keys[i], node.values[i]
        a = off(k.lineno, k.col_offset)  # type: ignore[union-attr]  # FIX_54 ast-pos
        b = off(v.end_lineno, v.end_col_offset)  # type: ignore[arg-type]  # FIX_54 ast-pos
        j = b
        while j < len(text) and text[j] in " \t\n":
            j += 1
        if j < len(text) and text[j] == ",":
            b = j + 1
            while b < len(text) and text[b] in " \t":
                b += 1
        else:   # last entry: take the comma before it
            j = a - 1
            while j >= 0 and text[j] in " \t\n":
                j -= 1
            if j >= 0 and text[j] == ",":
                a = j
        text = text[:a] + text[b:]
    lines[:] = text.split("\n")


def _terminates(st: Node) -> bool:
    """The reading of extended_semantic_checks._stmt_flow_state: a statement after which nothing runs."""
    if isinstance(st, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    if isinstance(st, ast.If):
        return bool(st.orelse) and _block_terminates(st.body) and _block_terminates(st.orelse)
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return _block_terminates(st.body)
    if isinstance(st, ast.Try):
        return any(isinstance(f, ast.Return) for f in st.finalbody)
    return False


def _block_terminates(block: list[Node]) -> bool:
    return any(_terminates(st) for st in block)


def _after_terminal(block: list[Node], simple_only: bool) -> tuple[ast.stmt, list[Node]] | None:
    """(terminal, dead statements after it) for the first terminal of the block, or None."""
    for i, st in enumerate(block[:-1]):
        hit = isinstance(st, (ast.Return, ast.Raise)) if simple_only else _terminates(st)
        if hit:
            dead = block[i + 1:]
            if simple_only and isinstance(dead[0], (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue   # the detector allows a def right after the terminal
            return st, dead
    return None


def _terminal_variants(broken_code: str, simple_only: bool) -> _Variants:
    """NAI-002 (simple_only: a return / raise, the next statement not a def) and NAI-140 (any terminal of the
    flow reading): `drop_dead` deletes what follows the terminal; `terminal_last` moves a simple terminal
    below it (the statements run, then the function ends as before)."""
    func = func_node(broken_code)
    if not func:
        return []
    hits = [(blk, r) for blk in _blocks(func) if (r := _after_terminal(blk, simple_only))]
    if not hits:
        return []
    lines0 = broken_code.splitlines()
    out: _Variants = []
    lines = list(lines0)
    what: list[str] = []
    for blk, (term, dead) in sorted(hits, key=lambda h: h[1][0].lineno, reverse=True):
        drop = [d for d in dead if not isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        _delete_stmts(lines, drop, blk)
        what.append(f"{len(drop)} statement(s) after the `{type(term).__name__.lower()}` at snippet line {term.lineno} deleted")
    out.append(("drop_dead", "\n".join(lines), "; ".join(reversed(what))))
    movable = all(isinstance(t, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                  and not any(isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for d in dead)
                  for _, (t, dead) in hits)
    if movable:
        lines = list(lines0)
        what = []
        for blk, (term, dead) in sorted(hits, key=lambda h: h[1][0].lineno, reverse=True):
            ta, tb = _rows(term)
            last = _rows(dead[-1])[1]
            moved = lines[ta:tb + 1]
            del lines[ta:tb + 1]
            lines[last - (tb - ta + 1) + 1:last - (tb - ta + 1) + 1] = moved
            what.append(f"the `{type(term).__name__.lower()}` at snippet line {term.lineno} moved below the {len(dead)} statement(s) that followed it")
        out.append(("terminal_last", "\n".join(lines), "; ".join(reversed(what))))
    return out


def fix_unreachable_after_return(broken_code: str) -> _Variants:
    """NAI-002 finite set: the terminal is right (drop the dead code) / the code after it was meant to run
    (move the terminal last) — the two readings the row's reason names; the Ranker decides."""
    return _terminal_variants(broken_code, simple_only=True)


def fix_immediate_overwrite(broken_code: str) -> _Variants:
    """NAI-006 finite set for `x = a` immediately followed by `x = b` (b not reading x) in the body:
    `keep_second` (the dead FIRST write goes, the live one survives), `keep_second_effect` (the first's
    right side stays as a bare statement when it is a call — its effect kept, its value not).

    FIX_56 (2026-09-17, the owner's ruling §A on rows #30 #33): `keep_first` is RETIRED as an unattended
    variant. The dead store is the FIRST write; deleting the live second one promotes a value the program
    never used, and it inverts the family's own name — `immediate_overwrite` is the rule, and the overwrite
    is what the program ran. Unattended repair must preserve observable behavior, so only the last-live
    repair is minted here, and G0 now says the same thing from both sides (`gate.live_store_removed` and
    `gate.PREDICATES[("NAI-006", "keep_first")]`, which stay as the gate's word on a keep_first minted
    anywhere else). "The first computation was the one meant" is an INTENT change and belongs to the client
    (the shape lane); NAI-006 has no shape path to carry it — a Generator is a rewriter OR a prescribed row,
    never both (`__init__.Generator.__post_init__`) — so the variant is retired outright rather than
    re-minted as a prescribed shape."""
    func = func_node(broken_code)
    if not func:
        return []
    body = func.body
    runs: list[list[ast.Assign]] = []
    cur: list[ast.Assign] = []
    def _name(st):
        return st.targets[0].id if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) else None
    for st in body:
        n = _name(st)
        if n and cur and _name(cur[-1]) == n and not any(isinstance(x, ast.Name) and x.id == n and isinstance(x.ctx, ast.Load) for x in ast.walk(st.value)):  # type: ignore[attr-defined]  # FIX_54 ast-pos
            cur.append(st)  # type: ignore[arg-type]  # FIX_54 ast-pos
            continue
        if len(cur) > 1:
            runs.append(cur)
        cur = [st] if n else []  # type: ignore[list-item]  # FIX_54 ast-pos
    if len(cur) > 1:
        runs.append(cur)
    if not runs:
        return []
    lines0 = broken_code.splitlines()
    out: _Variants = []
    lines = list(lines0)   # FIX_56: no `keep_first` — the later store is the live one, and it stays
    _delete_stmts(lines, [s for run in runs for s in run[:-1]], body)
    out.append(("keep_second", "\n".join(lines), "; ".join(f"`{_name(run[0])}`: the last assignment (snippet line {run[-1].lineno}) kept, {len(run) - 1} earlier one(s) deleted" for run in runs)))
    if all(isinstance(s.value, ast.Call) for run in runs for s in run[:-1]):
        lines = list(lines0)
        pad = snippet_pad(broken_code)
        for run in runs:
            for s in reversed(run[:-1]):
                a, _ = _rows(s)
                replace_cols(lines, a, pad + s.col_offset, pad + s.value.col_offset, "")
        out.append(("keep_second_effect", "\n".join(lines), "; ".join(f"`{_name(run[0])}`: the last assignment kept; the earlier right side(s) kept as bare call(s) — their effect stays, their value is not bound" for run in runs)))
    return out


def fix_unused_nested_def(broken_code: str) -> _Variants:
    """NAI-007 finite set for a nested def never read: `delete_nested`, `call_nested` (a bare call right after
    the def — only when it takes no required argument), `return_nested` (the def returned at the end of the body
    when the body does not already end in a return / raise)."""
    func = func_node(broken_code)
    if not func:
        return []
    used = {n.id for n in ast.walk(func) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    unused = [st for st in func.body if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name not in used]
    if not unused:
        return []
    lines0 = broken_code.splitlines()
    out: _Variants = []
    lines = list(lines0)
    _delete_stmts(lines, unused, func.body)
    out.append(("delete_nested", "\n".join(lines), "; ".join(f"nested `{d.name}` (snippet line {d.lineno}) deleted — never called, returned or read" for d in unused)))
    def _required(d) -> int:
        a = d.args
        return len(a.posonlyargs) + len(a.args) - len(a.defaults) + sum(1 for k, dv in zip(a.kwonlyargs, a.kw_defaults) if dv is None)
    if all(_required(d) == 0 for d in unused):
        lines = list(lines0)
        for d in sorted(unused, key=lambda d: d.lineno, reverse=True):
            _, b = _rows(d)
            lines.insert(b + 1, _indent(lines[_rows(d)[0]]) + f"{d.name}()")
        out.append(("call_nested", "\n".join(lines), "; ".join(f"`{d.name}()` called right after its def (snippet line {d.lineno})" for d in unused)))
    if not isinstance(func.body[-1], (ast.Return, ast.Raise)) and len(unused) == 1:
        lines = list(lines0)
        d = unused[0]
        _, b = _rows(func.body[-1])
        lines.insert(b + 1, _indent(lines[_rows(func.body[-1])[0]]) + f"return {d.name}")
        out.append(("return_nested", "\n".join(lines), f"`return {d.name}` appended — the nested def is the function's result"))
    return out


_DEAD_ACCEPTABLE = frozenset({
    'result', 'output', 'ret', 'rv', 'response', 'data', 'dummy', 'placeholder', 'unused', '_', 'exc_type', 'exc_val',
    'exc_tb', 'exc_info', 'exception_type', 'exception_value', 'traceback', 'e', 'ex', 'err', 'exc', 'exctype', 'exctb',
    'excinst', 'excinfo', 't', 'v', 'tb', 'exc_value', 'wrapper', 'inner', 'wrapped', 'decorator', 'new_func', 'decorated',
    'func_wrapper', 'method_wrapper', 'cache', 'memo', 'sentinel', 'MISSING', 'lock', 'hits', 'misses', 'full', 'currsize',
    'maxsize', 'cls', 'klass', 'base', 'bases', 'mcs', 'dct', 'type', 'owner', 'objtype', 'name', 'kwargs', 'args', 'kw',
    'pat', 'key', '_key', 'oldresult', 'oldkey', 'is_dir', 'scandir', 'exists', 'target_is_directory', 'mode', 'pathobj',
    'target', 'a', 'b', 'iterable', 'parts', 'path', 'filename', 'dirname', 'i', 'j', 'k', 'n', 'm', 'x', 'y', 'z', 'p',
    'q', 'r', 's', 'w'})   # the NAI-010 detector's own acceptable-name table (core_checks._check_dead_computation)


_PURE_TABLES: dict[str, frozenset[str]] = {}


def _pure_tables() -> dict[str, frozenset[str]]:
    """FIX_60 — the purity evidence, and it is the module's own, not this lane's invention: the two tables
    the NAI-022 detector already decides with (`detection/core_checks.py::_check_discarded_calls`, hardened
    F-022 2026-09-05 — *only* a call to a KNOWN-PURE callee is a discarded RESULT; a bare call to anything
    else is a side-effect call by the industry default), plus IG-10's string-receiver names. Read lazily
    (FIX_25's lazy-export discipline). If they ever move, this fails CLOSED — empty tables mean no callee is
    pure, so the delete variant is simply never minted, which is the direction that preserves behavior."""
    if not _PURE_TABLES:
        try:
            from ..detection.core_checks import CoreChecksMixin, _STR_METHOD_NAMES
            _PURE_TABLES["builtins"] = frozenset(CoreChecksMixin._PURE_BUILTINS)
            _PURE_TABLES["methods"] = frozenset(CoreChecksMixin._PURE_METHODS)
            _PURE_TABLES["str_methods"] = frozenset(_STR_METHOD_NAMES)
        except Exception:
            _PURE_TABLES["builtins"] = frozenset()
            _PURE_TABLES["methods"] = frozenset()
            _PURE_TABLES["str_methods"] = frozenset()
    return _PURE_TABLES


def _receiver_is_str(expr: Node, scope: Node) -> bool:
    """The detector's own IG-10 test (`core_checks._receiver_is_str`): the receiver is a string by a VISIBLE
    fact — a literal, an f-string, str() / repr() / format(), a string-method chain, or a name last bound to
    one of those. `os.replace(a, b)` and `thread.join()` share a pure method's name, not its purity."""
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, str)
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.Call):
        f = expr.func
        return ((isinstance(f, ast.Name) and f.id in ("str", "repr", "format"))
                or (isinstance(f, ast.Attribute) and f.attr in _pure_tables()["str_methods"] and _receiver_is_str(f.value, scope)))
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return _receiver_is_str(expr.left, scope)
    if isinstance(expr, ast.Name):
        last = None
        for n in ast.walk(scope):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == expr.id for t in n.targets):
                if last is None or n.lineno > last.lineno:
                    last = n
        return last is not None and _receiver_is_str(last.value, scope)
    return False


# FIX_65 (2026-09-17, I-117): the module the span was cut from, as purity EVIDENCE. `candidates_of` (the one
# publish choke point, reserved to G0) sets it around the rewriter call and the gate check; a rewriter's
# signature stays `fn(broken_code)`. Empty = no module in hand (health-check step 19, a bare proof call) and
# the evidence is the span alone, exactly as before.
_MODULE_EVIDENCE: contextvars.ContextVar[str] = contextvars.ContextVar("module_evidence", default="")


@contextlib.contextmanager
def module_evidence(module_src: str) -> Iterator[None]:
    """Make `module_src` the module-level purity evidence for the block (FIX_65)."""
    token = _MODULE_EVIDENCE.set(module_src or "")
    try:
        yield
    finally:
        _MODULE_EVIDENCE.reset(token)


@functools.lru_cache(maxsize=64)
def _module_defs(module_src: str) -> dict[str, Any]:
    """Every TOP-LEVEL def of the module that is the name's ONLY top-level binding — one def, and no
    top-level assignment / import / class of the same name that could rebind it. A name bound twice is
    evidence of nothing (fail closed). Methods are not names in the module's scope and are not here."""
    try:
        tree = ast.parse(module_src)
    except SyntaxError:
        return {}
    bound: dict[str, int] = {}
    defs: dict[str, Any] = {}
    for n in tree.body:
        names: list[str] = []
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names = [n.name]
            defs[n.name] = n
        elif isinstance(n, ast.ClassDef):
            names = [n.name]
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names = [(a.asname or a.name).split(".")[0] for a in n.names]
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            names = [x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)]
        elif isinstance(n, (ast.Global,)):
            names = list(n.names)
        for nm in names:
            bound[nm] = bound.get(nm, 0) + 1
    return {k: d for k, d in defs.items() if bound.get(k) == 1}


def _local_def_is_pure(name: str, scope: Node) -> bool:
    """The owner's first purity ground: *a local def with no side-effect statements*. The evidence is what
    the rewriter is HANDED — the function's own source — so a def visible here is a nested one; and, since
    FIX_65 (I-117), the module the span came from when `candidates_of` has it (`module_evidence`): a
    module-level helper that is the name's only top-level binding is read the same way. Unseen is still
    not pure — no module in hand, or a name bound more than once at the top level, fails closed."""
    defs = [n for n in ast.walk(scope)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name and n is not scope]
    if not defs:
        mod = _MODULE_EVIDENCE.get()
        d = _module_defs(mod).get(name) if mod else None
        if d is None or d is scope:
            return False
        defs = [d]
    for d in defs:
        for n in ast.walk(d):
            if isinstance(n, (ast.Raise, ast.Global, ast.Nonlocal, ast.Await, ast.Yield, ast.YieldFrom,
                              ast.Import, ast.ImportFrom, ast.With, ast.AsyncWith, ast.Try, ast.Delete, ast.Assert)):
                return False
            if isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(getattr(n, "ctx", None), (ast.Store, ast.Del)):
                return False
            if isinstance(n, ast.Call) and not _pure_call(n, scope, nested=True):
                return False
    return True


def _pure_call(call: Node, scope: Node, nested: bool = False) -> bool:
    """Is this callee pure by the module's own evidence? A known-pure builtin, a pure method (with IG-10's
    string receiver where the name is a string method's), or a local def with no side-effect statements.
    `nested` reads a local def's own body and does not recurse through another def (recursion terminates)."""
    t = _pure_tables()
    f = call.func
    if isinstance(f, ast.Name):
        if f.id in t["builtins"]:
            return True
        return (not nested) and _local_def_is_pure(f.id, scope)
    if isinstance(f, ast.Attribute):
        return f.attr in t["methods"] and (f.attr not in t["str_methods"] or _receiver_is_str(f.value, scope))
    return False


def _impure_callees(value: Node, scope: Node) -> list[str]:
    """Every call inside a right side that is NOT pure by that evidence — the effects that would leave the
    program with the statement. An await / yield is an effect in itself."""
    out: list[str] = []
    if value is None:
        return out
    for n in ast.walk(value):
        if isinstance(n, (ast.Await, ast.Yield, ast.YieldFrom)):
            out.append("await" if isinstance(n, ast.Await) else "yield")
        elif isinstance(n, ast.Call) and not _pure_call(n, scope):
            f = n.func
            out.append(f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "the call"))
    return out


def dead_local_variants(broken_code: str, acceptable: frozenset[str]) -> _Variants:
    """NAI-010 / NAI-147 finite set for a local assigned (a single-name Assign / AugAssign / AnnAssign of the
    function's own scope) and never read: `drop_assignment` (the statement goes; an emptied block gets `pass`),
    `keep_call_effect` (when every such right side is a call: the call stays as a bare statement).

    FIX_60 (2026-09-17, the owner's ruling §A on rows #73 #74 — `_GetConsoleScreenBufferInfo`,
    `_FillConsoleOutputCharacterA` deleted as "discarded result"): the DELETE variant is minted only when
    every call it would delete is pure by the module's own evidence (`_pure_call`). Otherwise the result was
    discarded but the CALL was not: `keep_call_effect` is offered as the first and only candidate — the call
    stays, the unread name goes — and `drop_assignment` is not offered at all. G0 states the same rule at the
    gate, `PREDICATES[("NAI-010" | "NAI-147", "drop_assignment")]` below, so the source and the gate agree."""
    func = func_node(broken_code)
    if not func:
        return []
    params = {a.arg for a in func.args.args + func.args.posonlyargs + func.args.kwonlyargs}
    if func.args.vararg:
        params.add(func.args.vararg.arg)
    if func.args.kwarg:
        params.add(func.args.kwarg.arg)
    loads = {n.id for n in ast.walk(func) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    outer = {nm for n in ast.walk(func) if isinstance(n, (ast.Global, ast.Nonlocal)) for nm in n.names}
    hits: list[tuple[list[Node], ast.stmt, str]] = []
    for blk in _blocks(func):
        for st in blk:
            tgt = None
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                tgt = st.targets[0].id
            elif isinstance(st, (ast.AugAssign, ast.AnnAssign)) and isinstance(st.target, ast.Name) and getattr(st, "value", None) is not None:
                tgt = st.target.id
            if tgt and tgt not in loads and tgt not in params and tgt not in outer and not tgt.startswith("_") and tgt not in acceptable:
                hits.append((blk, st, tgt))
    if not hits:
        return []
    lines0 = broken_code.splitlines()
    out: _Variants = []
    impure = [c for _, s, _ in hits for c in _impure_callees(getattr(s, "value", None), func)]   # FIX_60
    if not impure:
        lines = list(lines0)
        for blk in {id(b): b for b, _, _ in hits}.values():
            _delete_stmts(lines, [s for b, s, _ in hits if b is blk], blk)
        out.append(("drop_assignment", "\n".join(lines), "; ".join(f"`{t}` (snippet line {s.lineno}) never read — its assignment deleted" for _, s, t in hits)))
        if all(isinstance(getattr(s, "value", None), ast.Call) for _, s, _ in hits):
            lines = list(lines0)
            pad = snippet_pad(broken_code)
            for _, s, t in sorted(hits, key=lambda h: h[1].lineno, reverse=True):
                replace_cols(lines, _rows(s)[0], pad + s.col_offset, pad + s.value.col_offset, "")  # type: ignore[attr-defined]  # FIX_54 ast-pos
            out.append(("keep_call_effect", "\n".join(lines), "; ".join(f"`{t}` never read — the call on its right side kept as a bare statement, the name unbound" for _, s, t in hits)))
        return out
    # FIX_60: a right side whose effect leaves this function — the ONE candidate keeps the call. An impure
    # callee is always a call, so this variant always differs from the source. Columns first (no line moves),
    # then the rows of any right side that is not a call at all (nothing to keep) come out bottom-up.
    lines = list(lines0)
    pad = snippet_pad(broken_code)
    for _, s, t in sorted(hits, key=lambda h: h[1].lineno, reverse=True):
        if isinstance(getattr(s, "value", None), ast.Call):
            replace_cols(lines, _rows(s)[0], pad + s.col_offset, pad + s.value.col_offset, "")  # type: ignore[attr-defined]  # FIX_54 ast-pos
    valueless = [(b, s) for b, s, _ in hits if not isinstance(getattr(s, "value", None), ast.Call)]
    for blk in {id(b): b for b, _ in valueless}.values():
        _delete_stmts(lines, [s for b, s in valueless if b is blk], blk)
    out.append(("keep_call_effect", "\n".join(lines),
                "; ".join(f"`{t}` never read — the call on its right side kept as a bare statement, the name unbound"
                          if isinstance(getattr(s, "value", None), ast.Call) else
                          f"`{t}` (snippet line {s.lineno}) never read — its assignment deleted" for _, s, t in hits)
                + f"; `{impure[0]}` is not pure by the module's own evidence, so the call stays and the delete is not offered"))
    return out


def fix_dead_local(broken_code: str) -> _Variants:
    return dead_local_variants(broken_code, _DEAD_ACCEPTABLE)


def _nai010_pure_callee_only(rw: Any, before: Node, after: Node) -> "str | None":
    """FIX_60 at the gate — G0's word for the rule `dead_local_variants` now mints by, so a `drop_assignment`
    reaching the publish point from anywhere (this lane's rewriter, a client edit, an older cheatsheet) meets
    the same test: the delete may go out only when every call it deletes is pure by the module's own evidence.
    Rows #73 #74 are the class — `_GetConsoleScreenBufferInfo` / `_FillConsoleOutputCharacterA`, whose result
    is discarded and whose effect is the whole point.

    A statement counts as DELETED when its right side survives nowhere in the after-span; `keep_call_effect`
    keeps that very call as a bare statement, so it is never caught here. The gate's own contract is
    fail-OPEN (`gate.failures` swallows a raising predicate) while the rewriter above fails CLOSED — each
    layer erring in the direction that cannot lose a right repair, which for the gate is silence and for the
    rewriter is keeping the call."""
    scope = func_node(getattr(rw, "before_src", "") or "") or before
    live = {ast.dump(n) for n in ast.walk(after) if isinstance(n, ast.expr)}
    with module_evidence(getattr(rw, "module_src", "") or ""):     # FIX_65: the gate reads the same evidence
        for st in ast.walk(before):
            if not isinstance(st, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                continue
            value = getattr(st, "value", None)
            if value is None or ast.dump(value) in live:
                continue                      # the right side survives — keep_call_effect, not a delete
            impure = _impure_callees(value, scope)
            if impure:
                return (f"gate: `{impure[0]}` is not pure by the module's own evidence — the result was "
                        f"discarded, the call was not; keep the call and drop the unread name.")
    return None


# THE LANE CONTRACT (S5-1 §"The lane contract" 1): the predicate is declared beside the variant it rules on
# and registered in G0's table. NAI-147's `fix_unused_local` (extended_semantic.py, lane B's file) mints its
# variants through `dead_local_variants` above, so the same rule binds both ids by an exact key — not `"*"`,
# which would bind the variant NAME `drop_assignment` across rules that do not go through this helper.
_GATE_PREDICATES[("NAI-010", "drop_assignment")] = _nai010_pure_callee_only
_GATE_PREDICATES[("NAI-147", "drop_assignment")] = _nai010_pure_callee_only


def fix_exception_swallow(broken_code: str) -> _Variants:
    """NAI-017 finite set. Bare or broad `except: pass` / `except Exception: pass`: `reraise` (the handler re-raises).
    `with suppress(Exception / BaseException)`: `drop_suppress` (the block runs unwrapped). Declines when both
    shapes are present (each variant would leave the other shape)."""
    func = func_node(broken_code)
    if not func:
        return []
    excepts = [h for n in _own_scope(func) if isinstance(n, ast.Try) for h in n.handlers
               if (h.type is None or (isinstance(h.type, ast.Name) and h.type.id in ("Exception", "BaseException")))
               and len(h.body) == 1 and isinstance(h.body[0], ast.Pass)]
    def _broad(w: ast.With) -> bool:
        for it in w.items:
            c = it.context_expr
            if isinstance(c, ast.Call) and ((isinstance(c.func, ast.Name) and c.func.id == "suppress") or (isinstance(c.func, ast.Attribute) and c.func.attr == "suppress")):
                if any(isinstance(a, ast.Name) and a.id in ("Exception", "BaseException") for a in c.args):
                    return True
        return False
    withs = [n for n in _own_scope(func) if isinstance(n, ast.With) and _broad(n) and len(n.items) == 1]
    if bool(excepts) == bool(withs):
        return []
    lines0 = broken_code.splitlines()
    pad = snippet_pad(broken_code)
    out: _Variants = []
    if excepts:
        lines = list(lines0)
        for h in sorted(excepts, key=lambda h: h.lineno, reverse=True):
            p = h.body[0]
            replace_cols(lines, _rows(p)[0], pad + p.col_offset, pad + p.end_col_offset, "raise")  # type: ignore[operator]  # FIX_54 ast-pos
        out.append(("reraise", "\n".join(lines), "; ".join(f"`except: pass` at snippet line {h.lineno} → `except: raise` — the exception propagates" for h in excepts)))
        # owner 2026-10-07 (M-90): `narrow_to_exception` dropped — `except Exception: pass` still swallows, and NAI-017
        # now names that form too, so the variant only moved the infraction
    else:
        lines = list(lines0)
        for w in sorted(withs, key=lambda w: w.lineno, reverse=True):
            a, b = _rows(w)
            body_a, body_b = _rows(w.body[0])[0], _rows(w.body[-1])[1]
            delta = w.body[0].col_offset - w.col_offset
            _dedent_rows(lines, body_a, body_b, delta)
            del lines[a:body_a]
        out.append(("drop_suppress", "\n".join(lines), "; ".join(f"`with suppress(...)` at snippet line {w.lineno} removed — its body runs unwrapped, an exception propagates" for w in withs)))
    return out


# ── FIX_61 (a) (owner Part C ×2 + row #57, 2026-09-17): NAI-017 is no-fix-by-design, for real ──────
#
# The rule's own registry row now carries the flag (`no_fix_by_design=NAI017_NO_FIX` below); before
# FIX_61 the declaration existed only as prose — this module's docstring and the free-text `what` of
# the planted counterfeit in `.archive/runs/<target>/manifest.json` — which nothing read, so the
# rewriter fired on the fixture that said it must not (#57 `hushed`). Every variant the rewriter can
# emit answers through G0's `no_fix_by_design()` hook, so the row publishes withheld-by-design WITH
# the reason and keeps its candidates visible as shapes for the client (the shape lane).
#
# The import sits HERE rather than at the top of the file so that every line lane C touches in core.py
# lies below `fix_exception_swallow` — S5-0 split this file two ways, lane A above and lane C below,
# and a line added at the top would have moved lane A's windows under it.
from .gate import PREDICATES as _GATE_PREDICATES, Rewrite as _GateRewrite, no_fix_by_design as _gate_no_fix

NAI017_NO_FIX = ("what happens on a swallowed exception — propagate it, narrow the catch, log it, "
                 "return a value — is the dev's decision about this call site; every candidate here "
                 "changes what the caller sees, so none of them is an unattended repair")
#: The variants `fix_exception_swallow` (above) can emit. A variant added there is added here.
NAI017_VARIANTS = ("reraise", "drop_suppress")


def _nai017_declared(rw: _GateRewrite, before: ast.AST, after: ast.AST) -> "str | None":
    """The registry's flag, read at rewrite time through G0's hook — the flag IS the switch: clear
    `no_fix_by_design` on the row and the rewriter is live again. Fixture and rule cannot drift."""
    from . import REGISTRY
    g = REGISTRY.get("NAI-017")
    why = getattr(g, "no_fix_by_design", "") if g is not None else ""
    return _gate_no_fix("NAI-017", why) if why else None


for _v in NAI017_VARIANTS:
    _GATE_PREDICATES[("NAI-017", _v)] = _nai017_declared


_PURE_BUILTIN_CALLS = frozenset({'sorted', 'len', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'abs', 'round', 'min', 'max',
                                 'sum', 'repr', 'bool', 'reversed', 'enumerate', 'zip', 'map', 'filter', 'range', 'type', 'isinstance',
                                 'hash', 'format', 'any', 'all', 'ord', 'chr', 'hex', 'oct', 'bin', 'divmod', 'pow', 'frozenset'})
_PURE_METHOD_CALLS = frozenset({'strip', 'lstrip', 'rstrip', 'upper', 'lower', 'title', 'capitalize', 'replace', 'split', 'rsplit',
                                'join', 'format', 'encode', 'decode', 'startswith', 'endswith', 'find', 'rfind', 'index', 'count',
                                'isdigit', 'isalpha', 'zfill', 'center', 'ljust', 'rjust', 'partition', 'rpartition', 'splitlines',
                                'swapcase', 'casefold', 'expandtabs', 'keys', 'values', 'items', 'copy', 'get'})


def fix_discarded_pure_call(broken_code: str) -> _Variants:
    """NAI-022 finite set for a bare call to a known-pure callee in the body: `drop_call` (the line is noise),
    `assign_back` (the result was meant to be kept: `x = x.strip()` / `x = sorted(x)` — only when every hit is a
    method on a name or a builtin over a single name)."""
    func = func_node(broken_code)
    if not func:
        return []
    hits: list[tuple[ast.Expr, str]] = []
    for st in func.body:
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
            c = st.value
            if isinstance(c.func, ast.Name) and c.func.id in _PURE_BUILTIN_CALLS:
                hits.append((st, c.args[0].id if len(c.args) == 1 and isinstance(c.args[0], ast.Name) and not c.keywords else ""))
            elif isinstance(c.func, ast.Attribute) and c.func.attr in _PURE_METHOD_CALLS:
                hits.append((st, c.func.value.id if isinstance(c.func.value, ast.Name) else ""))
    if not hits:
        return []
    lines0 = broken_code.splitlines()
    out: _Variants = []
    lines = list(lines0)
    _delete_stmts(lines, [s for s, _ in hits], func.body)
    out.append(("drop_call", "\n".join(lines), "; ".join(f"bare `{ast.unparse(s.value)}` (snippet line {s.lineno}) deleted — its result was never used" for s, _ in hits)))
    if all(n for _, n in hits):
        lines = list(lines0)
        pad = snippet_pad(broken_code)
        for s, n in sorted(hits, key=lambda h: h[0].lineno, reverse=True):
            replace_cols(lines, _rows(s)[0], pad + s.col_offset, pad + s.col_offset, f"{n} = ")
        out.append(("assign_back", "\n".join(lines), "; ".join(f"`{ast.unparse(s.value)}` (snippet line {s.lineno}) → `{n} = {ast.unparse(s.value)}` — the result kept in the name it came from" for s, n in hits)))
    return out


def fix_pre_increment(broken_code: str) -> _Variants:
    """NAI-170 finite set for a statement `++x` / `--x`: `augmented` (`x += 1` / `x -= 1` — the C habit's
    intent), `drop` (a no-op deleted). Declines when the double unary sits inside a larger expression."""
    func = func_node(broken_code)
    if not func:
        return []
    hits: list[tuple[list[Node], ast.Expr, str, str]] = []
    def _double(v):
        if isinstance(v, ast.UnaryOp) and isinstance(v.operand, ast.UnaryOp) and type(v.op) is type(v.operand.op) and isinstance(v.op, (ast.UAdd, ast.USub)) and isinstance(v.operand.operand, ast.Name):
            return v.operand.operand.id, ("+=" if isinstance(v.op, ast.UAdd) else "-=")
        return None
    seen = set()
    for blk in _blocks(func):
        for st in blk:
            if isinstance(st, ast.Expr) and (d := _double(st.value)):
                hits.append((blk, st, d[0], d[1]))
                seen.add(id(st.value))
    for n in _own_scope(func):
        if isinstance(n, ast.UnaryOp) and _double(n) and id(n) not in seen:
            return []
    if not hits:
        return []
    lines0 = broken_code.splitlines()
    pad = snippet_pad(broken_code)
    out: _Variants = []
    lines = list(lines0)
    for _, st, name, op in sorted(hits, key=lambda h: h[1].lineno, reverse=True):
        replace_cols(lines, _rows(st)[0], pad + st.col_offset, pad + st.end_col_offset, f"{name} {op} 1")  # type: ignore[operator]  # FIX_54 ast-pos
    out.append(("augmented", "\n".join(lines), "; ".join(f"`{ast.unparse(st.value)}` (snippet line {st.lineno}) → `{name} {op} 1`" for _, st, name, op in hits)))
    lines = list(lines0)
    for blk in {id(b): b for b, _, _, _ in hits}.values():
        _delete_stmts(lines, [s for b, s, _, _ in hits if b is blk], blk)
    out.append(("drop", "\n".join(lines), "; ".join(f"`{ast.unparse(st.value)}` (snippet line {st.lineno}) deleted — a no-op in Python" for _, st, _, _ in hits)))
    return out


def _dict_variants(broken_code: str, same) -> _Variants:
    """The shared NAI-175 / NAI-177 body. FIX_63 (2026-09-17, I-115; the same ruling FIX_56 applied to
    NAI-006): `keep_first` is RETIRED. A dict literal is a sequence of stores into one object, and Python
    keeps the LAST value for a repeated key — `{"a": 1, "b": 2, "a": 3}` IS `{"a": 3, "b": 2}`. The shadowed
    first entry is the dead store; deleting the live last one promotes a value the program never held, and
    G0's `live_store_removed` cannot see it (it reads store statements, not keys in a literal — T6 let it
    through only because the shadowed key was never read). So only the last-live repair is minted here, and
    the gate says the same thing from its side (`gate.PREDICATES[("NAI-175" / "NAI-177", "keep_first")]`,
    `_dict_literal_value_changed`, the gate's word on a keep_first minted anywhere else). "The first value
    was the one meant" is an INTENT change and goes through the client (the shape lane)."""
    func = func_node(broken_code)
    if not func:
        return []
    pad = snippet_pad(broken_code)
    plans: list[tuple[ast.Dict, list[int]]] = []   # (dict, the shadowed earlier entries to drop)
    for n in _own_scope(func):
        if not isinstance(n, ast.Dict):
            continue
        drop: list[int] = []
        for i, k in enumerate(n.keys):
            if k is None:
                continue
            for j in range(i):
                kj = n.keys[j]
                if kj is not None and same(kj, k) and j not in drop:
                    drop.append(j)
        if drop:
            plans.append((n, drop))
    if not plans:
        return []
    lines = broken_code.splitlines()
    for n, drop in sorted(plans, key=lambda p: p[0].lineno, reverse=True):
        _remove_dict_entries(lines, n, drop, pad)
    keys = "; ".join(", ".join(ast.unparse(n.keys[i]) for i in drop) for n, drop in plans)  # type: ignore[arg-type]  # FIX_54 ast-pos
    return [("keep_last", "\n".join(lines), f"shadowed duplicate key entry(ies) {keys} removed — the last value for each key kept, which is the value the literal already had")]


def fix_duplicate_keys(broken_code: str) -> _Variants:
    """NAI-175 finite set for a literal key repeated in one dict literal: `keep_last` only (FIX_63 —
    `keep_first` retired, see `_dict_variants`)."""
    return _dict_variants(broken_code, lambda a, b: ast.dump(a) == ast.dump(b))


def fix_semantic_duplicate_keys(broken_code: str) -> _Variants:
    """NAI-177 finite set for keys of different types Python treats as equal (1 / True / 1.0, 0 / False):
    `keep_last` only (FIX_63 — `keep_first` retired, see `_dict_variants`)."""
    def same(a, b):
        return isinstance(a, ast.Constant) and isinstance(b, ast.Constant) and a.value == b.value and type(a.value) is not type(b.value)
    return _dict_variants(broken_code, same)


# P5 (orchestrator ruling 2026-09-29, I-81 / C1): NAI-025's shape carries the operator of the statement
# that FIRED — `x = x * 1` is handed `<x> = <x> * <real operand>`, never a `+`. The operator is read off
# the finding's own evidence: the validator's rendering of the NAI-025 observation (`op=Mult`), else the
# one no-op statement in the flagged function. A fire that carries no single operator gets the fixed `+`
# fallback, and its comment says the `+` is a stand-in.
_NAI025_OPS = {"Add": ("+", 0), "Sub": ("-", 0), "Mult": ("*", 1), "Div": ("/", 1)}
_NAI025_TEXT = ('Write the arithmetic that was meant (the real operand in place of 0 / 1) or delete the '
                'statement; the value changes or the line goes.')
_NAI025_FALLBACK_SHAPE = ('<x> = <x> + <real operand>   # `+` stands in for the flagged statement\'s own '
                          'operator (not read off this fire): the operand the arithmetic meant in place of '
                          'the 0 / 1 — or delete the line')


def _nai025_op(broken_code: str, failure_reason: str) -> str:
    """The ast op name (Add / Sub / Mult / Div) of the no-op NAI-025 flagged, or "" when not one."""
    m = re.match(r"NAI-025 \(line [^)]*\):.*\bop=(Add|Sub|Mult|Div)\b", failure_reason or "")
    import textwrap
    try:
        tree = ast.parse(textwrap.dedent(broken_code or ""))
    except (SyntaxError, ValueError):
        tree = ast.Module(body=[], type_ignores=[])
    seen = set()
    for node in ast.walk(tree):      # the detector's own shape (core_checks._check_noop_operations)
        match node:
            case ast.Assign(targets=[ast.Name(id=tid)], value=ast.BinOp(left=ast.Name(id=lid), op=op,
                                                                         right=ast.Constant(value=v))):
                name = type(op).__name__
                if lid == tid and name in _NAI025_OPS and v == _NAI025_OPS[name][1]:
                    seen.add(name)
    match (m.group(1) if m else None, sorted(seen)):
        case (str() as from_reason, _):
            return from_reason
        case (None, [one]):
            return one
    return ""


def nai025_prescription(broken_code: str = "", failure_reason: str = "") -> tuple:
    """NAI-025's (text, shape) with the fired statement's operator; the `+` fallback when unreadable."""
    sym, identity = _NAI025_OPS.get(_nai025_op(broken_code, failure_reason), ("", ""))
    return _NAI025_TEXT, (f'<x> = <x> {sym} <real operand>   # the operand the arithmetic meant in place of '
                          f'the {identity}, same `{sym}` as the flagged statement — or delete the line'
                          if sym else _NAI025_FALLBACK_SHAPE)


_SRC = "no_aivalidator/detection/core_checks.py"

GENERATORS = [
    rewriter("NAI-008", f"{_SRC}:_check_reimport_inside_function", "import_hoist_fix", fix_import_in_function,
             reason="direct-body stdlib absolute imports hoisted to module scope above a module-level def; "
                    "declines for methods / nested defs, relative or third-party imports, names bound elsewhere "
                    "in the function — fixture proves the call result is unchanged (import-order equivalence)"),
    prescribed('NAI-004', f"{_SRC}:_check_pass_only_function", "Write the body: compute from the parameters what the intent's expected output for this function names and return it; a declared abstract member raises NotImplementedError naming the missing piece.",
               'def <name>(<params>):\n    <compute from the parameters per the intent>\n    return <result>'),
    prescribed('NAI-015', f"{_SRC}:_check_fake_iteration", "Make the loop accumulate: build the value the function's name and the intent promise (append, sum, count, a dict) from each item and return or use it after the loop.",
               'result = <[] | 0 | {}>\nfor item in <iterable>:\n    <result.append(<f(item)>) | result += <g(item)>>\nreturn result'),
    # unbuilt — 24 ids of this family with no generator yet (item 4 first batch, 2026-09-08)
    rewriter("NAI-002", f"{_SRC}:_check_unreachable_after_return", "unreachable_code_fix", fix_unreachable_after_return,
             "FINITE SET (2 candidates): `drop_dead` — the terminal is right, the statements after the first return / raise of a block are deleted (a def / class right after it is left, the detector's own allowance); `terminal_last` — the code after it was meant to run, the terminal moves below it. Which reading is right is the intent's; both are offered, the Ranker decides (the row usually also carries NAI-140, whose candidates read the same) (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-003', f"{_SRC}:_check_unused_parameters", "Use the parameter as the signature promises — feed it into the computation the intent's expected input describes; if it is genuinely obsolete, remove it and its arguments at every call site in one change.",
               'def <name>(<param>, ...):\n    <result> = <computation that reads <param>>'),
    rewriter("NAI-005", f"{_SRC}:_check_redundant_else_after_return", "redundant_else_fix", fix_redundant_else,
             "the `else:` after an if whose body ends in return / raise is dropped and its two statements (`name = <expr>; return name` — the only shape the detector fires on) dedented to the if's level; the else ran exactly when the if body did not terminate, and it never terminates otherwise, so the statements run under the same condition as before — nothing on any path changes; declines an `elif`, an else statement spanning lines, or an `else:` line not found alone at the if's column (set 4b-19, 2026-09-10)",
             "2026-09-10", "set 4b-19 (2026-09-10)"),
    rewriter("NAI-006", f"{_SRC}:_check_variable_immediate_overwrite", "immediate_overwrite_fix", fix_immediate_overwrite,
             "FINITE SET (1–2 candidates) for `x = a` immediately followed by `x = b` in the body: `keep_second` (the dead first assignment deleted), `keep_second_effect` (the first right side kept as a bare call when it is one — its effect stays, its value is not bound). LAST-LIVE ONLY: `keep_first` was retired by FIX_56 (owner's ruling 2026-09-17) — the dead store is the first write, so deleting the live second one changes what the program does and inverts the rule's own name; \"the first value was meant\" is an intent change and goes through the client (the shape lane). The Ranker decides between what is left (FIX_43 (b) run 123 (owner rulings 2026-09-15/16); FIX_56 2026-09-17)",
             "2026-09-17", "FIX_56 (owner's ruling 2026-09-17, rows #30 #33)"),
    rewriter("NAI-007", f"{_SRC}:_check_nested_function_never_called", "unused_nested_def_fix", fix_unused_nested_def,
             "FINITE SET (2–3 candidates) for a nested def never called, returned or read: `delete_nested`, `call_nested` (a bare call right after the def, when it needs no argument), `return_nested` (appended `return <name>` when the body does not already end in a return / raise). The Ranker decides (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-009', f"{_SRC}:_check_input_output_disconnect", 'Compute the return value from the parameters: derive the expected output from the given inputs per the intent, in place of the literal / empty collection.',
               'def <name>(<params>):\n    return <expression over <params>>'),
    rewriter("NAI-010", f"{_SRC}:_check_dead_computation", "dead_local_fix", fix_dead_local,
             "FINITE SET (1–2 candidates) for a local assigned and never read (single-name Assign / AugAssign / AnnAssign of the own scope; the detector's acceptable-name table and `_`-names excluded): `drop_assignment` (the statement deleted; an emptied block gets `pass`) — offered ONLY when every call it deletes is pure by the module's own evidence (FIX_60, owner's ruling 2026-09-17, rows #73 #74: a discarded RESULT is not a discardable CALL; the evidence is the NAI-022 detector's own known-pure tables) — and `keep_call_effect` (the call stays as a bare statement, the unread name goes), which is the FIRST and only candidate when any callee is not provably pure. 'Meant to be used' has no finite form without the intent. The Ranker decides; the row usually also carries NAI-147 with the same candidates (FIX_43 (b) run 123 (owner rulings 2026-09-15/16); FIX_60 2026-09-17)",
             "2026-09-17", "FIX_60 (owner's ruling 2026-09-17, rows #73 #74)"),
    prescribed('NAI-011', f"{_SRC}:_check_side_effect_free", 'Give the function its effect: return the value or perform the action the name and the intent promise (a write, a call, a state change) and make the caller use it.',
               'def <name>(...):\n    <action | return <value>>'),
    prescribed('NAI-014', f"{_SRC}:_check_meaningless_operations", 'Delete the statement, or, when a value was meant to be kept, assign the expression to the name that uses it: a self-assignment goes, a discarded compare / operation becomes the assignment or the condition it was written for.',
               '<delete `x = x`>\n# or\nresult = <expr>   # the value was meant\n# or\nif <compare>:\n    ...'),
    prescribed('NAI-016', f"{_SRC}:_check_return_input_unchanged", "Transform the input: apply what the function's name and the intent's expected output require before returning, or delete the function and have callers use the value directly.",
               'def <name>(<param>):\n    return <transform(<param>)>'),
    rewriter("NAI-017", f"{_SRC}:_check_exception_swallow", "exception_swallow_fix", fix_exception_swallow,
             "FINITE SET for a bare `except: pass`: `reraise` (`except: raise`), for `with suppress(Exception / BaseException)`: `drop_suppress` (the body runs unwrapped). Declines when both shapes share one function. NO-FIX-BY-DESIGN since FIX_61 (owner Part C, 2026-09-17): the candidates are shapes for the client, G0 withholds every one of them",
             "2026-09-17", "FIX_61 (a) (owner Part C ×2 + row #57, 2026-09-17)",
             no_fix_by_design=NAI017_NO_FIX),
    prescribed('NAI-018', f"{_SRC}:_check_async_no_await", 'Await the I/O the function performs (or the coroutine it calls); when there is nothing to await, drop async and let the callers call it synchronously.',
               'async def <name>(...):\n    result = await <awaitable>\n    return result'),
    prescribed('NAI-019', f"{_SRC}:_check_constant_returns", 'Return a different value on each branch — the outcome the condition distinguishes (the value, an error, a status) per the intent; when the branches truly agree, remove the branching.',
               'if <cond>:\n    return <value for this case>\nreturn <value for the other case>'),
    prescribed('NAI-020', f"{_SRC}:_check_test_fakes", "Assert the behaviour the test's name promises: call the unit and compare its result (or its raised exception) to the expected literal from the spec / intent.",
               'def test_<what>():\n    result = <unit>(<input>)\n    assert result == <expected>'),
    prescribed('NAI-021', f"{_SRC}:_check_logging_only", "Do the work the function is named for and return or act on it; the log line stays as a side note, never as the function's only effect.",
               "def <name>(...):\n    result = <work>\n    logger.info('<what>', ...)\n    return result"),
    rewriter("NAI-022", f"{_SRC}:_check_discarded_calls", "discarded_call_fix", fix_discarded_pure_call,
             "FINITE SET (1–2 candidates) for a bare call to a known-pure callee whose result is dropped: `drop_call` (the line is noise), `assign_back` (`x = x.strip()` / `x = sorted(x)` — the result was meant to be kept; only when every hit is a method on a name or a builtin over one name). The Ranker decides (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-023', f"{_SRC}:_check_self_comparisons", 'Compare the name with the operand that was meant (the parameter, the previous value, the expected constant); when the comparison was a NaN check, write math.isnan(x).',
               'if <x> == <other>:   # or: if math.isnan(<x>):'),
    prescribed('NAI-024', f"{_SRC}:_check_loop_patterns", 'Let the loop visit every item: accumulate or test each one and return after the loop, or return inside only under the condition that selects the item the name promises.',
               'for item in <iterable>:\n    if <condition(item)>:\n        return item\nreturn <fallback>'),
    prescribed('NAI-025', f"{_SRC}:_check_noop_operations", _NAI025_TEXT, _NAI025_FALLBACK_SHAPE,
               shape_for=nai025_prescription),
    rewriter("NAI-170", f"{_SRC}:_check_pre_increment_decrement", "pre_increment_fix", fix_pre_increment,
             "FINITE SET (2 candidates) for a statement `++x` / `--x`: `augmented` (`x += 1` / `x -= 1`, the C habit's intent), `drop` (a no-op deleted). Declines when the double unary sits inside a larger expression. The Ranker decides (FIX_43 (b) run 123 (owner rulings 2026-09-15/16))",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    prescribed('NAI-174', f"{_SRC}:_check_shadowing_builtins", 'Rename the local to a domain name (items, mapping, ident, length) so the builtin the function calls stays reachable, changing every read of the local in the function.',
               '<domain_name> = <value>   # was: list = ... / id = ... / len = ...'),
    rewriter("NAI-175", f"{_SRC}:_check_duplicate_dict_keys", "duplicate_key_fix", fix_duplicate_keys,
             "FINITE SET (1 candidate) for a literal key repeated in one dict literal: `keep_last` (the shadowed earlier entry and its comma removed from the literal's text — the value the literal already evaluated to). LAST-LIVE ONLY: `keep_first` was retired by FIX_63 (2026-09-17, the FIX_56 ruling on dict literals) — Python keeps the last value for a repeated key, so deleting the last entry changes what the program does; \"the first value was meant\" is an intent change and goes through the client (the shape lane). Whether the second key was meant to be another name has no finite form (FIX_43 (b) run 123 (owner rulings 2026-09-15/16); FIX_63 2026-09-17)",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16); FIX_63 2026-09-17"),
    rewriter("NAI-177", f"{_SRC}:_check_duplicate_dict_keys_semantic", "semantic_duplicate_key_fix", fix_semantic_duplicate_keys,
             "FINITE SET (1 candidate) for keys of different types Python treats as equal in one dict literal (1 / True / 1.0, 0 / False): `keep_last`. LAST-LIVE ONLY: `keep_first` retired by FIX_63 (2026-09-17) for the same reason as NAI-175 — the last entry is the value the literal already held (FIX_43 (b) run 123 (owner rulings 2026-09-15/16); FIX_63 2026-09-17)",
             "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16); FIX_63 2026-09-17"),
    prescribed('NAI-212', f"{_SRC}:_check_canned_return", 'Return data from its real source: read it from the parameter, the store or the external system the intent names and shape it into the rows; sample rows live only in tests / fixtures.',
               'def <name>(<source>):\n    rows = <read from <source>>\n    return [<shape(r)> for r in rows]'),
]
