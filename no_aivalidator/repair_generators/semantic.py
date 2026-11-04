"""Semantic family (no_aivalidator/detection/semantic_checks.py) — item 4, 2026-09-08.

Every row is `unbuilt` (the honest placeholder) until this family is worked.
Set 4b-27 (2026-09-10, portion E's first): NAI-100 (which parameter reaches the result), NAI-101 (what the calculation
should be), NAI-102 (the docstring or the constant), NAI-103 (the branch or the name), NAI-104 (what operation the
name promised) no-fix-by-design. Facts: all five are called from `run_all_checks` (base.py:355-359) and every one is
name-gated (calculate / compute / sum / add; get_ / find_ / count; is_valid / has_ / can_; the verb table).
Set 4b-28 (2026-09-10): NAI-110 REWRITER `cross_language_fix` — a foreign-language method on a receiver whose kind
the function itself proves (a bare name bound in the function to a list / str / dict literal, constructor or
comprehension, or a parameter with such a default) is renamed to the exact Python equivalent: `.push(` → `.append(`
and `.addAll(` → `.extend(` on a list; `.toUpperCase()` / `.toLowerCase()` → `.upper()` / `.lower()` on a str;
`.putAll(` → `.update(`, `.keySet()` → `.keys()`, `.entrySet()` → `.items()` on a dict; `.length` and `.size()` →
`len(<name>)` on any of the three. Receiver evidence only: a hit on a receiver the function does not bind, an
attribute chain, or a call result declines the whole snippet (the Builder publishes `declined`); the methods whose
Python reading is NOT a rename (`indexOf` returns -1 where `.index()` raises; `charAt` / `substring` / `equals` /
`compareTo` / `contains` / `forEach` / `each` / `select` / `reject` / `include?` / `nil?` / `isEmpty` / `parseInt` /
`parseFloat` / `toString` / `toArray` / `to_s` / `to_i` / `to_f` / `map!`) are never rewritten. NAI-105 (what the
transformation should be), NAI-108 (the name or the returned value), NAI-109 (the name or the action), NAI-115
(where the data should come from) no-fix-by-design. Facts: all five are called from `run_all_checks`
(base.py:360-368); NAI-105 is name-gated (transform / process / convert / modify / update) and observes on the
`append` statement; NAI-108 reads only a Constant return against the name's suffix table; NAI-109 counts an
opposite-named call only at the body's top level on a bare local that a later return hands back; NAI-110 returns
after its first hit per function and skips names the module defines, stdlib method names and calls on imported
modules (IG-10); NAI-115 is prefix-gated (get_ / fetch_ / load_ / query_ / find_ / search_ / list_ / read_ /
retrieve_) and observes on the return of an all-literal list or dict.
Set 4b-29 (2026-09-10, portion E's last): NAI-116 REWRITER `join_fix` — THE JOIN ROLE, defined once here (`style`'s
NAI-088 / NAI-179 alias it in portion I): the detector's `acc += "<literal>"` / `acc += str(<expr>)` as the ONLY
statement of a `for` loop, with `acc = "<str literal>"` the statement directly above the loop, becomes
`acc = "".join(<value> for <target> in <iter>)` (`acc = "<init>" + "".join(…)` when the literal is not empty) —
one line for three, the string built once. Declines: a `while` loop (the detector's other shape has no iterable to
join over), a loop with `else`, a body of more than the one statement, no `acc = "<str>"` directly above, `acc`
read in the loop header or the value, a multi-line header / statement, or a loop-target name read anywhere outside
its loop (a `for` leaves its target bound after the loop; a generator expression does not — the one observable
difference, so the rewrite refuses it). Behaviour that changes: none — the same characters in the same order; only
the number of intermediate strings. NAI-118 (whether a validator should raise, report, or answer with a bool)
no-fix-by-design. Facts: both are called from `run_all_checks` (base.py:365, 367); NAI-116 observes on the `+=`
statement and returns after the first; NAI-118 observes on the def line, is prefix-gated (validate / verify /
check_), and needs two or more bool-constant returns with no raise and no error / warning / critical / exception
call.
Set 4b-43 (2026-09-10, portion I's last, the aliases' set): the join role WIDENED for `style`'s NAI-088 / NAI-179 —
the value may also be an f-string, and the statement may be the plain-assignment spelling `acc = acc + <value>`
(NAI-179's detector shape); the preconditions are unchanged, the NAI-116 plant is unchanged, and each alias carries
its own plant in `style.py`'s set.
"""
from __future__ import annotations

import ast
from typing import Any
import textwrap

from . import no_fix, prescribed, rewriter, unbuilt
from ._ast_edit import func_node, replace_cols, snippet_pad

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SRC = "no_aivalidator/detection/semantic_checks.py"

# ── NAI-110 (set 4b-28, 2026-09-10) ──────────────────────────────────────────

# foreign method → (receiver kind the rename is exact for, Python method name)
_RENAMES: dict[str, tuple[str, str]] = {
    "push": ("list", "append"),
    "addAll": ("list", "extend"),
    "toUpperCase": ("str", "upper"),
    "toLowerCase": ("str", "lower"),
    "putAll": ("dict", "update"),
    "keySet": ("dict", "keys"),
    "entrySet": ("dict", "items"),
}
_LEN_KINDS = ("list", "str", "dict")


def _value_kind(node: Node) -> str:
    """The kind a bound value proves: 'list' / 'str' / 'dict', or '' when the value proves nothing."""
    if isinstance(node, (ast.List, ast.ListComp)):
        return "list"
    if isinstance(node, (ast.Dict, ast.DictComp)):
        return "dict"
    if isinstance(node, ast.JoinedStr) or (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return "str"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _LEN_KINDS:
        return node.func.id
    return ""


def _receiver_evidence(func: Node) -> dict[str, str]:
    """Bare names the function itself binds to one kind: plain assignments (every one to the same name must agree)
    and parameter defaults. A name bound to two kinds is no evidence."""
    kinds: dict[str, set[str]] = {}
    args = func.args
    positional = args.posonlyargs + args.args
    for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
        kinds.setdefault(arg.arg, set()).add(_value_kind(default))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None:
            kinds.setdefault(arg.arg, set()).add(_value_kind(default))
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    kinds.setdefault(target.id, set()).add(_value_kind(node.value))
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)) and isinstance(node.target, ast.Name):
            kinds.setdefault(node.target.id, set()).add(_value_kind(node.value) if node.value is not None else "")
    return {name: next(iter(ks)) for name, ks in kinds.items() if len(ks) == 1 and "" not in ks}


def fix_cross_language(broken_code: str) -> tuple[str, str]:
    """NAI-110: the detector's foreign method (`.push(` / `.length` / `.toUpperCase()` …) on a receiver that is a bare
    name the function proves to be a list / str / dict (see `_receiver_evidence`) → the exact Python spelling from
    `_RENAMES`, or `len(<name>)` for `.length` / `.size()`. Every hit in the function is rewritten; ONE hit without
    receiver evidence declines the whole snippet — receiver evidence only. Columns are edited in place, nothing else
    on the line moves. Behaviour that changes, by the rule's meaning: the foreign spelling raises AttributeError on a
    Python list / str / dict at the first call; the rename is the one reading under which the function runs."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    evidence = _receiver_evidence(func)
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    # (row, start col, end col, replacement text, old text, new text)
    edits: list[tuple[int, int, int, str, str, str]] = []
    seen: set[tuple[int, int]] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func
            if attr.attr == "size" and not node.args and not node.keywords:
                if not (isinstance(attr.value, ast.Name) and evidence.get(attr.value.id) in _LEN_KINDS):
                    return "", ""
                if node.lineno != node.end_lineno:
                    return "", ""
                row = node.lineno - 1
                a, b = pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
                old = lines[row][a:b]
                edits.append((row, a, b, f"len({attr.value.id})", old, f"len({attr.value.id})"))
                seen.add((attr.lineno, attr.col_offset))
                continue
            if attr.attr in _RENAMES:
                kind, new_name = _RENAMES[attr.attr]
                if not (isinstance(attr.value, ast.Name) and evidence.get(attr.value.id) == kind):
                    return "", ""
                if attr.value.end_lineno != attr.end_lineno:
                    return "", ""
                row = attr.end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
                a, b = pad + attr.value.end_col_offset, pad + attr.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
                dot = lines[row].find(".", a, b)
                if dot < a or lines[row][dot + 1:b].strip() != attr.attr:
                    return "", ""  # no dot between receiver and method, or something other than the method after it
                s = b - len(attr.attr)
                old = lines[row][pad + attr.col_offset:b]
                edits.append((row, s, b, new_name, old, lines[row][pad + attr.col_offset:s] + new_name))
                seen.add((attr.lineno, attr.col_offset))
    for node in ast.walk(func):
        if isinstance(node, ast.Attribute) and node.attr == "length" and not isinstance(node.ctx, ast.Store) \
                and (node.lineno, node.col_offset) not in seen:
            if not (isinstance(node.value, ast.Name) and evidence.get(node.value.id) in _LEN_KINDS):
                return "", ""
            if node.lineno != node.end_lineno:
                return "", ""
            row = node.lineno - 1
            a, b = pad + node.col_offset, pad + node.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
            old = lines[row][a:b]
            edits.append((row, a, b, f"len({node.value.id})", old, f"len({node.value.id})"))
    if not edits:
        return "", ""
    for row, s, e, text, _old, _new in sorted(edits, key=lambda t: (t[0], t[1]), reverse=True):
        replace_cols(lines, row, s, e, text)
    what = "; ".join(f"`{old}` (snippet line {row + 1}) → `{new}`"
                     for row, _s, _e, _t, old, new in sorted(edits, key=lambda t: (t[0], t[1])))
    return "\n".join(lines), what + " — the receiver is bound in the function to the kind the rename is exact for"


# ── NAI-116 (set 4b-29, 2026-09-10) — the join role ──────────────────────────

def _names(node: Node) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def fix_string_concat_loop(broken_code: str) -> tuple[str, str]:
    """NAI-116 (and its aliases NAI-088 / NAI-179, set 4b-43): `acc = "<str>"` directly above a `for` whose only
    statement is the detector's `acc += "<literal>"` / `acc += str(<expr>)` / `acc += f"…"` — or, the NAI-179 spelling,
    `acc = acc + <the same values>` — → `acc = "".join(<value> for <target> in <iter>)` (`"<init>" + "".join(…)` for a
    non-empty literal); three lines become one at the assignment's indent. Preconditions (decline the whole snippet
    otherwise): a `for` (not `while`, not `async for`) with no `else` and exactly one body statement; the init
    assignment directly above it in the same block; the assignment, the loop header and the statement each on one
    line; `acc` not read in the loop header or the value; no loop-target name read outside its loop anywhere in the
    function. Behaviour that changes: none — the same characters in the same order, built once instead of per
    iteration."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    dedented = textwrap.dedent(broken_code)
    lines = broken_code.splitlines()
    hits: list[tuple[ast.Assign, ast.For, ast.stmt, str, ast.expr]] = []
    for parent in ast.walk(func):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(parent, field, None)
            if not isinstance(block, list):
                continue
            for i, stmt in enumerate(block):
                if not isinstance(stmt, ast.For) or stmt.orelse or len(stmt.body) != 1:
                    continue
                aug = stmt.body[0]
                if isinstance(aug, ast.AugAssign) and isinstance(aug.op, ast.Add) and isinstance(aug.target, ast.Name):
                    acc, val = aug.target.id, aug.value                      # `acc += <v>` — NAI-116 / NAI-088
                elif (isinstance(aug, ast.Assign) and len(aug.targets) == 1 and isinstance(aug.targets[0], ast.Name)
                      and isinstance(aug.value, ast.BinOp) and isinstance(aug.value.op, ast.Add)
                      and isinstance(aug.value.left, ast.Name) and aug.value.left.id == aug.targets[0].id):
                    acc, val = aug.targets[0].id, aug.value.right            # `acc = acc + <v>` — NAI-179 (set 4b-43)
                else:
                    continue
                literal = isinstance(val, ast.Constant) and isinstance(val.value, str)
                str_call = isinstance(val, ast.Call) and isinstance(val.func, ast.Name) and val.func.id == "str"
                if not (literal or str_call or isinstance(val, ast.JoinedStr)):
                    continue
                prev = block[i - 1] if i else None
                if not (isinstance(prev, ast.Assign) and len(prev.targets) == 1 and isinstance(prev.targets[0], ast.Name)
                        and prev.targets[0].id == acc and isinstance(prev.value, ast.Constant) and isinstance(prev.value.value, str)):
                    return "", ""  # the accumulator is not initialised to a string literal directly above: decline
                if prev.lineno != prev.end_lineno or stmt.lineno != aug.lineno - 1 or aug.lineno != aug.end_lineno:
                    return "", ""  # multi-line shapes are not edited
                if acc in _names(stmt.iter) or acc in _names(stmt.target) or acc in _names(val):
                    return "", ""  # the accumulator is read while it is being built: not the join
                hits.append((prev, stmt, aug, acc, val))
    if not hits:
        return "", ""
    for _prev, stmt, _aug, _acc, _val in hits:
        inside = {id(n) for n in ast.walk(stmt)}
        targets = _names(stmt.target)
        for n in ast.walk(func):
            if isinstance(n, ast.Name) and n.id in targets and id(n) not in inside:
                return "", ""  # a loop-target name is read after (or before) the loop: the for's binding is relied on
    edits: list[tuple[int, int, str, str]] = []
    for prev, stmt, _aug, acc, val in hits:
        row0, row1 = prev.lineno - 1, stmt.end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
        indent = lines[row0][:len(lines[row0]) - len(lines[row0].lstrip())]
        target_src = ast.get_source_segment(dedented, stmt.target) or ""
        iter_src = ast.get_source_segment(dedented, stmt.iter) or ""
        val_src = ast.get_source_segment(dedented, val) or ""
        init_src = ast.get_source_segment(dedented, prev.value) or ""
        joined = f'"".join({val_src} for {target_src} in {iter_src})'
        new_line = f"{indent}{acc} = {joined}" if not prev.value.value else f"{indent}{acc} = {init_src} + {joined}"  # type: ignore[attr-defined]  # FIX_54 ast-pos
        edits.append((row0, row1, new_line, f"`{lines[row0].strip()}` + `for {target_src} in {iter_src}: {lines[row1].strip()}`"))
    for row0, row1, new_line, _old in sorted(edits, key=lambda t: t[0], reverse=True):
        lines[row0:row1 + 1] = [new_line]
    what = "; ".join(f"{old} (snippet lines {row0 + 1}-{row1 + 1}) → `{new_line.strip()}`" for row0, row1, new_line, old in sorted(edits, key=lambda t: t[0]))
    return "\n".join(lines), what + " — the string is built once by join, the same characters in the same order"


GENERATORS = [
        prescribed("NAI-100", f"{_SRC}:_check_param_return_disconnect",
               "Make the disconnected parameter reach the result: a calculate / compute / sum function returns a value computed from every parameter the signature declares.",
               "def calculate_x(a, b):\n    return <expression over a and b>"),
        prescribed("NAI-101", f"{_SRC}:_check_magic_number_return",
               "Replace the magic-number return with the calculation the name promises, computed from the parameters; a constant that is genuinely part of the formula becomes a named module constant. <rate> is that constant's value, and it comes from the intent or from a constant the module already defines — never from the magic number the body returned, which is the counterfeit this rule is about (Q3, 2026-09-17).",
               "RATE = <rate>\n\ndef calculate_x(a):\n    return a * RATE"),
        prescribed("NAI-102", f"{_SRC}:_check_docstring_code_mismatch",
               "Make the body do what the docstring says — the operation it names (add, not subtract), the full range it names (both ends), every case it names (a range test, not one `==` value) — or, if the body is right, correct the docstring.",
               "def <fn>(<args>):\n    \"\"\"<what it does>\"\"\"\n    return <the operation / range / cases the docstring names>"),
        prescribed("NAI-103", f"{_SRC}:_check_boolean_logic_inversion",
               "Make the predicate answer its name: return True on the condition the name states (`is_positive` -> `x > 0`) and False otherwise.",
               "def is_positive(x):\n    return x > 0"),
        prescribed("NAI-104", f"{_SRC}:_check_name_operation_mismatch",
               "Perform the operation the verb in the name promises (add adds, remove removes, sort sorts) on the parameters, and return its result.",
               "def <verb>_x(target, value):\n    <the verb's operation on target with value>\n    return target"),
        prescribed("NAI-105", f"{_SRC}:_check_no_transform_passthrough",
               "Apply the transformation the name promises to each item before appending it; a function named transform / process / convert must change its items.",
               "def transform_items(items):\n    return [<transform>(x) for x in items]"),
        prescribed("NAI-108", f"{_SRC}:_check_return_type_name_mismatch",
               "Return the type the name suffix promises (`_count` -> int, `_name` -> str, `_list` -> list, `_dict` -> dict), computed from the inputs; or rename the function to what it returns.",
               "def get_item_count(items):\n    return len(items)"),
        prescribed("NAI-109", f"{_SRC}:_check_opposite_operation",
               "Make the action match the verb: `add_x` calls the adding method (`.add` / `.append`), `remove_x` the removing one; the name and the call must agree.",
               "def add_item(self, item):\n    self.items.append(item)\n    return self.items"),
    rewriter("NAI-110", f"{_SRC}:_check_cross_language_confusion", "cross_language_fix", fix_cross_language,
             "the foreign method is renamed to its exact Python equivalent ONLY when the receiver is a bare name the function itself binds to the kind the rename is exact for (list: push→append, addAll→extend; str: toUpperCase→upper, toLowerCase→lower; dict: putAll→update, keySet→keys, entrySet→items; any: .length / .size() → len(name)); every other hit declines the snippet; methods whose Python reading is not a rename are never touched (set 4b-28, 2026-09-10)",
             dated="2026-09-10", by="set 4b-28 (2026-09-10)"),
        prescribed("NAI-115", f"{_SRC}:_check_hardcoded_collection_return",
               "Fetch the data from the source the intent names (the external system, file or store) instead of returning a literal list / dict; a genuine fixture moves to a constant named as one.",
               "def get_items(store):\n    return store.query(<what the name promises>)"),
    rewriter("NAI-116", f"{_SRC}:_check_string_concat_in_loop", "join_fix", fix_string_concat_loop,
             "the join role: `acc = \"<str>\"` directly above a `for` whose only statement is `acc += \"<literal>\"` / `acc += str(<expr>)` becomes `acc = \"\".join(<value> for <target> in <iter>)` — the same characters in the same order, built once; declines a while loop, a loop with else, any other body statement, a missing or non-literal init, an accumulator read while built, multi-line shapes, and a loop-target name read outside its loop (the for's binding would be lost) (set 4b-29, 2026-09-10)",
             dated="2026-09-10", by="set 4b-29 (2026-09-10)"),
        prescribed("NAI-118", f"{_SRC}:_check_validation_missing_error",
               "Have the validator report the failure, not only answer False: raise the domain's exception (or return the failing reason) on each invalid case so callers cannot ignore it.",
               "def validate_x(value):\n    if <invalid condition>:\n        raise ValueError(f\"<why>: {value!r}\")\n    return True"),
]
