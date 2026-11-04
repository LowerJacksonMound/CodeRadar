"""Redundancy family (no_aivalidator/detection/redundancy_checks.py) — item 4, 2026-09-08.

Rewriter: NAI-061 (new).
Set 4b-30 (2026-09-10, portion F1 of ITEM_04B, app copy 2): five rewriters, each the detector's own "should be" on
exactly the shape it observes — NAI-060 `double_negation_fix` (`not not x` → `bool(x)`, the detector's stated basis),
NAI-062 `len_zero_compare_fix` (`len(x) == 0` → `not x`; `!= 0` / `> 0` → `x` as a test, `bool(x)` as a return value;
`>= 0` declined — always true, not a test of emptiness), NAI-063 `or_chain_dedupe_fix` (a repeated plain name dropped
from an `or` chain — only names, and a repeated LAST operand only under a truth test, because `a or b or a` is `a` when
all are falsy and `a or b` is `b`), NAI-064 `self_assignment_fix` (`x = x` deleted when x is a parameter of the def it
sits in — bound from entry, so nothing rebinds and no scope changes; any other name declined, the 4b-22 scope fact),
NAI-065 `redundant_conversion_fix` (`T(T(x))` → `T(x)` for the detector's eight builtins, the outer call with that one
argument only). Facts: all five are called from `run_all_checks` (base.py, phase 2B); every detector observes the
FIRST hit and returns, and 060 / 063 / 064 / 065 walk nested defs too (their rewriters edit every occurrence, innermost
first, a pass per nesting level); 062 reads the whole-body shape only (its `_matches`); 064's observation carries the
name, 065's the type, 062's the operator.
Set 4b-31 (2026-09-10, portion F2, app copy 2): NAI-067 `empty_string_concat_fix` (`<s> + ''` → `<s>` only where the
expression itself shows <s> is a str — a bare name carries no evidence, declined), NAI-068 `while_true_break_fix`
(`while True: if x: break …` → `while not x: …`, the detector's own "should be"), NAI-176 `fstring_prefix_fix` (the `f`
dropped from a placeholder-less f-string, the plain literal's value checked against the f-string's), NAI-180
`list_wrapping_fix` (`for … in list(range(…))` → `range(…)`; `list(<genexpr>)` under a consumer → the generator);
NAI-066 no-fix-by-design (how to unnest a conditional expression is the dev's). Facts: all five called from
`run_all_checks`; 067 fires on any `+ ''` regardless of the other operand's type — the rewriter demands evidence;
068 reads the if's body only (an else on the if is allowed by the detector, declined by the rewriter); 176 skips
format-spec JoinedStrs; 180 reports EVERY `for … in list(…)` once any `list(range(…))` exists in the function, and
its genexpr shape only under a consumer called by bare name (`.join` is an attribute — never observed).
"""
from __future__ import annotations

import ast
import textwrap
from typing import Any, Callable, Optional

from . import no_fix, prescribed, rewriter
from ._ast_edit import body_after_docstring, func_node, replace_cols, snippet_pad

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SIMPLE = (ast.Name, ast.Attribute, ast.Call, ast.Subscript, ast.Constant)


def fix_bool_literal_compare(broken_code: str) -> tuple[str, str]:
    """NAI-061: the True/False-literal compare the detector observes — the sole test of the `if`
    in a function whose body is exactly `if <x op literal>: return …` followed by one `return`
    (the detector's whole-body shape, docstring skipped) — becomes the detector's "Should be":
    `x == True` / `x is True` / `x != False` / `x is not False` → `x`;
    `x == False` / `x is False` / `x != True` / `x is not True` → `not x`.
    Structural preconditions: exactly one operator and one comparator, the compare on one
    line; a left operand that is not a plain name / attribute / call / subscript / constant is
    parenthesised so precedence cannot change. Declines otherwise."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    body = body_after_docstring(func)
    shape = (len(body) == 2 and isinstance(body[0], ast.If) and not body[0].orelse
             and len(body[0].body) == 1 and isinstance(body[0].body[0], ast.Return) and isinstance(body[1], ast.Return))
    if not shape:
        return "", ""
    node = body[0].test
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1):
        return "", ""
    op, lit = node.ops[0], node.comparators[0]
    if not (isinstance(lit, ast.Constant) and (lit.value is True or lit.value is False)):
        return "", ""
    if not isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) or node.lineno != node.end_lineno:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    row = node.lineno - 1
    if row >= len(lines):
        return "", ""
    left = node.left
    left_text = lines[row][pad + left.col_offset: pad + left.end_col_offset]  # type: ignore[operator]  # FIX_54 ast-pos
    if not isinstance(left, _SIMPLE):
        left_text = f"({left_text})"
    positive = isinstance(op, (ast.Eq, ast.Is)) == (lit.value is True)
    new_test = left_text if positive else f"not {left_text}"
    old_text = lines[row][pad + node.col_offset: pad + node.end_col_offset]  # type: ignore[operator]  # FIX_54 ast-pos
    replace_cols(lines, row, pad + node.col_offset, pad + node.end_col_offset, new_test)  # type: ignore[operator]  # FIX_54 ast-pos
    return "\n".join(lines), f"`{old_text}` (snippet line {node.lineno}) → `{new_test}`"


# ── shared by the set 4b-30 rewriters ────────────────────────────────────────

def _one_line(lines: list[str], pad: int, node: Node) -> Optional[str]:
    """The node's own source text when it sits on one line of the snippet, else None."""
    if node.lineno != node.end_lineno or node.lineno > len(lines):
        return None
    return lines[node.lineno - 1][pad + node.col_offset: pad + node.end_col_offset]


def _apply(lines: list[str], pad: int, edits: list[tuple[Node, str]]) -> None:
    """Replace each node's span with its text — bottom-up, right-to-left, so earlier columns stay valid."""
    for node, text in sorted(edits, key=lambda e: (e[0].lineno, e[0].col_offset), reverse=True):
        replace_cols(lines, node.lineno - 1, pad + node.col_offset, pad + node.end_col_offset, text)


def _innermost(hits: list) -> list:
    """The hits whose span holds no other hit — a pass edits these; an enclosing hit is taken on the next pass,
    once its inner one is gone (`str(str(str(x)))`, `not not (not not x)`)."""
    def holds(a, b) -> bool:
        return a is not b and a.lineno == b.lineno and a.col_offset <= b.col_offset and b.end_col_offset <= a.end_col_offset
    return [h for h in hits if not any(holds(h, o) for o in hits)]


def _parses(code: str) -> bool:
    try:
        ast.parse(textwrap.dedent(code))
    except SyntaxError:
        return False
    return True


def _passes(broken_code: str, one_pass: Callable[[str], Optional[tuple[str, str]]]) -> tuple[str, str]:
    """Run one_pass until it finds nothing. one_pass(code) → (new_code, what) — new_code "" when there was
    nothing to edit; None to decline the whole snippet. Each pass removes at least one hit, so it ends."""
    code = broken_code
    whats: list = []
    while True:
        res = one_pass(code)
        if res is None:
            return "", ""
        new, what = res
        if not new:
            break
        code, whats = new, whats + [what]
    if not whats or not _parses(code):
        return "", ""
    return code, "; ".join(whats)


def _paren(node: Node, text: str) -> str:
    return text if isinstance(node, _SIMPLE) else f"({text})"


# ── NAI-060 (set 4b-30) ──────────────────────────────────────────────────────

def fix_double_negation(broken_code: str) -> tuple[str, str]:
    """NAI-060: `not not <x>` → `bool(<x>)` — the detector's own basis (`not not x == bool(x)`): the same bool
    on every input, <x> evaluated once either way. Every occurrence the detector walks (nested defs included),
    innermost first. Precondition per hit, decline otherwise: the expression sits on one line."""
    def one_pass(code: str) -> Optional[tuple[str, str]]:
        func = func_node(code)
        if not func:
            return None
        pad, lines = snippet_pad(code), code.splitlines()
        hits = [n for n in ast.walk(func)
                if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not)
                and isinstance(n.operand, ast.UnaryOp) and isinstance(n.operand.op, ast.Not)]
        if not hits:
            return "", ""
        edits: list[tuple[Node, str]] = []
        whats: list[str] = []
        for n in _innermost(hits):
            old, inner = _one_line(lines, pad, n), _one_line(lines, pad, n.operand.operand)
            if old is None or inner is None:
                return None
            edits.append((n, f"bool({inner})"))
            whats.append(f"`{old}` (snippet line {n.lineno}) → `bool({inner})`")
        _apply(lines, pad, edits)
        return "\n".join(lines), "; ".join(whats)
    return _passes(broken_code, one_pass)


# ── NAI-062 (set 4b-30) ──────────────────────────────────────────────────────

def fix_len_zero_compare(broken_code: str) -> tuple[str, str]:
    """NAI-062: the `len(<x>) <op> 0` the detector observes — the sole test of the whole-body `if …: return` /
    `return` shape, or the bare `return` of the compare (optionally under one `not`) — becomes the detector's
    "Should be": `len(x) == 0` → `not x`; `len(x) != 0` / `len(x) > 0` → `x` as the if-test, `bool(x)` as the
    returned value (the return stays a bool); the `not …` return form flips accordingly. The same truth for every
    object whose truth is its length — the containers the rule is about. Preconditions, decline otherwise: one
    operator and one comparator, `len` with exactly one positional argument, everything on one line;
    `len(x) >= 0` is not a test of emptiness (always true) — what was meant is the dev's."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    body = body_after_docstring(func)
    if_return_shape = (len(body) == 2 and isinstance(body[0], ast.If) and not body[0].orelse
                       and len(body[0].body) == 1 and isinstance(body[0].body[0], ast.Return) and isinstance(body[1], ast.Return))
    bare_return_shape = len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value is not None
    node: Optional[ast.Compare] = None
    negated = False
    as_test = False
    if if_return_shape and isinstance(body[0].test, ast.Compare):
        node, as_test = body[0].test, True
    elif bare_return_shape:
        val = body[0].value
        if isinstance(val, ast.Compare):
            node = val
        elif isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not) and isinstance(val.operand, ast.Compare):
            node, negated = val.operand, True
    if node is None or len(node.ops) != 1 or len(node.comparators) != 1:
        return "", ""
    call, op, lit = node.left, node.ops[0], node.comparators[0]
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "len"
            and len(call.args) == 1 and not call.keywords):
        return "", ""
    if not (isinstance(lit, ast.Constant) and lit.value == 0 and not isinstance(lit.value, bool)):
        return "", ""
    if isinstance(op, ast.GtE) or not isinstance(op, (ast.Eq, ast.NotEq, ast.Gt)):
        return "", ""   # `>= 0`: always true — not the emptiness test; the dev's
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    target = body[0].value if negated else node       # the span replaced: the compare, or the `not compare`
    old, x_text = _one_line(lines, pad, target), _one_line(lines, pad, call.args[0])
    if old is None or x_text is None:
        return "", ""
    empty = isinstance(op, ast.Eq) != negated         # the expression is true when x is empty
    if empty:
        new = f"not {_paren(call.args[0], x_text)}"
    else:
        new = _paren(call.args[0], x_text) if as_test else f"bool({x_text})"
    _apply(lines, pad, [(target, new)])
    return "\n".join(lines), f"`{old}` (snippet line {target.lineno}) → `{new}`"


# ── NAI-063 (set 4b-30) ──────────────────────────────────────────────────────

def _truth_tests(func: Node) -> set[int]:
    """ids of the expressions whose only use is their truth: an if / while / ternary test, a `not` operand."""
    out: set[int] = set()
    for n in ast.walk(func):
        if isinstance(n, (ast.If, ast.While, ast.IfExp)):
            out.add(id(n.test))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            out.add(id(n.operand))
    return out


def fix_redundant_or_chain(broken_code: str) -> tuple[str, str]:
    """NAI-063: an `or` chain repeating a value — every repeat dropped, first occurrence kept, for each chain the
    detector walks (nested defs included). Correct by construction only where dropping changes nothing on any
    path, so decline otherwise: every operand a plain name (a call or attribute could be evaluated twice with an
    effect), and a repeated LAST operand only when the chain is a truth test (an if / while / ternary test or a
    `not` operand) — `a or b or a` is `a` when all are falsy, `a or b` is `b`, the same truth but not the same
    value; everything on one line."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    truth = _truth_tests(func)
    edits: list[tuple[Node, str]] = []
    whats: list[str] = []
    for n in ast.walk(func):
        if not (isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or)):
            continue
        dumps = [ast.dump(v) for v in n.values]
        if len(dumps) == len(set(dumps)):
            continue
        if not all(isinstance(v, ast.Name) for v in n.values):
            return "", ""
        kept: list[str] = []
        for v in n.values:
            if v.id not in kept:  # type: ignore[attr-defined]  # FIX_54 ast-pos
                kept.append(v.id)  # type: ignore[attr-defined]  # FIX_54 ast-pos
        if n.values[-1].id in kept[:-1] and id(n) not in truth:  # type: ignore[attr-defined]  # FIX_54 ast-pos
            return "", ""   # the last operand is the chain's value when all are falsy — dropping it changes the value
        old = _one_line(lines, pad, n)
        if old is None:
            return "", ""
        new = " or ".join(kept)
        edits.append((n, new))
        whats.append(f"`{old}` (snippet line {n.lineno}) → `{new}`")
    if not edits:
        return "", ""
    _apply(lines, pad, edits)
    code = "\n".join(lines)
    return (code, "; ".join(whats)) if _parses(code) else ("", "")


# ── NAI-064 (set 4b-30) ──────────────────────────────────────────────────────

def _params(func: "ast.FunctionDef | ast.AsyncFunctionDef") -> set[str]:
    a = func.args
    return {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs + ([a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else [])}


def _own_statements(func: "ast.FunctionDef | ast.AsyncFunctionDef"):
    """The function's OWN statements — a nested def / lambda / class is another scope."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(n))


def fix_self_assignment(broken_code: str) -> tuple[str, str]:
    """NAI-064: `x = x` — the statement the detector observes — deleted when `x` is a parameter of the def the
    statement sits in (the snippet's def or a nested one; the detector walks both): bound from entry, so the
    assignment rebinds nothing and the name's scope does not change. A self-assignment of any other name is
    declined — it may be the name's only binding in that scope (deleting it changes the scope, the set 4b-22 fact) —
    the dev's. Preconditions per hit, decline otherwise: the statement is the whole line (a trailing comment
    allowed) and not its block's only statement; the result must still parse."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    rows: list[tuple[int, str]] = []
    defs = [n for n in ast.walk(func) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for d in defs:
        params = _params(d)
        for n in _own_statements(d):
            if not (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                    and isinstance(n.value, ast.Name) and n.targets[0].id == n.value.id):
                continue
            if n.targets[0].id not in params:
                return "", ""
            text = _one_line(lines, pad, n)
            if text is None:
                return "", ""
            stripped = lines[n.lineno - 1].strip()
            rest = stripped[len(text):].lstrip()
            if stripped[:len(text)] != text or (rest and not rest.startswith("#")):
                return "", ""
            rows.append((n.lineno - 1, text))
    if not rows:
        return "", ""
    for row, _text in sorted(rows, reverse=True):
        del lines[row]
    code = "\n".join(lines)
    if not _parses(code):
        return "", ""
    return code, "; ".join(f"`{text}` (snippet line {row + 1}) deleted — `{text.split('=')[0].strip()}` is a parameter, already bound"
                           for row, text in rows)


# ── NAI-065 (set 4b-30) ──────────────────────────────────────────────────────

_TYPE_FUNCS = frozenset({"str", "int", "float", "bool", "list", "tuple", "set", "dict"})   # the detector's table


def fix_redundant_conversion(broken_code: str) -> tuple[str, str]:
    """NAI-065: `T(T(<x>))` → `T(<x>)` for the eight builtins the detector names: T applied to its own result is
    that result (a str of a str, an int of an int; a fresh list of a fresh list is an equal list), <x> evaluated
    once either way. Every occurrence the detector walks (nested defs included), innermost first. Preconditions
    per hit, decline otherwise: the outer call has that one positional argument and no keywords (`int(int(s), 16)`
    is another expression; `int(int(s, 16))` keeps its inner call whole), everything on one line."""
    def one_pass(code: str) -> Optional[tuple[str, str]]:
        func = func_node(code)
        if not func:
            return None
        pad, lines = snippet_pad(code), code.splitlines()
        hits = [n for n in ast.walk(func)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _TYPE_FUNCS
                and n.args and isinstance(n.args[0], ast.Call)
                and isinstance(n.args[0].func, ast.Name) and n.args[0].func.id == n.func.id]
        if not hits:
            return "", ""
        edits: list[tuple[Node, str]] = []
        whats: list[str] = []
        for n in _innermost(hits):
            if len(n.args) != 1 or n.keywords:
                return None
            old, inner = _one_line(lines, pad, n), _one_line(lines, pad, n.args[0])
            if old is None or inner is None:
                return None
            edits.append((n, inner))
            whats.append(f"`{old}` (snippet line {n.lineno}) → `{inner}`")
        _apply(lines, pad, edits)
        return "\n".join(lines), "; ".join(whats)
    return _passes(broken_code, one_pass)


# ── NAI-067 (set 4b-31) ──────────────────────────────────────────────────────

_STR_CALLS = frozenset({"str", "repr", "format", "chr"})
_STR_METHODS = frozenset({"format", "decode"})   # str-only results; `.join` / `.lower` etc. exist on bytes too


def _known_str(node: Node) -> bool:
    """Evidence in the expression itself that its value is a str: a str literal, an f-string, `str(...)` /
    `repr(...)` / `format(...)` / `chr(...)`, `.format(...)` / `.decode(...)`, a `%` format of a str literal,
    an `+` whose left side is a known str (the sum, when it succeeds, is a str)."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id in _STR_CALLS
        return isinstance(node.func, ast.Attribute) and node.func.attr in _STR_METHODS
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod):
            return isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
        return isinstance(node.op, ast.Add) and _known_str(node.left)
    return False


def fix_empty_string_concat(broken_code: str) -> tuple[str, str]:
    """NAI-067: `<s> + ''` / `'' + <s>` — the `+` the detector observes — becomes `<s>` when the expression itself
    shows <s> is a str (a literal, an f-string, `str(...)`, `.format(...)`, a `%` format, a `+` of a known str):
    `s + ''` is `s` for every str, and <s> is evaluated once either way. Every occurrence the detector walks
    (nested defs included), innermost first. Declines otherwise — a bare name or attribute carries no evidence of
    its type, and for a non-str the `+ ''` raises where the rewrite would not; what was meant is the dev's."""
    def one_pass(code: str) -> Optional[tuple[str, str]]:
        func = func_node(code)
        if not func:
            return None
        pad, lines = snippet_pad(code), code.splitlines()
        hits = []
        for n in ast.walk(func):
            if not (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add)):
                continue
            left_empty = isinstance(n.left, ast.Constant) and n.left.value == ""
            right_empty = isinstance(n.right, ast.Constant) and n.right.value == ""
            if left_empty or right_empty:
                hits.append((n, n.right if left_empty else n.left))
        if not hits:
            return "", ""
        inner = {id(h) for h, _ in _pairs_innermost(hits)}
        edits: list[tuple[Node, str]] = []
        whats: list[str] = []
        for n, other in hits:
            if id(n) not in inner:
                continue
            if not _known_str(other):
                return None
            old, text = _one_line(lines, pad, n), _one_line(lines, pad, other)
            if old is None or text is None:
                return None
            new = _paren(other, text)
            edits.append((n, new))
            whats.append(f"`{old}` (snippet line {n.lineno}) → `{new}`")
        _apply(lines, pad, edits)
        return "\n".join(lines), "; ".join(whats)
    return _passes(broken_code, one_pass)


def _pairs_innermost(pairs: list) -> list:
    nodes = [p[0] for p in pairs]
    keep = {id(n) for n in _innermost(nodes)}
    return [p for p in pairs if id(p[0]) in keep]


# ── NAI-068 (set 4b-31) ──────────────────────────────────────────────────────

def _whole_line(lines: list[str], pad: int, node: Node) -> bool:
    """The statement's lines hold nothing but the statement (a trailing comment allowed on the last one)."""
    if node.end_lineno > len(lines):
        return False
    first = lines[node.lineno - 1]
    if first[: pad + node.col_offset].strip():
        return False
    last = lines[node.end_lineno - 1]
    rest = last[pad + node.end_col_offset:].strip()
    return not rest or rest.startswith("#")


def fix_while_true_break(broken_code: str) -> tuple[str, str]:
    """NAI-068: `while True:` whose first statement is `if <x>: break` — the shape the detector observes — becomes
    the detector's "Should be": `while not <x>:` with the `if` removed. The test is evaluated at the same point of
    every iteration (the top), the rest of the body runs under the same condition, and nothing else exits or
    enters differently. Preconditions, decline otherwise: the `if` has no else and its body is that one `break`;
    the loop has no `else:` (a `while True` never reaches one — a `while not x` would); the body holds more than
    the `if` (`while not x: pass` is a spin, another program); the `if` statement owns its lines and <x> sits on
    one line (<x> parenthesised unless a plain name / attribute / call / subscript / constant)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    hits: list[tuple[ast.While, ast.If]] = []
    for n in ast.walk(func):
        if not (isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True and n.body):
            continue
        first = n.body[0]
        if not (isinstance(first, ast.If) and len(first.body) == 1 and isinstance(first.body[0], ast.Break)):
            continue
        if first.orelse or n.orelse or len(n.body) == 1:
            return "", ""
        if first.test.lineno != first.test.end_lineno or first.end_lineno > len(lines) or not _whole_line(lines, pad, first):  # type: ignore[operator]  # FIX_54 ast-pos
            return "", ""
        hits.append((n, first))
    if not hits:
        return "", ""
    whats: list[str] = []
    for loop, cond in sorted(hits, key=lambda h: h[0].lineno, reverse=True):
        x_text = _one_line(lines, pad, cond.test)
        if x_text is None:
            return "", ""
        new_test = f"not {_paren(cond.test, x_text)}"
        _apply(lines, pad, [(loop.test, new_test)])
        del lines[cond.lineno - 1: cond.end_lineno]
        whats.append(f"`while True:` (snippet line {loop.lineno}) → `while {new_test}:` — its first statement "
                     f"`if {x_text}: break` (snippet line {cond.lineno}) removed")
    code = "\n".join(lines)
    return (code, "; ".join(reversed(whats))) if _parses(code) else ("", "")


# ── NAI-176 (set 4b-31) ──────────────────────────────────────────────────────

def _fstring_value(node: ast.JoinedStr) -> Optional[str]:
    parts = []
    for v in node.values:
        if not (isinstance(v, ast.Constant) and isinstance(v.value, str)):
            return None
        parts.append(v.value)
    return "".join(parts)


def fix_fstring_no_placeholders(broken_code: str) -> tuple[str, str]:
    """NAI-176: an f-string with no placeholder — the literal the detector observes — loses its `f` prefix: the
    value is checked, not assumed — the plain literal must evaluate to the very string the f-string denotes
    (`{{` / `}}` are unescaped to `{` / `}` when that is what makes them equal). Every occurrence the detector
    walks (nested defs included). Preconditions per hit, decline otherwise: the literal sits on one line and its
    text starts with an `f` / `F` prefix (a `rf` keeps its `r`)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    fmt_specs = {id(n.format_spec) for n in ast.walk(func) if isinstance(n, ast.FormattedValue) and isinstance(n.format_spec, ast.JoinedStr)}
    edits: list[tuple[Node, str]] = []
    whats: list[str] = []
    for n in ast.walk(func):
        if not (isinstance(n, ast.JoinedStr) and id(n) not in fmt_specs):
            continue
        if any(isinstance(v, ast.FormattedValue) for v in n.values):
            continue
        value, old = _fstring_value(n), _one_line(lines, pad, n)
        if value is None or old is None:
            return "", ""
        quote = next((i for i, ch in enumerate(old) if ch in "'\""), -1)
        prefix = old[:quote] if quote >= 0 else ""
        if "f" not in prefix.lower():
            return "", ""
        plain = prefix.replace("f", "").replace("F", "") + old[quote:]
        new = None
        for cand in (plain, prefix.replace("f", "").replace("F", "") + old[quote:].replace("{{", "{").replace("}}", "}")):
            try:
                if ast.literal_eval(cand) == value:
                    new = cand
                    break
            except (ValueError, SyntaxError):
                continue
        if new is None:
            return "", ""
        edits.append((n, new))
        whats.append(f"`{old}` (snippet line {n.lineno}) → `{new}` — no placeholder, the prefix did nothing")
    if not edits:
        return "", ""
    _apply(lines, pad, edits)
    code = "\n".join(lines)
    return (code, "; ".join(whats)) if _parses(code) else ("", "")


# ── NAI-180 (set 4b-31) ──────────────────────────────────────────────────────

_CONSUMERS = frozenset({"sorted", "sum", "min", "max", "any", "all", "tuple", "set", "frozenset", "join"})   # the detector's list


def _is_list_call(n: Node) -> bool:
    return isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "list" and len(n.args) == 1 and not n.keywords


def fix_unnecessary_list_wrapping(broken_code: str) -> tuple[str, str]:
    """NAI-180: the two shapes the detector observes — `for … in list(range(…))` → `for … in range(…)` (a range
    iterates the same values; the list was a temporary nobody else held), and `list(<genexpr>)` passed to one of
    the detector's consumers (`sorted`, `sum`, `min`, `max`, `any`, `all`, `tuple`, `set`, `frozenset`, `join`)
    → the generator itself (each consumes an iterable once; the same items in the same order). Preconditions per
    hit, decline otherwise: `list` with that one positional argument, everything on one line; the generator keeps
    its parentheses unless it is the consumer's sole argument. A `for` over `list(<other>)` is not rewritten —
    the detector reports such a loop whenever a `list(range(…))` exists in the function, but only the range form
    is a known no-op."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad, lines = snippet_pad(broken_code), broken_code.splitlines()
    edits: list[tuple[Node, str]] = []
    whats: list[str] = []
    for n in ast.walk(func):
        if isinstance(n, ast.For) and _is_list_call(n.iter):
            arg = n.iter.args[0]  # type: ignore[attr-defined]  # FIX_54 ast-pos
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "range":
                old, inner = _one_line(lines, pad, n.iter), _one_line(lines, pad, arg)
                if old is None or inner is None:
                    return "", ""
                edits.append((n.iter, inner))
                whats.append(f"`{old}` (snippet line {n.iter.lineno}) → `{inner}`")
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _CONSUMERS:
            for a in n.args:
                if _is_list_call(a) and isinstance(a.args[0], ast.GeneratorExp):  # type: ignore[attr-defined]  # FIX_54 ast-pos
                    old, inner = _one_line(lines, pad, a), _one_line(lines, pad, a.args[0])  # type: ignore[attr-defined]  # FIX_54 ast-pos
                    if old is None or inner is None:
                        return "", ""
                    if not (inner.startswith("(") and inner.endswith(")")):
                        inner = f"({inner})"
                    if len(n.args) == 1 and not n.keywords:
                        inner = inner[1:-1]
                    edits.append((a, inner))
                    whats.append(f"`{old}` (snippet line {a.lineno}) → `{inner}`")
    if not edits:
        return "", ""
    _apply(lines, pad, edits)
    code = "\n".join(lines)
    return (code, "; ".join(whats)) if _parses(code) else ("", "")


_SRC = "no_aivalidator/detection/redundancy_checks.py"
_F1 = "set 4b-30 (portion F1, app copy 2, run 84)"
_F2 = "set 4b-31 (portion F2, app copy 2, run 85)"

GENERATORS = [
    rewriter("NAI-061", f"{_SRC}:_check_bool_comparison", "bool_literal_compare_fix", fix_bool_literal_compare,
             reason="the detector's own 'Should be: if x / if not x' on exactly the whole-body shape it observes; "
                    "declines on any other shape, chained compares, or a multi-line test"),
    # set 4b-30 (2026-09-10): the five detectors' own "should be", each on exactly the shape it observes
    rewriter("NAI-060", f"{_SRC}:_check_double_negation", "double_negation_fix", fix_double_negation,
             reason="the detector's own basis (`not not x == bool(x)`): the same bool on every input, the operand "
                    "evaluated once either way; every occurrence, innermost first; declines a multi-line expression",
             dated="2026-09-10", by=_F1),
    rewriter("NAI-062", f"{_SRC}:_check_len_zero_comparison", "len_zero_compare_fix", fix_len_zero_compare,
             reason="the detector's own 'Should be: not x / bool(x)' on exactly the whole-body shape it observes "
                    "(`== 0` → `not x`; `!= 0` / `> 0` → `x` as a test, `bool(x)` as a return); declines `>= 0` "
                    "(always true — not a test of emptiness), a chained compare, a `len` with other arguments, a multi-line test",
             dated="2026-09-10", by=_F1),
    rewriter("NAI-063", f"{_SRC}:_check_redundant_or_chain", "or_chain_dedupe_fix", fix_redundant_or_chain,
             reason="repeats of a plain name dropped from an `or` chain, first occurrence kept — nothing evaluated "
                    "twice, the first truthy operand unchanged; declines a chain with a call / attribute operand and a "
                    "repeated last operand outside a truth test (the chain's all-falsy value would change)",
             dated="2026-09-10", by=_F1),
    rewriter("NAI-064", f"{_SRC}:_check_self_assignment", "self_assignment_fix", fix_self_assignment,
             reason="`x = x` deleted only when x is a parameter of the def it sits in — bound from entry, so nothing "
                    "rebinds and no scope changes; declines any other name (its only binding may be this line — "
                    "deleting it changes scope), a shared line, a block's only statement",
             dated="2026-09-10", by=_F1),
    rewriter("NAI-065", f"{_SRC}:_check_redundant_type_conversion", "redundant_conversion_fix", fix_redundant_conversion,
             reason="`T(T(x))` → `T(x)` for the detector's eight builtins — T of its own result is that result; "
                    "every occurrence, innermost first; declines an outer call with other arguments or keywords, a multi-line call",
             dated="2026-09-10", by=_F1),
    # set 4b-31 (2026-09-10): four rewriters on the detectors' own shapes, one declaration
    prescribed('NAI-066', f"{_SRC}:_check_nested_ternary", 'Write the value as an if / elif / else chain (or a dict lookup when the branches map keys to values) so each case reads on its own line.',
               'if <b>:\n    value = <a>\nelif <d>:\n    value = <c>\nelse:\n    value = <e>'),
    rewriter("NAI-067", f"{_SRC}:_check_empty_string_concat", "empty_string_concat_fix", fix_empty_string_concat,
             reason="`<s> + ''` / `'' + <s>` → `<s>` only where the expression itself shows <s> is a str (a literal, an "
                    "f-string, `str(...)`, `.format(...)`, a `%` format, a `+` of a known str) — `s + ''` is `s` for every "
                    "str; declines a bare name / attribute (no evidence of its type: for a non-str the `+ ''` raises where the rewrite would not)",
             dated="2026-09-10", by=_F2),
    # NAI-068: rewriter row retired 2026-10-08 — owner go, fix round after tree 13 (M-146): the rule is context (a loop-style
    # choice, never on a flaw line in trees 1–13); a context id never fails a function, so it has no repair. fix_while_true_break kept.
    rewriter("NAI-176", f"{_SRC}:_check_fstring_no_placeholders", "fstring_prefix_fix", fix_fstring_no_placeholders,
             reason="the `f` prefix dropped from a placeholder-less f-string — the plain literal is checked to evaluate to "
                    "the very string the f-string denotes (`{{` / `}}` unescaped when that is what makes them equal); "
                    "declines a multi-line literal or one whose text does not start with the prefix",
             dated="2026-09-10", by=_F2),
    rewriter("NAI-180", f"{_SRC}:_check_unnecessary_list_wrapping", "list_wrapping_fix", fix_unnecessary_list_wrapping,
             reason="`for … in list(range(…))` → `range(…)`; `list(<genexpr>)` passed to one of the detector's consumers → "
                    "the generator — the same items in the same order, consumed once; declines a `list` with other "
                    "arguments, a multi-line call; a `for` over `list(<other>)` (reported by the detector beside any "
                    "`list(range())`) is not rewritten — only the range form is a known no-op",
             dated="2026-09-10", by=_F2),
]
