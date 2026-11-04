"""Safety family (no_aivalidator/detection/safety_checks.py) — item 4, 2026-09-08.

Rewriters: NAI-070 (new), NAI-071 / NAI-092 / NAI-093 (moved verbatim from
cheatsheet_intelligence/knowledge_base.py, plan item 5 of 2026-09-05).
No fix by design: NAI-076, NAI-078, NAI-094 (owner ruling 2026-09-08).
Set 4b-07 (2026-09-10): NAI-075 rewriter `open_with_fix`; NAI-072 / 073 / 074 / 077 no-fix-by-design (a
secret's source, a paramstyle, what to do on bad JSON, which default replaces a KeyError — the dev's).
Set 4b-08 (2026-09-10): NAI-096 rewriter `assert_guard_fix`; NAI-079 / 091 / 095 / 098 no-fix-by-design
(a path's source, copy or mutate by contract, which tolerance, what to return instead of printing).
Set 4b-09 (2026-09-10): NAI-159 rewriter `deprecated_alias_fix`; NAI-152 / 158 / 160 / 161 no-fix-by-design
(instance-owning a class container, which validation, which timeout); NAI-160's catalogue `where` corrected.
Set 4b-10 (2026-09-10): NAI-162 rewriter `verify_true_fix` (`verify=False` → `verify=True`, the library's
own default restored in place) and NAI-166 rewriter `not_implemented_error_fix` (`raise NotImplemented` →
`raise NotImplementedError`, the detector's own "should be"). NAI-163 (which address replaces 0.0.0.0 —
a specific interface or the loopback — is a deployment decision), NAI-164 (mkstemp returns an (fd, path)
pair and NamedTemporaryFile a file object: every replacement changes the value's type and the code around
it) and NAI-165 no-fix-by-design. NAI-165's fact: the detector reads the string constant's VALUE, so
writing the bidi character as `\\uXXXX` still fires it (probed 2026-09-10) and deleting the character
changes the string; which text the dev meant is theirs. All five decide function rows today.
Set 4b-11 (2026-09-10): NAI-172 rewriter `except_order_fix` (handlers of a try reordered so a child exception
reaches its own handler — a permutation of whole handler blocks; handlers whose type is not a plain name in
the detector's table stay where they are and are never crossed). NAI-167 (which environment variable names
the endpoint, which timeout or retry policy), NAI-173 (what a function should return when its finally block
overrides an exception), NAI-200 (which handler body) and NAI-201 (which guard, what to do on malformed
data) no-fix-by-design. Two `meaning_source` corrections: NAI-200 is emitted by `_check_risky_single_call`
(the catalogue says `_check_unguarded_file_ops`) and NAI-201 by `_check_unsafe_type_coercion` (the catalogue
says `_check_risky_single_call`). Facts: NAI-167 and NAI-200 observe on the function line; NAI-201 coerces
int / float only (bool is in its docstring, not its table) and its no-parameter / no-argument rows are
context only; a return in finally also fires NAI-143 (set 4b-17) on the same row.
Set 4b-12 (2026-09-10): NAI-203 (whether the cache or the side effect is the mistake — dropping the
decorator changes every repeated call's cost, moving the effect changes what the function does), NAI-204
(a sync function running a coroutine — making it async, taking the running loop or a thread is a design
decision), NAI-206 (which directory a path is meant against — the file's, a parameter's, a config key's),
NAI-210 (whether a thread belongs in a sync pipeline) no-fix-by-design. Facts: NAI-203 rows without a cache
decorator are context only and the observed line is the side-effect call; NAI-206 excludes a getcwd that is
returned, an `or` fallback, or bound only for chdir; NAI-204 and NAI-210 stay quiet on async defs. Family
`safety` CLOSED with this set (4b-07..12, runs 61–66); portion A of ITEM_04B closed.
"""
from __future__ import annotations

import ast
from typing import Any
import re
import textwrap

from . import no_fix, prescribed, rewriter, unbuilt
from ._ast_edit import body_after_docstring, func_node, head_insert_stmt, replace_cols, snippet_pad
from ._finite import (Variant, delete_rows, dedent_rows, edited, finish, fresh_name, indent, keyword_row, node_text,
                      prep, replace_node, rows, same_if_else_variants, single_line, whole_rows)
# FIX_58 (2026-09-17): the lane contract's "declare the predicate beside the variant" — this family's
# predicates are registered from here, so G0 and the rewriter say the same thing about the same shape.
from .gate import INPLACE_CONTRACT, Rewrite as _Rewrite, predicate as _predicate

# FIX_54 (2026-09-17): "any AST node" — these helpers are handed whatever node the walk
# produced and read positions / fields off it; `ast.AST` is the class that carries none of
# them, so the annotation said less than the code means. Naming the intent changes nothing at
# runtime and adds no isinstance early-out (which the pre-ranker hunter would count).
Node = Any

_SHELL_META = frozenset('|&;<>()$`\\"\'*?[]#~=%{}\n')
_BARE_EXCEPT = re.compile(r"except\s*:")


# ── NAI-070 (new, first batch) ──────────────────────────────────────────────

def fix_bare_except(broken_code: str) -> tuple[str, str]:
    """NAI-070: every `except:` in the function → `except Exception:` — the detector's own
    "Should be". Structural preconditions (each a fact of the snippet's AST, decline otherwise):
    the handler line reads `except:` at the handler's column (no line continuation); no bare
    handler's body re-raises (`except: cleanup(); raise` is the cleanup-then-re-raise idiom,
    where the bare form is deliberate — not rewritten). Behaviour that changes, by the rule's
    meaning: SystemExit / KeyboardInterrupt / GeneratorExit propagate instead of being caught."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    handlers = [n for n in ast.walk(func) if isinstance(n, ast.ExceptHandler) and n.type is None]
    if not handlers:
        return "", ""
    edits: list[tuple[int, int, int]] = []
    for h in handlers:
        if any(isinstance(n, ast.Raise) and n.exc is None for n in ast.walk(h)):
            return "", ""  # re-raise idiom: the bare except is deliberate
        row = h.lineno - 1
        if row >= len(lines):
            return "", ""
        col = pad + h.col_offset
        m = _BARE_EXCEPT.match(lines[row], col)
        if m is None:
            return "", ""
        edits.append((row, m.start(), m.end()))
    for row, s, e in sorted(edits, reverse=True):
        replace_cols(lines, row, s, e, "except Exception:")
    what = "; ".join(f"`except:` (snippet line {row + 1}) → `except Exception:`" for row, _s, _e in sorted(edits))
    what += " — SystemExit / KeyboardInterrupt / GeneratorExit now propagate"
    return "\n".join(lines), what


# ── NAI-075 (set 4b-07, 2026-09-10) ──────────────────────────────────────────

def _stmt_lists(func: "ast.FunctionDef | ast.AsyncFunctionDef") -> list[list[Node]]:
    """Every statement list of the function's OWN scope (nested defs / lambdas are other scopes)."""
    out: list[list[Node]] = []
    stack: list[list[Node]] = [list(func.body)]
    while stack:
        body = stack.pop()
        out.append(body)
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for field in ("body", "orelse", "finalbody"):
                sub = getattr(st, field, None)
                if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                    stack.append(list(sub))
            for h in getattr(st, "handlers", []) or []:
                stack.append(list(h.body))
            for case in getattr(st, "cases", []) or []:
                stack.append(list(case.body))
    return out


def fix_unguarded_open(broken_code: str) -> tuple[str, str]:
    """NAI-075: `name = open(...)` whose handle is closed by a plain `name.close()` statement
    LATER IN THE SAME BLOCK → `with open(...) as name:` over the statements between, the
    `.close()` line dropped. Equivalent by construction on the normal path (the handle is
    closed at the same point) and, by the rule's meaning, now closed on every exit path
    (exception, early return) too. Structural preconditions (decline otherwise): the assign
    is a single-target, single-line statement whose whole value is the open() call; the close
    is a single-line `name.close()` expression statement in the same statement list, after it,
    with at least one statement between; no statement between rebinds `name`; no line
    between is indented shallower than the assign (the block's own lines, re-indented by four). A handle that is never
    closed, closed in another block, returned or stored is NOT rewritten (where it should
    close is the dev's)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    for body in _stmt_lists(func):
        for i, st in enumerate(body):
            if not (isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)
                    and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Name)
                    and st.value.func.id == "open" and st.lineno == st.end_lineno):
                continue
            name = st.targets[0].id
            close_idx = None
            for j in range(i + 1, len(body)):
                cst = body[j]
                if (isinstance(cst, ast.Expr) and isinstance(cst.value, ast.Call)
                        and isinstance(cst.value.func, ast.Attribute) and cst.value.func.attr == "close"
                        and isinstance(cst.value.func.value, ast.Name) and cst.value.func.value.id == name
                        and not cst.value.args and not cst.value.keywords and cst.lineno == cst.end_lineno):
                    close_idx = j
                    break
                if any(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store) for n in ast.walk(cst)):
                    break  # rebound before any close: not this idiom
            if close_idx is None or close_idx == i + 1:
                continue
            a_row, c_row = st.lineno - 1, body[close_idx].lineno - 1
            if c_row >= len(lines):
                return "", ""
            indent = pad + st.col_offset
            between = lines[a_row + 1:c_row]
            if any(ln.strip() and (len(ln) - len(ln.lstrip())) < indent for ln in between):
                return "", ""  # a continuation line shallower than the block: not a shape this edit can re-indent
            call_text = lines[a_row][pad + st.value.col_offset: pad + st.value.end_col_offset]  # type: ignore[operator]  # FIX_54 ast-pos
            new_lines = lines[:a_row]
            new_lines.append(" " * indent + f"with {call_text} as {name}:")
            new_lines.extend(("    " + ln) if ln.strip() else ln for ln in between)
            new_lines.extend(lines[c_row + 1:])
            what = (f"`{name} = {call_text}` (snippet line {a_row + 1}) → `with {call_text} as {name}:` over "
                    f"{close_idx - i - 1} statement(s); `{name}.close()` (line {c_row + 1}) dropped — closed on every exit path")
            return "\n".join(new_lines), what
    return "", ""


# ── NAI-096 (set 4b-08, 2026-09-10) ──────────────────────────────────────────

def fix_assert_validation(broken_code: str) -> tuple[str, str]:
    """NAI-096: the function's first statement is `assert <test>[, <msg>]` on one parameter →
    `if not (<test>):` / `    raise AssertionError(<msg>)`. Equivalent by construction with
    assertions enabled (same exception, same message, same point) and, by the rule's meaning,
    the check now runs under `python -O` too. Preconditions (decline otherwise): the assert is
    the first statement after the docstring and sits on ONE line that holds nothing else but an
    optional trailing comment (kept on the `if` line)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    body = body_after_docstring(func)
    if not body or not isinstance(body[0], ast.Assert):
        return "", ""
    a = body[0]
    if a.lineno != a.end_lineno:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    row = a.lineno - 1
    if row >= len(lines):
        return "", ""
    line = lines[row]
    col = pad + a.col_offset
    if not line[col:].startswith("assert"):
        return "", ""
    tail = line[pad + a.end_col_offset:]  # type: ignore[operator]  # FIX_54 ast-pos
    if tail.strip() and not tail.lstrip().startswith("#"):
        return "", ""
    test_text = line[pad + a.test.col_offset: pad + a.test.end_col_offset]  # type: ignore[operator]  # FIX_54 ast-pos
    msg_text = line[pad + a.msg.col_offset: pad + a.msg.end_col_offset] if a.msg is not None else ""  # type: ignore[operator]  # FIX_54 ast-pos
    indent = line[:col]
    raise_text = f"raise AssertionError({msg_text})" if msg_text else "raise AssertionError"
    lines[row:row + 1] = [f"{indent}if not ({test_text}):{tail.rstrip()}", f"{indent}    {raise_text}"]
    what = (f"`assert {test_text}` (snippet line {row + 1}) → `if not ({test_text}): {raise_text}` — "
            f"the same AssertionError, and the check survives python -O")
    return "\n".join(lines), what


# ── NAI-159 (set 4b-09, 2026-09-10) ──────────────────────────────────────────

# Exact deprecated ALIASES: the new name is the same callable (logging.warn IS logging.warning;
# unittest's assertEquals / assertNotEquals / assertRegexpMatches are aliases of assertEqual /
# assertNotEqual / assertRegex). Nothing else in the detector's table is an alias: os.system /
# os.popen → subprocess.run is a different call (SEC-009), iteritems / has_key / xrange /
# raw_input are Python-2 names whose Python-3 form changes the object's type, and collections.X
# → collections.abc.X needs an import the snippet cannot add. Those decline.
_ALIAS_ATTRS: dict[str, str] = {"assertEquals": "assertEqual", "assertNotEquals": "assertNotEqual",
                                "assertRegexpMatches": "assertRegex"}
_ALIAS_MODULE_ATTRS: dict[tuple[str, str], str] = {("logging", "warn"): "warning"}


def fix_deprecated_alias(broken_code: str) -> tuple[str, str]:
    """NAI-159: every call through an exact deprecated alias → the current name, in place
    (`logging.warn(...)` → `logging.warning(...)`, `self.assertEquals(...)` → `self.assertEqual(...)`).
    Equivalent by construction: the alias and the name are the same callable. Declines when no
    alias call is present (the observed deprecated API is one whose replacement is a different
    call) and when the attribute text is not where the AST places it (a continuation line)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int, str, str]] = []
    for node in ast.walk(func):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        attr = node.func.attr
        new = _ALIAS_ATTRS.get(attr)
        if new is None and isinstance(node.func.value, ast.Name):
            new = _ALIAS_MODULE_ATTRS.get((node.func.value.id, attr))
        if new is None:
            continue
        row = node.func.lineno - 1
        end = pad + node.func.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        start = end - len(attr)
        if node.func.lineno != node.func.end_lineno or row >= len(lines) or lines[row][start:end] != attr:
            return "", ""
        edits.append((row, start, end, attr, new))
    if not edits:
        return "", ""
    for row, start, end, _old, new in sorted(edits, reverse=True):
        replace_cols(lines, row, start, end, new)
    what = "; ".join(f"`.{old}(` (snippet line {row + 1}) → `.{new}(`" for row, _s, _e, old, new in sorted(edits))
    what += " — the deprecated alias and the current name are the same callable"
    return "\n".join(lines), what


# ── NAI-162 / NAI-166 (set 4b-10, 2026-09-10) ───────────────────────────────

def fix_no_cert_validation(broken_code: str) -> tuple[str, str]:
    """NAI-162: every `requests.<method>(..., verify=False)` → `verify=True`, in place — the
    library's own default restored, no value chosen. Equivalent by construction on the request
    itself (method, URL, every other argument unchanged); by the rule's meaning the server's
    certificate is now validated, so a peer presenting an untrusted certificate fails the call
    instead of being accepted. Declines when the `False` token is not where the AST places it
    (a continuation line)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int, str]] = []
    for node in ast.walk(func):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "requests"):
            continue
        for kw in node.keywords:
            if not (kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False):
                continue
            v = kw.value
            row = v.lineno - 1
            s, e = pad + v.col_offset, pad + v.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
            if v.lineno != v.end_lineno or row >= len(lines) or lines[row][s:e] != "False":
                return "", ""
            edits.append((row, s, e, node.func.attr))
    if not edits:
        return "", ""
    for row, s, e, _m in sorted(edits, reverse=True):
        replace_cols(lines, row, s, e, "True")
    what = "; ".join(f"`requests.{m}(..., verify=False)` (snippet line {row + 1}) → `verify=True`"
                     for row, _s, _e, m in sorted(edits))
    what += " — the certificate is now validated (the library's default)"
    return "\n".join(lines), what


def fix_raise_not_implemented(broken_code: str) -> tuple[str, str]:
    """NAI-166: every `raise NotImplemented` → `raise NotImplementedError`, in place — the
    detector's own "should be". Before, the statement raised TypeError (NotImplemented is the
    binary-operator singleton, not an exception); after, it raises the exception the name was
    reaching for. The normal path is untouched. Declines when the name is not where the AST
    places it (a continuation line)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    edits: list[tuple[int, int, int]] = []
    for node in ast.walk(func):
        if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Name) and node.exc.id == "NotImplemented"):
            continue
        n = node.exc
        row = n.lineno - 1
        s, e = pad + n.col_offset, pad + n.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        if row >= len(lines) or lines[row][s:e] != "NotImplemented":
            return "", ""
        edits.append((row, s, e))
    if not edits:
        return "", ""
    for row, s, e in sorted(edits, reverse=True):
        replace_cols(lines, row, s, e, "NotImplementedError")
    what = "; ".join(f"`raise NotImplemented` (snippet line {row + 1}) → `raise NotImplementedError`" for row, _s, _e in sorted(edits))
    what += " — NotImplementedError instead of the TypeError the singleton raised"
    return "\n".join(lines), what


# ── NAI-172 (set 4b-11, 2026-09-10) ──────────────────────────────────────────

# Mirror of the detector's exception_hierarchy (safety_checks._check_except_clause_ordering): a smaller
# level is a wider class. Step 19's meaning check catches drift between the two tables.
_EXC_LEVELS: dict[str, int] = {
    'BaseException': -1, 'Exception': 0,
    'ArithmeticError': 1, 'LookupError': 1, 'OSError': 1,
    'ValueError': 2, 'TypeError': 2, 'KeyError': 2, 'IndexError': 2, 'AttributeError': 2, 'RuntimeError': 2,
    'IOError': 2, 'StopIteration': 2, 'StopAsyncIteration': 2, 'ImportError': 2,
    'FileNotFoundError': 3, 'PermissionError': 3, 'IsADirectoryError': 3, 'ZeroDivisionError': 3,
    'OverflowError': 3, 'FloatingPointError': 3, 'ModuleNotFoundError': 3, 'UnicodeError': 3,
    'ConnectionError': 3, 'TimeoutError': 3,
    'UnicodeDecodeError': 4, 'UnicodeEncodeError': 4,
}


def _handler_label(h: ast.ExceptHandler) -> str:
    return "except:" if h.type is None else f"except {h.type.id}:" if isinstance(h.type, ast.Name) else "except (...):"


def fix_except_ordering(broken_code: str) -> tuple[str, str]:
    """NAI-172: the handlers of a try whose adjacent pair catches a parent class before its child →
    the same handlers reordered so every child precedes its parent — a permutation of WHOLE handler
    blocks (each block's lines move together; the lines between blocks stay between). The set of
    exceptions caught is unchanged; by the rule's meaning a child exception now reaches the handler
    the dev wrote for it instead of the parent's. Handlers whose type is not a plain name in the
    detector's table (a tuple, an attribute, an unknown name) keep their place and are never crossed.
    Declines when a handler's `except` is not at the start of its own line or two handlers share a line."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    parts: list[str] = []
    tries = sorted((n for n in ast.walk(func) if isinstance(n, ast.Try) and len(n.handlers) > 1),
                   key=lambda t: t.lineno, reverse=True)  # bottom-up: earlier line indices stay valid
    for t in tries:
        hs = t.handlers
        levels = [(_EXC_LEVELS['BaseException'] if h.type is None
                   else _EXC_LEVELS.get(h.type.id) if isinstance(h.type, ast.Name) else None) for h in hs]
        order = list(range(len(hs)))
        changed = True
        while changed:
            changed = False
            for i in range(len(order) - 1):
                a, b = levels[order[i]], levels[order[i + 1]]
                if a is not None and b is not None and a < b:  # a wider class before a narrower one
                    order[i], order[i + 1] = order[i + 1], order[i]
                    changed = True
        if order == list(range(len(hs))):
            continue
        spans: list[tuple[int, int]] = []
        for h in hs:
            r0, r1 = h.lineno - 1, h.end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
            if r1 >= len(lines) or not lines[r0][pad + h.col_offset:].startswith("except"):
                return "", ""
            spans.append((r0, r1))
        if any(spans[k][1] >= spans[k + 1][0] for k in range(len(spans) - 1)):
            return "", ""
        blocks = [lines[r0:r1 + 1] for r0, r1 in spans]
        gaps = [lines[spans[k][1] + 1:spans[k + 1][0]] for k in range(len(spans) - 1)]
        new: list[str] = []
        for k, idx in enumerate(order):
            new += blocks[idx]
            if k < len(gaps):
                new += gaps[k]
        lines[spans[0][0]:spans[-1][1] + 1] = new
        parts.append(f"try at snippet line {t.lineno}: " + " / ".join(_handler_label(hs[i]) for i in range(len(hs)))
                     + " → " + " / ".join(_handler_label(hs[i]) for i in order))
    if not parts:
        return "", ""
    return "\n".join(lines), "; ".join(reversed(parts)) + " — a child exception now reaches its own handler; the set of exceptions caught is unchanged"


# ── NAI-071 / NAI-092 / NAI-093 (moved from knowledge_base.py, verbatim) ────

def fix_mutable_default(broken_code: str) -> tuple[str, str]:
    """NAI-071: `param=[]` / `{}` / `set()` (or `list()` / `dict()`) → `param=None`
    plus `if param is None: param = <same constructor>` as the first body
    statement (after the docstring). The body sees an equal, now per-call,
    value — the only behaviour that changes is the shared-mutable defect."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    args = func.args
    positional = args.posonlyargs + args.args
    pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
    pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
    targets = []
    for arg, default in pairs:
        ctor = None
        if isinstance(default, ast.List) and not default.elts:
            ctor = "[]"
        elif isinstance(default, ast.Dict) and not default.keys:
            ctor = "{}"
        elif (isinstance(default, ast.Call) and isinstance(default.func, ast.Name)
              and default.func.id in ("set", "list", "dict")
              and not default.args and not default.keywords):
            ctor = f"{default.func.id}()"
        if ctor and default.lineno == default.end_lineno:
            targets.append((arg.arg, default, ctor))
    if not targets:
        return "", ""
    lines = broken_code.splitlines()
    head = head_insert_stmt(func, lines, pad)   # R1: the shared after-the-docstring, own-row insertion point
    if head is None:
        return "", ""  # one-line def, empty body, or a first statement sharing its row — leave it alone
    first = lines[head.lineno - 1]
    indent = first[:len(first) - len(first.lstrip())]
    # Edit defaults right-to-left so earlier column offsets stay valid.
    for name, default, ctor in sorted(targets, key=lambda t: (t[1].lineno, t[1].col_offset), reverse=True):
        row = default.lineno - 1
        s, e = pad + default.col_offset, pad + default.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        lines[row] = lines[row][:s] + "None" + lines[row][e:]
    guards = []
    for name, _default, ctor in targets:
        guards += [f"{indent}if {name} is None:", f"{indent}    {name} = {ctor}"]
    lines[head.lineno - 1:head.lineno - 1] = guards
    what = "; ".join(f"`{name}={ctor}` → `{name}=None` with `if {name} is None: {name} = {ctor}` "
                     f"as the first statement" for name, _d, ctor in targets)
    return "\n".join(lines), what


def fix_unsafe_subprocess(broken_code: str) -> tuple[str, str]:
    """NAI-092: `subprocess.<run|call|check_call|check_output|Popen>("<literal>",
    shell=True, …)` whose command is ONE string literal using no shell syntax →
    the same call with the literal split into an argv list and `shell=True`
    removed. Equivalent by construction — no shell feature was in use.
    os.system(), non-literal commands and commands with shell metacharacters
    are not rewritten (that would be a guess)."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    for node in ast.walk(func):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                and node.func.attr in ("run", "call", "check_call", "check_output", "Popen")):
            continue
        shell_kw = next((kw for kw in node.keywords
                         if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True), None)
        if shell_kw is None or not node.args or node.lineno != node.end_lineno:
            continue
        cmd = node.args[0]
        if not (isinstance(cmd, ast.Constant) and isinstance(cmd.value, str)):
            continue
        if not cmd.value.strip() or any(ch in _SHELL_META for ch in cmd.value):
            continue
        argv = cmd.value.split()
        row = node.lineno - 1
        line = lines[row]
        s, e = pad + shell_kw.col_offset, pad + shell_kw.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        before = line[:s].rstrip()
        if not before.endswith(","):
            continue
        line = before[:-1].rstrip() + line[e:]
        s2, e2 = pad + cmd.col_offset, pad + cmd.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        line = line[:s2] + repr(argv) + line[e2:]
        lines[row] = line
        what = (f"`subprocess.{node.func.attr}({cmd.value!r}, shell=True)` → "
                f"`subprocess.{node.func.attr}({argv!r})` — argv list, no shell")
        return "\n".join(lines), what
    return "", ""


def fix_unsafe_deserialization(broken_code: str) -> tuple[str, str]:
    """NAI-093: `yaml.load(x)` with no Loader → `yaml.safe_load(x)`. PyYAML ≥ 6
    refuses the Loader-less call outright, so safe_load is the working
    equivalent for data documents. pickle has no safe equivalent that keeps the
    program's semantics — not rewritten."""
    func = func_node(broken_code)
    if not func:
        return "", ""
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    for node in ast.walk(func):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml"
                and node.func.attr == "load"):
            continue
        if any(kw.arg == "Loader" for kw in node.keywords) or len(node.args) > 1:
            continue
        f = node.func
        if f.lineno != f.end_lineno:
            continue
        row = f.lineno - 1
        s, e = pad + f.col_offset, pad + f.end_col_offset  # type: ignore[operator]  # FIX_54 ast-pos
        lines[row] = lines[row][:s] + "yaml.safe_load" + lines[row][e:]
        return "\n".join(lines), f"`yaml.load(...)` (snippet line {f.lineno}) → `yaml.safe_load(...)`"
    return "", ""


_SRC = "no_aivalidator/detection/safety_checks.py"


# ── FIX_43 (b) finite-set rewriters (2026-09-16, app copy 3): every candidate offered, the Ranker decides ──
_H43 = "FIX_43 (b) (2026-09-16, app copy 3)"


def _binds(func: Node, name: str) -> bool:
    """True when the function itself binds `name` (a parameter, an assignment target, an import alias,
    a with/except alias) — an inserted `import logging` would then shadow something of the unit's own."""
    for n in ast.walk(func):
        if isinstance(n, ast.arg) and n.arg == name:
            return True
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id == name:
            return True
        if isinstance(n, ast.ExceptHandler) and n.name == name:
            return True
        if isinstance(n, (ast.Import, ast.ImportFrom)) and any((a.asname or a.name.split(".")[0]) == name for a in n.names):
            return True
    return False


def _broad_handler(h: Node) -> bool:
    """A handler whose catch set is everything: bare `except:` or `except BaseException:`."""
    return h.type is None or (isinstance(h.type, ast.Name) and h.type.id == "BaseException")


def fix_fallback_return(broken_code: str) -> list[Variant]:
    """NAI-078 (finite set), the `fallback_return` shape: an except block whose only statement returns a literal /
    collection.

    FIX_61 (b) (owner Part C ×2 + rows #57 #75, 2026-09-17): the earlier candidates `re_raise` and `raise_named`
    are RETIRED. A documented fallback may not be turned into a raise by an unattended rewriter — value-vs-raise
    is an intent change and belongs to the client (the shape lane); G0's `fallback_to_raise` withheld both of
    them, which left an NAI-078 row with no fix at all. What the detector actually measures
    (`_check_silent_error_swallowing`) is a handler that returns a dummy value and keeps NO record of the error
    it swallowed, so the behaviour-preserving repairs are:

      `log_and_return`  the return is untouched; the handler gains `logging.getLogger(__name__).debug(...,
                        exc_info=True)` before it. The error stops being invisible — and at DEBUG nothing is
                        emitted unless the application configures logging (logging's own last-resort handler
                        starts at WARNING), so what the caller and the terminal see is unchanged.
      `narrow_and_log`  offered ONLY when a handler's catch set is everything (bare `except:` /
                        `except BaseException:`): that handler narrows to `except Exception:` — NAI-070's own
                        "Should be" — and the log is added. The fallback still answers for every error the body
                        can raise; KeyboardInterrupt / SystemExit / GeneratorExit propagate.

    Narrowing to the exact exception types the body can raise needs the call graph, not this span, so that
    remains the client's call. Declines when the unit binds the name `logging` itself. The `bare_pass` shape
    (`except: pass`) is NAI-017's — declined here."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    hits = [h for h in ast.walk(func) if isinstance(h, ast.ExceptHandler) and len(h.body) == 1
            and isinstance(h.body[0], ast.Return) and isinstance(h.body[0].value, (ast.Constant, ast.List, ast.Dict, ast.Tuple, ast.Set))]
    if not hits or not all(single_line(h.body[0]) and (h.type is None or single_line(h.type)) for h in hits):
        return []
    if not whole_rows(lines, [h.body[0] for h in hits]):
        return []
    if _binds(func, "logging"):
        return []                      # the unit owns that name; the inserted import would shadow it
    ordered = sorted(hits, key=lambda x: x.lineno, reverse=True)
    broad = [h for h in hits if _broad_handler(h)]

    def _log_into(ls: list[str], h: Node) -> bool:
        r = h.body[0].lineno - 1
        if r <= h.lineno - 1 or not ls[r].strip():
            return False               # the return must be on a row of its own, under its handler
        ind = " " * indent(ls[r])
        ls.insert(r, f'{ind}logging.getLogger(__name__).debug("{func.name}: error swallowed, returning the fallback", exc_info=True)')
        ls.insert(r, f"{ind}import logging")
        return True

    def _narrow(ls: list[str], h: Node) -> bool:
        r = h.lineno - 1
        if h.type is None:
            m = _BARE_EXCEPT.match(ls[r], pad + h.col_offset)
            if m is None:
                return False
            replace_cols(ls, r, m.start(), m.end(), "except Exception:")
            return True
        return replace_node(ls, h.type, pad, "Exception")

    def log_and_return(ls: list[str]) -> bool:
        return all(_log_into(ls, h) for h in ordered)

    def narrow_and_log(ls: list[str]) -> bool:
        for h in ordered:
            if not _log_into(ls, h):
                return False
            if _broad_handler(h) and not _narrow(ls, h):
                return False
        return True

    where = ", ".join(f"`{node_text(lines, h.body[0], pad)}` (line {h.body[0].lineno})" for h in hits)
    out = []
    v = edited(lines, log_and_return)
    if v is not None:
        out.append(("log_and_return", v, f"fallback {where} kept exactly as it is, with `logging.getLogger(__name__).debug(..., exc_info=True)` inserted before it — the swallowed error is recorded with its traceback instead of vanishing, and at DEBUG nothing is emitted unless the application configures logging, so the caller sees the same value it always saw (NAI-078)"))
    if broad:
        v = edited(lines, narrow_and_log)
        if v is not None:
            heads = ", ".join(f"`{'except:' if h.type is None else 'except BaseException:'}` (line {h.lineno})" for h in broad)
            out.append(("narrow_and_log", v, f"fallback {where} kept and logged as above, and {heads} narrowed to `except Exception:` — the fallback still answers for every error the body can raise, while KeyboardInterrupt / SystemExit / GeneratorExit propagate (NAI-078)"))
    return finish(out)


_MUTATING = {"append", "extend", "insert", "pop", "remove", "clear", "update", "add", "discard"}


def _identity_tested(func: Node, params: list[str]) -> str:
    """The parameter an `is` / `is not` comparison or an `id(...)` call in the unit tests — a unit that asks
    whether it was handed THAT object treats the caller's object itself as the contract (owner's condition 3)."""
    for n in ast.walk(func):
        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.Is, ast.IsNot)) for o in n.ops):
            for side in [n.left] + list(n.comparators):
                if isinstance(side, ast.Name) and side.id in params:
                    return side.id
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "id":
            for a in n.args:
                if isinstance(a, ast.Name) and a.id in params:
                    return a.id
    return ""


def fix_param_mutation(broken_code: str) -> list[Variant]:
    """NAI-091 (finite set): a parameter mutated in place with another parameter's value (`param[key] = value`,
    `param.append(value)`, `param += [...]`). Candidates: `shallow_copy` (`param = param.copy()` as the first
    statement — the caller's object is untouched, the function works on its own copy) and, when the function returns
    no value anywhere, `shallow_copy_returned` (the copy, and `return param` at the end so the caller receives the
    result it used to see in place). Declines a mutation reached through a loop iterator, or a param rebound before it.

    FIX_58 (owner's ruling 3, 2026-09-17 — rows #35 `push`, #71 `mark_twice`): the shallow copy is applicable only
    when ALL THREE hold, and the rewriter offers nothing when any of them fails —
      (1) the parameter is mutated (the detector's own observation, re-established above);
      (2) the function ALREADY returns that collection (→ `shallow_copy`), or the copy is added AND returned
          (→ `shallow_copy_returned`, which is only offered when the function returns no value anywhere, so the
          added return cannot shadow one);
      (3) nothing in the unit treats the in-place mutation as its contract — no `push` / `mark_*` / `append_to` /
          `add_*` / `extend_*` name (`gate.INPLACE_CONTRACT`, the owner's list), and no identity test on an
          argument. Condition (3) is a property of the UNIT, not of one variant, so it withholds both: copying
          `push`'s list and returning it leaves the caller's list empty just as surely as copying it silently.
    Otherwise the row goes to the shape lane — "return the copy" is the client's call, never this variant alone."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    params = [a.arg for a in func.args.args if a.arg not in ("self", "cls")]
    if not params:
        return []
    bare = lambda x: isinstance(x, ast.Name) and x.id in params
    target: str | None = None
    site = 0
    for n in ast.walk(func):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and bare(t.value) and bare(t.slice):
                    target, site = t.value.id, n.lineno  # type: ignore[attr-defined]  # FIX_54 ast-pos
        elif isinstance(n, ast.AugAssign) and bare(n.target) and isinstance(n.op, (ast.Add, ast.BitOr)):
            rhs = n.value
            # R1 (2026-09-30): a tuple / frozenset right-hand side is no evidence of an in-place change — `p += (x,)`
            # REBINDS an immutable p, and the `p.copy()` this rewriter inserts raises AttributeError on a tuple.
            if isinstance(rhs, (ast.List, ast.Set, ast.Dict)) or (isinstance(rhs, ast.Call) and isinstance(rhs.func, ast.Name) and rhs.func.id in ("list", "set", "dict")):
                target, site = n.target.id, n.lineno  # type: ignore[union-attr]  # FIX_54 ast-pos
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _MUTATING and bare(n.func.value):
            if any(bare(a) for a in list(n.args) + [k.value for k in n.keywords]):
                target, site = n.func.value.id, n.lineno  # type: ignore[attr-defined]  # FIX_54 ast-pos
        if target:
            break
    if not target:
        return []
    if any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == target for t in n.targets) and n.lineno < site for n in ast.walk(func)):
        return []
    # FIX_58 condition (3) — the unit's contract IS the in-place mutation: neither variant applies.
    if INPLACE_CONTRACT.match(func.name) or _identity_tested(func, params):
        return []
    # FIX_58 condition (2) — `shallow_copy` alone needs the collection to be returned already.
    returns_target = any(isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and n.value.id == target
                         for n in ast.walk(func))
    # R1 (2026-09-30): the copy goes after the docstring, on a row of its own — never above the docstring,
    # and never for a one-line def (the old `else body[0]` fallback put it above the `def` line itself).
    first = head_insert_stmt(func, lines, pad)
    if first is None:
        return []
    r0 = first.lineno - 1
    ind = " " * indent(lines[r0])
    returns_value = any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(func))

    def copy(ls: list[str]) -> bool:
        ls.insert(r0, f"{ind}{target} = {target}.copy()")
        return True

    def copy_returned(ls: list[str]) -> bool:
        ls.insert(r0, f"{ind}{target} = {target}.copy()")
        ls.insert(func.end_lineno, f"{ind}return {target}")
        return True

    out = []
    if returns_target:
        v = edited(lines, copy)
        if v is not None:
            out.append(("shallow_copy", v, f"`{target}` is mutated in place at snippet line {site} with another parameter's value and is returned by this function — `{target} = {target}.copy()` as the first statement; the caller's object is untouched and the caller still receives the mutated collection (NAI-091)"))
    if not returns_value:
        v = edited(lines, copy_returned)
        if v is not None:
            out.append(("shallow_copy_returned", v, f"`{target}` is mutated in place at snippet line {site} — copied first and returned at the end, so the caller receives the result it used to see in place (NAI-091)"))
    return finish(out)


# ── FIX_58: the predicate beside the variant (lane contract 1) ─────────────────────────────────────
# G0 already carries the owner's ruling for `shallow_copy`. `shallow_copy_returned` is the second half
# of condition (2) — it ADDS the return, so "never returned" is not its test — but condition (3) is a
# property of the unit and binds it too: on a `push` / `add_*` / `mark_*` name, or where the unit tests
# the argument's identity, no copy of the parameter is a repair. The source declines both above; this
# is the same sentence said at the publish point, for a rewrite that reaches the gate any other way.

@_predicate("NAI-091", "shallow_copy_returned")
def _nai091_copy_returned(rw: _Rewrite, before: ast.AST, after: ast.AST) -> "str | None":
    f = next((n for n in ast.walk(before) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if f is None:
        return None
    if INPLACE_CONTRACT.match(f.name):
        return (f"gate: `{f.name}` says in-place mutation IS the contract — a copy returned to the "
                f"caller leaves the object it handed in untouched; mutate-vs-copy is the same test.")
    who = _identity_tested(f, [a.arg for a in f.args.args if a.arg not in ("self", "cls")])
    if who:
        return (f"gate: this unit tests `{who}`'s identity — it is the caller's object that matters "
                f"here, and a copy is a different object.")
    return None


def fix_return_in_finally(broken_code: str) -> list[Variant]:
    """NAI-173 (finite set): a `return` that is a direct statement of a `finally` block (it overrides every exception
    and every return of the try). Candidates: `after_try` (the return moved to follow the whole try statement — the
    try's own returns and exceptions win, this value is the fall-through) and `drop_return` (the return deleted; a
    finally left empty is dropped when handlers exist, else becomes `pass`). Declines a return nested deeper in the
    finally, or one sharing its row."""
    p = prep(broken_code)
    if not p:
        return []
    func, pad, lines = p
    for t in ast.walk(func):
        if not (isinstance(t, ast.Try) and t.finalbody):
            continue
        ret = next((s for s in t.finalbody if isinstance(s, ast.Return)), None)
        if ret is None:
            if any(isinstance(x, ast.Return) for s in t.finalbody for x in ast.walk(s)):
                return []
            continue
        if not whole_rows(lines, list(t.finalbody)):
            return []
        f0, f1 = t.finalbody[0].lineno - 1, t.finalbody[-1].end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
        prev_end = (t.handlers[-1].body[-1] if t.handlers and not t.orelse else t.orelse[-1] if t.orelse else t.body[-1]).end_lineno - 1  # type: ignore[operator]  # FIX_54 ast-pos
        fin_row = keyword_row(lines, prev_end, f0, "finally")
        if fin_row is None:
            return []
        ra, rb = rows(ret)
        only = len(t.finalbody) == 1
        try_ind = " " * indent(lines[t.lineno - 1])
        ret_text = [lines[r] for r in range(ra, rb + 1)]

        def remove(ls: list[str]) -> None:
            if only and t.handlers:
                delete_rows(ls, fin_row, f1)
            elif only:
                delete_rows(ls, ra, rb)
                ls.insert(ra, " " * indent(lines[ra]) + "pass")
            else:
                delete_rows(ls, ra, rb)

        def after(ls: list[str]) -> bool:
            end = t.end_lineno  # row index just after the try statement (0-based end row + 1)
            remove(ls)
            shift = (f1 - fin_row + 1) if (only and t.handlers) else (rb - ra + 1) - (1 if only and not t.handlers else 0)
            at = end - shift  # type: ignore[operator]  # FIX_54 ast-pos
            delta = indent(ret_text[0]) - len(try_ind)
            for i, line in enumerate(ret_text):
                ls.insert(at + i, line[delta:] if line.strip() and delta > 0 else line)
            return True

        def drop(ls: list[str]) -> bool:
            remove(ls)
            return True

        rt = node_text(lines, ret, pad) or "return"
        out = []
        v = edited(lines, after)
        if v is not None:
            out.append(("after_try", v, f"`{rt}` (snippet line {ret.lineno}) moved out of the finally block to follow the try statement — the try's own return value and any exception win; this value is the fall-through (NAI-173)"))
        v = edited(lines, drop)
        if v is not None:
            out.append(("drop_return", v, f"`{rt}` (snippet line {ret.lineno}) deleted from the finally block — the try's own return value and any exception propagate (NAI-173)"))
        return finish(out)
    return []


# ── NAI-094's two families (R4, owner ruling 2026-09-21, run 164) ─────────────────────────────
# NAI-094's DETECTOR covers two families — a `sys.path` write and an `os.environ` write — and
# session 8's T1 found the second live at click `testing.py:574` while the prescription below was
# `sys.path`-shaped only: an `os.environ` fire was handed "delete the sys.path line and import
# through the package", a sentence about a statement that is not on the row. R4: the detector is
# the spec, so the prescription follows it family by family. Nothing here widens the detector.
#
# What the detector accepts as CLEAN (measured, both halves — the table `nai094_entry_proof`
# part 6 runs): every NON-MUTATING shape of the same object. For `os.environ` that is
# `os.environ.get(k)`, `os.environ.get(k, d)`, `os.getenv(k)`, `os.getenv(k, d)` — `os.getenv`
# IS `environ.get`, the same callable under another name, not a second shape — `k in os.environ`
# and a subscript READ `os.environ[k]`; for `sys.path`, any read (`list(sys.path)`, `sys.path[0]`)
# and the absence of the statement. They are not contradictory verdicts: the predicate measures
# the WRITE and never looks at a read, so all of them are the one verdict `no write`.
#
# The prescription is locked to ONE of them per family, and the choice is the detector's own fire
# case read backwards, not taste:
#   os.environ  ->  `os.environ.get(KEY, VALUE)` — same object, same API, the value the write was
#                   installing becomes the EXPLICIT DEFAULT, so a missing key yields exactly what
#                   the write guaranteed and nothing raises at import time. It is the one read
#                   that serves all three environ fires (`[k] = v`, `[k] += v`, `setdefault`,
#                   `update`). A bare subscript READ is refused: its missing-key behaviour is a
#                   KeyError at import time, which is NOT what the write left behind, and it is
#                   the detector's own fire case one `ctx` away. `__contains__` is refused: it
#                   yields a bool, not the value the write installed.
#   sys.path    ->  the line is DELETED and the import is made resolvable by packaging. (Unchanged
#                   — FIX_41's own sentence, now reached only by a `sys.path` fire.)
_NAI094_SYSPATH_TEXT = ('Delete the sys.path line and make the import resolvable by packaging — an installed '
                        'package (pyproject) or a relative import inside the package — for the module the hack '
                        'pointed at.')
_NAI094_SYSPATH_SHAPE = ('# delete: sys.path.insert(0, ...)\n'
                         'from <package>.<module> import <name>   # resolvable through the package, not the path hack')
_NAI094_ENVIRON_TEXT = ('Delete the os.environ write: the process environment must not be changed at import '
                        'time. Read the variable where it is used instead, with the value the write was '
                        'installing as the explicit default — os.environ.get(<KEY>, <value>) — so a missing key '
                        'still yields that value and nothing raises.')
_NAI094_ENVIRON_SHAPE = ("# delete: os.environ['<KEY>'] = <value>\n"
                         "<NAME> = os.environ.get('<KEY>', <value>)   # a read, never a write at import time; "
                         "missing key -> <value>")


def _nai094_family(broken_code: str, failure_reason: str) -> str:
    """Which of NAI-094's two families FIRED, read off the detector's own words.

    Both halves name the family literally: the module-scope half writes `Module-level
    os.environ[...] = at line N — …` / `Module-level sys.path.insert() at line N — …`, and the
    per-function half is rendered by `_format_observation` as `NAI-094 (line N):
    manipulation_target=os.environ, method=subscript_assignment`. The failure reason is read
    FIRST because it names exactly one family; the code is the fallback, and a body that holds
    both writes is classified by whichever the detector's own walk would reach first (`sys.path`,
    the family checked first in both halves). "" = neither could be read.
    """
    for hay in (failure_reason or "", broken_code or ""):
        has_env = "os.environ" in hay
        has_path = "sys.path" in hay
        if has_path and not has_env:
            return "sys.path"
        if has_env and not has_path:
            return "os.environ"
        if has_env and has_path:
            return "sys.path"
    return ""


def _nai094_environ_tokens(broken_code: str) -> tuple:
    """(key, value) of the environ write, when the fire case is on the row in readable form.

    A module-scope NAI-094 row carries NO body (`before_code` is "" — BUILDER_DAEMON's own line),
    so this returns ("", "") there and the shape keeps its `<KEY>` / `<value>` placeholders. When
    the body IS on the row, the tokens are the write's own — never invented, never renamed.
    """
    src = textwrap.dedent(broken_code or "")
    if not src.strip():
        return "", ""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return "", ""
    def _env_subscript(expr: Any) -> bool:
        return (isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Attribute)
                and expr.value.attr == "environ" and isinstance(expr.value.value, ast.Name)
                and expr.value.value.id == "os")

    for node in ast.walk(tree):
        written: list = []
        if isinstance(node, ast.Assign):
            written = [(t, node.value) for t in node.targets]
        elif isinstance(node, ast.AugAssign):
            written = [(node.target, node.value)]
        for tgt, val in written:
            if _env_subscript(tgt) and val is not None:
                try:
                    return ast.unparse(tgt.slice), ast.unparse(val)
                except Exception:
                    return "", ""
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setdefault" and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "os"):
            # `setdefault(KEY, DEFAULT)`: the pair is the first argument and the one after it.
            # Walked as a pair rather than indexed or counted, so the shape carries no number
            # for step 17 to read as a ranking (no pre-ranker arithmetic anywhere in the engine).
            previous: Any = None
            for arg in node.args:
                if previous is not None:
                    try:
                        return ast.unparse(previous), ast.unparse(arg)
                    except Exception:
                        return "", ""
                previous = arg
    return "", ""


def nai094_prescription(broken_code: str = "", failure_reason: str = "") -> tuple:
    """R4: NAI-094's (text, shape) for the family that FIRED — never the other family's.

    The `sys.path` family keeps FIX_41's sentence unchanged. The `os.environ` family gets the
    clean shape the detector already accepts, with the write's own key and value filled in when
    the row carries them. A fire whose family cannot be read off its own words gets the ROW's
    default (the registry's `text` / `shape`, i.e. the `sys.path` sentence) — the pre-R4
    behaviour, and the only case in which it is still reached.
    """
    fam = _nai094_family(broken_code, failure_reason)
    if fam == "os.environ":
        key, value = _nai094_environ_tokens(broken_code)
        if not key or not value:
            return _NAI094_ENVIRON_TEXT, _NAI094_ENVIRON_SHAPE
        # The bound name is the ENV VAR'S OWN NAME, and only when the key is a string literal
        # that spells one. A key that is an EXPRESSION (`os.environ[key] = value` in a loop, click
        # `testing.py:574`) is given the READ ITSELF, unbound: binding `key = os.environ.get(key,
        # value)` would rebind the caller's own variable, which is a rename, and the prescription
        # renames nothing.
        #
        # RUN 164, LAUNCH A — why the unbound read is emitted and not a `<NAME>` placeholder. A
        # client renders a shape by writing its concrete lines and leaving an unfilled
        # `<placeholder>` line to the dev (FIX_41: a shape is a template, not Python). At
        # `testing.py:574` the write is the WHOLE BODY of an `else:`, so leaving that line out
        # left the block empty and the file did not parse — and the rescan then read the row as
        # silent for the wrong reason. Every line the `os.environ` family emits is therefore
        # CONCRETE: the shape a client applies is always a statement.
        quoted = key.startswith(("'", '"')) and key.endswith(("'", '"'))
        inner = key[1:-1] if quoted else ""
        read = f"os.environ.get({key}, {value})"
        line = f"{inner} = {read}" if inner.isidentifier() else read
        return _NAI094_ENVIRON_TEXT, (
            f"# NAI-094: the os.environ write on this line is deleted — read the variable, "
            f"never write it\n"
            f"{line}   # missing key -> {value}, the value the write was installing")
    return _NAI094_SYSPATH_TEXT, _NAI094_SYSPATH_SHAPE


GENERATORS = [
    rewriter("NAI-070", f"{_SRC}:_check_bare_except", "bare_except_fix", fix_bare_except,
             reason="the detector's own 'Should be: except Exception:'; declines when the handler re-raises "
                    "(cleanup idiom) or the `except:` token is not on the handler's line"),
    rewriter("NAI-071", f"{_SRC}:_check_mutable_default_arg", "mutable_default_fix", fix_mutable_default,
             reason="param=<empty mutable> → None + first-statement guard; the body sees an equal per-call value",
             dated="2026-09-05", by="plan item 5 (2026-09-05); moved here item 4 (2026-09-08)"),
    rewriter("NAI-092", f"{_SRC}:_check_unsafe_subprocess", "subprocess_argv_fix", fix_unsafe_subprocess,
             reason="one literal command with no shell metacharacter → argv list, shell=True dropped; nothing else rewritten",
             dated="2026-09-05", by="plan item 5 (2026-09-05); moved here item 4 (2026-09-08)"),
    rewriter("NAI-093", f"{_SRC}:_check_unsafe_deserialization", "yaml_safe_load_fix", fix_unsafe_deserialization,
             reason="Loader-less yaml.load → yaml.safe_load (PyYAML ≥ 6 refuses the former); pickle is not rewritten",
             dated="2026-09-05", by="plan item 5 (2026-09-05); moved here item 4 (2026-09-08)"),
    # NAI-076: prescribed row retired 2026-10-08 — owner ruled the rule context (calibration M-121); a context id never fails a function, so it has no repair.
    rewriter("NAI-078", f"{_SRC}:_check_silent_error_swallowing", "fallback_return_fix", fix_fallback_return,
             reason="finite set — an except block that only returns a literal fallback: `log_and_return` (the return untouched, `logging.getLogger(__name__).debug(..., exc_info=True)` inserted before it, so the swallowed error is recorded and nothing is emitted unless the application configures logging) and, for a handler that catches everything, `narrow_and_log` (the same log, and the bare / BaseException handler narrowed to `except Exception:`); every candidate offered, the Ranker decides. FIX_61 (b) (owner Part C ×2 + row #75, 2026-09-17) RETIRED `re_raise` / `raise_named`: a documented fallback may not be turned into a raise unattended — value-vs-raise is the client's call. The `except: pass` shape is NAI-017's",
             dated="2026-09-17", by="FIX_61 (b) (owner Part C ×2 + row #75, 2026-09-17)"),
    # R4 (owner 2026-09-21, run 164): the row's default text / shape are the `sys.path` family's
    # — FIX_41's sentence, unchanged — and `shape_for` hands an `os.environ` fire the `os.environ`
    # family's instead. Before R4 there was one sentence for two families and click
    # `testing.py:574` (an `os.environ[key] = value`) was told to delete a sys.path line.
    prescribed('NAI-094', f"{_SRC}:_check_sys_path_manipulation", _NAI094_SYSPATH_TEXT,
               _NAI094_SYSPATH_SHAPE, shape_for=nai094_prescription),
    # unbuilt — 29 ids of this family with no generator yet (item 4 first batch, 2026-09-08)
    prescribed('NAI-072', "no_aivalidator/detection/safety_checks.py:_check_hardcoded_secrets", "Read the secret from the environment variable (or the secret store) the intent's external systems name, and fail loudly when it is absent; the literal never stays in code.",
               "<NAME> = os.environ.get('<ENV_NAME>')\nif not <NAME>:\n    raise RuntimeError('<ENV_NAME> is not set')"),
    prescribed('NAI-073', "no_aivalidator/detection/safety_checks.py:_check_sql_injection_risk", "Parametrise the statement with the driver's placeholders and pass the values as the execute call's second argument; no interpolated value stays in the query text.",
               "cursor.execute('<SELECT ... WHERE <col> = %s>', (<value>,))   # placeholder style per the driver: %s / ? / :name"),
    prescribed('NAI-074', "no_aivalidator/detection/safety_checks.py:_check_unguarded_json_parse", "Wrap the json.load(s) call in try/except json.JSONDecodeError and do what the intent's expected output says for malformed input: return the documented fallback or raise the module's own error naming the source.",
               "try:\n    data = json.loads(<text>)\nexcept json.JSONDecodeError as e:\n    <return <fallback> | raise <ModuleError>(f'<source>: {e}') from e>"),
    rewriter("NAI-075", "no_aivalidator/detection/safety_checks.py:_check_unguarded_file_ops", "open_with_fix", fix_unguarded_open,
             "`name = open(...)` closed by a plain `name.close()` later in the same block → `with open(...) as name:` over the statements between, the close dropped; the normal path closes at the same point, every other exit path now closes too; declines a handle never closed, closed elsewhere, returned or stored (set 4b-07, 2026-09-10)",
             "2026-09-10", "set 4b-07 (2026-09-10)"),
    prescribed('NAI-077', "no_aivalidator/detection/safety_checks.py:_check_unguarded_dict_access", "Replace d[key] with the access the contract implies: d.get(key, <documented default>) when a missing key is normal, or a membership check whose else-arm raises the module's error naming the key when it is not.",
               "value = d.get(<key>, <default from the intent>)\n# or\nif <key> not in d:\n    raise KeyError(f'<what> missing: {<key>}')\nvalue = d[<key>]"),
    prescribed('NAI-079', "no_aivalidator/detection/safety_checks.py:_check_hardcoded_paths", 'Take the path from where the intent says it comes — a parameter, a config key, an environment variable or a package resource (importlib.resources) — never an absolute or climbing literal.',
               "path = Path(<parameter | config['<key>'] | os.environ['<VAR>'] | importlib.resources.files(__package__) / '<name>'>)"),
    rewriter("NAI-091", "no_aivalidator/detection/safety_checks.py:_check_inplace_param_mutation", "param_mutation_fix", fix_param_mutation,
             reason="finite set — a parameter mutated in place with another parameter's value: `param = param.copy()` first (`shallow_copy`) or, for a function returning no value, the copy plus `return param` (`shallow_copy_returned`); every candidate offered, the Ranker decides; a deep copy needs an import the snippet cannot carry",
             dated="2026-09-16", by=_H43),
    prescribed('NAI-095', "no_aivalidator/detection/safety_checks.py:_check_float_equality", "Compare with a tolerance the domain sets: math.isclose(a, b, rel_tol=<r>, abs_tol=<a>) with the tolerance from the module's own constant or the intent's precision, not a default.",
               'if math.isclose(<a>, <b>, rel_tol=<REL_TOL>, abs_tol=<ABS_TOL>):'),
    rewriter("NAI-096", "no_aivalidator/detection/safety_checks.py:_check_assert_for_validation", "assert_guard_fix", fix_assert_validation,
             "first-statement `assert <test>[, <msg>]` on a parameter → `if not (<test>): raise AssertionError(<msg>)` — the same exception and message with assertions on, and the check now runs under python -O (the rule's meaning); declines a multi-line assert or a line holding anything else (set 4b-08, 2026-09-10)",
             "2026-09-10", "set 4b-08 (2026-09-10)"),
    prescribed('NAI-098', "no_aivalidator/detection/safety_checks.py:_check_print_only_output", "Return the value the function computes (the text, structure or status the intent's expected output names) and leave printing to the caller or the entry point.",
               'def <name>(...):\n    result = <computed value>\n    return result   # the entry point prints'),
    prescribed('NAI-152', "no_aivalidator/detection/safety_checks.py:_check_mutable_class_level_variables", 'Make the container instance-owned: assign a fresh list / dict / set in __init__ and mutate it through self; keep it at class level only when the intent says every instance shares it.',
               'def __init__(self, ...):\n    self.<name> = []   # or {} / set()'),
    prescribed('NAI-158', "no_aivalidator/detection/safety_checks.py:_check_missing_input_validation_extended", 'Validate the boundary parameter before the sink against the contract the intent gives it (type, pattern, allow-list, path inside the root) and raise ValueError naming the parameter when it fails.',
               "if not <check(<param>)>:\n    raise ValueError(f'<param>: <what was expected>')\n<sink>(<param>)"),
    rewriter("NAI-159", "no_aivalidator/detection/safety_checks.py:_check_deprecated_api_usage", "deprecated_alias_fix", fix_deprecated_alias,
             "exact deprecated aliases renamed in place — logging.warn → logging.warning, assertEquals / assertNotEquals / assertRegexpMatches → assertEqual / assertNotEqual / assertRegex — the alias and the name are the same callable; declines every other entry of the detector's table (os.system, py2 iterators, collections ABCs), whose replacement is a different call (set 4b-09, 2026-09-10)",
             "2026-09-10", "set 4b-09 (2026-09-10)"),
    prescribed('NAI-160', "no_aivalidator/detection/safety_checks.py:_check_missing_input_validation", 'Validate the parameter before it reaches open / exec / system / execute — a path under the allowed root, a known command, a typed value per the intent — and raise on failure; never hand a raw parameter to the sink.',
               "if not <check(<param>)>:\n    raise ValueError(f'<param>: <what was expected>')\n<sink>(<param>)"),
    prescribed('NAI-161', "no_aivalidator/detection/safety_checks.py:_check_http_without_timeout", "Pass timeout= on every requests call, taken from the module's TIMEOUT constant or config, so the call gives up after the seconds the intent's external system allows.",
               'requests.<method>(<url>, ..., timeout=<TIMEOUT_SECONDS>)'),
    rewriter("NAI-162", "no_aivalidator/detection/safety_checks.py:_check_no_cert_validation", "verify_true_fix", fix_no_cert_validation,
             "`requests.<method>(..., verify=False)` → `verify=True` in place — the library's own default restored, no value chosen; the request is unchanged and, by the rule's meaning, the certificate is now validated (an untrusted peer fails the call instead of being accepted); declines a `False` token on a continuation line (set 4b-10, 2026-09-10)",
             "2026-09-10", "set 4b-10 (2026-09-10)"),
    prescribed('NAI-163', "no_aivalidator/detection/safety_checks.py:_check_hardcoded_bind_all", "Bind to the address the deployment names: read it from config or an environment variable with 127.0.0.1 as the default; '0.0.0.0' only when the intent's external systems require every interface.",
               "host = os.environ.get('<APP>_HOST', '127.0.0.1')"),
    prescribed('NAI-164', "no_aivalidator/detection/safety_checks.py:_check_insecure_temp_file", "Replace mktemp with tempfile.NamedTemporaryFile (or mkstemp) and use the file object / descriptor it returns for the file's whole lifetime, closing or deleting it when done.",
               "with tempfile.NamedTemporaryFile(delete=<bool>, suffix='<ext>') as tmp:\n    <use tmp.name / tmp.write(...)>"),
    prescribed('NAI-165', "no_aivalidator/detection/safety_checks.py:_check_trojan_source_bidi", 'Remove the bidi control characters and write the visible text the string is meant to carry; a right-to-left segment, if intended, is marked in data, not with control characters in source.',
               "<NAME> = '<the intended visible text — no U+202A..U+202E / U+2066..U+2069 controls>'"),
    rewriter("NAI-166", "no_aivalidator/detection/safety_checks.py:_check_raise_not_implemented", "not_implemented_error_fix", fix_raise_not_implemented,
             "`raise NotImplemented` → `raise NotImplementedError` in place — the detector's own 'should be'; the statement raised TypeError before (NotImplemented is the binary-operator singleton) and raises the intended exception after; the normal path is untouched; declines a name on a continuation line (set 4b-10, 2026-09-10)",
             "2026-09-10", "set 4b-10 (2026-09-10)"),
    prescribed('NAI-167', "no_aivalidator/detection/safety_checks.py:_check_environmental_context_blindness", "Take the endpoint from the environment variable the intent's external systems name for it and give the call the timeout / retry policy that system needs; no literal URL and no unbounded call.",
               "url = os.environ['<SERVICE>_URL']\nresp = requests.get(url, timeout=<TIMEOUT>)"),
    rewriter("NAI-172", "no_aivalidator/detection/safety_checks.py:_check_except_clause_ordering", "except_order_fix", fix_except_ordering,
             "the handlers of a try reordered so every child class precedes its parent — a permutation of whole handler blocks, the set of exceptions caught unchanged; by the rule's meaning a child exception now reaches the handler the dev wrote for it; handlers not in the detector's table keep their place and are never crossed; declines an `except` not at the start of its own line (set 4b-11, 2026-09-10)",
             "2026-09-10", "set 4b-11 (2026-09-10)"),
    rewriter("NAI-173", "no_aivalidator/detection/safety_checks.py:_check_return_in_finally", "return_in_finally_fix", fix_return_in_finally,
             reason="finite set — a return inside finally: moved to follow the try statement (`after_try`, the try's value and exceptions win) or deleted (`drop_return`); every candidate offered, the Ranker decides; the same row also fires NAI-143",
             dated="2026-09-16", by=_H43),
    prescribed('NAI-200', "no_aivalidator/detection/safety_checks.py:_check_risky_single_call", "Wrap the call (open, json / yaml load, import_module, csv reader, config getter) in try/except for its documented exception and do what the intent says for that failure: return the fallback or raise the module's error naming the source.",
               "try:\n    <result> = <call>\nexcept <ExpectedError> as e:\n    <return <fallback> | raise <ModuleError>(f'<source>: {e}') from e>"),
    # NAI-201: prescribed row retired 2026-10-08 — owner ruled the rule context (calibration M-121); a context id never fails a function, so it has no repair.
    prescribed('NAI-203', "no_aivalidator/detection/safety_checks.py:_check_lru_cache_on_side_effect", 'Separate the pure computation from the side effect: cache the computation in its own function and perform the print / write / send in the caller every time; the cache decorator comes off the effectful function.',
               '@lru_cache\ndef <compute>(...):\n    return <pure value>\n\ndef <name>(...):\n    value = <compute>(...)\n    <side effect with value>'),
    prescribed('NAI-204', "no_aivalidator/detection/safety_checks.py:_check_sync_calling_async", 'Make the function async and await the coroutine directly, with its caller awaiting it (the entry point runs asyncio.run once at the top level); no event loop started inside library code.',
               'async def <name>(...):\n    result = await <coroutine>(...)\n    return result'),
    prescribed('NAI-206', "no_aivalidator/detection/safety_checks.py:_check_cwd_sensitive_path", "Anchor the path to what it is meant against — the module's directory (Path(__file__).parent), a parameter or a config key; the launch directory only when the intent says the user's cwd is the base.",
               "base = Path(__file__).resolve().parent   # or Path(<param>) / config['<key>']\npath = base / '<relative>'"),
    prescribed('NAI-210', "no_aivalidator/detection/safety_checks.py:_check_threading_in_sync", "Run the work where the intent's runner puts it: submit it to a concurrent.futures executor (or the running event loop) and return the future / result, or run it inline when the caller waits anyway; no bare Thread from a sync function.",
               'with ThreadPoolExecutor() as pool:\n    future = pool.submit(<work>, <args>)\n    return future.result()'),
]
