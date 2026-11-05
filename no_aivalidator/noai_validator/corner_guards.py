"""corner_guards.py — the code itself says a value may be empty or missing, then uses it unguarded (M-148, 2026-10-08).

NAI-242 corner_crash (boundary_probes) is context: probing a function into a raise cannot tell a missing guard from a
deliberate raise. These two variants need no probe and carry no such doubt, because the SAME function supplies the
corner and then walks into it:
  defaulted_empty_indexed  `xs = payload.get("recipients", [])` (or `… or []`, or `[]` then filled conditionally)
                           followed by `xs[0]` / `xs[-1]` with no test of `xs` (truthiness, `len`, `in`, try/except
                           IndexError) anywhere before it in the function — the empty default it chose is an IndexError.
  get_none_deref           `g = store.get(key)` (one argument: None when absent) followed by `g.attr` / `g[...]` /
                           `g.method()` with no test of `g` (`if g`, `if g is None`, `if not g`, `assert g`, a
                           try/except) before it — the None it may receive is an AttributeError.
Per function, AST only, nothing executes. rule_dispositions.json makes these two variants deciding.
"""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Set

_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _own(fn: ast.AST) -> List[ast.AST]:
    out: List[ast.AST] = []
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        out.append(n)
        if not isinstance(n, _NESTED):
            stack.extend(ast.iter_child_nodes(n))
    return out


def _empty_default(v: ast.AST) -> bool:
    if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "get" and v.args[1:] and not v.args[2:]:
        d = v.args[1]
        return (isinstance(d, (ast.List, ast.Tuple)) and not d.elts) or \
               (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("list", "tuple") and not d.args)
    if isinstance(v, ast.BoolOp) and isinstance(v.op, ast.Or):
        last = v.values[-1]
        return isinstance(last, (ast.List, ast.Tuple)) and not last.elts
    return False


def _one_arg_get(v: ast.AST) -> bool:
    return (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "get"
            and bool(v.args) and not v.args[1:] and not v.keywords)


def _tests_value(t: ast.AST, name: str) -> bool:
    """`t` tests the VALUE of `name` itself: `name`, `not name`, `name is None` / `== …` / `in …`, `len(name)`,
    `bool(name)`, `isinstance(name, …)`, or an and/or of those. `getattr(name, "x", d)` is not one — it is safe on
    None but leaves every later `name.attr` unguarded."""
    if isinstance(t, ast.Name):
        return t.id == name
    if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not):
        return _tests_value(t.operand, name)
    if isinstance(t, ast.BoolOp):
        return any(_tests_value(v, name) for v in t.values)
    if isinstance(t, ast.Compare):
        return any(isinstance(x, ast.Name) and x.id == name for x in [t.left, *t.comparators]) or \
            any(_tests_value(x, name) for x in [t.left, *t.comparators] if isinstance(x, ast.Call))
    if isinstance(t, ast.Call) and isinstance(t.func, ast.Name) and t.func.id in ("len", "bool", "isinstance"):
        return any(isinstance(a, ast.Name) and a.id == name for a in t.args)
    return False


def _guard_lines(fn: ast.AST, name: str) -> List[int]:
    """Lines where the value of `name` is tested (if / while / assert / conditional expression), or a try with
    handlers that encloses its uses."""
    out: List[int] = []
    for n in _own(fn):
        if isinstance(n, (ast.If, ast.While, ast.IfExp, ast.Assert)) and _tests_value(n.test, name):
            out.append(n.lineno)
        elif isinstance(n, ast.Try) and n.handlers:
            out.extend(range(n.lineno, (n.end_lineno or n.lineno) + 1))
    return out


def _const_index(s: ast.Subscript) -> bool:
    i = s.slice
    if isinstance(i, ast.UnaryOp) and isinstance(i.op, ast.USub):
        i = i.operand
    return isinstance(i, ast.Constant) and isinstance(i.value, int) and not isinstance(i.value, bool)


def static_observations(functions: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for f in functions:
        fn = getattr(f, "node", f)
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        own = _own(fn)
        sources: Dict[str, tuple] = {}
        for n in own:
            if isinstance(n, ast.Assign) and not n.targets[1:] and isinstance(n.targets[0], ast.Name):
                if _empty_default(n.value):
                    sources[n.targets[0].id] = ("defaulted_empty_indexed", n.lineno)
                elif _one_arg_get(n.value):
                    sources[n.targets[0].id] = ("get_none_deref", n.lineno)
        if not sources:
            continue
        stores: Dict[str, List[int]] = {}
        for n in own:
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                stores.setdefault(n.id, []).append(n.lineno)
        found: Optional[Dict[str, Any]] = None
        for name, (variant, at) in sources.items():
            if [x for x in stores.get(name, []) if x != at]:
                continue   # bound somewhere else too — the default is not the only value used
            guards = [g for g in _guard_lines(fn, name)]
            uses: List[ast.expr] = []
            for n in own:
                if variant == "defaulted_empty_indexed" and isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load) \
                        and isinstance(n.value, ast.Name) and n.value.id == name and _const_index(n):
                    uses.append(n)
                elif variant == "get_none_deref" and isinstance(n, (ast.Attribute, ast.Subscript)) \
                        and isinstance(n.value, ast.Name) and n.value.id == name:
                    uses.append(n)
            uses = [u for u in uses if u.lineno > at and not any(at <= g <= u.lineno for g in guards)]
            if uses:
                u = min(uses, key=lambda x: x.lineno)
                what = (f"`{name}` defaults to empty (line {at}) and `{ast.unparse(u)}` reads it unguarded — an empty "
                        f"input raises IndexError; test `{name}` first") if variant == "defaulted_empty_indexed" else \
                       (f"`{name}` is `.get()` with no default (None when absent, line {at}) and `{ast.unparse(u)}` uses "
                        f"it unguarded — a missing key raises; test `{name}` first")
                found = {"tag": "NAI-242", "line": u.lineno, "lines": [at, u.lineno], "variant": variant,
                         "description": what}
                break
        if found:
            out[f"{fn.name}@{fn.lineno}"] = [found]
    return out
