"""Top-10 wave 2 (owner 2026-10-08): the four weakest categories of the six-tree blind batch — condition / boundary,
units / scale, sentinel / missing data, formula / constant — web-ranked by frequency (owner's list, not shipped).
Only the patterns that are decidable from the code itself, with a low
false-flag risk, live here; each observes and reports its counterexample, the disposition table decides.

  NAI-244 shadowed_branch    an `elif` whose test can never be true because an earlier test on the same name already
                             covers it (`>= 60` before `>= 90`; `isinstance(v, int)` before `isinstance(v, bool)`).
  NAI-245 unit_name_factor   a function named `<a>_to_<b>` / `<a>2<b>` (or a `<b>` result from an `<a>` parameter)
                             whose probe `f(1)` is not the table factor a→b (inverted, missing, or the wrong constant).
  NAI-246 sentinel_aggregate a module constant named MISSING / UNKNOWN / NA / SENTINEL / INVALID / NO_* reaches sum /
                             mean / max / min / len-division with no comparison against that constant in the function.
  NAI-247 truthy_default     `p = p or K` / `if not p: p = K` on a numeric parameter: probed, p=0 returns what p=None
                             (the default) returns — a real 0 is swallowed.
  NAI-248 seed_extreme       a running max/min seeded with a literal (best = 0) and updated only by max()/min() or a
                             `>` / `<` swap over a parameter: probed with all-negative (max) / all-huge (min) input,
                             the seed comes back although it is not in the input.
  NAI-249 formula_shape      precedence shapes that are almost never meant: `x ** 1 / n` (a root written as a
                             division), `a + b / 2` returned from a mean / average / mid function, `f - 32 * 5 / 9`,
                             `c * 5 / 9 + 32` in a Celsius→Fahrenheit function, and a float literal that is a
                             near-miss of π / e (3.14, 3.1416, 22/7, 2.718).
  NAI-250 leap_year          `% 4 == 0` as a leap test with no `% 100` / `% 400` in the same function.
"""
from __future__ import annotations

import ast
import math
import re
from typing import Any, Callable, Dict, List, Optional

from .boundary_probes import _call, _kind, _NOMINAL
from .intent_claims import _compile, last_return_line, slice_lines


def _fns(functions: List[Any]) -> List[ast.FunctionDef]:
    return [n for n in (getattr(f, "node", f) for f in functions)
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("test")]


def _params(fn: ast.FunctionDef) -> List[str]:
    return [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _one(seq: Any) -> Any:
    """The only element of `seq`, or None — a structural shape test (one operator, one target, one parameter)."""
    items = list(seq)
    head, *more = items or [None]
    return None if more else head


def _is_const(node: Any, want: Any) -> bool:
    """`node` is the literal `want` — a shape match against the formula being recognised, not a threshold."""
    return isinstance(node, ast.Constant) and _num(node.value) and node.value in {want}


# ── NAI-244 shadowed_branch ──────────────────────────────────────────────────────────────────────────────────────────
_SUB = {"bool": "int", "int": "object", "float": "object", "str": "object"}   # isinstance: a later subtype is shadowed


def _interval(test: ast.AST) -> Optional[tuple]:
    """(name, lo, lo_closed, hi, hi_closed) for `name OP const` / `const OP name`; None otherwise."""
    if not (isinstance(test, ast.Compare) and _one(test.ops) is not None):
        return None
    l, op, r = test.left, test.ops[0], test.comparators[0]
    if isinstance(l, ast.Name) and isinstance(r, ast.Constant) and _num(r.value):
        name, c, flip = l.id, float(r.value), False
    elif isinstance(r, ast.Name) and isinstance(l, ast.Constant) and _num(l.value):
        name, c, flip = r.id, float(l.value), True
    else:
        return None
    kind = type(op)
    if flip:
        kind = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}.get(kind, kind)
    inf = math.inf
    return {ast.Gt: (name, c, False, inf, False), ast.GtE: (name, c, True, inf, False),
            ast.Lt: (name, -inf, False, c, False), ast.LtE: (name, -inf, False, c, True),
            ast.Eq: (name, c, True, c, True)}.get(kind)


def _contains(outer: tuple, inner: tuple) -> bool:
    _, olo, olc, ohi, ohc = outer
    _, ilo, ilc, ihi, ihc = inner
    lo_ok = olo < ilo or (olo == ilo and (olc or not ilc))
    hi_ok = ohi > ihi or (ohi == ihi and (ohc or not ihc))
    return lo_ok and hi_ok


def _isinst(test: ast.AST) -> Optional[tuple]:
    if isinstance(test, ast.Call) and getattr(test.func, "id", "") == "isinstance":
        match test.args:
            case [ast.Name(id=obj), ast.Name(id=typ)]:
                return obj, typ
    return None


def _shadowed(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        for node in ast.walk(f):
            if not isinstance(node, ast.If) or any(node is _one(p.orelse) for p in ast.walk(f) if isinstance(p, ast.If)):
                continue   # start only at the head of a chain
            chain, cur = [], node
            while True:
                chain.append(cur)
                nxt = _one(cur.orelse)
                if isinstance(nxt, ast.If):
                    cur = nxt
                else:
                    break
            for j, later in enumerate(chain[1:], 1):
                li, lt = _interval(later.test), _isinst(later.test)
                for earlier in chain[:j]:
                    ei, et = _interval(earlier.test), _isinst(earlier.test)
                    hit = None
                    if li and ei and li[0] == ei[0] and _contains(ei, li):
                        hit = (f"`elif {ast.unparse(later.test)}` (line {later.lineno}) can never run: the earlier "
                               f"`{ast.unparse(earlier.test)}` (line {earlier.lineno}) already takes every value it would")
                    elif lt and et and lt[0] == et[0] and (et[1] == lt[1] or _SUB.get(lt[1]) == et[1]):
                        hit = (f"`elif {ast.unparse(later.test)}` (line {later.lineno}) can never run: "
                               f"`{ast.unparse(earlier.test)}` (line {earlier.lineno}) already matches every {lt[1]}")
                    if hit:
                        out[f"{f.name}@{f.lineno}"] = {"tag": "NAI-244", "line": later.lineno,
                                                       "lines": [earlier.lineno, later.lineno],
                                                       "variant": "shadowed_branch", "description": hit}
                        break
                if f"{f.name}@{f.lineno}" in out:
                    break
            if f"{f.name}@{f.lineno}" in out:
                break
    return out


# ── NAI-245 unit_name_factor ─────────────────────────────────────────────────────────────────────────────────────────
# Each unit: (dimension, size in the dimension's base). Affine temperatures are anchored separately.
_U: Dict[str, tuple] = {
    "ns": ("t", 1e-9), "us": ("t", 1e-6), "ms": ("t", 1e-3), "millis": ("t", 1e-3), "msec": ("t", 1e-3),
    "s": ("t", 1.0), "sec": ("t", 1.0), "secs": ("t", 1.0), "seconds": ("t", 1.0),
    "min": ("t", 60.0), "mins": ("t", 60.0), "minutes": ("t", 60.0),
    "h": ("t", 3600.0), "hr": ("t", 3600.0), "hrs": ("t", 3600.0), "hours": ("t", 3600.0),
    "day": ("t", 86400.0), "days": ("t", 86400.0), "week": ("t", 604800.0), "weeks": ("t", 604800.0),
    "mcg": ("m", 1e-6), "ug": ("m", 1e-6), "mg": ("m", 1e-3), "g": ("m", 1.0), "grams": ("m", 1.0),
    "kg": ("m", 1e3), "kilograms": ("m", 1e3), "lb": ("m", 453.59237), "lbs": ("m", 453.59237),
    "pounds": ("m", 453.59237), "oz": ("m", 28.349523125), "ounces": ("m", 28.349523125), "tonne": ("m", 1e6),
    "mm": ("l", 1e-3), "cm": ("l", 1e-2), "m": ("l", 1.0), "meters": ("l", 1.0), "metres": ("l", 1.0),
    "km": ("l", 1e3), "in": ("l", 0.0254), "inches": ("l", 0.0254), "ft": ("l", 0.3048), "feet": ("l", 0.3048),
    "yd": ("l", 0.9144), "yards": ("l", 0.9144), "mi": ("l", 1609.344), "miles": ("l", 1609.344),
    "nm": ("l", 1852.0), "ml": ("v", 1e-3), "l": ("v", 1.0), "liters": ("v", 1.0), "litres": ("v", 1.0),
    "gal": ("v", 3.785411784), "gallons": ("v", 3.785411784),
    "wh": ("e", 3600.0), "kwh": ("e", 3.6e6), "mwh": ("e", 3.6e9), "j": ("e", 1.0), "kj": ("e", 1e3),
    "mj": ("e", 1e6), "w": ("p", 1.0), "kw": ("p", 1e3), "mw": ("p", 1e6), "hp": ("p", 745.6998715822702),
    "pct": ("r", 0.01), "percent": ("r", 0.01), "fraction": ("r", 1.0), "frac": ("r", 1.0), "bps": ("r", 1e-4),
    "b": ("d", 1.0), "bytes": ("d", 1.0), "kb": ("d", 1e3), "mb": ("d", 1e6), "gb": ("d", 1e9),
    "kib": ("d", 1024.0), "mib": ("d", 1024.0 ** 2), "gib": ("d", 1024.0 ** 3),
}
_TEMP = {"c": "C", "celsius": "C", "f": "F", "fahrenheit": "F", "k": "K", "kelvin": "K"}
_TEMP_AT = {("C", "F"): [(0, 32), (100, 212), (-40, -40)], ("F", "C"): [(32, 0), (212, 100), (-40, -40)],
            ("C", "K"): [(0, 273.15), (100, 373.15)], ("K", "C"): [(273.15, 0), (373.15, 100)],
            ("F", "K"): [(32, 273.15), (212, 373.15)], ("K", "F"): [(273.15, 32), (373.15, 212)]}
_ALSO_DECIMAL = {"kb": 1024.0, "mb": 1024.0 ** 2, "gb": 1024.0 ** 3}   # KB = 1000 or 1024 is a convention, both accepted
_PAIR = re.compile(r"^(?:convert_)?([a-z]+)_?(?:to|2)_?([a-z]+)$")


def _factor(a: str, b: str) -> Optional[List[float]]:
    ua, ub = _U.get(a), _U.get(b)
    if not ua or not ub or ua[0] != ub[0] or a == b:
        return None
    sizes_a = [ua[1]] + ([_ALSO_DECIMAL[a]] if a in _ALSO_DECIMAL else [])
    sizes_b = [ub[1]] + ([_ALSO_DECIMAL[b]] if b in _ALSO_DECIMAL else [])
    return [x / y for x in sizes_a for y in sizes_b]


def _module_consts(tree: Any) -> Dict[str, int]:
    """Module-level NAME = <expr> lines: a conversion factor kept in a named constant is part of the conversion."""
    out: Dict[str, int] = {}
    for n in getattr(tree, "body", []):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = n.lineno
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            out[n.target.id] = n.lineno
    return out


def _unit_factor(fns: List[ast.FunctionDef], tree: Any = None) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    consts = _module_consts(tree)
    for f in fns:
        m = _PAIR.match(f.name.lower())
        ps = _params(f)
        if not m or not ps:
            continue
        a, b = m.group(1), m.group(2)
        fn = _compile(f)
        if fn is None:
            continue
        if _one(ps) is None:
            continue   # a single-argument converter only: extra parameters (precision, rounding) change the answer
        hit = None
        if a in _TEMP and b in _TEMP and _TEMP[a] != _TEMP[b]:
            for x, want in _TEMP_AT[(_TEMP[a], _TEMP[b])]:
                got, exc = _call(fn, [float(x)])
                if exc is None and _num(got) and not math.isclose(got, want, rel_tol=1e-3, abs_tol=1e-3):
                    hit = (x, got, want)
                    break
        else:
            facs = _factor(a, b)
            if not facs:
                continue
            got, exc = _call(fn, [1.0])
            if exc is None and _num(got) and not any(math.isclose(got, k, rel_tol=1e-3) for k in facs):
                hit = (1, got, facs[0])
        if hit:
            x, got, want = hit
            rets = [n.lineno for n in ast.walk(f) if isinstance(n, ast.Return)]
            line = last_return_line(f.name) or (max(rets) if rets else f.lineno)   # the probe's own return when known
            out[f"{f.name}@{f.lineno}"] = {
                "tag": "NAI-245", "line": line, "variant": "unit_factor",
                "lines": sorted({line} | {x for r in rets for x in slice_lines(f, r)} | {consts[n.id] for n in ast.walk(f)
                                                              if isinstance(n, ast.Name) and n.id in consts}),
                "probe": {"input": x, "returned": got, "expected": want},
                "description": f"`{f.name}({x:g})` returns {got:g}, but {x:g} {a} is {want:g} {b}"
                               + (" — the factor is inverted" if want and math.isclose(got * want, 1.0, rel_tol=1e-3)
                                  else "")}
    return out


# ── NAI-246 sentinel_aggregate ───────────────────────────────────────────────────────────────────────────────────────
_SENT = re.compile(r"^(MISSING|UNKNOWN|NA|N_A|NAN_VALUE|SENTINEL|INVALID|NONE_VALUE|NO_[A-Z_]+|[A-Z_]*_(MISSING|UNKNOWN|SENTINEL|INVALID))$")
_AGG = {"sum", "max", "min", "mean", "fmean", "median", "sorted"}


def sentinel_aggregate(tree: Any, functions: List[Any]) -> Dict[str, Dict[str, Any]]:
    consts = set()
    for n in getattr(tree, "body", []):
        tgt = _one(n.targets) if isinstance(n, ast.Assign) else None
        if isinstance(tgt, ast.Name) and _SENT.match(tgt.id) and isinstance(n.value, (ast.Constant, ast.UnaryOp)):
            consts.add(tgt.id)
    out: Dict[str, Dict[str, Any]] = {}
    if not consts:
        return out
    for f in _fns(functions):
        used = {n.id for n in ast.walk(f) if isinstance(n, ast.Name) and n.id in consts}
        if not used:
            continue
        compared = {c.id for n in ast.walk(f) if isinstance(n, ast.Compare)
                    for c in [n.left, *n.comparators] if isinstance(c, ast.Name) and c.id in used}
        for s in used - compared:
            agg = next((n for n in ast.walk(f) if isinstance(n, ast.Call)
                        and (getattr(n.func, "id", "") in _AGG or getattr(n.func, "attr", "") in _AGG)), None)
            div = next((n for n in ast.walk(f) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)
                        and isinstance(n.right, ast.Call) and getattr(n.right.func, "id", "") == "len"), None)
            at = agg or div
            if at is None:
                continue
            out[f"{f.name}@{f.lineno}"] = {
                "tag": "NAI-246", "line": at.lineno, "variant": "sentinel_aggregate",
                "lines": sorted({at.lineno} | {n.lineno for n in ast.walk(f) if isinstance(n, ast.Name) and n.id == s}),
                "description": f"`{s}` (a missing-value marker) is placed in the data and `{ast.unparse(at)}` "
                               f"aggregates it with no `!= {s}` filter — the marker is counted as a real value"}
            break
    return out


# ── NAI-247 truthy_default ───────────────────────────────────────────────────────────────────────────────────────────
def _truthy(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        ps = _params(f)
        defaults = dict(zip([a.arg for a in f.args.args][-len(f.args.defaults):] if f.args.defaults else [],
                            f.args.defaults))
        for p in ps:
            d = defaults.get(p)
            if not (isinstance(d, ast.Constant) and d.value is None):
                continue
            ann = next((ast.unparse(a.annotation) for a in f.args.args if a.arg == p and a.annotation), "")
            if re.search(r"\b(str|list|dict|bool|List|Dict|Sequence)\b", ann):
                continue
            site = None
            for n in ast.walk(f):
                if isinstance(n, ast.Assign) and isinstance(n.value, ast.BoolOp) and isinstance(n.value.op, ast.Or) \
                        and isinstance(n.value.values[0], ast.Name) and n.value.values[0].id == p \
                        and isinstance(n.value.values[-1], ast.Constant) and _num(n.value.values[-1].value) \
                        and not _is_const(n.value.values[-1], 0):
                    site = n
                if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp) and isinstance(n.test.op, ast.Not) \
                        and isinstance(n.test.operand, ast.Name) and n.test.operand.id == p:
                    site = n
            if site is None:
                continue
            fn = _compile(f)
            if fn is None:
                continue
            idx = [a.arg for a in f.args.args].index(p)
            base = [_NOMINAL[_kind(f, q)] if q != p else None for q in [a.arg for a in f.args.args]]
            if any(not _num(x) for i, x in enumerate(base) if i != idx):
                continue
            none_v, e1 = _call(fn, list(base))
            zero = list(base)
            zero[idx] = 0
            zero_v, e2 = _call(fn, zero)
            other = list(base)
            other[idx] = 5
            other_v, e3 = _call(fn, other)
            if e1 or e2 or e3 or not (_num(none_v) and _num(zero_v) and _num(other_v)):
                continue
            if math.isclose(none_v, zero_v, rel_tol=1e-9, abs_tol=1e-12) and not math.isclose(other_v, none_v, rel_tol=1e-9):
                out[f"{f.name}@{f.lineno}"] = {
                    "tag": "NAI-247", "line": site.lineno, "lines": [site.lineno], "variant": "truthy_default",
                    "probe": {"param": p, "zero": zero_v, "none": none_v},
                    "description": f"`{ast.unparse(site).splitlines()[0]}` treats `{p}=0` as missing: probed, "
                                   f"{p}=0 returns {zero_v:g}, the same as {p}=None — a real zero is replaced by the "
                                   f"default; test `{p} is None` instead"}
                break
    return out


# ── NAI-248 seed_extreme ─────────────────────────────────────────────────────────────────────────────────────────────
def _seeded(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        ps = _params(f)
        param = _one(ps)
        if param is None or _kind(f, param) != "seq":
            continue
        seeds = {n.targets[0].id: (n.value.value if isinstance(n.value, ast.Constant) else -n.value.operand.value, n)
                 for n in f.body if isinstance(n, ast.Assign) and isinstance(_one(n.targets), ast.Name)
                 and ((isinstance(n.value, ast.Constant) and _num(n.value.value))
                      or (isinstance(n.value, ast.UnaryOp) and isinstance(n.value.op, ast.USub)
                          and isinstance(n.value.operand, ast.Constant) and _num(n.value.operand.value)))}
        if not seeds:
            continue
        loops = [n for n in f.body if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == param]
        if not loops:
            continue
        mode = None
        for n in ast.walk(loops[0]):
            if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in seeds \
                    and isinstance(n.value, ast.Call) and getattr(n.value.func, "id", "") in ("max", "min"):
                mode = (n.targets[0].id, n.value.func.id)
            if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and _one(n.test.ops) is not None:
                names = [x.id for x in (n.test.left, n.test.comparators[0]) if isinstance(x, ast.Name)]
                acc = next((x for x in names if x in seeds), None)
                if acc and any(isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name)
                               and s.targets[0].id == acc for s in n.body):
                    op = type(n.test.ops[0])
                    left_is_item = isinstance(n.test.left, ast.Name) and n.test.left.id != acc
                    bigger = op in (ast.Gt, ast.GtE) if left_is_item else op in (ast.Lt, ast.LtE)
                    mode = (acc, "max" if bigger else "min")
        if not mode:
            continue
        acc, kind = mode
        seed, node = seeds[acc]
        fn = _compile(f)
        if fn is None:
            continue
        probe = [-7.0, -3.0, -5.0] if kind == "max" else [7e12, 3e12, 5e12]
        got, exc = _call(fn, [probe])
        if exc is None and _num(got) and math.isclose(got, seed) and seed not in probe:
            out[f"{f.name}@{f.lineno}"] = {
                "tag": "NAI-248", "line": node.lineno, "lines": [node.lineno], "variant": "seed_extreme",
                "probe": {"input": probe, "returned": got},
                "description": f"the running {kind} starts at `{acc} = {seed}`: probed with {probe} it returns {got:g}, "
                               f"a value not in the input — seed it from the first item (or ±inf)"}
    return out


# ── NAI-249 formula_shape ────────────────────────────────────────────────────────────────────────────────────────────
_NEAR = [(math.pi, (3.14, 3.141, 3.1416, 3.14159, 22 / 7), "math.pi"), (math.e, (2.718, 2.7183, 2.71828), "math.e")]
_MEAN = re.compile(r"(mean|average|avg|mid|midpoint|centre|center)")


def _formula_shapes(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        name = f.name.lower()
        hit = None
        for n in ast.walk(f):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div) and isinstance(n.left, ast.BinOp) \
                    and isinstance(n.left.op, ast.Pow) and _is_const(n.left.right, 1) \
                    and isinstance(n.right, ast.Constant) and _num(n.right.value):
                hit = (n, f"`{ast.unparse(n)}` is `(x ** 1) / {n.right.value}` — a root needs `x ** (1 / {n.right.value})`")
            elif isinstance(n, ast.Return) and _MEAN.search(name) and isinstance(n.value, ast.BinOp) \
                    and isinstance(n.value.op, ast.Add) and isinstance(n.value.right, ast.BinOp) \
                    and isinstance(n.value.right.op, ast.Div) and _is_const(n.value.right.right, 2):
                hit = (n, f"`{ast.unparse(n.value)}` halves only the last term — a mean of two needs "
                          f"`({ast.unparse(n.value.left)} + {ast.unparse(n.value.right.left)}) / 2`")
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Sub) and isinstance(n.right, ast.BinOp) \
                    and isinstance(n.right.left, ast.BinOp) and _is_const(n.right.left.left, 32) \
                    and isinstance(n.right.left.op, ast.Mult):
                hit = (n, f"`{ast.unparse(n)}` multiplies only the 32 — Fahrenheit→Celsius is `(f - 32) * 5 / 9`")
            elif isinstance(n, ast.Constant) and isinstance(n.value, float):
                for true, misses, spelled in _NEAR:
                    if any(math.isclose(n.value, x, rel_tol=1e-9) for x in misses):
                        hit = (n, f"`{n.value}` is a truncated {spelled} ({true:.10f}) — use `{spelled}`")
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div) and isinstance(n.left, ast.Constant) \
                    and isinstance(n.right, ast.Constant) and (n.left.value, n.right.value) == (22, 7):
                hit = (n, "`22 / 7` is an approximation of π (3.142857…) — use `math.pi`")
            if hit:
                break
        if hit:
            node, why = hit
            out[f"{f.name}@{f.lineno}"] = {"tag": "NAI-249", "line": node.lineno, "lines": [node.lineno],
                                           "variant": "formula_shape", "description": why}
    return out


# ── NAI-250 leap_year ────────────────────────────────────────────────────────────────────────────────────────────────
def _mod_eq(n: ast.AST, k: int) -> bool:
    return isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) and _is_const(n.right, k)


def _leap(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        mods = [n for n in ast.walk(f) if _mod_eq(n, 4)]
        if not mods or not re.search(r"leap|year|feb|days_in", f.name.lower() + " " + ast.unparse(f).lower()):
            continue
        if any(_mod_eq(n, 100) or _mod_eq(n, 400) for n in ast.walk(f)):
            continue
        if any(isinstance(n, ast.Attribute) and n.attr in ("isleap", "monthrange") for n in ast.walk(f)):
            continue
        out[f"{f.name}@{f.lineno}"] = {
            "tag": "NAI-250", "line": mods[0].lineno, "lines": [mods[0].lineno], "variant": "leap_year",
            "description": f"`{ast.unparse(mods[0])}` alone calls 1900 and 2100 leap years — the Gregorian rule also "
                           f"needs `% 100 != 0 or % 400 == 0` (or `calendar.isleap`)"}
    return out


def observations(tree: Any, functions: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Every wave-2 finding, keyed `func@line` like the other probe modules."""
    fns = _fns(functions)
    merged: Dict[str, List[Dict[str, Any]]] = {}
    for part in (_shadowed(fns), _unit_factor(fns, tree), sentinel_aggregate(tree, functions), _truthy(fns),
                 _seeded(fns), _formula_shapes(fns), _leap(fns)):
        for k, v in part.items():
            merged.setdefault(k, []).append(v)
    return merged
