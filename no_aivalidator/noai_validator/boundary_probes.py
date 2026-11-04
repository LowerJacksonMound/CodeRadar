"""boundary_probes.py — wrong conditions and missing corner cases (owner 2026-10-07: the two most frequent real
counterfeit patterns together, ~30% of LLM bugs — COUNTERFEIT_TOP10_2026-10-07.md rows 2–3).

Three checks. Like relation_probes they OBSERVE only — each observation carries its counterexample; the Ranker
weighs them through rule_dispositions.json (nothing here counts, weighs or ranks).

  NAI-241 boundary_gap   (intent-free) — the function is probed on BOTH sides of every constant it compares a
        parameter against (c - step, c, c + step). Where it returns a value on both neighbours but falls through to
        an implicit `None` at the boundary itself, no branch handles `param == c` (the `<` / `>` gap).
  NAI-242 corner_crash   (intent-free) — the function runs on ordinary inputs but raises on a corner the top-10
        list names: empty collection, single element, zero, negative. A missing guard — or a deliberate raise;
        which one is the Ranker's (review by default).
  NAI-102 threshold      (intent) — the docstring states a threshold in words ("at least 5", "more than 5", "up to",
        "below") and the body compares against the same number with the other strictness (`>` for "at least",
        `>=` for "more than" …): the off-by-one at the boundary. Reported through intent_claims' NAI-102.
"""
from __future__ import annotations

import ast
import math
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .intent_claims import _LINE_BUDGET, _compile, last_return_line, slice_lines

_CORNER_EXC = (ZeroDivisionError, IndexError, ValueError, KeyError, StopIteration, ArithmeticError)


def _fns(functions: List[Any]) -> List[ast.FunctionDef]:
    return [n for n in (getattr(f, "node", f) for f in functions)
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("test")]


def _params(fn: ast.FunctionDef) -> List[str]:
    return [a.arg for a in fn.args.args]


def _call(fn: Callable, args: List[Any]) -> Tuple[Any, Optional[BaseException]]:
    """(value, None) or (None, the exception) — under the same line budget as intent_claims' probes."""
    count = [0]
    target = getattr(fn, "__code__", None)

    def tracer(frame, event, arg):
        if event == "line":
            count[0] += 1
            if count[0] > _LINE_BUDGET:
                raise TimeoutError
        return tracer
    old = sys.gettrace()
    sys.settrace(tracer)
    try:
        return fn(*args), None
    except TimeoutError as e:
        return None, e
    except Exception as e:   # noqa: BLE001 — the exception IS the observation
        return None, e
    finally:
        sys.settrace(old)
        del target


def _kind(fn: ast.FunctionDef, p: str) -> str:
    """What a parameter holds, from its annotation, else from how the body uses it: seq / num / str / other."""
    a = next((x.annotation for x in fn.args.args if x.arg == p), None)
    text = ast.unparse(a) if a is not None else ""
    if re.search(r"\b(list|List|Sequence|Iterable|tuple|Tuple)\b", text):
        return "seq"
    if re.search(r"\b(int|float)\b", text):
        return "num"
    if re.search(r"\bstr\b", text):
        return "str"
    for n in ast.walk(fn):
        if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == p:
            return "seq"
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") in ("len", "sum", "sorted", "max", "min") \
                and any(isinstance(x, ast.Name) and x.id == p for x in n.args):
            return "seq"
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id == p:
            return "seq"
        if isinstance(n, ast.BinOp) and any(isinstance(x, ast.Name) and x.id == p for x in (n.left, n.right)):
            return "num"
    return "other"


_NOMINAL = {"seq": [1.0, 2.0, 3.0], "num": 2.0, "str": "abc", "other": 2.0}
_CORNERS = {"seq": [("empty", []), ("single", [4.0])], "num": [("zero", 0.0), ("negative", -3.0)],
            "str": [("empty", "")], "other": []}


# ── NAI-241 boundary_gap ────────────────────────────────────────────────────────────────────────────────────────────
def _boundary_gap(f: ast.FunctionDef, fn: Callable) -> List[Dict[str, Any]]:
    ps = _params(f)
    kinds = {p: _kind(f, p) for p in ps}
    base = [_NOMINAL[kinds[p]] for p in ps]
    out: List[Dict[str, Any]] = []
    for c in (n for n in ast.walk(f) if isinstance(n, ast.Compare)):
        sides = [c.left, *c.comparators]
        names = [s.id for s in sides if isinstance(s, ast.Name) and s.id in ps and kinds[s.id] == "num"]
        consts = [s.value for s in sides if isinstance(s, ast.Constant) and isinstance(s.value, (int, float))
                  and not isinstance(s.value, bool)]
        for p in names:
            i = ps.index(p)
            for k in consts:
                step = 1 if isinstance(k, int) else max(abs(k) * 1e-3, 1e-3)
                vals = {}
                for label, x in (("below", k - step), ("at", k), ("above", k + step)):
                    args = list(base)
                    args[i] = x
                    vals[label] = _call(fn, args)
                (b, eb), (a, ea), (u, eu) = vals["below"], vals["at"], vals["above"]
                if None in (eb, ea, eu) and eb is None and eu is None and ea is None \
                        and b is not None and u is not None and a is None:
                    out.append({"tag": "NAI-241", "line": c.lineno, "lines": [c.lineno], "variant": "boundary_gap",
                                "description": f"{f.name}: `{p}` = {k - step:g} gives {b!r} and {k + step:g} gives "
                                               f"{u!r}, but exactly {k!r} falls through every branch and returns None "
                                               f"— no branch handles `{p} == {k!r}`"})
                    return out
    return out


# ── NAI-242 corner_crash ────────────────────────────────────────────────────────────────────────────────────────────
def _corner_crash(f: ast.FunctionDef, fn: Callable) -> List[Dict[str, Any]]:
    ps = _params(f)
    if not ps:
        return []
    kinds = {p: _kind(f, p) for p in ps}
    base = [_NOMINAL[kinds[p]] for p in ps]
    ok, err = _call(fn, base)
    if err is not None:
        return []                                       # ordinary inputs already fail: the probe cannot judge
    for i, p in enumerate(ps):
        for label, x in _CORNERS[kinds[p]]:
            args = list(base)
            args[i] = x
            _, e = _call(fn, args)
            if isinstance(e, _CORNER_EXC):
                raised_here = any(isinstance(n, ast.Raise) for n in ast.walk(f))
                line = getattr(e.__traceback__, "tb_lineno", None)
                tb = e.__traceback__
                while tb is not None:
                    if tb.tb_frame.f_code is fn.__code__:
                        line = tb.tb_lineno
                    tb = tb.tb_next
                return [{"tag": "NAI-242", "line": line or f.lineno, "lines": [line or f.lineno],
                         "variant": "corner_crash", "corner": f"{p}={label}", "deliberate_raise": raised_here,
                         "description": f"{f.name} works on ordinary input but raises {type(e).__name__} when "
                                        f"`{p}` is {label} ({x!r}) — {'it raises on purpose somewhere' if raised_here else 'no guard for that case'}"}]
    return []



# ── NAI-243 partial_cases ───────────────────────────────────────────────────────────────────────────────────────────
def _module_cases(tree: Any) -> Dict[str, List[str]]:
    """Top-level collections of string literals the module declares (`KINDS = ("dry", "reefer", "tank")`, a set, a
    list, or a dict's keys) — the module's own statement of which cases exist."""
    out: Dict[str, List[str]] = {}
    for n in getattr(tree, "body", []):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            v = n.value
            if [type(t) for t in tgts] != [ast.Name] or v is None:
                continue
            elts = v.elts if isinstance(v, (ast.Tuple, ast.List, ast.Set)) else v.keys if isinstance(v, ast.Dict) else []
            strs = [e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if strs and strs[1:] and [type(e) for e in elts] == [ast.Constant] * len(strs):
                out[tgts[0].id] = strs
    return out


def partial_case_observations(tree: Any, functions: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """owner 2026-10-07 (top-10 row 7, partial implementation): a function compares a parameter against string
    literals from one of the module's declared case lists, handles a strict subset of them, and on a case it does not
    name falls through to an implicit None — the cases the module says exist are not all implemented."""
    cases = _module_cases(tree)
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not cases:
        return out
    for f in _fns(functions):
        ps = _params(f)
        named: Dict[str, set] = {}
        for c in (n for n in ast.walk(f) if isinstance(n, ast.Compare)):
            sides = [c.left, *c.comparators]
            p = next((x.id for x in sides if isinstance(x, ast.Name) and x.id in ps), None)
            if p is None:
                continue
            lits = {x.value for s in sides for x in ([s] if isinstance(s, ast.Constant) else
                                                     getattr(s, "elts", []) if isinstance(s, (ast.Tuple, ast.List, ast.Set)) else [])
                    if isinstance(x, ast.Constant) and isinstance(x.value, str)}
            named.setdefault(p, set()).update(lits)
        for p, lits in named.items():
            for list_name, members in cases.items():
                hit = lits & set(members)
                left_out = [m for m in members if m not in lits]
                if not hit or not left_out or not lits <= set(members):
                    continue
                fn = _compile(f)
                if not fn:
                    continue
                i = ps.index(p)
                base = [_NOMINAL[_kind(f, q)] for q in ps]
                for m in left_out:
                    args = list(base)
                    args[i] = m
                    r, e = _call(fn, args)
                    if e is None and r is None:
                        out.setdefault(f"{f.name}@{f.lineno}", []).append({
                            "tag": "NAI-243", "line": f.lineno, "lines": [f.lineno], "variant": "partial_cases",
                            "cases": list_name,
                            "description": f"{f.name} handles {sorted(hit)} of the module's {list_name} {members}, but "
                                           f"`{p}` = {m!r} falls through and returns None — not every declared case "
                                           f"is implemented"})
                        break
    return out

def observations(functions: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for f in _fns(functions):
        fn = _compile(f)
        if not fn:
            continue
        for part in (_boundary_gap(f, fn), _corner_crash(f, fn)):
            for o in part:
                out.setdefault(f"{f.name}@{f.lineno}", []).append(o)
    return out


# ── NAI-102 threshold (intent) — used by intent_claims ─────────────────────────────────────────────────────────────
_WORDS = [(r"\bat least\b|\bno (?:less|fewer) than\b|\bminimum(?: of)?\b|\bor more\b", (ast.GtE, ast.LtE), "≥"),
          (r"\bmore than\b|\bgreater than\b|\bexceeds?\b|\babove\b|\bover\b", (ast.Gt, ast.Lt), ">"),
          (r"\bat most\b|\bno more than\b|\bup to\b|\bmaximum(?: of)?\b|\bor less\b|\bor fewer\b", (ast.LtE, ast.GtE), "≤"),
          (r"\bless than\b|\bfewer than\b|\bbelow\b|\bunder\b", (ast.Lt, ast.Gt), "<")]
_STRICTNESS_TWIN = {ast.GtE: ast.Gt, ast.Gt: ast.GtE, ast.LtE: ast.Lt, ast.Lt: ast.LtE}


def threshold_contradictions(func: ast.FunctionDef, doc: str) -> List[Dict[str, Any]]:
    """Docstring "at least 5" vs body `x > 5` (and the other three pairings): same number, other strictness."""
    low = doc.lower()
    out: List[Dict[str, Any]] = []
    for pattern, ops, sym in _WORDS:
        for m in re.finditer(rf"(?:{pattern})\s*(-?\d+(?:\.\d+)?)", low):
            n = float(m.group(1))
            for c in (x for x in ast.walk(func) if isinstance(x, ast.Compare)):
                sides = [c.left, *c.comparators]
                for j, op in enumerate(c.ops):
                    l, r = sides[j], sides[j + 1]
                    val = r.value if isinstance(r, ast.Constant) else l.value if isinstance(l, ast.Constant) else None
                    if not isinstance(val, (int, float)) or isinstance(val, bool) or not math.isclose(val, n):
                        continue
                    want = ops[0] if isinstance(r, ast.Constant) else ops[1]   # constant on the left flips direction
                    if type(op) is _STRICTNESS_TWIN.get(want):
                        out.append({"claim": "threshold", "says": f"{m.group(0).strip()}",
                                    "expected": f"`{sym} {m.group(1)}`", "got": f"`{ast.unparse(c)}`",
                                    "probe": "shape", "line": c.lineno, "lines": [c.lineno]})
    return out
