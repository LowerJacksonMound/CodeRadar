"""formulas.py — the known-formula / constants check (owner 2026-10-07; COUNTERFEIT_TOP10 row 4, wrong formula constant).

A function whose NAME or DOCSTRING names a formula in known_formulas.json is checked two ways:
  * constants — a `required` constant missing from the body, or none of the `any_of` constants present while the body
                uses some other number: the body is not that formula as written.
  * reference — when every role of the entry's reference expression maps onto the function's parameters by name, the
                function and the reference are probed on the entry's domain points and compared (rel_tol from the
                entry). A constant unit factor between them (×1000, ×60 …) is not reported — that is a unit, not a
                wrong formula.
It OBSERVES (contradictions carry the expected value / constant and what the body has); intent_claims reports them
through NAI-102 for the Ranker. The table is DATA — a new formula is a new JSON row, never new code.
"""
from __future__ import annotations

import ast
import itertools
import json
import math
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_TABLE: Optional[Dict[str, Any]] = None


def table() -> Dict[str, Any]:
    global _TABLE
    if _TABLE is None:
        _TABLE = json.loads((Path(__file__).with_name("known_formulas.json")).read_text(encoding="utf-8"))
    return _TABLE or {"formulas": []}


def _text(func: ast.FunctionDef) -> str:
    return " " + " ".join((func.name.replace("_", " ") + " " + (ast.get_docstring(func) or "")).lower().split()) + " "


def _body_constants(func: ast.FunctionDef) -> Dict[float, int]:
    """Numeric literals in the body (a unary minus folded in) -> the line each first appears on."""
    out: Dict[float, int] = {}
    for n in ast.walk(ast.Module(body=func.body, type_ignores=[])):
        v = None
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub) and isinstance(n.operand, ast.Constant):
            v = -n.operand.value if isinstance(n.operand.value, (int, float)) else None
        elif isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool):
            v = n.value
        if v is not None:
            out.setdefault(float(v), getattr(n, "lineno", func.lineno))
    return out


def _has(consts: Dict[float, int], want: float) -> bool:
    return any(math.isclose(c, want, rel_tol=1e-9, abs_tol=1e-12) for c in consts)


def check(func: ast.FunctionDef, compiled: Optional[Callable], run: Callable, not_run: Any) -> List[Dict[str, Any]]:
    t = table()
    text = _text(func)
    ignore = [float(x) for x in t.get("ignore_constants", [])]
    out: List[Dict[str, Any]] = []
    for f in t["formulas"]:
        if not any(trig.lower() in text for trig in f["triggers"]):
            continue
        consts = _body_constants(func)
        telling = {c: ln for c, ln in consts.items() if not any(math.isclose(c, i) for i in ignore)}
        missing = [c for c in f.get("required", []) if not _has(consts, c)]
        if missing and telling:
            line = min(telling.values())
            out.append({"claim": "formula", "says": f"names {f['name']} ({f['source']})",
                        "expected": f"its constant{'s' if missing[1:] else ''} {', '.join(f'{c:g}' for c in missing)}",
                        "got": f"body uses {', '.join(f'{c:g}' for c in sorted(telling))}", "probe": "shape",
                        "line": line, "lines": sorted(set(telling.values()))})
        anyof = f.get("any_of", [])
        if anyof and telling and not any(_has(consts, c) for c in anyof):
            out.append({"claim": "formula", "says": f"names {f['name']} ({f['source']})",
                        "expected": f"one of {', '.join(f'{c:g}' for c in anyof)}",
                        "got": f"body uses {', '.join(f'{c:g}' for c in sorted(telling))}", "probe": "shape",
                        "line": min(telling.values()), "lines": sorted(set(telling.values()))})
        if compiled is not None and f.get("reference"):
            bad = _reference(func, f, compiled, run, not_run)
            if bad:
                out.append(bad)
    return out


def _reference(func: ast.FunctionDef, f: Dict[str, Any], fn: Callable, run: Callable, not_run: Any) -> Optional[Dict[str, Any]]:
    params = [a.arg for a in func.args.args]
    roles = f.get("roles", {})
    mapping: Dict[str, str] = {}
    for role, rx in roles.items():
        hit = [p for p in params if re.fullmatch(rf"(?:{rx})(?:_\w+)?", p, re.I) and p not in mapping.values()]
        if not hit:
            return None
        mapping[role] = next(iter(hit))
    if set(mapping.values()) != set(params):
        return None                                        # a parameter the formula does not explain: not this formula
    ref = compile(f["reference"], f"<formula:{f['name']}>", "eval")
    roles_order = list(mapping)
    pts = list(itertools.product(*[f.get("domain", {}).get(r, [1.0]) for r in roles_order]))
    ratios: List[float] = []
    worst = None
    for pt in pts:
        env = dict(zip(roles_order, pt))
        want = eval(ref, {"__builtins__": {}, "math": math}, env)   # the table's own expression (trusted data)
        args = {}
        for r, v in env.items():
            p = mapping[r]
            args[p] = math.radians(v) if r in f.get("angle_roles", []) and "rad" in p.lower() else v
        got = run(fn, **args)
        if got is not_run or not isinstance(got, (int, float)) or isinstance(got, bool):
            return None
        if want:
            ratios.append(got / want)
        if not math.isclose(got, want, rel_tol=f.get("rel_tol", 1e-6)) and worst is None:
            worst = (args, want, got)
    if worst is None:
        return None
    if ratios and all(math.isclose(r, next(iter(ratios)), rel_tol=1e-6) for r in ratios):
        k = next(iter(ratios))
        if any(math.isclose(k, u, rel_tol=1e-6) for u in (1000, 0.001, 60, 1 / 60, 3600, 1 / 3600, 100, 0.01, 1e6, 1e-6)):
            return None                                    # the same formula in another unit
    args, want, got = worst
    return {"claim": "formula", "says": f"names {f['name']} ({f['source']})",
            "expected": f"{want:.6g} for {', '.join(f'{k}={v:g}' for k, v in args.items())}", "got": f"{got:.6g}",
            "probe": f"{func.name}({', '.join(f'{k}={v:g}' for k, v in args.items())})"}
