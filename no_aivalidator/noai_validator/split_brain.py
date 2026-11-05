"""Wave 3 #7 (owner 2026-10-08, frontier-model counterfeit list): split-brain twins — NAI-251.

A fix lands in one copy of a function while another module keeps an older clone (`app/utils/formatters.py` vs
`app/helpers/legacy_formatters.py`): the same operation answers differently depending on which entry point is called.

Measured, project-wide, once per scan (the per-file pass cannot see another file's functions):
  * two top-level functions in DIFFERENT files with the same name — after dropping the rename marks a stale copy
    carries (`legacy_` / `old_` / `new_` / `_old` / `_new` / `_legacy` / `_impl` / `_v2` …) — and the same parameter
    names;
  * near-identical bodies: not byte-identical (an exact clone is the duplicate rules' business) but the same shape
    (node-type sequence similarity ≥ 0.8) — so two unrelated `parse(text)` functions never pair;
  * probed on the same inputs inside the whole-module sandbox, they return different values (or one raises where
    the other returns).
Correct siblings (`price_kg` / `price_lb`) have different names and are never paired; NAI-238 keeps them as context.
Both copies carry the observation, each naming the other and the probe that split them; which copy is right is the
Ranker's (and intent's) business.
"""
from __future__ import annotations

import ast
import difflib
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .boundary_probes import _call, _kind, _NOMINAL
from .intent_claims import _compile, bind_module, unbind_module

_RENAME = re.compile(r"^(?:legacy|old|new|orig|original|deprecated|tmp)_+|_+(?:legacy|old|new|orig|impl|v\d+|\d+|copy|tmp)$")
_SHAPE_MIN = 0.8
_VARIANTS: Dict[str, List[Any]] = {"num": [0, 1, -1, 7.5, 100, 3.14159, 0.666], "int": [0, 1, -1, 7, 100, 13], "str": ["", "a", "Hello World", "x,y"],
             "seq": [[], [1], [3, 1, 2], [-2.5, 0, 4]]}


def _key(name: str) -> str:
    prev = None
    while prev != name:
        prev, name = name, _RENAME.sub("", name)
    return name.lower()


def _shape(fn: ast.FunctionDef) -> List[str]:
    body = fn.body[1:] if (fn.body and isinstance(fn.body[0], ast.Expr)
                           and isinstance(getattr(fn.body[0], "value", None), ast.Constant)) else fn.body
    return [type(n).__name__ for stmt in body for n in ast.walk(stmt)]


def _dump(fn: ast.FunctionDef) -> str:
    body = fn.body[1:] if (fn.body and isinstance(fn.body[0], ast.Expr)
                           and isinstance(getattr(fn.body[0], "value", None), ast.Constant)) else fn.body
    return "\n".join(ast.dump(s) for s in body)


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        try:
            return math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-12)
        except (TypeError, ValueError):
            return False
    return a == b


def _grid(fn: ast.FunctionDef, params: List[str]) -> List[List[Any]]:
    kinds = [_kind(fn, p) for p in params]
    base = [_NOMINAL[k] for k in kinds]
    grid = [list(base)]
    for i, k in enumerate(kinds):
        for v in _VARIANTS.get(k, _VARIANTS["num"]):   # "other" probes as a number — its nominal value already is one
            row = list(base)
            row[i] = v
            if row not in grid:
                grid.append(row)
    return grid


def _divergence(fa: ast.FunctionDef, ca: Any, cb: Any, params: List[str]) -> Optional[Tuple[List[Any], Any, Any]]:
    for args in _grid(fa, params):
        ra, ea = _call(ca, [list(x) if isinstance(x, list) else x for x in args])
        rb, eb = _call(cb, [list(x) if isinstance(x, list) else x for x in args])
        if ea is None and eb is None:
            if not _same(ra, rb):
                return args, ra, rb
        elif (ea is None) != (eb is None):
            return args, (f"raises {type(ea).__name__}" if ea else ra), (f"raises {type(eb).__name__}" if eb else rb)
    return None


def observations(trees_by_rel: Dict[str, ast.AST], root: Path) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """{absolute file path: {"func@line": [NAI-251 observation]}} for every split-brain pair in the project."""
    groups: Dict[Tuple[str, Tuple[str, ...]], List[Tuple[str, ast.FunctionDef]]] = defaultdict(list)
    for rel, tree in trees_by_rel.items():
        for n in getattr(tree, "body", []):
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("test") and not n.decorator_list:
                params = tuple(a.arg for a in n.args.args if a.arg not in ("self", "cls"))
                if params:
                    groups[(_key(n.name), params)].append((rel, n))
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(dict)
    bound: set = set()
    try:
        for (_, params), members in groups.items():
            first_rel = members[0][0]
            if all(rel == first_rel for rel, _ in members):
                continue   # every member in one file: not a cross-file pair
            for i, (ra, fa) in enumerate(members):
                for rb, fb in members[i + 1:]:
                    if ra == rb or _dump(fa) == _dump(fb):
                        continue
                    if difflib.SequenceMatcher(None, _shape(fa), _shape(fb)).ratio() < _SHAPE_MIN:
                        continue
                    for rel in (ra, rb):
                        if rel not in bound:
                            bind_module(trees_by_rel[rel])
                            bound.add(rel)
                    ca, cb = _compile(fa), _compile(fb)
                    if ca is None or cb is None:
                        continue
                    hit = _divergence(fa, ca, cb, list(params))
                    if hit is None:
                        continue
                    args, va, vb = hit
                    call = f"({', '.join(repr(x) for x in args)})"
                    for (me_rel, me, my_v), (other_rel, other, their_v) in (((ra, fa, va), (rb, fb, vb)),
                                                                            ((rb, fb, vb), (ra, fa, va))):
                        out[str((root / me_rel).resolve())][f"{me.name}@{me.lineno}"] = [{
                            "tag": "NAI-251", "line": me.lineno, "lines": [me.lineno], "variant": "split_brain",
                            "twin": f"{other_rel}::{other.name}", "probe": {"args": args, "here": my_v, "twin": their_v},
                            "description": f"`{me.name}` here and `{other.name}` in {other_rel} are the same operation "
                                           f"(same parameters, near-identical body) but answer differently: "
                                           f"{me.name}{call} → {my_v!r}, {other.name}{call} → {their_v!r} — one copy is stale"}]
    finally:
        for rel in bound:
            unbind_module(trees_by_rel[rel])
    return dict(out)
