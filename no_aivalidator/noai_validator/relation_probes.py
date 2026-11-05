"""relation_probes.py — INTENT-FREE relation checks (owner 2026-10-07 ~10:00, after the tree-3 review of the
"metamorphic / dimensional" ideas): what a function's NAME, its SIBLINGS and its PARAMETER NAMES imply, checked by
running it — never its docstring.

Rules here only OBSERVE: each observation carries its counterexample (the probe and what came back). Whether an
observation is an infraction, a review note or nothing is the Ranker's, read from `rule_dispositions.json` —
nothing in this file weighs, counts or ranks (owner: "all 'ranking' with the Ranker").

  NAI-239 relation_violation — the counterexample breaks a relation of ONE function:
      bound       a function taking a `capacity` / `cap` / `max_*` parameter plus at least one inflow: with every
                  inflow enormous and every outflow (`et`, `loss`, `drain`, …) 0 its result must sit exactly at the
                  capacity — a fill that cannot reach full, or passes it, is broken
      unit        parameter-name units (`_c`, `_kw`, `_kwh`, `_wm2`, `_m3`, …): an absolute °C multiplied or divided
                  (an affine quantity — 0 °C is not zero heat), or two different units added / subtracted
      sentinel    the module declares a missing-data marker (`MISSING = -1.0`) and a function aggregates a list
                  without ever comparing against it (sentinel_observations, which needs the module tree)
  NAI-240 relation_review — a relation between TWO functions (or two applications) is broken, and which side is
  wrong is not knowable without intent, so both carry it:
      inverse     `encode_x` / `decode_x`, `pack` / `unpack`, `a_from_b` / `b_from_a`: g(f(x)) must give x back
                  (probed on the smallest inputs any encoding must hold: every argument 0 or 1; floats 0, 1, 10, 100)
      partition   mirror siblings (`left_*` / `right_*`, `east_*` / `west_*`, `morning_*` / `afternoon_*`) whose
                  active regions are IDENTICAL over a symmetric sweep — they should cover opposite halves; which one
                  is wrong is not knowable without intent, so both carry it
      compose     an `f(value, items)` whose result feeds back as `value`: f(x, a + b) differs from f(f(x, a), b)
"""
from __future__ import annotations

import ast
import math
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from .intent_claims import _NOT_RUN, _compile, _run, last_return_line, slice_lines

_INVERSE_WORDS = [("encode", "decode"), ("pack", "unpack"), ("serialize", "deserialize"), ("compress", "decompress"),
                  ("encrypt", "decrypt"), ("to", "from"), ("dump", "load"), ("wrap", "unwrap")]
_MIRROR_WORDS = [("left", "right"), ("east", "west"), ("morning", "afternoon"), ("am", "pm"), ("north", "south")]
_CAPACITY = re.compile(r"^(capacity|cap|limit)(_\w+)?$|^max_\w+$|^\w+_(capacity|max|limit)$")
_OUTFLOW = re.compile(r"^(et|loss|losses|drain|drainage|demand|use|usage|draw|outflow|evap\w*|spill\w*)(_\w+)?$")
_FRACTION = re.compile(r"^(efficiency|eff|ratio|fraction|share|rate)(_\w+)?$|^\w+_(efficiency|eff|ratio|fraction)$")
_UNITS = {"c": "degC", "f": "degF", "k": "kelvin", "kw": "kW", "kwh": "kWh", "wh": "Wh", "w": "W", "wm2": "W/m2",
          "m": "m", "mm": "mm", "km": "km", "m2": "m2", "m3": "m3", "mj": "MJ", "kj": "kJ", "j": "J", "deg": "deg",
          "rad": "rad", "s": "s", "min": "min", "h": "h", "pct": "%", "m_s": "m/s", "kg": "kg", "g": "g", "l": "L"}
_ABSOLUTE_TEMP = {"degC", "degF"}


def _fns(functions: List[Any]) -> List[ast.FunctionDef]:
    return [n for n in (getattr(f, "node", f) for f in functions)
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("test")]


def _params(fn: ast.FunctionDef) -> List[str]:
    return [a.arg for a in fn.args.args]


def _unit(name: str) -> Optional[str]:
    """The unit a parameter's NAME carries (`cell_c` -> degC, `wind_m_s` -> m/s); None when it carries none."""
    for suffix in sorted(_UNITS, key=len, reverse=True):
        if name.endswith("_" + suffix) and name != "_" + suffix:
            return _UNITS[suffix]
    return None


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return list(a) == list(b) or (len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b)))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
    return a == b


def _pair_by_words(fns: List[ast.FunctionDef], words: List[Tuple[str, str]]) -> List[Tuple[ast.FunctionDef, ast.FunctionDef, str]]:
    out = []
    by_name = {f.name: f for f in fns}
    for f in fns:
        toks = f.name.split("_")
        for a, b in words:
            if a in toks:
                other = "_".join(b if t == a else t for t in toks)
                if other in by_name and other != f.name:
                    out.append((f, by_name[other], a))
    # `x_from_y` / `y_from_x`
    for f in fns:
        m = re.fullmatch(r"(\w+?)_from_(\w+)", f.name)
        if m and f"{m.group(2)}_from_{m.group(1)}" in by_name:
            out.append((f, by_name[f"{m.group(2)}_from_{m.group(1)}"], "from"))
    return out


# ── NAI-239 inverse ─────────────────────────────────────────────────────────────────────────────────────────────────
def _inverse(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f, g, word in _pair_by_words(fns, _INVERSE_WORDS):
        if word in ("decode", "unpack", "deserialize", "decompress", "decrypt", "load", "unwrap") or \
                (word == "from" and f.name > g.name):
            continue                                   # each pair is probed once, from its forward side
        ff, gg = _compile(f), _compile(g)
        if not ff or not gg:
            continue
        n = len(_params(f))
        grids: List[Tuple[float, ...]] = ([tuple((i >> k) & 1 for k in range(n)) for i in range(1 << n)] if n else []) or [()]
        if word == "from":
            grids = [(x,) for x in (0.0, 1.0, 10.0, 100.0)] if n == 1 and len(_params(g)) == 1 else []
        for args in grids:
            y = _run(ff, *args)
            if y is _NOT_RUN:
                break
            back = _run(gg, *(y if isinstance(y, tuple) else (y,)))
            if back is _NOT_RUN:
                break
            want = args if len(args) != 1 else args[0]
            if not _same(back, want):
                # which side is wrong is not knowable here: both carry it, as a review note (NAI-240)
                desc = (f"{g.name}({f.name}{args!r}) gives {back!r}, not {want!r} back — {f.name} and {g.name} "
                        f"are not inverses; one of them is wrong")
                for me, other in ((f, g), (g, f)):
                    out.setdefault(f"{me.name}@{me.lineno}", {
                        "tag": "NAI-240", "line": last_return_line(me.name) or me.lineno, "lines": slice_lines(me, last_return_line(me.name)), "variant": "inverse", "partner": other.name,
                        "description": desc})
                break
    return out


# ── NAI-239 bound ───────────────────────────────────────────────────────────────────────────────────────────────────
def _bound(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        ps = _params(f)
        caps = [p for p in ps if _CAPACITY.match(p)]
        state = next(iter(ps), None)
        if not caps or state in caps:
            continue
        cap = caps[0]
        ff = _compile(f)
        if not ff:
            continue
        inflows = [p for p in ps if p not in (cap, state) and not _FRACTION.match(p) and not _OUTFLOW.match(p)]
        if not inflows:
            continue                                   # nothing flows in (a ratio like soc / capacity): no fill to test
        big: Dict[str, float] = {p: (0.9 if _FRACTION.match(p) else 0.0 if _OUTFLOW.match(p) else 1e9) for p in ps}
        big[cap], big[cast(str, state)] = 10.0, 9.0
        r = _run(ff, **big)
        if r is _NOT_RUN or not isinstance(r, (int, float)):
            continue
        if not math.isclose(r, 10.0, rel_tol=1e-9):
            out[f"{f.name}@{f.lineno}"] = {
                "tag": "NAI-239", "line": last_return_line(f.name) or f.lineno, "lines": slice_lines(f, last_return_line(f.name)), "variant": "bound", "capacity": cap,
                "description": f"{f.name}({', '.join(f'{p}={v:g}' for p, v in big.items())}) gives {r:g} — with every "
                               f"inflow enormous and every outflow 0 the result should sit exactly at `{cap}` (10)"}
    return out


# ── NAI-239 unit ────────────────────────────────────────────────────────────────────────────────────────────────────
def _units(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        units = {p: _unit(p) for p in _params(f)}
        units = {p: u for p, u in units.items() if u}
        if not units:
            continue
        for n in ast.walk(ast.Module(body=f.body, type_ignores=[])):
            if not isinstance(n, ast.BinOp):
                continue
            sides = [s for s in (n.left, n.right) if isinstance(s, ast.Name) and s.id in units]
            if isinstance(n.op, (ast.Mult, ast.Div)) and any(units[s.id] in _ABSOLUTE_TEMP for s in sides):
                s = next(s for s in sides if units[s.id] in _ABSOLUTE_TEMP)
                out[f"{f.name}@{f.lineno}"] = {
                    "tag": "NAI-239", "line": n.lineno, "variant": "unit",
                    "description": f"`{ast.unparse(n)}` multiplies an absolute temperature `{s.id}` ({units[s.id]}) — "
                                   f"0 °C is not zero; a temperature enters a product as a difference (`{s.id} - ref`)"}
                break
            if isinstance(n.op, (ast.Add, ast.Sub)) and [type(s) for s in sides] == [ast.Name, ast.Name] \
                    and units[cast(ast.Name, n.left).id] != units[cast(ast.Name, n.right).id]:
                out[f"{f.name}@{f.lineno}"] = {
                    "tag": "NAI-239", "line": n.lineno, "variant": "unit",
                    "description": f"`{ast.unparse(n)}` adds {units[cast(ast.Name, n.left).id]} to {units[cast(ast.Name, n.right).id]}"}
                break
    return out


# ── NAI-240 partition ───────────────────────────────────────────────────────────────────────────────────────────────
def _partition(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f, g, word in _pair_by_words(fns, _MIRROR_WORDS):
        if word not in {a for a, _ in _MIRROR_WORDS}:
            continue                                   # probe each mirror pair once, from its first word (left_*)
        if _params(f) != _params(g):
            continue
        ff, gg = _compile(f), _compile(g)
        if not ff or not gg:
            continue
        ps = _params(f)
        sweep = [-60.0, -45.0, -30.0, -15.0, 15.0, 30.0, 45.0, 60.0]
        rest = {p: 2.0 for p in ps[1:]}
        act_f, act_g = [], []
        for x in sweep:
            a, b = _run(ff, x, **rest), _run(gg, x, **rest)
            if a is _NOT_RUN or b is _NOT_RUN:
                break
            act_f.append(bool(a)); act_g.append(bool(b))
        else:
            if act_f == act_g and any(act_f) and not all(act_f):
                side = "negative" if act_f[0] else "positive"
                for me, other in ((f, g), (g, f)):
                    out[f"{me.name}@{me.lineno}"] = {
                        "tag": "NAI-240", "line": last_return_line(me.name) or me.lineno, "lines": slice_lines(me, last_return_line(me.name)), "variant": "partition", "partner": other.name,
                        "description": f"{f.name} and {g.name} are active on the same ({side}) half of `{ps[0]}` and "
                                       f"both silent on the other — mirror functions should cover opposite halves"}
    return out


# ── NAI-240 compose ─────────────────────────────────────────────────────────────────────────────────────────────────
def _compose(fns: List[ast.FunctionDef]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        ps = _params(f)
        if ps[2:] or not ps[1:]:
            continue
        lists = {p for p in ps if any(isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == p
                                      for n in ast.walk(f))}
        if [p for p in ps if p in lists] != ps[1:]:
            continue
        ff = _compile(f)
        if not ff:
            continue
        x, a, b = 1000.0, [0.3], [0.3]
        once = _run(ff, x, a + b)
        first = _run(ff, x, a)
        twice = _run(ff, first, b) if first is not _NOT_RUN else _NOT_RUN
        if _NOT_RUN in (once, twice) or not all(isinstance(v, (int, float)) for v in (once, twice)):
            continue
        if not math.isclose(once, twice, rel_tol=1e-9):
            out[f"{f.name}@{f.lineno}"] = {
                "tag": "NAI-240", "line": last_return_line(f.name) or f.lineno, "lines": slice_lines(f, last_return_line(f.name)), "variant": "compose",
                "description": f"{f.name}({x:g}, {a + b}) gives {once:g} but {f.name}({f.name}({x:g}, {a}), {b}) gives "
                               f"{twice:g} — applying the items together and one after another disagree"}
    return out


# ── NAI-239 sentinel ────────────────────────────────────────────────────────────────────────────────────────────────
_SENTINEL_NAME = re.compile(r"^(MISSING|NO_?DATA|NODATA|SENTINEL|NA|NAN_VALUE|UNKNOWN|NULL_VALUE|FILL_VALUE|INVALID)(_\w+)?$")
_AGGREGATES = {"sum", "mean", "fmean", "median", "max", "min", "average", "stdev", "pstdev"}


def sentinel_observations(tree: ast.AST, functions: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """owner 2026-10-07 ~10:30 (blind tree 3 mean_moisture): a module that DECLARES an in-band "missing" marker
    (`MISSING = -1.0`, `NODATA = None`, …) and a function in it that aggregates a list parameter (sum / mean / max …)
    without ever comparing against that marker — by its name, its value, or (for a negative marker) a sign test — so
    the marker is averaged in as if it were data. Intent-free: the module's own constant is the evidence."""
    marks: Dict[str, Any] = {}
    for n in getattr(tree, "body", []):
        if (isinstance(n, ast.Assign) and [type(t) for t in n.targets] == [ast.Name]
                and _SENTINEL_NAME.match(cast(ast.Name, n.targets[0]).id)):
            v = n.value
            if isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.USub) and isinstance(v.operand, ast.Constant):
                marks[cast(ast.Name, n.targets[0]).id] = -cast(Any, v.operand.value)
            elif isinstance(v, ast.Constant):
                marks[cast(ast.Name, n.targets[0]).id] = v.value
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not marks:
        return out
    negative = [k for k, v in marks.items() if isinstance(v, (int, float)) and v != abs(v)]
    for f in _fns(functions):
        lists = set(_params(f))
        agg = [c for c in ast.walk(f) if isinstance(c, ast.Call) and
               (getattr(c.func, "id", None) or getattr(c.func, "attr", None)) in _AGGREGATES
               and any(isinstance(a, ast.Name) and a.id in lists for a in c.args)]
        if not agg:
            continue
        guarded = False
        for c in ast.walk(f):
            if isinstance(c, ast.Compare):
                names = {x.id for x in ast.walk(c) if isinstance(x, ast.Name)}
                consts = [x.value for x in ast.walk(c) if isinstance(x, ast.Constant)]
                if names & set(marks) or any(v in consts for v in marks.values()) or (negative and consts and any(
                        isinstance(o, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for o in c.ops)):
                    guarded = True
        if guarded:
            continue
        name, val = next(iter(marks.items()))
        call = agg[0]
        out.setdefault(f"{f.name}@{f.lineno}", []).append({
            "tag": "NAI-239", "line": call.lineno, "variant": "sentinel", "marker": name,
            "description": f"the module marks missing data as `{name} = {val!r}`, but {f.name} aggregates "
                           f"`{ast.unparse(call)}` without ever skipping it — the marker is counted as a real value"})
    return out

def observations(functions: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Every relation observation, keyed `name@line` like NAI-230 / 236 / 237; a function may carry several."""
    fns = _fns(functions)
    out: Dict[str, List[Dict[str, Any]]] = {}
    for part in (_inverse(fns), _bound(fns), _units(fns), _partition(fns), _compose(fns)):
        for k, v in part.items():
            out.setdefault(k, []).append(v)
    return out
