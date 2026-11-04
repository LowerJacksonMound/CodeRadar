"""intent_claims.py — the ONE place CodeRadar reads a function's stated INTENT and checks the body against it
(owner 2026-10-07 ~09:10: "gather this intent and make it available wherever it may be useful").

A docstring that states something checkable is turned into CLAIMS (data: {kind, ...}); each claim is checked against
the body in one of two ways:

  * PROBE — the claim names inputs and the answer they must give ("Monday is 0 … Saturday or Sunday" -> f(5) and f(6)
    are True, f(0..4) False). The probe runs the function ONLY when its AST is pure arithmetic over its own
    arguments (no import, no global but `math`, no call outside a fixed allow-list, no attribute write) in a
    namespace with nothing else in it, under a line budget. Anything else -> the probe is NOT RUN, never guessed.
  * SHAPE — the claim contradicts a body shape outright ("sum each pair" over `values[i] - values[i + 1]`;
    "in degrees" with `math.sin(x)` where x never passes through `math.radians`).

`claims(func)` publishes what was read (the intent, for mirrors / the ranker / the panel); `check(func)` returns
the contradictions as NAI-102 observations: {claim, expected, got, probe}. A claim whose check cannot run is
reported in `claims()` and silent in `check()` — absent, never wrong.
"""
from __future__ import annotations

import ast
import datetime as _dt
import math
import re
import statistics
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
_SAFE_CALLS = {"abs", "min", "max", "sum", "len", "range", "sorted", "round", "int", "float", "list", "bool", "enumerate",
               "zip", "reversed"}
_SAFE_METHODS = {"append", "timetuple", "strftime", "isoformat", "date", "get", "copy"}
_LINE_BUDGET = 20000
# Well-known one-argument conversions a docstring may name: (from, to) -> (probe input, expected output)
_KNOWN_CONVERSIONS = {
    ("celsius", "fahrenheit"): (100.0, 212.0), ("fahrenheit", "celsius"): (212.0, 100.0),
    ("celsius", "kelvin"): (0.0, 273.15), ("kelvin", "celsius"): (273.15, 0.0),
    ("inches", "millimetres"): (1.0, 25.4), ("inches", "millimeters"): (1.0, 25.4), ("millimetres", "inches"): (25.4, 1.0),
    ("millimeters", "inches"): (25.4, 1.0), ("wh", "kwh"): (1000.0, 1.0), ("kwh", "wh"): (1.0, 1000.0),
    ("degrees", "radians"): (180.0, math.pi), ("radians", "degrees"): (math.pi, 180.0),
    ("miles", "kilometres"): (1.0, 1.609344), ("miles", "kilometers"): (1.0, 1.609344),
}


def _doc(func: ast.FunctionDef) -> str:
    return (ast.get_docstring(func) or "").strip()


def _params(func: ast.FunctionDef) -> List[str]:
    return [a.arg for a in func.args.args]


# ── reading the claims ──────────────────────────────────────────────────────────────────────────────────────────────
def claims(func: ast.FunctionDef) -> List[Dict[str, Any]]:
    """Every checkable claim the docstring makes, as data. Empty when the docstring states nothing checkable."""
    doc = _doc(func)
    low = doc.lower()
    ps = _params(func)
    first = next(iter(ps), None)                      # the first parameter, or None
    second = next(iter(ps[1:2]), None) if first else None
    only = first if ps == [first] else None           # the sole parameter
    out: List[Dict[str, Any]] = []
    named = [i for i, d in enumerate(_DAYS) if re.search(rf"\b{d}\b", low)]
    if named and first and re.search(r"\bmonday is 0\b|\bmonday\s*=\s*0\b", low) and re.search(r"\b(true|when|is)\b", low):
        named = [i for i in named if not re.search(rf"\b{_DAYS[i]} is 0\b", low)]
        out.append({"kind": "weekday_set", "param": first, "true_for": named,
                    "says": f"True for {', '.join(_DAYS[i].title() for i in named)} (Monday is 0)"})
    m = re.search(r"(\w+) is the share given to the (\w+)", low)
    if m and m.group(1) in ps:
        target = next((p for p in ps if p.startswith(m.group(2)) or m.group(2).startswith(p)), None)
        if target:
            out.append({"kind": "share", "weight": m.group(1), "to": target,
                        "says": f"`{m.group(1)}` is the share given to `{target}`"})
    m = re.search(r"\b(after|before)\s+(\w+)", low)
    if m:
        target = next((p for p in ps if p.startswith(m.group(2))), None)
        if target:
            out.append({"kind": "order", "rel": m.group(1), "param": target, "says": f"{m.group(1)} `{target}`"})
    if re.search(r"\biso[- ]?8601\b.*\bdate\b|\biso\b.*\bcalendar date\b", low):
        out.append({"kind": "iso_date", "says": "an ISO-8601 calendar date (YYYY-MM-DD)"})
    if re.search(r"\blinear\b", low) and re.search(r"\bbetween\b", low) and {"t0", "t1", "v0", "v1"} <= set(ps):
        out.append({"kind": "interpolation", "says": "linear between (t0, v0) and (t1, v1)"})
    if re.search(r"\brunning median\b", low) and second:
        out.append({"kind": "running_median", "values": first, "window": second, "says": "a running median over the window"})
    m = re.search(r"\[(\w+),\s*(\w+)\]", doc)
    if m and re.search(r"\b(clip|clamp|into|within|inside)\b", low) and {m.group(1), m.group(2)} <= set(ps):
        val = next((p for p in ps if p not in (m.group(1), m.group(2))), None)
        if val:
            out.append({"kind": "clamp", "value": val, "low": m.group(1), "high": m.group(2),
                        "says": f"clips `{val}` into [{m.group(1)}, {m.group(2)}]"})
    if re.search(r"\bat or below zero yields 0\b|\bbelow zero (?:yields|returns|gives) 0\b", low) and first:
        out.append({"kind": "zero_floor", "param": first, "says": f"`{first}` at or below zero yields 0"})
    m = re.search(r"\bconvert (\w+) to (\w+)\b", low)
    if m and (m.group(1), m.group(2)) in _KNOWN_CONVERSIONS and only:
        out.append({"kind": "conversion", "pair": (m.group(1), m.group(2)),
                    "says": f"converts {m.group(1)} to {m.group(2)}"})
    if re.search(r"\b(sum|add)\s+each pair\b", low):
        out.append({"kind": "pair_sum", "says": "sums each pair"})
    if re.search(r"\bin degrees\b|\bdegrees\b", low) or any(p.endswith("_deg") for p in ps):
        out.append({"kind": "degrees", "says": "works in degrees"})
    return out


# ── the probe evaluator ─────────────────────────────────────────────────────────────────────────────────────────────
def _targets(node: ast.AST) -> List[ast.AST]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.For, ast.comprehension)):
        return [node.target]
    return []


def _is_radians(call: ast.AST) -> bool:
    """`math.radians(x)` or the code's own `to_radians(x)` / `deg2rad(x)` / `radians(x)`."""
    if not isinstance(call, ast.Call):
        return False
    name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
    return name in ("radians", "to_radians", "deg2rad", "deg_to_rad", "torad")


def _pure(func: ast.FunctionDef, callable_names: frozenset = frozenset(), constants: frozenset = frozenset()) -> bool:
    """True when the body only does arithmetic on its own arguments: no import / global / nonlocal / with / try /
    lambda / class / del, and every call is allow-listed. `callable_names` are the module's OTHER pure functions
    and `constants` its literal module constants (owner 2026-10-07: whole-module sandbox) — both may be used."""
    params = set(_params(func))
    body = ast.Module(body=func.body, type_ignores=[])          # annotations are types, not behaviour
    bound = {t.id for a in ast.walk(body) for tgt in _targets(a) for t in ast.walk(tgt) if isinstance(t, ast.Name)}
    for n in ast.walk(body):
        if isinstance(n, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.With, ast.AsyncWith, ast.Try,
                          ast.Lambda, ast.ClassDef, ast.Delete, ast.Await, ast.Yield, ast.YieldFrom, ast.AsyncFunctionDef)):
            return False
        if isinstance(n, ast.FunctionDef) and n is not func:
            return False
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id not in _SAFE_CALLS and f.id not in callable_names:
                return False
            if isinstance(f, ast.Attribute):
                if isinstance(f.value, ast.Name) and f.value.id == "math":
                    continue
                if f.attr not in _SAFE_METHODS:
                    return False
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in params and n.id != "math" \
                and n.id not in _SAFE_CALLS and n.id not in {"True", "False", "None"} \
                and n.id not in callable_names and n.id not in constants and n.id not in bound:
            return False
    return True


def _module_constants(tree: Any) -> Dict[str, Any]:
    """Top-level `NAME = <literal>` (numbers, strings, tuples, lists, dicts, sets, negatives) — evaluated by
    ast.literal_eval, never executed."""
    out: Dict[str, Any] = {}
    for n in getattr(tree, "body", []):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            if [type(t) for t in tgts] == [ast.Name] and n.value is not None:
                try:
                    out[tgts[0].id] = ast.literal_eval(n.value)
                except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                    pass
    return out


def _sandbox_env() -> Dict[str, Any]:
    import builtins as _b

    def _guarded_import(name, *a, **kw):   # datetime.timetuple() imports `time` internally — that, and nothing else
        if name.split(".")[0] not in ("time", "datetime", "math", "_strptime"):
            raise ImportError(f"probe sandbox: import of {name!r} refused")
        return _b.__import__(name, *a, **kw)
    # the allow-listed calls plus `format` (an f-string's format spec calls it) — nothing that reaches outside
    return {"__builtins__": {**{k: getattr(_b, k) for k in _SAFE_CALLS | {"format", "str", "repr"}},
                             "__import__": _guarded_import},
            "math": math}


def _strip(func: ast.FunctionDef) -> ast.FunctionDef:
    import copy as _copy
    args = _copy.deepcopy(func.args)         # never mutate the caller's tree
    for a in [*args.args, *args.kwonlyargs, *(x for x in (args.vararg, args.kwarg) if x)]:
        a.annotation = None
    kw = dict(name=func.name, args=args, body=_copy.deepcopy(func.body), decorator_list=[], returns=None)
    if sys.version_info >= (3, 12):
        kw["type_params"] = []
    return ast.FunctionDef(**kw)


_MODULE_ENVS: Dict[int, Tuple[Any, Dict[str, Any], frozenset]] = {}


def bind_module(tree: Any) -> None:
    """owner 2026-10-07 (whole-module sandbox): compile every PURE top-level function of `tree` into ONE sandbox
    namespace with the module's literal constants, so a pure function may call another (fixpoint: a function is
    pure only if everything it calls is). Keyed by each function node's id; replaced on the next bind."""
    consts = _module_constants(tree)
    tops = [n for n in getattr(tree, "body", []) if isinstance(n, ast.FunctionDef)]
    names = {n.name for n in tops}
    pure = set(names)
    while True:
        keep = {n.name for n in tops if n.name in pure and _pure(n, frozenset(pure - {n.name}), frozenset(consts))}
        if keep == pure:
            break
        pure = keep
    env = _sandbox_env()
    env.update(consts)
    mod = ast.fix_missing_locations(ast.Module(body=[_strip(n) for n in tops if n.name in pure], type_ignores=[]))
    try:
        exec(compile(mod, "<probe:module>", "exec"), env)
    except Exception:
        env, pure = {}, set()
    for n in tops:
        _MODULE_ENVS[id(n)] = (tree, env, frozenset(pure))


def unbind_module(tree: Any) -> None:
    for n in getattr(tree, "body", []):
        if isinstance(n, ast.FunctionDef):
            _MODULE_ENVS.pop(id(n), None)


def _compile(func: ast.FunctionDef) -> Optional[Callable]:
    bound = _MODULE_ENVS.get(id(func))
    if bound is not None:
        _tree, env, pure = bound
        return env.get(func.name) if func.name in pure else None
    if not _pure(func):
        return None
    env = _sandbox_env()
    mod = ast.fix_missing_locations(ast.Module(body=[_strip(func)], type_ignores=[]))
    try:
        exec(compile(mod, f"<probe:{func.name}>", "exec"), env)
    except Exception:
        return None
    return env.get(func.name)


_LAST_RETURN: Dict[str, int] = {}   # probed function name -> the line of the `return` its last probe executed


def slice_lines(func: ast.FunctionDef, return_line: Optional[int]) -> List[int]:
    """The statements the value returned at `return_line` depends on (a backward data slice over the function's own
    assignments — straight-line, names only): the `return` itself, then every assignment to a name it reads, then
    theirs. A finding carries these as `lines`, so it implicates the statements that produced the value."""
    stmts = [n for n in ast.walk(func) if isinstance(n, ast.stmt) and n is not func]
    ret = next((n for n in stmts if isinstance(n, ast.Return) and n.lineno == return_line), None)
    if ret is None:
        return [return_line] if return_line else []
    want = {x.id for x in ast.walk(ret) if isinstance(x, ast.Name)}
    lines = {ret.lineno}
    for n in sorted((n for n in stmts if getattr(n, "lineno", 0) < ret.lineno), key=lambda n: n.lineno, reverse=True):
        targets = {t.id for tgt in (getattr(n, "targets", None) or [getattr(n, "target", None)]) if tgt is not None
                   for t in ast.walk(tgt) if isinstance(t, ast.Name)}
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and targets & want:
            lines.add(n.lineno)
            want |= {x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)} if n.value is not None else set()
        elif isinstance(n, ast.If) and {x.id for x in ast.walk(n.test) if isinstance(x, ast.Name)} & want:
            lines.add(n.lineno)
    return sorted(lines)


def last_return_line(name: str) -> Optional[int]:
    """The statement that produced the probed value (line precision, owner 2026-10-07): the `return` line the last
    probe of `name` executed — so a finding points at the statement that gave the wrong answer, not the `def`."""
    return _LAST_RETURN.get(name)


def _run(fn: Callable, *args: Any, **kw: Any) -> Any:
    """Call under a line budget; any exception or budget overrun -> the sentinel _NOT_RUN. Records the line of the
    `return` the probed function executed (last_return_line)."""
    count = [0]
    target = getattr(fn, "__code__", None)

    def tracer(frame, event, arg):
        if event == "line":
            count[0] += 1
            if count[0] > _LINE_BUDGET:
                raise TimeoutError
        elif event == "return" and frame.f_code is target:
            _LAST_RETURN[target.co_name] = frame.f_lineno
        return tracer
    old = sys.gettrace()
    sys.settrace(tracer)
    try:
        return fn(*args, **kw)
    except Exception:
        return _NOT_RUN
    finally:
        sys.settrace(old)


_NOT_RUN = object()


# ── checking ────────────────────────────────────────────────────────────────────────────────────────────────────────
def check(func: ast.FunctionDef) -> List[Dict[str, Any]]:
    """The claims the body contradicts. Each: {claim, says, expected, got, probe}."""
    out: List[Dict[str, Any]] = []
    try:   # owner 2026-10-07: a stated threshold ("at least 5") against the body's strictness (`> 5`)
        from .boundary_probes import threshold_contradictions
        out.extend(threshold_contradictions(func, _doc(func)))
    except ImportError:
        pass
    try:   # M-144 (2026-10-08): point claims — one stated case against the body's shape, nothing executed
        from .point_claims import contradictions as _point_contradictions
        out.extend(_point_contradictions(func, _doc(func)))
    except ImportError:
        pass
    try:   # owner 2026-10-07 option 2: the general claim forms (claim_forms), probed in the module sandbox
        from . import claim_forms as _cf
        from .boundary_probes import _kind as _pkind
        _ps = _params(func)
        _kinds = {p: _pkind(func, p) for p in _ps}
        _ints = {a.arg: bool(a.annotation is not None and "int" in ast.unparse(a.annotation)
                             and "float" not in ast.unparse(a.annotation)) for a in func.args.args}
        _gen = _cf.read(_doc(func), _ps, _kinds) + _cf.read_name(
            func.name, _ps, _kinds, ast.unparse(func.returns) if func.returns is not None else "")
        _gfn = _compile(func) if _gen else None
        if _gfn is not None and "other" not in _kinds.values():
            for _b in _cf.check(func, _gen, _gfn, _run, _NOT_RUN, _ps, _kinds, _ints):
                _at = last_return_line(func.name)
                _b["line"] = _at or func.lineno
                _b["lines"] = slice_lines(func, _at)
                out.append(_b)
    except ImportError:
        pass
    try:   # owner 2026-10-07: the known-formula / constants table (formulas.py + known_formulas.json — data)
        from . import formulas as _fm
        for _b in _fm.check(func, _compile(func), _run, _NOT_RUN):
            if _b.get("probe") != "shape":
                _at = last_return_line(func.name)
                _b["line"], _b["lines"] = _at or func.lineno, slice_lines(func, _at)
            out.append(_b)
    except ImportError:
        pass
    cs = claims(func)
    if not cs:
        return out
    fn = _compile(func) if any(c["kind"] in ("weekday_set", "share", "order", "iso_date", "interpolation", "running_median",
                                             "clamp", "zero_floor", "conversion")
                               for c in cs) else None
    ps = _params(func)

    def bad(c: Dict[str, Any], expected: str, got: str, probe: str, line: Optional[int] = None) -> None:
        # the statement the evidence points at: a shape's own node, else the `return` the failing probe executed
        at = line if line is not None else (last_return_line(func.name) if probe != "shape" else None)
        out.append({"claim": c["kind"], "says": c["says"], "expected": expected, "got": got, "probe": probe,
                    "line": at if at is not None else func.lineno,
                    "lines": slice_lines(func, at) if probe != "shape" else [at]})

    for c in cs:
        k = c["kind"]
        if k == "weekday_set" and fn:
            got = {i: _run(fn, i) for i in range(7)}
            if _NOT_RUN not in got.values():
                wrong = [_DAYS[i].title() for i in range(7) if bool(got[i]) != (i in c["true_for"])]
                if wrong:
                    bad(c, "True only for " + ", ".join(_DAYS[i].title() for i in c["true_for"]),
                        "True for " + ", ".join(_DAYS[i].title() for i in range(7) if got[i]), f"{func.name}(0..6)")
        elif k == "share" and fn and ps:
            args = {p: 0.0 for p in ps}
            args.update({c["to"]: 10.0, c["weight"]: 1.0})
            other = next((p for p in ps if p not in (c["to"], c["weight"])), None)
            if other:
                args[other] = 2.0
            r = _run(fn, **args)
            if r is not _NOT_RUN and isinstance(r, (int, float)) and not math.isclose(r, 10.0):
                bad(c, f"{c['weight']}=1 gives all of `{c['to']}` (10)", f"{r:g}",
                    f"{func.name}({', '.join(f'{p}={v:g}' for p, v in args.items())})")
        elif k == "order" and fn:
            args = {p: 5.0 for p in ps}
            args[c["param"]] = 300.0
            r = _run(fn, **args)
            if r is not _NOT_RUN and isinstance(r, (int, float)):
                # the probe's own input is the reference: `after x` must not come out ahead of x, `before x` not behind
                if (c["rel"] == "after" and min(r, args[c["param"]]) == r != args[c["param"]]) or \
                        (c["rel"] == "before" and max(r, args[c["param"]]) == r != args[c["param"]]):
                    bad(c, f"{'≥' if c['rel'] == 'after' else '≤'} {c['param']} (300)", f"{r:g}",
                        f"{func.name}({', '.join(f'{p}={v:g}' for p, v in args.items())})")
        elif k == "iso_date" and fn and ps and ps == [next(iter(ps))]:
            r = _run(fn, _dt.datetime(2026, 3, 5, 14, 30))
            if isinstance(r, str) and not re.match(r"^\d{4}-\d{2}-\d{2}", r):
                bad(c, "2026-03-05", repr(r), f"{func.name}(datetime(2026, 3, 5, 14, 30))")
        elif k == "interpolation" and fn:
            base = {"t0": 0.0, "v0": 0.2, "t1": 10.0, "v1": 0.8}
            r0 = _run(fn, **{"t": 0.0, **base}) if "t" in ps else _NOT_RUN
            if r0 is not _NOT_RUN and isinstance(r0, (int, float)) and not math.isclose(r0, 0.2):
                bad(c, "f(t=t0) = v0 = 0.2", f"{r0:g}", f"{func.name}(t=0, t0=0, v0=0.2, t1=10, v1=0.8)")
        elif k == "running_median" and fn:
            vals, w = [5.0, 1.0, 9.0, 3.0, 7.0], 3
            r = _run(fn, vals, w)
            half = w // 2
            want = [statistics.median(vals[max(0, i - half):min(len(vals), i + half + 1)]) for i in range(len(vals))]
            if isinstance(r, list) and [round(x, 9) for x in r] != [round(x, 9) for x in want]:
                bad(c, str(want), str(r), f"{func.name}({vals}, {w})")
        elif k == "clamp" and fn:
            for v, want in ((-5.0, 0.0), (5.0, 5.0), (50.0, 10.0)):
                r = _run(fn, **{c["value"]: v, c["low"]: 0.0, c["high"]: 10.0})
                if r is not _NOT_RUN and isinstance(r, (int, float)) and not math.isclose(r, want):
                    bad(c, f"{want:g} for {v:g} in [0, 10]", f"{r:g}", f"{func.name}({c['value']}={v:g}, {c['low']}=0, {c['high']}=10)")
                    break
        elif k == "zero_floor" and fn:
            r = _run(fn, -10.0)
            if r is not _NOT_RUN and isinstance(r, (int, float)) and not math.isclose(r, 0.0):
                bad(c, "0 for -10", f"{r:g}", f"{func.name}(-10)")
        elif k == "conversion" and fn:
            x, want = _KNOWN_CONVERSIONS[c["pair"]]
            r = _run(fn, x)
            if r is not _NOT_RUN and isinstance(r, (int, float)) and not math.isclose(r, want, rel_tol=1e-6, abs_tol=1e-9):
                bad(c, f"{want:g} for {x:g}", f"{r:g}", f"{func.name}({x:g})")
        elif k == "pair_sum":
            for n in ast.walk(func):
                if (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Sub) and isinstance(n.left, ast.Subscript)
                        and isinstance(n.right, ast.Subscript)
                        and ast.dump(n.left.value) == ast.dump(n.right.value)):
                    bad(c, "a + b for each pair", f"`{ast.unparse(n)}`", "shape", n.lineno)
                    break
        elif k == "degrees":
            converted = {t.id for n in ast.walk(func) if isinstance(n, ast.Assign)
                         and any(_is_radians(x) for x in ast.walk(n.value))
                         for t in n.targets if isinstance(t, ast.Name)}
            for n in ast.walk(func):
                if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                        and n.func.value.id == "math" and n.func.attr in ("sin", "cos", "tan") and n.args):
                    arg = n.args[0]
                    via = any(_is_radians(x) for x in ast.walk(arg))
                    names = {x.id for x in ast.walk(arg) if isinstance(x, ast.Name)}
                    degreeish = bool(names & set(ps)) or any(isinstance(x, ast.Constant) and x.value == 360.0
                                                            for x in ast.walk(func))
                    if not via and not (names & converted) and degreeish:
                        bad(c, "math.radians(...) before the trig call", f"`{ast.unparse(n)}` on degrees", "shape", n.lineno)
                        break
    return out
