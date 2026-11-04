"""cr_probe_plan — runs CodeRadar's probe plan INSIDE the target's own pytest session, after the suite, with the real
argument sets the suite produced still alive (M-151 step 2, 2026-10-08; owner: run the target's functions at scan
time as a counterfeit detector).

The plan is computed by the scan from the code (noai_validator/runtime_probes.py); this module only executes it:
  twins   two functions with the same name and parameters in different files. Both are resolved from the real
          imported package and called on every recorded argument set of either (self dropped) plus the plan's fixed
          inputs. The first input on which they answer differently is reported, with which twin the suite called
          directly from a passing test.
Nothing here judges; results go back as data.
"""
from __future__ import annotations

import copy
import importlib
import inspect
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def _resolve(ref: Dict[str, Any], live: Dict[Tuple[str, int], Any]) -> Optional[Callable]:
    fn = live.get((ref["file"], ref["first"]))
    if fn is None:
        try:
            mod = importlib.import_module(ref["module"])
        except Exception:
            return None
        obj: Any = mod
        for part in ref["qual"].split("."):
            obj = inspect.getattr_static(obj, part, None) if isinstance(obj, type) else getattr(obj, part, None)
            if obj is None:
                return None
        fn = getattr(obj, "__func__", obj)
    if not callable(fn):
        return None
    if ref.get("method") and not ref.get("static"):
        owner = _owner(ref)
        if owner is None:
            return None
        try:
            inst = owner()
        except Exception:
            return None
        return lambda *a, _f=fn, _i=inst: _f(_i, *a)
    return fn


def _owner(ref: Dict[str, Any]) -> Optional[type]:
    try:
        obj: Any = importlib.import_module(ref["module"])
        for part in ref["qual"].split(".")[:-1]:
            obj = getattr(obj, part)
        return obj if isinstance(obj, type) else None
    except Exception:
        return None


def _call(fn: Callable, args: Tuple[Any, ...]) -> Tuple[Any, Optional[str]]:
    try:
        return fn(*args), None
    except Exception as e:   # the outcome IS the observation
        return None, type(e).__name__


def _same(a: Tuple[Any, Optional[str]], b: Tuple[Any, Optional[str]]) -> bool:
    (va, ea), (vb, eb) = a, b
    if ea or eb:
        return ea == eb
    if isinstance(va, float) and isinstance(vb, float):
        return math.isclose(va, vb, rel_tol=1e-9, abs_tol=1e-12) or (math.isnan(va) and math.isnan(vb))
    try:
        return bool(va == vb)
    except Exception:
        return repr(va) == repr(vb)


def _arg_sets(ref: Dict[str, Any], corpus: Dict[Tuple[str, int], List[Tuple[Any, ...]]]) -> List[Tuple[Any, ...]]:
    sets = corpus.get((ref["file"], ref["first"]), [])
    return [s[1:] if ref.get("method") and not ref.get("static") else s for s in sets]


class _Named:
    def __init__(self, name: str) -> None:
        self.name = name


_NOT_RUN = object()


def _load_claim_forms(path: str) -> Any:
    """CodeRadar's claim_forms (stdlib only), loaded by file path under a private name — never via the target's path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_cr_claim_forms", path)
    mod = importlib.util.module_from_spec(spec)   # type: ignore[arg-type]
    spec.loader.exec_module(mod)                   # type: ignore[union-attr]
    return mod


def _claims(plan: Dict[str, Any], corpus: Dict[Tuple[str, int], List[Tuple[Any, ...]]],
            live: Dict[Tuple[str, int], Any]) -> List[Dict[str, Any]]:
    items = plan.get("claims") or []
    if not items or not plan.get("claim_forms"):
        return []
    cf = _load_claim_forms(plan["claim_forms"])
    found: List[Dict[str, Any]] = []
    for it in items:
        ref = it["ref"]
        sets = corpus.get((ref["file"], ref["first"]))
        fn = live.get((ref["file"], ref["first"]))
        if not sets or fn is None:
            continue

        def run(f: Callable, *args: Any) -> Any:
            try:
                return f(*copy.deepcopy(args))
            except Exception:
                return _NOT_RUN
        try:
            broken = cf.check(_Named(ref["name"]), it["claims"], fn, run, _NOT_RUN, it["params"], it["kinds"],
                              it["ints"], recorded=[list(s) for s in sets])
        except Exception:   # a claim form that cannot read this function's real values says nothing about it
            continue
        if broken:
            found.append({"ref": ref, "broken": broken})
    return found


def run_plan(plan: Dict[str, Any], corpus: Dict[Tuple[str, int], List[Tuple[Any, ...]]],
             live: Dict[Tuple[str, int], Any], root: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {"twins": [], "claims": _claims(plan, corpus, live),
                           "direct_pass": sorted(plan.get("_direct_pass", []))}
    direct = {tuple(x) for x in plan.get("_direct_pass", [])}
    for pair in plan.get("twins", []):
        a, b = pair["a"], pair["b"]
        fa, fb = _resolve(a, live), _resolve(b, live)
        if fa is None or fb is None:
            continue
        inputs = _arg_sets(a, corpus) + _arg_sets(b, corpus) + [tuple(x) for x in pair.get("grid", [])]
        for args in inputs:
            ra, rb = _call(fa, args), _call(fb, args)
            if not _same(ra, rb):
                out["twins"].append({"a": a, "b": b, "args": repr(args),
                                     "a_result": repr(ra[0]) if ra[1] is None else f"raises {ra[1]}",
                                     "b_result": repr(rb[0]) if rb[1] is None else f"raises {rb[1]}",
                                     "recorded": args in inputs[:len(inputs) - len(pair.get("grid", []))],
                                     "a_tested": (a["file"], a["first"]) in direct,
                                     "b_tested": (b["file"], b["first"]) in direct})
                break
    return out
