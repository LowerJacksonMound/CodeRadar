"""claim_forms.py — the GENERAL claim forms (owner 2026-10-07 ~12:10, option 2: "one general claim form instead of many
patterns"). Not one regex per phrasing: the dozen most common WAYS a docstring states checkable intent, each mapped
to one property probed on generated inputs. intent_claims stays the one reader; this module is its general half.

Forms, most frequent first (counted over trees 1–4's docstrings; tree 5 left unread as the benchmark):
  out_range     the result lies in a stated range — "returns … between A and B", "in [A, B]", "A..B"
  fraction      the result is a fraction / share / ratio (0..1) or a percentage (0..100)
  mean          an average / mean of a list parameter lies between that list's min and max
  empty_value   "returns X for an empty …" / "X when there are no …": f(empty) == X
  non_negative  "never negative", "non-negative", "positive": the result is ≥ 0 (> 0)
  cap_param     "never exceeds `p`", "at most `p`", "capped at `p`": the result ≤ that parameter
  same_length   "one per …", "same length as …": len(result) == len(the list parameter)
  sorted        "sorted / ascending / descending / oldest first": the result list is in that order
  unique        "unique / distinct / without duplicates": no repeated element in the result
  total         "total / sum of / number of" over a list parameter: additive — f(a + b) == f(a) + f(b)
  unchanged     "does not modify / returns a copy": the list argument is unchanged after the call

Each check probes generated inputs (by parameter kind), never the code's own literals as the only input, inside the
whole-module sandbox. It OBSERVES: a contradiction carries its counterexample; the Ranker weighs it (NAI-102).
"""
from __future__ import annotations

import ast
import itertools
import math
import re
from typing import Any, Callable, Dict, List

def _f(x: str) -> float:
    return float(x)


def read(doc: str, params: List[str], kinds: Dict[str, str]) -> List[Dict[str, Any]]:
    """The general claims a docstring makes (data only)."""
    low = " ".join(doc.lower().split())
    out: List[Dict[str, Any]] = []
    seqs = [p for p in params if kinds.get(p) == "seq"]
    first_seq = next(iter(seqs), None)

    m = re.search(r"\b(?:returns?|gives?|yields?|result is|value is|is)\b[^.;]*?\b(?:between\s+(-?\d+(?:\.\d+)?)\s+and\s+"
                  r"(-?\d+(?:\.\d+)?)|in\s+\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\]|(-?\d+(?:\.\d+)?)\s*\.\.\s*"
                  r"(-?\d+(?:\.\d+)?))", low)
    if m:
        g = [x for x in m.groups() if x is not None]
        out.append({"form": "out_range", "lo": _f(g[0]), "hi": _f(g[1]), "says": m.group(0).strip()})
    if re.search(r"\b(?:returns?|as|is)\s+(?:a|the)\s+(?:fraction|share|ratio|proportion)\b", low):
        out.append({"form": "fraction", "lo": 0.0, "hi": 1.0, "says": "a fraction (0..1)"})
    elif re.search(r"\b(?:returns?|as|is)\s+(?:a|the)\s+percent(?:age)?\b", low):
        out.append({"form": "fraction", "lo": 0.0, "hi": 100.0, "says": "a percentage (0..100)"})
    if first_seq and re.search(r"\b(?:mean|average)\b", low) and not re.search(r"\bweighted\b|\brunning\b|\bmoving\b", low):
        out.append({"form": "mean", "of": first_seq, "says": f"the mean of `{first_seq}`"})
    m = re.search(r"\b(?:returns?|gives?|is)\s+(-?\d+(?:\.\d+)?|none|an? empty (?:list|string|dict))\s+(?:for|when|if)\s+"
                  r"(?:an?\s+)?(?:empty|no\b)", low)
    if m and first_seq:
        v = m.group(1)
        val: Any = None if v == "none" else [] if "list" in v else "" if "string" in v else {} if "dict" in v else _f(v)
        out.append({"form": "empty_value", "of": first_seq, "value": val, "says": m.group(0).strip()})
    if re.search(r"\bnever negative\b|\bnon-?negative\b|\bis (?:always )?positive\b|\breturns? (?:a )?positive\b", low):
        strict = bool(re.search(r"\bpositive\b", low)) and not re.search(r"\bnon-?negative\b|\bnever negative\b", low)
        out.append({"form": "non_negative", "strict": strict, "says": "positive" if strict else "never negative"})
    for p in params:
        if re.search(rf"\b(?:never (?:exceeds?|goes above|more than)|at most|capped at|no more than|up to)\s+`?{re.escape(p)}`?",
                     low):
            out.append({"form": "cap_param", "cap": p, "says": f"never more than `{p}`"})
    if first_seq and re.search(r"\bone (?:per|for each)\b|\bsame length\b|\beach (?:item|entry|row|element) gets\b", low):
        out.append({"form": "same_length", "of": first_seq, "says": f"one result per item of `{first_seq}`"})
    m = re.search(r"\b(ascending|descending|oldest first|newest first|earliest first|latest first|sorted)\b", low)
    if m and re.search(r"\breturns?\b|\blist\b|\border\b", low):
        desc = bool(re.search(r"\b(descending|newest first|latest first|largest first|highest first)\b", low))
        out.append({"form": "sorted", "desc": desc, "says": m.group(1)})
    if re.search(r"\bunique\b|\bdistinct\b|\bwithout duplicates\b|\bno duplicates\b|\bde-?duplicat", low):
        out.append({"form": "unique", "says": "no duplicates"})
    if first_seq and re.search(r"\btotal\b|\bsum of\b|\bnumber of\b|\bcount of\b", low) and \
            not re.search(r"\b(?:mean|average|weighted|max|min|percent)\b", low):
        out.append({"form": "total", "of": first_seq, "says": f"a total over `{first_seq}`"})
    if first_seq and re.search(r"\bdoes not (?:modify|mutate|change)\b|\breturns? a (?:new|copy)\b|\bunchanged\b|\bin place\b",
                               low) and not re.search(r"\bin place\b", low):
        out.append({"form": "unchanged", "of": first_seq, "says": f"`{first_seq}` is not modified"})
    return out



def read_name(name: str, params: List[str], kinds: Dict[str, str], returns: str) -> List[Dict[str, Any]]:
    """owner 2026-10-07 (top-10 row 1, misinterpretation): the function's NAME is stated intent too. Only names whose
    words imply a property of the result over its ONLY list parameter (or a boolean answer) are read."""
    toks = set(name.lower().split("_"))
    out: List[Dict[str, Any]] = []
    seqs = [p for p in params if kinds.get(p) == "seq"]
    only_seq = next(iter(seqs)) if seqs and params == [next(iter(seqs))] else None   # the function's ONLY parameter is a list
    if only_seq:
        for words, form, says in ((("max", "maximum", "largest", "highest", "biggest", "peak"), "name_max", "the largest"),
                                  (("min", "minimum", "smallest", "lowest", "least"), "name_min", "the smallest"),
                                  (("first", "earliest"), "name_first", "the first"),
                                  (("last", "latest", "final"), "name_last", "the last")):
            # ("count" was read as "a count of items" and dropped the same day: it also means "tally up" —
            #  blind tree 2's key says count_schemes = sum(stakes); a name word that means two things is not a claim)
            if toks & set(words) and not (form in ("name_first", "name_last") and toks & {"max", "min", "sorted"}):
                out.append({"form": form, "of": only_seq, "says": f"`{name}` names {says} of `{only_seq}`"})
                break
    if (next(iter(name.lower().split("_")), "") in ("is", "has", "can", "should", "needs", "allows")
            or returns == "bool"):
        out.append({"form": "predicate", "says": f"`{name}` is a yes/no question" + (" (-> bool)" if returns == "bool" else "")})
    return out

_SEQS = [[3.0, 1.0, 2.0], [5.0], [2.0, 8.0, 4.0, 6.0], [7.0, 7.0, 1.0]]
_NUMS = [2.0, 0.5, 7.0, 13.0, 1.0]
_INTS = [2, 1, 5, 9, 0]
_STRS = ["abc", "Hello World", "x"]


def samples(params: List[str], kinds: Dict[str, str], ints: Dict[str, bool]) -> List[List[Any]]:
    """A base call and one-parameter-at-a-time variations (bounded: never a full product)."""
    pools = []
    for p in params:
        k = kinds.get(p)
        pools.append(_SEQS if k == "seq" else _STRS if k == "str" else _INTS if ints.get(p) else _NUMS)
    base = [next(iter(pool)) for pool in pools]
    out = [list(base)]
    for i, pool in enumerate(pools):
        for v in itertools.islice(pool, 1, None):
            a = list(base)
            a[i] = list(v) if isinstance(v, list) else v
            out.append(a)
    return out


def check(func: Any, claims: List[Dict[str, Any]], fn: Callable, run: Callable, not_run: Any,
          params: List[str], kinds: Dict[str, str], ints: Dict[str, bool],
          recorded: Any = None) -> List[Dict[str, Any]]:
    """Probe each general claim; return the contradictions (claim, says, expected, got, probe). `recorded` (M-153):
    real argument sets the target's own run produced — probed before the generated samples, so a function that takes
    objects can be checked at all (scan-time execution, runtime_plugin/cr_probe_plan.py)."""
    out: List[Dict[str, Any]] = []
    calls = [list(a) for a in (recorded or [])] + ([] if recorded and "other" in kinds.values()
                                                    else samples(params, kinds, ints))

    def call(args: List[Any]) -> Any:
        return run(fn, *[list(a) if isinstance(a, list) else a for a in args])

    def bad(c: Dict[str, Any], expected: str, got: Any, args: List[Any]) -> None:
        out.append({"claim": c["form"], "says": c["says"], "expected": expected, "got": repr(got),
                    "probe": f"{func.name}({', '.join(repr(a) for a in args)})"})

    def nums(r: Any) -> bool:
        return isinstance(r, (int, float)) and not isinstance(r, bool) and math.isfinite(r)

    for c in claims:
        k = c["form"]
        if k in ("out_range", "fraction"):
            lo, hi, tol = c["lo"], c["hi"], 1e-9
            for a in calls:
                r = call(a)
                if r is not not_run and nums(r) and (r < lo - tol or r > hi + tol):
                    bad(c, f"in [{lo:g}, {hi:g}]", r, a)
                    break
        elif k == "mean":
            i = params.index(c["of"])
            for a in calls:
                r = call(a)
                xs = a[i]
                if r is not not_run and nums(r) and xs and (r < min(xs) - 1e-9 or r > max(xs) + 1e-9):
                    bad(c, f"between {min(xs):g} and {max(xs):g} (the list's min and max)", r, a)
                    break
        elif k == "empty_value":
            i = params.index(c["of"])
            a = list(next(iter(calls)))
            a[i] = []
            r = call(a)
            want = c["value"]
            same = (r == want) if not (nums(r) and nums(want)) else math.isclose(r, want, abs_tol=1e-9)
            if r is not not_run and not same:
                bad(c, repr(want), r, a)
        elif k == "non_negative":
            zero = 0.0
            for a in calls:
                r = call(a)
                if r is not not_run and nums(r) and (r < zero or (c["strict"] and r == zero)):
                    bad(c, "> 0" if c["strict"] else "≥ 0", r, a)
                    break
        elif k == "cap_param":
            i = params.index(c["cap"])
            for a in calls:
                r = call(a)
                if r is not not_run and nums(r) and nums(a[i]) and r > a[i] + 1e-9:
                    bad(c, f"≤ {c['cap']} ({a[i]:g})", r, a)
                    break
        elif k == "same_length":
            i = params.index(c["of"])
            for a in calls:
                r = call(a)
                if r is not not_run and isinstance(r, (list, tuple)) and len(r) != len(a[i]):
                    bad(c, f"{len(a[i])} items", f"{len(r)} items", a)
                    break
        elif k == "sorted":
            for a in calls:
                r = call(a)
                if r is not not_run and isinstance(r, list) and r[1:] and all(nums(x) or isinstance(x, str) for x in r):
                    try:
                        want = sorted(r, reverse=c["desc"])
                    except TypeError:
                        continue
                    if r != want:
                        bad(c, repr(want), r, a)
                        break
        elif k == "unique":
            for a in calls:
                r = call(a)
                if r is not not_run and isinstance(r, list):
                    try:
                        dup = len(set(r)) != len(r)
                    except TypeError:
                        continue
                    if dup:
                        bad(c, "no repeated element", r, a)
                        break
        elif k == "total":
            i = params.index(c["of"])
            base = list(next(iter(calls)))
            xs, ys = [3.0, 1.0], [2.0, 5.0]
            a1, a2, a3 = list(base), list(base), list(base)
            a1[i], a2[i], a3[i] = xs, ys, xs + ys
            r1, r2, r3 = call(a1), call(a2), call(a3)
            if not_run not in (r1, r2, r3) and all(nums(r) for r in (r1, r2, r3)) and \
                    not math.isclose(r3, r1 + r2, rel_tol=1e-9, abs_tol=1e-9):
                bad(c, f"f(a + b) = f(a) + f(b) = {r1 + r2:g}", r3, a3)
        elif k in ("name_max", "name_min", "name_first", "name_last"):
            i = params.index(c["of"])
            # "first" / "last" mean a position OR a time ("first arrival" = the earliest): either reading is correct
            accept = {"name_max": (max,), "name_min": (min,), "name_first": (lambda v: v[0], min),
                      "name_last": (lambda v: v[-1], max)}[k]
            pick = next(iter(accept))
            for a in calls:
                xs = a[i]
                if not xs:
                    continue
                r = call(a)
                if r is not_run or not nums(r):
                    continue
                want = pick(xs)
                if not any(math.isclose(r, g(xs), rel_tol=1e-9, abs_tol=1e-9) for g in accept):
                    bad(c, f"{want!r} ({c['says'].split(' names ')[1]})", r, a)
                    break
        elif k == "predicate":
            for a in calls:
                r = call(a)
                if r is not not_run and not isinstance(r, bool):
                    bad(c, "True or False", r, a)
                    break
        elif k == "unchanged":
            i = params.index(c["of"])
            a = [list(x) if isinstance(x, list) else x for x in next(iter(calls))]
            before = list(a[i])
            r = run(fn, *a)
            if r is not not_run and a[i] != before:
                bad(c, f"`{c['of']}` still {before!r}", a[i], a)
    return out
