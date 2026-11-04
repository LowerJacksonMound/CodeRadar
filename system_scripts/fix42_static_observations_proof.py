#!/usr/bin/env python3
"""FIX_42 + FIX_43a + FIX_43b unit proof (owner rulings 2026-09-15: the five static observations, run 120 `chemistry`;
the SEVEN METHODS table + `readability=` / `traps=`, run 121 `digital_man`; 2026-09-16 Calls A and B after the hand
check, run 122 `the_weapon`).

Part 1 (FIX_42/43a) — four synthetic candidates for one row, below. Part 2 (Call A) — a prescription's SHAPE is read as
code: NAI-127's `ast.literal_eval(<text>)` scores like code and outranks NAI-160's validate-the-sink shape on the
`evaluate` row (hand-check #15); NAI-011's placeholder-only body reads `opaque:1` and stays low against the
NotImplementedError stub on the `reserved` row (#17). Part 3 — `defensive=` says a risky call was removed (100) or
kept behind a guard (40): the removal wins. Part 4 (Call B) — on a two-rule row the neighbour rule's readable rewriter
no longer outranks the row's own readable candidate once the Builder names the deciding rule (`answers=row`,
hand-check #4); without a deciding rule nothing changes (other callers of decide() are untouched).

Four synthetic candidates for ONE row. A and B differ on every one of the seven token families; C keeps A's
logic but nests deeper with cryptic names (method 5); D keeps A's logic but introduces a mutable default
(method 7). Prints every candidate's seven tokens, the per-method scores, the selection totals in rank order
and the Ranker's `why` (which names the deciding method). Exits non-zero unless: every family differs between
A and B; C differs from A on readability and D on traps; the pick is A; A outranks B, C and D; the table's
weights sum to 100 with every method's best entry at 100. Nothing here decides for the Ranker — it only shows
what the Ranker was handed and what it did with it. No candidate is unpickable (owner, 2026-09-15 late).

    .venv_new/bin/python system_scripts/fix42_static_observations_proof.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "system_scripts"))

from no_aivalidator.cheatsheets.cheatsheet_intelligence.knowledge_base import (  # noqa: E402
    RANKER_METHOD_WEIGHTS, ProjectProfile, SolutionCandidate, SolutionRanker,
)
from no_aivalidator.cheatsheets.cheatsheet_reviewer import STATIC_OBSERVATION_ORDER  # noqa: E402

BEFORE = '''def first_big(items, limit):
    found = False
    for item in items:
        if item > limit:
            found = True
            break
    return found
'''

# A: the explicit loop becomes any() (flow states the loop + break went), no new nesting, the builtin, stdlib only, adds a None guard
AFTER_A = '''def first_big(items, limit):
    if items is None:
        return False
    return any(item > limit for item in items)
'''

# B: return moved into a nested loop, deeper + copies the input per iteration, re-rolls a running max,
# adds a third-party import and a match statement (needs 3.10), no guard; deeper nesting with a cryptic name;
# a mutable default and a shadowed builtin
AFTER_B = '''import numpy
def first_big(items, limit, seen=[]):
    best = 0
    for item in items:
        for other in list(items):
            if other > best:
                best = other
            match item:
                case _:
                    if item > limit:
                        list = seen
                        return True
    return False
'''

# C: A's logic, but nested deeper with cryptic names (method 5 only)
AFTER_C = '''def first_big(items, limit):
    if items is None:
        return False
    else:
        if True:
            q = any(item > limit for item in items)
            r2 = q
            return r2
'''

# D: A's logic with a mutable default introduced (method 7 only)
AFTER_D = '''def first_big(items, limit, cache={}):
    if items is None:
        return False
    return any(item > limit for item in items)
'''


# ---- Part 2-4 material (FIX_43b, 2026-09-16) ------------------------------------------------------------------
EVALUATE_BEFORE = "def evaluate(expr):\n    return eval(expr)\n"
SHAPE_127 = "value = ast.literal_eval(<text>)   # or: HANDLERS[<name>](<args>) / json.loads(<text>) / getattr(<obj>, <attr>)"
SHAPE_160 = "if not <check(<param>)>:\n    raise ValueError(f'<param>: <what was expected>')\n<sink>(<param>)"
RESERVED_BEFORE = 'def reserved():\n    """Reserved for a later release."""\n'
SHAPE_011 = "def <name>(...):\n    <action | return <value>>"
STUB_120 = 'def reserved():\n    """Reserved for a later release."""\n    raise NotImplementedError("reserved: not implemented")\n'
GUARDED_EVAL = "def evaluate(expr):\n    if not isinstance(expr, str):\n        raise TypeError('expr: a str was expected')\n    return eval(expr)\n"
REMOVED_EVAL = "def evaluate(expr):\n    return ast.literal_eval(expr)\n"
COLLECT_BEFORE = "def collect(items=[]):\n    items.append(1)\n    return items\n"
NEIGHBOUR_071 = "def collect(items=None):\n    if items is None:\n        items = []\n    items.append(1)\n    return items\n"
OWN_021S = "def collect(items=None):\n    collected = list(items) if items is not None else []\n    collected.append(1)\n    return collected\n"


def _shape(role: str, rule: str, before: str, shape: str) -> SolutionCandidate:
    """A prescribed candidate exactly as the Builder offers one (BUILDER_DAEMON._prescribed_candidate's tokens)."""
    return SolutionCandidate(solution=f"prescription {rule}", role=role, before_code=before, after_code=shape,
                             source="prescribed", observations=["kind=prescribed", "parse=shape", "differs=yes", f"rule={rule}"])


def _code(role: str, rule: str, before: str, after: str) -> SolutionCandidate:
    return SolutionCandidate(solution=f"rewrite {role}", role=role, before_code=before, after_code=after,
                             source="ast_rewriter", observations=["parse=ok", "differs=yes", "safety=clean", f"rule={rule}"])


def _tok(c: SolutionCandidate, fam: str) -> str:
    return next((o.split("=", 1)[1] for o in c.observations if o.startswith(fam + "=")), "")


def _show(title: str, decision, cands) -> None:
    print(f"\n{title}")
    for rec in sorted((r for r in decision.considered if "selection_total" in r), key=lambda r: -r["selection_total"]):
        print(f"  {rec['role']}: total {rec['selection_total']}  methods {rec['method_scores']}")
    for c in cands:
        print(f"  {c.role}: {[o for o in c.observations if o.split('=', 1)[0] in STATIC_OBSERVATION_ORDER or o.startswith(('answers=', 'rule='))]}")
    print(f"  why: {decision.why[:220]}")


def parts_2_to_4(ranker: SolutionRanker) -> list[str]:
    problems: list[str] = []
    # Part 2a — #15 evaluate: NAI-127's shape (code) vs NAI-160's shape (guard + placeholder call)
    c127, c160 = _shape("solution_NAI-127", "NAI-127", EVALUATE_BEFORE, SHAPE_127), _shape("solution_NAI-160", "NAI-160", EVALUATE_BEFORE, SHAPE_160)
    d = ranker.decide([c160, c127], error_message="NAI-160 (line 14): risky_sinks=['expr'], has_validation=False", rca_evidence=[],
                      target_code=EVALUATE_BEFORE, deciding_rule="NAI-160")
    _show("Part 2a — hand-check #15 `evaluate`: NAI-127 shape vs NAI-160 shape (deciding rule NAI-160)", d, [c127, c160])
    if "opaque" in " ".join(c127.observations):
        problems.append("NAI-127's shape must read as code (no opaque statement)")
    if not _tok(c127, "defensive").startswith("removes_risky_call:eval"):
        problems.append(f"NAI-127's defensive token should say removes_risky_call:eval, got {_tok(c127, 'defensive')!r}")
    if "risky_call_unknown:eval" not in _tok(c160, "defensive") or "adds_guard" not in _tok(c160, "defensive"):
        problems.append(f"NAI-160's defensive token should read a guard added and a placeholder call, got {_tok(c160, 'defensive')!r}")
    if d.pick is not c127:
        problems.append(f"#15: pick is {d.pick.role if d.pick else None}, expected solution_NAI-127 (remove the sink)")
    # Part 2b — #17 reserved: NAI-011's placeholder-only body vs the NotImplementedError stub (NAI-120's form)
    c011, cstub = _shape("solution_NAI-011", "NAI-011", RESERVED_BEFORE, SHAPE_011), _shape("solution_NAI-120", "NAI-120", RESERVED_BEFORE, STUB_120)
    d = ranker.decide([c011, cstub], error_message="NAI-011 (line 10): func_name=reserved, returns=0, yields=0, calls=0, assigns=0",
                      rca_evidence=[], target_code=RESERVED_BEFORE, deciding_rule="NAI-011")
    _show("Part 2b — hand-check #17 `reserved`: NAI-011 shape vs the stub in NAI-120's shape (deciding rule NAI-011)", d, [c011, cstub])
    if "opaque:1" not in _tok(c011, "readability"):
        problems.append(f"NAI-011's shape must read opaque:1, got {_tok(c011, 'readability')!r}")
    if d.pick is not cstub:
        problems.append(f"#17: pick is {d.pick.role if d.pick else None}, expected the stub (real code beats a prose shape even as the neighbour)")
    # Part 3 — a risky call removed vs guarded (real code)
    cg, cr = _code("guarded", "NAI-160", EVALUATE_BEFORE, GUARDED_EVAL), _code("removed", "NAI-127", EVALUATE_BEFORE, REMOVED_EVAL)
    d = ranker.decide([cg, cr], error_message="", rca_evidence=[], target_code=EVALUATE_BEFORE)
    _show("Part 3 — risky call removed vs kept behind a guard (no deciding rule)", d, [cg, cr])
    if not (cr.method_scores["defensive"] > cg.method_scores["defensive"]):
        problems.append("method 4 must score removing eval above guarding it")
    if "keeps_risky_call:eval" not in _tok(cg, "defensive"):
        problems.append(f"the guarded candidate should read keeps_risky_call:eval, got {_tok(cg, 'defensive')!r}")
    if d.pick is not cr:
        problems.append(f"Part 3: pick is {d.pick.role if d.pick else None}, expected `removed`")
    # Part 4 — Call B: a two-rule row (NAI-021S deciding, NAI-071 neighbour), both candidates readable
    cn, co = _code("mutable_default_fix", "NAI-071", COLLECT_BEFORE, NEIGHBOUR_071), _code("new_sequence_fix", "NAI-021S", COLLECT_BEFORE, OWN_021S)
    d0 = ranker.decide([cn, co], error_message="NAI-021S: Alias identity chain", rca_evidence=[], target_code=COLLECT_BEFORE)
    _show("Part 4a — hand-check #4 `collect` with NO deciding rule (other callers unchanged)", d0, [cn, co])
    if any(o.startswith("answers=") for c in (cn, co) for o in c.observations):
        problems.append("answers= must not be weighed when no deciding rule is passed")
    cn, co = _code("mutable_default_fix", "NAI-071", COLLECT_BEFORE, NEIGHBOUR_071), _code("new_sequence_fix", "NAI-021S", COLLECT_BEFORE, OWN_021S)
    d = ranker.decide([cn, co], error_message="NAI-021S: Alias identity chain", rca_evidence=[], target_code=COLLECT_BEFORE, deciding_rule="NAI-021S")
    _show("Part 4b — the same row with deciding rule NAI-021S", d, [cn, co])
    if _tok(co, "answers") != "row" or _tok(cn, "answers") != "neighbour":
        problems.append(f"answers tokens wrong: own={_tok(co, 'answers')!r} neighbour={_tok(cn, 'answers')!r}")
    if d.pick is not co:
        problems.append(f"#4: pick is {d.pick.role if d.pick else None}, expected new_sequence_fix (answers the deciding rule)")
    if "answers=row" not in d.why or "answers=neighbour" not in d.why:
        problems.append("decision.why must show answers=row / answers=neighbour")
    if any(not rec["pickable"] for rec in (d.considered + d0.considered)):
        problems.append("a candidate was made unpickable — nothing in FIX_43b may do that")
    return problems


def main() -> int:
    ranker = SolutionRanker(project_profile=ProjectProfile(python_version="3.8"))
    cands = {
        "A": SolutionCandidate(solution="use any()", role="A", before_code=BEFORE, after_code=AFTER_A, source="ast_rewriter"),
        "B": SolutionCandidate(solution="nested scan", role="B", before_code=BEFORE, after_code=AFTER_B, source="ast_rewriter"),
        "C": SolutionCandidate(solution="use any(), nested", role="C", before_code=BEFORE, after_code=AFTER_C, source="ast_rewriter"),
        "D": SolutionCandidate(solution="use any(), cache", role="D", before_code=BEFORE, after_code=AFTER_D, source="ast_rewriter"),
    }
    for c in cands.values():
        c.observations = ["parse=ok", "differs=yes", "safety=clean"] + list(c.observations)   # the Builder's order
    decision = ranker.decide(list(cands.values()), error_message="", rca_evidence=[], target_code=BEFORE)

    print("observations{} (the seven tokens per candidate):")
    tok: dict[str, dict[str, str]] = {}
    for rec in decision.considered:
        seven = [o for o in rec["observations"] if o.split("=", 1)[0] in STATIC_OBSERVATION_ORDER]
        print(f"  {rec['role']}: {seven}")
        tok[rec["role"]] = {o.split("=", 1)[0]: o.split("=", 1)[1] for o in rec["observations"] if "=" in o}
    ordered = sorted((rec for rec in decision.considered if "selection_total" in rec), key=lambda r: -r["selection_total"])
    print("selection{} (rank order; total = Σ weight × method score / 100):")
    for rec in ordered:
        print(f"  {rec['role']}: total {rec['selection_total']}  methods {rec['method_scores']}")
    print("the seven-method table (weight, token family):", {k: (m["weight"], m["token"]) for k, m in RANKER_METHOD_WEIGHTS.items()})
    print(f"decision.why: {decision.why}")

    a, b, c, d = cands["A"], cands["B"], cands["C"], cands["D"]
    problems: list[str] = []
    for fam in STATIC_OBSERVATION_ORDER:
        if tok["A"].get(fam) == tok["B"].get(fam):
            problems.append(f"{fam} does not differ between A and B: {tok['A'].get(fam)!r}")
    if tok["C"].get("readability") == tok["A"].get("readability"):
        problems.append("C's readability token does not differ from A's")
    if not tok["D"].get("traps", "").startswith("mutable_default:cache"):
        problems.append(f"D's traps token should name the mutable default, got {tok['D'].get('traps')!r}")
    if decision.pick is not a:
        problems.append(f"pick is {decision.pick.role if decision.pick else None}, expected A")
    for other in (b, c, d):
        if not a.total_score > other.total_score:
            problems.append(f"A {a.total_score:.2f} not above {other.role} {other.total_score:.2f}")
    if a.method_scores["readability"] <= c.method_scores["readability"]:
        problems.append("method 5 did not separate A from C")
    if a.method_scores["traps"] <= d.method_scores["traps"]:
        problems.append("method 7 did not separate A from D")
    if sum(m["weight"] for m in RANKER_METHOD_WEIGHTS.values()) != 100:
        problems.append("the seven weights must sum to 100")
    for name, m in RANKER_METHOD_WEIGHTS.items():
        if max(m["values"].values()) != 100:
            problems.append(f"{name}: best entry must be 100")
    if any(not rec["pickable"] for rec in decision.considered):
        problems.append("a candidate was made unpickable — nothing in the seven may do that")
    if "deciding method:" not in decision.why:
        problems.append("decision.why does not name the deciding method")
    problems += parts_2_to_4(ranker)
    for p in problems:
        print("PROBLEM:", p)
    print("FIX_42/43a/43b unit proof:", "PASS" if not problems else "FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
