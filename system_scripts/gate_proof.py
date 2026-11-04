#!/usr/bin/env python3
"""gate_proof.py — G0's fixture proof (S5-1, 2026-09-17; packet REWRITER_GATE_PACKET §B).

The corpus is the hand check itself: all 55 rewriter hunks run 141 published on its target, as
the client wrote them — `client_edit_log_after_T6.json` in run 141's evidence folder under
`.archive/gate_evidence/runs/`, 43 `standing` CORRECT + 12 `backed_out_by: T6` WRONG, with the
before/after bytes of every span. The module context each span was cut from is read from the
snapshot `~/CodeRadar_snapshots/<that target>_20260917_062701` (the pre-T6 bytes).

    the 12 WRONG must be WITHHELD, each by the check the packet names for it
    the 43 CORRECT must PASS — every one

Part 2 proves the WIRING on a fixture row (the health check's own FIX_51 shape): a row whose every
candidate G0 withholds is offered all the same, is unpickable, carries the gate's sentence in
`decision.why`, and appears in the mirror's withheld block as `withheld_by: "gate"`.

A CORRECT row failing a check does not mean the row was wrong: it means the check is too broad and
must be narrowed (three such narrowings are recorded in gate.py's header). Nothing here decides
anything the gate does not; it only shows the gate the hunks and prints what it said.

    .venv_new/bin/python system_scripts/gate_proof.py [--json OUT]     exit 0 = PASS
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from no_aivalidator.repair_generators import REGISTRY                      # noqa: E402
from no_aivalidator.repair_generators.gate import Rewrite, check, failures  # noqa: E402

_RUNS = ROOT / ".archive" / "gate_evidence" / "runs"
RUN_141 = next((p.parent for p in sorted(_RUNS.glob("*/obs_run141_phase1.py"))), _RUNS / "run_141")   # the folder is named after run 141's target
LOG = RUN_141 / "client_edit_log_after_T6.json"
SNAPSHOT = Path.home() / "CodeRadar_snapshots" / f"{RUN_141.name}_20260917_062701"

# The check the packet names for each WRONG row (row number in HAND_CHECK_T6_PART_B). A row is
# proven when at least one of its named checks is among the checks that withheld it.
EXPECTED: Dict[int, tuple] = {
    21: ("value_return_lost", "predicate:NAI-131:drop_value"),
    30: ("live_store_removed", "predicate:NAI-006:keep_first"),
    33: ("live_store_removed", "predicate:NAI-006:keep_first"),
    35: ("predicate:NAI-091:shallow_copy",),
    53: ("output_trips_rule",),
    57: ("fallback_to_raise",),
    61: ("value_return_lost", "predicate:NAI-026:else_not_implemented"),
    70: ("value_return_lost", "predicate:NAI-053:later_not_implemented"),
    71: ("predicate:NAI-091:shallow_copy",),
    73: ("side_effect_call_removed", "predicate:NAI-010:drop_assignment"),   # FIX_60 added the predicate
    74: ("side_effect_call_removed", "predicate:NAI-010:drop_assignment"),   # beside the packet's check
    75: ("fallback_to_raise",),
}

# Rows T6 hand-marked CORRECT that a LATER owner ruling withholds — the log keeps its verdicts (they are
# the record of what was seen then); the proof reads them through this table. FIX_63 (I-115, 2026-09-17):
# T6 passed both `keep_first` dict-literal repairs because the plant never READ the shadowed key, so
# nothing observable moved in that program — but the literal itself now evaluates to a value the program
# never held, the same inversion FIX_56 retired on NAI-006, and `live_store_removed` cannot see a store
# that is a key in a literal. The predicate is the gate's word.
RULED_AFTER_T6: Dict[str, tuple] = {
    "colorama/repair_plant_keys.py::palette::13": ("predicate:NAI-175:keep_first",),
    "colorama/repair_plant_keys.py::flags::18": ("predicate:NAI-177:keep_first",),
}

_ROLE_TO_RULE = {g.role: rid for rid, g in REGISTRY.items() if g.role}


def _rewrite(rec: Dict[str, Any]) -> Rewrite:
    role, _, variant = str(rec.get("selected_role") or "").partition(":")
    src = SNAPSHOT / rec["file"]
    return Rewrite(
        rule_id=_ROLE_TO_RULE.get(role, ""),
        role=role,
        variant=variant,
        file=rec["file"],
        span=rec.get("replace_span", ""),
        before_src=rec["before"],
        after_src=rec["after"],
        module_src=src.read_text(encoding="utf-8", errors="replace") if src.is_file() else "",
    )


def run() -> Dict[str, Any]:
    log = json.loads(LOG.read_text(encoding="utf-8"))
    rows = [r for r in log if r.get("kind") == "diff" and r.get("t6_verdict") in ("CORRECT", "WRONG")]
    wrong = [r for r in rows if r["t6_verdict"] == "WRONG"]
    correct = [r for r in rows if r["t6_verdict"] == "CORRECT"]
    res: Dict[str, Any] = {"rows": len(rows), "wrong": len(wrong), "correct": len(correct),
                           "withheld": [], "passed": [], "errors": []}
    if len(rows) != 55 or len(wrong) != 12 or len(correct) != 43:
        res["errors"].append(f"corpus is {len(rows)} rows ({len(wrong)} wrong / {len(correct)} correct), "
                             f"expected 55 (12 / 43)")

    print(f"G0 gate — {len(rows)} rewriter hunks from run 141 "
          f"({len(wrong)} WRONG must be withheld, {len(correct)} CORRECT must pass)\n")

    print("THE TWELVE")
    by_row = {int(r["t6_row"]): r for r in wrong}
    for n, want in EXPECTED.items():          # EXPECTED is in row order — no sort, nothing ordered here
        rec = by_row[n]
        rw = _rewrite(rec)
        failed = failures(rw)
        names = [f for f, _ in failed]
        verdict = check(rw)
        proven = (not verdict.ok) and any(w in names for w in want)
        res["withheld"].append({"row": n, "file": rec["file"], "role": rec["selected_role"],
                                "rule_id": rw.rule_id, "checks": names, "expected": list(want),
                                "reason": verdict.reason, "proven": proven})
        print(f"  #{n:<3} {rw.rule_id:<8} {rec['selected_role']:<44} "
              f"{'WITHHELD' if not verdict.ok else 'PASSED (!)':<11} {'✓' if proven else '✗'}")
        print(f"        checks: {', '.join(names) or '(none)'}")
        if verdict.reason:
            print(f"        {verdict.reason}")
        if not proven:
            res["errors"].append(f"#{n} ({rec['selected_role']}): expected one of {want}, got {names or '(passed)'}")

    print("\nRULED AFTER T6 — FIX_63 (I-115)")
    ruled = [r for r in correct if r["row"] in RULED_AFTER_T6]
    correct = [r for r in correct if r["row"] not in RULED_AFTER_T6]
    for rec in ruled:
        want = RULED_AFTER_T6[rec["row"]]
        rw = _rewrite(rec)
        failed = failures(rw)
        names = [f for f, _ in failed]
        verdict = check(rw)
        proven = (not verdict.ok) and any(w in names for w in want)
        res["withheld"].append({"row": rec["row"], "file": rec["file"], "role": rec["selected_role"],
                                "rule_id": rw.rule_id, "checks": names, "expected": list(want),
                                "reason": verdict.reason, "proven": proven, "ruled_after_t6": "FIX_63"})
        print(f"  {rec['row']:<44} {rec['selected_role']:<40} "
              f"{'WITHHELD' if not verdict.ok else 'PASSED (!)':<11} {'✓' if proven else '✗'}")
        print(f"        checks: {', '.join(names) or '(none)'}")
        if verdict.reason:
            print(f"        {verdict.reason}")
        if not proven:
            res["errors"].append(f"{rec['row']} ({rec['selected_role']}): FIX_63 expected one of {want}, "
                                 f"got {names or '(passed)'}")
    if len(ruled) != len(RULED_AFTER_T6):
        res["errors"].append(f"RULED_AFTER_T6 names {len(RULED_AFTER_T6)} rows, the corpus has {len(ruled)}")

    print("\nTHE FORTY-ONE (T6's forty-three less the two ruled after)")
    bad = 0
    for rec in correct:
        rw = _rewrite(rec)
        failed = failures(rw)
        verdict = check(rw)
        res["passed"].append({"row": rec["row"], "role": rec["selected_role"], "rule_id": rw.rule_id,
                              "ok": verdict.ok, "checks": [f for f, _ in failed]})
        if not verdict.ok:
            bad += 1
            print(f"  ✗ {rec['row']:<58} {rec['selected_role']}")
            for name, reason in failed:
                print(f"      {name}: {reason}")
            res["errors"].append(f"CORRECT row {rec['row']} ({rec['selected_role']}) withheld by "
                                 f"{[f for f, _ in failed]} — the check is too broad, narrow it")
    print(f"  {len(correct) - bad}/{len(correct)} pass the gate" + ("" if not bad else f" — {bad} WITHHELD (too broad)"))

    n_withheld = sum(1 for w in res["withheld"] if w["proven"] and "ruled_after_t6" not in w)
    n_ruled = sum(1 for w in res["withheld"] if w["proven"] and "ruled_after_t6" in w)
    print(f"\n{n_withheld}/12 withheld with the expected check · {n_ruled}/{len(RULED_AFTER_T6)} ruled after T6 "
          f"(FIX_63) withheld · {len(correct) - bad}/{len(correct)} correct rows pass")

    res["wiring"] = wiring(res["errors"])
    res["lane_a"] = lane_a(res["errors"])       # S5-2: FIX_56 · FIX_60, source and gate, both sides
    res["lane_b"] = lane_b(res["errors"])
    res["lane_c"] = lane_c(res["errors"])
    res["fix_63"] = fix_63(res["errors"])       # I-115: FIX_56's ruling on dict literals, source and gate
    res["fix_64"] = fix_64(res["errors"])       # I-116: FIX_60's rule on NAI-031, source and gate
    res["fix_65"] = fix_65(res["errors"])       # I-117: the module as purity evidence, via candidates_of
    res["fix_68"] = fix_68(res["errors"])       # I-150: NAI-120's false positive on a real lifecycle close
    res["fix_68b"] = fix_68b(res["errors"])     # I-150's sibling: solution_NAI-120 withheld on ONE site
    res["ok"] = not res["errors"]
    print("\n" + ("✓ PASSED — G0 withholds the twelve, keeps the forty-three, and the wiring carries the reason"
                  if res["ok"] else "✗ FAILED"))
    for e in res["errors"]:
        print(f"  - {e}")
    return res


def wiring(errors: List[str]) -> Dict[str, Any]:
    """PART 2 — the wiring, end to end on a fixture (the health check's own FIX_51 shape).

    A row whose EVERY candidate G0 withholds must come out: offered (not dropped), unpickable (the
    Ranker ships nothing), the gate's sentence in `decision.why`, and the row in the mirror's withheld
    block with `withheld_by: "gate"` — the path FIX_51's block did not have.

    S5-4 (FIX_58 + FIX_61 (a)) moved the fixture from `push(items, value)` to `hushed(value)`. The
    `push` row no longer reaches the gate at all: FIX_58 put the owner's three conditions at the source,
    so the rewriter offers nothing there and the row's reason is a decline, not a gate sentence — source
    and gate in step is what FIX_58 is. `hushed` is the same shape of proof and lane C's own landing:
    NAI-017 is declared no-fix-by-design in the registry, so every candidate is BUILT (the shapes stay
    visible for the client) and every one is withheld with that reason."""
    import asyncio
    import tempfile
    from no_aivalidator.BUILDER_DAEMON import CheatsheetBuilder, read_file_locked, stage_mirror

    print("\nTHE WIRING (fixture: one row, every candidate withheld)")
    out: Dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "plant.py").write_text(
            "from contextlib import suppress\n\n\ndef hushed(value):\n    with suppress(Exception):\n"
            "        value.close()\n", encoding="utf-8")
        state = {
            "phase": "MONITORING", "target_repo": tmpdir, "last_scan": "fixture",
            "summary": {"total_functions": 1, "passed": 0, "failed": 1, "files_scanned": 1},
            "flagged_nodes": ["plant"],
            "results_by_file": {"plant.py": [{
                "function": "hushed", "line": 4, "end_line": 6, "passed": False,
                "rule_ids": ["NAI-017"], "context_ids": [], "finding_lines": [5],
                "failure_layer": "detection",
                "failure_reason": "NAI-017: `with suppress(Exception):` swallows every error of the body",
                "triggered_patterns": [{"tag": "NAI-017", "line": 5}],
            }]},
            "cross_file_analysis": {"stale_for_files": []}, "semantic_analysis": {},
        }
        rows, bsummary = asyncio.run(CheatsheetBuilder().build_rows(
            state, circuit={"nodes": [{"name": "plant", "imports": []}]}))
        row = rows["plant.py::hushed::4"]
        n_rep, n_nvf, _dirs = stage_mirror(rows, state, bsummary, target_repo=tmpdir, return_channel="",
                                           system_copy=Path(tmpdir) / ".sys_copy.json", severed_links=[])
        import scan_scope as _ss_mirror  # the ONE mirror location (owner ruling 2026-09-28)
        mirror_dir = _ss_mirror.mirror_path(Path(tmpdir), Path(tmpdir), ".noai_state.json").parent
        mirror = read_file_locked(Path(mirror_dir) / ".noai_state.json") or {}
        wh = [w for w in (mirror.get("withheld") or []) if w.get("withheld_by") == "gate"]
        out = {"candidates_considered": row["candidates_considered"], "pick_role": row["decision"]["pick_role"],
               "digest": row["digest"], "withheld_by": row.get("withheld_by"),
               "withheld_reason": row.get("withheld_reason"), "gate_withheld": row.get("gate_withheld"),
               "why": row["decision"]["why"], "repairs": n_rep, "no_vetted_fix": n_nvf,
               "mirror_withheld": wh, "summary": mirror.get("summary")}

        def _want(cond: bool, what: str) -> None:
            print(f"  {'✓' if cond else '✗'} {what}")
            if not cond:
                errors.append(f"wiring: {what}")

        _want(row["candidates_considered"] > 0, "the candidates are still offered, not dropped")
        _want(len(row.get("gate_withheld") or {}) == row["candidates_considered"],
              "every candidate carries the gate's observation")
        _want(row["decision"]["pick_role"] is None and not row["digest"],
              "the Ranker picked nothing — a gate-withheld candidate is unpickable")
        _want("gate: " in row["decision"]["why"], "decision.why carries the gate's sentence")
        _want(row.get("withheld_by") == "gate", "the row is marked withheld_by: gate")
        _want(len(wh) == 1 and str(wh[0].get("withheld_reason", "")).startswith("gate: "),
              "the mirror's withheld block shows the row with the gate's reason")
        _want((mirror.get("summary") or {}).get("withheld_gate") == 1,
              "summary.withheld_gate counts it apart from species withholding")
        _want((mirror.get("summary") or {}).get("withheld") == len(mirror.get("withheld") or []),
              "summary.withheld still equals the block's length (FIX_51's invariant)")
        _want(n_rep == 0 and n_nvf == 1, "no repair is published for the row; it stays visible as a finding")
        print(f"      {row['decision']['why'][:150]}")
    return out


# ── PART 3 — S5-2 lane A: FIX_56 (NAI-006) · FIX_60 (NAI-010 / NAI-147) ─────────────────────────
#
# Both fixes RETIRE a repair at the SOURCE, so each is proven twice: what the rewriter now mints
# (a variant never offered is the point — no gate can withhold what nobody mints) and what the gate
# says about that variant when it arrives from anywhere else (a client edit, an older cheatsheet).
# The lane contract asks for both sides of each rule — the shape that withholds and the shape that
# passes — so every span below is paired.

_OV = 'def stamp(value):\n    width = len(str(value))\n    width = 8\n    return str(value).rjust(width)'
_OV_FIRST = 'def stamp(value):\n    width = len(str(value))\n    return str(value).rjust(width)'
_OV_SECOND = 'def stamp(value):\n    width = 8\n    return str(value).rjust(width)'
_IMPURE = 'def report(items):\n    total = compute(items)\n    return len(items)'
_IMPURE_DROP = 'def report(items):\n    return len(items)'
_IMPURE_KEEP = 'def report(items):\n    compute(items)\n    return len(items)'
_PURE = 'def total(items):\n    count = len(items)\n    return sum(items)'
_PURE_DROP = 'def total(items):\n    return sum(items)'

#: (what it proves, rule, role, variant, before, after, must be withheld)
_LANE_A_GATE = [
    ("FIX_56 the live store deleted, the dead first write kept",
     "NAI-006", "immediate_overwrite_fix", "keep_first", _OV, _OV_FIRST, True),
    ("FIX_56 last-live: the dead first write deleted",
     "NAI-006", "immediate_overwrite_fix", "keep_second", _OV, _OV_SECOND, False),
    ("FIX_60 a delete that takes a call no evidence calls pure (`compute` is not a handle, not "
     "foreign, not imported from os/sys — G0's generic check is silent; the lane's predicate speaks)",
     "NAI-010", "dead_local_fix", "drop_assignment", _IMPURE, _IMPURE_DROP, True),
    ("FIX_60 the same span, the call kept and only the unread name dropped",
     "NAI-010", "dead_local_fix", "keep_call_effect", _IMPURE, _IMPURE_KEEP, False),
    ("FIX_60 a delete whose only call is `len` — pure by the detector's own table",
     "NAI-010", "dead_local_fix", "drop_assignment", _PURE, _PURE_DROP, False),
    ("FIX_60 NAI-147 mints through the same helper, so the same rule binds its id",
     "NAI-147", "unused_local_fix", "drop_assignment", _IMPURE, _IMPURE_DROP, True),
]

#: (what it proves, generator, span, the variants the rewriter must now mint, in order)
_LANE_A_SOURCE = [
    ("FIX_56 NAI-006 mints no `keep_first`", "fix_immediate_overwrite", _OV,
     ["keep_second", "keep_second_effect"]),
    ("FIX_60 NAI-010 offers `keep_call_effect` FIRST and no delete", "fix_dead_local", _IMPURE,
     ["keep_call_effect"]),
    ("FIX_60 NAI-010 still deletes when the callee is pure", "fix_dead_local", _PURE,
     ["drop_assignment", "keep_call_effect"]),
    ("FIX_60 NAI-147 (lane B's file, this lane's helper) reads the same rule", "fix_unused_local",
     _IMPURE, ["keep_call_effect"]),
    ("FIX_60 NAI-147 still deletes when the callee is pure", "fix_unused_local",
     'def total(values):\n    result = len(values)\n    return sum(values)',
     ["drop_assignment", "keep_call_effect"]),
]


def lane_a(errors: List[str]) -> Dict[str, Any]:
    """PART 3 — the S5-2 fixtures (packet §B FIX_56 · FIX_60; the owner's rulings §A on #30 #33 #73 #74)."""
    from no_aivalidator.repair_generators.core import fix_dead_local, fix_immediate_overwrite
    from no_aivalidator.repair_generators.extended_semantic import fix_unused_local
    gens = {"fix_immediate_overwrite": fix_immediate_overwrite, "fix_dead_local": fix_dead_local,
            "fix_unused_local": fix_unused_local}

    print("\nLANE A — FIX_56 (NAI-006 last-live) · FIX_60 (NAI-010 / NAI-147 pure-callee delete)")
    out: Dict[str, Any] = {"source": [], "gate": []}

    print("  what the rewriters mint")
    for what, gen, span, want in _LANE_A_SOURCE:
        got = [v for v, _after, _w in gens[gen](span)]
        ok = got == want
        out["source"].append({"what": what, "generator": gen, "variants": got, "expected": want, "ok": ok})
        print(f"    {'✓' if ok else '✗'} {gen}: {got}")
        print(f"        {what}")
        if not ok:
            errors.append(f"lane A source: {gen} minted {got}, expected {want} — {what}")

    print("  what the gate says")
    for what, rule_id, role, variant, before, after, withheld in _LANE_A_GATE:
        rw = Rewrite(rule_id=rule_id, role=role, variant=variant, file="lane_a_fixture.py",
                     span="", before_src=before, after_src=after)
        failed = failures(rw)
        names = [f for f, _ in failed]
        verdict = check(rw)
        ok = (not verdict.ok) is withheld
        if withheld and ok:
            ok = f"predicate:{rule_id}:{variant}" in names or "live_store_removed" in names
        out["gate"].append({"what": what, "rule_id": rule_id, "variant": variant, "checks": names,
                            "expected": "withheld" if withheld else "passes", "reason": verdict.reason,
                            "ok": bool(ok)})
        print(f"    {'✓' if ok else '✗'} {rule_id}:{variant:<18} "
              f"{'WITHHELD' if not verdict.ok else 'passes':<9} {', '.join(names) or '—'}")
        print(f"        {what}")
        if verdict.reason:
            print(f"        {verdict.reason}")
        if not ok:
            errors.append(f"lane A gate: {rule_id}:{variant} expected "
                          f"{'withheld' if withheld else 'to pass'}, checks {names or '(none)'} — {what}")
    return out


# ── S5-3 LANE B — FIX_57 · FIX_59 · FIX_62, at the source (2026-09-17) ──────────────────────────

_F57_WORKING = ('def pick_label(flag, value):\n    if flag:\n        label = str(value)\n'
                '    else:\n        label = str(value)\n    return label')
_F57_DECLARED = ('def pick_label(flag, value):\n    if flag:\n        ...\n'
                 '    else:\n        ...\n    return None')
_F57_DUP_WORKING = ('def code_word(code):\n    if code == 1:\n        word = "one"\n'
                    '    elif code == 2:\n        word = "one"\n    else:\n        word = "many"\n    return word')
_F57_DUP_DECLARED = ('def code_word(code):\n    if code == 1:\n        ...\n'
                     '    elif code == 2:\n        ...\n    else:\n        word = "many"\n    return 1')
_F57_SUBTREES = ('def route(kind, payload):\n    if kind == "a":\n        data = list(payload)\n'
                 '        data.append(kind)\n        return data\n    else:\n        data = list(payload)\n'
                 '        data.append(kind)\n        return data')
_F59_BUILDER = "def set_title(title):\n    return OSC + '2;' + title + BEL"
_F59_SETTER = 'def set_width(self, width):\n    self.width = width\n    return width'
_F62_SELF = 'def tally(items):\n    total = sum(items)\n    total = total + 0\n    return total * 2'
_F62_EFFECT = 'def tally(counts, key):\n    counts[key()] = counts[key()] * 1\n    return counts'
_F62_CALL_RHS = 'def tally(x, f):\n    x = x + f()\n    return x'
_F62_PLANT = 'def widen(width, extra):\n    total = width + extra\n    return total + 0'


def lane_b(errors: List[str]) -> Dict[str, Any]:
    """PART 3 — LANE B's own fixtures (S5-3): the three owner rulings the SOURCE now carries, both
    sides of each. The 55-row corpus above is the regression; these rows say what changed and prove
    that the shape the owner allowed still works.

    FIX_57 `*_not_implemented` — a value-returning arm is offered the COLLAPSE and never the raise; an
    empty / declared-only arm (the NAI-120 shape) is still offered the raise, and it passes the gate.
    FIX_59 NAI-131 — a `set_`-named builder files no row and gets no rewrite; a real setter still does.
    FIX_62 NAI-032 — an identity that reduces a statement to `x = x` DELETES the statement (and the
    output passes the gate it used to trip); a right side with an effect withholds the whole snippet."""
    import asyncio
    import importlib.util as ilu

    from no_aivalidator.repair_generators.advanced import fix_duplicate_subtrees
    from no_aivalidator.repair_generators.extended_semantic import fix_setter_return
    from no_aivalidator.repair_generators.hallucination import fix_repetitive_branches
    from no_aivalidator.repair_generators.math_family import fix_algebraic_identity
    from no_aivalidator.repair_generators.structural import fix_identical_branches

    spec: Any = ilu.spec_from_file_location("generator_check", ROOT / "system_scripts" / "generator_check.py")
    gc = ilu.module_from_spec(spec); spec.loader.exec_module(gc)
    tags = lambda src, name: asyncio.run(gc._tags(src, name))     # noqa: E731 — the detector's own reading

    print("\nLANE B (S5-3) — FIX_57 · FIX_59 · FIX_62 at the source")
    out: Dict[str, Any] = {}

    def want(cond: bool, what: str) -> None:
        print(f"  {'✓' if cond else '✗'} {what}")
        if not cond:
            errors.append(f"lane B: {what}")

    def offered(fn: Any, src: str) -> List[str]:
        got = fn(src)
        return [v for v, _a, _w in got] if isinstance(got, list) else []

    def span(rule_id: str, role: str, variant: str, before: str, after: str) -> Rewrite:
        return Rewrite(rule_id=rule_id, role=role, variant=variant, file="fixture.py", span="",
                       before_src=before, after_src=after, module_src=before)

    # FIX_57 ─ NAI-026, the #61 shape and the shape the owner left standing
    working = offered(fix_identical_branches, _F57_WORKING)
    declared = fix_identical_branches(_F57_DECLARED)
    out["fix_57"] = {"nai026_working_arm": working, "nai026_declared_arm": [v for v, _a, _w in declared]}
    want("body_once" in working, "FIX_57 · NAI-026 · a value-returning arm is offered the collapse")
    want("else_not_implemented" not in working,
         "FIX_57 · NAI-026 · a value-returning arm is NEVER offered the raise")
    want({"body_once", "else_not_implemented"} <= {v for v, _a, _w in declared},
         "FIX_57 · NAI-026 · an empty / declared-only arm is still offered both")
    stub = next((a for v, a, _w in declared if v == "else_not_implemented"), "")
    verdict = check(span("NAI-026", "identical_branches_fix", "else_not_implemented", _F57_DECLARED, stub))
    out["fix_57"]["declared_arm_gate"] = {"ok": verdict.ok, "reason": verdict.reason}
    want(verdict.ok, "FIX_57 · NAI-026 · the raise on a declared-only arm PASSES the gate")

    # the gate still withholds the raise if a rewriter ever offers one on a working arm (the backstop)
    handmade = _F57_WORKING.replace("    else:\n        label = str(value)",
                                    '    else:\n        raise NotImplementedError("pick_label: not implemented")')
    names = [f for f, _r in failures(span("NAI-026", "identical_branches_fix", "else_not_implemented",
                                          _F57_WORKING, handmade))]
    out["fix_57"]["backstop_checks"] = names
    want("predicate:NAI-026:else_not_implemented" in names,
         "FIX_57 · NAI-026 · the predicate still withholds a raise over a working arm")

    # FIX_57 ─ NAI-053 (#70, the copied constant) and NAI-040 (the shared helper's other caller)
    dup_working = offered(fix_repetitive_branches, _F57_DUP_WORKING)
    dup_declared = offered(fix_repetitive_branches, _F57_DUP_DECLARED)
    subtrees = offered(fix_duplicate_subtrees, _F57_SUBTREES)
    out["fix_57"].update({"nai053_working": dup_working, "nai053_declared": dup_declared,
                          "nai040_working": subtrees})
    want(dup_working == ["merge_conditions"],
         "FIX_57 · NAI-053 · a copied-CONSTANT arm gets the collapse alone, not a raise")
    want("later_not_implemented" in dup_declared,
         "FIX_57 · NAI-053 · declared-only repeats are still offered the stub")
    want("else_not_implemented" not in subtrees and "body_once" in subtrees,
         "FIX_57 · NAI-040 · the shared helper's other caller collapses too (no raise)")

    # FIX_59 ─ the row must not exist on a builder, and must still exist on a real setter
    builder_tags, setter_tags = tags(_F59_BUILDER, "set_title"), tags(_F59_SETTER, "set_width")
    builder_fix, setter_fix = offered(fix_setter_return, _F59_BUILDER), offered(fix_setter_return, _F59_SETTER)
    out["fix_59"] = {"builder_tags": builder_tags, "setter_tags": setter_tags,
                     "builder_variants": builder_fix, "setter_variants": setter_fix}
    want("NAI-131" not in builder_tags,
         "FIX_59 · the DETECTOR files no NAI-131 row on a `set_`-named builder (#21 `set_title`)")
    want(not builder_fix, "FIX_59 · the rewriter offers a builder nothing, by the same reading")
    want("NAI-131" in setter_tags, "FIX_59 · a real setter still FIRES (stores on self, returns the echo)")
    want({"drop_value", "return_self"} <= set(setter_fix), "FIX_59 · a real setter is still fixed")
    fixed = next((a for v, a, _w in fix_setter_return(_F59_SETTER) if v == "drop_value"), "")
    sv = check(span("NAI-131", "setter_return_fix", "drop_value", _F59_SETTER, fixed))
    out["fix_59"]["setter_gate"] = {"ok": sv.ok, "reason": sv.reason}
    want(sv.ok, "FIX_59 · the real setter's `drop_value` passes the gate (narrowing 3 stands)")
    bv = failures(span("NAI-131", "setter_return_fix", "return_self", _F59_BUILDER,
                       "def set_title(title):\n    return self"))
    out["fix_59"]["builder_return_self_checks"] = [f for f, _r in bv]
    want("predicate:NAI-131:return_self" in [f for f, _r in bv],
         "FIX_59 · `return_self` on a builder is withheld too — both variants carry the predicate")

    # FIX_62 ─ delete the no-op statement; withhold when the right side has an effect
    deleted, what = fix_algebraic_identity(_F62_SELF)
    out["fix_62"] = {"after": deleted, "what": what,
                     "effect": fix_algebraic_identity(_F62_EFFECT),
                     "call_rhs": fix_algebraic_identity(_F62_CALL_RHS),
                     "plant": fix_algebraic_identity(_F62_PLANT)}
    want("total = total" not in deleted and "total = total + 0" not in deleted,
         "FIX_62 · `total = total + 0` is DELETED, not shipped as `total = total`")
    want(deleted == 'def tally(items):\n    total = sum(items)\n    return total * 2',
         "FIX_62 · the rest of the snippet is untouched by the deletion")
    dv = check(span("NAI-032", "algebraic_identity_fix", "", _F62_SELF, deleted))
    out["fix_62"]["gate"] = {"ok": dv.ok, "reason": dv.reason}
    want(dv.ok, "FIX_62 · the deletion PASSES the gate its own output used to trip (#53)")
    want(fix_algebraic_identity(_F62_EFFECT) == ("", ""),
         "FIX_62 · a right side with an effect (`counts[key()] * 1`) is WITHHELD, not deleted")
    want(fix_algebraic_identity(_F62_CALL_RHS) == ("", ""),
         "FIX_62 · `x = x + f()` carries no identity — nothing is offered, nothing is deleted")
    want(fix_algebraic_identity(_F62_PLANT)[0].endswith("return total"),
         "FIX_62 · an identity that is not a whole statement is still simplified in place (the plant)")
    return out


def lane_c(errors: List[str]) -> Dict[str, Any]:
    """PART 3 — S5-4 (FIX_58 + FIX_61), the source and the gate saying the same thing.

    Each fixture shows BOTH sides (the lane contract's rule 2): the shape the rewriter offers and the
    shape it does not, with the gate asked about the same span afterwards.

      NAI-091  `shallow_copy` is offered for a unit that mutates a parameter AND returns it, and is not
               offered for a `push`-style unit whose name says in-place mutation is the contract.
      NAI-017  every candidate comes back withheld BY DESIGN, carrying the registry's reason — not a
               generic post-condition, and not a fix.
      NAI-078  `narrow_and_log` is offered and passes the gate; `re_raise` and `raise_named` are gone
               from the source; and — S7-T2, the owner's 2026-09-21 ruling, packet Q2 — `log_and_return`
               is still OFFERED but G0 WITHHOLDS it on every target, with the owner's sentence.
      NAI-008  S7-T2 (I-126 / Q3): the import-graph guard. On a two-module fixture package the SAME
               `import_hoist_fix` is withheld on the eager module and offered on the lazy one, and a
               hoist of a name already in the eager closure is offered on both.
    """
    from no_aivalidator.repair_generators import candidates_of, gate_note
    from no_aivalidator.repair_generators.gate import BY_DESIGN

    print("\nLANE C — FIX_58 (NAI-091) · FIX_61 (NAI-017 / NAI-078)")
    out: Dict[str, Any] = {}

    def _want(cond: bool, what: str) -> None:
        print(f"  {'✓' if cond else '✗'} {what}")
        if not cond:
            errors.append(f"lane C: {what}")

    def _offer(rid: str, code: str) -> Dict[str, str]:
        """{variant: the gate's check, "" when it passes} for every candidate the SOURCE offers."""
        return {str(o[0]).split(":", 1)[-1]: gate_note(o)[0] for o in candidates_of(REGISTRY[rid], code)}

    # ── FIX_58, NAI-091 — the owner's three conditions at the source ──────────────────────────────
    mutate_and_return = ("def with_entry(table, key, value):\n"
                         "    table[key] = value\n"
                         "    return table\n")
    push_style = ("def push(items, value):\n"
                  "    items.append(value)\n")
    identity = ("def store(buffer, value, sink):\n"
                "    if buffer is sink:\n"
                "        return buffer\n"
                "    buffer.append(value)\n"
                "    return buffer\n")
    a, b, c = _offer("NAI-091", mutate_and_return), _offer("NAI-091", push_style), _offer("NAI-091", identity)
    out["nai091"] = {"mutate_and_return": a, "push_style": b, "identity_test": c}
    _want(a.get("shallow_copy") == "", "NAI-091: mutated AND returned → `shallow_copy` offered, and the gate passes it")
    _want("shallow_copy" not in b and "shallow_copy_returned" not in b,
          "NAI-091: a `push` name → no copy variant is offered at all (the row goes to the shape lane)")
    _want("shallow_copy" not in c, "NAI-091: an identity test on the argument → no copy variant is offered")
    _want(bool(failures(Rewrite(rule_id="NAI-091", role="param_mutation_fix", variant="shallow_copy_returned",
                                before_src=push_style,
                                after_src=push_style.replace("    items", "    items = items.copy()\n    items")
                                + "    return items\n"))),
          "NAI-091: the predicate beside the variant withholds `shallow_copy_returned` on the same name")

    # ── FIX_61 (a), NAI-017 — the registry's flag, read through G0's hook ─────────────────────────
    g17 = REGISTRY["NAI-017"]
    hushed = ("def hushed(value):\n"
              "    with suppress(Exception):\n"
              "        value.close()\n")
    bare = ("def parse_int(text):\n"
            "    try:\n"
            "        return int(text)\n"
            "    except:\n"
            "        pass\n"
            "    return 0\n")
    offers17 = {**_offer("NAI-017", hushed), **_offer("NAI-017", bare)}
    reasons17 = {str(o[0]): gate_note(o)[1] for o in candidates_of(REGISTRY["NAI-017"], hushed)}
    out["nai017"] = {"kind": g17.kind, "flag": g17.no_fix_by_design[:60], "variants": offers17,
                     "reasons": reasons17}
    _want(bool(g17.no_fix_by_design), "NAI-017: the registry row carries the no-fix-by-design reason as a field")
    _want(bool(offers17) and all(v.startswith("predicate:NAI-017:") for v in offers17.values()),
          "NAI-017: every candidate is withheld, each by its own variant's predicate")
    _want(all(BY_DESIGN in r and g17.no_fix_by_design in r for r in reasons17.values()),
          "NAI-017: the sentence the row publishes is the registry's reason, withheld BY DESIGN")

    # ── FIX_61 (b), NAI-078 — a fallback-return has a behaviour-preserving repair again ───────────
    narrow = ("def parse_count(text):\n"
              "    try:\n"
              "        return int(text)\n"
              "    except ValueError:\n"
              "        return 0\n")
    broad = ("def read_flag(path):\n"
             "    try:\n"
             "        return open(path).read()\n"
             "    except:\n"
             "        return ''\n")
    n78, b78 = _offer("NAI-078", narrow), _offer("NAI-078", broad)
    reasons78 = {str(o[0]).split(":", 1)[-1]: gate_note(o)[1] for o in candidates_of(REGISTRY["NAI-078"], narrow)}
    out["nai078"] = {"narrow_handler": n78, "broad_handler": b78, "reasons": reasons78}
    # S7-T2 (owner 2026-09-21, HAND_CHECK_S6 Part B; packet Q2) — THE FLIP. Until this session this
    # line read "`log_and_return` is offered and passes the gate". The owner walked six standing
    # `log_and_return` patches on click and scored all six WRONG, and the scope taken (Q2) is EVERY
    # target: a new log line plus an in-handler import is intent-changing everywhere. The variant is
    # still OFFERED — never dropped, so the shape lane can render it — and G0 withholds it.
    _want(n78.get("log_and_return") == "predicate:NAI-078:log_and_return",
          "NAI-078: `log_and_return` is offered and the gate WITHHOLDS it (owner 2026-09-21, Q2)")
    _want(_Q2_REASON in (reasons78.get("log_and_return") or ""),
          "NAI-078: the withheld sentence is the owner's — intent-changing: a log line and an in-handler import")
    # S7-T2 FOLLOW-UP (owner 2026-09-21, the same ruling): `narrow_and_log` was MEASURED, not assumed.
    # The generator runs the SAME `_log_into` over every handler before it narrows anything, so its
    # diff carries the identical `import logging` + `getLogger(…).debug(…)` rows above the same
    # untouched fallback return — a strict superset of `log_and_return`, the same class, so the same
    # withhold. The two `_emits_log_and_return` lines ARE the measurement the ruling turned on.
    _want(b78.get("narrow_and_log") == "predicate:NAI-078:narrow_and_log",
          "NAI-078: a handler that catches everything still gets `narrow_and_log`, and the gate WITHHOLDS it")
    _want(_emits_log_and_return("narrow_and_log"),
          "NAI-078: MEASURED — `narrow_and_log`'s diff inserts `import logging` + the `debug(…)` call above "
          "the kept fallback return, exactly as `log_and_return` does (same class → branch (a))")
    _want(_emits_log_and_return("log_and_return"),
          "NAI-078: MEASURED — `log_and_return`'s diff inserts the same two rows (the class both share)")
    _want("narrow_and_log" not in n78, "NAI-078: an already-narrow handler is not narrowed again")
    _want(not ({"re_raise", "raise_named"} & (set(n78) | set(b78))),
          "NAI-078: `re_raise` / `raise_named` are gone from the source, not merely withheld")
    _want("log_and_return" in n78 and "log_and_return" in b78 and "narrow_and_log" in b78,
          "NAI-078: every withheld variant is still OFFERED on the row, never dropped (the shape lane keeps it)")

    # ── S7-T2, NAI-008 — the import-graph guard (owner point 1; I-126, packet Q3) ─────────────────
    out["nai008"] = _nai008_fixture(_want)
    return out


#: The span the follow-up ruling was measured on: a bare `except:` returning a literal, which is the
#: ONLY shape that offers `narrow_and_log` at all (the generator gates it on a broad handler).
_BROAD_FALLBACK = ("def read_flag(path):\n"
                   "    try:\n"
                   "        return open(path).read()\n"
                   "    except:\n"
                   "        return ''\n")


def _emits_log_and_return(variant: str) -> bool:
    """THE MEASUREMENT the follow-up ruling turned on: does this variant's diff insert the log line
    and the in-handler import above a KEPT fallback return? Read off the generator's own output, not
    off its name or its docstring — `narrow_and_log` narrows on top of that pair, it does not replace
    it, which is why it is the same class as `log_and_return` and takes the same withhold."""
    import difflib
    before = _BROAD_FALLBACK
    fn = REGISTRY["NAI-078"].fn
    if fn is None:                             # a registry row with no rewriter cannot be measured
        return False
    got = [a for v, a, _w in (fn(before) or []) if v == variant]
    if not got:
        return False
    after = got[0]
    inserted = [ln[2:].strip() for ln in difflib.ndiff(before.splitlines(), after.splitlines())
                if ln.startswith("+ ")]
    return (any(x.startswith("import logging") for x in inserted)
            and any("getLogger" in x and "exc_info=True" in x for x in inserted)
            and "return ''" in after)          # the fallback return itself is untouched


#: The owner's Q2 sentence, quoted once — the proof asserts THIS text, not a paraphrase.
_Q2_REASON = ("intent-changing: adds a log line and an in-handler import "
              "(owner 2026-09-21, HAND_CHECK_S6 Part B)")

#: The S7-T2 fixture package: ONE eager module and ONE lazy module under one package root. `eager.py`
#: is reached from `__init__.py` by a module-level import; `lazy.py` is imported only inside a
#: function, so nothing of it runs at `import pkg`. `os` is already in the eager closure (the root
#: imports it at module level), which is the "hoisting it changes nothing observable" case.
_FIXTURE_PKG = {
    "pkg/__init__.py": "import os\nfrom . import eager\n\n\ndef load():\n    from . import lazy\n    return lazy\n",
    "pkg/eager.py": ("def open_stream(path):\n"
                     "    import random\n"
                     "    return open(path).read() + str(random.random())\n"),
    "pkg/lazy.py": ("def pick_pager(cmd):\n"
                    "    import shutil\n"
                    "    return shutil.which(cmd)\n"),
}
#: the same hoist of a name the eager closure ALREADY imports at module level
_ALREADY_EAGER = ("def dirname(path):\n"
                  "    import os\n"
                  "    return os.path.dirname(path)\n")


def _nai008_fixture(_want: Any) -> Dict[str, Any]:
    """S7-T2 (owner 2026-09-21, HAND_CHECK_S6 point 1; I-126, packet Q3). The SAME rewriter, the same
    rule, the same variant — `NAI-008 · import_hoist_fix` — is right on a module nothing imports at
    import time and wrong on one that runs at `import <pkg>`. Run 155 went 5 for 11 on one target for
    exactly this reason. The fixture is a two-module package: the hoist is WITHHELD on the eager
    module, OFFERED on the lazy one, and OFFERED on BOTH when the hoisted name is already in the
    eager closure (hoisting it adds nothing to what importing the package costs).

    Expected values are written HERE, before the compute: withheld on `pkg/eager.py`, offered on
    `pkg/lazy.py`, offered on both for `os`; and the withheld reason names the eager ROOT and the
    PATH that reached the module (`pkg/__init__.py → pkg/eager.py`)."""
    import tempfile
    from no_aivalidator.repair_generators import candidates_of, gate_note
    from no_aivalidator.repair_generators import gate as _gate

    print("\nS7-T2 — NAI-008's import-graph guard (I-126 / Q3): eager withholds, lazy offers")
    out: Dict[str, Any] = {}
    hoist = _FIXTURE_PKG["pkg/eager.py"]          # the identical span is judged on both modules
    with tempfile.TemporaryDirectory(prefix="nai008_eager_") as tmp:
        root = Path(tmp)
        for rel, text in _FIXTURE_PKG.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        previous = _gate._ROOT_OVERRIDE
        _gate.set_target_root(str(root))
        try:
            closure = _gate.eager_closure()
            out["closure"] = {"roots": list(closure.roots) if closure else None,
                              "eager_files": sorted(closure.files) if closure else None}
            _want(closure is not None and closure.is_eager("pkg/eager.py"),
                  "NAI-008 fixture: `pkg/eager.py` is measured EAGER (a module-level import from the root)")
            _want(closure is not None and not closure.is_eager("pkg/lazy.py"),
                  "NAI-008 fixture: `pkg/lazy.py` is measured LAZY (imported only inside a function body)")

            def judge(code: str, rel: str) -> Dict[str, str]:
                offers = candidates_of(REGISTRY["NAI-008"], code, file=rel)
                return {str(o[0]): gate_note(o)[1] for o in offers}

            on_eager, on_lazy = judge(hoist, "pkg/eager.py"), judge(hoist, "pkg/lazy.py")
            os_eager, os_lazy = judge(_ALREADY_EAGER, "pkg/eager.py"), judge(_ALREADY_EAGER, "pkg/lazy.py")
            out["same_hoist"] = {"on_eager": on_eager, "on_lazy": on_lazy}
            out["already_eager_name"] = {"on_eager": os_eager, "on_lazy": os_lazy}
            eager_reason = (on_eager.get("import_hoist_fix") or "")
            _want(bool(eager_reason), "NAI-008: the hoist is WITHHELD on the eager module")
            _want(on_lazy.get("import_hoist_fix") == "",
                  "NAI-008: the SAME hoist is OFFERED on the lazy module — one rewriter, two import graphs")
            _want("eager: pkg/__init__.py → pkg/eager.py" in eager_reason,
                  "NAI-008: the reason names the eager ROOT and the PATH that reached the module")
            _want("`random`" in eager_reason,
                  "NAI-008: the reason names the module the hoist would add to import time")
            _want(os_eager.get("import_hoist_fix") == "" and os_lazy.get("import_hoist_fix") == "",
                  "NAI-008: a hoist of a name already in the eager closure is offered on BOTH (it adds nothing)")

            # Run 159, launch B, found the reading the spec could not state: FOUR of click's six
            # Part C rows are `withheld_by: gate` at ROW level, but C1 (`_compat.open_stream`, also
            # NAI-087) and C6 (`__init__.__getattr__`, also NAI-057) carry a SECOND rule whose
            # prescribed solution is pickable, so those rows publish that solution and are not
            # row-level withheld. The hoist is withheld on all six all the same, and picked on none.
            # That is the gate working PER CANDIDATE, and this is the line that fences it: the eager
            # fact belongs to NAI-008's predicate and may never leak onto another rule of the same row.
            mutate_and_return = ("def with_entry(table, key, value):\n"
                                 "    table[key] = value\n"
                                 "    return table\n")
            other = {str(o[0]): gate_note(o)[1]
                     for o in candidates_of(REGISTRY["NAI-091"], mutate_and_return, file="pkg/eager.py")}
            out["other_rule_on_the_eager_file"] = other
            _want(any(v == "" for k, v in other.items() if k.endswith("shallow_copy")),
                  "NAI-008: the eager fact is scoped to its own predicate — another rule's candidate on "
                  "the SAME eager file is judged on its own merits and still passes")
        finally:
            _gate.set_target_root(previous)

    # NOT MEASURED — no target root at all — withholds nothing (the gate's fail-open rule).
    previous = _gate._ROOT_OVERRIDE
    _gate.set_target_root("")
    try:
        not_measured = {str(o[0]): gate_note(o)[1]
                      for o in candidates_of(REGISTRY["NAI-008"], hoist, file="pkg/eager.py")}
    finally:
        _gate.set_target_root(previous)
    out["not_measured"] = not_measured
    _want(not_measured.get("import_hoist_fix") == "",
          "NAI-008: NOT MEASURED (no target root) withholds nothing — the gate never loses a right repair")
    return out


_DK = 'def table():\n    return {"a": 1, "b": 2, "a": 3}'
_DK_FIRST = 'def table():\n    return {"a": 1, "b": 2}'
_DK_LAST = 'def table():\n    return {"a": 3, "b": 2}'
_SK = 'def flags():\n    return {True: "yes", 1: "one", "k": 0}'
_SK_FIRST = 'def flags():\n    return {True: "yes", "k": 0}'
_SK_LAST = 'def flags():\n    return {1: "one", "k": 0}'
_TRIPLE = 'def table():\n    return {"a": 1, "a": 2, "a": 3}'
_TRIPLE_LAST = 'def table():\n    return {"a": 3}'

#: (what it proves, rule, role, variant, before, after, must be withheld)
_FIX63_GATE = [
    ("FIX_63 the live (last) entry deleted, the shadowed first kept — `live_store_removed` is silent "
     "(no store statement), the predicate speaks",
     "NAI-175", "duplicate_key_fix", "keep_first", _DK, _DK_FIRST, True),
    ("FIX_63 last-live: the shadowed first entry deleted, the literal evaluates as before",
     "NAI-175", "duplicate_key_fix", "keep_last", _DK, _DK_LAST, False),
    ("FIX_63 NAI-177 `True` and `1` are one key to Python; `\"yes\"` was never the value",
     "NAI-177", "semantic_duplicate_key_fix", "keep_first", _SK, _SK_FIRST, True),
    ("FIX_63 NAI-177 last-live passes",
     "NAI-177", "semantic_duplicate_key_fix", "keep_last", _SK, _SK_LAST, False),
]

#: (what it proves, generator, span, the variants the rewriter must now mint, in order)
_FIX63_SOURCE = [
    ("FIX_63 NAI-175 mints no `keep_first`", "fix_duplicate_keys", _DK, ["keep_last"]),
    ("FIX_63 NAI-177 mints no `keep_first`", "fix_semantic_duplicate_keys", _SK, ["keep_last"]),
]


def _part(title: str, tag: str, gens: Dict[str, Any], source: list, gate: list, errors: List[str],
          extra: Optional[Callable[[Dict[str, Any], List[str]], None]] = None) -> Dict[str, Any]:
    """One post-lane proof part: what the rewriters mint (`source` rows) and what the gate says (`gate`
    rows, a withheld row proven only by ITS OWN predicate — the generic checks are silent on this class)."""
    print(f"\n{title}")
    out: Dict[str, Any] = {"source": [], "gate": []}
    print("  what the rewriters mint")
    for what, gen, span, want in source:
        got = [v for v, _after, _w in gens[gen](span)]
        ok = got == want
        out["source"].append({"what": what, "generator": gen, "variants": got, "expected": want, "ok": ok})
        print(f"    {'✓' if ok else '✗'} {gen}: {got}")
        print(f"        {what}")
        if not ok:
            errors.append(f"{tag} source: {gen} minted {got}, expected {want} — {what}")
    if extra is not None:
        extra(out, errors)
    print("  what the gate says")
    for what, rule_id, role, variant, before, after, withheld in gate:
        rw = Rewrite(rule_id=rule_id, role=role, variant=variant, file=f"{tag.lower()}_fixture.py",
                     span="", before_src=before, after_src=after)
        failed = failures(rw)
        names = [f for f, _ in failed]
        verdict = check(rw)
        ok = (not verdict.ok) is withheld
        if withheld and ok:
            ok = f"predicate:{rule_id}:{variant}" in names
        out["gate"].append({"what": what, "rule_id": rule_id, "variant": variant, "checks": names,
                            "expected": "withheld" if withheld else "passes", "reason": verdict.reason,
                            "ok": bool(ok)})
        print(f"    {'✓' if ok else '✗'} {rule_id}:{variant:<18} "
              f"{'WITHHELD' if not verdict.ok else 'passes':<9} {', '.join(names) or '—'}")
        print(f"        {what}")
        if verdict.reason:
            print(f"        {verdict.reason}")
        if not ok:
            errors.append(f"{tag} gate: {rule_id}:{variant} expected "
                          f"{'withheld' if withheld else 'passes'}, got {names} — {what}")
    return out


def fix_63(errors: List[str]) -> Dict[str, Any]:
    """FIX_63 (I-115) — NAI-175 / NAI-177 carried the same `keep_first` inversion FIX_56 retired on
    NAI-006, on dict literals: source (only `keep_last` minted, every shadowed entry dropped) and gate
    (`_dict_literal_value_changed`, since `live_store_removed` reads statements, not literal keys)."""
    from no_aivalidator.repair_generators.core import fix_duplicate_keys, fix_semantic_duplicate_keys

    def triple_check(out: Dict[str, Any], errs: List[str]) -> None:
        # a key repeated three times: every shadowed entry goes, not just the first (the old loop broke
        # on the first match and left the middle one)
        triple = {v: after for v, after, _w in fix_duplicate_keys(_TRIPLE)}
        got, want = [list(triple), triple.get("keep_last")], [["keep_last"], _TRIPLE_LAST]
        ok = got == want
        out["source"].append({"what": "FIX_63 a key repeated three times drops both shadowed entries",
                              "generator": "fix_duplicate_keys", "after": triple.get("keep_last"), "ok": ok})
        print(f"    {'✓' if ok else '✗'} fix_duplicate_keys on a triple: {(triple.get('keep_last') or '').splitlines()[-1:]}")
        if not ok:
            errs.append(f"FIX_63 source: a triple repeat left a shadowed entry — {triple}")

    return _part("FIX_63 — NAI-175 / NAI-177 last-live on dict literals", "FIX_63",
                 {"fix_duplicate_keys": fix_duplicate_keys, "fix_semantic_duplicate_keys": fix_semantic_duplicate_keys},
                 _FIX63_SOURCE, _FIX63_GATE, errors, triple_check)


_DS_IMPURE = 'def report(items):\n    info = compute(items)\n    return len(items)'
_DS_IMPURE_DROP = 'def report(items):\n    return len(items)'
_DS_IMPURE_KEEP = 'def report(items):\n    compute(items)\n    return len(items)'
_DS_PURE = 'def total(values):\n    count = len(values)\n    return sum(values)'
_DS_PURE_DROP = 'def total(values):\n    return sum(values)'

_FIX64_SOURCE = [
    ("FIX_64 NAI-031 offers `keep_effect` alone when the callee is not provably pure", "fix_dead_store",
     _DS_IMPURE, ["keep_effect"]),
    ("FIX_64 NAI-031 still deletes when the callee is pure (`len`, the detector's own table)", "fix_dead_store",
     _DS_PURE, ["drop_store", "keep_effect"]),
]
_FIX64_GATE = [
    ("FIX_64 a `drop_store` that takes an unproven call — G0's generic check is silent, the predicate speaks",
     "NAI-031", "dead_store_fix", "drop_store", _DS_IMPURE, _DS_IMPURE_DROP, True),
    ("FIX_64 the same span, the call kept as a statement",
     "NAI-031", "dead_store_fix", "keep_effect", _DS_IMPURE, _DS_IMPURE_KEEP, False),
    ("FIX_64 a `drop_store` whose only call is pure passes",
     "NAI-031", "dead_store_fix", "drop_store", _DS_PURE, _DS_PURE_DROP, False),
]


def fix_64(errors: List[str]) -> Dict[str, Any]:
    """FIX_64 (I-116) — NAI-031 `drop_store` under FIX_60's rule at the source and the gate: seen live on
    run 149 (#73 #74's class through a third helper), caught until now only by G0's generic check."""
    from no_aivalidator.repair_generators.math_family import fix_dead_store
    return _part("FIX_64 — NAI-031 pure-callee delete", "FIX_64", {"fix_dead_store": fix_dead_store},
                 _FIX64_SOURCE, _FIX64_GATE, errors)


_MS_SPAN = 'def report(items):\n    info = shape(items)\n    return len(items)'
_MS_DROP = 'def report(items):\n    return len(items)'
_MS_MOD = 'def shape(xs):\n    return [len(x) for x in xs]\n\n\n' + _MS_SPAN + '\n'
_MS_SHADOW = _MS_MOD + '\nshape = None\n'
_MS_IMPURE = 'def shape(xs):\n    print(xs)\n    return xs\n\n\n' + _MS_SPAN + '\n'

#: (what it proves, rule, the module in hand, the variants candidates_of must offer, gate-withheld ones)
_FIX65_OFFERS: List[Any] = [
    ("FIX_65 no module in hand — the span alone is the evidence, exactly as before (fail closed)",
     "NAI-010", "", ["keep_call_effect"], []),
    ("FIX_65 the module's sole `shape` is a pure def: the delete is offered and the gate passes it",
     "NAI-010", _MS_MOD, ["drop_assignment", "keep_call_effect"], []),
    ("FIX_65 `shape` bound twice at the top level is evidence of nothing",
     "NAI-010", _MS_SHADOW, ["keep_call_effect"], []),
    ("FIX_65 a module helper that prints is not pure",
     "NAI-010", _MS_IMPURE, ["keep_call_effect"], []),
    ("FIX_65 NAI-031 reads the same evidence through the same helper (FIX_64)",
     "NAI-031", _MS_MOD, ["drop_store", "keep_effect"], []),
]


def fix_65(errors: List[str]) -> Dict[str, Any]:
    """FIX_65 (I-117) — purity evidence widened to the module: `candidates_of` sets `core.module_evidence`
    around the rewriter call, the gate reads `rw.module_src`; a module-level def counts only as the name's
    sole top-level binding. Proven through `candidates_of` itself, since that is where the module arrives."""
    from no_aivalidator.repair_generators import candidates_of, gate_note
    from no_aivalidator.repair_generators.gate import Rewrite as _Rw
    print("\nFIX_65 — purity evidence from the module, through candidates_of")
    out: Dict[str, Any] = {"offers": [], "gate": []}
    for what, rid, mod, want_v, want_withheld in _FIX65_OFFERS:
        offers = candidates_of(REGISTRY[rid], _MS_SPAN, file="fix_65_fixture.py", module_src=mod)
        offered_v = [str(o[0]).split(":", 1)[-1] for o in offers]
        withheld = [str(o[0]).split(":", 1)[-1] for o in offers if gate_note(o)[0]]
        got: Any = [offered_v, withheld]
        want: Any = [want_v, want_withheld]
        ok = got == want
        out["offers"].append({"what": what, "rule_id": rid, "offered": offered_v, "withheld": withheld, "ok": ok})
        print(f"    {'✓' if ok else '✗'} {rid}: offered {offered_v}" + (f", withheld {withheld}" if withheld else ""))
        print(f"        {what}")
        if not ok:
            errors.append(f"FIX_65: {rid} offered {offered_v} withheld {withheld}, expected {want_v} / {want_withheld} — {what}")
    # the gate alone, handed the module on the Rewrite: the same delete passes with it and is withheld without
    for what, mod, withheld_want in (("FIX_65 the gate, handed the module, passes the delete", _MS_MOD, False),
                                     ("FIX_65 the gate without the module withholds it", "", True)):
        rw = _Rw(rule_id="NAI-010", role="dead_local_fix", variant="drop_assignment", file="fix_65_fixture.py",
                 before_src=_MS_SPAN, after_src=_MS_DROP, module_src=mod)
        names = [f for f, _ in failures(rw)]
        got, want = "predicate:NAI-010:drop_assignment" in names, withheld_want
        ok = got == want
        out["gate"].append({"what": what, "checks": names, "ok": ok})
        print(f"    {'✓' if ok else '✗'} gate: {names or '—'}")
        print(f"        {what}")
        if not ok:
            errors.append(f"FIX_65 gate: {names} — {what}")
    return out


# ── FIX_68 (I-150, run 163, owner ruling R1 2026-09-21) ────────────────────────────────────────────
#
# The site's OWN code, copied byte-for-byte from `src/click/testing.py` L156-L190 of
# `~/CodeRadar_snapshots/how_it_is_20260921_003842` (the run-163 target), reduced to the class header
# and the one method the row is about. `close` is a docstring-only override of `io.TextIOWrapper.close`
# whose emptiness IS the implementation; NAI-120 read it as an empty body and `solution_NAI-120`
# prescribed `raise NotImplementedError("close: not implemented")` in its place, which turned
# 1990 passed / 25 skipped / 1 xfailed into 1166 failed / 824 passed / 12 errors.
_F68_SITE = '''import io


class _NamedTextIOWrapper(io.TextIOWrapper):
    """A :class:`~io.TextIOWrapper` with custom ``name`` and ``mode``
    that does not close its underlying buffer.
    """

    def close(self) -> None:
        """The buffer this object contains belongs to some other object,
        so prevent the default ``__del__`` implementation from closing
        that buffer.

        .. versionadded:: 8.3.2
        """
'''

# THE NEGATIVE — a genuinely unsafe `close` of the kind NAI-120 exists for: named `close`, body does
# not close anything, no teardown side effect, and NOTHING inherited for the emptiness to suppress.
# It must still FIRE, and the prescription must still REPAIR it.
_F68_UNSAFE = '''class FileCache:
    def close(self) -> None:
        """Close the cache file and flush any pending writes to disk."""
'''

# The four conjuncts, each dropped once — every one of these still FIRES.
_F68_PASS_BODY = '''import io


class Wrapper(io.TextIOWrapper):
    def close(self) -> None:
        """Close the stream."""
        pass
'''
_F68_OTHER_NAME = '''import io


class Wrapper(io.TextIOWrapper):
    def read(self) -> bytes:
        """Return the next chunk of the stream."""
'''
_F68_VALUE_PROMISED = '''import io


class Wrapper(io.TextIOWrapper):
    def close(self) -> int:
        """Close the stream and return the number of bytes flushed."""
'''
_F68_MODULE_LEVEL = '''def close(handle) -> None:
    """Close the handle and release its file descriptor."""
'''


def _site_ids(src: str, name: str) -> List[str]:
    """The ids the VALIDATOR files on the def named `name` in the module `src`, read through the file
    scan's own wiring (`file_validation.py:582-595`) — collector for the class context and the base
    names, then `validate_function`.

    `generator_check._tags` cannot be used here: it builds the detector with `class_context=False` and
    never sets `class_bases`, so a method's receiver and its base classes are invisible to it, and
    I-150's shape is made of exactly those two facts."""
    import ast as _ast

    from no_aivalidator.noai_validator.collector import FunctionCollector
    from no_aivalidator.noai_validator.validator import NoAIMathValidator
    tree = _ast.parse(src)
    col = FunctionCollector(src)
    col.visit(tree)
    validator = NoAIMathValidator()
    for info in col.functions:
        if info.node.name != name:
            continue
        result = validator.validate_function(
            info.node,
            class_context=info.class_context,
            decorators=info.decorators,
            class_bases=getattr(info, "parent_bases", None),
            source_segment=info.source_segment,
            imported_names=col.imported_names,
            module_level_names=col.defined_symbols,
        )
        return [str(w).split(" ", 1)[0] for w in result.warnings]
    raise AssertionError(f"FIX_68 fixture has no def named {name!r}")


def fix_68(errors: List[str]) -> Dict[str, Any]:
    """FIX_68 (I-150) — NAI-120's false positive on a real lifecycle `close`, both sides.

    Owner ruling R1 (2026-09-21): `testing.py::close::184` / `solution_NAI-120` must not redden a suite
    that is green as written. The classification is (b): the DETECTOR's fire was a false positive on a
    real lifecycle close, so the predicate now carries F-NOP1 — a DOCUMENTED NO-OP OVERRIDE of an
    inherited release hook is a declaration, the fifth shape beside @overload / @abstractmethod /
    Protocol / `raise NotImplementedError`. The prescription is untouched: with no NAI-120 on the row
    there is no `solution_NAI-120` to publish, and nothing is applied at the site.

    This proof is the case, both halves:
      the site's own code            → NAI-120 SILENT (and the site's bytes never move)
      the unsafe `close`             → NAI-120 still FIRES, and the prescription still REPAIRS it
      each conjunct dropped once     → NAI-120 still FIRES (the predicate cannot be a rule-disabler)"""
    print("\nFIX_68 (I-150) — the documented no-op override, and the close that is really unimplemented")
    out: Dict[str, Any] = {"cases": []}

    def want(cond: bool, what: str) -> None:
        print(f"  {'✓' if cond else '✗'} {what}")
        if not cond:
            errors.append(f"FIX_68: {what}")

    def case(label: str, src: str, name: str, fires: bool, what: str) -> None:
        ids = _site_ids(src, name)
        got = "NAI-120" in ids
        out["cases"].append({"case": label, "ids": ids, "fires": got, "expected": fires})
        want(got == fires, what)

    case("site", _F68_SITE, "close", False,
         "I-150 · the SITE's own code (`_NamedTextIOWrapper.close`) files NO NAI-120 row — R1 (iii): "
         "the fire was a false positive on a real lifecycle close")
    case("unsafe", _F68_UNSAFE, "close", True,
         "I-150 · a `close` with nothing inherited to suppress still FIRES (the shape NAI-120 exists for)")
    case("pass_body", _F68_PASS_BODY, "close", True,
         "I-150 · conjunct 4 — a `pass`-bodied override declares nothing and still FIRES")
    case("other_name", _F68_OTHER_NAME, "read", True,
         "I-150 · conjunct 2 — an empty override that is not a release hook still FIRES")
    case("value_promised", _F68_VALUE_PROMISED, "close", True,
         "I-150 · conjunct 3 — `-> int` on an empty body is a broken promise and still FIRES")
    case("module_level", _F68_MODULE_LEVEL, "close", True,
         "I-150 · conjunct 1 — a module-level `close` has no base to override and still FIRES")

    # the prescription is UNCHANGED and still repairs the unsafe close: its shape applied to the
    # negative fixture leaves a body the detector reads as a declaration.
    shape = REGISTRY["NAI-120"].shape
    out["prescription_shape"] = shape
    want("raise NotImplementedError" in shape,
         "I-150 · `solution_NAI-120`'s shape is untouched — the prescription was not narrowed")
    repaired = _F68_UNSAFE.rstrip("\n") + '\n        raise NotImplementedError("close: not implemented")\n'
    repaired_ids = _site_ids(repaired, "close")
    out["unsafe_after_prescription"] = repaired_ids
    want("NAI-120" not in repaired_ids,
         "I-150 · the prescription still REPAIRS the unsafe close — NAI-120 silent after it is applied")
    return out


# ── FIX_68b (the I-150 SIBLING, owner ruling 2026-09-21) ───────────────────────────────────────
#
# `click.utils._KeepOpenFile.__exit__` — the one NAI-120 row left on the target after FIX_68, and the
# one whose `solution_NAI-120` the owner ruled withheld. The module below is the site's own class,
# copied from `src/click/utils.py` L211-L243 of `~/CodeRadar_snapshots/how_it_is_20260921_003842`
# (docstring trimmed to its first line; the class name, the method name and the no-op body — the
# three facts the predicate reads — are the site's own). The DETECTOR is untouched: the row still
# fires and still publishes; only the PRESCRIPTION is withheld, and only here.
_F68B_SITE = '''import typing as t
from types import TracebackType


class _KeepOpenFile:
    """Proxy a file object but keep it open across a ``with`` block."""

    _file: t.IO[t.Any]

    def __init__(self, file: t.IO[t.Any]) -> None:
        self._file = file

    def __enter__(self) -> "_KeepOpenFile":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        pass
'''

# THE NEGATIVE the ruling asks for by name: an empty `__exit__` somewhere else — its own class, no
# base, body `pass`. It must still FIRE and must still be OFFERED the repair. Nobody gets to "fix" a
# negative by pointing NAI-120 at `_KeepOpenFile`.
_F68B_ELSEWHERE = '''class Box:
    def __exit__(self, exc_type, exc_value, tb) -> None:
        pass
'''


def fix_68b(errors: List[str]) -> Dict[str, Any]:
    """FIX_68b (I-150's sibling) — `solution_NAI-120` withheld on ONE site, offered everywhere else.

    Owner ruling 2026-09-21, narrowed to the site: G0 withholds the PRESCRIPTION on
    `click.utils._KeepOpenFile.__exit__` — matched on the class+method shape, never on a line number
    — with the sentence naming the two tests it reddens. FIX_68's detector predicate is NOT relaxed
    and this does not reach `__exit__` generally: the detector still fires here, the row still
    publishes, and an empty `__exit__` anywhere else is still fired on AND still offered the fix."""
    import ast as _ast

    from no_aivalidator.repair_generators.gate import Rewrite as _Rw, prescription_check
    print("\nFIX_68b (I-150's sibling) — `_KeepOpenFile.__exit__`: the prescription withheld, the site alone")
    out: Dict[str, Any] = {}

    def want(cond: bool, what: str) -> None:
        print(f"  {'✓' if cond else '✗'} {what}")
        if not cond:
            errors.append(f"FIX_68b: {what}")

    def span_of(module: str, name: str) -> str:
        tree = _ast.parse(module)
        node = next(n for n in _ast.walk(tree)
                    if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and n.name == name)
        return _ast.get_source_segment(module, node) or ""

    shape = REGISTRY["NAI-120"].shape

    def ask(file: str, module: str, name: str) -> Any:
        return prescription_check(_Rw(rule_id="NAI-120", role="solution_NAI-120", variant="",
                                      file=file, before_src=span_of(module, name),
                                      after_src=shape, module_src=module))

    site = ask("src/click/utils.py", _F68B_SITE, "__exit__")
    out["site"] = {"ok": site.ok, "rule": site.rule, "reason": site.reason}
    want(not site.ok, "I-150 sibling · `solution_NAI-120` is WITHHELD on `_KeepOpenFile.__exit__`")
    want(site.rule == "prescription:NAI-120:solution_NAI-120",
         "I-150 sibling · the withhold is G0's, named `prescription:NAI-120:solution_NAI-120`")
    want(bool(site.reason) and "test_open_file" in (site.reason or "")
         and "test_open_file_ignore_errors_stdin" in (site.reason or ""),
         "I-150 sibling · the recorded reason names BOTH tests it reddens")

    # the DETECTOR is untouched — the row still fires and still publishes
    want("NAI-120" in _site_ids(_F68B_SITE, "__exit__"),
         "I-150 sibling · the DETECTOR still fires NAI-120 on the site (only the solution is withheld)")

    # THE NEGATIVE — an empty `__exit__` elsewhere still fires AND is still offered the repair
    ids = _site_ids(_F68B_ELSEWHERE, "__exit__")
    elsewhere = ask("src/pkg/box.py", _F68B_ELSEWHERE, "__exit__")
    out["elsewhere"] = {"ids": ids, "offered": elsewhere.ok}
    want("NAI-120" in ids, "I-150 sibling · an empty `__exit__` ELSEWHERE still FIRES")
    want(elsewhere.ok, "I-150 sibling · and is still OFFERED the repair — the withhold is the site's alone")

    # nothing leaks: not to another file, not to another rule's prescription
    same_name_other_file = ask("src/click/other.py", _F68B_SITE, "__exit__")
    other_rule = prescription_check(_Rw(rule_id="NAI-034", role="solution_NAI-034", variant="",
                                        file="src/click/utils.py", before_src=span_of(_F68B_SITE, "__exit__"),
                                        after_src=REGISTRY["NAI-034"].shape, module_src=_F68B_SITE))
    out["no_leak"] = {"other_file": same_name_other_file.ok, "other_rule": other_rule.ok}
    want(same_name_other_file.ok, "I-150 sibling · the same class in another file is NOT withheld")
    want(other_rule.ok, "I-150 sibling · another rule's prescription on the same span is NOT withheld")
    return out


def main() -> int:
    res = run()
    if "--json" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--json") + 1])
        out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
