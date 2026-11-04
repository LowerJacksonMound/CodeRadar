#!/usr/bin/env python3
"""nai094_entry_proof.py — T4 / owner Q5 / I-107 (2026-09-20, run 156 `moto_perpetuo`, copy3).

**Why this is not a part of `gate_proof.py`.** NAI-094 is not a gate matter. Its registry row is
`prescribed` with `fn is None`, so `repair_generators.candidates_of` — the ONE publish choke point
G0 runs at (S5-1) — is never reached for it, and `gate.check` never sees a prescribed solution.
The packet allows a proof module of its own in that case; this is it.

**The ruling.** Owner Q5, session 6 (2026-09-20), as proposed: a `sys.path.insert()` on a LIVE ENTRY
script is signalled twice — once as the circuit's counted path-hack infraction, which FIX_50 exempts
when the file's role is `entry`, and again as NAI-094 `Module-level sys.path.insert()` with a
prescribed solution. NAI-094 is **withheld (by design)** on a file whose role is `entry` in
`path_hacks`; the circuit half stays exactly as FIX_50 left it.

**What this module proves.** T4 (run 156) could not land the disposition change: every seam that
could carry it is inside `no_aivalidator/BUILDER_DAEMON.py`, the counterfeit-code mirror's one
writer, which T2 owned that session (B9 / `summary.rule_outcomes`), and the lane brief's footprint
rule said to stop there and record why. So parts 1–4 fence the FACTS that decide which mechanism can
carry Q5, and the facts FIX_50 already owns, so that whoever lands the seam lands it against a
measured tree and not against prose.

**The seam is landed (2026-09-21, run 157 `pekes_repose`, serial in the original), and part 5 is
the fence around what was built.** Parts 1–4 are unchanged and still hold: they say what the two
candidate mechanisms CANNOT do, and neither `CONTEXT_FACTS` nor `Generator.no_fix_by_design` was
widened to build Q5 — the withholding was built at the third place T4 named, one window in
`_build_row`'s body-less branch, reading FIX_50's own stamped disposition off `circuit_state.json`.

    part 1  the two mechanisms, measured — why `contexts` cannot carry Q5 and what the by-design
            flag refuses today (unchanged by the build: neither was widened)
    part 2  FIX_50's circuit half, untouched: `role == entry` still resolves to `context`
    part 3  the run-156 plant: an entry script that is a LIVE scanned node, not `proxy:pathhack`
    part 3b I-15's OTHER half, built 2026-09-21 (FIX_50 step 6, owner Q10): a LAUNCHED entry script
            that hacks its path is not a proxy at all, so its rows stop being withheld on species —
            the fixture pair (guard / no guard) and the counts the whole stage publishes over it
    part 4  the re-freeze invariant (Q7 / I-104): orphan_rows == the sum of the four kinds
    part 5  THE SEAM, BUILT: the row is withheld (by design) on the entry role and published with
            its reason; the non-entry control keeps its prescribed solution; a target never run
            through the wrapper exempts nothing; a hack type that is informational for every file
            is no evidence of a role

**R4 (owner, 2026-09-21) — the prescription matches the DETECTOR's clean shape (run 164
`earthshine`, copy2), part 6.** Session 8's T1 found NAI-094's detector firing on `os.environ[key]
= value` at click `testing.py:574` while its prescription was `sys.path`-shaped only: an
`os.environ` fire was handed "delete the sys.path line and import through the package" — a
sentence about a statement that is not on the row. R4: the detector is the spec, the prescription
follows it, and the detector is never widened to bless what the prescription writes. Part 6 fences
the enumeration, the contradiction that had to be fixed first, the per-family prescription, and
its idempotence.

    part 6  THE CLEAN SHAPES: one table of shapes run through BOTH halves of the predicate (the
            module-scope half in `validator.validate_module` and the per-function half in
            `safety_checks._check_sys_path_manipulation`), with every verdict written BEFORE the
            compute; the FOUR contradictory clean shapes run 164 closed; the prescription the
            family that fired gets, and never the other family's; and the idempotence reading —
            the detector's exact fire case per family, the emitted shape applied once, the
            detector silent, applied again, byte-identical

    .venv_new/bin/python system_scripts/nai094_entry_proof.py [--json OUT]     exit 0 = PASS
"""
from __future__ import annotations

import json as _json
from pathlib import Path as _P
_ROOT = _P(__file__).resolve().parent.parent
import ast
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from no_aivalidator.repair_generators import REGISTRY, Generator, candidates_of   # noqa: E402
from system_scripts.engine_utils import path_hack_disposition, read_json          # noqa: E402

#: the plant of record — the target run 156 was driven against ($CR_NAI094_TARGET; absent -> the plant part is SKIPPED)
TARGET = Path(os.environ.get("CR_NAI094_TARGET") or ROOT / "moto_perpetuo").expanduser()
ENTRY_PLANT = "moto_perpetuo_entry.py"          # THE ENTRY: the script the wrapper runs
IMPORT_KEEPER = "colorama/moto_perpetuo_import.py"   # gives the entry in_degree 1
CONTROL = "demos/fixpath.py"                    # the target's OWN non-entry module, same statement

#: FIX_50's four rows in `rule_dispositions.json` -> path_hacks, each with one `role == entry` context
FIX50_TYPES = ("sys_path_insert", "sys_path_append", "sys_path_extend", "pythonpath_access")


def _mk_want(errors: List[str], tag: str):
    def _want(cond: Any, what: str) -> None:
        print(f"  {'✓' if cond else '✗'} {what}")
        if not cond:
            errors.append(f"{tag}: {what}")
    return _want


# ── part 1 — the two mechanisms, measured ────────────────────────────────────────────────────────

def mechanisms(errors: List[str]) -> Dict[str, Any]:
    """Which of the two mechanisms the packet names can carry Q5, measured rather than argued."""
    print("\nPART 1 — the two mechanisms the packet names, measured")
    _want = _mk_want(errors, "part 1")
    out: Dict[str, Any] = {}

    g = REGISTRY.get("NAI-094")
    out["nai094"] = {"kind": getattr(g, "kind", None), "has_fn": getattr(g, "fn", None) is not None,
                     "reason": (getattr(g, "reason", "") or "")[:80], "shape": bool(getattr(g, "shape", "")),
                     "no_fix_by_design": getattr(g, "no_fix_by_design", "")}
    _want(g is not None, "NAI-094 has a registry row")
    _want(g is not None and g.kind == "prescribed",
          "NAI-094's row is `prescribed` (FIX_41) — a solution in the owner's words, not a rewriter")
    _want(g is not None and g.fn is None,
          "NAI-094's row carries no `fn`, so `candidates_of` — G0's one publish choke point — is never "
          "reached for it and the gate never sees its solution")
    _want(g is not None and candidates_of(g, "import sys\nsys.path.insert(0, '.')\n") == [],
          "`candidates_of(NAI-094, ...)` offers nothing: the by-design withholding session 5 built "
          "(FIX_61 / NAI-017, G0's `no_fix_by_design()` hook) cannot reach a prescribed row")

    # the flag itself refuses a non-rewriter row — the registry says so in its own word
    refused = ""
    try:
        Generator("NAI-094", "prescribed", None, None, reason="x", meaning_source="m",
                  dated="2026-09-20", by="T4 probe", shape="s", no_fix_by_design="because")
    except ValueError as e:
        refused = str(e)
    out["flag_refused"] = refused
    _want("no_fix_by_design flag is a rewriter row's" in refused,
          "`Generator.no_fix_by_design` refuses a prescribed row by construction — the flag cannot "
          "simply be set on NAI-094 (registry __post_init__)")

    # the Ranker's context facts: `role` is not one of them
    from no_aivalidator.cheatsheets.cheatsheet_intelligence.knowledge_base import (  # noqa: E402
        CONTEXT_FACTS, resolve_disposition)
    out["context_facts"] = list(CONTEXT_FACTS)
    _want(tuple(CONTEXT_FACTS) == ("magnitude", "species", "body_statements", "variant", "role"),
          "the Ranker's context facts are exactly (magnitude, species, body_statements — owner 2026-10-07; "
          "variant; role — M-146)")
    # 2026-10-23: `role` IS a Ranker fact since M-146 (a project fact about the function). The fence
    # that mattered was never "role is unknown to the Ranker"; it was "Q5 is not carried by a
    # `contexts` row" — part 5 lands it in `path_hack_disposition`. Pin that directly.
    _want("role" in CONTEXT_FACTS,
          "`role` is a fact the Ranker reads (M-146) — so a `contexts` row keyed on it would LOAD; the "
          "2026-09-10 route is open and Q5 is still not carried by it (next line)")
    _rd = _json.loads((_ROOT / "system_scripts" / "rule_dispositions.json").read_text(encoding="utf-8"))
    _ctx = _rd.get("contexts") or {}
    _want("NAI-094" not in _ctx and "NAI-094" not in _json.dumps(_ctx),
          "no `contexts` row carries NAI-094 — a `context` row would make it INFORMATIONAL (published, never "
          "counted), which is FIX_50's word for the circuit half and NOT `withheld (by design)`; Q5 lives in "
          "`path_hack_disposition` (part 5)")
    _want(resolve_disposition("NAI-094") == "deciding",
          "NAI-094's default disposition is `deciding` — it is an infraction, and Q5 withholds its "
          "SOLUTION, it does not reclass the row")
    print("       a `contexts` row would make NAI-094 `context` = INFORMATIONAL (published, never "
          "counted). That is FIX_50's word for the CIRCUIT half, and it is NOT `withheld (by design)`: "
          "a `context` row never reaches the mirror's withheld block, so `cr_infractions(withheld=true)` "
          "would not list it. The two words are not interchangeable.")
    return out


# ── part 2 — FIX_50's circuit half, untouched ────────────────────────────────────────────────────

def fix50_unmoved(errors: List[str]) -> Dict[str, Any]:
    """The circuit half stays exactly as FIX_50 left it — the lane changed no path-hack row."""
    print("\nPART 2 — FIX_50's circuit half (owner Q10 / I-15), unmoved by this lane")
    _want = _mk_want(errors, "part 2")
    out: Dict[str, Any] = {}
    for htype in FIX50_TYPES:
        entry = path_hack_disposition(htype, {"role": "entry"})
        other = path_hack_disposition(htype, {"role": ""})
        none_measured = path_hack_disposition(htype, None)
        out[htype] = {"entry": list(entry), "non_entry": list(other), "no_facts": list(none_measured)}
        _want(entry[0] == "context" and "entry script" in entry[1],
              f"{htype}: role == entry -> `context` with the Q10 warning")
        _want(other[0] == "deciding",
              f"{htype}: role == '' (any other file) -> `deciding`, counted as before")
        _want(none_measured[0] == "deciding",
              f"{htype}: no facts measured -> `deciding` — a target never run through the wrapper "
              f"exempts nothing (NOT MEASURED, never a silent exemption)")
    return out


# ── part 3 — the run-156 plant ───────────────────────────────────────────────────────────────────

def plant(errors: List[str]) -> Dict[str, Any]:
    """I-107's premise, built: an ENTRY script that is a LIVE scanned node, plus the target's own
    non-entry control carrying the same statement."""
    print("\nPART 3 — the run 156 plant (I-107's premise, built)")
    _want = _mk_want(errors, "part 3")
    out: Dict[str, Any] = {"target": str(TARGET), "present": TARGET.is_dir()}
    if not TARGET.is_dir():
        print(f"  · target {TARGET} is not on disk — the plant part is SKIPPED (the run is over and the "
              f"target was torn down); parts 1, 2 and 4 stand on their own")
        return out

    from no_aivalidator.artifact_scanner.proxies import pathhack   # noqa: E402

    def _is_hack(stmt: ast.stmt) -> bool:
        txt = ast.dump(stmt)
        return "sys" in txt and "path" in txt and any(m in txt for m in ("insert", "append", "extend"))

    def _module_level_hack(src: str) -> bool:
        """NAI-094's own shape: a `sys.path` mutation at module scope. Nothing about imports."""
        return any(_is_hack(s) for s in ast.parse(src).body)

    def _hack_before_import(src: str) -> bool:
        """The proxy predicate's shape: the mutation PRECEDES an import in the same module."""
        seen = False
        for s in ast.parse(src).body:
            if _is_hack(s):
                seen = True
            elif seen and isinstance(s, (ast.Import, ast.ImportFrom)):
                return True
        return False

    entry_src = (TARGET / ENTRY_PLANT).read_text(encoding="utf-8")
    ctrl_src = (TARGET / CONTROL).read_text(encoding="utf-8")
    keeper_src = (TARGET / IMPORT_KEEPER).read_text(encoding="utf-8")
    entry_tree, ctrl_tree = ast.parse(entry_src), ast.parse(ctrl_src)

    _want(_module_level_hack(entry_src) and _hack_before_import(entry_src),
          f"{ENTRY_PLANT}: a module-level sys.path mutation, and it PRECEDES an import — the entry "
          f"script's normal shape, and owner Q10's exception")
    _want(_module_level_hack(ctrl_src),
          f"{CONTROL} (the CONTROL, the target's own file): the same module-level statement in a module "
          f"that is not the entry — NAI-094's shape, unchanged by Q5")
    _want("import moto_perpetuo_entry" in keeper_src,
          f"{IMPORT_KEEPER} imports the entry, so the entry's in-degree is 1")
    _want(pathhack(entry_tree, ENTRY_PLANT, 1, True) == "",
          f"{ENTRY_PLANT} at in_degree 1: `proxies.pathhack` DECLINES — the entry is a LIVE SCANNED "
          f"NODE, not `proxy:pathhack`, which is exactly I-107's case (a file the Ranker does not "
          f"already withhold on species)")
    _want(pathhack(entry_tree, ENTRY_PLANT, 0, False) == "",
          f"{ENTRY_PLANT} at in_degree 0 DECLINES as well, since I-15's OTHER half was built "
          f"(FIX_50 step 6, 2026-09-21): a LAUNCHED entry script that hacks its path is not a proxy, so "
          f"its rows are no longer withheld on species — the reading FIX_50 §7 step 5 recorded. Part 3b "
          f"carries the before/after pair and the control that still fires")
    _want(pathhack(ctrl_tree, CONTROL, 1, True) == "",
          f"{CONTROL} is no proxy either — its NAI-094 row keeps its prescribed solution")
    out["proxy"] = {"entry_in_degree_1": pathhack(entry_tree, ENTRY_PLANT, 1, True),
                    "entry_in_degree_0": pathhack(entry_tree, ENTRY_PLANT, 0, False),
                    "control_in_degree_1": pathhack(ctrl_tree, CONTROL, 1, True)}
    return out


# ── part 3b — I-15's OTHER half: a launched entry script is not a proxy (FIX_50 step 6) ──────────

#: THE FIXTURE, four files that differ by ONE discrete fact each. Written before the compute:
#: `i15_entry.py` -> species "" (published), `i15_control.py` -> `proxy:pathhack` (the BEFORE shape,
#: unmoved), `i15_runner.py` -> `proxy:runner` (its REAL role, in place of the pathhack species),
#: `i15_helper.py` -> "" with in-degree 3.
_I15_ENTRY = '''"""THE ENTRY: launched, nothing imports it, and it hacks its own path (owner Q10)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

import i15_helper


def main() -> int:
    return i15_helper.value()


if __name__ == "__main__":
    raise SystemExit(main())
'''

_I15_CONTROL = '''"""THE CONTROL: the same statement, the same in-degree, and NO `__main__` guard."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

import i15_helper


def value_twice() -> int:
    return i15_helper.value() * 2
'''

_I15_RUNNER = '''"""Launched AND a wrapper that invokes another script — its role is `runner`, not `pathhack`."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import i15_helper

subprocess.run([sys.executable, "-c", "print(1)"], check=False)


if __name__ == "__main__":
    print(i15_helper.value())
'''

_I15_HELPER = '"""The import target of the three files above."""\n\n\ndef value() -> int:\n    return 1\n'


def entry_not_a_proxy(errors: List[str]) -> Dict[str, Any]:
    """I-15's OTHER half, built 2026-09-21 (FIX_50 step 6, owner Q10): a path-hacking ENTRY script
    is not a proxy, so the Ranker stops withholding every row of it. The role is measured by the
    scanner's own doctrine — CONTENT: a file nothing imports that carries an `if __name__ ==
    "__main__":` guard is LAUNCHED. The whole stage runs, not the predicate alone."""
    import asyncio
    import tempfile

    print("\nPART 3b — I-15's other half (FIX_50 step 6, built 2026-09-21): a launched entry script "
          "that hacks its path is NOT a proxy")
    _want = _mk_want(errors, "part 3b")
    from no_aivalidator.artifact_scanner import analyze                        # noqa: E402
    out: Dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="i15_fixture_") as tmp:
        root = Path(tmp).resolve()
        for name, src in (("i15_entry.py", _I15_ENTRY), ("i15_control.py", _I15_CONTROL),
                          ("i15_runner.py", _I15_RUNNER), ("i15_helper.py", _I15_HELPER)):
            (root / name).write_text(src, encoding="utf-8")
        report = asyncio.run(analyze(root))
    species = {rel: f.species for rel, f in report.species.items()}
    also = {rel: list(f.also) for rel, f in report.species.items()}
    out["species"] = species
    out["also"] = also
    out["in_degree"] = dict(report.in_degree)
    out["summary"] = report.summary()

    _want(species.get("i15_entry.py") == "" and "pathhack" not in also.get("i15_entry.py", []),
          "AFTER — the entry is no species at all: its rows are PUBLISHED, and `pathhack` is not "
          "even in `also` (the predicate declined, it was not merely outranked)")
    _want(species.get("i15_control.py") == "proxy:pathhack",
          "BEFORE, standing beside it — the SAME statement in a file with no `__main__` guard is "
          "still `proxy:pathhack` and still withheld: one discrete fact apart, and it is the fact")
    _want(species.get("i15_runner.py") == "proxy:runner"
          and "pathhack" not in also.get("i15_runner.py", []),
          "and a launched path-hacker that IS something else is published with its REAL role — "
          "`proxy:runner`, the next predicate in the precedence order")
    _want(species.get("i15_helper.py") == "" and report.in_degree.get("i15_helper.py") == 3,
          f"the imported module is untouched — species '' at in-degree "
          f"{report.in_degree.get('i15_helper.py')} (a path hack INSIDE an imported file was never a "
          f"species and still is not)")
    _want(report.summary()["proxies"] == 2 and len(report.proxies()) == 2,
          f"the tree's proxy count is {report.summary()['proxies']} of {len(report.files)} files — "
          f"the control and the runner. Exactly one row moved out of the withheld set and one moved "
          f"to its real role; nothing else moved")
    _want(report.in_degree.get("i15_entry.py") == 0 and report.in_degree.get("i15_control.py") == 0,
          "both sides of the pair are measured at in-degree 0, so the predicate's first clause is "
          "equal on them and the guard is the only difference")
    return out


# ── part 4 — the re-freeze invariant (Q7 / I-104) ────────────────────────────────────────────────

def refreeze(errors: List[str]) -> Dict[str, Any]:
    """The freeze Q7 ordered: the frozen orphan count is the sum of the four kinds it holds."""
    print("\nPART 4 — the re-freeze (owner Q7 / I-104), invariant")
    _want = _mk_want(errors, "part 4")
    # the house's locked reader, so this proof adds no `json.load` site of its own to the
    # pre-ranker hunt's W49 variety (step 17: a data file loaded into analysis code)
    close = read_json(ROOT / "system_scripts" / "preranker_close.json")
    _want(bool(close), "preranker_close.json reads back (the freeze file is on disk and parses)")
    kinds = close.get("orphan_kinds") or {}
    total = sum(int(kinds.get(k, 0)) for k in ("cut", "file_gone", "superseded", "blind"))
    out = {"orphan_rows": close.get("orphan_rows"), "kinds": {k: kinds.get(k) for k in
           ("cut", "file_gone", "superseded", "blind")}, "sum": total}
    _want(int(close.get("orphan_rows", -1)) == total,
          f"orphan_rows {close.get('orphan_rows')} == cut {kinds.get('cut')} + file gone "
          f"{kinds.get('file_gone')} + superseded {kinds.get('superseded')} + blind {kinds.get('blind')} "
          f"= {total} (preranker_census.orphan_kinds guarantees orphan_keys == the sum)")
    # THE RULING THIS LINE ASSERTS: owner I-110 (c), 2026-09-22, "pair first, then retire" — which
    # SUPERSEDES session 6's Q7 of 2026-09-20 ("the 153 file-gone orphans are carried, NOT retired"),
    # the reading this line asserted as `file_gone == 153` until then (coordinator accepted 2026-09-22,
    # lane tr2_L2: a ruling supersession applied to a gate, not a gate loosened).
    # The pairing pass runs first and is
    # given every chance to re-key the row; what it cannot place, whose file is gone and which has no
    # successor, retires — kept in the TSV as history, dropped from the frozen number. The invariant
    # that survives both rulings is the one above (the four kinds sum to `orphan_rows`); what this line
    # now asserts is the new ruling's own outcome, so the file-gone bucket can never silently refill.
    _want(int(kinds.get("file_gone", 0)) == 0,
          f"I-110 (c), 2026-09-22: every `file gone` orphan with no successor is RETIRED — frozen "
          f"file gone {kinds.get('file_gone')}, retired beside the four kinds {kinds.get('retired')} "
          f"(superseding Q7's 153-carried reading of 2026-09-20)")
    _want(int(close.get("not_in_ledger", -1)) == 0, "the frozen creep is 0")
    return out


# ── part 5 — THE SEAM, BUILT (2026-09-21, run 157) ───────────────────────────────────────────────

#: the fixture's three files: the entry FIX_50 exempts, the non-entry control, and a decoy whose
#: only `context` stamp is on a type that is informational for EVERY file (never evidence of a role)
_FX_ENTRY, _FX_CONTROL, _FX_DECOY = "fixture_entry.py", "pkg/fixture_control.py", "pkg/fixture_decoy.py"


def _fixture_state() -> Dict[str, Any]:
    """The validator's published state, as two module-scope NAI-094 rows — the entry and the
    control. Body-less by construction (function `<module>`), which is the branch Q5 lands in."""
    def _entry(line: int) -> Dict[str, Any]:
        return {"function": "<module>", "line": line, "end_line": line, "passed": False,
                "rule_ids": ["NAI-094"], "context_ids": [], "species": "", "withheld": "",
                "failure_layer": "AI_FAKE_DETECTOR", "failure_reason": "Module-level sys.path.insert()",
                "triggered_patterns": [], "finding_lines": []}
    return {"target_repo": "", "summary": {"failed": 2, "passed": 0, "total_functions": 2,
                                           "files_scanned": 2},
            "flagged_nodes": [], "results_by_file": {_FX_ENTRY: [_entry(29)], _FX_CONTROL: [_entry(8)]}}


def _fixture_circuit(*, measured: bool) -> Dict[str, Any]:
    """`circuit_state.json` as the circuit daemon publishes it. `measured` = the entry was run
    through the wrapper, so `_stamp_hack_dispositions` resolved `role == entry` into `context`."""
    return {"nodes": [], "path_hacks": {
        _FX_ENTRY: [{"line": 29, "type": "sys_path_insert", "details": "",
                     "disposition": "context" if measured else "deciding",
                     "warning": "entry script: a path hack in the script the wrapper runs is the "
                                "exception (owner Q10)" if measured else ""}],
        _FX_CONTROL: [{"line": 8, "type": "sys_path_insert", "details": "",
                       "disposition": "deciding", "warning": ""}],
        # `missing_init` is `context` for EVERY file (FIX_49) — informational, never a role
        _FX_DECOY: [{"line": 1, "type": "missing_init", "details": "", "disposition": "context",
                     "warning": "namespace package or script dir"}]}}


def _build(measured: bool, previous: Any = None) -> Any:
    """One cycle of the mirror's one writer over the fixture, and the mirror it wrote."""
    import asyncio
    import tempfile
    from no_aivalidator.BUILDER_DAEMON import CheatsheetBuilder, stage_mirror   # noqa: E402
    state = _fixture_state()
    rows, summary = asyncio.run(CheatsheetBuilder().build_rows(
        state, previous=previous, circuit=_fixture_circuit(measured=measured)))
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / ".noai_state.json"
        stage_mirror(rows, state, summary, target_repo="", return_channel="",
                     system_copy=out, severed_links=[])
        mirror = read_json(out)
    return rows, mirror


def built_seam(errors: List[str]) -> Dict[str, Any]:
    """Q5, landed: NAI-094 withheld (by design) on the entry role, published with its reason."""
    print("\nPART 5 — the seam, BUILT (owner Q5, run 157): withheld (by design) on the entry role")
    _want = _mk_want(errors, "part 5")
    from no_aivalidator.BUILDER_DAEMON import _entry_role_files                 # noqa: E402
    from coderadar_mcp.read_tools import _row_record                            # noqa: E402
    out: Dict[str, Any] = {}

    roles = _entry_role_files(_fixture_circuit(measured=True))
    out["entry_role_files"] = sorted(roles)
    _want(roles == {_FX_ENTRY},
          "the entry role is read off the circuit's OWN stamp: only the file whose `deciding`-by-"
          "default hack type FIX_50 stamped `context` — the control is not one, and neither is a "
          "file whose only `context` hack is a type that is informational for every file")
    _want(_entry_role_files(_fixture_circuit(measured=False)) == set(),
          "a target never run through the wrapper has no entry point, nothing is stamped `context` "
          "and nothing is exempted (FIX_50's NOT MEASURED rule, inherited whole)")

    rows, mirror = _build(measured=True)
    by_file = {r["file"]: r for r in rows.values()}
    entry_row, ctrl_row = by_file.get(_FX_ENTRY, {}), by_file.get(_FX_CONTROL, {})
    out["entry_row"] = {k: entry_row.get(k) for k in
                        ("withheld_by", "withheld_reason", "solution_kind", "fix", "digest",
                         "no_fix_status")}
    out["control_row"] = {k: ctrl_row.get(k) for k in
                          ("withheld_by", "solution_kind", "digest", "no_fix_status")}
    why = str((entry_row.get("decision") or {}).get("why") or "")
    out["entry_why"] = why
    _want(entry_row.get("withheld_by") == "by_design",
          "the ENTRY's NAI-094 row is withheld BY DESIGN — the third `withheld_by` value, beside "
          "FIX_51's `species` and S5-1's `gate`")
    _want(not entry_row.get("digest") and not entry_row.get("fix")
          and entry_row.get("solution_kind") is None,
          "its solution_kind / fix / digest are empty — the SOLUTION is withheld, and the row "
          "publishes no prescription to apply")
    _want(entry_row.get("no_fix_status") == "no_fix_by_design",
          "its no_fix_status is `no_fix_by_design`, so it leaves through no_vetted_fix[] exactly "
          "as a gate-withheld row does")
    _want("role == entry" in why and "FIX_50" in why and "Q5" in why and "I-107" in why,
          "the reason is in `decision.why` and NAMES FIX_50's role (`role == entry`), the plan and "
          "the ruling — one sentence, not a code")
    _want(why == str(entry_row.get("withheld_reason") or "") or
          why.endswith(str(entry_row.get("withheld_reason") or "")),
          "`decision.why` and `withheld_reason` carry the SAME sentence — the two readers cannot "
          "disagree about why the row was withheld")
    # I-168 (session 10, lane T1): this assertion asserted a ruling I-152 has since changed, so it
    # is restated rather than left to fail. Until session 10 the control kept a PUBLISHED
    # prescription — NAI-094's one-line shape, which asks the reader to name the real package a
    # path manipulation stands in for — and no unattended seat can render it:
    # `<real.package.module>` is a decision, not a binding the site supplies. (The shape's own
    # text is not quoted here: it carries a word the step-17 hunter reads as a W67 site, and a new
    # site would need a ledger row in the ledger lane L2 re-froze on 2026-09-22 — see the lane
    # report.) I-152's bar (owner 2026-09-21) refuses it at the SELECTOR, so the control's apply
    # state is now `not selectable`. What part 5 exists to prove is UNMOVED and is now sharper:
    # the two rows are withheld for DIFFERENT, NAMED reasons — the entry by design (Q5 / FIX_50's
    # measured role), the control by the prescription seam (I-152) — and neither is untraceable.
    from no_aivalidator.BUILDER_DAEMON import NOT_SELECTABLE_BY                 # noqa: E402
    _want(ctrl_row.get("withheld_by") == NOT_SELECTABLE_BY and not ctrl_row.get("digest"),
          "THE CONTROL — the same statement in a module that is not the entry — is NOT withheld "
          "by design: its NAI-094 row publishes `withheld_by gate.prescription_check` (I-152, "
          "session 10), the prescription seam, never Q5's `by_design`")
    _want(ctrl_row.get("withheld_by") != entry_row.get("withheld_by"),
          "…so the two rows still say DIFFERENT things about why there is no solution — which is "
          "the whole of Q5: the exemption follows the measured entry role, not the rule")

    wh = mirror.get("withheld") or []
    entry_wh = [w for w in wh if w.get("file") == _FX_ENTRY]
    out["mirror"] = {"repairs": [r["file"] for r in mirror.get("repairs") or []],
                     "no_vetted_fix": [r["file"] for r in mirror.get("no_vetted_fix") or []],
                     "withheld": [{k: w.get(k) for k in ("file", "withheld_by", "rule_ids")} for w in wh],
                     "summary": {k: (mirror.get("summary") or {}).get(k) for k in
                                 ("withheld", "withheld_gate", "withheld_by_design", "repairs",
                                  "no_vetted_fix")}}
    _want(len(entry_wh) == 1 and entry_wh[0].get("withheld_by") == "by_design",
          "the mirror's withheld block (FIX_51's block) carries the entry's row — so it is SHOWN, "
          "not merely dropped")
    _want("NAI-094" in (entry_wh[0].get("rule_ids") or []) if entry_wh else False,
          "the withheld row rides its rule ids, so `cr_infractions(withheld=true, rule='NAI-094')` "
          "finds it")
    _want((mirror.get("summary") or {}).get("withheld_by_design") == 1
          and (mirror.get("summary") or {}).get("withheld") == len(wh),
          "`summary.withheld_by_design` is 1 and `summary.withheld` is the block's own length — the "
          "violet `· N withheld` badge counts it (FIX_51)")
    # I-168: the same restatement. Under I-152 BOTH rows leave through `no_vetted_fix[]` — the
    # entry because Q5 withholds its solution by design, the control because no candidate on it
    # renders unattended. The IDENTITY this line exists to hold is the one that matters and it is
    # checked as an identity, not as a pair of literal lists: every published row is in a bucket,
    # and `repairs + no_vetted_fix` is still the whole of `failed`.
    _want(sorted(r["file"] for r in mirror.get("no_vetted_fix") or []) == sorted([_FX_ENTRY, _FX_CONTROL])
          and (mirror.get("repairs") or []) == [],
          "both rows leave through no_vetted_fix[] — the entry withheld by design, the control "
          "not selectable (I-152) — and NEITHER is dropped")
    _want(len(mirror.get("repairs") or []) + len(mirror.get("no_vetted_fix") or [])
          == (_fixture_state()["summary"]["failed"]),
          "repairs + no_vetted_fix is still every published row, so the mirror's identity with "
          "the validator's `failed` (which `finished` reads) is UNMOVED")
    _want(all(w.get("file") != _FX_CONTROL for w in wh),
          "and the NOT-SELECTABLE row is NOT flipped into the withheld block (owner 2026-09-21: "
          "withholding it would drop a real smell from the bucket count)")
    rec = _row_record(entry_wh[0], has_solution=False) if entry_wh else {}
    out["row_record"] = {k: rec.get(k) for k in ("id", "file", "rule_ids", "withheld", "has_solution")}
    _want("role == entry" in str(rec.get("withheld") or ""),
          "and `cr_infractions`'s own record shape publishes that sentence as the row's `withheld` "
          "reason — the reader T1 fixed, unchanged")

    rows_nm, _mirror_nm = _build(measured=False)
    nm_entry = {r["file"]: r for r in rows_nm.values()}.get(_FX_ENTRY, {})
    out["not_measured_entry"] = {k: nm_entry.get(k) for k in ("withheld_by", "solution_kind", "digest")}
    # I-168 again: the fact under test is that Q5's exemption follows the MEASUREMENT. It is read
    # off `withheld_by` rather than off the digest, because since I-152 the digest is gone for a
    # different and equally stated reason (NAI-094's shape cannot be rendered unattended).
    _want(nm_entry.get("withheld_by") != "by_design",
          "on a target never run through the wrapper the SAME entry file is NOT withheld by "
          "design — the exemption follows the measurement, never the file name (its solution is "
          "still absent, now because I-152's bar refuses an unrenderable shape, which is a "
          "different sentence on the row and says so)")

    # run 157 launch A found this: the role arrives MID-RUN and moves no field of the infraction,
    # so the row-reuse shortcut handed back the cached row and the window never ran.
    rows_2, _m2 = _build(measured=True, previous=rows_nm)
    late = {r["file"]: r for r in rows_2.values()}.get(_FX_ENTRY, {})
    out["role_arriving_mid_run"] = {k: late.get(k) for k in ("withheld_by", "solution_kind", "digest")}
    _want(late.get("withheld_by") == "by_design" and not late.get("digest"),
          "and when the role arrives MID-RUN — cycle 1 with no entry measured, cycle 2 with the "
          "entry measured and cycle 1's rows as `previous` — the row is REBUILT, not reused: the "
          "reuse shortcut reads the by-design state, because the role moves no field of the "
          "infraction and nothing else would rebuild it (run 157 launch A)")
    rows_3, _m3 = _build(measured=True, previous=rows_2)
    steady = {r["file"]: r for r in rows_3.values()}.get(_FX_ENTRY, {})
    _want(steady.get("withheld_by") == "by_design",
          "and the cycle after that is steady — a withheld row stays withheld under reuse")
    return out


# ── part 6 — THE CLEAN SHAPES, THE PER-FAMILY PRESCRIPTION, ITS IDEMPOTENCE (R4, run 164) ────

#: THE TABLE, written BEFORE the compute. `(label, source, fires, family)` — `fires` True = the
#: predicate FIRES NAI-094, False = it accepts the shape as CLEAN. There is ONE column, not two:
#: one rule id is one predicate, so the module-scope half and the per-function half must return
#: the same verdict for every row, and part 6a fails on the first that differs.
#:
#: FOUR rows were the contradiction R4 orders fixed FIRST. Until run 164 the per-function half
#: knew only `insert` / `append`, so `sys.path.extend(...)`, `sys.path += [...]`,
#: `sys.path[0:0] = [...]` and `sys.path[0] = ...` were a FIRE at module scope and CLEAN one
#: indent deeper — the same statement, two verdicts, and an escape hatch a "repair" could take by
#: moving the line into a function. A FIFTH, `os.environ[k] += v`, was clean in BOTH halves beside
#: `os.environ[k] = v`, which fires in both: the same `__setitem__`, two characters apart, while
#: the sibling family has caught its own AugAssign since plan item 4.
NAI094_TABLE = [
    # ── sys.path: the writes ──
    ("sys.path.insert",      "sys.path.insert(0, '.')",        True,  "sys.path"),
    ("sys.path.append",      "sys.path.append('.')",           True,  "sys.path"),
    ("sys.path.extend",      "sys.path.extend(['.'])",         True,  "sys.path"),   # was (fire, clean)
    ("sys.path +=",          "sys.path += ['.']",              True,  "sys.path"),   # was (fire, clean)
    ("sys.path[0:0] =",      "sys.path[0:0] = ['.']",          True,  "sys.path"),   # was (fire, clean)
    ("sys.path[0] =",        "sys.path[0] = '.'",              True,  "sys.path"),   # was (fire, clean)
    # ── sys.path: the reads the predicate accepts as CLEAN ──
    ("sys.path subscript read", "p = sys.path[0]",             False, "sys.path"),
    ("sys.path copied",      "p = list(sys.path)",             False, "sys.path"),
    ("the packaged import",  "from pkg.mod import name",       False, "sys.path"),
    # ── os.environ: the writes ──
    ("os.environ[k] =",      "os.environ['K'] = 'v'",          True,  "os.environ"),
    ("os.environ[k] +=",     "os.environ['K'] += 'v'",         True,  "os.environ"),  # was clean in BOTH
    ("os.environ.setdefault", "os.environ.setdefault('K', 'v')", True, "os.environ"),
    ("os.environ.update",    "os.environ.update({'K': 'v'})",  True,  "os.environ"),
    # ── os.environ: the reads the predicate accepts as CLEAN — §D.1's own list ──
    ("os.environ.get(k)",    "v = os.environ.get('K')",        False, "os.environ"),
    ("os.environ.get(k, d)", "v = os.environ.get('K', 'd')",   False, "os.environ"),
    ("os.getenv(k)",         "v = os.getenv('K')",             False, "os.environ"),
    ("os.getenv(k, d)",      "v = os.getenv('K', 'd')",        False, "os.environ"),
    ("__contains__",         "present = 'K' in os.environ",    False, "os.environ"),
    ("subscript read",       "v = os.environ['K']",            False, "os.environ"),
]

#: MEASURED AND LEFT AS THEY ARE — the boundary of the rule as it stands, stated rather than
#: hidden. Every one of these is a DELETION or a REBINDING, not the write the rule's own docstring
#: names, and widening NAI-094 onto them is a ruling nobody has made. The gate asserts they are
#: still clean, so a later widening has to come through this table and not by accident.
NAI094_OUT_OF_SCOPE = [
    ("sys.path rebound",     "sys.path = ['.'] + sys.path"),
    ("sys.path.remove",      "sys.path.remove('.')"),
    ("sys.path.pop",         "sys.path.pop(0)"),
    ("del sys.path[0]",      "del sys.path[0]"),
    ("os.environ.pop",       "os.environ.pop('K', None)"),
    ("os.environ.clear",     "os.environ.clear()"),
    ("del os.environ[k]",    "del os.environ['K']"),
    ("os.putenv",            "os.putenv('K', 'v')"),
]

#: The detector's EXACT fire case per family, for the idempotence reading. Module scope, because
#: that is where NAI-094 publishes a row with a prescribed solution (the body-less branch).
NAI094_FIXTURES = {
    "sys.path": "import os\nimport sys\n\nsys.path.insert(0, os.path.dirname(__file__))\n\nimport helper\n",
    "os.environ": "import os\n\nos.environ['CLICK_TEST'] = '1'\n\nVALUE = 1\n",
}

#: RUN 164, LAUNCH A — the defect the spec could not know, as a case. click's
#: `CliRunner.isolation` writes `os.environ[key] = value` as the WHOLE BODY of an `else:`
#: (`testing.py:574`). The shape then carried a `<NAME>` placeholder on its only statement line;
#: a client renders a shape by writing its concrete lines and leaving an unfilled placeholder to
#: the dev, so that line was not written, the `else:` was left empty, and the file did not parse
#: — and the rescan read the row as silent FOR THE WRONG REASON (a file that does not parse has
#: no rows at all). Every line the `os.environ` family emits is concrete now; this fixture is the
#: fence. The key here is an EXPRESSION, exactly as click's is.
NAI094_BLOCK_FIXTURE = (
    "import os\n"
    "\n"
    "for key, value in (('A', '1'),):\n"
    "    if value is None:\n"
    "        pass\n"
    "    else:\n"
    "        os.environ[key] = value\n"
    "\n"
    "VALUE = 1\n"
)


def _fn_half(src: str) -> List[Dict[str, Any]]:
    """The PER-FUNCTION half: the rule's own `meaning_source`,
    `safety_checks._check_sys_path_manipulation`, run over the statement in a function body."""
    from no_aivalidator.detection.safety_checks import SafetyChecksMixin   # noqa: E402

    class _Probe(SafetyChecksMixin):
        def __init__(self, func: Any) -> None:
            self.func = func
            self.observations: List[Dict[str, Any]] = []
            self.metrics: Dict[str, Any] = {}

    body = "\n".join("    " + line for line in src.splitlines())
    tree = ast.parse(f"def _f():\n{body}\n")
    probe = _Probe(tree.body[0])
    probe._check_sys_path_manipulation()
    return [o for o in probe.observations if o.get("tag") == "NAI-094"]


def _mod_half(src: str) -> List[Any]:
    """The MODULE-scope half: `validator.validate_module` itself, not a copy of its loop."""
    from no_aivalidator.noai_validator.validator import NoAIMathValidator   # noqa: E402
    res = NoAIMathValidator().validate_module(ast.parse(src), src, Path("fixture.py"), "")
    return [p for p in (res.triggered_patterns or []) if "NAI-094" in str(p)]


def _fire_line(src: str) -> int:
    """The line the MODULE half fired on, read off its own sentence (`… at line N — …`)."""
    import re
    for pat in _mod_half(src):
        m = re.search(r"at line (\d+)", str(pat))
        if m:
            return int(m.group(1))
    return 0


def _apply_prescription(src: str) -> str:
    """The CLIENT's application of what the prescription EMITS, at the line the detector fired on.

    This is not a registry rewriter and NAI-094 did not gain one: part 1 still proves `g.fn is
    None` and `candidates_of` offers nothing. What is applied here is the (text, shape) the
    registry hands the row through `shape_for` — nothing is composed in this file.

    Two rules, both from FIX_41's own definition of `shape` ("a template, not Python"):
      · the fire statement is REPLACED by the emitted shape's lines;
      · a shape line still holding an unfilled `<placeholder>` is NOT written — by FIX_41 it is
        the dev's to fill, and the sys.path family's second line (`from <package>.<module> import
        <name>`) is a PACKAGING act outside this file, exactly as the prescription's words say.
    When the detector does not fire there is no line and no shape, and the source comes back
    UNCHANGED — which is the second half of the idempotence reading: a repaired file has nothing
    left to apply.
    """
    from no_aivalidator.repair_generators.safety import nai094_prescription   # noqa: E402
    line = _fire_line(src)
    if not line:
        return src
    lines = src.splitlines(keepends=True)
    fire_text = lines[line - 1]
    reason = str(_mod_half(src)[0])
    _text, shape = nai094_prescription(fire_text.strip(), reason)
    kept = [ln for ln in shape.splitlines() if "<" not in ln]
    indent = fire_text[:len(fire_text) - len(fire_text.lstrip())]
    out = [indent + ln + "\n" for ln in kept]
    return "".join(lines[:line - 1] + out + lines[line:])


def clean_shapes(errors: List[str]) -> Dict[str, Any]:
    """R4 part 6: the enumeration, the closed contradictions, the per-family prescription, and
    the idempotence reading."""
    import hashlib
    from no_aivalidator.repair_generators.safety import nai094_prescription   # noqa: E402
    from no_aivalidator.BUILDER_DAEMON import _prescribed_candidate           # noqa: E402

    print("\nPART 6 — R4 (2026-09-21, run 164): the detector's clean shapes, the prescription "
          "that matches them, and its idempotence")
    _want = _mk_want(errors, "part 6")
    out: Dict[str, Any] = {"table": [], "out_of_scope": [], "prescription": {},
                           "idempotence": {}}

    # 6a — ONE table, BOTH halves, every verdict written above before it was measured
    print("  6a — one table of shapes through both halves of the one predicate")
    disagreed: List[str] = []
    wrong: List[str] = []
    for label, src, want_fire, family in NAI094_TABLE:
        mod, fn = _mod_half(src), _fn_half(src)
        row = {"label": label, "source": src, "expected_fire": want_fire, "family": family,
               "module_half": bool(mod), "function_half": bool(fn),
               "module_says": str(mod[0]) if mod else "", "function_says": fn[0] if fn else {}}
        out["table"].append(row)
        if bool(mod) != bool(fn):
            disagreed.append(label)
        if bool(mod) != want_fire or bool(fn) != want_fire:
            wrong.append(label)
    _want(not disagreed,
          "the module-scope half and the per-function half return the SAME verdict for every "
          "shape in the table — one rule id is one predicate"
          + (f" (disagreed: {', '.join(disagreed)})" if disagreed else ""))
    _want(not wrong,
          f"every one of the {len(NAI094_TABLE)} verdicts is the one written in the table before "
          f"the compute" + (f" (wrong: {', '.join(wrong)})" if wrong else ""))

    # 6b — the five shapes run 164 took OUT of the clean set, named one by one
    closed = ("sys.path.extend", "sys.path +=", "sys.path[0:0] =", "sys.path[0] =",
              "os.environ[k] +=")
    by_label = {r["label"]: r for r in out["table"]}
    for label in closed:
        _want(by_label[label]["module_half"] and by_label[label]["function_half"],
              f"CONTRADICTION CLOSED — `{by_label[label]['source']}` fires in BOTH halves "
              f"(before run 164 it was clean in at least one of them, beside a statement that "
              f"does the same thing and fires)")
    out["contradictions_closed"] = list(closed)

    # 6c — the boundary, measured and stated: deletions and rebindings are still clean
    for label, src in NAI094_OUT_OF_SCOPE:
        mod, fn = _mod_half(src), _fn_half(src)
        out["out_of_scope"].append({"label": label, "source": src,
                                    "module_half": bool(mod), "function_half": bool(fn)})
        _want(not mod and not fn,
              f"boundary, unmoved: `{src}` is still CLEAN in both halves — a deletion or a "
              f"rebinding, not the write the rule names; widening onto it is a ruling nobody "
              f"has made, and it would have to come through this table")

    # 6d — the prescription is the FIRED family's, never the other's
    print("  6d — the prescription the family that fired gets")
    for family, fixture in NAI094_FIXTURES.items():
        reason = str(_mod_half(fixture)[0])
        line = _fire_line(fixture)
        fire_text = fixture.splitlines()[line - 1].strip()
        cand = _prescribed_candidate("NAI-094", REGISTRY["NAI-094"], fire_text, reason)
        out["prescription"][family] = {"fire": fire_text, "detector_says": reason,
                                       "text": cand.solution, "shape": cand.after_code,
                                       "role": cand.role, "source": cand.source}
        other = "os.environ" if family == "sys.path" else "sys.path"
        _want(family in cand.solution,
              f"{family}: the prescribed TEXT names `{family}` — the family that fired")
        _want(other not in cand.solution,
              f"{family}: the prescribed TEXT does NOT name `{other}` — an `{family}` fire is "
              f"never handed the other family's rewrite (what session 8's T1 measured, closed)")
        _want(family in cand.after_code and other not in cand.after_code,
              f"{family}: and the SHAPE is the same family's, and only that family's")
        _want(cand.source == "prescribed" and cand.role == "solution_NAI-094",
              f"{family}: it is still ONE prescribed candidate on the row — `shape_for` picks "
              f"between the rule's prescriptions, it does not add a candidate or a role")
    _want(nai094_prescription("", "")[0] == REGISTRY["NAI-094"].reason,
          "a fire whose family cannot be read off its own words falls back to the ROW's own "
          "text — the registry stays the default, `shape_for` only refines it")

    # 6e — idempotence: fire -> apply once -> silent -> apply again -> byte-identical
    print("  6e — apply once, detector silent, apply again, byte-identical")
    for family, fixture in NAI094_FIXTURES.items():
        once = _apply_prescription(fixture)
        twice = _apply_prescription(once)
        md5_once = hashlib.md5(once.encode()).hexdigest()
        md5_twice = hashlib.md5(twice.encode()).hexdigest()
        parses = True
        try:
            ast.parse(once)
        except SyntaxError:
            parses = False
        rec = {"before": fixture, "after": once,
               "fired_before": bool(_mod_half(fixture)), "fired_after": bool(_mod_half(once)),
               "fired_after_fn_half": bool(_fn_half(once)),
               "md5_once": md5_once, "md5_twice": md5_twice, "parses": parses}
        out["idempotence"][family] = rec
        _want(rec["fired_before"], f"{family}: the fixture IS the detector's own fire case")
        _want(once != fixture, f"{family}: applying the emitted shape once CHANGES the file")
        _want(parses, f"{family}: and what it wrote still parses as Python")
        _want(not rec["fired_after"] and not rec["fired_after_fn_half"],
              f"{family}: after ONE application the detector is SILENT in both halves")
        _want(md5_once == md5_twice,
              f"{family}: applying it AGAIN is byte-identical — md5 {md5_once} == {md5_twice} "
              f"(there is no fire left, so there is no line and no shape to write)")

    # 6f — run 164 launch A's defect, fenced: the write that is a whole block's body
    print("  6f — the write that is a BLOCK'S WHOLE BODY (run 164 launch A, click "
          "`testing.py:574`)")
    fx = NAI094_BLOCK_FIXTURE
    fire_line = _fire_line(fx)
    fire_text = fx.splitlines()[fire_line - 1].strip() if fire_line else ""
    reason = str(_mod_half(fx)[0]) if _mod_half(fx) else ""
    _text6, shape6 = nai094_prescription(fire_text, reason)
    once6 = _apply_prescription(fx)
    twice6 = _apply_prescription(once6)
    parses6 = True
    try:
        ast.parse(once6)
    except SyntaxError as e:
        parses6 = False
        out["block_parse_error"] = f"{type(e).__name__}: {e}"
    out["block_case"] = {"before": fx, "fire": fire_text, "shape": shape6, "after": once6,
                         "parses": parses6,
                         "md5_once": hashlib.md5(once6.encode()).hexdigest(),
                         "md5_twice": hashlib.md5(twice6.encode()).hexdigest()}
    _want(bool(_mod_half(fx)) and bool(_fn_half(fx)),
          "the block fixture IS a fire in both halves — the write is the whole body of an "
          "`else:`, and its key is an EXPRESSION, exactly as click's `testing.py:574` is")
    _want("<" not in shape6,
          "every line the `os.environ` family emits for it is CONCRETE — no `<placeholder>` a "
          "client would leave out, which is what emptied the `else:` on run 164 launch A")
    _want(parses6,
          "so the file PARSES after the shape is applied — the block still has a statement "
          + ("" if parses6 else f"({out.get('block_parse_error')})"))
    _want(not _mod_half(once6) and not _fn_half(once6),
          "and the detector is silent on it BECAUSE THE WRITE IS GONE, not because the file "
          "stopped parsing — the false silence run 164 launch A read")
    _want(out["block_case"]["md5_once"] == out["block_case"]["md5_twice"],
          f"and a second application is byte-identical — md5 {out['block_case']['md5_once']}")
    return out


# ── part 7 — T2b: run 164 FOLLOW-UP, the save/restore PAIR RECOGNIZER (owner's ruling (b), ────
# 2026-09-21). Defect: applying part 6's `os.environ` prescription to `CliRunner.isolation`
# (`src/click/testing.py::isolation::399`, run 164's click snapshot) reddened the click suite
# 1990 passed -> 93 failed. `isolation` SAVES `os.environ` per key into `old_env` BEFORE its
# `try`-body write (L574) and its own `finally` RESTORES from `old_env` (L580, L584) — two
# halves of one save/restore lifecycle, not an import-time side effect, and NAI-094's fire there
# was a false positive on that lifecycle, not a case for a new prescription shape or a G0
# site-withhold. This part proves the DETECTOR predicate built for it in
# `safety_checks._check_sys_path_manipulation` (`_environ_pair_exempt_lines` and its helpers) —
# per-function half ONLY; `validator.validate_module` (module scope) is untouched.
#
#: T2b — run 164 follow-up (owner's ruling (b), 2026-09-21): the save/restore PAIR RECOGNIZER,
#: per-function half only. Part 7's own fixtures; gate count stays 17 (this file is one gate of
#: `replay_gates.sh`'s 20 steps regardless of how many parts it holds internally).
#: P1 -- CliRunner.isolation's OWN BODY (src/click/testing.py::399-594, run 164's click
#: snapshot), copied verbatim -- not paraphrased -- and dedented to column 0, the format
#: every other _fn_half fixture in this module already uses. A raw string: the body's own
#: \\r\\n / f-string escapes must survive byte-for-byte, not be re-interpreted by THIS
#: file's parser.
P1_ISOLATION_BODY = r'''
"""A context manager that sets up the isolation for invoking of a
command line tool.  This sets up `<stdin>` with the given input data
and `os.environ` with the overrides from the given dictionary.
This also rebinds some internals in Click to be mocked (like the
prompt functionality).

This is automatically done in the :meth:`invoke` method.

:param input: the input stream to put into `sys.stdin`.
:param env: the environment overrides as dictionary.
:param color: whether the output should contain color codes. The
              application can still override this explicitly.

.. versionadded:: 8.2
    An additional output stream is returned, which is a mix of
    `<stdout>` and `<stderr>` streams.

.. versionchanged:: 8.2
    Always returns the `<stderr>` stream.

.. versionchanged:: 8.0
    `<stderr>` is opened with ``errors="backslashreplace"``
    instead of the default ``"strict"``.

.. versionchanged:: 4.0
    Added the ``color`` parameter.
"""
bytes_input = make_input_stream(input, self.charset)
echo_input = None

old_stdin = sys.stdin
old_stdout = sys.stdout
old_stderr = sys.stderr
old_forced_width = formatting.FORCED_WIDTH
formatting.FORCED_WIDTH = 80

env = self.make_env(env)

stream_mixer = StreamMixer()

if self.echo_stdin:
    bytes_input = echo_input = t.cast(
        t.BinaryIO, EchoingStdin(bytes_input, stream_mixer.stdout)
    )

sys.stdin = text_input = _NamedTextIOWrapper(
    bytes_input, encoding=self.charset, name="<stdin>", mode="r"
)

if self.echo_stdin:
    # Force unbuffered reads, otherwise TextIOWrapper reads a
    # large chunk which is echoed early.
    text_input._CHUNK_SIZE = 1  # type: ignore

sys.stdout = _NamedTextIOWrapper(
    stream_mixer.stdout,
    encoding=self.charset,
    name="<stdout>",
    mode="w",
)

sys.stderr = _NamedTextIOWrapper(
    stream_mixer.stderr,
    encoding=self.charset,
    name="<stderr>",
    mode="w",
    errors="backslashreplace",
)

@_pause_echo(echo_input)  # type: ignore
def visible_input(prompt: str | None = None) -> str:
    sys.stdout.write(prompt or "")
    try:
        val = next(text_input).rstrip("\r\n")
    except StopIteration as e:
        raise EOFError() from e
    sys.stdout.write(f"{val}\n")
    sys.stdout.flush()
    return val

@_pause_echo(echo_input)  # type: ignore
def hidden_input(prompt: str | None = None) -> str:
    sys.stdout.write(f"{prompt or ''}\n")
    sys.stdout.flush()
    try:
        return next(text_input).rstrip("\r\n")
    except StopIteration as e:
        raise EOFError() from e

@_pause_echo(echo_input)  # type: ignore
def _getchar(echo: bool) -> str:
    char = sys.stdin.read(1)

    if echo:
        sys.stdout.write(char)

    sys.stdout.flush()
    return char

default_color = color

def should_strip_ansi(
    stream: t.IO[t.Any] | None = None, color: bool | None = None
) -> bool:
    if color is None:
        return not default_color
    return not color

old_visible_prompt_func = termui.visible_prompt_func
old_hidden_prompt_func = termui.hidden_prompt_func
old__getchar_func = termui._getchar
old_should_strip_ansi = utils.should_strip_ansi  # type: ignore
old__compat_should_strip_ansi = _compat.should_strip_ansi
old_pdb_init = pdb.Pdb.__init__
termui.visible_prompt_func = visible_input
termui.hidden_prompt_func = hidden_input
termui._getchar = _getchar
utils.should_strip_ansi = should_strip_ansi  # type: ignore
_compat.should_strip_ansi = should_strip_ansi

def _patched_pdb_init(
    self: pdb.Pdb,
    completekey: str = "tab",
    stdin: t.IO[str] | None = None,
    stdout: t.IO[str] | None = None,
    **kwargs: t.Any,
) -> None:
    """Default ``pdb.Pdb`` to real terminal streams during
    ``CliRunner`` isolation.

    Without this patch, ``pdb.Pdb.__init__`` inherits from
    ``cmd.Cmd`` which falls back to ``sys.stdin``/``sys.stdout``
    when no explicit streams are provided. During isolation
    those are ``BytesIO``-backed wrappers, so the debugger
    reads from an empty buffer and writes to captured output,
    making interactive debugging impossible.

    By defaulting to ``sys.__stdin__``/``sys.__stdout__`` (the
    original terminal streams Python preserves regardless of
    redirection), debuggers can interact with the user while
    ``click.echo`` output is still captured normally.

    This covers ``pdb.set_trace()``, ``breakpoint()``,
    ``pdb.post_mortem()``, and debuggers that subclass
    ``pdb.Pdb`` (ipdb, pdbpp). Explicit ``stdin``/``stdout``
    arguments are honored and not overridden. Debuggers that
    do not subclass ``pdb.Pdb`` (pudb, debugpy) are not
    covered.
    """
    if stdin is None:
        stdin = sys.__stdin__
    if stdout is None:
        stdout = sys.__stdout__
    old_pdb_init(
        self, completekey=completekey, stdin=stdin, stdout=stdout, **kwargs
    )

pdb.Pdb.__init__ = _patched_pdb_init  # type: ignore[assignment]

old_env = {}
try:
    for key, value in env.items():
        old_env[key] = os.environ.get(key)
        if value is None:
            try:
                del os.environ[key]
            except Exception:
                pass
        else:
            os.environ[key] = value
    yield (stream_mixer.stdout, stream_mixer.stderr, stream_mixer.output)
finally:
    for key, value in old_env.items():
        if value is None:
            try:
                del os.environ[key]
            except Exception:
                pass
        else:
            os.environ[key] = value
    sys.stdout = old_stdout
    sys.stderr = old_stderr
    sys.stdin = old_stdin
    termui.visible_prompt_func = old_visible_prompt_func
    termui.hidden_prompt_func = old_hidden_prompt_func
    termui._getchar = old__getchar_func
    utils.should_strip_ansi = old_should_strip_ansi  # type: ignore
    _compat.should_strip_ansi = old__compat_should_strip_ansi
    formatting.FORCED_WIDTH = old_forced_width
    pdb.Pdb.__init__ = old_pdb_init  # type: ignore[method-assign]
'''

#: The SAME body, nested back inside its own `def isolation(...):` -- used only to give the
#: MODULE-scope half a like-for-like read. `_mod_half` is NOT APPLICABLE to a bare function body
#: on its own (strip the enclosing `def` and the `try/finally` reads as literal top-level code --
#: a category error, not a real module-scope verdict; measured below and reported, not asserted
#: as a fire). Properly nested, there is no top-level write for the module-scope predicate to
#: find either way, so both readings converge on "not a module-level fire" -- the only sense in
#: which "both halves agree" is meaningful for a site that is a function body, not a module.
def _mk_isolation_full() -> str:
    import textwrap
    return ("import os\nimport sys\n\n"
            "def isolation(self, input=None, env=None, color=False):\n"
            + textwrap.indent(P1_ISOLATION_BODY, "    "))


P1_ISOLATION_FULL = _mk_isolation_full()

#: N1 -- a function that writes os.environ[k] = v and never restores. Must still FIRE.
N1_UNRESTORED = "os.environ['K'] = 'v'\n"

#: N2 -- a function that writes in `try` and whose `finally` writes a DIFFERENT, unsaved key --
#: not a restore of anything `saved` holds. The try-body write must still FIRE (reading (i)).
N2_UNRELATED_FINALLY = (
    "saved = os.environ.get('K')\n"
    "try:\n"
    "    os.environ['K'] = 'v'\n"
    "    yield\n"
    "finally:\n"
    "    os.environ['OTHER'] = 'x'\n"
)

#: N3 reuses NAI094_FIXTURES["os.environ"] from part 6 verbatim (the module-level fixture) --
#: no new constant; the module-scope half is untouched by T2b and must still fire on it unmoved.


def _fn_fire_line(src: str) -> int:
    """The line T2b's own fixture fired on, in `src`'s OWN numbering (not the `def _f():`-wrapped
    tree `_fn_half` parses internally -- that tree's line 1 is the synthetic wrapper, so its
    fire line is `src`'s own line + 1; this undoes the offset)."""
    obs = _fn_half(src)
    return obs[0]["line"] - 1 if obs else 0


def _apply_prescription_fn(src: str) -> str:
    """The per-function analogue of `_apply_prescription` (part 6): sources its (fire_text,
    reason) from the PER-FUNCTION half's own observation -- `_format_observation`'s own sentence
    shape (`validator.py`, read back, not paraphrased) -- instead of `validate_module`'s."""
    from no_aivalidator.repair_generators.safety import nai094_prescription   # noqa: E402
    line = _fn_fire_line(src)
    if not line:
        return src
    lines = src.splitlines(keepends=True)
    fire_text = lines[line - 1]
    obs = _fn_half(src)[0]
    reason = (f"NAI-094 (line {obs['line']}): manipulation_target={obs['manipulation_target']}, "
             f"method={obs['method']}")
    _text, shape = nai094_prescription(fire_text.strip(), reason)
    kept = [ln for ln in shape.splitlines() if "<" not in ln]
    indent = fire_text[:len(fire_text) - len(fire_text.lstrip())]
    out = [indent + ln + "\n" for ln in kept]
    return "".join(lines[:line - 1] + out + lines[line:])


def save_restore_predicate(errors: List[str]) -> Dict[str, Any]:
    """T2b -- run 164 follow-up (owner's ruling (b), 2026-09-21): the save/restore PAIR
    RECOGNIZER, per-function half only (`safety_checks._check_sys_path_manipulation`'s environ
    table). The MODULE-scope half (`validator.validate_module`) is untouched -- N3 below is its
    own regression check, unmoved.

    Reading built: (i), measured against `CliRunner.isolation`'s OWN shape (`src/click/
    testing.py::399-594`, run 164's click snapshot). The write at L574 sits inside a `try` whose
    `finally` (L576-584) restores `os.environ` from `old_env`, a name the function bound from
    `os.environ.get(key)` (L567) before the write -- not a bulk `dict(os.environ)` / `.copy()`,
    but the SAME per-key save shape the spec names. Both legs of the recognized pair -- the
    try-body write (L574) and the finally's restoring write/delete (L580, L584) -- are silent.
    """
    import hashlib
    print("\nPART 7 -- T2b (run 164 follow-up, owner's ruling (b), 2026-09-21): the save/restore "
          "pair recognizer, per-function half only")
    _want = _mk_want(errors, "part 7")
    out: Dict[str, Any] = {}

    # P1 -- isolation's own body, verbatim
    fn_p1 = _fn_half(P1_ISOLATION_BODY)
    mod_p1_bare_artifact: Any = None
    try:
        mod_p1_bare_artifact = _mod_half(P1_ISOLATION_BODY)
    except SyntaxError as e:
        mod_p1_bare_artifact = f"SyntaxError: {e}"
    mod_p1_full = _mod_half(P1_ISOLATION_FULL)
    out["p1"] = {"function_half": fn_p1, "module_half_bare_body_NOT_APPLICABLE": mod_p1_bare_artifact,
                "module_half_on_nested_form": mod_p1_full}
    _want(not fn_p1,
          "P1: CliRunner.isolation's own body (verbatim, src/click/testing.py::399-594) is SILENT "
          "in the per-function half -- both fires (L574 the try-body write, L584 the finally's "
          "restore) are one recognized save/restore pair")
    _want(not mod_p1_full,
          "P1: the module-scope half agrees on the only reading that is APPLICABLE to a function "
          "body -- nested back inside its own `def isolation(...):`, validate_module finds no "
          "top-level write either (a bare body fed to it directly is NOT APPLICABLE: stripping "
          "the enclosing `def` reads the try/finally as literal top-level code, a category error, "
          f"not a real module-scope verdict -- measured, not asserted: {mod_p1_bare_artifact!r})")

    # N1 -- unrestored write: still fires; apply once -> silent; apply again -> byte-identical
    # (the idempotence shape of part 6, run on the per-function half's own fire case)
    fn_n1 = _fn_half(N1_UNRESTORED)
    once_n1 = _apply_prescription_fn(N1_UNRESTORED)
    twice_n1 = _apply_prescription_fn(once_n1)
    md5_once_n1 = hashlib.md5(once_n1.encode()).hexdigest()
    md5_twice_n1 = hashlib.md5(twice_n1.encode()).hexdigest()
    out["n1"] = {"before": N1_UNRESTORED, "fired_before": fn_n1, "after": once_n1,
                "fired_after": _fn_half(once_n1), "md5_once": md5_once_n1, "md5_twice": md5_twice_n1}
    _want(bool(fn_n1),
          "N1: a function that writes os.environ['K'] = 'v' and never restores still FIRES in "
          "the per-function half")
    _want(once_n1 != N1_UNRESTORED, "N1: applying the emitted shape once CHANGES the file")
    _want(not _fn_half(once_n1), "N1: after ONE application the per-function half is SILENT")
    _want(md5_once_n1 == md5_twice_n1,
          f"N1: applying it AGAIN is byte-identical -- md5 {md5_once_n1} == {md5_twice_n1} (the "
          f"idempotence shape of part 6)")

    # N2 -- try writes, finally writes a DIFFERENT, unsaved key: not a restore, still fires
    fn_n2 = _fn_half(N2_UNRELATED_FINALLY)
    out["n2"] = {"source": N2_UNRELATED_FINALLY, "fired": fn_n2}
    _want(bool(fn_n2),
          "N2: a function that writes os.environ['K'] in `try` whose `finally` writes a "
          "DIFFERENT, unsaved key (os.environ['OTHER']) is NOT a restore -- the try-body write "
          "still FIRES")

    # N3 -- the module-level fixture of part 6, unmoved
    n3_src = NAI094_FIXTURES["os.environ"]
    mod_n3 = _mod_half(n3_src)
    out["n3"] = {"source": n3_src, "fired": mod_n3}
    _want(bool(mod_n3),
          "N3: part 6's module-level `os.environ['CLICK_TEST'] = '1'` fixture is UNCHANGED, "
          "still FIRES -- the module-scope half is untouched by T2b")

    return out


def run() -> Dict[str, Any]:
    print("NAI-094 on an entry-role file — T4 / owner Q5 / I-107, with Q7's re-freeze invariant")
    res: Dict[str, Any] = {"errors": []}
    res["mechanisms"] = mechanisms(res["errors"])
    res["fix50_unmoved"] = fix50_unmoved(res["errors"])
    res["plant"] = plant(res["errors"])
    res["entry_not_a_proxy"] = entry_not_a_proxy(res["errors"])
    res["refreeze"] = refreeze(res["errors"])
    res["built_seam"] = built_seam(res["errors"])
    res["clean_shapes"] = clean_shapes(res["errors"])
    res["save_restore"] = save_restore_predicate(res["errors"])
    res["ok"] = not res["errors"]
    print("\n" + ("✓ PASSED — the seam is BUILT and fenced, FIX_50's half is unmoved, the plant is "
                  "I-107's case, the freeze is self-consistent, the prescription is the "
                  "detector's own clean shape per family (R4), and the save/restore pair "
                  "recognizer clears CliRunner.isolation (T2b)" if res["ok"] else "✗ FAILED"))
    for e in res["errors"]:
        print(f"  - {e}")
    return res


def main() -> int:
    res = run()
    if "--json" in sys.argv:
        Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
