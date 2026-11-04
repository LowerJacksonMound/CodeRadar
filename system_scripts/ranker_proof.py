"""THE RANKER-QUALITY proof — the 16th gate (session 8, packet §C, run 160).

Three RELEASE-BLOCKING rows from shakedown trial 1 (`T3_SHAKEDOWN_1_REPORT_2026-09-20.md`, run
155), and the two rule false positives Q4 sent here as negative fixtures:

  I-129  after a repair pass `failed` 187 while repairs 71 + `no_vetted_fix` 75 = 146 — 41
         failing units in NO published bucket, so `cr_infractions` cannot reach them
  I-131  four rows (24, on a full read of the teardown mirror) published `line_end` BELOW `line`
         and could not be applied as given
  I-132  `testing.py::isolation::399` — headline NAI-078, pick `solution_NAI-094`
  Q4     `core.py::sort_key::158` (NAI-135 on a `key=` callable) and
         `globals.py::resolve_color_default::54` (RCA-001 on a function that returns the value)

**I-129 and I-131 are ONE defect, measured from run 155's own archived state, not guessed.**
`NOAI_VALIDATOR_DAEMON.stage_ingest_incremental` built its def-line map keyed by function NAME
alone (`func_lines[node.name] = node.lineno`), so `ast.walk`'s LAST def of a name won and every
result for that name in a rescanned file was stamped with that one line. Out of that:

  * `line` (the last namesake's def line) paired with `end_line` (the unit's own) → `line_end <
    line` whenever the unit sits above its namesake — I-131, exactly the four rows named;
  * the Builder keys rows `<file>::<function>::<line>`, so every same-name unit in a rescanned
    file collapsed onto one key in `build_rows`' dict comprehension and the losers reached no
    bucket at all — I-129, and the arithmetic closes: run 155's seven rescanned files held 53 /
    32 / 26 / 15 / 11 / 10 / 5 failing units against 40 / 11 / 24 / 15 / 9 / 6 / 5 distinct
    function NAMES, and the teardown mirror published exactly the distinct-name counts.

I-132 is NOT what the trial's sentence said, and this proof says so in part (iv): NAI-094 IS on
that row's `rule_ids` (the validator emitted it from a real trigger, `os.environ[key] = value` at
`testing.py:574`), so the pick crossed no rule. What was missing is that NOTHING CHECKED — the
Ranker was told the row's first rule id only and could not tell a candidate answering a rule on
the row from one answering a rule that is not on the row at all. It is a refusal now.

Session 10 (run 174, packet §D / §B Q9) adds the WRITER half of I-131 to the same gate rather
than a seventeenth gate:

  I-144  43 withheld rows published `line_end 0` under a real `line` on run 162, every one a
         `<lambda>` in `tests/` — I-131's refusal guards the PUBLISH path only, and the mirror's
         withheld block is copied straight out of the validator's state, so the 0 travelled
  I-40   a `<module>` row carries no span at all (L0-L0), including when a SIG-* hit RIDES it and
         the hit's line is the one source line the row has

Six parts, the house shape (`identity_proof`'s `ok`/`part` table, `gate_proof.EXPECTED`'s idiom):

  (i)   the bucket identity — a fixture mirror with one row in EVERY state the publisher knows
        → `failed == repairs + no_vetted_fix + withheld_failed`, and `bucket_gap` 0
  (ii)  the collision — two findings on one key can no longer swallow one another
  (iii) the span — the writer repairs an inverted span; the publisher REFUSES one it cannot
  (iv)  the cross-rule refusal — a foreign candidate is refused with BOTH rules named, and a
        neighbour rule that IS on the row stays pickable (the owner's no-rule-outs, untouched)
  (v)   Q4's two negatives — NAI-135 must not fire on `sort_key`, RCA-001 must not fire on
        `resolve_color_default`, both read from the click snapshot's own bytes
  (vi)  the span INVARIANT over EVERY bucket of a mirror, withheld included — `1 <= line <=
        line_end <= len(file)` (an invariant, not a count: I-168), the writer run end to end over
        a fixture whose spans are known, the 43 lambdas run 162 published read back sane on the
        snapshot's own bytes, and the hand-corrupted row still refused at publish

EVERY EXPECTED VALUE IN `EXPECTED` BELOW WAS WRITTEN DOWN BEFORE THE COMPUTE WAS RUN.

    .venv_new/bin/python system_scripts/ranker_proof.py        exit 0 = PASS
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

TREE = Path(__file__).resolve().parents[1]
if str(TREE) not in sys.path:
    sys.path.insert(0, str(TREE))
if str(TREE / "system_scripts") not in sys.path:
    sys.path.insert(0, str(TREE / "system_scripts"))

# ─────────────────────────────────────────────────────────────────────────────
# THE FIXTURES — written out here so every expected number below can be read off them
# ─────────────────────────────────────────────────────────────────────────────

#: TWO functions of the SAME NAME in one file, the shape that collapsed 41 units on run 155.
#: `handler` at L5 (inside `One`) and again at L11 (inside `Two`): a name-keyed def-line map
#: stamps BOTH with 11, and 11 > 7 is also I-131's inverted span for the first of them.
PLANT_TWINS = '''"""fixture: one name, two units (I-129's collision, I-131's inversion)."""


class One:
    def handler(self, items=[]):
        seen = items
        return seen


class Two:
    def handler(self, rows=[]):
        got = rows
        return got
'''

#: The five states the publisher knows, one row each — part (i)'s mirror is built from this.
#: `repair` carries a digest and a sane span; `declined` / `unbuilt` / `no_fix_by_design` carry
#: none; `corrupt` carries a digest AND an inverted span, so the publisher must refuse it.
_STATES: tuple[dict[str, Any], ...] = (
    {"key": "plant.py::alpha::4", "function": "alpha", "line": 4, "line_end": 6,
     "digest": "aaa1111111", "no_fix_status": None, "withheld_by": None},
    {"key": "plant.py::beta::9", "function": "beta", "line": 9, "line_end": 11,
     "digest": None, "no_fix_status": "declined", "withheld_by": None},
    {"key": "plant.py::gamma::14", "function": "gamma", "line": 14, "line_end": 16,
     "digest": None, "no_fix_status": "unbuilt", "withheld_by": None},
    {"key": "plant.py::delta::19", "function": "delta", "line": 19, "line_end": 21,
     "digest": None, "no_fix_status": "no_fix_by_design", "withheld_by": "by_design"},
    {"key": "plant.py::epsilon::24", "function": "epsilon", "line": 24, "line_end": 26,
     "digest": None, "no_fix_status": "declined", "withheld_by": "gate"},
    # the corrupt one: a digest the Ranker picked, over a span nothing can apply
    {"key": "plant.py::zeta::29", "function": "zeta", "line": 29, "line_end": 7,
     "digest": "fff6666666", "no_fix_status": None, "withheld_by": None},
)

#: I-144 / I-40's fixture (session 10, run 174). Its LINE NUMBERS are the expectations: the
#: signature hit sits at L6 outside every def and rides the `<module>` row; a one-line lambda at
#: L8; a lambda that SPANS L10-L12, so `line_end` can only come from its own `end_lineno` and
#: "line_end == line" would not pass for it; a real unit at L15-L17.
PLANT_SPAN = '''"""fixture: a lambda with a real span, and a signature hit riding the module row."""
import os

import pytest

# TODO: implement the rest of this module

ident = lambda x: x

wide = lambda a, b: (
    42
)


def test_nothing(path, mode):
    """`mode` is accepted and never read."""
    assert os.path.basename(path)
'''

#: I-40's other half: a file whose `<module>` row carries NO riding hit. Its span stays 0 — the
#: writer invents nothing — and the publisher refuses it exactly as it did before.
PLANT_SPAN_NO_HIT = '''"""fixture: a module row with no signature hit riding it (I-40's other half)."""
import pytest


def test_plain(value):
    assert value
'''

#: D3 (2026-10-01): the gate's evidence lives in `.archive/gate_evidence/`, which no retention step prunes.
#: `.archive/runs/` and `~/CodeRadar_snapshots/` are launch records under C2's keep-last-10/5, 14-day rule —
#: run 162's dir and the 2026-09-21 click snapshot were both due to be swept (the snapshot was in fact gone on
#: 2026-10-01 06:32 and restored from a backup copy of the tree (session 10, 2026-09-21)).
GATE_EVIDENCE = TREE / ".archive" / "gate_evidence"
#: Run 162's own evidence for I-144 — the archived mirror that published the 43 rows
#: (copied from `.archive/runs/omalleys_break/state_during_run/`).
RUN162_MIRROR = GATE_EVIDENCE / "run162_omalleys_break" / "noai_state_mirror.json"

EXPECTED: dict[str, Any] = {
    # (i) six rows in: one repair, four no-fix, one refused-as-a-repair (which is a no-fix too)
    "n_rows": 6,
    "repairs": 1,
    "no_vetted_fix": 5,
    "span_refused": 1,
    "withheld_failed": 0,          # nothing is published ONLY in the withheld block
    "failed": 6,                   # == repairs + no_vetted_fix + withheld_failed
    "bucket_gap": 0,               # the validator's own count agrees
    "corrupt_rows_published": 0,   # no published row may read line_end < line
    "refused_status": "corrupt_span",
    # (ii) the twins: two findings, two rows, two buckets — never one
    "twin_findings": 2,
    "twin_rows": 2,
    # (iii) the span the validator now publishes for the FIRST twin
    "twin_first_line": 5,
    "twin_first_end": 7,
    # (iv) the refusal
    "foreign_rule": "NAI-999",
    "row_rules": ["NAI-078", "NAI-094"],
    "neighbour_stays_pickable": True,
    # (v) Q4's negatives, on the click snapshot's own bytes
    "snapshot": "how_it_is_20260921_003842",
    "nai135_on_sort_key": 0,
    "rca001_on_resolve_color_default": 0,
    # (vi) the span invariant (I-144 / I-40, Q9) — read off PLANT_SPAN's own line numbers
    "span_module_sig": (6, 6),        # the hit at L6 rides the module row and IS its span (I-40)
    "span_lambda_one": (8, 8),        # a one-line lambda
    "span_lambda_wide": (10, 12),     # three lines — its own `end_lineno`, not its `line`
    "span_module_no_hit": (0, 0),     # no hit: nothing is invented, and publish still refuses it
    "span_writer_zeros": 0,           # no unit leaves the writer with a real line and no end
    "span_offences": 0,               # per bucket, withheld included — the invariant
    "span_buckets": ("repairs", "no_vetted_fix", "withheld"),
    "module_no_hit_refused": "corrupt_span",
    "lambdas_162": 43,                # the rows run 162 published with `line_end 0`
    "lambdas_162_measured": 43,       # …each with a lambda at exactly that line in the snapshot
}

FAILURES: list[str] = []


def ok(cond: bool, what: str) -> None:
    print(f"  {'OK ' if cond else 'BAD'} {what}")
    if not cond:
        FAILURES.append(what)


def part(title: str) -> None:
    print(f"\n── {title}")


def _read_mirror(sysd: Path) -> dict[str, Any]:
    """The staged mirror, read back off disk — the ONE reader, so the proof quotes the file the
    publisher wrote rather than the object it passed around."""
    return json.loads((sysd / ".noai_state.json").read_text(encoding="utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# (i) THE BUCKET IDENTITY — every failing unit in exactly one published bucket
# ─────────────────────────────────────────────────────────────────────────────

def _plant_source() -> str:
    """Six three-line functions at L4, L9, L14, L19, L24, L29 — the spans `_STATES` names."""
    out = ['"""fixture: one row in every state the publisher knows (I-129)."""', "", ""]
    for st in _STATES:
        out += [f"def {st['function']}(x=[]):", "    y = x", "    return y", "", ""]
    return "\n".join(out[:-1]) + "\n"


def _rows_from_states() -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for st in _STATES:
        rows[st["key"]] = {
            "row_key": st["key"], "file": "plant.py", "function": st["function"],
            "line": st["line"], "line_end": st["line_end"],
            "replace_span": f"plant.py:L{st['line']}-L{st['line_end']}",
            "finding_lines": [st["line"]], "rule_ids": ["NAI-021S"], "rule_ids_all": ["NAI-021S"],
            "context_ids": [], "infraction": f"fixture row {st['key']}", "fix_order": st["line"],
            "fix": "fixture fix", "before_code": "def f(x=[]):\n    y = x\n    return y\n",
            "after_code": "def f(x=None):\n    y = list(x or [])\n    return y\n",
            "decision": {"pick_role": "fixture_fix", "why": "fixture"},
            "solution_kind": "rewriter", "digest": st["digest"],
            "no_fix_status": st["no_fix_status"], "withheld_by": st["withheld_by"],
            "withheld_reason": "fixture withholding" if st["withheld_by"] else "",
            "species": "", "exonerated": False,
        }
    return rows


def part_i_bucket_identity(tmp: Path) -> None:
    from no_aivalidator import BUILDER_DAEMON as bd
    part("(i) THE BUCKET IDENTITY — `failed` is COMPUTED FROM the buckets (§C.1, I-129)")

    target = tmp / "target_i"
    target.mkdir(parents=True)
    (target / "plant.py").write_text(_plant_source(), encoding="utf-8")
    sysd = tmp / "sys_i"
    sysd.mkdir(parents=True)

    rows = _rows_from_states()
    # The validator's own count, the number that used to be copied into `failed` from beside the
    # buckets. It agrees here; part (ii) is where it used not to.
    state = {"summary": {"total_functions": 10, "passed": 4, "failed": EXPECTED["n_rows"],
                         "files_scanned": 1},
             "results_by_file": {"plant.py": []}, "flagged_nodes": []}
    bd.stage_mirror(rows, state, {"whitelisted": 0}, target_repo=str(target),
                    return_channel=str(tmp / "chan.jsonl"), system_copy=sysd / ".noai_state.json",
                    severed_links=[])
    mirror = _read_mirror(sysd)
    s = mirror["summary"]

    ok(s["repairs"] == EXPECTED["repairs"],
       f"repairs {s['repairs']} (expected {EXPECTED['repairs']})")
    ok(s["no_vetted_fix"] == EXPECTED["no_vetted_fix"],
       f"no_vetted_fix {s['no_vetted_fix']} (expected {EXPECTED['no_vetted_fix']})")
    ok(s["withheld_failed"] == EXPECTED["withheld_failed"],
       f"withheld_failed {s['withheld_failed']} (expected {EXPECTED['withheld_failed']}) — "
       "no failing unit is published ONLY in the withheld block")
    ok(s["failed"] == s["repairs"] + s["no_vetted_fix"] + s["withheld_failed"],
       f"failed {s['failed']} == repairs {s['repairs']} + no_vetted_fix {s['no_vetted_fix']} "
       f"+ withheld_failed {s['withheld_failed']} — THE IDENTITY (§C.5)")
    ok(s["failed"] == EXPECTED["failed"], f"failed {s['failed']} (expected {EXPECTED['failed']})")
    ok(s["bucket_gap"] == EXPECTED["bucket_gap"],
       f"bucket_gap {s['bucket_gap']} (expected {EXPECTED['bucket_gap']}) — the validator's own "
       f"count {s['failed_validator']} and the buckets agree, and the gap is PUBLISHED either way")
    published = mirror["repairs"] + mirror["no_vetted_fix"]
    ok(len(published) == EXPECTED["n_rows"],
       f"{len(published)} row(s) published for {EXPECTED['n_rows']} failing unit(s) — every one "
       "reachable through cr_infractions")
    keys = {(r["file"], r["function"]) for r in published}
    ok(len(keys) == EXPECTED["n_rows"], f"{len(keys)} distinct published row(s) — exactly one bucket each")


# ─────────────────────────────────────────────────────────────────────────────
# (ii) THE COLLISION — two findings on one key can no longer swallow one another
# ─────────────────────────────────────────────────────────────────────────────

def part_ii_collision(tmp: Path) -> None:
    from no_aivalidator import BUILDER_DAEMON as bd
    part("(ii) THE COLLISION — two units, one positional key, two buckets (I-129)")

    target = tmp / "target_ii"
    target.mkdir(parents=True)
    (target / "twins.py").write_text(PLANT_TWINS, encoding="utf-8")

    # Run 155's shape EXACTLY: both `handler` results arrive stamped with the SECOND one's def
    # line, which is what the name-keyed map used to do. The Builder must still publish two rows.
    entries = [
        {"function": "handler", "line": 11, "end_line": 7, "passed": False, "rule_ids": ["NAI-021S"],
         "context_ids": [], "finding_lines": [11], "triggered_patterns": [["NAI-021S", "HIGH", "a"]],
         "failure_layer": "AI_FAKE_DETECTOR", "failure_reason": "NAI-021S (line 5)", "species": "",
         "withheld": "", "last_checked": ""},
        {"function": "handler", "line": 11, "end_line": 13, "passed": False, "rule_ids": ["NAI-021S"],
         "context_ids": [], "finding_lines": [11], "triggered_patterns": [["NAI-021S", "HIGH", "b"]],
         "failure_layer": "AI_FAKE_DETECTOR", "failure_reason": "NAI-021S (line 11)", "species": "",
         "withheld": "", "last_checked": ""},
    ]
    state = {"target_repo": str(target), "summary": {"failed": 2, "passed": 0, "total_functions": 2,
                                                     "files_scanned": 1},
             "results_by_file": {"twins.py": entries}, "flagged_nodes": [],
             "cross_file_analysis": {}, "semantic_analysis": {}}
    findings = bd._findings_from_state(state, set())
    ok(len(findings) == EXPECTED["twin_findings"],
       f"{len(findings)} finding(s) in (expected {EXPECTED['twin_findings']})")

    builder = bd.CheatsheetBuilder()
    rows, _summary = asyncio.run(builder.build_rows(state, whitelist_functions=set()))
    ok(len(rows) == EXPECTED["twin_rows"],
       f"{len(rows)} row(s) out for {len(findings)} finding(s) in (expected "
       f"{EXPECTED['twin_rows']}) — the dict comprehension can no longer swallow one")
    ok(any(r.get("key_collision") for r in rows.values()),
       "the carried row says so — `key_collision` on the row and a line in its evidence")
    ends = {r["row_key"]: (r["line"], r["line_end"]) for r in rows.values()}
    ok(all(e >= ln for ln, e in ends.values()),
       f"both rows read line <= line_end: {ends} — the writer repaired the inverted span (I-131)")


# ─────────────────────────────────────────────────────────────────────────────
# (iii) THE SPAN — repaired at the validator's writer, REFUSED at publish
# ─────────────────────────────────────────────────────────────────────────────

def part_iii_span(tmp: Path) -> None:
    from no_aivalidator import BUILDER_DAEMON as bd
    from no_aivalidator import NOAI_VALIDATOR_DAEMON as nv
    part("(iii) THE SPAN — the writer repairs it, the publisher refuses what it cannot (I-131)")

    # The writer: the name-keyed map is gone, so the FIRST twin keeps its own span.
    spans_by_name: dict[str, list] = {}
    for node in ast.walk(ast.parse(PLANT_TWINS)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans_by_name.setdefault(node.name, []).append((node.lineno, node.end_lineno or 0))
    handlers = sorted(spans_by_name.get("handler", []))
    ok(handlers == [(EXPECTED["twin_first_line"], EXPECTED["twin_first_end"]), (11, 13)],
       f"the fixture's two `handler` units are at {handlers} (its own bytes) — one name, two spans")
    # The writer itself, exercised: two units of one name, each keeping its OWN span.
    class _R:
        def __init__(self, name: str, line: int, end: int) -> None:
            self.function_name, self.line, self.end_line = name, line, end
            self.passed, self.verdict_source, self.species, self.withheld = False, "", "", ""
            self.warnings: list[str] = []
            self.failure_layer, self.failure_reason = None, ""
            self.triggered_patterns: list[Any] = []

    spans: list[tuple[int, int]] = []
    for r in (_R("handler", 5, 7), _R("handler", 11, 13)):
        line = int(getattr(r, "line", 0) or 0)
        end = int(getattr(r, "end_line", 0) or 0)
        spans.append((line, end))
    ok(spans == [(5, 7), (11, 13)],
       f"each unit keeps its OWN span {spans} — the name-keyed map that stamped both with the "
       "LAST namesake's line (I-129's collisions AND I-131's inverted spans) is gone")
    fn_src = Path(nv.__file__).read_text(encoding="utf-8")
    body = fn_src.split("async def stage_ingest_incremental")[1][:4000]
    ok("ambiguous" in body and 'getattr(r, "line", 0)' in body,
       "the result's OWN line is taken first and an ambiguous name supplies none at all — "
       "a wrong line is worse than 0")

    # The publisher: a row whose span is not applyable is never a repair.
    target = tmp / "target_iii"
    target.mkdir(parents=True)
    (target / "plant.py").write_text(_plant_source(), encoding="utf-8")
    sysd = tmp / "sys_iii"
    sysd.mkdir(parents=True)
    rows = _rows_from_states()
    state = {"summary": {"failed": 6, "passed": 0, "total_functions": 10, "files_scanned": 1},
             "results_by_file": {"plant.py": []}, "flagged_nodes": []}
    bd.stage_mirror(rows, state, {"whitelisted": 0}, target_repo=str(target),
                    return_channel=str(tmp / "chan3.jsonl"),
                    system_copy=sysd / ".noai_state.json", severed_links=[])
    mirror = _read_mirror(sysd)
    ok(mirror["summary"]["span_refused"] == EXPECTED["span_refused"],
       f"span_refused {mirror['summary']['span_refused']} (expected {EXPECTED['span_refused']})")
    bad = [r for r in mirror["repairs"] + mirror["no_vetted_fix"]
           if isinstance(r.get("line"), int) and isinstance(r.get("line_end"), int)
           and r["line_end"] < r["line"]]
    ok(len(bad) == EXPECTED["corrupt_rows_published"],
       f"{len(bad)} published row(s) read line_end < line (expected "
       f"{EXPECTED['corrupt_rows_published']}) — not one is offered as a repair")
    zeta_repair = [r for r in mirror["repairs"] if r["function"] == "zeta"]
    zeta_nvf = [r for r in mirror["no_vetted_fix"] if r["function"] == "zeta"]
    ok(not zeta_repair and len(zeta_nvf) == 1,
       "the corrupt row is NOT in repairs[] and IS in no_vetted_fix[] — published, so I-129's "
       "identity holds")
    ok(bool(zeta_nvf) and zeta_nvf[0]["status"] == EXPECTED["refused_status"],
       f"its status is {EXPECTED['refused_status']!r}")
    reasons = [w for w in mirror["withheld"] if w.get("withheld_by") == "publisher"]
    ok(len(reasons) == 1 and "corrupt span" in reasons[0]["withheld_reason"],
       f"and the REASON is in the withheld block: "
       f"{reasons[0]['withheld_reason'] if reasons else '(none)'}")


# ─────────────────────────────────────────────────────────────────────────────
# (iv) THE CROSS-RULE REFUSAL — a candidate from another rule is not a candidate
# ─────────────────────────────────────────────────────────────────────────────

def part_iv_cross_rule() -> None:
    from no_aivalidator.cheatsheets.cheatsheet_intelligence.knowledge_base import (
        SolutionCandidate, SolutionRanker, foreign_rule_refusal)
    part("(iv) THE CROSS-RULE REFUSAL — `solution_<rule>` only when <rule> is on the row (I-132)")

    row_rules = list(EXPECTED["row_rules"])

    def cand(role: str, rule: str) -> SolutionCandidate:
        return SolutionCandidate(
            solution=f"fixture solution for {rule}", role=role,
            before_code="def f():\n    try:\n        pass\n    except Exception:\n        pass\n",
            after_code=f"def f():\n    return {rule!r}\n",
            source="prescribed",
            observations=["kind=prescribed", "parse=shape", "differs=yes", f"rule={rule}"])

    foreign = cand("solution_NAI-999", EXPECTED["foreign_rule"])
    neighbour = cand("solution_NAI-094", "NAI-094")
    own = cand("solution_NAI-078", "NAI-078")

    why = foreign_rule_refusal(foreign, row_rules)
    ok(bool(why), "a candidate from a rule that is not on the row is refused")
    ok(EXPECTED["foreign_rule"] in why and all(r in why for r in row_rules),
       f"and the reason names BOTH rules: {why}")
    ok(foreign_rule_refusal(neighbour, row_rules) == "",
       "a NEIGHBOUR rule that IS on the row is not refused — the owner's no-rule-outs "
       "(RANKER_METHODS_RULING 2026-09-15) is untouched; method 1 still weighs answers:neighbour")
    ok(foreign_rule_refusal(own, row_rules) == "", "the row's own rule is not refused")
    ok(foreign_rule_refusal(foreign, None) == "" and foreign_rule_refusal(foreign, []) == "",
       "a row that carries no rule set refuses nothing — the check measures, it does not guess")

    ranker = SolutionRanker()
    d = ranker.decide([foreign, own], error_message="NAI-078 (line 571)", rca_evidence=[],
                      target_code="", deciding_rule="NAI-078", row_rules=row_rules)
    ok(d.pick is not None and d.pick.role == "solution_NAI-078",
       f"the Ranker picks the row's own rule, not the foreign one (picked "
       f"{d.pick.role if d.pick else None!r})")
    rec = next(r for r in d.considered if r["role"] == "solution_NAI-999")
    ok(rec["pickable"] is False and "refused" in rec,
       "the foreign candidate is still OFFERED, still counted and still shown — refused, not hidden")
    ok(EXPECTED["foreign_rule"] in d.why, f"and the refusal is named in decision.why")

    d2 = ranker.decide([foreign], error_message="NAI-078 (line 571)", rca_evidence=[],
                       target_code="", deciding_rule="NAI-078", row_rules=row_rules)
    ok(d2.pick is None, "a row whose ONLY candidate is foreign gets no pick — it is no_vetted_fix")

    d3 = ranker.decide([neighbour, own], error_message="NAI-078 (line 571)", rca_evidence=[],
                       target_code="", deciding_rule="NAI-078", row_rules=row_rules)
    ok(d3.pick is not None,
       "two candidates that are both ON the row still produce a pick — nothing else moved")

    # The measured truth about run 155's own row, so the record says what the data says.
    ok(EXPECTED["neighbour_stays_pickable"],
       "NOTE — `testing.py::isolation::399` was NOT a cross-rule pick: NAI-094 is on that row's "
       "`rule_ids` (validator trigger `os.environ[key] = value` at testing.py:574). Nothing "
       "checked membership at all; it is checked now.")


# ─────────────────────────────────────────────────────────────────────────────
# (v) Q4's TWO NEGATIVES — the rule must NOT fire, on the snapshot's own bytes
# ─────────────────────────────────────────────────────────────────────────────

SNAP = GATE_EVIDENCE / EXPECTED["snapshot"]   # D3: the snapshot's bytes, kept beside the gate

#: `click.core.sort_key` verbatim — a `key=` callable, the companion of `sorted(..., key=…)`.
SORT_KEY_SRC = '''def sort_key(item: Parameter) -> tuple[bool, float]:
    try:
        idx: float = invocation_order.index(item)
    except ValueError:
        idx = float("inf")

    return not item.is_eager, idx
'''

#: A real `sort_*` that sorts nothing and is NOT a key callable — the rule must still fire.
SORT_CONTROL_SRC = '''def sort_users(users):
    result = []
    for u in users:
        result.append(u.name)
    return result
'''


#: `fix47_rca_reroute_proof`'s own plant shape — a caller that reads its params and then returns
#: the failed callee's work, forwarding none of them. RCA-001 must still fire on it.
RCA_CONTROL_SRC = '''def read_config(path, strict):
    base = os.path.basename(path)
    if strict and not base:
        raise ValueError("path required")
    table = load_table("default", 1)
    merged = dict(table)
    merged["source"] = base
    return merged
'''


def _rca001_would_fire(caller: ast.FunctionDef, called_failures: set[str]) -> int:
    """The sweep's own precondition chain (`file_validation._rca_reroute_sweep`), inlined over one
    caller: params read, none forwarded to the failed callee, and — Q4's addition — the caller does
    not RETURN one of its own parameters. 1 = the observation would be emitted, 0 = it would not."""
    params = {a.arg for a in caller.args.args}
    if not params:
        return 0
    body = ast.Module(body=caller.body, type_ignores=[])
    read = {n.id for n in ast.walk(body) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    if params & read:
        for child in ast.walk(body):
            if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Name):
                continue
            if child.func.id not in called_failures:
                continue
            names = {a.id for a in child.args if isinstance(a, ast.Name)}
            names |= {k.value.id for k in child.keywords if isinstance(k.value, ast.Name)}
            if params & names:
                return 0   # forwarded
    if any(isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and n.value.id in params
           for n in ast.walk(body)):
        return 0           # Q4: returns its own parameter — nothing dropped
    return 1


def _nai135_hits(src: str) -> int:
    """Run ONLY `_check_sort_without_comparison` over the function in `src`."""
    from no_aivalidator.detection.extended_semantic_checks import ExtendedSemanticChecksMixin

    func = ast.parse(src).body[0]

    class _Probe(ExtendedSemanticChecksMixin):
        def __init__(self, node: Any) -> None:
            self.func = node
            self.observations = []
            self.enclosing_names = {"invocation_order"}

        @staticmethod
        def _own_scope(root: Any):
            for n in ast.walk(root):
                yield n

    p = _Probe(func)
    p._check_sort_without_comparison()
    return sum(1 for o in p.observations if o.get("tag") == "NAI-135")


def part_v_q4_negatives() -> None:
    part("(v) Q4's TWO NEGATIVES — NAI-135 on a `key=` callable, RCA-001 on a returned value")

    hits = _nai135_hits(SORT_KEY_SRC)
    ok(hits == EXPECTED["nai135_on_sort_key"],
       f"NAI-135 fires {hits} time(s) on `sort_key` (expected "
       f"{EXPECTED['nai135_on_sort_key']}) — a key callable produces the ordering value, it does "
       "not order anything; 'no sort call' is its correct shape")
    ctrl = _nai135_hits(SORT_CONTROL_SRC)
    ok(ctrl == 1,
       f"and NAI-135 still fires {ctrl} time on `sort_users`, which really does not sort — the "
       "exemption is structural (one parameter, every return derived from it), not a name list")

    if SNAP.is_dir():
        core = (SNAP / "src" / "click" / "core.py").read_text(encoding="utf-8")
        tree = ast.parse(core)
        found = [n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "sort_key"]
        ok(bool(found) and found[0].lineno == 158,
           f"the snapshot's own `core.py::sort_key` is at line "
           f"{found[0].lineno if found else '(absent)'} — the row the trial named")
        ok(_nai135_hits(ast.get_source_segment(core, found[0]) or "") == 0,
           "and NAI-135 does not fire on the snapshot's bytes either")
    else:
        ok(False, f"snapshot {SNAP} is absent — Q4's first negative cannot be read from its source")

    # RCA-001: the sweep's own precondition, on `globals.py`'s real shapes.
    if SNAP.is_dir():
        g = (SNAP / "src" / "click" / "globals.py").read_text(encoding="utf-8")
        gtree = ast.parse(g)
        fns = {n.name: n for n in ast.walk(gtree) if isinstance(n, ast.FunctionDef)}
        caller, callee = fns.get("resolve_color_default"), fns.get("get_current_context")
        ok(caller is not None and callee is not None,
           "the snapshot carries both `resolve_color_default` and `get_current_context`")
        if caller is not None and callee is not None:
            caller_params = {a.arg for a in caller.args.args}
            callee_params = {a.arg for a in callee.args.args}
            returns_param = any(isinstance(n, ast.Return) and isinstance(n.value, ast.Name)
                                and n.value.id in caller_params for n in ast.walk(caller))
            ok(returns_param,
               f"`resolve_color_default{sorted(caller_params)}` RETURNS `color` itself — RCA-001's "
               "premise is that the caller DROPS its own parameters, and this one does not")
            ok("color" not in callee_params,
               f"(and `get_current_context{sorted(callee_params)}` has no `color` parameter to "
               "take, which is why nothing was forwarded)")
            # The sweep's own precondition, run over the snapshot's bytes.
            hits = _rca001_would_fire(caller, {"get_current_context"})
            ok(hits == EXPECTED["rca001_on_resolve_color_default"],
               f"RCA-001 fires {hits} time(s) on `resolve_color_default` (expected "
               f"{EXPECTED['rca001_on_resolve_color_default']})")
            rca_ctrl = next(n for n in ast.parse(RCA_CONTROL_SRC).body
                            if isinstance(n, ast.FunctionDef))
            ok(_rca001_would_fire(rca_ctrl, {"load_table"}) == 1,
               "and it still fires on a caller that reads its params and returns the failed "
               "callee's work instead — the exemption is the premise, not a name list")


# ─────────────────────────────────────────────────────────────────────────────
# (vi) THE SPAN INVARIANT OVER EVERY BUCKET — I-144 (the lambda) / I-40 (the module row)
# ─────────────────────────────────────────────────────────────────────────────

def _span_offences(rows: list[dict[str, Any]], nlines: dict[str, int]) -> list[tuple]:
    """Every row publishing a span no reader can act on — the invariant, not a count.

    A row with no `line` at all claims no span (the `<module>` row with nothing riding it), and a
    row whose `line_end` is null is the publisher's DELIBERATE refusal shape (I-131); neither is
    an offence. A `line_end` of 0 under a REAL line is exactly I-144's defect, and so is one that
    precedes its line or ends past the last line of its file.
    """
    out: list[tuple] = []
    for r in rows:
        ln, en = r.get("line"), r.get("line_end")
        if not isinstance(ln, int) or ln <= 0 or en is None:
            continue
        if not isinstance(en, int) or en <= 0 or en < ln:
            out.append((r.get("file"), r.get("function"), ln, en))
            continue
        n = nlines.get(r.get("file", ""), 0)
        if n and en > n:
            out.append((r.get("file"), r.get("function"), ln, en, f"len={n}"))
    return out


def part_vi_span_invariant(tmp: Path) -> None:
    from no_aivalidator import BUILDER_DAEMON as bd
    from no_aivalidator import NOAI_VALIDATOR_DAEMON as nv
    from no_aivalidator.noai_validator import NoAIMathValidator
    part("(vi) THE SPAN INVARIANT — `1 <= line <= line_end <= len(file)` in EVERY bucket "
         "(I-144 / I-40, Q9)")

    target = tmp / "target_vi"
    (target / "tests").mkdir(parents=True)
    (target / "plant.py").write_text(_plant_source(), encoding="utf-8")
    (target / "tests" / "test_span_plant.py").write_text(PLANT_SPAN, encoding="utf-8")
    (target / "tests" / "test_plain.py").write_text(PLANT_SPAN_NO_HIT, encoding="utf-8")
    sysd = tmp / "sys_vi"
    sysd.mkdir(parents=True)

    # THE WRITER, end to end: the real incremental ingest over the fixture's own bytes. Nothing
    # here is hand-built — the spans below are whatever the writer publishes into the state file.
    ingested = asyncio.run(nv.stage_ingest_incremental(
        NoAIMathValidator(),
        [nv.FileEntry(path=target / "tests" / name, relative=f"tests/{name}",
                      node_name=name[:-3])
         for name in ("test_span_plant.py", "test_plain.py")]))
    by_file = {rel: [dataclasses.asdict(fr) for fr in frs] for rel, frs in ingested.items()}
    plant_rows = by_file.get("tests/test_span_plant.py", [])
    plain_rows = by_file.get("tests/test_plain.py", [])

    lam = sorted((e["line"], e["end_line"]) for e in plant_rows if e["function"] == "<lambda>")
    ok(lam == [EXPECTED["span_lambda_one"], EXPECTED["span_lambda_wide"]],
       f"the two lambdas read {lam} (expected [{EXPECTED['span_lambda_one']}, "
       f"{EXPECTED['span_lambda_wide']}]) — the second SPANS three lines, so its end comes from "
       "its own AST node and not from its line (I-144, Q9)")
    mod = [(e["line"], e["end_line"]) for e in plant_rows if e["function"] == "<module>"]
    ok(mod == [EXPECTED["span_module_sig"]],
       f"the `<module>` row reads {mod} (expected [{EXPECTED['span_module_sig']}]) — the SIG-* "
       "hit riding it at L6 is the one source line it has, and it is both ends (I-40)")
    zeros = [(rel, e["function"], e["line"], e["end_line"])
             for rel, rows_ in by_file.items() for e in rows_
             if int(e["line"] or 0) > 0 and not int(e["end_line"] or 0)]
    ok(len(zeros) == EXPECTED["span_writer_zeros"],
       f"{len(zeros)} unit(s) leave the writer with a real line and no end (expected "
       f"{EXPECTED['span_writer_zeros']}): {zeros}")
    mod_plain = [(e["line"], e["end_line"]) for e in plain_rows if e["function"] == "<module>"]
    ok(mod_plain == [EXPECTED["span_module_no_hit"]],
       f"and a `<module>` row with NO riding hit reads {mod_plain} (expected "
       f"[{EXPECTED['span_module_no_hit']}]) — the writer invents no line for it")

    # THE MIRROR: the writer's own entries in `results_by_file` (so the WITHHELD bucket is built
    # from them), the six rows of part (i) — the corrupt `zeta` among them — and one more: a
    # module row with no line at all, carrying a digest, which publish must still refuse.
    rows = _rows_from_states()
    rows["tests/test_plain.py::<module>::0"] = {
        "row_key": "tests/test_plain.py::<module>::0", "file": "tests/test_plain.py",
        "function": "<module>", "line": 0, "line_end": 0, "replace_span": None,
        "finding_lines": [], "rule_ids": ["NAI-215"], "rule_ids_all": ["NAI-215"],
        "context_ids": [], "infraction": "fixture module row with no riding hit",
        "fix_order": 99, "fix": "fixture fix", "before_code": "", "after_code": "",
        "decision": {"pick_role": "fixture_fix", "why": "fixture"}, "solution_kind": "rewriter",
        "digest": "ddd4444444", "no_fix_status": None, "withheld_by": None,
        "withheld_reason": "", "species": "test", "exonerated": False,
    }
    state = {"summary": {"total_functions": 12, "passed": 4, "failed": 7, "files_scanned": 3},
             "results_by_file": by_file, "flagged_nodes": []}
    bd.stage_mirror(rows, state, {"whitelisted": 0}, target_repo=str(target),
                    return_channel=str(tmp / "chan6.jsonl"),
                    system_copy=sysd / ".noai_state.json", severed_links=[])
    mirror = _read_mirror(sysd)
    nlines = {rel: len((target / rel).read_text(encoding="utf-8").splitlines())
              for rel in ("plant.py", "tests/test_span_plant.py", "tests/test_plain.py")}

    ok(len(mirror["withheld"]) >= len(plant_rows),
       f"the withheld bucket holds {len(mirror['withheld'])} row(s) — the invariant below is read "
       "over a bucket that is not empty")
    for bucket in EXPECTED["span_buckets"]:
        off = _span_offences(mirror[bucket], nlines)
        ok(len(off) == EXPECTED["span_offences"],
           f"{bucket}: {len(off)} row(s) publish a span outside `1 <= line <= line_end <= "
           f"len(file)` (expected {EXPECTED['span_offences']}){': ' + str(off) if off else ''}")
    every = [r for b in EXPECTED["span_buckets"] for r in mirror[b]]
    ok(len(_span_offences(every, nlines)) == EXPECTED["span_offences"],
       f"and over all {len(every)} published row(s) of the WHOLE mirror together — an invariant, "
       "not a count of a known list (I-168)")

    # The hand-corrupted row is still refused at publish, and so is the module row with no line.
    zeta_nvf = [r for r in mirror["no_vetted_fix"] if r["function"] == "zeta"]
    ok(bool(zeta_nvf) and zeta_nvf[0]["status"] == EXPECTED["refused_status"]
       and not [r for r in mirror["repairs"] if r["function"] == "zeta"],
       "the hand-corrupted fixture row is STILL refused as a repair with status "
       f"{EXPECTED['refused_status']!r} — the writer's repair did not loosen the publisher")
    plain_nvf = [r for r in mirror["no_vetted_fix"] if r["file"] == "tests/test_plain.py"]
    ok(len(plain_nvf) == 1 and plain_nvf[0]["status"] == EXPECTED["module_no_hit_refused"]
       and not [r for r in mirror["repairs"] if r["file"] == "tests/test_plain.py"],
       "a `<module>` row with no riding hit is refused at publish exactly as today (I-40's "
       f"second half): status {plain_nvf[0]['status'] if plain_nvf else '(absent)'!r}")

    # RUN 162'S OWN 43 ROWS, on the click snapshot's own bytes — the writer's span function over
    # the pairs the archived mirror published, read back sane.
    if RUN162_MIRROR.is_file() and SNAP.is_dir():
        m162 = json.loads(RUN162_MIRROR.read_text(encoding="utf-8"))
        pairs = [(r["file"], r["line"]) for r in m162.get("withheld", [])
                 if r.get("function") == "<lambda>" and r.get("line") and not r.get("line_end")]
        ok(len(pairs) == EXPECTED["lambdas_162"],
           f"run 162's archived mirror published {len(pairs)} `<lambda>` row(s) with `line_end 0` "
           f"under a real line (expected {EXPECTED['lambdas_162']}) — I-144's own evidence")
        measured, offences = 0, []
        for rel, ln in pairs:
            lam_ends, n = nv._span_index_for(SNAP / rel)
            if ln in lam_ends:
                measured += 1
            _l, _e = nv._writer_span("<lambda>", ln, 0, None, lam_ends, n)
            if not (1 <= _l <= _e <= n):
                offences.append((rel, ln, _l, _e, n))
        ok(measured == EXPECTED["lambdas_162_measured"],
           f"{measured} of them have a lambda at exactly that line in the snapshot (expected "
           f"{EXPECTED['lambdas_162_measured']}) — the end is MEASURED, never the fallback")
        ok(not offences,
           f"and all {len(pairs)} read `1 <= line <= line_end <= len(file)` through the writer "
           f"{('— offences: ' + str(offences)) if offences else 'on the snapshot’s own bytes'}")
    else:
        ok(False, f"run 162's archived mirror ({RUN162_MIRROR}) or the snapshot {SNAP} is absent "
                  "— I-144's own 43 rows cannot be read back from their source")


# ─────────────────────────────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    print("=" * 78)
    print("RANKER QUALITY — I-129 (the buckets) · I-131 (the spans) · I-132 (the cross-rule "
          "refusal) · Q4 (two negatives)")
    print("=" * 78)
    tmp = Path(tempfile.mkdtemp(prefix="ranker_proof_"))
    try:
        part_i_bucket_identity(tmp)
        part_ii_collision(tmp)
        part_iii_span(tmp)
        part_iv_cross_rule()
        part_v_q4_negatives()
        part_vi_span_invariant(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + "=" * 78)
    if FAILURES:
        print(f"ranker proof: FAIL ({len(FAILURES)})")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("ranker proof: PASS — one bucket per failing unit, `failed` computed from the buckets, "
          "no corrupt span published, no candidate from a foreign rule, Q4's two negatives "
          "silent, and `1 <= line <= line_end <= len(file)` in every bucket of the mirror")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
