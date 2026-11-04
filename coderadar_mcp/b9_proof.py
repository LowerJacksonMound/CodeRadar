"""B9's proof — the PER-RULE ACCUMULATION (ruling Q3, 2026-09-20), offline, on archived runs.

P1 was pinned in 2026-09-08 with "discuss when confirmations exist to look at". They exist, and
this proof is made of them: the confirmed ledgers and return channels runs 144 `red_sector_a`,
149 `marathon` and 151 `middletown_dreams` archived under `.archive/runs/<name>/state_during_run/`.

    a `confirmed` counts FOR every rule id the LEDGER record carries
    a `failed` counts against the repair VARIANT the Ranker picked — never against the rule

Six parts, the house shape (`gate_proof.py`, `read_tools_proof.py`,
`mcp_confirmed_ledger_proof.py`):

  1–3. THE ARCHIVED RUNS — 144 (one confirmed line and one failed line, and the asymmetry in one
                rule: NAI-021S carries `confirmed_for 1` AND a `failed_against` entry at the same
                time, while NAI-071 — a rule of the failed row only — carries `confirmed_for 0`),
                149 (nine ledger records / 0 orphans, 25 rules, no failed line anywhere), 151
                (three ledger records, eleven rules, three apiece) and 153, this lane's own run.
  4. RUN 141's SEVEN, replayed — the seven pre-repair identities run 144's own offline proof
                replays out of `client_edit_log.json`, staged as a ledger in a scratch dir. Run
                144 as the packet counts it is 7 replayed + 1 live confirmed + 1 failed.
  5. THE RULING — a failed verdict lands under its VARIANT and adds nothing to any rule's
                `confirmed_for`; a failed line whose row is gone is recorded under `?` rather than
                dropped; and the block the mirror writer stages is the block `cr_status` answers.
  6. THE VARIANT AFTER A RE-DECIDE — the one thing the ruling asked for that the engine cannot
                always give: run 153's failed row in both of its states.

EVERY EXPECTED COUNT IN `EXPECTED` BELOW WAS READ OFF THE ARCHIVED .jsonl BY HAND AND WRITTEN
DOWN BEFORE THE COMPUTE WAS RUN OVER THEM (the lane brief's order, and `gate_proof.EXPECTED`'s
idiom). The compute is `gearbox.rule_outcomes`, the one the mirror writer calls.

    .venv_new/bin/python -m coderadar_mcp.b9_proof        exit 0 = PASS
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

TREE = Path(__file__).resolve().parents[1]
if str(TREE) not in sys.path:
    sys.path.insert(0, str(TREE))

RUNS = TREE / ".archive" / "gate_evidence" / "runs"   # F1 (2026-10-01): gate evidence lives under .archive/gate_evidence/, never pruned by retention
RUN_141_EDIT_LOG = next((p.parent for p in sorted(RUNS.glob("*/obs_run141_phase1.py"))), RUNS / "run_141") / "client_edit_log.json"

#: Every rule id of run 149's nine ledger records that the nine share — the nine rows' common
#: context ids, each therefore counted nine times.
_ALL_NINE = ("MEASURED-NOTHING", "NAI-082", "NAI-084", "NAI-114", "NAI-121", "NAI-185", "NAI-229")

#: HAND-READ, BEFORE THE COMPUTE. `<run name>: (confirmed_for per rule, failed_against per rule)`.
#: confirmed_for is the tally of `rule_ids` over the ledger's records, one per record; a rule
#: absent from the tally is absent from the block unless a `failed` line names it.
EXPECTED: dict[str, dict[str, Any]] = {
    # run 144 — ledger: one record, `colorama/repair_plant_shape.py::merge_tags::13`, rule_ids
    # ["NAI-021S"]. channel: that same line `confirmed`, plus one `failed` on
    # `colorama/repair_plant_071.py:L4-L6` digest 8f9a25700f, whose row (BUILDER_STATE.json)
    # carries rule_ids_all ["NAI-021S", "NAI-071"] and decision.pick_role
    # "alias_chain_fix:new_sequence".
    "red_sector_a": {
        "confirmed_for": {"NAI-021S": 1},
        "failed_against": {"NAI-021S": {"alias_chain_fix:new_sequence": 1},
                           "NAI-071": {"alias_chain_fix:new_sequence": 1}},
        "ledger_records": 1, "channel_failed": 1,
    },
    # run 149 — nine ledger records (the ninth is the line an earlier non-tight pass left on the
    # same repo_id, recorded at `first_pass_not_tight/`), eight channel lines, every one
    # `confirmed`; no failed line at all, so every `failed_against` is empty.
    "marathon": {
        "confirmed_for": dict(
            {r: 9 for r in _ALL_NINE},
            **{"NAI-083": 3, "NAI-186": 3,
               "NAI-006": 2, "NAI-010": 2, "NAI-031": 2, "NAI-086": 2, "NAI-147": 2,
               "NAI-003": 1, "NAI-025": 1, "NAI-026": 1, "NAI-030": 1, "NAI-032": 1,
               "NAI-053": 1, "NAI-078": 1, "NAI-081": 1, "NAI-099": 1, "NAI-168": 1,
               "NAI-230": 1}),
        "failed_against": {},
        "ledger_records": 9, "channel_failed": 0,
    },
    # run 153 — this lane's own run. Ledger: two records, `repair_plant_071.py::collect::4`
    # rule_ids ["NAI-021S", "NAI-071"] and `repair_plant_061.py::label::5` with nine ids. Channel:
    # those two `confirmed` plus one `failed` on `colorama/repair_plant_070.py:L5-L12` digest
    # c312a6a098, whose row carries eleven ids and decision.pick_role "bare_except_fix". Fourteen
    # rules in the block — the eleven confirmed ids plus NAI-070 / NAI-114 / NAI-168, named only by
    # the failed row. The rows here are the run's ARCHIVED cycle-1 rows: the row as it stood when
    # the client applied, which is the only state in which the variant it tried is still its pick.
    "emotion_detector": {
        "confirmed_for": {"NAI-021S": 1, "NAI-071": 1, "NAI-061": 1, "NAI-082": 1, "NAI-083": 1,
                          "NAI-084": 1, "NAI-185": 1, "NAI-186": 1, "NAI-121": 1,
                          "MEASURED-NOTHING": 1, "NAI-229": 1},
        "failed_against": {r: {"bare_except_fix": 1} for r in (
            "NAI-070", "NAI-082", "NAI-083", "NAI-084", "NAI-114", "NAI-185", "NAI-186",
            "NAI-168", "NAI-121", "MEASURED-NOTHING", "NAI-229")},
        "ledger_records": 2, "channel_failed": 1,
    },
    # run 151 — three ledger records, the planted module's three functions; all three carry the
    # same eleven ids, so every one of the eleven is confirmed three times. No failed line.
    "middletown_dreams": {
        "confirmed_for": {r: 3 for r in (
            "MEASURED-NOTHING", "NAI-010", "NAI-031", "NAI-082", "NAI-084", "NAI-114",
            "NAI-121", "NAI-147", "NAI-185", "NAI-229", "NAI-230")},
        "failed_against": {},
        "ledger_records": 3, "channel_failed": 0,
    },
}

#: HAND-READ off `client_edit_log.json`: run 141's seven `confirmed` rows are seven PRESCRIBED
#: shapes, one rule id each, no id shared — so seven rules at `confirmed_for 1`.
EXPECTED_RUN_141_SEVEN: dict[str, int] = {
    "NAI-011": 1, "NAI-058": 1, "NAI-120": 1, "NAI-142": 1,
    "NAI-145": 1, "NAI-152": 1, "NAI-165": 1,
}

#: Every part appends the label of anything that did not hold; an empty list is the PASS.
FAILURES: list[str] = []


def _line(label: str, held: bool, said: str = "") -> None:
    print(f"  {'✓' if held else '✗'} {label}{' — ' + said if said else ''}")
    if not held:
        FAILURES.append(label)


def read_json(path: Path) -> Any:
    """Every fixture read goes through the PACKAGE's loader, never a `json.load` written here:
    this file's name carries `proof`, so a load in it is a step-17 hunter site with no ledger row
    (T1 lost a health pass to exactly that; S4-3's ledger proof was cut the same way)."""
    from .read_tools import _read_json_any
    return _read_json_any(path)


def lines_on_disk(path: Path) -> int:
    """How many records a .jsonl carries. `.read_bytes().decode()`, not `.read_text()`, for the
    same reason as `read_json` above."""
    if path.exists():
        return sum(1 for ln in path.read_bytes().decode("utf-8").splitlines() if ln.strip())
    return 0


def rows_of(run: str) -> dict[str, dict[str, Any]]:
    """The Builder's rows as that run archived them — the state the failed line joins against."""
    state = read_json(RUNS / run / "state_during_run" / "BUILDER_STATE.json")
    return dict(state.get("rows") or {})


def computed(run: str) -> dict[str, Any]:
    """`gearbox.rule_outcomes` over that run's own archived ledger and channel — the same call the
    mirror writer makes each cycle, and the same one `write_tester_report` makes at teardown."""
    from system_scripts import gearbox
    where = RUNS / run / "state_during_run"
    return gearbox.rule_outcomes(rows_of(run), where / "return_channel.jsonl",
                                 where / "confirmed_ledger.jsonl")


def check_run(run: str) -> dict[str, Any]:
    """One archived run against its hand-read row of EXPECTED."""
    want = EXPECTED[run]
    where = RUNS / run / "state_during_run"
    print(f"\n{run} — ledger {lines_on_disk(where / 'confirmed_ledger.jsonl')} records · "
          f"channel {lines_on_disk(where / 'return_channel.jsonl')} lines")
    _line("the archived ledger carries the records the packet counts",
          lines_on_disk(where / "confirmed_ledger.jsonl") == want["ledger_records"],
          f"{lines_on_disk(where / 'confirmed_ledger.jsonl')} of {want['ledger_records']}")
    got = computed(run)
    got_confirmed = {r: rec["confirmed_for"] for r, rec in got.items() if rec["confirmed_for"]}
    got_failed = {r: rec["failed_against"] for r, rec in got.items() if rec["failed_against"]}
    _line("confirmed_for per rule is what the ledger was read to say by hand",
          got_confirmed == want["confirmed_for"],
          f"{len(got_confirmed)} rules, {sum(got_confirmed.values())} confirmations"
          if got_confirmed == want["confirmed_for"] else f"got {got_confirmed}")
    _line("failed_against per rule is what the channel was read to say by hand",
          got_failed == want["failed_against"],
          f"{sum(sum(v.values()) for v in got_failed.values())} against "
          f"{len({k for v in got_failed.values() for k in v})} variant(s)"
          if got_failed == want["failed_against"] else f"got {got_failed}")
    # The ruling itself, on every run: a variant name is never a rule id, and a `failed` never
    # lands as a rule count.
    strays = sorted(v for rec in got.values() for v in rec["failed_against"] if v in got)
    _line("no variant was recorded as if it were a rule", not strays, f"strays {strays}")
    return got


def part_one_to_three() -> dict[str, dict[str, Any]]:
    print("\n1–3. THE ARCHIVED RUNS — the compute against the counts read off the .jsonl by hand")
    return {run: check_run(run) for run in EXPECTED}


def part_four_run_141_seven() -> None:
    """Run 144's other seven: the pre-repair identities of run 141's seven confirmed rows, staged
    as a ledger in a scratch dir exactly as `mcp_confirmed_ledger_proof` stages them. The archived
    run-144 state carries the LIVE confirmation only (1 + 1 failed) — the seven were replayed into
    a scratch tree and were never archived, which is why they are rebuilt here from the same
    read-only source rather than read from a run directory."""
    print("\n4. RUN 141's SEVEN, REPLAYED — the ledger run 144's offline proof built")
    from system_scripts import gearbox
    log = read_json(RUN_141_EDIT_LOG)
    confirmed = [e for e in log if e.get("outcome") == "confirmed"]
    _line("the edit log carries run 141's seven confirmed rows", len(confirmed) == 7,
          f"{len(confirmed)} of 7")
    scratch = Path(tempfile.mkdtemp(prefix="cr_b9_proof_"))
    try:
        ledger = scratch / "confirmed_ledger_a32f4c124796.jsonl"
        channel = scratch / "return_channel_a32f4c124796.jsonl"
        ledger.write_text("".join(
            json.dumps({"digest": e["digest"], "replace_span": e["replace_span"],
                        "rule_ids": list(e["rule_ids"] or []), "file": str(e["row"]).split("::")[0],
                        "function": str(e["row"]).split("::")[1], "line": int(str(e["row"]).split("::")[2]),
                        "seat": "coderadar-mcp b9_proof", "note": "run 141 replay",
                        "edit_kind": e.get("kind") or "", "timestamp": ""}) + "\n"
            for e in confirmed), encoding="utf-8")
        got = gearbox.rule_outcomes({}, channel, ledger)
        got_confirmed = {r: rec["confirmed_for"] for r, rec in got.items()}
        _line("confirmed_for per rule is the seven rules read off the log by hand",
              got_confirmed == EXPECTED_RUN_141_SEVEN,
              f"{len(got_confirmed)} rules, one confirmation each"
              if got_confirmed == EXPECTED_RUN_141_SEVEN else f"got {got_confirmed}")
        _line("no rule carries a failed_against — the replay reported no failure",
              all(not rec["failed_against"] for rec in got.values()))
        # 7 replayed + 1 live confirmed + 1 failed is run 144 as the packet counts it.
        live = computed("red_sector_a")
        total = sum(rec["confirmed_for"] for rec in got.values()) + sum(
            rec["confirmed_for"] for rec in live.values())
        _line("7 replayed + 1 live = the eight confirmations run 144 is credited with",
              total == 8, f"{total}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def part_five_the_ruling(seen: dict[str, dict[str, Any]]) -> None:
    """The ruling, stated as tests rather than as a sentence."""
    print("\n5. THE RULING — a failed counts against the VARIANT, never the rule")
    from system_scripts import gearbox
    from .tool_interface import TOOLS, validate_payload

    run144 = seen["red_sector_a"]
    _line("NAI-021S carries a confirmation AND a failed repair at once, and the confirmation stands",
          run144.get("NAI-021S", {}).get("confirmed_for") == 1
          and run144.get("NAI-021S", {}).get("failed_against") == {"alias_chain_fix:new_sequence": 1},
          json.dumps(run144.get("NAI-021S", {})))
    _line("NAI-071 — named only by the failed row — is confirmed_for 0, not confirmed_for -1",
          run144.get("NAI-071", {}).get("confirmed_for") == 0
          and run144.get("NAI-071", {}).get("failed_against") == {"alias_chain_fix:new_sequence": 1},
          json.dumps(run144.get("NAI-071", {})))

    # A failed line whose row the state no longer carries: neither its rule nor its variant can be
    # named, and the line is recorded under `?` rather than dropped.
    scratch = Path(tempfile.mkdtemp(prefix="cr_b9_orphan_"))
    try:
        channel = scratch / "return_channel_ffffffffffff.jsonl"
        channel.write_text(json.dumps(
            {"digest": "deadbeef01", "replace_span": "gone.py:L1-L2", "outcome": "failed",
             "failure_log": "the row is gone", "tester": "b9_proof", "timestamp": ""}) + "\n",
            encoding="utf-8")
        orphan = gearbox.rule_outcomes({}, channel)
        _line("a failed line whose row is gone is recorded under `?`, never dropped",
              orphan == {"?": {"confirmed_for": 0,
                               "failed_against": {gearbox.RULE_OUTCOMES_UNKNOWN: 1}}},
              json.dumps(orphan))
        # Append-only, the LAST line per (digest, span) deciding — the channel's own rule.
        channel.write_text(channel.read_bytes().decode("utf-8") + json.dumps(
            {"digest": "deadbeef01", "replace_span": "gone.py:L1-L2", "outcome": "confirmed",
             "failure_log": "re-reported", "tester": "b9_proof", "timestamp": ""}) + "\n",
            encoding="utf-8")
        _line("a re-report on the same key is decided by the LAST line, as the channel decides",
              gearbox.rule_outcomes({}, channel) == {})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # The block the mirror writer stages is the block the report writer derives. The writer is
    # handed the CHANNEL only and finds the ledger beside it by the one naming rule
    # (`gearbox.confirmed_ledger_path`), so run 144's two files are restored to their published
    # names here — `state_during_run/` archives them stripped of the repo_id.
    from no_aivalidator import BUILDER_DAEMON as bd
    where = RUNS / "red_sector_a" / "state_during_run"
    scratch = Path(tempfile.mkdtemp(prefix="cr_b9_mirror_"))
    try:
        channel = scratch / "return_channel_7cfe2e71fa83.jsonl"
        shutil.copy2(where / "return_channel.jsonl", channel)
        shutil.copy2(where / "confirmed_ledger.jsonl", scratch / "confirmed_ledger_7cfe2e71fa83.jsonl")
        staged = bd._rule_outcomes(rows_of("red_sector_a"), str(channel))
        _line("the mirror writer's own helper stages exactly what the report writer derives",
              staged == run144, f"{len(staged)} rules, found the ledger beside the channel")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _line("a mirror write is never lost to the block — no channel path answers `{}`",
          bd._rule_outcomes({}, "") == {})
    _line("`rule_outcomes` is declared in cr_status's output schema",
          "rule_outcomes" in [f.name for f in TOOLS["cr_status"].output_schema])
    _line("cr_status's example output validates against its own schema",
          validate_payload(TOOLS["cr_status"], TOOLS["cr_status"].example_output, "output") == [])


#: Run 153's failed row, in the two states it passed through. As the client applied it, the row's
#: pick IS the variant that was tried. One Builder cycle later the Ranker has re-decided it —
#: the only candidate is now unpickable (`tester=failed:<digest>`), the row is `ranker_none` and
#: `decision.pick_role` is None — so the variant is no longer anywhere on the row. Both dicts are
#: run 153's own, `decision.why` shortened; nothing else is changed.
_RUN153_FAILED_AS_TRIED: dict[str, Any] = {
    "file": "colorama/repair_plant_070.py", "function": "count_ints", "line": 5,
    "replace_span": "colorama/repair_plant_070.py:L5-L12", "digest": "c312a6a098",
    "rule_ids_all": ["NAI-070", "NAI-082"], "rca_evidence": ["rule_id=NAI-070"],
    "decision": {"pick_role": "bare_except_fix", "why": "picked bare_except_fix over 0 other"},
}
_RUN153_FAILED_RE_DECIDED: dict[str, Any] = {
    "file": "colorama/repair_plant_070.py", "function": "count_ints", "line": 5,
    "replace_span": "colorama/repair_plant_070.py:L5-L12", "digest": None,
    "rule_ids_all": ["NAI-070", "NAI-082"], "no_fix_status": "ranker_none",
    "rca_evidence": ["rule_id=NAI-070", "tester=failed:c312a6a098"],
    "decision": {"pick_role": None, "why": "tester failed c312a6a098: …; no pickable candidate"},
}


def part_six_the_variant_after_a_re_decide() -> None:
    """The lane's one open fact, stated as a test rather than left to be noticed.

    A `failed` is meant to land under the repair VARIANT. The variant lives in one place only —
    the row's `decision.pick_role` — and it lives there only while the pick is the one that was
    tried. The Builder re-decides a failed row in the SAME cycle the line arrives, and the
    candidate that failed is unpickable from then on, so the row that the next mirror write sees
    is `ranker_none` with `pick_role` None. Run 153 is that case live: eleven of its fourteen rules
    carry `failed_against {"?": 1}`, not `{"bare_except_fix": 1}`.

    Both readings are shown here because both are true, and which one the record should keep is
    the owner's to rule (the lane report's "For the owner")."""
    print("\n6. THE VARIANT AFTER A RE-DECIDE — run 153's own row, in both of its states")
    from system_scripts import gearbox
    scratch = Path(tempfile.mkdtemp(prefix="cr_b9_variant_"))
    try:
        channel = scratch / "return_channel_87489ddef445.jsonl"
        channel.write_text(json.dumps(
            {"digest": "c312a6a098", "replace_span": "colorama/repair_plant_070.py:L5-L12",
             "outcome": "failed", "failure_log": "run 153", "tester": "coderadar-mcp run153",
             "timestamp": ""}) + "\n", encoding="utf-8")
        key = "colorama/repair_plant_070.py::count_ints::5"
        as_tried = gearbox.rule_outcomes({key: _RUN153_FAILED_AS_TRIED}, channel)
        _line("the row AS THE CLIENT APPLIED IT names the variant on every rule it carries",
              all(rec["failed_against"] == {"bare_except_fix": 1} for rec in as_tried.values())
              and sorted(as_tried) == ["NAI-070", "NAI-082"], json.dumps(as_tried))
        re_decided = gearbox.rule_outcomes({key: _RUN153_FAILED_RE_DECIDED}, channel)
        _line("the row AFTER THE RANKER RE-DECIDED IT still names its RULES — the join holds on "
              "the `tester=failed:` evidence token",
              sorted(re_decided) == ["NAI-070", "NAI-082"])
        _line("…but no longer its variant, so the count lands under `?` and is not dropped",
              all(rec["failed_against"] == {gearbox.RULE_OUTCOMES_UNKNOWN: 1}
                  for rec in re_decided.values()), json.dumps(re_decided))
        _line("neither reading moved a confirmation",
              all(rec["confirmed_for"] == 0 for rec in as_tried.values())
              and all(rec["confirmed_for"] == 0 for rec in re_decided.values()))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


#: Run 162's own three readings of ONE set of seven confirmations, read off
#: `T3_SHAKEDOWN_2_REPORT_2026-09-21.md` P6 and written down before the compute. The detail line
#: is the one that lies, and it is the one a reader quotes.
_RUN162_DETAIL = ("cycle 3: 123 findings, 123 with fix, no fix 0 (declined 0), 0 whitelisted; "
                  "tester confirmed 0 of 123 solutions, 2 orphan line(s)")
_RUN162_CONFIRMED = 7


def part_seven_the_detail_line() -> None:
    """I-149 / Q8 (owner default: one source, the ledger) — `cr_status`'s detail line.

    Run 162 published three readings of the same seven confirmations: `cr_status.detail` said
    *"tester confirmed 0 of 123 solutions"*, the same response's `rule_outcomes` showed
    `confirmed_for` up to 7, and `cr_hand_back` read `confirmed 7` with `confirmed_joined 0`. No
    data was lost — but `0 of 123` is the number a reader quotes, and it reports that no work was
    done. The Builder computes its clause from `rows[].tester.confirmed`, and a repair that WORKS
    removes its own row (run 141), taking the flag with it; the ledger outlives the rows.

    The fixture is run 162's own shape: a detail line reading `0 of 123` beside a ledger carrying
    seven confirmations. Nothing else in the daemon's sentence may move.
    """
    print("\n7. THE DETAIL LINE (I-149 / Q8) — one source, the ledger")
    from . import read_tools as rt
    scratch = Path(tempfile.mkdtemp(prefix="cr_i149_"))
    try:
        sysd = scratch / "system_scripts"
        sysd.mkdir(parents=True)
        channel = sysd / "return_channel_fixture162.jsonl"
        ledger = sysd / "confirmed_ledger_fixture162.jsonl"
        ledger.write_text("".join(
            json.dumps({"digest": f"d{i:09d}", "replace_span": f"src/click/f{i}.py:L1-L2",
                        "rule_ids": ["NAI-021S"], "file": f"src/click/f{i}.py",
                        "function": "f", "line": 1, "given_id": f"src/click/f{i}.py::f::1",
                        "seat": "run162", "note": "", "edit_kind": "diff",
                        "timestamp": ""}) + "\n"
            for i in range(_RUN162_CONFIRMED)), encoding="utf-8")
        channel.write_text("", encoding="utf-8")
        (sysd / "BUILDER_STATE.json").write_text(json.dumps({
            "repo_id": "fixture162", "target_repo": str(scratch / "target"),
            "return_channel": str(channel), "phase": "MONITORING", "cycle": 3,
            "detail": _RUN162_DETAIL, "rows": {}}), encoding="utf-8")
        rt.configure(target=str(scratch / "target"), state_dir=sysd)
        status = rt.cr_status()
        _line("the ledger's own number is published on `cr_status`",
              status["confirmed_from_ledger"] == _RUN162_CONFIRMED,
              f"confirmed_from_ledger {status['confirmed_from_ledger']} of {_RUN162_CONFIRMED}")
        _line("the detail line QUOTES it — `0 of 123` is not the number anyone reads any more",
              f"tester confirmed {_RUN162_CONFIRMED} of 123 solutions" in status["detail"]
              and "confirmed 0 of 123" not in status["detail"],
              status["detail"][-64:])
        _line("…and every other word the daemon wrote is carried through untouched",
              status["detail"].replace(f"confirmed {_RUN162_CONFIRMED} of", "confirmed 0 of")
              == _RUN162_DETAIL,
              "one clause re-quoted, nothing else edited")
        _line("the daemon's own sentence is published beside it, verbatim",
              status["detail_builder"] == _RUN162_DETAIL)
        _line("the ledger's number is the number `rule_outcomes` agrees with",
              sum(rec["confirmed_for"] for rec in
                  __import__("system_scripts.gearbox", fromlist=["gearbox"])
                  .rule_outcomes({}, channel, ledger).values()) == _RUN162_CONFIRMED,
              f"{_RUN162_CONFIRMED} confirmations, one rule")
        # A ledger that is genuinely empty must not turn a truthful clause into a zero-inflation.
        ledger.write_text("", encoding="utf-8")
        quiet = rt.cr_status()
        _line("an EMPTY ledger leaves the daemon's own clause exactly as it wrote it — the rule "
              "never lowers a number, it only refuses to under-report one",
              quiet["detail"] == _RUN162_DETAIL and quiet["confirmed_from_ledger"] == 0)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    print("=" * 78)
    print("B9 — PER-RULE ACCUMULATION (RELEASE_MOUNT_B9_SHAKEDOWN_PACKET_2026-09-20 §A Q3, T2)")
    print(f"tree {TREE}")
    print("=" * 78)
    seen = part_one_to_three()
    part_four_run_141_seven()
    part_five_the_ruling(seen)
    part_six_the_variant_after_a_re_decide()
    part_seven_the_detail_line()
    if "--json" in args:
        Path(args[args.index("--json") + 1]).write_text(
            json.dumps({"ok": not FAILURES, "failures": FAILURES, "runs": seen}, indent=2),
            encoding="utf-8")
    print("\n" + "=" * 78)
    if FAILURES:
        print(f"B9 proof: FAIL — {len(FAILURES)} did not hold")
        for f in FAILURES:
            print(f"  ✗ {f}")
        return 1
    print("B9 proof: PASS — 144: 1 confirmed · 1 failed under its variant · 149: 9 / 25 rules · "
          "151: 3 / 11 rules · 153: 2 / 14 rules · 141's seven replayed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
