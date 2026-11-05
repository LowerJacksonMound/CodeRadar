#!/usr/bin/env python3
"""RUN 144 — red_sector_a (copy1): the confirmed ledger, live.

One client edit, one `confirmed`, one `failed`, one Builder cycle, then the teardown and the
hand-back. What run 144 has to show: `confirmed 1` carried by the LEDGER (the repaired row is
gone, so the channel joins nothing), `failed 1` JOINED the ordinary way, `orphans 0`.
"""
from __future__ import annotations

import ast
import json
import sys
import time
from pathlib import Path

RUN_DIR = Path(__file__).resolve().parent
TREE = RUN_DIR.parents[2]
sys.path.insert(0, str(TREE))

TARGET = Path("/Users/dev/Desktop/red_sector_a")
SCRIPTS = TREE / "system_scripts"

from coderadar_mcp import read_tools, session_tools, write_tools  # noqa: E402


def save(name: str, doc: object) -> None:
    (RUN_DIR / name).write_text(json.dumps(doc, indent=2, default=str) + "\n", encoding="utf-8")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def say(*bits: object) -> None:
    print(*bits, flush=True)


def wait_for_cycle(at_least: int, limit_s: float) -> int:
    t0 = time.monotonic()
    seen = -1
    while time.monotonic() - t0 < limit_s:
        state = load(SCRIPTS / "BUILDER_STATE.json")
        seen = int(state.get("cycle") or 0)
        if seen >= at_least:
            return seen
        time.sleep(5.0)
    return seen


def main() -> int:
    say("=" * 78)
    say("RUN 144 — red_sector_a — the confirmed ledger, live")
    say("=" * 78)

    say("\n[1] cr_watch")
    watch = session_tools.cr_watch(str(TARGET))
    save("phase1_watch.json", watch)
    say(f"  started {watch['started']} · phase {watch['phase']} · repo_id {watch['repo_id']} "
        f"· budget {watch['gate_budget_s']}s")
    for g in watch["gates"]:
        say(f"    gate {g}")
    if not watch["started"]:
        say(f"  ABORT: {watch['error']}")
        return 1

    say("\n[2] cr_status")
    status = read_tools.cr_status()
    save("phase2_status.json", status)
    say(f"  cycle {status.get('cycle')} · finished {status.get('finished')} "
        f"· {status.get('finished_reason')}")
    say(f"  infractions {status.get('infractions')}")

    mirror = load(SCRIPTS / ".noai_state.json")
    rewriters = [r for r in mirror["repairs"] if r.get("solution_kind") == "rewriter"]
    rewriters.sort(key=lambda r: (len(r.get("rule_ids") or []), r.get("file") or ""))
    picked = rewriters[0]
    rid = f"{picked['file']}::{picked.get('function') or ''}::{picked['line']}"
    say(f"\n[3] the row the client will repair: {rid}")
    say(f"    rules {picked['rule_ids']} · role {picked.get('selected_role')} "
        f"· digest {picked['digest']} · span {picked['replace_span']}")

    payload = write_tools.cr_apply(rid)
    save("phase3_apply.json", payload)
    say(f"    cr_apply kind={payload['kind']} applies_cleanly={payload['applies_cleanly']}")
    say("    ---- the diff the server rendered (the client writes the bytes, Q3) ----")
    for ln in (payload["diff"] or "").splitlines():
        say(f"    {ln}")

    file_path = TARGET / picked["file"]
    span = picked["replace_span"]
    first = int(span.rsplit(":L", 1)[1].split("-L")[0])
    last = int(span.rsplit("-L", 1)[1])
    src = file_path.read_text(encoding="utf-8")
    lines = src.splitlines()
    lines[first - 1:last] = picked["after_code"].splitlines()
    fixed = "\n".join(lines) + "\n"
    ast.parse(fixed)
    file_path.write_text(fixed, encoding="utf-8")
    say(f"    CLIENT EDIT written: {picked['file']} lines {first}-{last} · ast.parse ok")

    say("\n[4] cr_report_outcome(confirmed) on the row just repaired — inside the cycle")
    ok = write_tools.cr_report_outcome(
        rid, "confirmed", "run 144: applied the rewriter diff; the function is repaired",
        "coderadar-mcp run144", "diff")
    save("phase4_confirmed.json", ok)
    say(f"    written {ok['written']} · bytes {ok['bytes_appended']}")
    say(f"    ledger_written {ok['ledger_written']} → {ok['ledger']}")
    say(f"    ledger record {json.dumps(ok['ledger_record'])}")

    others = [r for r in mirror["repairs"] if r["file"] != picked["file"]]
    unapplied = others[0]
    fid = f"{unapplied['file']}::{unapplied.get('function') or ''}::{unapplied['line']}"
    say(f"\n[5] cr_report_outcome(failed) on an UNAPPLIED row: {fid}")
    bad = write_tools.cr_report_outcome(
        fid, "failed", "run 144: not applied; reported failed so the Ranker re-decides",
        "coderadar-mcp run144")
    save("phase5_failed.json", bad)
    say(f"    written {bad['written']} · ledger_written {bad['ledger_written']} "
        f"· ledger {bad['ledger']!r} · record {bad['ledger_record']}")

    say("\n[6] one Builder cycle")
    cycle_now = int(load(SCRIPTS / "BUILDER_STATE.json").get("cycle") or 0)
    reached = wait_for_cycle(cycle_now + 2, 900.0)
    state = load(SCRIPTS / "BUILDER_STATE.json")
    rows = state.get("rows") or {}
    say(f"    cycle {cycle_now} → {reached} · rows {len(rows)}")
    say(f"    the repaired row is still in the mirror: {rid in rows}")
    say(f"    summary.tester {json.dumps((state.get('summary') or {}).get('tester'))}")
    failed_row = rows.get(fid) or {}
    save("phase6_redecide.json", {"repaired_row_present": rid in rows, "failed_row": failed_row,
                                  "summary": state.get("summary")})
    say(f"    the failed row's evidence: {failed_row.get('rca_evidence')}")

    say("\n[7] cr_stop with the client's manifest")
    stop = session_tools.cr_stop(expected_changes=[picked["file"]])
    save("phase7_stop.json", stop)
    say(f"    stopped {stop['stopped']} · residue_clean {stop['residue_clean']} "
        f"· byte_identical {stop['byte_identical']} · files {stop['files_compared']}")
    say(f"    client_edits {stop['client_edits']} · unexpected_changes {stop['unexpected_changes']}")
    for d in stop["daemons_exited"]:
        say(f"      {d}")

    say("\n[8] cr_hand_back — AFTER cr_stop (T4 decision 3)")
    back = session_tools.cr_hand_back("run 144: the confirmed ledger, live")
    save("phase8_hand_back.json", back)
    say(f"    report {back['report_path']}")
    say(f"    builder_cycles {back['builder_cycles']} · infractions {back['infractions']} "
        f"· solutions {back['solutions']}")
    say(f"    confirmed {back['confirmed']} (joined {back['confirmed_joined']} "
        f"· from_ledger {back['confirmed_from_ledger']}) · orphans {back['orphans']} "
        f"(channel {back['orphans_channel']}) · unparsed {back['unparsed']}")
    say(f"    confirmed_fraction {back['confirmed_fraction']} · tester_ran {back['tester_ran']} "
        f"· channel_lines {back['return_channel_lines']}")
    say(f"    ledger {back['confirmed_ledger']}")
    for rec in back["confirmed_ledger_rows"]:
        say(f"      ledger row: {json.dumps(rec)}")

    want = (back["confirmed"] == 1 and back["confirmed_from_ledger"] == 1
            and back["orphans"] == 0 and stop["client_edits"] == 1
            and stop["unexpected_changes"] == [] and stop["residue_clean"])
    say("\n" + ("RUN 144 PASS — confirmed 1 (from ledger) · failed 1 (joined) · orphans 0"
                if want else "RUN 144 — NOT the shape asked for; read the phases above"))
    return 0 if want else 1


if __name__ == "__main__":
    sys.exit(main())
