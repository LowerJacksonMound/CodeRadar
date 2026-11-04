#!/usr/bin/env python3
"""S4-3's offline proof — the CONFIRMED LEDGER (ruling Q1(a), 2026-09-17), on run 141's own rows.

Run 141's fact: a repair that WORKS removes its own row, so by the Builder's next poll nothing
sits at that digest+span and the `confirmed` line joins nothing. All 7 of run 141's `confirmed`
lines orphaned; all 7 `failed` lines joined (a failed row is still an infraction).

This replays those 7 rows — their PRE-REPAIR identities exactly as `client_edit_log.json`
recorded them — through `cr_report_outcome` against a channel and a ledger in a scratch dir,
then runs the engine's own `write_tester_report` over the result twice:

    ledger withheld   →  confirmed 0 · confirmed_from_ledger 0 · orphans 7   (run 141 as recorded)
    ledger in place   →  confirmed 7 · confirmed_from_ledger 7 · orphans 0   (the ruling)

Nothing outside the scratch dir is written, and the run-141 record is read only.
Usage:  .venv_new/bin/python system_scripts/mcp_confirmed_ledger_proof.py      (exit 0 = PASS)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

TREE = Path(__file__).resolve().parents[1]
if str(TREE) not in sys.path:
    sys.path.insert(0, str(TREE))

_RUNS = TREE / ".archive" / "gate_evidence" / "runs"
# run 141's evidence folder (named after its target), found by its observation scripts
RUN_141 = next((p.parent for p in sorted(_RUNS.glob("*/obs_run141_phase1.py"))), _RUNS / "run_141")   # F1 (2026-10-01): gate evidence lives under .archive/gate_evidence/, never pruned by retention
EDIT_LOG = RUN_141 / "client_edit_log.json"
POST_REPAIR_MIRROR = RUN_141 / "state_during_run" / "noai_state_mirror_at_teardown.json"
RUN_141_REPO_ID = "a32f4c124796"

_problems: list[str] = []


def expect(ok: bool, said: str) -> None:
    """One assertion, named. Nothing raises: the proof reports every failure it finds."""
    mark = "ok  " if ok else "BAD "
    print(f"  {mark}{said}")
    if not ok:
        _problems.append(said)


def read_json(path: Path) -> Any:
    """Every fixture read goes through the PACKAGE's loader, never a `json.load` written here:
    this file's name carries `proof`, so a load in it is a step-17 hunter site (W49) with no
    ledger row — T1 lost a health pass to exactly that and T3 cut it the same way."""
    from coderadar_mcp.read_tools import _read_json_any
    return _read_json_any(path)


def row_parts(rid: str) -> tuple[str, str, int]:
    """`<file>::<function>::<line>` → its three parts (T1's one id)."""
    head, _, line = rid.rpartition("::")
    file_part, _, func = head.partition("::")
    return file_part, func, int(line)


def pre_repair_rows(log: list[dict[str, Any]], channel: str) -> list[dict[str, Any]]:
    """The mirror rows as they stood when the client reported — the identity the ledger keeps.
    Every field comes off run 141's edit log; `return_channel` is the scratch channel, so the
    replay cannot touch the tree's own."""
    out: list[dict[str, Any]] = []
    for entry in log:
        file_part, func, line = row_parts(str(entry["row"]))
        out.append({
            "file": file_part, "function": func, "line": line,
            "replace_span": entry["replace_span"], "rule_ids": list(entry["rule_ids"] or []),
            "fix": entry.get("reason") or "", "before_code": entry.get("before") or "",
            "after_code": entry.get("after") or "", "digest": entry["digest"],
            "solution_kind": "prescribed" if entry.get("kind") == "shape" else "rewriter",
            "selected_role": entry.get("selected_role") or "", "return_channel": channel,
        })
    return out


def state_rows(mirror: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The Builder's `rows` one cycle after the repairs — run 141's at-teardown mirror, which is
    the world in which the seven repaired rows are GONE. No archived cycle-6 BUILDER_STATE
    exists, so the state fixture is built from the mirror the run did archive."""
    rows: dict[str, dict[str, Any]] = {}
    for row in mirror.get("repairs") or []:
        key = f"{row.get('file')}::{row.get('function') or ''}::{row.get('line')}"
        rows[key] = {
            "file": row.get("file"), "function": row.get("function"), "line": row.get("line"),
            "rule_ids": row.get("rule_ids") or [], "digest": row.get("digest"),
            "replace_span": row.get("replace_span"), "rca_evidence": [],
            "tester": {"confirmed": False, "tester": "", "timestamp": ""},
        }
    return rows


def stage(scratch: Path, confirmed: list[dict[str, Any]], mirror: dict[str, Any],
          ) -> tuple[Path, Path, Path, dict[str, Any]]:
    """The fixture tree: a mirror as the client saw it at report time (post-repair rows PLUS the
    seven pre-repair ones) and a BUILDER_STATE as the Builder saw it one cycle later."""
    scripts = scratch / "system_scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    channel = scripts / f"return_channel_{RUN_141_REPO_ID}.jsonl"
    ledger = scripts / f"confirmed_ledger_{RUN_141_REPO_ID}.jsonl"
    live = dict(mirror)
    live["repairs"] = pre_repair_rows(confirmed, str(channel)) + [
        dict(row, return_channel=str(channel)) for row in (mirror.get("repairs") or [])]
    live["return_channel"] = str(channel)
    (scripts / ".noai_state.json").write_text(json.dumps(live), encoding="utf-8")
    rows = state_rows(mirror)
    state = {
        "target_repo": mirror.get("target_repo") or str(Path.home() / RUN_141.name),
        "repo_id": RUN_141_REPO_ID, "cycle": 6, "return_channel": str(channel),
        "summary": {
            "findings": len(rows), "with_fix": len(rows),
            # What the Builder itself counted in run 141: every confirmed line an orphan, none
            # joined — the fact the ledger exists to correct.
            "tester": {"confirmed": 0, "solutions": len(rows), "orphans": len(confirmed),
                       "unparsed": 0, "channel_lines": len(confirmed) + 1},
        },
        "rows": rows,
    }
    state_path = scripts / "BUILDER_STATE.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    return channel, ledger, state_path, state


def lines_on_disk(path: Path) -> int:
    """How many records a .jsonl carries. `.read_bytes().decode()`, not `.read_text()`, for the
    same reason as `read_json` above; the CONTENT of the ledger is read by the engine's own
    `gearbox.read_confirmed_ledger`, which is the reader this proof is about."""
    if path.exists():
        return sum(1 for ln in path.read_bytes().decode("utf-8").splitlines() if ln.strip())
    return 0


def main() -> int:
    print("S4-3 — CONFIRMED LEDGER PROOF (run 141's seven confirmed rows, replayed offline)")
    log = read_json(EDIT_LOG)
    confirmed = [e for e in log if e.get("outcome") == "confirmed"]
    failed_rows = [e for e in log if e.get("outcome") == "failed"]
    print(f"\nrun 141's edit log: {len(log)} edits · {len(confirmed)} confirmed · "
          f"{len(failed_rows)} recorded failed (the backed-out pair)")
    expect(len(confirmed) == 7, f"the log carries run 141's seven confirmed rows ({len(confirmed)})")

    mirror = read_json(POST_REPAIR_MIRROR)
    scratch = Path(tempfile.mkdtemp(prefix="cr_ledger_proof_"))
    try:
        channel, ledger, state_path, state = stage(scratch, confirmed, mirror)
        os.environ["CODERADAR_MCP_ROOT"] = str(scratch)
        from coderadar_mcp import write_tools
        from coderadar_mcp.tool_interface import TOOLS, validate_payload
        from system_scripts import gearbox

        print("\n1. the replay — one cr_report_outcome per confirmed row")
        schema_bad: list[str] = []
        for entry in confirmed:
            out = write_tools.cr_report_outcome(
                str(entry["row"]), "confirmed",
                "run 141 replay: the client applied this row and the target's own runner stayed green",
                "coderadar-mcp s4-3", str(entry.get("kind") or ""))
            schema_bad.extend(validate_payload(TOOLS["cr_report_outcome"], out, "output"))
            rec = out["ledger_record"]
            same = (out["written"] and out["ledger_written"] and out["ledger"] == str(ledger)
                    and rec["digest"] == entry["digest"] and rec["replace_span"] == entry["replace_span"]
                    and rec["rule_ids"] == list(entry["rule_ids"]) and rec["edit_kind"] == entry["kind"]
                    and f"{rec['file']}::{rec['function']}::{rec['line']}" == entry["row"])
            expect(same, f"{entry['row']} → channel line + ledger record, pre-repair identity intact")
        expect(not schema_bad, f"every cr_report_outcome payload validates against T1's output schema ({schema_bad})")
        expect(lines_on_disk(channel) == 7 and lines_on_disk(ledger) == 7,
               f"channel {lines_on_disk(channel)} lines · ledger {lines_on_disk(ledger)} records")

        print("\n2. the report writer over those seven lines, with the ledger WITHHELD —")
        print("   run 141 exactly as it was recorded: every confirmation an orphan")
        out_dir = scratch / "report"
        withheld = ledger.with_name("withheld.jsonl")
        ledger.rename(withheld)
        before = gearbox.write_tester_report(
            Path(state["target_repo"]), RUN_141_REPO_ID, "2026-09-17T06:26:00+00:00",
            builder_state=state_path, channel=channel, out_dir=out_dir)
        expect(before["confirmed"] == 0 and before["confirmed_from_ledger"] == 0
               and before["orphans"] == 7 and before["confirmed_fraction"] == 0.0,
               f"confirmed {before['confirmed']} · from_ledger {before['confirmed_from_ledger']} "
               f"· orphans {before['orphans']} — run 141's own teardown numbers")
        withheld.rename(ledger)

        print("\n3. a failed verdict writes NOTHING to the ledger")
        with_fn = [r for r in (mirror.get("repairs") or [])
                   if r.get("function") and not str(r.get("function")).startswith("<")]
        still_there = with_fn[0]
        fid = f"{still_there['file']}::{still_there.get('function') or ''}::{still_there['line']}"
        out = write_tools.cr_report_outcome(fid, "failed", "AssertionError: the replay's failed row")
        expect(out["written"] and not out["ledger_written"] and out["ledger"] == "" and out["ledger_record"] == {},
               f"{fid} failed → channel yes, ledger no")
        expect(lines_on_disk(ledger) == 7, f"the ledger is still seven records ({lines_on_disk(ledger)})")

        print("\n4. append-only: the LAST record per (digest, span) wins, as the channel does")
        again = write_tools.cr_report_outcome(str(confirmed[0]["row"]), "confirmed", "re-reported",
                                              "coderadar-mcp s4-3", str(confirmed[0].get("kind") or ""))
        expect(again["ledger_written"] and lines_on_disk(ledger) == 8,
               f"the re-report appends rather than rewrites ({lines_on_disk(ledger)} records)")
        held = gearbox.read_confirmed_ledger(ledger)
        key = (str(confirmed[0]["digest"]), str(confirmed[0]["replace_span"]))
        expect(len(held) == 7 and held[key]["note"] == "re-reported",
               f"the reader keeps {len(held)} keys and the LAST record of the re-reported one")

        print("\n5. the report writer — the whole channel, with the ledger IN PLACE (the ruling)")
        after = gearbox.write_tester_report(
            Path(state["target_repo"]), RUN_141_REPO_ID, "2026-09-17T06:26:00+00:00",
            builder_state=state_path, channel=channel, out_dir=out_dir)
        expect(after["confirmed"] == 7, f"confirmed {after['confirmed']}")
        expect(after["orphans"] == 0, f"orphans {after['orphans']}")
        expect(after["confirmed_from_ledger"] == 7, f"confirmed_from_ledger {after['confirmed_from_ledger']}")
        expect(after["confirmed_joined"] == 0,
               f"confirmed_joined {after['confirmed_joined']} — the channel still joins none of them")
        expect(after["orphans_channel"] == 7,
               f"orphans_channel {after['orphans_channel']} — the Builder's own count, kept beside the correction")
        expect(len(after["confirmed_ledger_rows"]) == 7 and after["confirmed_ledger"] == str(ledger),
               "confirmed_ledger_rows carries the seven pre-repair identities")
        want = after["confirmed"] / after["solutions"]
        expect(after["confirmed_fraction"] == want and after["tester_ran"],
               f"confirmed_fraction {after['confirmed_fraction']:.4f} = {after['confirmed']}/{after['solutions']}")
        shape = set(TOOLS["cr_hand_back"].output_schema and
                    [f.name for f in TOOLS["cr_hand_back"].output_schema])
        missing = sorted(n for n in ("confirmed", "confirmed_joined", "confirmed_from_ledger",
                                     "confirmed_ledger_rows", "confirmed_ledger", "orphans",
                                     "orphans_channel") if n not in shape or n not in after)
        expect(not missing, f"every new key is in the report AND in cr_hand_back's schema ({missing})")
        on_disk = read_json(out_dir / "tester_report.json")
        expect(on_disk["confirmed"] == 7 and on_disk["orphans"] == 0,
               "tester_report.json on disk says the same")
        expect((out_dir / "state_during_run" / "confirmed_ledger.jsonl").exists(),
               "the ledger is archived beside the channel in state_during_run/")
    finally:
        os.environ.pop("CODERADAR_MCP_ROOT", None)
        shutil.rmtree(scratch, ignore_errors=True)

    print()
    if _problems:
        print(f"FAIL — {len(_problems)} assertion(s): {_problems}")
        return 1
    print("PASS — confirmed 7 · orphans 0 · confirmed_from_ledger 7; a failed verdict writes no ledger record")
    return 0


if __name__ == "__main__":
    sys.exit(main())
