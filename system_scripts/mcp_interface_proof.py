#!/usr/bin/env python3
"""T1 interface proof — the MCP tool surface of RELEASE_FORM_MCP_PACKET_2026-09-17 §B
(release form, session 3, 2026-09-17; FIX_43b's interface-first pattern: the interface is
proven in the original, serially, BEFORE T2/T3/T4 touch anything).

Part 1 (the surface) — every tool of §B has a name, an input schema, an output schema, a
source of record and a one-line contract; §B's 11 rows are covered exactly once; the tools that
write a file are exactly the six that do (`cr_watch`, `cr_stop`, `cr_hand_back`, `cr_apply`,
`cr_run_module`, `cr_report_outcome` — A3 2026-10-01, Q-H4-10), each naming its files, none of
them the target's code, and the ONE that records a verdict (return channel + confirmed ledger) is
`cr_report_outcome` (Q3); T1 registers no handler; and the three lanes' OWNED sets partition the
surface, so T2/T3/T4 cannot collide in a file.

Part 2 (the payloads) — every tool's example input and example output validate against its own
schema, and the validator refuses an unknown key, a wrong type and a word outside an enum. The
schema is the whole contract, not a prefix of it.

Part 3 (the return channel) — the round trip that matters. A `cr_report_outcome` record is
built by `tool_interface.return_channel_line`, appended to a real `.jsonl`, read back the way
`BuilderDaemon._poll_channel` reads it (from an offset, up to the last newline), and handed to
the ENGINE's OWN `_parse_channel_line`, `_join_channel` and `_tester_field`. The join is on
`digest` AND `replace_span`; a `failed` line lands in `failed`, a `confirmed` line on the
row's current digest lands in `confirmed`, and a half-written line is left for the next poll.
If the engine cannot be imported the part falls back to the recorded key contract and says so.

Part 4 (the vocabulary the rulings fixed) — outcomes are exactly {confirmed, failed} (the
run-53 ruling — no `refuted`, no `unmeasured`); edge states are exactly {possible, live,
severed} (Q7, `possible` is the new word for indigo); the default page is 50 rows (Q9); and a
prescription's `<placeholders>` are read off the shape the app really published (I-75).

    .venv_new/bin/python3 system_scripts/mcp_interface_proof.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from coderadar_mcp import tool_interface as ti  # noqa: E402

#: Two REAL repair rows, copied field-for-field out of run 136
#: (`.archive/runs/<run 136 target>/state_during_run/noai_state_mirror.json` → `repairs[0:2]`).
#: They are recorded here rather than loaded: this file's name matches the pre-ranker hunter's
#: rule-code pattern, so a data-file read inside it would be a hunter site with no ledger row
#: (health step 17). The values below are the mirror's, verbatim.
RUN136_ROWS: tuple[dict, ...] = (
    {"file": "colorama/repair_plant_071.py", "function": "collect", "line": 4,
     "replace_span": "colorama/repair_plant_071.py:L4-L6", "digest": "8f9a25700f",
     "solution_kind": "rewriter"},
    {"file": "colorama/repair_plant_061.py", "function": "label", "line": 5,
     "replace_span": "colorama/repair_plant_061.py:L5-L8", "digest": "2da1222e69",
     "solution_kind": "rewriter"},
)

#: A REAL prescribed shape from the same mirror — the `<placeholder>` form of I-75.
RUN136_SHAPE = "from <real.package.module> import <names actually used>"


# ─────────────────────────────────────────────────────────────────────────────


def part_1_surface() -> list[str]:
    problems: list[str] = []
    print(f"  tools: {len(ti.TOOLS)} names over {len(ti.PACKET_ROWS)} packet rows")
    # §B's 11 rows + the solution gate's `cr_submit` (owner 2026-10-08, M-132) = 12 (last plan 1b, 2026-10-10).
    if len(ti.PACKET_ROWS) != 12:
        problems.append(f"§B has 11 rows + cr_submit = 12, the interface covers {len(ti.PACKET_ROWS)}")
    for name, spec in ti.TOOLS.items():
        if spec.name != name:
            problems.append(f"{name}: registered under a different name ({spec.name})")
        if not spec.contract.strip():
            problems.append(f"{name}: no contract")
        if not spec.source_of_record.strip():
            problems.append(f"{name}: no source of record")
        if not spec.output_schema:
            problems.append(f"{name}: no output schema")
        if not spec.packet_row.strip():
            problems.append(f"{name}: not tied to a §B row")
        for f in tuple(spec.input_schema) + tuple(spec.output_schema):
            if not f.doc.strip():
                problems.append(f"{name}.{f.name}: no doc")
            if f.base_type not in ti._PY_TYPES:
                problems.append(f"{name}.{f.name}: unknown type {f.type!r}")
        print(f"    {name:<20} in {len(spec.input_schema):>2}  out {len(spec.output_schema):>2}  "
              f"{'WRITES' if spec.writes else 'reads '}  {spec.source_of_record.split(';')[0][:58]}")

    # A3 (2026-10-01, Q-H4-10): the gate names the REAL writing set, not one tool. `writes` is the
    # tuple of files each handler writes (session_tools/write_tools, grep'd by enclosing function);
    # the read tools carry `()`. Q3's standing rule is kept as its own check: the only tool that
    # records a verdict — the return channel and the confirmed ledger — is cr_report_outcome.
    expected_writers = ["cr_apply", "cr_hand_back", "cr_report_outcome", "cr_run_module", "cr_stop", "cr_submit",
                        "cr_watch"]   # cr_submit writes attempts_<repo_id>.jsonl (solution gate, owner 2026-10-08)
    writers = sorted(n for n, s in ti.TOOLS.items() if s.writes)
    if writers != expected_writers:
        problems.append(f"the writing tools must be exactly {expected_writers}; these do: {writers}")
    for name, spec in ti.TOOLS.items():
        if not isinstance(spec.writes, tuple) or not all(isinstance(w, str) and w for w in spec.writes):
            problems.append(f"{name}.writes must be a tuple of file names, got {spec.writes!r}")
    verdict_writers = sorted(n for n, s in ti.TOOLS.items()
                             if any("return_channel" in w or "confirmed_ledger" in w for w in s.writes))
    if verdict_writers != ["cr_report_outcome"]:
        problems.append(f"exactly one tool records a verdict (Q3); these name the channel/ledger: {verdict_writers}")
    if writers == expected_writers and verdict_writers == ["cr_report_outcome"]:
        print(f"    {len(writers)} tools write, all in CodeRadar's own tree: {', '.join(writers)}")
        for name in writers:
            for w in ti.TOOLS[name].writes:
                print(f"      {name:<18} {w}")
        print("    the one verdict writer (return channel + confirmed ledger): cr_report_outcome")

    if ti.HANDLERS:
        problems.append(f"T1 registers no handler; found {sorted(ti.HANDLERS)}")

    from coderadar_mcp import read_tools, session_tools, write_tools
    lanes = {"T2 read_tools": set(read_tools.OWNED),
             "T3 write_tools": set(write_tools.OWNED),
             "T4 session_tools": set(session_tools.OWNED)}
    union: set[str] = set()
    for a, owned in lanes.items():
        for b, other in lanes.items():
            if a < b and owned & other:
                problems.append(f"{a} and {b} both claim {sorted(owned & other)}")
        union |= owned
    if union != set(ti.TOOLS):
        problems.append(f"lanes do not partition the surface; unclaimed={sorted(set(ti.TOOLS) - union)}, "
                        f"unknown={sorted(union - set(ti.TOOLS))}")
    else:
        print(f"    lanes partition the surface: " +
              ", ".join(f"{a.split()[0]}={len(o)}" for a, o in lanes.items()))
    return problems


def part_2_payloads() -> list[str]:
    problems: list[str] = []
    for name, spec in ti.TOOLS.items():
        for which, payload in (("input", spec.example_input), ("output", spec.example_output)):
            if which == "output" and not payload:
                problems.append(f"{name}: no example output to validate")
                continue
            bad = ti.validate_payload(spec, payload, which)
            problems += bad
    print(f"  {len(ti.TOOLS)} example inputs + {len(ti.TOOLS)} example outputs validated")

    # The validator must refuse, or it is proving nothing.
    spec = ti.tool("cr_report_outcome")
    negatives = (
        ("unknown key", {"row": "a::b::1", "outcome": "failed", "nope": 1}),
        ("missing required", {"outcome": "failed"}),
        ("wrong type", {"row": 4, "outcome": "failed"}),
        ("word outside the enum", {"row": "a::b::1", "outcome": "refuted"}),
        ("bool where int is wanted", {"row": "a::b::1", "outcome": "failed", "note": True}),
    )
    for label, payload in negatives:
        if not ti.validate_payload(spec, payload, "input"):
            problems.append(f"validator accepted a payload it must refuse: {label}")
    print(f"  validator refused all {len(negatives)} bad payloads")
    return problems




def part_3_return_channel() -> list[str]:
    problems: list[str] = []
    row, row_b = RUN136_ROWS
    for r in (row, row_b):
        print(f"  run-136 row: {r['replace_span']} digest={r['digest']}")

    expected = {f.name for f in ti.RETURN_CHANNEL_RECORD}
    line = ti.return_channel_line(row, "failed", note="AssertionError: collect() returned an alias",
                                  tester="mcp-interface-proof")
    if set(line.as_dict()) != expected:
        problems.append(f"the record's keys drifted: {sorted(set(line.as_dict()) ^ expected)}")
    if not line.as_line().endswith("\n"):
        problems.append("the line must be newline-terminated — the reader only takes bytes up to the last \\n")
    for bad_outcome in ("refuted", "unmeasured", "FAILED", ""):
        try:
            ti.return_channel_line(row, bad_outcome)
        except ValueError:
            continue
        problems.append(f"return_channel_line accepted outcome {bad_outcome!r}")

    try:
        from no_aivalidator import BUILDER_DAEMON as bd
    except Exception as e:                                     # pragma: no cover - offline fallback
        print(f"  engine not importable ({type(e).__name__}) — checking the key contract only")
        doc = line.as_dict()
        for key in ("digest", "replace_span", "outcome", "failure_log", "tester", "timestamp"):
            if key not in doc:
                problems.append(f"return channel record is missing {key!r}")
        if doc["outcome"] not in ti.OUTCOMES:
            problems.append("outcome is not one of the two words the reader parses")
        return problems

    print("  reader: no_aivalidator.BUILDER_DAEMON._parse_channel_line / _join_channel / _tester_field")
    confirmed_line = ti.return_channel_line(row_b, "confirmed", tester="mcp-interface-proof")

    with tempfile.TemporaryDirectory() as td:
        channel = Path(td) / f"return_channel_{'0' * 12}.jsonl"
        channel.write_text(line.as_line() + confirmed_line.as_line() + '{"digest": "half-writt')

        # exactly what _poll_channel does: read from the offset, stop at the last newline
        raw = channel.read_bytes()
        cut = raw.rfind(b"\n")
        text = raw[:cut + 1].decode("utf-8")
        tail = raw[cut + 1:]
        if not tail:
            problems.append("the half-written line was consumed; _poll_channel must leave it for the next poll")

        def read_one(raw_line: str) -> dict:
            """The engine's parser, with `None` turned into a loud failure — a line this
            interface produced must always be the contract."""
            got = bd._parse_channel_line(raw_line)
            if got is None:
                raise AssertionError(f"the engine's own parser rejected a line we wrote: {raw_line!r}")
            return got

        try:
            parsed = [read_one(x) for x in text.splitlines() if x.strip()]
        except AssertionError as e:
            problems.append(str(e))
            return problems
        print(f"  {len(parsed)} line(s) parsed by the engine, 1 partial line left on disk")

        def engine_row(r: dict) -> dict:
            return {"row_key": ti.row_id(r), "file": r["file"], "function": r.get("function", ""),
                    "line": r["line"], "replace_span": r["replace_span"],
                    "digest": r["digest"], "rca_evidence": []}

        rows = {ti.row_id(r): engine_row(r) for r in (row, row_b)}
        failed, confirmed, orphans = bd._join_channel(parsed, rows)

        key, key_b = ti.row_id(row), ti.row_id(row_b)
        if key not in failed:
            problems.append("the failed line did not join to its row on digest + replace_span")
        elif failed[key][0]["digest"] != row["digest"]:
            problems.append("the failed entry carries the wrong digest")
        if key_b not in confirmed:
            problems.append("the confirmed line did not join to its row's CURRENT digest")
        if orphans:
            problems.append(f"{orphans} line(s) matched no row — the join key is wrong")
        else:
            print(f"  joined: failed={len(failed)} confirmed={len(confirmed)} orphans={orphans}")

        tf = bd._tester_field(row_b["digest"], confirmed.get(key_b))
        if tf != {"confirmed": True, "tester": "mcp-interface-proof", "timestamp": confirmed[key_b]["timestamp"]}:
            problems.append(f"rows[].tester is not what the engine builds: {tf}")
        else:
            print(f"  rows[].tester = {json.dumps(tf)}")

        # THE LAST LINE PER DIGEST WINS (`_join_channel` keeps `matching[-1]`). A client that
        # reports twice on one digest supersedes itself — this is the contract, not a bug.
        again = ti.return_channel_line(row, "confirmed", tester="mcp-interface-proof")
        f3, c3, _ = bd._join_channel(parsed + [read_one(again.as_line())], rows)
        if key in f3 or key not in c3:
            problems.append("a later line on the same digest did not supersede the earlier one")
        else:
            print("  a later line on the same digest supersedes the earlier one")

        # a line whose span does not match must NOT join — it is an orphan, counted, never applied
        wrong = ti.ReturnChannelLine(digest=row["digest"], replace_span="other/file.py:L1-L2",
                                     outcome="failed")
        f2, c2, o2 = bd._join_channel([read_one(wrong.as_line())], rows)
        if f2 or c2 or o2 != 1:
            problems.append("a line with the right digest but the wrong replace_span was not an orphan")
        else:
            print("  digest alone does not join: a wrong replace_span is an orphan")
    return problems


def part_4_vocabulary() -> list[str]:
    problems: list[str] = []
    if tuple(ti.OUTCOMES) != ("confirmed", "failed"):
        problems.append(f"the run-53 ruling fixes two outcomes; found {ti.OUTCOMES}")
    if tuple(ti.EDGE_STATES) != ("possible", "live", "severed", "live_via_tests"):
        problems.append(f"Q7 + I-198 fix four edge states; found {ti.EDGE_STATES}")
    if ti.PAGE_SIZE_DEFAULT != 50:
        problems.append(f"Q9 fixes the default page at 50; found {ti.PAGE_SIZE_DEFAULT}")
    state = ti.tool("cr_wiring").input_field("state")
    if state is None or tuple(state.choices) != ti.EDGE_STATES:
        problems.append("cr_wiring.state does not offer exactly the four edge states")
    outcome = ti.tool("cr_report_outcome").input_field("outcome")
    if outcome is None or tuple(outcome.choices) != ti.OUTCOMES:
        problems.append("cr_report_outcome.outcome does not offer exactly the two outcomes")
    page = ti.tool("cr_infractions").input_field("page_size")
    if page is None or page.default != 50:
        problems.append("cr_infractions.page_size does not default to 50")
    print(f"  outcomes={list(ti.OUTCOMES)}  edges={list(ti.EDGE_STATES)}  page={ti.PAGE_SIZE_DEFAULT}")

    shape = RUN136_SHAPE
    found = ti.placeholders_of(shape)
    if not found:
        problems.append(f"no <placeholder> read off a prescribed shape: {shape!r}")
    elif any(("<" in p["name"] or ">" in p["name"]) for p in found):
        problems.append("a placeholder name still carries its brackets")
    else:
        print(f"  shape placeholders: {[p['name'] for p in found]}")

    kinds = ti.tool("cr_apply").output_schema[0]
    if tuple(kinds.choices) != ("diff", "shape", "none"):
        problems.append(f"cr_apply.kind must be diff|shape|none (Q3/Q8); found {kinds.choices}")
    return problems


def main() -> int:
    print("=" * 72)
    print("T1 INTERFACE PROOF — coderadar_mcp.tool_interface (packet §B, 2026-09-17)")
    print("=" * 72)
    problems: list[str] = []
    for title, part in (
        ("Part 1 — the surface: 11 §B rows, schemas, sources of record, disjoint lanes", part_1_surface),
        ("Part 2 — the payloads: every example validates, every bad payload is refused", part_2_payloads),
        ("Part 3 — the return channel: round trip through the ENGINE's own reader", part_3_return_channel),
        ("Part 4 — the vocabulary the 2026-09-17 rulings fixed", part_4_vocabulary),
    ):
        print(f"\n{title}")
        problems += part()
    for p in problems:
        print("PROBLEM:", p)
    print("\nT1 interface proof:", "PASS" if not problems else "FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
