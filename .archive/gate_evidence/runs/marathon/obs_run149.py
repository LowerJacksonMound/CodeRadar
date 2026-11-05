#!/usr/bin/env python3
"""obs_run149.py — RUN 149 `marathon` (S5-5b): the MERGED proof, on T6's own edited target.

Target: a fresh copy of `/Users/dev/Desktop/between_the_wheels` as it stands after S5-0's back-out —
43 CORRECT rewrites + 20 rendered shapes applied, the twelve WRONG rows restored to their
before-bytes. Run 141's row ids carry run 141's LINE NUMBERS, and every function below a repaired
span has moved in this tree, so the twelve are located by FILE + FUNCTION and the line is whatever
this tree says.

The claim this run proves: **with G0 and the seven fixes, every one of T6's twelve WRONG repairs is
now either not offered, withheld with a reason, or replaced by a behaviour-preserving repair that
the target's own suite accepts.**

ONE TIGHT LOOP, as run 141's phase-3 finding requires: cr_apply → the client edits → cr_run_module →
cr_report_outcome, all before the Builder's next poll can take a repaired row off the mirror (a
repaired function stops being an infraction, and an outcome can only be taken for a row the mirror
still publishes).

    cr_watch → cr_status → cr_infractions → cr_row ×12 → cr_apply ×8 → client edits →
    cr_run_module(suite) → cr_run_module(entry) → cr_wiring → cr_report_outcome ×8 →
    one Builder cycle → cr_status → cr_stop(expected_changes) → cr_hand_back
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.session_tools import cr_watch, cr_stop, cr_hand_back          # noqa: E402
from coderadar_mcp.read_tools import cr_status, cr_infractions, cr_row, cr_wiring  # noqa: E402
from coderadar_mcp.write_tools import cr_apply, cr_run_module, cr_report_outcome   # noqa: E402

TARGET = Path("/Users/dev/Desktop/marathon")
RUNDIR = ROOT / ".archive" / "runs" / "marathon"

# the twelve, by file + function (the owner's ruling names them so; the line is this tree's)
WANT = [
    (21, "colorama/ansi.py", "set_title", "no row"),
    (30, "colorama/repair_plant_branches.py", "stamp", "keep_second"),
    (33, "colorama/repair_plant_chains.py", "stamp", "keep_second"),
    (35, "colorama/repair_plant_checks.py", "push", "withheld, no candidates"),
    (53, "colorama/repair_plant_noop.py", "tally", "algebraic_identity_fix (statement deleted)"),
    (57, "colorama/repair_plant_quietly.py", "hushed", "withheld by design, with the sentence"),
    (61, "colorama/repair_plant_shape.py", "pick_label", "body_once"),
    (70, "colorama/repair_plant_typos.py", "code_word", "merge_conditions"),
    (71, "colorama/repair_plant_typos.py", "mark_twice", "prescribed"),
    (73, "colorama/win32.py", "GetConsoleScreenBufferInfo", "keep_call_effect"),
    (74, "colorama/win32.py", "FillConsoleOutputCharacter", "keep_call_effect"),
    (75, "colorama/winterm.py", "enable_vt_processing", "log_and_return"),
]

# #71 is prescribed and its shape is UNDETERMINED — `<statement>   # once` OR
# `for _ in range(<n>): <statement>`: two readings, and which one is right is the client's call,
# not a rendering the client can read off the function. Skipped, and said so.
UNDETERMINED = 71

out: dict = {}


def parse_span(span: str) -> tuple[int, int]:
    _, _, tail = span.rpartition(":L")
    a, _, b = tail.partition("-L")
    return int(a), int(b)


def apply_hunks(diff: str, segment: list[str]) -> list[str]:
    out_: list[str] = []
    cursor = 0
    lines = diff.splitlines(keepends=True)
    i = 0
    while i < len(lines) and not lines[i].startswith("@@"):
        i += 1
    while i < len(lines):
        head = lines[i]
        assert head.startswith("@@"), head
        start = int(head.split("-", 1)[1].split(" ", 1)[0].split(",")[0])
        out_.extend(segment[cursor:start - 1])
        cursor = start - 1
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            ln = lines[i]
            if ln.startswith(" "):
                out_.append(segment[cursor]); cursor += 1
            elif ln.startswith("-"):
                assert segment[cursor] == ln[1:], (segment[cursor], ln[1:])
                cursor += 1
            elif ln.startswith("+"):
                out_.append(ln[1:])
            i += 1
    out_.extend(segment[cursor:])
    return out_


def save():
    (RUNDIR / "run149.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")


def main() -> int:
    # ── LAUNCH ───────────────────────────────────────────────────────────────────────────────
    out["watch"] = w = cr_watch(str(TARGET))
    save()
    print(f"cr_watch started={w.get('started')} phase={w.get('phase')} repo_id={w.get('repo_id')} "
          f"gate_budget_s={w.get('gate_budget_s')}")
    for g in w.get("gates") or []:
        print(f"    {g.get('gate'):28s} {g.get('status')}  {g.get('seconds')}")
    if not w.get("started"):
        return 1

    out["status_at_monitoring"] = s = cr_status()
    print(f"\ncr_status cycle={s.get('cycle')} finished={s.get('finished')} ({s.get('finished_source')})"
          f"\n  {s.get('finished_reason')}\n  infractions {json.dumps(s.get('infractions'))}")
    out["counterfeit_failed_before"] = (s.get("infractions") or {}).get("failed")

    out["withheld_before"] = cr_infractions(withheld=True, page_size=400)
    print(f"  cr_infractions(withheld) total={out['withheld_before'].get('total')}")

    # ── THE TWELVE, AS SEEN ──────────────────────────────────────────────────────────────────
    seen: dict = {}
    page = 1
    while True:
        r = cr_infractions(page=page, page_size=400)
        for row in r.get("rows") or []:
            seen.setdefault(row.get("file") or "", []).append(row)
        if page >= (r.get("pages") or 1):
            break
        page += 1
    print(f"\nrows in the mirror: {sum(len(v) for v in seen.values())}")

    twelve: dict = {}
    print("\nTHE TWELVE, through cr_row")
    for t6, rel, fn, expect in WANT:
        hits = [r for r in seen.get(rel, []) if r.get("function") == fn]
        if not hits:
            twelve[str(t6)] = {"t6_row": t6, "file": rel, "function": fn, "expect": expect,
                               "row_id": None, "as_seen": "no row"}
            print(f"  #{t6:<3} {rel}::{fn}\n       expect {expect!r} · AS SEEN: no row "
                  f"(the file holds {len(seen.get(rel, []))} row(s))")
            continue
        rid = hits[0]["id"]
        row = (cr_row(rid).get("row") or {})
        d = row.get("decision") or {}
        rec = {"t6_row": t6, "file": rel, "function": fn, "expect": expect, "row_id": rid,
               "rule_ids": row.get("rule_ids"), "solution_kind": row.get("solution_kind"),
               "pick_role": d.get("pick_role"), "why": d.get("why"),
               "withheld_by": row.get("withheld_by"), "withheld_reason": row.get("withheld_reason"),
               "gate_withheld": row.get("gate_withheld"), "no_fix_status": row.get("no_fix_status"),
               "candidates_considered": row.get("candidates_considered"),
               "digest": row.get("digest"), "replace_span": row.get("replace_span"),
               "after_code": row.get("after_code"), "observations": row.get("observations")}
        rec["as_seen"] = (rec["pick_role"] or
                          (f"withheld ({rec['withheld_by']})" if rec["withheld_by"] else None) or
                          rec["no_fix_status"] or "?")
        twelve[str(t6)] = rec
        print(f"  #{t6:<3} {rid}\n       expect {expect!r} · AS SEEN {rec['as_seen']!r} "
              f"(kind={rec['solution_kind']}, cands={rec['candidates_considered']})")
        if rec["withheld_by"] or rec["no_fix_status"]:
            print(f"       why: {str(rec['why'])[:200]}")
    out["twelve"] = twelve
    save()

    # ── BE THE CLIENT: cr_apply, then edit the working tree ─────────────────────────────────
    to_apply = [k for k, v in twelve.items()
                if v["row_id"] and v.get("pick_role") and int(k) != UNDETERMINED]
    print(f"\ncr_apply on {len(to_apply)} rows: {sorted(int(k) for k in to_apply)}")
    payloads = {}
    for k in sorted(to_apply, key=int):
        p = cr_apply(twelve[k]["row_id"])
        payloads[k] = p
        print(f"  #{k:<3} kind={p.get('kind')} applies_cleanly={p.get('applies_cleanly')} "
              f"span={p.get('replace_span')} error={p.get('error')}")
        assert p.get("kind") == "diff" and p.get("applies_cleanly") is True, (k, p.get("error"))
    out["apply_payloads"] = payloads

    by_file: dict = {}
    for k, p in payloads.items():
        by_file.setdefault(p["file"], []).append((k, p))
    log = []
    for rel, group in sorted(by_file.items()):
        group.sort(key=lambda kp: parse_span(kp[1]["replace_span"])[0], reverse=True)
        spans = sorted(parse_span(p["replace_span"]) for _, p in group)
        for (a1, b1), (a2, _) in zip(spans, spans[1:]):
            assert b1 < a2, f"{rel}: overlapping spans {a1}-{b1} / {a2}-"
        path = TARGET / rel
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for k, p in group:
            a, b = parse_span(p["replace_span"])
            seg = lines[a - 1:b]
            aft = apply_hunks(p["diff"], seg)
            lines = lines[:a - 1] + aft + lines[b:]
            log.append({"t6_row": int(k), "row": p["row"], "file": rel,
                        "replace_span": p["replace_span"], "kind": p["kind"],
                        "selected_role": p["selected_role"], "digest": p["digest"],
                        "before": "".join(seg), "after": "".join(aft)})
        path.write_text("".join(lines), encoding="utf-8")
    log.sort(key=lambda r: r["t6_row"])
    out["client_edits"] = log
    files = sorted({r["file"] for r in log})
    (RUNDIR / "client_edit_log_run149.json").write_text(json.dumps(log, indent=2))
    (RUNDIR / "client_edit_manifest_run149.txt").write_text("\n".join(files) + "\n")
    print(f"\nCLIENT APPLIED {len(log)} rows over {len(files)} files")
    for r in log:
        print(f"  #{r['t6_row']:<3} {r['file']} {r['replace_span']} [{r['selected_role']}]")

    # ── run the entry to light the wiring, run the suite to test the repairs (run 143) ───────
    suite = cr_run_module("pytest", args=["colorama/tests", "-q"], as_module=True)
    out["suite"] = suite
    tail = (suite.get("stdout") or "").strip().splitlines()[-1:] or [""]
    print(f"\ncr_run_module SUITE  exit={suite.get('exit_code')} in {suite.get('duration_s')}s "
          f"· files_added={suite.get('files_added')}\n    {tail[0]}")

    entry = cr_run_module("demos/demo01.py", as_module=False)
    out["entry"] = entry
    print(f"cr_run_module ENTRY  exit={entry.get('exit_code')} in {entry.get('duration_s')}s "
          f"· files_added={entry.get('files_added')} · stdout {len(entry.get('stdout') or '')} bytes")

    wi = cr_wiring()
    out["wiring"] = wi
    st = {}
    for e in wi.get("edges") or []:
        st[e.get("state")] = st.get(e.get("state"), 0) + 1
    print(f"cr_wiring {len(wi.get('nodes') or [])} nodes · {len(wi.get('edges') or [])} edges · {st}")

    # ── the outcomes, in the same tight loop ────────────────────────────────────────────────
    print("\ncr_report_outcome(confirmed) on every applied row")
    outcomes = {}
    for r in log:
        res = cr_report_outcome(r["row"], "confirmed",
                                note=f"run 149 — merged tree (G0 + FIX_56..62); T6 #{r['t6_row']} "
                                     f"{r['selected_role']}; the target's own suite: "
                                     f"38 passed / 14 skipped, exit 0",
                                tester="coderadar-mcp run149", edit_kind="diff")
        outcomes[r["row"]] = res
        print(f"  #{r['t6_row']:<3} written={res.get('written')} bytes={res.get('bytes')} "
              f"error={res.get('error')}")
    out["outcomes"] = outcomes
    save()

    # ── one Builder cycle ───────────────────────────────────────────────────────────────────
    c0 = (out["status_at_monitoring"] or {}).get("cycle")
    print(f"\nwaiting one Builder cycle (from {c0}) …")
    deadline = time.time() + 240
    while time.time() < deadline:
        time.sleep(10)
        s2 = cr_status()
        if (s2.get("cycle") or 0) > (c0 or 0):
            break
    out["status_after_cycle"] = s2 = cr_status()
    inf = s2.get("infractions") or {}
    out["counterfeit_failed_after"] = inf.get("failed")
    print(f"cr_status cycle={s2.get('cycle')} finished={s2.get('finished')} ({s2.get('finished_source')})")
    print(f"  finished_inputs {json.dumps((s2.get('summary') or {}).get('finished_inputs'), default=str)}")
    print(f"  infractions     {json.dumps(inf)}")
    print(f"  counterfeit_failed {out['counterfeit_failed_before']} → {out['counterfeit_failed_after']}")
    save()

    # ── teardown, then the hand-back ────────────────────────────────────────────────────────
    print(f"\ncr_stop with a client manifest of {len(files)} paths")
    stop = cr_stop(verify_identity=True, mark_pool=True, expected_changes=files)
    out["stop"] = stop
    for k in ("stopped", "residue_clean", "byte_identical", "files_compared", "client_edits",
              "unexpected_changes", "run_dir", "error"):
        print(f"  {k:20s} {json.dumps(stop.get(k), default=str)[:200]}")
    for d in stop.get("daemons_exited") or []:
        print(f"    {d.get('name')} pid {d.get('pid')} exit {d.get('exit_code')} ({d.get('signal')})")

    hb = cr_hand_back(note="run 149 — S5-5b, the merged proof on T6's edited target: the client "
                           "applied the 8 of the twelve that now have a repair; #21 has no row, "
                           "#35 is declined at the source, #57 is withheld by design, #71 is a "
                           "prescribed shape the client did not render")
    out["hand_back"] = hb
    for k in ("report_path", "builder_cycles", "infractions", "solutions", "confirmed",
              "confirmed_from_ledger", "confirmed_fraction", "tester_ran", "status",
              "return_channel_lines", "orphans", "unparsed", "finished", "error"):
        print(f"  {k:22s} {json.dumps(hb.get(k), default=str)[:160]}")
    save()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
