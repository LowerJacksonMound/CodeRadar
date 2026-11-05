#!/usr/bin/env python3
"""obs_run158.py — RUN 158 `force_ten`: THE DRIFT FIX, live (session 7 packet §C.7).

**Driver-driven, NOT a mounted MCP client.** The `cr_*` tools are called THROUGH THE STDIO /
IN-PROCESS DRIVER in this run record, exactly as runs 144–151, 153, 156 and 157 did; only T1
(run 152) and T3 (runs 154–155) of session 6 used the MOUNTED server. Q4's default, taken.

What it proves, live, on a fresh copy of `between_the_wheels_20260917_062701`:

  the seat is handed three rewriter rows IN ONE FILE, applies all three, measures them with the
  target's own suite, and then **waits out the retirement window on purpose** — the 30-60 s in
  which the Builder retires a repaired row (I-119 measured 8 of 18 outcomes lost to it in run
  155) — before reporting a single one. Every report must still land:

    * `cr_apply` leases what it hands out, and re-bases its diff against the LIVE span after
      each earlier edit to the same file shifts the rows below it (§C.1 / §C.4, I-130);
    * `cr_report_outcome` resolves against the lease when the live row is gone or has drifted,
      and says so as `resolved_by` (§C.2, I-119 / I-125 / I-138);
    * the channel line carries the PRE-EDIT identity — `row_key`, `rule_ids`, `variant`, `file`,
      `function` — so `rule_outcomes` names the variant of the failed repair instead of `?`
      (§C.3, I-122);
    * one verdict is `failed` and its edit is then REVERTED, which is exactly the row I-125
      said could not be reported at all.

  Then two MORE Builder cycles, and §C.6 (vii) is asserted off the record: every
  `cr_report_outcome` `written true`, `orphans_channel 0`, `failed_against` without `?`.

Every number written to run158.json is READ BACK from a tool payload or a state file on disk;
none is quoted from memory. `coderadar_mcp/identity_proof.py` part (vii) reads this file.

ONE TIGHT LOOP:
    cr_attach -> cr_status -> cr_infractions -> cr_run_module(-m pytest) [baseline] ->
    PASS 1: cr_apply row 1 (lease) -> the driver writes the edit as the client would, from
            `replace_span_live` + the diff -> ONE Builder cycle, on purpose ->
    PASS 2: cr_apply rows 2 and 3, RE-BASED against the file pass 1 moved -> written ->
            cr_run_module(-m pytest) -> ONE more Builder cycle, on purpose ->
    (>= 2 cycles have now turned and NOTHING has been reported) ->
    cr_report_outcome x3 (>= 1 `failed`, its edit then reverted) -> wait 2 more cycles ->
    assert (vii) -> cr_stop(expected_changes) -> cr_hand_back
"""
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH_copy1")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.session_tools import cr_watch, cr_attach, cr_stop, cr_hand_back  # noqa: E402
from coderadar_mcp.read_tools import cr_status, cr_infractions, cr_row               # noqa: E402
from coderadar_mcp.write_tools import cr_apply, cr_run_module, cr_report_outcome     # noqa: E402

TARGET = Path("/Users/dev/CodeRadar_snapshots/force_ten_20260921_122634")
RUNDIR = ROOT / ".archive" / "runs" / TARGET.name

#: ONE file, three rewriter rows — §C.7's shape. Every earlier edit shifts the rows below it,
#: which is what makes the re-base (I-130) a live fact rather than a fixture's.
THE_FILE = "colorama/repair_plant_branches.py"
ROWS = [f"{THE_FILE}::guarded::7", f"{THE_FILE}::pick::18", f"{THE_FILE}::stamp::26"]
#: the one reported `failed`, whose edit is then reverted — I-125's row exactly.
FAILED_ROW = ROWS[2]

#: the mount's own baseline for this target (packet §C.7), asserted, never assumed.
BASELINE = "38 passed"
BASELINE_SKIPPED = "14 skipped"

#: §C.7 — "wait >= 2 Builder cycles ON PURPOSE (the window I-119 measured at 30-60 s)".
#: §C.7 asks for ">= 2 Builder cycles on purpose" before a single outcome is reported, and
#: LAUNCH B proved that cannot be had by WAITING: the Builder is event-driven, not periodic
#: (`_read_validator_state` compares the validator state file's mtime; `_cycle` returns at once
#: unless the validator state, the return channel or the entry role changed). Three edits in one
#: batch are one validator re-scan and therefore ONE cycle; launch B sat out a 1800 s ceiling
#: for a second cycle that could never come. So the seat does what a seat really does — it
#: applies in two passes, and each pass is a cycle:
#:      pass 1: row 1  -> write it -> ONE cycle (the row is retired, the rows below it re-key)
#:      pass 2: rows 2, 3 (RE-BASED against the file pass 1 moved) -> write -> ONE more cycle
#: and only then are all three reported. Two cycles, both real, both waited out on purpose.
CYCLES_PER_PASS = 1
CYCLES_AFTER_REPORT = 2
#: The ceiling is the wait's BOUND, never its length — `wanted` vs `got` says which ended it.
CYCLE_WAIT_CEILING_S = 1800

SYS = ROOT / "system_scripts"
out: dict = {}


def save() -> None:
    (RUNDIR / "run158.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")


def read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:                       # never silent: the miss is the observation
        return {"__unreadable__": f"{type(e).__name__}: {e}"}


def jsonl(p: Path) -> list:
    if not p.exists():
        return []
    recs = []
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if raw:
            try:
                recs.append(json.loads(raw))
            except Exception:
                pass
    return recs


def after_lines_of(diff: str) -> list:
    """The bytes the hunk puts there, taken out of `cr_apply`'s own answer. A client that has
    `replace_span_live` and the diff needs nothing else — which is the point of the re-base:
    before it, run 155's client had to fall back to `before_code`/`after_code` because the hunk
    headers were not re-based against the file in front of it."""
    keep = []
    for ln in (diff or "").splitlines(keepends=True):
        if ln.startswith(("---", "+++", "@@")):
            continue
        if ln.startswith("+"):
            keep.append(ln[1:])
        elif ln.startswith(" "):
            keep.append(ln[1:])
    return keep


def span_bounds(span: str) -> tuple:
    head, _, tail = span.rpartition(":L")
    first, _, last = tail.partition("-L")
    return head, int(first), int(last)


def write_edit(span_live: str, diff: str) -> dict:
    """The client's own edit, exactly as a seat applies one: splice the hunk's result into the
    file at `replace_span_live`. Returns what was written, for the edit log.

    LAUNCH A's defect: the bytes it replaces are kept HERE, by the client. Launch A tried to back
    the failed edit out of `cr_row(row).before_code` and got nothing, because by then the Builder
    had retired the row and the before-code went with it. Under Q3 the client's own working tree
    IS the archive — so the client keeps what it overwrote, and the lease's `before_sha256` is
    what lets the back-out be PROVEN against what the server handed out."""
    rel, start, end = span_bounds(span_live)
    path = TARGET / rel
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    replaced = "".join(lines[start - 1:end])
    new = after_lines_of(diff)
    path.write_text("".join(lines[:start - 1] + new + lines[end:]), encoding="utf-8")
    return {"file": rel, "span_live": span_live, "lines_out": end - start + 1,
            "lines_in": len(new), "replaced_text": replaced,
            "replaced_sha256": hashlib.sha256(replaced.encode()).hexdigest()}


def suite(label: str) -> dict:
    r = cr_run_module("pytest", args=["colorama/tests", "-q"], as_module=True)
    tail = (r.get("stdout") or "").strip().splitlines()[-1:] or [""]
    rec = {"label": label, "exit_code": r.get("exit_code"), "duration_s": r.get("duration_s"),
           "seen_on_band": r.get("seen_on_band"), "last_line": tail[0],
           "baseline_passed": BASELINE in (r.get("stdout") or ""),
           "baseline_skipped": BASELINE_SKIPPED in (r.get("stdout") or "")}
    print(f"  suite [{label}] exit={rec['exit_code']} {rec['duration_s']}s  {rec['last_line']!r}")
    print(f"      baseline {BASELINE} {rec['baseline_passed']} · "
          f"{BASELINE_SKIPPED} {rec['baseline_skipped']}")
    return rec


def wait_cycles(n: int, why: str) -> dict:
    """Wait for the Builder to turn `n` more cycles — ON PURPOSE. Before session 7 this was the
    window that swallowed a seat's voice (I-119): a repaired row is retired inside it."""
    c0 = cr_status().get("cycle") or 0
    print(f"\nwaiting {n} Builder cycle(s) from {c0} — {why}")
    t0 = time.monotonic()
    deadline = t0 + CYCLE_WAIT_CEILING_S
    cyc = c0
    while time.monotonic() < deadline:
        time.sleep(5)
        cyc = cr_status().get("cycle") or 0
        if cyc >= c0 + n:
            break
    waited = round(time.monotonic() - t0, 1)
    got = cyc - c0
    print(f"  cycle {c0} -> {cyc} ({got} of {n} wanted) after {waited}s")
    return {"from": c0, "to": cyc, "wanted": n, "got": got, "seconds": waited,
            "reached_the_ceiling": got < n, "why": why}


def main() -> int:
    out["driver"] = ("stdio / in-process driver in a run record — NOT a mounted MCP client "
                     "(Q4's default; only T1 and T3 of session 6 mounted)")
    out["item"] = ("T1, the drift fix (session 7 §C): pre-edit identity — the apply lease, the "
                   "resolution order, the re-based diff, the tolerant id, the variant on the line")
    out["target"] = str(TARGET)
    out["watch"] = w = cr_attach(str(TARGET))
    out["bound_by"] = "cr_attach (run_proof.sh up launched)"
    if not w.get("attached"):
        print(f"cr_attach refused ({w.get('error')}) — falling back to cr_watch")
        out["watch"] = w = cr_watch(str(TARGET))
        out["bound_by"] = "cr_watch (the driver launched)"
    save()
    print(f"{out['bound_by']}: attached={w.get('attached')} phase={w.get('phase')} "
          f"repo_id={w.get('repo_id')}")
    if not (w.get("attached") or w.get("started")):
        print(f"  error: {w.get('error')}")
        return 1

    s = cr_status()
    out["status_at_monitoring"] = s
    repo_id = read_json(SYS / "BUILDER_STATE.json").get("repo_id") or ""
    out["repo_id"] = repo_id
    channel = SYS / f"return_channel_{repo_id}.jsonl"
    lease_file = SYS / f"apply_lease_{repo_id}.jsonl"
    ledger = SYS / f"confirmed_ledger_{repo_id}.jsonl"
    out["files"] = {"channel": str(channel), "lease": str(lease_file), "ledger": str(ledger)}
    print(f"cr_status cycle={s.get('cycle')} infractions={json.dumps(s.get('infractions'))}")
    print(f"  channel {channel.name} · lease {lease_file.name} · ledger {ledger.name}")

    # ── the three rows, read off the mirror ──────────────────────────────────────────────────
    listing = cr_infractions(file=THE_FILE, page_size=400)
    mirror_rows = {r["id"]: r for r in (listing.get("rows") or [])}
    out["rows_in_file"] = sorted(mirror_rows)
    chosen = [r for r in ROWS if r in mirror_rows]
    out["rows_chosen"] = chosen
    print(f"\n{len(mirror_rows)} rows in {THE_FILE}; taking {len(chosen)}: {chosen}")
    if len(chosen) < 3:
        print("  fewer than three rewriter rows in one file — the run cannot be made")
        return 1

    out["suite"] = [suite("baseline, before any edit")]
    save()

    # ── cr_apply x3, each re-based against the file the one before it moved ──────────────────
    out["applies"] = []
    out["edits"] = []
    out["cycles"] = []

    def apply_and_write(rid: str) -> dict:
        a = cr_apply(rid)
        rec = {"row": rid, "kind": a.get("kind"), "digest": a.get("digest"),
               "selected_role": a.get("selected_role"),
               "replace_span": a.get("replace_span"),
               "replace_span_live": a.get("replace_span_live"),
               "rebased": a.get("replace_span") != a.get("replace_span_live"),
               "applies_cleanly": a.get("applies_cleanly"),
               "lease": a.get("lease"), "lease_written": a.get("lease_written"),
               "resolved_by": a.get("resolved_by"), "error": a.get("error"),
               "diff_chars": len(a.get("diff") or "")}
        out["applies"].append(rec)
        print(f"  {rid}")
        print(f"      span {rec['replace_span']}  live {rec['replace_span_live']}  "
              f"rebased={rec['rebased']}")
        print(f"      digest {rec['digest']}  variant {rec['selected_role']}  "
              f"clean={rec['applies_cleanly']}  leased={rec['lease_written']}")
        if a.get("kind") == "diff" and a.get("applies_cleanly"):
            out["edits"].append(write_edit(a["replace_span_live"], a["diff"] or ""))
            print(f"      the client wrote it: "
                  f"{json.dumps({k: v for k, v in out['edits'][-1].items() if k != 'replaced_text'})}")
        return rec

    # ── PASS 1: one row, written, and one Builder cycle turned on it ─────────────────────────
    print("\nPASS 1 — cr_apply on the first row, written, then ONE Builder cycle")
    apply_and_write(chosen[0])
    out["cycles"].append(wait_cycles(
        CYCLES_PER_PASS, "pass 1's edit re-scanned: the repaired row is retired and every row "
                         "below it in the file is re-keyed (I-119 / I-130's window, on purpose)"))

    # ── PASS 2: the other two, RE-BASED against the file pass 1 moved ────────────────────────
    print("\nPASS 2 — cr_apply on the other two, now RE-BASED against the moved file")
    for rid in chosen[1:]:
        apply_and_write(rid)
    out["suite"].append(suite("after the three edits"))
    out["cycles"].append(wait_cycles(
        CYCLES_PER_PASS, "pass 2's edits re-scanned — the second cycle, so >= 2 have turned "
                         "since the first row was handed out and NOTHING has been reported yet"))
    out["cycles_before_reporting"] = sum(c["got"] for c in out["cycles"])
    print(f"\n{out['cycles_before_reporting']} Builder cycle(s) turned before a single outcome "
          f"was reported")
    out["leases_on_disk"] = jsonl(lease_file)
    print(f"{len(out['leases_on_disk'])} lease record(s) in {lease_file.name}")
    for lr in out["leases_on_disk"]:
        print(f"    {lr['row_key']:52s} digest {lr['digest']} variant {lr['variant']} "
              f"span {lr['replace_span']} live {lr['replace_span_live']}")
    save()

    # what the mirror thinks of the three rows NOW — the drift, measured
    after = {r["id"]: r for r in (cr_infractions(file=THE_FILE, page_size=400).get("rows") or [])}
    out["rows_after_wait"] = sorted(after)
    out["drift"] = {}
    for rid in chosen:
        was = mirror_rows[rid]
        now = after.get(rid)
        out["drift"][rid] = {
            "still_in_mirror_under_the_same_id": now is not None,
            "digest_then": was.get("digest"),
            "digest_now": (now or {}).get("digest"),
            "rule_ids_then": was.get("rule_ids"),
            "rule_ids_now": (now or {}).get("rule_ids"),
        }
        d = out["drift"][rid]
        print(f"  {rid}: same id {d['still_in_mirror_under_the_same_id']} · "
              f"digest {d['digest_then']} -> {d['digest_now']}")
    save()

    # ── the reports — after the window, which is the whole point ─────────────────────────────
    print("\ncr_report_outcome for all three, AFTER the window")
    out["report_outcomes"] = []
    for rid in chosen:
        verdict = "failed" if rid == FAILED_ROW else "confirmed"
        note = ("AssertionError: the repair did not preserve behaviour — reverted"
                if verdict == "failed" else "suite unmoved from baseline")
        r = cr_report_outcome(rid, verdict, note, edit_kind="diff")
        rec = {"row": rid, "outcome": verdict, "written": r.get("written"),
               "resolved_by": r.get("resolved_by"), "resolved_id": r.get("resolved_id"),
               "digest": r.get("digest"), "replace_span": r.get("replace_span"),
               "ledger_written": r.get("ledger_written"), "line": r.get("line"),
               "ledger_record": r.get("ledger_record"), "error": r.get("error")}
        out["report_outcomes"].append(rec)
        print(f"  {rid} -> {verdict}")
        print(f"      written={rec['written']} resolved_by={rec['resolved_by']!r} "
              f"ledger_written={rec['ledger_written']} error={rec['error']!r}")
        print(f"      line: {json.dumps(rec['line'])}")
    save()

    # ── the `failed` row's edit is REVERTED — I-125's row, reported and then backed out ──────
    print(f"\nreverting the edit of the `failed` row {FAILED_ROW} (I-125's shape)")
    rev = next(a for a in out["applies"] if a["row"] == FAILED_ROW)
    edit = next(e for e in out["edits"] if e["span_live"] == rev["replace_span_live"])
    # From the CLIENT's own copy of what it overwrote — see `write_edit`. The server cannot
    # give it back: `cr_row(FAILED_ROW).before_code` is empty here, because the row is retired,
    # and launch A's revert wrote nothing for exactly that reason. Recorded either way.
    row_doc = (cr_row(FAILED_ROW).get("row") or {})
    rel, start, _ = span_bounds(rev["replace_span_live"])
    end = start - 1 + edit["lines_in"]
    path = TARGET / rel
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    back = edit["replaced_text"].splitlines(keepends=True)
    path.write_text("".join(lines[:start - 1] + back + lines[end:]), encoding="utf-8")
    lease_rec = [r for r in jsonl(lease_file) if r.get("row_key") == FAILED_ROW][-1:]
    reverted = {
        "row": FAILED_ROW, "restored_from": "the client's own copy of what it overwrote",
        "server_could_give_it_back": bool(row_doc.get("before_code")),
        "span_restored": f"{rel}:L{start}-L{end}", "lines_back": len(back),
        "client_replaced_sha256": edit["replaced_sha256"],
        "lease_before_sha256": (lease_rec[0]["before_sha256"] if lease_rec else ""),
    }
    reverted["verified_against_the_lease"] = (
        bool(lease_rec) and reverted["client_replaced_sha256"] == reverted["lease_before_sha256"])
    out["reverted"] = reverted
    print(f"  {json.dumps({k: v for k, v in reverted.items() if k != 'replaced_text'})}")
    out["suite"].append(suite("after the failed edit was reverted"))
    out["cycles"].append(wait_cycles(CYCLES_AFTER_REPORT,
                                     "two more cycles, so the Builder has polled the channel and "
                                     "re-decided before (vii) is asserted"))
    save()

    # ── (vii): the numbers, read back off the files themselves ───────────────────────────────
    print("\n§C.6 (vii) — read back off the channel, the ledger and the mirror")
    out["channel_lines"] = jsonl(channel)
    out["ledger_records"] = jsonl(ledger)
    print(f"  channel lines {len(out['channel_lines'])} · ledger records "
          f"{len(out['ledger_records'])}")
    for ln in out["channel_lines"]:
        print(f"    {ln.get('outcome'):9s} {ln.get('row_key')} digest {ln.get('digest')} "
              f"variant {ln.get('variant')!r} rules {len(ln.get('rule_ids') or [])}")
    s2 = cr_status()
    out["status_after"] = s2
    out["rule_outcomes_after"] = dict(s2.get("rule_outcomes") or {})
    marked = sorted(r for r, rec in out["rule_outcomes_after"].items()
                    if r == "?" or "?" in (rec.get("failed_against") or {}))
    out["rule_outcomes_marked_unknown"] = marked
    print(f"  rule_outcomes: {len(out['rule_outcomes_after'])} rules · `?` in {marked}")
    fa = {r: rec["failed_against"] for r, rec in out["rule_outcomes_after"].items()
          if rec.get("failed_against")}
    out["failed_against"] = fa
    print(f"  failed_against: {json.dumps(fa)}")
    out["assert_vii"] = {
        "every_report_written": all(r["written"] for r in out["report_outcomes"]),
        "every_report_says_how_it_resolved": all(r["resolved_by"] for r in out["report_outcomes"]),
        "resolved_by_values": sorted({r["resolved_by"] for r in out["report_outcomes"]}),
        "failed_against_without_question_mark": not marked,
        "leases_written": all(a["lease_written"] for a in out["applies"]),
        "at_least_one_rebase": any(a["rebased"] for a in out["applies"]),
        "revert_verified_against_the_lease": out["reverted"]["verified_against_the_lease"],
        "waited_at_least_two_cycles_before_reporting": out["cycles_before_reporting"] >= 2,
        "suite_unmoved_from_baseline": all(r["baseline_passed"] and r["baseline_skipped"]
                                           for r in out["suite"]),
    }
    print(f"  (vii) so far: {json.dumps(out['assert_vii'], indent=1)}")
    save()

    # ── close ────────────────────────────────────────────────────────────────────────────────
    print(f"\ncr_stop(expected_changes=[{THE_FILE}])")
    stop = cr_stop(verify_identity=True, mark_pool=True, expected_changes=[THE_FILE])
    out["stop"] = stop
    for k in ("stopped", "residue_clean", "byte_identical", "files_compared", "client_edits",
              "unexpected_changes", "run_dir", "error"):
        print(f"  {k:20s} {json.dumps(stop.get(k), default=str)[:200]}")

    hb = cr_hand_back(note="run 158 — T1, the drift fix (session 7 §C): three rewriter rows in "
                           "ONE file applied and measured, the retirement window waited out ON "
                           "PURPOSE, and every outcome still reported — the apply lease carries "
                           "the pre-edit identity (I-119/125/138), the diff is re-based (I-130), "
                           "the channel line carries the variant (I-122), and an HTML-escaped or "
                           "stale id resolves (I-137). Driver-driven, not mounted.")
    out["hand_back"] = hb
    for k in ("report_path", "builder_cycles", "infractions", "solutions", "confirmed",
              "confirmed_from_ledger", "confirmed_ledger_rows", "return_channel_lines",
              "tester_ran", "status", "orphans", "orphans_channel", "unparsed", "finished",
              "error"):
        print(f"  {k:24s} {json.dumps(hb.get(k), default=str)[:160]}")
    out["assert_vii"]["orphans_channel_zero"] = hb.get("orphans_channel") == 0
    out["assert_vii"]["orphans_zero"] = hb.get("orphans") == 0
    out["assert_vii"]["residue_clean"] = stop.get("residue_clean") is True
    out["assert_vii"]["unexpected_changes_empty"] = stop.get("unexpected_changes") == []
    print(f"\n(vii) FINAL: {json.dumps(out['assert_vii'], indent=1)}")
    save()
    return 0 if all(out["assert_vii"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
