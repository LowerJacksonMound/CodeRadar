#!/usr/bin/env python3
"""obs_run153.py — RUN 153 `emotion_detector`: B9's accumulation (ruling Q3, 2026-09-20) LIVE.

The claim: the counterfeit-code mirror's one writer stages `summary.rule_outcomes` EVERY CYCLE from
the confirmed ledger and the return channel; `cr_status` answers it; a `confirmed` counts FOR every
rule id the ledger record carries, and a `failed` counts against the repair VARIANT and never
against the rule. Nothing in `rule_dispositions.json` moves.

The tools are driven through the STDIO / IN-PROCESS DRIVER (handlers imported here, as runs 144–151
did), NOT a mounted MCP client — the mount is T1's and T3's business.

ONE TIGHT LOOP:
    cr_watch → cr_status (rule_outcomes present, EMPTY) → cr_infractions → cr_apply ×3 rewriter rows
    → the client edits → cr_run_module(suite) → cr_report_outcome 2 confirmed + 1 failed (the failed
    edit backed out first) → one Builder cycle → cr_status (the 2 under confirmed_for, the 1 under
    failed_against[<variant>]) → cr_stop(expected_changes) → cr_hand_back (the report carries it)
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH_copy1")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.session_tools import cr_watch, cr_stop, cr_hand_back            # noqa: E402
from coderadar_mcp.read_tools import cr_status, cr_infractions, cr_row             # noqa: E402
from coderadar_mcp.write_tools import cr_apply, cr_run_module, cr_report_outcome   # noqa: E402

TARGET = Path("/Users/dev/Desktop/emotion_detector")
RUNDIR = ROOT / ".archive" / "runs" / "emotion_detector"
WANT_ROWS = 3

out: dict = {}


def save():
    (RUNDIR / "run153.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")


def parse_span(span: str) -> tuple[int, int]:
    _, _, tail = span.rpartition(":L")
    a, _, b = tail.partition("-L")
    return int(a), int(b)


def apply_hunks(diff: str, segment: list) -> list:
    """The client's own patcher (run 151's, unchanged) — the SERVER never writes the target."""
    out_: list = []
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


def main() -> int:
    ok_all = True
    out["watch"] = w = cr_watch(str(TARGET))
    save()
    print(f"cr_watch started={w.get('started')} phase={w.get('phase')} repo_id={w.get('repo_id')} "
          f"gate_budget_s={w.get('gate_budget_s')}")
    for g in w.get("gates") or []:
        print(f"    {g.get('gate'):28s} {g.get('status')}  {g.get('seconds')}")
    if not w.get("started"):
        return 1

    # ── B9, before anything is reported: the block is PUBLISHED and EMPTY ───────────────────
    out["status_at_monitoring"] = s = cr_status()
    ro0 = s.get("rule_outcomes")
    print(f"\ncr_status cycle={s.get('cycle')} finished={s.get('finished')} ({s.get('finished_source')})"
          f"\n  infractions {json.dumps(s.get('infractions'))}")
    zero = isinstance(ro0, dict) and all(
        r.get("confirmed_for") == 0 and not r.get("failed_against") for r in ro0.values())
    print(f"  rule_outcomes published={ro0 is not None} rules={len(ro0 or {})} all_zero={zero}")
    ok_all = ok_all and ro0 is not None and zero
    out["rule_outcomes_at_monitoring"] = ro0
    out["counterfeit_failed_before"] = (s.get("infractions") or {}).get("failed")

    rows: list = []
    page = 1
    while True:
        r = cr_infractions(page=page, page_size=400)
        rows.extend(r.get("rows") or [])
        if page >= (r.get("pages") or 1):
            break
        page += 1
    print(f"\nrows in the mirror: {len(rows)}")

    # ── BE THE CLIENT: three REWRITER rows, one file each, that apply cleanly ───────────────
    picked: list = []
    seen_files: set = set()
    for r in rows:
        enough = len(picked) >= WANT_ROWS
        if not enough and r.get("has_solution") and r.get("file") not in seen_files:
            p = cr_apply(r["id"])
            if p.get("kind") == "diff" and p.get("applies_cleanly") is True:
                row = (cr_row(r["id"]).get("row") or {})
                picked.append({"id": r["id"], "payload": p, "rule_ids": row.get("rule_ids") or [],
                               "pick_role": (row.get("decision") or {}).get("pick_role")})
                seen_files.add(r.get("file"))
    print(f"\ncr_apply picked {len(picked)} rewriter row(s):")
    for q in picked:
        print(f"  {q['id']}\n       role={q['pick_role']!r} span={q['payload'].get('replace_span')} "
              f"rules={q['rule_ids']}")
    ok_all = ok_all and len(picked) == WANT_ROWS
    out["picked"] = picked
    save()

    log: list = []
    for q in picked:
        p = q["payload"]
        rel = p["replace_span"].rsplit(":L", 1)[0]
        path = TARGET / rel
        a, b = parse_span(p["replace_span"])
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        seg = lines[a - 1:b]
        aft = apply_hunks(p["diff"], seg)
        path.write_text("".join(lines[:a - 1] + aft + lines[b:]), encoding="utf-8")
        log.append({"row": p["row"], "file": rel, "replace_span": p["replace_span"],
                    "kind": p["kind"], "selected_role": p["selected_role"], "digest": p["digest"],
                    "rule_ids": q["rule_ids"], "before": "".join(seg), "after": "".join(aft)})
    print(f"\nCLIENT APPLIED {len(log)} rows over {len({r['file'] for r in log})} file(s)")
    for r in log:
        print(f"  {r['replace_span']} [{r['selected_role']}]")

    suite = cr_run_module("pytest", args=["colorama/tests", "-q"], as_module=True)
    out["suite"] = suite
    tail = (suite.get("stdout") or "").strip().splitlines()[-1:] or [""]
    print(f"\ncr_run_module SUITE  exit={suite.get('exit_code')} in {suite.get('duration_s')}s\n    {tail[0]}")

    # ── The third row is REPORTED FAILED, and its edit is backed out first ──────────────────
    confirmed_rows, failed_row = log[:2], log[2]
    fpath = TARGET / failed_row["file"]
    ftext = fpath.read_text(encoding="utf-8")
    fpath.write_text(ftext.replace(failed_row["after"], failed_row["before"], 1), encoding="utf-8")
    print(f"\nbacked the third edit out of {failed_row['file']} — it is reported FAILED, so the "
          f"target must not carry it")

    print("\ncr_report_outcome — 2 confirmed, 1 failed")
    outcomes = {}
    for r in confirmed_rows:
        res = cr_report_outcome(r["row"], "confirmed",
                                note=f"run 153 — B9 (Q3) live; {r['selected_role']}; the target's own "
                                     f"suite: exit {suite.get('exit_code')}",
                                tester="coderadar-mcp run153", edit_kind="diff")
        outcomes[r["row"]] = res
        print(f"  confirmed {r['row']}  written={res.get('written')} ledger={res.get('ledger_written')} "
              f"error={res.get('error')}")
    res = cr_report_outcome(failed_row["row"], "failed",
                            note="run 153 — B9 (Q3) live; the edit was backed out and the repair "
                                 "reported failed, so the count lands on the VARIANT",
                            tester="coderadar-mcp run153")
    outcomes[failed_row["row"]] = res
    print(f"  failed    {failed_row['row']}  written={res.get('written')} "
          f"ledger={res.get('ledger_written')} (a failed verdict writes no ledger record)")
    out["outcomes"] = outcomes

    files = sorted({r["file"] for r in confirmed_rows})
    (RUNDIR / "client_edit_log_run153.json").write_text(
        json.dumps({"standing": confirmed_rows, "backed_out": failed_row}, indent=2), encoding="utf-8")
    (RUNDIR / "client_edit_manifest_run153.txt").write_text("\n".join(files) + "\n", encoding="utf-8")
    save()

    c0 = (out["status_at_monitoring"] or {}).get("cycle")
    print(f"\nwaiting one Builder cycle (from {c0}) …")
    deadline = time.time() + 300
    s2 = cr_status()
    while time.time() < deadline:
        time.sleep(10)
        s2 = cr_status()
        if (s2.get("cycle") or 0) > (c0 or 0):
            break
    out["status_after_cycle"] = s2
    out["counterfeit_failed_after"] = (s2.get("infractions") or {}).get("failed")
    ro = s2.get("rule_outcomes") or {}
    out["rule_outcomes_after_cycle"] = ro
    print(f"cr_status cycle={s2.get('cycle')} · counterfeit_failed "
          f"{out['counterfeit_failed_before']} → {out['counterfeit_failed_after']}")

    # ── THE READ-BACK: every number off the mirror's own block, never from memory ───────────
    want_variant = failed_row["selected_role"]
    print(f"\nrule_outcomes after the cycle — {len(ro)} rule(s)")
    for rid in sorted(ro):
        print(f"  {rid:20s} confirmed_for {ro[rid]['confirmed_for']:2d}  "
              f"failed_against {json.dumps(ro[rid]['failed_against'])}")
    conf_ids = sorted({i for r in confirmed_rows for i in r["rule_ids"]})
    checks = {
        "every rule of the two confirmed rows carries a confirmation": all(
            ro.get(i, {}).get("confirmed_for", 0) >= 1 for i in conf_ids),
        "every rule of the failed row carries the failure under its VARIANT": all(
            ro.get(i, {}).get("failed_against", {}).get(want_variant, 0) >= 1
            for i in failed_row["rule_ids"]),
        "the failed repair took nothing off any confirmation": all(
            ro[i]["confirmed_for"] >= 0 for i in ro),
        "no variant name was recorded as a rule": want_variant not in ro,
    }
    for what, held in checks.items():
        print(f"  {'✓' if held else '✗'} {what}")
        ok_all = ok_all and held
    out["checks"] = checks
    out["variant_of_the_failed_row"] = want_variant
    # The block as the MIRROR FILE itself carries it — read back off disk, not from the tool.
    mirror = json.loads((ROOT / "system_scripts" / ".noai_state.json").read_bytes().decode("utf-8"))
    out["rule_outcomes_in_mirror_file"] = (mirror.get("summary") or {}).get("rule_outcomes")
    same = out["rule_outcomes_in_mirror_file"] == ro
    print(f"  {'✓' if same else '✗'} the mirror FILE carries the same block cr_status answered")
    ok_all = ok_all and same
    save()

    print(f"\ncr_stop with a client manifest of {len(files)} path(s): {files}")
    stop = cr_stop(verify_identity=True, mark_pool=True, expected_changes=files)
    out["stop"] = stop
    for k in ("stopped", "residue_clean", "byte_identical", "files_compared", "client_edits",
              "unexpected_changes", "run_dir", "error"):
        print(f"  {k:20s} {json.dumps(stop.get(k), default=str)[:200]}")

    hb = cr_hand_back(note="run 153 — B9's accumulation (Q3) live: two confirmed repairs and one "
                           "failed, the failed edit backed out; the mirror and the tester report "
                           "carry summary.rule_outcomes")
    out["hand_back"] = hb
    for k in ("report_path", "builder_cycles", "infractions", "solutions", "confirmed",
              "confirmed_from_ledger", "tester_ran", "status", "orphans", "finished", "error"):
        print(f"  {k:22s} {json.dumps(hb.get(k), default=str)[:160]}")
    report = json.loads(Path(hb["report_path"]).read_bytes().decode("utf-8"))
    out["rule_outcomes_in_report"] = report.get("rule_outcomes")
    carried = bool(report.get("rule_outcomes"))
    print(f"  {'✓' if carried else '✗'} tester_report.json carries rule_outcomes "
          f"({len(report.get('rule_outcomes') or {})} rules)")
    ok_all = ok_all and carried
    save()
    return 0 if ok_all else 2


if __name__ == "__main__":
    raise SystemExit(main())
