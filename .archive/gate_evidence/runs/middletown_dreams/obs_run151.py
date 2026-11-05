#!/usr/bin/env python3
"""obs_run151.py — RUN 151 `middletown_dreams`: FIX_65 (I-117) LIVE on a planted module, applied and tested.

The claim: with the module as purity evidence, a dead store whose callee is the module's SOLE pure
top-level def gets the delete offered and passed by G0 (`sole`); a helper name bound twice at the top
level (`shadowed`) and a helper that prints (`loud`) keep the call. Run 150 showed colorama has no such
case (its two dead-store callees are Win32 handles), so this run adds `colorama/repair_plant_evidence.py`
— three functions, one dead store each — to a fresh copy of T6's edited target, and then BE THE CLIENT:
apply the Ranker's pick on each, run the suite and the entry, report the outcomes.

ONE TIGHT LOOP, handlers in-process (as runs 144–150):
    cr_watch → cr_status → cr_infractions → cr_row ×3 → the A/B offline → cr_apply ×3 → the client edits
    → cr_run_module(suite, entry) → cr_report_outcome ×3 → cr_stop(expected_changes) → cr_hand_back
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
from no_aivalidator.repair_generators import REGISTRY, candidates_of, gate_note  # noqa: E402

TARGET = Path("/Users/dev/Desktop/middletown_dreams")
RUNDIR = ROOT / ".archive" / "runs" / "middletown_dreams"
PLANT = "colorama/repair_plant_evidence.py"
# (function, the variants candidates_of must offer for NAI-010 with the module in hand)
WANT = [("sole", ["drop_assignment", "keep_call_effect"]), ("shadowed", ["keep_call_effect"]), ("loud", ["keep_call_effect"])]
RULES = ("NAI-031", "NAI-010", "NAI-147")
DELETES = {"drop_store", "drop_assignment"}

out: dict = {}


def save():
    (RUNDIR / "run151.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")


def span_text(rel: str, span: str) -> str:
    _, _, tail = span.rpartition(":L")
    a, _, b = tail.partition("-L")
    lines = (TARGET / rel).read_text(encoding="utf-8").splitlines(keepends=True)
    return "".join(lines[int(a) - 1:int(b)])


def offered(rid: str, before: str, module_src: str) -> dict:
    """{variant: gate check or ""} — what candidates_of offers for this rule on this span."""
    g = REGISTRY.get(rid)
    if g is None or g.fn is None:
        return {}
    return {str(o[0]).split(":", 1)[-1]: gate_note(o)[0] for o in candidates_of(g, before, module_src=module_src)}


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


def main() -> int:
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
          f"\n  infractions {json.dumps(s.get('infractions'))}")
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

    # ── THE THREE, through cr_row, then the A/B ────────────────────────────────────────────
    plant_rows = {r.get("function"): r for r in rows if r.get("file") == PLANT}
    print(f"\nTHE PLANT {PLANT}: {sorted(plant_rows)} ({len(plant_rows)} row(s))")
    module_src = (TARGET / PLANT).read_text(encoding="utf-8")
    three: dict = {}
    ok_all = True
    for fn, want in WANT:
        r = plant_rows.get(fn)
        if r is None:
            three[fn] = {"as_seen": "no row", "ok": False}; ok_all = False
            print(f"  {fn}: NO ROW"); continue
        row = (cr_row(r["id"]).get("row") or {})
        d = row.get("decision") or {}
        span = row.get("replace_span") or ""
        before = span_text(PLANT, span)
        ab = {rule: {"span_only": offered(rule, before, ""), "with_module": offered(rule, before, module_src)}
              for rule in [x for x in (row.get("rule_ids") or []) if x in RULES]}
        got = sorted(ab.get("NAI-010", {}).get("with_module", {}))
        ok = got == sorted(want)
        ok_all = ok_all and ok
        three[fn] = {"row_id": r["id"], "rule_ids": row.get("rule_ids"), "pick_role": d.get("pick_role"),
                     "why": d.get("why"), "withheld_by": row.get("withheld_by"),
                     "candidates_considered": row.get("candidates_considered"), "replace_span": span,
                     "before": before, "ab": ab, "want": want, "got": got, "ok": ok}
        print(f"  {'✓' if ok else '✗'} {fn} {r['id']}\n       pick {d.get('pick_role')!r} (cands={row.get('candidates_considered')})"
              f"{' · withheld ' + str(row.get('withheld_by')) if row.get('withheld_by') else ''}")
        for rule, v in ab.items():
            flag = "  ← the module was decisive" if set(v["with_module"]) - set(v["span_only"]) else ""
            print(f"       {rule}: span-only {sorted(v['span_only'])} · with module {sorted(v['with_module'])}{flag}")
    out["three"] = three
    out["three_ok"] = ok_all
    save()

    # ── BE THE CLIENT: cr_apply the Ranker's pick on each, then edit the working tree ───────
    to_apply = [fn for fn, v in three.items() if v.get("row_id") and v.get("pick_role")]
    print(f"\ncr_apply on {len(to_apply)} rows: {to_apply}")
    payloads = {}
    for fn in to_apply:
        p = cr_apply(three[fn]["row_id"])
        payloads[fn] = p
        print(f"  {fn:9} kind={p.get('kind')} applies_cleanly={p.get('applies_cleanly')} "
              f"role={p.get('selected_role')} span={p.get('replace_span')} error={p.get('error')}")
        assert p.get("kind") == "diff" and p.get("applies_cleanly") is True, (fn, p.get("error"))
    out["apply_payloads"] = payloads
    log = []
    path = TARGET / PLANT
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for fn, p in sorted(payloads.items(), key=lambda kp: parse_span(kp[1]["replace_span"])[0], reverse=True):
        a, b = parse_span(p["replace_span"])
        seg = lines[a - 1:b]
        aft = apply_hunks(p["diff"], seg)
        lines = lines[:a - 1] + aft + lines[b:]
        log.append({"function": fn, "row": p["row"], "file": PLANT, "replace_span": p["replace_span"],
                    "kind": p["kind"], "selected_role": p["selected_role"], "digest": p["digest"],
                    "before": "".join(seg), "after": "".join(aft)})
    path.write_text("".join(lines), encoding="utf-8")
    log.sort(key=lambda r: parse_span(r["replace_span"])[0])
    out["client_edits"] = log
    files = [PLANT] if log else []
    (RUNDIR / "client_edit_log_run151.json").write_text(json.dumps(log, indent=2))
    (RUNDIR / "client_edit_manifest_run151.txt").write_text("\n".join(files) + "\n")
    print(f"\nCLIENT APPLIED {len(log)} rows over {len(files)} file(s)")
    for r in log:
        print(f"  {r['function']:9} {r['replace_span']} [{r['selected_role']}]")

    # ── run the entry to light the wiring, run the suite to test the repairs ────────────────
    suite = cr_run_module("pytest", args=["colorama/tests", "-q"], as_module=True)
    out["suite"] = suite
    tail = (suite.get("stdout") or "").strip().splitlines()[-1:] or [""]
    print(f"\ncr_run_module SUITE  exit={suite.get('exit_code')} in {suite.get('duration_s')}s\n    {tail[0]}")
    plant_run = cr_run_module(PLANT, as_module=False)
    out["plant_run"] = plant_run
    print(f"cr_run_module PLANT  exit={plant_run.get('exit_code')} (the edited module imports and runs)")
    entry = cr_run_module("demos/demo01.py", as_module=False)
    out["entry"] = entry
    print(f"cr_run_module ENTRY  exit={entry.get('exit_code')} in {entry.get('duration_s')}s")
    wi = cr_wiring()
    out["wiring"] = wi
    print(f"cr_wiring {len(wi.get('nodes') or [])} nodes · {len(wi.get('edges') or [])} edges")

    print("\ncr_report_outcome(confirmed) on every applied row")
    outcomes = {}
    for r in log:
        res = cr_report_outcome(r["row"], "confirmed",
                                note=f"run 151 — FIX_65 (the module as purity evidence) on the planted module; "
                                     f"{r['function']} {r['selected_role']}; suite exit {suite.get('exit_code')}",
                                tester="coderadar-mcp run151", edit_kind="diff")
        outcomes[r["row"]] = res
        print(f"  {r['function']:9} written={res.get('written')} error={res.get('error')}")
    out["outcomes"] = outcomes
    save()

    c0 = (out["status_at_monitoring"] or {}).get("cycle")
    print(f"\nwaiting one Builder cycle (from {c0}) …")
    deadline = time.time() + 240
    s2 = cr_status()
    while time.time() < deadline:
        time.sleep(10)
        s2 = cr_status()
        if (s2.get("cycle") or 0) > (c0 or 0):
            break
    out["status_after_cycle"] = s2
    inf = s2.get("infractions") or {}
    out["counterfeit_failed_after"] = inf.get("failed")
    print(f"cr_status cycle={s2.get('cycle')} · counterfeit_failed {out['counterfeit_failed_before']} → {out['counterfeit_failed_after']}")
    save()

    print(f"\ncr_stop with a client manifest of {len(files)} path(s)")
    stop = cr_stop(verify_identity=True, mark_pool=True, expected_changes=files)
    out["stop"] = stop
    for k in ("stopped", "residue_clean", "byte_identical", "files_compared", "client_edits",
              "unexpected_changes", "run_dir", "error"):
        print(f"  {k:20s} {json.dumps(stop.get(k), default=str)[:200]}")

    hb = cr_hand_back(note="run 151 — FIX_65 live on a planted module (three dead stores: the module's sole pure "
                           "helper, a helper bound twice, a helper that prints); the client applied the Ranker's "
                           "pick on each and ran the suite and the entry")
    out["hand_back"] = hb
    for k in ("report_path", "builder_cycles", "infractions", "solutions", "confirmed",
              "confirmed_from_ledger", "tester_ran", "status", "orphans", "finished", "error"):
        print(f"  {k:22s} {json.dumps(hb.get(k), default=str)[:160]}")
    save()
    return 0 if ok_all else 2


if __name__ == "__main__":
    raise SystemExit(main())
