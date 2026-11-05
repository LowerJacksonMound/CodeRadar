#!/usr/bin/env python3
"""obs_run149_phase1.py — RUN 149 `marathon` (S5-5b, the MERGED proof).

Target: a fresh copy of T6's EDITED tree (43 CORRECT rewrites + 20 rendered shapes applied, the
twelve WRONG rows restored to their before-bytes by S5-0's back-out).

The claim: with G0 and the seven fixes merged, every one of T6's twelve WRONG repairs is now either
NOT OFFERED, WITHHELD with a reason, or REPLACED by a behaviour-preserving repair the target's own
suite accepts.

    cr_watch → cr_status → cr_infractions(withheld=True) → cr_row ×12 → cr_apply ×n → JSON
"""
import json
import sys
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.session_tools import cr_watch                          # noqa: E402
from coderadar_mcp.read_tools import cr_status, cr_infractions, cr_row    # noqa: E402
from coderadar_mcp.write_tools import cr_apply                            # noqa: E402

TARGET = "/Users/dev/Desktop/marathon"
RUNDIR = ROOT / ".archive" / "runs" / "marathon"
OUT = RUNDIR / "phase1_rows.json"
LOG = ROOT / ".archive" / "runs" / "between_the_wheels" / "client_edit_log_after_T6.json"


def main() -> int:
    log = json.loads(LOG.read_text(encoding="utf-8"))
    twelve = {r["row"]: r for r in log if r.get("t6_verdict") == "WRONG"}

    out = {"target": TARGET, "watch": None, "status": None, "withheld": None,
           "twelve": {}, "apply": {}}
    out["watch"] = cr_watch(TARGET)
    OUT.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    w = out["watch"]
    print(f"cr_watch started={w.get('started')} phase={w.get('phase')} "
          f"repo_id={w.get('repo_id')} gates={w.get('gates')} error={w.get('error')}")
    if not w.get("started"):
        return 1

    out["status"] = cr_status()
    s = out["status"]
    print(f"cr_status cycle={s.get('cycle')} finished={s.get('finished')} "
          f"({s.get('finished_source')}) · {s.get('finished_reason')}")
    print(f"  infractions {json.dumps(s.get('infractions'))}")

    out["withheld"] = cr_infractions(withheld=True, page_size=400)
    print(f"cr_infractions(withheld) total={out['withheld'].get('total')}")

    for rid, rec in sorted(twelve.items(), key=lambda kv: kv[1]["t6_row"]):
        r = cr_row(rid)
        row = r.get("row") or {}
        d = row.get("decision") or {}
        rec_out = {
            "t6_row": rec["t6_row"], "role_in_141": rec["selected_role"],
            "error": r.get("error"),
            "withheld_by": row.get("withheld_by"), "withheld_reason": row.get("withheld_reason"),
            "gate_withheld": row.get("gate_withheld"),
            "pick_role": d.get("pick_role"), "why": d.get("why"),
            "solution_kind": row.get("solution_kind"),
            "after_code": row.get("after_code"), "digest": row.get("digest"),
            "no_fix_status": row.get("no_fix_status"),
            "candidates_considered": row.get("candidates_considered"),
            "observations": row.get("observations"),
            "replace_span": row.get("replace_span"),
        }
        out["twelve"][rid] = rec_out
        print(f"\n#{rec['t6_row']:<3} {rid}")
        print(f"     error={rec_out['error']} withheld_by={rec_out['withheld_by']} "
              f"kind={rec_out['solution_kind']} cands={rec_out['candidates_considered']}")
        print(f"     pick={rec_out['pick_role']} no_fix_status={rec_out['no_fix_status']}")
        if rec_out["why"]:
            print(f"     why: {str(rec_out['why'])[:220]}")

    # cr_apply on every row of the twelve that has a repair
    for rid, v in out["twelve"].items():
        if v["error"] or not v["pick_role"]:
            continue
        p = cr_apply(rid)
        out["apply"][rid] = p
        print(f"\ncr_apply {rid}: kind={p.get('kind')} applies_cleanly={p.get('applies_cleanly')} "
              f"span={p.get('replace_span')} error={p.get('error')}")

    OUT.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(f"\nphase 1 written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
