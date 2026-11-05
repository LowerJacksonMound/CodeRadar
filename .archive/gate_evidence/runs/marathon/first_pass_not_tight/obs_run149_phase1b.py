#!/usr/bin/env python3
"""obs_run149_phase1b.py — RUN 149 `marathon`, locating the twelve in the EDITED tree.

Run 141's row ids carry run 141's line numbers. This target is T6's tree AFTER the 63 other rows
were applied, so every function below a repaired span has moved. The twelve are found here by
FILE + FUNCTION, which is what the owner's ruling names them by; the line is whatever the tree says.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.read_tools import cr_infractions, cr_row   # noqa: E402

RUNDIR = ROOT / ".archive" / "runs" / "marathon"
WANT = [
    (21, "colorama/ansi.py", "set_title"),
    (30, "colorama/repair_plant_branches.py", "stamp"),
    (33, "colorama/repair_plant_chains.py", "stamp"),
    (35, "colorama/repair_plant_checks.py", "push"),
    (53, "colorama/repair_plant_noop.py", "tally"),
    (57, "colorama/repair_plant_quietly.py", "hushed"),
    (61, "colorama/repair_plant_shape.py", "pick_label"),
    (70, "colorama/repair_plant_typos.py", "code_word"),
    (71, "colorama/repair_plant_typos.py", "mark_twice"),
    (73, "colorama/win32.py", "GetConsoleScreenBufferInfo"),
    (74, "colorama/win32.py", "FillConsoleOutputCharacter"),
    (75, "colorama/winterm.py", "enable_vt_processing"),
]


def main() -> int:
    # every row the mirror holds, by file
    seen: dict[str, list[dict]] = {}
    page = 1
    while True:
        res = cr_infractions(page=page, page_size=400)
        for r in res.get("rows") or []:
            seen.setdefault(r.get("file") or "", []).append(r)
        if page >= (res.get("pages") or 1):
            break
        page += 1
    total = sum(len(v) for v in seen.values())
    print(f"rows in the mirror: {total} over {len(seen)} files")

    out = {}
    for t6, rel, fn in WANT:
        hits = [r for r in seen.get(rel, []) if r.get("function") == fn]
        print(f"\n#{t6:<3} {rel}::{fn}  -> {len(hits)} row(s) in the mirror")
        if not hits:
            # is the file even scanned?
            print(f"     file rows: {[ (r.get('function'), r.get('line')) for r in seen.get(rel, []) ]}")
            out[f"{t6}"] = {"file": rel, "function": fn, "row_id": None, "detail": None}
            continue
        rid = hits[0]["id"]
        r = cr_row(rid)
        row = r.get("row") or {}
        d = row.get("decision") or {}
        det = {
            "row_id": rid, "rule_ids": row.get("rule_ids"),
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
        out[f"{t6}"] = {"file": rel, "function": fn, **det}
        print(f"     id={rid}")
        print(f"     rules={det['rule_ids']}")
        print(f"     kind={det['solution_kind']} pick={det['pick_role']} "
              f"cands={det['candidates_considered']} withheld_by={det['withheld_by']} "
              f"no_fix_status={det['no_fix_status']}")
        if det["why"]:
            print(f"     why: {str(det['why'])[:300]}")
        if det["after_code"]:
            print(f"     after_code:\n{chr(10).join('       | ' + l for l in det['after_code'].splitlines())}")
    (RUNDIR / "phase1b_twelve.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(f"\nwritten {RUNDIR / 'phase1b_twelve.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
