"""tail_evidence.py — the long tail (calibrator, 2026-09-06): every DECIDING family with evidence.kind 'none (pre-calibration)'
gets its precision row from the newest dumps written into the table as evidence.kind 'ruling' with note 'rare on honest code'
when it fires on <= RARE_MAX calibration libraries — the reason it stays deciding is the evidence itself, no corpus needed.
Families firing on more libraries are LEFT for a slice (listed). usage: tail_evidence.py CAL [--rare-max 2] [--apply]"""
from __future__ import annotations
import argparse, collections, json, sys
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, TABLE, load_table, table_dispositions, deciding_ids, recomputed_failed, load_dump, dump_libs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--rare-max", type=int, default=2); ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv); cal = Path(a.cal).resolve(); table = load_table(); disp = table_dispositions(table)
    libs = [l for l in dump_libs(cal) if not (l.startswith("chets_shirt") or l == "mels_offer")]
    P = collections.defaultdict(lambda: {"libs": set(), "anywhere": 0, "alone": 0, "in_tests": 0})
    for lib in libs:
        for r in load_dump(cal, lib)["rows"]:
            if r.get("species") == "test":
                for i in r["all_ids"]: P[i]["in_tests"] += 1
                continue
            if not recomputed_failed(r, disp): continue
            dd = deciding_ids(r, disp)
            for i in dd:
                P[i]["libs"].add(lib); P[i]["anywhere"] += 1
                if len(dd) == 1: P[i]["alone"] += 1
    rare, left, dormant = [], [], set(table.get("_dormant") or {})
    for rid, row in table["families"].items():
        if row["disposition"] != "deciding" or row.get("class") == "strict" or row["evidence"]["kind"] != "none (pre-calibration)" or rid in dormant: continue
        n = len(P[rid]["libs"])
        (rare if n <= a.rare_max else left).append((rid, n, P[rid]["anywhere"], P[rid]["alone"]))
    print(f"deciding families without evidence: {len(rare) + len(left)} — rare (<= {a.rare_max} of {len(libs)} libs): {len(rare)}; left for a slice: {len(left)}")
    print("left for a slice:", ", ".join(f"{r}({n})" for r, n, *_ in sorted(left, key=lambda x: -x[1])))
    if a.apply:
        today = date.today().isoformat()
        for rid, n, anyw, alone in rare:
            row = table["families"][rid]; row["evidence"]["kind"] = "ruling"; row["by"] = "calibration"; row["dated"] = today
            row["evidence"]["precision"] = {"libs_hit": sorted(P[rid]["libs"]), "libs_total": len(libs), "rows": {"first": 0, "anywhere": anyw, "alone": alone, "in_tests": P[rid]["in_tests"]}}
            row["evidence"]["sources"] = sorted(set(row["evidence"].get("sources", []) + [str(cal.relative_to(ROOT))]))
            row["note"] = (row["note"] + "; " if row["note"] else "") + f"long tail {today}: fires on {n} of {len(libs)} honest libraries ({anyw} rows) — rare on honest code, stays deciding; no plant yet (a plant is owed before any context ruling)"
        TABLE.write_text(json.dumps(table, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"applied: {len(rare)} rows now carry their precision evidence")
    (cal / "TAIL_EVIDENCE.md").write_text("# Long tail — deciding families without evidence\n\n| family | libs hit | rows | alone | status |\n|---|---|---|---|---|\n" +
        "\n".join(f"| {r} | {n}/{len(libs)} | {w} | {al} | {'rare → deciding by evidence' if n <= a.rare_max else 'LEFT for a slice'} |" for r, n, w, al in sorted(rare + left, key=lambda x: (-x[1], x[0]))) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
