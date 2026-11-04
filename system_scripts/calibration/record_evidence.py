"""record_evidence.py — write evidence-decided outcomes into the table WITHOUT a ruling (owner 2026-09-06: "if it only reads,
what's left to rule on"). A family the fit left 'below k' or 'refused (loses a plant)' stays DECIDING by the evidence itself;
its row gets evidence.kind 'calibrated' (bar: libs_hit, plants, labels present) or 'ruling' (bar not met) with the fit's
reason. Families the fit ADMITTED are listed for the owner and left untouched — a context ruling is the owner's.
usage: record_evidence.py CAL --fit fit_k7.json [--apply]"""
from __future__ import annotations
import argparse, json, sys
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, TABLE, load_table


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--fit", required=True); ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv); cal = Path(a.cal).resolve(); fit = json.load(open(cal / a.fit)); table = load_table(); fams = table["families"]
    ev = {e["family"]: e for e in json.load(open(cal / "evidence.json"))} if (cal / "evidence.json").exists() else {}
    today = date.today().isoformat(); decided, for_owner = [], []
    for fam, r in fit["families"].items():
        st = r["status"]
        if st.startswith("admitted"):
            for_owner.append((fam, r["why"])); continue
        e = ev.get(fam, {}); lab = e.get("labels", {"n": 0, "counterfeit": 0}); pa, pb = e.get("plants_A", {"planted": 0}), e.get("plants_B", {"planted": 0})
        bar_ok = bool(e.get("libs_hit") is not None) and (pa.get("planted") or pb.get("planted")) and lab.get("n", 0) >= 5
        if fams.get(fam, {}).get("disposition") == "context":   # F-REC-CTX1 (2026-09-07): a context ruling is the owner's — a below-k / refused fit never demotes it
            print(f"  {fam}: CONTEXT stands (owner ruling) — fit reads {st}; not demoted"); continue
        decided.append((fam, st, r["why"], "calibrated" if bar_ok else "ruling"))
        if a.apply:
            row = fams[fam]; row["disposition"] = "deciding"; row["by"] = "calibration"; row["dated"] = today
            row["evidence"]["kind"] = "calibrated" if bar_ok else "ruling"
            row["evidence"]["precision"] = {"libs_hit": e.get("fires_on", []), "libs_total": e.get("libs_total", 0), "rows": {"first": e.get("rows_first", 0), "anywhere": e.get("rows_anywhere", 0), "alone": e.get("rows_alone", 0), "in_tests": e.get("rows_in_tests", 0)}}
            row["evidence"]["plants"] = {"planted": pa.get("planted", 0) + pb.get("planted", 0), "caught_by_id": pa.get("caught_by_id", 0) + pb.get("caught_by_id", 0), "caught_in_substance": pa.get("caught_in_substance", 0) + pb.get("caught_in_substance", 0), "held_out": pb.get("planted", 0)}
            row["evidence"]["sources"] = sorted(set(row["evidence"].get("sources", []) + [str(cal.relative_to(ROOT))]))
            row["note"] = f"deciding by evidence {today} ({st}): {r['why']}"
    if a.apply and decided:
        TABLE.write_text(json.dumps(table, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    for fam, st, why, kind in decided: print(f"  {fam}: DECIDING by evidence ({st}; kind {kind}) — {why[:110]}")
    for fam, why in for_owner: print(f"  {fam}: ADMITTED — the owner rules (context candidate): {why[:110]}")
    print(f"{'applied' if a.apply else 'report'}: {len(decided)} decided by evidence, {len(for_owner)} for the owner")
    return 0


if __name__ == "__main__":
    sys.exit(main())
