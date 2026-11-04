"""precision_table.py — B2 aggregation (calibrator, 2026-09-06): PRECISION_TABLE.md + families.json for a calibration dir from
the v2 dumps (raw dispositions), plus the per-family delta against a previous calibration dir (v1 rows_detail or v2 rows).
usage: precision_table.py CAL [--prev ARCHIVE/health/calibration_20260906]"""
from __future__ import annotations
import argparse, collections, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, load_table, table_dispositions, deciding_ids, recomputed_failed


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--prev", default="")
    a = ap.parse_args(argv); cal = Path(a.cal); disp = table_dispositions(load_table())
    timings = json.load(open(cal / "precision" / "timings.json")) if (cal / "precision" / "timings.json").exists() else {}
    per = []; fam = collections.defaultdict(lambda: {"libs": set(), "first": 0, "anywhere": 0, "alone": 0, "in_tests": 0, "examples": []})
    for f in sorted((cal / "precision").glob("*.json")):
        d = json.load(open(f))
        if not (isinstance(d, dict) and "lib" in d and "rows" in d): continue
        lib = d["lib"]; rows = d["rows"]; honest = [r for r in rows if r.get("species") != "test"]; failed = [r for r in honest if not r["passed"]]
        per.append({"lib": lib, "files": d["files"], "rows": len(rows), "test_rows": len(rows) - len(honest), "failed": len(failed), "rate": len(failed) / max(len(honest), 1), "seconds": timings.get(lib, {}).get("seconds")})
        for r in rows:
            if r.get("species") == "test":
                for i in r["all_ids"]: fam[i]["in_tests"] += 1
                continue
            if r["passed"]: continue
            dd = deciding_ids(r, disp)
            for i in dd:
                x = fam[i]; x["libs"].add(lib); x["anywhere"] += 1
                if len(dd) == 1: x["alone"] += 1
                if len(x["examples"]) < 3: x["examples"].append(f"{lib}/{Path(r['file']).name}::{r['function']}")
            if r.get("first"): fam[r["first"]]["first"] += 1
    for lib, t in timings.items():
        if t.get("timed_out"): per.append({"lib": lib, "files": None, "rows": None, "test_rows": None, "failed": None, "rate": None, "seconds": t["seconds"], "timed_out": True})
    N = sum(1 for p in per if not p.get("timed_out")); tot_rows = sum(p["rows"] - p["test_rows"] for p in per if p["rows"]); tot_failed = sum(p["failed"] for p in per if p["failed"] is not None)
    L = [f"# Precision — {cal.name} ({N} libraries, {tot_rows} honest rows, {tot_failed} failed = {100 * tot_failed / max(tot_rows, 1):.0f} %; test-species rows withheld and excluded)", "",
         "| family | libs hit / N | first | anywhere | alone | in tests (withheld) | examples |", "|---|---|---|---|---|---|---|"]
    for rid, x in sorted(fam.items(), key=lambda kv: -kv[1]["anywhere"]):
        if not x["anywhere"] and not x["in_tests"]: continue
        L.append(f"| {rid} | {len(x['libs'])}/{N} | {x['first']} | {x['anywhere']} | {x['alone']} | {x['in_tests']} | {'; '.join('`' + e + '`' for e in x['examples'])} |")
    L += ["", "## Per library", "", "| library | files | rows | test rows (withheld) | failed | rate | seconds |", "|---|---|---|---|---|---|---|"]
    for p in per:
        if p.get("timed_out"): L.append(f"| {p['lib']} | — | — | — | TIMED OUT | — | {p['seconds']} |")
        else: L.append(f"| {p['lib']} | {p['files']} | {p['rows']} | {p['test_rows']} | {p['failed']} | {100 * p['rate']:.0f} % | {p['seconds']} |")
    if a.prev:
        prev = Path(a.prev); po = collections.Counter(); pn = collections.Counter(); libs = 0; of = nf = 0
        for f in sorted((cal / "precision").glob("*.json")):
            d = json.load(open(f))
            if not (isinstance(d, dict) and "lib" in d and "rows" in d): continue
            lib = d["lib"]; q = prev / f"{lib}.json"
            if not q.exists(): q = prev / "precision" / f"{lib}.json"
            if not q.exists(): continue
            o = json.load(open(q)); libs += 1
            orows = o.get("rows_detail") or o.get("rows") or []
            for r in orows:
                if r["passed"]: continue
                of += 1; po.update(r.get("deciding_anywhere") if "deciding_anywhere" in r else deciding_ids(r, disp))
            for r in d["rows"]:
                if r["passed"] or r.get("species") == "test": continue
                nf += 1; pn.update(deciding_ids(r, disp))
        L += ["", f"## Delta vs {prev.name} ({libs} common libraries; failed rows {of} → {nf}, {nf - of:+d})", "", "| family | before | after | delta |", "|---|---|---|---|"]
        for k in sorted(set(po) | set(pn), key=lambda k: -abs(pn[k] - po[k])):
            if po[k] != pn[k]: L.append(f"| {k} | {po[k]} | {pn[k]} | {pn[k] - po[k]:+d} |")
    (cal / "PRECISION_TABLE.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    json.dump({rid: {**x, "libs": sorted(x["libs"])} for rid, x in fam.items()}, open(cal / "families.json", "w"), indent=1, sort_keys=True)
    print(L[0]); print(f"written {cal / 'PRECISION_TABLE.md'} and families.json ({len(fam)} families)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
