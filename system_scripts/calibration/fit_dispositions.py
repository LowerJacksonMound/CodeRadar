"""fit_dispositions.py — the FIT (calibrator A7 / B3, 2026-09-06). One parameter k. Greedy admission of a slice's
families to CONTEXT: a family is admitted when it is CONFIRMED on >= k calibration libraries — a repo counts only when
the family has labeled rows there and every one of them is honest (owner 2026-09-06: "confirmation should be on a
repo-by-repo basis"; a repo merely hit counts for nothing; no family is pre-marked) — AND admitting it loses no
archived / corpus-A plant AND its labeled sample (labels/<family>.json) shows no counterfeit (any instrument-gap parks it).
Strict ids are never admitted except in the strict slice with the owner's note. No manifest with held_out: true
is ever loaded here (hard assert). The held-out score is a different script; nothing here targets it.

usage: fit_dispositions.py CAL --k 7 --cal-libs a,b,c --plants archived,corpus_A --families NAI-142,NAI-158 [--sweep 5,6,7,8,9]
       [--strict-slice --owner-note "..."]   → CAL/fit_k<k>.json
"""
from __future__ import annotations
import argparse, collections, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import (ROOT, load_table, table_dispositions, deciding_ids, recomputed_failed, consistency, load_dump, verify_rows, manifests, target_rows)
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("verify_manifest", ROOT / "system_scripts" / "verify_manifest.py"); vm = _ilu.module_from_spec(_spec); _spec.loader.exec_module(vm)  # type: ignore


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--k", type=int, required=True)
    ap.add_argument("--cal-libs", required=True); ap.add_argument("--plants", default="archived,corpus_A"); ap.add_argument("--families", required=True)
    ap.add_argument("--sweep", default=""); ap.add_argument("--strict-slice", action="store_true"); ap.add_argument("--owner-note", default="")
    a = ap.parse_args(argv)
    cal = Path(a.cal); table = load_table(); disp = table_dispositions(table)
    strict = {rid for rid, r in table["families"].items() if r.get("class") == "strict"}
    libs = [x for x in a.cal_libs.split(",") if x]; fams = [x for x in a.families.split(",") if x]
    dumps = {lib: load_dump(cal, lib) for lib in libs}
    incons = {lib: len(consistency(d["rows"], disp)) for lib, d in dumps.items()}
    # plants
    mans = []
    for kind in a.plants.split(","):
        mans += manifests(kind)
    for m in mans:
        assert not m.get("held_out"), f"REFUSED: manifest {m['_dir']} is held out — the fit never sees it"
    prow = {}
    for m in mans:
        t = vm.resolve_target(m["target"])   # retired targets may live under ~/Desktop/RUN_AGAINST_DIRS_*/
        if t.exists(): prow[m["_dir"]] = target_rows(t)
    absent = [m["_dir"] for m in mans if m["_dir"] not in prow]
    masked: dict[str, list] = {}   # family → per plant, the OTHER deciding ids on its row (a masked plant cannot detect its family's loss)
    def plant_state(overrides):
        st = {}
        for m in mans:
            if m["_dir"] not in prow: continue
            r = vm.check(m, verify_rows(prow[m["_dir"]], disp, overrides))
            for p in r["plants"]:
                st[(m["_dir"], p["file"], p["line"])] = (p["caught_in_substance"], p["caught_by_id"], p["family"], p["what"])
                if not overrides:
                    others = [i for i in p["row_deciding_ids"] if i not in set(p["accept_with_aliases"])]
                    masked.setdefault(p["family"], []).append({"target": m["_dir"], "file": p["file"], "line": p["line"], "masked_by": others})
            for t in r.get("honest_twins", []):
                st[(m["_dir"], "twin", t["file"], t["line"])] = (t["passed"], t["family"], t["what"])
        return st
    base = plant_state({})
    labels = {}
    for f in fams:
        p = cal / "labels" / f"{f}.json"
        if not p.exists():   # a re-slice may carry labels over from the previous slice dir
            for prev in sorted(cal.parent.glob("calibration_*/labels/" + f + ".json")):
                p = prev
        if p.exists():
            lab = json.load(open(p))
            # a label counts only where the family STILL fires on that row under this stamp (rows the fix cleared drop out)
            live_rows = {(lib, r["file"], r["line"], r["function"]) for lib, d in dumps.items() for r in d["rows"] if f in deciding_ids(r, disp)}
            kept = [x for x in lab.get("labels", []) if (x["lib"], x["file"], x["line"], x["function"]) in live_rows]
            labels[f] = {**lab, "labels": kept, "carried_from": str(p), "dropped_no_longer_firing": len(lab.get("labels", [])) - len(kept)}
    def fires_on(f, overrides):
        out = {}
        for lib, d in dumps.items():
            n = sum(1 for r in d["rows"] if recomputed_failed(r, disp, overrides) and f in deciding_ids(r, disp, overrides))
            if n: out[lib] = n
        return out
    admitted: dict[str, str] = {}; report = {}
    def confirmed_repos(f):
        """Repos where the family is CONFIRMED — at least one labeled row there and every one of them honest (owner
        2026-09-06: confirmation is repo by repo; a repo merely hit counts for nothing). Returns (confirmed, labeled)."""
        by: dict[str, list] = collections.defaultdict(list)
        for x in (labels.get(f) or {}).get("labels", []): by[x["lib"]].append(x.get("label"))
        return {lib for lib, ls in by.items() if ls and all(l == "honest" for l in ls)}, set(by)
    for f in fams:
        fo = fires_on(f, admitted); lab = labels.get(f) or {"labels": []}; conf, labeled = confirmed_repos(f)
        cf = [x for x in lab["labels"] if x.get("label") == "counterfeit"]; gap = [x for x in lab["labels"] if x.get("label") == "instrument-gap"]
        row = {"fires_on": fo, "libs_hit": len(fo), "rows": sum(fo.values()), "k": a.k, "confirmed_on": sorted(conf), "confirmed": len(conf), "labeled_on": sorted(labeled),
               "labels": {"n": len(lab["labels"]), "counterfeit": len(cf), "instrument_gap": len(gap)},
               "plants": masked.get(f, []), "plants_masked": sum(1 for x in masked.get(f, []) if x["masked_by"]), "plants_unmasked": sum(1 for x in masked.get(f, []) if not x["masked_by"])}
        if f in strict and not (a.strict_slice and a.owner_note):
            row.update(status="refused", why="strict (proof layer) — never admitted outside the strict slice with the owner's note"); report[f] = row; continue
        if cf:
            row.update(status="refused", why="counterfeit in the labeled sample: " + "; ".join(f"{x['lib']}/{x['file']}:{x['line']} {x['function']}" for x in cf[:3])); report[f] = row; continue
        if gap:
            row.update(status="parked", why="instrument gap in the labeled sample (ticket in INSTRUMENT_GAPS.md): " + "; ".join(f"{x['lib']}/{x['file']}:{x['line']}" for x in gap[:3])); report[f] = row; continue
        if len(conf) < a.k:
            row.update(status="unconfirmed", why=f"confirmed honest on {len(conf)} < k={a.k} repos (fires on {len(fo)}, labeled on {len(labeled)})"); report[f] = row; continue
        trial = dict(admitted); trial[f] = "context"; st = plant_state(trial)
        lost = [k for k, v in base.items() if k[1] != "twin" and v[0] and not st[k][0]]
        twins_lost = [k for k, v in base.items() if k[1] == "twin" and v[0] is True and st[k][0] is not True]
        if lost:
            row.update(status="refused", why="loses a plant: " + "; ".join(f"{k[0]}/{k[1]}:{k[2]} ({base[k][3]})" for k in lost[:4])); report[f] = row; continue
        row.update(status="admitted", why=f"confirmed honest on {len(conf)} repos (fires on {len(fo)}); no plant lost; {len(lab['labels'])} labels, 0 counterfeit")
        if twins_lost: row["twins_no_longer_pass"] = [f"{k[0]}/{k[2]}:{k[3]}" for k in twins_lost]
        admitted[f] = "context"; report[f] = row
    sweep = {}
    for kk in [int(x) for x in a.sweep.split(",") if x]:
        sweep[kk] = [f for f in fams if len(confirmed_repos(f)[0]) >= kk]
    final = plant_state(admitted)
    out = {"k": a.k, "cal_libs": libs, "families": report, "disposition_set_after": admitted, "plants": {"manifests": [m["_dir"] for m in mans], "absent": absent,
           "baseline_caught_in_substance": sum(1 for k, v in base.items() if k[1] != "twin" and v[0]), "after_caught_in_substance": sum(1 for k, v in final.items() if k[1] != "twin" and v[0]),
           "planted": sum(1 for k in base if k[1] != "twin")}, "sweep_families_at_k": sweep, "consistency_mismatches": incons,
           "owner_note": a.owner_note}
    (cal / f"fit_k{a.k}.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"fit k={a.k} on {len(libs)} libs, {out['plants']['planted']} plants from {len(mans)} manifests (absent {len(absent)}); consistency mismatches {incons}")
    for f, r in report.items(): print(f"  {f}: {r['status']:26s} libs {r['libs_hit']:2d} rows {r['rows']:4d} plants {r['plants_unmasked']} unmasked / {r['plants_masked']} masked — {r['why']}")
    print(f"  plants caught in substance: baseline {out['plants']['baseline_caught_in_substance']} → after {out['plants']['after_caught_in_substance']} / {out['plants']['planted']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
