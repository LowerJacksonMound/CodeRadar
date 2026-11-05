"""score_heldout.py — the SCORE (calibrator A7 / B5, 2026-09-06). Applies the fit's admitted set to HELD-OUT rows only:
held-out honest libraries + the two real repos + corpus B plants. Two primary halves — the false-verdict rate on
honest rows and the miss rate on plants — pooled Brier (= error rate on binary verdicts) a footnote. The rate is
REPORTED, never targeted. Also the consistency check (recomputed raw verdict == the dump's) and the per-row list of
predicted verdict flips for the live re-run (B8).

usage: score_heldout.py CAL --held-libs a,b --real x,y --plants corpus_B --fit fit_k7.json → CAL/HELDOUT_SCORE.md + heldout.json
"""
from __future__ import annotations
import argparse, collections, json, sys
from pathlib import Path
from typing import Any
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, load_table, table_dispositions, deciding_ids, recomputed_failed, consistency, load_dump, verify_rows, manifests, target_rows
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("verify_manifest", ROOT / "system_scripts" / "verify_manifest.py"); vm = _ilu.module_from_spec(_spec); _spec.loader.exec_module(vm)  # type: ignore


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--held-libs", required=True); ap.add_argument("--real", default="")
    ap.add_argument("--plants", default="corpus_B"); ap.add_argument("--fit", required=True)
    a = ap.parse_args(argv)
    cal = Path(a.cal); disp = table_dispositions(load_table()); fit = json.load(open(cal / a.fit)); ov = fit["disposition_set_after"]
    libs = [x for x in a.held_libs.split(",") if x]; real = [x for x in a.real.split(",") if x]
    per = {}; flips = []; honest_rows = honest_raw = honest_cal = 0; mism = 0
    for lib in libs + real:
        d = load_dump(cal, lib); rows = [r for r in d["rows"] if r.get("species") != "test"]
        raw = [r for r in rows if not r["passed"]]; calf = [r for r in rows if recomputed_failed(r, disp, ov)]
        mm = len(consistency(d["rows"], disp)); mism += mm
        fam_raw = collections.Counter(i for r in raw for i in deciding_ids(r, disp)); fam_cal = collections.Counter(i for r in calf for i in deciding_ids(r, disp, ov))
        per[lib] = {"kind": "real" if lib in real else "held", "rows": len(rows), "test_rows_withheld": sum(1 for r in d["rows"] if r.get("species") == "test"),
                    "raw_failed": len(raw), "cal_failed": len(calf), "delta": len(calf) - len(raw),
                    "raw_rate": round(len(raw) / max(len(rows), 1), 4), "cal_rate": round(len(calf) / max(len(rows), 1), 4), "consistency_mismatches": mm,
                    "families_raw": dict(fam_raw.most_common()), "families_cal": dict(fam_cal.most_common())}
        for r in rows:
            b, c = (not r["passed"]), recomputed_failed(r, disp, ov)
            if b != c: flips.append({"lib": lib, "file": r["file"], "function": r["function"], "line": r["line"], "raw": "FAIL" if b else "PASS", "calibrated": "FAIL" if c else "PASS",
                                     "ids_now_context": [i for i in r["all_ids"] if i in ov]})
        if lib not in real: honest_rows += len(rows); honest_raw += len(raw); honest_cal += len(calf)
    # plants (held-out corpus B)
    mans = manifests(a.plants); pl: dict[str, Any] = {"manifests": [m["_dir"] for m in mans], "families": {}}
    for m in mans:
        t = vm.resolve_target(m["target"])   # retired targets may live under ~/Desktop/RUN_AGAINST_DIRS_*/
        if not t.exists(): pl.setdefault("absent", []).append(m["_dir"]); continue
        rows = target_rows(t)
        r0 = vm.check(m, verify_rows(rows, disp)); r1 = vm.check(m, verify_rows(rows, disp, ov))
        for fam in set(r0["families"]) | set(r1["families"]):
            f = pl["families"].setdefault(fam, {"planted": 0, "raw_caught": 0, "cal_caught": 0, "raw_by_id": 0, "cal_by_id": 0})
            f["planted"] += r0["families"].get(fam, {}).get("planted", 0)
            f["raw_caught"] += r0["families"].get(fam, {}).get("caught_in_substance", 0); f["cal_caught"] += r1["families"].get(fam, {}).get("caught_in_substance", 0)
            f["raw_by_id"] += r0["families"].get(fam, {}).get("caught_by_id", 0); f["cal_by_id"] += r1["families"].get(fam, {}).get("caught_by_id", 0)
        pl.setdefault("twins", {})[m["_dir"]] = {"raw_passed": r0["summary"]["twins_passed"], "cal_passed": r1["summary"]["twins_passed"], "n": r0["summary"]["twins"]}
        pl.setdefault("controls", {})[m["_dir"]] = {"clean": r1["summary"]["controls_clean"], "n": r1["summary"]["controls"]}
    planted = sum(f["planted"] for f in pl["families"].values()); cal_caught = sum(f["cal_caught"] for f in pl["families"].values()); raw_caught = sum(f["raw_caught"] for f in pl["families"].values())
    fitA = fit.get("plants", {})
    score = {"fit": a.fit, "admitted": sorted(ov), "held_libs": libs, "real": real,
             "half_1_honest": {"rows": honest_rows, "raw_false_verdicts": honest_raw, "cal_false_verdicts": honest_cal,
                               "raw_rate": round(honest_raw / max(honest_rows, 1), 4), "cal_rate": round(honest_cal / max(honest_rows, 1), 4)},
             "half_2_plants": {"planted": planted, "raw_caught": raw_caught, "cal_caught": cal_caught, "raw_miss_rate": round((planted - raw_caught) / max(planted, 1), 4), "cal_miss_rate": round((planted - cal_caught) / max(planted, 1), 4)},
             "brier_pooled_footnote": {"raw": round((honest_raw + (planted - raw_caught)) / max(honest_rows + planted, 1), 4), "cal": round((honest_cal + (planted - cal_caught)) / max(honest_rows + planted, 1), 4)},
             "consistency_mismatches": mism, "per_lib": per, "plants": pl, "predicted_flips": flips, "corpus_A_from_fit": fitA}
    (cal / "heldout.json").write_text(json.dumps(score, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    L = [f"# Held-out score — {a.fit} (admitted to context: {', '.join(sorted(ov)) or 'none'})", "",
         "The rate is reported, never targeted. Half 1 = honest rows (held-out libraries only; the real repos are shown but not pooled). Half 2 = corpus-B plants.", "",
         f"**Half 1 — false verdicts on honest rows:** raw {honest_raw}/{honest_rows} = {score['half_1_honest']['raw_rate']:.1%} → calibrated {honest_cal}/{honest_rows} = {score['half_1_honest']['cal_rate']:.1%}",
         f"**Half 2 — plant misses (corpus B):** raw {planted - raw_caught}/{planted} → calibrated {planted - cal_caught}/{planted}",
         f"*Footnote — pooled Brier (error rate): raw {score['brier_pooled_footnote']['raw']:.4f} → calibrated {score['brier_pooled_footnote']['cal']:.4f}*",
         f"Consistency check (recomputed raw verdict == dump verdict): {'PASS' if mism == 0 else f'{mism} MISMATCHES'}", "",
         "| library | kind | rows | withheld (test) | raw failed | calibrated failed | delta | raw rate | cal rate |", "|---|---|---|---|---|---|---|---|---|"]
    for lib, p in per.items():
        L.append(f"| {lib} | {p['kind']} | {p['rows']} | {p['test_rows_withheld']} | {p['raw_failed']} | {p['cal_failed']} | {p['delta']:+d} | {p['raw_rate']:.1%} | {p['cal_rate']:.1%} |")
    L += ["", "## Plants — corpus A (fit) vs corpus B (held out), per family", "", "| family | B planted | B caught raw | B caught calibrated | B by id (cal) |", "|---|---|---|---|---|"]
    for fam, f in sorted(pl["families"].items()):
        L.append(f"| {fam} | {f['planted']} | {f['raw_caught']} | {f['cal_caught']} | {f['cal_by_id']} |")
    if pl.get("twins"): L += ["", "Twins (honest, expect pass): " + "; ".join(f"{k}: raw {v['raw_passed']}/{v['n']} → cal {v['cal_passed']}/{v['n']}" for k, v in pl["twins"].items())]
    if pl.get("controls"): L += ["Controls clean: " + "; ".join(f"{k}: {v['clean']}/{v['n']}" for k, v in pl["controls"].items())]
    L += ["", f"## Predicted verdict flips ({len(flips)} rows) — the live re-run (B8) must observe exactly these", ""] + [f"- {x['lib']}/{x['file']}:{x['line']} {x['function']} {x['raw']}→{x['calibrated']} ({'/'.join(x['ids_now_context'])})" for x in flips[:200]]
    (cal / "HELDOUT_SCORE.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L[:8])); print(f"written {cal / 'HELDOUT_SCORE.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
