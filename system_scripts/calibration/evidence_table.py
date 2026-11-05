"""evidence_table.py — one row per family joining precision, recall and labels (calibrator A7 / B6, 2026-09-06).
"Reads as" is PROSE from the evidence, never a threshold. usage: evidence_table.py CAL [--families a,b] [--fit fit_k7.json]"""
from __future__ import annotations
import argparse, collections, json, sys
from pathlib import Path
from typing import Any
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, load_table, table_dispositions, deciding_ids, recomputed_failed, load_dump, dump_libs


def reads_as(f: dict) -> str:
    bits = []
    n, N = f["libs_hit"], f["libs_total"]
    bits.append(f"fires on {n} of {N} honest libraries ({f['rows_anywhere']} rows, {f['rows_alone']} alone" + (f", {f['rows_in_tests']} in test files" if f['rows_in_tests'] else "") + ")")
    if f["plants_A"]["planted"] == 0 and f["plants_B"]["planted"] == 0 and f["plants_archived"]["planted"] == 0:
        bits.append("NO plant anywhere — a 'loses no plant' guard says nothing about it; it needs a plant before any ruling")
    else:
        if f.get("plants_masked") and not f.get("plants_unmasked"):
            bits.append(f"every fit plant is MASKED by a superset rule ({', '.join(sorted({i for x in f.get('plants_detail', []) for i in x['masked_by']}))}) — the plant guard cannot see this family's loss; the held-out plant and the labels carry it")
        pa, pb = f["plants_A"], f["plants_B"]
        bits.append(f"plants: A {pa['caught_in_substance']}/{pa['planted']} in substance ({pa['caught_by_id']} by id)" + (f", B {pb['caught_in_substance']}/{pb['planted']} ({pb['caught_by_id']} by id)" if pb["planted"] else ", no held-out plant") + (f", archived {f['plants_archived']['caught_in_substance']}/{f['plants_archived']['planted']}" if f["plants_archived"]["planted"] else ""))
        if pb["planted"] and pb["caught_in_substance"] < pb["planted"]: bits.append("a HELD-OUT plant is missed — context would lose it")
    lab = f["labels"]
    if lab["n"] == 0: bits.append("no labeled rows yet")
    elif lab["counterfeit"]: bits.append(f"{lab['counterfeit']} of {lab['n']} labeled rows are COUNTERFEIT — the rule catches real fakes on honest-looking code; stays deciding")
    elif lab["instrument_gap"]: bits.append(f"{lab['instrument_gap']} labeled rows are instrument gaps — fix the instrument first, no ruling this slice")
    else: bits.append(f"{lab['n']} labeled rows all honest")
    st = f.get("fit_status")
    if st: bits.append(f"fit: {st}")
    return "; ".join(bits)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--families", default=""); ap.add_argument("--fit", default="")
    a = ap.parse_args(argv); cal = Path(a.cal); table = load_table(); disp = table_dispositions(table)
    fit = json.load(open(cal / a.fit)) if a.fit and (cal / a.fit).exists() else {}
    held = json.load(open(cal / "heldout.json")) if (cal / "heldout.json").exists() else {}
    libs = dump_libs(cal)
    cal_libs = fit.get("cal_libs") or libs
    fams = [x for x in a.families.split(",") if x] or sorted(fit.get("families", {})) or sorted(table["families"])
    # precision over the calibration libs (raw dispositions)
    P: dict[str, dict[str, Any]] = collections.defaultdict(lambda: {"libs": set(), "anywhere": 0, "alone": 0, "in_tests": 0, "first": 0})
    for lib in cal_libs:
        try: d = load_dump(cal, lib)
        except SystemExit: continue
        for r in d["rows"]:
            if r.get("species") == "test":
                for i in r["all_ids"]: P[i]["in_tests"] += 1
                continue
            if not recomputed_failed(r, disp): continue
            dd = deciding_ids(r, disp)
            for i in dd:
                P[i]["libs"].add(lib); P[i]["anywhere"] += 1
                if len(dd) == 1: P[i]["alone"] += 1
            if r.get("first"): P[r["first"]]["first"] += 1
    # recall from the fit (archived + A) and the score (B)
    def plants_from(state, fam):
        return state.get(fam) or {"planted": 0, "caught_in_substance": 0, "caught_by_id": 0}
    recA: dict = {}; recArch = {}
    close = ROOT / "system_scripts" / "disposition_close.json"
    if close.exists():
        cl = json.load(open(close))
        for f, v in (cl.get("recall", {}).get("by_id_gaps") or {}).items(): recArch[f] = {"planted": v["planted"], "caught_in_substance": v["caught_in_substance"], "caught_by_id": v["caught_by_id"]}
        for f in cl.get("recall", {}).get("fully_caught_families") or []:
            recArch.setdefault(f, {"planted": 8, "caught_in_substance": 8, "caught_by_id": 8})
    recB = {f: {"planted": v["planted"], "caught_in_substance": v["cal_caught"], "caught_by_id": v["cal_by_id"]} for f, v in (held.get("plants", {}).get("families") or {}).items()}
    corpusA = {}
    ca = cal / "corpus_A_verify.json"
    if ca.exists():
        for f, v in json.load(open(ca)).get("families", {}).items(): corpusA[f] = {"planted": v["planted"], "caught_in_substance": v["caught_in_substance"], "caught_by_id": v["caught_by_id"]}
    rows = []
    for fam in fams:
        lp = cal / "labels" / f"{fam}.json"
        if not lp.exists():
            for prev in sorted(cal.parent.glob("calibration_*/labels/" + fam + ".json")): lp = prev
        lab = json.load(open(lp)) if lp.exists() else {"labels": []}
        live_rows = set()
        for lib in cal_libs:
            try: dl = load_dump(cal, lib)
            except SystemExit: continue
            live_rows |= {(lib, r["file"], r["line"], r["function"]) for r in dl["rows"] if fam in deciding_ids(r, disp)}
        lab["labels"] = [x for x in lab["labels"] if (x["lib"], x["file"], x["line"], x["function"]) in live_rows]
        lc = collections.Counter(x["label"] for x in lab["labels"])
        fr = fit.get("families", {}).get(fam, {})
        f = {"family": fam, "disposition": disp.get(fam, "deciding (no row)"), "class": table["families"].get(fam, {}).get("class", "?"),
             "libs_hit": len(P[fam]["libs"]), "libs_total": len(cal_libs), "rows_anywhere": P[fam]["anywhere"], "rows_alone": P[fam]["alone"], "rows_first": P[fam]["first"], "rows_in_tests": P[fam]["in_tests"],
             "fires_on": sorted(P[fam]["libs"]), "plants_archived": plants_from(recArch, fam), "plants_A": plants_from(corpusA, fam), "plants_B": plants_from(recB, fam),
             "labels": {"n": len(lab["labels"]), "honest": lc["honest"], "counterfeit": lc["counterfeit"], "instrument_gap": lc["instrument-gap"]},
             "fit_status": fr.get("status", ""), "fit_why": fr.get("why", ""),
             "plants_masked": fr.get("plants_masked", 0), "plants_unmasked": fr.get("plants_unmasked", 0), "plants_detail": fr.get("plants", [])}
        f["reads_as"] = reads_as(f); rows.append(f)
    (cal / "evidence.json").write_text(json.dumps(rows, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    L = [f"# Evidence table — {cal.name} ({len(cal_libs)} calibration libraries; k = {fit.get('k', '?')})", "",
         "| family | disposition | class | libs hit / N | first | anywhere | alone | in tests | plants arch / A / B (in substance, by id) | labels (h/c/g) | fit | reads as |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for f in rows:
        pa, pb, pr = f["plants_A"], f["plants_B"], f["plants_archived"]
        pl = f"{pr['caught_in_substance']}/{pr['planted']} · {pa['caught_in_substance']}/{pa['planted']} ({pa['caught_by_id']}) · {pb['caught_in_substance']}/{pb['planted']} ({pb['caught_by_id']})"
        L.append(f"| {f['family']} | {f['disposition']} | {f['class']} | {f['libs_hit']}/{f['libs_total']} | {f['rows_first']} | {f['rows_anywhere']} | {f['rows_alone']} | {f['rows_in_tests']} | {pl} | {f['labels']['n']} ({f['labels']['honest']}/{f['labels']['counterfeit']}/{f['labels']['instrument_gap']}) | {f['fit_status']} | {f['reads_as']} |")
    L += ["", "fires_on per family: " + "; ".join(f"{f['family']}: {', '.join(f['fires_on'])}" for f in rows)]
    (cal / "EVIDENCE_TABLE.md").write_text("\n".join(L) + "\n", encoding="utf-8"); print("\n".join(L[:3 + len(rows)])); print(f"written {cal / 'EVIDENCE_TABLE.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
