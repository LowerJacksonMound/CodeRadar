"""kept_sites_delta.py — convict / clear KEPT hunter sites by calibration evidence (calibrator B9, 2026-09-06).
For each slice family now CONTEXT: the KEPT rows of the hunt ledger that live inside that family's check function are
MARKED FOR CUT when the family never decided a verdict alone on either real repo (colorama / tqdm dumps); a family with a
counterfeit label stays. usage: kept_sites_delta.py CAL --families a,b --real x,y [--apply]"""
from __future__ import annotations
import argparse, ast, csv, json, sys, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, load_table, table_dispositions, deciding_ids, recomputed_failed, load_dump
LEDGER = ROOT / "ARCHIVE" / "PRERANKER_HUNT_2026-09-05.tsv"


def family_spans() -> dict[tuple[str, int], str]:
    """(file, line) → family for every line inside a detection check function that emits a tag literal."""
    out = {}
    for f in sorted((ROOT / "no_aivalidator/detection").glob("*.py")):
        rel = str(f.relative_to(ROOT)); tree = ast.parse(f.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                tags = sorted({c.value for c in ast.walk(n) if isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.startswith("NAI-") and " " not in c.value})
                if len(tags) == 1:
                    for ln in range(n.lineno, (n.end_lineno or n.lineno) + 1): out[(rel, ln)] = tags[0]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--families", required=True); ap.add_argument("--real", default=""); ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv); cal = Path(a.cal); disp = table_dispositions(load_table()); fams = [x for x in a.families.split(",") if x]
    alone = collections.Counter()
    for lib in [x for x in a.real.split(",") if x]:
        for r in load_dump(cal, lib)["rows"]:
            if r.get("species") == "test" or not recomputed_failed(r, disp): continue
            dd = deciding_ids(r, disp)
            if len(dd) == 1: alone[dd[0]] += 1
    labels = {f: json.load(open(cal / "labels" / f"{f}.json"))["labels"] if (cal / "labels" / f"{f}.json").exists() else [] for f in fams}
    spans = family_spans()
    with open(LEDGER, encoding="utf-8") as fh:
        rd = csv.DictReader(fh, delimiter="\t"); fields = rd.fieldnames; rows = list(rd)
    marked, stayed = [], []
    for r in rows:
        if not r["status"].startswith("KEPT"): continue
        fam = spans.get((r["file"], int(r["line"] or 0)))
        if fam not in fams: continue
        if disp.get(fam) != "context": continue
        if any(x["label"] == "counterfeit" for x in labels[fam]): stayed.append((fam, r["file"], r["line"], "counterfeit label")); continue
        if alone[fam]: stayed.append((fam, r["file"], r["line"], f"decided {alone[fam]} verdict(s) alone on a real repo")); continue
        marked.append((fam, r["file"], r["line"], r["expr"][:60])); r["status"] += f" | MARKED FOR CUT (calibration {cal.name}: {fam} is context and never decided a verdict alone on a real repo)"
    print(f"marked for cut: {len(marked)}; stayed: {len(stayed)}")
    for m in marked[:30]: print("  CUT?", *m)
    for s in stayed[:10]: print("  stay", *s)
    (cal / "kept_sites_delta.json").write_text(json.dumps({"marked": marked, "stayed": stayed}, indent=1) + "\n")
    if a.apply and marked:
        with open(LEDGER, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t", lineterminator="\n"); w.writeheader(); w.writerows(rows)
        print("ledger statuses updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
