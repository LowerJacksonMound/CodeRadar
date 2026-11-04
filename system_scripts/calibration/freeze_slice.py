"""freeze_slice.py — close a calibration slice (calibrator B10, 2026-09-06): CAL/CLOSE.json + an entry in
ARCHIVE/health/calibration_close.json; the corpora are retired (kept on disk as the recall guard's regression set) and
disposition_close.json's recall baseline is re-frozen from the live check. usage: freeze_slice.py CAL --slice N --next-specs a,b"""
from __future__ import annotations
import argparse, hashlib, json, sys
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, load_table, manifests


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--slice", type=int, required=True); ap.add_argument("--next-specs", default="")
    a = ap.parse_args(argv); cal = Path(a.cal).resolve(); table = load_table()
    fit = sorted(cal.glob("fit_k*.json")); fit = json.load(open(fit[-1])) if fit else {}
    ruled = {k: v for k, v in json.load(open(cal / "dispositions_after.json")).items()} if (cal / "dispositions_after.json").exists() else {}
    before = json.load(open(cal / "dispositions_before.json")) if (cal / "dispositions_before.json").exists() else {}
    changed = {k: (before.get(k), v) for k, v in ruled.items() if before.get(k) != v}
    corp = {m["corpus"]["half"]: {"target": m["target"], "manifest": m["_dir"], "held_out": m["held_out"]} for m in manifests("corpus_A") + manifests("corpus_B") if m["corpus"]["slice"] == a.slice}
    ruled_fams = set(changed) | {k for k in (fit.get("families") or {})}
    for spec in [x for x in a.next_specs.split(",") if x]:
        p = ROOT / "system_scripts/calibration/specs" / spec
        assert p.exists(), f"next spec missing: {p}"
        txt = p.read_text(encoding="utf-8")
        clash = [f for f in ruled_fams if f'"{f}"' in txt]
        assert not clash, f"next spec {spec} names ruled families: {clash}"
    # re-freeze the recall baseline from the live check (corpora included)
    import importlib.util as _ilu
    s = _ilu.spec_from_file_location("disposition_check", ROOT / "system_scripts" / "disposition_check.py"); dc = _ilu.module_from_spec(s); s.loader.exec_module(dc)  # type: ignore
    r = dc.check(); rc = r["recall"]; fams = rc["families"]
    close_path = dc.CLOSE; close = json.load(open(close_path)) if close_path.exists() else {}
    close["recall"] = {**close.get("recall", {}), "targets": rc["targets"], "plants": rc["plants"], "caught_in_substance": rc["caught_in_substance"], "caught_by_id": rc["caught_by_id"],
                       "controls": rc["controls"], "controls_clean": rc["controls_clean"], "controls_clean_required": True,
                       # a CONTEXT family's plants are caught only by superset rules — never a frozen recall obligation (slice 2 judges those rules on their own evidence)
                       "fully_caught_families": sorted(f for f, v in fams.items() if v["planted"] and v["caught_in_substance"] == v["planted"]
                                                       and table["families"].get(f, {}).get("disposition") != "context"),
                       "by_id_gaps": {f: v for f, v in fams.items() if v["caught_by_id"] < v["planted"]}, "refrozen": date.today().isoformat(), "slice": a.slice}
    json.dump(close, open(close_path, "w"), indent=1, sort_keys=True)
    entry = {"slice": a.slice, "cal_dir": str(cal.relative_to(ROOT)), "frozen": date.today().isoformat(), "k": fit.get("k"), "families": sorted(fit.get("families") or []),
             "admitted_by_fit": sorted(fit.get("disposition_set_after") or []), "ruled_changes": changed, "corpora": corp, "corpora_status": "retired — kept on disk as the recall guard's regression set",
             "instrument_stamp": json.load(open(cal / "versions.json"))["instrument_sha256"] if (cal / "versions.json").exists() else None,
             "table_sha256": hashlib.sha256((ROOT / "system_scripts/rule_dispositions.json").read_bytes()).hexdigest(),
             "recall_after": {"targets": rc["targets"], "plants": rc["plants"], "caught_in_substance": rc["caught_in_substance"], "controls_clean": rc["controls_clean"], "controls": rc["controls"]},
             "health_after": str((cal / "health_after.txt").relative_to(ROOT)) if (cal / "health_after.txt").exists() else None}
    (cal / "CLOSE.json").write_text(json.dumps(entry, indent=1, sort_keys=True) + "\n")
    allp = ROOT / "ARCHIVE/health/calibration_close.json"; allc = json.load(open(allp)) if allp.exists() else {"slices": []}
    allc["slices"] = [s_ for s_ in allc["slices"] if s_.get("slice") != a.slice] + [entry]; json.dump(allc, open(allp, "w"), indent=1, sort_keys=True)
    print(f"slice {a.slice} frozen: {len(changed)} ruled changes; recall {rc['caught_in_substance']}/{rc['plants']} over {rc['targets']} targets; {cal / 'CLOSE.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
