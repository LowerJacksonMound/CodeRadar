"""live_delta.py — the live re-run must observe EXACTLY the verdict flips the score predicted (calibrator B8, 2026-09-06).
usage: live_delta.py CAL --lib <dump name> --state NOAI_VALIDATION_STATE.json [--baseline-state OLD_STATE.json]
Compares, row for row (file, function, line), the live state's verdicts with the dump's calibrated verdicts; with a
baseline state it also compares the observed flips (baseline → live) with the predicted flips (heldout.json)."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, load_table, table_dispositions, recomputed_failed, load_dump
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("verify_manifest", ROOT / "system_scripts" / "verify_manifest.py"); vm = _ilu.module_from_spec(_spec); _spec.loader.exec_module(vm)  # type: ignore


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--lib", required=True); ap.add_argument("--state", required=True); ap.add_argument("--baseline-state", default="")
    a = ap.parse_args(argv); cal = Path(a.cal); disp = table_dispositions(load_table())
    dump = load_dump(cal, a.lib); live = {(r["file"], r["function"], r["line"]): r for r in vm.rows_from_state(Path(a.state))}
    pred = {(r["file"], r["function"], r["line"]): (not recomputed_failed(r, disp)) for r in dump["rows"] if r.get("species") != "test"}
    common = [k for k in live if k in pred]
    mism = [(k, live[k]["passed"], pred[k]) for k in common if live[k]["passed"] != pred[k]]
    print(f"{a.lib}: live rows {len(live)} | dump rows {len(pred)} | common {len(common)} | verdict mismatches live vs calibrated dump: {len(mism)}")
    for k, l, p in mism[:20]: print(f"  {k[0]}:{k[2]} {k[1]} live {'PASS' if l else 'FAIL'} vs predicted {'PASS' if p else 'FAIL'}")
    rc = 1 if mism else 0
    if a.baseline_state:
        base = {(r["file"], r["function"], r["line"]): r for r in vm.rows_from_state(Path(a.baseline_state))}
        observed = {k for k in common if k in base and base[k]["passed"] != live[k]["passed"]}
        held = json.load(open(cal / "heldout.json")) if (cal / "heldout.json").exists() else {}
        predicted = {(x["file"], x["function"], x["line"]) for x in held.get("predicted_flips", []) if x["lib"] == a.lib and (x["file"], x["function"], x["line"]) in common}
        print(f"  observed flips {len(observed)} vs predicted flips {len(predicted)} — unpredicted {len(observed - predicted)}, unobserved {len(predicted - observed)}")
        for k in sorted(observed - predicted)[:10]: print(f"    UNPREDICTED flip {k}")
        for k in sorted(predicted - observed)[:10]: print(f"    UNOBSERVED flip {k}")
        rc |= 1 if (observed ^ predicted) else 0
    print("☑ observed delta == predicted delta row for row" if rc == 0 else "☐ delta differs — read the rows above")
    return rc


if __name__ == "__main__":
    sys.exit(main())
