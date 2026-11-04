"""apply_dispositions.py — apply the OWNER's ruling to rule_dispositions.json (calibrator B7, 2026-09-06).
Reads CAL/RULING.md (a table `| family | disposition | reason |`) or CAL/RULING.json ({"by","dated","rulings":{fam:{disposition,reason}}}),
snapshots dispositions_before/after.json, writes the rows (by: calibration; evidence.kind: calibrated when the evidence bar
holds — libs_hit, plants, 5 labels, sources — else kind 'ruling' with the missing bar named), then runs the health gate.
usage: apply_dispositions.py CAL [--ruling FILE] [--no-gate]"""
from __future__ import annotations
import json, re, subprocess, sys, collections
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import ROOT, TABLE, load_table


def read_ruling(p: Path) -> dict:
    if p.suffix == ".json":
        return json.load(open(p))
    out = {"by": "owner", "dated": date.today().isoformat(), "rulings": {}}
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\|\s*([A-Z]+-[A-Za-z0-9*]+)\s*\|\s*(deciding|context)\s*\|\s*(.*?)\s*\|\s*$", line)
        if m: out["rulings"][m.group(1)] = {"disposition": m.group(2), "reason": m.group(3)}
        m2 = re.match(r"^(?:by|ruled by):\s*(.+)$", line, re.I)
        if m2: out["by"] = m2.group(1).strip()
    return out


def main(argv) -> int:
    cal = Path(argv[0]).resolve(); rp = Path(argv[argv.index("--ruling") + 1]) if "--ruling" in argv else (cal / "RULING.json" if (cal / "RULING.json").exists() else cal / "RULING.md")
    if not rp.exists(): raise SystemExit(f"no ruling at {rp} — B6 is the owner's step")
    ruling = read_ruling(rp); table = load_table(); fams = table["families"]
    ev = {e["family"]: e for e in json.load(open(cal / "evidence.json"))} if (cal / "evidence.json").exists() else {}
    (cal / "dispositions_before.json").write_text(json.dumps({k: v["disposition"] for k, v in fams.items()}, indent=1, sort_keys=True) + "\n")
    changed = []
    for fam, r in ruling["rulings"].items():
        if fam not in fams: raise SystemExit(f"ruling names {fam} which has no row")
        row = fams[fam]
        if row.get("class") == "strict" and r["disposition"] == "context" and not ruling.get("strict_note"):
            raise SystemExit(f"{fam} is strict — context needs the owner's strict-layer note (strict_note) in the ruling")
        e = ev.get(fam, {}); lab = e.get("labels", {"n": 0, "counterfeit": 0}); pa, pb = e.get("plants_A", {"planted": 0}), e.get("plants_B", {"planted": 0})
        bar_missing = []
        if not e.get("libs_hit"): bar_missing.append("libs_hit")
        if not (pa.get("planted") or pb.get("planted")): bar_missing.append("plants")
        if lab.get("n", 0) < 5: bar_missing.append(f"labels ({lab.get('n', 0)}/5)")
        if lab.get("counterfeit"): bar_missing.append("counterfeit in labels")
        before = row["disposition"]; row["disposition"] = r["disposition"]; row["by"] = "calibration"; row["dated"] = ruling.get("dated", date.today().isoformat())
        row["evidence"]["kind"] = "calibrated" if not bar_missing else "ruling"
        row["evidence"]["precision"] = {"libs_hit": e.get("fires_on", []), "libs_total": e.get("libs_total", 0),
                                        "rows": {"first": e.get("rows_first", 0), "anywhere": e.get("rows_anywhere", 0), "alone": e.get("rows_alone", 0), "in_tests": e.get("rows_in_tests", 0)}}
        row["evidence"]["plants"] = {"planted": pa.get("planted", 0) + pb.get("planted", 0), "caught_by_id": pa.get("caught_by_id", 0) + pb.get("caught_by_id", 0),
                                     "caught_in_substance": pa.get("caught_in_substance", 0) + pb.get("caught_in_substance", 0), "held_out": pb.get("planted", 0)}
        labels = json.load(open(cal / "labels" / f"{fam}.json"))["labels"] if (cal / "labels" / f"{fam}.json").exists() else []
        row["evidence"]["sample_labels"] = [{"row": f"{x['lib']}/{x['file']}:{x['line']} {x['function']}", "label": x["label"], "by": x.get("by", ""), "dated": x.get("dated", "")} for x in labels[:5]]
        row["evidence"]["sources"] = sorted(set(row["evidence"].get("sources", []) + [str(cal.relative_to(ROOT))]))
        row["note"] = f"ruled {r['disposition']} by {ruling.get('by', 'owner')} {row['dated']}: {r['reason']}" + (f" [bar not met: {', '.join(bar_missing)}]" if bar_missing else "")
        changed.append((fam, before, r["disposition"], row["evidence"]["kind"]))
    TABLE.write_text(json.dumps(table, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    (cal / "dispositions_after.json").write_text(json.dumps({k: v["disposition"] for k, v in fams.items()}, indent=1, sort_keys=True) + "\n")
    for c in changed: print(f"  {c[0]}: {c[1]} → {c[2]} (evidence.kind {c[3]})")
    if "--no-gate" not in argv:
        r = subprocess.run([sys.executable, str(ROOT / "system_scripts" / "health_check.py")], capture_output=True, text=True, cwd=str(ROOT))
        (cal / "health_after.txt").write_text(r.stdout + r.stderr); print(("gate PASSED" if "✓ PASSED" in r.stdout else "gate FAILED") + f" → {cal / 'health_after.txt'}")
        return 0 if "✓ PASSED" in r.stdout else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
