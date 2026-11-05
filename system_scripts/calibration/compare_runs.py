"""compare_runs.py OLD_CAL NEW_CAL — byte-identical dumps required when the instrument stamp is unchanged;
a per-family delta table (deciding ids anywhere on failed rows) when it changed. (calibrator A7, 2026-09-06)"""
from __future__ import annotations
import collections, hashlib, json, sys
from pathlib import Path


def _libs(cal: Path) -> dict[str, Path]:
    out = {}
    for f in sorted((cal / "precision").glob("*.json") if (cal / "precision").is_dir() else cal.glob("*.json")):
        try: d = json.load(open(f, encoding="utf-8"))
        except Exception: continue
        if isinstance(d, dict) and "rows" in d and "lib" in d: out[d["lib"]] = f
    return out


def _stamp(cal: Path) -> str:
    v = cal / "versions.json"
    return json.load(open(v)).get("instrument_sha256", "") if v.exists() else ""


def main(old: Path, new: Path) -> int:
    so, sn = _stamp(old), _stamp(new)
    lo, ln = _libs(old), _libs(new)
    common = sorted(set(lo) & set(ln)); rc = 0
    print(f"stamp old {so[:12] or '?'} new {sn[:12] or '?'} — {'UNCHANGED' if so and so == sn else 'CHANGED'}; libs old {len(lo)} new {len(ln)} common {len(common)}")
    if so and so == sn:
        for lib in common:
            a, b = lo[lib].read_bytes(), ln[lib].read_bytes()
            same = hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()
            print(f"  {lib}: {'byte-identical' if same else 'DIFFERS (same stamp!)'}"); rc |= (0 if same else 1)
        return rc
    print("| family | old failed rows | new failed rows | delta |"); print("|---|---|---|---|")
    fo: collections.Counter[str] = collections.Counter(); fn: collections.Counter[str] = collections.Counter(); vo = vn = 0
    for lib in common:
        do, dn = json.load(open(lo[lib])), json.load(open(ln[lib]))
        for r in do["rows"]:
            if not r["passed"]: vo += 1; fo.update(set(r["all_ids"]) - set(r.get("ctx_flagged", [])))
        for r in dn["rows"]:
            if not r["passed"]: vn += 1; fn.update(set(r["all_ids"]) - set(r.get("ctx_flagged", [])))
    for fam in sorted(set(fo) | set(fn), key=lambda k: -(abs(fn[k] - fo[k]))):
        if fo[fam] != fn[fam]: print(f"| {fam} | {fo[fam]} | {fn[fam]} | {fn[fam] - fo[fam]:+d} |")
    print(f"\nfailed rows: old {vo} new {vn} ({vn - vo:+d}) over {len(common)} common libraries")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
