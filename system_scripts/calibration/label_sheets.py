"""label_sheets.py — row-level label sheets for reviewers (calibrator A9 / B4, 2026-09-06). Per candidate family: n seeded
FAILED rows from the calibration dumps (rows where the family fires ALONE first, spread across libraries), each with a
±3-line excerpt from the wheel source centred on the family's observation line. "Label the code, not the family name":
honest | counterfeit | instrument-gap.

usage: label_sheets.py CAL --families NAI-142,NAI-158 --n 5 --seed 11 [--libs a,b,c] [--out ~/Desktop/CALIBRATION_REVIEW_<date>]
"""
from __future__ import annotations
import argparse, collections, json, random, sys
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import load_table, table_dispositions, deciding_ids, recomputed_failed, load_dump, dump_libs

INDEX = """# Calibration label sheets — {date}

Label the CODE, not the family name. For each row read the excerpt (and the file, if the excerpt is not enough) and write ONE word in the `label` column:

- `honest` — the code does what a library should; the rule fired on an idiom, not on counterfeit
- `counterfeit` — the code performs the appearance of work (a stub, a canned return, a swallowed error that hides a real failure …)
- `instrument-gap` — the rule fired on something the instrument mis-read (wrong span, wrong line, a parse artefact) — the fix is to the instrument, not to the rule

Add a short `note` when it helps. Leave a row blank if you cannot tell. Sheets: one per family under `sheets/`. Return the folder (or just the sheets) and they are merged with `labels_merge.py <folder> <tag>`.
"""


def excerpt(path: Path, line: int, pad: int = 3) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return f"(unreadable: {e})"
    lo, hi = max(1, line - pad), min(len(lines), line + pad)
    return "\n".join(f"{'>' if i == line else ' '}{i:5d} {lines[i-1]}" for i in range(lo, hi + 1))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--families", required=True); ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--seed", type=int, default=0); ap.add_argument("--libs", default=""); ap.add_argument("--out", default="")
    a = ap.parse_args(argv)
    cal = Path(a.cal); disp = table_dispositions(load_table()); fams = [x for x in a.families.split(",") if x]
    libs = [x for x in a.libs.split(",") if x] or dump_libs(cal)
    out = Path(a.out).expanduser() if a.out else Path.home() / "Desktop" / f"CALIBRATION_REVIEW_{date.today().isoformat()}"
    (out / "sheets").mkdir(parents=True, exist_ok=True); (cal / "label_requests").mkdir(exist_ok=True)
    (out / "00_INDEX.md").write_text(INDEX.format(date=date.today().isoformat()), encoding="utf-8")
    dumps = {lib: load_dump(cal, lib) for lib in libs}
    for fam in fams:
        rng = random.Random(f"{a.seed}:{fam}")
        cands = collections.defaultdict(list)
        for lib, d in dumps.items():
            for r in d["rows"]:
                if r.get("species") == "test" or not recomputed_failed(r, disp): continue
                dd = deciding_ids(r, disp)
                if fam in dd: cands[lib].append((dd == [fam], r))
        picked = []; order = sorted(cands); rng.shuffle(order)
        for alone_first in (True, False):
            while len(picked) < a.n and any(cands[l] for l in order):
                progressed = False
                for lib in order:
                    pool = [x for x in cands[lib] if x[0] == alone_first]
                    if not pool: continue
                    x = pool[rng.randrange(len(pool))]; cands[lib].remove(x); picked.append((lib, x[1])); progressed = True
                    if len(picked) >= a.n: break
                if not progressed: break
            if len(picked) >= a.n: break
        req = []; L = [f"# Labels — {fam} ({len(picked)} rows; seed {a.seed}; label the code, not the family name)", "",
                       "| # | lib | file | line | function | fires with | label | note |", "|---|---|---|---|---|---|---|---|"]
        for i, (lib, r) in enumerate(picked, 1):
            obs_line = next((o["line"] for o in r.get("obs", []) if o["tag"] == fam and o["line"]), 0) or r["line"]
            src = Path(dumps[lib]["path"]) / r["file"]
            req.append({"lib": lib, "file": r["file"], "line": r["line"], "function": r["function"], "obs_line": obs_line, "fires_with": [i for i in deciding_ids(r, disp) if i != fam]})
            L.append(f"| {i} | {lib} | {r['file']} | {r['line']} | {r['function']} | {'+'.join(req[-1]['fires_with']) or '— (alone)'} |  |  |")
            L += ["", f"```python", f"# {i}. {lib}/{r['file']}:{obs_line} {r['function']}", excerpt(src, obs_line), "```", ""]
        (out / "sheets" / f"labels_{fam}.md").write_text("\n".join(L) + "\n", encoding="utf-8")
        (cal / "label_requests" / f"{fam}.json").write_text(json.dumps({"family": fam, "seed": a.seed, "rows": req}, indent=1) + "\n", encoding="utf-8")
        print(f"{fam}: {len(picked)} rows ({sum(1 for _, r in picked if deciding_ids(r, disp) == [fam])} alone) across {len({l for l, _ in picked})} libs → {out / 'sheets' / f'labels_{fam}.md'}")
    print(f"index: {out / '00_INDEX.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
