"""repo_sheets.py — repo-by-repo label sheets (owner 2026-09-06: "confirmation should be on a repo-by-repo basis —
marking the top 6 is contamination"; "they need to be present, just not ranked"). One sheet per calibration library.
EVERY family in the set that fires there is PRESENT, ordered by id — never by count; up to --cap rows per (repo, family),
alone-first, seeded; each row a ±3-line excerpt at the family's observation line. Sheets merge per family
(labels_merge.py reads the `family` column) and the fit admits a family on CONFIRMED repos — every labeled row of it
there honest — never on repos merely hit.

usage: repo_sheets.py CAL --libs a,b,c [--families NAI-030,... | --unevidenced] [--cap 2] [--seed 11] [--out DIR] [--unlabeled-only]
"""
from __future__ import annotations
import argparse, collections, json, random, sys
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from calib_common import load_table, table_dispositions, deciding_ids, recomputed_failed, load_dump
from label_sheets import excerpt

INDEX = """# Calibration label sheets — repo by repo — {date}

One sheet per library. Every unevidenced family that fires in that library is PRESENT, in id order — no family is ranked,
marked or singled out. Label the CODE, not the family name: for each row read the excerpt (and the file, when the excerpt
is not enough) and write ONE word in the `label` column:

- `honest` — the code does what a library should; the rule fired on an idiom, not on counterfeit
- `counterfeit` — the code performs the appearance of work (a stub, a canned return, a swallowed error that hides a real failure …)
- `instrument-gap` — the rule fired on something the instrument mis-read (wrong span, wrong line, a parse artefact) — the fix is to the instrument, not to the rule

A short `note` helps. Leave a row blank if you cannot tell. A family is CONFIRMED on a repo when every labeled row of it
there is honest; the fit admits a family to context only on confirmed repos (k of them), never on repos merely hit.
Merge with `labels_merge.py CAL <folder> <tag>`; a conflict between reviewers stays counterfeit until adjudicated.
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("cal"); ap.add_argument("--libs", required=True)
    ap.add_argument("--families", default=""); ap.add_argument("--unevidenced", action="store_true")
    ap.add_argument("--cap", type=int, default=2); ap.add_argument("--seed", type=int, default=0); ap.add_argument("--out", default="")
    ap.add_argument("--unlabeled-only", action="store_true", help="round 2: skip rows that already carry a label in CAL/labels/")
    a = ap.parse_args(argv)
    cal = Path(a.cal); table = load_table(); disp = table_dispositions(table)
    if a.unevidenced:   # every deciding, non-strict family that carries no evidence yet — present, never ranked
        fams = sorted(f for f, r in table["families"].items() if r.get("disposition") == "deciding" and r.get("class") != "strict"
                      and str((r.get("evidence") or {}).get("kind", "")).startswith("none"))
    else:
        fams = sorted(x for x in a.families.split(",") if x)
    assert fams, "no families: pass --families or --unevidenced"
    libs = [x for x in a.libs.split(",") if x]
    out = Path(a.out).expanduser() if a.out else Path.home() / "Desktop" / f"CALIBRATION_REVIEW_{date.today().isoformat()}_repos"
    (out / "sheets").mkdir(parents=True, exist_ok=True); (cal / "label_requests").mkdir(exist_ok=True)
    (out / "00_INDEX.md").write_text(INDEX.format(date=date.today().isoformat()), encoding="utf-8")
    req: dict[str, list] = collections.defaultdict(list); total = 0
    labeled: set = set()   # (family, lib, file, line, function) already read in an earlier round
    if a.unlabeled_only:
        for lp in (cal / 'labels').glob('*.json'):
            lj = json.load(open(lp)); labeled |= {(lj['family'], x['lib'], x['file'], x['line'], x['function']) for x in lj.get('labels', [])}
    for lib in libs:
        d = load_dump(cal, lib); rng = random.Random(f"{a.seed}:{lib}")
        rows = [r for r in d["rows"] if r.get("species") != "test" and recomputed_failed(r, disp)]
        picked: list[tuple[str, dict]] = []; present = 0
        for fam in fams:
            cands = [(deciding_ids(r, disp) == [fam], r) for r in rows if fam in deciding_ids(r, disp)
                     and (fam, lib, r['file'], r['line'], r['function']) not in labeled]
            if not cands: continue
            present += 1; taken = 0
            for alone in (True, False):
                pool = [r for al, r in cands if al == alone]; rng.shuffle(pool)
                for r in pool:
                    if taken >= a.cap: break
                    picked.append((fam, r)); taken += 1
        L = [f"# Labels — {lib} ({len(picked)} rows over {present} families present; seed {a.seed}; cap {a.cap} per family; label the code, not the family name)", "",
             "| # | family | lib | file | line | function | fires with | label | note |", "|---|---|---|---|---|---|---|---|---|"]
        for i, (fam, r) in enumerate(picked, 1):
            dd = deciding_ids(r, disp); others = [x for x in dd if x != fam]
            obs_line = next((o["line"] for o in r.get("obs", []) if o["tag"] == fam and o["line"]), 0) or r["line"]
            src = Path(d["path"]) / r["file"]
            req[fam].append({"lib": lib, "file": r["file"], "line": r["line"], "function": r["function"], "obs_line": obs_line, "fires_with": others})
            L.append(f"| {i} | {fam} | {lib} | {r['file']} | {r['line']} | {r['function']} | {'+'.join(others) or '— (alone)'} |  |  |")
            L += ["", "```python", f"# {i}. {fam} — {lib}/{r['file']}:{obs_line} {r['function']}", excerpt(src, obs_line), "```", ""]
        (out / "sheets" / f"repo_{lib}.md").write_text("\n".join(L) + "\n", encoding="utf-8"); total += len(picked)
        print(f"{lib}: {len(picked)} rows, {present} families present → {out / 'sheets' / f'repo_{lib}.md'}")
    for fam, rows in sorted(req.items()):
        p = cal / "label_requests" / f"{fam}.json"
        cur = json.load(open(p)) if p.exists() else {"family": fam, "seed": a.seed, "rows": []}
        seen = {(x["lib"], x["file"], x["line"], x["function"]) for x in cur["rows"]}
        cur["rows"] += [x for x in rows if (x["lib"], x["file"], x["line"], x["function"]) not in seen]; cur["by_repo"] = True
        p.write_text(json.dumps(cur, indent=1) + "\n", encoding="utf-8")
    print(f"{total} rows over {len(libs)} libraries, {len(req)} families requested; index: {out / '00_INDEX.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
