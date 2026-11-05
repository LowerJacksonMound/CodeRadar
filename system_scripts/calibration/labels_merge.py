"""labels_merge.py — merge filled label sheets into CAL/labels/<family>.json (calibrator A9 / B4, 2026-09-06).
Joins each sheet row to CAL/label_requests/<family>.json by (lib, file, line, function). A row labeled differently by two
reviewers stays `counterfeit` until adjudicated (both labels kept). usage: labels_merge.py CAL SHEETS_DIR_OR_FILE TAG"""
from __future__ import annotations
import json, re, sys
from datetime import date
from pathlib import Path
LABELS = {"honest", "counterfeit", "instrument-gap"}


def parse_sheet(p: Path):
    """Rows of a filled sheet as [(family, row)]. A per-family sheet (labels_<FAMILY>.md) carries the family in its name;
    a repo sheet (repo_<lib>.md, repo_sheets.py) carries a `family` column — families present, never ranked."""
    m = re.search(r"labels_([A-Z]+-[A-Za-z0-9]+)\.md$", p.name); fam = m.group(1) if m else None
    out = []; by_col = False; f: str | None
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.startswith("| #"): by_col = "| family |" in line; continue
        if not line.startswith("|") or line.startswith("|---"): continue
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if not c or not c[0].isdigit(): continue
        if by_col:
            if len(c) < 9: continue
            f, c = c[1], [c[0]] + c[2:]
        else:
            if len(c) < 8: continue
            f = fam
        if not f: continue
        raw = c[6].strip().lower() if c[6] else ""
        lab = ("instrument-gap" if "gap" in raw else "counterfeit" if "counter" in raw else "honest" if "honest" in raw else raw) if raw else ""
        out.append((f, {"lib": c[1], "file": c[2], "line": int(c[3]) if c[3].isdigit() else 0, "function": c[4], "label": lab, "note": c[7] if len(c) > 7 else ""}))
    return out


def main(argv) -> int:
    cal = Path(argv[0]); src = Path(argv[1]).expanduser(); tag = argv[2]
    sheets = [src] if src.is_file() else sorted(list(src.rglob("labels_*.md")) + list(src.rglob("repo_*.md")))
    (cal / "labels").mkdir(exist_ok=True); today = date.today().isoformat()
    groups: dict = {}
    for sh in sheets:
        for fam, r in parse_sheet(sh): groups.setdefault(fam, []).append(r)
    for fam, rows in sorted(groups.items()):
        reqp = cal / "label_requests" / f"{fam}.json"
        req = {(r["lib"], r["file"], r["line"], r["function"]) for r in json.load(open(reqp))["rows"]} if reqp.exists() else set()
        outp = cal / "labels" / f"{fam}.json"
        cur = json.load(open(outp)) if outp.exists() else {"family": fam, "labels": []}
        idx = {(x["lib"], x["file"], x["line"], x["function"]): x for x in cur["labels"]}
        n = unmatched = conflicts = 0
        for r in rows:
            if not r["label"]: continue
            k = (r["lib"], r["file"], r["line"], r["function"])
            if req and k not in req: unmatched += 1; continue
            if k in idx and idx[k]["label"] != r["label"]:
                conflicts += 1; prev = idx[k]
                prev.setdefault("also", []).append({"label": r["label"], "by": tag, "dated": today, "note": r["note"]})
                prev["label"] = "counterfeit"; prev["note"] = (prev.get("note", "") + f" | CONFLICT with {tag}: {r['label']} — stays counterfeit until adjudicated").strip(" |")
            else:
                idx[k] = {**r, "by": tag, "dated": today}; n += 1
        cur["labels"] = list(idx.values())
        outp.write_text(json.dumps(cur, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        c = __import__("collections").Counter(x["label"] for x in cur["labels"])
        by_lib = __import__("collections").Counter(x["lib"] for x in cur["labels"])
        print(f"{fam}: +{n} from {tag} (unmatched {unmatched}, conflicts {conflicts}) → {dict(c)} over {len(by_lib)} repos")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
