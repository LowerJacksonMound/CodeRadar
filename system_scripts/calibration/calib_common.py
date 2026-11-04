"""calib_common.py — shared helpers for the bench v2 scripts (calibrator A7, 2026-09-06).
Verdicts are RECOMPUTED from a row's all_ids under a NAMED disposition set; nothing here is a threshold."""
from __future__ import annotations
import glob, json, sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
HERE = Path(__file__).resolve().parent; ROOT = HERE.parents[1]
for p in (str(ROOT), str(ROOT / "system_scripts"), str(HERE)):
    if p not in sys.path: sys.path.insert(0, p)
TABLE = ROOT / "system_scripts" / "rule_dispositions.json"


def load_table() -> Dict[str, Any]:
    return json.load(open(TABLE, encoding="utf-8"))


def table_dispositions(table: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    t = table or load_table()
    return {rid: r["disposition"] for rid, r in t["families"].items()}


def disposition_of(rid: str, disp: Dict[str, str], overrides: Optional[Dict[str, str]] = None) -> str:
    if overrides and rid in overrides: return overrides[rid]
    if rid in disp: return disp[rid]
    if rid.startswith("SIG-"): return disp.get("SIG-*", "context")
    return "deciding"   # no row = deciding (nothing inferred) — the gate fails on it


def deciding_ids(row: Dict[str, Any], disp: Dict[str, str], overrides: Optional[Dict[str, str]] = None) -> List[str]:
    if row.get("species") == "test": return []
    return [i for i in row["all_ids"] if i not in (row.get("ctx_flagged") or []) and disposition_of(i, disp, overrides) == "deciding"]


def context_ids(row: Dict[str, Any], disp: Dict[str, str], overrides: Optional[Dict[str, str]] = None) -> List[str]:
    d = set(deciding_ids(row, disp, overrides))
    return [i for i in row["all_ids"] if i not in d]


def recomputed_failed(row: Dict[str, Any], disp: Dict[str, str], overrides: Optional[Dict[str, str]] = None) -> bool:
    """A row fails when a deciding id is on it. A row that failed with NO id at all (an unreadable file) keeps its verdict."""
    if deciding_ids(row, disp, overrides): return True
    return (not row["passed"]) and not row["all_ids"]


def consistency(rows: Iterable[Dict[str, Any]], disp: Dict[str, str]) -> List[Dict[str, Any]]:
    """Rows whose recomputed raw verdict (no overrides) disagrees with the dump's verdict — must be empty."""
    return [r for r in rows if recomputed_failed(r, disp) != (not r["passed"])]


def dump_libs(cal: Path) -> List[str]:
    """Names of the row dumps in CAL/precision (files that carry `lib` and `rows`; timings.json and friends are not dumps)."""
    out = []
    for p in sorted((cal / "precision").glob("*.json")):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and "lib" in d and "rows" in d: out.append(p.stem)
    return out


def load_dump(cal: Path, lib: str) -> Dict[str, Any]:
    p = cal / "precision" / f"{lib}.json"
    if not p.exists(): raise SystemExit(f"no dump for {lib} at {p} (run dump_rows.py; a timed-out library is recorded in timings.json)")
    return json.load(open(p, encoding="utf-8"))


def verify_rows(rows: Iterable[Dict[str, Any]], disp: Dict[str, str], overrides: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Rows in verify_manifest's shape, verdicts recomputed under the named set."""
    out = []
    for r in rows:
        d = deciding_ids(r, disp, overrides); c = context_ids(r, disp, overrides)
        out.append({"file": r["file"], "function": r["function"], "line": r["line"], "end_line": r["end_line"],
                    "passed": not recomputed_failed(r, disp, overrides), "reason": r.get("reason", ""), "deciding_ids": d, "context_ids": c,
                    "species": r.get("species", "")})
    return out


def manifests(kind: str) -> List[Dict[str, Any]]:
    """'archived' = the pre-calibrator planted builds (never held out); 'corpus_A' / 'corpus_B' = calibrator corpora by half."""
    out = []
    for mf in sorted(glob.glob(str(ROOT / "ARCHIVE/runs/*/manifest.json"))):
        m = json.load(open(mf, encoding="utf-8")); m["_dir"] = str(Path(mf).parent.name)
        if not m.get("planted_findings"): continue
        corpus = m.get("corpus") or {}
        if kind == "archived" and not corpus: out.append(m)
        elif kind == "corpus_A" and corpus.get("half") == "A": out.append(m)
        elif kind == "corpus_B" and corpus.get("half") == "B": out.append(m)
    return out


def target_rows(target: Path) -> List[Dict[str, Any]]:
    """In-process v2 rows for a built target (all_ids; dispositions applied by the caller)."""
    from dump_rows import dump_one
    return dump_one(target)["rows"]
