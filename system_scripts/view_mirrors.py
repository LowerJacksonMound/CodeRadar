"""view_mirrors.py — the dash mirrors of every folder the owner has VIEWED (owner ruling 2026-10-07 ~05:50).

A folder the dash has shown this run (the root counts) gets two visible JSONL files IN that folder, next to its
code, for an agent working there to read:

    <folder>/coderadar_dash.jsonl   — what the dash shows for that folder: its files, links, breaks,
                                      dataflows, edit badges and the trackers' rows (mypy, path hacks,
                                      sync review, dead code, naming drift) for files under it
    <folder>/coderadar_noai.jsonl   — the counterfeit-code rows for files under it (repairs,
                                      no vetted fix, withheld) plus the folder's counts

One JSON object per line, each with a `kind`. Line 1 is always `kind: view` (the folder, when, and the counts).
A folder that was never viewed gets neither file. Written by the circuit daemon only, each frame, from the
same data as the dash; removed at teardown (gearbox) — they are never left in the target.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

DASH_NAME = "coderadar_dash.jsonl"
NOAI_NAME = "coderadar_noai.jsonl"
NAMES = (DASH_NAME, NOAI_NAME)


def is_view_mirror(rel_posix: str) -> bool:
    """True for a view mirror at any depth (the teardown identity check and the run diff exempt it)."""
    return rel_posix.rsplit("/", 1)[-1] in NAMES


def _under(path: Optional[str], folder: str) -> bool:
    """*path* (repo-relative, '/'-joined) sits in *folder* or below it; '' is the root (everything)."""
    if not path:
        return False
    return not folder or path == folder or path.startswith(folder + "/")


def dash_rows(folder: str, circuit: Dict[str, Any], monitor: Dict[str, Any]) -> List[dict]:
    """The dash's rows for *folder*: every file under it, every link with an end under it, and the tracker rows."""
    nodes = [n for n in circuit.get("nodes") or [] if _under(n.get("relative_path"), folder)]
    loaded = {n.get("name"): bool(n.get("runtime_loaded")) for n in circuit.get("nodes") or []}
    severed = {tuple(p) for p in circuit.get("severed_links") or [] if isinstance(p, (list, tuple)) and len(p) == 2}
    rows: List[dict] = []
    for n in nodes:
        rows.append({"kind": "file", "file": n.get("relative_path"), "connected": n.get("connected"),
                     "import_error": n.get("import_error"), "ran": bool(n.get("runtime_loaded")),
                     "edit_badges": [t.get("lines") for t in n.get("change_tags") or []]})
    for src, dst in (tuple(e) for e in circuit.get("edges") or [] if len(e) == 2):
        if _under(src, folder) or _under(dst, folder):
            state = "severed" if (src, dst) in severed else ("live" if loaded.get(dst) else "possible")
            rows.append({"kind": "link", "from": src, "to": dst, "state": state,
                         "leaves_folder": not (_under(src, folder) and _under(dst, folder))})
    for df in circuit.get("dataflows") or []:
        if _under(df.get("src"), folder) or _under(df.get("dst"), folder):
            rows.append({"kind": "dataflow", "from": df.get("src"), "to": df.get("dst"),
                         "channel": df.get("channel"), "proof": df.get("proof")})
    # one split with the dash (mypy_partition): a type error is `kind: mypy`; an annotation note is
    # `kind: mypy_note` — the dash shows "0 type errors, 30 annotation notes", so the mirror must not call notes errors
    try:
        import mypy_partition
        _errs, _notes = mypy_partition.partition(list((monitor.get("mypy") or {}).get("errors") or []))
    except Exception:
        _errs, _notes = list((monitor.get("mypy") or {}).get("errors") or []), []
    for kind, lines in (("mypy", _errs), ("mypy_note", _notes)):
        for line in lines:
            f, _, rest = str(line).partition(":")
            if _under(f, folder):
                ln, _, msg = rest.partition(":")
                rows.append({"kind": kind, "file": f, "line": int(ln) if ln.strip().isdigit() else None,
                             "message": msg.strip()})
    for f, hacks in ((monitor.get("path_hacks") or {}).get("hacks") or {}).items():
        if _under(f, folder):
            for h in hacks or []:
                rows.append({**{k: v for k, v in h.items() if k != "file"}, "file": f, "kind": "path_hack"})
    for r in (monitor.get("functions") or {}).get("sync_needs_review") or []:
        if _under(r.get("file"), folder):
            rows.append({**r, "kind": "sync_review"})
    for r in (monitor.get("dead_code") or {}).get("items") or []:
        if _under(r.get("file"), folder):
            rows.append({**r, "kind": "dead_code"})
    for r in (monitor.get("pytest") or {}).get("rows") or []:
        if _under(r.get("file"), folder):
            rows.append({**r, "kind": "pytest"})
    for r in (monitor.get("naming_drift") or {}).get("rows") or []:
        sites = [s for s in r.get("sites") or [] if _under(s.get("file"), folder)]
        if sites:
            rows.append({**{k: v for k, v in r.items() if k != "sites"}, "sites": sites, "kind": "naming_drift"})
    return rows


def noai_rows(folder: str, noai: Dict[str, Any]) -> List[dict]:
    rows: List[dict] = []
    for key, kind in (("repairs", "repair"), ("no_vetted_fix", "no_vetted_fix"), ("withheld", "withheld")):
        for r in noai.get(key) or []:
            if _under(r.get("file"), folder):
                rows.append({**r, "kind": kind})
    return rows


def _write_jsonl(path: Path, head: dict, rows: Iterable[dict]) -> None:
    """Atomic: a reader never sees half a file."""
    fd, tmp = tempfile.mkstemp(prefix=".cr_view_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for row in [head, *rows]:
                fh.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write(target: Path, folders: Iterable[str], circuit: Dict[str, Any], monitor: Dict[str, Any],
          noai: Dict[str, Any]) -> List[str]:
    """Write both mirrors into each viewed folder that exists inside *target*. Returns the folders written."""
    target = Path(target).resolve()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    done: List[str] = []
    for folder in sorted({(f or "").strip("/") for f in folders}):
        d = (target / folder).resolve() if folder else target
        if not d.is_dir() or (d != target and target not in d.parents):
            continue
        drows = dash_rows(folder, circuit, monitor)
        nrows = noai_rows(folder, noai)
        files = [r for r in drows if r["kind"] == "file"]
        links = [r for r in drows if r["kind"] == "link"]
        view = {"kind": "view", "folder": folder or ".", "written_at": stamp,
                "files": len(files), "files_not_connected": sum(1 for r in files if not r["connected"]),
                "links": len(links), "links_live": sum(1 for r in links if r["state"] == "live"),
                "links_severed": sum(1 for r in links if r["state"] == "severed"),
                "dataflows": sum(1 for r in drows if r["kind"] == "dataflow"),
                "mypy_errors": sum(1 for r in drows if r["kind"] == "mypy"),
                "mypy_notes": sum(1 for r in drows if r["kind"] == "mypy_note"),
                "path_hacks": sum(1 for r in drows if r["kind"] == "path_hack"),
                "pytest_failing": sum(1 for r in drows if r["kind"] == "pytest")}
        _write_jsonl(d / DASH_NAME, view, drows)
        _write_jsonl(d / NOAI_NAME, {**view, "repairs": sum(1 for r in nrows if r["kind"] == "repair"),
                                     "no_vetted_fix": sum(1 for r in nrows if r["kind"] == "no_vetted_fix"),
                                     "withheld": sum(1 for r in nrows if r["kind"] == "withheld")}, nrows)
        done.append(folder)
    return done


def remove_all(target: Path) -> List[str]:
    """Teardown: delete every view mirror under *target* (no symlink followed). Returns what was removed."""
    target = Path(target)
    gone: List[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(root, x))]
        for name in files:
            if name in NAMES:
                p = Path(root) / name
                try:
                    p.unlink()
                    gone.append(p.relative_to(target).as_posix())
                except OSError:
                    pass
    return gone
