"""launch_progress.json — the opening sequence's step list, shared by launch.sh and the gearbox.

owner 2026-09-29: EVERY step of the opening sequence has its own mention and light on the overlay, in run
order. launch.sh starts the gearbox in the background BEFORE its own target steps, so the two write this
file at the same time. Every write is read-modify-write under an exclusive flock on a sidecar lock file (a
lock on the JSON itself is lost when the rename swaps the file) through a temp file unique to the writer —
no update is lost and no writer trips over the other's temp file. Readers need no lock: the rename is atomic.

A write that fails is reported on stderr and never raised: a progress light must never stop the launch.

CLI (launch.sh): launch_progress.py <file> <stage|-> <status> [detail] [started-epoch] — the start time is for
steps that ran before the file existed. Always exits 0.
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import tempfile
import time
from pathlib import Path

STEPS = [("choices", "your choices"), ("preflight", "clear the last run"),
         ("gearbox", "start the supervisor"), ("dashboard", "open the dashboard"),
         ("snapshot", "back up your repo"), ("health", "CodeRadar self-test"),
         ("whitelist", "sort Python files from other files"), ("target_env", "set up your repo's Python"),
         ("circuit", "map which files import which"), ("wiring", "check every file is on the map"),
         ("noai", "check code does what it says"), ("solutions", "prepare fixes")]
ORDER = [k for k, _ in STEPS]
# A step is finished when it passed, or ran degraded: it did its job with a named shortfall and the
# scan proceeds (the target's Python env failed to build — the readers fall back and say so, Q5).
# `red` (M-54, 2026-10-07): the step finished and its verdict is red — the target cannot run in the env it was
# built — the scan still proceeds (Q5), so the launch goes on and the overlay keeps the red light with its reason.
FINISHED = ("pass", "degraded", "red")


def fresh() -> dict:
    return {"overall": "running", "order": list(ORDER),
            "stages": {k: {"status": "pending", "label": label} for k, label in STEPS}}


def read(path: Path | str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}


def unfinished(doc: dict) -> list[str]:
    """Every step of the opening sequence not yet pass/degraded, in run order."""
    stages = doc.get("stages") or {}
    return [k for k in ORDER if (stages.get(k) or {}).get("status") not in FINISHED]


def update(path: Path | str, stage: str, status: str, detail: str = "",
           started: float | None = None, create: bool = True) -> dict | None:
    """One step's status (or the overall status, stage '-') into the file. Returns the doc written,
    or None when nothing was written (the file is gone and create=False, or the write failed)."""
    path = Path(path)
    try:
        with open(f"{path}.lock", "a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if path.exists():
                doc = read(path) or fresh()
            elif create:
                doc = fresh()
            else:
                return None
            now = time.time()
            if stage == "-":
                doc["overall"] = status
                if detail:
                    doc["detail"] = detail
            else:
                st = doc.setdefault("stages", {}).setdefault(stage, {})
                # cr_trials F6 (2026-11-04): a step that already passed keeps its time; a later pass write (the
                # fix builder's build time is re-read every cycle) updates the detail only, so the launch row
                # shows the launch step's seconds, not the latest cycle's.
                passed_already = status == "pass" and st.get("status") == "pass" and "secs" in st
                if started is not None and not passed_already:
                    st["started"] = started
                if status == "running":
                    st["started"] = st.get("started", now)
                elif "started" in st and not passed_already:
                    st["secs"] = round(now - st["started"], 1)
                st["status"] = status
                st["detail"] = detail
            doc["updated"] = now
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}_{os.getpid()}_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(doc, f, indent=2)
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
            return doc
    except Exception as e:
        print(f"[launch progress] not recorded ({stage} {status}): {type(e).__name__}: {e}", file=sys.stderr)
        return None


if __name__ == "__main__":
    import argparse
    _ap = argparse.ArgumentParser(description="record one opening-sequence step in launch_progress.json")
    _ap.add_argument("file")
    _ap.add_argument("stage")
    _ap.add_argument("status")
    _ap.add_argument("detail", nargs="?", default="")
    _ap.add_argument("started", nargs="?", default="", help="epoch start time, for a step that ran before the file existed")
    try:
        _a = _ap.parse_args()
        update(_a.file, _a.stage, _a.status, _a.detail, started=float(_a.started) if _a.started else None)
    except (SystemExit, ValueError) as e:
        print(f"[launch progress] bad arguments: {e}", file=sys.stderr)
    sys.exit(0)
