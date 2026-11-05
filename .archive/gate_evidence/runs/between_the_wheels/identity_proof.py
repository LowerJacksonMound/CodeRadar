"""Run 141 — the Q3 identity proof.

The old guarantee was `byte_identical: true`. Under Q3 the CLIENT edits the target, so the new form
is: **the difference set between the COPY-FIRST snapshot and the final target equals EXACTLY the
client's edit log — nothing else.** No CodeRadar mirror, no `__pycache__`, no run state, no file
the client did not name.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/identity_proof.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

RUNDIR = Path(__file__).resolve().parent
TARGET = Path("/Users/dev/Desktop/between_the_wheels")
SNAP = sorted((Path.home() / "CodeRadar_snapshots").glob("between_the_wheels_*"))[-1]

log = json.loads((RUNDIR / "client_edit_log.json").read_text())
claimed = {r["file"] for r in log if not r["reverted"]}
backed_out = {r["file"] for r in log if r["reverted"]}


def listing(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.md5(p.read_bytes()).hexdigest()
    return out


a, b = listing(SNAP), listing(TARGET)
only_snap = sorted(set(a) - set(b))
only_target = sorted(set(b) - set(a))
changed = sorted(p for p in set(a) & set(b) if a[p] != b[p])
moved = set(only_snap) | set(only_target) | set(changed)

print(f"snapshot : {SNAP}   ({len(a)} files)")
print(f"target   : {TARGET}   ({len(b)} files)")
print(f"\nfiles only in the snapshot : {len(only_snap)}  {only_snap}")
print(f"files only in the target   : {len(only_target)}  {only_target}")
print(f"files with different bytes : {len(changed)}")
for p in changed:
    n = sum(1 for r in log if r["file"] == p and not r["reverted"])
    print(f"   {p:52s} {n} edit(s) in the client's log")

print(f"\nthe client's edit log claims {len(claimed)} files")
unclaimed = sorted(moved - claimed)
unmoved = sorted(claimed - moved)
print(f"  moved but NOT in the log (residue, CodeRadar or otherwise): {len(unclaimed)}  {unclaimed}")
print(f"  in the log but NOT moved                                  : {len(unmoved)}  {unmoved}")
print(f"  backed out (in the log, restored to snapshot bytes)       : {len(backed_out)}  "
      f"{sorted(backed_out)}")

verdict = not unclaimed and not unmoved
print(f"\nQ3 IDENTITY PROOF: {'PASS' if verdict else 'FAIL'} — the difference set "
      f"{'IS' if verdict else 'IS NOT'} exactly the client's edit log")
(RUNDIR / "identity_proof.json").write_text(json.dumps(
    {"snapshot": str(SNAP), "target": str(TARGET), "snapshot_files": len(a),
     "target_files": len(b), "only_in_snapshot": only_snap, "only_in_target": only_target,
     "changed": changed, "claimed": sorted(claimed), "unclaimed_moves": unclaimed,
     "claimed_but_unmoved": unmoved, "backed_out": sorted(backed_out), "pass": verdict},
    indent=2))
raise SystemExit(0 if verdict else 1)
