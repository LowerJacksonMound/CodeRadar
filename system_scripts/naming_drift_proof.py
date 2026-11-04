"""naming_drift_proof.py — the naming-drift data type tracker's gate (plan §F.1 + §F.4, 2026-10-01).

Runs the ONE launch scan over the plant repo `system_scripts/naming_drift/plants/` (12 files:
3 T1 groups, 2 T2, 1 T3, 2 pre-existing groups, a red-herring file of locals that must stay silent, one accepted
variant) and demands the launch-pass rows equal `expected_rows.json` byte-for-byte on
(key, spelling, tier, kind, sites). Also demands the block before any baseline reads NOT MEASURED (never 0).

    .venv_new/bin/python system_scripts/naming_drift_proof.py          exit 0 = PASS
    .venv_new/bin/python system_scripts/naming_drift_proof.py --write-expected   (re-plant only; owner's call)

State (the accepted ruling the plant needs) goes to a temp dir — nothing is written into the tree.
Promoted from seat ND1's `proof_f1.py` (LANES_1001/ND1.md §F.1) by the orchestrator.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

TREE = Path(__file__).resolve().parent.parent
SCRIPTS = TREE / "system_scripts"
PLANT = TREE / "system_scripts" / "naming_drift" / "plants"
sys.path.insert(0, str(SCRIPTS))
from ast_scanner import CircuitScanner  # noqa: E402
import naming_drift_detector as nd  # noqa: E402

FAILURES: list[str] = []


def ok(cond: bool, line: str) -> None:
    print(("  ✓ " if cond else "  ✗ ") + line)
    if not cond:
        FAILURES.append(line)


def _expected_rows_text(path: Path) -> str:
    """The plant's hand-checked rows — the proof's fixture, read beside its own module (gate 19 plants)."""
    text = path.read_text()
    return text.rstrip("\n")


def main() -> int:
    print("naming-drift proof — plant repo launch pass (§F.1) + NOT MEASURED before the baseline (§F.4)")
    if not PLANT.is_dir():
        ok(False, f"plant repo absent: {PLANT}")
        return 1
    with tempfile.TemporaryDirectory(prefix="naming_drift_proof_") as td:
        state = Path(td)
        repo_id = "plant"
        # the plant's accepted ruling (§F.1 "1 accepted variant"): buf_size is a legitimate variant of buffer_size
        (state / f"accepted_{repo_id}.json").write_text(json.dumps({
            "repo_id": repo_id,
            "entries": [{"spelling": "buf_size", "key": "buffer size", "ruling": "variant",
                         "at": "2026-10-01T00:00:00", "source": "dash"}]}, indent=1))
        tracker = nd.NamingDriftTracker(repo_id, data_dir=state,
                                        abbreviations_file=SCRIPTS / "naming_drift" / "abbreviations.json")
        # (§F.4) before the launch scan has completed: NOT MEASURED, never 0
        before = tracker.report()
        ok(before.get("ran") is False and before.get("new") is None and before.get("groups") is None,
           f"before the baseline the block is NOT MEASURED, not 0 — ran={before.get('ran')} "
           f"new={before.get('new')} status={before.get('status')!r}")

        scanner = CircuitScanner(repo_path=str(PLANT), project_root=str(PLANT))
        graph = scanner.get_full_graph(force_refresh=True)
        tracker.baseline(graph.nodes, now="2026-10-01T00:00:00")
        block = tracker.report()
        projection = [{k: r[k] for k in ("key", "spelling", "tier", "kind", "sites")} for r in block["rows"]]
        got = json.dumps(projection, indent=1, sort_keys=True)
        expected_file = PLANT / "expected_rows.json"
        if "--write-expected" in sys.argv:
            expected_file.write_text(got + "\n")
            print(f"  wrote {expected_file} ({len(projection)} rows)")
        print("  " + json.dumps({k: v for k, v in block.items() if k != "rows"}, sort_keys=True))
        for r in block["rows"]:
            print(f"    {r['kind']:12} {r['tier']} key={r['key']!r:28} canonical={r['canonical']:18} "
                  f"spelling={r['spelling']:18} sites={[(s['file'], s['line'], s['name_kind']) for s in r['sites']]}")
        want = _expected_rows_text(expected_file)
        ok(want == got, f"launch-pass rows == expected_rows.json byte-for-byte ({len(projection)} rows, "
                        f"{block['scanned_files']} files)")
        ok(block.get("ran") is True and block.get("new") == 0 and block.get("accepted") == 1,
           f"ran={block.get('ran')} new={block.get('new')} pre_existing={block.get('pre_existing')} "
           f"accepted={block.get('accepted')} by_tier={block.get('by_tier')}")
        silent = [r for r in block["rows"] if r["sites"] and r["sites"][0]["file"].startswith("red_herring")]
        ok(not silent, "red-herring locals (i / idx / index, nested def) fire nothing")
    print(f"naming-drift proof: {'PASS' if not FAILURES else f'FAIL ({len(FAILURES)})'}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
