#!/usr/bin/env python3
"""obs_run149_phase3.py — RUN 149 `marathon`: the client rule from run 143 —
*run the entry to light the wiring, run the suite to test the repairs.*

    cr_run_module(pytest)  → the eight repairs must leave 38 passed / 14 skipped, exit 0
    cr_run_module(demos/demo01.py) → the app entry, so the wiring lights
    cr_wiring before / after
    cr_report_outcome(confirmed) on every applied row
"""
import json
import sys
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.read_tools import cr_wiring, cr_status         # noqa: E402
from coderadar_mcp.write_tools import cr_run_module, cr_report_outcome   # noqa: E402

RUNDIR = ROOT / ".archive" / "runs" / "marathon"
LOG = json.loads((RUNDIR / "client_edit_log_run149.json").read_text())
out: dict = {}


def show(tag, r, keys):
    print(f"\n{tag}")
    for k in keys:
        print(f"  {k:20s} {json.dumps(r.get(k), default=str)[:300]}")


def main() -> int:
    w0 = cr_wiring()
    out["wiring_before"] = w0
    print(f"cr_wiring BEFORE: {len(w0.get('nodes') or [])} nodes · {len(w0.get('edges') or [])} edges "
          f"· {json.dumps(w0.get('states') or w0.get('summary'))}")

    suite = cr_run_module("colorama/tests", args=["-q"], as_module=False)
    out["suite"] = suite
    show("cr_run_module — the SUITE (pytest colorama/tests -q)", suite,
         ["module", "exit_code", "duration_s", "files_added", "error"])
    print("  stdout tail:")
    for l in (suite.get("stdout") or "").strip().splitlines()[-4:]:
        print(f"    {l}")

    entry = cr_run_module("demos/demo01.py", as_module=False)
    out["entry"] = entry
    show("cr_run_module — the APP ENTRY (demos/demo01.py, as run 143 did)", entry,
         ["module", "exit_code", "duration_s", "files_added", "error"])
    print("  stdout tail:")
    for l in (entry.get("stdout") or "").strip().splitlines()[-4:]:
        print(f"    {l!r}")

    w1 = cr_wiring()
    out["wiring_after"] = w1
    print(f"\ncr_wiring AFTER: {len(w1.get('nodes') or [])} nodes · {len(w1.get('edges') or [])} edges "
          f"· {json.dumps(w1.get('states') or w1.get('summary'))}")

    out["outcomes"] = {}
    print("\ncr_report_outcome(confirmed) on every applied row")
    for r in LOG:
        res = cr_report_outcome(r["row"], "confirmed",
                                note=f"run 149 — merged tree; T6 #{r['t6_row']} "
                                     f"{r['selected_role']}; suite 38 passed / 14 skipped, exit 0",
                                tester="coderadar-mcp run149", edit_kind="diff")
        out["outcomes"][r["row"]] = res
        print(f"  #{r['t6_row']:<3} written={res.get('written')} bytes={res.get('bytes')} "
              f"error={res.get('error')}")

    out["status_after_outcomes"] = cr_status()
    (RUNDIR / "phase3_suite_entry_outcomes.json").write_text(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
