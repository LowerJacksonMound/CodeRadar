"""Run 141 `between_the_wheels`, PHASE 5 — the teardown, the hand-back, and the Q3 identity proof.

`cr_stop` is given the client's own edit manifest (`expected_changes`), so the new form of the
guarantee is reported on the wire: `residue_clean true · client_edits N · unexpected_changes []`
beside a `byte_identical false` that is now explained rather than bare.

`cr_hand_back` runs AFTER `cr_stop` (T4 decision 3 / defect (b): the gearbox's own teardown writes
`tester_report.json` and would overwrite a hand-back published first).

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run141_phase5.py
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

TREE = Path(__file__).resolve().parents[3]
RUNDIR = Path(__file__).resolve().parent
SCRIPT = TREE / ".venv_new" / "bin" / "coderadar-mcp"
TARGET = "/Users/dev/Desktop/between_the_wheels"

MANIFEST = [p for p in (RUNDIR / "client_edit_manifest.txt").read_text().split() if p]


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", TARGET], cwd=str(TREE))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=3000.0) as session:
            await session.initialize()

            async def call(name, arguments=None):
                res = await session.call_tool(name, arguments or {})
                return json.loads(res.content[0].text)

            last = await call("cr_status")
            print(f"cr_status at close: cycle {last.get('cycle')} · finished {last.get('finished')}"
                  f" ({last.get('finished_source')}) · {last.get('finished_reason')}")
            print(f"  finished_inputs {json.dumps((last.get('summary') or {}).get('finished_inputs'))}")
            print(f"  infractions     {json.dumps(last.get('infractions'))}")
            (RUNDIR / "phase5_status_at_close.json").write_text(json.dumps(last, indent=2, default=str))

            print(f"\ncr_stop with a client manifest of {len(MANIFEST)} paths")
            stop = await call("cr_stop", {"verify_identity": True, "mark_pool": False,
                                          "expected_changes": MANIFEST})
            for k in ("stopped", "residue_clean", "byte_identical", "files_compared",
                      "client_edits", "unexpected_changes", "run_dir", "error"):
                print(f"  {k:20s} {json.dumps(stop.get(k), default=str)[:200]}")
            for d in stop.get("daemons_exited") or []:
                print(f"    {d.get('name')} pid {d.get('pid')} exit {d.get('exit_code')} "
                      f"({d.get('signal')})")
            (RUNDIR / "phase5_stop.json").write_text(json.dumps(stop, indent=2, default=str))

            hb = await call("cr_hand_back", {"note": "run 141 — T5's end-to-end proof: the client "
                                                     "applied 75 rows (55 rewriter diffs, 20 "
                                                     "rendered shapes) over 35 files"})
            for k in ("report_path", "builder_cycles", "infractions", "solutions", "confirmed",
                      "confirmed_fraction", "tester_ran", "status", "return_channel_lines",
                      "orphans", "unparsed", "finished", "error"):
                print(f"  {k:22s} {json.dumps(hb.get(k), default=str)[:160]}")
            print(f"  per_infraction rows: {len(hb.get('per_infraction') or [])}")
            (RUNDIR / "phase5_hand_back.json").write_text(json.dumps(hb, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
