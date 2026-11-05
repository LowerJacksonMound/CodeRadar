"""Run 141 `between_the_wheels`, PHASE 4 — the Builder takes the return channel.

Watches `cr_status.finished_inputs` cycle by cycle and reads three of the reported rows back with
`cr_row` to show the re-decide: a `confirmed` verdict joins the row's evidence, a `failed` one
re-routes the Ranker.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run141_phase4.py
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

WATCH = ["colorama/repair_plant_flow.py::sign::24",
         "colorama/repair_plant_trust.py::label::22",
         "colorama/repair_plant_invented.py::__serialize__::18",
         "colorama/ansitowin32.py::isatty::49",
         "colorama/ansitowin32.py::closed::62"]


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", TARGET], cwd=str(TREE))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=3000.0) as session:
            await session.initialize()

            async def call(name, arguments=None):
                res = await session.call_tool(name, arguments or {})
                return json.loads(res.content[0].text)

            track = []
            start = (await call("cr_status")).get("cycle")
            print(f"watching from cycle {start} …")
            for attempt in range(30):
                await asyncio.sleep(20)
                st = await call("cr_status")
                inp = ((st.get("summary") or {}).get("finished_inputs") or {})
                rec = {"cycle": st.get("cycle"), "finished": st.get("finished"),
                       "finished_reason": st.get("finished_reason"),
                       "finished_inputs": inp, "infractions": st.get("infractions")}
                if not track or track[-1]["cycle"] != rec["cycle"]:
                    track.append(rec)
                    print(f"  cycle {rec['cycle']}: counterfeit_failed="
                          f"{inp.get('counterfeit_failed')} mypy_errors={inp.get('mypy_errors')} "
                          f"severed_links={inp.get('severed_links')} · "
                          f"{json.dumps(st.get('infractions'))}")
                seen = 0
                rows = {}
                for rid in WATCH:
                    row = (await call("cr_row", {"id": rid})).get("row") or {}
                    rows[rid] = row
                    if row.get("tester"):
                        seen += 1
                if seen >= 3 and len(track) >= 2:
                    break
            (RUNDIR / "phase4_status_track.json").write_text(json.dumps(track, indent=2, default=str))

            out = {}
            for rid in WATCH:
                data = await call("cr_row", {"id": rid})
                row = data.get("row") or {}
                out[rid] = {
                    "found": bool(row), "solution_kind": row.get("solution_kind"),
                    "digest": row.get("digest"), "tester": row.get("tester"),
                    "evidence": row.get("evidence"), "status": row.get("status"),
                    "no_fix_status": row.get("no_fix_status"),
                    "why": (row.get("decision") or {}).get("why"),
                }
                print(f"\nROW {rid}")
                print(f"   found {bool(row)} · kind {row.get('solution_kind')} · "
                      f"digest {row.get('digest')} · status {row.get('no_fix_status') or row.get('status')}")
                print(f"   tester   {json.dumps(row.get('tester'))}")
                print(f"   evidence {json.dumps(row.get('evidence'))[:260]}")
                print(f"   why      {str((row.get('decision') or {}).get('why'))[:300]} …")
            (RUNDIR / "phase4_redecide.json").write_text(json.dumps(out, indent=2, default=str))

            final = await call("cr_status")
            (RUNDIR / "phase4_status_final.json").write_text(json.dumps(final, indent=2, default=str))
            print(f"\nfinal cycle {final.get('cycle')} · finished {final.get('finished')} "
                  f"({final.get('finished_source')}) · {final.get('finished_reason')}")
            print(f"  summary  {json.dumps(final.get('summary'))}")
            print(f"  rows     {json.dumps(final.get('infractions'))}")
            print("PHASE 4 DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
