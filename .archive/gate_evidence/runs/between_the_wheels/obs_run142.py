"""RUN 142 `the_big_money` — THE RUN OF RECORD.

A fresh gearbox on run 141's EDITED target (copied under the run-142 name, the client's 75 edits
kept). Nothing is applied this run: it measures what the client loop did to the target and proves
the teardown is byte-identical again, residue zero, because the client touched nothing.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run142.py <target>
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

TREE = Path(__file__).resolve().parents[3]
SCRIPT = TREE / ".venv_new" / "bin" / "coderadar-mcp"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "/Users/dev/Desktop/the_big_money"
RUNDIR = TREE / ".archive" / "runs" / Path(TARGET).name


def shown(data, keys=None, width=900):
    if keys:
        data = {k: data.get(k) for k in keys}
    text = json.dumps(data, default=str)
    return text if len(text) <= width else text[:width] + " …"


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", TARGET], cwd=str(TREE))
    print(f"$ {SCRIPT} --target {TARGET}")
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=3000.0) as session:
            info = await session.initialize()
            listed = await session.list_tools()
            print(f"INITIALIZE server {info.server_info.name} {info.server_info.version} · "
                  f"protocol {info.protocol_version}  LIST_TOOLS {len(listed.tools)}")

            async def call(name, arguments=None, keys=None, width=900, quiet=False):
                res = await session.call_tool(name, arguments or {})
                data = json.loads(res.content[0].text)
                if not quiet:
                    print(f"\nCALL {name}({json.dumps(arguments or {})[:110]})"
                          f"{'  [isError]' if res.is_error else ''}")
                    print("  " + shown(data, keys, width))
                return data

            watch = await call("cr_watch", {"target": TARGET},
                               keys=["started", "target", "repo_id", "phase", "gate_budget_s",
                                     "dashboard_url", "health_url", "error"])
            for g in watch.get("gates") or []:
                print(f"    GATE {g.get('gate')}: {g.get('status')} {g.get('seconds')}s")
            if not watch.get("started"):
                print("!! cr_watch did not bring the stack up")
                return 1
            RUNDIR.mkdir(parents=True, exist_ok=True)
            (RUNDIR / "run142_watch.json").write_text(json.dumps(watch, indent=2, default=str))

            at_monitoring = await call("cr_status",
                                       keys=["phase", "cycle", "finished", "finished_reason",
                                             "finished_source", "infractions", "summary"])
            (RUNDIR / "run142_status_monitoring.json").write_text(
                json.dumps(at_monitoring, indent=2, default=str))

            print("\nwaiting for the first FULL cycle (counterfeit_failed MEASURED) …")
            st = at_monitoring
            for attempt in range(40):
                reason = str(st.get("finished_reason") or "")
                if "NOT MEASURED" not in reason and (st.get("infractions") or {}).get("failed"):
                    break
                await asyncio.sleep(15)
                st = await call("cr_status", quiet=True)
                print(f"  poll {attempt + 1}: cycle {st.get('cycle')} · {st.get('finished_reason')}")
            print("\nCALL cr_status (first full cycle)")
            print("  " + shown(st, ["phase", "cycle", "finished", "finished_reason",
                                    "finished_source", "infractions", "summary"], 1200))
            (RUNDIR / "run142_status_cycle1.json").write_text(json.dumps(st, indent=2, default=str))

            rows = []
            page1 = await call("cr_infractions", {"page": 1},
                               keys=["page", "pages", "total", "page_size", "files"])
            rows.extend(page1["rows"])
            for p in range(2, int(page1["pages"]) + 1):
                rows.extend((await call("cr_infractions", {"page": p}, quiet=True))["rows"])
            (RUNDIR / "run142_rows.json").write_text(json.dumps(rows, indent=2, default=str))
            print(f"  {len(rows)} rows over {page1['pages']} pages")

            wiring = await call("cr_wiring", {}, keys=["counts", "all_connected", "cycles",
                                                       "severed_links"])
            print(f"  nodes {len(wiring['nodes'])} · edges {len(wiring['edges'])}")
            dt = await call("cr_data_types", {}, keys=["chosen", "not_run", "issues",
                                                       "contract_violations"])
            (RUNDIR / "run142_context.json").write_text(json.dumps(
                {"wiring_counts": wiring.get("counts"), "nodes": len(wiring["nodes"]),
                 "edges": len(wiring["edges"]), "data_types": {k: dt.get(k) for k in
                                                               ("chosen", "not_run", "issues")}},
                indent=2, default=str))

            run = await call("cr_run_module", {"path": "pytest", "args": ["colorama/tests", "-q"]},
                             keys=["exit_code", "duration_s", "args", "seen_on_band", "timed_out",
                                   "error"])
            print("  stdout tail: " + str(run.get("stdout") or "")[-200:].replace("\n", " | "))
            (RUNDIR / "run142_runner.json").write_text(json.dumps(run, indent=2, default=str))

            # Nothing was applied this run: the old guarantee, whole.
            stop = await call("cr_stop", {"verify_identity": True, "mark_pool": False},
                              keys=["stopped", "residue_clean", "byte_identical", "files_compared",
                                    "client_edits", "unexpected_changes", "run_dir", "error"])
            for d in stop.get("daemons_exited") or []:
                print(f"    {d.get('name')} pid {d.get('pid')} exit {d.get('exit_code')} "
                      f"({d.get('signal')})")
            (RUNDIR / "run142_stop.json").write_text(json.dumps(stop, indent=2, default=str))

            hb = await call("cr_hand_back", {"note": "run 142 — the run of record: a fresh gearbox "
                                                     "on run 141's edited target, nothing applied"},
                            keys=["report_path", "builder_cycles", "infractions", "solutions",
                                  "confirmed", "confirmed_fraction", "tester_ran", "status",
                                  "return_channel_lines", "orphans", "unparsed", "finished",
                                  "error"])
            print(f"  per_infraction rows: {len(hb.get('per_infraction') or [])}")
            (RUNDIR / "run142_hand_back.json").write_text(json.dumps(hb, indent=2, default=str))
            print("\nRUN 142 DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
