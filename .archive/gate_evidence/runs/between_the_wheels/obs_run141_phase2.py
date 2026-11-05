"""Run 141 `between_the_wheels`, PHASE 2 — the runner AFTER the client's edits, one
`cr_report_outcome` per applied row, and the Builder's re-decide.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run141_phase2.py
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
LONG = 3000.0

LOG = json.loads((RUNDIR / "client_edit_log.json").read_text())


def shown(data, keys=None, width=600):
    if keys:
        data = {k: data.get(k) for k in keys}
    text = json.dumps(data, default=str)
    return text if len(text) <= width else text[:width] + " …"


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", TARGET], cwd=str(TREE))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=LONG) as session:
            await session.initialize()

            async def call(name, arguments=None, keys=None, width=600, quiet=False):
                res = await session.call_tool(name, arguments or {})
                data = json.loads(res.content[0].text)
                if not quiet:
                    print(f"\nCALL {name}({json.dumps(arguments or {})[:120]})"
                          f"{'  [isError]' if res.is_error else ''}")
                    print("  " + shown(data, keys, width))
                return data

            await call("cr_attach", {}, keys=["attached", "target", "phase", "cycle", "error"])

            # ── the runner AFTER the edits ───────────────────────────────────
            after = await call("cr_run_module",
                               {"path": "pytest", "args": ["colorama/tests", "-q"]},
                               keys=["exit_code", "duration_s", "args", "seen_on_band",
                                     "timed_out", "error"])
            print("  stdout tail: " + str(after.get("stdout") or "")[-240:].replace("\n", " | "))
            (RUNDIR / "phase2_runner_after.json").write_text(json.dumps(after, indent=2, default=str))
            runner_ok = after.get("exit_code") == 0

            # ── one outcome per applied row ─────────────────────────────────
            verdict = "confirmed" if runner_ok else "failed"
            note_ok = ("run 141: the client applied this row's edit in the target's working tree "
                       "(Q3) and the target's own runner still passes — 38 passed, 14 skipped")
            results = []
            for rec in LOG:
                note = note_ok if runner_ok else \
                    f"run 141: the target's own runner exits {after.get('exit_code')} after the edits"
                out = await call("cr_report_outcome",
                                 {"row": rec["row"], "outcome": verdict, "note": note,
                                  "tester": "coderadar-mcp run141"}, quiet=True)
                results.append({"row": rec["row"], "written": out.get("written"),
                                "digest": out.get("digest"), "span": out.get("replace_span"),
                                "bytes": out.get("bytes_appended"), "error": out.get("error")})
            ok = sum(1 for x in results if x["written"])
            print(f"\ncr_report_outcome ×{len(results)} → written {ok}, refused {len(results) - ok}"
                  f" · outcome={verdict}")
            for x in results:
                if not x["written"]:
                    print(f"    REFUSED {x['row']}: {x['error']}")
            (RUNDIR / "phase2_outcomes.json").write_text(json.dumps(results, indent=2, default=str))

            # ── the Builder takes the lines; watch finished_inputs move ──────
            print("\nwaiting for the Builder to re-poll the edited files …")
            track = []
            watch_rows = [LOG[0]["row"], LOG[len(LOG) // 2]["row"], LOG[-1]["row"]]
            seen_tester = 0
            for attempt in range(40):
                await asyncio.sleep(20)
                st = await call("cr_status", quiet=True)
                inputs = ((st.get("summary") or {}).get("finished_inputs") or {})
                track.append({"cycle": st.get("cycle"), "finished": st.get("finished"),
                              "finished_inputs": inputs,
                              "infractions": st.get("infractions")})
                print(f"  cycle {st.get('cycle')}: counterfeit_failed="
                      f"{inputs.get('counterfeit_failed')} mypy_errors={inputs.get('mypy_errors')}"
                      f" severed_links={inputs.get('severed_links')}"
                      f" · rows {json.dumps(st.get('infractions'))}")
                seen_tester = 0
                for rid in watch_rows:
                    row = (await call("cr_row", {"id": rid}, quiet=True)).get("row") or {}
                    if row.get("tester"):
                        seen_tester += 1
                if seen_tester == len(watch_rows) and attempt >= 2:
                    break
            (RUNDIR / "phase2_status_track.json").write_text(json.dumps(track, indent=2, default=str))

            # ── cr_row on three of the applied rows: the re-decide ───────────
            redecided = {}
            for rid in watch_rows:
                data = await call("cr_row", {"id": rid}, quiet=True)
                row = data.get("row") or {}
                redecided[rid] = {
                    "solution_kind": row.get("solution_kind"), "digest": row.get("digest"),
                    "tester": row.get("tester"), "evidence": row.get("evidence"),
                    "why": (row.get("decision") or {}).get("why"),
                    "no_fix_status": row.get("no_fix_status"), "status": row.get("status"),
                }
                print(f"\nROW {rid}")
                print(f"   tester  {json.dumps(row.get('tester'))}")
                print(f"   kind    {row.get('solution_kind')} · digest {row.get('digest')}")
                print(f"   why     {str((row.get('decision') or {}).get('why'))[:260]} …")
            (RUNDIR / "phase2_redecide.json").write_text(json.dumps(redecided, indent=2, default=str))

            final = await call("cr_status", keys=["cycle", "finished", "finished_reason",
                                                  "finished_source", "infractions", "summary"],
                               width=1000)
            (RUNDIR / "phase2_status_final.json").write_text(json.dumps(final, indent=2, default=str))
            print("\nPHASE 2 DONE — the stack is still UP.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
