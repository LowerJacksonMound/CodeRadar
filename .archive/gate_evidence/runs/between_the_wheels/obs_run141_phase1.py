"""Run 141 `between_the_wheels`, PHASE 1 — the read pass + the baseline runner + every
`cr_apply` payload, driven over the REAL stdio protocol with the SDK client.

T5: the client is Claude Code. This script is the client's hands; the thinking (which rows to
apply, how a shape's <placeholders> are rendered) happens between phase 1 and phase 2.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run141_phase1.py <target>
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

TREE = Path(__file__).resolve().parents[3]
RUNDIR = Path(__file__).resolve().parent
SCRIPT = TREE / ".venv_new" / "bin" / "coderadar-mcp"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "/Users/dev/Desktop/between_the_wheels"
LONG = 3000.0


def shown(data, keys=None, width=520):
    if keys:
        data = {k: data.get(k) for k in keys}
    text = json.dumps(data, default=str)
    return text if len(text) <= width else text[:width] + " …"


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", TARGET], cwd=str(TREE))
    print(f"$ {SCRIPT} --target {TARGET}")
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream, read_timeout_seconds=LONG) as session:
            info = await session.initialize()
            print(f"INITIALIZE  server {info.server_info.name} {info.server_info.version} "
                  f"· protocol {info.protocol_version}")
            listed = await session.list_tools()
            print(f"LIST_TOOLS  {len(listed.tools)} tools")

            async def call(name, arguments=None, keys=None, width=520, quiet=False):
                result = await session.call_tool(name, arguments or {})
                text = result.content[0].text
                data = json.loads(text)
                if not quiet:
                    print(f"\nCALL {name}({json.dumps(arguments or {})})"
                          f"{'  [isError]' if result.is_error else ''}")
                    print("  " + shown(data, keys, width))
                return data

            # ── 1. cr_watch ─────────────────────────────────────────────────
            watch = await call("cr_watch", {"target": TARGET},
                               keys=["started", "target", "repo_id", "phase", "gate_budget_s",
                                     "dashboard_url", "health_url", "error"])
            for g in watch.get("gates") or []:
                print(f"    GATE {g.get('gate')}: {g.get('status')} {g.get('seconds')}s")
            if not watch.get("started"):
                print("!! cr_watch did not bring the stack up")
                return 1
            (RUNDIR / "phase1_watch.json").write_text(json.dumps(watch, indent=2, default=str))

            # ── 2. cr_status — wait for counterfeit_failed to be MEASURED ────
            st = None
            for attempt in range(40):
                st = await call("cr_status", quiet=True)
                reason = str(st.get("finished_reason") or "")
                if "NOT MEASURED" not in reason and (st.get("infractions") or {}).get("failed"):
                    break
                print(f"  poll {attempt + 1}: cycle {st.get('cycle')} · {reason}")
                await asyncio.sleep(15)
            print("\nCALL cr_status (measured)")
            print("  " + shown(st, ["phase", "cycle", "finished", "finished_reason",
                                    "finished_source", "infractions", "summary"], 900))
            (RUNDIR / "phase1_status.json").write_text(json.dumps(st, indent=2, default=str))

            # ── 3. cr_infractions — every page, by file ──────────────────────
            page1 = await call("cr_infractions", {"page": 1},
                               keys=["page", "pages", "total", "page_size", "files", "last_scan"])
            rows = list(page1["rows"])
            for p in range(2, int(page1["pages"]) + 1):
                got = await call("cr_infractions", {"page": p},
                                 keys=["page", "pages", "total", "page_size", "files"])
                rows.extend(got["rows"])
            print(f"\n  {len(rows)} rows over {page1['pages']} pages, total {page1['total']}")
            (RUNDIR / "phase1_rows.json").write_text(json.dumps(rows, indent=2, default=str))

            # ── 4. cr_wiring · cr_data_types · cr_intent ─────────────────────
            wiring = await call("cr_wiring", {},
                                keys=["counts", "all_connected", "cycles", "severed_links"])
            print(f"  nodes {len(wiring['nodes'])} · edges {len(wiring['edges'])}")
            dt = await call("cr_data_types", {},
                            keys=["chosen", "not_run", "issues", "contract_violations"])
            intent = await call("cr_intent", {},
                                keys=["target", "repo_id", "statement", "facts_by_source", "file"])
            (RUNDIR / "phase1_context.json").write_text(json.dumps(
                {"wiring": {k: wiring.get(k) for k in
                            ("counts", "all_connected", "cycles", "severed_links")},
                 "nodes": len(wiring["nodes"]), "edges": len(wiring["edges"]),
                 "data_types": {k: dt.get(k) for k in
                                ("chosen", "not_run", "issues", "contract_violations")},
                 "intent": {k: intent.get(k) for k in
                            ("statement", "facts_by_source", "file")}},
                indent=2, default=str))

            # ── 5. cr_run_module — the BASELINE, before a single edit ────────
            base = await call("cr_run_module", {"path": "pytest", "args": ["colorama/tests", "-q"]},
                              keys=["exit_code", "duration_s", "module", "args", "seen_on_band",
                                    "timed_out", "error"])
            print("  stdout tail: " + str(base.get("stdout") or "")[-200:].replace("\n", " | "))
            (RUNDIR / "phase1_runner_baseline.json").write_text(
                json.dumps(base, indent=2, default=str))

            # ── 6. cr_apply on EVERY row that has a solution ────────────────
            payloads = []
            t0 = time.time()
            for r in rows:
                if not r.get("has_solution"):
                    continue
                out = await call("cr_apply", {"row": r["id"]}, quiet=True)
                payloads.append(out)
            print(f"\ncr_apply over {len(payloads)} rows with a solution in {time.time() - t0:.1f}s")
            kinds: dict[str, int] = {}
            clean = 0
            for p in payloads:
                kinds[p.get("kind")] = kinds.get(p.get("kind"), 0) + 1
                if p.get("applies_cleanly") is True:
                    clean += 1
            print(f"  kinds {kinds} · applies_cleanly true on {clean}")
            (RUNDIR / "phase1_apply_payloads.json").write_text(
                json.dumps(payloads, indent=2, default=str))

            print("\nPHASE 1 DONE — the stack is still UP; the client now edits the target.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
