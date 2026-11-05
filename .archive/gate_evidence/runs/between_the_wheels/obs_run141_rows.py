"""Run 141 — `cr_row` in full for the prescription rows the client is about to render.
`decision.why`, the observations and the row's own `fix` are what the client reads before it
fills a shape's <placeholders> (Q8 / I-75).

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run141_rows.py <ids-file>
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

TREE = Path(__file__).resolve().parents[3]
RUNDIR = Path(__file__).resolve().parent
SCRIPT = TREE / ".venv_new" / "bin" / "coderadar-mcp"
TARGET = "/Users/dev/Desktop/between_the_wheels"
IDS = json.loads(Path(sys.argv[1]).read_text())
OUT = Path(sys.argv[2])


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", TARGET], cwd=str(TREE))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=600.0) as session:
            await session.initialize()
            got = {}
            for rid in IDS:
                res = await session.call_tool("cr_row", {"id": rid})
                data = json.loads(res.content[0].text)
                row = data.get("row") or {}
                got[rid] = {
                    "row_key": row.get("row_key"),
                    "rule_ids": row.get("rule_ids"),
                    "solution_kind": row.get("solution_kind"),
                    "selected_role": row.get("selected_role"),
                    "digest": row.get("digest"),
                    "replace_span": row.get("replace_span"),
                    "before_code": row.get("before_code"),
                    "after_code": row.get("after_code"),
                    "fix": row.get("fix"),
                    "decision": row.get("decision"),
                    "observations": row.get("observations"),
                    "infractions": row.get("infractions"),
                    "tester": row.get("tester"),
                    "return_channel": data.get("return_channel"),
                }
                print(f"{rid}\n  why: {str((row.get('decision') or {}).get('why'))[:300]}")
            OUT.write_text(json.dumps(got, indent=2, default=str))
            print(f"\n{len(got)} rows → {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
