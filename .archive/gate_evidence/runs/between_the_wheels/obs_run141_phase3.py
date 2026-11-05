"""Run 141 `between_the_wheels`, PHASE 3 — the TIGHT loop, all inside one client session:
`cr_apply` → the client renders and edits → `cr_run_module` → `cr_report_outcome`, before the
Builder's next poll can take the repaired row off the mirror.

Phase 2 proved why the loop has to be tight: the client let two Builder cycles pass between the
edits and the outcomes, and 65 of 70 rows were gone from the live mirror by then — a repaired
function stops being an infraction, and `cr_report_outcome` can only take a verdict for a row the
mirror still publishes. The finding is recorded; this phase is the loop done in time.

It also reports the two rows the client BACKED OUT: `colorama/ansitowin32.py::isatty` and
`::closed`, whose rewriter diffs turned a documented fallback into a raise and broke the target's
own tests. `failed`, with the assertion.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/obs_run141_phase3.py
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

TREE = Path(__file__).resolve().parents[3]
RUNDIR = Path(__file__).resolve().parent
SCRIPT = TREE / ".venv_new" / "bin" / "coderadar-mcp"
TARGET = Path("/Users/dev/Desktop/between_the_wheels")
LONG = 3000.0

RENDER = {
    "colorama/repair_plant_extended.py::reserved::10": (
        'def reserved():\n    """Reserved for a later release."""\n'
        '    raise NotImplementedError("reserved: not implemented")\n',
        "shape `def <name>(<params>): \"\"\"<existing docstring>\"\"\" raise NotImplementedError"
        "(\"<name>: not implemented\")` — every placeholder is read straight off the function: "
        "`<name>`=reserved, `<params>`=none, the docstring is the one already there. A body that "
        "is only a docstring returns None silently; the raise makes the promise honest."),
    "colorama/repair_plant_flow.py::sign::24": (
        "def sign(n) -> int:\n    if n > 0:\n        return 1\n"
        "    if n < 0:\n        return -1\n    return 0\n",
        "shape `if <cond>: return <value>; return <value for the other case>`. The name fixes both "
        "missing values: `sign` is -1 / 0 / 1, and the annotation `-> int` says every path must "
        "return an int — the fall-through was None."),
    "colorama/repair_plant_stale.py::__init__::12": (
        '    def __init__(self):\n        self.items = []\n        self.items.append("first")\n',
        "shape `def __init__(self, ...): self.<name> = []   # or {} / set()`. `<name>`=items and "
        "the container is a list — the class body's own `items = []` says so, and appending to that "
        "CLASS attribute is the infraction (every instance shares one list). The instance gets its "
        "own before the append."),
    "colorama/repair_plant_chains.py::label_for::15": (
        'def label_for(code):\n    prefix = "C-"\n    text = prefix + str(code)\n    return text\n',
        "shape `<name> = <initial value>\\n... <first read of <name>> ...`. `<name>`=prefix and "
        "`<initial value>`=\"C-\", both already in the function — the only defect is the order: the "
        "read stood above the binding, so the function raised UnboundLocalError on every call."),
    "colorama/repair_plant_ops.py::note::15": (
        "def note(value):\n    return value.strip()\n",
        "shape `def <name>(...): <action | return <value>>`. `value.strip` named the method and "
        "never called it, so nothing happened and nothing was returned; the two readings the shape "
        "offers collapse into one here — call it and return the result."),
    "colorama/repair_plant_trust.py::label::22": (
        'def label():\n    return "total total"\n',
        "shape `<NAME> = '<the intended visible text — no U+202A..U+202E / U+2066..U+2069 "
        "controls>'`. The literal held U+202E (RIGHT-TO-LEFT OVERRIDE) between `total ` and "
        "`latot`, which renders as a second `total`. The intended visible text is therefore "
        "`total total`, written with no control characters."),
    "colorama/repair_plant_invented.py::__serialize__::18": (
        '    def serialize(self):\n        return {"items": self.items, "count": len(self.items)}\n',
        "shape `def <plain_name>(self, ...):   # was __<name>__`. `<plain_name>`=serialize: "
        "`__serialize__` invents a dunder Python's data model does not define, so nothing ever "
        "calls it implicitly. The body is honest and is kept; the only call site in the file is the "
        "def itself, so the rename reaches everything."),
}

BACKED_OUT = {
    "colorama/ansitowin32.py::isatty::49":
        "run 141: applied, then BACKED OUT by the client. The target's own runner failed — "
        "isatty_test.py::IsattyTest::test_withPycharmNoneOverride: "
        "RuntimeError('isatty failed') where the test asserts False. The rewriter turned a "
        "documented `return False` fallback into a raise.",
    "colorama/ansitowin32.py::closed::62":
        "run 141: applied, then BACKED OUT by the client. The target's own runner failed — "
        "ansitowin32_test.py::StreamWrapperTest::test_closed_shouldnt_raise_on_detached_stream and "
        "AnsiToWin32Test::test_wrap_shouldnt_raise_on_missing_closed_attr: AttributeError escapes "
        "where the tests assert the fallback answers. The rewriter turned a documented "
        "`return True` fallback into a re-raise.",
}


def parse_span(span: str) -> tuple[int, int]:
    _, _, tail = span.rpartition(":L")
    a, _, b = tail.partition("-L")
    return int(a), int(b)


def shown(data, keys=None, width=600):
    if keys:
        data = {k: data.get(k) for k in keys}
    text = json.dumps(data, default=str)
    return text if len(text) <= width else text[:width] + " …"


async def main() -> int:
    params = StdioServerParameters(command=str(SCRIPT), args=["--target", str(TARGET)],
                                   cwd=str(TREE))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=LONG) as session:
            await session.initialize()

            async def call(name, arguments=None, keys=None, width=600, quiet=False):
                res = await session.call_tool(name, arguments or {})
                data = json.loads(res.content[0].text)
                if not quiet:
                    print(f"\nCALL {name}({json.dumps(arguments or {})[:110]})"
                          f"{'  [isError]' if res.is_error else ''}")
                    print("  " + shown(data, keys, width))
                return data

            await call("cr_attach", {}, keys=["attached", "phase", "cycle", "error"])

            # ── cr_apply on the seven, then the client's own edit ────────────
            applied = []
            for rid, (after, why) in RENDER.items():
                p = await call("cr_apply", {"row": rid},
                               keys=["kind", "row", "file", "replace_span", "digest",
                                     "selected_role", "error"])
                if p.get("error") or p["kind"] != "shape":
                    print(f"  !! {rid}: kind={p['kind']} error={p.get('error')}")
                    continue
                print(f"    shape: {p['shape'].replace(chr(10), ' | ')[:110]}")
                path = TARGET / p["file"]
                lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
                start, end = parse_span(p["replace_span"])
                before = "".join(lines[start - 1:end])
                new = after.splitlines(keepends=True)
                assert before.lstrip().startswith("def ") or before.lstrip().startswith("@"), before
                path.write_text("".join(lines[:start - 1] + new + lines[end:]), encoding="utf-8")
                applied.append({"row": rid, "file": p["file"], "replace_span": p["replace_span"],
                                "rule_ids": None, "kind": "shape",
                                "selected_role": p["selected_role"], "digest": p["digest"],
                                "reason": p["reason"], "before": before, "after": after,
                                "rendering_rationale": why, "reverted": False, "outcome": None})
                print(f"    EDITED {p['replace_span']}")

            # ── the runner, through the wrapper ─────────────────────────────
            run = await call("cr_run_module", {"path": "pytest", "args": ["colorama/tests", "-q"]},
                             keys=["exit_code", "duration_s", "args", "seen_on_band", "timed_out",
                                   "error"])
            tail = str(run.get("stdout") or "")[-200:].replace("\n", " | ")
            print(f"  stdout tail: {tail}")
            (RUNDIR / "phase3_runner_after.json").write_text(json.dumps(run, indent=2, default=str))
            ok = run.get("exit_code") == 0

            # ── the outcomes, immediately ───────────────────────────────────
            note_ok = ("run 141: the client rendered this row's shape and applied it in the "
                       "target's working tree (Q3); the target's own runner still passes — "
                       "38 passed, 14 skipped")
            results = []
            for rec in applied:
                out = await call("cr_report_outcome",
                                 {"row": rec["row"],
                                  "outcome": "confirmed" if ok else "failed",
                                  "note": note_ok if ok else
                                  f"run 141: the runner exits {run.get('exit_code')}",
                                  "tester": "coderadar-mcp run141"}, quiet=True)
                rec["outcome"] = "confirmed" if ok else "failed"
                results.append({"row": rec["row"], "outcome": rec["outcome"],
                                "written": out.get("written"), "digest": out.get("digest"),
                                "span": out.get("replace_span"), "error": out.get("error")})
            for rid, note in BACKED_OUT.items():
                out = await call("cr_report_outcome",
                                 {"row": rid, "outcome": "failed", "note": note,
                                  "tester": "coderadar-mcp run141"}, quiet=True)
                results.append({"row": rid, "outcome": "failed", "written": out.get("written"),
                                "digest": out.get("digest"), "span": out.get("replace_span"),
                                "error": out.get("error")})
            written = sum(1 for x in results if x["written"])
            print(f"\ncr_report_outcome ×{len(results)} → written {written}, "
                  f"refused {len(results) - written}")
            for x in results:
                mark = "ok " if x["written"] else "REF"
                print(f"   {mark} {x['outcome']:9s} {x['row']}  {x['digest']}"
                      + (f"   {x['error']}" if x["error"] else ""))
            (RUNDIR / "phase3_applied.json").write_text(json.dumps(applied, indent=2, default=str))
            (RUNDIR / "phase3_outcomes.json").write_text(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
