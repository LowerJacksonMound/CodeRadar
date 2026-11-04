"""T2's file — the MCP server itself: T1's registry over a stdio transport.

Q1, ruled 2026-09-17: a local stdio MCP server; no network port beyond the dash's own. So:
no host, no port, no socket here — the transport is this process's stdin and stdout.
R1 (2026-09-28) supersedes Q1's per-target mount: the server is registered ONCE and starts
with NO target; `cr_watch(target)` / `cr_attach(target)` bind it (B1). `--target` stays
as an optional pre-bind for proofs and old configs.

The surface is T1's and is not re-declared: `tool_interface.TOOLS` names all 14 tools (cr_submit added 2026-10-08, solution gate)
(packet §B's 11 rows — its first row names three), each with the input schema published
to the client and the contract shown as the tool's description. A tool answers only once
its lane has bound it through `register_handler`; every other name answers with a plain
"not implemented in this lane" error rather than disappearing from the surface, so a
client built against the packet sees the whole form from day one.

Importing the three lane modules is what binds the registry — T2's `read_tools` today,
T3's `write_tools` and T4's `session_tools` when their lanes land. Nothing here decides
which tools exist.
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
from typing import Any

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from . import __version__, read_tools, session_tools, write_tools
from .tool_interface import HANDLERS, TOOLS, Field, ToolSpec, validate_payload

#: Importing a lane module runs its `register_handler` calls. Named here so the import
#: is plainly load-bearing rather than an unused one a tidy-up could remove.
LANES = (read_tools, write_tools, session_tools)

#: The name the client sees (`mcp__coderadar__*`).
SERVER_NAME = "coderadar"

#: B1: set by `main` when the process starts with no `--target`; while no target is bound,
#: every tool but the two that bind one answers one sentence instead of reading a file.
PATH_FIRST = False
BINDING_TOOLS = ("cr_watch", "cr_attach")
#: run 177 re-seat: a restarted client spawns a NEW, unbound server while the stack is still live;
#: cr_stop reads the tree's own BUILDER_STATE (and refuses in words when nothing runs), so it must
#: answer unbound too, or a live stack is stranded behind "no target".
UNBOUND_OK = BINDING_TOOLS + ("cr_stop",)
NO_TARGET = "no target — call cr_watch with the repo path"

#: B4 + B5: every fact a client needs, carried by the server so no brief has to hand-feed it.
INSTRUCTIONS = """\
CodeRadar scans ONE Python repo at a time and hands you ranked findings; you write each repair as a whole \
function and file it with cr_submit — CodeRadar gates it and WRITES it. You do not edit the repo yourself.

START: the dev names a repo path (e.g. "scan ~/code/myrepo", or the /mcp__coderadar__scan prompt). \
Call cr_watch(target=<that path>). Until a target is bound every other tool except cr_stop answers \
"no target — call cr_watch with the repo path" (cr_stop always tears down whatever this CodeRadar runs). Give an absolute path; `~` expands, \
and a relative path resolves against the MCP server's working directory — the directory this \
client was started in (Claude Code: where `claude` was run), NOT the dev's shell — so a refused \
relative path is echoed back as the absolute path it resolved to. cr_watch refuses: a missing \
directory, a directory with zero .py files, CodeRadar's own tree, a second different target while \
one is live ("cr_stop first"; the same target again just attaches), a launch setup page open on the \
dash port with no target chosen yet (this tree's own `launch_setup.py`; choose there, or cr_stop closes \
it), and a busy dashboard/health port held by anything else (it names the holder). tracer is lsof only; \
trackers are drawn from io,mypy,crc,vulture (default io,mypy); naming_drift is permanent — it runs on every \
launch and is not a choice (cr_data_types lists it under `chosen` always, NOT MEASURED until the launch scan \
has completed).

cr_watch BLOCKS until every gate passes or its budget runs out. The budget is computed from the \
gate timeouts: 2190 s + 2 s per .py file in the repo, capped at 2970 s — 36.5 to 49.5 minutes — \
and the answer carries it as gate_budget_s; a small repo returns in a few minutes, a large one can \
use the whole budget. Do not cancel it or call it again while it runs. This client's MCP tool \
timeout must cover the budget: 3000000 ms (50 min), the value the install script sets. If the \
timeout is shorter the call is cut off client-side while the stack keeps coming up — then, or in a \
new seat, do NOT ask cr_status (it answers "no target" until this seat is bound): call \
cr_attach(target=<the same path>) directly; it answers MONITORING (attached) or names the launch \
still in flight and its phase — wait and call it again.

CODERADAR IS THE ONLY WRITER OF THE REPO'S CODE DURING A RUN (fix plan 2026-10-23, pass B): the Builder \
writes an integrated cr_submit attempt into the target — the function's LIVE span, once — and nothing else \
edits code; you do not. Beyond that the only files it writes in the repo are its two state \
mirrors, .noai_state.json (the counterfeit half) and .monitor_state.json (the non-counterfeit half), \
one pair per directory as it comes into view, all under ONE dir at the repo root: \
.coderadar/<same/sub/path>/ (the root's pair at .coderadar/). They persist after cr_stop as a log \
of the run — leave .coderadar/ alone and never touch it as part of a repair. Everything else the tools \
write lives in CodeRadar's own tree: cr_watch, cr_stop and cr_hand_back write the run's log, snapshots, \
teardown diff and tester_report.json under .archive/runs/<repo name>/; cr_apply appends one apply-lease \
record, cr_report_outcome one return-channel line (plus one confirmed-ledger record on "confirmed"), \
both in system_scripts/; cr_run_module's wrapper writes its running-state files there and puts back, from \
the launch snapshot, any file the RUN itself wrote inside the target (reported as target_writes). \
The read tools (cr_attach, cr_status, cr_infractions, cr_row, cr_wiring, cr_data_types, cr_intent) \
write nothing. cr_apply is a READ (write: false): it shows the engine's own candidate edit as a diff so \
you can read it before writing your attempt. It is NOT a second way to change the file — never apply it by \
hand; a row that already has a cr_submit attempt answers an error instead of a diff, and cr_submit refuses a \
row whose cr_apply bytes were edited by hand. Its diff is rendered against replace_span_live; replace_span is \
the Builder's join key and names STALE lines whenever span_current is false — never edit by it.

FIRST read cr_status: open_findings is how many rows are open right now and infraction_pages how many \
pages hold them; trackers_ran / trackers_not_requested / naming_drift say which checkers actually produced a \
reading (a tracker not requested is not a zero); dot_dirs_scanned names dot-directories whose files are in the \
scan. cr_infractions pages by page / pages / total (there is no has_more) and answers done: true only on the \
last page — keep paging until done is true, never stop on page 1. pick rows whose apply is \
"yes" (a concrete diff rendered at the site). A row whose apply is "review" (apply_reason "template \
only — no diff rendered at this site") carries the rule's template as a shape, not a diff: it is \
ranked after every "yes" row and is NOT to be applied blindly — read the site and decide, or leave \
it; it never counts as "yes". "no" = nothing to apply. Before any edit, lay the entry-point proof with cr_run_module (the target's entry script \
or module; on a library with no entry, its test suite, e.g. cr_run_module(path="pytest", \
args=["-q"])) BEFORE any `-m pytest` reading, and lay it AGAIN after the apply pass — without the \
second run severed_by_repair and re-promotion cannot be measured. A repeated cr_apply/cr_row \
reading of a row must be taken BEFORE that row is applied: an applied row is retired and a retry \
answers "not found".

THE SOLUTION GATE (owner 2026-10-08) — how a row is repaired: you WRITE the repair, CodeRadar checks, \
filters, ranks and applies it. For each row: read cr_row(id) (the code, the rule, its evidence), write the \
whole replacement function, and send it with cr_submit(row=<id>, code=<the full def>, note=<what changed>). \
Do NOT edit the file yourself. On its next cycle (seconds) the Builder joins your attempt to the row and gates \
it: filter (re-validated in a scratch copy — the row's rule must be gone, no new deciding rule), rank (against \
the engine's candidates and your other attempts), stage 1 runs (compiles, no undefined names, no new raise on \
the probe inputs), stage 2 integrates (the Builder writes it into the target at the function's live span, once, and every \
importer and the declared entry point must still work; a failure restores the original bytes), stage 3 tests (the repo's suite; only tests that passed before and fail \
now count). Then read cr_row(id) again: `attempts` lists each attempt with its status — integrated (done; the \
rescan closes the row; cr_row on the closed row answers `closed`, every verdict read from the gate ledger), failed (with `stage`, `detail` and `probe`: the input and exception, the traceback, the \
newly failing tests and their messages), refused, deferred — and `next`, the one thing to fix. Write the next \
attempt from that. A row takes at most 3 attempts; a row that reaches the cap with none integrated is \
`held_for_owner` — stop on it and report it. cr_report_outcome exists only for a repair made OUTSIDE CodeRadar \
(a dev's own edit, outcome="confirmed" or "failed"); during a trial you do not edit, so you do not call it. Between attempts cr_status answers phase, gates, health and finished.

TRACKER READINGS: before cr_stop, call cr_data_types() — it carries the mypy reading \
(import_errors, total_errors, files) and the io reading (functions, io_functions, exempt) — and \
REPORT both to the dev with the rest of your summary, even when they read 0 or "not measured". \
They are part of the scan's result, not optional detail. Also quote cr_wiring once: its live-edge \
count and, when 0, its `why` line.

At the end call cr_stop() then cr_hand_back() — cr_stop tears the stack down and proves the \
target byte-identical to its launch snapshot apart from the gate's own integrated writes (gate_writes). It \
answers open_findings and clear: clear is true ONLY when the processes are gone, residue and byte identity were \
measured clean, and open_findings is 0 — stopped alone is not a clean run, and anything NOT MEASURED is not clear \
(error says which). Report open_findings and clear to the dev. Its answer repeats a one-line \
`trackers` summary as a backstop, but read cr_data_types yourself first. cr_hand_back comes LAST: \
the gearbox's own teardown writes tester_report.json before its children stop, so a hand-back \
published before cr_stop is overwritten by it (cr_hand_back says so in `error` if you call it while \
the daemons are live); after cr_stop it reads BUILDER_STATE and the return channel, which outlive the \
daemons, and its report is the last word.
"""

#: Q9: the entry action, shown by Claude Code as `/mcp__coderadar__scan <path>`.
SCAN_PROMPT = types.Prompt(
    name="scan",
    title="Scan a Python repo with CodeRadar",
    description="Start CodeRadar on one repo and work its ranked repairs.",
    arguments=[types.PromptArgument(name="path", required=True,
                                    description="the repo directory to scan (absolute or ~; a relative path "
                                                "resolves against the directory this client was started in)")],
)

#: T1's `Field.type` names → JSON Schema types.
_JSON_TYPES = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "any": None,
}


def _property_of(f: Field) -> dict[str, Any]:
    """One `Field` as a JSON Schema property. A nullable field is `[type, "null"]`;
    `choices` become an enum; a default is published so the client can show it."""
    base = _JSON_TYPES.get(f.base_type)
    prop: dict[str, Any] = {"description": f.doc}
    if base is not None:
        prop["type"] = [base, "null"] if f.nullable else base
    if f.choices:
        prop["enum"] = list(f.choices)
    if f.default is not None:
        prop["default"] = f.default
    return prop


def _input_schema_of(spec: ToolSpec) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {f.name: _property_of(f) for f in spec.input_schema},
        "required": [f.name for f in spec.input_schema if f.required],
        "additionalProperties": False,
    }


def _described(spec: ToolSpec) -> str:
    """The contract, the source of record, and the keys the answer carries — T1's output
    schema reaches the client as prose. It is NOT declared as an `outputSchema`: a
    declared one is machine-enforced, and `cr_status` answers with one key beyond T1's
    schema (`finished_source`, this lane's brief) — see the report's decision 1."""
    keys = ", ".join(f.name for f in spec.output_schema)
    return f"{spec.contract}\n\nSource of record: {spec.source_of_record}\nAnswers with: {keys}"


def tool_list() -> list[types.Tool]:
    """Every tool of the surface, bound or not — the client sees the whole form."""
    return [
        types.Tool(name=spec.name, description=_described(spec), input_schema=_input_schema_of(spec))
        for spec in TOOLS.values()
    ]


def call(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Dispatch one tool call through T1's registry. Synchronous on purpose: every read
    tool opens a published file and answers; there is no long call in the read surface."""
    spec = TOOLS.get(name)
    if spec is None:
        return {"error": f"no such tool {name!r}; the surface is {sorted(TOOLS)}"}
    if PATH_FIRST and name not in UNBOUND_OK and read_tools.sources().target is None:
        return {"error": NO_TARGET}
    args = dict(arguments or {})
    problems = validate_payload(spec, args, "input")
    if problems:
        return {"error": "; ".join(problems)}
    fn = HANDLERS.get(name)
    if fn is None:
        return {"error": f"{name}: not implemented in this lane — the tool is in the surface "
                         f"but no module has bound it yet (T3 → write_tools.py, T4 → session_tools.py; "
                         f"RELEASE_FORM_MCP_PACKET_2026-09-17 §C)"}
    try:
        return fn(**args)
    except Exception as exc:
        return {"error": f"{name}: {type(exc).__name__}: {exc}"}


async def _on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    return types.ListToolsResult(tools=tool_list())


async def _on_list_prompts(ctx: Any, params: Any) -> types.ListPromptsResult:
    return types.ListPromptsResult(prompts=[SCAN_PROMPT])


async def _on_get_prompt(ctx: Any, params: types.GetPromptRequestParams) -> types.GetPromptResult:
    if params.name != SCAN_PROMPT.name:
        raise ValueError(f"no such prompt {params.name!r}; the only prompt is 'scan'")
    path = str((params.arguments or {}).get("path") or "").strip()
    text = (f"Scan {path} with CodeRadar: call cr_watch(target={path!r}) and wait for it to "
            f"return (up to its gate budget: 2190 s + 2 s per .py file, capped at 2970 s — "
            f"36.5 to 49.5 minutes; if the call is cut off, cr_attach(target={path!r}) binds to "
            f"the stack once it is MONITORING), then follow the CodeRadar server "
            f"instructions — cr_status, every page of cr_infractions, the entry-point proof, "
            f"for each row cr_row then cr_submit (CodeRadar gates and applies it; read the row's "
            f"`attempts` and resubmit from `next`, at most 3 per row), cr_data_types (report its mypy "
            f"and io readings), and at the end call cr_stop() then cr_hand_back()."
            if path else NO_TARGET)
    return types.GetPromptResult(
        description=SCAN_PROMPT.description,
        messages=[types.PromptMessage(role="user", content=types.TextContent(type="text", text=text))],
    )


async def _on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    answer = await anyio.to_thread.run_sync(functools.partial(call, params.name, params.arguments))
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(answer, indent=1, default=str))],
        structured_content=answer,
        is_error=answer.get("error") is not None,
    )


def build_server() -> Server[Any]:
    """The MCP server over T1's registry: the tool handlers and the one `scan` prompt."""
    return Server(
        SERVER_NAME,
        version=__version__,
        instructions=INSTRUCTIONS,
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
        on_list_prompts=_on_list_prompts,
        on_get_prompt=_on_get_prompt,
    )


async def serve() -> None:
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="coderadar-mcp",
        description="CodeRadar over MCP — stdio; registered once, the target named by cr_watch (R1).",
    )
    parser.add_argument("--target", default=None,
                        help="optional pre-bind (proofs, old configs); normally cr_watch names the target")
    parser.add_argument("--state-dir", default=None,
                        help="read the published files from this directory instead of the tree's "
                             "system_scripts/ (an archived run's state_during_run/, for a proof)")
    parser.add_argument("--tree", default=None,
                        help="the CodeRadar tree that publishes; default: the tree this package lives in")
    parser.add_argument("--print-tools", action="store_true",
                        help="print the tool surface as JSON and exit, without serving")
    args = parser.parse_args(argv)

    global PATH_FIRST
    PATH_FIRST = args.target is None
    src = read_tools.configure(target=args.target, state_dir=args.state_dir, tree=args.tree)
    if args.print_tools:
        print(json.dumps([t.model_dump(by_alias=True, exclude_none=True) for t in tool_list()], indent=1))
        return 0
    #: stderr, never stdout — stdout IS the transport.
    bound = f"target {src.target} (repo_id {src.repo_id})" if src.target else "no target yet (path-first)"
    print(f"coderadar-mcp {__version__}: {bound}; "
          f"state {src.state_dir}; {len(HANDLERS)}/{len(TOOLS)} tools bound", file=sys.stderr)
    anyio.run(serve)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
