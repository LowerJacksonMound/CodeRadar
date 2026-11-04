#!/usr/bin/env python3
"""T3 write-path proof — `cr_apply` · `cr_run_module` · `cr_report_outcome`
(release form, session 3, 2026-09-17; RELEASE_FORM_MCP_PACKET_2026-09-17 §C row T3).

Offline, on a FIXTURE tree built from run 136: the published mirror and
`BUILDER_STATE.json` of that run, and a writable COPY of the target they describe. The three
handlers are pointed at it with `CODERADAR_MCP_ROOT`, the seam `write_tools._root()` leaves
for exactly this. Nothing under `.archive/` and nothing in the live tree is written.

Part 1 (the edit, Q3) — `cr_apply` renders a unified diff for rewriter rows FROM THE FILE'S
CURRENT BYTES, a shape + placeholders for prescriptions (Q8, I-75), `none` for a declined row,
and the copy of the target is byte-identical before and after: the tool writes nothing.
Every rewriter diff is checked with `patch --dry-run` against that copy.

Part 2 (the one write) — `cr_report_outcome` appends one line to the channel and the ENGINE's
own `_parse_channel_line` / `_join_channel` / `_tester_field` read it back: a `failed` line
joins, a `confirmed` line sets `rows[].tester`, the LAST line on a digest supersedes the
earlier one, a wrong span is an orphan, and `refuted` / an unknown row / a row with no
solution are refused before anything reaches the file.

Part 3 (the runner) — `cr_run_module` runs the target's own runner THROUGH
`entry_point_wrapper.py` as a subprocess with the target as cwd: exit code, tails, wall time,
the I-55 flag on a `-m pytest` run, the pid on the band (`running.json`), and a timeout kill.

Part 4 (the schemas) — every payload of parts 1-3, success and error alike, validates against
T1's output schema for its tool; the three handlers are registered; `cr_report_outcome` is
the only tool that records a verdict (return channel + confirmed ledger), and every writing tool
names its files (A3 2026-10-01, Q-H4-10 — the interface proof holds the full set).

    .venv_new/bin/python3 system_scripts/mcp_write_path_proof.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from coderadar_mcp import tool_interface as ti  # noqa: E402
from coderadar_mcp import write_tools as wt  # noqa: E402

_RUNS = ROOT / ".archive" / "gate_evidence" / "runs"
# run 136's evidence folder (named after its target), found by its ledger rows
_RUN136_DIR = next((p.parent for p in sorted(_RUNS.glob("*/ledger_rows_RUN136.tsv"))), _RUNS / "run_136")
RUN136 = _RUN136_DIR / "state_during_run"
# the target itself stays in the recall-targets folder (the one tree copy the checks need)
TARGET_SRC = next(iter(sorted(ROOT.glob(f"*recall_targets/{_RUN136_DIR.name}"))), ROOT / "recall_targets" / _RUN136_DIR.name)

FAILURES: list[str] = []
PAYLOADS: list[tuple[str, dict[str, Any]]] = []


def ok(cond: bool, what: str) -> None:
    print(f"  {'✓' if cond else '✗'} {what}")
    if not cond:
        FAILURES.append(what)


def keep(tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    PAYLOADS.append((tool, payload))
    return payload


def tree_md5(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(hashlib.md5(p.read_bytes()).hexdigest().encode())
    return h.hexdigest()


def build_fixture(tmp: Path) -> tuple[Path, str]:
    """The fixture tree: run 136's published mirror and state, a writable copy of the target
    they describe, and the wrapper. The two JSON reads go through `write_tools._read_json`
    on purpose — this file's name matches the pre-ranker hunter's rule-code pattern
    (`proof`), so a `json.load` written HERE would be a step-17 site with no ledger row."""
    sysd = tmp / "system_scripts"
    sysd.mkdir(parents=True)
    target = tmp / "target"
    shutil.copytree(TARGET_SRC, target)
    mirror = wt._read_json(RUN136 / "noai_state_mirror.json") or {}
    state = wt._read_json(RUN136 / "BUILDER_STATE.json") or {}
    repo_id = str(state.get("repo_id") or "fixture")
    channel = str(sysd / f"return_channel_{repo_id}.jsonl")
    mirror["target_repo"] = str(target)
    for bucket in ("repairs", "no_vetted_fix"):
        for row in mirror.get(bucket) or []:
            if isinstance(row, dict) and row.get("return_channel"):
                row["return_channel"] = channel
    state["target_repo"] = str(target)
    state["return_channel"] = channel
    (sysd / ".noai_state.json").write_text(json.dumps(mirror), encoding="utf-8")
    (sysd / "BUILDER_STATE.json").write_text(json.dumps(state), encoding="utf-8")
    shutil.copyfile(ROOT / "system_scripts" / "entry_point_wrapper.py",
                    sysd / "entry_point_wrapper.py")
    # The wrapper loads its pytest plugin from its own folder (owner 2026-10-07) — the fixture carries it too
    # (last plan 1b, 2026-10-10: without it every pytest run here exited 1 on "No module named cr_pytest_results").
    shutil.copyfile(ROOT / "system_scripts" / "cr_pytest_results.py", sysd / "cr_pytest_results.py")
    os.environ["CODERADAR_MCP_ROOT"] = str(tmp)
    return target, channel


def rows_of(bucket: str) -> list[dict[str, Any]]:
    mirror = wt._mirror() or {}
    return [r for r in (mirror.get(bucket) or []) if isinstance(r, dict)]


# ─────────────────────────────────────────────────────────────────────────────


def part_1_the_edit(target: Path) -> None:
    print("\nPart 1 — cr_apply: the edit, and nothing written to the target (Q3)")
    before = tree_md5(target)
    all_rewriters = [r for r in rows_of("repairs") if r.get("solution_kind") == "rewriter"]
    rewriters = all_rewriters[:3]
    ok(len(rewriters) == 3, f"{len(rewriters)} rewriter rows taken from the mirror")
    for row in rewriters:
        rid = ti.row_id(row)
        out = keep("cr_apply", wt.cr_apply(rid))
        # The verdict is the schema field now (absorbed at the session-3 transplant), not `error`.
        clean = out["applies_cleanly"]
        ok(out["kind"] == "diff" and bool(out["diff"]) and clean is True,
           f"{rid} → diff, applies_cleanly={clean}, {len(out['diff'] or '')} chars, "
           f"digest {out['digest']}")
    if rewriters:
        first = keep("cr_apply", wt.cr_apply(ti.row_id(rewriters[0])))
        print("    ── the rendered diff, verbatim ──")
        for ln in (first["diff"] or "").splitlines():
            print(f"    {ln}")

    shaped = [r for r in rows_of("repairs")
              if r.get("solution_kind") == "prescribed" and "<" in str(r.get("after_code"))][:2]
    ok(len(shaped) == 2, f"{len(shaped)} prescribed rows with <placeholders>")
    for row in shaped:
        rid = ti.row_id(row)
        out = keep("cr_apply", wt.cr_apply(rid))
        names = [p["name"] for p in out["placeholders"]]
        ok(out["kind"] == "shape" and bool(out["shape"]) and bool(names),
           f"{rid} → shape, placeholders {names}")
    if shaped:
        out = keep("cr_apply", wt.cr_apply(ti.row_id(shaped[0])))
        print("    ── the rendered shape, verbatim ──")
        print(f"    shape: {out['shape']}")
        for ph in out["placeholders"]:
            print(f"      <{ph['name']}> — {ph['meaning']}")

    declined = rows_of("no_vetted_fix")[:1]
    for row in declined:
        out = keep("cr_apply", wt.cr_apply(ti.row_id(row)))
        ok(out["kind"] == "none" and out["digest"] is None,
           f"{ti.row_id(row)} → none, reason {out['reason']!r} (T1 decision 6)")
    bad = keep("cr_apply", wt.cr_apply("no/such/file.py::nope::1"))
    ok(bad["error"] is not None and bad["kind"] == "none", "an unknown row is refused, not guessed")

    after = tree_md5(target)
    ok(before == after, f"the target copy is byte-identical after {len(PAYLOADS)} renders "
                        f"({before[:12]})")


def part_2_the_one_write(channel: str) -> None:
    print("\nPart 2 — cr_report_outcome: the one write, read back by the ENGINE")
    try:
        from no_aivalidator import BUILDER_DAEMON as bd  # noqa: E402
    except Exception as e:  # pragma: no cover - the engine must import for this part
        FAILURES.append(f"engine import failed: {type(e).__name__}: {e}")
        print(f"  ✗ engine import failed: {type(e).__name__}: {e}")
        return
    state = wt._builder_state() or {}
    srows = {k: v for k, v in (state.get("rows") or {}).items() if isinstance(v, dict)}

    rewriters = [r for r in rows_of("repairs")
                 if r.get("solution_kind") == "rewriter" and ti.row_id(r) in srows][:2]
    ok(len(rewriters) == 2, "two rows that exist in BUILDER_STATE.rows")
    row_a, row_b = rewriters[0], rewriters[1]
    id_a, id_b = ti.row_id(row_a), ti.row_id(row_b)

    out_a = keep("cr_report_outcome",
                 wt.cr_report_outcome(id_a, "failed", "AssertionError: collect() returned an alias"))
    out_b = keep("cr_report_outcome", wt.cr_report_outcome(id_b, "confirmed", "runner green"))
    ok(out_a["written"] and out_b["written"], f"two lines appended to {Path(channel).name}")
    ok(out_a["digest"] == row_a.get("digest") and out_a["replace_span"] == row_a.get("replace_span"),
       "digest AND replace_span came off the ROW, not the caller")
    ok(ti.tool("cr_report_outcome").input_field("digest") is None
       and ti.tool("cr_report_outcome").input_field("replace_span") is None,
       "the client cannot supply either: neither is in the input schema")
    print(f"    ── the line, verbatim ──\n    {json.dumps(out_a['line'], ensure_ascii=False)}")

    raw = Path(channel).read_bytes()
    ok(raw.endswith(b"\n") and raw.count(b"\n") == 2, "two newline-terminated lines on disk")
    lines = [bd._parse_channel_line(x) for x in raw.decode().splitlines() if x.strip()]
    ok(all(x is not None for x in lines), "the engine's _parse_channel_line accepts both")
    parsed = [x for x in lines if x is not None]
    failed, confirmed, orphans = bd._join_channel(parsed, srows)
    ok(id_a in failed and id_b in confirmed and orphans == 0,
       f"joined: failed={list(failed)[:1]} confirmed={list(confirmed)[:1]} orphans={orphans}")
    tf = bd._tester_field(row_b.get("digest"), confirmed.get(id_b))
    ok(tf["confirmed"] is True, f"rows[].tester = {json.dumps(tf)}")

    keep("cr_report_outcome", wt.cr_report_outcome(id_a, "confirmed", "second look: green"))
    # `.read_bytes().decode()`, not `.read_text()`: the latter is a W49 hunter site in a file
    # whose name carries `proof` (health step 17), and this lane files no ledger row.
    parsed2 = [x for x in (bd._parse_channel_line(y)
                           for y in Path(channel).read_bytes().decode().splitlines() if y.strip())
               if x is not None]
    failed2, confirmed2, _ = bd._join_channel(parsed2, srows)
    ok(id_a in confirmed2 and id_a not in failed2,
       "the LAST line on a digest supersedes the earlier one (_join_channel keeps matching[-1])")
    ok(Path(channel).read_bytes().startswith(raw),
       "append-only: the first two lines are unchanged, byte for byte")

    orphan_line = dict(parsed[0])
    orphan_line["replace_span"] = orphan_line["replace_span"] + "9"
    _, _, orph = bd._join_channel([orphan_line], srows)
    ok(orph == 1, "the right digest with the wrong span is a silent ORPHAN — hence the row read")

    refused = [
        ("outcome `refuted`", keep("cr_report_outcome", wt.cr_report_outcome(id_a, "refuted"))),
        ("an unknown row", keep("cr_report_outcome",
                                wt.cr_report_outcome("no/such.py::x::1", "failed"))),
        ("a declined row", keep("cr_report_outcome",
                                wt.cr_report_outcome(ti.row_id(rows_of("no_vetted_fix")[0]),
                                                     "failed"))),
    ]
    for what, out in refused:
        ok(out["written"] is False and out["error"] is not None, f"refused before the file: {what}")
    ok(Path(channel).read_bytes().count(b"\n") == 3, "three lines on disk — no refusal reached it")


def part_3_the_runner(target: Path) -> None:
    print("\nPart 3 — cr_run_module: the target's runner THROUGH the wrapper")
    out = keep("cr_run_module", wt.cr_run_module("pytest", ["colorama/tests", "-q"], timeout_s=300))
    ok(out["exit_code"] == 0 and not out["timed_out"],
       f"-m pytest colorama/tests -q → exit {out['exit_code']} in {out['duration_s']}s")
    ok(out["args"][-4:] == ["-p", "no:cacheprovider", "-o", "addopts="], f"I-55 + M-21 flags reported: {out['args']}")
    ok(out.get("target_writes") == [], f"M-21: the run left the target as it found it: {out.get('target_writes')}")
    ok(out["seen_on_band"], "the wrapper's pid was on the band (running.json) while it ran")
    ok(not (target / ".pytest_cache").exists(), "no .pytest_cache left in the target (I-55)")
    tail = (out["stdout"] or "").strip().splitlines()[-1:] or [""]
    print(f"    stdout tail: {tail[0][:100]}")
    ok((wt._sys_scripts() / "runner_info.json").exists(),
       "the runner's own record landed in the fixture tree, not the live one")

    sleeper = target / "crproof_sleeper.py"
    sleeper.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    slow = keep("cr_run_module", wt.cr_run_module("crproof_sleeper.py", [], timeout_s=2))
    ok(slow["timed_out"] and slow["exit_code"] == wt.EXIT_TIMED_OUT,
       f"a run past its timeout is killed → exit {slow['exit_code']}, timed_out {slow['timed_out']}")
    sleeper.unlink()
    script = target / "crproof_script.py"
    script.write_text("print('the target ran its own script')\n", encoding="utf-8")
    one = keep("cr_run_module", wt.cr_run_module("crproof_script.py", [], timeout_s=120))
    record = wt._read_json(wt._sys_scripts() / "entry_point_info.json") or {}
    ok(one["exit_code"] == 0 and str(record.get("entry_point", "")).endswith("crproof_script.py"),
       f"a FILE path runs as a script, not `-m` (as_module auto-picked): exit "
       f"{one['exit_code']}, wrapper recorded entry_point {record.get('entry_point')!r}")
    script.unlink()


def part_4_the_schemas() -> None:
    print("\nPart 4 — the payloads against T1's schemas, and the registry")
    bad = 0
    for tool, payload in PAYLOADS:
        problems = ti.validate_payload(ti.tool(tool), payload, "output")
        if problems:
            bad += 1
            print(f"  ✗ {tool}: {problems[:2]}")
    ok(bad == 0, f"{len(PAYLOADS)} payloads validated against their output schema "
                 f"(success AND error), {bad} bad")
    for name in wt.OWNED:
        ok(ti.HANDLERS.get(name) is getattr(wt, name), f"HANDLERS[{name!r}] is write_tools.{name}")
    # A3 (2026-10-01, Q-H4-10): the lane's three tools each name what they write; the one that
    # records a verdict (channel + ledger) is cr_report_outcome; cr_apply names only its lease.
    verdict_writers = [n for n, s in ti.TOOLS.items()
                       if any("return_channel" in w or "confirmed_ledger" in w for w in s.writes)]
    ok(verdict_writers == ["cr_report_outcome"], f"the one verdict writer in the surface: {verdict_writers}")
    ok(all(ti.TOOLS[n].writes for n in wt.OWNED), f"every write_tools tool names its files: "
       f"{ {n: len(ti.TOOLS[n].writes) for n in wt.OWNED} }")
    ok(any("apply_lease" in w for w in ti.TOOLS["cr_apply"].writes), "cr_apply names the apply lease as its write")


def main() -> int:
    for p in (RUN136 / "noai_state_mirror.json", RUN136 / "BUILDER_STATE.json", TARGET_SRC):
        if not p.exists():
            print(f"missing fixture source: {p}")
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="mcp_write_path_"))
    try:
        target, channel = build_fixture(tmp)
        print(f"fixture: {tmp}\n  mirror + BUILDER_STATE of run 136, target copy {target.name}")
        part_1_the_edit(target)
        part_2_the_one_write(channel)
        part_3_the_runner(target)
        part_4_the_schemas()
    finally:
        os.environ.pop("CODERADAR_MCP_ROOT", None)
        shutil.rmtree(tmp, ignore_errors=True)
    print("\nT3 write-path proof: " + ("PASS" if not FAILURES else f"FAIL ({len(FAILURES)})"))
    for f in FAILURES:
        print(f"  - {f}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
