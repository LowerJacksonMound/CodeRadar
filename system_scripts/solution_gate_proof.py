"""Solution gate proof (owner 2026-10-08, item 8) — health step 22.

End to end, through the real tools, on a fixture repo built in a temp directory (never the live state, never a
target): a real validator scan publishes a row → the agent's side uses the MCP tools (cr_row, cr_submit) → the real
Builder joins, filters, ranks and gates the attempts (runs, integrates, tests) → cr_row shows the verdicts.

The fixture: `shift/units.py` converting minutes to hours with the wrong factor (`/ 100`, NAI-245), an importer
`shift/report.py` that uses it at import time, an entry point `python -m shift.runner`, and a 2-test suite (one
already failing on the bug). Four attempts:
  A  keeps a wrong factor (`/ 100.0`)               → refused at the filter (NAI-245 still fires)
  B  right idea, undefined constant                 → failed at stage 1 (runs: NameError)
  C  right factor but `-1` for zero                 → failed at stage 3 (test_zero passed before, fails now) — reverted
  D  the real fix (`/ 60`)                          → integrated (stays applied)
Every assertion prints `  ✓` / `  ✗`; the last line is `solution-gate proof: PASS` or `… FAIL`.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(ROOT), str(ROOT / "system_scripts")]
import logging  # noqa: E402
logging.disable(logging.CRITICAL)

FILES = {
    "shift/__init__.py": "",
    "shift/units.py": textwrap.dedent('''\
        def minutes_to_hours(minutes):
            """Convert a duration in minutes to hours."""
            return minutes / 100


        def seconds_to_minutes(seconds):
            """Convert a duration in seconds to minutes."""
            return seconds / 100
        '''),
    "shift/report.py": textwrap.dedent('''\
        from shift.units import minutes_to_hours

        SHIFT_MINUTES = [150, 90]
        TOTAL_HOURS = sum(minutes_to_hours(m) for m in SHIFT_MINUTES)
        '''),
    "shift/runner.py": textwrap.dedent('''\
        from shift.report import TOTAL_HOURS

        if __name__ == "__main__":
            assert TOTAL_HOURS >= 0
            print(TOTAL_HOURS)
        '''),
    "tests/test_units.py": textwrap.dedent('''\
        from shift.units import minutes_to_hours, seconds_to_minutes


        def test_two_hours():
            assert minutes_to_hours(120) == 2


        def test_zero():
            assert minutes_to_hours(0) == 0


        def test_seconds_zero():
            assert seconds_to_minutes(0) == 0
        '''),
    "README.md": "# shift\nRun with `python -m shift.runner`; tests run under pytest.\n",
}
DOC = '    """Convert a duration in minutes to hours."""\n'
FIX = "def minutes_to_hours(minutes):\n" + DOC + "    return minutes / 60\n"
ATTEMPTS = [
    ("A still the wrong factor", "def minutes_to_hours(minutes):\n" + DOC + "    return minutes / 100.0\n",
     "refused", "filter"),
    ("B undefined constant", "def minutes_to_hours(minutes):\n" + DOC + "    return minutes / MINUTES_PER_HOUR\n",
     "failed", "runs"),
    ("C breaks a passing test", "def minutes_to_hours(minutes):\n" + DOC + "    return minutes / 60 if minutes else -1\n",
     "failed", "tests"),
    ("D the real fix", FIX, "integrated", "tests"),
]
fails: list[str] = []


def check(ok: bool, label: str) -> None:
    print(f"  {'✓' if ok else '✗'} {label}")
    if not ok:
        fails.append(label)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="cr_gate_proof_"))
    try:
        return _run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run(tmp: Path) -> int:
    target, sys_dir = tmp / "target", tmp / "system_scripts"
    sys_dir.mkdir(parents=True)
    for rel, text in FILES.items():
        (target / rel).parent.mkdir(parents=True, exist_ok=True)
        (target / rel).write_text(text, encoding="utf-8")
    original = (target / "shift/units.py").read_bytes()

    import intent_file
    from no_aivalidator import BUILDER_DAEMON as B
    from no_aivalidator import NOAI_VALIDATOR_DAEMON as D
    from no_aivalidator.noai_validator.validator import NoAIMathValidator
    import coderadar_mcp.write_tools as W

    # every file any of these writes lands in the temp dir — the live system_scripts is never touched
    B.SYS_SCRIPTS = sys_dir
    W._sys_scripts = lambda: sys_dir
    intent_file.SCRIPTS_DIR = sys_dir
    intent_file.submit_statement(target, "A shift-hours tool; entry point python -m shift.runner; tests run under pytest.")

    # 1. a real scan of the fixture, through the validator daemon's own stages; stage_output writes its state file,
    #    so that path is pointed into the temp dir FIRST (the live NOAI_VALIDATION_STATE.json is never written)
    D.NOAI_STATE_FILE = sys_dir / "NOAI_VALIDATION_STATE.json"
    files = D.stage_discover(target)

    async def scan():
        with contextlib.redirect_stdout(io.StringIO()):
            return await D.stage_ingest(NoAIMathValidator(), target, files)

    results, cross_file = asyncio.run(scan())
    n_pass = sum(1 for rs in results.values() for r in rs if r.passed)
    n_fail = sum(1 for rs in results.values() for r in rs if not r.passed)
    with contextlib.redirect_stdout(io.StringIO()):
        D.stage_output(results, set(), str(target), n_pass, n_fail,
                       cross_file=cross_file)
    shaped = json.loads(D.NOAI_STATE_FILE.read_text())
    vat_failed = any(e.get("function") == "minutes_to_hours" and not e.get("passed", True)
                     for es in (shaped.get("results_by_file") or {}).values() for e in es)
    check(vat_failed, "the scan fails `minutes_to_hours` (wrong unit factor)")
    if not vat_failed:
        return _verdict()

    async def build():
        with contextlib.redirect_stdout(io.StringIO()):
            return await B.CheatsheetBuilder().build_rows(shaped, circuit={"nodes": [
                {"name": "shift/units", "imports": []}, {"name": "shift/report", "imports": ["shift/units"]},
                {"name": "shift/runner", "imports": ["shift/report"]}], "edges": []})

    def publish(rows):
        channel = str(sys_dir / f"return_channel_{B._repo_id(target)}.jsonl")
        (sys_dir / "BUILDER_STATE.json").write_text(json.dumps(
            {"target_repo": str(target), "return_channel": channel, "rows": rows}, default=str))
        repairs = [{"file": r.get("file"), "function": r.get("function"), "line": r.get("line"),
                    "rule_ids": r.get("rule_ids"), "before_code": r.get("before_code"), "return_channel": channel,
                    "replace_span": r.get("replace_span", "")} for r in rows.values()]
        (sys_dir / ".noai_state.json").write_text(json.dumps(
            {"target_repo": str(target), "return_channel": channel, "repairs": repairs, "no_vetted_fix": [],
             "withheld": []}, default=str))

    rows, _ = asyncio.run(build())
    publish(rows)
    key = next((k for k, r in rows.items() if r.get("function") == "minutes_to_hours"), None)
    check(key is not None, f"the Builder publishes the row ({key})")
    if key is None:
        return _verdict()

    # 2-3. the agent submits, the Builder's next cycle gates — three cycles, so every stage is exercised:
    #   cycle 1, row minutes_to_hours: A (wrong factor kept) + B (undefined constant) — A refused at the filter,
    #            B is the only pickable attempt, picked, fails stage 1;
    #   cycle 2, same row: D (the real fix) — picked, passes runs / integrates / tests, stays applied;
    #   cycle 3, row seconds_to_minutes: C (`-1` for zero) — passes stages 1-2, fails stage 3, reverted.
    def submit(row_key, items):
        for label, code, _, _ in items:
            r = W.cr_submit(row_key, code, note=label)
            check(bool(r["accepted"]), f"cr_submit accepts attempt {label}")

    def judged(row_key, label) -> tuple[dict, dict]:
        rws, _ = asyncio.run(build())
        publish(rws)
        return rws, next((a for a in rws[row_key].get("attempts") or [] if label in (a.get("note") or "")), {})

    submit(key, [ATTEMPTS[0], ATTEMPTS[1]])
    rows, a = judged(key, ATTEMPTS[0][0])
    check((a.get("status"), a.get("stage")) == ("refused", "filter"), f"A: refused at filter (got {a.get('status')} at {a.get('stage')})")
    a = next((x for x in rows[key].get("attempts") or [] if ATTEMPTS[1][0] in (x.get("note") or "")), {})
    check((a.get("status"), a.get("stage")) == ("failed", "runs"), f"B: failed at runs (got {a.get('status')} at {a.get('stage')})")
    check(bool(a.get("probe")) and bool(a.get("next")), "B: the agent gets a probe and a `next`")
    check((target / "shift/units.py").read_bytes() == original, "after cycle 1 the target is untouched")

    submit(key, [ATTEMPTS[3]])
    rows, a = judged(key, ATTEMPTS[3][0])
    check(a.get("status") == "integrated", f"D: integrated (got {a.get('status')})")
    now = (target / "shift/units.py").read_text()
    check("minutes / 60\n" in now and "MINUTES_PER_HOUR" not in now and "minutes / 100" not in now,
          "the target holds the real fix and none of the failed attempts")
    r4 = W.cr_submit(key, FIX + "\n# again\n", note="fourth")
    check(not r4["accepted"] and "cap" in (r4["error"] or ""), "a 4th attempt on the row is refused at the cap")
    check(not rows[key].get("held_for_owner"), "a row with an integrated attempt is not held for the owner")

    key2 = next((k for k, r in rows.items() if r.get("function") == "seconds_to_minutes"), None)
    check(key2 is not None, f"the second row is published ({key2})")
    if key2 is None:
        return _verdict()
    before_c = (target / "shift/units.py").read_bytes()
    c_code = ("def seconds_to_minutes(seconds):\n    \"\"\"Convert a duration in seconds to minutes.\"\"\"\n"
              "    return seconds / 60 if seconds else -1\n")
    r = W.cr_submit(key2, c_code, note="C breaks a passing test")
    check(bool(r["accepted"]), "cr_submit accepts attempt C")
    rows, a = judged(key2, "C breaks a passing test")
    check((a.get("status"), a.get("stage")) == ("failed", "tests"), f"C: failed at tests (got {a.get('status')} at {a.get('stage')})")
    check("test_seconds_zero" in json.dumps(a.get("probe") or {}), "C: the probe names the newly failing test")
    check((target / "shift/units.py").read_bytes() == before_c, "C was reverted byte-identical")

    # 4. the row the agent reads (cr_row returns the Builder row whole) carries every attempt
    seen_row = json.loads((sys_dir / "BUILDER_STATE.json").read_text())["rows"].get(key) or {}
    check(len(seen_row.get("attempts") or []) in (0, 3),
          "the published row carries its three attempts (or is closed by the rescan)")
    check(not list((ROOT / "system_scripts").glob(f"*{B._repo_id(target)}*")),
          "nothing for the fixture was written into the live system_scripts")
    return _verdict()


def _verdict() -> int:
    ok = not fails
    print(f"solution-gate proof: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
