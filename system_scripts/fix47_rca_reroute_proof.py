#!/usr/bin/env python3
"""FIX_47 + I-53 + I-55 unit proof (owner Q7, 2026-09-15 packet §F: "RE-ROUTE: RCA-001 becomes evidence
into the Ranker"; run 136, lane D, 2026-09-17).

Part 1 (I-03, the blinding) — `utils.code_analysis.fingerprint.normalized_fingerprint` may not write to
the tree it reads. `_ASTNormalizer` is an `ast.NodeTransformer`, and `NodeTransformer.generic_visit`
rewrites a node's list fields IN PLACE, so the fingerprint stage renamed the caller's own arguments and
Name nodes to `_var_0`, `_var_1`, … — and the RCA-001 split-fake sweep, which runs after it on the same
tree, could never match a callee name to a failed row (found run 80, set 4b-26). The hex is a pure
function of structure, so it is unchanged; the tree is not.

Part 2 (FIX_47, the re-route) — the sweep no longer decides. It emits the RCA-001 OBSERVATION
`{tag, line, description, callee, magnitude}` (the shape FIX_18's HR deficits and FIX_17's NAI-230 use)
onto the row and re-runs THE RANKER's `observations` stage over the row's whole observation set. The
plant (a caller of a detector-failed helper that forwards none of its own parameters) carries the token
and is decided by the ranker; the control (a caller of a passing callee, forwarding its params) carries
none. The layer is the ranker's (AI_FAKE_DETECTOR — the tag is not HR-0*), never a constant at the site.

Part 3 (I-53) — a ps-proven test runner is THIS target's only when the PROCESS sits under the target.
`_under` resolves a relative token against the target, so another tree's `pytest tests/test_ansi.py`
matched this target whenever it happened to hold `tests/test_ansi.py` (run 129, `obs_F_I53.txt`).

Part 4 (I-55) — the wrapper's `-m pytest` path appends `-p no:cacheprovider`, so a runner leaves no
`.pytest_cache/` in the target and teardown needs no hand cleanup. The path the runner was pointed at is
read from the caller's own arguments, so the flag can never be mistaken for it.

    .venv_new/bin/python3 system_scripts/fix47_rca_reroute_proof.py
"""
from __future__ import annotations

import ast
import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "system_scripts"))

import test_runner_tracker as trt  # noqa: E402
from no_aivalidator.noai_validator.file_validation import validate_file_async  # noqa: E402
from no_aivalidator.noai_validator.validator import NoAIMathValidator  # noqa: E402
from utils.code_analysis.fingerprint import normalized_fingerprint  # noqa: E402

PLANT = '''"""The RCA-001 plant: a split-fake, and beside it a control."""
import os


def load_table(name, version):
    """Load the lookup table for a named dataset."""
    return {"alpha": 1, "beta": 2, "gamma": 3}


def read_config(path, strict):
    """THE PLANT: reads its own params, then delegates to the failed helper forwarding none of them."""
    base = os.path.basename(path)
    if strict and not base:
        raise ValueError("path required")
    table = load_table("default", 1)
    merged = dict(table)
    merged["source"] = base
    return merged


def describe(prefix, suffix):
    """THE CONTROL: a caller of a passing callee, forwarding its own params."""
    joined = os.path.join(prefix, suffix)
    return os.path.basename(joined)
'''


def _defs(src: str) -> list[ast.FunctionDef]:
    return [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)]


def part_1_fingerprint_does_not_mutate() -> list[str]:
    problems: list[str] = []
    src = "def caller(alpha, beta):\n    total = alpha + beta\n    return helper(total)\n"
    node = _defs(src)[0]
    before = ast.dump(node)
    hex_live = normalized_fingerprint(node)
    after = ast.dump(node)
    params = [a.arg for a in node.args.args]
    print(f"  params before {['alpha', 'beta']} -> after {params}")
    print(f"  fingerprint {hex_live[:16]}…")
    if after != before:
        problems.append("normalized_fingerprint MUTATED the tree it was given")
    if params != ["alpha", "beta"]:
        problems.append(f"the caller's parameters were renamed: {params}")
    if hex_live != normalized_fingerprint(_defs(src)[0]):
        problems.append("the fingerprint hex changed — the measurement must be unchanged")
    return problems


def part_2_rca_observation() -> list[str]:
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "the_plant.py"
        p.write_text(PLANT, encoding="utf-8")
        rows = asyncio.run(validate_file_async(NoAIMathValidator(), p))
    by = {r.function_name: r for r in rows}
    for name in ("load_table", "read_config", "describe"):
        if name not in by:
            problems.append(f"{name} produced no row")
    if problems:
        return problems

    helper, plant, control = by["load_table"], by["read_config"], by["describe"]
    tok = [o for o in (plant.triggered_patterns or [])
           if isinstance(o, dict) and o.get("tag") == "RCA-001"]
    ctl = [o for o in (control.triggered_patterns or [])
           if isinstance(o, dict) and o.get("tag") == "RCA-001"]
    print(f"  helper   load_table  passed={helper.passed}  {str(helper.failure_reason)[:60]}")
    print(f"  PLANT    read_config passed={plant.passed}  layer={plant.failure_layer}  source={plant.verdict_source!r}")
    print(f"           token: {tok[0] if tok else None}")
    print(f"           reason: {plant.failure_reason}")
    print(f"  CONTROL  describe    passed={control.passed}  RCA-001 tokens={len(ctl)}")

    if helper.passed:
        problems.append("the helper must fail — the sweep has no evidence otherwise")
    if not tok:
        problems.append("no RCA-001 observation on the plant's row")
    else:
        if tok[0].get("callee") != "load_table":
            problems.append(f"the token must name the failed callee: {tok[0]}")
        if tok[0].get("magnitude") != 1:
            problems.append(f"the token must carry its measured magnitude: {tok[0]}")
        if tok[0].get("context") is True:
            problems.append("the token must reach the disposition table as evidence, not as context")
        if "description" not in tok[0]:
            problems.append("the token must carry its own sentence (ONE renderer, FIX_18)")
    if plant.passed:
        problems.append("the ranker did not decide the plant's row on the RCA-001 observation")
    if plant.verdict_source != "ranker":
        problems.append(f"verdict_source must be the ranker: {plant.verdict_source!r}")
    if not str(plant.failure_reason).startswith("RCA-001 (line "):
        problems.append(f"the reason must be the ranker's deciding observation: {plant.failure_reason!r}")
    if plant.failure_layer is None or plant.failure_layer.name != "AI_FAKE_DETECTOR":
        problems.append(f"the LAYER is the ranker's: {plant.failure_layer}")
    if ctl:
        problems.append("the control carries an RCA-001 token")
    if not control.passed:
        problems.append(f"the control must pass: {control.failure_reason}")
    return problems


def part_3_runner_scoped_by_cwd() -> list[str]:
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d) / "target"
        (repo / "tests").mkdir(parents=True)
        (repo / "tests" / "test_ansi.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")
        outside = Path(d) / "another_tree"
        (outside / "tests").mkdir(parents=True)
        ps = [(51, "python -m pytest tests/test_ansi.py")]

        inside = trt.collect_runner_executions({}, ps, None, repo, cwd_of={51: str(repo / "tests")}.get)
        foreign = trt.collect_runner_executions({}, ps, None, repo, cwd_of={51: str(outside)}.get)
        unknown = trt.collect_runner_executions({}, ps, None, repo, cwd_of=lambda _pid: None)
        print(f"  same command line, cwd under the target : {[(e['pid'], e['proof'], e['test_path']) for e in inside]}")
        print(f"  same command line, cwd another tree     : {foreign}")
        print(f"  same command line, cwd unreadable       : {unknown}")

        if [(e["pid"], e["proof"], e["test_path"]) for e in inside] != [(51, "ps", "tests/test_ansi.py")]:
            problems.append(f"a pytest inside the target must be listed: {inside}")
        if foreign:
            problems.append(f"I-53: another tree's pytest was listed in this target's band: {foreign}")
        if unknown:
            problems.append(f"an unreadable cwd is not proof of this target: {unknown}")
        # the wrapper's and the kernel's own records are unchanged by the cwd rule
        wrapper = {"41": {"pid": 41, "runner": "pytest", "test_path": "tests/test_ansi.py", "start_time": "t"}}
        kept = trt.collect_runner_executions(wrapper, [], {"pid": 42, "runner": "pytest", "command": "c",
                                                           "test_path": "", "started_at": "t"}, repo,
                                             cwd_of=lambda _pid: None)
        if [(e["pid"], e["proof"]) for e in kept] != [(41, "wrapper"), (42, "kernel")]:
            problems.append(f"the cwd rule must touch the ps source only: {kept}")
        mine = trt.proc_cwd(__import__("os").getpid())
        if not mine or Path(mine).resolve() != Path.cwd().resolve():
            problems.append(f"proc_cwd could not read this process's own cwd: {mine!r}")
    return problems


def part_4_pytest_leaves_no_cache() -> list[str]:
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d) / "target"
        (repo / "tests").mkdir(parents=True)
        (repo / "tests" / "test_ansi.py").write_text("def test_x():\n    assert 1 + 1 == 2\n", encoding="utf-8")
        before = sorted(q.relative_to(repo).as_posix() for q in repo.rglob("*"))
        # B10 / Q-H1-3 (2026-10-01): CR_STATE_DIR — the wrapper's running.json/.lock, entry_point_info.json and
        # runner_info.json land in THIS tmp dir, not beside the wrapper, so the gate never overwrites the live
        # run of record (the 21:36 runner_info.json held this proof's tests/test_ansi.py as the target's run).
        state_dir = Path(d) / "cr_state"; state_dir.mkdir()
        r = subprocess.run([sys.executable, str(ROOT / "system_scripts" / "entry_point_wrapper.py"),
                            "-m", "pytest", "tests/test_ansi.py", "-q"],
                           cwd=str(repo), capture_output=True, text=True,
                           env={**__import__("os").environ, "CODERADAR_TARGET": str(repo), "CR_STATE_DIR": str(state_dir)}, timeout=180)
        written = sorted(q.name for q in state_dir.iterdir())
        print(f"  wrapper state files went to the proof's own dir (CR_STATE_DIR): {written or 'none'}")
        if "runner_info.json" not in written:
            problems.append(f"Q-H1-3: the wrapper did not write runner_info.json into CR_STATE_DIR (got {written})")
        after = sorted(q.relative_to(repo).as_posix() for q in repo.rglob("*"))
        added = [q for q in after if q not in before]
        print(f"  wrapper -m pytest exit {r.returncode}; files added to the target: {added or 'none'}")
        if r.returncode != 0:
            problems.append(f"the wrapper's pytest run failed: {r.stdout[-200:]}{r.stderr[-200:]}")
        if added:
            problems.append(f"I-55: the runner left residue in the target: {added}")
    return problems


def main() -> int:
    problems: list[str] = []
    for title, part in (
        ("Part 1 — I-03: normalized_fingerprint reads, never writes", part_1_fingerprint_does_not_mutate),
        ("Part 2 — FIX_47: the split-fake fact as evidence into the Ranker", part_2_rca_observation),
        ("Part 3 — I-53: a ps-proven runner is scoped to the target by cwd", part_3_runner_scoped_by_cwd),
        ("Part 4 — I-55: the wrapper's pytest leaves no cache in the target", part_4_pytest_leaves_no_cache),
    ):
        print(f"\n{title}")
        problems += part()
    for p in problems:
        print("PROBLEM:", p)
    print("\nFIX_47 + I-53 + I-55 unit proof:", "PASS" if not problems else "FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
