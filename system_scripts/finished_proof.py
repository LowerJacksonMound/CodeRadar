"""THE `finished` INPUTS' proof — the 16th gate (session 8, packet §D).

`finished` is the release's own completion signal: **zero infractions · zero data-type issues ·
zero severed links.** Shakedown trial 1 (run 155) found two of its three inputs broken, in
opposite directions:

  I-127  every import edge incident on a file goes `severed` the moment the file's bytes change
         and is never re-promoted — `severed_links` went 0 → 16 in three bursts, each dated to
         the moment the client rewrote one file. A client that REPAIRED anything moved the
         release's completion signal further away BY repairing it.
  I-128  the target's own `[tool.mypy] python_version` decided the check. click pins "3.10", the
         stubs mypy resolves are the ENGINE's, and the engine venv's `numpy/__init__.pyi` needs
         3.12 or greater — so mypy aborted `rc 2`, 0 files checked, for the whole run, and the
         second input read NOT MEASURED while `mypy_errors` sat there saying 0.

Two repairs, both the owner's default (packet §B):

  Q1  an edge severed at or after the APPLY LEASE for one of its two files, whose lease
      after-text is what the file reads now, is `severed_by_repair` — published with its own
      count, still red on the wiring, and OUT of `finished`'s severed input. No lease, no bucket.
  Q2  `--python-version` is forced to the RUNNING interpreter's on every invocation and the
      target's `[tool.mypy]` is kept otherwise; a scan that did not run, or ran and checked no
      files, is not a zero — `cr_status.finished` reads `"not measured"`, never `true`.

Nine parts:

  (i)    the lease is READ, not re-implemented — `circuit_daemon.read_target_lease` returns what
         `coderadar_mcp.write_tools` wrote, beside the channel, by the channel's own naming rule
  (ii)   the rule, both halves: one LEASED edit and one UNLEASED edit → one edge in each bucket,
         and (I-146, 2026-09-21) the daemon's own log line per bucketed edge, read back off its
         logger — run 162 filled the bucket and left no line, so a mounted record could not show it
  (iii)  both halves are NECESSARY — a reverted after-text, a sever dated before the lease, and
         an edge with no lease at all are each refused the bucket
  (iv)   the two clocks: `severed_since` is naive LOCAL, the lease is aware UTC, and compared
         raw every sever reads as older than every lease by the UTC offset
  (v)    `finished`'s severed input, through the daemon's OWN `write_repo_mirror`: the verdict
         moves on the unleased edge and does not move on the leased one
  (vi)   the mypy invocation's literal argv — the running interpreter's version forced OVER a
         target that pins 3.10, the target's config still in force, and the scan RUNS
  (vi-b) I-128's SECOND cause, found by run 161 and not in the pinned row: the RUNNER's
         `PYTHONPATH` (I-134, which a src-layout target cannot do without) reaches mypy and makes
         every `src/<pkg>/<mod>.py` a duplicate module — rc 2, 0 files, the same silence
  (vii)  the abort: a target config that makes mypy crash → `mypy_ran false · mypy_rc 2 ·
         mypy_files_checked 0`, and `cr_status.finished` is `"not measured"`, never `true`
  (viii) re-promotion by the existing path is untouched: an edge live again leaves the set
  (ix)   THE LIVE PART — run 161's own record

EVERY EXPECTED VALUE IN `EXPECTED` BELOW WAS WRITTEN DOWN BEFORE THE COMPUTE WAS RUN
(`gate_proof.EXPECTED`'s idiom, as `identity_proof` follows it). The fixtures are synthetic on
purpose: an edge severed by a leased edit and an edge severed by an unleased one have to sit
side by side in one frame, and a hand-built frame is the only way to state that exactly.

    .venv_new/bin/python system_scripts/finished_proof.py        exit 0 = PASS
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

TREE = Path(__file__).resolve().parents[1]
for _p in (str(TREE), str(TREE / "system_scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import circuit_daemon as cd                                     # noqa: E402
from coderadar_mcp import read_tools as rt                      # noqa: E402
from coderadar_mcp import write_tools as wt                     # noqa: E402

RUNS = TREE / ".archive" / "gate_evidence" / "runs"   # F1 (2026-10-01): gate evidence lives under .archive/gate_evidence/, never pruned by retention

#: Run 161's record — the live part. `secret_touch` is the pool name of the run.
RUN_161 = RUNS / "secret_touch" / "run161_cr_status_after.json"

FAILURES: list[str] = []


# ─────────────────────────────────────────────────────────────────────────────
# WRITTEN DOWN BEFORE THE COMPUTE WAS RUN
# ─────────────────────────────────────────────────────────────────────────────

EXPECTED: dict[str, Any] = {
    # (ii) three red edges in the frame; exactly the one whose file was leased is bucketed
    "severed_pairs": 3,
    "severed_by_repair": 1,
    "severed_links_open": 2,
    # (ii) I-146: one line per BUCKETED edge — one edge is bucketed, so one line, and the two that
    # stay severed produce none; three further passes over the same edge add nothing (the owner's
    # dedupe ruling of 2026-09-21), and a second edge entering the bucket writes its own one line
    "log_lines_per_bucketed_edge": 1,
    "log_lines_on_repeat_passes": 0,
    "log_lines_for_a_second_edge": 1,
    # (v) the mirror's two readings
    "finished_with_open_sever": False,
    "finished_with_only_repair_severs": True,
    # (vi) the fixture pins 3.10 in `[tool.mypy]`; one source file, and it uses a `type`
    # statement, which is 3.12-or-greater syntax — under the pin mypy cannot even parse it
    "forced_version": f"{sys.version_info[0]}.{sys.version_info[1]}",
    "pinned_by_target": "3.10",
    "files_checked_when_forced": 1,
    # (vii) the extension the target's config names does not exist: mypy aborts before it checks
    "rc_on_abort": 2,
    "files_checked_on_abort": 0,
    "finished_on_abort": "not measured",
}


def _captured(fn: Any, *a: Any, **kw: Any) -> tuple[Any, str]:
    """Run `fn` with the daemon's OWN logger attached to a buffer, and hand back what it returned
    beside what it logged. I-146's line is read back from a real log record, never from a flag."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    root = logging.getLogger()
    kept_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        return fn(*a, **kw), buf.getvalue()
    finally:
        root.removeHandler(handler)
        root.setLevel(kept_level)


def _line(label: str, held: bool, said: str = "") -> None:
    print(f"  {'✓' if held else '✗'} {label}{' — ' + said if said else ''}")
    if held is False:
        FAILURES.append(label)


# ─────────────────────────────────────────────────────────────────────────────
# THE FIXTURE — four modules, two edits, one lease
# ─────────────────────────────────────────────────────────────────────────────

#: The LEASED file. `alpha`'s body is what `cr_apply` hands out and what the client writes back.
LEASED_BEFORE = '''"""fixture: the file the server handed out."""
import other_mod


def alpha(items=[]):
    seen = items
    return seen
'''

LEASED_AFTER_SPAN = """def alpha(items=None):
    items = [] if items is None else items
    seen = list(items)
    return seen
"""

#: The UNLEASED file — the client touched a file the server never handed out.
LOOSE_BEFORE = '''"""fixture: the file the server never handed out."""
import other_mod


def beta(values=[]):
    out = values
    return out
'''

OTHER = '"""fixture: the import target of all three edges."""\n\n\nVALUE = 1\n'

#: Neither end of this module's edge was ever handed out, and neither was edited. Q1's rule is
#: about the edge's TWO FILES, because an edit severs every edge INCIDENT on the file it
#: changes — so a fourth module is needed to state "never touched" without touching the leased
#: one from the other side.
QUIET = '"""fixture: neither edited nor leased."""\nimport other_mod\n'

#: `alpha` sits at L5-L7 of `leased_mod.py` — the span the lease is written against.
LEASED_SPAN = (5, 7)


def build_fixture(tmp: Path) -> tuple[Path, Path, str]:
    """`(target, scripts, channel)`. The target carries the four modules; `scripts` stands in
    for `system_scripts/`, which is where the channel — and so the lease — lives."""
    target = tmp / "target"
    scripts = tmp / "scripts"
    target.mkdir()
    scripts.mkdir()
    (target / "leased_mod.py").write_text(LEASED_BEFORE, encoding="utf-8")
    (target / "loose_mod.py").write_text(LOOSE_BEFORE, encoding="utf-8")
    (target / "other_mod.py").write_text(OTHER, encoding="utf-8")
    (target / "quiet_mod.py").write_text(QUIET, encoding="utf-8")
    repo_id = cd.get_repo_id(target)
    channel = str(scripts / f"return_channel_{repo_id}.jsonl")
    return target, scripts, channel


def write_lease(channel: str, when: datetime) -> dict[str, Any]:
    """One lease record for `leased_mod.py::alpha::5`, through the SERVER'S OWN writer —
    `write_tools._lease_record` builds it and `_append_lease` appends it, exactly as `cr_apply`
    does. The proof never hand-rolls the record: its field order is `APPLY_LEASE_RECORD` or the
    writer's own assertion fires."""
    row = {
        "digest": "a1b2c3d4e5", "replace_span": "leased_mod.py:L5-L7",
        "file": "leased_mod.py", "function": "alpha", "line": 5,
        "rule_ids": ["NAI-021S"], "selected_role": "alias_chain_fix:new_sequence",
        "solution_kind": "rewriter",
    }
    before = "".join(LEASED_BEFORE.splitlines(keepends=True)[LEASED_SPAN[0] - 1:LEASED_SPAN[1]])
    record = wt._lease_record("leased_mod.py::alpha::5", row, "leased_mod.py:L5-L7",
                              before, LEASED_AFTER_SPAN)
    record["timestamp"] = when.isoformat()
    wt._append_lease(channel, record)
    return record


def quiet_lease(when: datetime) -> dict[str, Any]:
    """A SECOND lease record, for `quiet_mod.py`, built by the same writer and never appended to the
    channel — it is handed to the classifier as `lease=` so the fixture's own lease on disk stays the
    one part (iii) and part (iv) read. Its after-text is the line the file already carries, so the
    IDENTITY half stands without touching a file (I-146's dedupe: a SECOND edge in the bucket)."""
    row = {"digest": "f0e1d2c3b4", "replace_span": "quiet_mod.py:L2-L2", "file": "quiet_mod.py",
           "function": "<module>", "line": 2, "rule_ids": ["NAI-021S"],
           "selected_role": "alias_chain_fix:new_sequence", "solution_kind": "rewriter"}
    after = QUIET.splitlines(keepends=True)[1]
    record = wt._lease_record("quiet_mod.py::<module>::2", row, "quiet_mod.py:L2-L2", after, after)
    record["timestamp"] = when.isoformat()
    return record


def client_applies_the_leased_edit(target: Path) -> None:
    """The client writes the lease's after-text at the lease's span — which is what
    `cr_apply`'s diff says, so this is the apply, not a re-creation of it."""
    path = target / "leased_mod.py"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    a, b = LEASED_SPAN
    path.write_text("".join(lines[:a - 1]) + LEASED_AFTER_SPAN + "".join(lines[b:]),
                    encoding="utf-8")


def client_touches_the_unleased_file(target: Path) -> None:
    """A file the server never handed out — edited anyway. Its severed edges stay `severed`."""
    path = target / "loose_mod.py"
    path.write_text(path.read_text(encoding="utf-8").replace("out = values", "out = list(values)"),
                    encoding="utf-8")


#: The three modules' node names, and what `circuit_daemon` calls their paths.
NODE_FILES = {"leased_mod": "leased_mod.py", "loose_mod": "loose_mod.py",
              "other_mod": "other_mod.py", "quiet_mod": "quiet_mod.py"}

PAIR_LEASED = ("leased_mod", "other_mod")
PAIR_LOOSE = ("loose_mod", "other_mod")
PAIR_UNTOUCHED = ("quiet_mod", "other_mod")


def severed_frame(after: datetime) -> dict:
    """One frame of `severed_since`, stamped the way `compute_severed_links` stamps it:
    `datetime.now().isoformat()` — NAIVE, on this machine's local clock."""
    stamp = after.astimezone().replace(tzinfo=None).isoformat()
    return {PAIR_LEASED: stamp, PAIR_LOOSE: stamp, PAIR_UNTOUCHED: stamp}


# ─────────────────────────────────────────────────────────────────────────────
# (i) the lease is read, not re-implemented
# ─────────────────────────────────────────────────────────────────────────────


def part_i_the_reader(target: Path, scripts: Path, record: dict[str, Any]) -> None:
    print("\n1. THE LEASE IS READ, NOT RE-IMPLEMENTED (§D.1)")
    cd.SCRIPT_DIR = scripts
    lease = cd.read_target_lease(target)
    _line("`read_target_lease` finds the lease beside the channel by the channel's own rule",
          set(lease) == {"leased_mod.py::alpha::5"},
          f"{len(lease)} record(s) at apply_lease_{cd.get_repo_id(target)}.jsonl")
    got = lease.get("leased_mod.py::alpha::5", {})
    _line("and it is the record the SERVER wrote — digest, span and after hash, unaltered",
          got.get("digest") == record["digest"]
          and got.get("replace_span_live") == record["replace_span_live"]
          and got.get("after_sha256") == record["after_sha256"],
          f"digest={got.get('digest')} span={got.get('replace_span_live')} "
          f"after={str(got.get('after_sha256'))[:10]}…")
    cd.SCRIPT_DIR = scripts / "nowhere"
    _line("a target whose channel was never published leases nothing, and says so as {}",
          cd.read_target_lease(target) == {})
    cd.SCRIPT_DIR = scripts


# ─────────────────────────────────────────────────────────────────────────────
# (ii) + (iii) the rule, and that both halves are necessary
# ─────────────────────────────────────────────────────────────────────────────


def part_ii_one_in_each_bucket(target: Path, lease_at: datetime) -> None:
    print("\n2. ONE LEASED EDIT, ONE UNLEASED EDIT — ONE EDGE IN EACH BUCKET (Q1)")
    frame = severed_frame(lease_at + timedelta(seconds=30))
    by_repair, logged = _captured(cd.classify_severed_by_repair, frame, NODE_FILES, repo=target)
    _line("the frame carries three red edges",
          len(frame) == EXPECTED["severed_pairs"], f"{len(frame)} pairs")
    _line("exactly the edge whose file the server HANDED OUT is `severed_by_repair`",
          by_repair == {PAIR_LEASED},
          f"{sorted(by_repair)} of {sorted(frame)}")
    _line("the edge severed by a file the server never handed out stays `severed`",
          PAIR_LOOSE not in by_repair)
    _line("and so does an edge that was never edited at all",
          PAIR_UNTOUCHED not in by_repair)
    _line("the open count is the frame less the repair-severed",
          len(frame) - len(by_repair) == EXPECTED["severed_links_open"]
          and len(by_repair) == EXPECTED["severed_by_repair"],
          f"severed_links {len(frame) - len(by_repair)} · "
          f"severed_by_repair {len(by_repair)}")
    # I-146 (2026-09-21): run 162 bucketed 14 edges and left no line naming the classifier, so a
    # MOUNTED record could not show the bucket firing. One line per bucketed edge, and none for an
    # edge that stays severed — read back off the daemon's own logger.
    bucket_lines = [ln for ln in logged.splitlines() if "SEVERED BY REPAIR" in ln]
    _line("I-146 — the bucket says so: ONE log line per bucketed edge, and none for the two that "
          "stay severed",
          len(bucket_lines) == len(by_repair) == EXPECTED["log_lines_per_bucketed_edge"]
          and f"{PAIR_LEASED[0]} -> {PAIR_LEASED[1]}" in bucket_lines[0]
          and PAIR_LOOSE[0] not in logged and PAIR_UNTOUCHED[0] not in logged,
          bucket_lines[0] if bucket_lines else "no line was logged")
    # I-146's DEDUPE (owner ruling 2026-09-21): the line is per bucketed edge per SEVER EVENT, in
    # `SEVERED LINK`'s own shape — the mirror writer classifies every frame, and three more frames of
    # the same red edge must add nothing to the record.
    again = "".join(_captured(cd.classify_severed_by_repair, frame, NODE_FILES, repo=target)[1]
                    for _ in range(3))
    repeats = [ln for ln in again.splitlines() if "SEVERED BY REPAIR" in ln]
    _line("and THREE further passes over the same red edge log nothing more — one line per edge per "
          "sever event, not one per classification pass",
          len(repeats) == EXPECTED["log_lines_on_repeat_passes"],
          f"{len(repeats)} line(s) across 3 passes")
    two = dict(cd.read_target_lease(target))
    two["quiet_mod.py::<module>::2"] = quiet_lease(lease_at)
    both, logged_two = _captured(cd.classify_severed_by_repair, frame, NODE_FILES,
                                 repo=target, lease=two)
    second = [ln for ln in logged_two.splitlines() if "SEVERED BY REPAIR" in ln]
    _line("while a SECOND edge entering the bucket logs its OWN line, the first still quiet",
          both == {PAIR_LEASED, PAIR_UNTOUCHED}
          and len(second) == EXPECTED["log_lines_for_a_second_edge"]
          and f"{PAIR_UNTOUCHED[0]} -> {PAIR_UNTOUCHED[1]}" in second[0]
          and f"{PAIR_LEASED[0]} -> {PAIR_LEASED[1]}" not in "".join(second),
          second[0] if second else "no line was logged")
    cd._SEVERED_BY_REPAIR_LOGGED.clear()


def part_iii_both_halves(target: Path, lease_at: datetime) -> None:
    print("\n3. BOTH HALVES OF THE RULE ARE NECESSARY (§D.1)")
    after = lease_at + timedelta(seconds=30)

    before_the_lease = {PAIR_LEASED: (lease_at - timedelta(seconds=30)).astimezone()
                        .replace(tzinfo=None).isoformat()}
    _line("TIME — a sever dated BEFORE the lease is not the lease's doing",
          cd.classify_severed_by_repair(before_the_lease, NODE_FILES, repo=target) == set(),
          "severed_since precedes the lease record's timestamp")

    path = target / "leased_mod.py"
    kept = path.read_text(encoding="utf-8")
    path.write_text(LEASED_BEFORE, encoding="utf-8")          # the client backed the edit out
    _line("IDENTITY — a lease whose after-text is NOT what the file reads now is refused",
          cd.classify_severed_by_repair(severed_frame(after), NODE_FILES, repo=target) == set(),
          "the client reverted; the bytes the server handed out are not on disk")
    path.write_text(kept, encoding="utf-8")

    moved = LEASED_AFTER_SPAN.join(["# a later edit above pushed the leased span down\n", ""])
    path.write_text(moved + kept, encoding="utf-8")
    _line("IDENTITY — but a LATER edit that only moved the leased text does not lose it",
          cd.classify_severed_by_repair(severed_frame(after), NODE_FILES,
                                        repo=target) == {PAIR_LEASED},
          "the same window, found where the later edit left it")
    path.write_text(kept, encoding="utf-8")

    _line("NO LEASE — an empty lease buckets nothing, whatever the frame says",
          cd.classify_severed_by_repair(severed_frame(after), NODE_FILES,
                                        repo=target, lease={}) == set())


def part_iv_the_two_clocks(target: Path, lease_at: datetime) -> None:
    print("\n4. THE TWO CLOCKS — naive LOCAL `severed_since` against an aware UTC lease")
    offset = datetime.now().astimezone().utcoffset() or timedelta(0)
    one_second_after = severed_frame(lease_at + timedelta(seconds=1))
    _line("a sever one second after the lease is bucketed, whatever this machine's offset",
          cd.classify_severed_by_repair(one_second_after, NODE_FILES,
                                        repo=target) == {PAIR_LEASED},
          f"local offset {offset} — compared raw, every sever would read as "
          f"{abs(offset)} older than every lease")
    one_second_before = severed_frame(lease_at - timedelta(seconds=1))
    _line("and one second BEFORE it is not — the boundary is the lease's own instant",
          cd.classify_severed_by_repair(one_second_before, NODE_FILES, repo=target) == set())


# ─────────────────────────────────────────────────────────────────────────────
# (v) `finished`'s severed input, through the daemon's own mirror writer
# ─────────────────────────────────────────────────────────────────────────────


class _Node:
    """What `write_repo_mirror` reads off a graph node, and nothing else."""

    def __init__(self, name: str, rel: str) -> None:
        self.name = name
        self.relative_path = rel
        self.connected = True
        self.import_error = None


class _Graph:
    def __init__(self) -> None:
        self.nodes = [_Node(n, r) for n, r in NODE_FILES.items()]
        self.cycles: list[Any] = []


def _mirror(target: Path, scripts: Path, severed: dict, mypy_results: dict) -> dict:
    """One `write_repo_mirror` frame, written into the FIXTURE's `system_scripts/` and read
    back. The daemon's own arithmetic decides `finished`; nothing is recomputed here."""
    cd.TARGET_REPO = target
    cd.SCRIPT_DIR = scripts
    cd.NOAI_MIRROR_FILE = scripts / ".noai_state.json"
    cd.write_repo_mirror(_Graph(), {}, mypy_results, {}, {}, severed_links=severed)
    return json.loads((scripts / ".monitor_state.json").read_text(encoding="utf-8"))["monitor"]


MYPY_MEASURED = {"mypy_ran": True, "mypy_rc": 0, "files_checked": 12, "recent_checks": []}


def part_v_the_finished_input(target: Path, scripts: Path, lease_at: datetime) -> None:
    print("\n5. `finished`'s SEVERED INPUT, THROUGH `write_repo_mirror` ITSELF (§D.1)")
    (scripts / ".noai_state.json").write_text(json.dumps({"summary": {"failed": 0}}),
                                              encoding="utf-8")
    frame = severed_frame(lease_at + timedelta(seconds=30))

    m = _mirror(target, scripts, frame, MYPY_MEASURED)
    s = m["summary"]
    _line("the mirror publishes both counts, and they sum to every red edge",
          s["severed_links"] == EXPECTED["severed_links_open"]
          and s["severed_by_repair"] == EXPECTED["severed_by_repair"]
          and len(m["wiring"]["severed"]) == EXPECTED["severed_pairs"],
          f"severed_links {s['severed_links']} + severed_by_repair "
          f"{s['severed_by_repair']} = wiring.severed {len(m['wiring']['severed'])}")
    _line("the repair-severed edge is still DRAWN RED — it is named, not hidden",
          [list(PAIR_LEASED)] == m["wiring"]["severed_by_repair"]
          and list(PAIR_LEASED) in m["wiring"]["severed"])
    _line("`finished` is false while an UNLEASED sever stands",
          s["finished"] is EXPECTED["finished_with_open_sever"]
          and s["finished_inputs"]["severed_links"] == EXPECTED["severed_links_open"],
          s["finished_reason"])

    only_repair = {PAIR_LEASED: frame[PAIR_LEASED]}
    s2 = _mirror(target, scripts, only_repair, MYPY_MEASURED)["summary"]
    _line("and TRUE with the same repair-severed edge still red — I-127's whole point",
          s2["finished"] is EXPECTED["finished_with_only_repair_severs"]
          and s2["severed_by_repair"] == 1 and s2["severed_links"] == 0,
          f"{s2['finished_reason']} · severed_by_repair {s2['severed_by_repair']}")


# ─────────────────────────────────────────────────────────────────────────────
# (vi) + (vii) the mypy invocation
# ─────────────────────────────────────────────────────────────────────────────


MYPY_FIXTURE_MODULE = "type Alias = int\n\n\ndef add(a: int, b: int) -> int:\n    return a + b\n"

PINNED_PYPROJECT = '[tool.mypy]\npython_version = "3.10"\nshow_error_codes = true\n'

CRASHING_PYPROJECT = ('[tool.mypy]\npython_version = "3.10"\n'
                      'plugins = ["no_such_plugin_at_all"]\n')


class _ArgvSpy:
    """`subprocess`, with every argv recorded on the way through. The proof quotes the LITERAL
    command the tracker built rather than a reconstruction of it."""

    def __init__(self, real) -> None:
        self.real = real
        self.argv: list[list[str]] = []

    def run(self, cmd, **kw):
        self.argv.append([str(c) for c in cmd])
        return self.real.run(cmd, **kw)

    def Popen(self, cmd, **kw):
        # B8 (2026-10-01, Q-H1-4): the tool scans go through `_run_tool`'s Popen so a shutdown
        # signal can stop a running mypy; the spy records that path too, or the proof reads an
        # empty argv and calls the forced flags missing (gates_after_lanes_1001).
        self.argv.append([str(c) for c in cmd])
        return self.real.Popen(cmd, **kw)

    def __getattr__(self, name):
        return getattr(self.real, name)


def _scan(where: Path, pyproject: str) -> tuple[dict, list[str]]:
    """One `run_mypy_scan` over a fixture target, with the argv it used."""
    (where / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    (where / "ok_mod.py").write_text(MYPY_FIXTURE_MODULE, encoding="utf-8")
    spy = _ArgvSpy(cd.subprocess)
    real_subprocess, real_target, real_cache = cd.subprocess, cd.TARGET_REPO, cd.MYPY_CACHE_DIR
    cd.subprocess, cd.TARGET_REPO, cd.MYPY_CACHE_DIR = spy, where, where / ".mypy_cache"
    try:
        result = cd.run_mypy_scan()
    finally:
        cd.subprocess, cd.TARGET_REPO, cd.MYPY_CACHE_DIR = real_subprocess, real_target, real_cache
    mypy_argv = next((a for a in spy.argv if "--config-file" in a), [])
    return result, mypy_argv


def part_vi_the_forced_version(tmp: Path) -> None:
    print("\n6. THE mypy INVOCATION — the RUNNING interpreter's version, forced (Q2)")
    where = tmp / "pinned"
    where.mkdir()
    result, argv = _scan(where, PINNED_PYPROJECT)
    forced = EXPECTED["forced_version"]
    _line("the target's own config is still in force — its excludes and its extensions are its own",
          "--config-file" in argv
          and argv[argv.index("--config-file") + 1].endswith("pyproject.toml"),
          f"--config-file {Path(argv[argv.index('--config-file') + 1]).name}"
          if "--config-file" in argv else "no --config-file in the argv")
    _line(f"and `--python-version {forced}` is forced over the `{EXPECTED['pinned_by_target']}` "
          f"it pins",
          "--python-version" in argv
          and argv[argv.index("--python-version") + 1] == forced
          and result.get("mypy_python_version") == forced,
          " ".join(argv[argv.index("--python-version"):argv.index("--python-version") + 2])
          if "--python-version" in argv else "no --python-version in the argv")
    _line("so the scan RUNS on a target that used to silence it",
          bool(result.get("mypy_ran")) is True
          and int(result.get("files_checked") or 0) == EXPECTED["files_checked_when_forced"],
          f"mypy_ran {result.get('mypy_ran')} · mypy_rc {result.get('mypy_rc')} · "
          f"{result.get('files_checked')} file(s) checked")
    _line("the fixture is I-128's shape in miniature: under the pin mypy cannot even parse it",
          _pinned_version_aborts(where),
          f"the module's `type` statement needs 3.12 or greater; "
          f"the target pins {EXPECTED['pinned_by_target']}")


def part_vi_b_the_runners_pythonpath(tmp: Path) -> None:
    """I-128's SECOND cause, found by run 161 and not in the pinned row.

    A src-layout target needs `PYTHONPATH=<target>/src` for the RUNNER (I-134). mypy reads that
    variable too, and then finds every `src/<pkg>/<mod>.py` twice — once as `<pkg>.<mod>` down
    that path, once as `src.<pkg>.<mod>` down the cwd base `--explicit-package-bases` gives it.
    "Source file found twice under different module names" is a BLOCKING error: rc 2, 0 files
    checked, exactly the silence I-128 pinned, from the other end."""
    print("\n6b. THE RUNNER's `PYTHONPATH` DOES NOT REACH mypy (I-128's second cause, run 161)")
    where = tmp / "srclayout"
    (where / "src" / "pkg").mkdir(parents=True)
    (where / "pyproject.toml").write_text(PINNED_PYPROJECT, encoding="utf-8")
    (where / "src" / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    # click ships `src/click/py.typed`; without the marker mypy skips an installed package as
    # untyped and never notices the duplicate, so the fixture is only I-128's shape WITH it.
    (where / "src" / "pkg" / "py.typed").write_text("", encoding="utf-8")
    (where / "src" / "pkg" / "mod.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    # The second half of the duplicate: a file OUTSIDE `src` that imports the package by its
    # installed name. With `<target>/src` on PYTHONPATH mypy resolves that import to
    # `src/pkg/__init__.py` as `pkg`, while the same file was handed to it explicitly and
    # computes as `src.pkg` — one file, two module names, and mypy stops.
    (where / "use_pkg.py").write_text("import pkg\n\nprint(pkg)\n", encoding="utf-8")

    kept = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(where / "src")
    try:
        result, argv = _scan_no_fixture(where)
        _line("with the runner's PYTHONPATH exported, the scan still RUNS and checks its files",
              bool(result.get("mypy_ran")) is True
              and int(result.get("files_checked") or 0) >= 1,
              f"PYTHONPATH={where.name}/src · mypy_ran {result.get('mypy_ran')} · "
              f"mypy_rc {result.get('mypy_rc')} · {result.get('files_checked')} file(s) checked")
        _line("the variable is dropped from mypy's own environment and nowhere else",
              _with_pythonpath_aborts(where),
              "the same argv WITH PYTHONPATH reaching mypy: rc 2, "
              "`Source file found twice under different module names`")
    finally:
        if kept is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = kept


def _scan_no_fixture(where: Path) -> tuple[dict, list[str]]:
    """`_scan` without overwriting the target's files — this fixture is a src layout, not the
    single module the version case needs."""
    spy = _ArgvSpy(cd.subprocess)
    real_subprocess, real_target, real_cache = cd.subprocess, cd.TARGET_REPO, cd.MYPY_CACHE_DIR
    cd.subprocess, cd.TARGET_REPO, cd.MYPY_CACHE_DIR = spy, where, where / ".mypy_cache"
    try:
        result = cd.run_mypy_scan()
    finally:
        cd.subprocess, cd.TARGET_REPO, cd.MYPY_CACHE_DIR = real_subprocess, real_target, real_cache
    return result, next((a for a in spy.argv if "--config-file" in a), [])


def _with_pythonpath_aborts(where: Path) -> bool:
    """The same command, with the variable left in place: measured, not asserted."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(where / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", "pyproject.toml",
         "--python-version", EXPECTED["forced_version"], "--no-incremental",
         "--explicit-package-bases", "--cache-dir", str(where / ".pp_cache"),
         "src/pkg/__init__.py", "src/pkg/mod.py", "use_pkg.py"],
        capture_output=True, text=True, cwd=str(where), env=env, timeout=300)
    return (proc.returncode == EXPECTED["rc_on_abort"]
            and "found twice under different module names" in proc.stdout + proc.stderr)


def _pinned_version_aborts(where: Path) -> bool:
    """The same fixture with the target's pin in force and nothing forced over it: rc 2, the
    reading run 155 carried for a whole run. Measured, so the claim above is not an assertion."""
    proc = subprocess.run([sys.executable, "-m", "mypy", "--config-file", "pyproject.toml",
                           "--no-incremental", "--cache-dir", str(where / ".pin_cache"),
                           "ok_mod.py"],
                          capture_output=True, text=True, cwd=str(where), timeout=300)
    return proc.returncode == EXPECTED["rc_on_abort"]


def part_vii_not_measured(tmp: Path) -> None:
    print("\n7. THE ABORT — `mypy_rc 2`, 0 files, and `finished` = \"not measured\" (Q2)")
    where = tmp / "crashing"
    where.mkdir()
    result, _ = _scan(where, CRASHING_PYPROJECT)
    _line("a target config that makes mypy crash is published LOUDLY, not as a clean zero",
          result.get("mypy_rc") == EXPECTED["rc_on_abort"]
          and bool(result.get("mypy_ran")) is False
          and int(result.get("files_checked") or 0) == EXPECTED["files_checked_on_abort"],
          f"mypy_ran {result.get('mypy_ran')} · mypy_rc {result.get('mypy_rc')} · "
          f"{result.get('files_checked')} file(s) checked")

    scripts = tmp / "crashing_scripts"
    scripts.mkdir()
    (scripts / ".noai_state.json").write_text(json.dumps({"summary": {"failed": 0}}),
                                              encoding="utf-8")
    monitor = _mirror(where, scripts, {}, result)
    _line("the mirror's second `finished` input is NOT MEASURED, and `mypy_errors` 0 is not it",
          monitor["summary"]["finished_inputs"]["mypy_errors"] is None,
          monitor["summary"]["finished_reason"])

    status = _cr_status_over(scripts, where, monitor)
    _line("`cr_status.finished` reads \"not measured\" — never `true`, and not `false` either",
          status["finished"] == EXPECTED["finished_on_abort"],
          f"finished={status['finished']!r} source={status['finished_source']}")
    _line("and the three mypy facts ride at the top level of the payload, additive",
          status["mypy_ran"] is False and status["mypy_rc"] == EXPECTED["rc_on_abort"]
          and status["mypy_files_checked"] == EXPECTED["files_checked_on_abort"]
          and status["severed_by_repair"] == 0,
          f"mypy_ran {status['mypy_ran']} · mypy_rc {status['mypy_rc']} · "
          f"mypy_files_checked {status['mypy_files_checked']} · "
          f"severed_by_repair {status['severed_by_repair']}")


def _cr_status_over(scripts: Path, target: Path, monitor: dict) -> dict[str, Any]:
    """`cr_status` over a fixture state directory, then the tree's own sources restored."""
    kept = rt.sources()
    state = scripts / "state"
    state.mkdir(exist_ok=True)
    (state / ".monitor_state.json").write_text(json.dumps({"monitor": monitor}), encoding="utf-8")
    (state / "BUILDER_STATE.json").write_text(json.dumps(
        {"phase": "MONITORING", "detail": "fixture", "cycle": 1,
         "target_repo": str(target), "repo_id": cd.get_repo_id(target)}), encoding="utf-8")
    (state / ".noai_state.json").write_text(json.dumps(
        {"summary": {"failed": 0, "repairs": 0, "no_vetted_fix": 0, "withheld": 0}}),
        encoding="utf-8")
    (state / "circuit_state.json").write_text(json.dumps({"scan_cadence": {}}), encoding="utf-8")
    try:
        rt.configure(target=str(target), state_dir=state)
        return rt.cr_status()
    finally:
        rt.configure(target=kept.target, state_dir=kept.state_dir)


# ─────────────────────────────────────────────────────────────────────────────
# (viii) re-promotion, unchanged
# ─────────────────────────────────────────────────────────────────────────────


def part_viii_re_promotion() -> None:
    print("\n8. RE-PROMOTION BY THE EXISTING PATH IS UNTOUCHED (§B Q1)")
    names = set(NODE_FILES)
    severed = {PAIR_LEASED: "2026-09-21T10:00:00"}
    held = cd.compute_severed_links(set(), set(), severed, names)
    _line("a pair still not live is HELD, with the instant it went red unchanged",
          held == severed, f"severed_since {held.get(PAIR_LEASED)}")
    back = cd.compute_severed_links(set(), {PAIR_LEASED}, severed, names)
    _line("and the frame it is live again it LEAVES the set — the entry run re-measures it",
          back == {}, "no patch re-promotes it; the flow evidence does")


# ─────────────────────────────────────────────────────────────────────────────
# (ix) the live part
# ─────────────────────────────────────────────────────────────────────────────


def part_ix_run_161() -> None:
    print("\n9. RUN 161's OWN RECORD — the live part")
    if not RUN_161.is_file():
        _line(f"run 161's `cr_status` is archived at {RUN_161.relative_to(TREE)}", False,
              "the record is not in this tree")
        return
    status = json.loads(RUN_161.read_text(encoding="utf-8"))
    _line("the apply pass left at least one edge bucketed `severed_by_repair`",
          int(status.get("severed_by_repair") or 0) >= 1,
          f"severed_by_repair {status.get('severed_by_repair')}")
    _line("mypy RAN on the click snapshot, which pins 3.10 — I-128's own target",
          bool(status.get("mypy_ran")) is True
          and int(status.get("mypy_files_checked") or 0) > 0,
          f"mypy_ran {status.get('mypy_ran')} · mypy_rc {status.get('mypy_rc')} · "
          f"{status.get('mypy_files_checked')} files checked")
    _line("and `finished` is a BOOLEAN — every one of the three inputs was measured",
          isinstance(status.get("finished"), bool),
          f"finished={status.get('finished')!r} · {status.get('finished_reason')}")


# ─────────────────────────────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    print("=" * 78)
    print("THE `finished` INPUTS — I-127 (severed by repair) · I-128 (the mypy gate)")
    print("=" * 78)
    kept = (cd.TARGET_REPO, cd.SCRIPT_DIR, cd.NOAI_MIRROR_FILE, cd.MYPY_CACHE_DIR)
    # `.resolve()` matters: on macOS `mkdtemp` hands back `/var/folders/…`, a symlink to
    # `/private/var/…`, and mypy then reads a file reached two ways as two FILES rather than
    # one file under two module names — which is the very thing (vi-b) measures.
    tmp = Path(tempfile.mkdtemp(prefix="finished_proof_")).resolve()
    try:
        target, scripts, channel = build_fixture(tmp)
        print(f"fixture tree: {tmp}")
        lease_at = datetime.now(timezone.utc)
        record = write_lease(channel, lease_at)
        client_applies_the_leased_edit(target)
        client_touches_the_unleased_file(target)
        part_i_the_reader(target, scripts, record)
        part_ii_one_in_each_bucket(target, lease_at)
        part_iii_both_halves(target, lease_at)
        part_iv_the_two_clocks(target, lease_at)
        part_v_the_finished_input(target, scripts, lease_at)
        part_vi_the_forced_version(tmp)
        part_vi_b_the_runners_pythonpath(tmp)
        part_vii_not_measured(tmp)
    finally:
        cd.TARGET_REPO, cd.SCRIPT_DIR, cd.NOAI_MIRROR_FILE, cd.MYPY_CACHE_DIR = kept
        shutil.rmtree(tmp, ignore_errors=True)
    part_viii_re_promotion()
    part_ix_run_161()
    print("\n" + "=" * 78)
    if FAILURES:
        print(f"finished proof: FAIL ({len(FAILURES)})")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("finished proof: PASS — the lease read, the bucket, both halves, the two clocks, "
          "the severed input, the forced version, the runner's PYTHONPATH, `not measured`, "
          "and run 161")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
