"""THE DRIFT FIX's proof — PRE-EDIT IDENTITY, the 15th gate (session 7, packet §C.6).

Six issues, one cause: **row identity is positional (`<file>::<function>::<line>`) and so is the
channel's join key (`digest` + `replace_span`), so the row a seat was handed drifts out from
under it between `cr_apply` and `cr_report_outcome`.**

  I-119  a repaired row is retired by the Builder within one cycle (30-60 s, shorter than one
         3-second suite) and the seat's report finds nothing — 8 of 18 outcomes lost in run 155
  I-125  a failed-then-reverted row is retired against bytes that no longer exist, so the
         negative — the scarcer datum — is lost
  I-130  every earlier edit to the same file shifts the rows below it and `cr_apply`'s diff is
         not re-based
  I-137  an HTML-escaped id (`&lt;module&gt;`) loses every module-scope row
  I-138  the digest and rule ids of a row can change between apply and report
  I-122  the variant of a failed repair lives only on the row and dies with the re-decide

One repair: **the server remembers what it handed out (the APPLY LEASE), and every record it
writes carries the PRE-EDIT identity.**

Seven parts, the house shape (`gate_proof.EXPECTED`'s table, `mcp_write_path_proof`'s fixture
tree behind `CODERADAR_MCP_ROOT`, `b9_proof`'s hand-read expectations):

  (i)   apply A → a lease is written with the row's digest / span / variant
  (ii)  retire A and shift every row below it → `cr_report_outcome(A, confirmed)` is
        `written true · resolved_by lease`, and the line AND the ledger record carry A's
        PRE-EDIT digest / span / rule_ids / variant
  (iii) `cr_report_outcome(A, failed)` after the retire → `written true`; and `_join_channel`
        over a mirror where A has returned RE-KEYED +3 lines joins it, `orphans 0`
  (iv)  a stale-line id and an `&lt;module&gt;` id both resolve; a repeated `(file, function)`
        is refused WITH THE CANDIDATES NAMED
  (v)   an earlier edit to the same file → `cr_apply`'s diff applies cleanly against the LIVE
        bytes and `replace_span_live` != `replace_span`
  (vi)  `rule_outcomes` over the new lines shows the VARIANT — no `?`, with the re-keyed rows
        and with no rows at all
  (vii) THE LIVE PART — run 158's own record: every `cr_report_outcome` `written true`,
        `orphans_channel 0`, `failed_against` without `?`

SESSION 10 (2026-09-22, lane T1) adds an eighth part over its own fixture tree, for the four
payload/identity rulings of that session's §B — each with the run whose measurement asked for it:

  (viii) a. I-148 (a) / Q3 — a recorded `replace_span` that matches NEITHER the original NOR the
            live file (run 162's `_termui_impl.py::open_url`, L804-L868 beside a correct
            L802-L869) is MARKED, never dropped: `span_current false` on the row and on the
            `cr_apply` answer, `replace_span_live` correct on both.
         b. I-148 (b) — the `reason` prose NAMES THE DECORATOR when the span starts at one (run
            162's `_pipepager`: the prose said "above `def`", the span began at
            `@contextlib.contextmanager`, and following it literally emits a `SyntaxError`).
         c. I-148 (c) / Q4 + I-145 / Q2 — `resolved_by` is a function of (id, mirror state) alone,
            proved on a repeated call with a different `context_lines`; `given_id` beside
            `resolved_id` on the payload, the lease, the channel line and the ledger record (run
            162: `::549` given, `::550` filed); `_lease_lookup` on the resolved key FIRST and an
            EXACT `given_id` second.
         d. I-152 / Q1 — a row whose every candidate is an un-renderable shape publishes
            `selected_role ""`, `apply "no"`, `withheld_by gate.prescription_check` and the
            sentence, stays in its bucket, and `cr_apply` on it offers nothing (run 163's
            `src/click/utils.py::__exit__::237`).

EVERY EXPECTED VALUE IN `EXPECTED` BELOW WAS WRITTEN DOWN BEFORE THE COMPUTE WAS RUN (the lane
brief's order, `gate_proof.EXPECTED`'s idiom). The fixture is synthetic on purpose: the drift
cases are the point, and a hand-built mirror is the only way to state them exactly.

    .venv_new/bin/python -m coderadar_mcp.identity_proof        exit 0 = PASS
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

TREE = Path(__file__).resolve().parents[1]
if str(TREE) not in sys.path:
    sys.path.insert(0, str(TREE))

RUNS = TREE / ".archive" / "gate_evidence" / "runs"   # F1 (2026-10-01): gate evidence lives under .archive/gate_evidence/, never pruned by retention

# ─────────────────────────────────────────────────────────────────────────────
# THE FIXTURE — written out here so every expected number below can be read off it
# ─────────────────────────────────────────────────────────────────────────────

#: Three rewriter rows in ONE file, at L4-L6, L9-L11 and L14-L16. `alpha` is row A.
PLANT_A = '''"""fixture: three rewriter rows in ONE file (I-130's shape)."""


def alpha(items=[]):
    seen = items
    return seen


def beta(values=[]):
    out = values
    return out


def gamma(rows=[]):
    got = rows
    return got
'''

#: A module-scope row at L2 (I-137's shape) and the SAME function name twice (§C.5's refusal).
PLANT_B = '''import sys
sys.path.insert(0, ".")


class One:
    def handler(self):
        return 1


class Two:
    def handler(self):
        return 2
'''

#: A's repair is TWO LINES LONGER than what it replaces — that is what shifts `beta` 9 → 11 and
#: `gamma` 14 → 16, which is (v), and what the mirror is re-staged to in (ii).
A_AFTER = """def alpha(items=None):
    items = [] if items is None else items
    seen = list(items)
    del items
    return seen
"""

_ROWS: tuple[dict[str, Any], ...] = (
    {"key": "plant_a.py::alpha::4", "file": "plant_a.py", "function": "alpha", "line": 4,
     "line_end": 6, "digest": "aaa1111111", "rule_ids": ["NAI-021S", "NAI-071"],
     "selected_role": "alias_chain_fix:new_sequence", "solution_kind": "rewriter",
     "before_code": "def alpha(items=[]):\n    seen = items\n    return seen\n",
     "after_code": A_AFTER},
    {"key": "plant_a.py::beta::9", "file": "plant_a.py", "function": "beta", "line": 9,
     "line_end": 11, "digest": "bbb2222222", "rule_ids": ["NAI-061"],
     "selected_role": "bool_literal_compare_fix", "solution_kind": "rewriter",
     "before_code": "def beta(values=[]):\n    out = values\n    return out\n",
     "after_code": "def beta(values=None):\n    out = list(values or [])\n    return out\n"},
    {"key": "plant_a.py::gamma::14", "file": "plant_a.py", "function": "gamma", "line": 14,
     "line_end": 16, "digest": "ccc3333333", "rule_ids": ["NAI-070"],
     "selected_role": "bare_except_fix", "solution_kind": "rewriter",
     "before_code": "def gamma(rows=[]):\n    got = rows\n    return got\n",
     "after_code": "def gamma(rows=None):\n    got = list(rows or [])\n    return got\n"},
    {"key": "plant_b.py::<module>::2", "file": "plant_b.py", "function": "<module>", "line": 2,
     "line_end": 2, "digest": "ddd4444444", "rule_ids": ["NAI-094"],
     "selected_role": "solution_NAI-094", "solution_kind": "prescribed",
     "before_code": 'sys.path.insert(0, ".")\n',
     "after_code": "# import <real.package.module> instead of hacking sys.path\n"},
    {"key": "plant_b.py::handler::6", "file": "plant_b.py", "function": "handler", "line": 6,
     "line_end": 7, "digest": "eee5555555", "rule_ids": ["NAI-082"],
     "selected_role": "magic_number_fix", "solution_kind": "rewriter",
     "before_code": "    def handler(self):\n        return 1\n",
     "after_code": "    def handler(self):\n        return ONE\n"},
    {"key": "plant_b.py::handler::11", "file": "plant_b.py", "function": "handler", "line": 11,
     "line_end": 12, "digest": "fff6666666", "rule_ids": ["NAI-082"],
     "selected_role": "magic_number_fix", "solution_kind": "rewriter",
     "before_code": "    def handler(self):\n        return 2\n",
     "after_code": "    def handler(self):\n        return TWO\n"},
)

#: HAND-WRITTEN BEFORE THE COMPUTE. Read straight off the fixture above.
EXPECTED: dict[str, Any] = {
    # (i) the lease A is handed — the row's own identity, frozen
    "lease_A": {
        "row_key": "plant_a.py::alpha::4",
        "digest": "aaa1111111",
        "replace_span": "plant_a.py:L4-L6",
        "replace_span_live": "plant_a.py:L4-L6",   # nothing has shifted yet
        "file": "plant_a.py", "function": "alpha", "line": 4,
        "rule_ids": ["NAI-021S", "NAI-071"],
        "variant": "alias_chain_fix:new_sequence",
        "solution_kind": "rewriter",
    },
    # (ii) / (iii) what the line and the ledger record must carry once A is GONE from the mirror
    "line_A": {
        "digest": "aaa1111111", "replace_span": "plant_a.py:L4-L6",
        "row_key": "plant_a.py::alpha::4", "rule_ids": ["NAI-021S", "NAI-071"],
        "variant": "alias_chain_fix:new_sequence",
        "file": "plant_a.py", "function": "alpha",
    },
    "resolved_by_after_retire": "lease",
    # (iii) the re-keyed row A comes back at +3 lines and the line still joins
    "rekeyed_key": "plant_a.py::alpha::7",
    "rekeyed_orphans": 0,
    # (iv) the three id cases
    "stale_line_id": "plant_a.py::beta::999",
    "stale_resolves_to": "plant_a.py::beta::9",
    "escaped_id": "plant_b.py::&lt;module&gt;::2",
    "escaped_resolves_to": "plant_b.py::<module>::2",
    "ambiguous_id": "plant_b.py::handler::77",
    "ambiguous_candidates": ["plant_b.py::handler::11", "plant_b.py::handler::6"],
    # (iv) is asked AFTER the Builder's rescan, so the live mirror's beta is at ::11; the
    # BUILDER_STATE rows the `cr_row` resolver is shown are the pre-rescan ones, at ::9.
    "stale_resolves_to_live": "plant_a.py::beta::11",
    # (v) after A's 5-line repair replaces 3 lines, beta is at L11-L13 and gamma at L16-L18
    "beta_span_recorded": "plant_a.py:L9-L11",
    "beta_span_live": "plant_a.py:L11-L13",
    "gamma_span_recorded": "plant_a.py:L14-L16",
    "gamma_span_live": "plant_a.py:L16-L18",
    # (vi) the block over the two lines A wrote: confirmed from the ledger, failed under the
    # VARIANT — and `?` nowhere, with rows and without them
    "rule_outcomes": {
        "NAI-021S": {"confirmed_for": 1,
                     "failed_against": {"alias_chain_fix:new_sequence": 1}},
        "NAI-071": {"confirmed_for": 1,
                    "failed_against": {"alias_chain_fix:new_sequence": 1}},
    },
}

FAILURES: list[str] = []


def ok(cond: bool, what: str) -> None:
    print(f"  {'OK ' if cond else 'BAD'} {what}")
    if not cond:
        FAILURES.append(what)


def part(title: str) -> None:
    print(f"\n{title}")


def read_json(path: Path) -> Any:
    """Through `read_tools._read_json_any`: this file's name carries `proof`, so a plain
    `json.load` written HERE would be a step-17 pre-ranker hunter site with no ledger row
    (`b9_proof` reads the same way for the same reason)."""
    from .read_tools import _read_json_any
    return _read_json_any(path)


def jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for raw in path.read_bytes().decode("utf-8", "replace").splitlines():
        raw = raw.strip()
        if raw:
            try:
                doc = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(doc, dict):
                out.append(doc)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# The fixture tree, behind the `CODERADAR_MCP_ROOT` seam `write_tools._root()` leaves
# ─────────────────────────────────────────────────────────────────────────────


def mirror_rows(skip: str = "", shift_below: int = 0) -> list[dict[str, Any]]:
    """The mirror's `repairs[]`. `skip` RETIRES a row (what the Builder does to a repaired row
    within one cycle — I-119); `shift_below` moves every row below it down that many lines in
    `plant_a.py`, which is what an applied repair two lines longer than its span really does."""
    out: list[dict[str, Any]] = []
    cut = next((r for r in _ROWS if r["key"] == skip), None)
    for row in _ROWS:
        if row["key"] == skip:
            continue
        line, end = row["line"], row["line_end"]
        if cut and row["file"] == cut["file"] and line > cut["line"]:
            line, end = line + shift_below, end + shift_below
        out.append({
            "file": row["file"], "function": row["function"], "line": line, "line_end": end,
            "replace_span": f"{row['file']}:L{line}-L{end}",
            "finding_lines": [line], "rule_ids": list(row["rule_ids"]),
            "infraction": f"fixture row {row['key']}",
            "fix": f"fixture fix for {row['function']}",
            "before_code": row["before_code"], "after_code": row["after_code"],
            "selected_role": row["selected_role"], "solution_kind": row["solution_kind"],
            "digest": row["digest"], "return_channel": CHANNEL[0],
        })
    return out


#: filled by `build_fixture`; a one-element list so the row builder above can see it.
CHANNEL: list[str] = [""]


def _lease_file() -> str:
    """The lease beside the fixture's channel, by the engine's own naming rule — never spelled
    twice (`write_tools._lease_path` is the rule)."""
    from .write_tools import _lease_path
    return _lease_path(CHANNEL[0])


def stage_mirror(target: Path, sysd: Path, skip: str = "", shift_below: int = 0) -> None:
    doc = {
        "status": "6 FINDINGS", "last_scan": "2026-09-21T00:00:00+00:00",
        "target_repo": str(target),
        "summary": {"failed": len(_ROWS), "repairs": len(_ROWS), "no_vetted_fix": 0},
        "repairs": mirror_rows(skip, shift_below), "no_vetted_fix": [], "withheld": [],
    }
    (sysd / ".noai_state.json").write_text(json.dumps(doc), encoding="utf-8")


def build_fixture(tmp: Path) -> tuple[Path, Path, str]:
    sysd = tmp / "system_scripts"
    sysd.mkdir(parents=True)
    target = tmp / "target"
    target.mkdir()
    (target / "plant_a.py").write_text(PLANT_A, encoding="utf-8")
    (target / "plant_b.py").write_text(PLANT_B, encoding="utf-8")
    CHANNEL[0] = str(sysd / "return_channel_fixture158.jsonl")
    stage_mirror(target, sysd)
    (sysd / "BUILDER_STATE.json").write_text(json.dumps({
        "repo_id": "fixture158", "target_repo": str(target), "return_channel": CHANNEL[0],
        "phase": "MONITORING", "rows": {},
    }), encoding="utf-8")
    os.environ["CODERADAR_MCP_ROOT"] = str(tmp)
    return target, sysd, CHANNEL[0]


def state_rows(shift: int = 0, rekey: str = "") -> dict[str, dict[str, Any]]:
    """`BUILDER_STATE.json`-shaped rows, the shape `_join_channel` and `rule_outcomes` read.
    `rekey` puts ONE row back at a new key `shift` lines further down — run 155's
    `utils.py::__getattr__` 669 → 558, the fact that made a re-keyed row unjoinable."""
    out: dict[str, dict[str, Any]] = {}
    for row in _ROWS:
        line, end, key = row["line"], row["line_end"], row["key"]
        if rekey and key == rekey:
            line, end = line + shift, end + shift
            key = f"{row['file']}::{row['function']}::{line}"
        out[key] = {
            "row_key": key, "file": row["file"], "function": row["function"],
            "line": line, "line_end": end,
            "replace_span": f"{row['file']}:L{line}-L{end}",
            "rule_ids": list(row["rule_ids"]), "rule_ids_all": list(row["rule_ids"]),
            "digest": row["digest"], "rca_evidence": [],
            "decision": {"pick_role": row["selected_role"], "why": "fixture"},
            "selected_role": row["selected_role"],
        }
    return out


# ─────────────────────────────────────────────────────────────────────────────
# (i) — (vi): the offline parts
# ─────────────────────────────────────────────────────────────────────────────


def part_i_the_lease(target: Path, channel: str) -> dict[str, Any]:
    from . import write_tools as wt
    part("(i) THE LEASE — `cr_apply` records what it hands out (§C.1, I-119 / I-125 / I-138)")
    rid = EXPECTED["lease_A"]["row_key"]
    out = wt.cr_apply(rid)
    ok(out["kind"] == "diff" and out["applies_cleanly"] is True and out["error"] is None,
       f"cr_apply({rid}) → diff, applies_cleanly={out['applies_cleanly']}")
    ok(out["lease_written"] is True and out["lease"].endswith("apply_lease_fixture158.jsonl"),
       f"lease written beside the channel: {Path(out['lease']).name}")
    leases = jsonl(Path(out["lease"]))
    ok(len(leases) == 1, f"one lease record on disk ({len(leases)})")
    rec = leases[-1] if leases else {}
    for key, want in EXPECTED["lease_A"].items():
        ok(rec.get(key) == want, f"lease.{key} = {rec.get(key)!r} (expected {want!r})")
    from .tool_interface import APPLY_LEASE_RECORD
    ok([f.name for f in APPLY_LEASE_RECORD] == list(rec),
       "the record IS `APPLY_LEASE_RECORD`, in that order")
    ok(bool(rec.get("before_sha256")) and bool(rec.get("after_sha256"))
       and rec.get("before_sha256") != rec.get("after_sha256"),
       "before_sha256 != after_sha256 — the bytes the edit replaces and the bytes it writes")
    before = (target / "plant_a.py").read_bytes()
    ok(before == PLANT_A.encode(), "cr_apply wrote NOTHING to the target")
    return out


def client_writes_As_edit(target: Path) -> None:
    """The client applies A's edit, exactly as a seat would — five lines where three were.
    Everything below `alpha` in `plant_a.py` has just moved two lines down on DISK, while the
    mirror still says where they were at the last scan. That gap is I-130."""
    text = (target / "plant_a.py").read_text(encoding="utf-8").splitlines(keepends=True)
    (target / "plant_a.py").write_text(
        "".join(text[:3]) + A_AFTER + "".join(text[6:]), encoding="utf-8")


def part_ii_retired(target: Path, sysd: Path, channel: str) -> None:
    from . import write_tools as wt
    part("(ii) THE ROW IS RETIRED AND EVERY ROW BELOW IT SHIFTS — the report still lands "
         "(§C.2, I-119)")
    # The Builder's next cycle: A is repaired, so A is retired, and what was under it is
    # re-keyed. This is the 30-60 s window run 155 lost 8 of 18 outcomes to.
    stage_mirror(target, sysd, skip="plant_a.py::alpha::4", shift_below=2)
    rid = EXPECTED["lease_A"]["row_key"]
    ok(wt._find_row(rid)[0] is None, f"{rid} is GONE from the live mirror (retired)")
    out = wt.cr_report_outcome(rid, "confirmed", "suite green", edit_kind="diff")
    ok(out["written"] is True, f"written={out['written']}")
    ok(out["resolved_by"] == EXPECTED["resolved_by_after_retire"],
       f"resolved_by={out['resolved_by']!r} (expected {EXPECTED['resolved_by_after_retire']!r})")
    line = out["line"]
    for key, want in EXPECTED["line_A"].items():
        ok(line.get(key) == want, f"line.{key} = {line.get(key)!r} (expected {want!r})")
    rec = out["ledger_record"]
    ok(out["ledger_written"] is True, f"ledger_written={out['ledger_written']}")
    ok(rec.get("digest") == "aaa1111111" and rec.get("replace_span") == "plant_a.py:L4-L6"
       and rec.get("rule_ids") == ["NAI-021S", "NAI-071"]
       and rec.get("file") == "plant_a.py" and rec.get("function") == "alpha"
       and rec.get("line") == 4,
       "the LEDGER record carries A's PRE-EDIT identity, not the shifted mirror's")
    # RUN 158 LAUNCH A's other defect: once the row is retired the SERVER can no longer hand
    # back the bytes that were there — `cr_row(A).before_code` is gone with the row. Under Q3
    # the client's own working tree is the archive, so the client keeps them; what the lease
    # gives it is the means to PROVE the back-out restored exactly what was leased.
    from .write_tools import _sha256
    leases_A = [r for r in jsonl(Path(_lease_file())) if r.get("row_key") == rid]
    replaced = "".join(PLANT_A.splitlines(keepends=True)[3:6])
    ok(bool(leases_A) and leases_A[-1]["before_sha256"] == _sha256(replaced),
       "the lease's `before_sha256` still identifies the bytes the edit replaced — a revert "
       "can be verified after the row is gone")


def part_iii_failed_and_rekeyed(channel: str) -> None:
    from no_aivalidator import BUILDER_DAEMON as bd
    from . import write_tools as wt
    part("(iii) A `failed` VERDICT SURVIVES THE RETIRE, AND A RE-KEYED ROW STILL JOINS "
         "(§C.2 / §C.3, I-125 / I-130)")
    rid = EXPECTED["lease_A"]["row_key"]
    out = wt.cr_report_outcome(rid, "failed", "AssertionError: alpha() aliased its default")
    ok(out["written"] is True and out["resolved_by"] == "lease",
       f"written={out['written']} resolved_by={out['resolved_by']!r} — the negative is kept")
    ok(out["ledger_written"] is False and out["ledger_record"] == {},
       "a `failed` verdict still writes NO ledger record (S4-3 stands)")
    lines = [x for x in (bd._parse_channel_line(y)
                         for y in Path(channel).read_bytes().decode().splitlines() if y.strip())
             if x is not None]
    ok(len(lines) == 2, f"the engine's `_parse_channel_line` accepts both lines ({len(lines)})")
    rows = state_rows(shift=3, rekey="plant_a.py::alpha::4")
    ok(EXPECTED["rekeyed_key"] in rows, f"A has come back re-keyed at {EXPECTED['rekeyed_key']}")
    failed, confirmed, orphans = bd._join_channel(lines, rows)
    ok(orphans == EXPECTED["rekeyed_orphans"],
       f"_join_channel orphans={orphans} (expected {EXPECTED['rekeyed_orphans']})")
    ok(EXPECTED["rekeyed_key"] in failed,
       f"the re-keyed row carries the failure: {sorted(failed)}")
    # the safety property the widening must NOT cost (I-138, and T3's write-path proof)
    bad = dict(lines[0])
    bad["replace_span"] = bad["replace_span"] + "9"
    bad["row_key"] = "plant_a.py::alpha::4"
    _, _, orph = bd._join_channel([bad], state_rows())
    ok(orph == 1,
       "the right digest with the wrong span on an UNMOVED key is still a silent ORPHAN")
    # RUN 158 LAUNCH A's defect: a LEASED row the Builder has RETIRED is not an orphan. Both
    # lines above report a row the Builder has since removed — the repair worked — and counting
    # them as orphans is what made `cr_hand_back` say `orphans_channel 3` on a run where every
    # outcome landed (I-138: "the server and the client do not agree on what an orphan is").
    from system_scripts import gearbox
    leased = bd._leased_keys(channel)
    ok(EXPECTED["lease_A"]["row_key"] in leased,
       f"the Builder reads the lease beside its channel: {sorted(leased)}")
    gone = {k: v for k, v in state_rows().items() if k != "plant_a.py::alpha::4"}
    _f, _c, orph_gone = bd._join_channel(lines, gone, leased)
    ok(orph_gone == 0,
       f"a line whose LEASED row the Builder retired is reported, not orphaned "
       f"(orphans={orph_gone})")
    _f, _c, orph_unleased = bd._join_channel(lines, gone)
    ok(orph_unleased == 2,
       "…and with NO lease beside it — every channel written before session 7 — the same two "
       f"lines count exactly as they always did (orphans={orph_unleased})")
    _f, _c, orph_live = bd._join_channel([bad], state_rows(), leased)
    ok(orph_live == 1,
       "…while a line naming a row that is STILL THERE and still does not join stays an orphan")
    # and the report writer's own count, which must not disagree with the Builder's
    _keys, unjoined = gearbox._channel_keys(Path(channel), gone)
    ok(unjoined == [],
       f"`gearbox._channel_keys` makes the same distinction off the same lease ({unjoined})")
    _keys, unjoined_unleased = gearbox._channel_keys(Path(channel), gone, leased=set())
    ok(len(unjoined_unleased) == 2,
       f"…and without the lease it counts the two as it always did ({unjoined_unleased})")


def part_iv_tolerant_id(sysd: Path) -> None:
    from . import write_tools as wt
    from .read_tools import _resolve_key
    part("(iv) THE TOLERANT ID — unescape, the unique (file, function), and the refusal "
         "(§C.5, I-137 / I-130)")
    row, _bucket, rid, how, err = wt._resolve_row(EXPECTED["stale_line_id"])
    ok(row is not None and rid == EXPECTED["stale_resolves_to_live"] and how == "function",
       f"a STALE-LINE id {EXPECTED['stale_line_id']} → {rid!r} by {how!r} "
       f"(expected {EXPECTED['stale_resolves_to_live']!r})")
    row, _bucket, rid, how, err = wt._resolve_row(EXPECTED["escaped_id"])
    ok(row is not None and rid == EXPECTED["escaped_resolves_to"] and how == "row",
       f"an HTML-ESCAPED id {EXPECTED['escaped_id']} → {rid!r} by {how!r} ({err})")
    out = wt.cr_apply(EXPECTED["escaped_id"])
    ok(out["kind"] == "shape" and out["error"] is None,
       f"cr_apply on the escaped module-scope id answers kind={out['kind']!r}, not `not found`")
    row, bucket, rid, how, err = wt._resolve_row(EXPECTED["ambiguous_id"])
    named = all(c in err for c in EXPECTED["ambiguous_candidates"])
    ok(row is None and bucket == "ambiguous" and named,
       f"a REPEATED (file, function) is refused with both candidates named — {err}")
    out = wt.cr_apply(EXPECTED["ambiguous_id"])
    ok(out["error"] is not None and all(c in out["error"]
                                        for c in EXPECTED["ambiguous_candidates"]),
       "cr_apply repeats the refusal with the candidates — never guessed")
    # RUN 158 LAUNCH C's defect: `cr_apply` on a STALE id files the lease under the id the
    # server RESOLVED, and the client goes on holding the id it was GIVEN. Filed under
    # `pick::17`, looked up under `pick::18`, the seat could not find its own lease and the
    # whole repair failed at the last step. The lease lookup is tolerant of a re-key too.
    stale = EXPECTED["stale_line_id"]
    a = wt.cr_apply(stale)
    ok(a["error"] is None and a["resolved_by"] == "function" and a["lease_written"] is True,
       f"cr_apply on a stale id leases under the RESOLVED key ({a['resolved_by']!r})")
    filed = [r["row_key"] for r in jsonl(Path(_lease_file())) if r["file"] == "plant_a.py"]
    ok(EXPECTED["stale_resolves_to_live"] in filed,
       f"the lease is filed under {EXPECTED['stale_resolves_to_live']}, not {stale}")
    back = wt._lease_lookup(CHANNEL[0], stale)
    ok(back is not None and back["row_key"] == EXPECTED["stale_resolves_to_live"],
       f"…and `_lease_lookup` under the id the CLIENT holds still finds it "
       f"({(back or {}).get('row_key')!r})")
    ok(wt._lease_lookup(CHANNEL[0], EXPECTED["ambiguous_id"]) is None,
       "…while a repeated (file, function) answers None rather than guessing a lease")
    # the same rule, spelled for BUILDER_STATE's rows by `read_tools` (id resolution only)
    keys = state_rows()
    key, how, problem = _resolve_key(keys, EXPECTED["escaped_id"])
    ok(key == EXPECTED["escaped_resolves_to"] and how == "row",
       f"cr_row's resolver unescapes too: {key!r} by {how!r} ({problem})")
    key, how, problem = _resolve_key(keys, EXPECTED["stale_line_id"])
    ok(key == EXPECTED["stale_resolves_to"] and how == "function",
       f"cr_row's resolver takes the unique (file, function): {key!r} by {how!r}")
    key, how, problem = _resolve_key(keys, EXPECTED["ambiguous_id"])
    ok(not key and all(c in problem for c in EXPECTED["ambiguous_candidates"]),
       f"cr_row's resolver refuses the repeated one with candidates — {problem}")


def part_v_rebased_apply(target: Path) -> None:
    from . import write_tools as wt
    part("(v) THE RE-BASED DIFF — an earlier edit to the same file (§C.4, I-130)")
    # Run BEFORE (ii) on purpose: this is the seat's real sequence. The mirror is the LAST
    # scan's, so `beta` and `gamma` are still recorded where they were, while on disk A's
    # repair has already pushed them down two lines. Before the re-base, `cr_apply` rendered
    # its hunk at the recorded span and the client had to apply from `before_code` instead
    # (run 155: "the hunk headers are not re-based").
    for who, rec_key, live_key in (("beta", "beta_span_recorded", "beta_span_live"),
                                   ("gamma", "gamma_span_recorded", "gamma_span_live")):
        row = next(r for r in _ROWS if r["function"] == who)
        rid = str(row["key"])
        out = wt.cr_apply(rid)
        ok(out["replace_span"] == EXPECTED[rec_key],
           f"{who}: replace_span (the Builder's key) = {out['replace_span']!r}")
        ok(out["replace_span_live"] == EXPECTED[live_key],
           f"{who}: replace_span_live = {out['replace_span_live']!r} "
           f"(expected {EXPECTED[live_key]!r})")
        ok(out["replace_span_live"] != out["replace_span"],
           f"{who}: the live span is NOT the recorded span — the diff would have drifted")
        ok(out["applies_cleanly"] is True and out["error"] is None,
           f"{who}: the diff applies cleanly against the LIVE bytes")


def part_vi_rule_outcomes(channel: str) -> None:
    from system_scripts import gearbox
    part("(vi) THE VARIANT IS ON THE LINE — `rule_outcomes` with no `?` (§C.3, I-122)")
    for label, rows in (("the re-keyed rows", state_rows(shift=3, rekey="plant_a.py::alpha::4")),
                        ("NO rows at all", {})):
        block = gearbox.rule_outcomes(rows, Path(channel))
        ok(block == EXPECTED["rule_outcomes"],
           f"over {label}: {json.dumps(block, sort_keys=True)}")
        marks = [r for r, rec in block.items()
                 if r == "?" or "?" in (rec.get("failed_against") or {})]
        ok(not marks, f"over {label}: no `?` anywhere ({marks})")


def part_vii_run_158() -> None:
    """THE LIVE PART (§C.6 vii) — run 158's own record, read back, never quoted from memory."""
    part("(vii) RUN 158, LIVE — the record's own numbers (§C.6 vii)")
    found = sorted(RUNS.glob("*/run158.json"))
    ok(bool(found), f"run 158's record is on disk: {[str(p.parent.name) for p in found]}")
    if not found:
        return
    doc = read_json(found[-1])
    if not isinstance(doc, dict):
        ok(False, f"run158.json is not a record: {type(doc).__name__}")
        return
    reports = doc.get("report_outcomes") or []
    ok(bool(reports), f"{len(reports)} `cr_report_outcome` calls in the record")
    unwritten = [r.get("row") for r in reports if not r.get("written")]
    ok(not unwritten, f"every `cr_report_outcome` is `written true` (not written: {unwritten})")
    by = sorted({str(r.get("resolved_by") or "") for r in reports})
    ok("" not in by, f"every report says how it resolved: {by}")
    hb = doc.get("hand_back") or {}
    ok(hb.get("orphans_channel") == 0,
       f"cr_hand_back orphans_channel = {hb.get('orphans_channel')!r}")
    ok(hb.get("orphans") == 0, f"cr_hand_back orphans = {hb.get('orphans')!r}")
    block = doc.get("rule_outcomes_after") or {}
    ok(bool(block), f"{len(block)} rules in the run's own `rule_outcomes`")
    marked = sorted(r for r, rec in block.items()
                    if r == "?" or "?" in (rec.get("failed_against") or {}))
    ok(not marked, f"`failed_against` without `?` — marked rules: {marked}")
    stop = doc.get("stop") or {}
    ok(stop.get("residue_clean") is True and stop.get("unexpected_changes") == [],
       f"cr_stop residue_clean={stop.get('residue_clean')!r} "
       f"unexpected_changes={stop.get('unexpected_changes')!r}")


# ─────────────────────────────────────────────────────────────────────────────
# (viii) SESSION 10 — I-148 (a)(b)(c) · I-145 · I-152, over a fixture tree of their own
# ─────────────────────────────────────────────────────────────────────────────

#: A decorated context manager at L5-L8 (run 162's `_pipepager` shape: the span starts at the
#: DECORATOR, not at the `def`) and a plain function at L11-L13.
PLANT_D = '''"""fixture: session 10 — I-148 (a)(b)(c) · I-145 · I-152."""
import contextlib


@contextlib.contextmanager
def piped(cmd):
    handle = None
    yield handle


def widget(items=[]):
    seen = items
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    h = 8
    return seen
'''

#: `widget`'s eleven lines, and the two-line change the fixture's repair makes to them. Long
#: enough that `context_lines=3` and `context_lines=7` render DIFFERENT diffs — which is what
#: makes I-148 (c)'s repeated call a real test and not two identical calls.
_WIDGET_BEFORE = ("def widget(items=[]):\n    seen = items\n" +
                  "".join(f"    {n} = {i + 1}\n" for i, n in enumerate("abcdefgh")) +
                  "    return seen\n")
_WIDGET_AFTER = ("def widget(items=None):\n    seen = list(items or [])\n" +
                 "".join(f"    {n} = {i + 1}\n" for i, n in enumerate("abcdefgh")) +
                 "    return seen\n")

#: HAND-WRITTEN BEFORE THE COMPUTE, read straight off PLANT_D above and off run 163's registry.
EXPECTED_S10: dict[str, Any] = {
    # (a) run 162's `open_url` shape — a recorded span matching neither the original nor the file
    "piped_recorded": "plant_d.py:L7-L11",
    "piped_live": "plant_d.py:L5-L8",
    "piped_span_current": False,
    # a row whose recorded span DOES match the live file
    "widget_recorded": "plant_d.py:L11-L21",
    "widget_live": "plant_d.py:L11-L21",
    "widget_span_current": True,
    # (b) the first line of `piped`'s live span
    "decorator": "@contextlib.contextmanager",
    # (c) the I-145 pair, run 162's `::549` given / `::550` resolved in this fixture's numbers
    "given_id": "plant_d.py::widget::9",
    "resolved_id": "plant_d.py::widget::11",
    # (d) run 163's own two shapes — the line between "render it from the row" and "decide it"
    "shape_renderable": 'def <name>(<params>):\n    """<existing docstring>"""\n'
                        '    raise NotImplementedError("<name>: not implemented")',
    "shape_not_renderable": "def <name>(<params>):\n"
                            "    <compute from the parameters per the intent>\n"
                            "    return <result>",
    "not_selectable_by": "gate.prescription_check",
    "not_selectable_id": "plant_d.py::__exit__::237",
}


def _s10_mirror(target: Path) -> dict[str, Any]:
    """The mirror for part (viii): two rewriter rows and one NOT-SELECTABLE row.

    The not-selectable row is staged exactly as the Builder's selector publishes it under I-152 —
    in `no_vetted_fix[]` (it has no digest), carrying `selected_role ""`, `apply "no"`,
    `withheld_by gate.prescription_check` and the seam's sentence — and it is deliberately NOT in
    `withheld[]`, which is the half of the ruling that keeps a real smell in the bucket count.
    """
    sentence = ("gate: not selectable — the shape carries 2 placeholder(s) the site cannot bind "
                "(`<compute from the parameters per the intent>`, `<result>`); an unattended seat "
                "has nothing to render (I-152)")
    return {
        "status": "3 FINDINGS", "last_scan": "2026-09-22T00:00:00+00:00",
        "target_repo": str(target),
        "summary": {"failed": 3, "repairs": 2, "no_vetted_fix": 1, "withheld": 0},
        "repairs": [
            {"file": "plant_d.py", "function": "piped", "line": 5, "line_end": 8,
             # THE STALE SPAN — run 162's `open_url`: matches neither the original nor the file.
             "replace_span": EXPECTED_S10["piped_recorded"],
             "finding_lines": [5], "rule_ids": ["NAI-021S"],
             "infraction": "fixture row plant_d.py::piped::5",
             "fix": "hoist the import above `def piped`",
             "before_code": "@contextlib.contextmanager\ndef piped(cmd):\n    handle = None\n    yield handle\n",
             "after_code": "@contextlib.contextmanager\ndef piped(cmd):\n    handle = None\n    try:\n        yield handle\n    finally:\n        handle = None\n",
             "selected_role": "import_hoist_fix", "solution_kind": "rewriter",
             "apply": "yes", "withheld_by": None,
             "digest": "ddd1111111", "return_channel": CHANNEL[0]},
            {"file": "plant_d.py", "function": "widget", "line": 11, "line_end": 21,
             "replace_span": EXPECTED_S10["widget_recorded"],
             "finding_lines": [11], "rule_ids": ["NAI-061"],
             "infraction": "fixture row plant_d.py::widget::11",
             "fix": "`items=[]` → `items=None`",
             "before_code": _WIDGET_BEFORE,
             "after_code": _WIDGET_AFTER,
             "selected_role": "mutable_default_fix", "solution_kind": "rewriter",
             "apply": "yes", "withheld_by": None,
             "digest": "eee2222222", "return_channel": CHANNEL[0]},
        ],
        "no_vetted_fix": [
            {"file": "plant_d.py", "function": "__exit__", "line": 237, "line_end": 238,
             "replace_span": "plant_d.py:L237-L238", "finding_lines": [237],
             "rule_ids": ["NAI-004", "NAI-120"],
             "infraction": "fixture row plant_d.py::__exit__::237 (run 163's site)",
             "status": "ranker_none",
             "selected_role": "", "apply": "no",
             "withheld_by": EXPECTED_S10["not_selectable_by"],
             "gate_withheld": {"solution_NAI-004": sentence}},
        ],
        "withheld": [],
    }


def part_viii_session_ten() -> None:
    from . import read_tools as rt
    from . import write_tools as wt
    from no_aivalidator import BUILDER_DAEMON as bd
    from .tool_interface import (APPLY_LEASE_RECORD, CONFIRMED_LEDGER_RECORD, NOT_SELECTABLE_BY,
                                 TOOLS, validate_payload)

    part("(viii) SESSION 10 — I-148 (a)(b)(c) · I-145 (given_id) · I-152 (not selectable)")
    tmp = Path(tempfile.mkdtemp(prefix="identity_proof_s10_"))
    keep_root = os.environ.get("CODERADAR_MCP_ROOT", "")
    keep_channel = CHANNEL[0]
    try:
        sysd = tmp / "system_scripts"
        sysd.mkdir(parents=True)
        target = tmp / "target"
        target.mkdir()
        (target / "plant_d.py").write_text(PLANT_D, encoding="utf-8")
        CHANNEL[0] = str(sysd / "return_channel_fixture173.jsonl")
        (sysd / ".noai_state.json").write_text(json.dumps(_s10_mirror(target)), encoding="utf-8")
        (sysd / "BUILDER_STATE.json").write_text(json.dumps({
            "repo_id": "fixture173", "target_repo": str(target), "return_channel": CHANNEL[0],
            "phase": "MONITORING", "cycle": 1,
            "detail": "cycle 1: 3 rows, 2 with fix; tester confirmed 0 of 2 solutions",
            "rows": {}}), encoding="utf-8")
        os.environ["CODERADAR_MCP_ROOT"] = str(tmp)
        rt.configure(target=str(target), state_dir=sysd)

        # ── (a) I-148 (a) / Q3 — the stale span is MARKED on the ROW and on the ANSWER ────────
        rows = {r["id"]: r for r in rt.cr_infractions()["rows"]}
        piped = rows.get("plant_d.py::piped::5", {})
        widget = rows.get("plant_d.py::widget::11", {})
        ok(piped.get("replace_span") == EXPECTED_S10["piped_recorded"],
           f"the row keeps the Builder's recorded span (half the join key): "
           f"{piped.get('replace_span')!r}")
        ok(piped.get("replace_span_live") == EXPECTED_S10["piped_live"],
           f"…and publishes `replace_span_live` read off the LIVE file: "
           f"{piped.get('replace_span_live')!r} (expected {EXPECTED_S10['piped_live']!r})")
        ok(piped.get("span_current") is EXPECTED_S10["piped_span_current"],
           f"…marked `span_current={piped.get('span_current')!r}` — run 162's `open_url` shape, "
           f"a recorded span matching neither the original nor the file")
        ok(widget.get("span_current") is EXPECTED_S10["widget_span_current"]
           and widget.get("replace_span_live") == EXPECTED_S10["widget_live"],
           f"a row whose recorded span DOES match the file reads "
           f"`span_current={widget.get('span_current')!r}` — the mark is a measurement, not a flag")
        answer = wt.cr_apply("plant_d.py::piped::5")
        ok(answer["replace_span_live"] == EXPECTED_S10["piped_live"]
           and answer["span_current"] is False,
           f"`cr_apply` answers the same two fields: {answer['replace_span_live']!r} · "
           f"span_current={answer['span_current']!r}")
        ok(answer["applies_cleanly"] is True and answer["error"] is None,
           "…and the diff still applies cleanly, because it was rendered at the LIVE span")
        ok(validate_payload(TOOLS["cr_apply"], answer, "output") == [],
           "the whole answer validates against T1's output schema")

        # ── (b) I-148 (b) — the prose NAMES THE DECORATOR ─────────────────────────────────────
        ok(EXPECTED_S10["decorator"] in answer["reason"],
           f"the `reason` names the decorator the span starts at: …{answer['reason'][-110:]!r}")
        ok(EXPECTED_S10["decorator"] not in wt.cr_apply("plant_d.py::widget::11")["reason"],
           "…and a row whose span starts at a `def` gains no such sentence")

        # ── (c) I-148 (c) / Q4 — `resolved_by` cannot be moved by a rendering argument ────────
        first = wt.cr_apply(EXPECTED_S10["given_id"], context_lines=3)
        second = wt.cr_apply(EXPECTED_S10["given_id"], context_lines=7)
        ok(first["resolved_by"] == second["resolved_by"] == "function",
           f"the SAME id twice with different `context_lines` answers the same word: "
           f"{first['resolved_by']!r} / {second['resolved_by']!r} (run 162 saw row → function)")
        ok(len(first["diff"]) != len(second["diff"]),
           "…while `context_lines` did move the render, so the two calls really did differ")

        # ── (c) I-145 / Q2 — `given_id` beside `resolved_id`, everywhere ──────────────────────
        ok(first["given_id"] == EXPECTED_S10["given_id"]
           and first["resolved_id"] == EXPECTED_S10["resolved_id"],
           f"`cr_apply` answers given_id={first['given_id']!r} resolved_id={first['resolved_id']!r}")
        leases = jsonl(Path(first["lease"]))
        mine = [r for r in leases if r.get("given_id") == EXPECTED_S10["given_id"]]
        ok(bool(mine) and mine[-1]["row_key"] == EXPECTED_S10["resolved_id"],
           f"the LEASE carries both — filed under {EXPECTED_S10['resolved_id']}, given "
           f"{EXPECTED_S10['given_id']} (run 162: filed ::550, given ::549)")
        ok([f.name for f in APPLY_LEASE_RECORD] == list(mine[-1]),
           "the record is still `APPLY_LEASE_RECORD`, in that order, with `given_id` in it")
        out = wt.cr_report_outcome(EXPECTED_S10["given_id"], "confirmed", "fixture",
                                   tester="s10-proof", edit_kind="diff")
        ok(out["written"] is True and out["given_id"] == EXPECTED_S10["given_id"],
           f"`cr_report_outcome` answers given_id={out['given_id']!r} "
           f"resolved_id={out['resolved_id']!r} resolved_by={out['resolved_by']!r}")
        ok(out["line"].get("given_id") == EXPECTED_S10["given_id"],
           "the CHANNEL LINE carries it — a seat reconciling its own log by the id it holds matches")
        ok(out["ledger_record"].get("given_id") == EXPECTED_S10["given_id"],
           "and so does the LEDGER RECORD")
        ok([f.name for f in CONFIRMED_LEDGER_RECORD] == list(out["ledger_record"]),
           "the ledger record is still `CONFIRMED_LEDGER_RECORD`, in that order")
        ok(bd._parse_channel_line(json.dumps(out["line"])) is not None,
           "…and the engine's own `_parse_channel_line` still accepts the line — `given_id` is a "
           "key it ignores, exactly as the session-7 identity fields were")
        # the ORDER: the resolved key is consulted before the given key. Two hand-written records
        # put the two steps in conflict — only the order decides which answers.
        wt._append_lease(CHANNEL[0], {**mine[-1], "row_key": "plant_d.py::zeta::1",
                                      "given_id": "plant_d.py::zeta::2", "digest": "111aaa1111"})
        wt._append_lease(CHANNEL[0], {**mine[-1], "row_key": "plant_d.py::zeta::2",
                                      "given_id": "plant_d.py::zeta::3", "digest": "222bbb2222"})
        back = wt._lease_lookup(CHANNEL[0], "plant_d.py::zeta::2")
        ok(back is not None and back.get("digest") == "222bbb2222",
           "`_lease_lookup` answers on the RESOLVED key first and the exact `given_id` second — "
           f"the id that is both answers as a row_key ({(back or {}).get('digest')!r})")
        ok((wt._lease_lookup(CHANNEL[0], "plant_d.py::zeta::3") or {}).get("digest") == "222bbb2222",
           "…and an id that is only a `given_id` still answers, by EQUALITY, not by a looser match")

        # ── (d) I-152 / Q1 — not selectable ───────────────────────────────────────────────────
        ok(bd.NOT_SELECTABLE_BY == NOT_SELECTABLE_BY == EXPECTED_S10["not_selectable_by"],
           f"the engine and the interface spell the seam the same way: {bd.NOT_SELECTABLE_BY!r}")
        ok(bd._unresolved_placeholders(EXPECTED_S10["shape_renderable"]) == [],
           "run 163's `solution_NAI-120` shape binds every placeholder off the SITE — `<name>`, "
           "`<params>`, `<existing docstring>` — so it IS renderable unattended and is still offered")
        ok(bd._unresolved_placeholders(EXPECTED_S10["shape_not_renderable"])
           == ["compute from the parameters per the intent", "result"],
           "run 163's `solution_NAI-004` shape carries two the site cannot bind — the fall-through "
           "that made `__exit__::237` look applyable")
        held = rows.get(EXPECTED_S10["not_selectable_id"], {})
        ok(held.get("apply") == "no" and held.get("selected_role") == "",
           f"the row publishes apply={held.get('apply')!r} selected_role={held.get('selected_role')!r}")
        ok(held.get("withheld_by") == NOT_SELECTABLE_BY,
           f"…withheld_by names the PRESCRIPTION seam, not G0: {held.get('withheld_by')!r}")
        ok("not selectable" in " ".join(held.get("gate_withheld_reasons", {}).values()),
           "…and the sentence rides in `gate_withheld_reasons`, per candidate")
        ok(EXPECTED_S10["not_selectable_id"] in rows and rt.cr_infractions()["total"] == 3,
           "the row is STILL AN INFRACTION in the default view — 3 of 3 — so the bucket count "
           "keeps a real smell (the owner's reason for not flipping it to withheld)")
        ok([r["id"] for r in rt.cr_infractions(withheld=True)["rows"]] == [],
           "…and it is NOT in the withheld block")
        offered = wt.cr_apply(EXPECTED_S10["not_selectable_id"])
        ok(offered["kind"] == "none" and "not selectable" in offered["reason"],
           f"`cr_apply` offers NOTHING and says why: kind={offered['kind']!r} "
           f"reason={offered['reason'][:70]!r}…")
        ok(all(r.get("apply") == "yes" for r in (piped, widget)),
           "while the two rows that CAN be rendered read `apply: \"yes\"` — the seat's own filter")
    finally:
        CHANNEL[0] = keep_channel
        if keep_root:
            os.environ["CODERADAR_MCP_ROOT"] = keep_root
        else:
            os.environ.pop("CODERADAR_MCP_ROOT", None)
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    print(__doc__.split("\n\n")[0])
    print("=" * 78)
    tmp = Path(tempfile.mkdtemp(prefix="identity_proof_"))
    try:
        target, sysd, channel = build_fixture(tmp)
        print(f"fixture tree: {tmp}")
        # The parts are RUN in the order the drift happens to a live seat — apply, edit,
        # apply again against the moved file, then the Builder's rescan, then the reports —
        # and are NUMBERED as §C.6 numbers them. (v) therefore runs before (ii): its whole
        # point is the window in which the file has moved and the mirror has not.
        part_i_the_lease(target, channel)
        client_writes_As_edit(target)
        part_v_rebased_apply(target)
        part_ii_retired(target, sysd, channel)
        part_iii_failed_and_rekeyed(channel)
        part_iv_tolerant_id(sysd)
        part_vi_rule_outcomes(channel)
        # Session 10's four rulings, over a fixture tree of their own so that nothing above
        # moves: the parts up to here are numbered by §C.6 and their expected values are read
        # off THIS fixture.
        part_viii_session_ten()
    finally:
        os.environ.pop("CODERADAR_MCP_ROOT", None)
        shutil.rmtree(tmp, ignore_errors=True)
    part_vii_run_158()
    print("\n" + "=" * 78)
    if FAILURES:
        print(f"identity proof: FAIL ({len(FAILURES)})")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("identity proof: PASS — the lease, the resolution order, the re-based diff, the "
          "tolerant id, the variant on the line, run 158, and session 10's span_current · "
          "decorator prose · given_id · not selectable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
