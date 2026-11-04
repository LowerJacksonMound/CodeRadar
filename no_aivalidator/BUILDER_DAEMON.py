#!/usr/bin/env python3
"""
BUILDER_DAEMON — the FOURTH gearbox child (NEW IMPLEMENTATION item 1, 2026-09-08).

    circuit_daemon  →  NOAI_VALIDATOR_DAEMON  →  BUILDER_DAEMON  →  proof_dashboard
    (watching)         (judging: findings)       (one before/after   (showing)
                                                  per finding)

The validator STOPS at findings (system_scripts/NOAI_VALIDATION_STATE.json). This
daemon reads that file, generates candidates per finding from the rule-id → rewriter
map, hands every candidate WITH its observations to the Ranker
(SolutionRanker.decide — THE decision point; nothing overturns its pick afterwards),
publishes ONE before/after per finding to system_scripts/BUILDER_STATE.json, and owns
the .noai_state.json mirror write + fan-out into the target. Never two writers: the
validator no longer touches the mirror.

The pipeline is the validator's inline `stage_cheatsheet` re-homed (the inline stage
stays in NOAI_VALIDATOR_DAEMON.py, uncalled, until item 2's parity comparator has run —
owner reading A, 2026-09-08; archived after item 2's parity proof), minus the three
post-Ranker decision points (FIX 11): the syntax re-check, the reviewer gate, and the
schema's second vetting. Their
facts — parse result, differs-or-not, the CodeAnalyzer safety scan — are observation
tokens the Builder fills on every candidate BEFORE the Ranker is called. The reason a
finding has (or has not) a fix lives in ONE place: rows[].decision.why.

Loop: asyncio; wait for the validator's MONITORING phase; poll every 2.5 s; a changed
mtime → read → sha256 of the bytes; unchanged bytes → nothing. Row key
file::function::line; row_hash over the finding's own fields; a row is rebuilt only
when its finding or its evidence changed; rows gone from the state are dropped.
Whole-set facts (graph context, ContextLinesCalculator scan, ProjectProfile) are
computed once per cycle / per target — never per row; per-row candidate builds run
under asyncio.gather (the AST rewrite inside a row is sync: one piece of evidence).
Target change → reset, phase WAITING. SIGTERM → stop, no final write.

Return channel (item 5, 2026-09-09): the tester appends one JSON line per outcome to
system_scripts/return_channel_<repoid>.jsonl (outside the target — never in the snapshot).
Each poll the daemon stats the file and reads only the new complete lines (offset kept in
memory); a line joins a row on digest AND replace_span. A `failed` line for the row's current
digest joins that ONE infraction's evidence (tester=failed:<digest> + the failure log), the
candidates are regenerated, the failed one is observed unpickable, the Ranker re-decides and
the row is rewritten. A `confirmed` line marks the row's solution confirmed. Nothing published
labels a kind of failure (owner 2026-09-09): the dash, the mirror and the state carry the
infractions, their solutions, and which solutions the tester confirmed — the measure is the
confirmed fraction. Lines naming no row are counted (summary.tester.orphans), malformed
lines too (summary.tester.unparsed) — never dropped silently.

Usage:
    python -m no_aivalidator.BUILDER_DAEMON            # daemon mode (gearbox child #4)
"""

from __future__ import annotations

import ast
import asyncio
import bisect
import fcntl
import hashlib
import json
import logging
import os
import re
import signal
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# The Builder's own log line prefix. basicConfig is a no-op once a handler exists, so
# this must run BEFORE the validator module (which calls basicConfig too) is imported.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [cheatsheets] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("builder_daemon")

# Shared helpers are IMPORTED from the validator module (one definition each — owner
# assumption 4, 2026-09-08): span text, rule-id extraction, infraction lines, whitelist
# loading, and the locked JSON I/O the dashboard reads with.
from .NOAI_VALIDATOR_DAEMON import (  # noqa: E402
    CIRCUIT_STATE_FILE,
    NOAI_STATE_FILE,
    read_file_locked,
    write_file_locked,
    _extract_rule_ids,
    _finding_lines,
    _load_whitelist,
    _repo_id,
    _span,
    _whitelisted_function,
)
from .cheatsheets.cheatsheet_intelligence.knowledge_base import (  # noqa: E402
    Decision,
    ProjectProfile,
    SolutionCandidate,
    SolutionRanker,
    candidate_pickable,
)
from .cheatsheets.cheatsheet_reviewer import CodeAnalyzer  # noqa: E402  (the Reviewer)
from .noai_validator.utils import read_source  # noqa: E402  (A1: the one source reader — BOM / coding cookie honoured)

# ── Paths / constants ────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SYS_SCRIPTS = PROJECT_ROOT / "system_scripts"
BUILDER_STATE_FILE = SYS_SCRIPTS / "BUILDER_STATE.json"
MIRROR_NAME = ".noai_state.json"
POLL_INTERVAL = 2.5   # FIX_46: the cadence table's row cheatsheets/build (1 cycle)
SYS_SCRIPTS_FOR_CADENCE = SYS_SCRIPTS
CADENCE_DAEMON = "cheatsheets"

# ── FIX_46 (owner Q6, 2026-09-15): this daemon's angle on the ONE cadence table ──────────────
# gearbox.py holds every period and phase in the app. This daemon sleeps its own slot offset ONCE
# at start-up so its near-non-stop poll lands on its own angle of the circumference instead of on
# top of the other three daemons' polls.
def _cadence_offset_s() -> float:
    try:
        import sys as _sys
        _sys.path.insert(0, str(SYS_SCRIPTS_FOR_CADENCE))
        import gearbox as _cadence
        return float(_cadence.blade_offset_s(CADENCE_DAEMON))
    except Exception:
        return 0.0

def _heartbeat(cycle: int, force: bool = False) -> None:
    """I-108 (MCP-working packet 2026-09-28): the Builder's liveness beat — the sidecar beside
    BUILDER_STATE.json, written through gearbox.write_heartbeat when the FIX_46 `cheatsheets /
    heartbeat` row is due (or at once when *force*). FIX_52's hang check reads it; the state
    itself stays on-change. Never raises."""
    try:
        import sys as _sys
        _sys.path.insert(0, str(SYS_SCRIPTS_FOR_CADENCE))
        import gearbox as _cadence
        if force or _cadence.due(CADENCE_DAEMON, "heartbeat", cycle):
            _cadence.write_heartbeat(BUILDER_STATE_FILE, CADENCE_DAEMON, cycle)
    except Exception:
        pass


# S4 item 4 (owner 2026-09-29): no restarts — a hang now ENDS the run, so a long rebuild must never look
# like one. The gearbox calls the Builder hung when the heartbeat is older than HUNG_STATE_S; while a
# cycle runs, this task beats at a third of that. The slow work (generation) runs in worker threads, so
# the event loop — and this task — stays free. It beats only while a cycle is in flight: a Builder that
# is truly stuck between cycles still goes quiet and is caught.
BUILD_BEAT_S = 30.0


async def _beat_during(work, cycle: int):
    """Await *work*, writing a heartbeat every BUILD_BEAT_S until it finishes."""
    async def _beats():
        while True:
            await asyncio.sleep(BUILD_BEAT_S)
            _heartbeat(cycle, force=True)
    beater = asyncio.create_task(_beats())
    try:
        return await work
    finally:
        beater.cancel()


# The five ways a infraction can have no fix (mirror no_vetted_fix[].status; BUILDER_STATE
# summary.no_fix). The REASON is never here — it is rows[].decision.why. Since item 4
# (2026-09-08) no_fix_by_design and unbuilt come from the registry row's kind (unbuilt also
# when the infraction has no function body to rewrite); no_generator = no registry row at all.
NO_FIX_STATUSES = ("no_generator", "declined", "no_fix_by_design", "ranker_none", "unbuilt")


# ── Rule-id → generator dispatch (item 4, 2026-09-08: the registry) ─────────
#
# Every deciding rule id has exactly ONE row in no_aivalidator/repair_generators
# (kind rewriter | no_fix_by_design | unbuilt, with its reason). The Builder asks
# for_rule(rule_id) per deciding id; health-check step 19 proves the registry is complete
# and runs every rewriter against its planted counterfeit. A rewriter returns
# (after_code, what_changed) — what_changed derived from the code it rewrote — or
# ("", "") to decline, which the Builder records as `declined`. The 21-entry template
# table the validator carried unreachably is archived verbatim at
# .archive/archived_20260908/no_aivalidator/NOAI_VALIDATOR_DAEMON_unreachable_fixer_table.py.txt.

from .repair_generators import for_rule, candidates_of, gate_note, rewriters as _registry_rewriters  # noqa: E402


def _rule_fixer_map() -> dict[str, list]:
    """rule_id → [(role, fixer_fn)] — the REWRITER view of the registry (health-check step 11
    reads it; the Builder itself dispatches through for_rule)."""
    return {g.rule_id: [(g.role, g.fn)] for g in _registry_rewriters()}


# ── Whole-set facts ──────────────────────────────────────────────────────────

# Owner 2026-10-08 (M-124 / M-126 / M-127): the facts the Ranker decides with, as STRUCTURED dicts (owner: "pass the
# unflattened dictionaries directly to the Ranker" — no string escaping on `@`, `:` or quotes). Pure plumbing: every
# item, unweighted and unfiltered; how much a fact counts is the owner's method (a weights table read by `decide`).
#   intent          — the target's intent file: the developer's statement (own words) + every fact with its source
#                     (developer, intent sources such as readme / docs / ci_workflow / packaging, tester)
#   function_intent — the function's own docstring and `intent_claims.claims`, failed or not
#   context         — every context observation the validator measured on the row: tag, line, measured facts
def _intent_facts(target_repo: str) -> dict[str, Any]:
    if not target_repo:
        return {"statement": None, "facts": []}
    try:
        ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
        if ss not in sys.path:
            sys.path.insert(0, ss)
        import intent_file as _intent  # type: ignore
        data = _intent.read(target_repo)
    except Exception as e:
        return {"status": "NOT MEASURED", "reason": f"{type(e).__name__}: {e}", "statement": None, "facts": []}
    st = data.get("statement")
    return {"statement": (st.get("text") if isinstance(st, dict) else st) or None,
            "facts": [dict(f) for f in data.get("facts") or [] if isinstance(f, dict)]}


def _function_intent(broken_code: str) -> dict[str, Any]:
    if not broken_code:
        return {"docstring": None, "claims": []}
    try:
        import ast as _ast
        import textwrap as _tw
        from .noai_validator.intent_claims import claims as _claims
        node = next((n for n in _ast.walk(_ast.parse(_tw.dedent(broken_code)))
                     if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))), None)
        if node is None:
            return {"docstring": None, "claims": []}
        return {"docstring": _ast.get_docstring(node), "claims": [dict(c) for c in _claims(node)]}
    except Exception as e:
        return {"status": "NOT MEASURED", "reason": f"{type(e).__name__}: {e}", "docstring": None, "claims": []}


_CTX_SKIP = {"tag", "line", "severity", "msg", "context", "withheld", "func_name"}


def _attempt_report(agent_cands: list[SolutionCandidate], gate_log: list[dict[str, Any]],
                    pick: SolutionCandidate | None) -> list[dict[str, Any]]:
    """Solution gate item 6: per agent attempt, `{attempt, attempt_id, note, status, stage, detail, probe, next}` —
    status one of `integrated` (passed every stage, applied; plus `not_measured` when stage 2 could run none of the
    declared entry points), `deferred` (the file moved; judged next cycle),
    `failed` (stage + what broke), `refused` (parse / differs / filter, before ranking), `not_judged` (another attempt
    was picked first). `next` is the one sentence the agent should act on."""
    out: list[dict[str, Any]] = []
    for c in agent_cands:
        _, n, attempt_id = c.role.rsplit("_", 2)   # agent_attempt_<n>_<id>
        rec: dict[str, Any] = {"attempt": int(n) if n.isdigit() else n, "attempt_id": attempt_id,
                               "note": c.solution, "status": "not_judged", "stage": "", "detail": "", "probe": {},
                               "next": ""}
        stages = [g for g in gate_log if g.get("role") == c.role]
        failed_obs = next((o for o in c.observations if o.startswith(("stage=fail", "filter=fail", "parse=fail",
                                                                     "differs=no"))), "")
        if any(o.startswith("gate=integrated") for o in c.observations):
            last = next((s for s in reversed(stages) if s.get("stage") in ("tests", "integrates")), {})
            rec.update(status="integrated", stage=last.get("stage", "integrates"), detail=last.get("detail", ""),
                       probe=last.get("probe") or {}, next="nothing — it was applied on an earlier cycle; the rescan closes the row")
            out.append(rec)
            continue
        if failed_obs.startswith("stage=fail"):
            _, stage, detail = failed_obs.split(":", 2)
            g = next((s for s in stages if s.get("stage") == stage), {})
            rec.update(status="failed", stage=stage, detail=detail, probe=g.get("probe") or {},
                       next=f"rewrite it so stage `{stage}` holds: {detail}")
        elif failed_obs:
            kind, _, detail = failed_obs.partition("=")
            rec.update(status="refused", stage=kind, detail=detail.partition(":")[2] or detail,
                       next=f"rewrite it: {detail.partition(':')[2] or detail}")
        elif stages and stages[-1].get("verdict") == "deferred":
            rec.update(status="deferred", stage=stages[-1].get("stage", ""), detail=stages[-1].get("detail", ""),
                       next="nothing — it is judged again on the next cycle")
        elif stages and c is pick:
            last = stages[-1]
            rec.update(status="integrated", stage=last.get("stage", ""), detail=last.get("detail", ""),
                       probe=last.get("probe") or {}, next="nothing — it is applied; the rescan closes the row")
            # Stage 2 passed on imports alone (no declared entry point could run): said on the attempt itself.
            nm = next((s["not_measured"] for s in stages if s.get("stage") == "integrates" and s.get("not_measured")),
                      None)
            if nm:
                rec.update(not_measured=nm, next="it is applied, but its entry point was NOT MEASURED — run it by "
                                                  "hand: " + "; ".join(nm))
        out.append(rec)
    return out


_GATE_LOCK: "asyncio.Lock | None" = None


def _gate_lock() -> "asyncio.Lock":
    """Solution gate: one target write at a time across every row of every build (created on first use, so it binds
    to the running loop)."""
    global _GATE_LOCK
    if _GATE_LOCK is None:
        _GATE_LOCK = asyncio.Lock()
    return _GATE_LOCK


def _VR_evidence_kind(rid: str) -> str:
    """The evidence kind on a rule family's table row ("ruling", "proof", "none (pre-calibration)"); a family with no
    row reads as pre-calibration. Read once per process from the one disposition table."""
    global _VR_EVIDENCE
    if _VR_EVIDENCE is None:
        try:
            from .cheatsheets.cheatsheet_intelligence.knowledge_base import RULE_DISPOSITIONS
            fams = json.loads(Path(RULE_DISPOSITIONS).read_text(encoding="utf-8")).get("families") or {}
            _VR_EVIDENCE = {k: ((v.get("evidence") or {}).get("kind") if isinstance(v.get("evidence"), dict) else "ruling")
                            for k, v in fams.items() if isinstance(v, dict)}
        except Exception:
            _VR_EVIDENCE = {}
    return _VR_EVIDENCE.get(rid) or "none (pre-calibration)"


_VR_EVIDENCE: dict[str, str] | None = None


def _VR_disposition(rid: str) -> str:
    """`deciding` / `context` for a rule id, from the one disposition table (the VerdictRanker's)."""
    try:
        from .cheatsheets.cheatsheet_intelligence.knowledge_base import resolve_disposition
        return resolve_disposition(rid)
    except Exception:
        return "deciding"


def _context_facts(finding: dict[str, Any]) -> list[dict[str, Any]]:
    deciding = {finding.get("rule_id")} | set(finding.get("rule_ids") or [])
    ctx_ids = set(finding.get("context_ids") or [])
    out: list[dict[str, Any]] = []
    for p in finding.get("triggered_patterns") or []:
        if isinstance(p, dict):
            tag = str(p.get("tag") or "")
            if not tag or not (p.get("context") is True or tag in ctx_ids or tag not in deciding):
                continue
            item = {"tag": tag, "line": p.get("line"), "facts": {k: v for k, v in p.items() if k not in _CTX_SKIP}}
            if p.get("msg"):
                item["msg"] = p["msg"]
        elif isinstance(p, (list, tuple)) and p and str(p[0]) in ctx_ids:
            item = {"tag": str(p[0]), "line": None, "facts": {}, "msg": " ".join(str(x) for x in p[1:])}
        else:
            continue
        if item not in out:
            out.append(item)
    named = {i["tag"] for i in out}
    out += [{"tag": t, "line": None, "facts": {}} for t in sorted(ctx_ids - named)]   # a context id with no observation
    return out


def _node_key(rel: str) -> str:
    """The circuit node name for a finding's repo-relative file: `ast_scanner` names a .py node
    `str(rel_to_repo.with_suffix(''))` (`colorama/ansitowin32`, not `ansitowin32`), so the
    lookup key is the relative PATH without `.py`, posix separators (Q-H3-1, 2026-10-01)."""
    return Path(rel).with_suffix("").as_posix()


def _graph_fact(value: int | None) -> str:
    """The evidence token for a circuit fact: None = the circuit has no node for the file —
    written as NOT MEASURED, never 0 (owner: NOT MEASURED is never 0/ok)."""
    return "NOT MEASURED (no circuit node for this file)" if value is None else str(value)


def _build_graph_context(circuit: dict[str, Any]) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Compute (node_depths, reverse_graph) from circuit_state nodes.

    Node 'name' is the repo-relative path without `.py` (ast_scanner `_analyze_script`:
    `name = str(rel_to_repo.with_suffix(''))`; the stem is only its ValueError fallback), and
    'imports' entries are node names in the same form — so findings are keyed by `_node_key(rel)`.
    (This docstring used to say the name IS the stem; it is not, and keying by stem found no
    node for any file below the target root: every row read depth 0 / dependents 0 — Q-H3-1.)
    The state carries NO 'depth' key at all (the old node.get('depth', 0) read a key that is
    never written), so depth is computed here from the import graph: depth(n) = longest
    importer chain above n (entry scripts = 0). Deeper + more dependents = fix first.
    """
    reverse: dict[str, list[str]] = {}
    names: list[str] = []
    for node in circuit.get("nodes", []):
        name = node.get("name", "")
        if not name:
            continue
        names.append(name)
        for imp in node.get("imports", []) or []:
            reverse.setdefault(imp, []).append(name)

    depths: dict[str, int] = {}

    def _depth(n: str, visiting: set[str]) -> int:
        if n in depths:
            return depths[n]
        if n in visiting:
            return 0  # cycle guard
        visiting.add(n)
        importers = reverse.get(n, [])
        d = 0 if not importers else 1 + max(_depth(i, visiting) for i in importers)
        visiting.discard(n)
        depths[n] = d
        return d

    for n in names:
        _depth(n, set())
    return depths, reverse


# ── Q5 / I-107 (owner, 2026-09-20): the entry script's role, as the circuit already stamped it ──
#
# NAI-094 `Module-level sys.path.insert()` is WITHHELD (BY DESIGN) on a file whose role is `entry`
# in rule_dispositions.json `path_hacks` — FIX_50's context row, the one that already exempts that
# file's own path manipulation from the circuit's counted total (owner Q10). I-107 was ONE
# infraction signalled twice; this is the second signal, and it reads the SAME table row the first
# one reads, so the two halves cannot drift apart: remove FIX_50's row and the withholding goes.
#
# The fact is not re-measured here. The circuit daemon stamps every published path manipulation with
# its disposition (`_stamp_hack_dispositions`, which resolves `role` from entry_point_info.json),
# and circuit_state.json is already in hand once per cycle — no new read, no new plumbing. A type
# that is informational for EVERY file (file_traversal, missing_init: `context` by default) is no
# evidence of a role, so the type must be `deciding` by default and `context` here, which only
# FIX_50's `role == entry` row can make it. A target never run through the wrapper has no entry
# point, so nothing is stamped `context` and nothing is withheld — FIX_50's NOT MEASURED rule,
# inherited whole.
NAI_094 = "NAI-094"
BY_DESIGN_WITHHELD = "by_design"   # beside FIX_51's "species" and S5-1's "gate" in the mirror block


def _entry_role_files(circuit: dict[str, Any]) -> set[str]:
    """The files the circuit exempts as `role == entry` — FIX_50's context row, fired, read back.

    (The shape is one loop and no early return on purpose — a guard clause and an `except: return`
    are both pre-ranker hunter sites; `_rule_outcomes` is shaped the same way for the same reason.)
    """
    files: set[str] = set()
    try:
        import sys as _sys
        _sys.path.insert(0, str(SYS_SCRIPTS))
        from engine_utils import path_hack_disposition
        for rel, hacks in (circuit.get("path_hacks") or {}).items():
            for hack in hacks or []:
                htype = str((hack or {}).get("type") or "")
                stamped = str((hack or {}).get("disposition") or "")
                if stamped == "context" and path_hack_disposition(htype, None)[0] == "deciding":
                    files.add(str(rel))
    except Exception as exc:
        logger.warning("entry role not read off the circuit this cycle: %s", exc)
    return files


def _q5_withheld_sentence(rel: str) -> str:
    """The ONE sentence the withheld row publishes — as `decision.why`, as `withheld_reason` and as
    the reason in the mirror's withheld block, so the three readers cannot disagree."""
    return (f"WITHHELD (BY DESIGN): {NAI_094} on {rel} — the ENTRY SCRIPT the wrapper runs, whose "
            f"path hack rule_dispositions.json `path_hacks` already exempts as `role == entry` "
            f"(FIX_50, owner Q10). A path hack in the entry script is the normal shape of an entry "
            f"script, so its solution is withheld by design; the infraction itself still stands and "
            f"is still counted (owner Q5, 2026-09-20 — I-107).")


def _row_key(file: str, function: str, line: int) -> str:
    return f"{file}::{function}::{line}"


def _row_hash(finding: dict[str, Any]) -> str:
    """Identity of the finding itself (the validator's own fields) — 16 hex."""
    payload = [finding.get("file"), finding.get("function"), finding.get("line"),
               finding.get("end_line"), finding.get("rule_ids"), finding.get("failure_reason"),
               finding.get("finding_lines"), finding.get("triggered_patterns")]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _digest(before: str, after: str) -> str:
    """sha256(before + after)[:10] — the id the tester's return channel refers to (item 5)."""
    return hashlib.sha256((before + after).encode()).hexdigest()[:10]


def _candidate_digest(c: SolutionCandidate) -> str:
    """A rewriter's digest is over before + after_code; a prescribed solution's (FIX_41) over before + the
    text — the shape is a template, the text is what the repair agent applies."""
    return _digest(c.before_code, c.solution if c.source == "prescribed" else c.after_code)


def _prescribed_role(rule_id: str) -> str:
    """The candidate role of a prescribed solution: one per rule id, so two prescribed ids on one row are
    two candidates the Ranker chooses between (owner vocabulary on the dash: a solution, never a kind)."""
    return f"solution_{rule_id}"


def _prescription_verdict(rule_id: str, g: Any, broken_code: str, *, file: str = "",
                          span: str = "", module_src: str = "") -> Any:
    """S9-T1 / I-150 follow-up (owner ruling 2026-09-21): G0 over a PRESCRIPTION, at the one place a
    prescribed candidate is minted. A prescribed row's `after_code` is a SHAPE and does not parse, so
    `gate.check` has never been able to judge one — `gate.prescription_check` judges the half that
    does, the site's own bytes. A role with no prescription predicate passes, so nothing that was
    published before is withheld now. Never raises."""
    from .repair_generators.gate import Rewrite, prescription_check
    try:
        return prescription_check(Rewrite(
            rule_id=rule_id, role=_prescribed_role(rule_id), variant="", file=file, span=span,
            before_src=broken_code, after_src=g.shape or "", module_src=module_src))
    except Exception:
        from .repair_generators.gate import GateVerdict
        return GateVerdict(ok=True, reason=None, rule="")


# ── I-152 (owner ruled 2026-09-21; built session 10, lane T1) ───────────────────────────────────
#
# THE DEFECT. G0 is asked per CANDIDATE, so a row goes on publishing as a live infraction as long
# as ANY candidate is left — even one no unattended seat can render. Run 163: with
# `solution_NAI-120` withheld on `src/click/utils.py::__exit__::237`, `selected_role` fell through
# to `solution_NAI-004`, a shape carrying placeholders only a decision can fill, and the row still
# published with `withheld_by` unset. A mounted seat reads that row as an offer, calls `cr_apply`,
# and gets a template it cannot apply. The owner's bar: **the placeholder fallback itself is the
# defect, not the withhold** — S5's "no offer an unattended seat can be damaged by" extends to "no
# offer an unattended seat cannot act on".
#
# THE REPAIR, here at the selector: a candidate whose shape cannot be rendered unattended is
# marked the way G0 marks a withheld rewrite, so the RANKER never picks it. When every candidate
# on the row is one of those, the row's apply state is `not selectable` — the seam is named and
# the ROW IS NOT FLIPPED TO WITHHELD, because withholding it would drop a real smell from
# `failed == repairs + no_vetted_fix`. The detector stays honest; only the offer goes.

#: The seam, named in the row rather than `gate` — G0 judges a rewrite; this is the prescription
#: half. `coderadar_mcp/tool_interface.NOT_SELECTABLE_BY` reads the same string; the engine never
#: imports that package, so the two are spelled separately and the proof asserts they agree.
NOT_SELECTABLE_BY: str = "gate.prescription_check"
NOT_SELECTABLE_REASON: str = (
    "not selectable: no candidate on this row renders unattended — its shape carries "
    "placeholders only a decision can fill")

#: S10b (owner 2026-09-29): a rewriter's named variants that are SHAPES, not repairs — "no rewrite; emit this
#: shape" (I-78, NAI-021S). The Builder publishes one as a prescribed solution; it is never gated, tested or applied.
SHAPE_ONLY_VARIANTS: frozenset[str] = frozenset({"no_rewrite_shape"})

#: `<…>` tokens a prescribed shape binds OFF THE SITE ITSELF: the def's own name, its own
#: parameters, its own docstring. Read off run 163's two shapes, which the owner's own report
#: separates by exactly this line — `solution_NAI-120` rendered at the site with "zero unresolved
#: placeholders once `<name>` is bound" (and IS therefore applicable unattended), while
#: `solution_NAI-034` "carries three unresolved placeholders (`<existing docstring>`,
#: `<implementation per the docstring>`, `<value>`) and is not renderable unattended".
_SITE_BOUND_PLACEHOLDERS: frozenset[str] = frozenset((
    "name", "params", "param", "signature", "existing docstring", "docstring",
))

_PLACEHOLDER_RE = re.compile(r"<[^<>\n]+>")


def _unresolved_placeholders(shape: str) -> list[str]:
    """The `<…>` tokens of a shape that the site's own bytes cannot bind, in order, deduplicated.
    An empty list means an unattended seat can render this shape from the row alone."""
    out: list[str] = []
    for tok in _PLACEHOLDER_RE.findall(shape or ""):
        name = tok[1:-1].strip()
        if name.lower() in _SITE_BOUND_PLACEHOLDERS or name in out:
            continue
        out.append(name)
    return out


def _not_renderable_reason(c: Any) -> str:
    """'' when this candidate can be rendered by an unattended seat, else the sentence the row
    publishes. Only a PRESCRIBED candidate can fail here: a rewriter's `after_code` is real
    Python that the seat applies as a diff, and it is never a template."""
    if getattr(c, "source", "") != "prescribed":
        return ""
    unresolved = _unresolved_placeholders(str(getattr(c, "after_code", "") or ""))
    if not unresolved:
        return ""
    named = ", ".join(f"`<{p}>`" for p in unresolved)
    return (f"gate: not selectable — the shape carries {len(unresolved)} placeholder(s) the site "
            f"cannot bind ({named}); an unattended seat has nothing to render (I-152)")


def _prescribed_candidate(rule_id: str, g: Any, broken_code: str,
                          failure_reason: str = "") -> SolutionCandidate:
    """FIX_41: the registry's prescribed solution as the row's candidate. after_code is the SHAPE (a template,
    not Python) so the Reviewer's parse / safety observations do not apply — the tokens say so instead of
    `parse=fail`, which would make it unpickable; the Ranker still decides (source trust, intent, RCA).

    R4 (owner 2026-09-21, run 164): a prescribed row whose DETECTOR covers more than one family
    carries a `shape_for` resolver, and the (text, shape) published here are the ones it reads off
    THIS fire — the row's own `reason` / `shape` otherwise, exactly as before. NAI-094 is the case:
    an `os.environ` write must never be handed the `sys.path` family's sentence."""
    text, shape = g.reason, (g.shape or "")
    resolver = getattr(g, "shape_for", None)
    if resolver is not None:
        text, shape = resolver(broken_code, failure_reason)
    return SolutionCandidate(
        solution=text,
        role=_prescribed_role(rule_id),
        before_code=broken_code,
        after_code=shape,
        source="prescribed",
        observations=["kind=prescribed", "parse=shape", "differs=yes", f"rule={rule_id}"],
    )


def _findings_from_state(state: dict[str, Any], whitelist_functions: set[str]) -> list[dict[str, Any]]:
    """Every failed row the validator published, as a flat finding dict (stage_flag's
    selection: passed == False, whatever the species). Whitelisted rows are carried
    with exonerated=True so the Builder can publish the exoneration."""
    out: list[dict[str, Any]] = []
    for rel_path, entries in (state.get("results_by_file") or {}).items():
        for entry in entries or []:
            if entry.get("passed", True):
                continue
            rule_ids = list(entry.get("rule_ids") or [])
            exonerated = bool(entry.get("whitelisted")) or _whitelisted_function(
                whitelist_functions, rel_path, entry.get("function", ""))
            out.append({
                "file": rel_path,
                "function": entry.get("function", ""),
                "line": int(entry.get("line") or 0),
                "end_line": int(entry.get("end_line") or 0),
                "finding_lines": list(entry.get("finding_lines") or _finding_lines(entry.get("triggered_patterns") or [])),
                "rule_ids": rule_ids,
                "rule_id": rule_ids[0] if rule_ids else "",
                "context_ids": list(entry.get("context_ids") or []),
                "species": entry.get("species", "") or "",
                "withheld": entry.get("withheld", "") or "",
                "failure_layer": entry.get("failure_layer", "") or "",
                "failure_reason": entry.get("failure_reason", "") or "",
                "triggered_patterns": list(entry.get("triggered_patterns") or []),
                "exonerated": exonerated,
            })
    return out


class _FileFacts:
    """One parse per flagged file per cycle: the source, its lines, and the span of
    every function definition (name → [(def_line, start, end)]). The span STARTS at the
    first decorator when the def carries any (item 4, 2026-09-08): the replace_span and
    before/after_code cover the whole statement, so a rewriter that hoists an import above
    the def (NAI-008) can never land it between a decorator and its def. The finding's
    `line` (the validator's node.lineno = the def line) stays the row key."""

    def __init__(self, src: str) -> None:
        self.src = src
        self.lines = src.splitlines()
        self.spans: dict[str, list[tuple[int, int, int]]] = {}
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                self.spans.setdefault(node.name, []).append((node.lineno, start, node.end_lineno or node.lineno))

    def function_source(self, name: str, at_line: int) -> tuple[str, int, int]:
        """(source, start, end) of the def named `name` — the one whose def line is the
        finding's line when several share the name, else the first (the inline stage's
        behaviour). ('', line, line) when the name is not defined in the file."""
        spans = self.spans.get(name) or []
        if not spans:
            return "", at_line, at_line
        chosen = next((s for s in spans if s[0] == at_line), spans[0])
        _def_line, start, end = chosen
        return "\n".join(self.lines[start - 1:end]), start, end

    def flagged_spans(self, names: set[str]) -> list[tuple[int, int]]:
        return [(s[1], s[2]) for n in names for s in self.spans.get(n, [])]


class _SpanIndex:
    """C1 (Q-H3b-7, 2026-10-01): "is `line` inside any flagged span of this file" as a bisect over
    the merged, sorted spans — built once per file per cycle. The answer is the one
    `any(s <= line <= e for s, e in flagged_spans)` gave; that generator ran once per semantic
    item per row, so a file with N flagged defs and N def_use items paid N × N × N (62.7 M steps
    for N = 500, the rows stage's 39 s at N = 1,500 and its kill at N = 6,000)."""

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        merged: list[list[int]] = []
        for s, e in sorted(spans):
            if merged and s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self._starts = [m[0] for m in merged]
        self._ends = [m[1] for m in merged]

    def covers(self, line: int) -> bool:
        i = bisect.bisect_right(self._starts, line) - 1
        return i >= 0 and line <= self._ends[i]


_SEMANTIC_SPAN_FAMILIES = ("def_use", "module", "api_compliance", "cfg")


def _semantic_items_for(semantic: dict[str, list], rel: str) -> dict[str, list[Any]]:
    """The semantic facts whose `file` names `rel` (the substring test the row loop always made),
    per family in published order — parameter_usage as the items, the span families as
    (line, item) with the line parsed once. One pass per flagged file per cycle (C1, Q-H3b-7)."""
    out: dict[str, list[Any]] = {}
    out["parameter_usage"] = [pu for pu in semantic.get("parameter_usage", []) or []
                              if isinstance(pu, dict) and rel in str(pu.get("file", ""))]
    for family in _SEMANTIC_SPAN_FAMILIES:
        items: list[Any] = []
        for item in semantic.get(family, []) or []:
            if not isinstance(item, dict):
                continue
            if rel not in str(item.get("file", "")):
                continue
            try:
                line = int(item.get("line", 0) or 0)
            except (TypeError, ValueError):
                line = 0
            items.append((line, item))
        out[family] = items
    return out


# owner 2026-09-30 (Lane A): the intent file's content hash — `intent_file.content_hash` (clocks dropped; a missing
# file is its fixed sentinel `intent_file.ABSENT_HASH`). A failed hash reads as NOT MEASURED — a value of its own that
# never equals a real hash, so the move into (and out of) that state rebuilds the ranker rather than silently keeping it.
_INTENT_ABSENT = "absent"


def _intent_content_hash(target_repo: str) -> str:
    try:
        import sys as _sys
        if str(SYS_SCRIPTS) not in _sys.path:
            _sys.path.insert(0, str(SYS_SCRIPTS))
        import intent_file as _intent  # type: ignore
        return _intent.content_hash(target_repo)
    except Exception as e:
        logger.warning(f"[INTENT] content hash NOT MEASURED: {type(e).__name__}: {e}")
        return f"not-measured:{type(e).__name__}"


# ── The Builder ──────────────────────────────────────────────────────────────

class CheatsheetBuilder:
    """The re-homed pipeline (name kept by owner ruling): findings in, ONE decided
    before/after per finding out. Owns nothing on disk — BuilderDaemon does the writes."""

    def __init__(self) -> None:
        self.fixer_map = _rule_fixer_map()  # the rewriter view; dispatch is for_rule (item 4)
        self._ranker: SolutionRanker | None = None
        self._ranker_target: str | None = None
        # owner 2026-09-30 (Lane A): the intent file's content hash the cached ranker was built under, and the
        # target it belongs to (kept apart from `_ranker_target`, which `_tester_facts` clears to force a re-read).
        self._intent_hash: str | None = None
        self._intent_hash_target: str | None = None
        # True for the build_rows call whose ranker was rebuilt under a NEW intent hash: that call re-ranks every row.
        self.intent_rerank: bool = False

    # -- whole-set facts ---------------------------------------------------

    def intent_moved(self, target_repo: str) -> bool:
        """owner 2026-09-30 (Lane A): the intent file's hash differs from the one the cached ranker was built under.
        False before the first build for this target (that cycle is the validator's to trigger)."""
        if not target_repo or self._intent_hash_target != target_repo:
            return False
        return _intent_content_hash(target_repo) != self._intent_hash

    async def ranker_for(self, target_repo: str) -> SolutionRanker:
        """ProjectProfile once per target AND intent hash (owner 2026-09-30, Lane A: the intent may be added or
        changed at any time — one small read per cycle hashes the file; a moved hash rebuilds the profile, an
        unchanged hash never does). Never per row."""
        ihash = _intent_content_hash(target_repo) if target_repo else _INTENT_ABSENT
        same_target = self._intent_hash_target == target_repo
        if self._ranker is not None and self._ranker_target == target_repo and same_target and ihash == self._intent_hash:
            self.intent_rerank = False
            return self._ranker
        # a moved hash on the SAME target → this call's rows are re-ranked (build_rows drops the reuse shortcut)
        self.intent_rerank = bool(same_target and self._intent_hash is not None and ihash != self._intent_hash)
        if self.intent_rerank:
            logger.info(f"[INTENT] intent file changed ({self._intent_hash} → {ihash}) — "
                        f"profile re-read, every row re-ranked this cycle")
        self._intent_hash, self._intent_hash_target = ihash, target_repo
        if target_repo:
            try:
                self._ranker = await SolutionRanker.from_repo_path(target_repo)
            except Exception as e:
                logger.debug(f"ProjectProfile analysis failed: {e}")
                self._ranker = SolutionRanker(project_profile=ProjectProfile())
        else:
            self._ranker = SolutionRanker(project_profile=ProjectProfile())
        self._ranker_target = target_repo
        return self._ranker

    @staticmethod
    async def _context_info(repo: Path, files: list[str]) -> dict[str, dict[str, Any]]:
        """ContextLinesCalculator: ONE scan per cycle, one recommendation per flagged
        file (the inline stage asked once per finding)."""
        info: dict[str, dict[str, Any]] = {}
        try:
            from rca_main.context_calculator import ContextLinesCalculator
            calc = ContextLinesCalculator(repo)
            await calc.scan()
            for rel in files:
                rec = await calc.recommend_for_file(repo / rel)
                # K2 (owner 2026-09-07): the three structural scores are context; the
                # calculator's `confidence` is not published (no confidence anywhere).
                info[rel] = {
                    "import_score": rec.import_score,
                    "caller_score": rec.caller_score,
                    "complexity_score": rec.complexity_score,
                }
        except Exception as e:
            logger.debug(f"ContextCalculator unavailable: {e}")
        return info

    @staticmethod
    async def _file_facts(repo: Path, files: list[str]) -> dict[str, _FileFacts | None]:
        """Read + parse every flagged file once (I/O off the loop)."""
        def _load(rel: str) -> _FileFacts | None:
            try:
                # A1 / C1 (2026-10-01): read_source, as the validator reads it — a BOM or a PEP 263
                # coding cookie decodes here exactly as it did there; what it cannot decode stays
                # None (the row publishes unbuilt), never a replacement-character parse.
                return _FileFacts(read_source(repo / rel))
            except Exception:
                return None
        loaded = await asyncio.gather(*(asyncio.to_thread(_load, rel) for rel in files))
        return dict(zip(files, loaded))

    # -- evidence ------------------------------------------------------------

    @staticmethod
    def _rca_evidence(finding: dict[str, Any], *, ctx: dict[str, Any], depth: int | None, dependents: int | None,
                      func_start: int, func_end: int, cross_file: dict[str, Any], stale: bool,
                      rca_reports: list[dict[str, Any]], semantic_items: dict[str, list[Any]] | None,
                      span_index: _SpanIndex, file_scope_emitted: set[tuple]) -> list[str]:
        """Every fact about the finding as flat tokens — the Ranker gets every fact
        (owner). Verbatim from the inline stage; the three pre-ranker flags and the
        prose 'confidence' label were excised there already (K2). `depth` / `dependents`
        None = the circuit has no node for this file (Q-H3-1): written as NOT MEASURED, never 0.

        C1 (Q-H3b-7 / Q-H3a-2, 2026-10-01): the whole-set lists are indexed ONCE per cycle by
        `build_rows` and this row reads its own slice — `rca_reports` = the validator's reports for
        this (file, function), in their published order; `semantic_items` = the semantic facts whose
        file names this row's file (None when the state carries no semantic block), each family in
        its published order with the line already parsed; `span_index` = this file's flagged spans.
        Before this every row re-scanned every report and every semantic item of the whole repo."""
        rel = finding["file"]
        fn = finding["function"]
        evidence = [
            f"rule_id={finding['rule_id']}",
            f"caller_score={ctx.get('caller_score', 0):.2f}",
            f"import_score={ctx.get('import_score', 0):.2f}",
            f"complexity_score={ctx.get('complexity_score', 0):.2f}",
            f"depth={_graph_fact(depth)}",
            f"dependents={_graph_fact(dependents)}",
        ]
        # Last plan 1R (2026-10-10): RCA's config reader — a magic number that equals a config file's value
        # names that file and key, so the repair can read the value from config instead of hard-coding it.
        for p in finding.get("triggered_patterns") or []:
            cm = p.get("config_match") if isinstance(p, dict) else None
            if cm:
                evidence.append(f"rca=config:{cm.get('file', '')}:{cm.get('key', '')}={p.get('magic_value')}")

        # ── Cross-file analysis (Phase 0 wiring). The validator publishes which files
        # were rescanned since the analysis was computed (cross_file_analysis.
        # stale_for_files); evidence for those files is prefixed STALE:.
        if cross_file:
            stale_prefix = "STALE:" if stale else ""
            for rca in cross_file.get("rca_cross_file_issues", []) or []:
                if rca.get("caller") == fn or rca.get("callee") == fn:
                    evidence.append(
                        f"{stale_prefix}rca_cross_file:caller={rca.get('caller','')}"
                        f",callee={rca.get('callee','')}"
                        f",severity={rca.get('severity', 'MEDIUM')}"
                    )
            for bt in cross_file.get("origin_trace_results", []) or []:
                if bt.get("function") == fn:
                    evidence.append(
                        f"{stale_prefix}origin_trace:wall_type={bt.get('wall_type','')}"
                        f",stack_depth={bt.get('stack_depth', 0)}"
                        f",root_cause={bt.get('root_cause', 'unknown')}"
                    )
            for op in cross_file.get("onion_peel_results", []) or []:
                if op.get("function") == fn:
                    evidence.append(
                        f"{stale_prefix}onion_peel:layers={op.get('layers_peeled', 0)}"
                        f",chain_id={op.get('chain_id', '')}"
                    )
            for ci in cross_file.get("circular_imports", []) or []:
                if rel in str(ci.get("cycle", [])):
                    evidence.append(
                        f"{stale_prefix}circular_import:cycle={ci.get('cycle', [])}"
                        f",severity={ci.get('severity', 'HIGH')}"
                    )
            for dup in cross_file.get("cross_file_duplicates", []) or []:
                if any(rel in str(loc) for loc in dup.get("locations", [])):
                    evidence.append(
                        f"{stale_prefix}cross_file_duplicate:fingerprint={dup.get('fingerprint', '')}"
                        f",count={len(dup.get('locations', []))}"
                    )
            # FIX_32 / FIX_33 (2026-09-10): the RootCause candidates of THIS row, one token per
            # candidate per direction — rca=upstream:<file> (imported by the failing file),
            # rca=downstream:<file> (a caller of it — corroboration, never redundancy),
            # rca=context:<why>:<file> (related by context: config_sibling / import / test),
            # rca=symbol:<file> (defines a symbol named in the error). The validator publishes the
            # evidence lines in cross_file_analysis.rca_reports; before this the callers were
            # computed and dropped, so a leaf file with callers carried nothing here.
            for rep in rca_reports:
                for cand, lines in (rep.get("evidence") or {}).items():
                    cand_name = os.path.basename(str(cand))
                    for ln in lines or []:
                        if ln.startswith("Imported by failing file"):
                            evidence.append(f"{stale_prefix}rca=upstream:{cand_name}")
                        elif ln.startswith("Downstream caller of failing file"):
                            evidence.append(f"{stale_prefix}rca=downstream:{cand_name}")
                        elif ln.startswith("Related by context ("):
                            why = ln[len("Related by context ("):].rstrip(")")
                            evidence.append(f"{stale_prefix}rca=context:{why}:{cand_name}")
                        elif ln.startswith("Defines symbol"):
                            evidence.append(f"{stale_prefix}rca=symbol:{cand_name}")

        # ── Semantic analysis (Phase-4 H1: dicts, all five keys). Corroboration ≠
        # redundancy (owner doctrine): every token carries its source family; a fact
        # detection already attested for the same infraction is ONE token listing both
        # attestations (attests_with=...), never a second free-standing piece of evidence.
        if semantic_items is not None:
            detection_facts: dict[str, list[str]] = {}
            for p in finding.get("triggered_patterns") or []:
                if not isinstance(p, dict):
                    continue
                ptag = p.get("tag", "")
                for lk in ("dead_variables", "dead_vars"):
                    for v in p.get(lk) or []:
                        detection_facts.setdefault(str(v), []).append(ptag)
                for sk in ("variable", "unused_param", "overwritten_var", "target_var"):
                    v = p.get(sk)
                    if v:
                        detection_facts.setdefault(str(v), []).append(ptag)

            def _emit_semantic(family: str, item: dict, scope: str = "function") -> None:
                token = (f"semantic_{family}:code={item.get('code', '')}"
                         f",line={item.get('line', 0)}")
                fact = str(item.get("name") or item.get("param") or "")
                if fact:
                    token += f",name={fact}"
                msg = str(item.get("message", ""))[:80]
                if msg:
                    token += f",msg={msg}"
                if scope != "function":
                    token += f",scope={scope}"
                if fact and fact in detection_facts:
                    attested = sorted({t for t in detection_facts[fact] if t})
                    if attested:
                        token += f",attests_with={'+'.join(attested)}"
                evidence.append(token)

            # parameter_usage carries a function field — attribute by name
            for pu in semantic_items.get("parameter_usage", []):
                if pu.get("function") == fn:
                    _emit_semantic("parameter_usage", pu)

            # def_use / module / api_compliance / cfg — attribute by line span;
            # facts outside any span attach once per file (scope=file)
            for family in _SEMANTIC_SPAN_FAMILIES:
                for line, item in semantic_items.get(family, []):
                    if func_start <= line <= func_end:
                        _emit_semantic(family, item)
                    elif span_index.covers(line):
                        # Belongs to another flagged function in this file — that
                        # infraction carries it (no duplication here).
                        continue
                    else:
                        fs_key = (rel, family, line, item.get("code", ""))
                        if fs_key not in file_scope_emitted:
                            file_scope_emitted.add(fs_key)
                            _emit_semantic(family, item, scope="file")
        return evidence

    # -- candidates + observations (sync: one piece of evidence per rewrite) ----

    @staticmethod
    def _observe(candidate: SolutionCandidate, broken_code: str) -> None:
        """Fill the observation tokens the Ranker reads (FIX 11): parse, differs, safety."""
        after = candidate.after_code
        obs: list[str] = []
        if not after or not after.strip():
            obs.append("parse=fail:empty rewrite")
        else:
            try:
                ast.parse(textwrap.dedent(after))
                obs.append("parse=ok")
            except SyntaxError as e:
                obs.append(f"parse=fail:{str(e)[:80]}")
        differs = bool(after) and textwrap.dedent(after).strip() != textwrap.dedent(broken_code).strip()
        obs.append("differs=yes" if differs else "differs=no")
        if after and after.strip():
            try:
                _ok, security, quality = CodeAnalyzer.analyze(after)
            except Exception as e:  # the Reviewer failing is itself an observation
                security, quality = [f"analyzer raised {type(e).__name__}: {str(e)[:60]}"], []
            if security:
                obs.extend(f"safety={s}" for s in security)
            else:
                obs.append("safety=clean")
            obs.extend(f"quality={q}" for q in quality)
        candidate.observations = obs + list(candidate.observations)

    @staticmethod
    def _consult(finding: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, Any]], list[tuple[str, Any]]]:
        """The registry consultation alone (repair_generators.for_rule per deciding rule id), no
        rewrite attempted: (generators_consulted, builder_facts, [(rule_id, rewriter row)],
        [(rule_id, prescribed row)]) — the fourth list since FIX_41 (2026-09-15).
        Split out of _generate on run 55 (set 4b-02): a body-less row — a module-scope
        infraction such as NAI-209/211 or NAI-094 — has nothing for a rewriter to take, but
        its rules' declarations (no_fix_by_design with the reason, or unbuilt) are still the
        registry's to publish; before this the row said "unbuilt" without ever asking."""
        consulted: list[dict[str, Any]] = []
        facts: list[str] = []
        rewriters: list[tuple[str, Any]] = []
        prescribed: list[tuple[str, Any]] = []
        dispatch_ids = finding.get("rule_ids") or ([finding["rule_id"]] if finding.get("rule_id") else [])
        for rid in dispatch_ids:
            g = for_rule(rid)
            if g is None:
                consulted.append({"rule_id": rid, "kind": "no_generator", "role": None})
                facts.append(f"no registry row for {rid}")
                continue
            if g.kind == "no_fix_by_design":
                consulted.append({"rule_id": rid, "kind": "no_fix_by_design", "role": None, "reason": g.reason})
                facts.append(f"no fix by design ({rid}): {g.reason}")
                continue
            if g.kind == "unbuilt":
                consulted.append({"rule_id": rid, "kind": "unbuilt", "role": None, "reason": g.reason})
                facts.append(f"unbuilt ({rid}): {g.reason}")
                continue
            if g.kind == "prescribed":
                consulted.append({"rule_id": rid, "kind": "prescribed", "role": _prescribed_role(rid), "reason": g.reason})
                prescribed.append((rid, g))
                continue
            consulted.append({"rule_id": rid, "kind": "rewriter", "role": g.role})
            rewriters.append((rid, g))
        return consulted, facts, rewriters, prescribed

    def _mark_judged(self, cands: list[SolutionCandidate]) -> list[dict[str, Any]]:
        """Item 6: an attempt the gate ledger already failed (stage 2 or 3, an earlier cycle) carries that verdict
        into this cycle BEFORE the Ranker decides — the failure is a fact of the row, not something to rediscover."""
        repo = getattr(self, "_target_repo", "") or ""
        ledger = SYS_SCRIPTS / f"gate_{_repo_id(Path(repo))}.jsonl" if repo else None
        if ledger is None or not ledger.exists():
            return []
        failed: dict[str, dict[str, Any]] = {}
        integrated: dict[str, list[dict[str, Any]]] = {}
        carried: list[dict[str, Any]] = []
        for raw in ledger.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if rec.get("verdict") == "fail" and rec.get("attempt_id") not in failed:
                failed[rec["attempt_id"]] = rec
            # cr_trials round two F7 (2026-11-04): an attempt the ledger already APPLIED is a fact of the row too. The
            # next cycle re-joined it against the rewritten live function, read "differs=no", and overwrote the row's
            # history with "refused". It carries its integrates (and tests) records forward instead.
            if rec.get("verdict") == "pass" and rec.get("stage") in ("integrates", "tests"):
                integrated.setdefault(rec.get("attempt_id"), []).append(rec)
        for c in cands:
            aid = c.role.rsplit("_", 1)[-1]
            rec = failed.get(aid)
            if rec and not any(o.startswith("stage=fail") for o in c.observations):
                c.observations.append(f"stage=fail:{rec.get('stage')}:{rec.get('detail')}")
                carried.append({"role": c.role, **{k: v for k, v in rec.items() if k not in ("attempt_id", "row_key", "at")}})
            done = integrated.get(aid)
            if done and any(r.get("stage") == "integrates" for r in done) and aid not in failed:
                c.observations.append("gate=integrated:applied on an earlier cycle")
                for r in done:
                    carried.append({"role": c.role, **{k: v for k, v in r.items() if k not in ("attempt_id", "row_key", "at")}})
        return carried

    async def _stage_integrates(self, pick: SolutionCandidate, finding: dict[str, Any],
                                p: dict[str, Any]) -> dict[str, Any]:
        """Stage 2 for one picked attempt, serialised by `_GATE_LOCK`; the gate ledger (gate_<repo_id>.jsonl, beside
        the return channel) keeps one record per attempt and stage, and an attempt already judged is not re-run."""
        from .solution_gate_integrate import stage_integrates
        repo = getattr(self, "_target_repo", "") or ""
        attempt_id = pick.role.rsplit("_", 1)[-1]
        if not repo:
            return {"stage": "integrates", "verdict": "fail", "detail": "NOT MEASURED — no target repo on the scan"}
        ledger = SYS_SCRIPTS / f"gate_{_repo_id(Path(repo))}.jsonl"
        judged: list[dict[str, Any]] = []
        for raw in (ledger.read_text(encoding="utf-8").splitlines() if ledger.exists() else []):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if rec.get("attempt_id") == attempt_id and rec.get("stage") in ("integrates", "tests"):
                judged.append({k: v for k, v in rec.items() if k not in ("attempt_id", "row_key", "at")})
        if judged:
            first = judged[0]
            later = next((j for j in judged if j.get("stage") == "tests"), None)
            return {**first, "tests": later} if later else first
        facts = ((p.get("ranker_facts") or {}).get("intent") or {}).get("facts") or []
        from .solution_gate_tests import baseline, stage_tests
        root = Path(repo)
        async with _gate_lock():
            # Stage 3 (item 5) needs the suite's result on the code as scanned — taken (or read from cache) BEFORE
            # stage 2 writes; then stage 2; then, on a pass, the suite with the attempt applied. Stages 2 and 3 run
            # under one lock, so no other row writes between the apply and the tests, and a stage-3 fail is reverted
            # with the bytes stage 2 kept.
            base = await asyncio.to_thread(baseline, root, SYS_SCRIPTS / f"gate_baseline_{_repo_id(root)}.json")
            verdict = await asyncio.to_thread(
                stage_integrates, root, finding["file"], int(p.get("func_start") or 0),
                int(p.get("func_end") or 0), pick.after_code, list(p.get("importers") or []), facts,
                p.get("broken_code") or "", finding.get("function") or "")   # B3: the write re-bases to the live span
            tests: dict[str, Any] | None = None
            if verdict["verdict"] == "pass":
                tests = await asyncio.to_thread(stage_tests, root, base)
                if tests["verdict"] == "fail" and verdict.get("applied"):
                    from .solution_gate_integrate import revert
                    revert(verdict["applied"])
        if verdict["verdict"] == "deferred":
            return verdict   # not a verdict on the attempt: never on the ledger, judged again next cycle
        row_key = _row_key(finding["file"], finding["function"], finding["line"])
        now = datetime.now(timezone.utc).isoformat()
        with open(ledger, "a", encoding="utf-8") as fh:
            for v in (verdict, tests):
                if v is not None:
                    fh.write(json.dumps({"attempt_id": attempt_id, "row_key": row_key, "at": now,
                                         **{k: x for k, x in v.items() if k != "applied"}},
                                        ensure_ascii=False, default=str) + "\n")
        if tests is not None:
            verdict = {**verdict, "tests": tests}
        return verdict

    async def _filter_attempts(self, cands: list[SolutionCandidate], finding: dict[str, Any],
                               p: dict[str, Any]) -> None:
        module_src = p.get("module_src") or ""
        start, end = int(p.get("func_start") or 0), int(p.get("func_end") or 0)
        rel = finding.get("file") or ""
        if not module_src or not start or not end or not rel:
            for c in cands:
                c.observations.append("filter=fail:NOT MEASURED — the row carries no module source or span")
            return
        lines = module_src.splitlines(keepends=True)
        indent = len(lines[start - 1]) - len(lines[start - 1].lstrip()) if start - 1 < len(lines) else 0
        row_rules = set(finding.get("rule_ids") or []) | {finding.get("rule_id")}
        before_deciding = await self._deciding_on(module_src, rel, finding.get("function") or "")
        for c in cands:
            if not candidate_pickable(c):
                continue   # parse / differs already ruled it out — no scratch run needed
            body = textwrap.indent(textwrap.dedent(c.after_code).strip("\n") + "\n", " " * indent)
            patched = "".join(lines[:start - 1]) + body + "".join(lines[end:])
            name = finding.get("function") or ""
            fn = next((n for n in ast.walk(ast.parse(textwrap.dedent(c.after_code)))
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
            if fn is not None and fn.name != name:
                c.observations.append(f"filter=fail:the attempt defines `{fn.name}`, the row's function is `{name}`")
                continue
            try:
                after_deciding = await self._deciding_on(patched, rel, name)
            except SyntaxError as e:
                c.observations.append(f"filter=fail:the file no longer parses with the attempt in place — {e.msg} "
                                      f"(line {e.lineno})")
                continue
            still = sorted(after_deciding & row_rules)
            # cr_trials round one, F2 (2026-11-04): a stub fires fewer rules than any real body, so "any new deciding
            # rule" refused four honest repairs on rules that have never been calibrated (NAI-108, 003, 030, 136). A
            # new rule vetoes only with evidence (a ruling or a proof); a pre-calibration rule is recorded, not decisive.
            # shortcut: evidence kind is the only signal; upgrade to the family's class once the slices rule these.
            newcomers = sorted(after_deciding - before_deciding)
            new = [r for r in newcomers if _VR_evidence_kind(r) != "none (pre-calibration)"]
            unruled = [r for r in newcomers if r not in new]
            if still:
                c.observations.append(f"filter=fail:the row's own rule still fires on the attempt ({', '.join(still)})")
            elif new:
                c.observations.append(f"filter=fail:the attempt brings a new deciding rule ({', '.join(new)})")
            else:
                c.observations.append("filter=pass" + (f":uncalibrated rules fire on the attempt, not decisive ({', '.join(unruled)})"
                                                       if unruled else ""))

    async def _deciding_on(self, source: str, rel: str, function: str) -> set[str]:
        """The deciding rule ids the validator raises on `function` when the file reads `source` — validated in a
        scratch directory under the file's own relative name, never in the target."""
        import tempfile
        from .noai_validator import file_validation as _fv
        from .noai_validator.validator import NoAIMathValidator as _V
        ast.parse(source)   # a SyntaxError is the caller's verdict
        with tempfile.TemporaryDirectory(prefix="cr_filter_") as tmp:
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
            results = await _fv.validate_file_async(_V(), path)
        out: set[str] = set()
        for r in results:
            if r.function_name == function and not r.passed:
                out |= set(_extract_rule_ids(r.triggered_patterns or [], r.failure_reason or ""))
        return {i for i in out if i and _VR_disposition(i) == "deciding"}

    def _attempt_candidates(self, row_key: str, broken_code: str) -> list[SolutionCandidate]:
        """Solution gate, item 1: every attempt the agent filed for `row_key` (attempts_<repo_id>.jsonl beside the
        return channel, written by cr_submit), as a candidate. The role `agent_attempt_<n>_<id>` names it; the code
        is the agent's whole replacement function."""
        repo = getattr(self, "_target_repo", "") or ""
        if not repo:
            return []
        path = SYS_SCRIPTS / f"attempts_{_repo_id(Path(repo))}.jsonl"   # beside return_channel_<repo_id>.jsonl
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        out: list[SolutionCandidate] = []
        for raw in lines:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("row_key") != row_key or not rec.get("code"):
                continue
            out.append(SolutionCandidate(
                solution=f"agent attempt {rec.get('attempt')}: {rec.get('note') or 'no note'}",
                role=f"agent_attempt_{rec.get('attempt')}_{rec.get('attempt_id')}",
                before_code=broken_code, after_code=rec["code"], source="agent"))
        return out

    def _generate(self, finding: dict[str, Any], broken_code: str,
                  module_src: str = "") -> tuple[list[SolutionCandidate], list[dict[str, Any]], list[str]]:
        """Dispatch every deciding rule id through the registry (repair_generators.for_rule).
        Returns (candidates, generators_consulted, builder_facts). generators_consulted carries
        one record per rule id: kind ∈ rewriter | no_fix_by_design | unbuilt | no_generator
        (no registry row — impossible while step 19 passes), the role for rewriters, and the
        registry's reason for the two no-fix kinds; the same reason is repeated in
        decision.why so the row stays the ONE place to look."""
        candidates: list[SolutionCandidate] = []
        consulted, facts, rewriters, prescribed = self._consult(finding)
        seen_roles: set[str] = set()
        for rid, g in rewriters:
            role, fixer = g.role, g.fn
            if role in seen_roles or fixer is None:
                continue
            seen_roles.add(role)
            try:
                # FIX_43 (b): one candidate, or a finite set of them. S5-1: every one passes G0 on the way
                # out — a candidate the gate withholds is offered all the same, carrying the gate's sentence.
                offered = candidates_of(g, broken_code, file=finding.get("file", ""),
                                        span=finding.get("replace_span", ""), module_src=module_src)
            except Exception as e:
                facts.append(f"declined: {role} raised {type(e).__name__}: {str(e)[:80]}")
                continue
            if not offered:
                facts.append(f"declined: {role} found nothing to rewrite")
                continue
            for offer in offered:
                cand_role, fixed, what_changed = offer
                if cand_role.rpartition(":")[2] in SHAPE_ONLY_VARIANTS:
                    # S10b (owner 2026-09-29, S10a hand-over): a rewriter's named "no rewrite; emit this shape"
                    # entry is valid Python with a stub body (`result = ...`), yet it is a SUGGESTION: it is
                    # published as a shape only — never gated, tested or applied as a repair. It enters as a
                    # prescribed candidate (FIX_41's path: solution_kind "prescribed", apply "review", the
                    # MCP hands it out as kind "shape"); the gate's note on the offer is not carried.
                    candidates.append(SolutionCandidate(
                        solution=what_changed, role=cand_role, before_code=broken_code, after_code=fixed,
                        source="prescribed",
                        observations=["kind=prescribed", "parse=shape", "differs=yes", f"rule={rid}"]))
                    continue
                cand = SolutionCandidate(
                    solution=what_changed,  # derived from the rewrite itself, never canned
                    role=cand_role,
                    before_code=broken_code,
                    after_code=fixed,
                    source="ast_rewriter",
                    observations=[f"rule={rid}"],   # which rule this candidate answers (FIX_43 (b), Call B)
                )
                self._observe(cand, broken_code)
                gate_rule, gate_reason = gate_note(offer)
                if gate_reason:
                    # S5-1 (owner's gate sentence): the candidate stays on the row and stays visible; the
                    # observation makes it unpickable (knowledge_base._UNPICKABLE_PREFIXES) and the reason
                    # rides the builder facts into decision.why, exactly as `declined: …` already does.
                    cand.observations.append(f"gate=withheld:{gate_rule}")
                    facts.append(f"{gate_reason} [{cand_role}]")
                candidates.append(cand)
        # FIX_41: every prescribed id on the row is a candidate too — the Ranker decides between a
        # rewriter's after-code and a prescription (or between two prescriptions) like any other pick.
        # S9-T1 (I-150 follow-up): and every prescribed candidate passes G0 on the way out too, the
        # same way a rewriter's does — withheld, it stays on the row, unpickable, with the sentence.
        for rid, g in prescribed:
            cand = _prescribed_candidate(rid, g, broken_code,
                                         finding.get("failure_reason", "") or "")
            verdict = _prescription_verdict(rid, g, broken_code, file=finding.get("file", ""),
                                            span=finding.get("replace_span", ""), module_src=module_src)
            if not verdict.ok:
                cand.observations.append(f"gate=withheld:{verdict.rule}")
                facts.append(f"{verdict.reason} [{cand.role}]")
            candidates.append(cand)
        return candidates, consulted, facts

    # -- rows ------------------------------------------------------------------

    async def build_rows(
        self,
        state: dict[str, Any],
        *,
        previous: dict[str, dict[str, Any]] | None = None,
        circuit: dict[str, Any] | None = None,
        whitelist_functions: set[str] | None = None,
        failed: dict[str, list[dict[str, Any]]] | None = None,
        confirmed: dict[str, dict[str, Any]] | None = None,
        channel: dict[str, Any] | None = None,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        """Findings in (the validator's published state) → {row_key: row}, summary.

        previous  — last cycle's rows: a row whose finding AND evidence are unchanged
                    is reused (fix_order refreshed — a whole-set fact).
        circuit   — circuit_state.json content (read here when not given).
        failed    — row_key → [{digest, failure_log, tester, timestamp}] the tester failed
                    (item 5: _join_channel; the failure joins that ONE row's evidence).
        confirmed — row_key → the confirming line for the row's current digest (item 5).
        channel   — {orphans, unparsed, channel_lines} for summary.tester (item 5).
        """
        previous = previous or {}
        whitelist_functions = whitelist_functions or set()
        failed = failed or {}
        confirmed = confirmed or {}
        target_repo = state.get("target_repo", "") or ""
        self._target_repo = target_repo   # solution gate, item 1: names the attempts file the rows join
        repo = Path(target_repo) if target_repo else None

        findings = _findings_from_state(state, whitelist_functions)

        # ── Whole-set facts, once per cycle ──
        if circuit is None:
            circuit = read_file_locked(CIRCUIT_STATE_FILE) or {}
        node_depths, reverse_graph = _build_graph_context(circuit)
        # Q5 / I-107: one whole-set fact per cycle — the files FIX_50's table already exempts.
        entry_role_files = _entry_role_files(circuit)
        files = sorted({f["file"] for f in findings})
        context_info: dict[str, dict[str, Any]] = {}
        file_facts: dict[str, _FileFacts | None] = {}
        if repo is not None:
            context_info, file_facts = await asyncio.gather(
                self._context_info(repo, files), self._file_facts(repo, files))
        ranker = await self.ranker_for(target_repo)
        if self.intent_rerank:
            # owner 2026-09-30 (Lane A): the reuse shortcut keys on the infraction and its evidence, which an intent
            # change moves neither of — so on the cycle the intent moved, no row is reused: every row is re-ranked.
            previous = {}
        cross_file = state.get("cross_file_analysis") or {}
        stale_files = set(cross_file.get("stale_for_files") or [])
        semantic = state.get("semantic_analysis") or {}
        flagged_names: dict[str, set[str]] = {}
        intent_facts = _intent_facts(target_repo)   # M-126/127: the target's intent, read once per build
        for f in findings:
            flagged_names.setdefault(f["file"], set()).add(f["function"])
        flagged_spans = {rel: (ff.flagged_spans(flagged_names[rel]) if ff else []) for rel, ff in file_facts.items()}
        # C1 (Q-H3b-7 / Q-H3a-2, 2026-10-01): the whole-set lists, indexed once — see _rca_evidence.
        span_index = {rel: _SpanIndex(spans) for rel, spans in flagged_spans.items()}
        rca_by_site: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
        for rep in cross_file.get("rca_reports", []) or []:
            rca_by_site.setdefault((rep.get("file"), rep.get("function")), []).append(rep)
        semantic_by_rel: dict[str, dict[str, list[Any]]] = {}

        # ── Order: fix the root, not the fruit — deeper first, then more dependents,
        # then source order (the plain tuple; cut 3 batch 5 excised the invented weights).
        # Q-H3-1 (2026-10-01): the lookup key is the node NAME form (`_node_key`: relative path
        # without `.py`), not the stem — by stem no file below the target root was ever found and
        # every row read 0/0. A file the circuit has no node for is NOT MEASURED, not 0: its depth
        # and dependents publish as None, the evidence says so, and it sorts after every measured
        # row (it cannot claim a place above one).
        def _graph_facts(f: dict[str, Any]) -> tuple[int | None, int | None]:
            key = _node_key(f["file"])
            measured = node_depths.get(key)
            if measured is None:
                return None, None
            return measured, len(reverse_graph.get(key, []))

        def _finding_priority(f: dict[str, Any]) -> tuple[int, int, int, int]:
            measured, importers = _graph_facts(f)
            if measured is None:
                return (1, 0, 0, f["line"])
            return (0, -measured, -(importers or 0), f["line"])

        ordered = sorted(findings, key=_finding_priority)

        # ── Evidence per row (sequential: the file-scope de-duplication is order-dependent) ──
        file_scope_emitted: set[tuple] = set()
        prepared: list[dict[str, Any]] = []
        for fix_order, f in enumerate(ordered, 1):
            depth, dependents = _graph_facts(f)
            ctx = context_info.get(f["file"], {})
            ff = file_facts.get(f["file"])
            if f["file"] not in semantic_by_rel:
                semantic_by_rel[f["file"]] = _semantic_items_for(semantic, f["file"])
            broken_code, func_start, func_end = (ff.function_source(f["function"], f["line"]) if ff else ("", f["line"], f["line"]))
            evidence: list[str] = []
            if f["exonerated"]:
                evidence = [f"rule_id={f['rule_id']}", "WHITELISTED:owner_exempted"]
            else:
                evidence = self._rca_evidence(
                    f, ctx=ctx, depth=depth, dependents=dependents, func_start=func_start, func_end=func_end,
                    cross_file=cross_file, stale=f["file"] in stale_files,
                    rca_reports=rca_by_site.get((f["file"], f["function"]), []),
                    semantic_items=(semantic_by_rel[f["file"]] if semantic else None),
                    span_index=span_index.get(f["file"]) or _SpanIndex([]), file_scope_emitted=file_scope_emitted)
            prepared.append({
                "finding": f, "fix_order": fix_order, "depth": depth, "dependents": dependents,
                "importers": list(reverse_graph.get(_node_key(f["file"]), [])),   # solution gate stage 2
                "cb_context": ctx, "broken_code": broken_code, "evidence": evidence, "func_start": func_start,
                "ranker_facts": {"intent": intent_facts, "function_intent": _function_intent(broken_code),
                                 "context": _context_facts(f)},
                # I-131: the span the Builder PARSED for this unit, so a finding that arrives with an
                # inverted or missing end can be repaired here rather than published as it came.
                "func_end": func_end, "n_lines": (len(ff.lines) if ff is not None else 0),
                "unbuilt": (ff is None or not broken_code) and not f["exonerated"],
                # Q5 / I-107: is this the entry script FIX_50's `role == entry` row exempts?
                "entry_role": f["file"] in entry_role_files,
                # S5-1: the module the span was cut from — G0's import context (the one parse per file
                # per cycle is already done; this is the same string, not a re-read).
                "module_src": (ff.src if ff is not None else ""),
            })

        # ── Per-row builds under gather ──
        built = await asyncio.gather(*(self._build_row(p, ranker=ranker, previous=previous, failed=failed,
                                                       confirmed=confirmed) for p in prepared))
        # I-129 (session 8, run 160): this was `rows = {r["row_key"]: r for r in built}` — a dict
        # comprehension over positional keys, so two findings that shared `<file>::<function>::<line>`
        # collapsed and the loser reached NO published bucket. On run 155 that swallowed 41 failing
        # units after the apply pass (`failed` 187 vs repairs 71 + no_vetted_fix 75 = 146): the
        # validator's incremental rescan was stamping every same-name unit in a file with one line
        # (fixed at its own writer, NOAI_VALIDATOR_DAEMON.stage_ingest_incremental). The cause is gone;
        # the LOSS must still be impossible, so a collision is now counted, logged and CARRIED — the
        # second and later rows keep their own bucket under a suffixed key rather than vanishing.
        rows: dict[str, dict[str, Any]] = {}
        collisions = 0
        for r in built:
            key = r["row_key"]
            if key in rows:
                collisions += 1
                n = 2
                while f"{key}#{n}" in rows:
                    n += 1
                key = f"{key}#{n}"
                r = {**r, "row_key": key, "key_collision": True}
                r["rca_evidence"] = list(r.get("rca_evidence") or []) + [
                    f"key_collision: {r['file']}::{r['function']}::{r['line']} is not unique this cycle — "
                    f"published as {key} so the unit stays in a bucket (I-129)"]
            rows[key] = r
        if collisions:
            logger.warning("[BUILD] %d row key collision(s) carried under suffixed keys — every failing "
                           "unit stays in a published bucket (I-129)", collisions)
        if len(rows) != len(findings):
            logger.error("[BUILD] %d finding(s) in, %d row(s) out — the buckets no longer cover the "
                         "validator's failures (I-129)", len(findings), len(rows))
        return rows, self._summary(rows, state, channel)

    async def _build_row(self, p: dict[str, Any], *, ranker: SolutionRanker,
                         previous: dict[str, dict[str, Any]], failed: dict[str, list[dict[str, Any]]],
                         confirmed: dict[str, dict[str, Any]]) -> dict[str, Any]:
        f = p["finding"]
        key = _row_key(f["file"], f["function"], f["line"])
        row_hash = _row_hash(f)
        failures = [r if isinstance(r, dict) else {"digest": r, "failure_log": "", "tester": "", "timestamp": ""}
                    for r in (failed.get(key) or [])]
        failed_digests = [r["digest"] for r in failures]
        # The tester's failure joins ALL the evidence for this ONE infraction (plan step 4): the
        # token the Ranker reads and the first TESTER_LOG_CHARS of the failure log. The evidence
        # is the ONLY place a failed digest lives (owner 2026-09-09: no failure-kind fields).
        evidence = list(p["evidence"])
        for r in failures:
            evidence.append(f"tester=failed:{r['digest']}")
            if r.get("failure_log"):
                evidence.append(f"tester_log={r['failure_log'][:TESTER_LOG_CHARS]}")
        prev = previous.get(key)
        conf = confirmed.get(key)

        # Q5 / I-107: the entry role is a WHOLE-SET fact, not a fact of the infraction — it is
        # measured only when the entry is first run through the wrapper, which is normally MID-RUN
        # (run 157 launch A: the first scan ran before the entry had been run), and it moves nothing
        # in `row_hash` or in the evidence. So the registry is consulted for a body-less row HERE,
        # once, and the reuse shortcut below honours the answer: a cached row whose by-design state
        # no longer matches the measurement is REBUILT, never reused. The same value decides the
        # publish window, so the guard and the window cannot disagree.
        consult = self._consult(f) if (p["unbuilt"] and not f["exonerated"]) else None
        q5_withheld = (bool(p.get("entry_role")) and consult is not None and not consult[2]
                       and {rid for rid, _g in consult[3]} == {NAI_094})

        # Unchanged infraction + unchanged evidence (the tester's failures included) → reuse
        # (whole-set facts refreshed; a `confirmed` line marks the solution confirmed — plan step 6).
        # Solution gate: an attempt filed since the row was built is in neither `row_hash` nor the evidence, so the
        # reuse also needs the attempts the row reported to be the attempts on file (live tree 1, 2026-10-10).
        filed = [c.role for c in self._attempt_candidates(key, "")]
        reported = [f"agent_attempt_{a.get('attempt')}_{a.get('attempt_id')}" for a in (prev or {}).get("attempts") or []]
        if prev and prev.get("row_hash") == row_hash and prev.get("rca_evidence") == evidence \
                and (prev.get("withheld_by") == BY_DESIGN_WITHHELD) == q5_withheld and filed == reported:
            row = dict(prev)
            row["fix_order"] = p["fix_order"]
            row["tester"] = _tester_field(row.get("digest"), conf)
            return row

        now = datetime.now(timezone.utc).isoformat()
        infraction = f"[{f['failure_layer']}] {f['failure_reason']}"
        # I-131 (session 8, run 160) — REPAIR AT THE WRITER. The four rows the shakedown named (and
        # 20 more it did not sample) published `line_end` BELOW `line`, because the validator's
        # incremental rescan paired one unit's def line with another unit's end. That writer is fixed;
        # this one no longer trusts what reaches it either. The Builder has already parsed the file
        # this cycle, so the unit's own span is here: when the finding's end is missing or precedes
        # its line, the PARSED span replaces it and the substitution is written into the evidence.
        # `line` itself is the ROW KEY and never moves here (the validator's def line, _FileFacts);
        # only the END is repaired, from the span the Builder parsed for this same unit.
        _line, _line_end = int(f["line"] or 0), int(f["end_line"] or 0)
        if p["broken_code"] and (not _line_end or _line_end < _line) and int(p["func_end"] or 0) >= _line:
            evidence = list(evidence) + [
                f"span_repaired: the finding arrived as {_line}..{_line_end}; the parsed span for "
                f"`{f['function']}` ends at {int(p['func_end'])} (I-131)"]
            _line_end = int(p["func_end"])
        # I-144 / Q9 (session 10, run 174) — AND NEVER A 0. When the end still cannot be read (a
        # row with no body for the Builder to parse, a unit whose file moved under the scan), the
        # row publishes a ONE-LINE span rather than a 0 no reader can act on. `line` is the row
        # key and never moves here either; a row with no line at all — a `<module>` row carrying
        # no riding SIG hit — keeps its 0 and is refused at publish exactly as today.
        elif _line > 0 and (not _line_end or _line_end < _line):
            evidence = list(evidence) + [
                f"span_one_line: the finding arrived as {_line}..{_line_end} and no wider span "
                f"could be read for `{f['function']}`; the row spans its own line (I-144)"]
            _line_end = _line
        row: dict[str, Any] = {  # type: ignore[no-redef]  # FIX_54 ast-pos
            "row_key": key,
            "file": f["file"],
            "function": f["function"],
            "line": _line,
            "line_end": _line_end,
            "replace_span": _span(f["file"], p["func_start"] if p["broken_code"] else _line, _line_end),
            "finding_lines": f["finding_lines"],
            "rule_ids": f["rule_ids"],
            "rule_ids_all": _extract_rule_ids(f["triggered_patterns"], f["failure_reason"]),
            "context_ids": f["context_ids"],
            "species": f["species"],
            "withheld": f["withheld"],
            # S5-1: the gate's half of "withheld". `withheld` above is the VALIDATOR's species reason;
            # these two are set only when G0 withheld every candidate this row had (packet §B).
            "withheld_by": "species" if f["withheld"] else None,
            "withheld_reason": "",
            "gate_withheld": {},
            "failure_layer": f["failure_layer"],
            "infraction": infraction,
            "failure_reason": f["failure_reason"],
            "row_hash": row_hash,
            "fix_order": p["fix_order"],
            "depth": p["depth"],
            "dependents": p["dependents"],
            "cb_context": p["cb_context"],
            "rca_evidence": evidence,
            "ranker_facts": p["ranker_facts"],
            "exonerated": f["exonerated"],
            "generators_consulted": [],
            "candidates_considered": 0,
            "observations": {},
            "selection": {},
            "decision": {"pick_role": None, "why": ""},
            "no_fix_status": None,
            "solution_kind": None,   # FIX_41: "rewriter" | "prescribed" once the Ranker picked, else None
            "fix": "",
            "before_code": p["broken_code"],
            "after_code": "",
            "digest": None,
            "tester": {"confirmed": False, "tester": "", "timestamp": ""},
            "built_at": now,
        }
        # error_message for the Ranker: the first line of the latest failure log when the tester
        # failed this infraction's solution (plan step 4); the validator's failure_reason otherwise.
        error_message = f["failure_reason"]
        tester_facts: list[str] = []
        for r in failures:
            first = next((ln.strip() for ln in (r.get("failure_log") or "").splitlines() if ln.strip()), "")
            tester_facts.append(f"tester failed {r['digest']}" + (f": {first[:TESTER_LOG_CHARS]}" if first else ""))
            if first:
                error_message = first

        if f["exonerated"]:
            row["decision"] = {"pick_role": None, "why": "WHITELISTED: owner-exempted — no fix owed"}
            row["before_code"] = ""
            return row

        if p["unbuilt"]:
            # No function body for a rewriter to take: a module-scope infraction (NAI-094 sys.path
            # manipulation, NAI-209/211 import fallbacks, file species — seen live on run 46) or a
            # function the file no longer holds. The registry is consulted all the same (run 55, set
            # 4b-02): when every rule on the row is declared no-fix-by-design the row publishes that
            # declaration and its reason — only a rewriter needs the body.
            consulted, reg_facts, rewriters_hit, prescribed_hit = consult or self._consult(f)
            row["generators_consulted"] = consulted
            if q5_withheld:
                # Q5 (owner, 2026-09-20) / I-107. The row is PUBLISHED and still counted — only its
                # SOLUTION is withheld, by design, because FIX_50 already exempts this file's own
                # path manipulation as `role == entry`. FIX_51's withheld block carries it with the
                # reason below, which is also the row's `decision.why`; solution_kind / fix / digest
                # stay empty, so
                # the row leaves through no_vetted_fix[] exactly as a gate-withheld row does and the
                # mirror's repairs + no_vetted_fix == failed identity is unmoved. NAI-094 must be the
                # ONLY rule the registry answered for on this row: a mixed row keeps its solution
                # (fail closed — Q5 withholds one rule's solution, not the row's).
                sentence = _q5_withheld_sentence(f["file"])
                row["withheld_by"] = BY_DESIGN_WITHHELD
                row["withheld_reason"] = sentence
                row["decision"] = {"pick_role": None, "why": "; ".join(reg_facts + [sentence])}
                row["no_fix_status"] = "no_fix_by_design"
                return row
            if prescribed_hit and not rewriters_hit:
                # FIX_41: a module-scope / body-less row with a prescribed solution publishes it — the
                # prescription needs no body (before_code stays the row's, "" at module scope).
                # R4: a module-scope row has NO body (`broken_code` is ""), so the family the fire
                # belongs to is read off the validator's own sentence — which names it literally
                # (`Module-level os.environ[...] = at line N — …`).
                pres = [_prescribed_candidate(rid, g, p["broken_code"] or "", f["failure_reason"])
                        for rid, g in prescribed_hit]
                # S9-T1 (I-150 follow-up): the body-less path asks G0 about its prescriptions too.
                for cand, (rid, g) in zip(pres, prescribed_hit):
                    v = _prescription_verdict(rid, g, p["broken_code"] or "", file=f["file"],
                                              span=f.get("replace_span", "") or "",
                                              module_src=p.get("module_src", "") or "")
                    if not v.ok:
                        cand.observations.append(f"gate=withheld:{v.rule}")
                        reg_facts = list(reg_facts) + [f"{v.reason} [{cand.role}]"]
                # I-152 (session 10): the same bar on the body-less path — a module-scope row's
                # prescription is the shape a seat would have to render too, and NAI-094's
                # `<real.package.module>` is a decision, not a binding.
                _gate_withheld: dict[str, str] = {}
                for cand in pres:
                    _why = _not_renderable_reason(cand)
                    if _why:
                        cand.observations.append(f"gate=withheld:{NOT_SELECTABLE_BY}")
                        reg_facts = list(reg_facts) + [f"{_why} [{cand.role}]"]
                        _gate_withheld[cand.role] = _why
                if _gate_withheld:
                    row["gate_withheld"] = {r: f"gate=withheld:{NOT_SELECTABLE_BY}" for r in _gate_withheld}
                    row["gate_withheld_reasons"] = dict(_gate_withheld)
                    if len(_gate_withheld) == len(pres):
                        row["withheld_by"] = NOT_SELECTABLE_BY
                        row["withheld_reason"] = NOT_SELECTABLE_REASON
                row["candidates_considered"] = len(pres)
                row["observations"] = {c.role: list(c.observations) for c in pres}
                decision = ranker.decide(pres, error_message=f["failure_reason"], rca_evidence=p["evidence"], target_code="",
                                         facts=p["ranker_facts"],
                                         deciding_rule=(f["rule_ids"] or [None])[0],   # FIX_43 (b), Call B
                                         row_rules=list(f["rule_ids"] or []))   # I-132: the row's rule set
                row["selection"] = {r["role"]: r["selection_total"] for r in decision.considered if "selection_total" in r}
                why = ("; ".join(reg_facts) + "; " if reg_facts else "") + decision.why
                if decision.pick is not None:
                    pick = decision.pick
                    digest = _candidate_digest(pick)
                    row["decision"] = {"pick_role": pick.role, "why": why}
                    row["solution_kind"] = "prescribed"
                    row["fix"] = pick.solution
                    row["after_code"] = pick.after_code
                    row["digest"] = digest
                    row["tester"] = _tester_field(digest, conf)
                    return row
                row["decision"] = {"pick_role": None, "why": why}
                row["no_fix_status"] = "ranker_none"
                return row
            decision = ranker.decide([], error_message=f["failure_reason"], rca_evidence=p["evidence"], target_code="",
                                     facts=p["ranker_facts"])
            kinds = {g["kind"] for g in consulted}
            if consulted and not rewriters_hit and "no_fix_by_design" in kinds:
                row["decision"] = {"pick_role": None, "why": "; ".join(reg_facts) + f"; {decision.why}"}
                row["no_fix_status"] = "no_fix_by_design"
                return row
            if f["function"] == "<module>":
                fact = f"unbuilt: module-scope infraction in {f['file']} — no function body to rewrite"
            else:
                fact = f"unbuilt: function `{f['function']}` not found in {f['file']}"
            row["decision"] = {"pick_role": None, "why": "; ".join([fact] + reg_facts) + f"; {decision.why}"}
            row["no_fix_status"] = "unbuilt"
            return row

        # Candidate generation + observations (sync inside a thread: one piece of evidence per rewrite)
        candidates, consulted, facts = await asyncio.to_thread(
            self._generate, f, p["broken_code"], p.get("module_src", ""))
        # Solution gate, item 1 (owner 2026-10-08): the agent's attempts for THIS row join the field as candidates
        # (source `agent`), observed exactly like the engine's own; the Ranker ranks them together.
        judged_before: list[dict[str, Any]] = []
        agent_cands = self._attempt_candidates(key, p["broken_code"])
        for c in agent_cands:
            self._observe(c, p["broken_code"])
        # Solution gate, item 2 (owner 2026-10-08): each attempt is spliced into a scratch copy of its file and the
        # file re-validated; it stays pickable only if the row's own rule no longer fires on the function and no new
        # deciding rule does. The verdict rides the candidate (`filter=pass` / `filter=fail:<why>`), so a filtered
        # attempt is out of the running before the Ranker scores anything and the agent reads why.
        if agent_cands:
            await self._filter_attempts(agent_cands, f, p)
            judged_before = self._mark_judged(agent_cands)
            # Owner 2026-10-08 (gate model: the agent writes, CodeRadar judges): a prescribed shape is the BRIEF the
            # agent's attempts answer, not a competitor — once an attempt is still in the running, the row's
            # prescribed shapes step aside. Code-writing generators (rewriters) still compete on equal terms.
            if any(candidate_pickable(c) for c in agent_cands):
                for c in candidates:
                    if c.source != "agent" and "kind=prescribed" in c.observations and candidate_pickable(c):
                        c.observations.append("gate=withheld:answered_by_agent — the agent's attempt implements this "
                                              "prescription and is judged instead")
        candidates = list(candidates) + agent_cands
        if agent_cands:
            consulted = list(consulted) + [{"rule_id": (f["rule_ids"] or [""])[0], "kind": "agent", "role": c.role,
                                            "source": "agent", "reason": c.solution} for c in agent_cands]
        for c in candidates:
            for d in failed_digests:
                if _candidate_digest(c) == d:
                    c.observations.append(f"tester=failed:{d}")
        row["generators_consulted"] = consulted
        row["candidates_considered"] = len(candidates)
        # I-152 (session 10): THE SELECTOR'S BAR, applied BEFORE the Ranker sees the field. A
        # candidate that cannot be rendered unattended is marked exactly the way G0 marks a
        # withheld rewrite — same token, same sentence channel — so `selected_role` can never name
        # it. Nothing is removed from `candidates`: the row keeps its whole record of what was
        # offered, and the reason each one went is on the row.
        for _c in candidates:
            _why = _not_renderable_reason(_c)
            if _why:
                _c.observations.append(f"gate=withheld:{NOT_SELECTABLE_BY}")
                facts = list(facts) + [f"{_why} [{_c.role}]"]
        row["observations"] = {c.role: list(c.observations) for c in candidates}
        # S5-1 (packet §B): a row whose every candidate G0 withheld is a GATE-WITHHELD row — published,
        # visible, and in the mirror's withheld block with the gate's sentence (FIX_51's block, which
        # until now carried species-withholding only). The reason is the first gate fact on the row.
        gated = [c for c in candidates if any(o.startswith("gate=withheld") for o in c.observations)]
        if gated:
            row["gate_withheld"] = {c.role: next(o for o in c.observations if o.startswith("gate=withheld"))
                                    for c in gated}
            # S9-T1 (I-150 follow-up, owner ruling 2026-09-21): the SENTENCE per withheld candidate, not
            # just the check's name. Until now it reached `decision.why` only, and only a row whose EVERY
            # candidate was withheld published a `withheld_reason` — so a row that keeps a pickable
            # candidate beside a withheld one (this site: `solution_NAI-120` withheld, `solution_NAI-004`
            # picked) showed the client a different solution and never said why the first one went.
            row["gate_withheld_reasons"] = {
                c.role: next((x for x in facts if x.endswith(f"[{c.role}]")), "") for c in gated}
            if len(gated) == len(candidates):
                row["withheld_by"] = "gate"
                row["withheld_reason"] = next((x for x in facts if x.startswith("gate: ")), "gate: withheld")
            # I-152 / Q1 (owner 2026-09-21): when the ONLY reason nothing is left is that no
            # candidate renders unattended, the seam is named — `gate.prescription_check`, not
            # G0's `gate` — and the row therefore does NOT enter the mirror's withheld block
            # (`stage_mirror`'s loop takes `gate` and by-design only). The row stays an
            # infraction in `no_vetted_fix[]`, exactly as the owner ruled: withholding it would
            # drop a real smell from `failed == repairs + no_vetted_fix`.
            if (row.get("withheld_by") == "gate" and candidates
                    and all(_not_renderable_reason(c) for c in candidates)):
                row["withheld_by"] = NOT_SELECTABLE_BY
                row["withheld_reason"] = NOT_SELECTABLE_REASON

        # THE decision point — nothing overturns it afterwards. The tester's failure reaches it as
        # the tester=failed observation on the candidate, the tester_log token in the evidence and
        # the failure's first line as error_message (item 5).
        decision: Decision = ranker.decide(  # type: ignore[no-redef]  # FIX_54 ast-pos
            candidates, error_message=error_message, rca_evidence=evidence, target_code=p["broken_code"],
            facts=p["ranker_facts"],
            deciding_rule=(f["rule_ids"] or [None])[0],   # FIX_43 (b), Call B: the row's deciding rule reaches method 1
            # I-132 (session 8, run 160): the row's WHOLE deciding set. Until now the Ranker was told
            # the first id only and had no way to tell a candidate answering a rule ON the row from one
            # answering a rule that is not on the row at all; membership held by accident, because
            # `_generate` happens to dispatch from the same list. It is a REFUSAL now, not an accident.
            row_rules=list(f["rule_ids"] or []))
        # Solution gate, stage 1 (owner 2026-10-08): an AGENT attempt the Ranker picks must run. A failure marks it
        # `stage=fail:runs:…` (unpickable), records the verdict for the agent, and the Ranker decides again among
        # what is left — never more rounds than there are agent attempts.
        # Stage 2 (item 4): an attempt that ran is WRITTEN into the target (always a copy — owner 2026-10-08) and the
        # codebase around it must still import and its entry point still run; a fail restores the bytes and goes
        # back to the Ranker the same way. One attempt at a time across every row (`_GATE_LOCK`), and a verdict on
        # the gate ledger is never re-run.
        gate_log: list[dict[str, Any]] = []
        for _round in range(sum(1 for c in candidates if c.source == "agent")):
            pick = decision.pick
            if pick is None or pick.source != "agent":
                break
            from .solution_gate import stage_runs
            verdict = stage_runs(p.get("module_src") or "", int(p.get("func_start") or 0), int(p.get("func_end") or 0),
                                 f["function"], pick.after_code)
            gate_log.append({"role": pick.role, **verdict})
            if verdict["verdict"] != "fail":
                verdict = await self._stage_integrates(pick, f, p)
                gate_log.append({"role": pick.role, **{k: v for k, v in verdict.items() if k not in ("applied", "tests")}})
                tests = verdict.get("tests")
                if tests:
                    gate_log.append({"role": pick.role, **tests})
                if verdict["verdict"] == "fail":
                    pick.observations.append(f"stage=fail:integrates:{verdict['detail']}")
                elif tests and tests["verdict"] == "fail":
                    pick.observations.append(f"stage=fail:tests:{tests['detail']}")
                else:
                    break   # passed every stage, or deferred to the next cycle (the pick stands, nothing is marked)
            else:
                pick.observations.append(f"stage=fail:runs:{verdict['detail']}")
            decision = ranker.decide(
                candidates, error_message=error_message, rca_evidence=evidence, target_code=p["broken_code"],
                facts=p["ranker_facts"], deciding_rule=(f["rule_ids"] or [None])[0], row_rules=list(f["rule_ids"] or []))
        if gate_log:
            row["gate"] = gate_log
        if agent_cands:
            # Item 6 (owner 2026-10-08): ONE record per attempt — where it stands and, when it failed, exactly what
            # broke (stage, detail, the probe: inputs / traceback / newly failing tests) — published on the row the
            # agent reads with cr_row, and in the Ranker's facts.
            report = _attempt_report(agent_cands, judged_before + gate_log, decision.pick)
            row["attempts"] = report
            p["ranker_facts"]["gate"] = report
            # Item 7: the cap reached and nothing integrated (or waiting) — the row is HELD for the owner with every
            # attempt and what broke it; cr_submit refuses further attempts on it.
            from .solution_gate import MAX_ATTEMPTS
            live = [a for a in report if a["status"] in ("integrated", "deferred", "not_judged")]
            if len(report) >= MAX_ATTEMPTS and not live:
                row["held_for_owner"] = {
                    "reason": f"{len(report)} agent attempts, none integrated — the cap is {MAX_ATTEMPTS}",
                    "attempts": [{k: a[k] for k in ("attempt", "attempt_id", "note", "status", "stage", "detail")}
                                 for a in report]}
        row["selection"] = {r["role"]: r["selection_total"] for r in decision.considered if "selection_total" in r}
        facts = tester_facts + facts
        why = ("; ".join(facts) + "; " if facts else "") + decision.why

        if decision.pick is not None:
            pick = decision.pick
            digest = _candidate_digest(pick)
            row["decision"] = {"pick_role": pick.role, "why": why}
            row["solution_kind"] = "prescribed" if pick.source == "prescribed" else "rewriter"
            row["fix"] = pick.solution
            row["before_code"] = pick.before_code
            row["after_code"] = pick.after_code
            row["digest"] = digest
            row["tester"] = _tester_field(digest, conf)
            return row

        row["decision"] = {"pick_role": None, "why": why}
        kinds = {g["kind"] for g in consulted}
        if candidates:
            row["no_fix_status"] = "ranker_none"
        elif "rewriter" in kinds:
            row["no_fix_status"] = "declined"
        elif "no_fix_by_design" in kinds:
            row["no_fix_status"] = "no_fix_by_design"
        elif "unbuilt" in kinds:
            row["no_fix_status"] = "unbuilt"
        else:
            row["no_fix_status"] = "no_generator"
        return row

    @staticmethod
    def _summary(rows: dict[str, dict[str, Any]], state: dict[str, Any],
                 channel: dict[str, Any] | None = None) -> dict[str, Any]:
        live = [r for r in rows.values() if not r.get("exonerated")]
        with_fix = sum(1 for r in live if r.get("digest"))
        no_fix = {s: sum(1 for r in live if r.get("no_fix_status") == s) for s in NO_FIX_STATUSES}
        confirmed = sum(1 for r in live if (r.get("tester") or {}).get("confirmed"))
        channel = channel or {}
        return {
            "findings": len(live),
            "with_fix": with_fix,
            # FIX_41: with_fix by the kind of solution the Ranker picked (a prescription counts as a solution)
            "solution_kinds": {k: sum(1 for r in live if r.get("digest") and (r.get("solution_kind") or "rewriter") == k)
                               for k in ("rewriter", "prescribed")},
            "no_fix": no_fix,
            "whitelisted": sum(1 for r in rows.values() if r.get("exonerated")),
            # item 6 (owner 2026-09-09): the measure — how many of the solutions the tester
            # confirmed; no failure kinds. orphans / unparsed / channel_lines = the channel's own
            # accounting (never silent).
            "tester": {
                "confirmed": confirmed,
                "solutions": with_fix,
                "orphans": int(channel.get("orphans", 0)),
                "unparsed": int(channel.get("unparsed", 0)),
                "channel_lines": int(channel.get("channel_lines", 0)),
            },
            "validator": dict(state.get("summary") or {}),
        }


# ── Mirror (moved from the validator's stage_output, item 1) ─────────────────

def _fanout_dirs(repo: Path) -> list[Path]:
    """Every directory of the target that receives a mirror: the root and each directory that holds a LIVE .py
    or lies on the path from the root down to one (FIX_35 e, 2026-09-15, run 111 launch B: the old os.walk with
    name tests wrote `.noai_state.json` into a 15 MB venv-by-size dir whose every file the whitelist names —
    4 mirrors under `venv_shape/` — and skipped dot-dirs by name against FIX_13). The ONE walk:
    `scan_scope.iter_live_py` (whitelist, engine hard-skips, containment — never a symlink, never outside)."""
    import sys as _sys
    _ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
    if _ss not in _sys.path:
        _sys.path.insert(0, _ss)
    import scan_scope  # type: ignore
    root = repo.resolve()
    live_dirs: set[Path] = set()
    for py in scan_scope.iter_live_py(repo):
        d = py.parent
        while d.resolve() != root and d not in live_dirs:
            live_dirs.add(d)
            d = d.parent
    return [repo] + sorted(live_dirs)


def _rule_outcomes(rows: dict[str, dict[str, Any]], return_channel: str) -> dict[str, Any]:
    """B9 (ruling Q3, 2026-09-20): the per-rule accumulation the mirror publishes as
    `summary.rule_outcomes`, computed at write time from the confirmed ledger and the return
    channel — the two files that already exist. The rule is spelled ONCE, in `gearbox`, beside
    `read_confirmed_ledger` and `confirmed_ledger_path`, and the tester report derives its own copy
    from the same function; the import is the idiom `_cadence_offset_s` already uses. A mirror write
    is never lost to this: the block is empty when the channel has no path or the read fails.
    (The shape is one `if` and no early return on purpose — a guard clause and an `except: return`
    are both pre-ranker hunter sites, and S4-3 cut four of them out of `gearbox.py` the same way.)"""
    block: dict[str, Any] = {}
    if return_channel:
        try:
            import sys as _sys
            _sys.path.insert(0, str(SYS_SCRIPTS))
            import gearbox as _gearbox
            block = dict(_gearbox.rule_outcomes(rows, Path(return_channel)))
        except Exception as exc:
            logger.warning("rule_outcomes not staged this cycle: %s", exc)
    return block


#: T-08 (R7, 2026-09-30): strings the rule-id reader returns that are not a rule — never a mirror rule id.
_MIRROR_ID_MARKERS = frozenset({"MEASURED-NOTHING"})


def _mirror_ids(row: dict[str, Any]) -> tuple[list[str], list[str]]:
    """T-08 (R7, 2026-09-30): (rule_ids, context_ids) for one mirror row. rule_ids = the validator's DECIDING
    ids — the one that decided the verdict first (the validator orders it so), then the other deciding ids;
    no context id, no marker. Every other id the row carried (its context_ids, plus anything in
    rule_ids_all that is not deciding) goes to context_ids. The mirror published rule_ids_all as
    rule_ids before, so a context marker could lead the list."""
    deciding = [i for i in dict.fromkeys(row.get("rule_ids") or []) if i not in _MIRROR_ID_MARKERS]
    context = [i for i in dict.fromkeys(list(row.get("context_ids") or []) + list(row.get("rule_ids_all") or []))
               if i not in deciding]
    return deciding, context


def stage_mirror(rows: dict[str, dict[str, Any]], state: dict[str, Any], summary: dict[str, Any],
                 *, target_repo: str, return_channel: str,
                 system_copy: Path | None = None, severed_links: list | None = None) -> tuple[int, int, int]:
    """Write .noai_state.json: repairs[] (apply these — every row the Ranker picked,
    with its digest) + no_vetted_fix[] (finding only + status; the reason lives ONLY in
    BUILDER_STATE.json rows[].decision.why). Whitelisted rows in neither.
    Returns (repairs, no_vetted_fix, dirs_written)."""
    repairs: list[dict[str, Any]] = []
    no_vetted_fix: list[dict[str, Any]] = []
    # I-131 (session 8, run 160) — THE REFUSAL AT PUBLISH. The writer is fixed twice over (the
    # validator's incremental rescan and the Builder's row writer), and a third reader still refuses:
    # a span that is not `1 <= line <= line_end <= len(file)` is NEVER published as a repair. The row
    # is published all the same — `no_vetted_fix[]` with status `corrupt_span` and a withheld entry
    # carrying the reason — so I-129's identity (every failing unit in exactly one bucket) holds.
    _repo_for_len = Path(target_repo) if target_repo else None
    _len_cache: dict[str, int] = {}

    def _file_lines(rel: str) -> int:
        if rel not in _len_cache:
            n = 0
            if _repo_for_len is not None:
                try:
                    n = len((_repo_for_len / rel).read_text(encoding="utf-8", errors="replace").splitlines())
                except Exception:
                    n = 0
            _len_cache[rel] = n
        return _len_cache[rel]

    def _span_refusal(row: dict[str, Any]) -> str:
        """'' when the row's span is applyable; the reason it is not otherwise."""
        line, end = row.get("line"), row.get("line_end")
        if not isinstance(line, int) or not isinstance(end, int) or line <= 0 or end <= 0:
            return f"corrupt span: line {line!r}, line_end {end!r} — not a pair of source lines"
        if end < line:
            return f"corrupt span: line_end {end} precedes line {line}"
        n = _file_lines(row.get("file", ""))
        if n and end > n:
            return f"corrupt span: line_end {end} is past the end of {row.get('file')} ({n} lines)"
        return ""

    span_refused: list[dict[str, Any]] = []
    for row in sorted(rows.values(), key=lambda r: (r["fix_order"], r["file"], r["line"])):
        if row.get("exonerated"):
            continue
        _rids, _cids = _mirror_ids(row)   # T-08 (R7): deciding ids first, context apart, no markers
        base = {
            "file": row["file"],
            "function": row["function"],
            "line": row["line"],
            "line_end": row["line_end"],
            "replace_span": row["replace_span"],
            "finding_lines": row["finding_lines"],
            "rule_ids": _rids,
            "context_ids": _cids,
            "infraction": row["infraction"],
        }
        # S9-T1 (I-150 follow-up): a candidate G0 withheld is published WITH its sentence, on whatever
        # bucket the row lands in. Additive — a row with nothing withheld carries no such key and no
        # published row's shape moves.
        if row.get("gate_withheld_reasons"):
            base["gate_withheld"] = {k: v for k, v in row["gate_withheld_reasons"].items() if v}
        _refusal = _span_refusal(row)
        if row.get("digest") and _refusal:
            # Published, never as a repair: an unapplyable span is a finding with no vetted fix.
            span_refused.append({**base, "reason": _refusal, "row_key": row.get("row_key", "")})
            # The row is published — it is a failing unit and must be in a bucket — but NOT with a
            # span it does not have: `line_end` and `replace_span` read null rather than a number
            # no reader can act on, and the measured pair is in the refusal reason below.
            no_vetted_fix.append({**base, "line_end": None, "replace_span": None,
                                  "status": "corrupt_span"})
        elif row.get("digest"):
            repairs.append({
                **base,
                "fix": row["fix"],
                "before_code": row["before_code"],
                "after_code": row["after_code"],
                "selected_role": row["decision"]["pick_role"],
                "solution_kind": row.get("solution_kind") or "rewriter",   # FIX_41
                "digest": row["digest"],
                # I-152 / Q1 (session 10): the APPLY STATE, published beside the offer rather
                # than inferred from the bucket. A repairs row reached here with a pick the
                # selector's bar let through, so it is an offer an unattended seat can act on —
                # when it renders a concrete diff. Fix A (owner 2026-09-28): a prescribed shape is
                # the rule's template, never rendered at the site, so it is `review`, not `yes`
                # (label only; the row stays in repairs). `read_tools._row_record` says the same.
                "apply": ("review" if (row.get("solution_kind") or "rewriter") == "prescribed"
                          else "yes"),
                "withheld_by": row.get("withheld_by"),
                "return_channel": return_channel,
            })
        else:
            # status only — the mirror repeats the dash, and the dash never labels a kind of
            # failure (owner 2026-09-09).
            # I-152 / Q1: …plus the apply state. `selected_role ""` and `apply "no"` are the
            # truth of every no-vetted-fix row, and `withheld_by` names the seam when the reason
            # there is no offer is that no candidate renders unattended
            # (`gate.prescription_check`). The row is NOT flipped to withheld: it is here, in a
            # bucket, and `failed == repairs + no_vetted_fix` is unmoved.
            no_vetted_fix.append({**base, "status": row.get("no_fix_status") or "unbuilt",
                                  "selected_role": "", "apply": "no",
                                  "withheld_by": row.get("withheld_by")})

    # FIX_51 (owner Q11, 2026-09-15): the WITHHELD rows ride in the mirror too. The ranker withheld its
    # verdict because of the file's SPECIES (a library's tests; a proxy), so the row is a published PASS
    # that is not a clean pass — neither a repair nor a no_vetted_fix, and until now it was in the state
    # and on no screen (I-17). The ids ride as they were published: context, never a verdict.
    withheld_rows: list[dict[str, Any]] = []
    for _rel, _entries in (state.get("results_by_file") or {}).items():
        for _e in _entries:
            if not _e.get("withheld") or _e.get("whitelisted"):
                continue
            withheld_rows.append({
                "file": _rel,
                "function": _e.get("function", ""),
                "line": _e.get("line"),
                "line_end": _e.get("end_line"),
                "species": _e.get("species", "") or "",
                "withheld": _e.get("withheld", "") or "",   # the reason, the validator's string verbatim
                "withheld_by": "species",
                "withheld_reason": _e.get("withheld", "") or "",
                "rule_ids": list(_e.get("rule_ids") or []),
                "context_ids": list(_e.get("context_ids") or []),
            })
    # S5-1 (2026-09-17, packet §B): the GATE's withheld rows ride in the same block. FIX_51's loop above
    # reads the validator's state, which knows nothing of G0 — a row whose every candidate the gate
    # withheld had no path onto any screen. It has one now: same shape, `withheld_by: "gate"` and the
    # gate's sentence as the reason, so the shape lane can render it and cr_infractions(withheld=true)
    # shows it. The row is also in no_vetted_fix[] (it has no digest) — this block is where the REASON is.
    # Q5 (owner, 2026-09-20) / I-107: the BY-DESIGN withheld row rides in the same block, the third
    # and last `withheld_by` value — NAI-094 on the file FIX_50 exempts as `role == entry`. Same
    # shape, same reader: `cr_infractions(withheld=true)` lists it and FIX_51's badge counts it.
    n_gate = n_by_design = 0
    for row in rows.values():
        by = row.get("withheld_by")
        if by not in ("gate", BY_DESIGN_WITHHELD) or row.get("exonerated"):
            continue
        if by == "gate":
            n_gate += 1
        else:
            n_by_design += 1
        reason = row.get("withheld_reason", "") or (
            "gate: withheld" if by == "gate" else "withheld (by design)")
        withheld_rows.append({
            "file": row["file"],
            "function": row["function"],
            "line": row["line"],
            "line_end": row["line_end"],
            "species": row.get("species", "") or "",
            "withheld": reason,
            "withheld_by": by,
            "withheld_reason": reason,
            "rule_ids": _mirror_ids(row)[0],      # T-08 (R7): deciding ids first, no context, no markers
            "context_ids": _mirror_ids(row)[1],
            "replace_span": row.get("replace_span"),
        })
    # I-131: every span-refused row rides the withheld block with the refusal as its reason, so the
    # reason for a repair not being offered lives where every other withholding reason lives.
    # I-144 (session 10, run 174): and with the SAME null span the `no_vetted_fix[]` copy carries.
    # This block used to repeat the measured corrupt pair (`line 29, line_end 7`) verbatim, so the
    # one row the publisher had just refused was the one row in the mirror still offering a span
    # no reader can act on — the withheld bucket is where I-144's 43 rows lived too. The measured
    # pair is not lost: `withheld_reason` quotes both numbers, as evidence rather than as a span.
    for _sr in span_refused:
        withheld_rows.append({
            "file": _sr["file"], "function": _sr["function"], "line": _sr["line"],
            "line_end": None, "species": "",
            "withheld": _sr["reason"], "withheld_by": "publisher", "withheld_reason": _sr["reason"],
            "rule_ids": list(_sr.get("rule_ids") or []), "context_ids": list(_sr.get("context_ids") or []),
            "replace_span": _sr.get("replace_span"),
        })
    if span_refused:
        # Every one of them, never a head slice: a truncated defect list is how 41 units stayed
        # invisible for five runs.
        logger.warning("[MIRROR] %d row(s) refused as repairs — corrupt span (I-131): %s",
                       len(span_refused), "; ".join(f"{r['file']}::{r['function']}::{r['line']} {r['reason']}"
                                                    for r in span_refused))
    withheld_rows.sort(key=lambda r: (r["file"], r["line"] or 0))

    vsum = state.get("summary") or {}
    _not_scanned = list(vsum.get("files_not_scanned") or [])
    n_findings = len(repairs) + len(no_vetted_fix)
    # I-129 (session 8, run 160) — ONE NUMBER, ONE SOURCE. `failed` used to be copied from the
    # validator's own summary (`vsum["failed"]`) and published BESIDE buckets built from a different
    # collection; when the two disagreed nothing said so, and run 155 shipped `failed` 187 against
    # repairs 71 + no_vetted_fix 75 = 146 with 41 failing units reachable through neither. `failed` is
    # now COMPUTED FROM THE BUCKETS. The validator's count is published beside it, never instead of
    # it, with the gap named: a non-zero `bucket_gap` is a defect, and it is now visible as one.
    _failed_validator = int(vsum.get("failed", 0) or 0)
    _bucket_keys = {(r["file"], r["function"], r["line"]) for r in repairs + no_vetted_fix}
    # A failing unit published ONLY in the withheld block would be in no bucket; there is no such
    # path today (a gate / by-design / span-refused row is always a no_vetted_fix row too) and the
    # count is published so the three-term identity `failed == repairs + no_vetted_fix + withheld_failed`
    # is something a reader can check rather than something the publisher asserts.
    _withheld_failed = sum(1 for w in withheld_rows
                           if w.get("withheld_by") in ("gate", BY_DESIGN_WITHHELD, "publisher")
                           and (w["file"], w["function"], w["line"]) not in _bucket_keys)
    _failed = len(repairs) + len(no_vetted_fix) + _withheld_failed
    if _failed != _failed_validator:
        logger.error("[MIRROR] bucket gap (I-129): the validator counts %d failed, the published "
                     "buckets hold %d (repairs %d + no_vetted_fix %d + withheld-only %d)",
                     _failed_validator, _failed, len(repairs), len(no_vetted_fix), _withheld_failed)
    if severed_links is None:
        try:
            severed_links = (read_file_locked(CIRCUIT_STATE_FILE) or {}).get("severed_links") or []
        except Exception:
            severed_links = []
    _severed = [p for p in severed_links if isinstance(p, (list, tuple)) and len(p) == 2]
    mirror = {
        # Last plan 1a: a file the scan could not judge never reads as clean.
        "status": (f"{n_findings} FINDINGS" if n_findings else "ALL CLEAR")
                  + (f" · {len(_not_scanned)} FILE(S) NOT SCANNED" if _not_scanned else ""),
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "target_repo": target_repo,
        "summary": {
            "total_functions": vsum.get("total_functions", 0),
            "passed": vsum.get("passed", 0),
            # I-129: computed from the buckets below, never copied from beside them.
            "failed": _failed,
            # …and the validator's own count, published beside it with the gap named (0 = they agree).
            "failed_validator": _failed_validator,
            "bucket_gap": _failed_validator - _failed,
            "files_scanned": vsum.get("files_scanned", 0),
            "files_not_scanned": _not_scanned,
            "repairs": len(repairs),
            "no_vetted_fix": len(no_vetted_fix),
            # I-129: failing units published ONLY in the withheld block — the third term of
            # `failed == repairs + no_vetted_fix + withheld_failed`. 0 on every healthy run.
            "withheld_failed": _withheld_failed,
            # I-131: rows refused as repairs because their span is not applyable.
            "span_refused": len(span_refused),
            "whitelisted": summary.get("whitelisted", 0),
            # FIX_51: the same number the validator's own summary line carries
            "withheld": len(withheld_rows),
            # S5-1: of those, the rows G0 withheld (the rest are the validator's species withholding)
            "withheld_gate": n_gate,
            # Q5 / I-107: and of those, the rows withheld BY DESIGN (NAI-094 on the entry role)
            "withheld_by_design": n_by_design,
            # B9 (Q3, 2026-09-20): what the tester has said about each RULE, accumulated over the
            # whole ledger and the whole channel. A published record only — no disposition moves.
            "rule_outcomes": _rule_outcomes(rows, return_channel),
        },
        "repairs": repairs,
        "no_vetted_fix": no_vetted_fix,
        # FIX_51 (owner Q11): shown, not merely counted — each row with the reason it was withheld.
        "withheld": withheld_rows,
        "flagged_nodes": sorted(state.get("flagged_nodes") or []),
        "return_channel": return_channel,
        # ITEM 11 (2026-09-15, owner B8): the mirror carries ONLY the severed connections, as text, red —
        # the circuit daemon's `severed_links` copied verbatim; nothing else of the graph.
        "wiring": {"severed": [list(p) for p in _severed], "drawn": "red"},
    }

    written = 0
    # system_copy: the engine-side copy (system_scripts/.noai_state.json); the health
    # gate's fixture passes its own path so a launch never sees a fixture mirror.
    write_file_locked(system_copy or (SYS_SCRIPTS / MIRROR_NAME), mirror)
    repo = Path(target_repo) if target_repo else None
    if repo is not None and repo.is_dir():
        fanout = _fanout_dirs(repo)  # puts system_scripts on sys.path
        import scan_scope  # type: ignore
        for d in fanout:
            try:
                # owner ruling 2026-09-28: into <target>/.coderadar/<rel>/, never the code folder itself
                write_file_locked(scan_scope.mirror_path(repo, d, MIRROR_NAME, create=True), mirror)
                written += 1
            except Exception:
                pass
    return len(repairs), len(no_vetted_fix), written


# ── Return channel (item 5, 2026-09-09) ─────────────────────────────────────

TESTER_LOG_CHARS = 2000  # the slice of a failure log that joins the row's evidence (plan step 4)


def _parse_channel_line(raw: str) -> dict[str, Any] | None:
    """One tester line → the record below, or None when the line is not the contract (counted as
    unparsed by the caller, never dropped silently).
    Contract: {"digest": str, "replace_span": str, "outcome": "confirmed"|"failed",
    "failure_log": str, "tester": str, "timestamp": iso}.

    Q1 / I-122 (session 7, the drift fix): the line may ALSO carry its own pre-edit identity —
    `row_key`, `rule_ids`, `variant`, `file`, `function`. They are carried through here with
    empty defaults and NOTHING is rejected on their account: a line written before session 7
    parses exactly as it did, and the three keys the contract has always required are still the
    three keys that decide. Whatever reads a line prefers the LINE's identity over the row's,
    because the row is the thing that drifts (I-119 / I-125 / I-130 / I-138)."""
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    digest, span, outcome = doc.get("digest"), doc.get("replace_span"), doc.get("outcome")
    if not (isinstance(digest, str) and digest and isinstance(span, str) and span
            and outcome in ("confirmed", "failed")):
        return None
    return {
        "digest": digest,
        "replace_span": span,
        "outcome": outcome,
        "failure_log": str(doc.get("failure_log") or ""),
        "tester": str(doc.get("tester") or ""),
        "timestamp": str(doc.get("timestamp") or ""),
        "row_key": str(doc.get("row_key") or ""),
        "rule_ids": [str(r) for r in (doc.get("rule_ids") or []) if r],
        "variant": str(doc.get("variant") or ""),
        "file": str(doc.get("file") or ""),
        "function": str(doc.get("function") or ""),
    }


def _leased_keys(channel: str) -> set[str]:
    """Every `row_key` the server has handed out on this channel — `apply_lease_<repo_id>.jsonl`
    beside it, by the writer's own naming rule (`coderadar_mcp.write_tools._lease_path`; the
    reader is `gearbox.read_apply_lease`, so the rule is spelled once). Empty when no lease file
    exists, which is every channel written before session 7.

    (The shape is one `if` and no early return on purpose — a guard clause and an
    `except: return` are both pre-ranker hunter sites (V18), and `_rule_outcomes` below is
    written the same way for the same reason.)"""
    keys: set[str] = set()
    if channel:
        try:
            import sys as _sys
            _sys.path.insert(0, str(SYS_SCRIPTS))
            import gearbox as _gearbox
            keys = set(_gearbox.read_apply_lease(_gearbox.apply_lease_path(Path(channel))))
        except Exception as exc:
            logger.warning("apply lease not read this cycle: %s", exc)
    return keys


def _join_channel(lines: list[dict[str, Any]], rows: dict[str, dict[str, Any]],
                  leased: set[str] | None = None,
                  ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]], int]:
    """Join the tester's lines to the rows on digest AND (span OR the line's own file+function).
    Returns (failed, confirmed, orphans):
      failed    — row_key → one entry per digest the tester failed among those the row has
                  carried (the current digest and the tester=failed:<digest> tokens already in
                  its evidence), the LATEST line for that digest deciding;
      confirmed — row_key → the latest line for the row's CURRENT digest when it says confirmed;
      orphans   — lines that match no row at all AND do not name a LEASED row the Builder has
                  since retired (plan step 7; the retire clause is session 7's, below).
    `leased` is the set of `row_key`s `cr_apply` has handed out on this channel; nothing is
    passed for an archived channel and the count is then exactly what it always was.

    Q1 / I-130 (session 7): the second half of the key is now `replace_span` EXACT **or** the
    line's own `file` + `function` equal to the row's *while the row has been RE-KEYED under
    it*. Both halves are positional facts, and run 155 watched them move under a live seat:
    every hoist shifted the rows below it (`_pipepager` 549→550→552, `utils.py::__getattr__`
    re-keyed 669→558), so a row that came back re-keyed could never be joined to the line that
    reported it.

    The re-key clause is what makes the widening safe, and it is not decoration. "The right
    digest with the WRONG SPAN is a silent orphan" is a real safety property (I-138) and T3's
    write-path proof asserts it: a line that names a span its own row never had must not be
    credited to that row. The line says which row it was handed (`row_key`), so the two cases
    are told apart by the line itself rather than guessed:
      * `row_key` == the row's key and the spans differ → the line names a span this row never
        had. ORPHAN, exactly as before.
      * `row_key` != the row's key → the row has been re-keyed since the line was written; the
        file and function are the identity that survived. JOIN.
    A line written before session 7 carries no `row_key`, `file` or `function`, so neither
    clause can fire on it and the old join stands untouched — nothing that joined before stops
    joining, nothing that orphaned before is credited now, and the digest still has to match."""
    by_digest: dict[str, list[dict[str, Any]]] = {}
    for ln in lines:
        by_digest.setdefault(ln["digest"], []).append(ln)
    failed: dict[str, list[dict[str, Any]]] = {}
    confirmed: dict[str, dict[str, Any]] = {}
    joined: set[int] = set()

    def _re_keyed_here(ln: dict[str, Any], key: str, row: dict[str, Any]) -> bool:
        """The line and the row name the same function, and the row is no longer at the key the
        line was handed. Only a line that CARRIES the identity can answer yes, so this is never
        a guess about an old line."""
        lf, lfn, lkey = (str(ln.get("file") or ""), str(ln.get("function") or ""),
                         str(ln.get("row_key") or ""))
        if not (lf and lkey) or lkey == key:
            return False
        return lf == str(row.get("file") or "") and lfn == str(row.get("function") or "")

    for key, row in rows.items():
        span = row.get("replace_span")
        known: list[str] = []
        earlier = [e[len("tester=failed:"):] for e in (row.get("rca_evidence") or []) if e.startswith("tester=failed:")]
        for d in [row.get("digest")] + earlier:
            if d and d not in known:
                known.append(d)
        for d in known:
            matching = [ln for ln in by_digest.get(d, [])
                        if ln["replace_span"] == span or _re_keyed_here(ln, key, row)]
            if not matching:
                continue
            joined.update(id(ln) for ln in matching)
            latest = matching[-1]
            entry = {"digest": d, "failure_log": latest["failure_log"], "tester": latest["tester"],
                     "timestamp": latest["timestamp"]}
            if latest["outcome"] == "failed":
                failed.setdefault(key, []).append(entry)
            elif d == row.get("digest"):
                confirmed[key] = entry
    # I-138 / run 158, launch A: "the server and the client do not agree on what an orphan is."
    # A line that joins nothing has two quite different causes, and until session 7 the Builder
    # could not tell them apart because a line carried no name for the row it reported:
    #   * the row it names has been RETIRED — the repair worked, so the infraction is gone and
    #     with it the only thing the line could have joined. That is the SUCCESS case, and it is
    #     the case every `resolved_by: "lease"` report is in. Counting it as an orphan is what
    #     made run 155's `cr_hand_back` say `orphans 0 · orphans_channel 4` while the client
    #     counted 8 rows it could not report at all;
    #   * the line names a row that is STILL THERE and still did not join — a real mismatch, the
    #     right digest with the wrong span. That is an orphan and stays one.
    # The clause turns on the SERVER'S OWN MEMORY, not on the line's word: the key must be one
    # `cr_apply` LEASED. So a channel with no lease file beside it — every channel written
    # before session 7, and every archived one replayed since — counts exactly as it always did,
    # and `leased` defaults to nothing for every caller that does not pass it.
    held = leased or set()
    orphans = retired = 0
    for ln in lines:
        if id(ln) in joined:
            continue
        key = str(ln.get("row_key") or "")
        if key and key in held and key not in rows:
            retired += 1
        else:
            orphans += 1
    if retired:
        logger.info(f"[CHANNEL] {retired} line(s) report a LEASED row the Builder has since "
                    f"retired (the repair removed its own row) — reported, not orphaned; "
                    f"{orphans} orphan(s) remain")
    return failed, confirmed, orphans


def _tester_field(digest: str | None, conf: dict[str, Any] | None) -> dict[str, Any]:
    """rows[].tester — whether the tester CONFIRMED the row's current solution (item 5 step 6;
    owner 2026-09-09: this is the only tester fact a row carries — no failure kinds)."""
    if digest and conf and conf.get("digest") == digest:
        return {"confirmed": True, "tester": conf.get("tester", ""), "timestamp": conf.get("timestamp", "")}
    return {"confirmed": False, "tester": "", "timestamp": ""}


# ── Daemon ───────────────────────────────────────────────────────────────────

def _read_bytes_locked(path: Path) -> bytes:
    """The validator's state as bytes under the shared lock (sha256 is over these bytes)."""
    try:
        with open(path, "rb") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                return f.read()
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except (FileNotFoundError, OSError):
        return b""


class BuilderDaemon:
    """Reads the validator's findings, builds, publishes BUILDER_STATE.json + the mirror."""

    def __init__(self) -> None:
        self.builder = CheatsheetBuilder()
        self.rows: dict[str, dict[str, Any]] = {}
        self.summary: dict[str, Any] = {}
        self.target_repo: str = ""
        self.repo_id: str = ""
        self.whitelist_functions: set[str] = set()
        self.source_mtime: float | None = None
        self.source_sha: str = ""
        self.source_last_scan: str = ""
        self.last_state: dict[str, Any] | None = None   # the validator's last parsed state (item 5: a
                                                          # channel-only change rebuilds against it)
        self.channel_offset = 0                           # bytes of return_channel_<id>.jsonl consumed
        self.channel_lines: list[dict[str, Any]] = []     # every parsed line so far, file order
        self.channel_unparsed = 0                         # malformed lines seen (never dropped silently)
        self.entry_role: set[str] = set()                 # Q5 / I-107: the files FIX_50 exempts as `role == entry`
        self.attempts_stat: tuple[int, int] = (0, 0)      # solution gate: (size, mtime_ns) of attempts_<id>.jsonl
        self.intent_applied_hash = ""                     # owner 2026-09-30 (Lane A): the intent hash the rows were
        self.intent_applied_cycle = 0                     # ranked under, and the cycle that ranked them
        self.cycle = 0
        self.last_build = ""
        self.phase = "STARTING"
        self._stop = asyncio.Event()

    # -- state file -----------------------------------------------------------

    @property
    def return_channel(self) -> str:
        return str(SYS_SCRIPTS / f"return_channel_{self.repo_id}.jsonl") if self.repo_id else ""

    def write_state(self, phase: str, detail: str = "") -> None:
        """tmp + replace on every write — the dashboard never sees a half-written file."""
        self.phase = phase
        doc = {
            "phase": phase,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_repo": self.target_repo,
            "repo_id": self.repo_id,
            "source": {
                "path": str(NOAI_STATE_FILE),
                "mtime": self.source_mtime,
                "sha256": self.source_sha,
                "last_scan": self.source_last_scan,
            },
            "cycle": self.cycle,
            "last_build": self.last_build,
            "return_channel": self.return_channel,
            "summary": self.summary,
            "rows": self.rows,
        }
        BUILDER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=BUILDER_STATE_FILE.parent, prefix=".BUILDER_STATE_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f, indent=2, default=str)
            os.replace(tmp, BUILDER_STATE_FILE)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def reset_for_target(self, target_repo: str) -> None:
        """Target change → everything from the previous target goes (the Builder's own
        files only: BUILDER_STATE.json and the system_scripts mirror copy)."""
        logger.info(f"Target: {self.target_repo or '(none)'} → {target_repo}")
        for p in (BUILDER_STATE_FILE, SYS_SCRIPTS / MIRROR_NAME):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        self.rows.clear()
        self.summary = {}
        self.cycle = 0
        self.last_build = ""
        self.source_sha = ""
        self.last_state = None
        self.channel_offset = 0
        self.channel_lines = []
        self.channel_unparsed = 0
        self.entry_role = set()
        self.attempts_stat = (0, 0)
        self.intent_applied_hash = ""
        self.intent_applied_cycle = 0
        self.target_repo = target_repo
        repo = Path(target_repo)
        self.repo_id = _repo_id(repo)
        _files, self.whitelist_functions = _load_whitelist(repo)
        self.write_state("WAITING", f"target set: {target_repo}")

    # -- loop -------------------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    async def _sleep(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=POLL_INTERVAL)
        except asyncio.TimeoutError:
            pass

    async def run(self) -> None:
        # FIX_46: take this daemon's slot on the circumference before the first poll.
        _off = _cadence_offset_s()
        if _off:
            logger.info(f"CADENCE: cheatsheets takes its slot at +{_off:.4f}s (FIX_46 table)")
            await asyncio.sleep(_off)
        self.write_state("STARTING", "cheatsheets up; waiting for the validator's findings")
        logger.info(f"cheatsheets daemon started — source {NOAI_STATE_FILE.name}, state {BUILDER_STATE_FILE.name}")
        _hb_cycle = 0
        _heartbeat(_hb_cycle, force=True)   # I-108: the first beat before the first poll
        while not self._stop.is_set():
            _hb_cycle += 1
            _heartbeat(_hb_cycle)
            try:
                await _beat_during(self._cycle(), _hb_cycle)   # S4: long rebuilds keep beating
            except Exception as e:
                logger.exception(f"cycle failed: {e}")
                self.write_state("WAITING", f"cycle failed: {type(e).__name__}: {str(e)[:120]}")
            await self._sleep()
        logger.info("cheatsheets daemon stopped (no final write).")

    def _read_validator_state(self) -> tuple[dict[str, Any] | None, bool]:
        """The validator's state this poll: (state, changed). (None, False) while there is nothing
        to build against (not published / not MONITORING / no target); (last_state, False) when the
        bytes are unchanged; (state, True) on new bytes."""
        try:
            st = NOAI_STATE_FILE.stat()
        except FileNotFoundError:
            if self.phase != "WAITING" or self.source_mtime is not None:
                self.source_mtime = None
                self.write_state("WAITING", "validator state not published")
            return None, False
        if st.st_mtime == self.source_mtime:
            return self.last_state, False  # nothing new on disk
        raw = _read_bytes_locked(NOAI_STATE_FILE)
        if not raw:
            return self.last_state, False
        try:
            state = json.loads(raw)
        except json.JSONDecodeError:
            return self.last_state, False  # a write in flight; next poll
        self.source_mtime = st.st_mtime

        phase = state.get("phase", "")
        if phase != "MONITORING":
            self.write_state("WAITING", f"validator phase {phase or 'unknown'}: {state.get('detail', '')}"[:200])
            return None, False
        target = state.get("target_repo", "") or ""
        if not target:
            self.write_state("WAITING", "validator state carries no target_repo")
            return None, False
        if target != self.target_repo:
            self.reset_for_target(target)

        sha = hashlib.sha256(raw).hexdigest()
        if sha == self.source_sha:
            return self.last_state, False  # mtime moved, bytes did not
        self.source_sha = sha
        self.source_last_scan = state.get("last_scan", "") or ""
        self.last_state = state
        return state, True

    def _poll_channel(self) -> bool:
        """Item 5 step 3: stat the return channel; read only the new COMPLETE lines from the offset
        kept in memory; parse; keep. Returns True when anything new arrived (parsed or malformed).
        A file shorter than the offset was rewritten → start over from byte 0."""
        if not self.return_channel:
            return False
        path = Path(self.return_channel)
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        if size < self.channel_offset:
            logger.info(f"[CHANNEL] {path.name} shrank ({self.channel_offset} → {size} bytes): re-reading from 0")
            self.channel_offset, self.channel_lines, self.channel_unparsed = 0, [], 0
        if size == self.channel_offset:
            return False
        try:
            with open(path, "rb") as fh:
                fh.seek(self.channel_offset)
                chunk = fh.read()
        except OSError as e:
            logger.warning(f"[CHANNEL] read failed: {type(e).__name__}: {e}")
            return False
        cut = chunk.rfind(b"\n")
        if cut < 0:
            return False  # a line still being written; next poll
        text = chunk[:cut + 1]
        self.channel_offset += len(text)
        parsed = unparsed = 0
        for raw in text.decode("utf-8", "replace").splitlines():
            if not raw.strip():
                continue
            line = _parse_channel_line(raw)
            if line is None:
                unparsed += 1
                continue
            self.channel_lines.append(line)
            parsed += 1
        self.channel_unparsed += unparsed
        if parsed or unparsed:
            logger.info(f"[CHANNEL] {path.name}: {parsed} new line(s), {unparsed} unparsed "
                        f"(total {len(self.channel_lines)} lines, offset {self.channel_offset})")
        return bool(parsed or unparsed)

    async def _cycle(self) -> None:
        state, state_changed = self._read_validator_state()
        if state is None:
            return
        channel_changed = self._poll_channel()
        # Q5 / I-107: the THIRD thing that can oblige a rebuild. The entry role is measured when the
        # target's entry is first RUN through the wrapper, which moves nothing in the validator's
        # state and nothing in the return channel — so without this a row whose solution Q5 withholds
        # would keep its prescription until something else happened to republish (run 157 launch B).
        role_changed = self._entry_role_changed()
        # owner 2026-09-30 (Lane A): the FOURTH thing that can oblige a rebuild — the intent file moved (a statement
        # added or changed on the dashboard, any time after cycle 1). One small read per poll hashes the file.
        intent_changed = self.builder.intent_moved(self.target_repo)
        # Solution gate (live tree 1, 2026-10-10): the FIFTH — cr_submit appended an attempt. It moves none of the four
        # above, so without this an attempt sat unjudged until the validator happened to rescan.
        attempts_changed = self._attempts_changed()
        if not state_changed and not channel_changed and not role_changed and not intent_changed \
                and not attempts_changed:
            return
        if channel_changed:
            await self._tester_facts()

        n = sum(1 for es in (state.get("results_by_file") or {}).values() for e in es or [] if not e.get("passed", True))
        why = ("validator state changed" if state_changed else
               "return channel changed" if channel_changed else
               "entry role measured" if role_changed else
               "intent changed" if intent_changed else "agent attempt filed")
        self.write_state("BUILDING", f"cycle {self.cycle + 1}: {n} findings ({why})")
        t0 = time.monotonic()
        # Join the tester's lines to the rows the Builder published; build; a row that first
        # appears this cycle can join only after it exists, so join once more and rebuild if the
        # join moved (two passes at most — the second is the fixpoint).
        # Session 7 (§C.1): the leases the server has handed out on this channel, so a line
        # whose row the Builder has since RETIRED is told apart from a line that named nothing
        # (I-138). Read once per cycle, beside the channel, never guessed.
        leased = _leased_keys(self.return_channel)
        failed, confirmed, orphans = _join_channel(self.channel_lines, self.rows, leased)
        channel = {"orphans": orphans, "unparsed": self.channel_unparsed, "channel_lines": len(self.channel_lines)}
        rows, summary = await self.builder.build_rows(
            state, previous=self.rows, whitelist_functions=self.whitelist_functions,
            failed=failed, confirmed=confirmed, channel=channel)
        failed2, confirmed2, orphans2 = _join_channel(self.channel_lines, rows, leased)
        if (failed2, confirmed2) != (failed, confirmed):
            channel["orphans"] = orphans2
            rows, summary = await self.builder.build_rows(
                state, previous=rows, whitelist_functions=self.whitelist_functions,
                failed=failed2, confirmed=confirmed2, channel=channel)
        # Item 9 (2026-09-15): the intent file's shape rides the Builder's summary too — the Builder is the writer of
        # the tester's and the docs' facts. I-23 / I-29 (run 117): the NOAI daemon now refreshes ITS copy every poll.
        try:
            import sys as _sys
            _ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
            if _ss not in _sys.path:
                _sys.path.insert(0, _ss)
            import intent_file as _intent  # type: ignore
            _idata = _intent.read(self.target_repo)
            summary["intent"] = {"statement": bool(_idata.get("statement")), "facts_by_source": _intent.facts_by_source(_idata),
                                 "file": _intent.path(self.target_repo).name,
                                 "owner": "NOAI_VALIDATION_STATE.summary.intent"}   # I-23 / I-29 (run 117): the NOAI daemon owns the published copy (refreshed every poll); this is the same file read at the Builder's write
        except Exception as e:
            summary["intent"] = {"status": "NOT MEASURED", "reason": f"{type(e).__name__}: {e}"}
        # owner 2026-09-30 (Lane A): which intent these rows were ranked under — `applied_hash` (the full
        # `intent_file.content_hash`, the dashboard compares it to the file's) and `applied_cycle` (the cycle whose
        # rows were ranked under it). Moves only when the ranker was rebuilt under a new hash.
        built_hash = self.builder._intent_hash or ""
        if built_hash != self.intent_applied_hash:
            self.intent_applied_hash, self.intent_applied_cycle = built_hash, self.cycle + 1
        summary["intent"]["applied_hash"] = self.intent_applied_hash
        summary["intent"]["applied_cycle"] = self.intent_applied_cycle
        self.rows, self.summary = rows, summary
        self.cycle += 1
        self.last_build = datetime.now(timezone.utc).isoformat()
        nf = summary["no_fix"]
        ts = summary["tester"]
        detail = (f"cycle {self.cycle}: {summary['findings']} findings, {summary['with_fix']} with fix, "
                  f"no fix {sum(nf.values())} ({', '.join(f'{k} {v}' for k, v in nf.items() if v)}), "
                  f"{summary['whitelisted']} whitelisted; tester confirmed {ts['confirmed']} of {ts['solutions']} solutions"
                  + (f", {ts['orphans']} orphan line(s)" if ts['orphans'] else "")
                  + (f", {ts['unparsed']} unparsed line(s)" if ts['unparsed'] else "")
                  + f" — {time.monotonic() - t0:.1f}s")
        self.write_state("MONITORING", detail)
        n_rep, n_nvf, n_dirs = stage_mirror(rows, state, summary, target_repo=self.target_repo,
                                            return_channel=self.return_channel)
        logger.info(f"[BUILD] {detail}")
        logger.info(f"[MIRROR] {MIRROR_NAME} → system_scripts + {n_dirs} target dirs ({n_rep} repairs, {n_nvf} no_vetted_fix)")
        await self._doc_facts_once(state)

    def _entry_role_changed(self) -> bool:
        """Q5 / I-107: has the set of files FIX_50 exempts as `role == entry` moved since the last
        poll? Read from `circuit_state.json`, the file the build already reads for its whole-set
        facts; the set holds at most the one measured entry, so the comparison is a set comparison."""
        now = _entry_role_files(read_file_locked(CIRCUIT_STATE_FILE) or {})
        changed = now != self.entry_role
        self.entry_role = now
        return changed

    def _attempts_changed(self) -> bool:
        """Solution gate: has attempts_<repo_id>.jsonl (cr_submit's append-only store, beside the return channel)
        grown or been replaced since the last poll? Size + mtime, one stat per poll; a missing file reads as (0, 0)."""
        if not self.repo_id:
            return False
        try:
            st = (SYS_SCRIPTS / f"attempts_{self.repo_id}.jsonl").stat()
            now = (st.st_size, st.st_mtime_ns)
        except OSError:
            now = (0, 0)
        changed = now != self.attempts_stat
        self.attempts_stat = now
        return changed

    async def _tester_facts(self) -> None:
        """Item 9 (2026-09-15): every NEW failed return-channel line → discrete facts by the fixed rules
        (`intent_file.extract_failure_log_facts`, source "tester", evidence = the digest) appended to the intent
        file (dedupe there); `seen_digests` in memory so a digest is read once. New facts → the cached Ranker is
        dropped so THIS cycle's build re-decides with the profile that now holds them (Item 5's route)."""
        target = self.target_repo
        if not target:
            return
        seen: set[str] = getattr(self, "_intent_seen_digests", set())
        idx: int = getattr(self, "_intent_channel_idx", 0)
        new = self.channel_lines[idx:]
        self._intent_channel_idx = len(self.channel_lines)
        if not new:
            return
        try:
            import sys as _sys
            _ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
            if _ss not in _sys.path:
                _sys.path.insert(0, _ss)
            import intent_file as _intent  # type: ignore
        except Exception as e:
            logger.warning(f"[INTENT] tester facts not written: {type(e).__name__}: {e}")
            return
        total_added = 0
        for ln in new:
            if ln.get("outcome") != "failed" or ln.get("digest") in seen:
                continue
            seen.add(ln["digest"])
            try:
                facts = _intent.extract_failure_log_facts(ln, target)
                _, added = _intent.append_facts(target, facts)
            except Exception as e:
                logger.warning(f"[INTENT] tester facts not written for {ln.get('digest')}: {type(e).__name__}: {e}")
                continue
            total_added += added
            logger.info(f"[INTENT] +{added} fact(s) from tester (digest {ln['digest']}; {len(facts)} extracted, "
                        f"{[f['fact'] for f in facts]})")
        self._intent_seen_digests = seen
        if total_added:
            self.builder._ranker = None
            self.builder._ranker_target = None
            logger.info(f"[INTENT] profile re-read this cycle ({total_added} new tester fact(s))")

    async def _doc_facts_once(self, state: dict[str, Any]) -> None:
        """FIX_33 step 3 (Item 8, 2026-09-15): ONCE per target, after the first build — the context manager's
        `doc_facts_async(keywords from the findings)` appended to the intent file (`intent_file.append_facts`
        dedupes). Keywords = the failing functions' names + the significant words of their failure reasons,
        through `extract_keywords_from_context` (the same extractor RCA uses). Nothing ranked."""
        target = self.target_repo
        if not target or getattr(self, "_doc_facts_target", None) == target:
            return
        self._doc_facts_target = target
        try:
            import sys as _sys
            _ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
            if _ss not in _sys.path:
                _sys.path.insert(0, _ss)
            import intent_file as _intent  # type: ignore
            from rca_main.context_gathering_manager import ContextManager
            failed = [(rel, e) for rel, es in (state.get("results_by_file") or {}).items()
                      for e in es or [] if not e.get("passed", True)]
            cm = ContextManager(target, files=sorted({rel for rel, _ in failed}))
            keywords: list[str] = []
            for rel, e in failed:
                for k in cm.extract_keywords_from_context(str(e.get("failure_reason") or ""), rel):
                    if k not in keywords:
                        keywords.append(k)
                fn = str(e.get("function") or "")
                if fn and fn != "<module>" and fn not in keywords:
                    keywords.append(fn)
            facts = await cm.doc_facts_async(keywords)
            _, added = _intent.append_facts(target, facts)
            logger.info(f"[INTENT] docs: {len(facts)} doc_mention fact(s) from {len(keywords)} keyword(s), "
                        f"{added} new in {_intent.path(target).name}")
        except Exception as e:
            logger.warning(f"[INTENT] docs facts not written: {type(e).__name__}: {e}")


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    daemon = BuilderDaemon()

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, daemon.stop)
        await daemon.run()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
