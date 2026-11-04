#!/usr/bin/env python3
"""
NoAI Validator Daemon — Standalone process that detects AI-generated counterfeit code.

Reads circuit_state.json from the monitor daemon, runs the full detection
pipeline, and writes results to system_scripts/ for the dashboard.

Pipeline (baseline):
  1. Detritus       — scan + holding dead code, stubs, unreachable modules
  2. Discovery      — find .py files, apply the launch scan's whitelist (scan_scope)
  3. Import_Tools   — cross-file validation (CallerMap, ImportGraph, RCA, authorship_signatures,
                      code_analysis.graph, rca modules) — raw data, no scoring
  4. Semantics      — def-use chains, module handling — raw data, no scoring
  5. Output         — flag failed functions, publish NOAI_VALIDATION_STATE.json

Steps 1-4 collect raw unfiltered data. The validator STOPS at findings (item 1,
2026-09-08): candidates, the Ranker's decision and the .noai_state.json mirror are
the Builder daemon's (no_aivalidator/BUILDER_DAEMON.py, gearbox child #4). The
inline stage_cheatsheet was archived after item 2's parity proof (2026-09-08).

Incremental (on change_tags): steps 3-5 on affected functions only.

Usage:
    python no_aivalidator/NOAI_VALIDATOR_DAEMON.py
"""
from __future__ import annotations

import ast
import asyncio
import dataclasses
import fcntl
import hashlib
import json
import logging
import os
import re
import tempfile
import traceback
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .noai_validator import NoAIMathValidator, ValidationLayer, ValidationResult
from .noai_validator.utils import read_source   # A1 (2026-10-01): the one PEP 263 source reader
from .cheatsheets.cheatsheet_intelligence.knowledge_base import (
    VerdictRanker,
    unknown_seen as _dispositions_unknown_seen,   # calibrator A3/A4 (2026-09-06)
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NoAIValidator] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("noai_validator_daemon")

# ── Paths ────────────────────────────────────────────────────────────────────
CIRCUIT_STATE_FILE = Path(__file__).resolve().parent.parent / "system_scripts" / "circuit_state.json"
NOAI_STATE_FILE = Path(__file__).resolve().parent.parent / "system_scripts" / "NOAI_VALIDATION_STATE.json"

POLL_INTERVAL = 2.5   # FIX_46: the cadence table's row noai_validator/validate (1 cycle)
SYS_SCRIPTS_FOR_CADENCE = Path(__file__).resolve().parent.parent / "system_scripts"
CADENCE_DAEMON = "noai_validator"

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


def _heartbeat(cycle: int) -> None:
    """I-108 (MCP-working packet 2026-09-28): this daemon's liveness beat — the sidecar beside
    NOAI_VALIDATION_STATE.json, written through gearbox.write_heartbeat. FIX_52's hang check reads
    it; the state itself stays on-change. Never raises."""
    try:
        import sys as _sys
        _sys.path.insert(0, str(SYS_SCRIPTS_FOR_CADENCE))
        import gearbox as _cadence
        _cadence.write_heartbeat(NOAI_STATE_FILE, CADENCE_DAEMON, cycle)
    except Exception:
        pass


def _purge_noai_state_files() -> None:
    """Delete the validator's own state file in system_scripts/.

    Item 1 (2026-09-08): .noai_state.json is the Builder daemon's file (it owns the
    mirror write and fan-out) — the validator never touches it. Never two writers."""
    if NOAI_STATE_FILE.exists():
        try:
            NOAI_STATE_FILE.unlink()
        except Exception:
            pass


def _write_progress(phase: str, detail: str = "", progress: float = 0.0,
                    substeps: list[dict[str, Any]] | None = None) -> None:
    """Write a progress update to NOAI_VALIDATION_STATE.json for dashboard display."""
    state = {
        "phase": phase,
        "detail": detail,
        "progress": round(progress, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if substeps:
        state["substeps"] = substeps
    write_file_locked(NOAI_STATE_FILE, state)


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class FileEntry:
    """A discovered Python file."""
    path: Path
    relative: str  # relative to repo root
    node_name: str  # stem name for graph matching


@dataclass
class FunctionResult:
    """Result of validating a single function."""
    function: str
    line: int
    passed: bool
    failure_layer: Optional[str] = None
    failure_reason: Optional[str] = None
    triggered_patterns: list = field(default_factory=list)
    last_checked: str = ""
    whitelisted: bool = False  # force-passed via function whitelist (WHITELISTED warning)
    end_line: int = 0          # last line of the function — the replace span (owner 2026-09-05)
    verdict_source: str = ""   # "ranker" when VerdictRanker decided (cut 1, 2026-09-06)
    warnings: list = field(default_factory=list)  # F-WARN-UNPUB (2026-09-06): the validator's module/row facts (IGR-001, FRN-001, FILE-ROLE, NAI-103 count, "No functions found") — published verbatim, never dropped
    species: str = ""          # the file's species fact ("test" by content; owner decisions 1+5, 2026-09-06)
    withheld: str = ""         # "species:test" when the ranker withheld its verdict (a published PASS that is not a clean pass)


@dataclass
class FlaggedIssue:
    """A function that failed validation — input to cheatsheet generation."""
    file_relative: str
    node_name: str
    function: str
    line: int
    failure_layer: str
    failure_reason: str
    triggered_patterns: list
    rule_id: str  # first NAI rule that triggered
    job_type: str  # mapped cheatsheet job type
    rule_ids: list = field(default_factory=list)  # DECIDING rule ids (dispatch keys); context never dispatches a repair
    context_ids: list = field(default_factory=list)  # cut 2: magnitude / regex observations published as context, not verdict
    species: str = ""                                    # calibrator A4 (2026-09-06)
    dispositions: dict = field(default_factory=dict)     # {id: deciding|context} as the table said at flag time


# (CrossFileContext archived 2026-09-08 with the inline stage — item 2; .archive/archived_20260908/no_aivalidator/NOAI_VALIDATOR_DAEMON_stage_cheatsheet.py.txt)



# ── Helpers ──────────────────────────────────────────────────────────────────

def read_file_locked(filepath: Path) -> dict[str, Any]:
    """Read JSON with shared file lock."""
    try:
        with open(filepath, "r") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def write_file_locked(filepath: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically via temp file + rename (no truncate-before-lock race)."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=filepath.parent,
        prefix=f".{filepath.stem}_{os.getpid()}_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        Path(tmp_path).rename(filepath)  # atomic on same filesystem
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def parse_line_ranges(tag_lines: str) -> set[int]:
    """Parse 'L42, L50-L55' into {42, 50, 51, 52, 53, 54, 55}."""
    lines: set[int] = set()
    for part in tag_lines.split(","):
        part = part.strip().lstrip("L")
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                lines.update(range(int(start_s), int(end_s) + 1))
            except ValueError:
                continue
        else:
            try:
                lines.add(int(part))
            except ValueError:
                continue
    return lines


def functions_at_lines(filepath: Path, target_lines: set[int]) -> list[tuple[str, int]]:
    """Return (func_name, start_line) for functions spanning any target lines."""
    try:
        tree = ast.parse(read_source(filepath))   # A1: BOM / coding cookie honoured
    except (SyntaxError, OSError, UnicodeDecodeError):
        return []
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = node.end_lineno or start
            if target_lines & set(range(start, end + 1)):
                hits.append((node.name, start))
    return hits


def _rule_to_job_type(rule_id: str) -> str:
    """Map NAI rule ID to cheatsheet job type."""
    try:
        num = int(rule_id.replace("NAI-", ""))
    except (ValueError, AttributeError):
        return "logic_fix"
    if num <= 25:
        return "logic_fix"       # Core checks: dead computation, identity, constants
    if num <= 29:
        return "refactor"        # Structural: identical branches, unreachable code
    if num <= 39:
        return "logic_fix"       # Math: data flow, liveness, algebraic identity
    if num <= 49:
        return "logic_fix"       # Advanced: subtree dup, param shadow, closures
    if num <= 58:
        return "logic_fix"       # Hallucination: undefined calls, misspelled builtins
    if num <= 69:
        return "refactor"        # Redundancy: double negation, bool comparison
    if num <= 79:
        return "defensive_guard" # Safety: bare except, mutable default, secrets
    if num <= 95:
        return "refactor"        # Style: naming, nesting, length
    if num <= 119:
        return "logic_fix"       # Semantic: param disconnect, magic numbers
    return "logic_fix"           # Extended semantic


# F-ID-RE1 (2026-09-06): `\d+[A-Z]?` dropped every SIG-<name>, HR-NAME, NAI-IM01 and MEASURED-NOTHING id from publication —
# the published context_ids never listed a regex hit or a name/body disagreement. Every id family the instrument emits:
_RULE_ID_RE = re.compile(r"\b((?:NAI|RCA|HR|IGR|FRN|SEC|GRF|SYM|SIG)-[A-Za-z0-9_]+|MEASURED-NOTHING)\b")


def _extract_rule_id(triggered_patterns: list, failure_reason: str = "") -> str:
    """Extract first rule ID from triggered patterns (or the failure reason).

    Layer-1 strict-check failures carry their rule id (e.g. 'NAI-021S') only
    in failure_reason, with NO triggered_patterns — fall back to parsing it.
    """
    ids = _extract_rule_ids(triggered_patterns, failure_reason)
    return ids[0] if ids else ""



def _finding_lines(triggered_patterns: list) -> list[int]:
    """The exact source lines the rules fired on (dict observations carry 'line'; a probe-backed observation also
    carries `lines` — the statements the wrong value was built from, owner 2026-10-07 line precision)."""
    lines: set[int] = set()
    for p in triggered_patterns or []:
        if isinstance(p, dict):
            for ln in [p.get("line"), *(p.get("lines") or [])]:
                if isinstance(ln, int) and ln > 0:
                    lines.add(ln)
    return sorted(lines)


def _span(rel_path: str, start: int, end: int) -> str:
    """'file.py:L12-L20' — the location the 1-best solution replaces."""
    if end and end >= start:
        return f"{rel_path}:L{start}-L{end}"
    return f"{rel_path}:L{start}"


_VR = VerdictRanker()   # calibrator A3 (2026-09-06): ONE ranker instance for publication; the two row sites below cannot drift


def _row_ids(fr: "FunctionResult") -> tuple[list[str], list[str]]:
    """(rule_ids, context_ids) for one published row — the single definition (stage_flag and stage_output both use it).
    Observations flagged context=True never decide (cut 3 batch 4); the disposition table splits the rest;
    a test-species row withholds every id into context (owner decision 1)."""
    pats = list(fr.triggered_patterns or [])
    deciding_pats = [p for p in pats if not (isinstance(p, dict) and p.get("context") is True)]
    all_ids = _extract_rule_ids(deciding_pats, fr.failure_reason or "")
    ctx_only = [i for i in _extract_rule_ids(pats) if i not in all_ids]
    # FIX_17 (2026-09-10): the observations' measured facts (magnitude) reach the per-(rule, context) table
    rule_ids, context_ids = _VR.split_ids(all_ids, getattr(fr, "species", "") or "", facts_by_id=_VR.facts_by_id(pats))
    return rule_ids, list(dict.fromkeys(context_ids + ctx_only))


def _row_severity(fr: "FunctionResult") -> Optional[int]:
    """DASH_R round 2 (owner 2026-09-28: severity first, L1 first): the row's severity = the position of the layer
    that failed it in the validator's own layer order (ValidationLayer: HARD_REQUIREMENTS = L1 → 1,
    AI_FAKE_DETECTOR = L2 → 2). None for a row no layer failed (a pass, a withheld row, an unnamed layer).
    Published so a reader orders by it instead of re-deriving an order of its own; no weight, no score."""
    if fr.passed or not fr.failure_layer or fr.failure_layer not in ValidationLayer.__members__:
        return None
    return ValidationLayer[fr.failure_layer].value


def _extract_rule_ids(triggered_patterns: list, failure_reason: str = "") -> list[str]:
    """Extract ALL rule ids from triggered patterns + failure reason (ordered, unique)."""
    ids: list[str] = []
    for p in triggered_patterns or []:
        tag = ""
        if isinstance(p, dict):
            tag = p.get("tag", "")
        elif isinstance(p, (list, tuple)) and p:
            tag = str(p[0])
        else:
            tag = str(p)
        m = _RULE_ID_RE.search(tag)
        if m and m.group(1) not in ids:
            ids.append(m.group(1))
    if failure_reason:
        m = _RULE_ID_RE.search(failure_reason)
        if m and m.group(1) not in ids:
            # failure_reason id first: it names the rule that decided the verdict
            ids.insert(0, m.group(1))
    return ids


# ── Whitelist (launcher artifact: system_scripts/whitelist_<repoid>.json) ────

def _repo_id(repo_path: Path) -> str:
    """Repo id — replicates circuit_daemon.get_repo_id's scheme inline
    (sha256(resolved path)[:12]); deliberately NOT imported from circuit_daemon."""
    return hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:12]


def _load_whitelist(repo: Path) -> tuple[set[str], set[str]]:
    """Load the persisted whitelist for this target.

    Returns (files, functions):
      files      — relative paths from entries[].path (IGNORE list: union into
                   the detritus set fed to stage_discover)
      functions  — optional "functions" key: ["rel.py::name", "rel.py::*"]
                   entries, consulted by validate_directory_async (force-pass
                   w/ WHITELISTED warning) and by the ranker (no fix owed).
    """
    wl_path = (Path(__file__).resolve().parent.parent / "system_scripts"
               / f"whitelist_{_repo_id(repo)}.json")
    data = read_file_locked(wl_path)
    if not data:
        logger.info(f"[WHITELIST] No whitelist at {wl_path.name}")
        return set(), set()
    files = {e.get("path", "") for e in data.get("entries", []) if e.get("path")}
    functions = {f for f in data.get("functions", []) if isinstance(f, str) and "::" in f}
    _load_whitelist.proxies = {k: v for k, v in (data.get("proxies") or {}).items() if isinstance(k, str)}   # type: ignore[attr-defined]  # FIX_54 ast-pos; Item 3 (2026-09-15)
    _load_whitelist.tests = {k: v for k, v in (data.get("tests") or {}).items() if isinstance(k, str)}       # type: ignore[attr-defined]  # FIX_54 ast-pos; Item 10 (2026-09-15)
    _load_whitelist.unreachable = list(data.get("unreachable_by_import") or [])   # type: ignore[attr-defined]  # owner 2026-09-29: the launch scan's fact
    _load_whitelist.stubs = {e["path"]: str(e["reason"])[5:] for e in data.get("entries", [])  # type: ignore[attr-defined]  # FIX_54 ast-pos
                             if e.get("path") and str(e.get("reason", "")).startswith("stub:")}   # Item 3: the whitelist stage's stub consult
    logger.info(f"[WHITELIST] Loaded {wl_path.name}: "
                f"{len(files)} file entries, {len(functions)} function entries")
    return files, functions


def _whitelisted_function(whitelist_functions: set[str] | None, rel: str, func: str) -> bool:
    """True if rel::func matches a function-whitelist entry (exact or rel::*)."""
    if not whitelist_functions:
        return False
    return f"{rel}::{func}" in whitelist_functions or f"{rel}::*" in whitelist_functions


# ── Pipeline stages ──────────────────────────────────────────────────────────

def _scan_scope():
    """S2 (2026-09-29): the ONE scope module (system_scripts/scan_scope.py) — the same .py walk and the
    same whitelist matcher the circuit uses, so baseline, incremental and circuit agree on every path."""
    ss = str(SYS_SCRIPTS_FOR_CADENCE)
    if ss not in sys.path:
        sys.path.insert(0, ss)
    import scan_scope  # type: ignore
    return scan_scope


def _content_hashes(files: list[FileEntry]) -> dict[str, str]:
    """S2 (2026-09-29): relative_path → sha256 of the bytes on disk now, for every discovered file. The
    circuit publishes a shortened sha256 of the same bytes (ast_scanner.compute_content_hash); _same_bytes
    reads the two as equal when the circuit's digest is a prefix of the stored one. An unreadable file gets
    no hash, so the next tick treats it as changed."""
    out: dict[str, str] = {}
    for fe in files:
        try:
            out[fe.relative] = hashlib.sha256(fe.path.read_bytes()).hexdigest()
        except OSError as e:
            logger.warning(f"[HASHES] {fe.relative}: unreadable at discovery ({e}) — left unhashed, rescanned next tick")
    return out


def _same_bytes(prev: str | None, h: str) -> bool:
    """True when the stored digest and the circuit's digest name the same bytes (either may be the
    shortened form of the other's sha256)."""
    if not prev or not h:
        return False
    return prev.startswith(h) or h.startswith(prev)


def stage_discover(repo: Path, detritus_files: set[str] | None = None) -> list[FileEntry]:
    """Step 2: Find all .py files in target dir (recursive, all depths).

    Filters out:
      - (cut 3 batch 5, 2026-09-06) the name-based skips are GONE: __init__.py/setup.py/conftest.py/__main__.py and
        rca_main.constants.should_exclude_path (substring 'venv'/'env'/'.git'/…) were scope mutes outside the whitelist
      - Files the launch scan's whitelist excludes (Step 1: non-.py artifacts, whole-file stubs, bytecode)
    """
    # EXCISED cut 3 batch 5 (2026-09-06, line read): `_SKIP_NAMES` {__init__.py, setup.py, conftest.py, __main__.py} and
    # rca_main.constants.should_exclude_path (substring match on 'venv'/'env'/'.git'/…) were name-based scope mutes at
    # discovery, outside the whitelist (owner doctrine: the whitelist is the ONE discovery; venv by size, never by name).

    detritus = detritus_files or set()

    # S2 (2026-09-29): the walk IS scan_scope.iter_live_py — hard-skips, containment (no symlink, nothing outside
    # the root) and the B8 env-dir-by-shape rule exactly as the circuit walks them. It is handed an empty
    # whitelist so the whitelisted entries can be counted here; scan_scope.is_whitelisted is the ONE matcher
    # (exact path, directory prefix, glob) that the incremental path and the circuit use too.
    _ss = _scan_scope()
    entries = []
    whitelisted = 0
    for f in _ss.iter_live_py(repo, frozenset()):
        rel = str(f.relative_to(repo))
        if _ss.is_whitelisted(f.relative_to(repo).as_posix(), detritus):
            whitelisted += 1
            continue
        entries.append(FileEntry(
            path=f,
            relative=rel,
            node_name=f.stem,
        ))
    logger.info(f"[DISCOVERY] {len(entries)} Python files in {repo} "
                f"({whitelisted} whitelisted by the launch scan — artifacts / whole-file stubs)")
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# THE SPAN WRITER — I-144 / I-40 (session 10, run 174; packet §B Q9)
#
# Q9: a unit's `end_line` comes from ITS OWN AST node, and a unit whose end cannot be read
# publishes a ONE-LINE span (`line_end = line`) — never 0.
#
# I-144. Run 162 published 43 withheld rows reading `line_end 0` under a real `line`, every one a
# `<lambda>` in `tests/` (`test_arguments.py::<lambda>::91 → 0` and 42 more). The end never
# existed to be read: `NoAIMathValidator.validate_lambda` builds its result with no span at all,
# and the file route then stamps `line` from the Lambda node and nothing else, so 0 is what
# arrives here. I-131's refusal guards the PUBLISH path only, and the mirror's withheld block is
# copied straight out of this state file, so the 0 travelled untouched onto a reader's screen. A
# lambda has no name to key a def map with; it is keyed here by the line it STARTS on and its end
# is its own node's `end_lineno`.
#
# I-40. A `<module>` row carries no span at all (L0-L0). When a SIG-* hit RIDES that row (FIX_35 k:
# a signature hit outside every def is attributed to `<module>` rather than to whichever function
# came first), the hit's line is the only source line the row has, and it becomes both `line` and
# `line_end`. A module row with NO hit keeps its 0 and stays refused at publish exactly as today.
#
# The rules apply in that order and end in the one-line fallback, so no result leaves this stage
# with a real `line` and no end.
_SIG_LINE_RE = re.compile(r"\[line (\d+)\]")
_SPAN_IDX_CACHE: dict[tuple[str, int, int], tuple[dict[int, int], int]] = {}


def _span_index(tree: ast.AST | None, source: str | None) -> tuple[dict[int, int], int]:
    """(lambda ends keyed by the line the lambda STARTS on, file length in lines).

    Two lambdas can start on one line (`f(lambda: 1, lambda: 2)`); the widest end wins, because it
    is the only end that contains both.
    """
    lambda_ends: dict[int, int] = {}
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Lambda):
                start = int(getattr(node, "lineno", 0) or 0)
                end = int(getattr(node, "end_lineno", 0) or 0)
                if start and end >= start:
                    lambda_ends[start] = max(lambda_ends.get(start, 0), end)
    return lambda_ends, len(source.splitlines()) if source else 0


def _span_index_for(path: Path) -> tuple[dict[int, int], int]:
    """`_span_index` for a file on disk, cached on (path, mtime, size) — the full-ingest path
    walks every result in the target and must not re-parse a file per result."""
    try:
        st = path.stat()
        key = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return {}, 0
    hit = _SPAN_IDX_CACHE.get(key)
    if hit is None:
        try:
            src = read_source(path)   # A1: BOM / coding cookie honoured
            hit = _span_index(ast.parse(src, filename=str(path)), src)
        except Exception:
            hit = ({}, 0)
        if len(_SPAN_IDX_CACHE) > 4096:
            _SPAN_IDX_CACHE.clear()
        _SPAN_IDX_CACHE[key] = hit
    return hit


def _riding_sig_line(patterns: Any) -> int:
    """The first source line a SIG-* pattern riding this row names; 0 when none rides it (I-40).

    The file route writes the hit as `["SIG-<name>", "CRITICAL", "<description> [line N]"]`; the
    observation shape (`{"tag": …, "line": …}`) is read too, so this does not depend on which of
    the two producers wrote the pattern.
    """
    best = 0
    for p in patterns or []:
        tag, line = "", 0
        if isinstance(p, dict):
            tag, line = str(p.get("tag", "")), int(p.get("line", 0) or 0)
        elif isinstance(p, (list, tuple)) and p:
            tag = str(p[0])
            m = _SIG_LINE_RE.search(" ".join(str(x) for x in p[1:]))
            if m:
                line = int(m.group(1))
        if tag.startswith("SIG-") and line > 0 and (not best or line < best):
            best = line
    return best


def _writer_span(function: str, line: int, end: int, patterns: Any,
                 lambda_ends: dict[int, int], n_lines: int) -> tuple[int, int]:
    """Q9's span for one result: `(line, line_end)`, never a 0 end under a real line."""
    if function == "<module>" and not (0 < line <= end):
        hit = _riding_sig_line(patterns)
        if hit:
            return hit, hit                        # I-40: the riding hit's line IS the row's span
    if function == "<lambda>" and line > 0 and (end <= 0 or end < line):
        end = int(lambda_ends.get(line, 0) or 0)   # I-144: the lambda's own end_lineno
    if line > 0 and n_lines and line <= n_lines and end > n_lines:
        end = n_lines                              # a span cannot end past the file
    if line > 0 and (end <= 0 or end < line):
        end = line                                 # Q9: a one-line span, never 0
    return line, end


def _published_patterns(r: Any) -> list:
    """T-07 (R7, 2026-09-30): the ONE conversion of a validator result's triggered_patterns, shared by the
    baseline (stage_ingest) and the edit path (stage_ingest_incremental). A dict pattern stays a dict —
    the edit path used to stringify it (`[str(p)]`), so `_extract_rule_ids` read different ids from
    the same function after the first edit."""
    return [
        p if isinstance(p, dict) else list(p) if isinstance(p, (list, tuple)) else [str(p)]
        for p in (getattr(r, "triggered_patterns", None) or [])
    ]


def _artifact_report_dict(report: Any) -> Optional[dict[str, Any]]:
    """T-07 (R7): the artifact scanner's report as stage_output publishes it — the baseline and every edit
    cycle pass the same thing; None = NOT MEASURED (no report)."""
    return None if report is None else report.as_dict()


def _published_whitelisted(r: Any) -> bool:
    """T-07 (R7): the force-pass flag both ingest paths publish — a WHITELISTED warning on the result."""
    return any("WHITELISTED" in str(w) for w in (getattr(r, "warnings", None) or []))


async def stage_ingest(
    validator: NoAIMathValidator,
    repo: Path,
    files: list[FileEntry],
    progress_callback: Any = None,
    whitelist: set[str] | None = None,
) -> tuple[dict[str, list[FunctionResult]], dict[str, Any]]:
    """Stage 2: Validate directory with cross-file analysis.

    Uses validate_directory_async for full cross-file RCA, CallerMap,
    ImportGraph, duplicate detection, and circular import detection.

    whitelist: function-level entries ("rel.py::name" / "rel.py::*") — the
    the validator force-passes matches with a WHITELISTED warning (detection still
    runs in full; the whitelist is a virtual stripper, never a scan gap).

    Returns: (results_by_file, cross_file_analysis)
    """
    from .noai_validator.file_validation import validate_directory_async

    # Owner 2026-09-05: the scan (and its cross-file analysis) honours the whitelist —
    # validate exactly the discovered, filtered files; never a fresh walk of the repo.
    vresults, cross_file = await validate_directory_async(
        validator, repo, progress_callback=progress_callback,
        whitelist=whitelist or None,
        files=[e.path for e in files],
    )

    # Group results by relative path (validate_directory_async sets r.file_path)
    all_results: dict[str, list[FunctionResult]] = {}
    total = 0
    for r in vresults:
        rel = getattr(r, "file_path", None) or "<unknown>"
        # Q9 (I-144 / I-40, run 174): this path never had I-131's inversion — it takes both ends
        # from the result itself — but it had the missing end: a lambda arrives with a real line
        # and no span, and a module row with neither. The span is settled HERE, at the writer,
        # before anything downstream can copy a 0 onto a screen.
        _lam, _nl = _span_index_for(repo / rel) if rel != "<unknown>" else ({}, 0)
        _line, _end = _writer_span(r.function_name,
                                   int(getattr(r, "line", 0) or 0),
                                   int(getattr(r, "end_line", 0) or 0),
                                   getattr(r, "triggered_patterns", None), _lam, _nl)
        fr = FunctionResult(
            function=r.function_name,
            line=_line,
            end_line=_end,
            passed=r.passed,
            verdict_source=getattr(r, "verdict_source", ""),
            species=getattr(r, "species", "") or "",      # F-SPECIES-PUB (run 31, 2026-09-06): the full-ingest path dropped the species fact
            withheld=getattr(r, "withheld", "") or "",
            warnings=[str(w) for w in (getattr(r, "warnings", None) or [])],  # F-WARN-UNPUB (2026-09-06)
            failure_layer=r.failure_layer.name if r.failure_layer else None,
            failure_reason=r.failure_reason,
            triggered_patterns=_published_patterns(r),
            last_checked=datetime.now(timezone.utc).isoformat(),
            whitelisted=_published_whitelisted(r),
        )
        all_results.setdefault(rel, []).append(fr)
        # Only count real functions, not <module>/<file>/<lambda> phantoms
        if not r.function_name.startswith("<"):
            total += 1

    logger.info(f"[INGEST] {total} functions across {len(all_results)} files")
    rca_count = len(cross_file.get("rca_cross_file_issues", []))
    circ_count = len(cross_file.get("circular_imports", []))
    if rca_count or circ_count:
        logger.info(f"[CROSS-FILE] RCA issues: {rca_count}, circular imports: {circ_count}")
    return all_results, cross_file


async def stage_ingest_incremental(
    validator: NoAIMathValidator,
    files: list[FileEntry],
) -> dict[str, list[FunctionResult]]:
    """Incremental ingestion: validate individual files (no cross-file analysis)."""
    all_results: dict[str, list[FunctionResult]] = {}
    total = 0
    for fe in files:
        try:
            vresults = await validator.validate_file_async(fe.path)
        except Exception as e:
            logger.warning(f"[INGEST] Skip {fe.relative}: {e}")
            continue

        # I-129 / I-131 (session 8, run 160): this map used to be keyed by function NAME alone
        # (`func_lines[node.name] = node.lineno`), so `ast.walk`'s LAST def of a name won and EVERY
        # result for that name in the file was stamped with that one def line. Two defects fell out
        # of the one line, and both were RELEASE-BLOCKING:
        #   I-131 — `line` came from the last def of the name while `end_line` came from the result's
        #           own span, so a unit defined above its namesake published `line_end < line`
        #           (run 155: 24 rows at teardown, e.g. core.py::__init__ line 3678 / end 514 —
        #           Argument.__init__'s def line against Context.__init__'s end);
        #   I-129 — the Builder keys its rows `<file>::<function>::<line>`, so every same-name unit in
        #           a rescanned file collapsed onto ONE key in build_rows' dict comprehension and the
        #           losers reached NO published bucket at all (run 155: 41 units, the exact gap
        #           between `failed` 187 and repairs 71 + no_vetted_fix 75 = 146).
        # The full-ingest path (stage_ingest above) never had either: it takes `line`/`end_line` from
        # the result itself. This path now does the same, and the name map survives only as a
        # last-resort fallback for names that are UNIQUE in the file — an ambiguous name never
        # supplies a line, because a wrong line is worse than 0.
        func_lines: dict[str, int] = {}
        func_ends: dict[str, int] = {}
        ambiguous: set[str] = set()
        _lam_ends: dict[int, int] = {}
        _n_lines = 0
        try:
            _src = read_source(fe.path)   # A1: BOM / coding cookie honoured
            tree = ast.parse(_src, filename=str(fe.path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name in func_lines:
                        ambiguous.add(node.name)
                        continue
                    func_lines[node.name] = node.lineno
                    func_ends[node.name] = getattr(node, "end_lineno", 0) or 0
            # Q9 (I-144, run 174): the same parse answers for the unit the name map cannot key —
            # a lambda has no name, so its end is keyed by the line it starts on.
            _lam_ends, _n_lines = _span_index(tree, _src)
        except Exception:
            pass
        for name in ambiguous:
            func_lines.pop(name, None)
            func_ends.pop(name, None)

        frs = []
        for r in vresults:
            _line = int(getattr(r, "line", 0) or 0) or func_lines.get(r.function_name, 0)
            _end = int(getattr(r, "end_line", 0) or 0) or func_ends.get(r.function_name, 0)
            # The span is the unit's own or it is not published: a fallback line paired with a
            # measured end (or the reverse) is what produced I-131's inverted spans.
            if _end and _line and _end < _line:
                _line, _end = (int(getattr(r, "line", 0) or 0), int(getattr(r, "end_line", 0) or 0))
                if _end and _line and _end < _line:
                    logger.warning("[INGEST] %s::%s inverted span (%d > %d) — span dropped",
                                   fe.relative, r.function_name, _line, _end)
                    _end = 0
            # Q9 (I-144 / I-40, run 174): a lambda's end from its own AST node, a module row's
            # span from the SIG hit riding it, and never a 0 end under a real line — the dropped
            # span above leaves this line as a one-line span, not as a 0.
            _line, _end = _writer_span(r.function_name, _line, _end,
                                       getattr(r, "triggered_patterns", None), _lam_ends, _n_lines)
            frs.append(FunctionResult(
                function=r.function_name,
                line=_line,
                end_line=_end,
                passed=r.passed,
                verdict_source=getattr(r, "verdict_source", ""),
                species=getattr(r, "species", "") or "",
                withheld=getattr(r, "withheld", "") or "",
                warnings=[str(w) for w in (getattr(r, "warnings", None) or [])],  # F-WARN-UNPUB (2026-09-06)
                failure_layer=r.failure_layer.name if r.failure_layer else None,
                failure_reason=r.failure_reason,
                triggered_patterns=_published_patterns(r),   # T-07 (R7): the baseline's own conversion
                last_checked=datetime.now(timezone.utc).isoformat(),
                whitelisted=_published_whitelisted(r),       # T-07 (R7): was dropped on the edit path
            ))
            if not r.function_name.startswith("<"):
                total += 1
        if frs:
            all_results[fe.relative] = frs
    logger.info(f"[INGEST] {total} functions across {len(all_results)} files (incremental)")
    return all_results


async def stage_semantic(repo: Path, files: list[Path] | None = None) -> dict[str, list]:
    """Stage 2b: Run semantic analysis (all five analyzers, raw, no scoring).

    files: whitelist-filtered file list from stage_discover. When provided, the
    analyzers scan exactly these files instead of re-walking the whole repo
    (closes whitelist leak #7). None = legacy full-glob behavior.

    Hand-off contract (Phase-4 H1): analyzers return dataclass Issues; the
    consumer (stage_cheatsheet) expects dicts. Convert with dataclasses.asdict
    HERE, at the producer boundary, so 100% of semantic evidence survives.
    """
    semantic: dict[str, list] = {
        "def_use": [], "module": [],
        "api_compliance": [], "parameter_usage": [], "cfg": [],
    }

    def _as_dicts(issues: list) -> list[dict]:
        out = []
        for i in issues:
            if dataclasses.is_dataclass(i) and not isinstance(i, type):
                out.append(dataclasses.asdict(i))
            elif isinstance(i, dict):
                out.append(i)
        return out

    try:
        from semantic_analysis.def_use_chains import analyze_directory as du_analyze
        semantic["def_use"] = _as_dicts(await du_analyze(repo, files=files))
    except Exception as e:
        logger.warning(f"[SEMANTIC] def_use_chains unavailable: {e}")
    try:
        from semantic_analysis.module_handling import analyze_directory as mod_analyze
        semantic["module"] = _as_dicts(await mod_analyze(repo, files=files))
    except Exception as e:
        logger.warning(f"[SEMANTIC] module_handling unavailable: {e}")
    try:
        from semantic_analysis.api_compliance import analyze_directory as api_analyze
        semantic["api_compliance"] = _as_dicts(await api_analyze(repo, files=files))
    except Exception as e:
        logger.warning(f"[SEMANTIC] api_compliance unavailable: {e}")
    try:
        from semantic_analysis.parameter_usage import analyze_directory as param_analyze
        semantic["parameter_usage"] = _as_dicts(await param_analyze(repo, files=files))
    except Exception as e:
        logger.warning(f"[SEMANTIC] parameter_usage unavailable: {e}")
    try:
        from semantic_analysis.cfg_analysis import analyze_directory as cfg_analyze
        semantic["cfg"] = _as_dicts(await cfg_analyze(repo, files=files))
    except Exception as e:
        logger.warning(f"[SEMANTIC] cfg_analysis unavailable: {e}")
    return semantic


def stage_flag(
    results: dict[str, list[FunctionResult]],
    files: list[FileEntry],
) -> tuple[list[FlaggedIssue], set[str], int, int]:
    """Stage 3: Separate passed/failed, build flagged issues list.

    Returns: (flagged_issues, flagged_node_names, pass_count, fail_count, tracked_test_rows)

    Item 10 (2026-09-15): a row the ranker WITHHELD (species:test) is counted under the test-runner
    tracker (`tracked_test_rows`), never as a pass — `pass_count` is clean passes only.
    """
    # Build node_name lookup
    rel_to_node = {fe.relative: fe.node_name for fe in files}

    flagged: list[FlaggedIssue] = []
    flagged_nodes: set[str] = set()
    passed = 0
    failed = 0
    tracked_test_rows = 0

    for rel_path, frs in results.items():
        node_name = rel_to_node.get(rel_path, Path(rel_path).stem)
        for fr in frs:
            if fr.passed and not fr.withheld:
                passed += 1
            elif fr.passed:
                tracked_test_rows += 1   # Item 10: withheld test-species row — the tracker's, not a pass
            else:
                failed += 1
                # cut 2 (2026-09-05): rule_ids = deciding ids only; context ids published beside them — one definition (_row_ids)
                rule_ids, context_ids = _row_ids(fr)
                rule_id = rule_ids[0] if rule_ids else ""
                flagged.append(FlaggedIssue(
                    file_relative=rel_path,
                    node_name=node_name,
                    function=fr.function,
                    line=fr.line,
                    failure_layer=fr.failure_layer or "",
                    failure_reason=fr.failure_reason or "",
                    triggered_patterns=fr.triggered_patterns,
                    rule_id=rule_id,
                    job_type=_rule_to_job_type(rule_id),
                    rule_ids=rule_ids,
                    context_ids=context_ids,
                    species=getattr(fr, "species", "") or "",
                    dispositions={i: _VR.disposition(i) for i in rule_ids + context_ids},
                ))
                flagged_nodes.add(node_name)

    logger.info(f"[FLAG] {passed} passed, {failed} failed, {tracked_test_rows} tracked test rows, {len(flagged_nodes)} flagged nodes")
    return flagged, flagged_nodes, passed, failed, tracked_test_rows  # type: ignore[return-value]  # FIX_54 ast-pos


# ── Repair stage: MOVED OUT (item 1 / item 2, 2026-09-08) ─────────────────────────
# The rule-id → rewriter dispatch, the graph context, and stage_cheatsheet with its two
# gate helpers are archived at .archive/archived_20260908/no_aivalidator/
# NOAI_VALIDATOR_DAEMON_stage_cheatsheet.py.txt after item 2's parity proof (run 47).
# The live pipeline is no_aivalidator/BUILDER_DAEMON.py (gearbox child #4).


def _intent_summary(target_repo: str) -> dict:
    """Item 8 (2026-09-15): the intent file's shape for the state summary — `{statement, facts_by_source}`;
    `{"status": "NOT MEASURED"}` when the reader is unavailable (never a silent empty)."""
    try:
        ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
        if ss not in sys.path:
            sys.path.insert(0, ss)
        import intent_file as _intent  # type: ignore
        data = _intent.read(target_repo)
        return {"statement": bool(data.get("statement")), "facts_by_source": _intent.facts_by_source(data),
                "file": _intent.path(target_repo).name}
    except Exception as e:
        return {"status": "NOT MEASURED", "reason": f"{type(e).__name__}: {e}"}


def stage_output(
    results: dict[str, list[FunctionResult]],
    flagged_nodes: set[str],
    target_repo: str,
    pass_count: int,
    fail_count: int,
    cross_file: Optional[dict[str, Any]] = None,
    semantic: Optional[dict[str, list]] = None,
    whitelist_functions: Optional[set[str]] = None,
    stale_for_files: Optional[set[str]] = None,
    artifact_report: Optional[dict[str, Any]] = None,
    tracked_test_rows: int = 0,
) -> None:
    """Stage 5: Write NOAI_VALIDATION_STATE.json — the validator STOPS at findings.

    artifact_report (Item 3, 2026-09-10) — the artifact scanner's whole-set report (`ArtifactReport.as_dict()`):
    published top-level as `artifact_report` (summary, species facts, stubs, intent facts); None = NOT MEASURED
    (the daemon says so in the phase detail).

    Item 1 (2026-09-08): the Builder daemon (no_aivalidator/BUILDER_DAEMON.py) reads
    this file, decides one before/after per finding through the Ranker, and owns the
    .noai_state.json mirror (repairs[] / no_vetted_fix[]) and its fan-out. Rows carry
    no `cheatsheet` key any more. Never two writers.

    stale_for_files — every file rescanned since the baseline cross-file analysis was
    computed; published as cross_file_analysis.stale_for_files so the Builder can
    prefix evidence for those files with STALE:.
    """
    results_by_file: dict[str, list[dict[str, Any]]] = {}
    for rel_path, frs in results.items():
        entries = []
        for fr in frs:
            _rids, _cids = _row_ids(fr)
            entry = {
                "function": fr.function,
                "line": fr.line,
                "end_line": fr.end_line,
                "finding_lines": _finding_lines(fr.triggered_patterns),
                "passed": fr.passed,
                "verdict_source": fr.verdict_source,
                "rule_ids": _rids,                    # DECIDING ids on the row (calibrator A4, 2026-09-06)
                "context_ids": _cids,                 # published context, never a verdict
                "dispositions": {i: _VR.disposition(i) for i in _rids + _cids},
                "species": getattr(fr, "species", "") or "",
                "withheld": getattr(fr, "withheld", "") or "",
                "failure_layer": fr.failure_layer,
                "severity": _row_severity(fr),        # DASH_R r2: L1 = 1, L2 = 2 (ValidationLayer order); None = no failing layer
                "failure_reason": fr.failure_reason,
                "triggered_patterns": fr.triggered_patterns,
                "warnings": sorted(getattr(fr, "warnings", []) or []),  # F-WARN-UNPUB (2026-09-06): module/row facts reach the state; I-05 (run 117): sorted at the writer — the order no longer varies per process (set iteration under hash randomisation)
                "last_checked": fr.last_checked,
            }
            if fr.whitelisted:
                entry["whitelisted"] = True
                entry["warnings"] = ["WHITELISTED: owner-exempted"]
            entries.append(entry)
        results_by_file[rel_path] = entries

    total = pass_count + fail_count + tracked_test_rows   # Item 10: passes + failures + the tracker's test rows
    state = {
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "baseline_timestamp": datetime.now(timezone.utc).isoformat(),
        "target_repo": target_repo,
        "phase": "MONITORING",
        "summary": {
            "total_functions": total,
            "passed": pass_count,
            "failed": fail_count,
            "files_scanned": len(results),
            # Last plan 1a (2026-10-10): files the scan could not judge (a rule crashed, the file does not parse or
            # decode). Before this they were only in cross_file_analysis.parse_errors, which nothing showed — a
            # crashed file read as fewer rows and "clean".
            "files_not_scanned": [dict(e) for e in (cross_file or {}).get("parse_errors", [])],
            "tracked_test_rows": tracked_test_rows,   # Item 10 (2026-09-15): test-species rows counted under the tracker, never as passes
            "withheld": sum(1 for frs in results.values() for fr in frs if getattr(fr, "withheld", "")),   # alias of tracked_test_rows, kept one run (Item 10)
            "dispositions_unknown": _dispositions_unknown_seen(),   # ids decided with no table row (step 18 fails on them)
            "intent": _intent_summary(target_repo),   # Item 8 (2026-09-15): {statement: bool, facts_by_source} from the intent file
        },
        "flagged_nodes": sorted(flagged_nodes),
        "results_by_file": results_by_file,
        "artifact_report": artifact_report,   # Item 3 (2026-09-10): the artifact scanner's report; None = NOT MEASURED
        "cross_file_analysis": {**(cross_file or {}), "stale_for_files": sorted(stale_for_files or [])},
        "semantic_analysis": semantic or {},
    }
    write_file_locked(NOAI_STATE_FILE, state)
    logger.info(f"[OUTPUT] {pass_count}/{total} passed | {fail_count} failed | {len(flagged_nodes)} flagged → {NOAI_STATE_FILE.name}")


# ── Daemon ───────────────────────────────────────────────────────────────────

class NoAIValidatorDaemon:
    """Standalone daemon: detects AI-generated code and publishes the findings."""

    def __init__(self) -> None:
        self.validator = NoAIMathValidator()
        # Item 1 (2026-09-08): KnowledgeBase / CheatsheetReviewer are no longer constructed
        # here — candidates and the Ranker call live in the Builder daemon.
        self.running = True
        self._hb_cycle = 0   # I-108: poll cycles counted for the heartbeat row's cadence
        # Files rescanned since the baseline cross-file analysis (published for the Builder).
        self.stale_files: set[str] = set()

        # Calibrator: STRUCK 2026-09-05 (plan item 9) — no working example in any
        # copy and no place for a tolerance scorer under the binary-verdict doctrine.
        self.calibrator = None

        # The always-pass repair validation LOST — cut 3 round 1 (owner 2026-09-06): an always-pass verdict from the 'atomic' era
        # whose premise (an upstream agent already validated the repair) is false here. R-REV-WORKS / §S.6 replaces it.

        # State carried between cycles
        self.target_repo: Optional[str] = None
        self.files: list[FileEntry] = []
        self.results: dict[str, list[FunctionResult]] = {}
        # Plan item 7: relative_path → circuit content_hash of every node at the
        # last scan; the ONLY trigger for a rescan is a changed hash.
        self.node_hashes: dict[str, str] = {}
        # Plan item 8: executed_at of the last execution proof consumed (origin tracer feed)
        self._last_proof_stamp: Optional[str] = None
        self.cross_file_analysis: dict[str, Any] = {}
        self.flagged_nodes: set[str] = set()
        self.processed_tags: dict[str, set[str]] = {}
        # Whitelist artifact (system_scripts/whitelist_<repoid>.json), loaded
        # at baseline start; consulted by discovery, the validator, semantics,
        # ranker, and mirror writer.
        self.whitelist_files: set[str] = set()
        self.whitelist_functions: set[str] = set()

        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name if signum in signal.Signals._value2member_map_ else str(signum)
        logger.info(f"Received {sig_name} — shutting down...")
        self.running = False
        # Schedule task cancellation safely via the event loop (not from signal context)
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(self._cancel_tasks)
        except RuntimeError:
            pass

    def _cancel_tasks(self) -> None:
        """Cancel pending asyncio tasks — called from within the event loop."""
        for task in asyncio.all_tasks():
            if task is not asyncio.current_task():
                task.cancel()

    # ── Baseline (stages 1-5) ────────────────────────────────────────────
    def _beat(self, force: bool = False) -> None:
        """I-108: count a poll cycle and beat when the FIX_46 `noai_validator / heartbeat` row is due
        (or at once when *force*, e.g. a baseline stage boundary)."""
        self._hb_cycle += 1
        try:
            import sys as _sys
            _sys.path.insert(0, str(SYS_SCRIPTS_FOR_CADENCE))
            import gearbox as _cadence
            due = force or _cadence.due(CADENCE_DAEMON, "heartbeat", self._hb_cycle)
        except Exception:
            due = True
        if due:
            _heartbeat(self._hb_cycle)

    async def run_baseline(self, repo_path: str) -> None:
        """Full pipeline: detritus → discovery → import_tools → semantics → output."""
        logger.info(f"═══ BASELINE: {repo_path} ═══")
        self.target_repo = repo_path
        self.processed_tags.clear()
        repo = Path(repo_path)

        # ── Step 0: Load the launcher-persisted whitelist (seam S1) ──
        # Repo-id computed identically to circuit_daemon.get_repo_id (inline).
        self.whitelist_files, self.whitelist_functions = _load_whitelist(repo)

        # ── Step 1: the ONE scan's result (owner 2026-09-29) ──
        # There is one scan per launch — the whitelist stage — and its result is handed to whoever needs it; this
        # daemon no longer runs a detritus scan of its own. Every .py is scanned, recursively: the only files left
        # out are the whitelist's (non-.py artifacts, known whole-file stubs, bytecode). Modules no import reaches
        # are a fact of that scan (`unreachable_by_import`), reported here and scanned like every other file.
        _unreach = getattr(_load_whitelist, "unreachable", []) or []
        _write_progress("DETRITUS", f"whitelist from the launch scan: {len(self.whitelist_files)} entries; "
                                    f"{len(_unreach)} module(s) no import reaches — scanned",
                        progress=1.0)
        logger.info(f"[DETRITUS] no second scan — the launch scan's whitelist: {len(self.whitelist_files)} entries, "
                    f"{len(_unreach)} unreachable-by-import module(s) scanned")
        detritus_files: set[str] = set(self.whitelist_files)

        # ── Step 2: Discovery — find .py files, apply the launch scan's whitelist ──
        _write_progress("DISCOVERY", f"Scanning {repo_path} for Python files...")
        self._beat(force=True)   # I-108: a long baseline beats at each stage boundary
        self.files = stage_discover(repo, detritus_files=detritus_files)
        # S2 (2026-09-29): the per-file content hashes are taken HERE, from the bytes on disk before any stage
        # reads them — never from the circuit after the baseline. A file added during the baseline then has no
        # hash (the incremental tick finds it as new) and a file edited during the baseline keeps its
        # pre-edit hash (the tick sees the change and rescans). Hashing before the read errs toward one extra
        # rescan, never toward a missed one.
        self.node_hashes = _content_hashes(self.files)

        # ── Step 2b: ARTIFACT SCANNER (Item 3, 2026-09-10) — one stage under that name: species by CONTENT with the
        # proxy kinds (whole-set facts measured once), the whole-file stub consult, the dot-dir intent sources. The
        # report is attached to the validator so every row of the ingest carries the same `species` fact the
        # disposition table reads; proxies and tests are scanned and WITHHELD, never stripped.
        self.artifact_report = None
        self.validator.artifact_report = None  # type: ignore[attr-defined]  # FIX_54 ast-pos
        _write_progress("ARTIFACTS", f"Classifying {len(self.files)} files by content (proxies, stubs, intent sources)...")
        try:
            from no_aivalidator.artifact_scanner import analyze as _artifact_analyze
            report = await _artifact_analyze(repo, files=[fe.path for fe in self.files],
                                             whitelist=(self.whitelist_files, self.whitelist_functions))
            # the whole-file stubs were consulted at the whitelist stage and are already OUT of self.files —
            # carry them into the published report so `artifact_report.stubs` states the whole set, not zero.
            for _rel, _kind in (getattr(_load_whitelist, "stubs", {}) or {}).items():
                report.stubs.setdefault(_rel, _kind)
            self.artifact_report = report
            self.validator.artifact_report = report  # type: ignore[attr-defined]  # FIX_54 ast-pos
            # Owner 2026-10-08 (M-126, intent plumbing): the intent sources' facts (README, docs, CI, packaging …)
            # are written into the target's intent file — before this they were only counted on the dash, so the
            # Ranker never saw them. `replace_source_facts` refreshes only these sources; the developer's statement,
            # its facts and the tester's facts stay.
            try:
                _ss = str(Path(__file__).resolve().parent.parent / "system_scripts")
                if _ss not in sys.path:
                    sys.path.insert(0, _ss)
                import intent_file as _intent  # type: ignore
                _intent.replace_source_facts(repo, [f.as_dict() for f in report.intent_facts])
            except Exception as _ie:
                logger.warning(f"[ARTIFACTS] intent facts not written to the intent file: {_ie}")
            _s = report.summary()
            _write_progress("ARTIFACTS",
                            f"species {sum(_s['species'].values())} (proxy {_s['proxies']}, test {_s['tests']}) · "
                            f"stubs {sum(_s['stubs'].values())} · intent sources {len(_s['intent_sources'])} · facts {_s['intent_facts']}",
                            progress=1.0,
                            substeps=[{"file": f, "status": sp} for f, sp in sorted(report.proxies().items())[:20]])
            logger.info(f"[ARTIFACTS] {_s}")
        except Exception as e:
            _write_progress("ARTIFACTS", f"NOT MEASURED: {type(e).__name__}: {e}", progress=1.0)
            logger.warning(f"[ARTIFACTS] not measured: {e}")
        # Owner 2026-10-10 (last plan 1R): RCA's config reader feeds NAI-099's config match — the detector read
        # `validator._artifact_values` but nothing ever set it, so "magic number duplicates config key" never fired.
        self.validator._artifact_values = None  # type: ignore[attr-defined]
        try:
            from rca_main.rca_analyzer import RCAAnalyzer
            self.validator._artifact_values = RCAAnalyzer.scan_config_files(Path(repo))  # type: ignore[attr-defined]
            logger.info(f"[ARTIFACTS] config values: {len(self.validator._artifact_values)}")  # type: ignore[attr-defined]
        except Exception as e:
            logger.warning(f"[ARTIFACTS] config values NOT MEASURED: {type(e).__name__}: {e}")
        await asyncio.sleep(0.3)
        if not self.files:
            # F11 fix (rung 0, owner ruling 2026-08-28): a stub/all-detritus CB is
            # the OUTLINE of what's being built or repaired — the app goes into
            # MONITOR MODE with an honest empty baseline (overlay lifts, gate
            # passes; user switches the app off if monitoring isn't wanted).
            # Never a parked DISCOVERY phase / gearbox gate abort.
            logger.warning("No Python files found — entering MONITORING with honest empty baseline (F11)")
            stage_output({}, set(), repo_path, 0, 0,
                         whitelist_functions=self.whitelist_functions)
            return
        file_names = [f.relative for f in self.files]
        _write_progress("DISCOVERY", f"Found {len(self.files)} Python files (launch-scan whitelist applied)",
                        progress=1.0,
                        substeps=[{"file": f, "status": "pending"} for f in file_names])
        await asyncio.sleep(0.3)

        # ── Step 3: Import_Tools — cross-file validation + signatures + rca ──
        _write_progress("IMPORT_TOOLS", f"Analyzing {len(self.files)} files with cross-file analysis...",
                        progress=0.0)

        def _ingest_progress(done: int, total: int, current_file: str) -> None:
            pct = done / total if total else 0.0
            _write_progress("IMPORT_TOOLS",
                            f"[{done}/{total}] {current_file}",
                            progress=round(pct, 2))

        self.results, self.cross_file_analysis = await stage_ingest(
            self.validator, repo, self.files,
            progress_callback=_ingest_progress,
            whitelist=self.whitelist_functions,
        )
        _write_progress("IMPORT_TOOLS",
                        f"Analyzed {len(self.results)} files",
                        progress=1.0,
                        substeps=[{"file": f, "status": "done"} for f in file_names])
        await asyncio.sleep(0.3)

        # ── Step 4: Semantics — raw data collection, no scoring ──
        # Whitelist-filtered file list: the analyzers scan exactly what
        # discovery kept, never re-walking the whole repo.
        _write_progress("SEMANTICS", "Running semantic analysis...")
        self._beat(force=True)
        semantic_results = await stage_semantic(
            repo, files=[fe.path for fe in self.files])
        sem_counts = {k: len(v) for k, v in semantic_results.items()}
        if any(sem_counts.values()):
            logger.info(f"[SEMANTICS] {sem_counts}")
        _write_progress("SEMANTICS",
                        f"{sum(sem_counts.values())} semantic issues collected",
                        progress=1.0)
        await asyncio.sleep(0.3)

        # ── Step 5: flag + output — the validator STOPS at infractions (item 1, 2026-09-08).
        # Candidates, the Ranker's decision and the mirror are the Builder daemon's.
        self._beat(force=True)
        issues, self.flagged_nodes, passed, failed, tracked = stage_flag(self.results, self.files)  # type: ignore[misc]  # FIX_54 ast-pos
        self.stale_files = set()  # baseline = every file fresh for the cross-file analysis

        # Output to dashboard (+ the Builder reads it)
        # NOTE: stage_output writes the final NOAI_VALIDATION_STATE.json with
        # results_by_file, summary, etc. Do NOT call _write_progress after this
        # or it will overwrite the results with just phase/detail metadata.
        stage_output(self.results, self.flagged_nodes, repo_path, passed, failed, tracked_test_rows=tracked,
                     cross_file=self.cross_file_analysis, semantic=semantic_results,
                     stale_for_files=self.stale_files,
                     whitelist_functions=self.whitelist_functions,
                     artifact_report=_artifact_report_dict(getattr(self, "artifact_report", None)))  # FIX_54 ast-pos; T-07 (R7): one helper, both paths
        # Plan item 7 (owner 2026-09-05): the first scan gets EVERYTHING; after it
        # only NEW EDITS are scanned. The per-file content hashes were seeded at discovery (S2, above) from
        # the bytes this baseline scanned, so the cycle can tell an edit from a re-walk.
        logger.info(f"[HASHES] seeded {len(self.node_hashes)} per-file content hashes from the baseline's discovery")
        logger.info("═══ BASELINE COMPLETE ═══")

    # ── Incremental (edits only, driven by the circuit's content hashes) ──
    async def check_incremental(self, circuit_state: dict[str, Any]) -> None:
        """Edits-only cycle (plan item 7, owner 2026-09-05).

        The circuit publishes a content_hash per file every poll. A file is
        rescanned — whole file, all functions plus module level, because an
        edit changes context for everything in it — exactly when that hash
        differs from the one seen at the last scan. No walk, no re-baseline:
        an unchanged tree costs nothing. A NEW .py file that the whitelist does
        not exclude is an edit too; a scanned file whose node vanished and is
        gone from disk drops out of the results. Cross-file context from the
        baseline is carried along and marked stale for the edited files.
        """
        nodes = circuit_state.get("nodes", [])
        repo_path = circuit_state.get("target_repo", "")
        if not repo_path:
            logger.debug("[INCREMENTAL] No target_repo in circuit_state — skipping")
            return
        repo = Path(repo_path)
        # EXCISED cut 3 batch 5 (2026-09-06, line read): `_SKIP_NAMES` and rca_main.constants.should_exclude_path were
        # name-based scope mutes at discovery, outside the whitelist (the one discovery; venv by size, never by name).

        # S2 (2026-09-29): scan_scope.is_whitelisted is the ONE matcher (exact path, directory prefix, glob) —
        # the same one stage_discover and the circuit use.
        _ss = _scan_scope()

        affected_files: list[FileEntry] = []
        removed: list[str] = []
        scoped: dict[str, FileEntry] = {fe.relative: fe for fe in self.files}
        seen_now: set[str] = set()

        for node in nodes if isinstance(nodes, list) else []:
            if not isinstance(node, dict):
                logger.warning(f"[INCREMENTAL] malformed circuit node ignored: {type(node).__name__}")
                continue
            name = node.get("name", "")
            rel_path = node.get("relative_path") or f"{name}.py"
            h = node.get("content_hash")
            if not h:
                continue
            seen_now.add(rel_path)
            filepath = repo / rel_path
            # S2: a live .py that is neither in the scanned list nor whitelisted has never been scanned —
            # it is NEW whatever hash is on record for it.
            unscanned = (rel_path not in scoped and filepath.suffix == ".py"
                         and not _ss.is_whitelisted(Path(rel_path).as_posix(), self.whitelist_files))
            prev = self.node_hashes.get(rel_path)
            if not unscanned and _same_bytes(prev, h):
                continue                      # same bytes as last scan → nothing to do
            self.node_hashes[rel_path] = h
            if not filepath.exists():
                continue
            if rel_path in scoped:
                fe = scoped[rel_path]
            elif unscanned:  # EXCISED cut 3 batch 5 (2026-09-06, line read): `_SKIP_NAMES` / should_exclude_path mutes removed
                fe = FileEntry(path=filepath, relative=rel_path, node_name=filepath.stem)
                self.files.append(fe)
                scoped[rel_path] = fe
                logger.info(f"[INCREMENTAL] new live file: {rel_path}")
            else:
                logger.debug(f"[INCREMENTAL] {rel_path}: content changed but outside the scanned list "
                             f"(whitelisted / excluded) — hash noted, not scanned")
                continue
            logger.info(f"[INCREMENTAL] content hash changed: {rel_path} "
                        f"({(prev or 'new')[:10]} → {h[:10]}) — rescanning the whole file")
            affected_files.append(fe)

        for rel_path in list(scoped):
            if rel_path not in seen_now and not (repo / rel_path).exists():
                removed.append(rel_path)
                self.results.pop(rel_path, None)
                self.node_hashes.pop(rel_path, None)
                self.files = [fe for fe in self.files if fe.relative != rel_path]
        if removed:
            logger.info(f"[INCREMENTAL] file(s) gone: {removed} — results dropped")

        # Plan item 8 (2026-09-05): an execution recorded by entry_point_wrapper
        # (published by the circuit as execution_proof) feeds the origin tracer —
        # the deepest in-target traceback frame is the measured root cause.
        proof_changed = False
        proof = circuit_state.get("execution_proof") or {}
        stamp = (proof.get("captured_at") or proof.get("executed_at")) if proof.get("status") == "MEASURED" else None
        if stamp and stamp != self._last_proof_stamp:
            self._last_proof_stamp = stamp
            proof_changed = True
            exc = proof.get("exception") or {}
            frames = exc.get("frames") or []
            traces: list[dict[str, Any]] = []
            if frames:
                root = frames[-1]
                traces.append({
                    "function": root.get("function"), "file": root.get("file"), "line": root.get("line"),
                    "wall_type": exc.get("type"), "message": exc.get("message"),
                    "stack_depth": len(frames), "root_cause": f"{root.get('file')}:{root.get('line')} {exc.get('type')}",
                    "entry_point": proof.get("entry_point"), "executed_at": stamp,
                })
            self.cross_file_analysis["origin_trace_results"] = traces
            self.cross_file_analysis.setdefault("tier2_status", {})["origin_tracer"] = (
                f"MEASURED — executed proof from entry_point_wrapper ({proof.get('entry_point')}, "
                f"exit {proof.get('exit_code')}, {stamp}): "
                + (f"{len(frames)} in-target frame(s), root cause {traces[0]['root_cause']}" if traces
                   else (f"{exc.get('type')} raised, no in-target frame parsed" if exc else "no exception raised")))
            logger.info(f"[EXECUTED] proof consumed: {self.cross_file_analysis['tier2_status']['origin_tracer']}")

        if not affected_files and not removed and not proof_changed:
            return

        if affected_files:
            logger.info(f"[INCREMENTAL] Re-scanning {len(affected_files)} file(s): {[f.relative for f in affected_files]}")
            # Full-script rescan: validate entire file (all functions + module-level)
            new_results = await stage_ingest_incremental(self.validator, affected_files)
            # Replace ALL results for each edited file — edit changes context for everything
            for rel_path, frs in new_results.items():
                old_fails = sum(1 for f in self.results.get(rel_path, []) if not f.passed)
                new_fails = sum(1 for f in frs if not f.passed)
                logger.info(f"[INCREMENTAL] {rel_path}: {old_fails} failures → {new_fails} failures")
                self.results[rel_path] = frs

        # Semantic analysis on the whitelist-filtered baseline file list plus
        # the affected files (edits may change cross-file interactions)
        sem_paths = {fe.path for fe in self.files} | {fe.path for fe in affected_files}
        semantic_results = await stage_semantic(repo, files=sorted(sem_paths))

        # Flag + output; the baseline cross-file analysis is carried along and the edited
        # files are published as stale for it (item 1: the Builder prefixes their evidence STALE:)
        self._beat(force=True)
        issues, self.flagged_nodes, passed, failed, tracked = stage_flag(self.results, self.files)  # type: ignore[misc]  # FIX_54 ast-pos
        self.stale_files |= {fe.relative for fe in affected_files}
        stage_output(self.results, self.flagged_nodes, repo_path, passed, failed, tracked_test_rows=tracked,
                     cross_file=self.cross_file_analysis, semantic=semantic_results,
                     whitelist_functions=self.whitelist_functions,
                     stale_for_files=self.stale_files,
                     # T-07 (R7, 2026-09-30): the baseline's artifact report rides every edit cycle too —
                     # without it each edit rewrote the state with artifact_report = null (NOT MEASURED).
                     artifact_report=_artifact_report_dict(getattr(self, "artifact_report", None)))
        logger.info(f"[INCREMENTAL] Output written: {passed} passed, {failed} failed")

    # ── Main loop ────────────────────────────────────────────────────────
    async def _run_health_checks(self) -> list[dict[str, Any]]:
        """Run startup health checks — verify all detection modules are loaded."""
        checks: list[dict[str, Any]] = []

        # 1. Detection mixins (the 80+ NAI checks)
        modules = [
            ("core_checks", "CoreChecksMixin"),
            ("structural_checks", "StructuralChecksMixin"),
            ("math_checks", "MathChecksMixin"),
            ("advanced_checks", "AdvancedChecksMixin"),
            ("hallucination_checks", "HallucinationChecksMixin"),
            ("redundancy_checks", "RedundancyChecksMixin"),
            ("safety_checks", "SafetyChecksMixin"),
            ("style_checks", "StyleChecksMixin"),
            ("semantic_checks", "SemanticChecksMixin"),
            ("extended_semantic_checks", "ExtendedSemanticChecksMixin"),
        ]
        for mod_name, cls_name in modules:
            try:
                mod = __import__(f"no_aivalidator.detection.{mod_name}", fromlist=[cls_name])
                cls = getattr(mod, cls_name)
                n_checks = sum(1 for m in dir(cls) if m.startswith("_check_"))
                checks.append({"module": mod_name, "status": "ok", "checks": n_checks})
            except Exception as e:
                checks.append({"module": mod_name, "status": f"FAIL: {e}", "checks": 0})

        # 2. Signature engine (signature_engine/signatures.py)
        try:
            from signature_engine.signatures import AuthorshipSignatureDatabase as _FSD
            checks.append({"module": "authorship_signatures", "status": "ok", "checks": 0})
        except Exception:
            checks.append({"module": "authorship_signatures", "status": "unavailable", "checks": 0})

        # 3. Utils / code analysis
        try:
            from utils.code_analysis import graph as _g
            n_graph = sum(1 for m in dir(_g) if not m.startswith("_"))
            checks.append({"module": "code_analysis.graph", "status": "ok", "checks": n_graph})
        except Exception as e:
            checks.append({"module": "code_analysis.graph", "status": f"FAIL: {e}", "checks": 0})

        # 4. RootCause
        rca_mods = [
            "rca_main.import_graph", "rca_main.rca_unit",
            "rca_main.onion_peeler", "rca_main.constants",
        ]
        for fm in rca_mods:
            try:
                __import__(fm)
                checks.append({"module": fm.split(".")[-1], "status": "ok", "checks": 0})
            except Exception:
                checks.append({"module": fm.split(".")[-1], "status": "unavailable", "checks": 0})

        # 5. The Builder (item 1, 2026-09-08): candidates + the Ranker's decision live in the
        # fourth daemon; here only the rewriter map it dispatches through is checked importable.
        try:
            from .cheatsheets.cheatsheet_intelligence.knowledge_base import SolutionRanker as _SR
            assert hasattr(_SR, "decide")
            checks.append({"module": "builder_ranker", "status": "ok", "checks": 0})
        except Exception as e:
            checks.append({"module": "builder_ranker", "status": f"FAIL: {e}", "checks": 0})

        return checks

    async def run(self) -> None:
        """Main daemon loop."""
        logger.info("NoAI Validator Daemon starting...")
        logger.info(f"Watching: {CIRCUIT_STATE_FILE}")
        logger.info(f"Output:   {NOAI_STATE_FILE}")

        # FIX_46: take this daemon's slot on the circumference before anything polls.
        _off = _cadence_offset_s()
        if _off:
            logger.info(f"CADENCE: noai_validator takes its slot at +{_off:.4f}s (FIX_46 table)")
            await asyncio.sleep(_off)

        # Clear stale state from previous runs so dashboard starts clean
        _purge_noai_state_files()
        logger.info("Cleared stale NOAI state files")

        # ── Phase 1: Health checks ──
        _write_progress("HEALTH_CHECK", "Verifying detection modules...")
        await asyncio.sleep(0.3)  # brief pause so dashboard can render
        health = await self._run_health_checks()
        ok_count = sum(1 for c in health if c["status"] == "ok")
        total_checks = sum(c["checks"] for c in health)
        _write_progress("HEALTH_CHECK", f"{ok_count}/{len(health)} modules loaded — {total_checks} detection checks available",
                        progress=1.0, substeps=health)
        logger.info(f"Health check: {ok_count}/{len(health)} modules, {total_checks} checks")
        await asyncio.sleep(1.0)  # hold for visibility

        try:
            # ── Wait for circuit daemon ──
            _write_progress("WAITING", "Waiting for circuit daemon to populate target repo...")
            while self.running:
                state = read_file_locked(CIRCUIT_STATE_FILE)
                target = state.get("target_repo")
                nodes = state.get("nodes", [])

                phase = state.get("daemon_phase", "")
                if target and Path(target).is_dir() and phase in ("READY", "RUNNING"):
                    logger.info(f"Circuit ready (phase={phase}, {len(nodes)} nodes) — starting baseline scan")
                    self._beat(force=True)
                    try:
                        await self.run_baseline(target)
                    except Exception:
                        # S2: a first baseline that raises does not end the daemon — no target is recorded,
                        # so the steady-state loop below re-baselines it on its next tick (with backoff).
                        logger.error(f"[LOOP] baseline failed — retried by the monitoring loop:\n{traceback.format_exc()}")
                        self.target_repo = ""
                    break
                if target:
                    _write_progress("WAITING", f"Circuit initializing... (phase={phase})")
                    logger.info(f"Waiting for circuit daemon (phase={phase})...")
                else:
                    logger.info("Waiting for circuit_state.json...")
                self._beat()
                await asyncio.sleep(POLL_INTERVAL)

            # ── Phase 6: Monitoring ──
            # NOTE: Do NOT call _write_progress here — stage_output already wrote
            # the full results with phase=MONITORING. Calling _write_progress would
            # overwrite results_by_file/summary with just phase/detail metadata.
            logger.info("Monitoring for changes...")
            # S2 (2026-09-29): a failed tick is logged with its traceback and the loop goes on, backing off
            # 1s → 2s → … → 60s like the circuit's poll loop, reset by the next clean tick. A baseline that
            # raises leaves no target recorded, so the next tick re-baselines instead of editing a half state.
            backoff = 1
            max_backoff = 60
            while self.running:
                await asyncio.sleep(POLL_INTERVAL)
                self._beat()
                rebaselining = False
                try:
                    state = read_file_locked(CIRCUIT_STATE_FILE)
                    if not state:
                        continue

                    # Target change → purge stale state, then re-baseline
                    new_target = state.get("target_repo", "")
                    if new_target and new_target != self.target_repo:
                        logger.info(f"Target changed: {self.target_repo} → {new_target}")

                        # Purge state files in system_scripts/
                        _purge_noai_state_files()

                        # Flush in-memory caches
                        self.validator.clear_cache()

                        # Clear the find_spec lru_cache (a helper kept from the STRUCK always-pass validation)
                        try:
                            from .noai_validator.find_spec_cache import _cached_find_spec, CACHE_AVAILABLE  # always-pass validation LOST cut 3
                            if CACHE_AVAILABLE and _cached_find_spec is not None:
                                _cached_find_spec.cache_clear()
                        except Exception:
                            pass

                        # Clear carried state
                        self.results.clear()
                        self.cross_file_analysis.clear()
                        self.flagged_nodes.clear()
                        self.files.clear()
                        self.processed_tags.clear()
                        self.node_hashes.clear()
                        self._last_proof_stamp = None

                        rebaselining = True
                        await self.run_baseline(new_target)
                        backoff = 1
                        continue

                    # Plan item 7 (owner 2026-09-05): no follow-up re-baseline — the
                    # first scan got everything; from here only changed hashes are scanned.
                    await self.check_incremental(state)
                    self._refresh_intent_summary()   # I-23 / I-29 (run 117): summary.intent mirrors the intent file on every poll
                    backoff = 1
                except Exception:
                    logger.error(f"[LOOP] tick failed — retrying in {backoff}s:\n{traceback.format_exc()}")
                    if rebaselining:
                        self.target_repo = ""
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
        except asyncio.CancelledError:
            pass

        logger.info("Daemon stopped.")

    def _refresh_intent_summary(self) -> None:
        """I-23 / I-29 (run 117, 2026-09-15): `summary.intent` is a MIRROR of the intent file, refreshed on EVERY poll —
        not only on this daemon's own rescan (the lag pinned as I-23). The intent file is the source; this daemon owns
        the published copy (the Builder's `summary.intent` is the same read at ITS write and names this owner), so the
        two states carry the same counts on every poll. Rewrites the state only when the mirror actually changed."""
        if not self.target_repo:
            return
        state = read_file_locked(NOAI_STATE_FILE)
        summary = state.get("summary") if isinstance(state, dict) else None
        if not isinstance(summary, dict) or state.get("phase") != "MONITORING":
            return
        fresh = _intent_summary(self.target_repo)
        if summary.get("intent") == fresh:
            return
        summary["intent"] = fresh
        write_file_locked(NOAI_STATE_FILE, state)
        logger.info(f"[INTENT] summary.intent refreshed from {fresh.get('file')}: {fresh.get('facts_by_source')}")


# ── Entry point ──────────────────────────────────────────────────────────────
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="NoAI Validator Daemon")
    parser.add_argument("target", nargs="?", default=None,
                        help="Target directory to scan (one-shot baseline, no daemon loop)")
    args = parser.parse_args()

    daemon = NoAIValidatorDaemon()

    if args.target:
        # One-shot mode: run baseline on the given directory and exit
        target = Path(args.target).resolve()
        if not target.is_dir():
            logger.error(f"Not a directory: {target}")
            sys.exit(1)
        logger.info(f"One-shot scan: {target}")
        asyncio.run(daemon.run_baseline(str(target)))
    else:
        # Daemon mode: wait for circuit_state.json, then monitor
        try:
            asyncio.run(daemon.run())
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
