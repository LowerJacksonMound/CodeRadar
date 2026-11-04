"""
Knowledge Base Module for GRANULARIZE

Delivers minimal, targeted documentation bundles to agents.
The 'Answer Key' for Atomic Jobs.

Philosophy: "Agents are provided with the 'answer'... a very small set of 'docs'
that contain all answers and troubleshooting specific to that agent's very small
job scope." We are not sending them the whole manual. We are sending them a
"Cheat Sheet."

Stop 5.3: Knowledge Injection
- Lookup job_type in KnowledgeBase
- If unavailable, use local knowledge base
- Solution governed by job AND target repo context
- Generate "Cheat Sheet" with 1:1 correlation to agent's job:
  * Role description
  * Fix rules
  * Examples
  * Troubleshooting tips
- Attach docs_bundle to job
"""

from __future__ import annotations

import ast
import json
import logging
import math
import asyncio
import os
import re
import textwrap
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Final, List, Optional, Tuple, TypeVar, cast

# FIX_24 (2026-09-15): the cheatsheets "shared" tracing package (its only module, flow_tracer, existed
# nowhere) is archived under .archive/archived_20260915/no_aivalidator/cheatsheets/; the 24 `@trace`
# no-op decorators it fed were deleted with it — nothing traced, no sink ever existed.

F = TypeVar("F", bound=Callable[..., Any])

try:
    import yaml  # type: ignore[import-untyped]
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None


try:
    from shared.instrumentation.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Adapter: stdlib logger that accepts structlog-style kwargs without crashing.
    # Key fix: process() must strip non-standard kwargs BEFORE LoggerAdapter
    # forwards them to the underlying Logger (which rejects unknown kwargs).
    class _KwargsLogger(logging.LoggerAdapter):
        _STANDARD_KEYS = frozenset({'exc_info', 'stack_info', 'stacklevel', 'extra'})

        def process(self, msg, kwargs):
            extra_kw = {k: v for k, v in list(kwargs.items())
                        if k not in self._STANDARD_KEYS}
            for k in extra_kw:
                kwargs.pop(k)
            if extra_kw:
                parts = ", ".join(f"{k}={v}" for k, v in extra_kw.items())
                msg = f"{msg} [{parts}]"
            return msg, kwargs

    logger = _KwargsLogger(logging.getLogger(__name__), {})


# =============================================================================
# NAI CODE FIX GENERATORS — MOVED (item 4, 2026-09-08)
# =============================================================================
# The vetted rewriters (_nai_fix_mutable_default / _nai_fix_unsafe_subprocess /
# _nai_fix_unsafe_deserialization) and their AST-edit helpers now live in the registry
# package no_aivalidator/repair_generators/ (one row per deciding rule id; the Builder
# dispatches through repair_generators.for_rule). The section that stood here is archived
# verbatim at .archive/archived_20260908/no_aivalidator/cheatsheets/cheatsheet_intelligence/
# knowledge_base_fix_generators.py.txt. The 18 other _nai_fix_* names that KnowledgeBase.
# _find_specific_solution (uncalled since item 1) refers to never existed in this file.


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Main classes
    "KnowledgeBase",
    "CheatSheet",
    "SolutionRanker",
    "VerdictRanker",
    "Verdict",
    "ProjectProfile",
    "SolutionCandidate",
    # Statistics functions
    "get_knowledge_base_statistics",
    "reset_knowledge_base_statistics",
    # Constants
    "MAX_SAMPLE_FILES",
    "MAX_RCA_EVIDENCE",
    "MAX_CANDIDATES_DISPLAY",
]


# =============================================================================
# MODULE CONSTANTS
# =============================================================================

MAX_SAMPLE_FILES: Final[int] = 10         # Max Python files to sample for analysis
MAX_RCA_EVIDENCE: Final[int] = 3    # Max rca items to display
MAX_CANDIDATES_DISPLAY: Final[int] = 5    # Max solution candidates to show
MAX_KEYWORD_OVERLAP: Final[int] = 30      # Max points for keyword overlap
MAX_FIX_TERM_BONUS: Final[int] = 5        # Bonus for fix-related terms


# =============================================================================
# MODULE-LEVEL STATISTICS (thread-safe)
# =============================================================================

_stats_lock = threading.Lock()
_bundles_retrieved = 0
_cheatsheets_generated = 0
_solutions_ranked = 0


def get_knowledge_base_statistics() -> Dict[str, Any]:
    """Get knowledge base module statistics."""
    with _stats_lock:
        return {
            'bundles_retrieved': _bundles_retrieved,
            'cheatsheets_generated': _cheatsheets_generated,
            'solutions_ranked': _solutions_ranked,
        }


def reset_knowledge_base_statistics() -> None:
    """Reset knowledge base module statistics."""
    global _bundles_retrieved, _cheatsheets_generated, _solutions_ranked
    with _stats_lock:
        _bundles_retrieved = 0
        _cheatsheets_generated = 0
        _solutions_ranked = 0


# =============================================================================
# SOLUTION RANKER - Pick THE ONE solution from candidates
# =============================================================================
# Per app_rationale: Only ONE solution per CheatSheet. When we have multiple
# candidates (from local bundles), we must pick
# the BEST one based on target repo context.
# =============================================================================

@dataclass
class ProjectProfile:
    """Target repo characteristics for solution ranking."""
    uses_async: bool = False           # Project uses asyncio/await patterns
    frameworks: List[str] = field(default_factory=list)  # Django, Flask, FastAPI, etc.
    python_version: str = ""           # "3.10", "3.11", etc.
    typing_style: str = "none"         # "none", "type_hints", "strict"
    import_style: str = "relative"     # "relative", "absolute"
    code_patterns: Dict[str, Any] = field(default_factory=dict)  # Detected patterns
    # Item 8 (2026-09-15): the intent file's discrete facts (developer statement + Item 3's intent sources +
    # FIX_33's docs + Item 9's tester logs) — every value a fact the Ranker can hold; absent = empty, never wrong.
    domain: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    expected_inputs: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    runner: List[str] = field(default_factory=list)
    external_systems: List[str] = field(default_factory=list)
    statement_present: bool = False
    intent_facts_by_source: Dict[str, int] = field(default_factory=dict)
    # Item 9 (2026-09-15): the tester's failure logs as facts (source "tester") — the unit that failed under test
    # (`rel::func`), the exception observed, the literal the test expected vs got.
    tested_units: List[str] = field(default_factory=list)
    observed_exceptions: List[str] = field(default_factory=list)
    expected_literals: List[Tuple[str, str]] = field(default_factory=list)

    def has_intent(self) -> bool:
        return bool(self.entry_points or self.expected_inputs or self.expected_outputs or self.runner
                    or self.external_systems or self.domain or self.tested_units or self.observed_exceptions)
    

@dataclass
class SolutionCandidate:
    """A candidate solution with ranking metadata."""
    solution: str
    role: str
    before_code: str = ""
    after_code: str = ""
    if_stuck: str = ""
    steps: List[str] = field(default_factory=list)  # Ordered steps for LLM to follow

    # Source metadata
    source: str = "local"
    source_url: str = ""
    votes: int = 0
    accepted: bool = False

    # Observations (item 1 / FIX 11, 2026-09-08): facts the Builder establishes about the
    # candidate BEFORE the Ranker decides — never a verdict. Tokens:
    #   parse=ok | parse=fail:<msg>      the rewrite parses (or why not)
    #   differs=yes | differs=no         the rewrite differs from the broken code
    #   safety=clean | safety=<issue>    CodeAnalyzer security scan (one token per issue)
    #   quality=<issue>                  CodeAnalyzer quality notes (context only)
    #   tester=failed:<digest>           the tester failed this exact before/after (item 5)
    #   flow= complexity= idiom= deps= defensive=   FIX_42 (owner ruling 2026-09-15): the Reviewer's five
    #                                    STATIC observations of after_code against before_code, seeded at
    #                                    construction (CodeAnalyzer.observe_pair) so every publisher of
    #                                    `observations` carries them; SolutionRanker weighs them below intent.
    # SolutionRanker.decide() treats parse=fail, differs=no and tester=failed as not
    # pickable; everything else is evidence.
    observations: List[str] = field(default_factory=list)
    # Item 8 (2026-09-15): the discrete intent facts this candidate matched / contradicted — the Ranker's
    # `_score_framework_match` records them, `decide()` cites them in `why`.
    profile_matches: List[str] = field(default_factory=list)
    
    # Ranking scores (0-100 each, weighted sum = final score)
    error_match_score: float = 0.0     # How well it matches the error pattern
    style_match_score: float = 0.0     # How well code style matches target repo
    framework_match_score: float = 0.0 # Uses same frameworks as target
    quality_score: float = 0.0         # SO votes, accepted status
    rca_score: float = 0.0       # Addresses identified root cause
    static_score: float = 0.0    # FIX_43a: methods 2-7 (the six static families) as a 0-100 weighted score, for display
    method_scores: Dict[str, float] = field(default_factory=dict)   # FIX_43a: the seven methods, each 0-100

    def __post_init__(self) -> None:
        """FIX_42 / FIX_43a: seed the Reviewer's seven static tokens once, from the code pair, before anyone reads
        `observations` (the Builder snapshots them before the Ranker decides — item 1 / FIX 11 order)."""
        if (self.before_code or self.after_code) and not any(o.startswith("flow=") for o in self.observations):
            from ..cheatsheet_reviewer import CodeAnalyzer  # the Reviewer; local import keeps the package acyclic
            self.observations = list(self.observations) + getattr(CodeAnalyzer, 'observe_pair')(self.before_code, self.after_code)
    
    @property
    def intent_alignment(self) -> float:
        """The Ranker's intent-side scores (error match, style match, the profile's intent facts, RCA match) in their
        FIX_11 proportions, re-normalised to 0-100 — the "intent" half of method 1."""
        return sum(getattr(self, k) * w for k, w in _INTENT_SIDE_WEIGHTS.items()) / sum(_INTENT_SIDE_WEIGHTS.values())

    @property
    def total_score(self) -> float:
        """FIX_43a: the selection total = Σ method weight × method score / 100, over the owner's seven methods
        (RANKER_METHOD_WEIGHTS; weights sum to 100, every method 0-100, so the total is 0-100). `method_scores` is
        filled by SolutionRanker.rank_candidates; before that the six static methods read as their "other" entry
        and method 1 as intent alignment alone."""
        return sum(m["weight"] * self.method_scores.get(name, 0.0) for name, m in RANKER_METHOD_WEIGHTS.items()) / 100.0


# FIX_43 part (a) (owner ruling 2026-09-15 late — RANKER_METHODS_RULING_2026-09-15.md): THE SEVEN METHODS, ONE table.
# The owner's weights are the dimension weights of the selection total (they sum to 100). Each method scores 0-100:
#   method 1 = (intent alignment + logic soundness) / 2 — intent alignment is the Ranker's existing intent-side
#              scores (error match, style match, the profile's intent facts, RCA match) re-normalised to 0-100;
#              logic soundness is the Reviewer's `flow=` token by the table below;
#   methods 2-7 = the Reviewer's `idiom= complexity= defensive= readability= deps= traps=` tokens by the table.
# A token family's score is its value's entry (0-100), else the family's "other"; a `+`-joined value scores its
# lowest part (the worst fact counts). NO RULE-OUTS: a trap or a fatal flow flaw is a heavily weighted fact, never
# a gate — no token here is ever unpickable. Source trust / votes (`quality_score`) are not one of the seven: still
# computed and recorded on the candidate, weight 0 in the total.
# FIX_43 (b) (owner rulings 2026-09-16): `opaque` (a shape's placeholder-only statement — the reading is partial)
# weighs like `unreadable` in every family; `defensive=` gained the risky-call facts — removing a risky call (100)
# is worth more than a guard around one that stays (the `+`-joined value scores its lowest part: keeps 40).
# S10b / I-80b (owner ruling 2026-09-29): a "not implemented" placeholder — a rewrite that adds a `raise
# NotImplementedError` to a body that did real work — leaves no code for these tokens to read, so its `same` /
# `same_paths` readings described the placeholder's absence of change, not a sound result (run 125: +23 points in
# method 1 over a real branch collapse). Every family reads such a candidate as `placeholder`, weight 0, so a
# placeholder can never outrank a real simplification of the same rule by the score (see candidate_is_placeholder).
RANKER_METHOD_WEIGHTS: Final[Dict[str, Dict[str, Any]]] = {
    "intent_logic": {"weight": 35, "token": "flow",        "values": {"same_paths": 100, "unreadable": 50, "opaque": 50, "placeholder": 0, "other": 33}},
    "builtins":     {"weight": 20, "token": "idiom",       "values": {"builtin_used": 100, "same": 80, "unreadable": 40, "opaque": 40, "placeholder": 0, "other": 20}},
    "big_o":        {"weight": 15, "token": "complexity",  "values": {"same": 100, "shallower": 100, "unreadable": 50, "opaque": 50, "placeholder": 0, "other": 25}},
    "defensive":    {"weight": 10, "token": "defensive",   "values": {"adds_guard": 100, "removes_risky_call": 100, "same": 67,
                                                                       "risky_call_unknown": 50, "keeps_risky_call": 40, "unreadable": 33,
                                                                       "opaque": 33, "placeholder": 0, "adds_risky_call": 10, "other": 20}},
    "readability":  {"weight": 10, "token": "readability", "values": {"same": 100, "flatter": 100, "fewer_branches": 100, "unreadable": 50, "opaque": 50, "placeholder": 0, "other": 30}},
    "deps":         {"weight": 5,  "token": "deps",        "values": {"none_added": 100, "stdlib_only": 100, "third_party_known": 75, "needs_py_ok": 60, "unreadable": 50, "opaque": 50, "placeholder": 0, "other": 25}},
    "traps":        {"weight": 5,  "token": "traps",       "values": {"none": 100, "removed": 100, "unreadable": 50, "opaque": 50, "placeholder": 0, "other": 0}},
}
# FIX_43 (b), Call B (owner 2026-09-16, hand-check #4): inside method 1, whether the candidate answers the row's
# deciding rule (`rule=` token = the row's first rule id) or a neighbour rule on the same row — weighed with the
# intent word match and `flow=`, never a veto. Not weighed when the Builder passes no deciding rule.
_ANSWERS_VALUES: Final[Dict[str, int]] = {"row": 100, "neighbour": 25}
_FLOW_VALUATION_PATH = Path(__file__).resolve().parents[3] / "system_scripts" / "flow_valuation.json"


def _flow_valuation() -> Dict[str, Any]:
    """M-128: the owner's adaptive flow table (system_scripts/flow_valuation.json); absent or unreadable → {} (every
    rule keeps the original flow table)."""
    try:
        return json.loads(_FLOW_VALUATION_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
RANKER_METHOD_LABELS: Final[Dict[str, str]] = {
    "intent_logic": "intent alignment & logic soundness", "builtins": "built-in function & library leverage",
    "big_o": "algorithmic complexity (Big O)", "defensive": "input validation & defensive structure",
    "readability": "readability & cyclomatic complexity", "deps": "dependency & environment footprint",
    "traps": "mutable defaults & scope traps",
}
assert sum(m["weight"] for m in RANKER_METHOD_WEIGHTS.values()) == 100
# intent alignment: the existing intent-side scores in their FIX_11 proportions (0.35 / 0.20 / 0.10 / 0.20 → sum 0.85)
_INTENT_SIDE_WEIGHTS: Final[Dict[str, float]] = {"error_match_score": 0.35, "style_match_score": 0.20,
                                                  "framework_match_score": 0.10, "rca_score": 0.20}

# Observation tokens that make a candidate NOT pickable (item 1 / FIX 11, 2026-09-08).
# S5-1 (2026-09-17, the owner's gate sentence): `gate=withheld:<check>` joins them — G0 withheld this
# rewrite at the publish choke point (repair_generators.candidates_of), so the Ranker may not ship it.
# The candidate is still offered, still counted and still shown; the reason rides in decision.why.
_UNPICKABLE_PREFIXES: Final[tuple[str, ...]] = ("parse=fail", "differs=no", "tester=failed", "gate=withheld",
                                                  "filter=fail", "stage=fail")   # solution gate items 2-5 (owner 2026-10-08)


def candidate_pickable(candidate: "SolutionCandidate") -> bool:
    """True unless an observation says the candidate cannot be shipped as written."""
    return not any(o.startswith(_UNPICKABLE_PREFIXES) for o in candidate.observations)


def candidate_rule(candidate: "SolutionCandidate") -> Optional[str]:
    """The rule this candidate answers — its `rule=<id>` observation (FIX_43 (b)), or None."""
    for o in candidate.observations:
        if o.startswith("rule="):
            return o[len("rule="):].strip()
    return None


# S10b / I-80 (owner ruling 2026-09-29 (a)): THE TIE-BREAK, written down and applied AFTER the score — it only
# orders candidates whose selection totals are exactly equal, in this order:
#   1. an applicable rewrite beats a suggestion (a prescribed shape: FIX_41's, or a rewriter's named "no rewrite;
#      emit this shape" entry such as NAI-021S's `no_rewrite_shape`, which the Builder publishes as one);
#   2. a real simplification beats a "not implemented" placeholder;
#   3. a stable key: rule id (its place in the row's published rule ids — the validator's order, deciding rule
#      first — then the id's text); inside one rule the smaller rewrite (fewer after-code characters), then the
#      variant's name; the list index only as the very last fallback (two candidates identical in all of these).
# A variant list's ORDER is therefore no longer the policy: reversing a list never changes the pick.
TIE_BREAK_STEPS: Final[tuple[str, ...]] = ("rewrite over suggestion", "simplification over placeholder",
                                           "rule id", "smaller rewrite", "variant name", "list index")
PLACEHOLDER_TOKEN: Final[str] = "placeholder=adds_not_implemented"


def candidate_is_suggestion(candidate: "SolutionCandidate") -> bool:
    """True for a suggestion — a shape the client renders — rather than a rewrite the seat applies."""
    return candidate.source == "prescribed" or "kind=prescribed" in candidate.observations


def _not_implemented_raises(tree: ast.AST) -> int:
    count = 0
    for n in ast.walk(tree):
        exc = n.exc if isinstance(n, ast.Raise) else None
        name = exc.func if isinstance(exc, ast.Call) else exc
        if isinstance(name, ast.Name) and name.id == "NotImplementedError":
            count += 1
    return count


def _declared_only(tree: ast.AST) -> bool:
    """Every function in the snippet is declaration alone (docstring, `pass`, `...`, a NotImplementedError raise) —
    the body NAI-120 flags, where the stub IS the rule's repair rather than a placeholder for real work."""
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for f in funcs:
        for st in f.body:
            if isinstance(st, ast.Pass) or (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)):
                continue
            if isinstance(st, ast.Raise) and _not_implemented_raises(st):
                continue
            return False
    return bool(funcs)


def candidate_is_placeholder(candidate: "SolutionCandidate") -> bool:
    """S10b / I-80b: a rewrite that adds a `raise NotImplementedError` to code that did real work — it answers the
    rule by removing behaviour, not by simplifying it. A suggestion is never one (it is not applied); a declared-only
    body (NAI-120's stub) is not one; a side that does not parse is judged by the Reviewer's `unreadable`, not here."""
    if candidate_is_suggestion(candidate):
        return False
    try:
        before = ast.parse(textwrap.dedent(candidate.before_code or ""))
        after = ast.parse(textwrap.dedent(candidate.after_code or ""))
    except SyntaxError:
        return False
    return _not_implemented_raises(after) > _not_implemented_raises(before) and not _declared_only(before)


def foreign_rule_refusal(candidate: "SolutionCandidate", row_rules: Optional[List[str]]) -> str:
    """I-132 (session 8, run 160) — the cross-rule refusal, in ONE place.

    The Ranker may select `solution_<rule>` only when `<rule>` is a rule of the ROW. A candidate
    built for any other rule is not a candidate at all: it is refused before ranking, and the
    reason names both rules. Until now nothing checked this — membership held only because
    `BuilderDaemon._generate` happens to dispatch the registry from the same list the row carries,
    so any future generator that widened its dispatch would have shipped a foreign shape in
    silence. Returns '' when the candidate may be ranked, the refusal sentence otherwise.

    NO-RULE-OUTS (RANKER_METHODS_RULING 2026-09-15) is untouched: a candidate answering a
    NEIGHBOUR rule that IS on the row stays fully pickable and is weighed by method 1's
    answers:row / answers:neighbour, exactly as Call B ruled.
    """
    if not row_rules:
        return ""
    rule = candidate_rule(candidate)
    if rule is None or rule in row_rules:
        return ""
    return (f"refused: candidate `{candidate.role}` answers {rule}, which is not a rule of this row "
            f"({', '.join(row_rules)}) — a candidate from another rule is not a candidate (I-132)")


@dataclass
class Decision:
    """The Ranker's one answer for one finding (item 1 / FIX 11, 2026-09-08).

    pick        — the chosen candidate, or None (no candidate was pickable / none offered)
    why         — the reason in words: the observations of every candidate and, when a pick
                  was made, which role won over how many. ONE PLACE TO LOOK: this string is
                  what BUILDER_STATE.json rows[].decision.why carries; nothing else records
                  a reason.
    considered  — one record per candidate: role, observations, pickable, and the Ranker's
                  own selection total for the pickable ones (the decision-point number).
    """
    pick: Optional["SolutionCandidate"]
    why: str
    considered: List[Dict[str, Any]] = field(default_factory=list)


class SolutionRanker:
    """
    Ranks solution candidates using target repo context.
    
    Uses all available data to pick THE ONE best solution:
    - Error message patterns
    - Target repo code style (async/sync, typing, naming)
    - Framework alignment (Django, Flask, FastAPI, etc.)
    - RootCause evidence (addresses root cause)
    - Quality signals (SO votes, accepted answers)
    """
    
    def __init__(self, project_profile: Optional[ProjectProfile] = None):
        self.profile = project_profile or ProjectProfile()
        # S10b / I-80: the last rank_candidates() ordering and each candidate's tie-break key (by id), so
        # deciding_method() names the runner-up and the step that broke an exact tie from the same ranking
        self.last_ranking: List[SolutionCandidate] = []
        self._tie_keys: Dict[int, Tuple[Any, ...]] = {}
        self._row_rules: List[str] = []

    @classmethod
    async def from_repo_path(cls, repo_path: str) -> 'SolutionRanker':
        """Create a ranker by analyzing the target repo."""
        logger.debug("from_repo_path called", repo_path=repo_path)
        profile = await cls._analyze_repo(repo_path)
        logger.debug("from_repo_path result",
                     frameworks=profile.frameworks,
                     uses_async=profile.uses_async)
        return cls(project_profile=profile)

    @staticmethod
    async def _analyze_repo(repo_path: str) -> ProjectProfile:
        """Analyze target repo to build profile."""
        logger.debug("_analyze_repo called", repo_path=repo_path)
        from pathlib import Path
        
        # Try to use aiofiles for async I/O, fallback to sync
        try:
            import aiofiles
            HAS_AIOFILES = True
        except ImportError:
            HAS_AIOFILES = False
        
        profile = ProjectProfile()
        repo = Path(repo_path)
        
        async def read_file_content(file_path: Path) -> str:
            """Read file content, using aiofiles if available."""
            if HAS_AIOFILES:
                async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                    return await f.read()
            else:
                # Fallback to sync read
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
        
        try:
            # Check pyproject.toml for dependencies/frameworks
            pyproject = repo / "pyproject.toml"
            if pyproject.exists():
                content = await read_file_content(pyproject)
                profile = SolutionRanker._parse_pyproject(content, profile)
            
            # Check requirements.txt as fallback
            requirements = repo / "requirements.txt"
            if requirements.exists():
                content = await read_file_content(requirements)
                profile = SolutionRanker._parse_requirements(content, profile)

            # Item 8 (2026-09-15): the intent file — the developer's statement (labelled developer) and every
            # intent-bearing source's facts (Item 3's intent sources, FIX_33's docs, Item 9's tester logs) —
            # read after the packaging files; frameworks merged, the discrete fields filled from the facts.
            profile = SolutionRanker._read_intent_file(repo, profile)
            
            # Sample Python files for patterns
            from rca_main.constants import live_py_files as _live_py_files  # FIX_15: the ONE contained walk
            py_files = _live_py_files(repo)[:MAX_SAMPLE_FILES]  # Sample up to MAX files
            for py_file in py_files:
                try:
                    content = await read_file_content(py_file)
                    profile = SolutionRanker._analyze_code_patterns(content, profile)
                except Exception:
                    continue
                    
        except Exception as e:
            logger.warning("Repo analysis error", error=str(e))

        return profile
    
    @staticmethod
    def _read_intent_file(repo: "Path", profile: ProjectProfile) -> ProjectProfile:
        """Item 8: fill the profile's discrete fields from `system_scripts/intent_<repoid>.json` (reader:
        `intent_file.read`). No file → nothing changes (absent, never wrong)."""
        try:
            import sys as _sys
            _ss = str(Path(__file__).resolve().parents[3] / "system_scripts")
            if _ss not in _sys.path:
                _sys.path.insert(0, _ss)
            import intent_file as _intent  # type: ignore
        except Exception as e:
            logger.debug("intent file reader unavailable", error=str(e))
            return profile
        try:
            data = _intent.read(repo)
        except Exception as e:
            logger.debug("intent file unreadable", error=str(e))
            return profile
        profile.statement_present = bool(data.get("statement"))
        profile.intent_facts_by_source = _intent.facts_by_source(data)
        profile.domain = _intent.facts_of(data, "domain")
        # entry points are IDENTIFIERS the code can be matched against: the developer's corroborated `entry_point`
        # facts as they are; an intent source's `entry_points` line (a CI `run:` line, a console-script line, a
        # README command) reduced to its module / script name — `python -m X` → X, `name = mod:fn` → name,
        # `X.py` → X; a line that names none is not an entry point for the profile (it stays a fact in the file).
        _eps: List[str] = list(_intent.facts_of(data, "entry_point"))
        for v in _intent.facts_of(data, "entry_points"):
            m = (re.search(r"python3?\s+-m\s+([A-Za-z_][\w.]*)", v) or re.match(r"\s*([A-Za-z_][\w-]*)\s*=\s*[\w.]+:", v)
                 or re.match(r"\s*([A-Za-z_][\w.]*)$", v) or re.search(r"\b([A-Za-z_]\w*)\.py\b", v))
            if m and m.group(1) not in _eps:
                _eps.append(m.group(1))
        profile.entry_points = _eps
        profile.expected_inputs = _intent.facts_of(data, "expected_input")
        profile.expected_outputs = _intent.facts_of(data, "expected_output")
        profile.runner = _intent.facts_of(data, "runner")
        profile.external_systems = _intent.facts_of(data, "external_system")
        for fw in _intent.facts_of(data, "framework") + _intent.facts_of(data, "frameworks"):
            if fw.lower() not in [x.lower() for x in profile.frameworks]:
                profile.frameworks.append(fw.lower())
        # Item 9: the tester's facts (runner merged above through facts_of, every source)
        profile.tested_units = _intent.facts_of(data, "function_under_test", ["tester"]) + [
            m for m in _intent.facts_of(data, "module_under_test", ["tester"])
            if not any(u.startswith(m + "::") for u in _intent.facts_of(data, "function_under_test", ["tester"]))]
        profile.observed_exceptions = _intent.facts_of(data, "exception_type", ["tester"])
        by_digest: Dict[str, Dict[str, str]] = {}
        for f in data.get("facts") or []:
            if f.get("source") == "tester" and f.get("fact") in ("expected_literal", "actual_literal"):
                by_digest.setdefault(str(f.get("evidence", "")).split(" | ")[0], {})[f["fact"]] = str(f["value"])
        profile.expected_literals = [(d["expected_literal"], d["actual_literal"]) for d in by_digest.values()
                                     if "expected_literal" in d and "actual_literal" in d]
        return profile

    @staticmethod
    def _parse_pyproject(content: str, profile: ProjectProfile) -> ProjectProfile:
        """Extract framework info from pyproject.toml."""
        content_lower = content.lower()
        
        # Detect frameworks
        frameworks = []
        if 'django' in content_lower:
            frameworks.append('django')
        if 'flask' in content_lower:
            frameworks.append('flask')
        if 'fastapi' in content_lower:
            frameworks.append('fastapi')
            profile.uses_async = True
        if 'asyncio' in content_lower or 'aiohttp' in content_lower or 'aiofiles' in content_lower:
            profile.uses_async = True
        if 'pytest' in content_lower:
            frameworks.append('pytest')
        if 'sqlalchemy' in content_lower:
            frameworks.append('sqlalchemy')
        if 'pydantic' in content_lower:
            frameworks.append('pydantic')
            
        profile.frameworks = frameworks
        
        # Detect Python version
        import re
        version_match = re.search(r'python\s*[>=<]+\s*["\']?(\d+\.\d+)', content_lower)
        if version_match:
            profile.python_version = version_match.group(1)
            
        return profile
    
    @staticmethod
    def _parse_requirements(content: str, profile: ProjectProfile) -> ProjectProfile:
        """Extract framework info from requirements.txt."""
        content_lower = content.lower()
        
        if 'django' in content_lower:
            profile.frameworks.append('django')
        if 'flask' in content_lower:
            profile.frameworks.append('flask')
        if 'fastapi' in content_lower:
            profile.frameworks.append('fastapi')
            profile.uses_async = True
        if 'asyncio' in content_lower or 'aiohttp' in content_lower:
            profile.uses_async = True
            
        return profile
    
    @staticmethod
    def _analyze_code_patterns(content: str, profile: ProjectProfile) -> ProjectProfile:
        """Detect coding patterns from Python source."""
        # Detect async usage
        if 'async def' in content or 'await ' in content:
            profile.uses_async = True
            
        # Detect typing style
        if ': ' in content and '->' in content:
            profile.typing_style = "type_hints"
        if 'from typing import' in content:
            profile.typing_style = "type_hints"
            
        # Detect import style
        if 'from .' in content:
            profile.import_style = "relative"
        elif 'from ' in content and ' import ' in content:
            profile.import_style = "absolute"
            
        return profile
    
    def rank_candidates(
        self,
        candidates: List[SolutionCandidate],
        error_message: str,
        rca_evidence: Optional[List[str]] = None,
        target_code: str = "",
        deciding_rule: Optional[str] = None,
    ) -> Optional[SolutionCandidate]:
        """
        Rank candidates and return THE BEST one. `deciding_rule` (FIX_43 (b), Call B): the row's deciding rule id —
        method 1 then weighs each candidate's `rule=` token as answers:row / answers:neighbour.

        Args:
            candidates: List of solution candidates
            error_message: The error being fixed
            rca_evidence: Root cause hints from Phase 6
            target_code: Code around the error location

        Returns:
            The single best solution candidate
        """
        logger.debug("rank_candidates called",
                     n_candidates=len(candidates),
                     error_len=len(error_message),
                     n_rca=len(rca_evidence or []))
        if not candidates:
            return None

        # ALWAYS-SCORE (Phase-5 H2): scoring runs even for a single candidate.
        # The ranker is the app's single decision point — every selection must
        # carry real scores (recorded as selection metadata in the cheatsheet),
        # never a silent index-0 bypass that discards the assembled evidence.
        rca_evidence = rca_evidence or []
        
        for candidate in candidates:
            # Score each dimension
            candidate.error_match_score = self._score_error_match(
                candidate, error_message
            )
            candidate.style_match_score = self._score_style_match(
                candidate, target_code
            )
            candidate.framework_match_score = self._score_framework_match(
                candidate
            )
            candidate.quality_score = self._score_quality(candidate)
            candidate.rca_score = self._score_rca_match(
                candidate, rca_evidence
            )
            candidate.method_scores = self._score_methods(candidate, deciding_rule)   # FIX_43a: the seven methods
            candidate.static_score = self._static_display_score(candidate)
        
        # Sort by total score, then THE TIE-BREAK (S10b / I-80) between exactly equal totals; return best
        self._tie_keys = {id(c): self._tie_key(c, i) for i, c in enumerate(candidates)}
        ranked = sorted(candidates, key=lambda c: (-c.total_score,) + self._tie_keys[id(c)])
        self.last_ranking = ranked

        best = ranked[0]
        logger.debug("rank_candidates result",
                     best_source=best.source,
                     best_score=round(best.total_score, 1),
                     best_votes=best.votes,
                     best_accepted=best.accepted,
                     n_candidates=len(candidates))

        return best

    def decide(
        self,
        candidates: List[SolutionCandidate],
        *,
        error_message: str,
        rca_evidence: Optional[List[str]] = None,
        target_code: str = "",
        deciding_rule: Optional[str] = None,
        row_rules: Optional[List[str]] = None,
        facts: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """THE decision point (item 1 / FIX 11, 2026-09-08): every fact reaches the Ranker
        BEFORE it picks, as observation tokens on the candidates; nothing overturns the
        pick afterwards. A candidate observed parse=fail, differs=no or tester=failed is
        not pickable. None pickable → pick=None and `why` = the observations, so the
        reason a finding has no fix lives in exactly one place.
        """
        # M-127 (owner 2026-10-08): `facts` = the row's structured intent / function intent / context dicts. Held on the
        # Ranker for the owner's weighting method (a weights table); nothing here weighs them yet.
        self.last_facts = facts or {}
        considered: List[Dict[str, Any]] = []
        pickable: List[SolutionCandidate] = []
        refusals: List[str] = []
        for c in candidates:
            # I-132: a candidate from a rule that is not on this row is refused BEFORE ranking —
            # it is not a candidate, so it is never scored and never picked; it stays visible,
            # counted and published, with the reason naming both rules.
            refused = foreign_rule_refusal(c, row_rules)
            ok = (not refused) and candidate_pickable(c)
            rec: Dict[str, Any] = {"role": c.role, "observations": list(c.observations), "pickable": ok}
            if refused:
                rec["refused"] = refused
                refusals.append(refused)
            considered.append(rec)
            if ok:
                pickable.append(c)

        def _obs(c: SolutionCandidate) -> str:
            return f"{c.role}[{', '.join(c.observations) or 'no observations'}]"

        if not candidates:
            return Decision(pick=None, why="no candidates offered", considered=considered)
        if not pickable:
            why = ("; ".join(refusals) + "; " if refusals else "") + \
                  "no pickable candidate: " + "; ".join(_obs(c) for c in candidates)
            # Item 9: the tester's facts about this infraction are cited even when nothing is pickable
            notes = self.profile_notes_for(target_code or "".join(c.before_code for c in candidates))
            if notes:
                why += "; profile: " + ", ".join(notes)
            return Decision(pick=None, why=why, considered=considered)

        self._row_rules = list(row_rules or [])   # the tie-break's rule step reads the row's published rule order
        best = self.rank_candidates(pickable, error_message=error_message,
                                    rca_evidence=rca_evidence, target_code=target_code, deciding_rule=deciding_rule)
        for rec in considered:
            if rec["pickable"]:
                cand = next(c for c in pickable if c.role == rec["role"])
                rec["selection_total"] = round(cand.total_score, 2)
                rec["method_scores"] = {k: round(v, 1) for k, v in cand.method_scores.items()}   # FIX_43a
                rec["observations"] = list(cand.observations)   # FIX_43 (b): carries answers= once weighed
        if best is None:  # rank_candidates only returns None for an empty list — kept explicit
            return Decision(pick=None, why="ranker returned no pick", considered=considered)
        others = [c for c in pickable if c is not best]
        why = (("; ".join(refusals) + "; " if refusals else "")   # I-132: refusals are named first
               + f"picked {best.role} over {len(others)} other pickable candidate(s)"
               f" of {len(candidates)} offered; deciding method: {self.deciding_method(best, others)}; "
               + "; ".join(_obs(c) for c in candidates))   # FIX_43a: the deciding method is named
        # Item 8 (2026-09-15): the profile's intent facts the pick matched (or contradicted) are cited here —
        # the ONE place a reason lives; nothing when the profile holds no facts.
        if self.profile.has_intent() or self.profile.statement_present:
            cited = list(best.profile_matches) + [n for n in self.profile_notes_for(target_code or best.before_code)
                                                  if n not in best.profile_matches]
            why += (f"; profile: {', '.join(cited)}" if cited else "; profile: no intent fact matched")
        return Decision(pick=best, why=why, considered=considered)
    
    def _score_error_match(self, candidate: SolutionCandidate, error_msg: str) -> float:
        """Score how well solution addresses the error (0-100)."""
        if not error_msg:
            return 50.0  # Neutral
        
        score = 0.0
        error_lower = error_msg.lower()
        solution_lower = (candidate.solution + candidate.after_code).lower()
        
        # Extract error type
        error_types = [
            'syntaxerror', 'indentationerror', 'nameerror', 'typeerror',
            'importerror', 'modulenotfounderror', 'attributeerror',
            'keyerror', 'valueerror', 'indexerror', 'zerodivisionerror',
            'filenotfounderror', 'oserror', 'runtimeerror', 'assertionerror'
        ]
        
        for err_type in error_types:
            if err_type in error_lower:
                if err_type in solution_lower:
                    score += 40  # Direct error type match
                break
        
        # Check for keyword overlap
        error_keywords = set(error_lower.split())
        solution_keywords = set(solution_lower.split())
        overlap = len(error_keywords & solution_keywords)
        score += min(overlap * 5, 30)  # Up to 30 points for keyword overlap
        
        # Bonus for fix-related terms
        fix_terms = ['fix', 'solve', 'solution', 'correct', 'change', 'add', 'remove']
        for term in fix_terms:
            if term in solution_lower:
                score += 5
                break
        
        return min(score, 100.0)
    
    def _score_style_match(self, candidate: SolutionCandidate, target_code: str) -> float:
        """Score how well solution matches target code style (0-100)."""
        score = 50.0  # Start neutral
        
        if not target_code:
            return score
        
        code = candidate.after_code or candidate.solution
        if not code:
            return score
        
        # Check async alignment
        target_uses_async = 'async def' in target_code or 'await ' in target_code
        solution_uses_async = 'async def' in code or 'await ' in code
        
        if self.profile.uses_async:
            # Repo uses async - prefer async solutions
            if solution_uses_async:
                score += 25
            elif target_uses_async and not solution_uses_async:
                score -= 15  # Mismatch penalty
        else:
            # Repo doesn't use async - prefer sync solutions
            if not solution_uses_async:
                score += 15
            elif solution_uses_async:
                score -= 10  # Async solution for sync repo
        
        # Check type hint alignment
        has_type_hints = ':' in code and '->' in code
        if self.profile.typing_style == "type_hints":
            if has_type_hints:
                score += 15
        
        return min(max(score, 0.0), 100.0)
    
    def _score_framework_match(self, candidate: SolutionCandidate) -> float:
        """Score framework alignment (0-100). Item 8 (2026-09-15): the intent file's DISCRETE facts count too —
        a stated entry point / external system / expected format / runner present in the after-code is a match;
        a stated entry point present in the before-code and absent in the after-code is a MISMATCH (the rewrite
        dropped what the developer named); no facts at all → neutral. The matches are recorded on the candidate
        (`profile_matches`) so `decide()` can cite them; no new weight in `total_score`."""
        if not self.profile.frameworks and not self.profile.has_intent():
            return 50.0  # Neutral if unknown
        
        score = 50.0
        code = (candidate.solution + candidate.after_code).lower()
        candidate.profile_matches = []
        
        for framework in self.profile.frameworks:
            if framework.lower() in code:
                score += 20  # Framework match bonus
                candidate.profile_matches.append(f"framework:{framework}")
        
        # Check for framework-specific patterns
        if 'fastapi' in self.profile.frameworks or 'aiohttp' in self.profile.frameworks:
            if 'async' in code or 'await' in code:
                score += 10

        before = candidate.before_code.lower()
        after = candidate.after_code.lower()
        for kind, values in (("entry_point", self.profile.entry_points), ("external_system", self.profile.external_systems),
                             ("expected_input", self.profile.expected_inputs), ("expected_output", self.profile.expected_outputs),
                             ("runner", self.profile.runner)):
            for v in values:
                tok = v.lower().split(".")[0]
                if tok and re.search(r"\b" + re.escape(tok) + r"\b", after):
                    score += 10
                    candidate.profile_matches.append(f"{kind}:{v}")
                elif kind == "entry_point" and tok and re.search(r"\b" + re.escape(tok) + r"\b", before):
                    score -= 20
                    candidate.profile_matches.append(f"{kind}:{v} DROPPED by the rewrite")
        # Item 9: a candidate that references a unit the tester saw fail is a match (the fix touches what failed)
        for unit in self.profile.tested_units:
            fn = unit.split("::")[-1] if "::" in unit else Path(unit).stem
            if fn and re.search(r"\b" + re.escape(fn) + r"\b", after):
                score += 10
                candidate.profile_matches.append(f"tested_unit:{unit}")
        
        return max(0.0, min(score, 100.0))

    def profile_notes_for(self, code: str) -> List[str]:
        """Item 9: the tester's facts that name THIS infraction's code — cited in `decide()`'s `why` whether or not a
        candidate is picked (a failed solution's row cites what the tester observed): the tested unit whose function
        is in the code, the exception observed, the literal expected vs got."""
        notes: List[str] = []
        low = (code or "").lower()
        hit = False
        for unit in self.profile.tested_units:
            fn = unit.split("::")[-1] if "::" in unit else Path(unit).stem
            if fn and re.search(r"\b" + re.escape(fn.lower()) + r"\b", low):
                notes.append(f"tested_unit:{unit}")
                hit = True
        if hit:
            notes += [f"observed_exception:{e}" for e in self.profile.observed_exceptions]
            notes += [f"expected_literal:{e} actual:{a}" for e, a in self.profile.expected_literals]
        return notes
    
    def _token_family_score(self, family: str, value: str, table: Dict[str, int]) -> float:
        """One token family's 0-100 score by its table: the value's entry, else "other"; a `+`-joined value scores its
        lowest part. The profile's facts decide two `deps=` parts: `third_party:x` is known when x is a framework the
        profile names; `needs_py:V` is fine when the profile's python_version is V or newer (unknown → fine)."""
        parts = value.split("+") if value else []
        if not parts:
            return float(table["other"])
        keys: List[str] = []
        for part in parts:
            if family == "deps" and part.startswith("third_party:"):
                known = set(f.lower() for f in self.profile.frameworks)
                keys.append("third_party_known" if all(n in known for n in part.split(":", 1)[1].split(",")) else "other")
            elif family == "deps" and part.startswith("needs_py:"):
                need = tuple(int(x) for x in part.split(":", 1)[1].split("."))
                have = tuple(int(x) for x in self.profile.python_version.split(".")) if self.profile.python_version else ()
                keys.append("needs_py_ok" if (not have or have >= need) else "other")
            else:
                keys.append(part.split(":", 1)[0])
        return float(min(table.get(k, table["other"]) for k in keys))

    def _score_methods(self, candidate: SolutionCandidate, deciding_rule: Optional[str] = None) -> Dict[str, float]:
        """FIX_43a (owner ruling 2026-09-15 late): the seven methods, each 0-100, from the candidate's tokens and the
        Ranker's intent-side scores. Method 1 = (intent alignment + logic soundness) / 2 — and, when the Builder names
        the row's deciding rule (FIX_43 (b), Call B), the mean of three: intent alignment, `flow=`, and whether the
        candidate's `rule=` answers that rule (row 100 / neighbour 25); the fact is written on the candidate as
        `answers=row|neighbour` so `decide().why` shows it. Never a verdict; a missing token family scores its "other"
        entry so a candidate without the tokens is not silently favoured."""
        tokens = {o.split("=", 1)[0]: o.split("=", 1)[1] for o in candidate.observations if "=" in o}
        # S10b / I-80b: a placeholder reads `placeholder` (weight 0) in every family; the fact rides the candidate.
        placeholder = candidate_is_placeholder(candidate)
        candidate.observations = [o for o in candidate.observations if o != PLACEHOLDER_TOKEN] + \
            ([PLACEHOLDER_TOKEN] if placeholder else [])
        scores: Dict[str, float] = {}
        for name, m in RANKER_METHOD_WEIGHTS.items():
            fam = m["token"]
            fam_score = self._token_family_score(fam, "placeholder" if placeholder else tokens.get(fam, ""), m["values"])
            if fam == "flow" and not placeholder:
                fam_score = self._adaptive_flow(candidate, tokens.get("flow", ""), deciding_rule, fam_score)
            if name == "intent_logic":
                parts = [candidate.intent_alignment, fam_score]
                rule = tokens.get("rule")
                if deciding_rule and rule:
                    answers = "row" if rule == deciding_rule else "neighbour"
                    candidate.observations = [o for o in candidate.observations if not o.startswith("answers=")] + [f"answers={answers}"]
                    parts.append(float(_ANSWERS_VALUES[answers]))
                scores[name] = round(sum(parts) / len(parts), 4)
            else:
                scores[name] = fam_score
        return scores

    def _adaptive_flow(self, candidate: SolutionCandidate, value: str, deciding_rule: Optional[str],
                       original: float) -> float:
        """M-128 (owner 2026-10-08): the row's deciding rule picks a category in system_scripts/flow_valuation.json;
        that category's table and combine rule score the candidate's control-flow change, and a `bound_changed` part
        is multiplied by the direction verdict (`_bound_direction`). A rule with no category returns `original`
        untouched. The verdict rides the candidate as `flow_judged=` so `decide().why` shows it."""
        cfg = _flow_valuation()
        cat = (cfg.get("rule_category") or {}).get(deciding_rule or "")
        table = ((cfg.get("categories") or {}).get(cat) or {}) if cat else {}
        if not table:
            return original
        values, combine = table.get("values") or {}, table.get("combine", "min")
        parts = [p for p in (value or "").split("+") if p] or [""]
        scored: List[Tuple[str, float]] = []
        verdict = ""
        for part in parts:
            base = part.split(":", 1)[0] or "other"
            score = float(values.get(base, values.get("other", 33)))
            if base == "bound_changed":
                verdict = self._bound_direction(candidate)
                score *= float((cfg.get("direction") or {}).get(verdict, 1.0))
            scored.append((base, score))
        destructive = set(cfg.get("destructive") or [])
        if combine == "best_capped" and not any(b in destructive for b, _ in scored):
            final = max(s for _, s in scored)
        else:
            final = min(s for _, s in scored)
        candidate.observations = [o for o in candidate.observations if not o.startswith("flow_judged=")] + \
            [f"flow_judged={cat}:{final:g}" + (f":direction={verdict}" if verdict else "")]
        return final

    def _bound_direction(self, candidate: SolutionCandidate) -> str:
        """`aligned` / `reversed` / `neutral` for a candidate that changed a comparison: the function's own docstring
        threshold (boundary_probes._WORDS — phrase AND number, negations such as "no more than" included) names the
        operator; the before and after comparisons against that same number are read with the constant normalised to
        the right. after == target → aligned; before == target and after != target, or after on the other side →
        reversed; nothing to compare → neutral."""
        try:
            from no_aivalidator.noai_validator.boundary_probes import _WORDS
        except Exception:
            return "neutral"
        facts = getattr(self, "last_facts", {}) or {}
        doc = ((facts.get("function_intent") or {}).get("docstring") or "")
        try:
            before = ast.parse(textwrap.dedent(candidate.before_code or ""))
            after = ast.parse(textwrap.dedent(candidate.after_code or ""))
        except SyntaxError:
            return "neutral"
        if not doc:
            fn = next((n for n in ast.walk(before) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
            doc = (ast.get_docstring(fn) if fn else "") or ""
        low = doc.lower()
        side = {ast.Gt: "up", ast.GtE: "up", ast.Lt: "down", ast.LtE: "down"}
        flip = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}

        def ops_at(tree: ast.AST, n: float) -> List[type]:
            found: List[type] = []
            for c in (x for x in ast.walk(tree) if isinstance(x, ast.Compare)):
                sides = [c.left, *c.comparators]
                for j, op in enumerate(c.ops):
                    lhs, rhs = sides[j], sides[j + 1]
                    for const, opt in ((rhs, type(op)), (lhs, flip.get(type(op), type(op)))):
                        if isinstance(const, ast.Constant) and isinstance(const.value, (int, float)) \
                                and not isinstance(const.value, bool) and math.isclose(const.value, n):
                            found.append(opt)
                            break
            return found

        # Every phrase match, longest first where two overlap: "no more than 5" is read as ≤, never as "more than 5".
        hits = sorted(((m.start(), -(m.end() - m.start()), float(m.group(1)), ops[0])
                       for pattern, ops, _sym in _WORDS
                       for m in re.finditer(rf"(?:{pattern})\s*(-?\d+(?:\.\d+)?)", low)))
        taken: List[Tuple[int, int]] = []
        for start, neg_len, n, target in hits:
            if any(a <= start < b or start <= a < start - neg_len for a, b in taken):
                continue
            taken.append((start, start - neg_len))
            b_ops, a_ops = ops_at(before, n), ops_at(after, n)
            if not a_ops:
                continue
            if target in a_ops:
                return "aligned"
            if target in b_ops or any(side.get(o) != side.get(target) for o in a_ops):
                return "reversed"
        return "neutral"

    def _static_display_score(self, candidate: SolutionCandidate) -> float:
        """Methods 2-7 (the six static families) as one 0-100 number for the record — display only."""
        static = [n for n in RANKER_METHOD_WEIGHTS if n != "intent_logic"]
        wsum = sum(RANKER_METHOD_WEIGHTS[n]["weight"] for n in static)
        return round(sum(RANKER_METHOD_WEIGHTS[n]["weight"] * candidate.method_scores.get(n, 0.0) for n in static) / wsum, 2)

    def deciding_method(self, pick: SolutionCandidate, others: List[SolutionCandidate]) -> str:
        """The method whose weighted contribution separates the pick from the runner-up the most (the owner's
        "decisive factor"); `n/a (one candidate)` when nothing was there to separate."""
        if not others:
            return "n/a (one candidate)"
        # the runner-up is the next candidate in THIS ranking (score, then the tie-break), never list order
        runner = others[0]
        for c in getattr(self, "last_ranking", []):
            if c is not pick and any(c is o for o in others):
                runner = c
                break
        if runner.total_score == pick.total_score:
            return (f"tie at {pick.total_score:.2f} with {runner.role}, broken by the tie-break: "
                    f"{self.tie_break_step(pick, runner)}")
        best_name, best_gap = "", None
        for name, m in RANKER_METHOD_WEIGHTS.items():
            gap = m["weight"] * (pick.method_scores.get(name, 0.0) - runner.method_scores.get(name, 0.0)) / 100.0
            if best_gap is None or gap > best_gap:
                best_name, best_gap = name, gap
        return f"{RANKER_METHOD_LABELS[best_name]} ({best_gap:+.2f} over {runner.role})"

    def _tie_key(self, candidate: SolutionCandidate, index: int) -> Tuple[Any, ...]:
        """S10b / I-80: the tie-break key, one part per TIE_BREAK_STEPS entry, lower sorting first. The rule step is
        the rule's place in the row's published rule ids (the validator's order — the deciding rule first), then
        the id's text; a rule the row does not name sorts after every one it does."""
        rule = candidate_rule(candidate) or ""
        rules = getattr(self, "_row_rules", [])
        place = rules.index(rule) if rule in rules else len(rules)
        return (candidate_is_suggestion(candidate), PLACEHOLDER_TOKEN in candidate.observations,
                (place, rule), len((candidate.after_code or "").strip()), candidate.role, index)

    def tie_break_step(self, pick: SolutionCandidate, runner: SolutionCandidate) -> str:
        """The TIE_BREAK_STEPS entry that ordered two equal-total candidates — the first part of their keys to differ."""
        pk, rk = self._tie_keys.get(id(pick), ()), self._tie_keys.get(id(runner), ())
        for step, a, b in zip(TIE_BREAK_STEPS, pk, rk):
            if a != b:
                return step
        return TIE_BREAK_STEPS[-1]

    def _score_quality(self, candidate: SolutionCandidate) -> float:
        """Score based on quality signals (0-100)."""
        score = 30.0  # Base score
        
        # SO votes (logarithmic scale)
        if candidate.votes > 0:
            import math
            score += min(math.log10(candidate.votes + 1) * 15, 35)
        
        # Accepted answer bonus
        if candidate.accepted:
            score += 25
        
        # Source trust hierarchy
        source_trust = {
            'python_docs': 15,
            'local': 10,
            'ast_rewriter': 12,
        }
        score += source_trust.get(candidate.source, 0)
        
        return min(score, 100.0)
    
    def _score_rca_match(
        self,
        candidate: SolutionCandidate,
        rca_evidence: List[str]
    ) -> float:
        """
        Score how well solution addresses rca findings (0-100).
        
        ENHANCED: Uses semantic pattern matching to recognize when a solution
        addresses the root cause identified by rca, even if the exact
        words don't match.
        """
        if not rca_evidence:
            return 50.0  # Neutral if no evidence
        
        score = 30.0
        solution_text = (candidate.solution + " " + candidate.after_code).lower()
        evidence_text = " ".join(rca_evidence).lower()
        
        # =====================================================================
        # SEMANTIC PATTERN MATCHING
        # These patterns link rca infractions to solution patterns
        # =====================================================================
        
        semantic_patterns: List[Dict[str, Any]] = [
            # Pattern: Function/variable returns/is None → check for None
            {
                'rca_signals': ['returns none', 'may be none', 'could be none', 'is none', 'variable none'],
                'solution_signals': ['if .* is none', 'is not none', '!= none', '== none', 'none:', 'or none'],
                'bonus': 25
            },
            # Pattern: Missing null check → add null check
            {
                'rca_signals': ['missing .* check', 'null check', 'none check', 'not checking'],
                'solution_signals': ['if .* is none', 'if .* is not none', 'if .* :', 'guard', 'check'],
                'bonus': 25
            },
            # Pattern: Subscript/index on None → check before subscript
            {
                'rca_signals': ['subscript', 'not subscriptable', 'index', 'key error'],
                'solution_signals': ['if .* is none', 'try:', 'except', r'\.get\(', r'or \{\}', r'or \[\]'],
                'bonus': 20
            },
            # Pattern: Sort/assignment returns None → use in-place or chain
            {
                'rca_signals': [r'\.sort\(', 'sort returns', r'sorted\('],
                'solution_signals': [r'\.sort\(\)', r'sorted\(', 'in.place', 'in place'],
                'bonus': 25
            },
            # Pattern: Import/module issues
            {
                'rca_signals': ['import', 'module', 'package', 'modulenotfound'],
                'solution_signals': ['import', 'pip install', 'from .* import', 'sys.path'],
                'bonus': 20
            },
            # Pattern: Async/await issues
            {
                'rca_signals': ['async', 'await', 'coroutine', 'event loop'],
                'solution_signals': ['async def', 'await', 'asyncio', r'run\('],
                'bonus': 20
            },
            # ── Cross-file diagnostic patterns (from Phase 0 enrichment) ──
            # RCA cross-file: prefer conservative fixes for callers of broken code
            {
                'rca_signals': ['rca_cross_file', 'caller='],
                'solution_signals': ['conservative', 'backward.compatible', 'wrapper', 'adapter'],
                'bonus': 25
            },
            # Origin trace: wall_type guides fix strategy (type errors)
            {
                'rca_signals': ['origin_trace:wall_type=type_error', 'origin_trace:wall_type=attribute'],
                'solution_signals': ['type.check', 'isinstance', 'hasattr', 'getattr'],
                'bonus': 30
            },
            # Origin trace: None/null wall types
            {
                'rca_signals': ['origin_trace:wall_type=none', 'origin_trace:wall_type=null'],
                'solution_signals': ['is.not.none', 'is none', 'optional', 'default'],
                'bonus': 30
            },
            # Onion peel: deep chains need careful fixes
            {
                'rca_signals': [r'onion_peel:layers=[3-9]', r'onion_peel:layers=\d{2}'],
                'solution_signals': ['refactor', 'extract', 'simplify', 'decompose'],
                'bonus': 20
            },
            # Circular imports: prefer lazy import or restructure
            {
                'rca_signals': ['circular_import'],
                'solution_signals': ['lazy.import', 'import.inside', 'TYPE_CHECKING', 'restructur'],
                'bonus': 35
            },
            # (K2, owner 2026-09-07: the 'High coupling' bonus keyed on a caller_score magnitude regex was excised)
            # Def-use chain issues: prefer fixes that wire unused variables
            {
                'rca_signals': ['def_use'],
                'solution_signals': ['wire', 'assign', 'return', 'use'],
                'bonus': 20
            },
        ]
        
        import re
        for pattern in semantic_patterns:
            # Check if ANY rca signal matches
            rca_match = any(
                re.search(signal, evidence_text) for signal in pattern['rca_signals']
            )
            # Check if ANY solution signal matches
            solution_match = any(
                re.search(signal, solution_text) for signal in pattern['solution_signals']
            )
            
            if rca_match and solution_match:
                score += pattern['bonus']
                logger.debug("RootCause pattern match",
                             bonus=pattern['bonus'],
                             signal=pattern['rca_signals'][0])
        
        # =====================================================================
        # KEYWORD OVERLAP (original logic, kept as secondary signal)
        # =====================================================================
        for evidence in rca_evidence:
            evidence_lower = evidence.lower()
            solution_lower = solution_text
            
            # Check for keyword overlap with rca
            evidence_words = set(evidence_lower.split())
            solution_words = set(solution_lower.split())
            overlap = len(evidence_words & solution_words)
            
            if overlap >= 3:
                score += 10
            elif overlap >= 1:
                score += 5
        
        return min(score, 100.0)


# =============================================================================
# CHEAT SHEET - THE ANSWER KEY
# =============================================================================
# Per app_rationale: "Agents are provided with the 'answer'... a very small set
# of 'docs' that contain all answers and troubleshooting specific to that 
# agent's very small job scope." 
#
# CRITICAL: Each CheatSheet contains EXACTLY ONE solution for ONE job.
# This is a 1:1 correlation - not a menu of options.
# =============================================================================

@dataclass
class CheatSheet:
    """
    THE ANSWER KEY - Contains EXACTLY ONE solution for the agent's specific job.
    
    Per app_rationale:
    - "make the tasks super small but also super easy - these plus the answer(cheatsheet)"
    - "there should be no need for any validation" because the answer is provided
    - 1:1 correlation between CheatSheet and job - NOT a menu of options
    
    STANDARDIZED FORMAT (legible to all agents):
    ┌──────────────────────────────────────────┐
    │ CHEAT SHEET: [JOB_TYPE]                  │
    │ Job ID: [job_id]                         │
    ├──────────────────────────────────────────┤
    │ YOUR ROLE: [single role description]     │
    ├──────────────────────────────────────────┤
    │ THE PROBLEM:                             │
    │ [exact error message/issue description]  │
    ├──────────────────────────────────────────┤
    │ THE SOLUTION:                            │
    │ [EXACTLY what to do - one clear action]  │
    ├──────────────────────────────────────────┤
    │ BEFORE → AFTER:                          │
    │ [single concrete example]                │
    ├──────────────────────────────────────────┤
    │ IF STUCK:                                │
    │ [one specific troubleshooting tip]       │
    └──────────────────────────────────────────┘
    """
    # Identity
    job_id: str           # Short ID for display (first 8 chars)
    job_type: str
    
    # THE ANSWER (singular - not plural!)
    role: str                    # Single role description
    problem: str = ""            # The exact problem to solve
    solution: str = ""           # THE solution (singular!)
    steps: List[str] = field(default_factory=list)  # Ordered steps to apply fix
    before_code: str = ""        # Code before fix
    after_code: str = ""         # Code after fix
    if_stuck: str = ""           # One troubleshooting tip
    
    # Context
    file_path: str = ""          # Target file
    line_number: int = 0         # Target line
    repo_context: str = ""       # What the repo does
    
    # PHASE 6: RootCause evidence (upstream deps, root cause hints)
    rca_evidence: List[str] = field(default_factory=list)
    
    # Metadata
    confidence: float = 1.0      # Confidence in solution (0.0-1.0)
    source: str = "local"        # "local", "web", "generated"
    issue_uuid: str = ""         # TRACKING: Full RepairJobUUID from birth to death
    
    def to_prompt_string(self) -> str:
        """
        Format as a clean, direct, actionable cheatsheet.

        REDESIGNED: Removed verbose box formatting to save tokens and improve clarity.
        Now uses a direct, code-focused format that LLMs can easily parse and apply.
        """
        # DEBUG: Log cheatsheet content for troubleshooting
        logger.debug("to_prompt_string called",
                    job_id=self.job_id, issue_uuid=self.issue_uuid,
                    job_type=self.job_type,
                    file_path=self.file_path, line_number=self.line_number,
                    problem_len=len(self.problem) if self.problem else 0,
                    solution_len=len(self.solution) if self.solution else 0,
                    has_before=bool(self.before_code),
                    has_after=bool(self.after_code),
                    has_if_stuck=bool(self.if_stuck),
                    source=self.source)

        # Build clean, direct format
        uuid_display = self.issue_uuid if self.issue_uuid else self.job_id

        lines = [
            "=" * 60,
            f"CHEAT SHEET: {self.job_type.upper()}",
            f"RepairJobUUID: {uuid_display}",
            "=" * 60,
            "",
        ]

        # Target location - CRITICAL for multi-function files
        if self.file_path:
            loc = f"{self.file_path}:{self.line_number}" if self.line_number else self.file_path
            lines.append(f"TARGET LOCATION: {loc}")
            lines.append(f"FIX ONLY the function at/near line {self.line_number}")
            lines.append("")

        # The Problem - what's wrong
        if self.problem:
            lines.append("PROBLEM:")
            lines.append(self.problem)
            lines.append("")

        # THE SOLUTION - the answer! This is the most important part
        lines.append(">>> EXACT FIX REQUIRED <<<")
        if self.solution:
            lines.append(self.solution)
        else:
            lines.append("[Solution not available - use first principles]")
        lines.append("")

        # STEPS - ordered sequence to apply fix (if provided)
        if self.steps:
            lines.append("STEPS TO FOLLOW:")
            for i, step in enumerate(self.steps, 1):
                lines.append(f"  {i}. {step}")
            lines.append("")

        # Before/After example - CRITICAL for code changes
        # Show EXACT code transformation in code blocks
        if self.before_code or self.after_code:
            lines.append("CODE CHANGE:")
            if self.before_code:
                lines.append("FIND THIS (before):")
                lines.append("```python")
                lines.append(self.before_code)
                lines.append("```")
            if self.after_code:
                lines.append("REPLACE WITH (after):")
                lines.append("```python")
                lines.append(self.after_code)
                lines.append("```")
            lines.append("")

        # If Stuck - troubleshooting hint
        if self.if_stuck:
            lines.append("IF STUCK:")
            lines.append(self.if_stuck)
            lines.append("")

        # RootCause Evidence - root cause hints
        if self.rca_evidence:
            lines.append("RCA EVIDENCE:")
            for ev in self.rca_evidence[:MAX_RCA_EVIDENCE]:
                lines.append(f"  - {ev}")
            lines.append("")

        # Footer
        lines.append("-" * 60)
        source_info = f"Source: {self.source}"
        lines.append(source_info)
        lines.append("=" * 60)

        return "\n".join(lines)
    
    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to fit in box."""
        words = text.split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                current_line += (" " if current_line else "") + word
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word[:width]  # Truncate long words
        
        if current_line:
            lines.append(current_line)
        
        return lines if lines else [""]
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage/transmission."""
        return {
            "job_id": self.job_id,
            "job_type": self.job_type,
            "role": self.role,
            "problem": self.problem,
            "solution": self.solution,
            "before_code": self.before_code,
            "after_code": self.after_code,
            "if_stuck": self.if_stuck,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "repo_context": self.repo_context,
            "rca_evidence": self.rca_evidence,
            "confidence": self.confidence,
            "source": self.source,
        }


class KnowledgeBase:
    """
    Provides "Minimal Docs Bundles" to agents based on the job type.

    Each bundle contains:
    - role: The persona/specialty the agent should assume
    - rules: Strict constraints for the fix
    - examples: Before/after code patterns
    - troubleshooting: Common gotchas and their solutions
    
    Stop 5.3: Knowledge Injection.
    """

    def __init__(self, repo_context: str = "", repo_path: str = ""):
        """
        Initialize KnowledgeBase.
        
        Args:
            repo_context: Description of target repo's purpose/design
            repo_path: Path to target repo for project profile analysis
        """
        # Item 8 (2026-09-15): repo_context finally WIRED — when no description is handed in, it is the developer's
        # statement from the target's intent file (`system_scripts/intent_<repoid>.json`), or "" when none.
        if not repo_context and repo_path:
            try:
                import sys as _sys
                _ss = str(Path(__file__).resolve().parents[3] / "system_scripts")
                if _ss not in _sys.path:
                    _sys.path.insert(0, _ss)
                import intent_file as _intent  # type: ignore
                _st = (_intent.read(repo_path).get("statement") or {})
                repo_context = str(_st.get("text") or "")
            except Exception:
                repo_context = ""
        self.repo_context = repo_context
        self.repo_path = repo_path
        
        # Project profile for solution ranking (lazy-initialized, thread-safe)
        self._project_profile: Optional[ProjectProfile] = None
        self._profile_lock = threading.Lock()
        
        # The 'Cheat Sheets' - tailored to the specific job_types
        # generated by the Granulator (fix_syntax, fix_import, etc.)
        self.bundles: Dict[str, Dict[str, Any]] = {
            # ================================================================
            # JOB-TYPE SPECIFIC BUNDLES (Primary - match Granulator output)
            # ================================================================
            "fix_syntax": {
                "role": "Python Syntax Specialist",
                "rules": [
                    "Fix ONLY the syntax error reported.",
                    "Ensure all open parentheses/brackets are closed.",
                    "Check for missing colons at the end of control flow statements.",
                    "Maintain correct indentation (4 spaces).",
                    "Do NOT add new logic or functionality."
                ],
                "examples": [
                    "Bad: `def foo` -> Good: `def foo():`",
                    "Bad: `if x = 5:` -> Good: `if x == 5:`",
                    "Bad: `print 'hello'` -> Good: `print('hello')`"
                ],
                "troubleshooting": [
                    "If 'unexpected EOF', check for unclosed brackets on previous lines.",
                    "Look at the line BEFORE the error - often the issue is there.",
                    "Check for mixing tabs and spaces."
                ]
            },

            "fix_import": {
                "role": "Dependency Manager",
                "rules": [
                    "Resolve the specific ImportError/ModuleNotFound error.",
                    "Do NOT delete existing imports unless they are strictly duplicates.",
                    "If a local module is missing, check relative paths (e.g., `from . import utils`).",
                    "Standard library imports go first, then 3rd party, then local."
                ],
                "examples": [
                    "Error: `ModuleNotFound: x` -> Fix: `pip install x` (if external) or correct path.",
                    "Error: `ImportError: cannot import name 'y'` -> Check if 'y' exists in source file.",
                    "Fix: `import mymodule` -> `from . import mymodule` (local)",
                ],
                "troubleshooting": [
                    "Circular imports: Move the import inside the function/method.",
                    "Shadowing: Ensure file name is not same as a package (e.g., `email.py`).",
                    "Verify __init__.py exists in package directories."
                ]
            },

            "fix_security": {
                "role": "Security Engineer",
                "rules": [
                    "Address the specific vulnerability (Bandit ID or CWE).",
                    "Replace `eval()` or `exec()` with safer alternatives (e.g., `ast.literal_eval`).",
                    "Do NOT use hardcoded secrets/passwords.",
                    "Sanitize inputs before passing to shell commands (`subprocess.run`).",
                    "Use parameterized queries for SQL operations."
                ],
                "examples": [
                    "Bad: `subprocess.call('ls ' + user_input, shell=True)`",
                    "Good: `subprocess.run(['ls', user_input], check=True)`",
                    "Bad: `assert x` (B101) -> Good: `if not x: raise ValueError(...)`",
                    "Bad: `password = 'admin123'` -> Good: `password = os.environ['PASSWORD']`"
                ],
                "troubleshooting": [
                    "B101: assert is stripped in optimized mode - use proper validation.",
                    "B311: random is not cryptographically secure - use secrets module.",
                    "If fixing SQL Injection, use parameterized queries."
                ]
            },

            "fix_logic": {
                "role": "Logic Bug Specialist",
                "rules": [
                    "Read the ASSERTION DETAILS carefully - they show expected vs actual values",
                    "For 'DID NOT RAISE' errors: ADD validation code with raise statement",
                    "For numeric mismatches (e.g., 2 == 5): check if you need sum() vs len(), or wrong variable",
                    "For boolean failures (expected False, got True): check comparison operators (<, <=, >, >=, ==, !=)",
                    "NEVER just change comments - you must change the actual logic",
                    "Analyze the Class/Module scope to understand state.",
                    "Preserve the original method signature.",
                    "CRITICAL: When 'item_count' or similar count variable shows wrong value, find 'variable_name =' assignment and fix calculation",
                    "len(items) counts NUMBER OF ITEMS. sum(item['quantity'] for item in items) counts TOTAL QUANTITY. Pick correctly!"
                ],
                "examples": [
                    "DID NOT RAISE ValueError -> Add: if invalid_condition: raise ValueError('message')",
                    "assert 2 == 5 in item_count -> MUST change: len(items) to sum(item.get('quantity', 1) for item in items)",
                    "assert True is False in can_retry -> Change: <= to < or vice versa",
                    "Off-by-one: `range(n)` vs `range(n+1)` or `<=` vs `<`",
                    "Boolean logic: `and` vs `or`, `not` placement",
                    "item_count = len(items) WRONG when test expects sum of quantities -> item_count = sum(item.get('quantity', 1) for item in items)"
                ],
                "troubleshooting": [
                    "If assertion shows 'DID NOT RAISE': you need to ADD a raise statement, not modify existing code",
                    "If numeric mismatch: trace where the number comes from and fix the calculation",
                    "Changing comments does NOT fix bugs - change the actual code",
                    "AttributeError? Check `__init__` for variable definition.",
                    "TypeError? Check argument types being passed.",
                    "If item_count shows 2 but expected 5: items probably have quantity field - use sum() not len()"
                ]
            },

            "fix_type": {
                "role": "Type System Expert",
                "rules": [
                    "Ensure variable types match function parameter type hints.",
                    "Do not concatenate incompatible types (str + int).",
                    "Use explicit type conversion when needed.",
                    "Preserve type safety - don't bypass with Any unless necessary."
                ],
                "examples": [
                    "Bad: `'age: ' + 10` -> Good: `'age: ' + str(10)`",
                    "Bad: `x: int = 'hello'` -> Good: `x: str = 'hello'`",
                    "Bad: `Optional[int] = None` used without check -> Good: `if x is not None:`"
                ],
                "troubleshooting": [
                    "Check if Optional[] is needed for nullable values.",
                    "Verify generic types match (List[int] vs List[str]).",
                    "Union types: ensure all branches are handled."
                ]
            },

            # DEPRECATED: implement_stub is no longer a valid job type
            # Stubs are whitelisted (owner's future plans), not repair targets
            # Kept for backward compatibility if legacy code references it
            "implement_stub": {
                "role": "DEPRECATED - Stubs are whitelisted owner decisions",
                "rules": [
                    "DEPRECATED: This job type should not be created.",
                    "Stubs are detected by ArtifactScanner and added to whitelist.",
                    "Whitelisted items are owner decisions - we do NOT modify them."
                ],
                "examples": [],
                "troubleshooting": [
                    "If you see this job type, the whitelist check may have failed.",
                    "Check that ArtifactScanner ran before Granulator.",
                    "Verify whitelist was passed to Granulator."
                ]
            },

            "remove_dead_code": {
                "role": "Code Cleaner",
                "rules": [
                    "Remove ONLY the unused code identified in the issue.",
                    "Verify the code is truly unused (not dynamically accessed).",
                    "Remove unused imports completely, not just comment out.",
                    "If removing function, check for decorators that might use it."
                ],
                "examples": [
                    "Unused import: `import os  # never used` -> Remove entire line",
                    "Unused variable: `x = compute()  # never used` -> Remove if side-effect free",
                    "For unused loop var: `for i in range(10)` -> `for _ in range(10)`"
                ],
                "troubleshooting": [
                    "Check if import is used indirectly via __all__.",
                    "Verify variable isn't needed for unpacking.",
                    "Check for dynamic access via getattr/globals()."
                ]
            },

            "fix_entry_point": {
                "role": "Application Architect",
                "rules": [
                    "Ensure __main__.py or main() function properly initializes the app.",
                    "Handle command-line arguments correctly.",
                    "Set up logging and configuration before main logic.",
                    "Ensure proper exit codes (0 for success, non-zero for failure)."
                ],
                "examples": [
                    "Missing guard: Add `if __name__ == '__main__': main()`",
                    "Missing args: Add `parser = argparse.ArgumentParser()`",
                    "Missing exit: Add `sys.exit(0)` after successful completion"
                ],
                "troubleshooting": [
                    "Check if relative imports work from entry point.",
                    "Use proper package imports (no PYTHONPATH manipulation).",
                    "Check for missing __init__.py files."
                ]
            },

            "wire_unused_config": {
                "role": "Configuration Specialist",
                "rules": [
                    "Connect unused config values to where they should be used.",
                    "Do not delete config - find where it should be passed.",
                    "Check for environment variable fallbacks.",
                    "Ensure type conversion for non-string config values."
                ],
                "examples": [
                    "Unused: `TIMEOUT = 30` -> Wire: `requests.get(url, timeout=TIMEOUT)`",
                    "Unused: `MAX_RETRIES = 3` -> Wire: `for _ in range(MAX_RETRIES):`"
                ],
                "troubleshooting": [
                    "Search codebase for where this value should be used.",
                    "Check if config is meant for external module.",
                    "Verify spelling matches expected config key."
                ]
            },

            "improve_quality": {
                "role": "Code Quality Reviewer",
                "rules": [
                    "Reduce complexity while preserving functionality.",
                    "Break complex functions into smaller, focused functions.",
                    "Use early returns to reduce nesting.",
                    "Add type hints where missing."
                ],
                "examples": [
                    "Deep nesting: Use guard clauses with early return.",
                    "Long function: Extract logical sections into named functions.",
                    "Repeated code: Extract into helper function."
                ],
                "troubleshooting": [
                    "Consider state machine for complex state logic.",
                    "Look for repeated patterns that can be abstracted.",
                    "Use comprehensions for simple transformations."
                ]
            },

            "general_fix": {
                "role": "Python Developer",
                "rules": [
                    "Fix the reported issue with minimal code changes.",
                    "Follow PEP-8 style guide.",
                    "Do not break existing tests.",
                    "Preserve existing code style and formatting."
                ],
                "examples": [],
                "troubleshooting": [
                    "When in doubt, make the smallest change that fixes the issue.",
                    "Check test file for expected behavior.",
                    "Look at similar code in the file for patterns."
                ]
            },

            # ================================================================
            # LEGACY BUNDLES (For backwards compatibility with old categories)
            # ================================================================
            "syntax_error": {
                "role": "Python Syntax Specialist",
                "rules": [
                    "Check for missing colons after def, class, if, for, while, try, except.",
                    "Ensure indentation is consistent (4 spaces per level).",
                    "Check for unmatched parentheses, brackets, or braces.",
                    "Verify string quotes are properly closed.",
                ],
                "examples": [
                    "Fix: `def foo` -> `def foo():`",
                    "Fix: `if x == 1` -> `if x == 1:`",
                    "Fix: `print('hello` -> `print('hello')`",
                ],
                "troubleshooting": [
                    "Look at the line BEFORE the error - often the issue is there.",
                    "Check for mixing tabs and spaces.",
                ]
            },

            "import_error": {
                "role": "Dependency Manager",
                "rules": [
                    "Standard library imports come first, then third-party, then local.",
                    "Use relative imports for local modules: `from . import module`",
                    "Check if the module is installed in the environment.",
                ],
                "examples": [
                    "Fix: `import mymodule` -> `from . import mymodule`",
                    "Fix: `from foo import bar` -> `from .foo import bar`",
                ],
                "troubleshooting": [
                    "ModuleNotFound: Use proper package imports (no PYTHONPATH manipulation)",
                    "ImportError: Look for circular imports between modules",
                    "Verify __init__.py exists in package directories",
                ]
            },

            "security_vuln": {
                "role": "Security Engineer",
                "rules": [
                    "Never hardcode secrets, API keys, or passwords.",
                    "Use environment variables for sensitive configuration.",
                    "Sanitize all user inputs before SQL/shell operations.",
                    "Use secrets module for cryptographic randomness.",
                ],
                "examples": [
                    "Bad: `password = 'admin123'` -> Good: `password = os.environ['PASSWORD']`",
                    "Bad: `random.randint()` -> Good: `secrets.randbelow()` for security",
                ],
                "troubleshooting": [
                    "B101: assert is stripped in optimized mode - use proper validation",
                    "B311: random is not cryptographically secure",
                ]
            },

            "general": {
                "role": "Python Developer",
                "rules": [
                    "Keep changes minimal and focused on the specific issue.",
                    "Do not delete code unless it's confirmed unused.",
                    "Preserve existing code style and formatting.",
                    "Add comments only if logic is non-obvious.",
                ],
                "examples": [],
                "troubleshooting": [
                    "When in doubt, make the smallest change that fixes the issue.",
                ]
            },

            # ================================================================
            # ROOT CAUSE ANALYSIS BUNDLES (For upstream config/constant fixes)
            # ================================================================
            "RCA_LOGIC": {
                "role": "Configuration Specialist",
                "rules": [
                    "CHEATSHEET VALUES ARE AUTHORITATIVE - use EXACT values from provided documentation.",
                    "Fix ALL incorrect constants in one pass, not just the first one.",
                    "Do NOT guess or approximate values - copy them exactly from the cheatsheet.",
                    "If cheatsheet says MAX_USERS=1000, use exactly 1000, not 500 or 999.",
                    "Preserve existing code style and comments.",
                    "Output the COMPLETE fixed file, not just the changed lines.",
                ],
                "examples": [
                    "Cheatsheet: 'MAX_USERS should be 1000' -> Set: MAX_USERS = 1000",
                    "Cheatsheet: 'FLAKY_THRESHOLD should be 0.2' -> Set: FLAKY_THRESHOLD = 0.2",
                    "Cheatsheet: 'CYCLE_MOD should be prime (13)' -> Set: CYCLE_MOD = 13",
                    "Cheatsheet: 'Use secrets.token_hex(16)' -> Set: SALT = secrets.token_hex(16)",
                ],
                "troubleshooting": [
                    "Scan the ENTIRE cheatsheet for all correct values before making changes.",
                    "Tests may check for EXACT equality (==), not ranges or approximations.",
                    "Multiple constants may be wrong - fix all of them in one pass.",
                    "If a test expects MAX_USERS == 1000, setting 999 will still fail.",
                ]
            },

            "RCA_QUALITY": {
                "role": "Configuration Specialist",
                "rules": [
                    "CHEATSHEET VALUES ARE AUTHORITATIVE - use EXACT values from provided documentation.",
                    "Fix ALL incorrect constants in one pass, not just the first one.",
                    "Do NOT guess or approximate values - copy them exactly from the cheatsheet.",
                    "Preserve existing code style and comments.",
                    "Output the COMPLETE fixed file.",
                ],
                "examples": [
                    "Cheatsheet: 'MAX_USERS should be 1000' -> Set: MAX_USERS = 1000",
                    "Cheatsheet: 'Use RLock() instead of Lock()' -> Change threading.Lock() to threading.RLock()",
                ],
                "troubleshooting": [
                    "Scan the ENTIRE cheatsheet for all correct values.",
                    "Tests check for EXACT values - approximations will fail.",
                    "Fix all mismatched constants in one pass.",
                ]
            }
        }

        # Category keyword mappings for flexible matching
        self.category_keywords = {
            "fix_syntax": ["syntax", "indent", "parse", "unexpected", "SyntaxError"],
            "fix_import": ["import", "module", "ModuleNotFound", "ImportError"],
            "fix_security": ["security", "B101", "B311", "password", "secret", "bandit", "vulnerability"],
            "fix_logic": ["logic", "assertion", "AssertionError", "test fail"],
            "fix_type": ["type", "arg-type", "assignment", "incompatible", "TypeError"],
            # DEPRECATED: implement_stub - stubs are whitelisted owner decisions
            # "implement_stub": ["stub", "NotImplementedError", "pass", "empty", "not implemented"],
            "remove_dead_code": ["unused", "F401", "never used", "dead code"],
            "fix_entry_point": ["__main__", "entry point", "main()"],
            "wire_unused_config": ["config", "settings", "wire"],
            "improve_quality": ["complexity", "too complex", "long function", "too many"],
            "general_fix": ["general", "fix"],
            # RCA (Root Cause Analysis) keywords - for upstream config files
            "RCA_LOGIC": ["RCA_LOGIC", "RCA", "root cause", "constant", "config"],
            "RCA_QUALITY": ["RCA_QUALITY", "quality", "upstream"],
        }
    
    async def get_project_profile(self) -> ProjectProfile:
        """
        Get or initialize project profile for solution ranking.

        Lazy-initializes by analyzing the target repo if repo_path is set.
        Thread-safe: uses lock for initialization check.
        """
        logger.debug("get_project_profile called",
                     has_profile=self._project_profile is not None,
                     repo_path=self.repo_path or "")
        
        # Check if already initialized (fast path)
        with self._profile_lock:
            if self._project_profile is not None:
                return self._project_profile
            need_init = self.repo_path
        
        # Initialize outside lock (async operation)
        if need_init:
            profile = await SolutionRanker._analyze_repo(self.repo_path)
            with self._profile_lock:
                # Double-check after async operation
                if self._project_profile is None:
                    self._project_profile = profile
                    logger.debug("get_project_profile initialized",
                                 uses_async=self._project_profile.uses_async,
                                 frameworks=self._project_profile.frameworks)
                return self._project_profile
        else:
            with self._profile_lock:
                if self._project_profile is None:
                    self._project_profile = ProjectProfile()
                return self._project_profile
    
    def set_project_profile(self, profile: ProjectProfile) -> None:
        """Set project profile directly (for testing or when already analyzed)."""
        with self._profile_lock:
            self._project_profile = profile

    def close(self) -> None:
        """
        Clean up resources and reset state.
        
        For orchestrators: Call this when done with the KnowledgeBase.
        """
        logger.debug("KnowledgeBase.close called")
        with self._profile_lock:
            self._project_profile = None

    def get_bundle(self, job_type: str) -> str:
        """
        Retrieves and formats the docs bundle for the given job type.

        Returns a string ready for injection into the LLM prompt.
        This is the primary method used by FixerChain.

        Args:
            job_type: The job type from Granulator (e.g., 'fix_syntax', 'fix_import')

        Returns:
            Formatted string with role, rules, examples, and troubleshooting
        """
        logger.debug("get_bundle called", job_type=job_type)
        # 1. Direct match first
        if job_type in self.bundles:
            data = self.bundles[job_type]
        else:
            # 2. Keyword-based matching
            data = self._find_bundle_by_keywords(job_type)

        # 3. Format as String for prompt injection
        return cast(str, self._format_bundle(data))

    def _find_bundle_by_keywords(self, category: str) -> Dict[str, Any]:
        """Find bundle by keyword matching."""
        category_lower = category.lower()

        for bundle_key, keywords in self.category_keywords.items():
            for keyword in keywords:
                if keyword.lower() in category_lower:
                    return self.bundles.get(bundle_key, self.bundles["general"])

        return self.bundles["general"]

    def _format_bundle(self, data: Dict[str, Any]) -> str:
        """Format a bundle dictionary as a string for prompt injection."""
        logger.debug("_format_bundle called", n_rules=len(data.get('rules', [])))
        formatted = f"ROLE: {data.get('role', 'Python Developer')}\n\n"

        if data.get("rules"):
            formatted += "--- RULES ---\n"
            for rule in data["rules"]:
                formatted += f"- {rule}\n"

        if data.get("examples"):
            formatted += "\n--- PATTERNS ---\n"
            for ex in data["examples"]:
                formatted += f"- {ex}\n"

        if data.get("troubleshooting"):
            formatted += "\n--- TROUBLESHOOTING ---\n"
            for tip in data["troubleshooting"]:
                formatted += f"- {tip}\n"

        return formatted

    def get_bundle_dict(self, job_type: str) -> Dict[str, Any]:
        """
        Get the raw bundle dictionary.

        Args:
            job_type: The job type from Granulator

        Returns:
            Dictionary containing rules, examples, and troubleshooting tips
        """
        logger.debug("get_bundle_dict called", job_type=job_type)
        try:
            # Try local bundles first
            if job_type in self.bundles:
                return self.bundles[job_type]

            # Try keyword matching
            bundle = self._find_bundle_by_keywords(job_type)
            if bundle:
                return bundle

            # Fallback to generic bundle
            logger.warning("No specific bundle found, using generic guidance",
                          job_type=job_type)
            generic_bundle = cast(Dict[str, Any], self._generate_generic_bundle(job_type))
            return generic_bundle if generic_bundle else self.bundles.get("general_fix", {})

        except Exception as e:
            logger.error("Error retrieving bundle", job_type=job_type,
                        error=str(e))
            return cast(Dict[str, Any], self._generate_generic_bundle(job_type))

    def get_all_rules(self, categories: List[str]) -> List[str]:
        """Get combined rules from multiple categories (deduplicated)."""
        all_rules = []
        seen = set()

        for category in categories:
            bundle = self.get_bundle_dict(category)
            for rule in bundle.get("rules", []):
                if rule not in seen:
                    all_rules.append(rule)
                    seen.add(rule)

        return all_rules

    def search_solutions(
        self,
        error_message: str,
        file_path: str = "",
        max_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Search for solutions given a runtime error message.
        
        This is the interface used by OnionPeeler for dynamic error discovery.
        Maps runtime exceptions (KeyError, ZeroDivisionError, etc.) to KB solutions.
        
        Args:
            error_message: The error string (e.g., "KeyError: 'num_shows'")
            file_path: Path to the file where error occurred
            max_results: Maximum number of solutions to return
            
        Returns:
            List of solution dictionaries with 'code', 'source', 'score' keys
        """
        logger.debug("search_solutions called", error_message=error_message[:80])
        solutions = []
        msg_lower = error_message.lower()
        
        # Extract error type from message
        error_type = ""
        if ':' in error_message:
            error_type = error_message.split(':')[0].strip().lower()
        
        # Map runtime errors to KB handlers
        # These patterns match the _find_specific_solution routing logic
        
        if 'keyerror' in msg_lower or 'key error' in msg_lower:
            # KeyError: missing dict key - route to unguarded dict handler
            key_match = re.search(r"['\"]([^'\"]+)['\"]", error_message)
            key_name = key_match.group(1) if key_match else "key"
            
            solutions.append({
                'code': f"value = data.get('{key_name}', default_value)",
                'source': 'local',
                'score': 85.0,
                'description': f"Use .get('{key_name}', default) instead of direct subscript access",
                'fix_type': 'unguarded_dict_access'
            })
            solutions.append({
                'code': f"if '{key_name}' in data:\n    value = data['{key_name}']",
                'source': 'local', 
                'score': 75.0,
                'description': f"Check key existence before access",
                'fix_type': 'unguarded_dict_access'
            })
            
        elif 'zerodivisionerror' in msg_lower or 'division by zero' in msg_lower:
            if 'literal' in msg_lower:
                # Division by literal zero
                solutions.append({
                    'code': "result = value / divisor  # FIXME: replace literal 0 with correct divisor",
                    'source': 'local',
                    'score': 90.0,
                    'description': 'Replace literal zero with the intended divisor',
                    'fix_type': 'division_by_literal_zero'
                })
            else:
                # Division by variable
                solutions.append({
                    'code': "if divisor == 0:\n    raise ZeroDivisionError('divisor is zero')\nresult = value / divisor",
                    'source': 'local',
                    'score': 85.0,
                    'description': 'Add zero-check guard before division',
                    'fix_type': 'division_by_variable'
                })
                
        elif 'typeerror' in msg_lower:
            if 'int()' in msg_lower or "invalid literal" in msg_lower:
                solutions.append({
                    'code': "try:\n    value = int(text)\nexcept (ValueError, TypeError):\n    value = default_value",
                    'source': 'local',
                    'score': 80.0,
                    'description': 'Wrap type conversion in try/except',
                    'fix_type': 'type_coercion'
                })
            else:
                solutions.append({
                    'code': "# Check types before operation",
                    'source': 'local',
                    'score': 60.0,
                    'description': 'Add type checking before operation',
                    'fix_type': 'type_error'
                })
                
        elif 'valueerror' in msg_lower:
            solutions.append({
                'code': "try:\n    result = operation(value)\nexcept ValueError as e:\n    handle_error(e)",
                'source': 'local',
                'score': 70.0,
                'description': 'Wrap operation in try/except ValueError',
                'fix_type': 'value_error'
            })
            
        elif 'attributeerror' in msg_lower:
            attr_match = re.search(r"'(\w+)'", error_message)
            attr_name = attr_match.group(1) if attr_match else "attr"
            solutions.append({
                'code': f"if hasattr(obj, '{attr_name}'):\n    value = obj.{attr_name}",
                'source': 'local',
                'score': 75.0,
                'description': f'Check attribute existence with hasattr()',
                'fix_type': 'attribute_error'
            })
            solutions.append({
                'code': f"value = getattr(obj, '{attr_name}', default_value)",
                'source': 'local',
                'score': 70.0,
                'description': 'Use getattr() with default',
                'fix_type': 'attribute_error'
            })
            
        elif 'indexerror' in msg_lower:
            solutions.append({
                'code': "if index < len(items):\n    value = items[index]",
                'source': 'local',
                'score': 75.0,
                'description': 'Check index bounds before access',
                'fix_type': 'index_error'
            })
            
        elif 'importerror' in msg_lower or 'modulenotfounderror' in msg_lower:
            solutions.append({
                'code': "try:\n    import module\nexcept ImportError:\n    module = None  # Graceful degradation",
                'source': 'local',
                'score': 70.0,
                'description': 'Wrap import in try/except for graceful degradation',
                'fix_type': 'import_error'
            })
            
        elif 'filenotfounderror' in msg_lower or 'ioerror' in msg_lower:
            solutions.append({
                'code': "from pathlib import Path\nif Path(filepath).exists():\n    with open(filepath) as f:\n        data = f.read()",
                'source': 'local',
                'score': 80.0,
                'description': 'Check file existence before opening',
                'fix_type': 'file_not_found'
            })
            solutions.append({
                'code': "try:\n    with open(filepath) as f:\n        data = f.read()\nexcept FileNotFoundError:\n    data = default_value",
                'source': 'local',
                'score': 75.0,
                'description': 'Handle FileNotFoundError with try/except',
                'fix_type': 'file_not_found'
            })
        
        # Sort by score and limit results
        solutions.sort(key=lambda x: cast(float, x.get('score', 0)), reverse=True)
        return solutions[:max_results]

    def _generate_generic_bundle(self, job_type: str) -> Dict[str, Any]:
        """
        Generate a basic generic bundle as last resort.
        
        Args:
            job_type: Type of job
            
        Returns:
            Basic bundle dictionary
        """
        logger.debug("_generate_generic_bundle called", job_type=job_type)
        return {
            "role": f"You are tasked with {job_type.replace('_', ' ')}.",
            "rules": [
                "Analyze the issue carefully",
                "Make minimal, targeted changes", 
                "Preserve existing functionality",
                "Test your changes"
            ],
            "examples": [
                "# Generic example pattern",
                "# Before: problematic code",
                "# After: fixed code"
            ],
            "troubleshooting": [
                "Read the error message thoroughly",
                "Check related code and imports",
                "Apply standard Python best practices",
                "Verify the fix works"
            ]
        }

    def format_for_prompt(self, category: str) -> str:
        """
        Format a bundle as a string suitable for LLM prompts.
        Alias for get_bundle() for backwards compatibility.
        """
        return cast(str, self.get_bundle(category))

    def add_bundle(self, job_type: str, bundle: Dict[str, Any]) -> None:
        """
        Add a new bundle at runtime (for testing or dynamic extension).

        Args:
            job_type: The job type key
            bundle: Dictionary with role, rules, examples, troubleshooting
        """
        logger.debug("add_bundle called", job_type=job_type,
                    n_rules=len(bundle.get('rules', [])))
        self.bundles[job_type] = bundle
        logger.info("Added knowledge bundle", job_type=job_type)

    def _parse_bundle_content(self, content: str, suffix: str, path: str) -> Optional[Dict[str, Any]]:
        """Parse bundle file content based on file extension. Returns dict or None."""
        if suffix in (".yaml", ".yml"):
            if not YAML_AVAILABLE:
                logger.warning("PyYAML not installed, cannot load bundle",
                               path=path)
                return None
            return cast(Optional[Dict[str, Any]], yaml.safe_load(content))
        elif suffix == ".json":
            return cast(Dict[str, Any], json.loads(content))
        else:
            # Try JSON first, then YAML if available
            try:
                return cast(Dict[str, Any], json.loads(content))
            except json.JSONDecodeError:
                if YAML_AVAILABLE:
                    return cast(Optional[Dict[str, Any]], yaml.safe_load(content))
                else:
                    logger.error("Unknown format and PyYAML unavailable",
                               path=path)
                    return None

    def _ingest_bundles(self, data: Any, path: str) -> int:
        """Ingest parsed bundle data into self.bundles. Returns count loaded."""
        if not isinstance(data, dict):
            logger.error("Bundle file must contain a dict",
                        got_type=type(data).__name__, path=path)
            return 0

        count = 0
        for job_type, bundle in data.items():
            if isinstance(bundle, dict):
                self.bundles[job_type] = bundle
                count += 1
                logger.debug("Loaded bundle", job_type=job_type)
            else:
                logger.warning("Skipping invalid bundle: expected dict",
                               job_type=job_type)

        logger.info("Loaded bundles", count=count, path=path)
        return count

    async def load_from_file(self, path: str) -> int:
        """
        Load additional bundles from YAML or JSON file (async, uses asyncio.to_thread for I/O).

        Args:
            path: Path to bundles file

        Returns:
            Number of bundles loaded
        """
        logger.debug("load_from_file called", path=path)
        file_path = Path(path)
        exists = await asyncio.to_thread(file_path.exists)
        if not exists:
            logger.warning("Bundle file not found", path=path)
            return 0

        try:
            content = await asyncio.to_thread(file_path.read_text, "utf-8")
            data = self._parse_bundle_content(content, file_path.suffix.lower(), path)
            if data is None:
                return 0
            return self._ingest_bundles(data, path)
        except Exception as e:
            logger.error("Failed to load bundles", path=path, error=str(e))
            return 0

    async def load_from_file_async(self, path: str) -> int:
        """
        Load additional bundles from YAML or JSON file (async).

        Args:
            path: Path to bundles file

        Returns:
            Number of bundles loaded
        """
        logger.debug("load_from_file_async called", path=path)
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Bundle file not found (async)", path=path)
            return 0

        try:
            try:
                import aiofiles
                async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                    content = await f.read()
            except ImportError:
                content = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: file_path.read_text(encoding="utf-8")
                )

            data = self._parse_bundle_content(content, file_path.suffix.lower(), path)
            if data is None:
                return 0
            return self._ingest_bundles(data, path)
        except Exception as e:
            logger.error("Failed to load bundles (async)", path=path,
                        error=str(e))
            return 0

    async def load_from_directory(self, directory: str) -> int:
        """Load all .yaml/.json bundle files from a directory (async, uses asyncio.to_thread for I/O)."""
        logger.debug("load_from_directory called", directory=directory)
        dir_path = Path(directory)
        is_dir = await asyncio.to_thread(dir_path.is_dir)
        if not is_dir:
            return 0

        def _glob_pattern(p: str) -> List[Path]:
            return list(dir_path.glob(p))

        files: List[Path] = []
        for pattern in ("*.yaml", "*.yml", "*.json"):
            found = await asyncio.to_thread(_glob_pattern, pattern)
            files.extend(found)

        total = 0
        for file in files:
            total += await self.load_from_file(str(file))
        return total

    async def load_from_directory_async(self, directory: str) -> int:
        """Load all .yaml/.json bundle files from a directory (async)."""
        logger.debug("load_from_directory_async called", directory=directory)
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return 0

        files: List[Path] = []
        for pattern in ("*.yaml", "*.yml", "*.json"):
            files.extend(dir_path.glob(pattern))

        total = 0
        for file in files:
            total += await self.load_from_file_async(str(file))
        return total

    # =========================================================================
    # STOP 5.3: KNOWLEDGE INJECTION - Cheat Sheet Generation
    # =========================================================================
    # Per app_rationale: "Agents are provided with the 'answer'... a very small 
    # set of 'docs' that contain all answers and troubleshooting specific to 
    # that agent's very small job scope."
    #
    # CRITICAL: Each CheatSheet = ONE solution for ONE job. Not a menu!
    #
    # PHASE 6 INTEGRATION: RootCause evidence is injected into CheatSheet
    # to provide rich context about upstream dependencies and root causes.
    # =========================================================================
    
    async def generate_cheat_sheet_async(
        self,
        job_id: str,
        job_type: str,
        job_context: Optional[Dict[str, Any]] = None,
        rca_evidence: Optional[List[str]] = None,
        target_code: str = ""
    ) -> CheatSheet:
        """
        Generate THE ANSWER KEY for a specific job.
        
        Per app_rationale:
        - "make the tasks super small but also super easy - these plus the answer"
        - "there should be no need for any validation" because answer is provided
        
        This generates a SINGLE, TARGETED solution - not a menu of options.
        
        SOLUTION RANKING: When multiple candidates are found (local bundles),
        we use SolutionRanker to pick THE BEST one based on:
        - Error pattern match
        - Target repo code style (async/sync, typing)
        - Framework alignment
        - RootCause evidence alignment
        
        Args:
            job_id: Unique job identifier
            job_type: Type of job (fix_syntax, fix_import, etc.)
            job_context: Context with file_path, message, line, etc.
            rca_evidence: Evidence list from RootCauseReport (Phase 6)
            target_code: Code around the error (for style matching)
            
        Returns:
            CheatSheet with THE solution (singular!)
        """
        job_context = job_context or {}
        rca_evidence = rca_evidence or []

        file_path = job_context.get("file_path", "")
        line_number = job_context.get("line", 0)
        message = job_context.get("message", "")
        details = job_context.get("details", "")
        broken_code = job_context.get("broken_code", "")  # PATCHED: Actual broken code

        # DEBUG: Comprehensive logging for cheatsheet pipeline
        logger.debug("generate_cheat_sheet_async called",
                    job_id=job_id, job_type=job_type,
                    file_path=file_path, line_number=line_number,
                    issue_uuid=job_context.get('issue_uuid', ''),
                    msg_len=len(message), details_len=len(details),
                    broken_code_len=len(broken_code),
                    n_rca=len(rca_evidence))

        # Try to read target code if not provided (for style matching)
        if not target_code and file_path and self.repo_context:
            target_code = await self._read_target_code(file_path, line_number)
        
        # Enrich message with rca evidence if available
        enriched_message = message
        if rca_evidence:
            evidence_summary = " | ".join(rca_evidence[:MAX_RCA_EVIDENCE])  # Top N pieces
            enriched_message = f"{message} [Evidence: {evidence_summary}]"
            logger.debug("Enriched message with rca evidence",
                        n_evidence=len(rca_evidence))
        
        # =====================================================================
        # COLLECT ALL CANDIDATES (not just first match)
        # =====================================================================
        candidates: List[SolutionCandidate] = []
        
        # Step 1: Try local bundles (now with file context for specific before/after)
        # PATCHED: Pass job_context to get actual broken_code for before/after
        local_solution = await self._find_specific_solution(
            job_type, message, details, file_path, line_number, job_context
        )
        if local_solution and local_solution.get("solution"):
            candidates.append(SolutionCandidate(
                solution=local_solution.get("solution", ""),
                role=local_solution.get("role", f"{job_type.title()} Specialist"),
                before_code=local_solution.get("before", ""),
                after_code=local_solution.get("after", ""),
                if_stuck=local_solution.get("if_stuck", ""),
                steps=local_solution.get("steps", []),  # Ordered steps from ranker
                source="local",
                votes=0,
                accepted=False
            ))
        
        # Step 2: Always have a generic fallback
        generic_solution = self._generate_generic_solution(job_type, message)
        candidates.append(SolutionCandidate(
            solution=generic_solution.get("solution", ""),
            role=generic_solution.get("role", f"{job_type.title()} Specialist"),
            before_code=generic_solution.get("before", ""),
            after_code=generic_solution.get("after", ""),
            if_stuck=generic_solution.get("if_stuck", ""),
            steps=generic_solution.get("steps", []),  # Ordered steps for ranker
            source="generated",
            votes=0,
            accepted=False
        ))
        
        # =====================================================================
        # RANK AND SELECT THE ONE BEST SOLUTION
        # =====================================================================
        # DEBUG: Log all candidates before ranking
        logger.debug("Candidates collected for ranking",
                    n_candidates=len(candidates),
                    sources=[c.source for c in candidates])

        # Short-circuit: if the local candidate has actual code fix
        # (not a comment placeholder), use it directly — no ranking needed.
        local_with_code = [
            c for c in candidates
            if c.source == "local"
            and c.after_code
            and not c.after_code.lstrip().startswith("#")
        ]
        best: Any
        if local_with_code:
            best = local_with_code[0]
            logger.debug("Using local code fix directly (skipped ranking)",
                        source=best.source, after_len=len(best.after_code))
        else:
            project_profile = await self.get_project_profile()
            ranker = SolutionRanker(project_profile=project_profile)
            best = ranker.rank_candidates(
                candidates=candidates,
                error_message=message,
                rca_evidence=rca_evidence,
                target_code=target_code
            )

        # DEBUG: Log selected solution after ranking
        logger.debug("Selected best solution",
                    source=best.source if best else "NONE",
                    score=round(best.total_score, 1) if best else 0.0,
                    solution_len=len(best.solution) if best and best.solution else 0,
                    has_before=bool(best.before_code) if best else False,
                    has_after=bool(best.after_code) if best else False,
                    n_steps=len(best.steps) if best else 0)

        # Determine source metadata
        source = best.source if best else "generated"

        # Confidence based on source and ranking
        confidence_map = {
            "local": 1.0,
            "python_docs": 0.85,
            "generated": 0.5
        }
        confidence = confidence_map.get(source, 0.5)
        
        # Boost confidence for high-ranked solutions
        if best and best.total_score > 70:
            confidence = min(confidence + 0.1, 1.0)
        
        # Step 4: Build the CheatSheet with THE selected solution
        # [FIX] Include assertion details in problem description for LLM visibility
        problem_text = message or f"Fix {job_type.replace('_', ' ')} issue"
        if details and details != message:
            # Append assertion details if available (e.g., "assert 2 == 5")
            problem_text = f"{problem_text}\n\n{details}"
        # PATCHED: Include actual broken code in problem description
        if broken_code:
            problem_text = f"{problem_text}\n\n=== BROKEN CODE (fix this) ===\n{broken_code}"
        
        # PATCHED: When pattern provides specific before_code (like "return False"),
        # use that instead of generic broken_code (function definition).
        # Pattern's before/after is tailored to the specific bug type.
        if best and best.before_code and best.after_code:
            # Pattern matched and provided specific before/after - use those
            actual_before = best.before_code
        else:
            # Fall back to broken code from file context
            actual_before = broken_code if broken_code else ""

        # TRACKING: Get full UUID from job_context (passed from granulator)
        full_issue_uuid = job_context.get("issue_uuid", "")

        cheat_sheet = CheatSheet(
            job_id=job_id,
            job_type=job_type,
            issue_uuid=full_issue_uuid,  # TRACKING: Full RepairJobUUID
            role=best.role if best else f"{job_type.replace('_', ' ').title()} Specialist",
            problem=problem_text,
            solution=best.solution if best else "",
            steps=best.steps if best else [],  # Ordered steps from ranker
            before_code=actual_before,  # PATCHED: Uses actual broken code
            after_code=best.after_code if best else "",
            if_stuck=best.if_stuck if best else "",
            file_path=file_path,
            line_number=line_number,
            repo_context=self.repo_context,
            confidence=confidence,
            source=source,
            rca_evidence=rca_evidence,  # Store for reference
        )

        # RECORD CHEATSHEET: Store for display in final report
        # Use full UUID directly instead of searching
        if full_issue_uuid:
            try:
                from orchestrator.core.issue_tracker import get_tracker
                tracker = get_tracker()
                tracker.record_cheatsheet(full_issue_uuid, {
                    'job_type': job_type,
                    'file': file_path,
                    'line': line_number,
                    'solution': best.solution if best else "",
                    'before_code': actual_before,
                    'after_code': best.after_code if best else "",
                    'if_stuck': best.if_stuck if best else "",
                    'source': source,
                })
            except Exception as e:
                logger.debug("Could not record cheatsheet",
                            error=str(e))
        else:
            # Fallback: search for matching issue_id (when no full UUID available)
            try:
                from orchestrator.core.issue_tracker import get_tracker
                tracker = get_tracker()
                for issue_id in tracker.issues:
                    if issue_id.startswith(job_id):
                        tracker.record_cheatsheet(issue_id, {
                            'job_type': job_type,
                            'file': file_path,
                            'line': line_number,
                            'solution': best.solution if best else "",
                            'before_code': actual_before,
                            'after_code': best.after_code if best else "",
                            'if_stuck': best.if_stuck if best else "",
                            'source': source,
                        })
                        break
            except Exception as e:
                logger.debug("Could not record cheatsheet (fallback)",
                            error=str(e))

        best_score = best.total_score if best else 0.0
        logger.info("Generated CheatSheet",
                    job_id=job_id, job_type=job_type, source=source,
                    confidence=round(confidence, 2),
                    score=round(best_score, 1),
                    n_candidates=len(candidates),
                    n_evidence=len(rca_evidence))
        return cheat_sheet
    
    async def _read_target_code(self, file_path: str, line_number: int, context_lines: int = 10) -> str:
        """Read code around the error location for style matching."""
        logger.debug("_read_target_code called",
                    file_path=file_path, line_number=line_number,
                    context_lines=context_lines)
        try:
            import aiofiles
            from pathlib import Path
            
            # Try to resolve file path
            if self.repo_context:
                # Assume repo_context might contain repo path hint
                full_path = Path(file_path)
            else:
                full_path = Path(file_path)
            
            if not full_path.exists():
                return ""
            
            async with aiofiles.open(full_path, 'r', encoding='utf-8') as f:
                lines = await f.readlines()
            
            # Get lines around the error
            start = max(0, line_number - context_lines)
            end = min(len(lines), line_number + context_lines)
            
            return "".join(lines[start:end])
            
        except Exception as e:
            logger.debug("Could not read target code", error=str(e))
            return ""
    
    def _extract_error_class(self, error_message: str) -> Optional[str]:
        """Extract the Python error class name from an error message.
        
        Examples:
            "IndentationError: expected an indented block" -> "IndentationError"
            "TypeError: 'NoneType' object is not subscriptable" -> "TypeError"
            "ModuleNotFoundError: No module named 'foo'" -> "ModuleNotFoundError"
        """
        if not error_message:
            return None
        
        # Common Python error patterns
        error_patterns = [
            r'^(\w*Error):\s',      # StandardError: message
            r'^(\w*Exception):\s',  # SomeException: message
            r'^(\w*Warning):\s',    # SomeWarning: message
            r'\b(IndentationError)\b',
            r'\b(SyntaxError)\b',
            r'\b(TypeError)\b',
            r'\b(ValueError)\b',
            r'\b(KeyError)\b',
            r'\b(AttributeError)\b',
            r'\b(ImportError)\b',
            r'\b(ModuleNotFoundError)\b',
            r'\b(NameError)\b',
            r'\b(IndexError)\b',
            r'\b(FileNotFoundError)\b',
            r'\b(ZeroDivisionError)\b',
            r'\b(RuntimeError)\b',
            r'\b(StopIteration)\b',
            r'\b(RecursionError)\b',
            r'\b(MemoryError)\b',
            r'\b(OverflowError)\b',
            r'\b(AssertionError)\b',
            r'\b(UnicodeError)\b',
            r'\b(UnicodeDecodeError)\b',
            r'\b(UnicodeEncodeError)\b',
            r'\b(JSONDecodeError)\b',
            r'\b(ConnectionError)\b',
            r'\b(TimeoutError)\b',
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, error_message)
            if match:
                return match.group(1)
        
        return None
    
    def _build_optimized_query(
        self,
        job_type: str,
        error_message: str,
        error_class: Optional[str]
    ) -> tuple[str, List[str]]:
        """Build an optimized search query for Stack Overflow.
        
        Returns:
            (query_string, tags_list)
        """
        # Job type to search term mappings (curated for SO)
        job_type_terms = {
            'fix_syntax': 'python syntax error fix',
            'fix_import': 'python import error modulenotfounderror fix',
            'fix_type': 'python type error typeerror fix',
            'fix_attribute': 'python attribute error attributeerror fix',
            'fix_key': 'python key error keyerror dictionary fix',
            'fix_index': 'python index error indexerror list fix',
            'fix_value': 'python value error valueerror fix',
            'fix_name': 'NameError undefined variable',
            'fix_indentation': 'IndentationError tabs spaces',
            'fix_async': 'asyncio coroutine await',
            'fix_file': 'FileNotFoundError IOError',
            'fix_encoding': 'UnicodeDecodeError encoding utf-8',
            'fix_json': 'JSONDecodeError parsing',
            'fix_runtime': 'RuntimeError',
            'fix_security': 'python security vulnerability bandit fix',
            'fix_logic': 'python test failure assertion fix debug',
            'RCA_LOGIC': 'python test failure root cause analysis',
        }
        
        # Tag mappings for better filtering
        job_type_tags = {
            'fix_syntax': ['python', 'syntax-error'],
            'fix_import': ['python', 'import'],
            'fix_indentation': ['python', 'indentation'],
            'fix_async': ['python', 'asyncio'],
            'fix_json': ['python', 'json'],
            'fix_encoding': ['python', 'unicode'],
            'fix_security': ['python', 'security'],
            'fix_logic': ['python', 'testing', 'pytest'],
            'RCA_LOGIC': ['python', 'debugging'],
        }
        
        # Start with job-type specific terms or default
        base_terms = job_type_terms.get(job_type, 'python error')
        tags = job_type_tags.get(job_type, ['python'])
        
        # Build a SHORT, FOCUSED query for SO API
        # SO works best with concise queries (under 50 chars)
        query_parts = []
        
        # 1. Error class is the most important - ALWAYS include
        if error_class:
            query_parts.append(f"python {error_class}")
        else:
            # Use base terms if no error class
            query_parts.append(base_terms)
        
        # 2. Add key phrase from error message (SHORT - just the core issue)
        if error_message:
            # FILTER OUT triage summary patterns - these are NOT useful for search
            # Patterns like "Fix 2 SYNTAX issues in foo.py" are internal summaries
            triage_pattern = re.match(
                r'^Fix\s+\d+\s+(SYNTAX|IMPORT|TYPE|SECURITY|LOGIC)\s+issues?\s+in\s+',
                error_message,
                re.IGNORECASE
            )
            if triage_pattern:
                # This is a triage summary, not an actual error - skip adding to query
                logger.debug("Skipping triage summary in query",
                            error_message=error_message[:80])
                msg_part = ""
            else:
                # Get the part after the colon (the actual message)
                if ':' in error_message:
                    msg_part = error_message.split(':', 1)[1].strip()
                else:
                    msg_part = error_message
            
            if msg_part:
                # Clean up
                msg_part = re.sub(r'[\'"`]', '', msg_part)  # Remove quotes
                msg_part = re.sub(r'\s+', ' ', msg_part)     # Normalize whitespace
                msg_part = re.sub(r'\bon line \d+\b', '', msg_part)  # Remove line refs
                msg_part = msg_part.strip()
                
                # Take ONLY first 3-4 words (most relevant)
                words = msg_part.split()[:4]
                if words:
                    query_parts.append(' '.join(words))
        
        query = ' '.join(query_parts)
        
        # Cap query length for SO API
        if len(query) > 60:
            query = query[:60].rsplit(' ', 1)[0]  # Cut at word boundary
        
        logger.debug("Optimized query built", query=query, tags=tags)
        
        return query, tags

    async def _find_specific_solution(
        self,
        job_type: str,
        error_message: str,
        details: str = "",
        file_path: str = "",
        line_number: int = 0,
        job_context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Find THE specific solution for this exact error.

        Maps error patterns to single solutions.
        Now includes file context to show actual problematic line in before/after.

        PATCHED: Now uses job_context.get("broken_code") as the actual before_code
        so the LLM sees the REAL broken line, not generic examples.
        """
        logger.debug("_find_specific_solution called",
                     job_type=job_type, file_path=file_path,
                     line_number=line_number,
                     msg_len=len(error_message))
        job_context = job_context or {}

        # Get base bundle
        bundle = self.bundles.get(job_type)
        if not bundle:
            bundle = self._find_bundle_by_keywords(job_type)

        if not bundle:
            return None

        role = bundle.get("role", "Python Developer")
        rules = bundle.get("rules", [])
        examples = bundle.get("examples", [])
        troubleshooting = bundle.get("troubleshooting", [])

        # Extract THE solution from rules (first applicable rule)
        solution = rules[0] if rules else ""
        steps = []  # Ordered steps for LLM to follow (populated by pattern matching)

        # ═══════════════════════════════════════════════════════════════════════
        # PATCHED: Use ACTUAL broken code from job_context, not generic examples!
        # The LLM needs to SEE the real broken line to fix it properly.
        # ═══════════════════════════════════════════════════════════════════════
        broken_code = job_context.get("broken_code", "")
        before_code = broken_code  # Default to actual broken code
        after_code = ""

        # Fallback to generic examples only if no broken_code available
        if not before_code and examples:
            example = examples[0]
            if " -> " in example or "→" in example:
                parts = example.replace("→", "->").split("->")
                if len(parts) >= 2:
                    before_code = parts[0].strip()
                    after_code = parts[1].strip()

        # Log what we're using for debugging
        if broken_code:
            logger.debug("_find_specific_solution using actual broken_code",
                         broken_code_len=len(broken_code))
        else:
            logger.debug("_find_specific_solution no broken_code, using generic examples")
        
        # Extract THE troubleshooting tip (first applicable)
        if_stuck = troubleshooting[0] if troubleshooting else ""
        
        # Pattern matching for MORE SPECIFIC solutions
        msg_lower = error_message.lower()
        details_lower = details.lower() if details else ""

        # ═════════════════════════════════════════════════════════════════════
        # NAI DETECTION RULES — produce actual code fixes from broken source
        # ═════════════════════════════════════════════════════════════════════
        if "nai-" in details_lower:
            # NAI-104: implied operation not implemented
            if "implies" in msg_lower and "operation" in msg_lower and "none found" in msg_lower:
                return {"role": role, "before": broken_code or "",
                        "after": broken_code or "",
                        "solution": "The function name implies an operation (e.g. validate, transform, filter) but the body does not perform it. Implement the operation the name describes.",
                        "if_stuck": "Read the function name as a specification — implement what it promises.",
                        "steps": ["1. Identify the operation implied by the function name",
                                  "2. Implement that operation in the function body",
                                  "3. Ensure the return value reflects the operation"]}

            # NAI-153: membership test on list instead of set
            if "membership test" in msg_lower and "list" in msg_lower:
                before = broken_code or "if x in [1, 2, 3]:"
                after = "if x in {1, 2, 3}:" if not broken_code else broken_code.replace("[", "{").replace("]", "}")
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Membership test uses a list literal. Convert to a set literal for O(1) lookup instead of O(n).",
                        "if_stuck": "Replace square brackets with curly braces: [1,2,3] → {1,2,3}.",
                        "steps": ["1. Find the 'in [...]' membership test",
                                  "2. Replace [...] with {...} to use a set literal",
                                  "3. Verify elements are hashable (strings, ints, tuples are fine)"]}

            # NAI-154: noqa / type: ignore overuse
            if "noqa" in msg_lower or ("type: ignore" in msg_lower and "overuse" in msg_lower):
                return {"role": role, "before": broken_code or "x = foo()  # type: ignore\ny = bar()  # noqa: E501",
                        "after": broken_code or "x: int = foo()\ny = bar()",
                        "solution": "Suppression comments (noqa, type: ignore) are overused. Fix the underlying issues instead of silencing them.",
                        "if_stuck": "Remove each suppression comment and fix the actual warning it was hiding.",
                        "steps": ["1. Remove the noqa / type: ignore comment",
                                  "2. Read the resulting warning or type error",
                                  "3. Fix the root cause (add type annotation, fix line length, etc.)"]}

            # NAI-155: copy-paste / structural duplication in tests
            if "copy-paste test" in msg_lower or "structural duplication" in msg_lower:
                return {"role": role, "before": broken_code or "def test_a():\n    assert func(1) == 2\ndef test_b():\n    assert func(2) == 4",
                        "after": broken_code or "@pytest.mark.parametrize('inp,expected', [(1,2),(2,4)])\ndef test_func(inp, expected):\n    assert func(inp) == expected",
                        "solution": "Tests contain structural duplication. Use pytest.mark.parametrize to collapse repeated test bodies into a single parameterized test.",
                        "if_stuck": "Extract the varying parts (inputs + expected outputs) into a parametrize decorator.",
                        "steps": ["1. Identify the repeated test structure",
                                  "2. Extract varying values into a parametrize list",
                                  "3. Collapse into a single parameterized test function"]}

            # NAI-159: deprecated API / stale dependency
            if "deprecated" in msg_lower and ("api" in msg_lower or "stale" in msg_lower):
                return {"role": role, "before": broken_code or "",
                        "after": broken_code or "",
                        "solution": "Code uses a deprecated API or stale dependency. Check the library changelog for the modern replacement.",
                        "if_stuck": "Search the library docs for a migration guide from the deprecated API.",
                        "steps": ["1. Identify the deprecated function or module",
                                  "2. Check the library changelog or deprecation warning for the replacement",
                                  "3. Update the call site to use the modern API"]}

            # NAI-167: hardcoded environmental values
            if "environmental context" in msg_lower or "hardcoded url" in msg_lower:
                return {"role": role, "before": broken_code or 'API_URL = "https://prod.example.com/api"',
                        "after": broken_code or 'API_URL = os.environ.get("API_URL", "https://prod.example.com/api")',
                        "solution": "Hardcoded URLs or environment-specific values should use os.environ.get() so they can vary across deployments.",
                        "if_stuck": "Replace the hardcoded string with os.environ.get('VAR_NAME', <current_value>) as default.",
                        "steps": ["1. Identify the hardcoded environment-specific value",
                                  "2. Choose a descriptive environment variable name",
                                  "3. Replace with os.environ.get('NAME', original_value)"]}

            # NAI-168: over-engineering / excessive structure
            if "over-engineering" in msg_lower or "structural over" in msg_lower:
                return {"role": role, "before": broken_code or "",
                        "after": broken_code or "",
                        "solution": "Code is over-engineered with excessive try/except layers or abstraction. Consolidate into simpler, flatter control flow.",
                        "if_stuck": "Merge nested try/except blocks into a single handler; remove wrapper functions that add no logic.",
                        "steps": ["1. Identify redundant try/except nesting or trivial wrapper layers",
                                  "2. Merge exception handlers that catch the same thing",
                                  "3. Inline wrapper functions that just delegate without adding logic"]}

            # NAI-169: compulsive modularization / tiny helpers
            if "compulsive modularization" in msg_lower or "tiny nested" in msg_lower:
                return {"role": role, "before": broken_code or "",
                        "after": broken_code or "",
                        "solution": "Trivial helper functions add indirection without value. Inline them into the caller.",
                        "if_stuck": "If a helper is called once and its body is shorter than the call + definition, inline it.",
                        "steps": ["1. Identify single-use helpers with trivial bodies",
                                  "2. Copy the helper body into the call site",
                                  "3. Remove the now-unused helper definition"]}

            # ─── GENERAL DETECTION RULES ───

            if "not defined" in msg_lower or "not imported" in msg_lower:
                after = broken_code or "from mymodule import load_data, process_data\n\ndef run():\n    data = load_data()\n    return process_data(data)"
                before = broken_code or "def run():\n    data = load_data()\n    return process_data(data)"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Function references names that are not defined or imported in this scope. Add the missing imports or define the functions.",
                        "if_stuck": "Add 'from module import function_name' at the top of the file for each undefined name.",
                        "steps": ["1. Identify which names are undefined",
                                  "2. Add imports for external functions or define them locally",
                                  "3. Verify the imported module exists and is installed"]}

            if "unguarded json" in msg_lower or "jsondecode" in msg_lower or ("json.load" in msg_lower and "try" in msg_lower):
                after = broken_code or "try:\n    data = json.loads(raw)\nexcept json.JSONDecodeError as e:\n    logging.error('Invalid JSON: %s', e)\n    return default"
                before = broken_code or "data = json.loads(raw)"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Unguarded json.loads()/json.load() call with no try/except for JSONDecodeError. Wrap in error handling.",
                        "if_stuck": "Add try/except json.JSONDecodeError around the json.loads() call and handle the parse failure gracefully.",
                        "steps": ["1. Wrap json.loads() in try/except json.JSONDecodeError",
                                  "2. Log the error with context (what was being parsed)",
                                  "3. Return a sensible default or re-raise with a better message"]}

            # ─── SAFETY RULES (NAI-076 to NAI-098) ───

            if "no error handling" in msg_lower and "external" in msg_lower:
                after = broken_code or "try:\n    result = external_call()\nexcept Exception as e:\n    logging.error('External call failed: %s', e)\n    raise"
                before = broken_code or "result = external_call()"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Function calls multiple external functions with no try/except. Add error handling to catch and handle downstream failures.",
                        "if_stuck": "Wrap the external calls in try/except Exception as e: and handle gracefully (log, return error, re-raise with context).",
                        "steps": ["1. Wrap external function calls in try/except",
                                  "2. Log or handle the exception appropriately",
                                  "3. Consider what the caller needs on failure (None, empty list, re-raise)"]}

            if "risky i/o" in msg_lower or ("without try/except" in msg_lower and ("file" in msg_lower or "import" in msg_lower or "parse" in msg_lower)):
                after = broken_code or "try:\n    with open(filepath) as f:\n        data = f.read()\nexcept (FileNotFoundError, IOError) as e:\n    logging.error('I/O failed: %s', e)\n    data = default"
                before = broken_code or "with open(filepath) as f:\n    data = f.read()"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "File/import/parse operations can fail for reasons outside the code's control. Wrap in try/except.",
                        "if_stuck": "Wrap the I/O operation in try/except catching the relevant exception (FileNotFoundError, ImportError, JSONDecodeError, etc.).",
                        "steps": ["1. Identify the risky I/O operation (open, import_module, json.load, etc.)",
                                  "2. Wrap it in try/except with the appropriate exception type",
                                  "3. Handle the error gracefully (default value, logging, re-raise with context)"]}

            if "bare except" in msg_lower or "catches systemExit" in msg_lower.lower():
                after = broken_code.replace("except:", "except Exception:") if broken_code else "try:\n    do_work()\nexcept Exception as e:\n    logging.warning('Error: %s', e)"
                before = broken_code or "try:\n    do_work()\nexcept:\n    pass"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Bare 'except:' catches SystemExit, KeyboardInterrupt, and GeneratorExit. Use 'except Exception:' to only catch real errors.",
                        "if_stuck": "Replace 'except:' with 'except Exception as e:' to avoid catching control-flow exceptions.",
                        "steps": ["1. Replace 'except:' with 'except Exception as e:'",
                                  "2. Log the exception: logging.warning('Error: %s', e)",
                                  "3. Consider catching only the specific exception you expect"]}

            if "float equality" in msg_lower or "math.isclose" in msg_lower:
                after = broken_code or "import math\nif math.isclose(a, b, rel_tol=1e-9):\n    pass"
                before = broken_code or "if a == b:\n    pass"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Floating point equality comparison is unreliable. Use math.isclose(a, b) or abs(a - b) < epsilon.",
                        "if_stuck": "import math; use math.isclose(a, b, rel_tol=1e-9) instead of a == b for floats.",
                        "steps": ["1. Replace 'a == b' with 'math.isclose(a, b)'",
                                  "2. Choose appropriate tolerance (rel_tol or abs_tol)",
                                  "3. Import math at the top of the file"]}

            if "assert" in msg_lower and ("stripped" in msg_lower or "-O flag" in msg_lower or "validation" in msg_lower):
                after = broken_code or "if x <= 0:\n    raise ValueError('x must be positive')"
                before = broken_code or "assert x > 0"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Assert is used for runtime validation but is stripped with python -O. Use explicit if/raise for input validation.",
                        "if_stuck": "Replace 'assert x > 0' with 'if x <= 0: raise ValueError(\"x must be positive\")'.",
                        "steps": ["1. Replace assert with an explicit if-check",
                                  "2. Raise an appropriate exception (ValueError, TypeError)",
                                  "3. Include a descriptive error message"]}

            if "magic number" in msg_lower or "named constant" in msg_lower:
                after = broken_code or "MARGIN_FACTOR = 0.65\n\ndef process(data):\n    return data * MARGIN_FACTOR"
                before = broken_code or "def process(data):\n    return data * 0.65"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Magic number in function body. Extract to a named constant at module level for clarity and maintainability.",
                        "if_stuck": "Replace the literal number with a named constant: MY_CONSTANT = 0.65 at the top of the file.",
                        "steps": ["1. Identify the magic number and its purpose",
                                  "2. Create a named constant at module level (UPPER_SNAKE_CASE)",
                                  "3. Replace the literal with the constant name"]}

            if "dead code" in msg_lower or "never imported" in msg_lower or "never called" in msg_lower:
                after = broken_code or "# Function removed — was never called in the pipeline"
                before = broken_code or "def unused_function():\n    pass"
                return {"role": role, "before": before,
                        "after": after,
                        "solution": "Function is defined but never imported or called anywhere in the repo. Remove it or wire it into the pipeline.",
                        "if_stuck": "Delete the function if it's truly unused, or add the missing import/call in the appropriate file.",
                        "steps": ["1. Verify the function is truly unused (search all files)",
                                  "2. If unused, delete it to reduce maintenance burden",
                                  "3. If it should be used, add the missing import and call"]}

            # ─── NEW CORE RULES (NAI-002 to NAI-008) ───

            if "unreachable code" in msg_lower or "after return" in msg_lower:
                after = broken_code or "def process(x):\n    if x < 0:\n        return None\n    return x * 2"
                before = broken_code or "def process(x):\n    if x < 0:\n        return None\n        x = abs(x)\n    return x * 2"
                return {"role": role, "before": before, "after": after,
                        "solution": "Code after return/raise is unreachable and will never execute. Remove it or move it before the return.",
                        "if_stuck": "Delete the unreachable statements or restructure the logic so the code executes before the return.",
                        "steps": ["1. Find the return/raise statement with code after it",
                                  "2. Move the unreachable code before the return, or delete it"]}

            if "unused parameter" in msg_lower or ("never referenced" in msg_lower and "param" in msg_lower):
                after = broken_code or "def process(data, config):\n    return transform(data, config)"
                before = broken_code or "def process(data, config):\n    return transform(data)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Parameters are declared but never used. Wire them into the function body or remove them from the signature.",
                        "if_stuck": "Use the parameter in the function body, or remove it from the function signature if it's not needed.",
                        "steps": ["1. Identify which parameters are unused",
                                  "2. Wire them into the function logic or remove from signature"]}

            if "no implementation" in msg_lower or "only pass" in msg_lower or "only ellipsis" in msg_lower:
                after = broken_code or "def process(data):\n    result = [item for item in data if item.is_valid()]\n    return result"
                before = broken_code or "def process(data):\n    pass"
                return {"role": role, "before": before, "after": after,
                        "solution": "Function has no implementation — only pass or ellipsis. Add the actual logic.",
                        "if_stuck": "Replace pass with the intended implementation. If placeholder, mark as TODO or raise NotImplementedError.",
                        "steps": ["1. Determine what the function should do from its name/docstring",
                                  "2. Implement the logic or raise NotImplementedError"]}

            if "redundant else" in msg_lower and "return" in msg_lower:
                after = broken_code or "def check(x):\n    if x < 0:\n        return -1\n    return x"
                before = broken_code or "def check(x):\n    if x < 0:\n        return -1\n    else:\n        return x"
                return {"role": role, "before": before, "after": after,
                        "solution": "Redundant else after if-return. The else block is unnecessary since the if already returns.",
                        "if_stuck": "Remove the else: and dedent its body — the code after if-return only runs when the condition is false anyway.",
                        "steps": ["1. Remove the else: keyword",
                                  "2. Dedent the else body to be at the same level as the if"]}

            if "immediately overwritten" in msg_lower or "previous assignment wasted" in msg_lower:
                after = broken_code or "def f():\n    result = compute()"
                before = broken_code or "def f():\n    result = initial()\n    result = compute()"
                return {"role": role, "before": before, "after": after,
                        "solution": "Variable is assigned then immediately overwritten without being read. Remove the first useless assignment.",
                        "if_stuck": "Delete the first assignment — its value is never used before being overwritten.",
                        "steps": ["1. Remove the first assignment to the variable",
                                  "2. Keep only the final assignment that is actually used"]}

            if "nested function" in msg_lower and ("never called" in msg_lower or "never returned" in msg_lower):
                after = broken_code or "def outer():\n    def helper():\n        return 42\n    return helper()"
                before = broken_code or "def outer():\n    def helper():\n        return 42\n    return None"
                return {"role": role, "before": before, "after": after,
                        "solution": "Nested function is defined but never called or returned. Call it or remove the dead definition.",
                        "if_stuck": "Either call the nested function or return it. If it's truly unused, delete it.",
                        "steps": ["1. Call the nested function in the enclosing function body",
                                  "2. Or return it if it's meant to be a closure/factory"]}

            if "import inside function" in msg_lower or "move to module level" in msg_lower:
                after = broken_code or "import os\n\ndef process(path):\n    return os.path.exists(path)"
                before = broken_code or "def process(path):\n    import os\n    return os.path.exists(path)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Import inside function body. Move to module level for clarity and performance.",
                        "if_stuck": "Move the import statement to the top of the file unless it's a conditional import in a try/except.",
                        "steps": ["1. Move the import to the top of the file",
                                  "2. Keep inside function only if it's a conditional import (try/except ImportError)"]}

            # ─── NEW MATH/ADVANCED/HALLUCINATION RULES ───

            if "constant conditional" in msg_lower or "always true" in msg_lower or "always false" in msg_lower:
                after = broken_code or "def f(x):\n    if x > 0:\n        return x"
                before = broken_code or "def f(x):\n    if True:\n        return x"
                return {"role": role, "before": before, "after": after,
                        "solution": "Condition is always True or always False — it's a constant. Replace with the actual condition or remove the branch.",
                        "if_stuck": "Replace 'if True:' with a meaningful condition or remove the if statement entirely.",
                        "steps": ["1. Replace the constant condition with a real boolean expression",
                                  "2. Or remove the if/else and keep only the relevant branch"]}

            if "identical method" in msg_lower or "same implementation" in msg_lower:
                after = broken_code or "def process(data):\n    return transform(data)"
                before = broken_code or "def process_a(data):\n    return transform(data)\ndef process_b(data):\n    return transform(data)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Multiple methods have identical bodies — copy-paste code. Consolidate into one method or factor out the shared logic.",
                        "if_stuck": "Create one method and have the duplicates call it, or merge them into a single function.",
                        "steps": ["1. Identify the duplicated logic",
                                  "2. Extract into a single method",
                                  "3. Replace duplicates with calls to the shared method"]}

            if "hallucinated constant" in msg_lower or "verify this constant" in msg_lower:
                after = broken_code or "status = config.get('status', 'active')"
                before = broken_code or "status = Module.STATUS_ACTIVE"
                return {"role": role, "before": before, "after": after,
                        "solution": "Accessing a constant that may not exist in the referenced module. Verify the constant exists or use a string/enum.",
                        "if_stuck": "Check the module's documentation for valid constant names, or define your own constant.",
                        "steps": ["1. Verify the constant exists in the referenced module",
                                  "2. If not, define it locally or use a string literal"]}

            # ─── NEW SEMANTIC RULES (NAI-108, 109, 115-118) ───

            if "name implies" in msg_lower and "returns" in msg_lower:
                after = broken_code or "def get_count():\n    return len(items)"
                before = broken_code or "def get_count():\n    return 'none'"
                return {"role": role, "before": before, "after": after,
                        "solution": "Return type doesn't match function name convention. Function name suggests one type but returns another.",
                        "if_stuck": "Change the return value to match what the name implies, or rename the function.",
                        "steps": ["1. Check what the function name implies (count→int, name→str, list→list)",
                                  "2. Fix the return type or rename the function"]}

            if "does opposite" in msg_lower or "opposite of name" in msg_lower:
                after = broken_code or "def add_item(items, item):\n    items.append(item)"
                before = broken_code or "def add_item(items, item):\n    items.remove(item)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Function does the opposite of what its name says. Fix the implementation or rename the function.",
                        "if_stuck": "The function name says add but the code removes (or vice versa). Fix whichever is wrong.",
                        "steps": ["1. Determine the correct behavior from context",
                                  "2. Fix the implementation to match the name, or rename"]}

            if "hardcoded" in msg_lower and ("list" in msg_lower or "dict" in msg_lower) and "dynamic" in msg_lower:
                after = broken_code or "def get_users(db):\n    return db.query('SELECT * FROM users')"
                before = broken_code or "def get_users(db):\n    return ['alice', 'bob']"
                return {"role": role, "before": before, "after": after,
                        "solution": "Function returns hardcoded data but name implies dynamic retrieval. Implement actual data fetching.",
                        "if_stuck": "Replace the hardcoded list/dict with actual data retrieval logic.",
                        "steps": ["1. Replace hardcoded return with actual data source query",
                                  "2. Use the function parameters to fetch real data"]}

            if "string concatenation" in msg_lower and "loop" in msg_lower:
                after = broken_code or "result = ''.join(str(x) for x in items)"
                before = broken_code or "result = ''\nfor x in items:\n    result += str(x)"
                return {"role": role, "before": before, "after": after,
                        "solution": "String concatenation in loop creates O(n^2) behavior. Use ''.join() instead.",
                        "if_stuck": "Collect items in a list, then ''.join() at the end, or use a generator expression.",
                        "steps": ["1. Replace += with list.append()",
                                  "2. Use ''.join(parts) after the loop",
                                  "3. Or use a generator: ''.join(str(x) for x in items)"]}

            if "mixed naming" in msg_lower or ("camelcase" in msg_lower and "snake_case" in msg_lower):
                after = broken_code or "user_name = get_name()\nuser_age = get_age()"
                before = broken_code or "userName = get_name()\nuser_age = get_age()"
                return {"role": role, "before": before, "after": after,
                        "solution": "Mixed camelCase and snake_case naming in same function. Pick one convention (Python prefers snake_case).",
                        "if_stuck": "Rename all local variables to snake_case to follow PEP 8.",
                        "steps": ["1. Identify variables using camelCase",
                                  "2. Rename them to snake_case"]}

            if "validates but never raises" in msg_lower or "only returns true/false" in msg_lower:
                after = broken_code or "def validate_input(x):\n    if x < 0:\n        raise ValueError(f'x must be non-negative, got {x}')\n    return True"
                before = broken_code or "def validate_input(x):\n    if x < 0:\n        return False\n    return True"
                return {"role": role, "before": before, "after": after,
                        "solution": "Validation function only returns True/False without raising or reporting errors. Add raise/logging for invalid cases.",
                        "if_stuck": "Replace 'return False' with 'raise ValueError(description)' so callers get actionable error messages.",
                        "steps": ["1. Replace return False with raise ValueError('description')",
                                  "2. Or add logging.error() before returning False"]}

            # ─── NEW EXTENDED SEMANTIC RULES (NAI-128, 133-138, 148) ───

            if "mutable default" in msg_lower and "nested" in msg_lower:
                after = broken_code or "def outer():\n    def inner(items=None):\n        if items is None:\n            items = []\n        items.append(1)"
                before = broken_code or "def outer():\n    def inner(items=[]):\n        items.append(1)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Mutable default argument in nested function. Use None and assign inside the function.",
                        "if_stuck": "Change def f(x=[]) to def f(x=None): if x is None: x = []",
                        "steps": ["1. Change default from [] or {} to None",
                                  "2. Add 'if param is None: param = []' at function start"]}

            if "implies batch" in msg_lower or ("process" in msg_lower and "no loop" in msg_lower):
                after = broken_code or "def process_items(items):\n    return [transform(item) for item in items]"
                before = broken_code or "def process_items(items):\n    return transform(items[0])"
                return {"role": role, "before": before, "after": after,
                        "solution": "Function name implies batch processing but has no loop or comprehension. Add iteration logic.",
                        "if_stuck": "Add a for-loop or list comprehension to process all items, not just one.",
                        "steps": ["1. Add a loop or comprehension to iterate over the input",
                                  "2. Process each item and collect results"]}

            if "implies filtering" in msg_lower or ("filter" in msg_lower and "no conditional" in msg_lower):
                after = broken_code or "def filter_valid(items):\n    return [x for x in items if x.is_valid()]"
                before = broken_code or "def filter_valid(items):\n    return items"
                return {"role": role, "before": before, "after": after,
                        "solution": "Filter function has no conditional logic — returns everything unchanged. Add filtering criteria.",
                        "if_stuck": "Add an if-condition in a comprehension: [x for x in items if condition(x)]",
                        "steps": ["1. Define what makes an item valid/invalid",
                                  "2. Add a conditional filter (if clause or explicit if-statement)"]}

            if "implies sorting" in msg_lower or ("sort" in msg_lower and "no sort" in msg_lower and "comparison" in msg_lower):
                after = broken_code or "def sort_by_name(items):\n    return sorted(items, key=lambda x: x.name)"
                before = broken_code or "def sort_by_name(items):\n    return items"
                return {"role": role, "before": before, "after": after,
                        "solution": "Sort function has no sorting logic. Add sorted() or .sort() with appropriate key.",
                        "if_stuck": "Use sorted(items, key=lambda x: x.field) or items.sort(key=...).",
                        "steps": ["1. Use sorted() or list.sort() with appropriate key function",
                                  "2. Determine the sort field from the function name"]}

            if "implies counting" in msg_lower or ("count" in msg_lower and "no counter" in msg_lower):
                after = broken_code or "def count_valid(items):\n    return sum(1 for x in items if x.is_valid())"
                before = broken_code or "def count_valid(items):\n    return 0"
                return {"role": role, "before": before, "after": after,
                        "solution": "Count function has no counter or accumulator. Add len(), sum(), or += logic.",
                        "if_stuck": "Use sum(1 for x in items if condition) or len([x for x in items if condition]).",
                        "steps": ["1. Add counting logic using sum(), len(), or a counter variable",
                                  "2. Count items matching the criteria implied by the function name"]}

            if "implies searching" in msg_lower or ("search" in msg_lower and "no comparison" in msg_lower):
                after = broken_code or "def find_item(items, target):\n    for item in items:\n        if item.id == target:\n            return item\n    return None"
                before = broken_code or "def find_item(items, target):\n    return items[0]"
                return {"role": role, "before": before, "after": after,
                        "solution": "Search function has no comparison or lookup logic. Add search criteria.",
                        "if_stuck": "Add a loop with a comparison: for item in items: if item == target: return item.",
                        "steps": ["1. Add iteration over the collection",
                                  "2. Add comparison to find the target",
                                  "3. Return None or raise if not found"]}

            if "implies building" in msg_lower or ("create" in msg_lower and "never returns" in msg_lower):
                after = broken_code or "def build_report(data):\n    report = {'title': data.title, 'items': data.items}\n    return report"
                before = broken_code or "def build_report(data):\n    report = {'title': data.title}"
                return {"role": role, "before": before, "after": after,
                        "solution": "Build/create function never returns the constructed object. Add a return statement.",
                        "if_stuck": "Add 'return result' at the end of the function.",
                        "steps": ["1. Identify the object being built",
                                  "2. Add 'return object' at the end of the function"]}

            if "shadows the import" in msg_lower or "imported name" in msg_lower and "reassigned" in msg_lower:
                after = broken_code or "import os\npath_str = '/tmp/data'"
                before = broken_code or "import os\nos = '/tmp/data'"
                return {"role": role, "before": before, "after": after,
                        "solution": "Imported module/name is reassigned, shadowing the import. Use a different variable name.",
                        "if_stuck": "Rename the local variable so it doesn't shadow the imported name.",
                        "steps": ["1. Rename the local variable to avoid shadowing",
                                  "2. Or remove the import if it's no longer needed"]}

            # ─── AI FINGERPRINT RULES (NAI-110, 111, 112, 119) ───

            if "cross-language" in msg_lower or "not python" in msg_lower:
                after = broken_code or "items.append(x)\nresult = len(items)\ntext = s.upper()"
                before = broken_code or "items.push(x)\nresult = items.length\ntext = s.toUpperCase()"
                return {"role": role, "before": before, "after": after,
                        "solution": "Code uses methods from another language (JS/Java/Ruby). Replace with Python equivalents.",
                        "if_stuck": ".push()→.append(), .length→len(), .toString()→str(), .forEach()→for loop, .equals()→==",
                        "steps": ["1. Identify the non-Python method call",
                                  "2. Replace with the Python equivalent"]}

            if "phantom api" in msg_lower or ("does not exist" in msg_lower and "verify" in msg_lower):
                after = broken_code or "# Verify method exists in library docs\nresult = pd.read_csv('data.csv')"
                before = broken_code or "result = pd.optimize('data.csv')"
                return {"role": role, "before": before, "after": after,
                        "solution": "Calling a method that doesn't exist on this library. Check the library's documentation for the correct method name.",
                        "if_stuck": "Search the library docs or dir(module) to find the actual method name.",
                        "steps": ["1. Check the library documentation for valid methods",
                                  "2. Replace with the correct method name"]}

            if "hallucinated package" in msg_lower or "ai-invented package" in msg_lower:
                after = broken_code or "import json\nimport os\n\ndef process(path):\n    with open(path) as f:\n        return json.load(f)"
                before = broken_code or "from dataprocessor import load_data\n\ndef process(path):\n    return load_data(path)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Importing a package that likely doesn't exist. Use stdlib or verified PyPI packages instead.",
                        "if_stuck": "Check if the package exists on PyPI. If not, implement the functionality with stdlib or install a real package.",
                        "steps": ["1. Verify the package exists: pip search or pypi.org",
                                  "2. Replace with stdlib equivalent or a real PyPI package"]}

            if "hedging" in msg_lower or "uncertainty" in msg_lower:
                after = broken_code or "def process(data):\n    \"\"\"Process and validate input data.\"\"\"\n    return transform(data)"
                before = broken_code or "def process(data):\n    \"\"\"This should hopefully work for most cases.\"\"\"\n    return transform(data)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Hedging language ('hopefully', 'should work', 'might') in docstring indicates uncertainty. Rewrite with confidence or fix the underlying issue.",
                        "if_stuck": "Remove hedging words and either fix the code or document the known limitation clearly.",
                        "steps": ["1. Remove hedging language from docstrings/comments",
                                  "2. If uncertain, fix the code; if a known limitation, document it precisely"]}

            # ─── STYLE FINGERPRINT RULES (NAI-113, 114) ───

            if "over-documented" in msg_lower or ("ai fingerprint" in msg_lower and "doc" in msg_lower):
                after = broken_code or "def add(a, b):\n    return a + b"
                before = broken_code or "def add(a, b):\n    \"\"\"Add two numbers together.\"\"\"\n    # First number\n    # Second number\n    # Return result\n    return a + b"
                return {"role": role, "before": before, "after": after,
                        "solution": "Excessive documentation for obvious code — AI fingerprint. Remove comments that state the obvious.",
                        "if_stuck": "Delete comments that just restate the code. Keep only comments that explain WHY, not WHAT.",
                        "steps": ["1. Remove comments that merely restate the code",
                                  "2. Keep only comments that explain non-obvious decisions"]}

            if "hyper-descriptive" in msg_lower or "identifier length" in msg_lower:
                after = broken_code or "user_count = len(users)\nmax_retries = 3"
                before = broken_code or "active_registered_user_quantity = len(users)\nmaximum_number_of_retry_attempts = 3"
                return {"role": role, "before": before, "after": after,
                        "solution": "Hyper-descriptive variable names (>25 chars) are an AI fingerprint. Use reasonable abbreviations.",
                        "if_stuck": "Shorten variable names to 2-3 words. Use common abbreviations: config, msg, ctx, num, max, min.",
                        "steps": ["1. Shorten overly long variable names",
                                  "2. Use standard abbreviations where appropriate"]}

            # ─── TEST QUALITY RULES (NAI-129, 139, 149, 150) ───

            if "mock-heavy" in msg_lower or "mocks vs" in msg_lower:
                after = broken_code or "def test_integration():\n    db = create_test_db()\n    result = process(db)\n    assert result.status == 'ok'"
                before = broken_code or "def test_integration():\n    with patch('module.db') as m:\n        m.return_value = Mock()\n        result = process(m)\n        assert result"
                return {"role": role, "before": before, "after": after,
                        "solution": "Test mocks too many dependencies — doesn't validate real behavior. Use real dependencies or test doubles with actual behavior.",
                        "if_stuck": "Reduce mocks. Use test databases, fixtures, or fakes instead of mocking everything.",
                        "steps": ["1. Replace mocks with real test dependencies where possible",
                                  "2. Use fixtures or test doubles with real behavior"]}

            if "tautological test" in msg_lower or "mirrors implementation" in msg_lower:
                after = broken_code or "def test_discount():\n    assert calculate_discount(100, 0.1) == 90.0"
                before = broken_code or "def test_discount():\n    result = calculate_discount(100, 0.1)\n    assert result == 100 * (1 - 0.1)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Test re-derives expected values using the same logic as the code under test. Use pre-computed expected values instead.",
                        "if_stuck": "Replace inline calculations in assertions with literal expected values (e.g., assert result == 90.0).",
                        "steps": ["1. Replace inline computations in assertions with literal expected values",
                                  "2. Test BEHAVIOR, not implementation details"]}

            if "happy-path-only" in msg_lower or "no error/edge" in msg_lower:
                after = broken_code or "def test_divide():\n    assert divide(10, 2) == 5\n    with pytest.raises(ZeroDivisionError):\n        divide(10, 0)"
                before = broken_code or "def test_divide():\n    assert divide(10, 2) == 5\n    assert divide(6, 3) == 2"
                return {"role": role, "before": before, "after": after,
                        "solution": "Test only covers happy path — no error, edge, or boundary cases. Add negative tests.",
                        "if_stuck": "Add tests for: empty input, None, wrong types, boundary values, expected exceptions.",
                        "steps": ["1. Add error case tests (invalid input, exceptions)",
                                  "2. Add edge cases (empty, None, zero, boundary values)",
                                  "3. Add negative tests (assert False, assertRaises)"]}

            if "assertion-free test" in msg_lower or "never asserts" in msg_lower:
                after = broken_code or "def test_process():\n    result = process(data)\n    assert result is not None\n    assert len(result) > 0"
                before = broken_code or "def test_process():\n    result = process(data)\n    transform(result)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Test calls code but never asserts anything — runs without verifying behavior. Add assertions.",
                        "if_stuck": "Add assert statements after each function call to verify the return value or side effects.",
                        "steps": ["1. Add assertions after function calls",
                                  "2. Verify return values, state changes, or side effects"]}

            # ─── FINAL BATCH RULES (NAI-170-186) ───

            if "pre-increment" in msg_lower or "pre-decrement" in msg_lower or "++x" in msg_lower or "--x" in msg_lower:
                after = broken_code or "x += 1  # Python increment\nx -= 1  # Python decrement"
                before = broken_code or "++x  # no-op in Python\n--x  # no-op in Python"
                return {"role": role, "before": before, "after": after,
                        "solution": "++x and --x are no-ops in Python (C/Java habit). Use x += 1 or x -= 1.",
                        "if_stuck": "Replace ++x with x += 1 and --x with x -= 1.",
                        "steps": ["1. Replace ++x with x += 1",
                                  "2. Replace --x with x -= 1"]}

            if "loop else without break" in msg_lower or "always executes the else" in msg_lower:
                after = broken_code or "for item in items:\n    if item == target:\n        break\nelse:\n    print('not found')"
                before = broken_code or "for item in items:\n    process(item)\nelse:\n    print('done')"
                return {"role": role, "before": before, "after": after,
                        "solution": "Loop else without break always executes — the else clause only has meaning when break can skip it.",
                        "if_stuck": "Either add a break statement or remove the else clause.",
                        "steps": ["1. Add a break statement in the loop if else is needed",
                                  "2. Or remove the else clause and put the code after the loop"]}

            if "except ordering" in msg_lower or "child is unreachable" in msg_lower:
                after = broken_code or "try:\n    risky()\nexcept ValueError:\n    handle_value()\nexcept Exception:\n    handle_generic()"
                before = broken_code or "try:\n    risky()\nexcept Exception:\n    handle_generic()\nexcept ValueError:\n    handle_value()"
                return {"role": role, "before": before, "after": after,
                        "solution": "Parent exception caught before child makes child handler unreachable. Order from most specific to most general.",
                        "if_stuck": "Reorder except clauses: most specific first (ValueError), most general last (Exception).",
                        "steps": ["1. Move specific exceptions (ValueError, KeyError) before general ones",
                                  "2. Put Exception/BaseException last"]}

            if "return in finally" in msg_lower or ("silently swallows" in msg_lower and "finally" in msg_lower):
                after = broken_code or "try:\n    result = risky()\nexcept Exception:\n    logger.error('Failed')\n    raise\nfinally:\n    cleanup()"
                before = broken_code or "try:\n    result = risky()\nfinally:\n    return default_value"
                return {"role": role, "before": before, "after": after,
                        "solution": "Return in finally block silently swallows any exception being propagated. Move the return outside finally.",
                        "if_stuck": "Remove return from finally block. Use try/except/else pattern instead.",
                        "steps": ["1. Remove the return statement from the finally block",
                                  "2. Use try/except/else to handle the return cases explicitly"]}

            if "shadowing builtin" in msg_lower or "overwrites python builtin" in msg_lower:
                after = broken_code or "items = [1, 2, 3]\nobj_type = type(obj)\nuser_id = get_id()"
                before = broken_code or "list = [1, 2, 3]\ntype = type(obj)\nid = get_id()"
                return {"role": role, "before": before, "after": after,
                        "solution": "Variable shadows a Python builtin. Use a different name to avoid breaking builtin access later.",
                        "if_stuck": "Rename: list->items, dict->mapping, type->kind, id->obj_id, input->user_input",
                        "steps": ["1. Rename the variable to not shadow the builtin",
                                  "2. Common renames: list->items, dict->mapping, type->kind, id->obj_id"]}

            if "duplicate dict key" in msg_lower or "silently overwrites earlier" in msg_lower:
                after = broken_code or "config = {'host': 'localhost', 'port': 8080, 'debug': True}"
                before = broken_code or "config = {'host': 'localhost', 'port': 8080, 'host': '0.0.0.0'}"
                return {"role": role, "before": before, "after": after,
                        "solution": "Duplicate key in dict literal — second value silently overwrites first. Remove the duplicate.",
                        "if_stuck": "Remove the duplicate key or rename it if both values are needed.",
                        "steps": ["1. Remove the duplicate dict key",
                                  "2. Keep the intended value"]}

            if "f-string without placeholders" in msg_lower or "f-prefix is unnecessary" in msg_lower:
                after = broken_code or "msg = 'hello world'"
                before = broken_code or "msg = f'hello world'"
                return {"role": role, "before": before, "after": after,
                        "solution": "f-string has no {} placeholders — the f-prefix is pointless. Use a regular string.",
                        "if_stuck": "Remove the f prefix from the string literal.",
                        "steps": ["1. Remove the f prefix from the string"]}

            if "repeated lookup" in msg_lower and "loop" in msg_lower and "cache" in msg_lower:
                after = broken_code or "cached = obj.attr\nfor item in items:\n    use(cached)"
                before = broken_code or "for item in items:\n    use(obj.attr)\n    process(obj.attr)\n    check(obj.attr)"
                return {"role": role, "before": before, "after": after,
                        "solution": "Repeated dict/attribute lookup inside loop. Cache the value before the loop.",
                        "if_stuck": "Assign the repeated lookup to a local variable before the loop.",
                        "steps": ["1. Create a local variable before the loop",
                                  "2. Assign the repeated lookup to it",
                                  "3. Use the local variable inside the loop"]}

            if "concat in loop" in msg_lower and ("join" in msg_lower or "extend" in msg_lower):
                after = broken_code or "parts = []\nfor x in items:\n    parts.append(str(x))\nresult = ''.join(parts)"
                before = broken_code or "result = ''\nfor x in items:\n    result = result + str(x)"
                return {"role": role, "before": before, "after": after,
                        "solution": "String/list concatenation with = in loop is O(n^2). Use join() or list.extend().",
                        "if_stuck": "Collect parts in a list, then ''.join(parts) at the end.",
                        "steps": ["1. Create a list to collect parts",
                                  "2. Append to the list in the loop",
                                  "3. Join or extend after the loop"]}

            if "commented-out code" in msg_lower or ("dead code" in msg_lower and "string" in msg_lower):
                after = broken_code or "def process(data):\n    return transform(data)"
                before = broken_code or "def process(data):\n    'old_result = legacy_transform(data)'\n    return transform(data)"
                return {"role": role, "before": before, "after": after,
                        "solution": "String constant appears to contain commented-out code. Delete dead code — use version control.",
                        "if_stuck": "Delete the string constant containing dead code. Git history preserves old code.",
                        "steps": ["1. Delete the string constant containing old code",
                                  "2. If needed later, retrieve from git history"]}

            if "unnecessary list()" in msg_lower or "pass generator directly" in msg_lower:
                after = broken_code or "total = sum(x**2 for x in items)\nfor i in range(10):"
                before = broken_code or "total = sum(list(x**2 for x in items))\nfor i in list(range(10)):"
                return {"role": role, "before": before, "after": after,
                        "solution": "Unnecessary list() wrapping — consuming function already accepts iterables. Pass generator directly.",
                        "if_stuck": "Remove list() wrapper. range(), generators are already iterable.",
                        "steps": ["1. Remove the list() wrapper",
                                  "2. Pass the iterable directly"]}

            if "god class" in msg_lower or "too many responsibilities" in msg_lower:
                after = broken_code or "# Split class into smaller focused classes:\n# UserAuth, UserProfile, UserNotifications"
                before = broken_code or "# One class doing auth, profile, notifications, billing, etc."
                return {"role": role, "before": before, "after": after,
                        "solution": "Method accesses too many self attributes — class likely has too many responsibilities. Split into focused classes.",
                        "if_stuck": "Group related attributes and extract them into separate classes using composition.",
                        "steps": ["1. Group related self.xxx attributes by responsibility",
                                  "2. Extract each group into its own class",
                                  "3. Use composition: self.auth = AuthHandler()"]}

            if "feature envy" in msg_lower or "method may belong elsewhere" in msg_lower:
                after = broken_code or "# Move method to the class it actually uses\nclass Order:\n    def calculate_total(self): ..."
                before = broken_code or "class Invoice:\n    def calc(self, order):\n        return order.price * order.qty"
                return {"role": role, "before": before, "after": after,
                        "solution": "Method uses another object's data more than its own — it may belong in that other class.",
                        "if_stuck": "Move the method to the class whose attributes it uses most.",
                        "steps": ["1. Consider moving the method to the class it envies",
                                  "2. Or extract the needed values as parameters"]}

            if "cyclomatic complexity" in msg_lower or "decision paths" in msg_lower:
                after = broken_code or "def process(data):\n    if not is_valid(data): return None\n    return transform(data)"
                before = broken_code or "# Too many if/elif/for/while branches in one function"
                return {"role": role, "before": before, "after": after,
                        "solution": "Function has too many execution paths (high cyclomatic complexity). Split into smaller functions.",
                        "if_stuck": "Extract conditional blocks into helper methods. Use early returns.",
                        "steps": ["1. Extract complex conditions into named helper functions",
                                  "2. Use early returns for guard clauses",
                                  "3. Replace nested if/else with dispatch dict"]}

            if "cognitive complexity" in msg_lower or "hard to understand" in msg_lower:
                after = broken_code or "def process(items):\n    return [transform(x) for x in items if is_valid(x)]"
                before = broken_code or "def process(items):\n    for x in items:\n        if x:\n            if is_valid(x):\n                ..."
                return {"role": role, "before": before, "after": after,
                        "solution": "Function has high cognitive complexity due to deep nesting. Flatten the logic.",
                        "if_stuck": "Reduce nesting: use guard clauses, extract helpers, replace loops with comprehensions.",
                        "steps": ["1. Use early returns to eliminate nesting",
                                  "2. Extract deeply nested blocks into helper functions"]}

            # ─── EXTENDED SECURITY RULES (NAI-160 to NAI-166) ───

            if "missing input validation" in msg_lower or "without sanitization" in msg_lower:
                after = broken_code or "def run_query(user_input):\n    if not isinstance(user_input, str):\n        raise TypeError('Expected string')\n    sanitized = user_input.strip().replace(\"'\", \"''\")\n    cursor.execute('SELECT * FROM t WHERE name = %s', (sanitized,))"
                before = broken_code or "def run_query(user_input):\n    cursor.execute(f'SELECT * FROM t WHERE name = {user_input}')"
                return {"role": role, "before": before, "after": after,
                        "solution": "Function passes external input directly to risky operations without validation (CWE-20). Add input validation and sanitization.",
                        "if_stuck": "Add isinstance checks, strip/escape input, or use parameterized queries.",
                        "steps": ["1. Validate input type and format (isinstance, regex)",
                                  "2. Sanitize/escape before passing to sensitive operations",
                                  "3. Use parameterized queries for SQL, shlex.quote for shell"]}

            if "http request without timeout" in msg_lower or "can hang indefinitely" in msg_lower:
                after = broken_code or "response = requests.get(url, timeout=30)"
                before = broken_code or "response = requests.get(url)"
                return {"role": role, "before": before, "after": after,
                        "solution": "HTTP request has no timeout — can hang indefinitely if server doesn't respond. Always set timeout=.",
                        "if_stuck": "Add timeout=30 (or appropriate value) to all requests calls.",
                        "steps": ["1. Add timeout= parameter to the requests call",
                                  "2. Consider using a session with default timeout for multiple requests"]}

            if "certificate validation disabled" in msg_lower or "verify=false" in msg_lower:
                after = broken_code or "response = requests.get(url, timeout=30)\n# If using self-signed certs:\n# response = requests.get(url, verify='/path/to/ca-bundle.crt', timeout=30)"
                before = broken_code or "response = requests.get(url, verify=False)"
                return {"role": role, "before": before, "after": after,
                        "solution": "verify=False disables TLS certificate validation, allowing MITM attacks. Remove verify=False or use a custom CA bundle.",
                        "if_stuck": "Remove verify=False. For self-signed certs, point verify= to the CA bundle file.",
                        "steps": ["1. Remove verify=False from the request",
                                  "2. For self-signed certs, use verify='/path/to/ca-bundle.crt'",
                                  "3. For dev/test, use environment-based config instead of hardcoding"]}

            if "hardcoded bind" in msg_lower or "0.0.0.0" in msg_lower:
                after = broken_code or "host = os.environ.get('BIND_HOST', '127.0.0.1')\nserver.bind((host, port))"
                before = broken_code or "server.bind(('0.0.0.0', port))"
                return {"role": role, "before": before, "after": after,
                        "solution": "Binding to 0.0.0.0 exposes the service on all network interfaces. Use 127.0.0.1 for local-only or make it configurable.",
                        "if_stuck": "Replace '0.0.0.0' with '127.0.0.1' or read from config/environment variable.",
                        "steps": ["1. Replace '0.0.0.0' with '127.0.0.1' for local-only",
                                  "2. Or read bind address from environment/config",
                                  "3. Document why all-interfaces binding is needed if intentional"]}

            if "insecure temp file" in msg_lower or "mktemp" in msg_lower:
                after = broken_code or "import tempfile\nfd, path = tempfile.mkstemp(suffix='.tmp')\n# or: with tempfile.NamedTemporaryFile() as f:"
                before = broken_code or "import tempfile\npath = tempfile.mktemp(suffix='.tmp')"
                return {"role": role, "before": before, "after": after,
                        "solution": "tempfile.mktemp() is vulnerable to TOCTOU race conditions. Use mkstemp() or NamedTemporaryFile() instead.",
                        "if_stuck": "Replace mktemp() with mkstemp() (returns fd + path) or NamedTemporaryFile().",
                        "steps": ["1. Replace tempfile.mktemp() with tempfile.mkstemp()",
                                  "2. Or use tempfile.NamedTemporaryFile() as context manager",
                                  "3. mkstemp returns (fd, path) — remember to close the fd"]}

            if "trojan source" in msg_lower or "bidi control" in msg_lower:
                after = broken_code or "# Remove all hidden Unicode bidi characters from source code\n# Use a linter or editor that highlights invisible characters"
                before = broken_code or "# String contains hidden bidi override characters"
                return {"role": role, "before": before, "after": after,
                        "solution": "String contains hidden Unicode bidirectional control characters that can make code appear different from what executes. Remove all bidi characters.",
                        "if_stuck": "Use 'cat -v' or a hex editor to find hidden characters. Remove all U+200E-U+200F, U+202A-U+202E, U+2066-U+2069.",
                        "steps": ["1. Find hidden bidi characters with a hex editor or linter",
                                  "2. Remove all bidirectional control characters",
                                  "3. Review the actual logic now that the characters are visible"]}

            if "raise notimplemented" in msg_lower or "notimplemented is a singleton" in msg_lower:
                after = broken_code or "raise NotImplementedError('Method not implemented')"
                before = broken_code or "raise NotImplemented"
                return {"role": role, "before": before, "after": after,
                        "solution": "'raise NotImplemented' raises TypeError at runtime. NotImplemented is a singleton for binary ops, not an exception. Use NotImplementedError.",
                        "if_stuck": "Replace 'raise NotImplemented' with 'raise NotImplementedError(\"...\")'.",
                        "steps": ["1. Replace NotImplemented with NotImplementedError",
                                  "2. Add a descriptive message to the exception"]}

        # PATCHED: Include assertion_info AND broken_code in pattern matching!
        # Without this, patterns like "result == true" and "return false" can't be detected
        assertion_info = job_context.get("assertion_info", "") if job_context else ""
        assertion_lower = assertion_info.lower() if assertion_info else ""
        broken_lower = broken_code.lower() if broken_code else ""

        logger.debug("_find_specific_solution pattern inputs",
                     has_assertion=bool(assertion_info),
                     assertion_len=len(assertion_info) if assertion_info else 0,
                     has_broken_code=bool(broken_code),
                     broken_code_len=len(broken_code) if broken_code else 0)

        # COMBINED TEXT for pattern matching - check message, details, assertion, AND broken code
        combined_lower = f"{msg_lower} {details_lower} {assertion_lower} {broken_lower}".lower()

        logger.debug("_find_specific_solution combined text",
                     combined_len=len(combined_lower))

        # =================================================================
        # TEST FAILURE ASSERTIONS - The assertion IS the answer!
        # Parse the assertion to extract expected vs actual values.
        # Also triggers on test_failure messages that contain descriptive test names
        # =================================================================
        is_test_failure = "test_failure" in combined_lower or "test failure" in combined_lower or "pytest" in combined_lower
        has_assertion = "assert" in combined_lower or "assertionerror" in combined_lower
        logger.debug("_find_specific_solution entry check",
                    job_type=job_type, is_test_failure=is_test_failure,
                    has_assertion=has_assertion,
                    entering_assertion_block=has_assertion or is_test_failure)
        if has_assertion or is_test_failure:
            # Extract assertion info from details
            # Common patterns: "assert X == Y", "expected X got Y", "At index N diff"

            # For ordering issues (common in async code)
            if "at index" in combined_lower and "diff" in combined_lower:
                logger.info("[MATCHED] at index/diff")
                solution = "FIX THE ORDER: Results are returned out of order. Replace asyncio.wait() with asyncio.gather() to preserve input order, or use enumerate to track indices."
                if_stuck = "asyncio.wait() returns a SET which loses order. Use: results = await asyncio.gather(*tasks)"
                before_code = "done, _ = await asyncio.wait(tasks)\nreturn [t.result() for t in done]"
                after_code = "results = await asyncio.gather(*tasks)\nreturn list(results)"

            # CACHE-SPECIFIC PATTERNS - Must come BEFORE generic time/sleep check!
            # (cache.py uses time.time() so "time" appears in combined_lower)

            # For LRU cache eviction
            elif "lru" in combined_lower or ("cache" in combined_lower and "evict" in combined_lower):
                logger.info("[MATCHED] lru")
                solution = "FIX THE LRU ORDER: LRU should evict OLDEST (least recently used), not newest. Pop from front of list, not back."
                if_stuck = "access_order[0] is oldest, access_order[-1] is newest"
                before_code = "oldest = self.access_order[-1]  # Wrong: this is newest"
                after_code = "oldest = self.access_order[0]  # Correct: this is oldest"

            # For TTL cache expiry
            elif "ttl" in combined_lower or ("cache" in combined_lower and "expir" in combined_lower):
                logger.info("[MATCHED] ttl")
                solution = "FIX THE TTL CALCULATION: Expiry should be current_time + ttl, not minus."
                if_stuck = "expiry = time.time() + ttl (add, not subtract)"
                before_code = "expiry = time.time() - actual_ttl  # Wrong"
                after_code = "expiry = time.time() + actual_ttl  # Correct"

            # For memoize kwargs issues
            elif "memoize" in combined_lower or "kwargs" in combined_lower:
                logger.info("[MATCHED] memoize")
                solution = "FIX THE CACHE KEY: Include both args AND kwargs in the cache key for proper memoization."
                if_stuck = "key = (args, tuple(sorted(kwargs.items())))"
                before_code = "key = str(args)  # Missing kwargs"
                after_code = "key = (args, tuple(sorted(kwargs.items())))"

            # For timing/sleep issues (AFTER cache-specific patterns!)
            elif "time" in combined_lower and ("sleep" in combined_lower or "< 0." in combined_lower):
                logger.info("[MATCHED] time/sleep")
                solution = "FIX THE TIMING: The code is sleeping when it shouldn't, or not sleeping when it should. Check the sleep/wait logic."
                if_stuck = "Look for 'pass' statements that should be 'await asyncio.sleep()' calls"
                before_code = "if condition:\n    pass  # Should sleep"
                after_code = "if condition:\n    await asyncio.sleep(interval)"

            # For value comparison issues (median, statistics, etc.)
            elif "==" in combined_lower and any(x in combined_lower for x in ["median", "mean", "std", "average"]):
                logger.info("[MATCHED] stats")
                solution = "FIX THE CALCULATION: The math formula is wrong. Check the algorithm - especially for edge cases like even-length lists."
                if_stuck = "For median of even-length list: average of two middle elements, not just one"
                before_code = "median = sorted_nums[n // 2]  # Wrong for even length"
                after_code = "median = sorted_nums[n // 2] if n % 2 else (sorted_nums[n//2-1] + sorted_nums[n//2]) / 2"

            # For CSV parsing with quotes - MUST have CSV-specific keywords, not just commas/quotes
            elif "csv" in combined_lower or (
                (',' in combined_lower and '"' in combined_lower) and
                any(kw in combined_lower for kw in ["parse", "split", "delimiter", "field", "column", "row", "reader", "writer"])
            ):
                logger.info("[MATCHED] csv")
                solution = "FIX THE CSV PARSING: Simple split() doesn't handle quoted fields. Use csv module or implement proper quote handling."
                if_stuck = "csv.reader handles quotes automatically: list(csv.reader([line]))[0]"
                before_code = "return line.split(delimiter)"
                after_code = "import csv\nreturn list(csv.reader([line], delimiter=delimiter))[0]"

            # For function returning wrong boolean value
            # Pattern: test has "assert result == True" (meaning test expects True but got False)
            # Common case: function does work but returns hardcoded False instead of True
            elif "result == true" in combined_lower or "result is true" in combined_lower:
                logger.info("[MATCHED] result_should_be_true")
                # Check if this is a file operation (create_, save_, write_, export_)
                if any(op in combined_lower for op in ["create_", "save_", "write_", "export_"]):
                    solution = "FIX THE FINAL RETURN ONLY: The function has TWO 'return False' statements - (1) early return for error case (KEEP THIS), (2) FINAL return after plt.close(fig) (FIX THIS to 'return os.path.exists(output_path)'). Do NOT change the early error-checking return."
                    if_stuck = "Find the LAST 'return False' that comes AFTER plt.close(fig) - change ONLY that one to 'return os.path.exists(output_path)'. Keep the first 'return False' that checks input lengths."
                    # CRITICAL: Indentation must match actual file (4-space indent for both lines)
                    before_code = "    plt.close(fig)\n\n    return False"
                    after_code = "    plt.close(fig)\n\n    return os.path.exists(output_path)"
                    # STEPS: Ordered sequence for LLM to follow
                    steps = [
                        "Locate the function at the TARGET LINE in the file",
                        "Find the LAST 'return False' in that function (comes AFTER plt.close(fig))",
                        "Change ONLY that return statement to: return os.path.exists(output_path)",
                        "Keep the FIRST 'return False' (the error-checking one) unchanged",
                        "Keep ALL other code exactly as-is"
                    ]
                else:
                    solution = "FIX THE FINAL RETURN ONLY: The function may have multiple 'return False' - keep early returns for error cases, only change the LAST 'return False' at the END to 'return True'."
                    if_stuck = "Find the LAST 'return False' in the function body - that's the success return to fix. Keep any early returns for validation."
                    before_code = "# ... function body completes ...\n    return False"
                    after_code = "# ... function body completes ...\n    return True"
                    steps = [
                        "Locate the function at the TARGET LINE in the file",
                        "Find the LAST 'return False' in that function (at the END after successful work)",
                        "Change ONLY that return to: return True",
                        "Keep any EARLY 'return False' (error-checking returns) unchanged",
                        "Keep ALL other code exactly as-is"
                    ]

            # ARITHMETIC OPERATOR BUGS - add/multiply/subtract/divide with wrong operator
            # Pattern: function is arithmetic (add, multiply, etc.) but returns wrong value
            elif any(op in combined_lower for op in ["add(", "multiply(", "subtract(", "divide(", "_add", "_multiply", "_subtract", "_divide"]):
                logger.info("[MATCHED] arithmetic_operator_bug")

                # Detect which arithmetic operation
                if "add" in combined_lower or "_add" in combined_lower:
                    solution = "FIX THE OPERATOR: The add function uses the WRONG operator. Change '-' to '+' or fix the arithmetic expression."
                    if_stuck = "add(a, b) should return a + b, not a - b. Find 'return a - b' and change to 'return a + b'."
                    before_code = "return a - b  # WRONG"
                    after_code = "return a + b  # CORRECT"
                    steps = [
                        "Find the return statement in the add function",
                        "Look for 'return a - b' or similar wrong operator",
                        "Change the operator from '-' to '+'",
                        "Result: return a + b"
                    ]
                elif "multiply" in combined_lower or "_multiply" in combined_lower:
                    solution = "FIX THE OPERATOR: The multiply function uses the WRONG operator. Change '+' to '*' or fix the arithmetic expression."
                    if_stuck = "multiply(a, b) should return a * b, not a + b. Find 'return a + b' and change to 'return a * b'."
                    before_code = "return a + b  # WRONG"
                    after_code = "return a * b  # CORRECT"
                    steps = [
                        "Find the return statement in the multiply function",
                        "Look for 'return a + b' or similar wrong operator",
                        "Change the operator from '+' to '*'",
                        "Result: return a * b"
                    ]
                elif "subtract" in combined_lower or "_subtract" in combined_lower:
                    solution = "FIX THE OPERATOR: The subtract function uses the WRONG operator. Change '+' to '-' or fix the arithmetic expression."
                    if_stuck = "subtract(a, b) should return a - b, not a + b."
                    before_code = "return a + b  # WRONG"
                    after_code = "return a - b  # CORRECT"
                    steps = [
                        "Find the return statement in the subtract function",
                        "Change the operator to '-'",
                        "Result: return a - b"
                    ]
                elif "divide" in combined_lower or "_divide" in combined_lower:
                    solution = "FIX THE OPERATOR: The divide function uses the WRONG operator. Change '*' or '+' or '-' to '/' for division."
                    if_stuck = "divide(a, b) should return a / b."
                    before_code = "return a * b  # WRONG"
                    after_code = "return a / b  # CORRECT"
                    steps = [
                        "Find the return statement in the divide function",
                        "Change the operator to '/'",
                        "Result: return a / b"
                    ]
                else:
                    # Generic arithmetic
                    solution = "FIX THE ARITHMETIC OPERATOR: Check the operator used in the return statement. The operator is wrong."
                    if_stuck = "The function name tells you what operation to use: add=+, subtract=-, multiply=*, divide=/"
                    steps = ["Check the function name", "Fix the operator to match the expected operation"]

            # Generic assertion failure - use the assertion itself as guidance
            else:
                logger.info("[NO PATTERN MATCHED] using generic assertion guidance")
                solution = f"FIX TO MATCH EXPECTED: The test shows exactly what's expected. Make the code produce the expected output shown in the assertion."
                if_stuck = "Read the assert statement carefully - it shows EXPECTED == ACTUAL. Make code produce EXPECTED."

        # Syntax-specific patterns - NOW WITH ACTUAL LINE CONTENT!
        elif job_type == "fix_syntax" or "syntax" in msg_lower:
            # PATCHED: Use broken_code from job_context if available (already extracted in granulator)
            # This is preferred because it includes surrounding context lines
            actual_line = ""
            if broken_code:
                # broken_code already has context, use the line at the error position
                # Format is "LINE_NUM: code" for each line
                actual_line = broken_code  # Use full context as actual_line for now
                logger.debug("Using broken_code from job_context for syntax fix")
            elif file_path and line_number > 0:
                # Fallback: Try to read the actual problematic line
                try:
                    from pathlib import Path
                    p = Path(file_path)
                    if not p.is_absolute() and self.repo_path:
                        p = Path(self.repo_path) / file_path
                    if p.exists():
                        with open(p, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            if 0 < line_number <= len(lines):
                                actual_line = lines[line_number - 1].rstrip()
                            # Also try line before (syntax errors often point to next line)
                            elif 0 < line_number - 1 <= len(lines):
                                actual_line = lines[line_number - 2].rstrip()
                except Exception as e:
                    logger.debug("Could not read actual line",
                                error=str(e))

            if "unexpected eof" in msg_lower or "eof" in msg_lower:
                solution = "Check for unclosed brackets/parentheses on the line BEFORE the error"
                if_stuck = "Count opening and closing brackets - they must match"
            elif "indent" in msg_lower:
                solution = "Fix indentation to use exactly 4 spaces per level"
                if actual_line:
                    before_code = actual_line
                    # Calculate proper indent
                    stripped = actual_line.lstrip()
                    current_indent = len(actual_line) - len(stripped)
                    proper_indent = ((current_indent + 3) // 4) * 4  # Round to nearest 4
                    after_code = " " * proper_indent + stripped
                else:
                    before_code = "   code  # wrong indent"
                    after_code = "    code  # 4 spaces"
            elif "colon" in msg_lower or "expected ':'" in msg_lower:
                solution = "Add missing colon at end of statement"
                if actual_line:
                    before_code = actual_line
                    # Add colon if missing
                    if not actual_line.rstrip().endswith(':'):
                        after_code = actual_line.rstrip() + ":"
                    else:
                        after_code = actual_line  # Already has colon, issue might be elsewhere
                else:
                    before_code = "def foo()"
                    after_code = "def foo():"
            else:
                # Generic syntax error - show actual line if available
                solution = "Fix the syntax error - check for missing colons, parentheses, or quotes"
                if actual_line:
                    before_code = actual_line
                    after_code = f"# FIX: {actual_line}  # Check syntax carefully"
                    if_stuck = f"Look at line {line_number}: check for missing colons, unmatched brackets, or typos"
        
        # Import-specific patterns
        elif job_type == "fix_import" or "import" in msg_lower or "modulenotfound" in msg_lower:
            if "circular" in msg_lower:
                solution = "Move the import inside the function that needs it (lazy import)"
                before_code = "from other import func\ndef my_func(): func()"
                after_code = "def my_func():\n    from other import func\n    func()"
            elif "no module named" in msg_lower:
                solution = "Check if module exists and use relative import: from . import module"
        
        # Security-specific patterns
        elif job_type == "fix_security" or "security" in msg_lower:
            if "b101" in msg_lower or "assert" in msg_lower:
                solution = "Replace assert with proper if/raise - assert is stripped in optimized mode"
                before_code = "assert condition, 'message'"
                after_code = "if not condition:\n    raise ValueError('message')"
            elif "b311" in msg_lower or "random" in msg_lower:
                solution = "Use secrets module for cryptographic operations"
                before_code = "import random\ntoken = random.randint(0, 999)"
                after_code = "import secrets\ntoken = secrets.randbelow(1000)"
        
        return {
            "role": role,
            "solution": solution,
            "steps": steps,  # Ordered steps for LLM to follow
            "before": before_code,
            "after": after_code,
            "if_stuck": if_stuck,
        }

    def _generate_generic_solution(
        self,
        job_type: str,
        error_message: str
    ) -> Dict[str, Any]:
        """
        Generate a solution from local bundles as fallback.
        
        Per app_rationale 4X-TRY rule: Agent may need to work without
        web-sourced cheatsheet. Use our curated local bundles which have
        rich domain-specific rules, examples, and troubleshooting tips.
        """
        job_name = job_type.replace("fix_", "").replace("_", " ")
        
        # ENHANCED: Use local bundles if available - they have rich content!
        bundle = self.bundles.get(job_type) or self.bundles.get("general_fix", {})
        
        if bundle.get("rules") or bundle.get("examples"):
            # Build solution from bundle content
            solution_parts = []
            
            # Add primary rules as guidance
            rules = bundle.get("rules", [])
            if rules:
                solution_parts.append("Follow these rules:")
                for i, rule in enumerate(rules[:3], 1):  # Top 3 rules
                    solution_parts.append(f"  {i}. {rule}")
            
            # Add first troubleshooting tip if it matches error
            troubleshooting = bundle.get("troubleshooting", [])
            for tip in troubleshooting:
                # Check if any word from error message appears in tip
                error_words = set(error_message.lower().split())
                tip_words = set(tip.lower().split())
                if error_words & tip_words:
                    solution_parts.append(f"\nRelevant tip: {tip}")
                    break
            
            solution_text = "\n".join(solution_parts) if solution_parts else \
                f"Analyze the {job_name} error and apply the minimal fix needed."
            
            # Build before/after from examples
            examples = bundle.get("examples", [])
            before_code = "# Code with issue"
            after_code = "# Fixed code"
            if examples:
                # Parse first example if it has "Bad:" ... "Good:" format
                first_ex = examples[0]
                if "Bad:" in first_ex and "Good:" in first_ex:
                    parts = first_ex.split("->")
                    if len(parts) == 2:
                        before_code = parts[0].replace("Bad:", "").strip().strip("`")
                        after_code = parts[1].replace("Good:", "").strip().strip("`")
            
            return {
                "role": bundle.get("role", f"{job_name.title()} Specialist"),
                "solution": solution_text,
                "before": before_code,
                "after": after_code,
                "if_stuck": troubleshooting[0] if troubleshooting else \
                    "Read the error message carefully and check similar patterns in the codebase",
            }
        
        # True fallback for unknown job types
        return {
            "role": f"{job_name.title()} Specialist",
            "solution": f"Analyze the {job_name} error and apply the minimal fix needed. "
                       f"Make the smallest change that resolves the issue.",
            "before": "# Code with issue",
            "after": "# Fixed code",
            "if_stuck": "Read the error message carefully and check similar patterns in the codebase",
        }
    
    def attach_docs_bundle_to_job(self, job: Any, cheat_sheet: CheatSheet) -> Any:
        """
        Attach CheatSheet to an AtomicJob.

        Stop 5.3: Output - AtomicJob with populated docs_bundle

        THE ANSWER KEY is attached as a formatted string ready for
        injection into the agent's prompt.

        Args:
            job: AtomicJob instance
            cheat_sheet: Generated CheatSheet (THE answer)

        Returns:
            Job with attached docs_bundle
        """
        logger.debug("attach_docs_bundle_to_job called",
                    job_id=cheat_sheet.job_id, source=cheat_sheet.source)
        prompt_string = cheat_sheet.to_prompt_string()
        
        if hasattr(job, 'docs_bundle'):
            job.docs_bundle = prompt_string
        elif hasattr(job, '__dict__'):
            job.__dict__['docs_bundle'] = prompt_string
        else:
            logger.warning("Cannot attach docs_bundle to job type",
                          job_type=type(job).__name__)
        
        # Also attach the raw cheat sheet for potential later use
        if hasattr(job, '__dict__'):
            job.__dict__['_cheat_sheet'] = cheat_sheet
        
        logger.debug("Attached docs_bundle to job",
                    job_id=cheat_sheet.job_id, source=cheat_sheet.source)
        return job
    
    async def inject_knowledge_async(
        self,
        jobs: List[Any],
        job_contexts: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> List[Any]:
        """
        Inject THE ANSWER KEY into each job.
        
        Per app_rationale: "make the tasks super small but also super easy - 
        these plus the answer(cheat-sheet), I hope, creates an environment 
        where there's 'no reason to fake anything'"
        
        Each job gets EXACTLY ONE solution - not a menu of options.
        
        Args:
            jobs: List of AtomicJob instances
            job_contexts: Optional dict mapping job_id to context
            
        Returns:
            Jobs with attached docs_bundles (THE ANSWERS)
        """
        logger.debug("inject_knowledge_async called",
                    n_jobs=len(jobs),
                    has_contexts=bool(job_contexts))
        job_contexts = job_contexts or {}

        async def inject_single(job: Any) -> Any:
            job_id = getattr(job, 'id', str(id(job)))
            job_type = getattr(job, 'job_type', 'general_fix')
            
            # Build context from job attributes
            context = job_contexts.get(job_id, {})
            if not context:
                context = {
                    "file_path": getattr(job, 'file_path', ''),
                    "line": getattr(job, 'line_number', 0),
                    "message": getattr(job, 'description', ''),
                    "details": getattr(job, 'details', ''),
                }
            
            # Generate THE ANSWER for this job
            cheat_sheet = await self.generate_cheat_sheet_async(job_id, job_type, context)
            
            # Attach to job
            return self.attach_docs_bundle_to_job(job, cheat_sheet)
        
        # Process in parallel for efficiency
        tasks = [inject_single(job) for job in jobs]
        results = await asyncio.gather(*tasks)
        
        # Log summary
        sources = {"local": 0, "generated": 0}
        for job in results:
            if hasattr(job, '_cheat_sheet'):
                sources[job._cheat_sheet.source] = sources.get(job._cheat_sheet.source, 0) + 1

        logger.info("Injected CheatSheets",
                   n_total=len(results), n_local=sources['local'],
                   n_generated=sources['generated'])

        return list(results)


# =============================================================================
# VerdictRanker — THE single decision point for pass/fail (owner ruling
# 2026-09-05 21:55: "the ranker is the only ranker"; spec RULES_HARDENING §S.2-S.3).
#
# Cut 1 (2026-09-06): behaviour-identical. Every place the validator used to
# write `passed=` now asks this class. The POLICY below reproduces the
# pre-cut-1 rules exactly so the proof is "same counts on the same input":
#   strict proof matched        -> FAIL (layer HARD_REQUIREMENTS)
#   hard-requirement deficit    -> FAIL (layer HARD_REQUIREMENTS)
#   any detector observation    -> FAIL (layer AI_FAKE_DETECTOR), first observation decides
#   module rule with sev HIGH   -> FAIL (layer AI_FAKE_DETECTOR)
#   class rule (NAI-213)        -> FAIL (layer AI_FAKE_DETECTOR)
#   otherwise                   -> PASS
# Cut 2 changes ONLY this table (magnitudes = context, never a verdict alone;
# owner 2026-09-06 "context is fine"). Nothing upstream decides anything.
# =============================================================================

# ── Dispositions are DATA (owner decision 3, 2026-09-06) ─────────────────────────────────────────
# system_scripts/rule_dispositions.json holds one row per rule family: disposition ∈ {deciding, context},
# with the evidence that earned it. The ranker READS the table; it never infers a disposition. An id with
# no row is deciding (nothing inferred) and is recorded so health-check step 18 (disposition_check.py) can
# fail on it. An absent table is a broken install: launch.sh runs the gate first, so the RuntimeError
# below can only mean the table was deleted after the gate passed.
import json as _json
from pathlib import Path as _Path
RULE_DISPOSITIONS = _Path(__file__).resolve().parents[3] / "system_scripts" / "rule_dispositions.json"
_DISPOSITIONS: Optional[Dict[str, str]] = None   # loaded ONCE per process
_UNKNOWN_SEEN: set = set()                        # ids decided with no table row (reported, never inferred)

# FIX_17 (2026-09-10, owner ruling): a disposition is per (rule, CONTEXT). A family row keeps ONE default
# disposition and may carry `contexts` — an ordered list of {"when": {fact: condition, …}, "disposition"} rows.
# A fact is a MEASURED value the route already carries, never prose: the observation's own `magnitude` (the
# count / group size the rule computed) and the file's `species`. A condition is {op: value} with op below, or
# a bare value (equality). The FIRST context row whose every condition holds wins; none → the default. The
# table is the Ranker's (step 17 keeps thresholds out of rules): the number is data, never a code literal.
import operator as _operator


# I-114 / Q2 (MCP-working packet 2026-09-28): the 17 `_nai_fix_*` branches FIX_54 declared here
# for the type checker only are REMOVED from _find_specific_solution. Proof they were dead: its only
# caller is generate_cheat_sheet_async, whose only caller is inject_knowledge_async, which nothing
# calls — and `KnowledgeBase(` is constructed nowhere since Item 1. The repair-generator registry
# (Item 4) is the route; no branch was reachable, so none became a named refusal.
CONTEXT_FACTS: Final[tuple] = ("magnitude", "species", "body_statements", "variant", "role")   # body_statements: owner 2026-10-07; role: M-146 (a project fact about the function, e.g. inherited_hook)
_CONTEXT_OPS: Dict[str, Any] = {
    ">=": _operator.ge, ">": _operator.gt, "<=": _operator.le, "<": _operator.lt,
    "==": _operator.eq, "!=": _operator.ne,
    "in": lambda a, b: a in b, "not_in": lambda a, b: a not in b,
}
_CONTEXTS: Dict[str, List[tuple]] = {}           # rid → [(when, disposition), …] in table order


def _load_dispositions() -> Dict[str, str]:
    global _DISPOSITIONS
    if _DISPOSITIONS is not None:
        return _DISPOSITIONS
    if not RULE_DISPOSITIONS.exists():
        raise RuntimeError(f"rule_dispositions.json is missing at {RULE_DISPOSITIONS} — a broken install; "
                           f"run system_scripts/disposition_check.py --seed, then the health check (step 18)")
    data = _json.load(open(RULE_DISPOSITIONS, encoding="utf-8"))
    table: Dict[str, str] = {}
    for rid, row in (data.get("families") or {}).items():
        d = row.get("disposition")
        if d not in ("deciding", "context"):
            raise RuntimeError(f"rule_dispositions.json: {rid} has disposition {d!r}; only deciding|context are dispositions")
        if row.get("class") == "strict" and d == "context":
            raise RuntimeError(f"rule_dispositions.json: strict family {rid} cannot be context (a proof is never context)")
        table[rid] = d
        # FIX_17: the family's context rows, validated on load (the table is data; a bad row is a broken table)
        ctxs = row.get("contexts") or []
        if ctxs and row.get("class") == "strict":
            raise RuntimeError(f"rule_dispositions.json: strict family {rid} cannot carry contexts (a proof is never context)")
        parsed: List[tuple] = []
        for c in ctxs:
            cd = (c or {}).get("disposition")
            when = (c or {}).get("when") or {}
            if cd not in ("deciding", "context"):
                raise RuntimeError(f"rule_dispositions.json: {rid} context row has disposition {cd!r}")
            unknown = sorted(k for k in when if k not in CONTEXT_FACTS)
            if not when or unknown:
                raise RuntimeError(f"rule_dispositions.json: {rid} context row uses unknown facts {unknown} (facts: {CONTEXT_FACTS})")
            for k, cond in when.items():
                if isinstance(cond, dict) and any(op not in _CONTEXT_OPS for op in cond):
                    raise RuntimeError(f"rule_dispositions.json: {rid} context row on {k!r} uses an unknown op (ops: {sorted(_CONTEXT_OPS)})")
            parsed.append((dict(when), cd))
        if parsed:
            _CONTEXTS[rid] = parsed
    _DISPOSITIONS = table
    return table


def _condition_holds(fact: Any, cond: Any) -> bool:
    """FIX_17: one table condition against one measured fact. A missing fact never holds."""
    if fact is None:
        return False
    try:
        if isinstance(cond, dict):
            return all(_CONTEXT_OPS[op](fact, value) for op, value in cond.items())
        return fact == cond
    except TypeError:
        return False


def resolve_disposition(rid: str, facts: Optional[Dict[str, Any]] = None) -> str:
    """FIX_17: the disposition of `rid` under `facts` — the first context row whose conditions all hold,
    else the family's default. `rid` must be a table row."""
    default = _load_dispositions()[rid]
    rows = _CONTEXTS.get(rid)
    if not rows or not facts:
        return default
    for when, disp in rows:
        if all(_condition_holds(facts.get(k), cond) for k, cond in when.items()):
            return disp
    return default


def unknown_seen() -> List[str]:
    """Ids the ranker decided with NO table row this process (each was treated as deciding)."""
    return sorted(_UNKNOWN_SEEN)


@dataclass
class Verdict:
    """The ranker's decision for one unit (function / module / class)."""
    passed: bool
    layer: Optional[str] = None          # "HARD_REQUIREMENTS" | "AI_FAKE_DETECTOR" | None
    reason: Optional[str] = None         # human-readable deciding reason (presentation)
    deciding: Any = None                 # the proof / deficit / observation that decided
    source: str = "ranker"
    policy: str = ""
    withheld: Optional[str] = None       # "species:test" — a PASS the ranker WITHHELD a verdict on (owner decision 1, 2026-09-06)


class VerdictRanker:
    """Single decision point. Stages mirror the validator's evidence order so
    cut 1 is behaviour-identical; the stage is recorded on the verdict."""

    POLICY: Final[str] = "cut2:magnitude-is-context"

    # Cut 2 (2026-09-05, owner "context is fine"): observations whose whole content is a
    # MAGNITUDE (a count, ratio, depth, length, complexity) are CONTEXT — published, never a
    # verdict on their own. A verdict comes only from a strict proof, a hard-requirement deficit,
    # or a structural observation (a shape that is present or absent). Regex signature hits
    # (SIG-*) are context too: a regex is not a proof. Source: EXCISION_LIST_2026-09-05.md.
    #
    # 2026-09-06 (calibrator, owner decision 3): this frozenset is the MIGRATION SEED only — the live
    # dispositions are rows in system_scripts/rule_dispositions.json (disposition_check.py --seed wrote
    # them from this set; the ranker reads the table, never this constant). NAI-019S dropped (never
    # emitted since cut 2). The A1 renumber split six shared ids; the new ids inherit the context the
    # shared id had, so the split changes no verdict: NAI-220 (was validator NAI-106), NAI-221 (NAI-111),
    # NAI-222 (NAI-112), NAI-223 (NAI-113), NAI-224 (NAI-114), NAI-228 (utils NAI-090).
    _SEED_CONTEXT_2026_09_06: Final[frozenset] = frozenset({
        "NAI-080", "NAI-081", "NAI-082", "NAI-083", "NAI-084", "NAI-086", "NAI-090", "NAI-097",
        "NAI-106", "NAI-107", "NAI-111", "NAI-112", "NAI-113", "NAI-114", "NAI-117", "NAI-119",
        "NAI-121", "NAI-123", "NAI-129", "NAI-149", "NAI-150", "NAI-151", "NAI-153", "NAI-154",
        "NAI-155", "NAI-156", "NAI-168", "NAI-169", "NAI-178", "NAI-181", "NAI-182", "NAI-183",
        "NAI-184", "NAI-185", "NAI-186",
        "NAI-099",  # cut 3 round 1 (2026-09-06): a comparison against an unnamed literal is a smell, not counterfeit — context; the value is published
        "HR-NAME",  # cut 2b (2026-09-06, §S.7 item 4): a name/body disagreement is an observation for the ranker, never a verdict
        "NAI-220", "NAI-221", "NAI-222", "NAI-223", "NAI-224", "NAI-228",  # A1 split: inherited context (see above)
    })
    CONTEXT_RULES = _SEED_CONTEXT_2026_09_06   # name kept for readers of old code; NOT consulted by the ranker

    @classmethod
    def disposition(cls, tag: Any, facts: Optional[Dict[str, Any]] = None) -> str:
        """'deciding' | 'context' for a rule id, from rule_dispositions.json. SIG-* is the one wildcard row.
        An id with no row is DECIDING (nothing inferred) and is recorded for step 18 (unknown_seen()).
        FIX_17 (2026-09-10): with `facts` (the observation's measured context — magnitude, species) the
        family's context rows are consulted first; without facts, the default."""
        t = str(tag or "")
        base = t.split()[0] if t else ""
        if not base:
            return "deciding"
        table = _load_dispositions()
        if base in table:
            return resolve_disposition(base, facts)
        if base.startswith("SIG-") and "SIG-*" in table:
            return table["SIG-*"]
        _UNKNOWN_SEEN.add(base)
        return "deciding"

    @classmethod
    def is_context(cls, tag: Any, facts: Optional[Dict[str, Any]] = None) -> bool:
        return cls.disposition(tag, facts) == "context"

    @classmethod
    def is_context_obs(cls, obs: Any, species: str = "") -> bool:
        """An observation is context if its rule is a context rule OR it carries context=True —
        cut 3 batch 4 (2026-09-06): a rule that measured NOTHING records that as context rather than going silent.
        FIX_17 (2026-09-10): the observation's own measured facts (`magnitude`) and the file's `species` reach
        the table, so a family that is context by default can DECIDE in the context its row names."""
        if isinstance(obs, dict):
            if obs.get("context") is True:
                return True
            facts: Dict[str, Any] = {"species": species}
            for k in CONTEXT_FACTS:
                if k in obs:
                    facts[k] = obs[k]
            return cls.is_context(obs.get("tag"), facts)
        return cls.is_context(obs, {"species": species})

    def __init__(self) -> None:
        self.decisions: Dict[str, int] = {"pass": 0, "fail": 0, "withheld": 0}

    @staticmethod
    def withholds(species: str) -> bool:
        """Item 3 (2026-09-10): the species on which the ranker WITHHOLDS its verdict — a library's tests (owner
        decision 1, 2026-09-06) and every proxy for not running the source (`proxy:<kind>`, the artifact scanner's
        classification by content): drawn and judged as a proxy, never as the app. The evidence is still published."""
        # owner 2026-10-07 ~13:45: test code is JUDGED like any other file ("tests are one of the biggest harbingers
        # of counterfeit code"); the 09-06 test withhold is lifted. Noisy app rules on test idioms are context rows in
        # rule_dispositions.json (species == "test"), read like every other disposition. proxy:* is unchanged.
        return str(species or "").startswith("proxy:")

    def _withheld(self, why: str) -> Verdict:
        """A PASS the ranker withholds a verdict on — published as such, never as a clean pass."""
        self.decisions["withheld"] += 1
        return Verdict(passed=True, policy=self.POLICY, withheld=why)

    def _fail(self, layer: str, reason: Optional[str], deciding: Any) -> Verdict:
        self.decisions["fail"] += 1
        return Verdict(passed=False, layer=layer, reason=reason, deciding=deciding, policy=self.POLICY)

    def _pass(self) -> Verdict:
        self.decisions["pass"] += 1
        return Verdict(passed=True, policy=self.POLICY)

    def decide(self, stage: str, evidence: Any, species: str = "") -> Verdict:
        """stage ∈ {"strict", "observations", "module", "class", "lambda", "rule"}.

        strict:           {"rule_id", "description", "proof": True}   (a matched proof)
        observations:     list[dict]  (HR deficit observations {tag HR-00N, type, deficit, votes} first —
                          FIX_18, 2026-09-10 — then the detector's observations; may be empty). The
                          `hard_requirement` stage (a first-hit deficit string) is RETIRED: HR deficits
                          are observations decided by disposition like every other id; the deciding HR
                          observation keeps the HARD_REQUIREMENTS layer.
        module:           list[tuple[rule_id, severity, msg]]
        class:            tuple[rule_id, severity, msg]

        species: the file's species fact (owner decision 1 + 5, 2026-09-06). A library's tests are CONTEXT:
        for species == "test" the ranker WITHHOLDS its verdict before any stage (the strict layer included) —
        the evidence is still published by the caller as context, never dropped.
        """
        if self.withholds(species):
            return self._withheld(f"species:{species}")
        if stage == "strict":
            e = evidence or {}
            return self._fail("HARD_REQUIREMENTS", f"{e.get('rule_id', '?')}: {e.get('description', '')}", e)
        if stage == "observations":
            obs = list(evidence or [])
            deciding = [o for o in obs if not self.is_context_obs(o, species=species)]   # FIX_17: facts reach the table
            if deciding:
                d = deciding[0]
                _tag = str((d.get("tag") if isinstance(d, dict) else d) or "")
                layer = "HARD_REQUIREMENTS" if _tag.startswith("HR-0") else "AI_FAKE_DETECTOR"   # FIX_18
                return self._fail(layer, None, d)   # reason formatted by the caller
            return self._pass()   # context only (or nothing) -> PASS, context published by the caller
        if stage == "module":
            triggered = list(evidence or [])
            # cut 2: decided by RULE ID, never by the severity string (D4 retired)
            deciding = [(rid, sev, msg) for rid, sev, msg in triggered if not self.is_context(rid)]
            if deciding:
                rid, _sev, msg = deciding[0]
                return self._fail("AI_FAKE_DETECTOR", f"{rid}: {msg}", deciding[0])
            return self._pass()
        if stage == "class":
            rid, _sev, msg = evidence
            if self.is_context(rid):
                return self._pass()
            return self._fail("AI_FAKE_DETECTOR", f"{rid}: {msg}", evidence)
        if stage == "lambda":
            return self._pass()   # lambda observations are context by construction (they always were)
        if stage == "rule":
            # cut 2c (2026-09-06): a file-level rule hit routed from file_validation — (rule_id, severity, msg, layer);
            # decided by RULE ID (context ids pass), never by a `passed=False` assignment at the site.
            rid, _sev, msg, layer = evidence
            if self.is_context(rid):
                return self._pass()
            reason = str(msg) if str(msg).startswith(str(rid)) else f"{rid}: {msg}"
            return self._fail(layer, reason, evidence)
        raise ValueError(f"VerdictRanker.decide: unknown stage {stage!r}")

    @classmethod
    def facts_by_id(cls, patterns: Any) -> Dict[str, Dict[str, Any]]:
        """FIX_17 (2026-09-10): the measured context facts each observation carries, keyed by its rule id —
        for `split_ids`, so publication reads the same table rows the verdict did."""
        out: Dict[str, Dict[str, Any]] = {}
        for p in patterns or []:
            if not isinstance(p, dict):
                continue
            tag = str(p.get("tag", "") or "").split()[0] if p.get("tag") else ""
            facts = {k: p[k] for k in CONTEXT_FACTS if k in p}
            if tag and facts:
                out[tag] = {**out.get(tag, {}), **facts}
        return out

    def split_ids(self, ids: List[str], species: str = "",
                  facts_by_id: Optional[Dict[str, Dict[str, Any]]] = None) -> tuple[List[str], List[str]]:
        """(deciding_ids, context_ids) — for publication: rule_ids must never list context as a verdict.
        For test species every id is context (the verdict was withheld).
        FIX_17 (2026-09-10): `facts_by_id` (the observations' measured facts, see `facts_by_id`) lets an id that is
        context by default publish as deciding in the context its table row names — the split the verdict used."""
        if self.withholds(species):
            return [], list(ids)
        def _ctx(i: str) -> bool:
            return self.is_context(i, {"species": species, **((facts_by_id or {}).get(i) or {})})
        deciding = [i for i in ids if not _ctx(i)]
        context = [i for i in ids if _ctx(i)]
        return deciding, context
