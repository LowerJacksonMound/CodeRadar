"""
NoAIMathValidator - Main validator class of the NOAI validator.

Two-layer validation system for detecting AI-generated counterfeit code:
- Layer 1: Hard Requirements (pure boolean structural invariants)
- Layer 2: AI Fake Detector (97+ pattern rules)

Sync-primary for computation; async for I/O operations.
"""

import ast
import asyncio
import hashlib
import logging
import re
from collections import defaultdict, OrderedDict
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple, TypeVar, Union

from .core import (
    FunctionType,
    FunctionMetrics,
    ValidationResult,
    ValidationLayer,
    HardRequirements,
)
from .config import DEFAULT_CONFIG
from .canonicals import DEFAULT_CANONICALS
from .extractor import MetricsExtractor
from .identifier import FunctionIdentifier, VariableTracker
from ..detection.base import AIFakeDetector
# FIX_34 (2026-09-10): `.indexer.ProjectIndexer` archived (0 callers; never instantiated here) — `_project_index` stays a None-able seam
from .models import (
    FunctionInfo,
    ComprehensionInfo,
    ParseError,
    StringValidationResult,
    LambdaMetrics,
)
from signature_engine.builtins_registry import PYTHON_BUILTINS
from signature_engine.stdlib import STDLIB_MODULES
from signature_engine.packages import COMMON_PACKAGES
from signature_engine.signatures import AuthorshipSignatureDatabase
from .strict_checks import STRICT_CHECKS, strict_finding_observations
from ..cheatsheets.cheatsheet_intelligence.knowledge_base import VerdictRanker, Verdict

# Cut 1 (2026-09-06): THE single decision point. Nothing in this module writes
# `passed=` from its own judgement — every verdict is asked of the ranker
# (owner ruling 2026-09-05 21:55; spec RULES_HARDENING §S.2-S.3).
VERDICT_RANKER = VerdictRanker()


def _layer_of(verdict: "Verdict") -> Optional["ValidationLayer"]:
    if verdict.passed or not verdict.layer:
        return None
    return ValidationLayer[verdict.layer]
from .utils import module_scope_nodes, base_name, is_sys_path, is_os_environ, read_source

_F = TypeVar('_F', bound=Callable[..., Any])
T = TypeVar('T')

# Flow tracing integration
try:
    from flow_tracer import trace as _flow_trace, emit_trace, set_workflow
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False
    def _flow_trace(func: _F) -> _F: return func
    def emit_trace(*args: Any, **kwargs: Any) -> None: pass
    def set_workflow(*args: Any, **kwargs: Any) -> None: pass

def trace(func: _F) -> _F:
    return _flow_trace(func)  # type: ignore[no-any-return]

# Configure module logger
logger = logging.getLogger(__name__)

__all__ = ["NoAIMathValidator", "MAX_CACHE_SIZE"]

# FIX_26 (2026-09-15): the module-import magnitude constant is gone with its dead config key (the count
# is published as NAI-215, the ranker decides).
MAX_CACHE_SIZE = 1000  # LRU cache size for file validation results


def _mutable_default_observations(node: ast.FunctionDef) -> list:
    """NAI-071 observations for a function's mutable default arguments (list /
    dict / set literals or their constructor calls) — shared by the strict
    branch (F-LBL1) so the finding is never hidden behind a strict label."""
    obs = []
    args = node.args
    for default in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
        kind = None
        if isinstance(default, (ast.List, ast.Dict, ast.Set)):
            kind = type(default).__name__.lower()
        elif isinstance(default, ast.Call) and isinstance(default.func, ast.Name) \
                and default.func.id in ('list', 'dict', 'set'):
            kind = default.func.id
        if kind:
            obs.append({"tag": "NAI-071", "line": getattr(default, 'lineno', node.lineno),
                        "func_name": node.name, "default_type": kind})
    return obs


class NoAIMathValidator:
    """
    Main validator class for detecting AI-generated counterfeit code.

    Uses a two-layer validation approach:
    1. Hard Requirements: Structural invariants that must be satisfied
    2. AI Fake Detector: 97+ pattern rules for detecting AI fakes

    Supports both file-based and in-memory (string) validation.
    Sync-primary for computation; async wrappers for I/O paths.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Merge provided config with defaults
        self.config = {**DEFAULT_CONFIG, **(config or {})}

        # Caches with LRU eviction
        self._file_cache: OrderedDict[str, Tuple[str, List[ValidationResult]]] = OrderedDict()
        self._cache_max_size = self.config.get('cache_max_size', MAX_CACHE_SIZE)
        self._import_graph: Dict[str, Set[str]] = defaultdict(set)

        # Cross-file state
        self.parse_errors: List[ParseError] = []
        self.module_symbols: Set[str] = set()
        self.module_imports: Set[str] = set()
        self.defined_functions: Set[str] = set()
        self.symbol_references: Set[str] = set()

        # Builtin registries
        self.builtins = PYTHON_BUILTINS
        self.stdlib = STDLIB_MODULES
        self.packages = COMMON_PACKAGES

        # Signature signature database for source-level pattern scanning
        self._signature_db = AuthorshipSignatureDatabase()

        # Project indexer for cross-file resolution
        self._project_index: Optional[Any] = None   # FIX_34: the indexer is archived; a cross-file index plugs in here when one is wired
        self._module_map: Dict[str, Path] = {}
        self._export_cache: Dict[Tuple[str, int], Set[str]] = {}  # NAI-217 (was NAI-210) resolver cache (plan item 4)
        self._current_file: Optional[Path] = None

        # Policy hooks for extensibility
        self._policy_hooks: List[Callable[[ValidationResult, str], List[str]]] = []

        logger.info("NoAIMathValidator initialized with config: %s",
                    {k: v for k, v in self.config.items() if k != 'secret'})

    def _cache_set(self, key: str, value: Tuple[str, List[ValidationResult]]) -> None:
        """Set cache entry with LRU eviction."""
        if key in self._file_cache:
            self._file_cache.move_to_end(key)
        self._file_cache[key] = value
        # Evict oldest entries if over limit
        while len(self._file_cache) > self._cache_max_size:
            self._file_cache.popitem(last=False)

    def _cache_get(self, key: str) -> Optional[Tuple[str, List[ValidationResult]]]:
        """Get cache entry, updating LRU order."""
        if key in self._file_cache:
            self._file_cache.move_to_end(key)
            return self._file_cache[key]
        return None

    # =========================================================================
    # PUBLIC API - FILE VALIDATION (I/O — async primary, sync wrappers)
    # =========================================================================

    def validate_file(self, filepath: Path) -> List[ValidationResult]:
        """Validate all functions in a Python file (sync wrapper for async I/O)."""
        return self._run_sync(self.validate_file_async(filepath))

    async def validate_file_async(self, filepath: Path) -> List[ValidationResult]:
        """Validate all functions in a file (async)."""
        from .file_validation import validate_file_async
        result = await validate_file_async(self, filepath)
        return result

    def validate_string(self, source: str, file_path: str = "<string>") -> StringValidationResult:
        """
        Validate code from a string (in-memory, no disk I/O).

        Crucial for FixerChain retry loops - runs validation in milliseconds.
        """
        return self._run_sync(self.validate_string_async(source, file_path))

    async def validate_string_async(self, source: str, file_path: str = "<string>") -> StringValidationResult:
        """Validate code from a string (async)."""
        from .file_validation import validate_string_async
        return await validate_string_async(self, source, file_path)

    def validate_directory(
        self,
        dirpath: Path,
        max_files: Optional[int] = None
    ) -> Tuple[List[ValidationResult], Dict[str, Any]]:
        """Validate all Python files in a directory (sync wrapper for async I/O)."""
        return self._run_sync(self.validate_directory_async(dirpath, max_files))

    async def validate_directory_async(
        self,
        dirpath: Path,
        max_files: Optional[int] = None
    ) -> Tuple[List[ValidationResult], Dict[str, Any]]:
        """Validate directory (async)."""
        from .file_validation import validate_directory_async
        result = await validate_directory_async(self, dirpath, max_files)
        return result

    # =========================================================================
    # CORE VALIDATION LOGIC (sync primary)
    # =========================================================================

    @trace
    def validate_function(
        self,
        node: ast.FunctionDef,
        class_context: bool = False,
        decorators: Optional[List[str]] = None,
        source_segment: Optional[str] = None,
        imported_names: Optional[Dict[str, str]] = None,
        module_level_names: Optional[Set[str]] = None,
        class_bases: Optional[List[str]] = None,
        species: str = "",
        noreturn_names: Optional[Set[str]] = None,
        enclosing_names: Optional[Set[str]] = None,
        module_attr_names: Optional[Set[str]] = None,
        route_observations: Optional[List[Dict[str, Any]]] = None,
    ) -> ValidationResult:
        """
        Validate a single function AST node.

        route_observations (FIX_17, 2026-09-10): observations the file-level route measured for THIS function
        (NAI-229 repetition, NAI-230 normalized-duplicate group — each carrying its `magnitude`). They join the
        observations stage after the detector's; the Ranker decides them by the per-(rule, context) table.

        species: the file's species fact ("test" by content — owner decisions 1+5, 2026-09-06). For a test file the
        ranker WITHHOLDS its verdict at every layer; the strict / hard-requirement evidence is published as context.

        Two-layer validation:
        1. Hard Requirements check (structural invariants)
        2. AI Fake Detector (pattern matching)

        Args:
            imported_names: Mapping of imported names to their source modules.
                           If None, falls back to identity map of self.module_imports.
            module_level_names: Set of names defined at module level (sibling functions, classes).
        """
        logger.debug("Validating function: %s", node.name)

        # =====================================================================
        # STRICT CHECKS — pure yes/no AST predicates, no scores
        # Any match = immediate FAIL, no further analysis needed
        # =====================================================================
        _withheld_obs: list = []   # strict / HR evidence the ranker withheld a verdict on (species) — published, never dropped
        for rule_id, predicate, description in STRICT_CHECKS:
            if predicate(node):
                # Cut 1 (2026-09-06): a matched proof is EVIDENCE; the ranker decides.
                verdict = VERDICT_RANKER.decide("strict", {"rule_id": rule_id, "description": description, "proof": True}, species=species)
                if verdict.withheld:
                    _withheld_obs.append({"tag": rule_id, "line": node.lineno, "context": True, "withheld": verdict.withheld,
                                          "proof": True, "description": description})
                if not verdict.passed:
                    logger.info("Function %s FAILED strict check %s: %s", node.name, rule_id, description)
                    # F-LBL1 (2026-09-05): a strict verdict must not HIDE a infraction
                    # that has a vetted rewriter — a mutable default (NAI-071) is
                    # recorded beside the strict id so the repair stage dispatches.
                    return ValidationResult(
                        function_name=node.name,
                        function_type=FunctionType.UNKNOWN,
                        passed=False,
                        failure_layer=_layer_of(verdict),
                        failure_reason=verdict.reason,
                        # T-09 (R7, 2026-09-30): + the lines the strict check fired on (NAI-021S's
                        # returns / alias links) — it published finding_lines: [] before.
                        triggered_patterns=(strict_finding_observations(rule_id, node)
                                            + _mutable_default_observations(node)),
                        verdict_source=verdict.source,
                        species=species,
                    )

        # Extract metrics
        extractor = MetricsExtractor(node, class_context=class_context, source=source_segment)
        metrics = extractor.extract()

        # Identify function type
        var_tracker = VariableTracker(node)
        identifier = FunctionIdentifier(metrics, node, var_tracker)
        func_type, roles = identifier.identify()   # cut 2b (2026-09-06, §S.7): structure first; the name is a weak prior

        # Layer 1: Hard Requirements — cut 2b (§S.7 items 3, 5, 6): a canonical is checked ONLY for a role the code
        # itself DECLARES (a decorator), never for one a name suggested; an empty feasible set is UNTYPED, never a
        # failure. The `test*` special case went with the name votes — nothing needs it now.
        # F-HR1: does the body READ its receiver? (self/cls are stripped from params_declared by the extractor.)
        self._receiver_reads = set()
        if class_context and node.args.args and node.args.args[0].arg in ('self', 'cls'):
            recv = node.args.args[0].arg
            if any(isinstance(n, ast.Name) and n.id == recv and isinstance(n.ctx, ast.Load)
                   for n in ast.walk(ast.Module(body=node.body, type_ignores=[]))):
                self._receiver_reads = {recv}
        # FIX_18 (2026-09-10): every deficit is an OBSERVATION {tag, type, deficit, votes}, one per deficit,
        # never a first-hit verdict string. The observations ride the single `observations` stage below and
        # the ranker decides by disposition (HR-001..008 are deciding rows); the deciding HR observation
        # keeps the HARD_REQUIREMENTS layer. The `hard_requirement` stage is retired.
        _votes = {"structural": list(roles.get("structural", [])),
                  "declared": [(r.name, by) for r, by in roles.get("declared", [])],
                  "name": list(roles.get("name", []))}
        _hr_obs: list = []
        for _role, _by in roles.get("declared", []):
            _canon = DEFAULT_CANONICALS.get(_role)
            if _canon is None:
                continue
            for _o in self._check_hard_requirements(metrics, _canon.hard_reqs, _role, _votes):
                _o["line"] = node.lineno
                _o["established_by"] = _by
                _hr_obs.append(_o)

        # Layer 2: AI Fake Detector
        effective_imported_names = imported_names if imported_names is not None else {
            name: name for name in self.module_imports
        }
        effective_module_names = module_level_names if module_level_names is not None else self.module_symbols
        detector = AIFakeDetector(
            metrics=metrics,
            func_node=node,
            project_index=self._project_index,
            imported_names=effective_imported_names,
            current_module=str(self._current_file) if self._current_file else "",
            module_level_names=effective_module_names,
            artifact_values=getattr(self, '_artifact_values', None),
            noreturn_names=noreturn_names,
            enclosing_names=enclosing_names,      # IG-9
            module_attr_names=module_attr_names,  # IG-10
            dunder_counts=self._dunder_counts_for_current_file(),   # FIX_34 (b): the NAI-058 whole-set fact, once per directory
        )
        detector.class_bases = list(class_bases or [])
        observations = self._run_sync(detector.run_all_checks())
        if roles.get("hr_name"):
            observations = [roles["hr_name"]] + observations   # cut 2b: the name/body disagreement is an OBSERVATION (context), never a verdict
        # cut 3 batch 4 (2026-09-06): rules that measured NOTHING record it as context. Collapse those into one
        # summary observation per function so the published state stays bounded while nothing is hidden.
        _nothing = [o for o in observations if isinstance(o, dict) and o.get("context") is True and o.get("measured") == "nothing"]
        if _nothing:
            observations = [o for o in observations if o not in _nothing] + [{
                "tag": "MEASURED-NOTHING", "line": node.lineno, "context": True,
                "rules": sorted({str(o.get("tag")) for o in _nothing}),
            }]

        # Cut 1 (2026-09-06): observations are EVIDENCE. The VerdictRanker is
        # the single decision point (owner 2026-09-05 21:55, spec §S.2-S.3);
        # its cut-1 policy reproduces "any observation fails" exactly. This
        # module formats the deciding observation; it does not decide.
        # FIX_18: the HR deficits come first (a declared role's canonical outranks a pattern), then the
        # withheld strict evidence (context), then the detector's observations.
        # FIX_17: the route's file-level measurements for this function come last (context by default; a
        # magnitude above the table's N decides).
        observations = _hr_obs + _withheld_obs + observations + list(route_observations or [])
        # M-146 (2026-10-08): a project fact about the FUNCTION (e.g. role=inherited_hook from hook_stubs.py) reaches every
        # observation on it, so the dispositions table — not this code — says which rules are context in that role.
        _roles = sorted({str(o["role"]) for o in observations if isinstance(o, dict) and o.get("tag") == "HOOK" and o.get("role")})
        if _roles:
            observations = [({**o, "role": _roles[0]} if isinstance(o, dict) and "role" not in o else o) for o in observations]
        verdict = VERDICT_RANKER.decide("observations", observations, species=species)
        if not verdict.passed:
            first_obs = verdict.deciding
            first_tag = first_obs.get("tag", "?")
            logger.info("Function %s failed %s: %s", node.name, verdict.layer or "AI_FAKE_DETECTOR", first_tag)
            if _TRACING_ENABLED:
                emit_trace("validate_function_complete", function=node.name, passed=False, layer=verdict.layer or "AI_FAKE_DETECTOR")
            return ValidationResult(
                function_name=node.name,
                function_type=func_type,
                passed=False,
                failure_layer=_layer_of(verdict),
                failure_reason=self._format_observation(first_obs),
                warnings=[self._format_observation(obs) for obs in observations],
                metrics=metrics,
                triggered_patterns=observations,
                verdict_source=verdict.source,
                species=species,
            )

        # The ranker passed it — clean pass. Cut 2: CONTEXT observations (magnitudes) are
        # published on a pass too, so the dashboard / VS Code see the measurements without a verdict.
        if _TRACING_ENABLED:
            emit_trace("validate_function_complete", function=node.name, passed=True, warning_count=len(observations))

        return ValidationResult(
            function_name=node.name,
            function_type=func_type,
            passed=True,
            warnings=[self._format_observation(obs) for obs in observations],
            metrics=metrics,
            triggered_patterns=observations,
            verdict_source=verdict.source,
            species=species,
            withheld=verdict.withheld or "",
        )

    async def validate_function_async(
        self,
        node: ast.FunctionDef,
        class_context: bool = False,
        decorators: Optional[List[str]] = None,
        source_segment: Optional[str] = None,
        imported_names: Optional[Dict[str, str]] = None,
    ) -> ValidationResult:
        """Validate a single function (async wrapper)."""
        return self.validate_function(node, class_context, decorators, source_segment, imported_names)

    def validate_module(
        self,
        tree: ast.AST,
        source: str,
        filepath: Optional[Path] = None,
        species: str = "",
    ) -> ValidationResult:
        """Validate module-level patterns."""
        logger.debug("validate_module called: filepath=%s", filepath)
        warnings = []

        # Check for excessive imports
        import_count = sum(1 for _ in ast.walk(tree) if isinstance(_, (ast.Import, ast.ImportFrom)))
        if import_count > 0:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was a magnitude gate on the import count — the count is published, the ranker decides
            warnings.append(f"NAI-215: imports ({import_count})")  # A1 renumber 2026-09-06: was NAI-100 (collided with detection NAI-100 param-not-in-return)

        # Check for global mutable state
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
                        warnings.append(f"NAI-216 (LOW): Global mutable state: {target.id}")  # A1 renumber: was NAI-101 (detection NAI-101 = magic-number return)

        # NAI-094 at module level: sys.path manipulation and os.environ mutation.
        # Plan item 4 (2026-09-05): a module-level path hack is a FINDING here
        # (before: appended to `warnings` only, so the module PASSed and only the
        # circuit's path-hack panel saw it). Predicate = the circuit's
        # (path_hack_detector: insert / append / extend, `sys.path += [...]`,
        # slice assignment); module scope only — function bodies belong to the
        # per-function NAI-094 check.
        # R4 (owner 2026-09-21, run 164): that per-function check now runs the SAME table of
        # shapes — until run 164 it knew only insert / append, so extend / `+=` / `[...] =`
        # were a fire here and clean one indent deeper. `nai094_entry_proof` part 6 holds the
        # two halves to one table and fails on the first verdict that differs.
        triggered: list = []
        # IG-16 (2026-09-06): every module-level infraction below is anchored to a real AST node — a
        # (line, end_line) span recorded here in lockstep with `triggered` (same index) so the
        # published row can carry the span of the node that actually triggered it, instead of
        # always defaulting to line 0 (the numpy f2py/crackfortran.py, ctypeslib/_ctypeslib.py gap).
        _spans: list = []

        def _trigger(rid: str, sev: str, msg: str, node: object = None) -> None:
            triggered.append((rid, sev, msg))
            _spans.append((getattr(node, "lineno", 0) or 0, getattr(node, "end_lineno", 0) or 0))

        _found_syspath = False
        _found_environ = False
        for node in module_scope_nodes(tree):
            if not _found_syspath:
                hit = None
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ('insert', 'append', 'extend')
                        and is_sys_path(node.func.value)):
                    hit = f"sys.path.{node.func.attr}()"
                elif isinstance(node, ast.AugAssign) and is_sys_path(node.target):
                    hit = "sys.path +="
                elif isinstance(node, ast.Assign) and any(
                        isinstance(t, ast.Subscript) and is_sys_path(t.value) for t in node.targets):
                    hit = "sys.path[...] ="
                if hit:
                    _trigger("NAI-094", "HIGH",
                        f"Module-level {hit} at line {node.lineno} — "
                        f"runtime path manipulation creates fragile imports", node)
                    _found_syspath = True
                    continue
            if not _found_environ:
                hit = None
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ('setdefault', 'update')
                        and is_os_environ(node.func.value)):
                    hit = f"os.environ.{node.func.attr}()"
                elif isinstance(node, ast.Assign) and any(
                        isinstance(t, ast.Subscript) and is_os_environ(t.value) for t in node.targets):
                    hit = "os.environ[...] ="
                elif (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Subscript)
                        and is_os_environ(node.target.value)):
                    # R4 (owner 2026-09-21, run 164): `os.environ[k] += v` is the same
                    # `__setitem__` as `os.environ[k] = v`, which fires two lines up — the
                    # sys.path family above has caught its AugAssign since plan item 4. Leaving
                    # it clean was an escape hatch: a "repair" could silence the row by adding
                    # two characters and changing nothing the rule measures.
                    hit = "os.environ[...] +="
                if hit:
                    _trigger("NAI-094", "HIGH",
                        f"Module-level {hit} at line {node.lineno} — "
                        f"modifies process environment at import time", node)
                    _found_environ = True

        # NAI-209/211: try/except ImportError fallback patterns (unchanged)
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, ast.Try):
                continue

            # Extract imported names from the try body
            imported_names: list[str] = []
            import_module: str = ""
            for stmt in list(node.body) + list(node.orelse):   # IG-11: a try's else: branch imports pair with the except fallbacks
                if isinstance(stmt, ast.ImportFrom) and stmt.module:
                    import_module = stmt.module
                    for alias in stmt.names:
                        imported_names.append(alias.asname or alias.name)
                elif isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        imported_names.append(alias.asname or alias.name)

            if not imported_names:
                continue

            for handler in node.handlers:
                if handler.type is None:
                    continue
                exc_name = None
                if isinstance(handler.type, ast.Name):
                    exc_name = handler.type.id
                elif isinstance(handler.type, ast.Tuple):
                    for elt in handler.type.elts:
                        if isinstance(elt, ast.Name) and elt.id in ('ImportError', 'ModuleNotFoundError'):
                            exc_name = elt.id
                            break
                if exc_name not in ('ImportError', 'ModuleNotFoundError'):
                    continue

                # Check handler body for `X = None` pattern
                for stmt in handler.body:
                    if not isinstance(stmt, ast.Assign):
                        continue
                    for tgt in stmt.targets:
                        if not (isinstance(tgt, ast.Name)
                                and isinstance(stmt.value, ast.Constant)
                                and stmt.value.value is None):
                            continue
                        fallback_name = tgt.id

                        # NAI-211: Mismatched fallback — except block assigns to a name
                        # that doesn't match any of the imported names
                        if fallback_name not in imported_names:
                            _trigger("NAI-211", "HIGH",
                                f"Mismatched fallback in except {exc_name}: "
                                f"assigns '{fallback_name} = None' but imported "
                                f"{imported_names} — downstream use will crash", stmt)

                        # NAI-209: Silent import failure (any = None fallback)
                        # IG-16: span is the `fallback_name = None` Assign itself (`stmt`), not the
                        # enclosing Try — that's the node that actually triggered the infraction.
                        _trigger("NAI-209", "MEDIUM",
                            f"Silent import failure — '{fallback_name} = None' "
                            f"swallows {exc_name}, downstream code will crash "
                            f"with AttributeError", stmt)
                        break

        # NAI-217 (A1 renumber 2026-09-06, was NAI-210 — detection NAI-210 = threading in a sync function): Hallucinated import — `from X import Y` where Y is not defined
        # in X. Plan item 4 (2026-09-05): EVERY module-scope `from … import …` is
        # checked (top level, inside try/if too) and X is resolved honouring the
        # relative-import `level`. Before: only imports inside try/except
        # ImportError were checked and `.sibling` never resolved, so a
        # hallucinated name in a relative import PASSed. A module that does not
        # resolve to a local file (stdlib / third-party), or that cannot be
        # measured statically (`import *`, module __getattr__), yields NO infraction.
        if filepath:
            for node in module_scope_nodes(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                resolved = self._resolve_import_file(node.module or "", filepath, node.level)
                if resolved is None:
                    continue
                exported = self._exported_names(resolved)
                if exported is None:
                    continue
                shown = "." * node.level + (node.module or "")
                for alias in node.names:
                    if alias.name != "*" and alias.name not in exported:
                        _trigger("NAI-217", "HIGH",
                            f"Hallucinated import — 'from {shown} import {alias.name}' "
                            f"(line {node.lineno}) but '{alias.name}' is not defined in {resolved.name}", node)

        # Convert to warnings list for backward compat; fail if any HIGH severity
        for rule_id, severity, msg in triggered:
            warnings.append(f"{rule_id} ({severity}): {msg}")

        # Cut 1 (2026-09-06): the (rule, severity, msg) triples are EVIDENCE;
        # the ranker decides (the HIGH gate — D4 in §S.1 — now lives only in
        # its cut-1 policy table, to be retired in cut 2).
        verdict = VERDICT_RANKER.decide("module", triggered, species=species)

        # IG-16 (2026-09-06): the module row's own span — same node VERDICT_RANKER used to decide
        # (its own first non-context entry), so a numpy-style single-infraction module (NAI-209 in
        # f2py/crackfortran.py, ctypeslib/_ctypeslib.py) reports the Assign's real line, not 0.
        _deciding_idx = next((i for i, (rid, _sev, _msg) in enumerate(triggered)
                              if not VERDICT_RANKER.is_context(rid)), None)
        _row_line, _row_end = _spans[_deciding_idx] if _deciding_idx is not None else (0, 0)

        return ValidationResult(
            function_name="<module>",
            function_type=FunctionType.UNKNOWN,
            passed=verdict.passed,
            failure_layer=_layer_of(verdict),
            failure_reason=verdict.reason,
            triggered_patterns=([{"tag": rid, "severity": sev, "msg": msg, "context": True, "withheld": verdict.withheld,
                                   "line": _spans[i][0], "end_line": _spans[i][1]} for i, (rid, sev, msg) in enumerate(triggered)]
                                if verdict.withheld else [[rid, sev, msg] for rid, sev, msg in triggered]) if triggered else [],
            warnings=warnings,
            line=_row_line,
            end_line=_row_end,
            verdict_source=verdict.source,
            species=species,
            withheld=verdict.withheld or "",
        )

    async def validate_module_async(
        self,
        tree: ast.AST,
        source: str,
        filepath: Optional[Path] = None,
    ) -> ValidationResult:
        """Validate module-level patterns (async wrapper)."""
        return self.validate_module(tree, source, filepath)

    def validate_classes(self, tree: ast.AST, filepath: Optional[Path] = None, species: str = "") -> List[ValidationResult]:
        """NAI-213 empty_class (SPECIES_DICT stubs.empty_class; plan item 4, 2026-09-05):
        a class whose body is only `pass` / `...` / a docstring — no attribute, no method.
        Exception subclasses (`class XError(Exception): pass` is the idiom), typing shells
        (Protocol / TypedDict / NamedTuple / Enum bases), classes with a metaclass keyword
        or a decorator declare intent and are not this species. One result per empty
        class, at the class's own line. Before this check a class with no methods was
        never analysed at all (the per-function pipeline only sees functions)."""
        _honest_bases = ('Error', 'Exception', 'Warning', 'Protocol', 'TypedDict', 'NamedTuple', 'Enum')
        results: List[ValidationResult] = []
        # IG-11 (2026-09-06): a base defined in THIS module resolves through its own bases — `class ReadTimeout(Timeout)` where
        # `Timeout(RequestException)` is an exception class; the suffix test alone read it as an empty class.
        _cls_bases = {n.name: [base_name(b) for b in n.bases] for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        def _honest_base(b: str, seen: frozenset = frozenset()) -> bool:
            if b.endswith(_honest_bases) or b == 'BaseException':
                return True
            if b in _cls_bases and b not in seen:
                return any(_honest_base(x, seen | {b}) for x in _cls_bases[b])
            return False
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body = body[1:]
            if not all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                                    and s.value.value is Ellipsis) for s in body):
                continue
            # Body-shape fact (NAI-213, 2026-09-06): a class with ANY explicit base at all — mixin
            # composition (StreamWriter(Codec, codecs.StreamWriter)), an AST/dispatch marker
            # (ContextReference(Expr)), a sentinel type, a platform shim — declares a supertype on
            # purpose; the counterfeit stub is always bare (implicit object). This subsumes the old
            # suffix-only _honest_base test below (kept, now unreachable, as the documented IG-11 fix).
            if node.bases:
                continue
            bases = [base_name(b) for b in node.bases]
            if any(_honest_base(b) for b in bases):
                continue
            if node.keywords or node.decorator_list:
                continue
            # Body-shape fact (NAI-213): a bare (baseless) empty class whose NAME is referenced again
            # anywhere else in the module — used as another class's base (Event <- Preamble(Event)),
            # instantiated (C(), Foo()), or assigned to another name (HTTPSConnection = DummyConnection)
            # — is a deliberate marker/sentinel/fixture, not an abandoned stub. The plant is only ever
            # referenced from a separate entry module (Cache.__name__), never again inside its own file.
            if any(isinstance(n, ast.Name) and n.id == node.name for n in ast.walk(tree)):
                continue
            what = 'a docstring' if not body else ('pass' if isinstance(body[0], ast.Pass) else '...')
            msg = (f"Empty class '{node.name}' at line {node.lineno} — body is only {what}"
                   f"{' (bases: ' + ', '.join(bases) + ')' if bases else ''}: no attribute, no method")
            # Cut 1 (2026-09-06): the ranker decides.
            verdict = VERDICT_RANKER.decide("class", ("NAI-213", "HIGH", msg), species=species)
            if verdict.withheld:   # species: the empty class is published as context, the verdict withheld
                results.append(ValidationResult(
                    function_name=f"<class {node.name}>", function_type=FunctionType.UNKNOWN, passed=verdict.passed,   # the ranker's withheld PASS
                    warnings=[f"NAI-213 (HIGH): {msg}"], line=node.lineno, end_line=getattr(node, "end_lineno", 0) or 0,
                    triggered_patterns=[{"tag": "NAI-213", "line": node.lineno, "context": True, "withheld": verdict.withheld, "msg": msg}],
                    verdict_source=verdict.source, species=species, withheld=verdict.withheld,
                ))
                continue
            if not verdict.passed:
                results.append(ValidationResult(
                    function_name=f"<class {node.name}>",
                    function_type=FunctionType.UNKNOWN,
                    passed=False,
                    failure_layer=_layer_of(verdict),
                    failure_reason=verdict.reason,
                    triggered_patterns=[["NAI-213", "HIGH", msg]],
                    warnings=[f"NAI-213 (HIGH): {msg}"],
                    line=node.lineno,
                    # Tooling defect fix (2026-09-06): this branch omitted end_line, defaulting to 0
                    # for every class-level row — take the span from the ClassDef node itself.
                    end_line=getattr(node, "end_lineno", 0) or 0,
                    verdict_source=verdict.source,
                ))
        return results

    def validate_lambda(self, info: Union[FunctionInfo, LambdaMetrics], species: str = "") -> ValidationResult:
        """Validate a lambda expression."""
        # Handle both FunctionInfo and LambdaMetrics
        node: Union[ast.FunctionDef, ast.Lambda]
        if isinstance(info, LambdaMetrics):
            node = info.node
        else:
            node = info.node
            if not isinstance(node, ast.Lambda):
                return ValidationResult(
                    function_name="<lambda>",
                    function_type=FunctionType.UNKNOWN,
                    passed=True,
                )
        warnings = []

        # Check for identity lambda: lambda x: x
        if isinstance(node.body, ast.Name):
            if len(node.args.args) == 1 and node.body.id == node.args.args[0].arg:
                warnings.append("NAI-218 (LOW): Identity lambda (redundant)")  # A1 renumber: was NAI-104 (detection NAI-104 = name implies op not found)

        # Check for constant lambda: lambda x: 42
        if isinstance(node.body, ast.Constant):
            warnings.append("NAI-219 (MEDIUM): Constant lambda (ignores input)")  # A1 renumber: was NAI-105 (detection NAI-105 = passthrough)

        # Cut 2 (2026-09-05): the ranker decides here too (totality of the single decision point)
        verdict = VERDICT_RANKER.decide("lambda", warnings, species=species)
        return ValidationResult(
            function_name="<lambda>",
            function_type=FunctionType.UNKNOWN,
            passed=verdict.passed,
            warnings=warnings,
            verdict_source=verdict.source,
            species=species,
            withheld=verdict.withheld or "",
        )

    async def validate_lambda_async(self, info: Union[FunctionInfo, LambdaMetrics]) -> ValidationResult:
        """Validate a lambda expression (async wrapper)."""
        return await asyncio.to_thread(self.validate_lambda, info)

    def validate_comprehension(self, info: ComprehensionInfo) -> Optional[Tuple[str, str, str]]:
        """Validate a comprehension expression."""
        if info.nesting_level > 0:  # EXCISED cut 2 (2026-09-05): was `info.nesting_level > 2` — EXCISION_LIST class A
            return ("NAI-220", "MEDIUM", f"Deeply nested comprehension (depth {info.nesting_level})")  # A1 renumber: was NAI-106 (detection NAI-106 = unnormalized string compare); context inherited

        if info.filter_count > 0:  # EXCISED cut 2 (2026-09-05): was `info.filter_count > 3` — EXCISION_LIST class A
            return ("NAI-107", "LOW", f"Comprehension with many filters ({info.filter_count})")

        return None

    async def validate_comprehension_async(self, info: ComprehensionInfo) -> Optional[Tuple[str, str, str]]:
        """Validate a comprehension expression (async wrapper)."""
        return await asyncio.to_thread(self.validate_comprehension, info)

    # =========================================================================
    # HARD REQUIREMENTS CHECK
    # =========================================================================

    def _check_hard_requirements(
        self,
        metrics: FunctionMetrics,
        reqs: HardRequirements,
        func_type: FunctionType,
        votes: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Measure a declared role's canonical against the body. FIX_18 (2026-09-10): returns ONE observation
        per deficit — `{"tag": "HR-00N", "type": <role>, "deficit": <feature>, "votes": <identifier roles>,
        "description": "<role> requires <feature> but has none"}` — never a first-hit verdict string.
        The ranker decides (HR-001..008 are deciding rows in rule_dispositions.json); `votes` is the
        identifier's roles dict as built (structural / declared / name), no feasible set invented.
        """
        # Core boolean invariants. Layer-1 deficits carry a rule id (F-HR1,
        # 2026-09-05): HR-001 params, HR-002 return, HR-003 yield, HR-004
        # branch, HR-005 loop, HR-006 call, HR-007 assign, HR-008 comparison —
        # so the badge can name them and a rule can be reasoned about.
        # A METHOD's receiver is an input when the body reads it: a formatter
        # `nav_subtitle(self)` formats `self` — it does not lack parameters.
        out: List[Dict[str, Any]] = []
        _votes = dict(votes or {})

        def deficit(tag: str, feature: str) -> None:
            out.append({"tag": tag, "type": func_type.name, "deficit": feature, "votes": _votes,
                        "description": f"{func_type.name} requires {feature} but has none"})

        receiver_read = bool(getattr(metrics, 'is_method', False)
                             and ({'self', 'cls'} & set(getattr(metrics, 'params_declared', set()) | getattr(self, '_receiver_reads', set()))))
        if reqs.requires_params and metrics.params == 0 and not receiver_read:
            deficit("HR-001", "parameters")

        # IG-12 (yield-blindness, body-shape 2026-09-06, G7): a `yield` / `yield from` IS a
        # return-shape statement — MetricsExtractor already counts both into metrics.yields
        # (extractor.py), and the requires_return_or_yield compound check below already treats
        # a yield as satisfying "return". This plain requires_return branch did not, so a
        # generator property (`yield from self._cells`, no explicit `return`) was misread as
        # "returns nothing" (rich table.py:121 `cells`, HR-002 instrument-gap).
        if reqs.requires_return and metrics.returns == 0 and metrics.yields == 0:
            if not reqs.allows_method_delegation or metrics.calls == 0:
                deficit("HR-002", "return")

        if reqs.requires_yield and metrics.yields == 0:
            deficit("HR-003", "yield")

        if reqs.requires_branch and metrics.branches == 0:
            deficit("HR-004", "branches")

        if reqs.requires_loop and metrics.loops == 0:
            deficit("HR-005", "loops")

        if reqs.requires_call and metrics.calls == 0:
            if not reqs.allows_call_delegation:
                deficit("HR-006", "calls")

        if reqs.requires_assign and metrics.assigns == 0:
            deficit("HR-007", "assignments")

        if reqs.requires_comparison and metrics.comparisons == 0:
            if not reqs.allows_call_delegation or metrics.calls == 0:
                deficit("HR-008", "comparisons")

        # Compound requirements (requires_loop_or_comprehension, requires_comparison_or_call,
        # requires_return_or_yield, requires_return_or_side_effect) carry NO rule id and no declared
        # role's canonical sets one (GETTER: return; SETTER: params; CONTEXT_MANAGER: yield —
        # signature_engine/canonicals.py) — unreachable on the declared-role route, which is the only
        # caller (cut 2b). When a canonical with a compound flag becomes a declarable role it needs an
        # HR id and a disposition row before it can be measured here (FIX_18 fact, 2026-09-10).

        # Count requirements
        # min_calls / max_args / max_complexity enforcement EXCISED cut 2 (2026-09-05): count and
        # magnitude gates in the hard-requirement layer (EXCISION_LIST class A). The fields stay on
        # HardRequirements as inert metadata until the canonicals are re-specified (§S.7).

        return out

    # =========================================================================
    # ANALYSIS HELPERS (sync, called from file_validation)
    # =========================================================================

    def _validate_imports(self, collector: Any) -> List[str]:
        """Validate top-level imports against known stdlib and common packages."""
        warnings = []
        for imp in collector.imports:
            if imp not in self.stdlib and imp not in self.packages:
                warnings.append(f"NAI-IM01 (MEDIUM): Unresolved import: '{imp}'")
        return warnings

    async def _validate_imports_async(self, collector: Any) -> List[str]:
        """Async compat wrapper for _validate_imports."""
        return self._validate_imports(collector)

    def _dunder_counts_for_current_file(self) -> Optional[Dict[str, int]]:
        """FIX_34 (b) (2026-09-10): the NAI-058 whole-set fact for the current file's directory subtree, computed
        once per directory validation (`file_validation._dunder_counts_by_dir`, keyed by the resolved parent
        directory). None when no directory validation set it (a single-file validation) — the exemption is then
        not measurable and the detector keeps a singleton reported."""
        by_dir = getattr(self, '_dunder_counts_by_dir', None)
        if by_dir is None or not self._current_file:
            return None
        return by_dir.get(str(Path(self._current_file).resolve().parent), {})

    def _set_current_file_context(self, filepath: Path) -> None:
        """Set current file context for cross-file resolution."""
        self._current_file = filepath
        logger.debug("Set current file context: %s", filepath)

    def _analyze_comment_density_for_range(
        self,
        source: str,
        start_line: int,
        end_line: int,
    ) -> List[str]:
        """Analyze comment density for a line range."""
        warnings = []
        lines = source.split("\n")[start_line - 1:end_line]

        comment_count = sum(1 for line in lines if line.strip().startswith("#"))
        total_lines = end_line - start_line + 1

        if total_lines > 0:  # EXCISED cut 2 (2026-09-05): was `total_lines > 10 and comment_count / total_lines < 0.05` — EXCISION_LIST class A
            warnings.append("NAI-221 (LOW): Low comment density in function")  # A1 renumber: was NAI-111 (detection NAI-111 = nonexistent library method); context inherited

        return warnings

    def _check_type_hint_issues(self, collector: Any) -> List[Tuple[str, str, str]]:
        """Check for type hint issues across collected functions."""
        issues = []

        hints_present = sum(1 for f in collector.functions if hasattr(f.node, 'returns') and f.node.returns)
        hints_missing = len(collector.functions) - hints_present

        if hints_present > 0 and hints_missing > 0:
            ratio = hints_missing / len(collector.functions)
            if True:  # EXCISED cut 2 (2026-09-05): was `ratio > 0.5` — EXCISION_LIST class A
                issues.append((
                    "NAI-222",  # A1 renumber: was NAI-112 (detection NAI-112 = hallucinated package); context inherited
                    "LOW",
                    f"Inconsistent type hints ({hints_missing}/{len(collector.functions)} missing)"
                ))

        return issues

    def _find_unused_definitions(
        self,
        tree: ast.AST,
        defined: Set[str],
        referenced: Set[str],
    ) -> List[Tuple[str, str, str]]:
        """Find unused definitions in module."""
        issues = []

        unused = defined - referenced - {"_", "__all__", "__name__", "__file__"}
        unused = {n for n in unused if not n.startswith("_")}

        for name in list(unused):  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `[:5]` trim removed
            issues.append(("NAI-223", "LOW", f"Unused definition: {name}"))  # A1 renumber: was NAI-113 (detection NAI-113 = comment/code ratio); context inherited

        return issues

    def _check_call_graph_issues(self, call_graph: Dict[str, Set[str]]) -> List[Tuple[str, str, str]]:
        """Check for issues in call graph (cycles, etc.)."""
        issues = []
        cycles = self._detect_cycles(call_graph)

        for cycle in cycles:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `[:3]` trim removed
            issues.append((
                "NAI-224",  # A1 renumber: was NAI-114 (detection NAI-114 = hyper-descriptive naming); context inherited
                "MEDIUM",
                f"Call graph cycle: {' -> '.join(cycle)}"
            ))

        return issues

    def _check_cross_function(
        self,
        node: ast.FunctionDef,
        defined_functions: Optional[Set[str]] = None,
        builtins: Optional[Set[str]] = None,
        module_imports: Optional[Set[str]] = None,
    ) -> List[Tuple[str, str, str]]:
        """Check for cross-function issues within a module.

        Accepts explicit sets to avoid dependence on mutable self state.
        Falls back to self attributes if not provided (backward compat).
        """
        defs = defined_functions if defined_functions is not None else self.defined_functions
        blts = builtins if builtins is not None else self.builtins
        imps = module_imports if module_imports is not None else self.module_imports

        issues = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                call_name = child.func.id
                if (call_name not in defs and
                    call_name not in blts and
                    call_name not in imps):
                    issues.append((
                        "NAI-225",  # A1 renumber: was NAI-110 (detection NAI-110 = cross-language method call)
                        "MEDIUM",
                        f"Undefined function call: {call_name}"
                    ))
        return issues

    # =========================================================================
    # GRAPH ANALYSIS
    # =========================================================================

    def _detect_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        """Detect cycles in a directed graph using DFS."""
        cycles = []
        visited = set()
        rec_stack = []

        def dfs(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.append(node)
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor, path)
                elif neighbor in rec_stack:
                    idx = path.index(neighbor)
                    cycles.append(path[idx:] + [neighbor])

            path.pop()
            rec_stack.pop()

        for node in graph:
            if node not in visited:
                dfs(node, [])

        return cycles

    def _detect_import_cycles(self, import_graph: Dict[str, Set[str]]) -> List[List[str]]:
        """Detect circular import cycles."""
        return self._detect_cycles(import_graph)

    # =========================================================================
    # CROSS-FILE ANALYSIS
    # =========================================================================

    async def _build_module_map(self, dirpath: Path, files: Optional[List[Path]] = None) -> None:
        """Build mapping of module names to file paths.

        files (FIX_34, 2026-09-10): the directory validation's discovered list — the map is built from it and
        no second walk of the tree happens; without it (a caller with no list) the ONE contained walk runs."""
        self._module_map = {}
        if files is not None:
            pyfiles = list(files)
        else:
            # FIX_15 (2026-09-10): the ONE contained walk (whitelist, hard-skips, no symlink) — never a bare rglob
            from rca_main.constants import live_py_files as _live_py_files
            pyfiles = await asyncio.to_thread(_live_py_files, dirpath)
        for pyfile in pyfiles:
            try:
                rel = pyfile.relative_to(dirpath)
                parts = list(rel.parts)
                if parts[-1] == "__init__.py":
                    parts = parts[:-1]
                else:
                    parts[-1] = parts[-1][:-3]  # Remove .py
                module_name = ".".join(parts)
                self._module_map[module_name] = pyfile
            except ValueError:
                pass
        logger.debug("Built module map with %d entries", len(self._module_map))

    def _resolve_import(
        self,
        module: str,
        current_file: Path,
        base_dir: Path,
        level: int,
    ) -> bool:
        """Resolve an import to check if it exists."""
        if level == 0:
            return module in self._module_map or module in self.stdlib or module in self.packages
        else:
            try:
                current = current_file.parent
                for _ in range(level - 1):
                    current = current.parent
                target = current / (module.replace(".", "/") + ".py")
                target_init = current / module.replace(".", "/") / "__init__.py"
                return target.exists() or target_init.exists()
            except Exception:
                return False

    def _resolve_import_file(self, module: str, current_file: Path, level: int) -> Optional[Path]:
        """Resolve `from <module> import …` to the LOCAL file that defines it,
        honouring the relative-import `level` (plan item 4, 2026-09-05). None =
        not a local module (stdlib / third-party / unresolvable) — callers treat
        that as NOT MEASURED, never as a hallucination."""
        try:
            if level > 0:
                base = current_file.parent
                for _ in range(level - 1):
                    base = base.parent
                if not module:
                    init = base / "__init__.py"
                    return init if init.exists() else None
                rel = Path(*module.split("."))
                for cand in (base / rel.with_suffix(".py"), base / rel / "__init__.py"):
                    if cand.exists():
                        return cand
                return None
            if not module or module.split(".")[0] in self.stdlib:
                return None
            mapped = self._module_map.get(module)
            if mapped is not None and mapped.exists():
                return mapped
            rel = Path(*module.split("."))
            for cand in (current_file.parent / rel.with_suffix(".py"),
                         current_file.parent / rel / "__init__.py"):
                if cand.exists():
                    return cand
        except (OSError, ValueError):
            pass
        return None

    def _exported_names(self, module_file: Path) -> Optional[Set[str]]:
        """Names a `from X import …` can legitimately take from X: every def /
        class / bound / imported name anywhere in X (an over-approximation — the
        safe direction), plus sibling submodules when X is a package. None when
        X cannot be measured statically (`import *`, a module-level __getattr__,
        unreadable, syntax error)."""
        try:
            key = (str(module_file), module_file.stat().st_mtime_ns)
        except OSError:
            return None
        cached = self._export_cache.get(key)
        if cached is not None:
            return cached
        try:
            # C3 (g) / A1: BOM and PEP 263 cookie honoured, so a latin-1 or BOM module keeps its
            # export facts; one that cannot be decoded stays None (= not measured, NAI-217 then
            # judges without facts), never a decode error out of the rule.
            mod_tree = ast.parse(read_source(module_file))
        except (SyntaxError, OSError, UnicodeDecodeError, ValueError):
            return None
        if any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name == "__getattr__"
               for s in mod_tree.body):
            return None
        names: Set[str] = set()
        for n in ast.walk(mod_tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(n.name)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    names.add(a.asname or a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                for a in n.names:
                    if a.name == "*":
                        return None
                    names.add(a.asname or a.name)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names.add(n.id)
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                names.update(n.names)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                names.add(n.name)
        if module_file.name == "__init__.py":
            try:
                for p in module_file.parent.iterdir():
                    if p.is_symlink():
                        continue  # FIX_15: a symlinked sibling is never an export of the package
                    if p.suffix == ".py" and p.name != "__init__.py":
                        names.add(p.stem)
                    elif p.suffix in (".so", ".pyd"):
                        names.add(p.name.split(".")[0])
                    elif p.is_dir() and (p / "__init__.py").exists():
                        names.add(p.name)
            except OSError:
                pass
        self._export_cache[key] = names
        return names

    # =========================================================================
    # UNSAFE PATTERN CHECKS
    # =========================================================================

    def check_vuln_patterns(
        self,
        source: str,
        filepath: Optional[Path] = None,
    ) -> List[Tuple[str, str, str, int]]:
        """Check for unsafe patterns in source code."""
        issues = []
        lines = source.split("\n")

        vuln_patterns = [
            (r"eval\s*\(", "SEC-001", "HIGH", "eval() usage"),
            (r"exec\s*\(", "SEC-002", "HIGH", "exec() usage"),
            (r"pickle\.loads?\s*\(", "SEC-003", "HIGH", "pickle deserialization"),
            (r"yaml\.load\s*\([^,]*\)$", "SEC-004", "MEDIUM", "unsafe yaml.load"),
            (r"shell\s*=\s*True", "SEC-005", "HIGH", "shell=True in subprocess"),
            (r"password\s*=\s*['\"]", "SEC-006", "CRITICAL", "hardcoded password"),
            (r"api_key\s*=\s*['\"]", "SEC-007", "CRITICAL", "hardcoded API key"),
            (r"\.format\s*\([^)]*sql", "SEC-008", "HIGH", "SQL injection risk"),            (r"os\.system\s*\(", "SEC-009", "HIGH", "os.system() usage"),
            (r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True", "SEC-010", "HIGH", "subprocess with shell=True"),
            (r"(token|secret|private_key)\s*=\s*['\"]\w+", "SEC-011", "CRITICAL", "hardcoded secret"),
            (r"__import__\s*\(", "SEC-012", "MEDIUM", "dynamic import"),
            (r"compile\s*\([^)]+,\s*['\"]exec", "SEC-013", "HIGH", "code compilation"),        ]

        for i, line in enumerate(lines, 1):
            for pattern, code, severity, msg in vuln_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append((code, severity, msg, i))

        return issues

    def scan_source_signatures(
        self,
        source: str,
    ) -> List[Tuple[str, str, str, int]]:
        """Scan source code against the signatures signature database.

        Returns list of (signature_name, severity, description, line_number) tuples.
        """
        scan_result = self._signature_db.scan(source)
        issues = []
        for match in scan_result:
            issues.append((
                match.signature.name,
                match.signature.severity.upper(),
                match.signature.description,
                match.line_number,
            ))
        return issues

    # =========================================================================
    # POLICY HOOKS
    # =========================================================================

    def register_policy_hook(self, hook: Callable[[ValidationResult, str], List[str]]) -> None:
        """Register a policy hook for custom validation rules."""
        self._policy_hooks.append(hook)
        logger.info("Registered policy hook: %s", hook.__name__)

    def run_policy_hooks(self, result: ValidationResult, source: str) -> List[str]:
        """Run all registered policy hooks."""
        warnings = []
        for hook in self._policy_hooks:
            try:
                hook_warnings = hook(result, source)
                warnings.extend(hook_warnings)
            except Exception as e:
                logger.warning("Policy hook %s failed: %s", hook.__name__, e)
        return warnings

    # =========================================================================
    # CACHING
    # =========================================================================

    async def get_file_hash(self, filepath: Path) -> str:
        """Get hash of file contents for caching (async I/O)."""
        try:
            content = await asyncio.to_thread(filepath.read_bytes)
            return hashlib.md5(content).hexdigest()
        except Exception:
            return ""

    # Keep the _async alias for backward compatibility
    get_file_hash_async = get_file_hash

    @staticmethod
    def _format_observation(obs: Dict[str, Any]) -> str:
        """Format a raw detection observation into a human-readable string.

        Detection emits raw AST observations (no severity, no message).
        This method generates readable output for warnings/failure_reason.
        """
        tag = obs.get("tag", "?")
        line = obs.get("line", "?")
        details = {k: v for k, v in obs.items() if k not in ("tag", "line")}
        # FIX_18 (2026-09-10): an observation that carries its own sentence (an HR deficit, a withheld
        # strict proof) is rendered from it — ONE renderer, the ranker's deciding observation as the text.
        if "description" in details:
            desc = details.pop("description")
            by = details.get("established_by")
            return f"{tag} (line {line}): {desc}" + (f" [role established by {by}]" if by else "")
        if details:
            detail_parts = []
            for k, v in details.items():
                if isinstance(v, (list, set)):
                    detail_parts.append(f"{k}={list(v)}")
                else:
                    detail_parts.append(f"{k}={v}")
            return f"{tag} (line {line}): {', '.join(detail_parts)}"
        return f"{tag} (line {line})"

    def clear_cache(self) -> None:
        """Clear file cache, import graph, and cross-file analysis state."""
        self._file_cache.clear()
        self._import_graph.clear()
        self._export_cache.clear()
        self.parse_errors.clear()
        self.module_symbols.clear()
        self.module_imports.clear()
        self.defined_functions.clear()
        self.symbol_references.clear()
        logger.info("Cache cleared")

    async def clear_cache_async(self) -> None:
        """Clear the file cache (async wrapper)."""
        self.clear_cache()

    # =========================================================================
    # UTILITY
    # =========================================================================

    def _run_sync(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run coroutine synchronously. Only used for I/O wrappers."""
        # Last plan 1a (2026-10-10): only "no running loop" picks asyncio.run — before this a RuntimeError raised
        # INSIDE the coroutine (a crashing rule) was caught here too, and the re-run hid it behind "cannot be
        # called from a running event loop".
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()


if __name__ == "__main__":
    import sys
    from pathlib import Path

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage: python validator.py <file_or_dir>")
        sys.exit(1)

    target = Path(sys.argv[1])
    validator = NoAIMathValidator()

    if target.is_file():
        results = validator.validate_file(target)
        print(f"File: {target}")
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)
        print(f"  Functions: {len(results)} ({passed} passed, {failed} failed)")
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"    [{status}] {r.function_name}", end="")
            if not r.passed and r.failure_reason:
                print(f" — {r.failure_reason[:80]}", end="")
            if r.warnings:
                print(f" ({len(r.warnings)} warnings)", end="")
            print()
    elif target.is_dir():
        all_results, summary = validator.validate_directory(target, max_files=50)
        print(f"Directory: {target}")
        print(f"  Files scanned: {summary.get('files_scanned', '?')}")
        passed = sum(1 for r in all_results if r.passed)
        failed = sum(1 for r in all_results if not r.passed)
        print(f"  Functions: {len(all_results)} ({passed} passed, {failed} failed)")
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(1)
