"""
File and directory validation methods for NoAIMathValidator.

This module extends the validator with file I/O operations.
Async I/O via asyncio.to_thread(read_source) (A1: PEP 263 reader); sync computation for validation logic.
"""

import ast
import asyncio
import os
import time
import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple

from .core import FunctionType, ValidationLayer, ValidationResult
from .models import FunctionInfo, ParseError, StringValidationResult
from .collector import FunctionCollector
from .utils import fingerprint_all_functions, check_duplicate_functions, base_name, read_source
from .utils import (  # FIX_17 (2026-09-10): NAI-229 / NAI-230 wired into the per-function observations
    symmetry_229_observation as _symmetry_229_observation,
    normalized_duplicates_230_observations as _normalized_duplicates_230_observations,
    disabled_case_236_observations as _disabled_case_236_observations,
    test_gaming_237_observations as _test_gaming_237_observations,
    sibling_divergence_238_observations as _sibling_divergence_238_observations,
    normalized_fingerprint as _noai_normalized_fingerprint,
)
from ..detection.hallucination_checks import dunder_names_in_tree as _dunder_names_in_tree   # FIX_34 (b)
from ..cheatsheets.cheatsheet_intelligence.knowledge_base import VerdictRanker as _VerdictRanker  # cut 2c
import re as _re
_VR = _VerdictRanker()   # cut 2c (2026-09-06): file-level verdicts are the ranker's, never an assignment

if TYPE_CHECKING:
    from .validator import NoAIMathValidator

try:
    from utils.code_analysis.graph import (
        find_unused_assignments as _graph_find_unused,
        find_undefined_uses as _graph_find_undefined,
        build_data_flow_graph as _build_dfg,
        build_dependency_graph as _build_dep_graph,
        find_cycles as _graph_find_cycles,
        dfs_reachability as _dfs_reachability,
        bfs_shortest_path as _bfs_shortest_path,
        reverse_graph as _reverse_graph,
        topological_sort as _topological_sort,
        find_all_paths as _find_all_paths,
        is_identity_chain as _is_identity_chain,
    )
    from utils.code_analysis.symmetry import (
        check_arithmetic_symmetry as _check_arith_symmetry,
        check_suspicious_symmetry as _check_suspicious_symmetry,
    )
    from utils.code_analysis.fingerprint import (
        normalized_fingerprint as _normalized_fingerprint,
    )
    from utils.code_analysis.duplicate import (
        check_duplicate_functions_strict as _check_dup_strict,
    )
    from utils.code_analysis.extractor import MetricsExtractor as _UtilsMetricsExtractor
    _UTILS_AVAILABLE = True
except ImportError:
    _UTILS_AVAILABLE = False

try:
    # FIX_14 (2026-09-10): the ONE walk (scan_scope.iter_live_py through rca_main.constants) replaces
    # the substring exclusion table when no discovered list is handed over.
    from rca_main.constants import live_py_files as _live_py_files
    _RCA_WALK_AVAILABLE = True
except ImportError:
    _RCA_WALK_AVAILABLE = False

try:
    from rca_main.import_graph import ImportGraphBuilder as _ImportGraphBuilder
    _IMPORT_GRAPH_AVAILABLE = True
except ImportError:
    _IMPORT_GRAPH_AVAILABLE = False

try:
    from rca_main.rca_unit import RootCauseUnit as _RootCauseUnit
    _RCA_UNIT_AVAILABLE = True
except ImportError:
    _RCA_UNIT_AVAILABLE = False

# Tier-2 runtime tools. Imported only so future gearbox wiring can populate
# origin_trace_results / onion_peel_results from real CrashArtifacts produced by
# validation-run / test execution. The static path below NEVER invokes them: no
# subprocess, no file writes, no synthesized failures.
try:
    from rca_main.onion_peeler import (  # noqa: F401
        peel_and_fix_async as _peel_and_fix_async,
    )
    _ONION_PEELER_AVAILABLE = True
except ImportError:
    _ONION_PEELER_AVAILABLE = False

try:
    from rca_main.origin_tracer import (  # noqa: F401
        run_with_tracing as _run_with_tracing,
    )
    _BLAME_TRACER_AVAILABLE = True
except ImportError:
    _BLAME_TRACER_AVAILABLE = False

try:
    from rca_main.caller_map import CallerMapBuilder as _CallerMapBuilder
    _CALLER_MAP_AVAILABLE = True
except ImportError:
    _CALLER_MAP_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

logger = logging.getLogger(__name__)

# Unified walk policy (reverse-run R8): per-file size cap for directory walks.
_MAX_FILE_BYTES = None  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 2 MB — a file budget is silence; no cap unless configured

_ENTRYPOINT_DECORATORS = {
    'app.route', 'click.command', 'shared_task', 'click.group',
    'router.post', 'pytest.mark.parametrize', 'staticmethod', 'pytest.fixture',
    'abstractmethod', 'router.get', 'contextmanager', 'asynccontextmanager',
    'fixture', 'classmethod', 'override', 'router.put', 'router.delete',
    'property', 'celery.task',
}


# Signature names whose shape is a DECLARATION in typed / abstract code; the
# per-function rules (NAI-004 / NAI-120 / NAI-214 / NAI-142) judge them with
# @overload / Protocol / ABC / NotImplementedError context — the regex cannot.
# Lexical file roles (cut 3 batch 5 addendum, owner 2026-09-06): the language / its tools define these names —
# __init__.py and __main__.py by Python's import system, conftest.py by pytest (SPECIES_DICT: a signature of the test
# species), setup.py by setuptools. Published as FILE-ROLE (INFO) on the module row; never a scan gate.
_LEXICAL_FILE_ROLES = {
    '__init__.py': 'package marker — Python package declaration (lexical: name defined by the language)',
    '__main__.py': 'package entry — `python -m pkg` (lexical: name defined by the language; same class as __init__.py)',
    'conftest.py': 'pytest fixture module — test species (SPECIES_DICT signature); measured like any live source',
    'setup.py': 'setuptools build script — packaging code (often a deprecation stub); measured like any live source',
}

# ── Species: CONTENT first, the path a published PRIOR (owner decision 5, 2026-09-06) ────────────────
# A file is test species when its content says so: it imports unittest (not merely unittest.mock) or pytest,
# defines a class with a *TestCase base, or defines top-level test_* functions. A tests/ dir or a test_*.py
# name is PUBLISHED as a prior on the module row and never decides. A library's tests are CONTEXT (owner
# decision 1): the ranker withholds its verdict on every row of a test file; the evidence is published.
_TEST_DIR_NAMES = frozenset({'test', 'tests', 'testing'})


def _file_species(tree: ast.AST, rel: str) -> Tuple[str, str, bool]:
    """(species, content_reason, path_prior). species is 'test' or '' — the only species this classifier names.
    Item 3 (2026-09-10): the classifier lives in the ARTIFACT SCANNER (`no_aivalidator/artifact_scanner/species.py::
    test_species`, moved unchanged — IG-5 and the path prior included); this name is the alias the route keeps."""
    from no_aivalidator.artifact_scanner.species import test_species
    return test_species(tree, rel)


def _species_from_report(validator: 'NoAIMathValidator', rel: str, tree: ast.AST) -> Tuple[str, str, bool]:
    """Item 3 (2026-09-10): the file's species FACT for the route — from the artifact scanner's whole-set report when
    the daemon attached one (`validator.artifact_report`, built once per baseline: proxies by content need the
    in-degree and cross-file references only the whole set knows), else the content classifier alone (test | '').
    The vocabulary is `artifact_scanner.SPECIES_VOCABULARY`: '' | 'test' | 'proxy:<kind>'."""
    report = getattr(validator, 'artifact_report', None)
    fact = report.species.get(rel) if report is not None and getattr(report, 'species', None) else None
    if fact is not None:
        return fact.species, fact.reason, fact.path_prior
    return _file_species(tree, rel)


def _function_species(file_species: str, node: Any) -> str:
    """owner 2026-10-07 (blind tree 1 L4 miss, M-90): a test-species FILE withholds only its test code — a `test_*`
    function, a method of a `Test*` class, or a pytest fixture. Any other function in that file is real code and is
    judged like code anywhere else; before this, one `test_` function in a module withheld the planted code beside it."""
    if file_species != "test":
        return file_species
    name = getattr(node, "name", "") or ""
    if name.startswith("test") or name in ("setUp", "tearDown", "setUpClass", "tearDownClass", "setup_method",
                                           "teardown_method", "setup_module", "teardown_module"):
        return file_species
    for dec in getattr(node, "decorator_list", []) or []:
        text = ast.unparse(dec) if hasattr(ast, "unparse") else ""
        if "fixture" in text or text.startswith("pytest.") or text.startswith("mock.") or text.startswith("patch"):
            return file_species
    return ""


def _species_line(species: str, reason: str, prior: bool) -> str:
    return f"FILE-SPECIES (INFO): {species + ' — ' + reason if species else 'none by content'}; path prior: {'yes' if prior else 'no'}"


def _noreturn_names(tree: ast.AST) -> Set[str]:
    """IG-6 (2026-09-06): names of defs in this module annotated -> NoReturn / Never — a lexical fact handed to the detector."""
    out: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.returns is not None:
            r = n.returns
            name = r.id if isinstance(r, ast.Name) else r.attr if isinstance(r, ast.Attribute) else (r.value.rsplit('.', 1)[-1] if isinstance(r, ast.Constant) and isinstance(r.value, str) else '')
            if name in ('NoReturn', 'Never'):
                out.add(n.name)
    return out


def _module_attr_names(tree: ast.AST) -> Set[str]:
    """IG-10 (2026-09-06): every def name and every attribute name this module assigns (`self.x = …`, `obj.x: T = …`,
    class-level names) — a name the module defines is a fact, not a hallucination."""
    out: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.add(n.name)
        elif isinstance(n, ast.ClassDef):
            out.update(s.targets[0].id for s in n.body if isinstance(s, ast.Assign) and s.targets and isinstance(s.targets[0], ast.Name))
            out.update(s.target.id for s in n.body if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name))
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Store):
            out.add(n.attr)
    return out


def _module_dotted_name(rel_path: str) -> str:
    """IG-13 (2026-09-06): the dotted module name for a project-relative path — an `__init__.py` names its
    own package, not a `.__init__` submodule."""
    posix = rel_path.replace('\\', '/')
    if posix.endswith('/__init__.py'):
        posix = posix[: -len('/__init__.py')]
    elif posix == '__init__.py':
        posix = ''
    elif posix.endswith('.py'):
        posix = posix[:-3]
    return posix.replace('/', '.')


def _package_of(rel_path: str) -> str:
    """IG-13: the dotted package a module's relative imports (`from . import x`, level>=1) resolve against —
    itself, for an `__init__.py`; its parent, for a plain module."""
    posix = rel_path.replace('\\', '/')
    if posix.endswith('/__init__.py') or posix == '__init__.py':
        return _module_dotted_name(rel_path)
    dotted = _module_dotted_name(rel_path)
    return dotted.rsplit('.', 1)[0] if '.' in dotted else ''


def _resolve_import_target(rel_path: str, level: int, module: Optional[str]) -> str:
    """IG-13: resolve a (possibly relative) `from X import ...` to the dotted module name X names, following
    Python's own relative-import rule (level 1 = the current package, each further level climbs one package)."""
    if not level:
        return module or ''
    pkg = _package_of(rel_path)
    bits = pkg.split('.') if pkg else []
    if level > 1:
        bits = bits[: max(0, len(bits) - (level - 1))]
    base = '.'.join(b for b in bits if b)
    if module:
        return f'{base}.{module}' if base else module
    return base


def _module_top_level_names(tree: ast.AST) -> Set[str]:
    """IG-13: a module's own top-level definitions — def/class names, module-level Assign/AnnAssign targets,
    and names it itself imports by name (a re-export chain) — what `from <this module> import *` binds absent
    an explicit `__all__`."""
    out: Set[str] = set()
    for n in getattr(tree, 'body', ()):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.Assign):
            out.update(t.id for t in n.targets if isinstance(t, ast.Name))
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            out.add(n.target.id)
        elif isinstance(n, ast.ImportFrom):
            out.update((a.asname or a.name) for a in n.names if a.name != '*')
        elif isinstance(n, ast.Import):
            out.update((a.asname or a.name.split('.')[0]) for a in n.names)
    return out


def _module_dunder_all(tree: ast.AST) -> Optional[List[str]]:
    """IG-13: a literal top-level `__all__ = [...]` (or `(...)`)  — the names a module exports via `import *`
    when it declares one explicitly."""
    for n in getattr(tree, 'body', ()):
        target = None
        if isinstance(n, ast.Assign) and len(n.targets) == 1:
            target = n.targets[0]
        elif isinstance(n, ast.AugAssign):
            target = n.target
        if isinstance(target, ast.Name) and target.id == '__all__' and isinstance(n.value, (ast.List, ast.Tuple)):
            return [e.value for e in n.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return None


def _wildcard_export_names(dotted: str, dotted_to_rel: Dict[str, str], trees_by_rel: Dict[str, ast.AST],
                            seen: Set[str]) -> Set[str]:
    """IG-13 (2026-09-06): what `from <dotted> import *` actually binds when <dotted> resolves to a module
    inside the scanned tree — its own top-level definitions, its literal `__all__` when it has one, and
    (bounded, cycle-guarded) whatever it itself re-exports through a further `from Y import *` / `from Y import
    __all__` (numpy: `numpy.strings` -> `numpy._core.strings`). A target outside the tree (stdlib / a
    dependency not part of this scan) yields nothing — never a hallucination guess."""
    if dotted in seen or dotted not in dotted_to_rel:
        return set()
    seen.add(dotted)
    tree = trees_by_rel.get(dotted_to_rel[dotted])
    if tree is None:
        return set()
    names = _module_top_level_names(tree)
    all_names = _module_dunder_all(tree)
    if all_names is not None:
        names |= set(all_names)
    for n in getattr(tree, 'body', ()):
        if isinstance(n, ast.ImportFrom):
            forwards = any(a.name in ('*', '__all__') for a in n.names)
            if forwards:
                target = _resolve_import_target(dotted_to_rel[dotted], n.level, n.module)
                if target:
                    names |= _wildcard_export_names(target, dotted_to_rel, trees_by_rel, seen)
    return names


def _enclosing_names(tree: ast.AST) -> Dict[int, Set[str]]:
    """IG-9 (2026-09-06): for every nested def, the names bound in its ENCLOSING function scopes (parameters, assignments,
    walrus targets, for / with / except names, sibling defs) — what a closure can see. Keyed by id(node)."""
    def bound(fn: ast.AST) -> Set[str]:
        a = fn.args; names = {x.arg for x in a.args + a.posonlyargs + a.kwonlyargs} | {x.arg for x in (a.vararg, a.kwarg) if x}  # type: ignore[attr-defined]  # FIX_54 ast-pos
        stack = list(ast.iter_child_nodes(fn))
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store): names.add(n.id)
            elif isinstance(n, ast.NamedExpr): names.add(n.target.id)
            elif isinstance(n, ast.ExceptHandler) and n.name: names.add(n.name)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): names.add(n.name); continue
            elif isinstance(n, ast.Lambda): continue
            stack.extend(ast.iter_child_nodes(n))
        return names
    out: Dict[int, Set[str]] = {}
    def walk(node: ast.AST, inherited: Set[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[id(child)] = set(inherited)
                walk(child, inherited | bound(child))
            elif isinstance(child, ast.ClassDef):
                walk(child, inherited)      # a class body is not an enclosing function scope
            else:
                walk(child, inherited)
    walk(tree, set())
    return out


_SIG_CONTEXTUAL_STUBS = frozenset({
    'notimplemented_error', 'ellipsis_body', 'pass_only_function',
    # Run 19 (2026-09-05): style / quality opinions are not counterfeit signals;
    # the per-function rules own the ones that are (NAI-071 mutable default,
    # NAI-078 swallow, NAI-002 unreachable). silent_exception, the
    # hallucination / misspelling / placeholder / security signatures stay.
    'bare_except', 'pokemon_exception', 'mutable_default_arg', 'global_statement',
    'mixed_quotes', 'trailing_whitespace', 'missing_docstring', 'star_import',
    'comparison_to_none', 'comparison_to_true_false', 'god_class', 'god_function',
    'deep_nesting', 'too_many_params', 'high_cyclomatic', 'redundant_return_none',
    'empty_if_body', 'unreachable_code',
})


def _run_dead_function_scan(
    tree: ast.AST,
    collector: 'FunctionCollector',
    results: List[ValidationResult],
    filepath: Optional[Path] = None,
) -> None:
    """
    NAI-202: Detect functions defined but never referenced within the module.

    Runs after the per-function validation loop. Uses collector.functions,
    collector.defined_symbols, and collector.referenced_symbols plus a
    full ast.walk to find call references.
    """
    func_names: Set[str] = set()
    for info in collector.functions:
        node = info.node
        if not hasattr(node, 'name'):
            continue
        if info.nesting_depth != 0:
            continue
        func_names.add(node.name)
    if not func_names:
        return

    # C1 (Q-H3b-6, 2026-10-01): ONE walk of the module feeds every per-function question below.
    # Before this the loop re-walked the whole tree once PER top-level function to count its
    # references (functions × nodes — 6,000 trivial defs in one generated file = 600 M node visits,
    # the hang of Q-H3b-6). A name is "referenced" exactly when some ast.Name node carries it —
    # the Name under a Call's func is itself walked, so the old `ref_count != 0` test and this
    # membership test are the same answer for every function.
    referenced_names: Set[str] = set()
    all_names: Set[str] = set()
    for node in ast.walk(tree):  # type: ignore[assignment]  # FIX_54 ast-pos
        if isinstance(node, ast.Name):
            referenced_names.add(node.id)
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id != '__all__':
                continue
            if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        all_names.add(elt.value)

    # the row the message attaches to: the FIRST result carrying the name (as the linear search did)
    first_row_by_name: Dict[str, ValidationResult] = {}
    for r in results:
        first_row_by_name.setdefault(r.function_name, r)

    for info in collector.functions:
        node = info.node
        if not hasattr(node, 'name') or info.nesting_depth != 0:
            continue
        name = node.name
        if name.startswith('__') and name.endswith('__'):
            continue
        if name.startswith('test_'):
            continue
        if name in all_names:
            continue

        is_entrypoint = False
        for dec in node.decorator_list:
            dec_name = ''
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Attribute):
                if isinstance(dec.value, ast.Name):
                    dec_name = f'{dec.value.id}.{dec.attr}'
                else:
                    dec_name = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    if isinstance(dec.func.value, ast.Name):
                        dec_name = f'{dec.func.value.id}.{dec.func.attr}'
                    else:
                        dec_name = dec.func.attr
            if dec_name in _ENTRYPOINT_DECORATORS:
                is_entrypoint = True
                break
        if is_entrypoint:
            continue

        if name in referenced_names:
            continue

        msg = (
            f"NAI-202 (LOW): DEAD_CODE — function '{name}' is defined but never "
            f"called or referenced within the module"
        )
        row = first_row_by_name.get(name)
        if row is not None:
            row.warnings.append(msg)
        elif results:
            results[0].warnings.append(msg)


async def validate_file_async(
    validator: 'NoAIMathValidator',
    filepath: Path,
) -> List[ValidationResult]:
    """
    Validate all functions in a Python file (async I/O).

    Reads the file with read_source (BOM / coding cookie honoured), parses AST, delegates to shared validation logic.
    """
    logger.debug('Validating file: %s', filepath)

    try:
        source = await asyncio.to_thread(read_source, filepath)   # A1 (Q-H3b-4/5): BOM / PEP 263 cookie honoured
    except (IOError, OSError) as e:
        logger.error('Cannot read file %s: %s', filepath, e)
        return [ValidationResult(
            function_name='<file>',
            function_type=FunctionType.UNKNOWN,
            passed=False,
            failure_layer=ValidationLayer.HARD_REQUIREMENTS,
            failure_reason=f'Cannot read file: {e}',
            file_path=str(filepath),
        )]
    except (SyntaxError, UnicodeDecodeError) as e:   # A1: undecodable source — reported as NOT MEASURED, never dropped
        # Python's own verdict here is SyntaxError (bad coding cookie / undecodable bytes): NAI-208, decided by the ranker.
        logger.warning('could not decode %s: %s — NOT MEASURED', filepath, e)
        validator.parse_errors.append(ParseError(filepath=filepath, error_type='DecodeError', message=str(e)))
        _v = _VR.decide("rule", ("NAI-208", "HIGH", f'could not decode {filepath.name}: {e} — NOT MEASURED', "HARD_REQUIREMENTS"))
        return [ValidationResult(
            function_name='<file>',
            function_type=FunctionType.UNKNOWN,
            passed=_v.passed,
            failure_layer=ValidationLayer.HARD_REQUIREMENTS if not _v.passed else None,
            failure_reason=_v.reason,
            verdict_source=_v.source,
            file_path=str(filepath),
            warnings=[f'NAI-208 (HIGH): File could not be decoded — {e} — NOT MEASURED'],
        )]

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        logger.warning('Syntax error in %s:%s: %s', filepath.name, e.lineno, e.msg)
        validator.parse_errors.append(ParseError(
            filepath=filepath,
            error_type='SyntaxError',
            message=str(e.msg),
            line=e.lineno,
            column=e.offset,
        ))
        return [ValidationResult(
            function_name='<file>',
            function_type=FunctionType.UNKNOWN,
            passed=False,
            failure_layer=ValidationLayer.HARD_REQUIREMENTS,
            failure_reason=f'NAI-208 (HIGH): Syntax error in {filepath.name}:{e.lineno}: {e.msg}',
            warnings=[f'NAI-208 (HIGH): File contains syntax error — {e.msg} at line {e.lineno}'],
            file_path=str(filepath),
        )]

    results, _, _ = await _validate_file_from_ast(validator, tree, source, filepath)
    # Single-file scope: an abstract shell can only be judged against this module.
    results.extend(_check_abstract_shells({str(filepath): (filepath, tree)}, 'this module'))
    for r in results:
        if not r.file_path:
            r.file_path = str(filepath)
    return results


async def _validate_file_from_ast(
    validator: 'NoAIMathValidator',
    tree: ast.AST,
    source: str,
    filepath: Path,
    rel: Optional[str] = None,
    project_attr_names: Optional[Set[str]] = None,
) -> Tuple[List[ValidationResult], FunctionCollector, Dict[str, Any]]:
    """
    Core file validation logic.

    Returns (results, collector, fingerprints) so callers (e.g. directory
    validation) can reuse data without re-reading/re-parsing the file.
    rel: the target-relative path (the species PRIOR reads directory names; the content decides).
    """
    logger.debug('_validate_file_from_ast called: filepath=%s', filepath)
    results: List[ValidationResult] = []
    _sp, _sp_reason, _sp_prior = _species_from_report(validator, rel or Path(filepath).name, tree)   # computed ONCE per file (A4, 2026-09-06); Item 3: the scanner's fact when a report is attached
    _nr = _noreturn_names(tree)   # IG-6
    _ma = _module_attr_names(tree) | set(project_attr_names or ()); _enc = _enclosing_names(tree)   # IG-10 / IG-9; IG-10b: names any module of the PROJECT defines

    # FIX_34 (a) (2026-09-10): the only await of this function runs FIRST — after it the validator's per-file
    # state (current file, module symbols / imports) is set and read with no await in between, so files
    # validated as a gathered batch can never interleave inside one another's state window.
    fingerprints = await fingerprint_all_functions(filepath)

    validator._set_current_file_context(filepath)
    # owner 2026-10-07 (whole-module sandbox): every probe this file triggers sees its module's constants and its
    # other pure functions. Set after the only await (FIX_34 a), so no other file's binding can interleave.
    try:
        from .intent_claims import bind_module as _bind_module
        _bind_module(tree)
    except Exception as _bme:
        logging.getLogger(__name__).warning("module sandbox bind failed on %s: %r", filepath, _bme)

    collector = FunctionCollector(source)
    collector.visit(tree)

    validator.module_symbols = collector.defined_symbols
    validator.module_imports = collector.imports
    validator.defined_functions = {
        f.node.name for f in collector.functions if hasattr(f.node, 'name')
    }
    validator.symbol_references = collector.referenced_symbols

    # Owner 2026-10-08, wave 3 #1 (NAI-253): harness tampering, measured once per file before the module row —
    # module-level statements become rows right here, per-function ones join the probe observations below.
    _tamper_fn: Dict[str, List[Dict[str, Any]]] = {}
    _tamper_module: List[Dict[str, Any]] = []
    try:
        from .harness_tamper import observations as _tamper_observations
        _tamper_fn, _tamper_module = _tamper_observations(tree, str(filepath))
    except Exception as _hte:
        logging.getLogger(__name__).warning("harness-tamper probe failed on %s: %r", filepath, _hte)
    # NAI-253 at module level (pytestmark skip, a clock swapped at import time …): one row per statement, the ranker
    # decides like any rule — the empty-class row's shape (owner 2026-10-08, wave 3 #1).
    for _to in _tamper_module:
        from .validator import VERDICT_RANKER as _VR253, _layer_of
        _tv = _VR253.decide("rule", ("NAI-253", "HIGH", f"NAI-253 (line {_to['line']}): {_to['description']}",
                                     "AI_FAKE_DETECTOR"), species=_sp)
        results.append(ValidationResult(
            function_name="<module>", function_type=FunctionType.UNKNOWN, passed=_tv.passed,
            failure_layer=_layer_of(_tv), failure_reason=_tv.reason, triggered_patterns=[dict(_to)],
            warnings=[f"NAI-253 (HIGH): {_to['description']}"], file_path=str(filepath), line=_to["line"],
            end_line=_to["line"], verdict_source=_tv.source, species=_sp, withheld=_tv.withheld or "",
        ))
    module_result = validator.validate_module(tree, source, filepath, species=_sp)
    if module_result.warnings or not module_result.passed:
        results.append(module_result)
    # NAI-213 empty_class — classes with no methods never reach the per-function
    # pipeline, so they are checked here (plan item 4, 2026-09-05).
    results.extend(validator.validate_classes(tree, filepath, species=_sp))

    dup_issues = check_duplicate_functions(fingerprints)

    func_line_ranges: Dict[str, Tuple[int, Optional[int]]] = {}
    for info in collector.functions:
        node = info.node
        if hasattr(node, 'lineno') and hasattr(node, 'end_lineno') and hasattr(node, 'name'):
            func_line_ranges[node.name] = (node.lineno, node.end_lineno)

    # FIX_17 (2026-09-10): NAI-229 / NAI-230 reach the per-function OBSERVATIONS stage — the Ranker decides
    # them by the per-(rule, context) table, their `magnitude` the context fact. The whole-file normalized-
    # fingerprint map is computed ONCE (a whole-set fact, THE ASYNC LAW); members are keyed name@line so
    # nested or same-named defs never share an observation.
    _fp230: Dict[str, List[str]] = defaultdict(list)
    for info in collector.functions:
        node = info.node
        if hasattr(node, 'name') and hasattr(node, 'lineno'):
            _fp230[_noai_normalized_fingerprint(node)].append(f"{node.name}@{node.lineno}")
    _obs230 = _normalized_duplicates_230_observations(dict(_fp230))
    # owner 2026-10-07 (blind tree 3 decoys, M-100): the group's `body_statements` — the most statements any member
    # holds, docstring excluded. A table of one-line conversions (`return x * 25.4`) shares a fingerprint by nature;
    # the disposition table's context row reads this fact, the rule keeps firing (ranker decides FPs, 09-30)
    _stmts = {f"{n.name}@{n.lineno}": len([b for b in n.body if not (isinstance(b, ast.Expr) and isinstance(
        getattr(b, 'value', None), ast.Constant) and isinstance(b.value.value, str))])
              for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for _o in _obs230.values():
        _o["body_statements"] = max(_stmts.get(m, 0) for m in _o.get("group") or [])
    _obs236 = _disabled_case_236_observations(list(collector.functions))   # owner 2026-10-07: L3 disabled case
    _obs237 = _test_gaming_237_observations(list(collector.functions))     # owner 2026-10-07: L4 test gaming
    _obs238 = _sibling_divergence_238_observations(list(collector.functions))   # owner 08:15: L5 review note
    # owner 2026-10-07 ~10:00: intent-free relation probes (inverse / partition / compose / bound / unit) — they
    # OBSERVE only; the Ranker weighs them through rule_dispositions.json (NAI-239 deciding, NAI-240 context)
    try:
        from .relation_probes import observations as _relation_observations, sentinel_observations as _sentinel_obs
        _obs239 = _relation_observations(list(collector.functions))
        for _k, _v in _sentinel_obs(tree, list(collector.functions)).items():
            _obs239.setdefault(_k, []).extend(_v)
        from .boundary_probes import observations as _boundary_observations   # owner 2026-10-07: NAI-241 / 242
        for _k, _v in _boundary_observations(list(collector.functions)).items():
            _obs239.setdefault(_k, []).extend(_v)
        from .boundary_probes import partial_case_observations as _partial_obs   # owner 2026-10-07: NAI-243
        for _k, _v in _partial_obs(tree, list(collector.functions)).items():
            _obs239.setdefault(_k, []).extend(_v)
        from .corner_guards import static_observations as _corner_obs   # M-148: the function supplies the corner itself
        for _k, _v in _corner_obs(list(collector.functions)).items():
            _obs239.setdefault(_k, []).extend(_v)
    except Exception as _rpe:   # a probe must never take the file down; reported, never silent
        _obs239 = {}
        logging.getLogger(__name__).warning("relation probes failed on %s: %r", filepath, _rpe)
    try:   # owner 2026-10-08, top-10 wave 2: NAI-244..250 — own guard, so a failure here never wipes the probes above
        from .top10_wave2 import observations as _wave2_observations
        for _k, _v in _wave2_observations(tree, list(collector.functions)).items():
            _obs239.setdefault(_k, []).extend(_v)
    except Exception as _w2e:
        logging.getLogger(__name__).warning("top-10 wave 2 probes failed on %s: %r", filepath, _w2e)
    for _k, _v in _tamper_fn.items():   # owner 2026-10-08, wave 3 #1 (NAI-253): this file's per-function share
        _obs239.setdefault(_k, []).extend(_v)
    try:   # owner 2026-10-08, wave 3 #7: this file's share of the project-wide split-brain pairs (NAI-251)
        for _k, _v in (getattr(validator, "_split_brain_obs", {}) or {}).get(str(Path(filepath).resolve()), {}).items():
            _obs239.setdefault(_k, []).extend(_v)
    except Exception as _sbm:
        logging.getLogger(__name__).warning("split-brain merge failed on %s: %r", filepath, _sbm)

    for info in collector.functions:
        _route_obs: List[Dict[str, Any]] = []
        _o229 = _symmetry_229_observation(info.node)
        if _o229 is not None:
            _route_obs.append(_o229)
        _o230 = _obs230.get(f"{getattr(info.node, 'name', '')}@{getattr(info.node, 'lineno', 0)}")
        if _o230 is not None:
            _route_obs.append({**_o230, "line": info.node.lineno})
        _o236 = _obs236.get(f"{getattr(info.node, 'name', '')}@{getattr(info.node, 'lineno', 0)}")
        if _o236 is not None:
            _route_obs.append(_o236)
        _o237 = _obs237.get(f"{getattr(info.node, 'name', '')}@{getattr(info.node, 'lineno', 0)}")
        if _o237 is not None:
            _route_obs.append(_o237)
        _o238 = _obs238.get(f"{getattr(info.node, 'name', '')}@{getattr(info.node, 'lineno', 0)}")
        if _o238 is not None:
            _route_obs.append(_o238)
        _route_obs.extend(_obs239.get(f"{getattr(info.node, 'name', '')}@{getattr(info.node, 'lineno', 0)}", []))
        result = validator.validate_function(
            info.node,
            class_context=info.class_context,
            decorators=info.decorators,
            class_bases=getattr(info, 'parent_bases', None),
            source_segment=info.source_segment,
            imported_names=collector.imported_names,
            module_level_names=collector.defined_symbols,
            species=_function_species(_sp, info.node) if not info.class_context or not str(info.class_context).startswith('Test') else _sp,
            noreturn_names=_nr,
            enclosing_names=_enc.get(id(info.node), set()),
            module_attr_names=_ma,
            route_observations=_route_obs,
        )
        result.line = getattr(info.node, 'lineno', 0) or 0
        result.end_line = getattr(info.node, 'end_lineno', 0) or 0

        for dup in dup_issues:
            if hasattr(info.node, 'name') and info.node.name in dup[2]:
                result.warnings.append(f'{dup[0]} ({dup[1]}): {dup[2]}')

        cross_func_issues = validator._check_cross_function(
            info.node,
            defined_functions=validator.defined_functions,
            builtins=validator.builtins,  # type: ignore[arg-type]  # FIX_54 ast-pos
            module_imports=validator.module_imports,
        )
        for issue in cross_func_issues:
            result.warnings.append(f'{issue[0]} ({issue[1]}): {issue[2]}')

        if hasattr(info.node, 'name') and info.node.name in func_line_ranges:
            start, end = func_line_ranges[info.node.name]
            if end is not None:
                comment_warnings = validator._analyze_comment_density_for_range(
                    source, start, end)
                result.warnings.extend(comment_warnings)

        if info.nesting_depth > 0:
            result.warnings.append(
                f'NAI-226 (LOW): Nested function at depth {info.nesting_depth}')  # A1 renumber: was NAI-102 (detection NAI-102 = docstring mismatch)

        results.append(result)

    for lambda_info in collector.lambdas:
        lambda_result = validator.validate_lambda(lambda_info, species=_sp)
        lambda_result.line = getattr(lambda_info.node, 'lineno', 0) or 0
        if lambda_result.warnings or not lambda_result.passed:
            results.append(lambda_result)

    for comp_info in collector.comprehensions:
        comp_issue = validator.validate_comprehension(comp_info)
        if comp_issue and results:
            results[0].warnings.append(
                f'{comp_issue[0]} ({comp_issue[1]}): {comp_issue[2]}')

    # NAI-227 (was NAI-103): EXCISED cut 2 (2026-09-05) — `len(lambdas) > <a config-valued lambda ceiling (10)>` was a
    # magnitude gate the syntax census cannot see; the COUNT is published whenever lambdas exist.
    if collector.lambdas and results:
        results[0].warnings.append(f'NAI-227: lambda_count={len(collector.lambdas)}')  # A1 renumber: was NAI-103 (detection NAI-103 = inverted boolean)

    # cut 3 batch 5 addendum (owner, 2026-09-06): lexical file role published as a module-level fact (see _LEXICAL_FILE_ROLES);
    # this is the directory path — the in-memory path (_validate_ast) carries the same line. Emits, never gates.
    _role = _LEXICAL_FILE_ROLES.get(Path(filepath).name)
    if _role:
        if results:
            results[0].warnings.append(f'FILE-ROLE (INFO): {_role}')
        else:  # an empty marker (no functions, no warnings) still gets its module row — never a silent file
            results.append(ValidationResult(function_name='<module>', function_type=FunctionType.UNKNOWN,
                                            passed=True, warnings=[f'FILE-ROLE (INFO): {_role}']))
    # A4 (2026-09-06): the species FACT rides on the module row — content reason + path prior, published, never a gate
    if _sp or _sp_prior:
        if results:
            results[0].warnings.append(_species_line(_sp, _sp_reason, _sp_prior))
        else:
            results.append(ValidationResult(function_name='<module>', function_type=FunctionType.UNKNOWN, passed=True,
                                            warnings=[_species_line(_sp, _sp_reason, _sp_prior)], species=_sp))

    type_hint_issues = validator._check_type_hint_issues(collector)
    if type_hint_issues and results:
        for issue in type_hint_issues:
            results[0].warnings.append(f'{issue[0]} ({issue[1]}): {issue[2]}')

    unused_issues = validator._find_unused_definitions(
        tree, collector.defined_symbols, collector.referenced_symbols)
    if unused_issues and results:
        for issue in unused_issues:
            results[0].warnings.append(f'{issue[0]} ({issue[1]}): {issue[2]}')

    cycle_issues = validator._check_call_graph_issues(collector.call_graph)
    if cycle_issues and results:
        for issue in cycle_issues:
            results[0].warnings.append(f'{issue[0]} ({issue[1]}): {issue[2]}')

    if filepath and filepath.name == '__init__.py':
        for node in ast.iter_child_nodes(tree):  # type: ignore[assignment]  # FIX_54 ast-pos
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != '__getattr__':
                continue
            has_import = any(
                isinstance(child, (ast.Import, ast.ImportFrom))
                for child in ast.walk(node)
            )
            raises_attr_error = any(
                isinstance(child, ast.Raise) and child.exc is not None
                and isinstance(child.exc, ast.Call)
                and isinstance(child.exc.func, ast.Name)
                and child.exc.func.id == 'AttributeError'
                for child in ast.walk(node)
            )
            severity = 'HIGH' if has_import else 'MEDIUM'
            msg = (
                f'NAI-205 ({severity}): Module-level __getattr__ in __init__.py '
                f'creates dynamic attribute dispatch — static analysis cannot '
                f'resolve attribute lookups on this package'
            )
            if has_import:
                msg += ' (contains dynamic imports — may simulate cyclic imports)'
            if not raises_attr_error:
                msg += ' (does not raise AttributeError on fallback — violates module protocol)'
            if results:
                results[0].warnings.append(msg)
            else:
                results.append(ValidationResult(
                    function_name='<module>',
                    function_type=FunctionType.UNKNOWN,
                    passed=True,
                    warnings=[msg],
                ))
            break

    _run_dead_function_scan(tree, collector, results, filepath)

    if _UTILS_AVAILABLE:
        for info in collector.functions:
            node = info.node
            if not hasattr(node, 'name'):
                continue
            func_name = node.name
            func_result = None
            for r in results:
                if r.function_name == func_name:
                    func_result = r
                    break
            if func_result is None:
                continue
            try:
                ux = _UtilsMetricsExtractor(node)
                um = ux.metrics
                if hasattr(um, 'assignment_sources') and um.assignment_sources:
                    dfg = _build_dfg(um.assignment_sources)
                    logger.debug('DFG for %s: %d edges', func_name, len(dfg))
                for var in _graph_find_unused(um):
                    func_result.warnings.append(
                        f"GRF-001 (MEDIUM): Graph analysis: variable '{var}' "
                        f"assigned but never used in '{func_name}'")
                    logger.debug('GRF-001: %s — unused assignment: %s', func_name, var)
                for var in _graph_find_undefined(um):
                    func_result.warnings.append(
                        f"GRF-002 (HIGH): Graph analysis: variable '{var}' "
                        f"used before definition in '{func_name}'")
                    logger.debug('GRF-002: %s — undefined use: %s', func_name, var)
                arith_issue = _check_arith_symmetry(node)
                if arith_issue is not None:
                    rule_id, severity, description = arith_issue
                    func_result.warnings.append(f'SYM-002 ({severity}): {description}')
                    logger.debug('SYM-002: %s — arithmetic symmetry: %s',
                                 func_name, arith_issue)
                for sym_issue in _check_suspicious_symmetry(node):
                    rule_id, severity, description = sym_issue
                    func_result.warnings.append(f'{rule_id} ({severity}): {description}')
                    logger.debug('%s: %s — suspicious symmetry: %s',
                                 rule_id, func_name, description)
                if _is_identity_chain(um):
                    func_result.warnings.append(
                        f"GRF-003 (HIGH): Identity chain detected — all data flow "
                        f"is copy/alias in '{func_name}'")
                    logger.debug('GRF-003: %s — identity chain detected via graph analysis',
                                 func_name)
            except Exception as e:
                logger.debug('utils.code_analysis per-function analysis failed for %s: %s',
                             func_name, e)

        try:
            norm_fp_map: Dict[str, List[str]] = defaultdict(list)
            for info in collector.functions:
                node = info.node
                if not hasattr(node, 'name'):
                    continue
                # I-101 (S6, 2026-09-29): the fingerprint is computed ONCE per function, here — the per-function
                # loop above computed the same deep-copying call again only for this debug line.
                try:
                    norm_fp = _normalized_fingerprint(node)
                except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                    logger.warning("reported, not swallowed (cut 3): %s: %r", '_validate_file_from_ast', _e)
                    continue
                logger.debug('NORM-FP: %s — normalized fingerprint: %s',
                             node.name, norm_fp[:16])
                norm_fp_map[norm_fp].append(node.name)
            strict_dup_issues = _check_dup_strict(dict(norm_fp_map))
            for dup_issue in strict_dup_issues:
                rule_id, severity, description = dup_issue
                if results:
                    results[0].warnings.append(f'{rule_id} ({severity}): {description}')
                logger.debug('%s: strict duplicate: %s', rule_id, description)
        except Exception as e:
            logger.debug('check_duplicate_functions_strict failed: %s', e)

    signatures_issues = validator.scan_source_signatures(source)
    if signatures_issues and results:
        for sig_name, severity, description, line_num in signatures_issues:
            if sig_name in _SIG_CONTEXTUAL_STUBS:
                continue  # 2026-09-05: a regex cannot see @overload / Protocol / ABC; NAI-004/120/214 can
            pattern_tuple = [
                f'SIG-{sig_name}', 'CRITICAL', f'{description} [line {line_num}]',
            ]
            # Attribute the signatures infraction to the function that CONTAINS the
            # signatures line, not blindly to results[0] (Phase-5 mis-attribution
            # fix: FRD candidates must attach to the offending function).
            target = None
            if line_num:
                containing = None
                for fname, (start, end) in func_line_ranges.items():
                    if end is not None and start <= line_num <= end:
                        containing = fname
                        break
                if containing is not None:
                    for r in results:
                        if r.function_name == containing:
                            target = r
                            break
            if target is None:
                # FIX_35 k (2026-09-15): a hit outside every def rides the `<module>` row when the file has one
                # (F-SIG-NOID: results[0] was whichever function came first — an arbitrary attribution).
                target = next((r for r in results if r.function_name == '<module>'), results[0])
            # Cut 2 (2026-09-05): a regex signature hit is CONTEXT, not a verdict — published on the
            # containing function; VerdictRanker treats SIG-* as context. Pre-ranker `passed = False` EXCISED.
            target.triggered_patterns.append(pattern_tuple)

    results = _rca_intra_file_sweep(results, collector, tree, validator)   # FIX_47: the validator renders the ranker's deciding observation

    for _r in results:
        if not _r.species and _r is results[0]:   # the module row carries the file's species; functions keep their own
            _r.species = _sp
    try:
        from .intent_claims import unbind_module as _unbind_module
        _unbind_module(tree)
    except Exception:
        pass
    return results, collector, fingerprints


# FIX-B (run 186, owner ruling 2026-09-28, miss M-1): the SIMILARITY family — rules whose evidence
# is that a function's structure RESEMBLES other structure (a fingerprint / hash / symmetry
# measurement), with no claim about what the function DOES. Identified from the emitters, not by
# name: noai utils' fingerprint trio NAI-228 (duplicate fingerprint), NAI-229 (structural symmetry),
# NAI-230 (normalized-fingerprint cluster — M-1's callee); `utils/code_analysis/duplicate.py`'s
# NAI-012 / NAI-231 (duplicate fingerprints, non-strict / strict); NAI-040 (hash-based duplicate
# subtrees) and NAI-155 (structural-duplication ratio). NOT in it: NAI-054 (a repeated statement
# runs twice — behaviour), NAI-175/177 (duplicate dict keys overwrite — behaviour), SYM-002
# (algebraic identity — behaviour), NAI-013 (literal progressions), NAI-114 (naming).
# A callee failed ONLY by this family is not a behavioural failure, so RCA-001 never chains off it.
_RCA_SIMILARITY_FAMILY = frozenset({
    "NAI-012", "NAI-040", "NAI-155", "NAI-228", "NAI-229", "NAI-230", "NAI-231"})


def _rca_behavioural_failure(r: ValidationResult) -> bool:
    """True when `r` failed on something other than the similarity family: the Ranker re-decides
    the row's observations with the family removed; a row whose failure needs the family passes.
    A failed row without an observation list (strict / module paths) stays a failure."""
    if r.passed:
        return False
    obs = [o for o in (r.triggered_patterns or []) if isinstance(o, dict)]
    if not any(str(o.get("tag", "")) in _RCA_SIMILARITY_FAMILY for o in obs):
        return True
    rest = [o for o in obs if str(o.get("tag", "")) not in _RCA_SIMILARITY_FAMILY]
    if not rest:
        return False
    return not _VR.decide("observations", rest, species=getattr(r, "species", "") or "").passed


def _rca_closure_reads_enclosing(inner: ast.AST, outer: ast.AST) -> bool:
    """True when nested def `inner` loads a name bound in `outer`'s own scope (a param or a local
    assignment) that `inner` does not bind itself — a closure over the caller (miss M-3)."""
    def _bound(fn: ast.AST) -> Set[str]:
        a = fn.args  # type: ignore[attr-defined]
        names = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
        names |= {x.arg for x in (a.vararg, a.kwarg) if x is not None}
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                names.add(n.id)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not fn:
                names.add(n.name)
        return names
    outer_bound = _bound(outer) - {inner.name}  # type: ignore[attr-defined]
    inner_bound = _bound(inner)
    loads = {n.id for n in ast.walk(inner) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return bool((loads - inner_bound) & outer_bound)


def _rca_intra_file_sweep(
    results: List[ValidationResult],
    collector: FunctionCollector,
    tree: ast.AST,
    validator: 'NoAIMathValidator',
) -> List[ValidationResult]:
    """The split-fake fact, as EVIDENCE INTO THE RANKER (FIX_47, owner Q7 2026-09-15).

    For each function that PASSED: if it calls a function that FAILED in this file and does
    not forward its own params to that callee, the sweep emits an RCA-001 OBSERVATION on that
    row — `{tag, line, description, callee, magnitude}`, the shape FIX_18's HR deficits and
    FIX_17's NAI-230 use — and re-runs the Ranker's `observations` stage over the row's whole
    observation set. THE RANKER decides; this function measures. Before FIX_47 the site
    called the `rule` stage and rewrote the row after its verdict — a post-verdict override,
    which THE FLOWCHART's doctrine (owner 2026-09-09: the Ranker is the last step of every
    line that ends in a decision) does not allow.

    The sweep reads the UN-NORMALIZED tree: `utils.code_analysis.fingerprint.normalized_fingerprint`
    no longer renames the caller's identifiers in place (I-03, closed in that module).
    """
    # FIX-B (run 186, owner ruling 2026-09-28; misses M-1 six, M-3 arrow): every def is keyed by
    # (class-qualified name, line), never by bare name — `A.run` and `B.run` (or a method and a
    # module function sharing a name) no longer collide as caller or callee. A bare-name call
    # `foo()` resolves ONLY to a def the caller itself encloses, else to a MODULE-LEVEL `foo`;
    # a method is never reachable by a bare name.
    infos: Dict[Tuple[str, int], Any] = {}
    for info in collector.functions:
        node = info.node
        if hasattr(node, 'name') and hasattr(node, 'lineno'):
            infos[(node.name, node.lineno)] = info

    def _qual(info: Any) -> str:
        return f"{info.parent_class}.{info.node.name}" if info.parent_class else info.node.name

    def _own_defs(fn: ast.AST) -> List[Any]:
        """The defs directly in `fn`'s own scope (not inside a nested def or class)."""
        out: List[Any] = []
        stack: List[ast.AST] = list(ast.iter_child_nodes(fn))
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append(n)
                continue
            if isinstance(n, (ast.ClassDef, ast.Lambda)):
                continue
            stack.extend(ast.iter_child_nodes(n))
        return out

    row_of: Dict[Tuple[str, int], ValidationResult] = {
        (r.function_name, getattr(r, 'line', 0) or 0): r for r in results}
    failed_keys: Set[Tuple[str, int]] = set()
    for (fname, fline), info in infos.items():
        fr = row_of.get((fname, fline))
        if fr is not None and _rca_behavioural_failure(fr):
            failed_keys.add((_qual(info), fline))
    if not failed_keys:
        return results
    module_level: Dict[str, Tuple[str, int]] = {
        info.node.name: (_qual(info), ln) for (nm, ln), info in infos.items()
        if not info.parent_class and info.nesting_depth == 0}

    for idx, r in enumerate(list(results)):
        if r.function_name.startswith('<'):
            continue
        if not r.passed:
            continue
        caller = infos.get((r.function_name, getattr(r, 'line', 0) or 0))
        if caller is None:
            continue
        node = caller.node
        func_name = r.function_name
        raw_params = {arg.arg for arg in node.args.args}
        # (1) `self` / `cls` are the receiver, not data the caller was handed to forward.
        params = raw_params - {'self', 'cls'}
        if not params:
            continue
        own = {d.name: d for d in _own_defs(node)}
        called_failures: Set[str] = set()
        for child in ast.walk(node):
            if not (isinstance(child, ast.Call) and isinstance(child.func, ast.Name)):
                continue
            cname = child.func.id
            if cname in own:
                target = infos.get((cname, own[cname].lineno))
                key = (_qual(target), own[cname].lineno) if target is not None else None
                # (4) a NESTED closure that reads the enclosing scope already sees the caller's
                # data — it is part of the caller, not a callee the params were withheld from.
                if key in failed_keys and not _rca_closure_reads_enclosing(own[cname], node):
                    called_failures.add(cname)
            elif module_level.get(cname) in failed_keys:
                called_failures.add(cname)
        if not called_failures:
            continue

        body_module = ast.Module(body=node.body, type_ignores=[])
        read_names: Set[str] = set()
        for child in ast.walk(body_module):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                read_names.add(child.id)

        params_used = params & read_names
        if params_used:
            forwarded = False
            for child in ast.walk(body_module):
                if not isinstance(child, ast.Call):
                    continue
                if not isinstance(child.func, ast.Name):
                    continue
                if child.func.id not in called_failures:
                    continue
                call_arg_names: Set[str] = set()
                for arg in list(child.args) + [kw.value for kw in child.keywords]:
                    # (2) `opts.path` forwards `opts`: the root name of an attribute chain counts, bare
                    # names as before — but only a REAL param's root; `self.cache` forwards nothing,
                    # since lever 1 already dropped the receiver (fpB2, M-new-2).
                    while isinstance(arg, ast.Attribute):
                        arg = arg.value
                    if isinstance(arg, ast.Name):
                        call_arg_names.add(arg.id)
                if params & call_arg_names:
                    forwarded = True
                    break
            if forwarded:
                continue

        # Q4 (session 8, run 160): RCA-001's premise is that the caller DROPS its own parameters —
        # it reads them, then hands the work to a failed callee that never sees them, so the caller's
        # pass is a split fake. A caller that RETURNS one of its own parameters has dropped nothing:
        # that parameter IS its answer. `click.globals.resolve_color_default` was failed for not
        # forwarding `color` to `get_current_context(silent=True)` while its first statement is
        # `if color is not None: return color` — a category error, not a finding. The test is the
        # premise itself, not a name list: a bare `return <param>` anywhere in the caller's own scope.
        _returns_own_param = any(
            isinstance(child, ast.Return) and isinstance(child.value, ast.Name)
            and child.value.id in params
            for child in ast.walk(body_module))
        if _returns_own_param:
            logger.debug("RCA sweep: %s returns one of %s itself — nothing dropped, no RCA-001",
                         func_name, sorted(params))
            continue

        failed_callee = sorted(called_failures)[0]
        _msg = f"Calls failed function '{failed_callee}' without forwarding params {sorted(params)}"
        # FIX_47: the fact, as an observation — never a verdict at this site.
        _obs = {
            "tag": "RCA-001",
            "line": r.line,
            "description": _msg,
            "callee": failed_callee,
            "magnitude": len(called_failures),   # how many failed callees this caller delegates to
        }
        _all_obs = list(r.triggered_patterns or []) + [_obs]
        _species = getattr(r, "species", "") or ""
        _v = _VR.decide("observations", _all_obs, species=_species)
        _rendered = validator._format_observation(_obs)
        logger.info(
            'RCA sweep: %s calls failed function %s without forwarding params — RCA-001 observation '
            'to the ranker (verdict: %s)', func_name,
            failed_callee, "withheld" if _v.withheld else ("fail" if not _v.passed else "pass"))
        results[idx] = ValidationResult(
            function_name=func_name,
            function_type=r.function_type,
            passed=_v.passed,
            # the LAYER is the ranker's too (it names HARD_REQUIREMENTS for an HR-0* deciding
            # observation, AI_FAKE_DETECTOR otherwise) — never a constant written at this site
            failure_layer=(ValidationLayer[_v.layer] if (not _v.passed and _v.layer) else None),
            failure_reason=(validator._format_observation(_v.deciding)
                            if (not _v.passed and isinstance(_v.deciding, dict)) else _v.reason),
            verdict_source=_v.source,
            warnings=r.warnings + [_rendered + (f" [withheld: {_v.withheld}]" if _v.withheld else "")],
            metrics=r.metrics,
            file_path=r.file_path,
            line=r.line,
            end_line=getattr(r, "end_line", 0) or 0,
            triggered_patterns=_all_obs,
            species=_species, withheld=(_v.withheld or getattr(r, "withheld", "") or ""),
        )

    return results


async def validate_string_async(
    validator: 'NoAIMathValidator',
    source: str,
    file_path: str = '<string>',
) -> StringValidationResult:
    """
    Validate code from a string (async, no disk I/O).
    Delegates to sync implementation since all operations are in-memory.
    """
    return _validate_string_impl(validator, source, file_path)


def validate_string(
    validator: 'NoAIMathValidator',
    source: str,
    file_path: str = '<string>',
) -> StringValidationResult:
    """
    In-Memory Entry Point: Validates code string without disk I/O.
    Crucial for FixerChain retry loops - runs validation in milliseconds.
    """
    return _validate_string_impl(validator, source, file_path)


def _validate_string_impl(
    validator: 'NoAIMathValidator',
    source: str,
    file_path: str,
) -> StringValidationResult:
    """Shared string validation implementation (sync, no I/O)."""
    logger.debug('Validating string source (%d chars)', len(source))

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        logger.warning('Syntax error in string source at line %s: %s', e.lineno, e.msg)
        return StringValidationResult(
            passed=False,
            failure_reason=f'Syntax Error: {e.msg} at line {e.lineno}',
            results=[],
        )

    results = _validate_ast(validator, tree, source, file_path)

    critical_failures = [r for r in results if not r.passed]
    if critical_failures:
        first_failure = critical_failures[0]
        logger.info('Validation failed: %s', first_failure.failure_reason)
        return StringValidationResult(
            passed=False,
            failure_reason=first_failure.failure_reason or 'Validation failed',
            results=results,
        )

    all_warnings: List[str] = []
    for r in results:
        all_warnings.extend(r.warnings)
    if all_warnings:
        logger.debug('Validation passed with %d warnings', len(all_warnings))

    return StringValidationResult(
        passed=True,
        failure_reason=None,
        results=results,
        warnings=all_warnings,
    )


def _validate_ast(
    validator: 'NoAIMathValidator',
    tree: ast.AST,
    source: str,
    file_path: str,
) -> List[ValidationResult]:
    """Full AST validation for in-memory source."""
    results: List[ValidationResult] = []
    _sp, _sp_reason, _sp_prior = _file_species(tree, file_path)   # A4 (2026-09-06): once per file, same fact as the directory path
    _nr = _noreturn_names(tree)   # IG-6
    _ma = _module_attr_names(tree); _enc = _enclosing_names(tree)   # IG-10 / IG-9

    collector = FunctionCollector(source)
    collector.visit(tree)

    validator.module_symbols = collector.defined_symbols
    validator.module_imports = collector.imports
    validator.defined_functions = {
        f.node.name for f in collector.functions if hasattr(f.node, 'name')
    }
    validator.symbol_references = collector.referenced_symbols

    import_warnings = validator._validate_imports(collector)
    if import_warnings:
        # A1 (2026-09-06): the import helper emits NAI-IM01, whose id shape `\d{3}` never matched — every import verdict
        # was decided under the bare id "IMPORT" (no table row could ever name it). The id is now extracted as written.
        _m = _re.match(r'([A-Z]{2,4}-[A-Z0-9]{2,5})', import_warnings[0])
        _v = _VR.decide("rule", (_m.group(1) if _m else "NAI-IM01", "HIGH", import_warnings[0], "HARD_REQUIREMENTS"), species=_sp)  # cut 2c: routed via VerdictRanker
        results.append(ValidationResult(
            function_name='<module>',
            function_type=FunctionType.UNKNOWN,
            passed=_v.passed,
            failure_layer=ValidationLayer.HARD_REQUIREMENTS if not _v.passed else None,
            failure_reason=_v.reason,
            verdict_source=_v.source,
            warnings=import_warnings,
            species=_sp, withheld=_v.withheld or "",
        ))

    if not collector.functions:
        results.append(ValidationResult(
            function_name='<module>',
            function_type=FunctionType.UNKNOWN,
            passed=True,
            warnings=['No functions found in module.']
                     + ([f'FILE-ROLE (INFO): {_r}'] if (_r := _LEXICAL_FILE_ROLES.get(Path(file_path).name)) else [])  # cut 3 batch 5 addendum: the role rides on the empty-module row
                     + ([_species_line(_sp, _sp_reason, _sp_prior)] if (_sp or _sp_prior) else []),
            species=_sp,
        ))
        return results

    for info in collector.functions:
        result = validator.validate_function(
            info.node,
            class_context=info.class_context,
            decorators=info.decorators,
            class_bases=getattr(info, 'parent_bases', None),
            source_segment=info.source_segment,
            imported_names=collector.imported_names,
            module_level_names=collector.defined_symbols,
            species=_function_species(_sp, info.node) if not info.class_context or not str(info.class_context).startswith('Test') else _sp,
            noreturn_names=_nr,
            enclosing_names=_enc.get(id(info.node), set()),
            module_attr_names=_ma,
        )
        result.line = getattr(info.node, 'lineno', 0) or 0
        result.end_line = getattr(info.node, 'end_lineno', 0) or 0

        cross_func_issues = validator._check_cross_function(
            info.node,
            defined_functions=validator.defined_functions,
            builtins=validator.builtins,  # type: ignore[arg-type]  # FIX_54 ast-pos
            module_imports=validator.module_imports,
        )
        for issue in cross_func_issues:
            result.warnings.append(f'{issue[0]} ({issue[1]}): {issue[2]}')

        if info.nesting_depth > 0:
            result.warnings.append(
                f'NAI-226 (LOW): Nested function at depth {info.nesting_depth}')  # A1 renumber: was NAI-102 (detection NAI-102 = docstring mismatch)

        results.append(result)

    for lambda_info in collector.lambdas:
        lambda_result = validator.validate_lambda(lambda_info, species=_sp)
        lambda_result.line = getattr(lambda_info.node, 'lineno', 0) or 0
        if lambda_result.warnings or not lambda_result.passed:
            results.append(lambda_result)

    for comp_info in collector.comprehensions:
        comp_issue = validator.validate_comprehension(comp_info)
        if comp_issue and results:
            results[0].warnings.append(
                f'{comp_issue[0]} ({comp_issue[1]}): {comp_issue[2]}')

    # NAI-227 (was NAI-103): EXCISED cut 2 (2026-09-05) — config-valued magnitude gate (a lambda ceiling of 10) replaced by the count
    if collector.lambdas and results:
        results[0].warnings.append(f'NAI-227: lambda_count={len(collector.lambdas)}')  # A1 renumber: was NAI-103 (detection NAI-103 = inverted boolean)

    # cut 3 batch 5 addendum (owner, 2026-09-06): names the LANGUAGE or its tools define are lexical facts, not heuristics.
    # The skip went (`_SKIP_NAMES`); per the standing ruling (`_name` = lexical prior: the skip goes, the observation is
    # emitted) the role is PUBLISHED as a module-level fact. It never mutes anything.
    _role = _LEXICAL_FILE_ROLES.get(Path(file_path).name)
    if _role and results:
        results[0].warnings.append(f'FILE-ROLE (INFO): {_role}')
    if (_sp or _sp_prior) and results:
        results[0].warnings.append(_species_line(_sp, _sp_reason, _sp_prior))

    signatures_issues = validator.scan_source_signatures(source)
    if signatures_issues and results:
        for sig_name, severity, description, line_num in signatures_issues:
            if sig_name in _SIG_CONTEXTUAL_STUBS:
                continue  # 2026-09-05: a regex cannot see @overload / Protocol / ABC; NAI-004/120/214 can
            pattern_tuple = [
                f'SIG-{sig_name}', 'CRITICAL', f'{description} [line {line_num}]',
            ]
            # FIX_35 k (2026-09-15): the sync path — the same `<module>` attribution as the live path above
            target = next((r for r in results if r.function_name == '<module>'), results[0])
            # Cut 2 (2026-09-05): SIG-* is context, never a verdict (see above). `passed = False` EXCISED.
            target.triggered_patterns.append(pattern_tuple)

    # I-102 (S6, 2026-09-29): the sync path runs the same RCA-001 sweep as `_validate_file_from_ast`, at the same
    # step (after the signatures, before the species fill) — before this the in-memory path could never decide RCA-001.
    results = _rca_intra_file_sweep(results, collector, tree, validator)

    for _r in results:  # type: ignore[assignment]  # FIX_54 ast-pos
        if not _r.species and _r is results[0]:  # type: ignore[union-attr]  # the module row; functions keep their own
            _r.species = _sp  # type: ignore[union-attr]  # FIX_54 ast-pos
    return results


def _is_stub_method_body(body: List[ast.stmt]) -> bool:
    """NAI-214 fact (body-shape stage, 2026-09-06): a stub method body carries no behavior of its
    own -- at most a leading docstring, then either nothing or a single `pass` / `...` / `raise
    NotImplementedError(...)`. Any other statement (an assignment, a real `return`, a loop, a call
    with a side effect, an f-string built from `self`, ...) is a concrete implementation, whatever
    decorator the method wears. A class that has such a method is not a pure ABC stub, even when it
    also declares @abstractmethod members (the slice-2 `Sink` twins: `write` is a docstring-only
    @abstractmethod stub, `describe` is a real concrete method -- Sink is not architecture theatre)."""
    stmts = list(body)
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
            and isinstance(stmts[0].value.value, str):
        stmts = stmts[1:]
    if not stmts:
        return True
    if len(stmts) != 1:
        return False
    stmt = stmts[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
        return True
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        exc = stmt.exc
        callee = exc.func if isinstance(exc, ast.Call) else exc
        return isinstance(callee, ast.Name) and callee.id == 'NotImplementedError'
    return False


def _check_abstract_shells(
    file_trees: Dict[str, Tuple[Path, ast.AST]],
    scope: str,
) -> List[ValidationResult]:
    """NAI-214 abstract_shell (SPECIES_DICT stubs.abstract_shell; plan item 4,
    2026-09-05): an ABC (`ABC` base or `metaclass=ABCMeta`) carrying at least one
    @abstractmethod that NO class in `file_trees` subclasses — architecture
    theatre when never implemented. Needs every tree at once because the
    subclass may live in another file; `scope` says what was searched so the
    finding states exactly what was measured. Before this check the shell's
    abstract methods were judged one by one and the class itself never was."""
    bases_seen: Set[str] = set()
    candidates: List[Tuple[str, str, int, List[str]]] = []
    for rel, (_pyfile, tree) in file_trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [base_name(b) for b in node.bases]
            bases_seen.update(bases)
            is_abc = 'ABC' in bases or any(
                kw.arg == 'metaclass' and base_name(kw.value) == 'ABCMeta' for kw in node.keywords)
            abstract = [m.name for m in node.body
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and any(base_name(d) == 'abstractmethod' for d in m.decorator_list)]
            # NAI-214 fact (2026-09-06): a non-abstract method with a real (non-stub) body means
            # this ABC already does something -- it is not a pure, never-implemented shell. See
            # _is_stub_method_body.
            has_concrete_method = any(
                isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not any(base_name(d) == 'abstractmethod' for d in m.decorator_list)
                and not _is_stub_method_body(m.body)
                for m in node.body)
            if is_abc and abstract and not has_concrete_method:
                candidates.append((rel, node.name, node.lineno, abstract))
    results: List[ValidationResult] = []
    for rel, name, line, abstract in candidates:
        if name in bases_seen:
            continue
        msg = (f"Abstract shell '{name}' at line {line} — ABC with abstract "
               f"{', '.join(abstract)} and no concrete subclass in {scope}")
        _sp214 = _file_species(file_trees[rel][1], rel)[0] if rel in file_trees else ''
        _v = _VR.decide("rule", ("NAI-214", "HIGH", msg, "AI_FAKE_DETECTOR"), species=_sp214)  # cut 2c (2026-09-06): routed via VerdictRanker
        results.append(ValidationResult(
            function_name=f'<class {name}>',
            function_type=FunctionType.UNKNOWN,
            passed=_v.passed,
            failure_layer=ValidationLayer.AI_FAKE_DETECTOR if not _v.passed else None,
            failure_reason=_v.reason,
            verdict_source=_v.source,
            species=_sp214, withheld=_v.withheld or "",
            triggered_patterns=[{'tag': 'NAI-214', 'line': line, 'context': True, 'withheld': _v.withheld, 'msg': msg}] if _v.withheld else [['NAI-214', 'HIGH', msg]],
            warnings=[f'NAI-214 (HIGH): {msg}'],
            file_path=rel,
            line=line,
        ))
    return results




def _dunder_counts_by_dir(dirpath: Path, trees_by_rel: Dict[str, ast.AST]) -> Dict[str, Dict[str, int]]:
    """FIX_34 (b) (2026-09-10): the NAI-058 fact per directory subtree — every dunder-shaped name's
    occurrence count — from the trees parsed ONCE up front (THE ASYNC LAW: a whole-set fact is computed once,
    never inside per-item work). A file's counts join every ancestor directory from its own up to the target
    root, so `str(file.resolve().parent)` looks up the same subtree fact the old per-dirpath walk produced —
    scoped to the discovered list instead of a private rglob, and with no process-lifetime cache."""
    by_dir: Dict[str, Dict[str, int]] = {}
    root = dirpath.resolve()
    for rel, tree in trees_by_rel.items():
        counts = _dunder_names_in_tree(tree)
        if not counts:
            continue
        d = (dirpath / rel).resolve().parent
        while True:
            bucket = by_dir.setdefault(str(d), {})
            for name, n in counts.items():
                bucket[name] = bucket.get(name, 0) + n
            if d == root or d.parent == d:
                break
            d = d.parent
    return by_dir

async def validate_directory_async(
    validator: 'NoAIMathValidator',
    dirpath: Path,
    max_files: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    whitelist: Optional[Set[str]] = None,
    files: Optional[List[Path]] = None,
) -> Tuple[List[ValidationResult], Dict[str, Any]]:
    """Validate all Python files in a directory with cross-file analysis (async).

    files: when given (the daemon's discovered, whitelist-filtered list) it is
    validated as-is — cross-file analysis included — and no directory walk
    happens (owner 2026-09-05).

    whitelist entries are "relpath::qualname" (function-level) or "relpath::*"
    (whole-file). Detection always runs in full; a matching entry forces the
    result to passed=True with a WHITELISTED warning appended.
    """
    validator.parse_errors = []
    validator._import_graph = defaultdict(set)

    global_symbols: Dict[str, Set[str]] = {}
    global_imports: Dict[str, Set[str]] = {}
    all_defined: Set[str] = set()
    all_references: Set[str] = set()
    all_fingerprints: Dict[str, List[Tuple[str, str, int]]] = {}
    global_call_graph: Dict[str, Set[str]] = defaultdict(set)

    effective_max = max_files or validator.config.get('max_files')

    if files is not None:
        all_py = [p for p in files if not p.is_symlink()]
        logger.info('validate_directory_async: validating the discovered list (%d files, no walk)', len(all_py))
    elif _RCA_WALK_AVAILABLE:
        # FIX_14 / FIX_15 (2026-09-10): the ONE walk — whitelist, engine hard-skips, containment;
        # no substring table, no private rglob.
        all_py = await asyncio.to_thread(_live_py_files, dirpath)
        logger.info('validate_directory_async: the ONE walk (scan_scope.iter_live_py) — %d files', len(all_py))
    else:
        # Unified walk policy (R8): single rglob, symlinks skipped — only when rca_main is absent.
        all_py = await asyncio.to_thread(
            lambda: [p for p in dirpath.rglob('*.py') if not p.is_symlink()])
        logger.debug('rca_main.constants not available: R8 walk without the scope')

    py_files = all_py[:effective_max] if effective_max else all_py
    # FIX_34 (2026-09-10): the module map takes the discovered list — no second walk of the tree.
    await validator._build_module_map(dirpath, files=py_files)
    # IG-10b (2026-09-06): every def / attribute name ANY module of this project defines — `node.find_all(...)` (jinja2.nodes),
    # `ctx.push()` (flask.ctx), `Timeout.clone()` (urllib3.util) are project facts, not hallucinations. One parse per file, up front.
    project_attr_names: Set[str] = set()
    _proj_trees_by_rel: Dict[str, ast.AST] = {}
    for _pf in py_files:
        try:
            _proj_rel = str(_pf.relative_to(dirpath))
            _proj_tree = ast.parse(read_source(_pf), filename=str(_pf))   # A1: same reader as the per-file pass
        except (SyntaxError, ValueError, OSError):
            continue
        _proj_trees_by_rel[_proj_rel] = _proj_tree
        project_attr_names |= _module_attr_names(_proj_tree)
    # IG-13 (2026-09-06): a name defined by a wildcard import (`from .numeric import *`, numpy) — or forwarded
    # to one through a further wildcard (`numpy.strings` -> `numpy._core.strings`) — is a project fact too:
    # resolve the wildcard's target module WITHIN the scanned tree and take its top-level definitions / __all__.
    _proj_dotted_to_rel: Dict[str, str] = {_module_dotted_name(_r): _r for _r in _proj_trees_by_rel}
    for _proj_rel, _proj_tree in _proj_trees_by_rel.items():  # type: ignore[assignment]  # FIX_54 ast-pos
        for _node in ast.walk(_proj_tree):
            if isinstance(_node, ast.ImportFrom) and any(a.name == '*' for a in _node.names):
                _target = _resolve_import_target(_proj_rel, _node.level, _node.module)
                if _target:
                    project_attr_names |= _wildcard_export_names(_target, _proj_dotted_to_rel, _proj_trees_by_rel, set())
    # FIX_34 (b) (2026-09-10, THE ASYNC LAW): the NAI-058 whole-set fact — every dunder-shaped name's
    # occurrence count per directory subtree — computed ONCE here from the trees parsed once above, never
    # inside per-function work; scoped to the discovered list (no private rglob, no module cache).
    validator._dunder_counts_by_dir = _dunder_counts_by_dir(dirpath, _proj_trees_by_rel)  # type: ignore[attr-defined]  # FIX_54 ast-pos
    # Owner 2026-10-08 (wave 3 #7, NAI-251): split-brain twins are a project fact — measured once here from the trees
    # parsed once above; the per-file pass merges each file's share. A failure is reported, never silent, and never
    # stops the scan.
    try:
        from .split_brain import observations as _split_brain_observations
        validator._split_brain_obs = _split_brain_observations(_proj_trees_by_rel, dirpath)  # type: ignore[attr-defined]
    except Exception as _sbe:
        validator._split_brain_obs = {}  # type: ignore[attr-defined]
        logger.warning("split-brain probe failed on %s: %r", dirpath, _sbe)
    try:   # owner 2026-10-08, wave 3 #6 (NAI-252): phantom wiring — a project fact, merged per file like NAI-251
        from .phantom_wiring import observations as _phantom_observations
        for _pf_path, _pf_obs in _phantom_observations(_proj_trees_by_rel, dirpath).items():
            _bucket = validator._split_brain_obs.setdefault(_pf_path, {})  # type: ignore[attr-defined]
            for _k, _v in _pf_obs.items():
                _bucket.setdefault(_k, []).extend(_v)
    except Exception as _pwe:
        logger.warning("phantom-wiring probe failed on %s: %r", dirpath, _pwe)
    try:   # owner 2026-10-08 (NAI-008 option B): an inline import that dodges a load-time import cycle — merged like NAI-252
        from .import_cycles import observations as _cycle_observations
        for _ic_path, _ic_obs in _cycle_observations(_proj_trees_by_rel, dirpath).items():
            _bucket = validator._split_brain_obs.setdefault(_ic_path, {})  # type: ignore[attr-defined]
            for _k, _v in _ic_obs.items():
                _bucket.setdefault(_k, []).extend(_v)
    except Exception as _ice:
        logger.warning("import-cycle probe failed on %s: %r", dirpath, _ice)
    try:   # M-143 (2026-10-08): NAI-237 test_literal when the asserting test lives in another file (tests/)
        from .utils import test_gaming_237_project_observations as _tg_observations
        for _tg_path, _tg_obs in _tg_observations(_proj_trees_by_rel, dirpath).items():
            _bucket = validator._split_brain_obs.setdefault(_tg_path, {})  # type: ignore[attr-defined]
            for _k, _v in _tg_obs.items():
                _bucket.setdefault(_k, []).extend(_v)
    except Exception as _tge:
        logger.warning("cross-file test-literal probe failed on %s: %r", dirpath, _tge)
    try:   # M-146 (2026-10-08): empty methods on a base class some other class inherits — the hook, not a placeholder
        from .hook_stubs import observations as _hook_observations
        for _hk_path, _hk_obs in _hook_observations(_proj_trees_by_rel, dirpath).items():
            _bucket = validator._split_brain_obs.setdefault(_hk_path, {})  # type: ignore[attr-defined]
            for _k, _v in _hk_obs.items():
                _bucket.setdefault(_k, []).extend(_v)
    except Exception as _hke:
        logger.warning("hook-stub probe failed on %s: %r", dirpath, _hke)
    try:   # M-147 (2026-10-08): NAI-237 test_input — a canned return keyed on a literal only a test feeds in
        from .test_inputs import observations as _ti_observations
        for _ti_path, _ti_obs in _ti_observations(_proj_trees_by_rel, dirpath).items():
            _bucket = validator._split_brain_obs.setdefault(_ti_path, {})  # type: ignore[attr-defined]
            for _k, _v in _ti_obs.items():
                _bucket.setdefault(_k, []).extend(_v)
    except Exception as _tie:
        logger.warning("test-input probe failed on %s: %r", dirpath, _tie)
    try:   # M-150 (2026-10-08, owner: run the target's functions at scan time): NAI-254 — the target's own failing tests
        from .runtime_probes import observations as _runtime_observations   # NAI-254 + runtime probes, one suite run
        for _tb_path, _tb_obs in _runtime_observations(_proj_trees_by_rel, dirpath).items():
            _bucket = validator._split_brain_obs.setdefault(_tb_path, {})  # type: ignore[attr-defined]
            for _k, _v in _tb_obs.items():
                _bucket.setdefault(_k, []).extend(_v)
    except Exception as _tbe:
        logger.warning("test-blame probe failed on %s: %r", dirpath, _tbe)
    del _proj_trees_by_rel

    results: List[ValidationResult] = []
    vuln_issues: List[Dict[str, Any]] = []
    file_trees: Dict[str, Tuple[Path, ast.AST]] = {}

    show_progress = validator.config.get('show_progress', True) and TQDM_AVAILABLE
    total_files = len(py_files)
    # FIX_34 (a) (2026-09-10, THE ASYNC LAW): the per-file pass is a gathered batch under a semaphore, not a
    # sequential await of each file. Every file returns its OWN evidence (results, tree, the collector's facts,
    # fingerprints, import edges, vuln issues, parse errors) and the merge below runs in py_files order — the
    # dump stays byte-identical. The AST work per file stays sync (one piece of evidence per file); the awaits
    # are the reads. The width is plumbing (the machine's cores), never a verdict.
    _concurrency = os.cpu_count() or 4
    _sem = asyncio.Semaphore(_concurrency)
    _done = 0
    _bar = tqdm(total=total_files, desc='Validating') if show_progress else None
    _t_files = time.perf_counter()

    async def _one(pyfile: Path) -> Dict[str, Any]:
        file_key_rel = str(pyfile.relative_to(dirpath))
        out: Dict[str, Any] = {'rel': file_key_rel, 'path': pyfile, 'results': [], 'parse_errors': [],
                               'tree': None, 'collector': None, 'fps': [], 'edges': [], 'vulns': []}
        try:
            try:
                if _MAX_FILE_BYTES is not None and pyfile.stat().st_size > _MAX_FILE_BYTES:
                    out['parse_errors'].append(ParseError(
                        filepath=pyfile,
                        error_type='FileTooLarge',
                        message=f'File exceeds {_MAX_FILE_BYTES} byte walk-policy cap',
                    ))
                    return out
            except OSError as e:
                out['parse_errors'].append(ParseError(
                    filepath=pyfile,
                    error_type='OSError',
                    message=str(e),
                ))
                return out

            try:
                source = await asyncio.to_thread(read_source, pyfile)   # A1 (Q-H3b-4/5): BOM / PEP 263 cookie honoured
            except (IOError, OSError) as e:
                logger.error('Cannot read file %s: %s', pyfile, e)
                out['results'].append(ValidationResult(
                    function_name='<file>',
                    function_type=FunctionType.UNKNOWN,
                    passed=False,
                    failure_layer=ValidationLayer.HARD_REQUIREMENTS,
                    failure_reason=f'Cannot read file: {e}',
                    file_path=file_key_rel,
                ))
                return out
            except (SyntaxError, UnicodeDecodeError) as e:   # A1: undecodable source — a counted <file> row, never a silent drop
                # Python's own verdict on a bad coding cookie / undecodable bytes is SyntaxError, so the id is
                # NAI-208 and the verdict is the ranker's (cut 2c); the reason says the rules never ran on it.
                logger.warning('could not decode %s: %s — NOT MEASURED', file_key_rel, e)
                out['parse_errors'].append(ParseError(filepath=pyfile, error_type='DecodeError', message=str(e)))
                _v = _VR.decide("rule", ("NAI-208", "HIGH", f'could not decode {file_key_rel}: {e} — NOT MEASURED', "HARD_REQUIREMENTS"))
                out['results'].append(ValidationResult(
                    function_name='<file>',
                    function_type=FunctionType.UNKNOWN,
                    passed=_v.passed,
                    failure_layer=ValidationLayer.HARD_REQUIREMENTS if not _v.passed else None,
                    failure_reason=_v.reason,
                    verdict_source=_v.source,
                    file_path=file_key_rel,
                    warnings=[f'NAI-208 (HIGH): File could not be decoded — {e} — NOT MEASURED'],
                ))
                return out

            try:
                tree = ast.parse(source, filename=str(pyfile))
            except SyntaxError as e:
                logger.warning('Syntax error in %s:%s: %s', pyfile.name, e.lineno, e.msg)
                out['parse_errors'].append(ParseError(
                    filepath=pyfile,
                    error_type='SyntaxError',
                    message=str(e.msg),
                    line=e.lineno,
                    column=e.offset,
                ))
                _v = _VR.decide("rule", ("NAI-208", "HIGH", f'Syntax error in {pyfile.name}:{e.lineno}: {e.msg}', "HARD_REQUIREMENTS"))  # cut 2c: routed via VerdictRanker
                out['results'].append(ValidationResult(
                    function_name='<file>',
                    function_type=FunctionType.UNKNOWN,
                    passed=_v.passed,
                    failure_layer=ValidationLayer.HARD_REQUIREMENTS if not _v.passed else None,
                    failure_reason=_v.reason,
                    verdict_source=_v.source,
                    file_path=file_key_rel,
                    warnings=[
                        f'NAI-208 (HIGH): File contains syntax error — '
                        f'{e.msg} at line {e.lineno}',
                    ],
                ))
                return out

            file_results, collector, file_fps = await _validate_file_from_ast(
                validator, tree, source, pyfile, rel=file_key_rel, project_attr_names=project_attr_names)
            for r in file_results:
                r.file_path = file_key_rel

            out['results'].extend(file_results)
            out['tree'] = tree
            out['collector'] = collector

            fps_list: List[Tuple[str, str, int]] = []
            for funcs in file_fps.values():
                fps_list.extend(funcs)
            out['fps'] = fps_list

            # F-CYC1 (2026-09-05): import edges are FILE -> FILE, with package-
            # relative imports (`from . import x`, `from .x import y`) resolved
            # through the same resolver NAI-217 (was NAI-210) uses. Module-name edges could
            # never close a cycle against file keys (F-CYC2: chains logged,
            # zero published).
            for imp_node in ast.walk(tree):
                targets = []
                if isinstance(imp_node, ast.Import):
                    for alias in imp_node.names:
                        targets.append(validator._resolve_import_file(alias.name, pyfile, 0))
                elif isinstance(imp_node, ast.ImportFrom):
                    base_mod = imp_node.module or ''
                    targets.append(validator._resolve_import_file(base_mod, pyfile, imp_node.level))
                    for alias in imp_node.names:   # `from pkg import submodule`
                        sub = f"{base_mod}.{alias.name}" if base_mod else alias.name
                        targets.append(validator._resolve_import_file(sub, pyfile, imp_node.level))
                for tgt in targets:
                    if tgt is None:
                        continue
                    try:
                        tgt_key = str(Path(tgt).resolve().relative_to(dirpath.resolve()))
                    except ValueError:
                        continue
                    if tgt_key != file_key_rel:
                        out['edges'].append(tgt_key)

            # EXCISED cut 3 batch 5 (2026-09-06, line read): config switch 'vuln_check_enabled' retired — the `if True:` shell removed (FIX_31 step 4 / FIX_35 n, 2026-09-15)
            vulns = validator.check_vuln_patterns(source, pyfile)
            for code, sev, msg, line in vulns:
                out['vulns'].append({
                    'file': file_key_rel,
                    'code': code,
                    'severity': sev,
                    'message': msg,
                    'line': line,
                })
                if file_results:
                    file_results[0].warnings.append(f'{code} ({sev}): {msg}')

            if validator._policy_hooks and file_results:
                for result in file_results:
                    hook_warnings = validator.run_policy_hooks(result, source)
                    result.warnings.extend(hook_warnings)
        except Exception as e:
            out['parse_errors'].append(ParseError(
                filepath=pyfile,
                error_type='ValidationError',
                message=str(e),
            ))
        return out

    async def _bounded(pyfile: Path) -> Dict[str, Any]:
        nonlocal _done
        async with _sem:
            out = await _one(pyfile)
        _done += 1
        if _bar is not None:
            _bar.update(1)
        if progress_callback is not None:
            progress_callback(_done, total_files, out['rel'])
        return out

    per_file = await asyncio.gather(*(_bounded(p) for p in py_files))
    if _bar is not None:
        _bar.close()
    for out in per_file:   # py_files order — determinism
        validator.parse_errors.extend(out['parse_errors'])
        results.extend(out['results'])
        if out['tree'] is None:
            continue
        file_key_rel = out['rel']
        collector = out['collector']
        file_trees[file_key_rel] = (out['path'], out['tree'])
        global_symbols[file_key_rel] = collector.defined_symbols
        global_imports[file_key_rel] = collector.imports
        all_defined.update(collector.defined_symbols)
        all_references.update(collector.referenced_symbols)
        all_fingerprints[file_key_rel] = out['fps']
        for func, callees in collector.call_graph.items():
            global_call_graph[f'{file_key_rel}:{func}'].update(callees)
        for tgt_key in out['edges']:
            validator._import_graph[file_key_rel].add(tgt_key)
        vuln_issues.extend(out['vulns'])
    _t_files = time.perf_counter() - _t_files
    timing: Dict[str, Any] = {
        'files': total_files,
        'seconds': round(_t_files, 3),
        's_per_file': round(_t_files / total_files, 4) if total_files else None,
        'concurrency': _concurrency,
    }
    logger.info('validated %d files in %.1f s (%s s/file, concurrency %d)',
                total_files, _t_files, timing['s_per_file'], _concurrency)


    # NAI-214 abstract_shell needs every tree (the subclass may live in another
    # file) — judged here, after the per-file pass (plan item 4, 2026-09-05).
    for shell in _check_abstract_shells(file_trees, f'the {len(file_trees)} scanned files'):
        # EXCISED cut 3 batch 2 (2026-09-06, agreed): shell whitelist force-pass deleted (function whitelist removed by the owner)
        results.append(shell)

    _total = total_files
    _xf_step = 0
    _xf_steps = 7

    def _xf_progress(label: str) -> None:
        nonlocal _xf_step
        _xf_step += 1
        if progress_callback is not None:
            progress_callback(_total, _total, f'xfile {_xf_step}/{_xf_steps}: {label}')

    _xf_progress('import resolution')
    cross_file_issues: List[Tuple[str, str, str]] = []
    for file_key, (xf_pyfile, xf_tree) in file_trees.items():
        for walk_node in ast.walk(xf_tree):
            if not isinstance(walk_node, ast.ImportFrom):
                continue
            level = walk_node.level
            module = walk_node.module or ''
            if level > 0:
                if not validator._resolve_import(module, xf_pyfile, dirpath, level):
                    cross_file_issues.append((
                        file_key,
                        f".{'.' * (level - 1)}{module}",
                        f"Relative import '.{'.' * (level - 1)}{module}' not resolved",
                    ))
            else:
                imp = module.split('.')[0] if module else ''
                if not imp:
                    continue
                if imp in validator.builtins:
                    continue
                if imp in validator.packages:
                    continue
                if validator._resolve_import(imp, xf_pyfile, dirpath, 0):
                    continue
                if imp in all_defined:
                    continue
                cross_file_issues.append((
                    file_key,
                    imp,
                    f"Import '{imp}' not found in project or stdlib",
                ))

    _xf_progress('duplicate detection')
    cross_file_dups = _check_cross_file_duplicates(all_fingerprints)
    dir_symmetry_issues = _check_directory_symmetry(all_fingerprints)

    unused_symbols = sorted(
        sym for sym in all_defined
        if not sym.startswith('_') and sym not in all_references
    )

    # F-CYC1 (run 19, 2026-09-05): the daemon's discovered list excludes package
    # markers (nothing to judge in them) — but `__init__.py` CARRIES IMPORTS, and
    # colorama's cycle runs through it. Their edges join the graph here.
    try:
        seen_keys = set(validator._import_graph.keys())
        for _mod, _pf in list(getattr(validator, '_module_map', {}).items()):
            if _pf.name != '__init__.py':
                continue
            try:
                _key = str(_pf.relative_to(dirpath))
            except ValueError:
                continue
            if _key in seen_keys or (whitelist and (_key in whitelist or f'{_key}::*' in whitelist)):
                continue
            # EXCISED cut 3 batch 5 (2026-09-06, line read): `.git`/`__pycache__` name skip removed — the whitelist check above is the one discovery
            try:
                _tree = ast.parse(read_source(_pf))   # A1: same reader as the per-file pass
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logger.warning("reported, not swallowed (cut 3): %s: %r", 'validate_directory_async', _e)
                continue
            for imp_node in ast.walk(_tree):
                targets = []
                if isinstance(imp_node, ast.Import):
                    for alias in imp_node.names:
                        targets.append(validator._resolve_import_file(alias.name, _pf, 0))
                elif isinstance(imp_node, ast.ImportFrom):
                    base_mod = imp_node.module or ''
                    targets.append(validator._resolve_import_file(base_mod, _pf, imp_node.level))
                    for alias in imp_node.names:
                        sub = f"{base_mod}.{alias.name}" if base_mod else alias.name
                        targets.append(validator._resolve_import_file(sub, _pf, imp_node.level))
                for tgt in targets:
                    if tgt is None:
                        continue
                    try:
                        tgt_key = str(Path(tgt).resolve().relative_to(dirpath.resolve()))
                    except ValueError:
                        continue
                    if tgt_key != _key:
                        validator._import_graph[_key].add(tgt_key)
    except Exception as _e:
        logger.debug('package-marker import edges skipped: %s', _e)

    _xf_progress('cycle detection')
    global_cycles = validator._detect_cycles(dict(global_call_graph))

    circular_imports: List[Dict[str, Any]] = []
    circular_import_total = 0
    # EXCISED cut 3 batch 5 (2026-09-06, line read): config switch 'detect_circular_imports' retired — the `if True:` shell removed (FIX_31 step 4 / FIX_35 n, 2026-09-15)
    import_cycles = validator._detect_import_cycles(dict(validator._import_graph))
    seen_cycles: set = set()
    for cycle in import_cycles:
        if len(cycle) < 3:      # [a, a] = self-import, not a cycle between files
            continue
        key = frozenset(cycle)
        if key in seen_cycles:
            continue
        seen_cycles.add(key)
        circular_import_total += 1
        # cap `len(circular_imports) < 50` EXCISED cut 2 (2026-09-05): every distinct cycle is published
        circular_imports.append({'cycle': cycle, 'severity': 'HIGH', 'files': len(key)})

    _xf_progress('RCA sweep')
    rca_cross_file_issues: List[Dict[str, Any]] = []
    if _CALLER_MAP_AVAILABLE:
        try:
            caller_map = _CallerMapBuilder(dirpath, files=py_files)   # owner 2026-09-05: same whitelist-filtered list
            await caller_map.scan()

            cross_failed = {
                r.function_name for r in results
                if not r.passed and not r.function_name.startswith('<')
            }
            if cross_failed:
                for failed_fn in list(cross_failed):
                    callers = caller_map.get_callers(failed_fn)
                    for caller_info in callers:
                        caller_name = caller_info.caller.split('.')[-1]
                        for i, r in enumerate(results):
                            if r.function_name != caller_name:
                                continue
                            if not r.passed:
                                continue
                            caller_file_rel = None
                            try:
                                caller_file_rel = str(
                                    caller_info.file_path.relative_to(dirpath))
                            except ValueError:
                                pass
                            if not caller_file_rel:
                                continue
                            if caller_file_rel not in file_trees:
                                continue
                            _, caller_tree = file_trees[caller_file_rel]
                            for node in ast.walk(caller_tree):
                                if not isinstance(
                                        node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                    continue
                                if node.name != caller_name:
                                    continue
                                params = {a.arg for a in node.args.args}
                                if not params:
                                    break
                                body_mod = ast.Module(body=node.body, type_ignores=[])
                                read_names: Set[str] = set()
                                for child in ast.walk(body_mod):
                                    if (isinstance(child, ast.Name)
                                            and isinstance(child.ctx, ast.Load)):
                                        read_names.add(child.id)
                                if not (params & read_names):
                                    # Recovered lineage replaced results[i] with a
                                    # failed RCA-002 result here. Doctrine: nothing
                                    # upstream of the ranker re-ranks or replaces raw
                                    # results — the infraction is emitted as cross_file
                                    # evidence only.
                                    rca_cross_file_issues.append({
                                        'caller': caller_name,
                                        'caller_file': caller_file_rel,
                                        'callee': failed_fn,
                                        'severity': 'CRITICAL',
                                    })
                                break
            logger.info('Cross-file RCA sweep: %d issues found',
                        len(rca_cross_file_issues))
        except Exception as e:
            logger.warning('Cross-file RCA sweep failed: %s', e)

    _xf_progress('dependency graph')
    dep_graph_cycles: List[List[str]] = []
    if _UTILS_AVAILABLE:
        try:
            edges: List[Tuple[str, str]] = []
            for caller, callees in global_call_graph.items():
                for callee in callees:
                    edges.append((caller, callee))
            dep_graph = _build_dep_graph(edges)
            dep_cycles = _graph_find_cycles(dep_graph)
            dep_graph_cycles = dep_cycles
            logger.info('utils.graph dependency analysis: %d nodes, %d cycles found',
                        len(dep_graph), len(dep_cycles))

            rev_graph = _reverse_graph(dep_graph)
            logger.debug('Reverse dependency graph: %d nodes', len(rev_graph))

            topo_order = _topological_sort(dep_graph)
            if topo_order is not None:
                logger.debug('Topological sort: %d nodes ordered', len(topo_order))
            else:
                logger.debug('Topological sort: graph has cycles, no valid ordering')

            failed_funcs: Set[str] = set()
            passing_funcs: Set[str] = set()
            for r in results:
                if r.function_name.startswith('<'):
                    continue
                if not r.passed:
                    failed_funcs.add(r.function_name)
                else:
                    passing_funcs.add(r.function_name)

            if failed_funcs and passing_funcs:
                reachable = _dfs_reachability(dep_graph, passing_funcs, failed_funcs)
                if reachable:
                    logger.info('DFS reachability: passing functions CAN reach failed functions')
                else:
                    logger.debug('DFS reachability: no path from passing to failed functions')

                for pfunc in passing_funcs:
                    for ffunc in failed_funcs:
                        path = _bfs_shortest_path(dep_graph, pfunc, ffunc)
                        if path and len(path) > 1:
                            logger.debug('BFS shortest path: %s → %s (%d hops): %s',
                                         pfunc, ffunc, len(path) - 1, ' → '.join(path))

                failed_list = sorted(failed_funcs)
                for i, f1 in enumerate(failed_list):
                    for f2 in failed_list[i + 1:]:
                        all_paths = _find_all_paths(dep_graph, f1, f2, max_paths=None)  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 5
                        if all_paths:
                            logger.debug('All paths: %s → %s: %d path(s) found',
                                         f1, f2, len(all_paths))
        except Exception as e:
            logger.debug('utils.graph dependency analysis failed: %s', e)

    _xf_progress('import graph')
    import_graph_data: Dict[str, Any] = {}
    if _IMPORT_GRAPH_AVAILABLE:
        try:
            ig_builder = _ImportGraphBuilder(dirpath, files=py_files)   # plan item 6: same whitelist-filtered list
            await ig_builder.scan()
            import_graph_data = {
                'files_indexed': len(ig_builder.file_imports),
                'modules_mapped': len(ig_builder.module_to_file),
            }
            for r in results:
                if r.passed:
                    continue
                if not r.file_path:
                    continue
                _fp = Path(r.file_path)
                importers = ig_builder.get_importers(_fp if _fp.is_absolute() else dirpath / _fp)  # F-IGR-ZERO (cut 3 batch 5, 2026-09-06): the graph keys by absolute path; a relative key never matched, so the count was always 0 and IGR-001 never fired
                # EXCISED cut 3 batch 5 (2026-09-06, line read): `if not importers: continue` removed — 0 importers is a published count (an orphan module is a fact)
                r.warnings.append(
                    f'IGR-001 (INFO): {len(importers or [])} file(s) import this module')
            logger.info('ImportGraphBuilder: %d files indexed, %d module mappings',
                        len(ig_builder.file_imports), len(ig_builder.module_to_file))
        except Exception as e:
            logger.debug('ImportGraphBuilder failed: %s', e)

    _xf_progress('rca')
    rca_reports: List[Dict[str, Any]] = []
    if _RCA_UNIT_AVAILABLE:
        try:
            # FIX_39 (owner Q1, 2026-09-15; closes I-04 + I-06): ONE tree store for the whole scan —
            # every live file read ONCE and parsed ONCE, the caller indices derived in that pass, and
            # the store shared with every failure site this unit analyses. Before this the unit
            # re-read and re-parsed the whole live list for every site (and again per direct caller to
            # depth 3), which is why a ~400-file repo never reached MONITORING (run 113). A file that
            # cannot be read or parsed is in the store's `errors` once, counted and published below —
            # the `return_exceptions=True` swallow that made FRN-001's candidate count flutter (I-06)
            # goes with the loop it lived in.
            _trees = None
            try:
                from rca_main.scan_trees import ScanTrees as _ScanTrees
                _trees = await _ScanTrees(str(dirpath), py_files).load()
                logger.info('RCA tree store: %s', _trees.stats_line())
                for _p, _err in _trees.errors.items():   # every one — a truncated list is a swallow (I-06)
                    logger.warning('RCA tree store: %s could not be read/parsed: %s', _p, _err)
            except Exception as _e:
                logger.warning('RCA tree store unavailable (%s) — the per-site path stands', _e)
                _trees = None
            rca_unit = _RootCauseUnit(str(dirpath), files=py_files, trees=_trees)   # plan item 6: same whitelist-filtered list
            # Candidates must stay inside that list too: ImportTracer resolves
            # imports to files, and a live module importing a venv-internal
            # package would otherwise drag the venv back in as a "root cause".
            _allowed = {str(Path(p).resolve()) for p in py_files}
            _clipped = 0
            # C1 (Q-H3b-6 / Q-H3a-1, 2026-10-01): the unit's answer is a function of (failing file,
            # failure reason) and of nothing that changes during this sweep, so a site that repeats
            # a (file, reason) pair reads the answer already computed — no second walk. Every row
            # still publishes its own report (nothing is dropped); a site whose analysis raised is
            # asked again, as before. (The per-candidate `Path.resolve()` memo C1 added here was
            # taken out again by the orchestrator, 2026-10-01 06:55: it re-keyed the hunter's W14
            # site at the clip below out of its ledger row — health step 17 creep 1. The 1.8 M
            # realpath calls on pandas, Q-H3a-2, stay a queue row for the owner.)
            _analysed: Dict[Tuple[str, str], Dict[str, List[str]]] = {}
            _sites: List[Tuple[ValidationResult, str]] = [
                (r, r.file_path) for r in results
                if not r.passed and r.file_path and not r.function_name.startswith('<')]
            _n_sites = len(_sites)
            _last_progress = time.monotonic()
            for _i, (r, _rel) in enumerate(_sites, 1):
                # Q-H3a-4: the progress writer hears the sweep (the longest phase on a big repo was
                # frozen on the last per-file line) — at most about once a second, and at the last site.
                _now = time.monotonic()
                _due = (_now - _last_progress) >= 1.0 or _i == _n_sites
                if _due and progress_callback is not None:
                    _last_progress = _now
                    progress_callback(_total, _total,
                                      f'xfile {_xf_step}/{_xf_steps}: rca [{_i}/{_n_sites}] '
                                      f'{_rel}:{r.function_name}')
                try:
                    failing_file = str(dirpath / _rel)
                    _site_key = (failing_file, r.failure_reason or '')
                    candidates_ctx = _analysed.get(_site_key)
                    if candidates_ctx is None:
                        candidates_ctx = await rca_unit.analyze(
                            failing_file, r.failure_reason or '')
                        _analysed[_site_key] = candidates_ctx
                except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                    logger.warning("reported, not swallowed (cut 3): %s: %r", 'validate_directory_async', _e)
                    continue
                if candidates_ctx:
                    _before = len(candidates_ctx)
                    candidates_ctx = {k: v for k, v in candidates_ctx.items()
                                      if str(Path(k).resolve()) in _allowed}
                    _clipped += _before - len(candidates_ctx)
                candidates_ctx = candidates_ctx or {}
                # EXCISED cut 3 batch 5 (2026-09-06, line read): `if not candidates_ctx: continue` removed — zero candidates is a published RCA result, not silence
                candidate_count = len(candidates_ctx)
                rca_reports.append({
                    'file': r.file_path,
                    'function': r.function_name,
                    'candidates': candidate_count,
                    'candidate_files': list(candidates_ctx.keys()),
                    # FIX_32 / FIX_33 (2026-09-10): the evidence LINES are published beside the
                    # candidates — "Imported by failing file", "Downstream caller of failing file",
                    # "Related by context (why)", "Defines symbol" — the Builder turns them into
                    # rca=upstream/downstream/context/symbol tokens on the row (every fact reaches the Ranker).
                    'evidence': {str(k): list(v) for k, v in candidates_ctx.items()},
                })
                if candidate_count:
                    r.warnings.append(
                        f'FRN-001 (INFO): RootCause: {candidate_count} '
                        f'candidate file(s) identified')
            logger.info('RootCauseUnit: %d analysis reports generated (%d candidate(s) outside the scanned list clipped)'
                        '%s',
                        len(rca_reports), _clipped,
                        (f"; tree store {_trees.stats()['parses']} parse(s) for "
                         f"{_trees.stats()['files']} live file(s) over {len(rca_reports)} site(s), "
                         f"{_trees.stats()['errors']} load error(s)") if _trees is not None else
                        '; no tree store (per-site path)')
        except Exception as e:
            logger.debug('RootCauseUnit failed: %s', e)

    # Tier-2: origin_tracer (BLT-001) and onion_peeler (ONP-001) are RUNTIME
    # tools — they need a real execution of the target (a CrashArtifact, a run
    # command). The static validator never executes target code, so here they
    # are NOT MEASURED and published as such (plan item 6, 2026-09-05) — never
    # as an empty list that reads "no issues". Their feed is plan item 8's
    # executed proof; when it lands, the same whitelist-filtered list scopes them.
    origin_trace_results: List[Dict[str, Any]] = []
    onion_peel_results: List[Dict[str, Any]] = []
    tier2_status: Dict[str, Any] = {
        'origin_tracer': 'NOT MEASURED — runtime tool; fed only by executed proof (plan item 8)',
        'onion_peeler': 'NOT MEASURED — runtime tool; fed only by executed proof (plan item 8)',
        'importable': {'origin_tracer': _BLAME_TRACER_AVAILABLE, 'onion_peeler': _ONION_PEELER_AVAILABLE},
    }
    rca_scope: Dict[str, Any] = {
        'files': len(py_files),
        'source': 'whitelist-filtered list (no own walk)' if files is not None else 'directory walk',
        'candidates_clipped_outside_list': _clipped if _RCA_UNIT_AVAILABLE else None,
    }

    # Excised subsystems (context_calculator, context_gathering_manager,
    # gateway, session_state): keys kept present-but-empty for schema stability.
    context_recommendations: List[Dict[str, Any]] = []
    context_gathering_results: List[Dict[str, Any]] = []
    gateway_health: Dict[str, Any] = {}
    session_metrics: Dict[str, Any] = {}

    cross_file_analysis: Dict[str, Any] = {
        'files_analyzed': len(py_files),
        'files_limited': effective_max is not None,
        'parse_errors': [
            {'file': str(e.filepath), 'type': e.error_type, 'message': e.message}
            for e in validator.parse_errors
        ],
        'global_symbols': {k: list(v) for k, v in global_symbols.items()},
        'cross_file_issues': cross_file_issues,
        'cross_file_duplicates': cross_file_dups,
        'directory_symmetry_issues': dir_symmetry_issues,
        'symbol_overlap': _find_symbol_overlap(global_symbols),
        'unused_symbols': unused_symbols,
        'call_cycles': [cycle for cycle in global_cycles],
        'circular_imports': circular_imports,
        'circular_import_total': circular_import_total,
        'rca_cross_file_issues': rca_cross_file_issues,
        'unsafe_pattern_issues': vuln_issues,
        'cache_stats': {'hits': 0, 'misses': 0, 'enabled': False},
        'dep_graph_cycles': dep_graph_cycles,
        'import_graph': import_graph_data,
        'context_recommendations': context_recommendations,
    }
    cross_file_analysis.update({
        'rca_reports': rca_reports,
        'origin_trace_results': origin_trace_results,
        'context_gathering': context_gathering_results,
        'gateway_health': gateway_health,
        'session_metrics': session_metrics,
        'onion_peel_results': onion_peel_results,
        'tier2_status': tier2_status,
        'timing': timing,   # FIX_34: the per-file pass's true numbers, every run
        'rca_scope': rca_scope,
    })

    return results, cross_file_analysis


def validate_directory(
    validator: 'NoAIMathValidator',
    dirpath: Path,
    max_files: Optional[int] = None,
) -> Tuple[List[ValidationResult], Dict[str, Any]]:
    """Validate all Python files in a directory (sync wrapper)."""
    result = asyncio.run(validate_directory_async(validator, dirpath, max_files))
    return result


def _check_cross_file_duplicates(
    all_fingerprints: Dict[str, List[Tuple[str, str, int]]],
) -> List[Dict[str, Any]]:
    """Check for duplicate functions across files."""
    fingerprint_to_files: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for file_key, fps in all_fingerprints.items():
        for func_name, fingerprint, _ in fps:
            fingerprint_to_files[fingerprint].append((file_key, func_name))

    duplicates: List[Dict[str, Any]] = []
    for fp, locations in fingerprint_to_files.items():
        if len(locations) > 1:
            files = set(loc[0] for loc in locations)
            if len(files) > 1:
                duplicates.append({
                    'fingerprint': fp[:16] + '...',
                    'locations': [{'file': f, 'function': n} for f, n in locations],
                    'severity': 'HIGH',
                })
    return duplicates


def _check_directory_symmetry(
    all_fingerprints: Dict[str, List[Tuple[str, str, int]]],
) -> List[Dict[str, Any]]:
    """Check for suspicious structural symmetry across files."""
    issues: List[Dict[str, Any]] = []

    file_signatures: Dict[Tuple[int, ...], List[str]] = defaultdict(list)
    for file_key, fps in all_fingerprints.items():
        if not fps:
            continue
        signature = tuple(sorted(fp_len for _, _, fp_len in fps))
        file_signatures[signature].append(file_key)

    for signature, files in file_signatures.items():
        if len(files) > 1:  # EXCISED cut 2 (2026-09-05): was `len(files) > 2 and len(signature) > 2` — 'across files' needs two; signature size was a magnitude
            issues.append({
                'pattern': 'Identical structural complexity',
                'files': files,
                'signature': str(signature),  # EXCISED cut 2: truncation `[:5]` removed
                'severity': 'MEDIUM',
            })
    return issues


def _find_symbol_overlap(
    global_symbols: Dict[str, Set[str]],
) -> List[Dict[str, Any]]:
    """Find symbols defined in multiple files."""
    symbol_files: Dict[str, List[str]] = defaultdict(list)
    for file_key, symbols in global_symbols.items():
        for sym in symbols:
            symbol_files[sym].append(file_key)

    overlaps: List[Dict[str, Any]] = []
    for sym, files in symbol_files.items():
        if len(files) > 1:
            overlaps.append({
                'symbol': sym,
                'files': files,
                'severity': 'MEDIUM' if sym.startswith('_') else 'HIGH',
            })
    return overlaps
