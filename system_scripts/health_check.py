#!/usr/bin/env python3
"""
health_check.py — the 16-step regression harness (extracted verbatim from
.archive/cli.py lines 1-1588 on 2026-08-27; the pipeline map below is the
canonical step->module->symbols inventory).

Usage:
    .venv_new/bin/python system_scripts/health_check.py   # Two-tier health check, Steps 1-22 (17 = pre-ranker ranking census, 18 = rule-disposition table + recall guard, 19 = repair-generator registry + plants, 20 = venv compatibility, 22 = solution gate)

Pipeline:
    Step 1: Duplicate (check_duplicate_functions, check_duplicate_functions_strict)
    Step 2: Fingerprint (fingerprint_function, normalized_fingerprint, fingerprint_all_functions, check_normalized_duplicates)
    Step 3: Extractor (MetricsExtractor, collect_method_ids)
    Step 4: Graph (build_dependency_graph, reverse_graph, dfs_reachability, bfs_shortest_path, find_all_paths, topological_sort, find_cycles, build_data_flow_graph, find_unused_assignments, find_undefined_uses, is_identity_chain)
    Step 5: Symmetry (check_suspicious_symmetry, check_arithmetic_symmetry)
    Step 6: RootCause (ImportTracer, ASTCache)
    Step 7: Signature engine (signature_engine/: core, AuthorshipSignatureDatabase, authorship_rules, hallucinations, stdlib, packages, dunders, canonicals, builtins_registry)
    Step 8: Detection (AIFakeDetector + 10 check mixins: core, structural, math, advanced, hallucination, redundancy, safety, style, semantic, extended_semantic)
    Step 9: NoAI Validator (NoAIMathValidator, MetricsExtractor, FunctionCollector, ToleranceCalibrator, etc.; FIX_34 determinism)
    Step 10: RootCause Main (RootCauseUnit, ContextManager, ContextCalculator, ImportGraphBuilder, CallerMapBuilder, OnionPeeler, OriginTracer, SessionState, constants)
    Step 11: cheatsheets daemon (BUILDER_DAEMON: CheatsheetBuilder, BuilderDaemon, stage_mirror, _rule_fixer_map; repair_generators.for_rule / REGISTRY; SolutionRanker.decide, Decision; CodeAnalyzer) — tier 2 = one NAI-071 plant → row has digest + decision.pick_role (item 1, 2026-09-08; dispatch through the registry since item 4)
    Step 12: Detritus Cleaner (DetritusCleaner, DetritusConfig, CleanseResult, etc.)
    Step 13: Finding Ordering + CB Context (FlaggedIssue, ContextLinesCalculator)
    Step 14: Semantic Analysis (DefUseAnalyzer, ModuleAnalyzer, analyze_file, analyze_directory)
    Step 15: Circuit Daemon (get_config, get_repo_id, is_pid_alive, read/write_file_locked, etc.)
    Step 16: NOAI Validator Daemon (NoAIValidatorDaemon, parse_line_ranges, functions_at_lines, stage_discover, etc.)
    Step 17: Pre-ranker ranking census (system_scripts/preranker_census.py + preranker_hunt.py; owner ruling 2026-09-05)
    Step 18: Rule-disposition table + recall guard (system_scripts/disposition_check.py + verify_manifest.py; calibrator 2026-09-06)
    Step 19: Repair-generator registry (system_scripts/generator_check.py + generator_plants/; no_aivalidator/repair_generators — every deciding id has a row; every rewriter proven on its plant: fires, parses, differs, meaning quiet, equivalent; item 4, 2026-09-08)
    Step 20: venv compatibility (system_scripts/venv_check.py — the running interpreter inside every installed distribution's Requires-Python, pip check clean, every pyproject dependency installed, no module-level unguarded import of an absent module in live engine code; tested-ceiling and call-time absences are INFO; FIX_44, owner 2026-09-15)

    Types (no step): core.py (FunctionMetrics, DataFlowEdge, Issue, SEVERITY_*)
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# HEALTH CHECK — Two-tier validation for Steps 1-22
# ═══════════════════════════════════════════════════════════════════

def _run_script_cli(module: str, args: List[str], timeout: int = 10) -> tuple[bool, str]:
    """
    Run a script as a subprocess via `python3 -m module`.
    
    Returns:
        (success, message) tuple
    """
    cmd = [sys.executable, "-m", module] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=_REPO_ROOT,
        )
        # Accept both 0 (success) and 1 (found issues) as valid CLI runs
        # Only fail on crashes (exit code > 1 or exception)
        if result.returncode in (0, 1):
            return True, "✓"
        return False, f"exit code {result.returncode}: {result.stderr[:100]}"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


class _StepStdout:
    """E1 (2026-10-01): a per-thread stdout. Steps 17, 18 and 20 are independent, so the slow callables of 18
    (the recall guard) and 20 (interpreter / pip check / declared deps) run on worker threads while step 17 runs
    on the main thread. A thread that registered a buffer has its print() lines kept there; every other write
    goes straight to the real stdout. Each step's block below emits its buffer where the lines used to be
    printed, so the health log's `▶ Step` markers and line order are the same as before — only the wall-clock
    changes. Nothing is measured less."""

    def __init__(self, real: Any) -> None:
        import io as _io, threading as _th
        self._real = real; self._io = _io; self._th = _th
        self._bufs: Dict[int, Any] = {}

    def register(self) -> None:
        self._bufs[self._th.get_ident()] = self._io.StringIO()

    def take(self) -> str:
        b = self._bufs.pop(self._th.get_ident(), None)
        return b.getvalue() if b is not None else ""

    def write(self, s: str) -> int:
        b = self._bufs.get(self._th.get_ident())
        return (b if b is not None else self._real).write(s)

    def flush(self) -> None:
        self._real.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def run_buffered(self, fn: Any) -> tuple:
        """(result, printed text). An exception is re-raised to the joining step with the text printed before it
        attached as `hc_printed`, so the step's own except can emit those lines before its failure line."""
        self.register()
        try:
            r: Any = fn()
        except Exception as e:
            setattr(e, "hc_printed", self.take())
            raise
        return r, self.take()

    @staticmethod
    def failed(exc: Exception) -> Any:
        """A finished future carrying `exc` — a module that failed to load joins like a step that failed to run."""
        import concurrent.futures as _cf
        f: Any = _cf.Future(); f.set_exception(exc)
        return f


# Synthetic test source for health checks
_TEST_SOURCE = '''
def simple_add(x, y):
    """Add two numbers."""
    result = x + y
    return result

def unused_var():
    """Function with unused variable."""
    x = 10
    y = 20
    return y  # x is unused

def identity_func(data):
    """Identity function - returns input unchanged."""
    return data

class Calculator:
    def multiply(self, a, b):
        """Multiply method."""
        return a * b
'''


def _m48_process_scan_cases(scan) -> str:
    """M-48 / C (owner 2026-10-06): the process-scan fixture — a target run is seen however it was started:
    `-m pkg.mod` (joined `-mpkg.mod` too), `-m pkg` running pkg/__main__.py, a `.py` path relative to the
    process's OWN cwd; a `-m` of a module outside the repo (a linter) is not a target run. Fake pids, a
    throwaway repo, an injected cwd lookup — no process is started. Returns '' or what was wrong."""
    import shutil
    repo = Path(tempfile.mkdtemp(prefix="hc_m48_")).resolve()
    try:
        for rel in ("pkg/__init__.py", "pkg/mod.py", "app/__init__.py", "app/__main__.py", "sub/x.py"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text("v = 1\n")
        nodes = ["pkg/__init__", "pkg/mod", "app/__init__", "app/__main__", "sub/x"]
        ps = [(91001, "python3 -B -m pkg.mod --flag"), (91002, "python3 -mpkg.mod"),
              (91003, "python3 -m app"), (91004, "python3 x.py"), (91005, "python3 -m pylint pkg")]
        cwd = {91001: str(repo), 91002: str(repo), 91003: str(repo), 91004: str(repo / "sub"), 91005: str(repo)}
        want = {"91001": ("pkg/mod", "module"), "91002": ("pkg/mod", "module"),
                "91003": ("app/__main__", "module"), "91004": ("sub/x", "path")}
        seen = {p: (r.get("node"), r.get("how")) for p, r in scan(nodes, repo, ps, cwd_of=cwd.get).items()}
        return "" if seen == want else f"M-48: process scan matched {seen}, expected {want}"
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def _load_proof_rule_cases() -> List[str]:
    """A (owner 2026-10-06): the eslogger load-proof reducer on canned events, in a throwaway repo shaped
    like the gang target — load_recorder_trial's canned cases. Returns what failed ([] = pass)."""
    import shutil
    import load_recorder_trial
    repo = Path(tempfile.mkdtemp(prefix="hc_lp_")).resolve()
    fails: List[str] = []
    try:
        for rel in ("charlie_work/__init__.py", "charlie_work/the_gang_runs_for_office.py", "x/y.py"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text("v = 1\n")
        load_recorder_trial.canned_cases(repo, fails)
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    return fails


async def run_health_check() -> Dict[str, Any]:
    """
    Run two-tier health check for Steps 1-18.

    Tier 1: Function-level — each function runs without crash
    Tier 2: Script-level — functions wired together work

    Returns:
        Dict with health check results per step
    """
    results: Dict[str, Any] = {
        "status": "unknown",
        "steps": {},
    }
    
    all_passed = True
    
    print("=" * 60)
    print("HEALTH CHECK — Steps 1-22")
    print("=" * 60)
    
    # Parse test source once
    test_tree = ast.parse(_TEST_SOURCE)
    test_funcs = [n for n in ast.walk(test_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    
    # ─────────────────────────────────────────────────────────────
    # Step 1: Duplicate (duplicate.py)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 1: Duplicate")
    step1_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}
    
    try:
        from utils.code_analysis.duplicate import check_duplicate_functions, check_duplicate_functions_strict
        from utils.code_analysis.fingerprint import fingerprint_all_functions
        
        # Tier 1: Function-level
        test_fps = {"fp1": ["func_a", "func_b"], "fp2": ["func_c"]}
        
        try:
            r1 = check_duplicate_functions(test_fps)
            step1_health["tier1"]["check_duplicate_functions"] = "✓"
        except Exception as e:
            step1_health["tier1"]["check_duplicate_functions"] = f"✗ {e}"
            all_passed = False
        
        try:
            r2 = check_duplicate_functions_strict(test_fps)
            step1_health["tier1"]["check_duplicate_functions_strict"] = "✓"
        except Exception as e:
            step1_health["tier1"]["check_duplicate_functions_strict"] = f"✗ {e}"
            all_passed = False
        
        # Create temp file once for tier 2 and 3
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(_TEST_SOURCE)
            temp_path = Path(f.name)
        
        # Tier 2: Script-level (integration)
        try:
            fps = await fingerprint_all_functions(temp_path)
            issues = check_duplicate_functions(fps)
            issues_strict = check_duplicate_functions_strict(fps)
            step1_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step1_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False
        
        # Tier 3: CLI (subprocess)
        try:
            success, msg = _run_script_cli("utils.code_analysis.duplicate", [str(temp_path)])
            step1_health["tier3"] = {"cli_run": "✓" if success else f"✗ {msg}"}
            if not success:
                all_passed = False
        except Exception as e:
            step1_health["tier3"] = {"cli_run": f"✗ {e}"}
            all_passed = False
        
        temp_path.unlink()  # Clean up
        
        print(f"  Tier 1: {len([v for v in step1_health['tier1'].values() if v == '✓'])}/2 functions OK")
        print(f"  Tier 2: {step1_health['tier2'].get('integrated_workflow', '✗')}")
        print(f"  Tier 3: {step1_health['tier3'].get('cli_run', '✗')}")
        
    except ImportError as e:
        step1_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")
    
    results["steps"]["step_1_duplicate"] = step1_health
    
    # ─────────────────────────────────────────────────────────────
    # Step 2: Fingerprint (fingerprint.py)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 2: Fingerprint")
    step2_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}
    
    try:
        from utils.code_analysis.fingerprint import (
            fingerprint_function, normalized_fingerprint, fingerprint_all_functions,
            check_normalized_duplicates
        )
        from utils.code_analysis.extractor import MetricsExtractor
        
        # Tier 1: Function-level
        test_func = test_funcs[0]  # simple_add
        extractor = MetricsExtractor(test_func, class_context=False)
        
        try:
            fp = fingerprint_function(extractor.metrics)
            step2_health["tier1"]["fingerprint_function"] = "✓"
        except Exception as e:
            step2_health["tier1"]["fingerprint_function"] = f"✗ {e}"
            all_passed = False
        
        try:
            nfp = normalized_fingerprint(test_func)
            step2_health["tier1"]["normalized_fingerprint"] = "✓"
        except Exception as e:
            step2_health["tier1"]["normalized_fingerprint"] = f"✗ {e}"
            all_passed = False
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)
            fps = await fingerprint_all_functions(temp_path)
            step2_health["tier1"]["fingerprint_all_functions"] = "✓"
        except Exception as e:
            step2_health["tier1"]["fingerprint_all_functions"] = f"✗ {e}"
            all_passed = False
        
        try:
            norm_dups = await check_normalized_duplicates(temp_path)
            temp_path.unlink()
            step2_health["tier1"]["check_normalized_duplicates"] = "✓"
        except Exception as e:
            step2_health["tier1"]["check_normalized_duplicates"] = f"✗ {e}"
            all_passed = False
        
        # Tier 2: Script-level
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)
            
            fps = await fingerprint_all_functions(temp_path)
            norm_dups = await check_normalized_duplicates(temp_path)
            source = temp_path.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ext = MetricsExtractor(node, class_context=False)
                    _ = fingerprint_function(ext.metrics)
                    _ = normalized_fingerprint(node)
            temp_path.unlink()
            step2_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step2_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        # FIX_47 (2026-09-17, I-03): reading may not write. normalized_fingerprint used to rename the
        # CALLER's tree in place (NodeTransformer.generic_visit rewrites list fields), which blinded the
        # RCA-001 split-fake sweep running after it. The hex must be unchanged and the tree untouched.
        try:
            _fp_src = "def caller(alpha, beta):\n    total = alpha + beta\n    return helper(total)\n"
            _fp_defs = [n for n in ast.walk(ast.parse(_fp_src)) if isinstance(n, ast.FunctionDef)]
            _fp_fresh = [n for n in ast.walk(ast.parse(_fp_src)) if isinstance(n, ast.FunctionDef)]
            _fp_node = _fp_defs[0]
            _fp_before = ast.dump(_fp_node)
            _fp_hex = normalized_fingerprint(_fp_node)
            assert ast.dump(_fp_node) == _fp_before, "normalized_fingerprint MUTATED its input tree"
            assert [a.arg for a in _fp_node.args.args] == ["alpha", "beta"], [a.arg for a in _fp_node.args.args]
            assert _fp_hex == normalized_fingerprint(_fp_fresh[0]), "fingerprint hex changed"
            step2_health["tier2"]["no_mutation (FIX_47)"] = "✓"
        except Exception as e:
            step2_health["tier2"]["no_mutation (FIX_47)"] = f"✗ {e}"
            all_passed = False

        # Tier 3: CLI (subprocess)
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)
            success, msg = _run_script_cli("utils.code_analysis.fingerprint", [str(temp_path)])
            step2_health["tier3"] = {"cli_run": "✓" if success else f"✗ {msg}"}
            if not success:
                all_passed = False
            temp_path.unlink()
        except Exception as e:
            step2_health["tier3"] = {"cli_run": f"✗ {e}"}
            all_passed = False
        
        print(f"  Tier 1: {len([v for v in step2_health['tier1'].values() if v == '✓'])}/4 functions OK")
        print(f"  Tier 2: {step2_health['tier2'].get('integrated_workflow', '✗')}; "
              f"fingerprint does not mutate its input (FIX_47): {step2_health['tier2'].get('no_mutation (FIX_47)', '✗')}")
        print(f"  Tier 3: {step2_health.get('tier3', {}).get('cli_run', '✗')}")
        
    except ImportError as e:
        step2_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")
    
    results["steps"]["step_2_fingerprint"] = step2_health
    
    # ─────────────────────────────────────────────────────────────
    # Step 3: Extractor (extractor.py)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 3: Extractor")
    step3_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}
    
    try:
        from utils.code_analysis.extractor import MetricsExtractor, collect_method_ids
        
        # Tier 1: Function-level
        try:
            method_ids = collect_method_ids(test_tree)
            step3_health["tier1"]["collect_method_ids"] = "✓"
        except Exception as e:
            step3_health["tier1"]["collect_method_ids"] = f"✗ {e}"
            all_passed = False
        
        try:
            extractor = MetricsExtractor(test_funcs[0], class_context=False)
            m = extractor.metrics
            step3_health["tier1"]["MetricsExtractor"] = "✓"
        except Exception as e:
            step3_health["tier1"]["MetricsExtractor"] = f"✗ {e}"
            all_passed = False
        
        # Tier 2: Script-level
        try:
            tree = ast.parse(_TEST_SOURCE)
            method_ids = collect_method_ids(tree)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    in_class = id(node) in method_ids
                    ext = MetricsExtractor(node, class_context=in_class)
                    _ = ext.metrics
            step3_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step3_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False
        
        # Tier 3: CLI (subprocess)
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)
            success, msg = _run_script_cli("utils.code_analysis.extractor", [str(temp_path)])
            step3_health["tier3"] = {"cli_run": "✓" if success else f"✗ {msg}"}
            if not success:
                all_passed = False
            temp_path.unlink()
        except Exception as e:
            step3_health["tier3"] = {"cli_run": f"✗ {e}"}
            all_passed = False
        
        print(f"  Tier 1: {len([v for v in step3_health['tier1'].values() if v == '✓'])}/2 OK")
        print(f"  Tier 2: {step3_health['tier2'].get('integrated_workflow', '✗')}")
        print(f"  Tier 3: {step3_health.get('tier3', {}).get('cli_run', '✗')}")
        
    except ImportError as e:
        step3_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")
    
    results["steps"]["step_3_extractor"] = step3_health
    
    # ─────────────────────────────────────────────────────────────
    # Step 4: Graph (graph.py) — All 11 functions
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 4: Graph")
    step4_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}
    
    try:
        from utils.code_analysis.graph import (
            build_dependency_graph, reverse_graph, dfs_reachability,
            bfs_shortest_path, find_all_paths, topological_sort, find_cycles,
            build_data_flow_graph, find_unused_assignments, find_undefined_uses, is_identity_chain
        )
        from utils.code_analysis.extractor import MetricsExtractor
        
        # Get metrics for test functions
        extractor = MetricsExtractor(test_funcs[1], class_context=False)  # unused_var
        m = extractor.metrics
        
        # Tier 1: Function-level
        try:
            edges = [("a", "b"), ("b", "c"), ("c", "d")]
            graph = build_dependency_graph(edges)
            step4_health["tier1"]["build_dependency_graph"] = "✓"
        except Exception as e:
            step4_health["tier1"]["build_dependency_graph"] = f"✗ {e}"
            all_passed = False
        
        try:
            rev = reverse_graph(graph)
            step4_health["tier1"]["reverse_graph"] = "✓"
        except Exception as e:
            step4_health["tier1"]["reverse_graph"] = f"✗ {e}"
            all_passed = False
        
        try:
            reach = dfs_reachability(graph, {"a"}, {"d"})
            step4_health["tier1"]["dfs_reachability"] = "✓"
        except Exception as e:
            step4_health["tier1"]["dfs_reachability"] = f"✗ {e}"
            all_passed = False
        
        try:
            path = bfs_shortest_path(graph, "a", "d")
            step4_health["tier1"]["bfs_shortest_path"] = "✓"
        except Exception as e:
            step4_health["tier1"]["bfs_shortest_path"] = f"✗ {e}"
            all_passed = False
        
        try:
            paths = find_all_paths(graph, "a", "d")
            step4_health["tier1"]["find_all_paths"] = "✓"
        except Exception as e:
            step4_health["tier1"]["find_all_paths"] = f"✗ {e}"
            all_passed = False
        
        try:
            topo = topological_sort(graph)
            step4_health["tier1"]["topological_sort"] = "✓"
        except Exception as e:
            step4_health["tier1"]["topological_sort"] = f"✗ {e}"
            all_passed = False
        
        try:
            cycles = find_cycles(graph)
            step4_health["tier1"]["find_cycles"] = "✓"
        except Exception as e:
            step4_health["tier1"]["find_cycles"] = f"✗ {e}"
            all_passed = False
        
        try:
            # build_data_flow_graph takes dict[str, set[str]] of assignments
            test_assignments = {"result": {"x", "y"}, "output": {"result"}}
            df_graph = build_data_flow_graph(test_assignments)
            step4_health["tier1"]["build_data_flow_graph"] = "✓"
        except Exception as e:
            step4_health["tier1"]["build_data_flow_graph"] = f"✗ {e}"
            all_passed = False
        
        try:
            unused = find_unused_assignments(m)
            step4_health["tier1"]["find_unused_assignments"] = "✓"
        except Exception as e:
            step4_health["tier1"]["find_unused_assignments"] = f"✗ {e}"
            all_passed = False
        
        try:
            undefined = find_undefined_uses(m)
            step4_health["tier1"]["find_undefined_uses"] = "✓"
        except Exception as e:
            step4_health["tier1"]["find_undefined_uses"] = f"✗ {e}"
            all_passed = False
        
        try:
            identity = is_identity_chain(m)
            step4_health["tier1"]["is_identity_chain"] = "✓"
        except Exception as e:
            step4_health["tier1"]["is_identity_chain"] = f"✗ {e}"
            all_passed = False
        
        # Tier 2: Script-level
        try:
            tree = ast.parse(_TEST_SOURCE)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ext = MetricsExtractor(node, class_context=False)
                    m = ext.metrics
                    
                    _ = find_unused_assignments(m)
                    _ = find_undefined_uses(m)
                    _ = is_identity_chain(m)
                    
                    # Use data_flow_edges from metrics (already built by extractor)
                    edges = m.data_flow_edges  # type: ignore[assignment]  # FIX_54 ast-pos
                    if edges:
                        edge_tuples = [(e.source, e.target) for e in edges]  # type: ignore[attr-defined]  # FIX_54 ast-pos
                        g = build_dependency_graph(edge_tuples)
                        _ = reverse_graph(g)
                        _ = find_cycles(g)
                        _ = topological_sort(g)
                        nodes = list(g.keys())
                        if len(nodes) >= 2:
                            _ = dfs_reachability(g, {nodes[0]}, {nodes[-1]})
                            _ = bfs_shortest_path(g, nodes[0], nodes[-1])
                            _ = find_all_paths(g, nodes[0], nodes[-1])
                    
                    # Also test build_data_flow_graph with assignments extracted from metrics
                    if m.vars_assigned:
                        # Create simple assignments mapping for testing
                        test_assigns = {v: m.vars_used for v in m.vars_assigned}
                        _ = build_data_flow_graph(test_assigns)
            
            step4_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step4_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False
        
        # Tier 3: CLI (subprocess)
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)
            success, msg = _run_script_cli("utils.code_analysis.graph", [str(temp_path)])
            step4_health["tier3"] = {"cli_run": "✓" if success else f"✗ {msg}"}
            if not success:
                all_passed = False
            temp_path.unlink()
        except Exception as e:
            step4_health["tier3"] = {"cli_run": f"✗ {e}"}
            all_passed = False
        
        ok_count = len([v for v in step4_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok_count}/11 functions:")
        for fname, status in step4_health['tier1'].items():
            print(f"    • {fname}: {status}")
        print(f"  Tier 2: {step4_health['tier2'].get('integrated_workflow', '✗')}")
        print(f"  Tier 3: {step4_health.get('tier3', {}).get('cli_run', '✗')}")
        
    except ImportError as e:
        step4_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")
    
    results["steps"]["step_4_graph"] = step4_health

    # ─────────────────────────────────────────────────────────────
    # Step 5: Symmetry (symmetry.py) — 6 functions
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 5: Symmetry")
    step5_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from utils.code_analysis.symmetry import (
            check_suspicious_symmetry, check_arithmetic_symmetry,
            _check_if_else_symmetry, _check_if_elif_symmetry,
            _check_loop_symmetry, _check_comprehension_symmetry,
        )

        # Tier 1: Function-level — each function runs without crash
        for fn_name, fn in [
            ("check_suspicious_symmetry", lambda: check_suspicious_symmetry(test_funcs[0])),
            ("check_arithmetic_symmetry", lambda: check_arithmetic_symmetry(test_funcs[0])),
            ("_check_if_else_symmetry", lambda: _check_if_else_symmetry(test_funcs[0])),
            ("_check_if_elif_symmetry", lambda: _check_if_elif_symmetry(test_funcs[0])),
            ("_check_loop_symmetry", lambda: _check_loop_symmetry(test_funcs[0])),
            ("_check_comprehension_symmetry", lambda: _check_comprehension_symmetry(test_funcs[0])),
        ]:
            try:
                fn()
                step5_health["tier1"][fn_name] = "✓"
            except Exception as e:
                step5_health["tier1"][fn_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Script-level — all functions wired together
        try:
            tree = ast.parse(_TEST_SOURCE)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _ = check_suspicious_symmetry(node)
                    _ = check_arithmetic_symmetry(node)
                    _ = _check_if_else_symmetry(node)
                    _ = _check_if_elif_symmetry(node)
                    _ = _check_loop_symmetry(node)
                    _ = _check_comprehension_symmetry(node)
            step5_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step5_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step5_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/6 functions OK")
        print(f"  Tier 2: {step5_health['tier2'].get('integrated_workflow', '✗')}")

    except ImportError as e:
        step5_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_5_symmetry"] = step5_health

    # ─────────────────────────────────────────────────────────────
    # Step 6: RootCause (import_tracer, ast_cache) — symbol_analyzer and bias_checker archived 2026-10-10 (last plan 1R)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 6: RootCause")
    step6_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from rca_main.analyzers.import_tracer import ImportTracer
        from rca_main.analyzers.ast_cache import ASTCache

        # Tier 1: Function-level
        try:
            it = ImportTracer(str(Path(__file__).parent))
            _ = await it.trace_imports_async(str(Path(__file__).resolve()), depth=1)
            step6_health["tier1"]["ImportTracer.trace_imports_async"] = "✓"
        except Exception as e:
            step6_health["tier1"]["ImportTracer.trace_imports_async"] = f"✗ {e}"
            all_passed = False

        try:
            _ = await it.get_candidate_files_async(str(Path(__file__).resolve()), depth=1)
            step6_health["tier1"]["ImportTracer.get_candidate_files_async"] = "✓"
        except Exception as e:
            step6_health["tier1"]["ImportTracer.get_candidate_files_async"] = f"✗ {e}"
            all_passed = False

        try:
            it.clear_cache()
            step6_health["tier1"]["ImportTracer.clear_cache"] = "✓"
        except Exception as e:
            step6_health["tier1"]["ImportTracer.clear_cache"] = f"✗ {e}"
            all_passed = False

        try:
            ac = ASTCache(max_size=10)
            _ = await ac.get("<test>", content=_TEST_SOURCE)
            step6_health["tier1"]["ASTCache.get"] = "✓"
        except Exception as e:
            step6_health["tier1"]["ASTCache.get"] = f"✗ {e}"
            all_passed = False

        # Tier 2: Script-level — all components wired together
        try:
            it2 = ImportTracer(str(Path(__file__).parent))
            _ = await it2.trace_imports(str(Path(__file__).resolve()), depth=1)
            it2.clear_cache()
            ac2 = ASTCache(max_size=10)
            _ = await ac2.get("<test>", content=_TEST_SOURCE)
            step6_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step6_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step6_health['tier1'].values() if v == '✓'])
        total = len(step6_health['tier1'])
        print(f"  Tier 1: {ok}/{total} functions OK")
        print(f"  Tier 2: {step6_health['tier2'].get('integrated_workflow', '✗')}")

    except ImportError as e:
        step6_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_6_rca"] = step6_health

    # ─────────────────────────────────────────────────────────────
    # Step 7: Signature Detector (10 modules)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 7: Signature engine")
    step7_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from signature_engine.core import FunctionType, HardRequirements, CanonicalDefinition, AuthorshipSignature
        from signature_engine.signatures import AuthorshipSignatureDatabase, get_signature_database, get_default_signatures
        from signature_engine.authorship_rules import DEFAULT_AUTHORSHIP_SIGNATURES, get_signatures_by_category, get_signature_by_name
        from signature_engine.hallucinations import MISSPELLED_BUILTINS, is_misspelled_builtin, get_correct_builtin
        from signature_engine.stdlib import STDLIB_MODULES as FD_STDLIB, is_stdlib_module
        from signature_engine.packages import COMMON_PACKAGES as FD_PACKAGES, is_common_package, get_package_category
        from signature_engine.dunders import DUNDER_METHODS, is_dunder, get_dunder_category
        from signature_engine.canonicals import DEFAULT_CANONICALS as FD_CANONICALS, get_canonical, get_requirements, validate_against_canonical
        from signature_engine.builtins_registry import PYTHON_BUILTINS, is_builtin, get_builtin_info

        # Tier 1: Function-level — one check per module
        for fn_name, fn in [  # type: ignore[assignment]  # FIX_54 ast-pos
            ("core.FunctionType", lambda: FunctionType.VALIDATOR),
            ("signatures.get_default_signatures", lambda: get_default_signatures()),
            ("signatures.get_signatures_by_category", lambda: get_signatures_by_category("hallucination")),
            ("hallucinations.is_misspelled_builtin", lambda: is_misspelled_builtin("pirnt")),
            ("stdlib.is_stdlib_module", lambda: is_stdlib_module("os")),
            ("packages.is_common_package", lambda: is_common_package("numpy")),
            ("dunders.is_dunder", lambda: is_dunder("__init__")),
            ("canonicals.get_canonical", lambda: get_canonical(FunctionType.VALIDATOR)),
            ("builtins.is_builtin", lambda: is_builtin("print")),
        ]:
            try:
                fn()
                step7_health["tier1"][fn_name] = "✓"
            except Exception as e:
                step7_health["tier1"][fn_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Script-level — gateway integration
        try:
            db = await get_signature_database()
            scan = db.scan(_TEST_SOURCE)
            canon = get_canonical(FunctionType.VALIDATOR)
            reqs = get_requirements(FunctionType.VALIDATOR)
            violations = validate_against_canonical(FunctionType.VALIDATOR, has_params=True, has_return=True, has_comparison=True)
            _ = get_correct_builtin("pirnt")
            _ = get_package_category("numpy")
            _ = get_dunder_category("__init__")
            _ = get_builtin_info("print")
            step7_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step7_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step7_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/{len(step7_health['tier1'])} modules OK")
        print(f"  Tier 2: {step7_health['tier2'].get('integrated_workflow', '✗')}")

    except ImportError as e:
        step7_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_7_signature_engine"] = step7_health

    # ─────────────────────────────────────────────────────────────
    # Step 8: Detection (AIFakeDetector + 10 check mixins)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 8: Detection")
    step8_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from no_aivalidator.detection.base import AIFakeDetector
        from no_aivalidator.detection.core_checks import CoreChecksMixin
        from no_aivalidator.detection.structural_checks import StructuralChecksMixin
        from no_aivalidator.detection.math_checks import MathChecksMixin
        from no_aivalidator.detection.advanced_checks import AdvancedChecksMixin
        from no_aivalidator.detection.hallucination_checks import HallucinationChecksMixin
        from no_aivalidator.detection.redundancy_checks import RedundancyChecksMixin
        from no_aivalidator.detection.safety_checks import SafetyChecksMixin
        from no_aivalidator.detection.style_checks import StyleChecksMixin
        from no_aivalidator.detection.semantic_checks import SemanticChecksMixin
        from no_aivalidator.detection.extended_semantic_checks import ExtendedSemanticChecksMixin

        # FIX_25 (2026-09-15): the package-level lazy export resolves and IS the class the submodule
        # defines (the 11 tuples in detection/__init__.py pointed at the dropped `gauntlet.detection`).
        try:
            import no_aivalidator.detection as _det_pkg
            _pkg_cls = _det_pkg.AIFakeDetector
            assert _pkg_cls is AIFakeDetector, "package-level AIFakeDetector is not base.AIFakeDetector"
            _pkg_mixin = _det_pkg.ExtendedSemanticChecksMixin
            assert _pkg_mixin is ExtendedSemanticChecksMixin, "package-level ExtendedSemanticChecksMixin differs"
            step8_health["tier1"]["package-level lazy export (FIX_25)"] = "✓"
        except Exception as e:
            step8_health["tier1"]["package-level lazy export (FIX_25)"] = f"✗ {e}"
            all_passed = False

        # Tier 1: Verify each mixin is importable and a class
        for mixin_name, mixin_cls in [
            ("AIFakeDetector", AIFakeDetector),
            ("CoreChecksMixin", CoreChecksMixin),
            ("StructuralChecksMixin", StructuralChecksMixin),
            ("MathChecksMixin", MathChecksMixin),
            ("AdvancedChecksMixin", AdvancedChecksMixin),
            ("HallucinationChecksMixin", HallucinationChecksMixin),
            ("RedundancyChecksMixin", RedundancyChecksMixin),
            ("SafetyChecksMixin", SafetyChecksMixin),
            ("StyleChecksMixin", StyleChecksMixin),
            ("SemanticChecksMixin", SemanticChecksMixin),
            ("ExtendedSemanticChecksMixin", ExtendedSemanticChecksMixin),
        ]:
            try:
                assert isinstance(mixin_cls, type), f"{mixin_name} is not a class"
                step8_health["tier1"][mixin_name] = "✓"
            except Exception as e:
                step8_health["tier1"][mixin_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Script-level — AIFakeDetector runs all checks
        try:
            from no_aivalidator.noai_validator.extractor import MetricsExtractor as _HC_Extractor
            tree = ast.parse(_TEST_SOURCE)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    ext = _HC_Extractor(node, class_context=False, source=_TEST_SOURCE)  # type: ignore[assignment]  # FIX_54 ast-pos
                    detector = AIFakeDetector(
                        metrics=ext.metrics,
                        func_node=node,
                    )
                    issues = await detector.run_all_checks()  # type: ignore[assignment]  # FIX_54 ast-pos
                    break
            step8_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step8_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        # I-01 (2026-09-15, run 116): NAI-010 must DECIDE in this process. core_checks is the first module of the
        # package imported here, so its module-top `VariableTracker` import failed on the package cycle and was None
        # for the rest of the process — the recall guard's by-id count ran one short on every run. The lazy binding
        # resolves at first use; a dead name on no acceptable list must be observed by NAI-010 right here.
        try:
            import no_aivalidator.detection.core_checks as _cc01
            _src01 = "def dead_name_holder(v):\n    total_unused = v * 2\n    return v\n"
            _fn01 = next(n for n in ast.walk(ast.parse(_src01)) if isinstance(n, ast.FunctionDef))
            _ext01 = _HC_Extractor(_fn01, class_context=False, source=_src01)
            _det01 = AIFakeDetector(metrics=_ext01.metrics, func_node=_fn01)
            await _det01.run_all_checks()
            assert _cc01.VariableTracker is not None, "I-01: VariableTracker must be bound after the first NAI-010 pass"
            _obs01 = [o for o in getattr(_det01, "observations", []) if o.get("tag") == "NAI-010"]
            assert _obs01 and "total_unused" in _obs01[0].get("dead_variables", []), f"I-01: NAI-010 must observe the dead name in this process, got {_obs01}"
            step8_health["tier2"]["nai010_decides_in_process (I-01)"] = "✓ VariableTracker bound lazily; NAI-010 observed `total_unused`"
        except Exception as e:
            step8_health["tier2"]["nai010_decides_in_process (I-01)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        ok = len([v for v in step8_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/{len(step8_health['tier1'])} OK (11 classes + the package-level lazy export, FIX_25)")
        print(f"  Tier 2: {step8_health['tier2'].get('integrated_workflow', '✗')}")
        print(f"  {step8_health['tier2'].get('nai010_decides_in_process (I-01)', '✗ not run')} — nai010_decides_in_process (I-01)")

    except ImportError as e:
        step8_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_8_detection"] = step8_health

    # ─────────────────────────────────────────────────────────────
    # Step 9: NoAI Validator (14 modules)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 9: NoAI Validator")
    step9_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from no_aivalidator.noai_validator.validator import NoAIMathValidator
        from no_aivalidator.noai_validator.collector import FunctionCollector
        # FIX_34 (2026-09-10): ProjectIndexer archived (indexer.py → .archive/archived_20260910/), no import
        from no_aivalidator.noai_validator.identifier import VariableTracker, FunctionIdentifier
        from no_aivalidator.noai_validator.extractor import MetricsExtractor as NAI_HC_Extractor
        from no_aivalidator.noai_validator.models import (
            FunctionInfo as NAI_HC_FI, ParseError as NAI_HC_PE,
            LambdaMetrics as NAI_HC_LM, ComprehensionInfo as NAI_HC_CI,
            StringValidationResult as NAI_HC_SVR,
        )
        from no_aivalidator.noai_validator.strict_checks import (
            is_naive_constant_ignore as _hc_sc1, is_exact_identity as _hc_sc2,
            is_canned_static_dict as _hc_sc3,  # is_dead_simple_body (_hc_sc4) removed: NAI-019S deleted, cut 2 2026-09-05
            is_alias_identity_chain as _hc_sc5, is_sophisticated_identity_chain as _hc_sc6,
            has_dead_zero_arithmetic as _hc_sc7, has_self_canceling_arithmetic as _hc_sc8,
            is_for_loop_identity_accumulator as _hc_sc9,
        )
        from no_aivalidator.noai_validator.config import DEFAULT_CONFIG as NAI_HC_CFG
        # ToleranceCalibrator (§4.2/4.3 statistical outlier detection): STRUCK
        # 2026-09-05 (plan item 9). No working example exists in any copy
        # (REFERENCE_AUDIT 2026-09-05, Part A), and a tolerance/outlier scorer
        # contradicts the engine's doctrine that every check is a binary verdict
        # with no severity, score or confidence. It is not a component: never
        # measured, never stubbed (a fake calibrator.py would be the species we
        # hunt). Reported as STRUCK so the gate says exactly that.
        NAI_HC_Cal = None
        step9_health["struck"] = [
            "always-pass repair validation: LOST 2026-09-06 (owner) — always-pass repair verdict from the 'atomic' era; premise (an upstream agent validated the repair) false here; the TESTER seat replaces it (REPAIR_LOOP_AND_TESTER_2026-09-07.md; owner 2026-09-07)",
            "calibrator: STRUCK 2026-09-05 (plan item 9) — no working example in any copy; "
            "binary-verdict doctrine leaves no place for a tolerance scorer"]
        from no_aivalidator.noai_validator.utils import (
            fingerprint_function as _hc_nai_fp, check_duplicate_functions as _hc_nai_dup,
        )
        # always-pass repair validation: LOST cut 3 round 1 (owner 2026-09-06) — see step 9 struck list
        from no_aivalidator.noai_validator import file_validation as _hc_fv
        from no_aivalidator.noai_validator.canonicals import DEFAULT_CANONICALS as NAI_HC_CANONS

        # Tier 1: Function-level — one check per module
        _hc_tree = ast.parse(_TEST_SOURCE)
        _hc_funcs = [n for n in ast.walk(_hc_tree) if isinstance(n, ast.FunctionDef)]
        _hc_node = _hc_funcs[0]

        def _hc_hr_observation():
            # FIX_18 (2026-09-10): a declared role's deficit is an OBSERVATION the ranker decides — a
            # @property with no return must publish {tag HR-002, type GETTER, deficit return, votes}.
            _t = ast.parse("class C:\n    @property\n    def p(self):\n        pass\n")
            _n = [n for n in ast.walk(_t) if isinstance(n, ast.FunctionDef)][0]
            _r = NoAIMathValidator().validate_function(_n, class_context=True)
            _hr = [o for o in (_r.triggered_patterns or []) if isinstance(o, dict) and o.get("tag") == "HR-002"]
            assert _hr and _hr[0].get("deficit") == "return" and _hr[0].get("type") == "GETTER" and "votes" in _hr[0], _r
            assert _r.passed is False and str(_r.failure_reason).startswith("HR-002"), _r.failure_reason
            assert _r.verdict_source == "ranker", _r.verdict_source
            return True

        for fn_name, fn in [
            ("validator.validate_function", lambda: NoAIMathValidator().validate_function(_hc_node)),
            ("validator.hr_observation (FIX_18)", _hc_hr_observation),
            ("collector.visit", lambda: FunctionCollector(_TEST_SOURCE).visit(_hc_tree)),
            ("extractor.metrics", lambda: NAI_HC_Extractor(_hc_node, class_context=False).metrics),
            ("identifier.identify", lambda: FunctionIdentifier(
                NAI_HC_Extractor(_hc_node, class_context=False).metrics, node=_hc_node
            ).identify()),
            ("variable_tracker", lambda: VariableTracker(_hc_node).unused_vars),
            ("strict.is_naive_constant_ignore", lambda: _hc_sc1(_hc_node)),
            ("strict.is_canned_static_dict", lambda: _hc_sc3(_hc_node)),
            ("strict.has_dead_zero_arithmetic", lambda: _hc_sc7(_hc_node)),
            ("strict.is_for_loop_identity_accumulator", lambda: _hc_sc9(_hc_node)),
            *([("calibrator.add_sample", lambda: NAI_HC_Cal().add_sample(
                FunctionType.VALIDATOR, NAI_HC_Extractor(_hc_node, class_context=False).metrics
            ))] if NAI_HC_Cal is not None else []),
            ("utils.fingerprint_function", lambda: _hc_nai_fp(_hc_node)),
            ("config.DEFAULT_CONFIG", lambda: NAI_HC_CFG.get("enable_cache")),   # FIX_26: the dead magnitude key is gone; a live key is read
            ("canonicals", lambda: NAI_HC_CANONS[FunctionType.VALIDATOR]),
        ]:
            try:
                fn()
                step9_health["tier1"][fn_name] = "✓"
            except Exception as e:
                step9_health["tier1"][fn_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Script-level — full pipeline
        try:
            v = NoAIMathValidator()
            coll = FunctionCollector(_TEST_SOURCE)
            coll.visit(ast.parse(_TEST_SOURCE))
            for fi in coll.functions:
                _ = v.validate_function(fi.node, class_context=fi.class_context)
            _ = v.validate_string(_TEST_SOURCE)
            # always-pass repair validation: LOST (cut 3 round 1, owner 2026-09-06) — nothing to exercise
            # file_validation
            sv = _hc_fv.validate_string(v, "def f(): return 1")
            assert isinstance(sv, NAI_HC_SVR)
            # calibrator: STRUCK (plan item 9, 2026-09-05) — nothing to exercise
            if NAI_HC_Cal is not None:
                cal = NAI_HC_Cal()
                _cm = NAI_HC_Extractor(_hc_node, class_context=False).metrics
                cal.add_sample(FunctionType.VALIDATOR, _cm)
                cal.add_bad_sample(FunctionType.VALIDATOR, _cm)
                _ = cal.generate_canonical(FunctionType.VALIDATOR)
                _ = cal.generate_tolerance_ranges(FunctionType.VALIDATOR)
                _ = cal.generate_signatures(FunctionType.VALIDATOR)
            step9_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step9_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        # FIX_34 (2026-09-10): the gathered per-file batch must be deterministic — two directory validations of
        # the same fixture dump the same rows in the same order — and must publish its timing (files, seconds,
        # s_per_file, concurrency) every run. Run on a worker thread's loop (the health check may sit in a loop).
        try:
            import tempfile as _hc_tmp, json as _hc_json, concurrent.futures as _hc_cf
            with _hc_tmp.TemporaryDirectory() as _td:
                _tdp = Path(_td)
                (_tdp / "alpha.py").write_text("def f(x):\n    return x\n\n\ndef g(y):\n    return y + 0\n", encoding="utf-8")
                (_tdp / "beta.py").write_text("import os\n\n\ndef h(items):\n    out = []\n    for i in items:\n        out.append(i)\n    return out\n", encoding="utf-8")
                _files = [_tdp / "alpha.py", _tdp / "beta.py"]

                def _hc_dump():
                    _r, _cf = asyncio.run(_hc_fv.validate_directory_async(NoAIMathValidator(), _tdp, files=_files))
                    return (_hc_json.dumps([(x.file_path, x.function_name, x.line, x.passed, x.failure_reason, list(x.warnings or [])) for x in _r]),
                            (_cf or {}).get("timing"))
                with _hc_cf.ThreadPoolExecutor(max_workers=1) as _ex:
                    _d1, _t1 = _ex.submit(_hc_dump).result()
                    _d2, _t2 = _ex.submit(_hc_dump).result()
            assert _d1 == _d2, "validate_directory_async: two runs of one fixture differ"
            assert _t1 and _t1.get("files") == 2 and "concurrency" in _t1 and "s_per_file" in _t1, f"timing not published: {_t1}"
            step9_health["tier2"]["directory_determinism_and_timing (FIX_34)"] = "✓"
        except Exception as e:
            step9_health["tier2"]["directory_determinism_and_timing (FIX_34)"] = f"✗ {e}"
            all_passed = False

        # FIX_47 (2026-09-17, owner Q7): the split-fake fact reaches THE RANKER as an observation.
        # A caller of a detector-failed helper that forwards none of its own params carries the
        # RCA-001 observation and the ranker decides the row on it; a caller of PASSING callees
        # carries none. The whole route is exercised (the fingerprint stage runs before the sweep).
        try:
            import tempfile as _hc_tmp47
            _sf_src = (
                '"""split-fake + control."""\n'
                'import os\n\n\n'
                'def load_table(name, version):\n'
                '    """Load the lookup table for a named dataset."""\n'
                '    return {"alpha": 1, "beta": 2, "gamma": 3}\n\n\n'
                'def read_config(path, strict):\n'
                '    """Read the configuration rooted at path."""\n'
                '    base = os.path.basename(path)\n'
                '    if strict and not base:\n'
                '        raise ValueError("path required")\n'
                '    table = load_table("default", 1)\n'
                '    merged = dict(table)\n'
                '    merged["source"] = base\n'
                '    return merged\n\n\n'
                'def describe(prefix, suffix):\n'
                '    """The control: a caller of a passing callee, forwarding its own params."""\n'
                '    joined = os.path.join(prefix, suffix)\n'
                '    return os.path.basename(joined)\n'
            )
            with _hc_tmp47.TemporaryDirectory() as _td47:
                _p47 = Path(_td47) / "split_fake.py"
                _p47.write_text(_sf_src, encoding="utf-8")
                _rows47 = await _hc_fv.validate_file_async(NoAIMathValidator(), _p47)
            _by47 = {r.function_name: r for r in _rows47}
            _rc47 = _by47["read_config"]
            _tok = [o for o in (_rc47.triggered_patterns or []) if isinstance(o, dict) and o.get("tag") == "RCA-001"]
            assert _by47["load_table"].passed is False, "the helper must fail for the sweep to have evidence"
            assert _tok, f"no RCA-001 observation on the split-fake caller: {_rc47.triggered_patterns}"
            assert _tok[0].get("callee") == "load_table" and _tok[0].get("magnitude") == 1, _tok[0]
            assert _tok[0].get("context") is not True, "the RCA-001 observation must reach the table as evidence"
            assert _rc47.passed is False and _rc47.verdict_source == "ranker", (_rc47.passed, _rc47.verdict_source)
            assert str(_rc47.failure_reason).startswith("RCA-001 (line "), _rc47.failure_reason
            assert _rc47.failure_layer is not None and _rc47.failure_layer.name == "AI_FAKE_DETECTOR", _rc47.failure_layer
            _ctl = _by47["describe"]
            assert not [o for o in (_ctl.triggered_patterns or [])
                        if isinstance(o, dict) and o.get("tag") == "RCA-001"], "control carries an RCA-001 token"
            step9_health["tier2"]["rca_001_observation_to_ranker (FIX_47)"] = "✓"
        except Exception as e:
            step9_health["tier2"]["rca_001_observation_to_ranker (FIX_47)"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step9_health['tier1'].values() if v == '✓'])
        total = len(step9_health['tier1'])
        print(f"  Tier 1: {ok}/{total} checks OK")
        print(f"  Tier 2: {step9_health['tier2'].get('integrated_workflow', '✗')}; determinism + timing (FIX_34): {step9_health['tier2'].get('directory_determinism_and_timing (FIX_34)', '✗')}; "
              f"RCA-001 observation -> ranker (FIX_47): {step9_health['tier2'].get('rca_001_observation_to_ranker (FIX_47)', '✗')}")
        for _nm in step9_health.get("not_measured", []):
            print(f"  Not measured: {_nm}")

    except ImportError as e:
        step9_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_9_noai_validator"] = step9_health

    # ─────────────────────────────────────────────────────────────
    # Step 10: RootCause Main (9 modules)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 10: RootCause Main")
    step10_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        # EvidenceBundle / RootCauseReport ARCHIVED 2026-09-10 (FIX_32 §4.3: one analyzer);
        # should_exclude_path ARCHIVED 2026-09-10 (FIX_14: the ONE walk is live_py_files).
        from rca_main.rca_unit import RootCauseUnit, CallerTracer
        from rca_main.import_graph import ImportGraphBuilder
        from rca_main.caller_map import CallerMapBuilder
        from rca_main.context_calculator import ContextLinesCalculator
        from rca_main.context_gathering_manager import ContextManager, get_file_summary as _hc_gfs
        from rca_main.onion_peeler import OnionPeeler, SolutionChain, peel_and_fix
        from rca_main.origin_tracer import (
            TraceContext, CrashArtifact, StackFrame,
            get_tracer, reset_tracer, trace_me, trace_class, run_with_tracing,
        )
        from rca_main.session_state import CacheMetrics, RootCauseSession
        from rca_main.constants import live_py_files as _hc_live_py

        _hc_repo = Path(__file__).parent
        # FIX_14 (2026-09-10): the smoke hands the ONE walk's list over, exactly as the validator does
        _hc_files = list(_hc_live_py(_hc_repo))

        # Tier 1: Function-level — one check per module
        for fn_name, fn in [  # type: ignore[assignment]  # FIX_54 ast-pos
            ("rca_unit.RootCauseUnit", lambda: RootCauseUnit(str(_hc_repo), files=_hc_files)),
            ("rca_unit.CallerTracer", lambda: CallerTracer(str(_hc_repo), files=_hc_files)),
            ("import_graph.ImportGraphBuilder", lambda: ImportGraphBuilder(_hc_repo, files=_hc_files)),
            ("caller_map.CallerMapBuilder", lambda: CallerMapBuilder(_hc_repo, files=_hc_files)),
            ("context_calculator.ContextLinesCalculator", lambda: ContextLinesCalculator(_hc_repo, files=_hc_files)),
            ("context_manager.ContextManager", lambda: ContextManager(str(_hc_repo), files=_hc_files)),
            ("onion_peeler.SolutionChain", lambda: SolutionChain()),
            ("origin_tracer.get_tracer", lambda: get_tracer()),
            ("origin_tracer.CrashArtifact", lambda: CrashArtifact()),
            ("origin_tracer.trace_class", lambda: trace_class(type("_X", (), {"m": lambda self: 1}))),
            ("session_state.CacheMetrics", lambda: CacheMetrics(hits=1, misses=1, evictions=0)),
            ("constants.live_py_files", lambda: _hc_live_py(_hc_repo)),
        ]:
            try:
                fn()
                step10_health["tier1"][fn_name] = "✓"
            except Exception as e:
                step10_health["tier1"][fn_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Script-level — components wired together
        try:
            # import_graph: scan + get_imports/get_importers/get_import_depth/get_coupling_score
            ig = ImportGraphBuilder(_hc_repo, files=_hc_files)
            await ig.scan()
            if ig.file_imports:
                _sample = next(iter(ig.file_imports))
                _ = ig.get_imports(_sample)
                _ = ig.get_importers(_sample)
                _ = ig.get_import_depth(_sample)
                _ = ig.get_coupling_score(_sample)

            # caller_map: scan + get_callers/get_callees/get_call_depth/get_cross_file_caller_count
            cm = CallerMapBuilder(_hc_repo, files=_hc_files)
            await cm.scan()
            if cm.functions:
                _sf = next(iter(cm.functions))
                _ = cm.get_callers(_sf)
                _ = cm.get_callees(_sf)
                _ = cm.get_call_depth(_sf)
                _ = cm.get_cross_file_caller_count(_sf)
                for _qn in cm.class_inheritance:
                    _ = cm.get_inherited_methods(_qn)
                    break
                if ig.file_imports:
                    _ = cm.get_class_coupling(next(iter(ig.file_imports)))

            # context_calculator: scan + scan_async
            calc = ContextLinesCalculator(_hc_repo, files=_hc_files)
            await calc.scan()
            calc2 = ContextLinesCalculator(_hc_repo, files=_hc_files)
            await calc2.scan_async()

            # context_manager (FIX_33 API): related_files_async, find_relevant_docs_async, get_file_summary
            ctxm = ContextManager(str(_hc_repo), files=_hc_files)
            _ = await ctxm.related_files_async(str(Path(__file__).resolve()))
            kws = ctxm.extract_keywords_from_context("gate", "health_check.py")
            _ = await ctxm.find_relevant_docs_async(kws)
            _ = await _hc_gfs(str(_hc_repo), files=_hc_files)
            # FIX_33 step 3 (Item 8, 2026-09-15): the docs as discrete facts for the intent file
            import tempfile as _tf33
            _fx33 = Path(_tf33.mkdtemp(prefix="hc_fix33_"))
            (_fx33 / "docs").mkdir()
            (_fx33 / "docs" / "guide.md").write_text("# guide\n\nThe gate runs every launch.\n")
            (_fx33 / "app.py").write_text("def gate():\n    return 1\n")
            _df = await ContextManager(str(_fx33), files=["app.py"]).doc_facts_async(["gate", "zzz_absent"])
            # I-22 (run 117, 2026-09-15): the docs facts carry their own label `doc_mention`, not the `docs` species
            assert len(_df) == 1 and _df[0]["source"] == "doc_mention" and _df[0]["value"] == "gate" \
                and _df[0]["evidence"].startswith("docs/guide.md:3"), _df
            step10_health["tier2"]["context_manager.doc_facts_async (FIX_33 step 3)"] = f"✓ {_df[0]['evidence']}"

            # FIX_32 / FIX_33 fixture (2026-09-10): a leaf `b.py` imported by `a.py` and `c.py`, a
            # sibling `config.py`, a matching `test_b.py`; an infraction in b → the candidates carry
            # BOTH callers with the downstream line and the two related-by-context lines.
            import tempfile as _tf32
            _fx = Path(_tf32.mkdtemp(prefix="hc_fix32_"))
            (_fx / "b.py").write_text("def leaf(x):\n    return x\n")
            (_fx / "a.py").write_text("import b\n\ndef use_a():\n    return b.leaf(1)\n")
            (_fx / "c.py").write_text("from b import leaf\n\ndef use_c():\n    return leaf(2)\n")
            (_fx / "config.py").write_text("LIMIT = 3\n")
            (_fx / "test_b.py").write_text("import b\n\ndef test_leaf():\n    assert b.leaf(1) == 1\n")
            _fx_files = list(_hc_live_py(_fx))
            _fx_unit = RootCauseUnit(str(_fx), files=_fx_files)
            _cands = await _fx_unit.analyze_async(str(_fx / "b.py"), error_message="leaf returned wrong value")
            _down = {Path(k).name for k, v in _cands.items() if any(e.startswith("Downstream caller of failing file") for e in v)}
            assert {"a.py", "c.py"} <= _down, f"FIX_32 downstream callers missing: {_cands}"
            _rel = {(Path(k).name, e) for k, v in _cands.items() for e in v if e.startswith("Related by context")}
            assert ("config.py", "Related by context (config_sibling)") in _rel, f"FIX_33 config sibling missing: {_cands}"
            assert ("test_b.py", "Related by context (test)") in _rel, f"FIX_33 test missing: {_cands}"

            # onion_peeler: peel callable, SolutionChain, rollback
            op = OnionPeeler(target_app="test", working_dir=str(_hc_repo))
            _ = op.get_chain_status()
            sc = SolutionChain()
            _ = sc.get_all_code()
            _ = await op.rollback_all()
            assert callable(peel_and_fix)

            # origin_tracer: enter, exit, report_crash, trace_me, run_with_tracing
            reset_tracer()
            tr = get_tracer()
            tr.enter("hc_fn", "mod.hc_fn", "hc.py", {"a": 1})
            tr.exit("hc_fn", 42)
            tr.enter("crash_fn", "mod.crash_fn", "hc.py", {})
            try:
                raise ValueError("hc crash")
            except ValueError as _e:
                _ = tr.report_crash("crash_fn", _e, 1, {})

            def _hc_trivial() -> int:
                return 99
            _rv, _ca = run_with_tracing(_hc_trivial)
            assert _rv == 99 and _ca is None

            @trace_me
            def _hc_dec(x: int) -> int:
                return x * 2
            assert _hc_dec(3) == 6

            # session_state
            cm_obj = CacheMetrics(hits=10, misses=5, evictions=1)
            assert cm_obj.hit_rate > 0
            _ = cm_obj.to_dict()
            _ = cm_obj.check_health()

            async with RootCauseSession(
                session_id="hc_test", repo_path=str(_hc_repo), auto_cleanup=True,
            ) as _ss:
                _ = _ss.get_metrics()

            # rca_unit: analyze_async + find_callers_async/recursive
            fu = RootCauseUnit(str(_hc_repo), files=_hc_files)
            await fu.build_relationship_graphs_async()
            _cli_file = str(Path(__file__).resolve())
            _ = await fu.analyze_async(_cli_file, error_message="test")
            ct = CallerTracer(str(_hc_repo), files=_hc_files)
            _ = await ct.find_callers_async(_cli_file)
            _ = await ct.find_callers_recursive(_cli_file, depth=1)

            step10_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step10_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step10_health['tier1'].values() if v == '✓'])
        total = len(step10_health['tier1'])
        print(f"  Tier 1: {ok}/{total} checks OK")
        print(f"  Tier 2: {step10_health['tier2'].get('integrated_workflow', '✗')}")

    except ImportError as e:
        step10_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_10_rca_main"] = step10_health

    # ─────────────────────────────────────────────────────────────
    # Step 11: the cheatsheets daemon (BUILDER_DAEMON.py, gearbox child #4; item 1, 2026-09-08)
    # Tier 1: the fourth daemon's module imports and the Ranker's decision point exist.
    # Tier 2: a fixture state with ONE NAI-071 plant is built through
    # CheatsheetBuilder.build_rows → the row carries a digest, the Ranker picked
    # mutable_default_fix, the observations say parse=ok / differs=yes, and the mirror
    # written into the fixture dir has the digest on its one repair and no review_status.
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 11: cheatsheets daemon")
    step11_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from no_aivalidator.BUILDER_DAEMON import (
            CheatsheetBuilder, BuilderDaemon, stage_mirror, _rule_fixer_map, _build_graph_context,
        )
        from no_aivalidator.cheatsheets.cheatsheet_intelligence.knowledge_base import (
            SolutionRanker, Decision, candidate_pickable,
        )
        from no_aivalidator.cheatsheets.cheatsheet_reviewer import CodeAnalyzer
        from no_aivalidator.repair_generators import for_rule as _rg_for_rule, REGISTRY as _rg_registry

        for comp_name, comp in [
            ("CheatsheetBuilder", CheatsheetBuilder),
            ("repair_generators.for_rule", _rg_for_rule),
            ("repair_generators.REGISTRY (non-empty)", (lambda: True) if _rg_registry else None),
            ("BuilderDaemon", BuilderDaemon),
            ("stage_mirror", stage_mirror),
            ("_rule_fixer_map", _rule_fixer_map),
            ("_build_graph_context", _build_graph_context),
            ("SolutionRanker.decide", getattr(SolutionRanker, "decide", None)),
            ("Decision", Decision),
            ("candidate_pickable", candidate_pickable),
            ("CodeAnalyzer.analyze", getattr(CodeAnalyzer, "analyze", None)),
        ]:
            try:
                assert callable(comp), f"{comp_name} is not callable"
                step11_health["tier1"][comp_name] = "✓"
            except Exception as e:
                step11_health["tier1"][comp_name] = f"✗ {e}"
                all_passed = False

        try:
            fmap = _rule_fixer_map()
            assert set(fmap) >= {"NAI-071", "NAI-092", "NAI-093"}, f"fixer map lost an entry: {sorted(fmap)}"
            step11_health["tier1"]["fixer_map"] = f"✓ {len(fmap)} rule ids"
        except Exception as e:
            step11_health["tier1"]["fixer_map"] = f"✗ {e}"
            all_passed = False

        # Tier 2: the fixture plant
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                plant = Path(tmpdir) / "plant.py"
                plant.write_text("def collect(items=[]):\n    items.append(1)\n    return items\n")
                fixture_state = {
                    "phase": "MONITORING", "target_repo": tmpdir, "last_scan": "fixture",
                    "summary": {"total_functions": 1, "passed": 0, "failed": 1, "files_scanned": 1},
                    "flagged_nodes": ["plant"],
                    "results_by_file": {"plant.py": [{
                        "function": "collect", "line": 1, "end_line": 3, "passed": False,
                        "rule_ids": ["NAI-071"], "context_ids": [], "finding_lines": [1],
                        "failure_layer": "detection", "failure_reason": "NAI-071: mutable default argument",
                        "triggered_patterns": [{"tag": "NAI-071", "line": 1}],
                    }, {
                        # FIX_51 (owner Q11, 2026-09-15): a WITHHELD row — a published PASS the ranker
                        # withheld a verdict on because of the file's species. Neither a repair nor a
                        # no_vetted_fix; the mirror must carry it under its own key with its reason.
                        "function": "test_collect", "line": 5, "end_line": 6, "passed": True,
                        "rule_ids": [], "context_ids": ["NAI-020"], "finding_lines": [],
                        "species": "test", "withheld": "species:test",
                        "failure_layer": None, "failure_reason": None, "triggered_patterns": [],
                    }]},
                    "cross_file_analysis": {"stale_for_files": []}, "semantic_analysis": {},
                }
                rows, bsummary = await CheatsheetBuilder().build_rows(
                    fixture_state, circuit={"nodes": [{"name": "plant", "imports": []}]})
                row = rows["plant.py::collect::1"]
                assert row["digest"], "row has no digest"
                assert row["decision"]["pick_role"] == "mutable_default_fix", f"pick_role = {row['decision']['pick_role']!r}"
                obs = row["observations"].get("mutable_default_fix", [])
                assert "parse=ok" in obs and "differs=yes" in obs, f"observations = {obs}"
                assert "if items is None" in row["after_code"], "rewrite missing the None guard"
                assert bsummary["with_fix"] == 1 and bsummary["findings"] == 1, f"summary = {bsummary}"
                n_rep, n_nvf, n_dirs = stage_mirror(
                    rows, fixture_state, bsummary, target_repo=tmpdir, return_channel="",
                    system_copy=Path(tmpdir) / ".sys_copy.json", severed_links=[["plant", "gone"]])
                import scan_scope as _ss_mirror  # the ONE mirror location (owner ruling 2026-09-28)
                mirror_dir = _ss_mirror.mirror_path(Path(tmpdir), Path(tmpdir), ".noai_state.json").parent
                mirror = json.loads((Path(mirror_dir) / ".noai_state.json").read_text())
                assert n_rep == 1 and mirror["repairs"][0]["digest"] == row["digest"], "mirror repair digest mismatch"
                assert "review_status" not in json.dumps(mirror) and "gate_rejection" not in json.dumps(mirror), "post-ranker verdict field in the mirror"
                assert (mirror.get("wiring") or {}).get("severed") == [["plant", "gone"]] and mirror["wiring"].get("drawn") == "red", f"ITEM_11: the mirror carries wiring.severed as text, red: {mirror.get('wiring')}"
                # FIX_51 (owner Q11): the withheld rows are IN the counterfeit-code mirror, under their
                # own key, each with the reason — and the count matches the validator's line.
                _wh = mirror.get("withheld")
                assert isinstance(_wh, list) and len(_wh) == 1, f"FIX_51: mirror.withheld is not the one fixture row: {_wh}"
                assert _wh[0]["function"] == "test_collect" and _wh[0]["withheld"] == "species:test", f"FIX_51: withheld row lost its reason: {_wh[0]}"
                assert mirror["summary"]["withheld"] == len(_wh), f"FIX_51: summary.withheld != len(withheld): {mirror['summary']}"
                assert all(r["function"] != "test_collect" for r in mirror["repairs"] + mirror["no_vetted_fix"]), "FIX_51: a withheld row must be neither a repair nor a no_vetted_fix"
                # unchanged infraction + evidence → the row is reused, revision stable
                rows2, _ = await CheatsheetBuilder().build_rows(
                    fixture_state, previous=rows, circuit={"nodes": [{"name": "plant", "imports": []}]})
                assert rows2["plant.py::collect::1"]["digest"] == row["digest"] and rows2["plant.py::collect::1"]["built_at"] == row["built_at"], "an unchanged row was rebuilt"
            step11_health["tier2"]["nai071_plant"] = (
                f"✓ one NAI-071 plant → pick mutable_default_fix, digest {row['digest']}, "
                f"observations {obs}, mirror repair digest matches, no review_status; "
                f"FIX_51: mirror.withheld carries the 1 withheld row with its reason, summary matches")
        except Exception as e:
            step11_health["tier2"]["nai071_plant"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        ok = len([v for v in step11_health['tier1'].values() if str(v).startswith('✓')])
        print(f"  Tier 1: {ok}/{len(step11_health['tier1'])} components OK")
        print(f"  Tier 2: {step11_health['tier2'].get('nai071_plant', '✗')}")

    except ImportError as e:
        step11_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    # Item 8 (2026-09-15): the intent file — ProjectProfile's discrete fields; the fixed-rule statement extractor
    # returns the five fact kinds on a fixture whose `orders` module corroborates the entry point.
    try:
        import tempfile as _tf8, sys as _sys8
        from no_aivalidator.cheatsheets.cheatsheet_intelligence.knowledge_base import ProjectProfile as _PP8, SolutionRanker as _SR8, SolutionCandidate as _SC8
        _pp = _PP8()
        for _f in ("domain", "entry_points", "expected_inputs", "expected_outputs", "runner", "external_systems",
                   "statement_present", "intent_facts_by_source"):
            assert hasattr(_pp, _f), f"ProjectProfile lacks {_f}"
        _ss8 = str(Path(__file__).resolve().parent)
        if _ss8 not in _sys8.path:
            _sys8.path.insert(0, _ss8)
        import intent_file as _intent8
        with _tf8.TemporaryDirectory(prefix="hc_item8_") as _d8:
            (Path(_d8) / "orders").mkdir()
            (Path(_d8) / "orders" / "__init__.py").write_text("")
            (Path(_d8) / "orders" / "__main__.py").write_text("def main():\n    pass\n")
            _txt = "A command line tool that reads a CSV of orders and writes a JSON report; run with `python -m orders`; tests with pytest"
            _facts = _intent8.extract_statement_facts(_txt, Path(_d8))
            _got = {(f["fact"], f["value"]) for f in _facts}
            assert _got == {("domain", "cli"), ("entry_point", "orders"), ("expected_input", "csv"),
                            ("expected_output", "json"), ("runner", "pytest")}, sorted(_got)
            assert all(f["source"] == "developer" and f["evidence"] for f in _facts), _facts
            assert _intent8.extract_statement_facts("", Path(_d8)) == [], "empty statement must yield no fact"
            # write → read → the profile holds the facts; then the file is removed (hygiene: no fixture intent file stays)
            _intent8.submit_statement(Path(_d8), _txt)
            try:
                _prof = _SR8._read_intent_file(Path(_d8), _PP8())
                assert _prof.statement_present and _prof.entry_points == ["orders"] and _prof.runner == ["pytest"] \
                    and _prof.expected_inputs == ["csv"] and _prof.expected_outputs == ["json"] and _prof.domain == ["cli"], _prof
                _rk = _SR8(project_profile=_prof)
                _c_keep = _SC8(solution="s", role="keep", before_code="import orders\nx = orders.run()", after_code="import orders\nx = orders.run(1)")
                _c_drop = _SC8(solution="s", role="drop", before_code="import orders\nx = orders.run()", after_code="x = 1")
                _s_keep = _rk._score_framework_match(_c_keep); _s_drop = _rk._score_framework_match(_c_drop)
                assert _s_keep > _s_drop and "entry_point:orders" in _c_keep.profile_matches \
                    and any("DROPPED" in m for m in _c_drop.profile_matches), (_s_keep, _s_drop, _c_keep.profile_matches, _c_drop.profile_matches)
            finally:
                _intent8.path(Path(_d8)).unlink(missing_ok=True); _intent8._lock_path(Path(_d8)).unlink(missing_ok=True)
        step11_health["tier2"]["intent_file (Item 8)"] = "✓ five facts (cli, orders, csv, json, pytest); profile fields; entry-point kept > dropped"
    except Exception as e:
        step11_health["tier2"]["intent_file (Item 8)"] = f"✗ {type(e).__name__}: {e}"
        all_passed = False
    print(f"  Item 8: {step11_health['tier2'].get('intent_file (Item 8)', '✗')}")
    # Item 9 (2026-09-15): a tester failure log → facts by the fixed rules (source tester, evidence = the digest)
    try:
        import tempfile as _tf9, sys as _sys9
        _ss9 = str(Path(__file__).resolve().parent)
        if _ss9 not in _sys9.path:
            _sys9.path.insert(0, _ss9)
        import intent_file as _intent9
        with _tf9.TemporaryDirectory(prefix="hc_item9_") as _d9:
            (Path(_d9) / "orders").mkdir(); (Path(_d9) / "tests").mkdir()
            (Path(_d9) / "orders" / "__init__.py").write_text("def total(xs):\n    return sum(xs)\n")
            (Path(_d9) / "tests" / "test_orders.py").write_text("def test_total():\n    assert 1\n")
            _log = ("============================= test session starts ==============================\n"
                    "tests/test_orders.py F\n"
                    "    def test_total():\n>       assert orders.total([1, 2]) == 4\nE       assert 3 == 4\n"
                    "tests/test_orders.py:5: AssertionError\n"
                    "Traceback (most recent call last):\n"
                    f'  File "{_d9}/tests/test_orders.py", line 5, in test_total\n    assert orders.total([1, 2]) == 4\n'
                    f'  File "{_d9}/orders/__init__.py", line 2, in total\n    return sum(xs)\n'
                    "AssertionError: 3 != 4\n")
            _entry = {"digest": "0123456789", "replace_span": "orders/__init__.py:L1-L2", "outcome": "failed", "failure_log": _log, "tester": "hc", "timestamp": "t"}
            _f9 = _intent9.extract_failure_log_facts(_entry, Path(_d9))
            _got9 = {(f["fact"], f["value"]) for f in _f9}
            assert _got9 == {("exception_type", "AssertionError"), ("module_under_test", "orders/__init__.py"),
                             ("function_under_test", "orders/__init__.py::total"), ("expected_literal", "4"),
                             ("actual_literal", "3"), ("runner", "pytest")}, sorted(_got9)
            assert all(f["source"] == "tester" and f["evidence"].startswith("0123456789") for f in _f9), _f9
            assert _intent9.extract_failure_log_facts({**_entry, "failure_log": "build failed"}, Path(_d9)) == [], "no fact from a log with nothing to read"
            assert _intent9.extract_failure_log_facts({**_entry, "outcome": "confirmed"}, Path(_d9)) == [], "a confirmed line carries no failure"
        step11_health["tier2"]["tester_facts (Item 9)"] = "✓ six facts from a pytest log (AssertionError, orders/__init__.py::total, 4 vs 3, pytest); nothing from an empty log or a confirmed line"
    except Exception as e:
        step11_health["tier2"]["tester_facts (Item 9)"] = f"✗ {type(e).__name__}: {e}"
        all_passed = False
    print(f"  Item 9: {step11_health['tier2'].get('tester_facts (Item 9)', '✗')}")
    results["steps"]["step_11_builder"] = step11_health

    # ─────────────────────────────────────────────────────────────
    # Step 12: Detritus Cleaner
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 12: Detritus Cleaner")
    step12_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from detritus_cleaner import DetritusCleaner, DetritusConfig, CleanseResult
        from detritus_cleaner.graph import ImportGraphBuilder  # type: ignore[assignment]  # FIX_54 ast-pos
        from detritus_cleaner.holding import HoldingManager
        from detritus_cleaner.models import FileStatus

        for comp_name, comp in [
            ("DetritusCleaner", DetritusCleaner),
            ("DetritusConfig", DetritusConfig),
            ("CleanseResult", CleanseResult),
            ("ImportGraphBuilder", ImportGraphBuilder),
            ("HoldingManager", HoldingManager),
            ("FileStatus", FileStatus),
        ]:
            try:
                assert comp is not None, f"{comp_name} is None"
                step12_health["tier1"][comp_name] = "✓"
            except Exception as e:
                step12_health["tier1"][comp_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Integration — scan a test directory
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Create a minimal test file
                test_file = Path(tmpdir) / "test_entry.py"
                test_file.write_text("print('hello')\n")
                cleaner = DetritusCleaner(tmpdir)
                result = await cleaner.scan()
                assert isinstance(result, CleanseResult), "scan() didn't return CleanseResult"
                step12_health["tier2"]["scan_integration"] = "✓"
        except Exception as e:
            step12_health["tier2"]["scan_integration"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step12_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/6 components OK")
        print(f"  Tier 2: {step12_health['tier2'].get('scan_integration', '✗')}")

    except ImportError as e:
        step12_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    # Step 12b: ARTIFACT SCANNER (Item 3, 2026-09-10) — one stage under that name: species by content with the proxy
    # kinds, the whole-file stub consult, the dot-dir intent sources. Tier 1 imports the five names; tier 2 a temp
    # target with demo.py / app.py / README.md / .github/workflows/ci.yml / a stub file.
    print("\n▶ Step 12b: Artifact scanner")
    step12b_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}
    try:
        from no_aivalidator.artifact_scanner import analyze as _as_analyze, ArtifactReport, SpeciesFact, IntentFact, STUB_KINDS
        for comp_name, comp in [("analyze", _as_analyze), ("ArtifactReport", ArtifactReport), ("SpeciesFact", SpeciesFact),
                                ("IntentFact", IntentFact), ("STUB_KINDS", STUB_KINDS)]:
            step12b_health["tier1"][comp_name] = "✓" if comp is not None else "✗ None"
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                _t = Path(tmpdir)
                (_t / "app.py").write_text("def add(a, b):\n    return a + b\n\n\ndef total(xs):\n    return sum(add(x, 1) for x in xs)\n")
                (_t / "demo.py").write_text("print('hello')\nprint('world', 42)\n")
                (_t / "shim.py").write_text("import sys\nfrom app import total\nsys.exit(total([1]))\n")
                (_t / "proto.py").write_text("def a():\n    ...\n\n\ndef b():\n    ...\n")
                (_t / "README.md").write_text("# demo\n\nRun the tests:\n\n```\npytest\n```\n")
                (_t / ".github" / "workflows").mkdir(parents=True)
                (_t / ".github" / "workflows" / "ci.yml").write_text("jobs:\n  t:\n    steps:\n      - run: pytest -q\n")
                _rep = await _as_analyze(_t)
                assert _rep.species["demo.py"].species == "proxy:demo", _rep.species["demo.py"].as_dict()
                assert _rep.species["app.py"].species == "", _rep.species["app.py"].as_dict()
                assert _rep.species["shim.py"].species == "proxy:entry_shim", _rep.species["shim.py"].as_dict()
                assert _rep.stubs.get("proto.py") == "ellipsis_body", _rep.stubs
                _facts = {(f.fact, f.value, f.source) for f in _rep.intent_facts}
                assert ("runner", "pytest", "ci_workflow") in _facts, sorted(_facts)
                assert ("runner", "pytest", "readme") in _facts, sorted(_facts)
                assert _rep.whitelist_entries() == [{"path": "proto.py", "reason": "stub:ellipsis_body"}], _rep.whitelist_entries()
                step12b_health["tier2"]["classify_integration"] = "✓"
        except Exception as e:
            step12b_health["tier2"]["classify_integration"] = f"✗ {e}"
            all_passed = False
        print(f"  Tier 1: {sum(1 for v in step12b_health['tier1'].values() if v == '✓')}/5 names OK")
        print(f"  Tier 2: {step12b_health['tier2'].get('classify_integration', '✗')} (demo → proxy:demo, app → '', shim → proxy:entry_shim, proto → stub:ellipsis_body, ci_workflow + readme runner facts)")
    except ImportError as e:
        step12b_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")
    results["steps"]["step_12b_artifact_scanner"] = step12b_health

    results["steps"]["step_12_detritus"] = step12_health

    # ─────────────────────────────────────────────────────────────
    # Step 13: Infraction Ordering + CB Context
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 13: Finding Ordering + CB Context")
    step13_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from no_aivalidator.NOAI_VALIDATOR_DAEMON import FlaggedIssue
        from rca_main.context_calculator import ContextLinesCalculator

        for comp_name, comp in [
            ("FlaggedIssue", FlaggedIssue),
            ("ContextLinesCalculator", ContextLinesCalculator),
        ]:
            try:
                assert comp is not None, f"{comp_name} is None"
                step13_health["tier1"][comp_name] = "✓"
            except Exception as e:
                step13_health["tier1"][comp_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Verify depth-based ordering works
        try:
            issues_test = [
                FlaggedIssue(file_relative="shallow.py", node_name="shallow",
                             function="fn_a", line=1, failure_layer="", failure_reason="",
                             triggered_patterns=[], rule_id="NAI-010", job_type=""),
                FlaggedIssue(file_relative="deep.py", node_name="deep",
                             function="fn_b", line=1, failure_layer="", failure_reason="",
                             triggered_patterns=[], rule_id="NAI-010", job_type=""),
            ]
            depths = {"shallow": 0, "deep": 3}
            deps = {"shallow": [], "deep": ["a", "b", "c"]}

            def _priority(i: FlaggedIssue) -> tuple:
                d = depths.get(Path(i.file_relative).stem, 0)
                n = len(deps.get(Path(i.file_relative).stem, []))
                return (-(d * 10 + n * 5), i.line)

            ordered = sorted(issues_test, key=_priority)
            assert ordered[0].file_relative == "deep.py", f"Expected deep first, got {ordered[0].file_relative}"
            step13_health["tier2"]["finding_ordering"] = "✓"
        except Exception as e:
            step13_health["tier2"]["finding_ordering"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step13_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/2 components OK")
        print(f"  Tier 2: {step13_health['tier2'].get('finding_ordering', '✗')}")

    except ImportError as e:
        step13_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_13_prioritizer"] = step13_health

    # ─────────────────────────────────────────────────────────────
    # Step 14: Semantic Analysis (all analyzers + FP reduction)
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 14: Semantic Analysis")
    step14_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from semantic_analysis.def_use_chains import (
            DefUseAnalyzer, DefUseIssue,
            analyze_file as duc_analyze_file,
            analyze_directory as duc_analyze_directory,
        )
        from semantic_analysis.module_handling import (
            ModuleAnalyzer, ModuleIssue,
            analyze_file as mod_analyze_file,
            analyze_directory as mod_analyze_directory,
        )

        # Tier 1: Function-level — existing analyzers
        try:
            duc = DefUseAnalyzer("test.py")
            duc.visit(test_tree)
            assert isinstance(duc.issues, list)
            step14_health["tier1"]["DefUseAnalyzer"] = "✓"
        except Exception as e:
            step14_health["tier1"]["DefUseAnalyzer"] = f"✗ {e}"
            all_passed = False

        try:
            mod = ModuleAnalyzer("test.py")
            mod.visit(test_tree)
            assert isinstance(mod.issues, list)
            step14_health["tier1"]["ModuleAnalyzer"] = "✓"
        except Exception as e:
            step14_health["tier1"]["ModuleAnalyzer"] = f"✗ {e}"
            all_passed = False

        try:
            _ = DefUseIssue(file="t.py", line=1, name="x", code="DUC001", message="test")
            step14_health["tier1"]["DefUseIssue"] = "✓"
        except Exception as e:
            step14_health["tier1"]["DefUseIssue"] = f"✗ {e}"
            all_passed = False

        try:
            _ = ModuleIssue(file="t.py", line=1, code="MOD001", message="test")
            step14_health["tier1"]["ModuleIssue"] = "✓"
        except Exception as e:
            step14_health["tier1"]["ModuleIssue"] = f"✗ {e}"
            all_passed = False

        # Tier 1: New analyzers
        try:
            from semantic_analysis.cfg_analysis import CFGAnalyzer
            cfg = CFGAnalyzer("test.py")
            cfg.visit(test_tree)
            assert isinstance(cfg.issues, list)
            step14_health["tier1"]["CFGAnalyzer"] = "✓"
        except Exception as e:
            step14_health["tier1"]["CFGAnalyzer"] = f"✗ {e}"
            all_passed = False

        try:
            from semantic_analysis.parameter_usage import ParameterAnalyzer
            pa = ParameterAnalyzer("test.py")
            pa.visit(test_tree)
            assert isinstance(pa.issues, list)
            step14_health["tier1"]["ParameterAnalyzer"] = "✓"
        except Exception as e:
            step14_health["tier1"]["ParameterAnalyzer"] = f"✗ {e}"
            all_passed = False

        try:
            from semantic_analysis.api_compliance import APIComplianceChecker
            acc = APIComplianceChecker("test.py")
            acc.visit(test_tree)
            assert isinstance(acc.issues, list)
            step14_health["tier1"]["APIComplianceChecker"] = "✓"
        except Exception as e:
            step14_health["tier1"]["APIComplianceChecker"] = f"✗ {e}"
            all_passed = False

        # Tier 2: Integration — analyze_file + analyze_directory
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)

            duc_issues = await duc_analyze_file(temp_path)
            mod_issues = await mod_analyze_file(temp_path)
            assert isinstance(duc_issues, list)
            assert isinstance(mod_issues, list)

            temp_dir = temp_path.parent
            duc_dir_issues = await duc_analyze_directory(temp_dir, pattern=temp_path.name)
            mod_dir_issues = await mod_analyze_directory(temp_dir, pattern=temp_path.name)
            assert isinstance(duc_dir_issues, list)
            assert isinstance(mod_dir_issues, list)

            temp_path.unlink()
            step14_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step14_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        tier1_ok = len([v for v in step14_health['tier1'].values() if v == '✓'])
        tier1_total = len(step14_health['tier1'])
        print(f"  Tier 1: {tier1_ok}/{tier1_total} checks OK")
        print(f"  Tier 2: {step14_health['tier2'].get('integrated_workflow', '✗')}")

    except ImportError as e:
        step14_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_14_semantic"] = step14_health

    # ─────────────────────────────────────────────────────────────
    # Step 15: Circuit Daemon
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 15: Circuit Daemon")
    step15_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        import system_scripts.circuit_daemon as _cd_mod

        def _hc_declared_deps():
            # FIX_16 (2026-09-10): the path-hack detector's expected-external set comes from the target's
            # declared dependencies (pyproject [project.dependencies] + requirements*.txt), normalised.
            import tempfile as _tf
            from system_scripts.path_hack_detector import declared_dependencies as _dd
            with _tf.TemporaryDirectory() as _d:
                (Path(_d) / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = [\n  "click>=8.0",\n  "rich",\n]\n')
                (Path(_d) / "requirements.txt").write_text("python-dateutil~=2.8\n# comment\n")
                _got = _dd(Path(_d))
                assert _got == {"click", "rich", "python_dateutil"}, _got
                (Path(_d) / "pyproject.toml").unlink(); (Path(_d) / "requirements.txt").unlink()
                assert _dd(Path(_d)) == set(), "empty tree must declare nothing"
                # FIX_16 step 3 (Item 8, 2026-09-15): the intent file's packaging facts are the PRIMARY source
                import sys as _sys16
                if str(Path(__file__).resolve().parent) not in _sys16.path:
                    _sys16.path.insert(0, str(Path(__file__).resolve().parent))
                import intent_file as _intent16
                _intent16.replace_source_facts(Path(_d), [{"fact": "dependencies", "value": "python-dateutil>=2.8", "source": "packaging", "evidence": "pyproject.toml"}])
                try:
                    from system_scripts.path_hack_detector import declared_dependencies_with_source as _dds
                    _got16 = _dds(Path(_d))
                    assert _got16 == ({"python_dateutil"}, "intent file (packaging facts)"), _got16
                finally:
                    _intent16.path(Path(_d)).unlink(missing_ok=True); _intent16._lock_path(Path(_d)).unlink(missing_ok=True)
            return True

        import system_scripts.test_runner_tracker as _trt   # Item 10

        def _hc_runner_presence():
            # Item 10: presence read from a node list (no walker of its own): a pytest test file with a
            # fixture + a mark, a unittest TestCase with unittest.main(), a conftest, a pytest.ini; the
            # runner-execution join dedupes by PID with wrapper > kernel > ps.
            import tempfile as _tf
            from types import SimpleNamespace as _NS
            with _tf.TemporaryDirectory() as _d:
                _r = Path(_d); (_r / "tests").mkdir()
                (_r / "tests" / "test_a.py").write_text("import pytest\n\n@pytest.fixture\ndef f():\n    return 1\n\n@pytest.mark.slow\ndef test_x(f):\n    assert f == 1\n")
                (_r / "tests" / "test_u.py").write_text("import unittest\n\nclass T(unittest.TestCase):\n    def test_y(self):\n        self.assertTrue(True)\n\nif __name__ == '__main__':\n    unittest.main()\n")
                (_r / "tests" / "conftest.py").write_text("import pytest\n")
                (_r / "app.py").write_text("print('app')\n")
                (_r / "pytest.ini").write_text("[pytest]\n")
                _nodes = [_NS(path=p, relative_path=p.relative_to(_r).as_posix()) for p in sorted(_r.rglob("*.py"))]
                _p = _trt.scan_test_runner_presence(_nodes, _r)
                assert _p["pytest"]["files"] == ["tests/conftest.py", "tests/test_a.py"], _p["pytest"]["files"]
                assert {e["kind"] for e in _p["pytest"]["evidence"]} == {"import", "fixture", "mark", "conftest"}, _p["pytest"]["evidence"]
                assert _p["unittest"]["files"] == ["tests/test_u.py"] and {e["kind"] for e in _p["unittest"]["evidence"]} == {"import", "TestCase", "main_call"}, _p["unittest"]
                assert [c["file"] for c in _p["config"]] == ["pytest.ini"], _p["config"]
                _run = {"41": {"script": "pytest", "pid": 41, "source": "wrapper", "runner": "pytest", "test_path": "tests/test_a.py", "start_time": "t"}}
                _ps = [(41, "python -m pytest tests/test_a.py"), (42, f"python -m unittest {_r}/tests/test_u.py"), (43, "python app.py"),
                       (44, "python -m pytest -q")]   # a runner pointed at nothing under the target is NOT this target's event (run 108 launch C)
                _ex = _trt.collect_runner_executions(_run, _ps, {"pid": 42, "command": "python -m unittest", "test_path": "", "started_at": "t"}, _r)
                assert [(e["pid"], e["runner"], e["proof"]) for e in _ex] == [(41, "pytest", "wrapper"), (42, "pytest", "kernel")], _ex
                assert _trt.match_runner_cmd(f"python -m unittest tests.test_u", _r) == ("unittest", "tests/test_u.py")
                # I-53 (2026-09-17, FIX_47 lane): a ps-proven runner must sit UNDER the target. Another
                # tree's `pytest tests/test_a.py` resolves against this target (same relative path) and
                # matched by command line alone — run 129 carried two such foreign pids for its whole band.
                # `cwd_of` is injected here exactly as ps_lines and the kernel record are.
                _ps53 = [(51, "python -m pytest tests/test_a.py")]
                _cwds = {51: str(_r / "tests")}
                _in = _trt.collect_runner_executions({}, _ps53, None, _r, cwd_of=_cwds.get)
                assert [(e["pid"], e["proof"], e["test_path"]) for e in _in] == [(51, "ps", "tests/test_a.py")], _in
                _cwds_out = {51: str(Path(_d).parent)}   # same command line, a process outside the target
                assert _trt.collect_runner_executions({}, _ps53, None, _r, cwd_of=_cwds_out.get) == [], "I-53: a foreign pytest was listed"
                assert _trt.collect_runner_executions({}, _ps53, None, _r, cwd_of=lambda _p: None) == [], "I-53: an unreadable cwd is not this target"
                _self_cwd = _trt.proc_cwd(os.getpid())
                assert _self_cwd and Path(_self_cwd).resolve() == Path.cwd().resolve(), _self_cwd
            return True

        # Tier 1: Exercise individual functions
        _cd_fns = {
            "path_hack.declared_dependencies (FIX_16)": _hc_declared_deps,
            "get_config": lambda: _cd_mod.get_config(),
            "get_ping_interval": lambda: _cd_mod.get_ping_interval(),
            "get_repo_id": lambda: _cd_mod.get_repo_id(Path("/tmp")),
            "is_pid_alive_true": lambda: _cd_mod.is_pid_alive(os.getpid()),
            "is_pid_alive_false": lambda: _cd_mod.is_pid_alive(-1),
            "_vulture_zero_dict": lambda: _cd_mod._vulture_zero_dict(),
            # Item 7 (2026-09-10): the launch control reader answers a dict offline (no launch
            # in flight → ok False with the reason). PMC removed 2026-10-07 (owner).
            "read_launch_control": lambda: _cd_mod.read_launch_control(),
            "_is_sync_by_design": lambda: _cd_mod._is_sync_by_design(test_funcs[0], test_tree, "test.py"),  # type: ignore[arg-type]  # FIX_54 ast-pos
            "count_disk_py_files": lambda: _cd_mod.count_disk_py_files(Path(__file__).parent),
            "_AsyncBridge": lambda: _cd_mod._AsyncBridge,
            # Item 10 (2026-09-15): the test-runner tracker's four entry points answer offline
            "test_runner.scan_test_runner_presence (ITEM_10)": lambda: _trt.scan_test_runner_presence([]),
            "test_runner.match_runner_cmd pytest (ITEM_10)": lambda: _trt.match_runner_cmd("python -m pytest tests/", Path("/tmp")),
            "test_runner.match_runner_cmd app (ITEM_10)": lambda: _trt.match_runner_cmd("python app.py", Path("/tmp")),
            "test_runner.collect_runner_executions (ITEM_10)": lambda: _trt.collect_runner_executions({}, [], None, Path("/tmp")),
            "test_runner.presence_on_fixture (ITEM_10)": _hc_runner_presence,
        }

        _cd_asserts = {
            "path_hack.declared_dependencies (FIX_16)": lambda r: r is True,
            "get_config": lambda r: isinstance(r, dict),
            "get_ping_interval": lambda r: isinstance(r, (int, float)),
            "get_repo_id": lambda r: isinstance(r, str) and len(r) == 12,
            "is_pid_alive_true": lambda r: r is True,
            "is_pid_alive_false": lambda r: r is False,
            "_vulture_zero_dict": lambda r: isinstance(r, dict) and "files_scanned" in r,
            "read_launch_control": lambda r: isinstance(r, dict) and set(r) >= {"ok", "control", "reason"},
            "_is_sync_by_design": lambda r: isinstance(r, tuple),
            "count_disk_py_files": lambda r: isinstance(r, list),
            "_AsyncBridge": lambda r: isinstance(r, type),
            "test_runner.scan_test_runner_presence (ITEM_10)": lambda r: isinstance(r, dict) and set(r) >= {"pytest", "unittest", "config", "scanned_at"},
            "test_runner.match_runner_cmd pytest (ITEM_10)": lambda r: isinstance(r, tuple) and r[0] == "pytest",
            "test_runner.match_runner_cmd app (ITEM_10)": lambda r: r is None,
            "test_runner.collect_runner_executions (ITEM_10)": lambda r: isinstance(r, list) and r == [],
            "test_runner.presence_on_fixture (ITEM_10)": lambda r: r is True,
        }

        for fn_name in _cd_fns:
            try:
                result = _cd_fns[fn_name]()
                assert _cd_asserts[fn_name](result), f"Assertion failed for {fn_name}: got {type(result)}"
                step15_health["tier1"][fn_name] = "✓"
            except Exception as e:
                step15_health["tier1"][fn_name] = f"✗ {e}"
                all_passed = False

        # Tier 2: Integration — read/write round-trip + scan_running_processes
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_json = Path(f.name)
            test_data = {"health_check": True, "step": 15}
            _cd_mod.write_file_locked(temp_json, test_data)
            read_back = _cd_mod.read_file_locked(temp_json)
            assert read_back == test_data, f"Round-trip mismatch: {read_back}"
            temp_json.unlink()

            procs = _cd_mod.scan_running_processes([], Path(__file__).parent)
            assert isinstance(procs, dict)

            # M-48 / C (owner 2026-10-06): a target run is seen however it was started.
            _m48_miss = _m48_process_scan_cases(_cd_mod.scan_running_processes)
            step15_health["tier2"]["process_scan_any_start"] = f"✗ {_m48_miss}" if _m48_miss else "✓"
            all_passed = all_passed and not _m48_miss
            # A (owner 2026-10-06): the eslogger load-proof reducer on canned events — json.tool / an
            # editor stay dark, a fork inherits, an edit goes stale (load_recorder_trial's canned cases)
            _lp_fails = _load_proof_rule_cases()
            step15_health["tier2"]["load_proof_rule"] = f"✗ {'; '.join(_lp_fails)}" if _lp_fails else "✓"
            all_passed = all_passed and not _lp_fails

            # FIX_13 / FIX_15 (2026-09-10): the ONE scan surface — a dot-dir's .py IS live
            # (live_py_count of a dir holding only `.ci/x.py` == 1, was 0); a symlinked dir and a
            # symlinked .py pointing outside the root are never walked (live_py_count == 0,
            # iter_contained yields neither). No size or depth policy anywhere.
            import scan_scope as _ss15
            _fx = Path(tempfile.mkdtemp(prefix="hc_fix13_"))
            (_fx / ".ci").mkdir(); (_fx / ".ci" / "x.py").write_text("x = 1\n")
            assert _ss15.live_py_count(_fx, frozenset()) == 1, "FIX_13: a dot-dir .py must be live"
            _out = Path(tempfile.mkdtemp(prefix="hc_fix15_outside_"))
            (_out / "x.py").write_text("y = 2\n")
            _fx2 = Path(tempfile.mkdtemp(prefix="hc_fix15_"))
            (_fx2 / "link").symlink_to(_out, target_is_directory=True)
            (_fx2 / "outside.py").symlink_to(_out / "x.py")
            assert _ss15.live_py_count(_fx2, frozenset()) == 0, "FIX_15: symlinks must not be walked"
            _seen = [str(p.relative_to(_fx2)) for p in _ss15.iter_contained(_fx2)]
            assert not any(s.startswith("link") or s == "outside.py" for s in _seen), f"FIX_15: iter_contained followed a link: {_seen}"
            # B8 (MCP-working packet 2026-09-28): an env / site-packages dir is skipped by SHAPE, never by
            # name — `.venv` holding pyvenv.cfg is out, `.venv` without it stays live (FIX_13 stands).
            _fx8 = Path(tempfile.mkdtemp(prefix="hc_b8_"))
            (_fx8 / ".venv" / "lib" / "python3.x" / "site-packages").mkdir(parents=True)
            (_fx8 / ".venv" / "pyvenv.cfg").write_text("home = /x\n")
            (_fx8 / ".venv" / "lib" / "python3.x" / "site-packages" / "m.py").write_text("m = 1\n")
            (_fx8 / "env2" / "conda-meta").mkdir(parents=True); (_fx8 / "env2" / "c.py").write_text("c = 1\n")
            (_fx8 / "vendor" / "lib" / "python3.x" / "site-packages").mkdir(parents=True)
            (_fx8 / "vendor" / "lib" / "python3.x" / "site-packages" / "s.py").write_text("s = 1\n")
            (_fx8 / ".tools").mkdir(); (_fx8 / ".tools" / "t.py").write_text("t = 1\n")
            _live8 = sorted(str(p.relative_to(_fx8)) for p in _ss15.iter_live_py(_fx8, frozenset()))
            assert _live8 == [".tools/t.py"], f"B8: env dirs skipped by shape, dot-dir kept: {_live8}"
            # I-90 / Q1: the frame-stale threshold scales with the measured cycle, no cap.
            import electricity as _el90
            assert _el90.stale_threshold_s(2.5) == max(5.0, _el90._STALE_FLOOR_SECONDS), "I-90: no cycle = the old rule"
            assert _el90.stale_threshold_s(2.5, 300.0) == 2.0 * (2.5 + 300.0), "I-90: scales with the cycle, no cap"

            step15_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step15_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        # FIX_19 (2026-09-15, R-D): the health endpoint answers 200 once a poll and the tracer are
        # recorded — construct on an ephemeral port, record_poll + record_kernel_tracer("lsof", True),
        # GET /health -> 200 with checks.tracer == "ok". Before Item 7 step 4 it was 503 on every run.
        try:
            import urllib.request as _ur19, json as _json19
            from system_scripts.observability import Observability as _Obs19
            _o = _Obs19(port=0, log_path=Path(tempfile.mkdtemp(prefix="hc_fix19_")) / "obs.jsonl")
            try:
                assert _o._server is not None, "FIX_19: the health server did not start"
                _port = _o._server.server_address[1]
                with _ur19.urlopen(f"http://127.0.0.1:{_port}/health", timeout=3) as _r0:
                    _c0 = _r0.status
            except _ur19.HTTPError as _he:
                _c0 = _he.code
            assert _c0 == 503, f"FIX_19: /health before any poll must be 503, got {_c0}"
            _o.record_poll(1, 1.0, 0, 0)
            _o.record_kernel_tracer("lsof", True, 0, 0)
            with _ur19.urlopen(f"http://127.0.0.1:{_port}/health", timeout=3) as _r1:
                _b1 = _json19.loads(_r1.read().decode()); _c1 = _r1.status
            _o.stop()
            assert _c1 == 200 and _b1.get("checks", {}).get("tracer") == "ok" and _b1.get("checks", {}).get("polls") == "ok", \
                f"FIX_19: expected 200 tracer ok / polls ok, got {_c1} {_b1.get('checks')}"
            step15_health["tier2"]["observability_health (FIX_19)"] = "✓ 503 before the first poll, 200 tracer ok after record_poll + record_kernel_tracer"
        except Exception as e:
            step15_health["tier2"]["observability_health (FIX_19)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        # FIX_20 (2026-09-15, R-D): circuit_views.running_entries — a dead PID -> []; a live PID whose
        # recorded start_time does not match `ps -o lstart=` (a reused PID) -> []; a live PID that matches -> 1.
        try:
            import json as _json20
            from datetime import datetime as _dt20
            import circuit_views as _cv20
            _rf = Path(tempfile.mkdtemp(prefix="hc_fix20_")) / "running.json"
            _rf.write_text(_json20.dumps({"999999": {"script": "dead.py", "pid": 999999, "start_time": "2026-01-01T00:00:00", "source": "wrapper"}}))
            assert _cv20.running_entries(_rf) == [], "FIX_20: a dead PID must not be running"
            _me = os.getpid(); _ls = _cv20._lstart_epoch(_cv20._ps_field(_me, "lstart"))
            assert _ls is not None, "FIX_20: ps -o lstart= must parse"
            _rf.write_text(_json20.dumps({str(_me): {"script": "me.py", "pid": _me, "start_time": _dt20.fromtimestamp(_ls - 30).isoformat(), "source": "wrapper"}}))
            assert _cv20.running_entries(_rf) == [], "FIX_20: a start_time 30 s off the process's lstart is a reused PID"
            _rf.write_text(_json20.dumps({str(_me): {"script": "me.py", "pid": _me, "start_time": _dt20.fromtimestamp(_ls).isoformat(), "source": "wrapper"}}))
            _live = _cv20.running_entries(_rf)
            assert len(_live) == 1 and _live[0]["script"] == "me.py", f"FIX_20: the live matching entry must be reported, got {_live}"
            assert _cv20.get_entry_point_from_proof(_rf) == ["me"], "FIX_20: the entry triangle reads the same definition"
            step15_health["tier2"]["running_entries (FIX_20)"] = "✓ dead PID [], reused PID [], live matching PID 1 (stat + lstart checked)"
        except Exception as e:
            step15_health["tier2"]["running_entries (FIX_20)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        # FIX_21 (respawn gate) retired 2026-09-29 with S4: no daemon is restarted, so there is no respawn
        # to gate. The gate itself (Child.gate) is still how every daemon is started — see FIX_52 below.

        # FIX_52 → S4 (owner 2026-09-29): no restarts — a daemon that dies or hangs STOPS the run. (a) the
        # restart machinery is gone; (b) the hang signals — a SIGSTOP'd process reads T (I-12's own case), the
        # circuit's stalled state file reads hung, the validator / Builder are NOT judged by their mtime (they
        # write on change), the dashboard is judged by its gate; (c) the failure record, the run feed and the
        # tester report's trust.
        # S4c (owner 2026-09-29): S4's conditions are recorded through _need52, not asserted — every one that
        # does not hold is collected and the step reads ✗ with all of them, never only the first.
        _miss52: List[str] = []

        def _need52(holds: bool, what: str) -> None:
            if not holds:
                _miss52.append(what)
        try:
            import importlib.util as _ilu52, json as _json52, subprocess as _sp52, signal as _sig52, time as _t52
            _spec52: Any = _ilu52.spec_from_file_location("gearbox_fix52", Path(__file__).resolve().parent / "gearbox.py")
            _gb52 = _ilu52.module_from_spec(_spec52); _spec52.loader.exec_module(_gb52)  # type: ignore[union-attr]
            # (a) the restart machinery is gone — nothing left to restart a daemon with
            for _gone52 in ("restart_in_place", "RestartEvents", "respawn_gate", "mark_respawning",
                            "MAX_RESTARTS_WINDOW", "RESTART_WINDOW_S"):
                _need52(not hasattr(_gb52, _gone52), f"S4: {_gone52} must be gone (no restarts)")
            _c52 = _gb52.Child("noai_validator", ["true"])
            _need52(not hasattr(_c52, "restart_times") and not hasattr(_c52, "restarts"), "S4: a Child keeps no restart count")
            # (b) the hang signals
            # I-154 (owner 2026-09-21, launch-hygiene class): this block used to signal and then
            # read the process state after a FIXED sleep. The kernel stops the process when it
            # stops it, so the read could land early — the assertion failed once on T2b's second
            # replay and once on the transplant's first `s9a` replay, and passed on both re-runs
            # with every other reading identical. A flaky gate step can pass a broken tree as
            # easily as fail a good one, and a re-run policy teaches a seat to discount a real
            # failure. Two changes, both bounded and both loud on a timeout:
            #   * the wait on the STOP ITSELF is the kernel's own report — `waitpid(WUNTRACED)`
            #     answers "has this child actually stopped", which no amount of `ps` polling can;
            #   * the wait on the ENGINE's reading (`proc_state` -> `ps -o state=`) is a bounded
            #     poll AFTER that, so the only thing it can still catch is the reading itself.
            # A timed-out line names the raw `ps` row it last saw, so a genuine failure arrives as
            # evidence rather than as one letter.
            def _ps_row52(pid: int) -> str:
                try:
                    _r = _sp52.run(["ps", "-o", "pid,ppid,state,command", "-p", str(pid)],
                                   capture_output=True, text=True, timeout=5)
                    return " | ".join(_l.strip() for _l in _r.stdout.strip().splitlines())
                except Exception as _e:   # the diagnostic must never raise over the assertion
                    return f"(ps unreadable: {type(_e).__name__})"

            def _stop_child52(proc, attempts: int = 10, per_attempt_s: float = 1.0,
                              step_s: float = 0.02) -> str:
                """SIGSTOP the child and wait, bounded, for the KERNEL's own report that it
                stopped. Returns "" on success, otherwise the reason it did not stop.

                Why the signal is re-sent rather than sent once: a spawn is not instantaneous, and
                a SIGSTOP that lands inside the spawn window can be undone by the spawn machinery
                itself — MEASURED HERE on 2026-09-21, twice in five health runs under load and
                once live during run 165's launch B, each time as `ps: … SN …` (alive, niced, NOT
                stopped) ten seconds after the send, with `waitpid(WUNTRACED)` reporting no stop at
                all. SIGSTOP can be neither caught nor ignored, so a re-send once the window has
                closed is guaranteed to take; what must never happen is a SILENT pass or a silent
                hang, and neither can: every attempt is bounded and the last one prints what it
                saw. This is the flake I-154 names, and it is the read, not the restarter, that
                was wrong."""
                for _n in range(1, attempts + 1):
                    try:
                        proc.send_signal(_sig52.SIGSTOP)
                    except (ProcessLookupError, OSError) as _e:
                        return f"the child could not be signalled ({type(_e).__name__}: {_e})"
                    _deadline = _t52.monotonic() + per_attempt_s
                    while _t52.monotonic() < _deadline:
                        try:
                            _w, _st = os.waitpid(proc.pid, os.WNOHANG | os.WUNTRACED)
                        except ChildProcessError:
                            return "the child was already reaped"
                        if _w == proc.pid and os.WIFSTOPPED(_st):
                            if _n > 1:
                                print(f"    Step 15 FIX_52: the child stopped on SIGSTOP attempt {_n} "
                                      f"(a signal inside the spawn window does not take; bounded, never silent)")
                            return ""
                        if _w == proc.pid and os.WIFEXITED(_st):
                            return f"the child EXITED (code {os.WEXITSTATUS(_st)}) instead of stopping"
                        _t52.sleep(step_s)
                print(f"    Step 15 FIX_52: TIMED OUT after {attempts} SIGSTOP attempt(s) over "
                      f"{attempts * per_attempt_s:.0f}s waiting for pid {proc.pid} to be reported "
                      f"STOPPED — ps: {_ps_row52(proc.pid)}")
                return (f"waitpid never reported a stop after {attempts} SIGSTOP(s) over "
                        f"{attempts * per_attempt_s:.0f}s")

            def _await_state52(pid: int, pred, what: str, limit_s: float = 10.0, step_s: float = 0.02) -> str:
                """Poll `ps -o state=` — the engine's OWN reading — until *pred* accepts the state
                letter, or the bound expires. Returns the last state read: the caller asserts on
                it, so a timeout arrives as a named state and a printed line, never as a hang and
                never as a silent pass."""
                _deadline = _t52.monotonic() + limit_s
                _state = _gb52.proc_state(pid)
                while not pred(_state) and _t52.monotonic() < _deadline:
                    _t52.sleep(step_s)
                    _state = _gb52.proc_state(pid)
                if not pred(_state):
                    print(f"    Step 15 FIX_52: TIMED OUT after {limit_s:.0f}s waiting for pid {pid} "
                          f"to read {what} — last state '{_state}' — ps: {_ps_row52(pid)}")
                return _state

            _p52 = _sp52.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                _ch52 = _gb52.Child("victim", ["x"]); _ch52.proc = _p52
                assert _gb52.hang_reason(_ch52, _t52.monotonic()) is None, "FIX_52: a running child is not hung"
                _why52 = _stop_child52(_p52)
                assert _why52 == "", f"FIX_52: the kernel must report the SIGSTOPped child stopped — {_why52}"
                _st52 = _await_state52(_p52.pid, lambda s: s == "T", "'T' (stopped)")
                if _st52 != "T":
                    # R9 (2026-10-10): ONE retry. Measured on a clean release run: waitpid reported the
                    # stop, then `ps` read 'S' for the whole bound — the stop was undone after the kernel
                    # reported it (the spawn-window race above, one step later). Re-send once and read
                    # again; a process that still does not read T fails the step, loudly, as before.
                    print(f"    Step 15 FIX_52: read '{_st52}' after a reported stop — SIGSTOP re-sent once "
                          f"(bounded, never silent)")
                    _why52 = _stop_child52(_p52)
                    assert _why52 == "", f"FIX_52: the kernel must report the SIGSTOPped child stopped (retry) — {_why52}"
                    _st52 = _await_state52(_p52.pid, lambda s: s == "T", "'T' (stopped, retry)")
                assert _st52 == "T", f"FIX_52: a SIGSTOPped process reads T (bounded poll read '{_st52}')"
                assert _gb52.hang_reason(_ch52, _t52.monotonic()) == "hung (process STOPPED)", "FIX_52: I-12's case is hung at once"
                _p52.send_signal(_sig52.SIGCONT)
                # the other direction is the same race: CONT is delivered when it is delivered, and
                # a resumed process may read R or S — anything but T is the reading that matters.
                _sc52 = _await_state52(_p52.pid, lambda s: s not in ("T", ""), "any state but 'T'")
                assert _sc52 not in ("T", ""), f"FIX_52: a continued process no longer reads T (bounded poll read '{_sc52}')"
                assert _gb52.hang_reason(_ch52, _t52.monotonic()) is None, "FIX_52: continued -> not hung"
                # a state file that is written ON CHANGE is never a hang signal (the validator / Builder)
                _sf52 = Path(tempfile.mkdtemp(prefix="hc_fix52_")) / "NOAI_VALIDATION_STATE.json"
                _sf52.write_text("{}"); os.utime(_sf52, (time.time() - 10_000, time.time() - 10_000))
                _ch52.state_file = _sf52
                assert _gb52.hang_reason(_ch52, _t52.monotonic()) is None, "FIX_52: an on-change state file is not a heartbeat"
                # I-108: ... but its HEARTBEAT sidecar is. A fresh beat from this pid -> not hung; a
                # beat older than HUNG_STATE_S -> hung (a FAILURE); a beat from another pid (a
                # previous run's leftover) is not judged.
                _hb52 = _gb52.heartbeat_file(_sf52)
                assert _hb52.name == "NOAI_VALIDATION_STATE.heartbeat.json", f"I-108: sidecar name {_hb52.name}"
                _hb52.write_text(json.dumps({"pid": _p52.pid, "cycle": 4, "ts": time.time()}))
                assert _gb52.hang_reason(_ch52, _t52.monotonic()) is None, "I-108: a fresh heartbeat is not hung"
                _hb52.write_text(json.dumps({"pid": _p52.pid, "cycle": 4, "ts": time.time() - _gb52.HUNG_STATE_S - 5}))
                _rh52 = _gb52.hang_reason(_ch52, _t52.monotonic())
                assert _rh52 is not None and _rh52.startswith("hung (no heartbeat for"), f"I-108: a stale heartbeat reads as a failure, got {_rh52}"
                _hb52.write_text(json.dumps({"pid": _p52.pid + 1, "cycle": 4, "ts": 0.0}))
                assert _gb52.hang_reason(_ch52, _t52.monotonic()) is None, "I-108: another process's beat is not judged"
                assert {d.duty for d in _gb52.DUTY_CADENCE if d.duty == "heartbeat"} == {"heartbeat"} and \
                    {d.daemon for d in _gb52.DUTY_CADENCE if d.duty == "heartbeat"} == {"noai_validator", "cheatsheets"}, \
                    "I-108: the heartbeat cadence is a FIX_46 table row for the validator and the Builder"
                # the circuit's state file IS a heartbeat
                _ch52.state_file = _gb52.CIRCUIT_STATE
                _r52 = _gb52.hang_reason(_ch52, _t52.monotonic())
                assert _r52 is None or _r52.startswith("hung (no state write"), f"FIX_52: circuit judged by its state file, got {_r52}"
            finally:
                _p52.kill(); _p52.wait()
            # the dashboard: no state file, judged by its gate, and only after HUNG_STATE_S
            _p52b = _sp52.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                _dash52 = _gb52.Child("dashboard", ["x"], gate=lambda: False, state_file=None); _dash52.proc = _p52b
                assert _gb52.hang_reason(_dash52, 100.0) is None, "FIX_52: the clock starts, nothing fires yet"
                assert _dash52.unhealthy_since == 100.0
                assert _gb52.hang_reason(_dash52, 100.0 + _gb52.HUNG_STATE_S) == f"hung (gate failing for {_gb52.HUNG_STATE_S:.0f}s)"
                _dash52.gate = lambda: True
                assert _gb52.hang_reason(_dash52, 999.0) is None and _dash52.unhealthy_since is None, "FIX_52: a healthy gate clears the clock"
            finally:
                _p52b.kill(); _p52b.wait()
            # (c) the failure record, the run feed and the tester report
            _td52 = Path(tempfile.mkdtemp(prefix="hc_fix52e_"))
            # the log runs past the tail gearbox keeps, so the record must carry the END of it; the tail
            # length is log_tail's own default, not a copy of it
            import inspect as _insp52
            _tail_n52 = _insp52.signature(_gb52.log_tail).parameters["n"].default
            _log_lines52 = [f"line {i}" for i in range(2 * _tail_n52)]
            _log52 = _td52 / "noai_validator_x.log"; _log52.write_text("\n".join(_log_lines52))
            _c52.log_path = _log52
            _f52 = _gb52.daemon_failure(_c52, _gb52._exit_how(-_sig52.SIGKILL))
            _need52(_f52["daemon"] == "noai_validator" and _f52["reason"] == "killed by SIGKILL", f"S4: the failure names the daemon and why, got {_f52}")
            _need52(_f52["log_tail"] == _log_lines52[len(_log_lines52) - _tail_n52:], "S4: the failure carries the end of the log")
            _need52(_gb52._exit_how(1) == "exited (exit code 1)", "S4: an exit code reads as one")
            _ev52 = _gb52.RunEvents(_td52 / "gearbox_events.json", "iso")
            _d52 = _json52.loads(_ev52.path.read_text())
            _need52(_d52["events"] == [] and _d52["run_started"] == "iso" and _d52["failure"] is None, "S4: the feed starts clean (run_started kept for the MCP)")
            _ev52.failed(_f52); _d52 = _json52.loads(_ev52.path.read_text())
            _need52(_d52["failure"]["daemon"] == "noai_validator" and _d52["stopped"].endswith("the run stopped"), "S4: the failure and its stop line are on the feed")
            _ev52.remove(); _need52(not _ev52.path.exists(), "S4: the feed leaves with the run")
            _rep52 = _gb52.write_tester_report(Path("/nonexistent/target"), "x", "iso", out_dir=_td52 / "run", daemon_failure=_f52)
            _need52(_rep52["run_trusted"] is False and _rep52["daemon_failure"]["daemon"] == "noai_validator", "S4: the report marks the run untrusted")
            _need52(_gb52.write_tester_report(Path("/nonexistent/target"), "x", "iso", out_dir=_td52 / "run2")["run_trusted"] is True, "S4: a clean run stays trusted")
            if _miss52:
                step15_health["tier2"]["restarter (FIX_52)"] = f"✗ {len(_miss52)} S4 condition(s) not met: " + "; ".join(_miss52)
                all_passed = False
            else:
                step15_health["tier2"]["restarter (FIX_52)"] = ("✓ no restart machinery left (S4); SIGSTOP reads T -> hung "
                                                               "(bounded poll, timed-out line — I-154); "
                                                               "on-change state files are not heartbeats; dashboard judged by its gate; "
                                                               "failure record + run feed + untrusted tester report")
        except Exception as e:
            step15_health["tier2"]["restarter (FIX_52)"] = f"✗ {type(e).__name__}: {e}" + "".join(f"; {m}" for m in _miss52)
            all_passed = False

        # I-153 (owner 2026-09-21, the upgraded four parts) + I-99 + I-155 + I-69 — LAUNCH HYGIENE.
        # A target that ARRIVES with stale bytecode can shadow an applied repair and make the run
        # read the failure as the repair's. The four parts are (a) the bytecode class stated as an
        # EXPLICIT whitelist row, (b) `pyc_preexisting=<n>` as a launch fact, (c) a teardown VERDICT
        # that calls the suite reading `not clean` when anything entered or left the target, and
        # (d) PYTHONDONTWRITEBYTECODE=1 on every subprocess the engine spawns. Nothing here deletes
        # anything inside a target — that is the teardown's byte-identity, and it stays.
        try:
            import importlib.util as _ilu53
            import scan_scope as _ss153
            _spec153: Any = _ilu53.spec_from_file_location("gearbox_i153", Path(__file__).resolve().parent / "gearbox.py")
            _gb153 = _ilu53.module_from_spec(_spec153); _spec153.loader.exec_module(_gb153)  # type: ignore[union-attr]

            # (a) the EXPLICIT whitelist rows, not only the implicit _HARD_SKIP_PARTS
            assert {e["path"] for e in _ss153.BYTECODE_WHITELIST_ENTRIES} == {"__pycache__/", "*.pyc"}, \
                "I-153 (a): the bytecode class is two explicit whitelist rows"
            assert _ss153.BYTECODE_WHITELIST_PATHS <= _ss153.load_whitelist(Path(tempfile.mkdtemp(prefix="hc_i153w_"))), \
                "I-153 (a): every load_whitelist reader receives the rows, artifact or no artifact"
            assert _ss153.is_whitelisted("pkg/mod.pyc", _ss153.BYTECODE_WHITELIST_PATHS) is True, \
                "I-153 (a): the glob row matches a nested .pyc"
            assert _ss153.is_whitelisted("pkg/mod.py", _ss153.BYTECODE_WHITELIST_PATHS) is False, \
                "I-153 (a): the rows can never move a live .py count"
            assert _ss153.is_bytecode("a/__pycache__/m.cpython-311.pyc") and _ss153.is_bytecode("m.pyo") \
                and not _ss153.is_bytecode("a/m.py"), "I-153 (a): the explicit named test"

            # (b) the launch reading, and (c) the teardown verdict, on a planted fixture target
            _fx153 = Path(tempfile.mkdtemp(prefix="hc_i153_"))
            (_fx153 / "pkg").mkdir(); (_fx153 / "pkg" / "__init__.py").write_text("")
            (_fx153 / "pkg" / "m.py").write_text("X = 1\n")
            assert _gb153.bytecode_files(_fx153) == [], "I-153 (b): a clean target reads zero"
            _pyc153 = _fx153 / "pkg" / "__pycache__"; _pyc153.mkdir()
            (_pyc153 / "m.cpython-311.pyc").write_bytes(b"\x00stale")
            _before153 = _gb153.bytecode_files(_fx153)
            assert _before153 == ["pkg/__pycache__/m.cpython-311.pyc"], \
                f"I-153 (b): the planted stale .pyc is COUNTED at launch, got {_before153}"
            _v153 = _gb153.bytecode_verdict(_before153, _before153)
            assert _v153["polluted"] == "no" and _v153["suite_reading"] == "clean" and _v153["pyc_preexisting"] == 1, \
                "I-153 (c): bytecode that ARRIVED with the target is declared, not blamed on the run"
            (_pyc153 / "extra.cpython-311.pyc").write_bytes(b"\x00new")
            _v153b = _gb153.bytecode_verdict(_before153, _gb153.bytecode_files(_fx153))
            assert _v153b["polluted"] == "yes" and _v153b["suite_reading"] == "not clean", \
                "I-153 (c): bytecode written DURING the run makes the suite reading not clean"
            assert _v153b["added"] == ["pkg/__pycache__/extra.cpython-311.pyc"] and _v153b["removed"] == [], \
                "I-153 (c): the verdict names what entered"
            _v153c = _gb153.bytecode_verdict(_before153 + ["gone.pyc"], _before153)
            assert _v153c["polluted"] == "yes" and _v153c["removed"] == ["gone.pyc"], \
                "I-153 (c): the engine deletes none, so a disappearance is declared too"
            assert _gb153.pycache_residue(_fx153) and (_pyc153 / "m.cpython-311.pyc").exists(), \
                "I-153: NO DELETION in the target, ever — the residue is reported and left"

            # (d) every spawned subprocess carries the statement
            assert _gb153.no_bytecode_env({"PATH": "/x"}) == {"PATH": "/x", "PYTHONDONTWRITEBYTECODE": "1"}, \
                "I-153 (d): the child environment carries PYTHONDONTWRITEBYTECODE=1"
            assert _gb153.no_bytecode_env({"PYTHONPYCACHEPREFIX": "/scratch"})["PYTHONPYCACHEPREFIX"] == "/scratch", \
                "I-153 (d): a caller's scratch prefix is passed through untouched"
            _gbsrc153 = (Path(__file__).resolve().parent / "gearbox.py").read_text(encoding="utf-8")
            assert "env=no_bytecode_env()" in _gbsrc153, "I-153 (d): Child.launch spawns with that environment"
            _rpsrc153 = (Path(__file__).resolve().parent / "run_proof.sh").read_text(encoding="utf-8")
            assert "export PYTHONDONTWRITEBYTECODE=1" in _rpsrc153, "I-153 (d): the run of record exports it for the whole launch tree"
            assert "PYTHONPYCACHEPREFIX=" in _rpsrc153 and "pyc_preexisting=" in _rpsrc153, \
                "I-153 (b): the launch fact and the scratch prefix are in the run of record"
            _epwsrc153 = (Path(__file__).resolve().parent / "entry_point_wrapper.py").read_text(encoding="utf-8")
            assert _epwsrc153.count('os.environ["PYTHONDONTWRITEBYTECODE"] = "1"') == 2, \
                "I-153 (d): both wrapper entry paths carry it into whatever the target spawns"

            # (e) B10 (Q-H1-1 / Q-H0-10, 2026-10-01): CodeRadar's OWN tree. The owner's launch path
            # (launch.sh) and the gate run (replay_gates.sh) export the three variables ONCE for every
            # child — the import writes nothing, py_compile/compileall and mypy (which ignore (d)) go to
            # the engine's scratch — and both take the tree reading AFTER their children ran. The reading
            # walks the tree; it is not a list of __pycache__ dirs the check already knew. Read as a
            # list of findings, one line each; a non-empty list is the step's ✗ below (no assert here).
            _lsrc153 = (Path(__file__).resolve().parent.parent / "launch.sh").read_text(encoding="utf-8")
            _gsrc153 = (Path(__file__).resolve().parent.parent / "replay_gates.sh").read_text(encoding="utf-8")
            _hcsrc153 = Path(__file__).read_text(encoding="utf-8")
            _fix31_153 = _hcsrc153[_hcsrc153.rindex('"-m", "mypy", *_pkgs31'):].split("\n", 1)[0]   # the FIX_31 call line
            _exports153 = ("export PYTHONDONTWRITEBYTECODE=1", "export PYTHONPYCACHEPREFIX=", "export MYPY_CACHE_DIR=")
            _findings153e = [why for ok, why in (
                (all(x in _lsrc153 for x in _exports153), "launch.sh does not export all three for the whole launch tree"),
                ("/.cr_pycache/launch_" in _lsrc153, "the launch's bytecode prefix is not the engine's own per-run scratch"),
                ("I-153 (e)" in _lsrc153 and "os.walk(root)" in _lsrc153 and "NOT MEASURED" in _lsrc153,
                 "launch.sh has no tree walk that says NOT MEASURED when it cannot walk"),
                (_lsrc153.find("os.walk(root)") > _lsrc153.find("target_env.py"), "the launch's tree reading is not AFTER the last launch-step child"),
                (all(x in _gsrc153 for x in _exports153), "replay_gates.sh does not export all three for every gate"),
                (_gsrc153.find("export PYTHONPYCACHEPREFIX=") < _gsrc153.find("run compileall"), "the compileall gate does not compile into the scratch prefix"),
                ("tree pollution (I-153 e)" in _gsrc153 and _gsrc153.find("tree pollution (I-153 e)") > _gsrc153.find("run mypy "),
                 "the gate run takes no tree reading after its last gate"),
                ('"--cache-dir", _cache31' in _fix31_153 and 'setdefault("MYPY_CACHE_DIR"' in _hcsrc153, "the engine's own mypy count can still cache at CR's root"),
            ) if not ok]

            # I-99 — the console-script path, I-55's other half, one flag on the other call site
            import ast as _ast99
            _fn99 = next(n for n in _ast99.parse(_epwsrc153).body
                         if isinstance(n, _ast99.FunctionDef) and n.name == "run_script")
            _src99 = _ast99.get_source_segment(_epwsrc153, _fn99) or ""
            assert 'runner == "pytest"' in _src99 and '"no:cacheprovider"' in _src99, \
                "I-99: run_script adds the flag for a pytest console script"
            assert "sys.argv = [str(script_path_obj)] + run_args" in _src99, \
                "I-99: the flag reaches the runner through sys.argv, not just a local"
            _fn99m = next(n for n in _ast99.parse(_epwsrc153).body
                          if isinstance(n, _ast99.FunctionDef) and n.name == "run_module")
            assert '"no:cacheprovider"' in (_ast99.get_source_segment(_epwsrc153, _fn99m) or ""), \
                "I-99: I-55's own `-m pytest` half is untouched"

            # I-155 / SP-2 — the auto-mark is RETIRED; the hand-mark is the lane's step
            assert "pool marked:" not in _rpsrc153 and "pool NOT marked" not in _rpsrc153, \
                "I-155: the auto-mark that could never match is gone, not repaired"
            assert "POOL HAND-MARK" in _rpsrc153 and "This script does NOT write it." in _rpsrc153, \
                "I-155 / SP-2: the hand-mark is named as the lane's own step"
            # I-69 — the whitelist stage's intent-file line is archived beside the gearbox lines
            assert "intent_file_line.txt" in _rpsrc153 and "- intent file (I-69)" in _rpsrc153, \
                "I-69: the [intent file] line gets its own archived record and its RUN.md line"

            if _findings153e:   # (e): every miss is NAMED; the step reads ✗ and the launch stops here
                step15_health["tier2"]["launch hygiene (I-153/I-99/I-155/I-69)"] = "✗ I-153 (e): " + "; ".join(_findings153e)
                all_passed = False
            else:
                step15_health["tier2"]["launch hygiene (I-153/I-99/I-155/I-69)"] = (
                    "✓ bytecode is an explicit whitelist row; pyc_preexisting counted at launch; a planted stale .pyc "
                    "is declared and a .pyc written during the run reads polluted=yes / suite reading not clean; no deletion "
                    "in the target; every spawned subprocess carries PYTHONDONTWRITEBYTECODE=1; launch.sh and replay_gates.sh "
                    "send CR's own bytecode and mypy cache to .cr_pycache and read the tree after their children (e); the console-script pytest "
                    "path adds no:cacheprovider; the pool auto-mark is retired for the hand-mark; the intent-file line is archived")
        except Exception as e:
            step15_health["tier2"]["launch hygiene (I-153/I-99/I-155/I-69)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        # FIX_53 (owner Q5 / I-47, 2026-09-17): a target's lexer/parser fixtures are unparsable BY
        # DESIGN — named by PATTERN, they stop being wiring breaks; a genuine break still is one.
        # And the syntax check PARSES (ast.parse on bytes) instead of COMPILING (py_compile): a
        # module-scope `return` is parse-legal and compile-illegal, which is why pygments'
        # switch_case.py was called broken while the venv's own ast.parse called it fine.
        try:
            import scan_scope as _ss53
            assert _ss53.syntax_fixture("tests/examplefiles/python/switch_case.py") is True
            assert _ss53.syntax_fixture("pkg/tests/fixtures/a.py") is True
            assert _ss53.syntax_fixture("colorama/ansi.py") is False
            assert _ss53.syntax_fixture("tests/test_ansi.py") is False, "FIX_53: a real test file is not a fixture"
            _d53 = Path(tempfile.mkdtemp(prefix="hc_fix53_"))
            (_d53 / "tests" / "examplefiles" / "python").mkdir(parents=True); (_d53 / "pkg").mkdir()
            (_d53 / "tests" / "examplefiles" / "python" / "bad.py").write_text("def broken(:\n")
            (_d53 / "pkg" / "real_bad.py").write_text("def broken(:\n")
            (_d53 / "pkg" / "modret.py").write_text("match x:\n    case 1:\n        return 1\n")
            import ast_scanner as _as53
            _sc53 = _as53.CircuitScanner(str(_d53))
            _n53 = {str(p.relative_to(_d53)): _sc53.scan_script(p) for p in sorted(_d53.rglob("*.py"))}
            assert _n53["pkg/modret.py"].syntax_valid is True, "FIX_53: a module-scope return PARSES (it does not compile)"
            assert _n53["pkg/real_bad.py"].syntax_valid is False and _n53["pkg/real_bad.py"].connected is False, "FIX_53: a genuine break is still a break"
            assert "line 1" in (_n53["pkg/real_bad.py"].import_error or ""), "FIX_53: the break names its line"
            _f53 = _n53["tests/examplefiles/python/bad.py"]
            assert _f53.syntax_valid is False and _f53.syntax_fixture is True and _f53.connected is True and _f53.import_error is None, "FIX_53: a fixture is not a wiring break"
            assert _sc53.syntax_error(_d53 / "pkg" / "modret.py") is None
            # the gate's own guard reads the SAME definition (gearbox consults scan_scope too)
            assert _gb52._syntax_fixture("tests/examplefiles/python/bad.py") is True
            assert _gb52._syntax_fixture("pkg/real_bad.py") is False
            step15_health["tier2"]["syntax_fixture (FIX_53)"] = ("✓ fixtures matched by pattern and dropped from the wiring break set; "
                                                                 "a genuine break still stops the launch and names its line; check_syntax parses bytes")
        except Exception as e:
            step15_health["tier2"]["syntax_fixture (FIX_53)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        # ITEM 11 (2026-09-15): the severed-link transition, pure — a live pair that drops is severed and HELD,
        # it leaves the set the frame it is live again or a node is gone; live_links joins edges to coverage.
        try:
            from types import SimpleNamespace as _NS11
            _g11 = _NS11(nodes=[_NS11(name="a", relative_path="a.py"), _NS11(name="b", relative_path="b.py")], edges=[("a", "b")])
            assert _cd_mod.live_links(_g11, {"a.py", "b.py"}, []) == {("a", "b")}, "ITEM_11: both ends proven -> live"
            assert _cd_mod.live_links(_g11, {"a.py"}, []) == set(), "ITEM_11: one end proven -> not live"
            assert _cd_mod.live_links(_g11, set(), [{"src": "a", "dst": "b"}]) == {("a", "b")}, "ITEM_11: a dataflow is live"
            _s1 = _cd_mod.compute_severed_links({("a", "b")}, set(), {}, {"a", "b"}, now="t1")
            assert _s1 == {("a", "b"): "t1"}, f"ITEM_11: dropped -> severed: {_s1}"
            _s2 = _cd_mod.compute_severed_links(set(), set(), _s1, {"a", "b"}, now="t2")
            assert _s2 == {("a", "b"): "t1"}, "ITEM_11: held with its first-seen time"
            _s3 = _cd_mod.compute_severed_links(set(), {("a", "b")}, _s2, {"a", "b"}, now="t3")
            assert _s3 == {}, "ITEM_11: live again -> restored"
            _s4 = _cd_mod.compute_severed_links(set(), set(), _s1, {"a"}, now="t4")
            assert _s4 == {}, "ITEM_11: a node gone -> not a severed link"
            # FIX_45 / I-54 (owner Q3, 2026-09-15): "only a broken import severs" — the SEVERABLE pairs
            # are the import-live ones; a pair live only through a sensed dataflow (a test runner's flow)
            # simply stops being live when the flow ends and never turns red.
            assert _cd_mod.import_live_links(_g11, {"a.py", "b.py"}) == {("a", "b")}, "FIX_45: an import edge with both ends proven is severable"
            assert _cd_mod.import_live_links(_g11, {"a.py"}) == set(), "FIX_45: one end proven -> not severable"
            _s5 = _cd_mod.compute_severed_links({("a", "b")}, set(), {}, {"a", "b"}, now="t5", severable={("a", "b")})
            assert _s5 == {("a", "b"): "t5"}, f"FIX_45: a broken import severs: {_s5}"
            _s6 = _cd_mod.compute_severed_links({("a", "b")}, set(), {}, {"a", "b"}, now="t6", severable=set())
            assert _s6 == {}, f"I-54: a runner's flow ENDING is not a severed link: {_s6}"
            _s7 = _cd_mod.compute_severed_links(set(), set(), _s5, {"a", "b"}, now="t7", severable=set())
            assert _s7 == {("a", "b"): "t5"}, "FIX_45: a pair already severed stays HELD whatever is severable now"
            step15_health["tier2"]["severed_links (ITEM_11)"] = "✓ live needs both ends proven or a dataflow; dropped -> severed, held with its first time, restored when live, dropped with its node; FIX_45/I-54: only an import-live pair may sever, a flow ending never does, a held pair stays held"
        except Exception as e:
            step15_health["tier2"]["severed_links (ITEM_11)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        # FIX_40 (owner 2026-09-15): (a) the dash's layout carries ONE text band above the graph (`status-band`
        # with `alerts-text` + `live-events`) and NO bottom alert banner; (b) the circuit graph's Loading keeps
        # the previous frame visible (overlay visibility 'visible' — Dash's default hides it: the flash); (c) both
        # legend lines of a figure sit inside the panel: anchored at paper y=0 / y=1 with a margin >= their room.
        # Static facts of the source (the dash is never imported here) + the figure built on a two-node fixture.
        try:
            import ast as _ast40, re as _re40
            _pd_src = (Path(__file__).resolve().parent / "proof_dashboard.py").read_text(encoding="utf-8")
            _ast40.parse(_pd_src)
            _ids = _re40.findall(r"id='([a-z\-]+)'", _pd_src)
            assert _ids.count("status-band") == 1 and _ids.count("alerts-text") == 1 and _ids.count("live-events") == 1, \
                f"FIX_40: the band must exist exactly once with its two fields, got {[i for i in _ids if i in ('status-band','alerts-text','live-events')]}"
            assert "alerts-container" not in _ids and "dbc.Alert(id='alerts'" not in _pd_src, "FIX_40: the bottom alert banner must be gone"
            assert _ids.index("status-band") < _ids.index("script-search") < _ids.index("circuit-graph"), "FIX_40: the band sits ABOVE the Circuit Status header and the graph"
            assert _ids.index("alerts-text") < _ids.index("live-events") < _ids.index("script-search"), "FIX_40: both fields are inside the band, above the graph"
            _ld = _pd_src[_pd_src.index("id='circuit-graph-container'"):_pd_src.index("id='circuit-graph'")]
            assert "overlay_style={'visibility': 'visible'" in _ld, "FIX_40: the circuit graph's Loading must keep the previous frame visible"
            assert "Output('alerts-text', 'children')" in _pd_src and "Output('alerts', " not in _pd_src, "FIX_40: check_alerts writes the band's text, not a banner"
            _fig40, _ = _cv20.generate_figure(
                [{"name": "a", "connected": True}, {"name": "pkg/b", "connected": True}],
                {"a": ["pkg/b"]}, {"a": None, "pkg/b": "pkg"}, scanned_dirs={"pkg"}, watched_names=["pkg"])
            _top = next(a for a in _fig40.layout.annotations if "scanned dir" in (a.text or ""))
            _bot = next(a for a in _fig40.layout.annotations if "possible" in (a.text or ""))
            _m = _fig40.layout.margin
            assert _top.y == 1 and _top.yanchor == "bottom" and _m.t >= 10 + abs(_top.yshift or 0) + 6, f"FIX_40: dir legend outside the top margin: y={_top.y} yanchor={_top.yanchor} t={_m.t}"
            assert _bot.y == 0 and _bot.yanchor == "top" and _m.b >= 10 + abs(_bot.yshift or 0) + 6, f"FIX_40: edge legend outside the bottom margin: y={_bot.y} yanchor={_bot.yanchor} b={_m.b}"
            # S5b (owner 2026-09-29): uirevision is the VIEW's key — the same view (selected dirs + depth) keeps
            # it across refresh ticks, so Plotly reacts in place and a zoom holds; a drill-in or a Reverse1
            # (another dir set, or another depth) gets a new one, so the next view opens unzoomed.
            def _rev40(nodes, imp, subs, sel, tick):
                _f, _ = _cv20.generate_figure([{"name": n, "connected": True} for n in nodes], imp, subs,
                                              selected_dirs=sel, animation_tick=tick)
                return _f.layout.uirevision
            _v40 = (["a", "\U0001f4c1pkg", "\U0001f4c1lib"], {"a": ["\U0001f4c1pkg"]}, {"a": None, "\U0001f4c1pkg": "pkg", "\U0001f4c1lib": "lib"})
            _d40 = (["a", "pkg/b", "\U0001f4c1lib"], {"a": ["pkg/b"]}, {"a": None, "pkg/b": "pkg", "\U0001f4c1lib": "lib"})
            _root_a, _root_b = _rev40(*_v40, None, 0), _rev40(*_v40, None, 5)
            _drill_a, _drill_b = _rev40(*_d40, ["pkg"], 1), _rev40(*_d40, ["pkg"], 6)
            _deeper = _rev40(*_d40, None, 2)               # same nodes' depth, other dirs
            _dep = _rev40(["a", "pkg/b", "pkg/c/d"], {"a": ["pkg/b"]}, {"a": None, "pkg/b": "pkg", "pkg/c/d": "pkg"}, ["pkg"], 3)
            _miss40: List[str] = []
            for _holds40, _what40 in (
                    (isinstance(_root_a, str) and bool(_root_a), f"uirevision must be set, got {_root_a!r}"),
                    (_root_a == _root_b and _drill_a == _drill_b, f"uirevision must hold across ticks of one view: {_root_a}/{_root_b}, {_drill_a}/{_drill_b}"),
                    (_root_a != _drill_a, "a drill-in (dirs + depth change) must get a new uirevision — the next view opens unzoomed"),
                    (_drill_a != _deeper, "another dir selection must get a new uirevision"),
                    (_drill_a != _dep, "another depth (same dirs) must get a new uirevision")):
                if not _holds40:
                    _miss40.append(_what40)
            if _miss40:
                step15_health["tier2"]["status_band (FIX_40)"] = "✗ FIX_40: " + "; ".join(_miss40)
                all_passed = False
            else:
                step15_health["tier2"]["status_band (FIX_40)"] = "✓ one text band above the graph (alerts + events), no bottom banner; Loading overlay visible; both legends anchored inside a 24-px margin; uirevision stable across ticks of a view, new on a dirs/depth change"
        except Exception as e:
            step15_health["tier2"]["status_band (FIX_40)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        # FIX_38 (2026-09-15, run 116): step 15 BUILDS A GRAPH on a fixture — discovery, the per-file scan, edge
        # resolution and one BROKEN node: the subsystem's one job, measured (FIX_35 h: before this the step exercised
        # helpers only). No production change; the scanner is read only. The fixture and the syntax check's bytecode
        # (PYTHONPYCACHEPREFIX under .cr_pycache) are removed afterwards.
        try:
            import shutil as _sh38
            from ast_scanner import CircuitScanner as _CS38
            _fx38 = Path(tempfile.mkdtemp(prefix="hc_fix38_"))
            try:
                (_fx38 / "pkg").mkdir(); (_fx38 / "pkg" / "__init__.py").write_text("")
                (_fx38 / "pkg" / "a.py").write_text("from pkg import b\n"); (_fx38 / "pkg" / "b.py").write_text("def f():\n    return 1\n")
                (_fx38 / "run.py").write_text("import pkg.a\n"); (_fx38 / "bad.py").write_text("def x(:\n")
                _sc38 = _CS38(str(_fx38), exclude_relpaths=set())
                _scripts38 = _sc38.discover_scripts()
                assert sorted(str(p.relative_to(_fx38)) for p in _scripts38) == ["bad.py", "pkg/__init__.py", "pkg/a.py", "pkg/b.py", "run.py"], f"FIX_38: discovery must find the five files, got {_scripts38}"
                _sc38._known_filenames = {p.name for p in _scripts38}
                _nodes38 = [_sc38.scan_script(p) for p in _scripts38]
                _edges38 = _sc38._resolve_edges(_nodes38)
                assert len(_nodes38) == len(_scripts38), "FIX_38: one node per discovered file"
                assert ("run", "pkg/a") in _edges38, f"FIX_38: at least one resolved in-target import edge (run -> pkg/a), got {_edges38}"
                _bad38 = [n for n in _nodes38 if n.name == "bad"]
                # FIX_53 (2026-09-17): the reason now NAMES THE LINE (`Syntax error: line N: <msg>`) — the gate
                # prints it, so a real break says where it is. `bad.py` is under no fixture pattern, so it is
                # still a BROKEN node and still stops a launch.
                assert _bad38 and _bad38[0].syntax_valid is False and _bad38[0].connected is False \
                    and (_bad38[0].import_error or "").startswith("Syntax error") and "line 1" in (_bad38[0].import_error or ""), \
                    f"FIX_38: the broken file is the BROKEN node (the WIRING gate's reason, offline), got {_bad38[0].import_error if _bad38 else None!r}"
                assert _bad38[0].syntax_fixture is False, "FIX_53: a break outside a fixture pattern is never excused"
                assert all(n.syntax_valid and n.connected for n in _nodes38 if n.name != "bad"), "FIX_38: every other node parses and connects"
                step15_health["tier2"]["circuit.graph_on_fixture (FIX_38)"] = f"✓ {len(_nodes38)} nodes, {len(_edges38)} edges ({', '.join(a + ' -> ' + b for a, b in sorted(_edges38))}), 1 BROKEN (bad: Syntax error)"
            finally:
                _sh38.rmtree(_fx38, ignore_errors=True)
                _cr38 = Path(__file__).resolve().parent / ".cr_pycache"; _pyc38 = _cr38 / str(_fx38).lstrip("/")
                _sh38.rmtree(_pyc38, ignore_errors=True)
                _p38 = _pyc38.parent
                while _p38 != _cr38 and _p38.exists() and not any(_p38.iterdir()):
                    _p38.rmdir(); _p38 = _p38.parent
        except Exception as e:
            step15_health["tier2"]["circuit.graph_on_fixture (FIX_38)"] = f"✗ {type(e).__name__}: {e}"
            all_passed = False

        ok = len([v for v in step15_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/{len(step15_health['tier1'])} checks OK")
        print(f"  Tier 2: {step15_health['tier2'].get('integrated_workflow', '✗')}")
        for _k in ("observability_health (FIX_19)", "running_entries (FIX_20)", "restarter (FIX_52)",
                   "launch hygiene (I-153/I-99/I-155/I-69)",
                   "syntax_fixture (FIX_53)", "severed_links (ITEM_11)", "circuit.graph_on_fixture (FIX_38)", "status_band (FIX_40)"):
            print(f"  {step15_health['tier2'].get(_k, '✗ not run')} — {_k}")

    except Exception as e:
        step15_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_15_circuit_daemon"] = step15_health

    # ─────────────────────────────────────────────────────────────
    # Step 16: NOAI Validator Daemon
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 16: NOAI Validator Daemon")
    step16_health: Dict[str, Any] = {"tier1": {}, "tier2": {}}

    try:
        from no_aivalidator.NOAI_VALIDATOR_DAEMON import (
            NoAIValidatorDaemon,
            FileEntry, FunctionResult, FlaggedIssue,
            read_file_locked as nvd_read_file_locked,
            write_file_locked as nvd_write_file_locked,
            parse_line_ranges,
            functions_at_lines,
            _rule_to_job_type,
            _extract_rule_id,
            stage_discover,
        )

        # Tier 1: Dataclass constructability
        for dc_name, dc_factory in [
            ("FileEntry", lambda: FileEntry(path=Path("/tmp/test.py"), relative="test.py", node_name="test")),
            ("FunctionResult", lambda: FunctionResult(function="fn", line=1, passed=True)),
            ("FlaggedIssue", lambda: FlaggedIssue(
                file_relative="test.py", node_name="test", function="fn",
                line=1, failure_layer="L1", failure_reason="test",
                triggered_patterns=["NAI-010"], rule_id="NAI-010", job_type="logic_fix",
            )),
        ]:
            try:
                obj = dc_factory()
                assert obj is not None
                step16_health["tier1"][dc_name] = "✓"
            except Exception as e:
                step16_health["tier1"][dc_name] = f"✗ {e}"
                all_passed = False

        # Tier 1: Pure helper functions
        try:
            result = parse_line_ranges("L42, L50-55")  # type: ignore[assignment]  # FIX_54 ast-pos
            assert result == {42, 50, 51, 52, 53, 54, 55}, f"Got {result}"
            step16_health["tier1"]["parse_line_ranges"] = "✓"
        except Exception as e:
            step16_health["tier1"]["parse_line_ranges"] = f"✗ {e}"
            all_passed = False

        try:
            jt = _rule_to_job_type("NAI-010")
            assert isinstance(jt, str) and len(jt) > 0
            step16_health["tier1"]["_rule_to_job_type"] = "✓"
        except Exception as e:
            step16_health["tier1"]["_rule_to_job_type"] = f"✗ {e}"
            all_passed = False

        try:
            rid = _extract_rule_id(["NAI-010"])
            assert rid == "NAI-010"
            rid_empty = _extract_rule_id([])
            assert rid_empty == ""
            step16_health["tier1"]["_extract_rule_id"] = "✓"
        except Exception as e:
            step16_health["tier1"]["_extract_rule_id"] = f"✗ {e}"
            all_passed = False

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(_TEST_SOURCE)
                temp_path = Path(f.name)
            hits = functions_at_lines(temp_path, {2, 7})
            assert isinstance(hits, list)
            temp_path.unlink()
            step16_health["tier1"]["functions_at_lines"] = "✓"
        except Exception as e:
            step16_health["tier1"]["functions_at_lines"] = f"✗ {e}"
            all_passed = False

        # Tier 2: Integration
        try:
            # read/write round-trip
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_json = Path(f.name)
            test_data = {"health_check": True, "step": 16}
            nvd_write_file_locked(temp_json, test_data)
            read_back = nvd_read_file_locked(temp_json)
            assert read_back == test_data, f"Round-trip mismatch: {read_back}"
            temp_json.unlink()

            # stage_discover on a temp dir with a test .py file
            with tempfile.TemporaryDirectory() as tmpdir:
                test_file = Path(tmpdir) / "sample.py"
                test_file.write_text(_TEST_SOURCE)
                entries = stage_discover(Path(tmpdir))
                assert isinstance(entries, list)

            # NoAIValidatorDaemon — instantiate without starting loop
            daemon = NoAIValidatorDaemon()
            assert hasattr(daemon, 'validator')
            assert hasattr(daemon, 'running')
            daemon.running = False

            step16_health["tier2"]["integrated_workflow"] = "✓"
        except Exception as e:
            step16_health["tier2"]["integrated_workflow"] = f"✗ {e}"
            all_passed = False

        ok = len([v for v in step16_health['tier1'].values() if v == '✓'])
        print(f"  Tier 1: {ok}/{len(step16_health['tier1'])} checks OK")
        print(f"  Tier 2: {step16_health['tier2'].get('integrated_workflow', '✗')}")

    except ImportError as e:
        step16_health["error"] = str(e)
        all_passed = False
        print(f"  ✗ Import failed: {e}")

    results["steps"]["step_16_noai_daemon"] = step16_health

    # ─────────────────────────────────────────────────────────────
    # E1 (2026-10-01): steps 17, 18 and 20 overlapped. 18's recall guard (58.6 s of the 80 s health check)
    # and 20's venv check start HERE on worker threads, before 17 runs on this thread; each step's block
    # below joins its own result exactly where it used to compute it and emits the lines the callable
    # printed, so the log reads in step order. Neither 17 (census + hunter, subprocess output captured,
    # tmp files outside the tree), 18 (reads only) nor 20 (importlib.metadata, pip check captured, AST
    # walk) writes into the tree, so the overlap cannot race a read. A load failure here is handed to the
    # step's own except (the same "failed to run" line as before).
    # ─────────────────────────────────────────────────────────────
    import concurrent.futures as _cf_e1
    _e1_out = _StepStdout(sys.stdout); sys.stdout = _e1_out  # type: ignore[assignment]
    _e1_pool = _cf_e1.ThreadPoolExecutor(max_workers=2, thread_name_prefix="hc_step")
    _fut18: Any = None; _fut20: Any = None
    try:
        import importlib.util as _ilu18
        _spec18: Any = _ilu18.spec_from_file_location("disposition_check", Path(__file__).resolve().parent / "disposition_check.py")
        _dc = _ilu18.module_from_spec(_spec18); _spec18.loader.exec_module(_dc)  # type: ignore[union-attr]
        _fut18 = _e1_pool.submit(_e1_out.run_buffered, _dc.check)
    except Exception as _e18:
        _fut18 = _StepStdout.failed(_e18)
    try:
        import importlib.util as _ilu20
        _spec20: Any = _ilu20.spec_from_file_location("venv_check", Path(__file__).resolve().parent / "venv_check.py")
        _vc = _ilu20.module_from_spec(_spec20); _spec20.loader.exec_module(_vc)  # type: ignore[union-attr]
        _fut20 = _e1_pool.submit(_e1_out.run_buffered, _vc.check)
    except Exception as _e20:
        _fut20 = _StepStdout.failed(_e20)

    # ─────────────────────────────────────────────────────────────
    # Step 17: Pre-ranker ranking census (owner ruling 2026-09-05, late sitting)
    # "every time I've said no ranking before the ranker it has been broken" —
    # scan every rule-bearing module for numeric decisions; each must be on the
    # explicit allowlist (structural fact / plumbing) or carry a dated exemption
    # naming the plan item that removes it. Anything else FAILS the gate.
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 17: Pre-ranker ranking census (no ranking before the ranker)")
    step17_health: Dict[str, Any] = {}
    try:
        import importlib.util as _ilu
        _spec: Any = _ilu.spec_from_file_location("preranker_census", Path(__file__).resolve().parent / "preranker_census.py")
        _pc = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_pc)  # type: ignore[union-attr]
        _res = _pc.check()
        step17_health["sites_scanned"] = _res["sites"]
        step17_health["allowed"] = _res["allowed"]
        step17_health["exempt"] = [f"{r['file']}:{r['line']} {r['func']} {r['expr']}" for r in _res["exempt"]]
        step17_health["disallowed"] = [f"{r['file']}:{r['line']} {r['func']} [{r['kind']}] {r['expr']}" for r in _res["disallowed"]]
        step17_health["stale_allowlist_entries"] = _res["stale_allowlist_entries"]
        print(f"  {_res['sites']} numeric sites scanned — allowed {_res['allowed']}, exempt {len(_res['exempt'])}, DISALLOWED {len(_res['disallowed'])}")
        for line in step17_health["exempt"]:
            print(f"  ⚠ exempt (dated, plan item named in preranker_allowlist.json): {line}")
        if _res["stale_allowlist_entries"]:
            print(f"  ⚠ {len(_res['stale_allowlist_entries'])} allowlist entries no longer match any site (clean up)")
        if _res["disallowed"]:
            for line in step17_health["disallowed"]:
                print(f"  ✗ DISALLOWED pre-ranker ranker: {line}")
            all_passed = False
        else:
            print("  ✓ no disallowed pre-ranker ranking (literal-comparison census)")
        # owner 2026-10-07 03:35 ("any way we can get rid of this one completely"): the extended pre-ranker
        # HUNTER and its ledger join / creep gate are GONE from the health check. Every build edit raised
        # "CREEP: n hunter site(s) with no ledger row" and stopped the launch; the literal-comparison census
        # above is the gate that stays. The hunter script and ledger remain on disk for a hand run.
    except Exception as e:
        step17_health["error"] = f"{type(e).__name__}: {e}"
        print(f"  ✗ census failed to run: {e}")
        all_passed = False
    results["steps"]["step_17_preranker_census"] = step17_health

    # ─────────────────────────────────────────────────────────────
    # Step 18: Rule-disposition table + recall guard (calibrator, owner decisions 2026-09-06)
    # Dispositions are DATA (system_scripts/rule_dispositions.json); the ranker reads
    # them. The gate FAILS when an emitted id has no row, a strict (proof) family is
    # marked context, or a plant of a frozen fully-caught family is no longer caught in
    # substance. Deciding families without evidence are REPORTED (FAIL once
    # disposition_close.json says so). The strict layer's precision is surfaced every run.
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 18: Rule-disposition table + recall guard (dispositions are data; nothing inferred)")
    step18_health: Dict[str, Any] = {}
    try:
        # E1: the guard has been running on its worker thread since before step 17 — join it here, emit what it
        # printed (the GUARDED / NOT GUARDED lines) in the place they used to be printed, then report as before.
        _r18, _out18 = _fut18.result()
        print(_out18, end="")
        for _k in ("emitted", "rows", "missing_rows", "strict_context_overlap", "deciding_unevidenced", "unevidenced_mode", "stale_rows", "recall", "strict_precision", "fails"):
            if _k in _r18:
                step18_health[_k] = _r18[_k]
        print(f"  {_r18.get('emitted', 0)} emitted ids / {_r18.get('rows', 0)} rows — missing {len(_r18.get('missing_rows', []))}, "
              f"strict∩context {len(_r18.get('strict_context_overlap', []))}, stale {len(_r18.get('stale_rows', []))}, "
              f"deciding without evidence {len(_r18.get('deciding_unevidenced', []))} ({_r18.get('unevidenced_mode', 'REPORT')})")
        _rc = _r18.get("recall") or {}
        if _rc.get("not_measured"):
            print(f"  ▣ recall guard STRUCK (owner 2026-09-08): {_rc.get('why') or _rc.get('error') or 'no planted target on disk'}")
        else:
            print(f"  recall guard: {_rc['targets']} archived targets ({_rc.get('from_gate_evidence', 0)} from gate_evidence, {_rc.get('from_runs', 0)} from runs) "
                  f"/ {_rc['plants']} plants — {_rc['caught_in_substance']} caught in substance, "
                  f"{_rc['caught_by_id']} by id; controls {_rc['controls_clean']}/{_rc['controls']} clean; lost families {len(_rc.get('lost_families') or [])}")
        _sp = _r18.get("strict_precision") or {}  # type: ignore[assignment]  # FIX_54 ast-pos
        if _sp:
            print("  strict precision (" + str(_sp.get("dir")) + "): " + "; ".join(  # type: ignore[attr-defined]  # FIX_54 ast-pos
                f"{i} {len(v['libs_hit'])}/{v['libs_total']} libs / {v['rows']['anywhere']} rows" for i, v in _sp.items() if i != "dir"))  # type: ignore[attr-defined]  # FIX_54 ast-pos
        for _f in _r18.get("fails", []):
            print(f"  ✗ {_f}")
        if _r18.get("passed"):
            print("  ✓ every emitted id has a row; no strict family is context; no frozen plant lost")
        else:
            all_passed = False
    except Exception as e:
        print(getattr(e, "hc_printed", ""), end="")   # E1: what the guard printed before it failed
        step18_health["error"] = f"{type(e).__name__}: {e}"
        print(f"  ✗ disposition check failed to run: {e}")
        all_passed = False
    results["steps"]["step_18_dispositions"] = step18_health

    # ─────────────────────────────────────────────────────────────
    # Step 19: Repair-generator registry + plants (NEW IMPLEMENTATION item 4, 2026-09-08)
    # Every deciding id in rule_dispositions.json has exactly one registry row
    # (rewriter | no_fix_by_design | unbuilt) → FAIL on a missing row; counts by kind
    # printed every run (unbuilt LOUDLY); every rewriter runs against its planted
    # counterfeit: fires, parses, differs, the rule goes quiet on the rewrite, and the
    # before/after modules return the same value when the plant declares a call.
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 19: Repair-generator registry + plants (one row per deciding id; rewriters proven on their plants)")
    step19_health: Dict[str, Any] = {}
    try:
        import importlib.util as _ilu19
        _spec19: Any = _ilu19.spec_from_file_location("generator_check", Path(__file__).resolve().parent / "generator_check.py")
        _gc = _ilu19.module_from_spec(_spec19); _spec19.loader.exec_module(_gc)  # type: ignore[union-attr]
        _r19 = await _gc.acheck()
        for _k in ("deciding", "rows", "missing_rows", "rows_not_deciding", "by_kind", "rewriters", "no_fix_by_design", "fails"):
            step19_health[_k] = _r19.get(_k)
        step19_health["plants"] = {p["rule_id"]: ("✓" if p["ok"] else f"✗ {p.get('error')}") for p in _r19.get("plants", [])}
        step19_health["unbuilt"] = len(_r19.get("unbuilt_ids") or [])
        _bk = _r19.get("by_kind") or {}
        # FIX_41 (2026-09-15): every deciding id carries a solution kind — rewriter or prescribed; no_fix_by_design only for
        # the ids listed in solution_kinds_pending.json (the FIX_43 finite set, or another lane's prescriptions), else FAIL.
        print(f"  {_r19.get('rows', 0)} registry rows / {_r19.get('deciding', 0)} deciding ids — rewriter {_bk.get('rewriter', 0)}, "
              f"prescribed {_bk.get('prescribed', 0)}, no_fix (pending FIX_43 finite set) {len(_r19.get('no_fix_pending_finite_set') or [])}, "
              f"no_fix (pending another lane) {len(_r19.get('no_fix_pending_lane') or [])}, no_fix UNLISTED {len(_r19.get('no_fix_unlisted') or [])}, "
              f"UNBUILT {_bk.get('unbuilt', 0)}")
        for _p in _r19.get("plants", []):
            if _p.get("alias_of"):   # set 4b-13 (2026-09-10): a plant-less alias row, proven by its canonical row's plant
                print(f"  {'≡' if _p['ok'] else '✗'} {_p['rule_id']} {_p['role']}: {_p.get('what') or _p.get('error', '')}")
                continue
            print(f"  {'✓' if _p['ok'] else '✗'} {_p['rule_id']} {_p['role']}: fires={_p.get('fires')} meaning_quiet={_p.get('meaning_quiet')} equivalent={_p.get('equivalent')}")
        for _f in _r19.get("fails", []):
            print(f"  ✗ {_f}")
        if _r19.get("passed"):
            print("  ✓ every deciding id has a registry row; every rewriter proven on its plant")
        else:
            all_passed = False
    except Exception as e:
        step19_health["error"] = f"{type(e).__name__}: {e}"
        print(f"  ✗ generator check failed to run: {e}")
        all_passed = False
    # Item 6 (2026-09-09): the tester's report — gearbox.write_tester_report() on a fixture
    # state yields the schema (the measure: infractions, solutions, confirmed, per-infraction
    # confirmed — no failure kinds, owner 2026-09-09); confirmed_fraction is null when
    # solutions == 0 (never 0.0), confirmed / solutions otherwise; an unreadable state yields
    # status NOT MEASURED.
    try:
        import importlib.util as _ilu6, tempfile as _tf6, json as _json6
        _spec6: Any = _ilu6.spec_from_file_location("gearbox", Path(__file__).resolve().parent / "gearbox.py")
        _gb = _ilu6.module_from_spec(_spec6); _spec6.loader.exec_module(_gb)  # type: ignore[union-attr]
        _keys = {"target", "repo_id", "run_started", "run_ended", "builder_cycles", "infractions", "solutions", "confirmed",
                 "status", "confirmed_fraction", "tester_ran", "per_infraction", "return_channel_lines", "builder_state_sha256"}
        with _tf6.TemporaryDirectory() as _d6:
            _d = Path(_d6); _t = _d / "fixture_target"; _t.mkdir()
            _tester = {"confirmed": 0, "solutions": 0, "orphans": 0, "unparsed": 0, "channel_lines": 0}
            _row = {"file": "a.py", "function": "f", "line": 1, "rule_ids": ["NAI-078"], "digest": None,
                    "tester": {"confirmed": False}, "fix_order": 1, "exonerated": False}
            _st = _d / "BUILDER_STATE.json"
            _st.write_text(_json6.dumps({"cycle": 3, "summary": {"findings": 1, "with_fix": 0, "tester": _tester}, "rows": {"a.py::f::1": _row}}))
            _r0 = _gb.write_tester_report(_t, "fixture000000", "2026-09-09T00:00:00+00:00", builder_state=_st, channel=_d / "none.jsonl", out_dir=_d / "out")
            assert _keys <= set(_r0), f"report keys missing: {_keys - set(_r0)}"
            assert _r0["confirmed_fraction"] is None and _r0["solutions"] == 0 and _r0["status"] == "MEASURED", "solutions 0 must give confirmed_fraction null"
            assert _r0["per_infraction"][0]["confirmed"] is False and _r0["builder_cycles"] == 3, _r0["per_infraction"]
            assert (_d / "out" / "tester_report.json").exists(), "tester_report.json not written"
            _tester2 = dict(_tester, confirmed=1, solutions=2, channel_lines=1)
            _ch = _d / "return_channel_fixture000000.jsonl"; _ch.write_text('{"digest": "abc", "replace_span": "a.py:L1-L2", "outcome": "confirmed"}\n')
            _st.write_text(_json6.dumps({"cycle": 4, "summary": {"findings": 2, "with_fix": 2, "tester": _tester2}, "rows": {}}))
            _r1 = _gb.write_tester_report(_t, "fixture000000", "2026-09-09T00:00:00+00:00", builder_state=_st, channel=_ch, out_dir=_d / "out")
            assert _r1["confirmed_fraction"] == 0.5 and _r1["return_channel_lines"] == 1 and (_d / "out" / "state_during_run" / "return_channel.jsonl").exists(), _r1
            _r2 = _gb.write_tester_report(_t, "fixture000000", "2026-09-09T00:00:00+00:00", builder_state=_d / "missing.json", channel=_ch, out_dir=_d / "out")
            assert _r2["status"] == "NOT MEASURED" and _r2.get("error"), _r2
            # I-14 (2026-09-15): solutions exist but NO tester ran (no channel line, channel_lines 0) -> null, never 0.0
            _tester3 = dict(_tester, confirmed=0, solutions=2, channel_lines=0)
            _st.write_text(_json6.dumps({"cycle": 5, "summary": {"findings": 2, "with_fix": 2, "tester": _tester3}, "rows": {}}))
            _r3 = _gb.write_tester_report(_t, "fixture000000", "2026-09-09T00:00:00+00:00", builder_state=_st, channel=_d / "none.jsonl", out_dir=_d / "out")
            assert _r3["status"] == "MEASURED" and _r3["solutions"] == 2 and _r3["tester_ran"] is False and _r3["confirmed_fraction"] is None, \
                f"I-14: solutions without a tester run must give confirmed_fraction null, got {_r3['confirmed_fraction']} tester_ran={_r3['tester_ran']}"
            assert _r1["tester_ran"] is True, "I-14: a channel line means the tester ran"
        step19_health["tester_report"] = "✓ schema; confirmed_fraction null at 0 solutions, null at 2 solutions with no tester run (I-14), 0.5 at 1 of 2; NOT MEASURED on an unreadable state"
        print(f"  {step19_health['tester_report']} (item 6)")
    except Exception as e:
        step19_health["tester_report"] = f"✗ {type(e).__name__}: {e}"
        print(f"  ✗ tester report fixture: {e}")
        all_passed = False
    results["steps"]["step_19_generators"] = step19_health

    # ─────────────────────────────────────────────────────────────
    # Step 20: venv compatibility (FIX_44, owner 2026-09-15 "yes of course")
    # FAIL: the running interpreter outside any installed distribution's Requires-Python; pip check
    # broken; a pyproject dependency not installed; a module imported unguarded at MODULE LEVEL by
    # live engine code that cannot be imported. INFO only: tested-classifier ceilings below the
    # running Python; absent imports at call time (uncalled path ≠ defect, owner 2026-09-09) or in a
    # file off the daemon route. No network — importlib.metadata + pip check + an AST import walk.
    # ─────────────────────────────────────────────────────────────
    print("\n▶ Step 20: venv compatibility (interpreter inside every Requires-Python; pip check; declared deps present; no absent module-level import)")
    step20_health: Dict[str, Any] = {}
    try:
        # E1: joined here — the venv check ran on its worker thread alongside steps 17 and 18.
        _r20, _out20 = _fut20.result()
        print(_out20, end="")
        for _k in ("python", "executable", "distributions", "declared", "import_walk", "fails", "info", "passed"):
            step20_health[_k] = _r20.get(_k)
        step20_health["pip_check"] = _r20.get("pip_check", {}).get("ok")
        step20_health["third_party"] = _r20.get("third_party")
        print(f"  python {_r20['python']} at {_r20['executable']}; {_r20['distributions']} distributions; "
              f"pip check {'clean' if _r20['pip_check']['ok'] else 'BROKEN'}; declared {len(_r20['declared'])}; "
              f"import walk {_r20['import_walk']['files']} files over {', '.join(_r20['import_walk']['packages'])}; "
              f"third-party names {len(_r20['third_party'])} (present {sum(1 for v in _r20['third_party'].values() if v['present'])})")
        for _f in _r20["fails"]:
            print(f"  ✗ {_f}")
        for _i in _r20["info"]:
            print(f"  · {_i}")
        if _r20["passed"]:
            print("  ✓ venv matches what the app needs")
        else:
            all_passed = False
    except Exception as e:
        print(getattr(e, "hc_printed", ""), end="")   # E1: what the venv check printed before it failed
        step20_health["error"] = f"{type(e).__name__}: {e}"
        print(f"  ✗ venv check failed to run: {e}")
        all_passed = False
    results["steps"]["step_20_venv"] = step20_health
    _e1_pool.shutdown(wait=True)
    sys.stdout = _e1_out._real   # E1: both worker threads joined — the real stdout is back

    # Step 21: naming-drift data type tracker (permanent, 2026-10-01) — the plant repo's launch pass equals
    # its expected rows byte-for-byte and the block before any baseline reads NOT MEASURED, never 0.
    print("\n▶ Step 21: Naming-drift data type tracker (plant repo rows == expected; NOT MEASURED before the scan)")
    step21_health: Dict[str, Any] = {}
    try:
        import subprocess as _sp21
        _r21 = _sp21.run([sys.executable, str(Path(__file__).resolve().parent / "naming_drift_proof.py")],
                         cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True, timeout=300)
        _verdict21 = next((ln for ln in reversed(_r21.stdout.splitlines()) if ln.startswith("naming-drift proof:")), "")
        _fails21 = [ln.strip() for ln in _r21.stdout.splitlines() if ln.startswith("  ✗ ")]
        step21_health["rc"] = _r21.returncode
        step21_health["verdict"] = _verdict21 or "NOT MEASURED — the proof printed no verdict"
        step21_health["fails"] = _fails21
        if _r21.returncode == 0 and _verdict21.endswith("PASS"):
            print(f"  ✓ {_verdict21}")
        else:
            for ln in _fails21:
                print(f"  {ln}")
            print(f"  ✗ {_verdict21 or 'naming-drift proof: no verdict'} (rc {_r21.returncode})"
                  + (f" — {_r21.stderr.strip().splitlines()[-1]}" if _r21.stderr.strip() else ""))
            all_passed = False
    except Exception as e:
        step21_health["error"] = f"{type(e).__name__}: {e}"
        print(f"  ✗ naming-drift proof failed to run: {e}")
        all_passed = False
    results["steps"]["step_21_naming_drift"] = step21_health

    # Step 22: the solution gate (owner 2026-10-08) — end to end on a fixture repo built in a temp directory: a real
    # scan, cr_submit, three Builder cycles (filter refusal, stage-1 fail, integrated fix, stage-3 fail + revert),
    # the cap, and proof that nothing touched the live state. A broken gate fails here, never as a silent zero.
    print("\n▶ Step 22: Solution gate (submit → filter → rank → runs → integrates → tests, revert, cap)")
    step22_health: Dict[str, Any] = {}
    try:
        _r22 = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve().parent / "solution_gate_proof.py")],
                              capture_output=True, text=True, timeout=600)
        _verdict22 = next((ln.strip() for ln in reversed(_r22.stdout.splitlines())
                           if ln.startswith("solution-gate proof:")), "")
        _fails22 = [ln.strip()[2:] for ln in _r22.stdout.splitlines() if ln.startswith("  ✗ ")]
        step22_health["rc"] = _r22.returncode
        step22_health["verdict"] = _verdict22 or "NOT MEASURED — the proof printed no verdict"
        step22_health["fails"] = _fails22
        if _r22.returncode == 0 and _verdict22.endswith("PASS"):
            print(f"  ✓ {_verdict22}")
        else:
            for ln in _fails22 or [(_r22.stderr or _r22.stdout).strip().splitlines()[-1:] or ["no output"]][0]:
                print(f"  ✗ {ln}")
            print(f"  ✗ {_verdict22 or 'solution-gate proof: NOT MEASURED'} (rc {_r22.returncode})")
            all_passed = False
    except Exception as e:
        step22_health["error"] = f"{type(e).__name__}: {e}"
        print(f"  ✗ solution-gate proof failed to run: {e}")
        all_passed = False
    results["steps"]["step_22_solution_gate"] = step22_health

    # ─────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    not_measured = {k: v["not_measured"] for k, v in results["steps"].items() if v.get("not_measured")}
    if not_measured:
        results["not_measured"] = not_measured
    struck = {k: v["struck"] for k, v in results["steps"].items() if v.get("struck")}
    if struck:
        results["struck"] = struck
    # FIX_31 (2026-09-15): the engine's OWN mypy count, watched every launch — true or NOT MEASURED.
    # Informational (the item does not require zero); the number is whatever it is.
    try:
        import subprocess as _sp31, re as _re31
        _root31 = Path(__file__).resolve().parent.parent
        # T7 (2026-09-17): `coderadar_mcp` joins the ENGINE list — the release form's package is
        # engine code now (session_tools imports system_scripts.gearbox), so its type count is
        # watched every launch like the rest. T2 left this line to T7; it moves a health number.
        _pkgs31 = [d for d in ("no_aivalidator", "system_scripts", "rca_main", "utils", "signature_engine", "detritus_cleaner", "semantic_analysis", "coderadar_mcp") if (_root31 / d).is_dir()]
        # B10 (Q-H1-1, 2026-10-01): the cache never lands at CR's root (<root>/.mypy_cache was 134 MB of it).
        # The launcher's MYPY_CACHE_DIR wins; run by hand, the default is pinned to the engine's own scratch
        # (setdefault: the value stays whatever the launcher exported, and mypy's own reader sees the same one).
        _cache31 = os.environ.setdefault("MYPY_CACHE_DIR", str(Path(__file__).resolve().parent / ".cr_pycache" / "mypy"))
        _r31 = _sp31.run([sys.executable, "-m", "mypy", *_pkgs31, "--ignore-missing-imports", "--cache-dir", _cache31], cwd=str(_root31), capture_output=True, text=True, timeout=300)
        _m31 = _re31.search(r"Found (\d+) errors? in (\d+) files?", _r31.stdout) or _re31.search(r"Success: no issues found in (\d+) source files", _r31.stdout)
        if _r31.returncode not in (0, 1) and "No module named mypy" in (_r31.stderr or ""):
            results["engine_mypy"] = "NOT MEASURED (mypy not importable by this interpreter)"
        elif _m31 and _m31.re.pattern.startswith("Found"):
            results["engine_mypy"] = f"{_m31.group(1)} errors in {_m31.group(2)} files"
        elif _m31:
            results["engine_mypy"] = f"0 errors in 0 files ({_m31.group(1)} checked)"
        else:
            results["engine_mypy"] = f"NOT MEASURED (mypy rc {_r31.returncode}: {(_r31.stderr or _r31.stdout)[-120:].strip()})"
    except Exception as _e31:
        results["engine_mypy"] = f"NOT MEASURED ({type(_e31).__name__}: {_e31})"
    print(f"engine mypy: {results['engine_mypy']}")
    if all_passed:
        results["status"] = "PASSED"
        print("HEALTH CHECK: ✓ PASSED — All measured steps ready")
    else:
        results["status"] = "FAILED"
        print("HEALTH CHECK: ✗ FAILED — Some steps have issues")
    for step, items in not_measured.items():
        print(f"NOT MEASURED: {step}: " + "; ".join(items))
    for step, items in struck.items():
        print(f"STRUCK: {step}: " + "; ".join(items))
    print("=" * 60)

    return results



def main() -> int:
    health = asyncio.run(run_health_check())
    return 0 if health.get("status") == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
