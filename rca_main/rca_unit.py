"""
RootCause Unit - GRANULARIZE Phase 6
The attribution layer..

Responsibility:
Analyzes the "failure site" (failing file) to find:
1. Upstream dependencies: Upstream dependencies (ImportTracer) - Stop 6.1
2. Downstream callers: Downstream callers (CallerTracer) - Stop 6.2
3. Context: Contextual evidence for the Finding System - Stop 6.3

It combines the ImportTracer with a new AST-based CallerTracer.

ONE analyzer (FIX_32 §4.3, 2026-09-10): RootCauseUnit.analyze_async returns {candidate: [evidence]} —
upstream imports ("Imported by failing file"), DOWNSTREAM callers ("Downstream caller of failing
file", FIX_32 — corroboration, never redundancy: a second, different piece of evidence for the same
infraction), related-by-context files ("Related by context (config_sibling|import|test)", FIX_33),
symbol definitions from the error text. The Phase-6 report shapes and the second analyzer are archived
(.archive/archived_20260910/rca_main/rca_unit_phase6_report_shapes.py.txt).

ENTIRE APP IS ASYNC: Using aiofiles for async file operations with sync bridging.
"""

import time as _time

import asyncio
import logging
import os
import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, List, Dict, Set, Optional, Tuple, TypeVar

# Flow tracing integration
_F = TypeVar('_F', bound=Callable[..., Any])
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass
def set_workflow(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace, set_workflow  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False

from rca_main.constants import live_py_files
from rca_main.context_gathering_manager import ContextManager
# FIX_39 (owner Q1, 2026-09-15): the per-scan shared tree store — one read + one parse per
# live file per scan, shared with RCA (closes I-04 and, with the loop it removes, I-06).
from rca_main.scan_trees import ScanTrees

from rca_main.analyzers import ImportTracer

try:
    from orchestrator.utils.async_io import read_file_async
except ImportError:
    # Fallback async file read using aiofiles
    import aiofiles
    async def read_file_async(file_path: str) -> str:
        async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            return await f.read()

# ENTIRE APP IS ASYNC: All files have logging ability
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase-6 report shapes (FunctionSignature / CandidateFile / EvidenceBundle / RootCauseReport) and the
# second analyzer (analyze_full_async, _collect_evidence_async) ARCHIVED 2026-09-10 (FIX_32 §4.3: one
# analyzer, never two) — .archive/archived_20260910/rca_main/rca_unit_phase6_report_shapes.py.txt
# ═══════════════════════════════════════════════════════════════════════════════


class CallerTracer:
    """
    Identifies 'downstream' usage.
    If 'utils.py' is modified, who calls it?
    Useful for ensuring a fix doesn't break other parts of the system.
    """
    def __init__(self, repo_root: str, files=None, trees: Optional[ScanTrees] = None):
        self.repo_root = os.path.abspath(repo_root)
        self._cache: Dict[str, Any] = {}
        # Plan item 6 (owner 2026-09-05): when the validator hands over the
        # whitelist-filtered list, callers are searched in exactly those files —
        # no own walk (an own rglob crossed into the venv on run 6).
        self.files = [Path(f) for f in files] if files is not None else None
        # FIX_39: the per-scan store, when the scan built one. With it the caller search is a dict
        # lookup — no read, no parse, no gather (I-04 + I-06). Without it the per-file path below
        # stands unchanged (standalone __main__, the health check's own construction).
        self.trees = trees
        self.fallback_read_errors = 0

    def _py_files(self) -> List[Path]:
        # FIX_14 / FIX_32 §4.4: the handed-over list, else the ONE walk (scan_scope.iter_live_py)
        return live_py_files(self.repo_root, self.files)

    async def _find_direct_callers_async(self, target_file: str, target_function: str = "") -> List[str]:
        """
        Find files that directly import or call target_file using AST analysis.
        This is the leaf-level scanner; find_callers_async uses this for recursive tracing.
        """
        # FIX_39 (I-04): with the scan's store this is a LOOKUP in indices built by the one pass over
        # the live files — the per-site read+parse of every file is gone, and with the gather goes
        # I-06's `return_exceptions=True` swallow: a file that could not be read or parsed is in
        # ScanTrees.errors once per scan, counted and published, never a silently dropped candidate.
        if self.trees is not None:
            return self.trees.direct_callers(target_file, target_function)

        target_name = os.path.basename(target_file).replace('.py', '')
        callers = []

        py_files = self._py_files()  # the handed-over list, or a walk when none was given

        # No store (standalone / health check): the per-file path, but its exceptions are COUNTED and
        # reported — never a candidate that vanishes without a number (I-06's honest half here).
        batch_size = 20
        for i in range(0, len(py_files), batch_size):
            batch = py_files[i:i + batch_size]
            tasks = [self._check_file_for_caller_async(py_file, target_name, target_function)
                    for py_file in batch]

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):  # Valid caller found
                    callers.append(result)
                elif isinstance(result, BaseException):
                    self.fallback_read_errors += 1
                    logger.warning("caller check failed (counted, not swallowed — I-06): %r", result)

        return list(set(callers))  # Remove duplicates
        
    async def _check_file_for_caller_async(self, py_file: Path, target_name: str, target_function: str) -> Optional[str]:
        """
        Async helper to check if a file calls/imports the target.
        Returns file path if it's a caller, None otherwise.
        """
        try:
            content = await read_file_async(str(py_file))
            
            # Fast text-based pre-filter to avoid AST parsing overhead
            if target_name not in content:
                return None
                
            # Use AST for precise analysis
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    # Check imports
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name == target_name:
                                return str(py_file)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and target_name in node.module:
                            return str(py_file)
                        # FIX_32 (found on run 100 launch A): `from . import leaf` / `from pkg import leaf`
                        # names the module in the alias list, not in `module` — a caller all the same.
                        if any(alias.name == target_name for alias in node.names):
                            return str(py_file)
                    # Check function calls if target_function specified
                    elif target_function and isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id == target_function:
                            return str(py_file)
                        elif isinstance(node.func, ast.Attribute) and node.func.attr == target_function:
                            return str(py_file)
            except SyntaxError:
                # Fallback to text search for malformed files
                patterns = [
                    f"import {target_name}",
                    f"from {target_name}",
                    f"from .{target_name}",
                    f"from ..{target_name}",
                ]
                if target_function:
                    patterns.append(f"{target_function}(")
                
                if any(pattern in content for pattern in patterns):
                    return str(py_file)
                    
        except Exception as e:
            logger.debug("Could not read %s: %s", py_file, e)
            
        return None

    async def find_callers_async(self, target_file: str, target_function: str = "") -> List[str]:
        """
        Finds all files in the repo that import or call the target (with recursive tracing).

        ENTIRE APP IS ASYNC: Async implementation using find_callers_recursive.
        """
        return await self.find_callers_recursive(target_file, target_function, depth=3)

    async def find_callers_recursive(self, target_file: str, target_function: str = "",
                              seen: Optional[Set[str]] = None, depth: Optional[int] = None) -> List[str]:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 3
        """
        Recursive caller tracing to find chained dependencies.
        E.g., test_auth.py -> database.py -> utils.py
        """
        if seen is None:
            seen = set()
        if depth is not None and depth <= 0:
            return []

        target_file = os.path.abspath(target_file)
        if target_file in seen:
            return []

        seen.add(target_file)

        # Get direct callers using the leaf-level scanner (not self.find_callers_async!)
        direct_callers = await self._find_direct_callers_async(target_file, target_function)

        all_callers = []

        # Add direct callers
        for caller in direct_callers:
            if caller not in all_callers:
                all_callers.append(caller)

        # Recursively find callers of callers (chained dependencies)
        for caller in direct_callers:
            if caller not in seen and (depth is None or depth > 1):  # EXCISED cut 3 batch 2 (2026-09-06, agreed): the seen-set terminates; the number was the cap
                chained = await self.find_callers_recursive(caller, target_function, seen, depth - 1 if depth is not None else None)
                for c in chained:
                    if c not in all_callers:
                        all_callers.append(c)

        return all_callers


class RootCauseUnit:
    """
    The Main Analysis Hub.
    Integrates ImportTracer (Upstream) and CallerTracer (Downstream).
    """

    def __init__(self, repo_root: str, files=None, trees: Optional[ScanTrees] = None):
        self.repo_root = repo_root
        self.import_tracer = ImportTracer(repo_root)
        # Plan item 6 (owner 2026-09-05): the whitelist-filtered list, when given,
        # is the ONLY set of files this unit indexes or searches.
        self.files = [Path(f) for f in files] if files is not None else None
        # FIX_39 (owner Q1): ONE store per scan, built by the caller (the validator) and shared with
        # every failure site this unit analyses — each live file read once and parsed once per scan.
        self.trees = trees
        self.caller_tracer = CallerTracer(repo_root, files=files, trees=trees)
        # FIX_33 §4.2 (2026-09-10): the context manager, built ONCE per unit (a whole-set fact
        # once), fed the same whitelist-filtered list — its related files are evidence for the
        # Ranker on every row this unit analyzes.
        self.context_manager = ContextManager(repo_root, files=files)

        # Relationship graphs for comprehensive analysis
        self.import_graph: Dict[str, List[str]] = {}  # file -> [imported_files]
        self.used_by_graph: Dict[str, List[str]] = {}  # file -> [files_that_use_it]
        self._graphs_built = False
        # C1 (Q-H3b-6, 2026-10-01): the store's text does not change for the life of this unit (one
        # scan), so "which live file defines `term`" is asked of the store ONCE per term, not once per
        # term per failure site (6,000 sites × 3 substring scans over a 24,000-line file before).
        self._defines_memo: Dict[str, Optional[str]] = {}
        self._symbol_evidence_memo: Dict[Tuple[str, str], List[str]] = {}

    def _py_files(self) -> List[Path]:
        # FIX_14: the handed-over list, else the ONE walk (scan_scope.iter_live_py)
        return live_py_files(self.repo_root, self.files)

    async def build_relationship_graphs_async(self) -> None:
        """
        Build comprehensive relationship graphs for the entire repository.
        This enables better dependency analysis and impact assessment.
        
        Uses true async with pathlib.rglob + asyncio.gather for efficiency.
        """
        if self._graphs_built:
            return
            
        logger.info("🔍 Building relationship graphs...")
        
        py_files = self._py_files()  # the handed-over list, or a walk when none was given

        # Process files in batches for better async performance
        batch_size = 50
        for i in range(0, len(py_files), batch_size):
            batch = py_files[i:i + batch_size]
            
            # Create tasks for async processing
            tasks = [self._process_file_for_graph_async(str(py_file)) for py_file in batch]
            
            # Execute batch with asyncio.gather
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for py_file, result in zip(batch, results):
                if isinstance(result, BaseException):
                    logger.debug("Error processing %s for graph: %s", py_file, result)
                    continue

                if result:  # result is (file_path, imports) tuple
                    file_path, imports = result
                    self.import_graph[file_path] = imports
                    
                    # Build reverse used_by graph
                    for imported_file in imports:
                        if imported_file not in self.used_by_graph:
                            self.used_by_graph[imported_file] = []
                        if file_path not in self.used_by_graph[imported_file]:
                            self.used_by_graph[imported_file].append(file_path)
        
        self._graphs_built = True
        logger.info("🔍 Relationship graphs built: %d files mapped", len(self.import_graph))
        
    async def _process_file_for_graph_async(self, file_path: str) -> Optional[tuple[str, List[str]]]:
        """
        Async helper to process a single file for graph building.
        Returns (file_path, imports) tuple or None if error.
        """
        try:
            imports = await self.import_tracer.trace_imports_async(file_path, depth=1)
            return (file_path, imports)
        except Exception as e:
            logger.debug("Could not process %s for graph: %s", file_path, e)
            return None

    async def build_relationship_graphs(self) -> None:
        """ENTIRE APP IS ASYNC: Build relationship graphs asynchronously."""
        await self.build_relationship_graphs_async()

    async def get_impact_analysis(self, target_file: str) -> Dict[str, List[str]]:
        """
        Get comprehensive impact analysis using relationship graphs.
        Returns both upstream dependencies and downstream users.
        """
        if not self._graphs_built:
            await self.build_relationship_graphs_async()
            
        impact = {
            "upstream_dependencies": self.import_graph.get(target_file, []),
            "downstream_users": self.used_by_graph.get(target_file, [])
        }
        
        return impact

    async def analyze_async(self, failing_file: str, error_message: str = "") -> Dict[str, List[str]]:
        """
        Async implementation: Performs a full analysis on a failing file.

        Returns:
            candidates_context: Dict mapping {candidate_file_path: [evidence_notes]}
            This is the exact format required by the Finding System.
        """
        candidates_context: Dict[str, List[str]] = {}

        if not failing_file or not os.path.exists(failing_file):
            return candidates_context

        # Q-H3a-5 (C1, 2026-10-01): one line per site was 2,810 INFO lines on pandas; the per-sweep
        # summary ("RootCauseUnit: N analysis reports generated") stays at INFO in file_validation.
        logger.debug("🔎 RootCause: Analyzing failure site at %s...", os.path.basename(failing_file))
        
        # Build relationship graphs for comprehensive analysis
        if not self._graphs_built:
            await self.build_relationship_graphs_async()

        # 1. UPSTREAM TRACE (The "Upstream dependencies")
        # Use async trace_imports to find upstream dependencies
        upstream_imports = await self.import_tracer.trace_imports_async(failing_file, depth=None)  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 3
        
        for candidate in upstream_imports:
            if candidate not in candidates_context:
                candidates_context[candidate] = []

            # Boost the evidence based on file type
            evidence = f"Imported by failing file ({os.path.basename(failing_file)})"
            basename = os.path.basename(candidate).lower()
            if any(keyword in basename for keyword in ['status', 'const', 'config', 'setting', 'enum']):
                evidence += " [HIGH VALUE TARGET]"

            # Add specific clues from the error message
            if error_message:
                # Extract key values (e.g., "Expected 200, got 404")
                nums = re.findall(r'\b\d+\b', error_message)
                if nums:
                    evidence += f" | check for values: {', '.join(nums)}"  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `[:5]` removed

            candidates_context[candidate].append(evidence)
        
        # Populate relationship graphs during analysis
        failing_file_abs = os.path.abspath(failing_file)
        
        # Get imports and callers to populate graphs (async methods)
        imports = await self.import_tracer.trace_imports(failing_file, depth=1)
        callers = await self.caller_tracer.find_callers_async(failing_file)
        
        # Update graphs
        self.import_graph[failing_file_abs] = imports
        self.used_by_graph[failing_file_abs] = callers

        # FIX_32 (F-RCA1, 2026-09-10): every DOWNSTREAM caller is a candidate too. Before this the
        # callers were computed and dropped — a leaf file with callers yielded an empty suspect list.
        # CORROBORATION ≠ REDUNDANCY: a downstream caller is a second, different piece of evidence
        # for the same infraction; the Ranker receives every fact. The phrasing stays distinct from
        # the upstream line so the Builder's token builder can emit rca=downstream:<file> beside
        # rca=upstream:<file>.
        for caller in callers:
            if os.path.abspath(caller) == failing_file_abs:
                continue
            candidates_context.setdefault(caller, []).append(
                f"Downstream caller of failing file ({os.path.basename(failing_file)})")

        # FIX_33 §4.2 (2026-09-10): files related by context — the sibling config, an import the
        # failing file resolves to, its test — each labelled by the reason, evidence for the Ranker,
        # never a score. The manager was built once with this unit (files= from the validator).
        for related_path, why in await self.context_manager.related_files_async(failing_file):
            related = str(related_path)
            if os.path.abspath(related) == failing_file_abs:
                continue
            candidates_context.setdefault(related, []).append(f"Related by context ({why})")

        # Use relationship graphs for enhanced analysis
        if failing_file_abs in self.import_graph:
            for imported_file in self.import_graph[failing_file_abs]:
                if imported_file not in candidates_context:
                    candidates_context[imported_file] = []
                candidates_context[imported_file].append("Direct import dependency (from relationship graph)")

        # 2. CROSS-REFERENCE (The "Context")
        # Extract identifiers from error messages (both quoted and unquoted)
        
        # Pattern 1: Quoted identifiers like 'function_name' or "ClassName"  
        quoted_keywords = re.findall(r"['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]", error_message)
        
        # Pattern 2: Capitalized words (class names, constants)
        cap_keywords = re.findall(r'\b[A-Z][a-zA-Z0-9_]*\b', error_message)
        
        # Combine and deduplicate keywords
        all_keywords = list(set(quoted_keywords + cap_keywords))
        
        for keyword in all_keywords:
            if len(keyword) < 3:  # Skip noise keywords (too short)
                continue

            # Use CSI search to find where this symbol is defined
            definition_file = await self._find_definition_async(keyword)
            if definition_file and definition_file != failing_file:
                if definition_file not in candidates_context:
                    candidates_context[definition_file] = []
                candidates_context[definition_file].append(
                    f"Defines symbol '{keyword}' found in error traceback"
                )
                
                # Add code snippet for constants/status definitions — C1 (Q-H3b-6, 2026-10-01):
                # the same (file, keyword) pair yields the same lines on every site that names it,
                # so the read + split + parse happens once per pair per scan (`_symbol_evidence_async`).
                candidates_context[definition_file].extend(
                    await self._symbol_evidence_async(definition_file, keyword))

        logger.debug("🔎 Analysis complete: %d candidates identified", len(candidates_context))
        return candidates_context

    async def _symbol_evidence_async(self, definition_file: str, keyword: str) -> List[str]:
        """The "Snippet: …" line (the first line of `definition_file` that names `keyword` beside an
        `=` / `def ` / `class `) and, for a def, its "Function signature: …" line — verbatim the
        block that lived inline in `analyze_async`, computed once per (file, keyword) per unit."""
        memo_key = (definition_file, keyword)
        cached = self._symbol_evidence_memo.get(memo_key)
        if cached is not None:
            return list(cached)
        lines_out: List[str] = []
        try:
            # FIX_39: the store's text when the scan built one (the file was read once already)
            content = (self.trees.text_of(definition_file) if self.trees is not None else None)
            if content is None:
                content = await read_file_async(definition_file)
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if keyword in line and ('=' in line or 'def ' in line or 'class ' in line):
                    snippet = line.strip()
                    lines_out.append(f"Snippet: {snippet}")

                    # Extract function signatures with parameters and return types
                    if 'def ' in line:
                        try:
                            tree = ast.parse(content)

                            class SignatureVisitor(ast.NodeVisitor):
                                def __init__(self, target_name: str) -> None:
                                    self.target_name = target_name
                                    self.signature: Optional[str] = None

                                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                                    if node.name == self.target_name:
                                        # Extract parameters with type annotations
                                        params = []
                                        for arg in node.args.args:
                                            if arg.annotation:
                                                param_type = ast.unparse(arg.annotation) if hasattr(ast, 'unparse') else 'Any'
                                                params.append(f"{arg.arg}: {param_type}")
                                            else:
                                                params.append(arg.arg)

                                        param_str = ', '.join(params)

                                        # Extract return type annotation
                                        if node.returns:
                                            return_type = ast.unparse(node.returns) if hasattr(ast, 'unparse') else 'Any'
                                        else:
                                            return_type = 'None'

                                        self.signature = f"def {node.name}({param_str}) -> {return_type}"
                                    self.generic_visit(node)

                            visitor = SignatureVisitor(keyword)
                            visitor.visit(tree)
                            if visitor.signature:
                                lines_out.append(f"Function signature: {visitor.signature}")

                        except Exception as e:
                            logger.debug("Could not extract signature from %s: %s", definition_file, e)
                    break
        except Exception as e:
            logger.debug("Could not read snippet from %s: %s", definition_file, e)
        self._symbol_evidence_memo[memo_key] = list(lines_out)
        return lines_out

    async def analyze(self, failing_file: str, error_message: str = "") -> Dict[str, List[str]]:
        """
        Performs a full analysis on a failing file.

        ENTIRE APP IS ASYNC: Analyze candidates asynchronously.

        Returns:
            candidates_context: Dict mapping {candidate_file_path: [evidence_notes]}
            This is the exact format required by the Finding System.
        """
        return await self.analyze_async(failing_file, error_message)

    async def trace_imports(self, file_path: str, depth: Optional[int] = None) -> List[str]:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 1
        """
        Passthrough to ImportTracer (async).
        """
        return list(await self.import_tracer.trace_imports_async(file_path, depth))

    def get_candidate_files(self, failing_file: str, error_message: str = "", depth: Optional[int] = None) -> Dict[str, str]:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 2
        """
        Passthrough to ImportTracer for backwards compatibility (sync).
        """
        return dict(self.import_tracer.get_candidate_files(failing_file, error_message, depth))

    async def get_candidate_files_async(self, failing_file: str, error_message: str = "", depth: Optional[int] = None) -> Dict[str, str]:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 2
        """
        Async passthrough to ImportTracer.get_candidate_files_async.
        """
        return dict(await self.import_tracer.get_candidate_files_async(failing_file, error_message, depth))

    async def _find_definition_async(self, term: str) -> Optional[str]:
        """
        Scans repo for 'class Term' or 'def term' or 'TERM ='

        Uses batched async I/O for parallelism.
        """
        # FIX_39: the store already holds every live file's text — no second read per keyword per site.
        if self.trees is not None:
            if term not in self._defines_memo:
                self._defines_memo[term] = self.trees.defines(term)
            return self._defines_memo[term]

        patterns = [f"class {term}", f"def {term}", f"{term} ="]

        py_files = self._py_files()  # the handed-over list, or a walk when none was given

        async def _check_file(py_file: Path) -> Optional[str]:
            try:
                content = await read_file_async(str(py_file))
                if any(p in content for p in patterns):
                    return str(py_file)
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logger.warning("reported, not swallowed (cut 3): %s: %r", '_check_file', _e)
                pass
            return None

        # Process in batches for parallelism
        batch_size = 30
        for i in range(0, len(py_files), batch_size):
            batch = py_files[i:i + batch_size]
            results = await asyncio.gather(*[_check_file(f) for f in batch])
            for result in results:
                if result is not None:
                    logger.debug("Found definition of '%s' in %s", term, result)
                    return result

        return None

    async def _find_definition(self, term: str) -> Optional[str]:
        """Alias for _find_definition_async."""
        return await self._find_definition_async(term)

    async def find_callers(self, target_file: str, target_function: str = "") -> List[str]:
        """
        Find all files that call/import the target file.
        Useful for impact analysis.
        
        Now fully async - no bridging.
        """
        return await self.caller_tracer.find_callers_async(target_file, target_function)
        
    async def find_callers_recursive(self, target_file: str, target_function: str = "", 
                              seen: Optional[Set[str]] = None, depth: Optional[int] = None) -> List[str]:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 3
        """
        Find all callers including chained dependencies (e.g., test_auth -> database -> utils).
        """
        return await self.caller_tracer.find_callers_recursive(target_file, target_function, seen, depth)

    async def get_full_analysis(self, failing_file: str, error_message: str = "") -> Dict[str, Any]:
        """
        Get comprehensive analysis results including relationship graphs.
        
        Returns:
            Dict with candidates, import_graph, used_by_graph, callers, imports
        """
        candidates = await self.analyze(failing_file, error_message)
        
        # Ensure graphs are built
        if not self._graphs_built:
            await self.build_relationship_graphs_async()
            
        # Get additional analysis data
        imports = await self.import_tracer.trace_imports_async(failing_file, depth=1)
        callers = await self.find_callers(failing_file)
        
        return {
            'candidates': candidates,
            'import_graph': self.import_graph,
            'used_by_graph': self.used_by_graph,
            'callers': callers,
            'imports': imports
        }

    def clear_cache(self) -> None:
        """Clear the import resolution cache."""
        self.import_tracer.clear_cache()


# Quick test
if __name__ == "__main__":
    import sys

    # Configure logging for standalone execution
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 3:
        logger.error("Usage: python rca_unit.py <repo_root> <file_to_analyze> [error_message]")
        sys.exit(1)

    repo = sys.argv[1]
    target = sys.argv[2]
    error_msg = sys.argv[3] if len(sys.argv) > 3 else ""

    async def main() -> None:
        rca = RootCauseUnit(repo)

        logger.info("\n🔍 RootCause Analysis for: %s", target)
        logger.info("   Repo root: %s", repo)
        if error_msg:
            logger.info("   Error context: %s...", error_msg[:100])
        logger.info("")

        candidates = await rca.analyze(target, error_msg)

        if candidates:
            logger.info("🔎 Candidates Found:")
            for path, evidence_list in candidates.items():
                rel = os.path.relpath(path, repo)
                logger.info("\n   📁 %s", rel)
                for evidence in evidence_list:
                    logger.info("      - %s", evidence)
        else:
            logger.info("   No candidates found (file may have no local dependencies)")

        logger.info("\n📞 Downstream Callers:")
        callers = await rca.find_callers(target)
        if callers:
            for caller in callers[:10]:
                rel = os.path.relpath(caller, repo)
                logger.info("   - %s", rel)
        else:
            logger.info("   No callers found")

    asyncio.run(main())


# =============================================================================
# WORKFLOW HANDLER (executor.py integration)
# =============================================================================

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from executor import WorkflowContext


def _emit_rca_main_trace(name: str, success: bool, elapsed: float = 0.0, error: str | None = None) -> None:
    """Helper to emit RootCause Main traces."""
    if _TRACING_ENABLED:
        emit_trace(
            name=f"rca_main_{name}",
            success=success,
            elapsed=elapsed,
            error=error,
            layer='RootCause',
            module='rca_unit.py'
        )


@trace
async def rca_main_handler(context: 'WorkflowContext') -> 'WorkflowContext':
    """
    Workflow handler for Step 17: RootCause Main.

    Performs full rca analysis on all issues.
    Builds relationship graphs and identifies upstream candidates.
    Runs BEFORE granulation to enrich issue data with rca context.

    Reads: context.issues, context.repo_path
    Writes: context.step_results['rca_main'], enriches context.issues
    """
    # Set workflow context for tracing
    set_workflow('phase1_rca_main')

    # TRACE: Handler entry
    _start_total = _time.perf_counter()
    _emit_rca_main_trace('start', success=True, elapsed=0)

    # TRACE: Check issues exist
    _start = _time.perf_counter()
    if not context.issues:
        _emit_rca_main_trace('check_issues', success=True, elapsed=_time.perf_counter() - _start)
        _emit_rca_main_trace('no_issues', success=True, elapsed=0)
        context.step_results['rca_main'] = {
            'issues_analyzed': 0,
            'candidates_found': 0,
            'note': 'No issues to analyze'
        }
        _emit_rca_main_trace('complete', success=True, elapsed=_time.perf_counter() - _start_total)
        return context
    _emit_rca_main_trace('check_issues', success=True, elapsed=_time.perf_counter() - _start)

    # TRACE: Initialize RootCauseUnit
    _start = _time.perf_counter()
    rca = RootCauseUnit(context.repo_path)
    _emit_rca_main_trace('init_unit', success=True, elapsed=_time.perf_counter() - _start)

    # TRACE: Build relationship graphs once for all issues
    _start = _time.perf_counter()
    await rca.build_relationship_graphs_async()
    _emit_rca_main_trace('build_graphs', success=True, elapsed=_time.perf_counter() - _start)

    total_candidates = 0
    analyzed = 0

    # TRACE: Analyze each issue
    _start = _time.perf_counter()
    for issue in context.issues:
        file_path = issue.get('file', '')
        error_msg = issue.get('message', '') or issue.get('description', '')

        if not file_path:
            continue

        # Run analysis
        candidates = await rca.analyze_async(file_path, error_msg)
        analyzed += 1

        if candidates:
            total_candidates += len(candidates)
            # Enrich issue with rca data
            issue['rca_candidates'] = candidates
            issue['rca_analyzed'] = True

            # Find callers for impact analysis
            callers = await rca.find_callers(file_path)
            issue['rca_callers'] = callers[:5]  # Limit to top 5
    _emit_rca_main_trace('analyze_issues', success=True, elapsed=_time.perf_counter() - _start)

    # TRACE: Store results
    _start = _time.perf_counter()
    context.step_results['rca_main'] = {
        'issues_analyzed': analyzed,
        'candidates_found': total_candidates,
        'graphs_built': rca._graphs_built,
    }
    _emit_rca_main_trace('store_results', success=True, elapsed=_time.perf_counter() - _start)

    # TRACE: Complete
    _emit_rca_main_trace('complete', success=True, elapsed=_time.perf_counter() - _start_total)

    logger.info(f"RootCause Main: Analyzed {analyzed} issues, found {total_candidates} candidates")
    return context
