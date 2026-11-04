"""
Context Manager for GRANULARIZE

Intelligently gathers related code context for complex repairs.
Provides multi-file awareness so the LLM isn't coding blind.

Phase 5 Addition: "The Librarian" - Cheat Sheet Injection
Scans docs/ or reference/ directories for relevant documentation
based on keywords in the task context.

ENTIRE APP IS ASYNC: All I/O operations are fully async.

UPGRADES APPLIED:
- #1: WhitelistRecipientRegistry Registration
- #2: Whitelist-Aware Context Selection
- #9: File Read Semaphore (prevents file descriptor exhaustion)
- #10: Centralized exclude patterns
"""

from __future__ import annotations

import ast
import asyncio
import logging
import re
import time as _time
from pathlib import Path
from typing import Any, Callable, List, Dict, Set, Optional, Tuple, TYPE_CHECKING, TypeVar

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

from rca_main.analyzers.ast_cache import ast_cache

# ENTIRE APP IS ASYNC: aiofiles is a HARD REQUIREMENT
import aiofiles
import aiofiles.os

# Centralized constants — FIX_14 (2026-09-10): the ONE walk (live_py_files) replaces should_exclude_path
from rca_main.constants import live_py_files, _scan_scope, MAX_CONCURRENT_FILE_READS

logger = logging.getLogger(__name__)

# UPGRADE #9: Semaphore to limit concurrent file reads (prevents fd exhaustion)
_file_read_semaphore: Optional[asyncio.Semaphore] = None
_semaphore_lock = asyncio.Lock()


async def _get_file_read_semaphore() -> asyncio.Semaphore:
    """Get or create the file read semaphore (lazy init for event loop safety)."""
    global _file_read_semaphore
    if _file_read_semaphore is None:
        async with _semaphore_lock:
            # Double-check after acquiring lock
            if _file_read_semaphore is None:
                _file_read_semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILE_READS)
    return _file_read_semaphore


class ContextManager:
    """
    Gathers relevant context from related files to support complex fixes.

    FIX_33 (2026-09-10): the manager returns STRUCTURED DATA, not prose — `related_files_async`
    yields (path, reason) with reason ∈ {config_sibling, import, test}; `get_context_for_job` is
    a renderer over that list. K5: one extractor over every intent-bearing element, each fact
    labelled by its source; CORROBORATION — related files are evidence for the Ranker, not a
    score. The scope is the daemon's whitelist-filtered list handed in as files= (FIX_14): a
    related file outside it is never offered. The old WhitelistRecipientRegistry hook is archived.

    Strategies:
    1. Always include config/settings files (same dir, then repo root)
    2. For stubs, include imported modules
    3. Include the matching test file
    """

    def __init__(self, repo_path: str, files=None):
        self.repo_path = Path(repo_path)
        # FIX_14 / FIX_33: the caller's whitelist-filtered list; None = the ONE walk when a scope
        # question is asked (never a private rglob).
        self._files = frozenset(Path(f).resolve() for f in files) if files is not None else None

        # Common config file names to always consider
        self.config_names = [
            "config.py", "settings.py", "constants.py",
            "conf.py", "configuration.py"
        ]

        # Max lines to include per context file (to save tokens)
        self.max_lines_per_file = None  # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): was 150 — context is not truncated unless configured

        # C1 (Q-H3b-6, 2026-10-01): one walk per file. `_extract_imports` walked the WHOLE tree of
        # the failing file on every call, and RCA calls it once per failure site — 6,000 failing defs
        # in one generated file re-walked that file's ~100,000 nodes 6,000 times. The answer depends
        # on the file's bytes only, so it is keyed by (path, mtime_ns) and the walk happens once per
        # version of the file; `related_files_async` is keyed the same way (plus the job type) —
        # its other inputs are the sibling / test files beside it, fixed for the life of this manager
        # (one scan, FIX_33 §4.2).
        self._imports_memo: Dict[Tuple[str, int], List[str]] = {}
        self._related_memo: Dict[Tuple[str, int, str], List[Tuple[Path, str]]] = {}

    # =========================================================================
    # Whitelist registry + set_whitelist / is_whitelisted ARCHIVED 2026-09-10 (FIX_33 §4.4): the
    # daemon's whitelist-filtered list arrives as files= (FIX_14); nothing registers anywhere.
    # .archive/archived_20260910/rca_main/context_gathering_manager_shims.py.txt
    # =========================================================================

    def _in_scope(self, path: Path) -> bool:
        """A related file counts only inside the scope this manager was given (files=); with no
        list the scope is the ONE walk — contained (FIX_15) and not whitelisted."""
        try:
            resolved = Path(path).resolve()
        except OSError:
            return False
        if self._files is not None:
            return resolved in self._files
        ss = _scan_scope()
        return ss.contained(Path(path), self.repo_path) and not ss.excluded(Path(path))

    # =========================================================================
    # RELATED FILES — structured (FIX_33 §4.1); the prose block renders over this
    # =========================================================================

    async def related_files_async(self, file_path: str, job_type: str = "") -> List[Tuple[Path, str]]:
        """Every file related to *file_path* with the reason it is related:
        ("config_sibling") a config/settings/constants module beside it or at the repo root;
        ("import") a module the file imports — only for stub jobs, as before, or when job_type is
        "" (RCA asks without a job type: every resolvable import is a related file);
        ("test") its matching test file. Each once, in that order; nothing outside the scope."""
        target_file = Path(file_path) if Path(file_path).is_absolute() else self.repo_path / file_path
        if not await aiofiles.os.path.exists(target_file):
            logger.debug("related_files_async: target does not exist: %s", target_file)
            return []
        memo_key = self._file_version_key(target_file) + (job_type,)
        cached = self._related_memo.get(memo_key)
        if cached is not None:
            return list(cached)
        related: List[Tuple[Path, str]] = []
        seen: Set[Path] = {target_file}

        def _offer(p: Path, why: str) -> None:
            if p in seen:
                return
            seen.add(p)
            if self._in_scope(p):
                related.append((p, why))

        # 1. config siblings — same directory, then the repo root
        for cfg in self.config_names:
            for cfg_path in (target_file.parent / cfg, self.repo_path / cfg):
                if await aiofiles.os.path.exists(cfg_path):
                    _offer(cfg_path, "config_sibling")

        # 2. imports — for stub jobs (the old strategy 2), or for RCA (no job type)
        if job_type in ("", "implement_stub", "stub_implementation"):
            for imp in await self._extract_imports(target_file):
                imp_path = await self._resolve_import(imp, target_file)
                if imp_path and await aiofiles.os.path.exists(imp_path):
                    _offer(imp_path, "import")

        # 3. the matching test file
        for pattern in (f"test_{target_file.stem}.py", f"{target_file.stem}_test.py",
                        f"tests/test_{target_file.stem}.py"):
            for test_path in (self.repo_path / pattern, target_file.parent / pattern):
                if await aiofiles.os.path.exists(test_path):
                    _offer(test_path, "test")

        logger.debug("related_files_async: %s → %d related", target_file.name, len(related))
        self._related_memo[memo_key] = list(related)
        return related

    @staticmethod
    def _file_version_key(path: Path) -> Tuple[str, int]:
        """(path, mtime_ns): the version of the file a memoised answer was computed for.
        A file the stat cannot see keys as (path, -1) — the one answer for "not there"."""
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            return (str(path), -1)
        return (str(path), mtime_ns)

    # =========================================================================
    # ASYNC CONTEXT GATHERING (UPGRADE #9: with semaphore) — a renderer over related_files_async
    # =========================================================================

    async def get_context_for_job(
        self,
        file_path: str,
        job_type: str,
        job_description: str = ""
    ) -> str:
        """
        Builds a context string containing relevant definitions from other files —
        the text form of related_files_async (FIX_33: the list is the data, this is its rendering).

        UPGRADE #9: Uses semaphore to limit concurrent file reads.

        Args:
            file_path: Path to the file being fixed (relative to repo)
            job_type: Type of job (implement_stub, wire_unused_config, etc.)
            job_description: Description of the issue for additional hints

        Returns:
            Formatted context string for injection into LLM prompt
        """
        logger.debug("get_context_for_job: file=%s job_type=%s", file_path, job_type)
        related = await self.related_files_async(file_path, job_type or "general_fix")
        if not related:
            logger.debug("get_context_for_job: no context found for %s", file_path)
            return ""

        labels = {"config_sibling": "RELEVANT FILE", "import": "IMPORTED", "test": "TEST FILE"}
        context_parts = []
        sem = await _get_file_read_semaphore()
        for path, why in related:
            async with sem:
                content = await self._read_file_smart(path)
            if content:
                context_parts.append(f"--- {labels.get(why, why.upper())}: {path.name} ---\n{content}\n")

        if not context_parts:
            return ""
        logger.debug("get_context_for_job: done — %d context parts", len(context_parts))
        return "\n".join([
            "=== RELATED CODE CONTEXT ===",
            "The following files may be relevant to the fix:",
            "",
            *context_parts,
            "=== END CONTEXT ==="
        ])

    # =========================================================================
    # FILE READING UTILITIES
    # =========================================================================

    async def _read_file_smart(self, file_path: Path) -> str:
        """
        Read file content, truncating if too long.

        Args:
            file_path: Path to file

        Returns:
            File content (possibly truncated)
        """
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = await f.read()

            lines = content.splitlines()

            if self.max_lines_per_file is not None and len(lines) > self.max_lines_per_file:
                truncated = lines[:self.max_lines_per_file]
                truncated.append(f"\n... [TRUNCATED: {len(lines) - self.max_lines_per_file} more lines]")
                return '\n'.join(truncated)

            return content
        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")
            return ""

    async def _extract_imports(self, file_path: Path) -> List[str]:
        """
        Extract import statements from a Python file.

        Args:
            file_path: Path to Python file

        Returns:
            List of imported module names
        """
        memo_key = self._file_version_key(file_path)
        cached = self._imports_memo.get(memo_key)
        if cached is not None:
            return list(cached)
        imports = []
        try:
            tree = await ast_cache.get_async(str(file_path))
            if tree is None:
                async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = await f.read()
                tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
        except Exception as e:
            logger.debug(f"Could not parse imports from {file_path}: {e}")

        self._imports_memo[memo_key] = list(imports)
        return imports

    async def _resolve_import(self, module_name: str, source_file: Path) -> Optional[Path]:
        """
        Resolve an import name to a file path.

        Args:
            module_name: Module name (e.g., "config" or "utils.helpers")
            source_file: The file containing the import

        Returns:
            Path to the module file, or None if not found
        """
        logger.debug("_resolve_import: %s from %s", module_name, source_file.name)
        # Convert module.submodule to path
        parts = module_name.split('.')

        # Try relative to source file's directory
        rel_path = source_file.parent / '/'.join(parts)
        if await aiofiles.os.path.exists(rel_path.with_suffix('.py')):
            return rel_path.with_suffix('.py')
        if await aiofiles.os.path.exists(rel_path / '__init__.py'):
            return rel_path / '__init__.py'

        # Try relative to repo root
        root_path = self.repo_path / '/'.join(parts)
        if await aiofiles.os.path.exists(root_path.with_suffix('.py')):
            return root_path.with_suffix('.py')
        if await aiofiles.os.path.exists(root_path / '__init__.py'):
            return root_path / '__init__.py'

        return None

    # =========================================================================
    # LIBRARIAN: Documentation Search
    # =========================================================================

    def extract_keywords_from_context(self, description: str, file_path: str) -> List[str]:
        """
        Extract keywords from job description and file path.

        Args:
            description: Job description
            file_path: File being fixed

        Returns:
            List of keywords for documentation search
        """
        logger.debug("extract_keywords_from_context: file=%s desc_len=%d", file_path, len(description))
        keywords = []

        # Extract from file path
        if file_path:
            stem = Path(file_path).stem
            keywords.extend(re.findall(r'[a-z]+', stem.lower()))

        # Extract from description
        if description:
            # Get significant words (exclude common words)
            common = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
                     'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                     'would', 'could', 'should', 'may', 'might', 'must', 'shall',
                     'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from',
                     'this', 'that', 'these', 'those', 'it', 'its', 'not', 'and', 'or'}
            words = re.findall(r'[a-z]+', description.lower())
            keywords.extend(w for w in words if w not in common and len(w) > 2)

        return list(set(keywords))[:10]

    async def find_relevant_docs_async(self, keywords: List[str]) -> str:
        """
        Search docs/ and reference/ directories for relevant documentation.

        Args:
            keywords: Keywords to search for

        Returns:
            Concatenated relevant documentation
        """
        logger.debug("find_relevant_docs_async: %d keywords", len(keywords))
        doc_dirs = ['docs', 'reference', 'doc', 'documentation']
        doc_files: List[Path] = []

        # FIX_15 (2026-09-10): a contained walk — never through a symlink, never outside the target
        _ss = _scan_scope()
        for doc_dir in doc_dirs:
            doc_path = self.repo_path / doc_dir
            if doc_path.exists() and _ss.contained(doc_path, self.repo_path):
                for ext in ['*.md', '*.txt', '*.rst']:
                    doc_files.extend(_ss.iter_contained(doc_path, ext))

        if not doc_files:
            return ""

        relevant_docs = []
        sem = await _get_file_read_semaphore()

        for doc_file in doc_files:  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): `[:20]` trim removed
            try:
                async with sem:
                    async with aiofiles.open(doc_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = await f.read()

                content_lower = content.lower()
                matches = sum(1 for kw in keywords if kw in content_lower)

                if matches >= 2:  # At least 2 keyword matches
                    relevant_docs.append((doc_file.name, content[:2000], matches))
            except Exception:
                continue

        if not relevant_docs:
            return ""

        # Sort by match count
        relevant_docs.sort(key=lambda x: x[2], reverse=True)

        result_parts = ["=== RELEVANT DOCUMENTATION ==="]
        for name, content, _ in relevant_docs:  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): `[:3]` trim removed
            result_parts.append(f"\n--- {name} ---\n{content}")
        result_parts.append("\n=== END DOCUMENTATION ===")

        return '\n'.join(result_parts)


    async def doc_facts_async(self, keywords: List[str]) -> List[Dict[str, str]]:
        """FIX_33 step 3 (Item 8, 2026-09-15): the docs as DISCRETE facts for the intent file — one
        `{fact: "doc_mention", value: <keyword>, source: "doc_mention", evidence: "<rel>:<line> <excerpt>"}` per (keyword,
        doc file), the first line that mentions the keyword as the evidence. Same doc dirs and the same contained
        walk as `find_relevant_docs_async`; nothing ranked, nothing trimmed. The Builder cycle appends these once
        per target (`intent_file.append_facts` dedupes). I-22 (run 117, 2026-09-15): the source label is `doc_mention`,
        NOT `docs` — `docs` is Item 3's intent-source SPECIES (the docs directory's own facts), which the whitelist
        stage REPLACES on every launch; under the shared label these facts were wiped each launch instead of kept."""
        doc_dirs = ['docs', 'reference', 'doc', 'documentation']
        _ss = _scan_scope()
        doc_files: List[Path] = []
        for doc_dir in doc_dirs:
            doc_path = self.repo_path / doc_dir
            if doc_path.exists() and _ss.contained(doc_path, self.repo_path):
                for ext in ['*.md', '*.txt', '*.rst']:
                    doc_files.extend(_ss.iter_contained(doc_path, ext))
        kws = [k.lower() for k in keywords if k and len(k) > 2]
        if not doc_files or not kws:
            return []
        facts: List[Dict[str, str]] = []
        sem = await _get_file_read_semaphore()
        for doc_file in sorted(doc_files):
            try:
                async with sem:
                    async with aiofiles.open(doc_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = await f.read()
            except Exception:
                continue
            try:
                rel = doc_file.relative_to(self.repo_path).as_posix()
            except ValueError:
                rel = doc_file.name
            lines = content.splitlines()
            for kw in kws:
                pat = re.compile(r"(?<![a-z0-9_])" + re.escape(kw) + r"(?![a-z0-9_])")   # a WORD, never a substring
                for i, line in enumerate(lines, 1):
                    if pat.search(line.lower()):
                        facts.append({"fact": "doc_mention", "value": kw, "source": "doc_mention",
                                      "evidence": f"{rel}:{i} {line.strip()[:120]}"})
                        break
        return facts


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

async def get_file_summary(repo_path: str, files=None) -> Dict[str, List[str]]:
    """
    Get a summary of the repository structure.

    Returns:
        Dict mapping directories to list of Python files
    """
    logger.debug("get_file_summary: %s", repo_path)
    repo = Path(repo_path)

    # FIX_14: the handed-over list, else the ONE walk (sync metadata, in a thread)
    py_files = await asyncio.to_thread(live_py_files, repo, files)

    summary: Dict[str, List[str]] = {}
    for py_file in py_files:
        rel_dir = str(py_file.parent.relative_to(repo))
        if rel_dir not in summary:
            summary[rel_dir] = []
        summary[rel_dir].append(py_file.name)

    logger.debug("get_file_summary: done — %d directories", len(summary))
    return summary


# =============================================================================
# gather_context_handler (executor.WorkflowContext shim, no caller) ARCHIVED 2026-09-10 (FIX_33 §4.4):
# .archive/archived_20260910/rca_main/context_gathering_manager_shims.py.txt
# =============================================================================
# build_cheatsheets_handler ARCHIVED 2026-09-08 (item 2 / FIX 11; FIX 33 §4.4): a dead workflow shim with no caller —
# .archive/archived_20260908/rca_main/context_gathering_manager_build_cheatsheets_handler.py.txt
