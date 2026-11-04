"""
Import Tracer - The Detective
Identifies 'upstream' dependencies for a failing file.

If 'streams.py' fails, this tracer says:
"You should also check 'status.py' because streams imports from it."

This solves the "Symptom Trap" where the agent keeps fixing the wrong file
because the actual bug is in an upstream dependency.

ENTIRE APP IS ASYNC: Using aiofiles for async file operations.
"""

import ast
import asyncio
import logging
import os
from pathlib import Path
from typing import Optional, Any, Callable, List, Set, Dict, Optional, TypeVar

import aiofiles
import aiofiles.os

_F = TypeVar('_F', bound=Callable[..., Any])

# Flow tracing integration
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False

logger = logging.getLogger(__name__)


class ImportTracer:
    """
    The Detective.
    Identifies 'upstream' dependencies for a failing file using AST analysis.

    Usage:
        tracer = ImportTracer("/path/to/repo")
        candidates = tracer.trace_imports("/path/to/repo/httpie/output/streams.py")
        # Returns: ["/path/to/repo/httpie/status.py", "/path/to/repo/httpie/output/utils.py", ...]
    """

    def __init__(self, repo_root: str):
        self.repo_root = os.path.abspath(repo_root)
        # Cache for resolved imports to avoid redundant file system lookups
        self._cache: Dict[str, List[str]] = {}
        # [FIX] File Content Cache to prevent re-parsing the same AST 10,000 times
        # This is the "Silver Bullet" - reduces 160K parses to ~50 (one per unique file)
        self._direct_import_cache: Dict[str, List[str]] = {}
        logger.debug("ImportTracer initialized for repo: %s", repo_root)

    @trace
    async def trace_imports_async(self, file_path: str, depth: Optional[int] = None) -> List[str]:  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was depth=1
        """
        Async version: Returns a list of local file paths that the given file imports.

        Args:
            file_path: Path to the file to analyze
            depth: How many levels deep to trace (1 = direct imports only,
                   2 = imports of imports, etc.)

        Returns:
            List of absolute paths to local files that are imported
        """
        file_path = os.path.abspath(file_path)
        logger.debug("trace_imports_async: %s (depth=%d)", os.path.basename(file_path), depth)

        if not os.path.exists(file_path):
            logger.debug("trace_imports_async: file not found: %s", file_path)
            return []

        # Check cache
        cache_key = f"{file_path}:{depth}"
        if cache_key in self._cache:
            logger.debug("trace_imports_async: cache hit for %s", os.path.basename(file_path))
            return self._cache[cache_key]

        all_imports: Set[str] = set()
        await self._trace_recursive(file_path, all_imports, depth, set())

        result = list(all_imports)
        self._cache[cache_key] = result
        logger.debug("trace_imports_async: found %d imports for %s", len(result), os.path.basename(file_path))
        return result
        
    async def trace_imports(self, file_path: str, depth: Optional[int] = None) -> List[str]:  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was depth=1
        """
        Returns a list of local file paths that the given file imports.
        
        ENTIRE APP IS ASYNC: Uses direct async implementation.

        Args:
            file_path: Path to the file to analyze
            depth: How many levels deep to trace (1 = direct imports only,
                   2 = imports of imports, etc.)

        Returns:
            List of absolute paths to local files that are imported
        """
        result: List[str] = await self.trace_imports_async(file_path, depth)
        return result

    async def _trace_recursive(
        self,
        file_path: str,
        results: Set[str],
        remaining_depth: Optional[int],
        visited: Set[str]
    ) -> None:
        """Recursively trace imports up to the specified depth."""
        if (remaining_depth is not None and remaining_depth <= 0) or file_path in visited:  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): the visited set is the terminator; the depth number was the cap
            return

        visited.add(file_path)
        direct_imports = await self._get_direct_imports(file_path)

        for imp in direct_imports:
            if imp not in results and imp != file_path:
                results.add(imp)
                # Recurse into the imported file
                await self._trace_recursive(imp, results, None if remaining_depth is None else remaining_depth - 1, visited)

    async def _get_direct_imports(self, file_path: str) -> List[str]:
        """Get immediate imports from a single file (Cached)."""
        # [FIX] Check cache first - prevents re-parsing the same file 200 times
        if file_path in self._direct_import_cache:
            return self._direct_import_cache[file_path]

        try:
            # ENTIRE APP IS ASYNC: Using async I/O with proper await
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                source = await f.read()
            tree = ast.parse(source)
        except Exception as e:
            logger.debug("_get_direct_imports: parse failed for %s: %s", os.path.basename(file_path), e)
            # Silently cache empty result for unparseable files
            self._direct_import_cache[file_path] = []
            return []

        imported_files: Set[str] = set()
        base_dir = os.path.dirname(file_path)

        # Determine the package context for relative imports
        package_parts = self._get_package_parts(file_path)

        for node in ast.walk(tree):
            # Handle: import my_lib
            if isinstance(node, ast.Import):
                for alias in node.names:
                    await self._resolve_import(alias.name, base_dir, package_parts, imported_files)

            # Handle: from my_lib import something
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    # from httpie.status import ExitStatus
                    await self._resolve_import(node.module, base_dir, package_parts, imported_files, node.level)
                    # FIX_14 (found on run 100 launch A): `from pkg import environment` names a
                    # SUBMODULE in the alias list — resolve `pkg.environment` too; a name that is
                    # not a module resolves to nothing and adds nothing.
                    for alias in node.names:
                        if alias.name != "*":
                            await self._resolve_import(f"{node.module}.{alias.name}", base_dir, package_parts,
                                                       imported_files, node.level)
                elif node.level > 0:
                    # from . import utils, helpers (relative import with no module name)
                    # Resolve each imported name as a module in the target package
                    for alias in node.names:
                        await self._resolve_relative_import(node.level, alias.name, base_dir, package_parts, imported_files)

        result = list(imported_files)
        # [FIX] Save to cache
        self._direct_import_cache[file_path] = result
        return result

    def _get_package_parts(self, file_path: str) -> List[str]:
        """
        Determine the package context of a file.
        E.g., /repo/httpie/output/streams.py -> ["httpie", "output"]
        """
        rel_path = os.path.relpath(file_path, self.repo_root)
        parts = Path(rel_path).parts[:-1]  # Exclude the filename
        return list(parts)

    async def _resolve_import(
        self,
        module_name: str,
        base_dir: str,
        package_parts: List[str],
        results: Set[str],
        level: int = 0
    ) -> None:
        """
        Converts 'httpie.status' -> '/path/to/httpie/status.py'

        Handles:
        - Absolute imports: import httpie.status
        - Relative imports: from .status import X (level=1)
        - Parent relative: from ..core import X (level=2)
        """
        if level > 0:
            # Relative import
            await self._resolve_relative_import(level, module_name, base_dir, package_parts, results)
            return

        # Absolute import
        parts = module_name.split('.')

        # Strategy 1: Check relative to repo root (most common for project imports)
        # httpie.status -> repo/httpie/status.py
        candidate = os.path.join(self.repo_root, *parts) + ".py"
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)
            return

        # Strategy 2: Package directory (httpie -> httpie/__init__.py)
        candidate = os.path.join(self.repo_root, *parts, "__init__.py")
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)
            return

        # Strategy 3: Check in src/ subdirectory (common Python project layout)
        # flask -> repo/src/flask/__init__.py
        candidate = os.path.join(self.repo_root, "src", *parts) + ".py"
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)
            return

        candidate = os.path.join(self.repo_root, "src", *parts, "__init__.py")
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)
            return

        # Strategy 4: Check relative to current file's directory
        # (for local imports like 'from utils import X' in same package)
        candidate = os.path.join(base_dir, *parts) + ".py"
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)
            return

    async def _resolve_relative_import(
        self,
        level: int,
        module_name: Optional[str],
        base_dir: str,
        package_parts: List[str],
        results: Set[str]
    ) -> None:
        """
        Resolve relative imports like:
        - from . import utils (level=1, module_name=None, imports utils.py)
        - from .status import X (level=1, module_name='status')
        - from ..core import X (level=2, module_name='core')
        - from ...status import X (level=3, module_name='status')

        [FIX] Corrected the calculation for multi-level relative imports.
        level=1 means same directory, level=2 means parent, level=3 means grandparent, etc.
        """
        # [FIX] level=1 stays in current package, level=2 goes up one, etc.
        # So we remove (level - 1) parts from the package path
        levels_up = level - 1

        if levels_up > len(package_parts):
            return  # Can't go higher than repo root

        # Calculate the target directory by going up 'levels_up' directories
        if levels_up == 0:
            # Same directory (from . import X)
            target_parts = package_parts
        else:
            # Go up the directory tree
            target_parts = package_parts[:-levels_up] if levels_up > 0 else package_parts

        target_dir = os.path.join(self.repo_root, *target_parts) if target_parts else self.repo_root

        if not module_name:
            return

        # from .status import X -> look for status.py
        module_parts = module_name.split('.')
        candidate = os.path.join(target_dir, *module_parts) + ".py"
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)
            return

        # Check for package (status/__init__.py)
        candidate = os.path.join(target_dir, *module_parts, "__init__.py")
        if await aiofiles.os.path.exists(candidate):
            results.add(candidate)

    def get_candidate_files(
        self,
        failing_file: str,
        error_message: str = "",
        depth: Optional[int] = None  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was 2
    ) -> Dict[str, str]:
        """
        High-level API: Get "candidate" files that might contain the root cause.

        Returns a dict mapping file paths to suspicion reasons.

        Args:
            failing_file: The file where the error manifested
            error_message: The error message (for keyword analysis)
            depth: Import trace depth

        Returns:
            Dict like {"/path/to/status.py": "Imported by streams.py"}
        """
        candidates: Dict[str, str] = {}

        # Get direct and transitive imports (sync wrapper for async method)
        try:
            loop = asyncio.get_running_loop()
            # Already in async context - create a task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                imports = pool.submit(
                    asyncio.run,
                    self.trace_imports(failing_file, depth=depth)
                ).result()
        except RuntimeError:
            # No running loop - safe to use asyncio.run
            imports = asyncio.run(self.trace_imports(failing_file, depth=depth))

        for imp in imports:
            reason = f"Imported by {os.path.basename(failing_file)}"

            # Boost suspicion for certain file patterns
            basename = os.path.basename(imp).lower()
            if any(keyword in basename for keyword in ['status', 'const', 'config', 'setting', 'enum']):
                reason += " (constants/config file - high suspicion)"

            # Check if error message mentions this file
            if error_message:
                imp_stem = Path(imp).stem
                if imp_stem.lower() in error_message.lower():
                    reason += " (mentioned in error)"

            candidates[imp] = reason

        return candidates

    @trace
    async def get_candidate_files_async(
        self,
        failing_file: str,
        error_message: str = "",
        depth: Optional[int] = None  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was 2
    ) -> Dict[str, str]:
        """
        Async version of get_candidate_files.

        Returns a dict mapping file paths to suspicion reasons.
        """
        logger.debug("get_candidate_files_async: analyzing %s (depth=%d)", os.path.basename(failing_file), depth)
        candidates: Dict[str, str] = {}
        imports = await self.trace_imports(failing_file, depth=depth)

        for imp in imports:
            reason = f"Imported by {os.path.basename(failing_file)}"

            basename = os.path.basename(imp).lower()
            if any(keyword in basename for keyword in ['status', 'const', 'config', 'setting', 'enum']):
                reason += " (constants/config file - high suspicion)"

            if error_message:
                imp_stem = Path(imp).stem
                if imp_stem.lower() in error_message.lower():
                    reason += " (mentioned in error)"

            candidates[imp] = reason

        logger.debug("get_candidate_files_async: identified %d candidates for %s", len(candidates), os.path.basename(failing_file))
        return candidates

    def clear_cache(self) -> None:
        """Clear both import resolution caches."""
        self._cache.clear()
        self._direct_import_cache.clear()


# Quick test
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python import_tracer.py <repo_root> <file_to_analyze>")
        sys.exit(1)

    repo = sys.argv[1]
    target = sys.argv[2]

    tracer = ImportTracer(repo)

    print(f"\n🔍 Tracing imports for: {target}")
    print(f"   Repo root: {repo}\n")

    imports = asyncio.run(tracer.trace_imports(target, depth=2))

    if imports:
        print("📦 Imported local files:")
        for imp in sorted(imports):
            rel = os.path.relpath(imp, repo)
            print(f"   - {rel}")
    else:
        print("   No local imports found (only stdlib/third-party)")

    print("\n🔎 Candidate Analysis:")
    candidates = asyncio.run(tracer.get_candidate_files_async(target, depth=2))
    for path, reason in candidates.items():
        rel = os.path.relpath(path, repo)
        print(f"   [{rel}] {reason}")
