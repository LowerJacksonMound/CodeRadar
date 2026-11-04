"""Core DetritusCleaner class for orchestrating analysis and cleaning."""

from __future__ import annotations

import logging
import ast
import asyncio
import os
import time
from collections import deque
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple, Union

from detritus_cleaner.models import (
    DetritusConfig,
    CleanseResult,
    ProgressCallback,
)
from detritus_cleaner.holding import HoldingManager
from detritus_cleaner.graph import ImportGraphBuilder
from detritus_cleaner.utils import logger, tomli, TRACING_ENABLED, set_workflow, emit_trace

# R8 / T-10 (2026-09-30): CodeRadar's OWN output dir at the target root (the state mirrors, never
# source). Skipped at THAT spot only, the same rule as system_scripts/scan_scope.MIRROR_DIR — a
# deeper `.coderadar` is the target's own and is walked.
_CR_MIRROR_DIR = ".coderadar"


__all__ = ['DetritusCleaner']


def _load_species_filters() -> dict:
    """Owner 2026-09-05: the species dictionary is the ONE place artifact/detritus
    species live; the filters read it. Stricken-name species are taken from the
    dict's own wild-only list at runtime and are never spelled here."""
    import json
    try:
        d = json.loads((Path(__file__).resolve().parents[1] / "SPECIES_DICT.json").read_text(encoding="utf-8"))
    except Exception as e:  # pragma: no cover
        logger.warning(f"SPECIES_DICT.json unreadable ({e}); filters run on built-in extensions only")
        return {}
    f = dict(d.get("filters", {}))
    wild = (d.get("detritus", {}).get("tool_caches", {}) or {}).get("stricken_name_wild_only", []) or []
    f["_stricken_dirs"] = [w.rstrip("/") for w in wild if w.endswith("/")]
    return f


class DetritusCleaner:
    """
    Main orchestrator for detritus detection and cleaning.
    Integrates graph analysis, holding management, and validation.
    """

    DEFAULT_ENTRY_POINTS = {
        "main.py", "app.py", "manage.py", "setup.py", "run.py",
        "cli.py", "wsgi.py", "asgi.py", "__main__.py"
    }

    # Owner 2026-09-05: the whitelist is artifacts + detritus and nothing else.
    # The only implicit keep is the package marker; nothing is kept by name.
    IMPLICIT_KEEP_PATTERNS = {
        "__init__.py",
    }

    # Non-Python file extensions to scan as potential detritus artifacts.
    # These cannot participate in the Python import graph, so any that are
    # not explicitly referenced by live code are classified as detritus.
    ARTIFACT_EXTENSIONS = {
        ".sh", ".bash", ".zsh",           # shell scripts
        ".js", ".mjs", ".cjs", ".ts",     # javascript / typescript
        ".txt", ".log", ".md", ".rst",    # text / docs
        ".csv", ".tsv",                   # tabular data
        ".json", ".yaml", ".yml",         # config / data
        ".xml", ".toml", ".cfg",          # config
        ".ini", ".conf", ".env",          # config
        ".sql",                           # database
        ".html", ".htm", ".css",          # web
    }

    def __init__(
        self,
        config_or_repo_path: DetritusConfig | str | Path,
        entry_points: Optional[List[str]] = None,
        dry_run: bool = False
    ):
        """
        Initialize DetritusCleaner.

        Args:
            config_or_repo_path: Either a DetritusConfig or a path to the repository
            entry_points: Optional list of additional entry points (backward compat)
            dry_run: If True, don't actually move files (backward compat)
        """
        # Handle backward-compatible initialization
        if isinstance(config_or_repo_path, DetritusConfig):
            self.config = config_or_repo_path
        else:
            # Legacy initialization: repo_path string/Path
            repo_path = Path(config_or_repo_path).resolve()
            additional_eps = set(entry_points) if entry_points else set()
            self.config = DetritusConfig(
                repo_path=repo_path,
                dry_run=dry_run,
                additional_entry_points=additional_eps
            )

        self.repo_path = self.config.repo_path.resolve()

        # Legacy attribute for backward compatibility
        self.dry_run = self.config.dry_run
        self.unused_dir = self.repo_path / self.config.holding_dir_name

        # Initialize components
        self.holding_mgr = HoldingManager(
            self.repo_path,
            self.config.holding_dir_name,
            self.config.verify_checksums
        )
        self.graph_builder = ImportGraphBuilder(self.repo_path)

        # Configure entry points
        self.entry_points = self.DEFAULT_ENTRY_POINTS.copy()
        self.entry_points.update(self.config.additional_entry_points)

        # Legacy attribute (populated by graph_builder internally)
        self.module_to_file: Dict[str, str] = {}

        # Species filters (owner 2026-09-05) — read from SPECIES_DICT.json, one place to look
        self.species = _load_species_filters()
        self.artifact_extensions: Set[str] = set(self.ARTIFACT_EXTENSIONS) | set(self.species.get("artifact_extensions", [])) | {".pyi"}
        self.artifact_filenames: Set[str] = set(self.species.get("artifact_filenames", []))
        self.artifact_globs: List[str] = list(self.species.get("artifact_globs", []))
        self.artifact_dirs: Set[str] = set(self.species.get("artifact_dirs", [])) | set(self.species.get("_stricken_dirs", []))
        self.artifact_dir_paths: List[Path] = [Path(p) for p in self.species.get("artifact_dir_paths", [])]
        self.venv_shape: dict = dict(self.species.get("venv_shape", {}))
        self.artifact_species: Dict[str, str] = {}   # rel path -> species (disclosure)
        self.venv_dirs: Dict[str, int] = {}          # rel dir -> bytes (rule 9)
        self.composition: Dict[str, int] = {}        # python-only disclosure (py vs non-py)
        self._venv_scanned = False

        logger.debug(f"DetritusCleaner initialized: repo={self.repo_path}, "
                      f"dry_run={self.config.dry_run}, "
                      f"entry_points={len(self.entry_points)}, "
                      f"exclude_dirs={self.config.exclude_dirs}")

    # =========================================================================
    # Main Async API
    # =========================================================================

    async def scan(
        self,
        progress_callback: Optional[ProgressCallback] = None
    ) -> CleanseResult:
        """
        Analyze repository to identify live vs detritus files.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            CleanseResult with categorized files
        """
        start_time = time.time()

        logger.info(f"Scanning repository: {self.repo_path}")
        if TRACING_ENABLED:
            emit_trace('scan_start', success=True, elapsed=0,
                       layer='Scanner', module='core.py')

        # 1. Discover all Python files
        if progress_callback:
            progress_callback(0, 100, "Discovering Python files...")

        all_py_files = await self._discover_python_files()
        logger.info(f"Found {len(all_py_files)} Python files")

        if TRACING_ENABLED:
            emit_trace('scan_discover_files', success=True,
                       elapsed=time.time() - start_time,
                       layer='Scanner', module='core.py')

        if not all_py_files:
            logger.warning("No Python files found in repository")
            return CleanseResult(total_scanned=0, scan_duration_seconds=time.time() - start_time)

        # 2. Build import graph
        if progress_callback:
            progress_callback(10, 100, "Building import graph...")

        _graph_start = time.time()
        import_graph = await self.graph_builder.build_graph_async(
            all_py_files,
            self.config.max_concurrent_tasks,
            progress_callback
        )
        logger.debug(f"Import graph built: {len(import_graph)} nodes, "
                      f"{sum(len(v) for v in import_graph.values())} edges")

        if TRACING_ENABLED:
            emit_trace('scan_build_graph', success=True,
                       elapsed=time.time() - _graph_start,
                       layer='Scanner', module='core.py')

        # 3. Enrich entry points from metadata
        if progress_callback:
            progress_callback(70, 100, "Detecting entry points...")

        await self._enrich_entry_points(all_py_files)
        logger.info(f"Using {len(self.entry_points)} entry points")
        logger.debug(f"Entry points: {sorted(self.entry_points)}")

        # 4. Find reachable files via BFS
        if progress_callback:
            progress_callback(80, 100, "Computing reachability...")

        _bfs_start = time.time()
        live_files = self._find_reachable(import_graph, all_py_files)

        if TRACING_ENABLED:
            emit_trace('scan_bfs_reachability', success=True,
                       elapsed=time.time() - _bfs_start,
                       layer='Scanner', module='core.py')

        # 5. Apply whitelist logic
        if progress_callback:
            progress_callback(90, 100, "Applying whitelist rules...")

        whitelisted = self._identify_implicit_active(all_py_files)

        # 6. Determine detritus (Python files)
        kept_files = live_files | whitelisted
        detritus = all_py_files - kept_files

        # 7. Discover non-Python artifact files — auto-classified as detritus
        #    (PYTHON-ONLY: every non-.py file lands here, disclosed by species)
        artifact_files = await self._discover_artifact_files()
        self.composition = {
            "py_files": len(all_py_files) + sum(1 for a in artifact_files if a.endswith(".py")),
            "non_py_files": sum(1 for a in artifact_files if not a.endswith(".py")),
        }
        if artifact_files:
            logger.info(f"Found {len(artifact_files)} non-Python artifact files (auto-detritus)")
            detritus |= artifact_files

        logger.debug(f"Detritus breakdown: {len(live_files)} live, "
                      f"{len(whitelisted)} whitelisted, {len(detritus)} detritus")
        if detritus:
            logger.debug(f"Detritus files (first 20): {sorted(detritus)[:20]}")

        scan_duration = time.time() - start_time

        result = CleanseResult(
            live_files=live_files,
            whitelisted_files=whitelisted,
            detritus_files=detritus,
            total_scanned=len(all_py_files) + len(artifact_files),
            circular_imports=self.graph_builder.get_circular_imports(),
            scan_duration_seconds=scan_duration
        )

        logger.info(f"Scan complete in {scan_duration:.2f}s: {result.summary()}")

        if TRACING_ENABLED:
            emit_trace('scan_complete', success=True,
                       elapsed=scan_duration,
                       layer='Scanner', module='core.py')

        if progress_callback:
            progress_callback(100, 100, "Scan complete")

        return result

    async def clean_async(
        self,
        result: Optional[CleanseResult] = None,
        progress_callback: Optional[ProgressCallback] = None
    ) -> CleanseResult:
        """
        Execute the cleaning operation based on scan results.

        Args:
            result: Pre-computed scan result (will scan if None)
            progress_callback: Optional callback for progress updates

        Returns:
            Updated CleanseResult with cleaning outcomes
        """
        start_time = time.time()
        logger.debug("clean_async: starting cleaning pipeline")

        if TRACING_ENABLED:
            emit_trace('clean_async_start', success=True, elapsed=0,
                       layer='Cleaner', module='core.py')

        # Run scan if not provided
        if result is None:
            logger.debug("clean_async: no pre-computed result, running scan")
            result = await self.scan(progress_callback)

        if not result.detritus_files:
            logger.info("No detritus files to clean")
            return result

        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would holding {len(result.detritus_files)} files")
            logger.debug(f"[DRY RUN] Files: {sorted(result.detritus_files)[:20]}")
            return result

        logger.info(f"Moving to holding {len(result.detritus_files)} detritus files...")

        _held_start = time.time()
        moved, failed = await self.holding_mgr.holding_files(
            result.detritus_files,
            progress_callback
        )

        if TRACING_ENABLED:
            emit_trace('clean_async_held', success=(len(failed) == 0),
                       elapsed=time.time() - _held_start,
                       layer='Cleaner', module='core.py')

        result.moved_files = moved
        result.failed_files = failed
        result.manifest_path = str(self.holding_mgr.manifest_file)
        result.clean_duration_seconds = time.time() - start_time

        logger.info(f"Cleaning complete: {len(moved)} moved, {len(failed)} failed")
        if failed:
            logger.debug(f"Failed files: {failed}")

        if TRACING_ENABLED:
            emit_trace('clean_async_complete', success=(len(failed) == 0),
                       elapsed=result.clean_duration_seconds,
                       layer='Cleaner', module='core.py')

        return result

    async def restore_held(
        self,
        progress_callback: Optional[ProgressCallback] = None
    ) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Restore all holdingd files.

        Returns:
            Tuple of (restored files, failed files)
        """
        logger.info("Restoring holdingd files...")
        if TRACING_ENABLED:
            emit_trace('restore_start', success=True, elapsed=0,
                       layer='Cleaner', module='core.py')

        _restore_start = time.time()
        restored, failed = await self.holding_mgr.restore_files(
            progress_callback
        )

        if TRACING_ENABLED:
            emit_trace('restore_complete', success=(len(failed) == 0),
                       elapsed=time.time() - _restore_start,
                       layer='Cleaner', module='core.py')

        logger.debug(f"Restore result: {len(restored)} restored, {len(failed)} failed")
        return restored, failed

    async def _cleanse_impl(self) -> CleanseResult:
        """Async implementation of the legacy cleanse pipeline."""
        mode = "DRY RUN" if self.dry_run else "LIVE"
        logger.info(f"Starting Detritus Cleanse ({mode})...")
        _cleanse_start = time.perf_counter()

        # Set workflow context for tracing
        set_workflow('phase1_detritus_cleaner')

        if TRACING_ENABLED:
            emit_trace('detritus_cleanse_start', success=True, elapsed=0,
                       layer='Scanner', module='core.py')

        all_py_files = await self._discover_python_files()

        # Build import graph (async)
        import_graph = await self.graph_builder.build_graph_async(
            all_py_files, self.config.max_concurrent_tasks
        )

        if TRACING_ENABLED:
            emit_trace('detritus_import_graph_built', success=True,
                       elapsed=time.perf_counter() - _cleanse_start,
                       layer='Scanner', module='core.py')

        # Find reachable files
        live_files = self._find_reachable(import_graph, all_py_files)

        if TRACING_ENABLED:
            emit_trace('detritus_bfs_complete', success=True,
                       elapsed=time.perf_counter() - _cleanse_start,
                       layer='Scanner', module='core.py')

        # Load whitelist
        whitelisted_files = await self._load_whitelist()

        if TRACING_ENABLED:
            emit_trace('detritus_whitelist_loaded', success=True,
                       elapsed=time.perf_counter() - _cleanse_start,
                       layer='Scanner', module='core.py')

        # Always keep entry points
        existing_entry_points = {ep for ep in self.entry_points if ep in all_py_files}
        live_files.update(existing_entry_points)

        # Filter whitelisted to only existing .py files
        whitelisted_files = whitelisted_files & all_py_files

        # Add implicit active files
        implicit_active = self._identify_implicit_active(all_py_files)
        live_files.update(implicit_active)

        # Calculate detritus
        kept_files = live_files | whitelisted_files
        detritus = sorted([f for f in all_py_files if f not in kept_files])

        # Report results
        if whitelisted_files:
            logger.info(f"  WHITELISTED (protected): {len(whitelisted_files)} files")

        if detritus:
            logger.info(f"  DETRITUS (to be REMOVED): {len(detritus)} files")
            if not self.dry_run:
                await self.holding_mgr.holding_files(set(detritus))

        # Build result
        result = CleanseResult(
            live_files=live_files,
            whitelisted_files=whitelisted_files,
            detritus_files=set(detritus),
            total_scanned=len(all_py_files)
        )

        logger.info(f"Detritus Cleanse Complete: {len(live_files)} live, "
                    f"{len(whitelisted_files)} whitelisted, {len(detritus)} detritus")

        return result

    async def _load_whitelist(self) -> Set[str]:
        """Load whitelist files from WhitelistManager."""
        whitelisted_files: Set[str] = set()

        # Try multiple import paths for WhitelistManager
        WhitelistManager = None
        for module_path in [
            'data.whitelist',
            'orchestrator.core.data.whitelist',
        ]:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                WhitelistManager = getattr(mod, 'WhitelistManager', None)
                if WhitelistManager:
                    break
            except ImportError:
                continue

        if WhitelistManager is None:
            return whitelisted_files

        try:
            wm = WhitelistManager(str(self.repo_path))
            exists = await asyncio.to_thread(wm.exists)
            if exists:
                whitelist = await asyncio.to_thread(wm.load)
                whitelisted_files = {item.file for item in whitelist.items}
                logger.info(f"  Loaded whitelist: {len(whitelist.items)} items")
        except Exception as e:
            logger.warning(f"Failed to load whitelist: {e}")

        return whitelisted_files

    # =========================================================================
    # Core Analysis Methods
    # =========================================================================

    # ── species filters (owner 2026-09-05: filter 2 = ARTIFACTS, by species) ──
    def _find_venv_dirs(self) -> None:
        """Rule 9: a venv is recognised by SHAPE (markers) corroborated by SIZE
        (>= min_bytes), never by name. Every match is disclosed with its size."""
        if self._venv_scanned:
            return
        self._venv_scanned = True
        shape = self.venv_shape or {}
        markers = shape.get("markers_any", [])
        sp_glob = shape.get("site_packages_glob", "")
        min_bytes = int(shape.get("min_bytes", 10 * 1024 * 1024))
        found: Dict[str, int] = {}
        for d in sorted(p for p in self.repo_path.rglob("*") if p.is_dir() and not p.is_symlink()):
            rel = d.relative_to(self.repo_path).as_posix()
            if any(rel == v or rel.startswith(v + "/") for v in found):
                continue
            # B8 (MCP-working packet 2026-09-28): a dir that IS an env (`pyvenv.cfg` / `conda-meta/`)
            # or IS a site-packages dir (in `lib/python*/` or `Lib/`) is an env by SHAPE alone — a fresh
            # `uv venv` is ~64 KB and must not be scanned as source. Other markers keep the size test.
            definitive = ((d / "pyvenv.cfg").is_file() or (d / "conda-meta").is_dir()
                          or (d.name in ("site-packages", "dist-packages")
                              and (d.parent.name.startswith("python") or d.parent.name == "Lib")))
            shaped = definitive or any((d / m).exists() for m in markers) or (bool(sp_glob) and any(d.glob(sp_glob)))
            if not shaped:
                continue
            size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file() and not f.is_symlink())
            if definitive:
                found[rel] = size
                logger.info(f"[filter 2 · env by shape] {rel}/ = {size / 1e6:.1f} MB (pyvenv.cfg / conda-meta / site-packages) -> artifact")
            elif size >= min_bytes:
                found[rel] = size
                logger.info(f"[filter 2 · venv by size] {rel}/ = {size / 1e6:.1f} MB (>= {min_bytes / 1e6:.0f} MB) -> artifact")
            else:
                logger.info(f"[filter 2 · venv shape, under size] {rel}/ = {size / 1e6:.1f} MB -> scanned like any source dir")
        self.venv_dirs = found

    def _classify_artifact(self, rel: Path) -> Optional[str]:
        """Artifact species label for a repo-relative path, or None if the path is
        (potentially) live source. Order: venv > dir species > dir paths > exact
        filename > glob > extension."""
        import fnmatch
        self._find_venv_dirs()
        posix = rel.as_posix()
        for v in self.venv_dirs:
            if posix.startswith(v + "/"):
                return "venv"
        for part in rel.parts[:-1]:
            if part in self.artifact_dirs:
                return f"dir:{part}"
            for pat in self.artifact_dirs:
                if "*" in pat and fnmatch.fnmatch(part, pat):
                    return f"dir:{pat}"
        for dp in self.artifact_dir_paths:
            if posix.startswith(dp.as_posix() + "/"):
                return f"dir:{dp.as_posix()}"
        name = rel.name
        if name in self.artifact_filenames:
            return f"file:{name}"
        for g in self.artifact_globs:
            if fnmatch.fnmatch(name, g):
                return f"glob:{g}"
        sfx = rel.suffix.lower()
        if sfx and sfx in self.artifact_extensions:
            return f"ext:{sfx}"
        # Owner 2026-09-05 (evening): PYTHON-ONLY. The only live source is a .py
        # file. Anything else is an artifact BY CONSTRUCTION — disclosed as
        # 'non_python:<ext>' when no finer species above matched (and by content
        # header first: an SQLite file is SQLite whatever it is called — F13-c).
        if sfx != ".py":
            sniff = self._sniff_content(rel)
            if sniff:
                return sniff
            return f"non_python:{sfx or 'noext'}"
        return None

    def _sniff_content(self, rel: Path) -> Optional[str]:
        """Content beats name (SPECIES_DICT filters.content_sniff): return a species
        label from the file's leading bytes, or None."""
        sniff = self.species.get("content_sniff", {}) or {}
        magic = sniff.get("sqlite_data")
        if not magic:
            return None
        try:
            with open(self.repo_path / rel, "rb") as fh:
                head = fh.read(16)
        except Exception:
            return None
        if head.startswith(magic.encode("latin-1")):
            return "sqlite_data"
        return None

    async def _discover_python_files(self) -> Set[str]:
        """Discover all Python files in the repository, respecting exclusions."""
        import fnmatch

        def _discover_sync() -> Set[str]:
            py_files = set()
            _excluded_count = 0

            for py_path in self.repo_path.rglob("*.py"):
                # Skip symlinks if configured
                if py_path.is_symlink() and not self.config.follow_symlinks:
                    continue

                # Get relative path
                try:
                    rel_path = py_path.relative_to(self.repo_path)
                except ValueError:
                    continue

                rel_path_str = str(rel_path)

                # CodeRadar's own root .coderadar/ (R8 / T-10) is never source
                if rel_path.parts[:1] == (_CR_MIRROR_DIR,):
                    continue

                # Owner 2026-09-05: artifact-class files belong to filter 2, disclosed there
                if self._classify_artifact(rel_path) is not None:
                    _excluded_count += 1
                    continue

                # Skip holding directory
                if self.config.holding_dir_name in rel_path.parts:
                    _excluded_count += 1
                    continue

                py_files.add(rel_path_str)

            logger.debug(f"_discover_python_files: found {len(py_files)}, excluded {_excluded_count}")
            return py_files

        return await asyncio.to_thread(_discover_sync)

    async def _discover_artifact_files(self) -> Set[str]:
        """Discover non-Python artifact files (.sh, .js, .txt, .csv, etc.).

        These files cannot participate in the import graph and are
        automatically classified as detritus unless the repo has an
        explicit reason to keep them (which the caller can override).
        """
        import fnmatch

        def _discover_sync() -> Set[str]:
            artifact_files: Set[str] = set()
            self.artifact_species = {}
            for path in self.repo_path.rglob("*"):
                if path.is_symlink() and not self.config.follow_symlinks:
                    continue
                if not path.is_file():
                    continue
                try:
                    rel_path = path.relative_to(self.repo_path)
                except ValueError:
                    continue
                if rel_path.parts[:1] == (_CR_MIRROR_DIR,):   # R8 / T-10: CodeRadar's own root .coderadar/
                    continue
                if self.config.holding_dir_name in rel_path.parts:
                    continue
                species = self._classify_artifact(rel_path)
                if species is None:
                    continue
                rel_path_str = str(rel_path)
                self.artifact_species[rel_path_str] = species
                artifact_files.add(rel_path_str)
            from collections import Counter
            breakdown = ", ".join(f"{k} {v}" for k, v in Counter(self.artifact_species.values()).most_common())
            logger.info(f"[filter 2 · artifacts] {len(artifact_files)} files: {breakdown or 'none'}")

            logger.debug(f"_discover_artifact_files: found {len(artifact_files)} artifacts")
            return artifact_files

        return await asyncio.to_thread(_discover_sync)

    def _find_reachable(
        self,
        graph: Dict[str, Set[str]],
        all_files: Set[str]
    ) -> Set[str]:
        """
        Perform BFS from entry points to find all reachable files.

        Args:
            graph: Import dependency graph
            all_files: All Python files in repo

        Returns:
            Set of reachable file paths
        """
        reachable: Set[str] = set()
        queue: deque[str] = deque()

        # Seed with explicit entry points that exist
        for file_path in all_files:
            if file_path in self.entry_points:
                # Exact path match (user-specified full paths)
                queue.append(file_path)
                reachable.add(file_path)
                logger.debug(f"Entry point (exact): {file_path}")
            else:
                # Basename match for bare filenames (e.g. "main.py" matches "src/main.py")
                basename = os.path.basename(file_path)
                if basename in self.entry_points:
                    queue.append(file_path)
                    reachable.add(file_path)
                    logger.debug(f"Entry point (basename): {file_path}")

        # Also seed with package markers. F-DET1 (owner 2026-09-05, evening):
        # verification-suite files are NOT seeded — nothing imports them, so
        # filter 1 classes them unreachable like any other orphan module. The
        # name of a file is never a reason to call it live (rule 1: species
        # live in content, never in names).
        for file_path in all_files:
            f_name = os.path.basename(file_path).lower()
            if f_name == "__init__.py":
                if file_path not in reachable:
                    queue.append(file_path)
                    reachable.add(file_path)

        _seed_count = len(reachable)
        logger.debug(f"_find_reachable: BFS seeded with {_seed_count} files")

        # BFS traversal
        while queue:
            current = queue.popleft()
            for dependency in graph.get(current, set()):
                if dependency not in reachable:
                    reachable.add(dependency)
                    queue.append(dependency)

        logger.debug(f"_find_reachable: BFS discovered {len(reachable) - _seed_count} additional files")
        logger.info(f"Reachable from entry points: {len(reachable)} files")
        return reachable

    def _identify_implicit_active(self, all_files: Set[str]) -> Set[str]:
        """
        Identify files that should be kept even if not imported.

        Examples: __init__.py, test files, conftest.py
        """
        whitelisted = set()
        for filepath in all_files:
            # Owner 2026-09-05: nothing is kept by name except the package marker
            if Path(filepath).name in self.IMPLICIT_KEEP_PATTERNS:
                whitelisted.add(filepath)
        logger.info(f"Whitelisted (implicit active): {len(whitelisted)} files")
        return whitelisted

    async def _enrich_entry_points(self, all_files: Set[str]) -> None:
        """Detect additional entry points from pyproject.toml, shebangs, and __main__ guards."""
        _before = len(self.entry_points)

        # 1. Parse pyproject.toml for script entry points
        await self._parse_pyproject_toml(all_files)

        # 2. Check for shebang lines
        await self._detect_shebang_scripts(all_files)

        # 3. Detect files with if __name__ == "__main__" guards
        await self._detect_main_guard_scripts(all_files)

        _added = len(self.entry_points) - _before
        logger.debug(f"_enrich_entry_points: discovered {_added} additional entry points")

    async def _detect_main_guard_scripts(self, all_files: Set[str]) -> None:
        """Detect Python files with if __name__ == '__main__' blocks."""

        async def check_main_guard(filepath: str) -> Optional[str]:
            try:
                path = self.repo_path / filepath
                content = await asyncio.to_thread(
                    path.read_text, encoding="utf-8", errors="ignore"
                )
                if '__name__' in content and '__main__' in content:
                    tree = ast.parse(content, filename=str(path))
                    for node in ast.walk(tree):
                        if (isinstance(node, ast.If)
                                and isinstance(node.test, ast.Compare)
                                and len(node.test.comparators) == 1):
                            left = node.test.left
                            comp = node.test.comparators[0]
                            if (isinstance(left, ast.Name)
                                    and left.id == "__name__"
                                    and isinstance(comp, ast.Constant)
                                    and comp.value == "__main__"):
                                # F-DET1 (run 19, 2026-09-05): a guard whose only
                                # job is to hand the file to a verification
                                # runner (`unittest.main()`, `pytest.main()`,
                                # `doctest.testmod()`) is the harness's hook,
                                # not an application entry point. Judged by
                                # CONTENT of the guard body, never by file name.
                                calls = [c for c in ast.walk(ast.Module(body=node.body, type_ignores=[]))
                                         if isinstance(c, ast.Call)]
                                def _cname(c):
                                    f = c.func
                                    return (f.attr if isinstance(f, ast.Attribute)
                                            else f.id if isinstance(f, ast.Name) else '')
                                harness = {'main', 'testmod', 'run_module', 'run'}
                                mods = {'unittest', 'pytest', 'doctest', 'nose', 'nose2'}
                                def _is_harness(c):
                                    f = c.func
                                    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                                        return f.value.id in mods and f.attr in harness
                                    return False
                                if calls and all(_is_harness(c) for c in calls):
                                    return None
                                return filepath
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'check_main_guard', _e)
                pass
            return None

        tasks = [check_main_guard(f) for f in all_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, BaseException):
                continue
            if result:
                self.entry_points.add(result)
                logger.debug(f"Found __main__ guard script: {result}")

    async def _parse_pyproject_toml(self, all_files: Set[str]) -> None:
        """Parse pyproject.toml for console_scripts entry points."""
        toml_path = self.repo_path / "pyproject.toml"
        if not toml_path.exists():
            return

        if tomli is None:
            logger.debug("tomli not available, using regex fallback for pyproject.toml")
            await self._parse_pyproject_regex(toml_path, all_files)
            return

        import re
        try:
            content = await asyncio.to_thread(toml_path.read_bytes)
            data = await asyncio.to_thread(tomli.loads, content.decode('utf-8'))

            # Check for poetry scripts
            scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})
            for script_def in scripts.values():
                if isinstance(script_def, str) and ":" in script_def:
                    module_path = script_def.split(":")[0]
                    file_path = module_path.replace(".", os.sep) + ".py"
                    if file_path in all_files:
                        self.entry_points.add(file_path)
                        logger.debug(f"Found poetry entry point: {file_path}")

            # Check for setuptools console_scripts
            entry_points = data.get("project", {}).get("scripts", {})
            for script_def in entry_points.values():
                if isinstance(script_def, str) and ":" in script_def:
                    module_path = script_def.split(":")[0]
                    file_path = module_path.replace(".", os.sep) + ".py"
                    if file_path in all_files:
                        self.entry_points.add(file_path)
                        logger.debug(f"Found setuptools entry point: {file_path}")

        except (KeyError, ValueError, TypeError, UnicodeDecodeError, OSError) as e:
            logger.debug(f"Failed to parse pyproject.toml: {e}")

    async def _parse_pyproject_regex(self, toml_path: Path, all_files: Set[str]) -> None:
        """Fallback regex-based parsing of pyproject.toml."""
        import re
        try:
            content = await asyncio.to_thread(toml_path.read_text)
            # Match patterns like: script-name = "module.path:function"
            matches = re.findall(r'[\w-]+\s*=\s*"([\w.]+):', content)
            for module_path in matches:
                file_path = module_path.replace(".", os.sep) + ".py"
                if file_path in all_files:
                    self.entry_points.add(file_path)
                    logger.debug(f"Found entry point (regex): {file_path}")
        except (OSError, re.error) as e:
            logger.debug(f"Regex parsing of pyproject.toml failed: {e}")

    async def _detect_shebang_scripts(self, all_files: Set[str]) -> None:
        """Detect executable Python scripts with shebang lines."""

        # Only check files in bin/, scripts/, or root
        candidates = {
            f for f in all_files
            if "/" not in f or f.startswith(("bin/", "scripts/"))
        }

        async def check_shebang(filepath: str) -> Optional[str]:
            try:
                path = self.repo_path / filepath
                content = await asyncio.to_thread(path.read_text, encoding='utf-8', errors='ignore')
                first_line = content.split('\n', 1)[0]
                if first_line.startswith("#!") and "python" in first_line.lower():
                    return filepath
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'check_shebang', _e)
                pass
            return None

        tasks = [check_shebang(f) for f in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, BaseException):
                logger.debug(f"Shebang check failed: {result}")
                continue
            if result:
                self.entry_points.add(result)
                logger.debug(f"Found shebang script: {result}")
