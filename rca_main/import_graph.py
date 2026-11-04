"""
PRE-SCAN RCA - Import Graph Builder
Builds a map of which files import which other files.
Used to calculate context_lines based on coupling depth.
"""

import ast
import asyncio
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

import aiofiles

from rca_main.constants import live_py_files

logger = logging.getLogger(__name__)

# Flow tracing integration
_F = TypeVar('_F', bound=Callable[..., Any])
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False


@dataclass
class ImportInfo:
    """Information about a single import"""
    module: str  # What's being imported
    alias: Optional[str] = None  # 'as X' name
    is_from: bool = False  # from X import Y
    names: list[str] = field(default_factory=list)  # specific names imported


@dataclass 
class FileImports:
    """All imports for a single file"""
    file_path: Path
    imports: list[ImportInfo] = field(default_factory=list)
    
    # Resolved paths (after mapping module names to actual files)
    imports_files: list[Path] = field(default_factory=list)


class ImportGraphBuilder:
    """
    Builds a graph of import relationships between Python files.
    
    Usage:
        builder = ImportGraphBuilder(project_root)
        await builder.scan()
        
        # Who does this file import?
        imports = builder.get_imports(Path("orchestrator/core/scanner.py"))
        
        # Who imports this file?
        importers = builder.get_importers(Path("witness/mission_tracker.py"))
    """
    
    def __init__(self, project_root: Path, files=None):
        self.project_root = project_root.resolve()
        # Plan item 6 (owner 2026-09-05): when the validator hands over the
        # whitelist-filtered list, the graph is built from exactly those files.
        self.files = [Path(f) for f in files] if files is not None else None

        # file_path -> FileImports
        self.file_imports: dict[Path, FileImports] = {}
        
        # file_path -> list of files that import it (reverse index)
        self.imported_by: dict[Path, list[Path]] = {}
        
        # module name -> file path mapping
        self.module_to_file: dict[str, Path] = {}
    
    @trace
    async def _build_module_index(self) -> None:
        """Build mapping from module names to file paths"""
        logger.debug("_build_module_index: scanning %s", self.project_root)
        # FIX_14 (2026-09-10): the handed-over list, else the ONE walk (scan_scope.iter_live_py)
        py_files = await asyncio.to_thread(live_py_files, self.project_root, self.files)
        for py_file in py_files:

            # Convert path to module name
            # /project/orchestrator/core/scanner.py -> orchestrator.core.scanner
            try:
                rel_path = py_file.relative_to(self.project_root)
                parts = list(rel_path.parts)

                # Remove .py extension
                if parts[-1].endswith('.py'):
                    parts[-1] = parts[-1][:-3]

                # Handle __init__.py
                if parts[-1] == '__init__':
                    parts = parts[:-1]

                if parts:
                    module_name = '.'.join(parts)
                    self.module_to_file[module_name] = py_file

                    # Also add partial paths for relative imports
                    # orchestrator.core.scanner -> also index as core.scanner, scanner
                    for i in range(1, len(parts)):
                        partial = '.'.join(parts[i:])
                        if partial not in self.module_to_file:
                            self.module_to_file[partial] = py_file

            except ValueError:
                continue
    
    async def _extract_imports(self, file_path: Path) -> FileImports:
        """Extract all imports from a Python file"""
        file_imports = FileImports(file_path=file_path)

        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source = await f.read()
            tree = ast.parse(source)
        except Exception as e:
            logger.debug(f"Could not parse {file_path}: {e}")
            return file_imports

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.imports.append(ImportInfo(
                        module=alias.name,
                        alias=alias.asname,
                        is_from=False
                    ))

            elif isinstance(node, ast.ImportFrom):
                if node.module:  # from X import Y
                    names = [alias.name for alias in node.names]
                    file_imports.imports.append(ImportInfo(
                        module=node.module,
                        is_from=True,
                        names=names
                    ))

        return file_imports
    
    def _resolve_imports(self, file_imports: FileImports) -> None:
        """Resolve module names to actual file paths"""
        for imp in file_imports.imports:
            # Try to find the file for this module
            module = imp.module
            
            # Try exact match first
            if module in self.module_to_file:
                resolved = self.module_to_file[module]
                if resolved not in file_imports.imports_files:
                    file_imports.imports_files.append(resolved)
                continue
            
            # Try partial matches (for relative-style imports)
            for mod_name, mod_path in self.module_to_file.items():
                if mod_name.endswith('.' + module) or mod_name == module:
                    if mod_path not in file_imports.imports_files:
                        file_imports.imports_files.append(mod_path)
                    break
    
    @trace
    async def scan(self) -> int:
        """
        Scan all Python files and build import graph.
        Returns number of files scanned.
        """
        logger.debug("scan: starting import graph build for %s", self.project_root)
        # First build the module -> file index
        await self._build_module_index()
        logger.info(f"Indexed {len(self.module_to_file)} modules")

        # Collect file list: the handed-over list, or the ONE walk when none was given (FIX_14)
        py_files = await asyncio.to_thread(live_py_files, self.project_root, self.files)

        # Scan each file for imports using async I/O
        count = 0
        batch_size = 30
        for i in range(0, len(py_files), batch_size):
            batch = py_files[i:i + batch_size]
            results = await asyncio.gather(
                *[self._extract_imports(f) for f in batch],
                return_exceptions=True
            )
            for py_file, result in zip(batch, results):
                if isinstance(result, BaseException):
                    logger.debug(f"Error scanning {py_file}: {result}")
                    continue
                self._resolve_imports(result)
                self.file_imports[py_file] = result
                count += 1

        # Build reverse index
        self._build_reverse_index()

        logger.info(f"Scanned {count} files, found {sum(len(f.imports_files) for f in self.file_imports.values())} import relationships")
        return count
    
    def _build_reverse_index(self) -> None:
        """Build imported_by reverse index"""
        self.imported_by.clear()
        
        for file_path, file_imports in self.file_imports.items():
            for imported_file in file_imports.imports_files:
                if imported_file not in self.imported_by:
                    self.imported_by[imported_file] = []
                if file_path not in self.imported_by[imported_file]:
                    self.imported_by[imported_file].append(file_path)
    
    def get_imports(self, file_path: Path) -> list[Path]:
        """Get list of files that this file imports"""
        file_path = file_path.resolve()
        if file_path in self.file_imports:
            return self.file_imports[file_path].imports_files
        return []
    
    def get_importers(self, file_path: Path) -> list[Path]:
        """Get list of files that import this file"""
        file_path = file_path.resolve()
        return self.imported_by.get(file_path, [])
    
    @trace
    def get_import_depth(self, file_path: Path, max_depth: Optional[int] = None) -> int:  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was max_depth=5 (a clamp)
        """
        Calculate how deep this file is in the import tree.
        Files imported by many others = lower depth (core/shared)
        Files that import many others = higher depth (orchestration)
        """
        logger.debug("get_import_depth: %s (max_depth=%d)", file_path, max_depth)
        file_path = file_path.resolve()
        
        importers = len(self.get_importers(file_path))
        imports = len(self.get_imports(file_path))
        
        if importers == 0 and imports == 0:
            return 1  # Isolated file
        
        # Ratio: more importers = more "core" = lower depth
        # More imports = more "leaf" = higher depth
        if importers > imports:
            return imports + 1 if max_depth is None else max(1, min(max_depth, imports + 1))  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous)
        else:
            return importers + 1 if max_depth is None else max(1, min(max_depth, importers + 1))
    
    @trace
    async def scan_async(self) -> int:
        """
        Async version: delegates to scan() which is now fully async.
        Kept for backward compatibility.
        Returns number of files scanned.
        """
        return await self.scan()

    @trace
    def get_coupling_score(self, file_path: Path) -> float:
        """
        Calculate coupling score (0-1).
        Higher = more coupled = needs more context lines.
        """
        logger.debug("get_coupling_score: %s", file_path)
        file_path = file_path.resolve()
        
        importers = len(self.get_importers(file_path))
        imports = len(self.get_imports(file_path))
        
        total = importers + imports
        # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): `0.1` for isolated and `min(1.0, total / 50)` were a normalised SCORE against an assumed
        # 'typical project'; the raw connection count is the measurement — the ranker decides what it means.
        return float(total)


# === CLI ===

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 2:
        print("Usage: python import_graph.py /path/to/project [file_to_inspect]")
        sys.exit(1)

    async def _cli_main() -> None:
        project_root = Path(sys.argv[1]).resolve()

        builder = ImportGraphBuilder(project_root)
        await builder.scan()

        print(f"\nProject: {project_root}")
        print(f"Files scanned: {len(builder.file_imports)}")
        print(f"Modules indexed: {len(builder.module_to_file)}")

        # If specific file given, show its details
        if len(sys.argv) > 2:
            target = Path(sys.argv[2]).resolve()
            print(f"\n{'='*50}")
            print(f"File: {target.name}")
            print(f"{'='*50}")

            imports = builder.get_imports(target)
            print(f"\nImports ({len(imports)} files):")
            for f in imports[:10]:
                print(f"  -> {f.relative_to(project_root)}")
            if len(imports) > 10:
                print(f"  ... and {len(imports)-10} more")

            importers = builder.get_importers(target)
            print(f"\nImported by ({len(importers)} files):")
            for f in importers[:10]:
                print(f"  <- {f.relative_to(project_root)}")
            if len(importers) > 10:
                print(f"  ... and {len(importers)-10} more")

            print(f"\nCoupling score: {builder.get_coupling_score(target)}")
            print(f"Import depth: {builder.get_import_depth(target)}")

        # Show most coupled files
        else:
            print(f"\n{'='*50}")
            print("Most coupled files (highest import connections):")
            print(f"{'='*50}")

            scores = []
            for fp in builder.file_imports:
                score = builder.get_coupling_score(fp)
                num_importers = len(builder.get_importers(fp))
                num_imports = len(builder.get_imports(fp))
                scores.append((fp, score, num_importers, num_imports))

            scores.sort(key=lambda x: x[1], reverse=True)

            for fp, score, num_importers, num_imports in scores[:15]:
                rel = fp.relative_to(project_root)
                print(f"  {score:.2f}  <-{num_importers:2d} ->{num_imports:2d}  {rel}")

    asyncio.run(_cli_main())
