#!/usr/bin/env python3
"""
ast_scanner.py - AST-based dependency analysis for circuit monitoring.

Provides real-time import relationship scanning for the proof dashboard
and daemon. Scans script files directly via AST parsing to build an
accurate dependency graph, independent of daemon log state.

Features:
- Recursive script discovery with caching
- Import relationship extraction via AST
- Connection state verification (syntax + imports)
- Circular dependency detection
- Module-level caching for efficiency

Usage:
    from ast_scanner import CircuitScanner
    
    scanner = CircuitScanner('/path/to/repo')
    graph = scanner.get_full_graph()
    # Returns: {'nodes': [...], 'edges': [...], 'import_map': {...}}
"""

import logging
import ast
import subprocess
import os
import sys
import time
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union, cast
from dataclasses import dataclass, field
from datetime import datetime


def _syntax_fixture_path(rel_posix: str) -> bool:
    """FIX_53 (2026-09-17): consult the ONE scan-surface module for "is this path a shipped
    syntax fixture" (rule 15 — scan_scope holds the definition, no walker carries its own list).
    scan_scope is loaded by file location by the harness, so the import is done here and a failure
    means NO fixtures (every syntax break is genuine — today's behaviour), reported, never silent."""
    try:
        import scan_scope
    except Exception as _e:
        logging.getLogger(__name__).warning("ast_scanner: scan_scope unavailable for the "
                                            "syntax-fixture consult (%r) — every break is genuine", _e)
        return False
    return bool(scan_scope.syntax_fixture(rel_posix))


@dataclass
class ChangeTag:
    """Represents a single code change event."""
    lines: str  # Formatted line numbers e.g., "L12-L13, L45"
    timestamp: str  # ISO timestamp of detection


@dataclass
class SubdirInfo:
    """Represents a subdirectory within the monitored repo."""
    name: str  # Directory name (e.g., 'tests')
    relative_path: str  # Path relative to repo root
    script_count: int = 0
    scripts: List[str] = field(default_factory=list)  # Script names in this subdir
    external_imports: List[str] = field(default_factory=list)  # Imports from parent dir
    internal_edges: List[Tuple[str, str]] = field(default_factory=list)  # Edges within subdir


@dataclass
class ResolvedImport:
    """A single import statement with full resolution metadata."""
    module_name: str                      # Local name for edges (e.g., 'ast_cache')
    raw_import: str                       # Original dotted path (e.g., 'rca_main.analyzers.ast_cache')
    is_local: bool                        # Resolved to a file in the repo
    is_guarded: bool                      # Inside try/except ImportError block
    resolved_path: Optional[Path] = None  # Disk path if is_local


@dataclass
class ScriptNode:
    """Represents a monitored script with its connection state."""
    name: str  # Stem name (e.g., 'script_A')
    path: Path  # Full path to script
    relative_path: str  # Path relative to project root
    connected: Optional[bool] = None  # None=pending, True=ok, False=broken
    imports: Set[str] = field(default_factory=set)  # Set of imported local modules
    resolved_imports: List[ResolvedImport] = field(default_factory=list)  # Rich import metadata
    syntax_valid: bool = True
    import_error: Optional[str] = None
    last_modified: float = 0
    content_hash: str = ""
    change_tags: List[ChangeTag] = field(default_factory=list)  # FIFO queue, max 3
    subdir: Optional[str] = None  # Subdirectory name if in a nested dir, else None
    # FIX_53 (2026-09-17): the file does not parse AND its path matches a shipped syntax-fixture
    # pattern (scan_scope.syntax_fixture) — a lexer/parser corpus file, unparsable on purpose. It
    # stays a node and stays drawn; it is NOT a wiring break, so `connected` stays True.
    syntax_fixture: bool = False
    # Naming-drift data type tracker (PLAN_NAMING_DRIFT_TRACKER_2026-09-29 §E, lane ND1 2026-10-01): the §B
    # names of this file as (spelling, line, col, name_kind), collected from the SAME tree parse_imports built
    # in scan_script — never a second open or parse. Empty for non-Python files and files that do not parse;
    # None when the collector itself failed on this file (the tracker then says NOT MEASURED, never 0).
    names: Optional[List[tuple]] = field(default_factory=list)


@dataclass
class CircuitGraph:
    """Complete circuit graph with nodes and edges."""
    nodes: List[ScriptNode]
    edges: List[Tuple[str, str]]  # (from_script, to_script)
    import_map: Dict[str, List[str]]  # {script: [imports]}
    cycles: List[List[str]]  # Detected circular dependencies
    subdirs: Dict[str, SubdirInfo] = field(default_factory=dict)  # {subdir_name: info}
    scan_timestamp: str = ""
    

class CircuitScanner:
    """AST-based circuit scanner for dependency analysis."""
    
    def __init__(
        self,
        repo_path: str,
        project_root: Optional[str] = None,
        syntax_timeout: int = 10,
        import_timeout: int = 30,
        cache_ttl: int = 5,  # Cache TTL in seconds
        max_depth: Optional[int] = None,  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 4 — no discovery depth cap
        exclude_relpaths: Optional[Set[str]] = None,  # Whitelisted repo-relative paths (virtual stripper)
        state_dir: Optional[Union[str, Path]] = None,  # C3 (f) / B10 Q-H1-3: where the change-tag state lives
    ):
        """
        Initialize the circuit scanner.

        Args:
            repo_path: Path to the repository to scan
            project_root: Project root for relative paths (default: repo parent)
            syntax_timeout: Timeout for syntax checks (seconds)
            import_timeout: Timeout for import verification (seconds)
            cache_ttl: How long to cache results (seconds)
            max_depth: Maximum directory depth to scan (default: 4)
            exclude_relpaths: Repo-relative paths (files or dirs) to exclude from
                discovery entirely — the monitor-side whitelist ("virtual stripper",
                insertion point ①). Excluded files produce no node, no change tags,
                nothing in state or mirror. Mutable: the daemon may reassign this
                attribute between cycles (whitelist hot-reload).
            state_dir: Directory for the scanner's own persisted state —
                `change_tags_state.json` and `change_tag_overflow.log`. Default
                unchanged: `system_scripts/daemon_log/`, the daemon's. A harness or a
                gate passes a scratch dir so nothing of its run lands in the live tree
                (C3 (f) / B10 Q-H1-3).
        """
        self.repo_path = Path(repo_path)
        self.project_root = Path(project_root) if project_root else self.repo_path.parent
        self.syntax_timeout = syntax_timeout
        self.import_timeout = import_timeout
        self.cache_ttl = cache_ttl
        self.max_depth = max_depth
        self.exclude_relpaths: Set[str] = set(exclude_relpaths or ())
        
        # Cache
        self._script_cache: Dict[str, ScriptNode] = {}
        
        # Line-level tracking for code change detection
        self._line_hashes: Dict[str, List[str]] = {}  # {script_path: [hash_per_line]}
        self._change_tags: Dict[str, List[ChangeTag]] = {}  # {script_name: [tag1, tag2, tag3]}
        self._overflow_log: List[Dict] = []  # Evicted tags go here
        self.state_dir = Path(state_dir) if state_dir else Path(__file__).parent / "daemon_log"
        self._overflow_log_file = self.state_dir / "change_tag_overflow.log"
        self._overflow_log_file.parent.mkdir(parents=True, exist_ok=True)

        # Persistence for change tags (survive daemon restarts)
        self._change_tags_file = self.state_dir / "change_tags_state.json"
        self._load_persisted_change_tags()

        # Known filenames for file reference detection (populated on scan)
        self._known_filenames: Set[str] = set()

        # Detect self-referential package name (repo root has __init__.py and files
        # import from e.g. "rca_main.X" where "rca_main" IS this repo)
        self._package_name: Optional[str] = self._detect_package_name()

        # M-68 (2026-10-07): the dirs an absolute import resolves from — the repo root, plus every
        # non-package dir that holds a top-level package (a wrapper folder). Refreshed each tick.
        self._import_roots: List[Path] = [self.repo_path]
        # the names of the repo's own top-level packages (a dir with __init__.py whose parent has none)
        self._own_packages: Set[str] = set()

        # Set after each get_full_graph() call: True on the launch pass or when changed_files is non-empty
        self.rescan_triggered: bool = False
        self.changed_files: List[str] = []  # Files new/changed/deleted THIS tick (node name format)

        # ── FIX_39 (owner Q1, 2026-09-15): per-directory scan cadence ───────────────────────────
        # "400 files pinged constantly overheats the machine ... directories NOT being viewed by the
        #  user are pinged on a cadence derived from their file count; the viewed directory at full
        #  rate." Until now get_full_graph() re-read and re-parsed EVERY discovered script on EVERY
        # 2.5 s cycle ("Always do a fresh scan (no caching)"). It still returns the WHOLE graph every
        # frame — only the RE-READING is on a cadence; a directory off its turn keeps its nodes, its
        # edges and its change tags, and any file whose mtime moved is re-read whatever its cadence,
        # so a developer's edit is never missed.
        self._cycle: int = 0                        # cadence cycle counter (one per get_full_graph)
        self._viewed_dirs: Set[str] = set()         # repo-relative dirs the user is looking at ('' = root)
        self._cadence_mtimes: Dict[str, float] = {}  # cadence-only mtime memory (self.changed_files untouched)
        self._cadence_last: Dict[str, int] = {}     # dir -> the cycle it was last re-read on
        self.scan_cadence: Dict[str, Dict[str, Any]] = {}   # published into circuit_state.json
    
    def _detect_package_name(self) -> Optional[str]:
        """Detect if repo root is itself a Python package with a canonical import name.

        Scans a few .py files for absolute imports like 'from X.module import ...'
        where X/ doesn't exist as a subdirectory but repo_root has __init__.py.
        If a consistent top-level name appears, that's the package name.
        """
        init_file = self.repo_path / '__init__.py'
        if not init_file.exists():
            return None

        # Sample up to 10 .py files for self-referencing imports
        import collections as _collections
        candidates: _collections.Counter = _collections.Counter()
        # FIX_15 (2026-09-10): root-level LIVE .py only — the one walk, contained, whitelist-filtered
        # (a bare glob would read a symlinked .py at the root). EXCISED cut 3 batch 2 (2026-09-06,
        # agreed): `[:10]` sample removed.
        py_files = [p for p in self._scan_scope().iter_live_py(self.repo_path, frozenset(self.exclude_relpaths))
                    if p.parent == self.repo_path]
        for py_file in py_files:
            try:
                tree = ast.parse(py_file.read_text(), filename=str(py_file))
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", '_detect_package_name', _e)
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.ImportFrom) and node.module
                        and node.level == 0 and '.' in node.module):
                    top = node.module.split('.')[0]
                    # Only count if it's NOT a directory inside the repo
                    if not (self.repo_path / top).is_dir():
                        candidates[top] += 1

        if not candidates:
            return None
        best, count = candidates.most_common(1)[0]
        if count >= 1:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was `>= 3` — the best candidate is reported with its count; the consumer sees the number
            return best
        return None

    def _resolve_self_import(self, parts: list) -> Optional[Union[str, Path]]:
        """Resolve a dotted path after stripping the self-referential package name.

        For 'from rca_main.analyzers.symbol_analyzer import X':
            parts = ['analyzers', 'symbol_analyzer']
            -> walks repo_path/analyzers/ (subpackage dir) and returns 'symbol_analyzer'
               which _resolve_edges maps to 'analyzers/symbol_analyzer'

        For 'from rca_main.rca_unit import X':
            parts = ['rca_unit']
            -> returns 'rca_unit' (file at repo root)
        """
        # M-68: the walk starts from each import root in turn (repo root first)
        for root in self._import_roots:
            resolved = self._walk_dotted(root, parts)
            if resolved:
                return resolved
        return None

    @staticmethod
    def _walk_dotted(root: Path, parts: list) -> Optional[Union[str, Path]]:
        """The dotted walk of _resolve_self_import from one import root."""
        # Walk the path: each component is either a subpackage dir or a leaf module
        current = root
        for i, part in enumerate(parts):
            as_file = current / f"{part}.py"
            as_pkg = current / part
            if as_file.exists():
                # Leaf module — this is the import target. Its PATH is kept (owner 2026-10-07 04:45 wiring
                # rule): the bare name was re-searched only two levels deep, so a deeper leaf never linked.
                return as_file
            elif as_pkg.is_dir() and (as_pkg / '__init__.py').exists():
                # Subpackage — keep walking
                current = as_pkg
                continue
            else:
                # Can't resolve further
                return parts[0] if (root / f"{parts[0]}.py").exists() else None
        # Ended on a package dir (e.g. 'from rca_main.analyzers import X')
        return parts[0]


    def _resolve_module(self, module_name: str, context_dir: Path) -> Optional[Path]:
        """Single source of truth: find a module in the repo by name.

        Checks (in order): same directory, repo root, root packages,
        then modules inside any subpackage. Returns the Path if found, None if external.
        """
        # 1. Same directory as the importing file
        candidate = context_dir / f"{module_name}.py"
        if candidate.exists():
            return candidate
        # Steps 2-4 run from each import root in turn (M-68: a wrapper folder's packages too)
        for root in self._import_roots:
            # 2. Import root
            candidate = root / f"{module_name}.py"
            if candidate.exists():
                return candidate
            # 3. Package directory at the import root (dir with __init__.py)
            pkg = root / module_name
            if pkg.is_dir() and (pkg / "__init__.py").exists():
                return pkg / "__init__.py"
            # 4. Module inside any subpackage (e.g. ast_cache inside analyzers/)
            for subdir in root.iterdir():
                if not self._scan_scope().contained(subdir, self.repo_path):
                    continue  # FIX_15: a symlinked subpackage is never resolved into
                if subdir.is_dir() and (subdir / "__init__.py").exists():
                    candidate = subdir / f"{module_name}.py"
                    if candidate.exists():
                        return candidate
        return None

    def _path_to_node_name(self, path: Path) -> str:
        """Convert a resolved file path to its canonical node name.

        Mirrors the naming logic in scan_script(): relative to repo_path,
        .py extension stripped for Python files.
        """
        try:
            rel = path.relative_to(self.repo_path)
            if path.suffix == '.py':
                return str(rel.with_suffix(''))
            return str(rel)
        except ValueError:
            return path.stem

    def _get_guarded_lines(self, tree: ast.Module) -> Set[int]:
        """Return line numbers inside try/except blocks that guard imports.

        Detects: except ImportError, except ModuleNotFoundError, except Exception,
        bare except, and tuple forms like except (ImportError, Exception).
        """
        guarded: Set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            has_import_guard = False
            for handler in node.handlers:
                if handler.type is None:
                    # bare except:
                    has_import_guard = True
                elif isinstance(handler.type, ast.Name):
                    if handler.type.id in ('ImportError', 'ModuleNotFoundError', 'Exception'):
                        has_import_guard = True
                elif isinstance(handler.type, ast.Tuple):
                    for elt in handler.type.elts:
                        if isinstance(elt, ast.Name) and elt.id in ('ImportError', 'ModuleNotFoundError', 'Exception'):
                            has_import_guard = True
            if has_import_guard:
                for stmt in node.body:
                    start = getattr(stmt, 'lineno', 0)
                    end = getattr(stmt, 'end_lineno', start)
                    for line in range(start, end + 1):
                        guarded.add(line)
        return guarded

    def _drop_deleted_files(self, current_keys: Set[str], first_pass: bool) -> None:
        """S1: forget every file of this repo that is no longer on the scan surface (deleted, renamed
        away or whitelisted out) — its cached node, line hashes, change tags and cadence mtime. A file the
        scanner knew this run is also named in self.changed_files, so the daemon drops its findings;
        on the launch pass only the persisted state is pruned (nothing was reported yet).
        """
        known_keys = set(self._script_cache) | set(self._cadence_mtimes)
        # The persisted line hashes are shared by every target this engine has scanned; only this
        # repo's entries are ours to prune.
        for key in self._line_hashes:
            if Path(key).is_relative_to(self.repo_path):
                known_keys.add(key)
        gone = sorted(known_keys - current_keys)
        dirty = False
        for key in gone:
            name = self._script_path_to_node_name(Path(key))
            reported = key in self._script_cache or key in self._cadence_mtimes
            self._script_cache.pop(key, None)
            self._cadence_mtimes.pop(key, None)
            if self._line_hashes.pop(key, None) is not None:
                dirty = True
            if self._change_tags.pop(name, None) is not None:
                dirty = True
            if reported and not first_pass:
                self.changed_files.append(name)
        if dirty:
            self._save_persisted_change_tags()

    def _script_path_to_node_name(self, script_path: Path) -> str:
        """Convert script path to node name format using full relative path."""
        is_python = script_path.suffix == '.py'
        
        try:
            rel_to_repo = script_path.relative_to(self.repo_path)
            if is_python:
                # Remove .py extension
                return str(rel_to_repo.with_suffix(''))
            else:
                # Keep extension for non-Python files
                return str(rel_to_repo)
        except ValueError:
            return script_path.stem if is_python else script_path.name
    
    def _file_content_differs(self, script_path: Path) -> bool:
        """Quick check if file content differs from stored hashes.
        
        Used to detect changes when TTL expires (not mtime-triggered).
        """
        path_str = str(script_path)
        if path_str not in self._line_hashes:
            return True  # No stored hashes = treat as different
        # S1: key presence, not truthiness — an empty file stores [] and must not read as changed
        # on every tick.
        current_hashes = self._compute_line_hashes(script_path)
        return current_hashes != self._line_hashes[path_str]
    
    def _compute_line_hashes(self, script_path: Path) -> List[str]:
        """Compute hash for each line in a script."""
        try:
            with open(script_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            return [hashlib.md5(line.encode()).hexdigest()[:8] for line in lines]
        except Exception:
            return []
    
    def _detect_changed_lines(self, script_path: Path, script_name: str) -> Optional[str]:
        """Detect which lines changed and return formatted string.
        
        Returns:
            Formatted string like "L12-L13, L45" or None if no changes
        """
        path_str = str(script_path)
        current_hashes = self._compute_line_hashes(script_path)
        
        # First time seeing this file - store hashes (an empty file stores []), no change tag
        if path_str not in self._line_hashes:
            self._line_hashes[path_str] = current_hashes
            return None
        previous_hashes = self._line_hashes[path_str]
        
        # Find changed lines
        changed_lines = []
        max_lines = max(len(current_hashes), len(previous_hashes))
        
        for i in range(max_lines):
            curr = current_hashes[i] if i < len(current_hashes) else None
            prev = previous_hashes[i] if i < len(previous_hashes) else None
            if curr != prev:
                changed_lines.append(i + 1)  # 1-indexed
        
        # Update stored hashes
        self._line_hashes[path_str] = current_hashes
        
        if not changed_lines:
            return None
        
        # Format as ranges: "L12-L13, L45-L47, L50"
        return self._format_line_ranges(changed_lines)
    
    def _format_line_ranges(self, lines: List[int]) -> str:
        """Format line numbers as compact ranges."""
        if not lines:
            return ""
        
        lines = sorted(set(lines))
        ranges = []
        start = lines[0]
        end = lines[0]
        
        for line in lines[1:]:
            if line == end + 1:
                end = line
            else:
                if start == end:
                    ranges.append(f"L{start}")
                else:
                    ranges.append(f"L{start}-L{end}")
                start = end = line
        
        # Don't forget the last range
        if start == end:
            ranges.append(f"L{start}")
        else:
            ranges.append(f"L{start}-L{end}")
        
        return ", ".join(ranges)
    
    def _add_change_tag(self, script_name: str, lines_str: str) -> Optional[Dict]:
        """Add a change tag to a script's FIFO queue. Returns evicted tag if any.
        
        Order: [newest, middle, oldest] - slot 0 = newest, slot 2 = oldest (gets evicted)
        """
        if script_name not in self._change_tags:
            self._change_tags[script_name] = []
        
        tags = self._change_tags[script_name]
        evicted = None
        
        # FIFO: if at capacity (3), evict oldest (last slot) and write to log file
        if len(tags) >= 3:
            evicted_tag = tags.pop()  # Remove oldest (index -1, last slot)
            evicted = {
                'script': script_name,
                'lines': evicted_tag.lines,
                'timestamp': evicted_tag.timestamp,
                'evicted_at': datetime.now().isoformat()
            }
            self._overflow_log.append(evicted)
            # Write to log file
            self._write_evicted_tag_to_log(evicted)
        
        # Insert new tag at beginning (slot 0 = newest)
        tags.insert(0, ChangeTag(
            lines=lines_str,
            timestamp=datetime.now().isoformat()
        ))
        
        # Persist to disk (survives daemon restarts)
        self._save_persisted_change_tags()
        
        return evicted
    
    def _write_evicted_tag_to_log(self, evicted: Dict):
        """Append evicted tag to overflow log file."""
        try:
            with open(self._overflow_log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{evicted['evicted_at']}] {evicted['script']}: {evicted['lines']} (originally: {evicted['timestamp']})\n")
        except Exception as e:
            pass  # Don't fail on log write errors
    
    def _load_persisted_change_tags(self):
        """Load change tags from disk (survives daemon restarts)."""
        try:
            if self._change_tags_file.exists():
                import json
                with open(self._change_tags_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Check if target repo matches - clear if different
                if data.get('target_repo') != str(self.repo_path):
                    return  # Different target, don't load old tags
                
                # Restore change tags
                for script_name, tags_data in data.get('tags', {}).items():
                    self._change_tags[script_name] = [
                        ChangeTag(lines=t['lines'], timestamp=t['timestamp'])
                        for t in tags_data
                    ]
                
                # Restore line hashes (for change detection continuity)
                self._line_hashes = data.get('line_hashes', {})
        except Exception:
            pass  # Start fresh if load fails
    
    def _save_persisted_change_tags(self):
        """Save change tags to disk."""
        try:
            import json
            data = {
                'target_repo': str(self.repo_path),
                'tags': {
                    name: [{'lines': t.lines, 'timestamp': t.timestamp} for t in tags]
                    for name, tags in self._change_tags.items()
                },
                'line_hashes': self._line_hashes,
                'saved_at': datetime.now().isoformat()
            }
            # S1: atomic — temp file + rename (like write_file_locked), so a reader or a crash never
            # sees a half-written file.
            self._change_tags_file.parent.mkdir(exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                dir=self._change_tags_file.parent,
                prefix=f".{self._change_tags_file.stem}_{os.getpid()}_",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                Path(tmp_path).rename(self._change_tags_file)  # atomic on same filesystem
            except BaseException:
                Path(tmp_path).unlink(missing_ok=True)
                raise
        except Exception:
            pass  # Don't fail on save errors
    
    def get_change_tags(self, script_name: str) -> List[ChangeTag]:
        """Get change tags for a script (up to 3)."""
        return self._change_tags.get(script_name, [])
    
    def get_overflow_log(self) -> List[Dict]:
        """Get all evicted change tags."""
        return self._overflow_log.copy()
    
    def clear_all_change_tags(self):
        """Clear all change tags and overflow log (called on target change)."""
        self._change_tags.clear()
        self._overflow_log.clear()
        self._line_hashes.clear()
        # Clear persisted file too
        try:
            if self._change_tags_file.exists():
                self._change_tags_file.unlink()
        except Exception:
            pass

    def reset_caches(self):
        """Flush all in-memory scan caches (target change safety net)."""
        self._script_cache.clear()

    def _is_excluded(self, rel_posix: str) -> bool:
        """True if a repo-relative path is whitelisted (exact file/dir or under a whitelisted dir)."""
        if not self.exclude_relpaths:
            return False
        if rel_posix in self.exclude_relpaths:
            return True
        return any(rel_posix.startswith(w.rstrip('/') + '/')
                   for w in self.exclude_relpaths)

    @staticmethod
    def _scan_scope():
        """The ONE scan surface (system_scripts/scan_scope.py) — the same module object the daemon
        published the whitelist into (set_scope), so this walker sees the scope every other walker sees."""
        try:
            import scan_scope
        except ImportError:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).resolve().parent))
            import scan_scope
        return scan_scope

    def discover_scripts(self) -> List[Path]:
        """
        Auto-discover all files in the repository up to max_depth levels.

        Returns:
            List of Path objects for each discovered file
        """
        if not self.repo_path.exists():
            return []

        scripts = []
        # PYTHON-ONLY (owner 2026-09-05, evening): only .py files are ever nodes.
        # A non-.py file is an artifact by construction (whitelisted at launch);
        # it is never drawn, never hashed, never a node (F-CIRC-WALK docs/ svg).
        # FIX_13 / FIX_15 (2026-09-10): the walk IS scan_scope.iter_live_py — the whitelist
        # (virtual stripper, insertion point ①: a whitelisted file never becomes a node, emits
        # no change tags ②, never serializes ⑤), the engine hard-skips, containment (no symlink,
        # nothing outside the root). No private dot / egg-info / .git name test remains here:
        # a dot-dir is in scope unless the whitelist names it, so NOAI's `files_scanned` and the
        # circuit's `total_scripts` count the same set.
        for file_path in self._scan_scope().iter_live_py(self.repo_path, frozenset(self.exclude_relpaths)):
            # Skip files beyond max_depth
            rel_path = file_path.relative_to(self.repo_path)
            if self.max_depth is not None and len(rel_path.parts) > self.max_depth:
                continue
            scripts.append(file_path)

        return scripts
        
    def parse_imports(self, script_path: Path) -> Tuple[Set[str], List['ResolvedImport']]:
        """
        Parse a Python script and extract imports using AST.

        Returns:
            Tuple of (local_names, resolved_imports) where:
            - local_names: Set[str] of module names for edges (backward compat)
            - resolved_imports: List[ResolvedImport] with full metadata
        """
        self._naming_tree = None   # ND1: the tree scan_script's naming hook reads — this parse, not another
        try:
            with open(script_path, 'r') as f:
                content = f.read()
                tree = ast.parse(content, filename=str(script_path))
        except (SyntaxError, Exception):
            return set(), []
        self._naming_tree = tree

        local_names: Set[str] = set()
        resolved_imports: List[ResolvedImport] = []
        script_dir = script_path.parent
        guarded_lines = self._get_guarded_lines(tree)

        def _add(module_name: Union[str, Path], raw_import: str, line: int, broken: bool = False) -> None:
            """Resolve an import and record it. *broken*: a dotted import into the repo's own package whose
            module does not exist — recorded unresolved, never as a link to the package (owner 04:45)."""
            is_guarded = line in guarded_lines
            # a dotted walk hands over the leaf file it found; a name is resolved here
            path = None if broken else (module_name if isinstance(module_name, Path)
                                        else self._resolve_module(module_name, script_dir))
            is_local = path is not None
            # Normalize to canonical node name so edges resolve directly
            canonical = self._path_to_node_name(path) if path is not None else module_name
            resolved_imports.append(ResolvedImport(
                module_name=canonical,
                raw_import=raw_import,
                is_local=is_local,
                is_guarded=is_guarded,
                resolved_path=path,
            ))
            # Only add to local_names if it resolved locally AND isn't a guarded external
            if is_local:
                local_names.add(canonical)

        for node in ast.walk(tree):
            # Handle: import module_name
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw = alias.name
                    parts = raw.split('.')
                    top_level = parts[0]
                    # Self-referential: import rca_main.X -> track X
                    if (self._package_name and top_level == self._package_name
                            and len(parts) >= 2):
                        resolved_name = self._resolve_self_import(parts[1:])
                        if resolved_name:
                            _add(resolved_name, raw, node.lineno)
                        else:
                            _add(top_level, raw, node.lineno, broken=True)
                    elif len(parts) >= 2:
                        # Dotted import: try walking full path through local packages
                        resolved_name = self._resolve_self_import(parts)
                        if resolved_name:
                            _add(resolved_name, raw, node.lineno)
                        else:
                            _add(top_level, raw, node.lineno, broken=top_level in self._own_packages)
                    else:
                        _add(top_level, raw, node.lineno)

            # Handle: from module_name import something
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    raw = node.module
                    parts = raw.split('.')
                    top_level = parts[0]
                    # Self-referential: from rca_main.analyzers.X import ...
                    if (self._package_name and top_level == self._package_name
                            and len(parts) >= 2):
                        resolved_name = self._resolve_self_import(parts[1:])
                        if resolved_name:
                            _add(resolved_name, raw, node.lineno)
                        else:
                            _add(top_level, raw, node.lineno, broken=True)
                    elif len(parts) >= 2:
                        # Dotted import: try walking full path through local packages
                        resolved_name = self._resolve_self_import(parts)
                        if resolved_name:
                            _add(resolved_name, raw, node.lineno)
                        else:
                            _add(top_level, raw, node.lineno, broken=top_level in self._own_packages)
                    else:
                        _add(top_level, raw, node.lineno)
                elif node.level > 0:
                    # from . import name1, name2
                    for alias in node.names:
                        module_name = alias.name.split('.')[0]
                        _add(module_name, f'.{module_name}', node.lineno)

        return local_names, resolved_imports
            
    def parse_file_references(self, script_path: Path, known_files: Optional[Set[str]] = None) -> Set[str]:
        """
        Parse a Python script for file references to other repo files.

        Detects patterns like:
            SCRIPT_DIR / "kernel_trace.sh"
            Path("config.json")
            subprocess.run(["./script.sh", ...])
            open("data.csv")

        Args:
            script_path: Path to the Python script
            known_files: Set of filenames (with extensions) that exist in the repo

        Returns:
            Set of filenames referenced (e.g., {"kernel_trace.sh", "config.json"})
        """
        if not known_files:
            return set()

        try:
            with open(script_path, 'r') as f:
                tree = ast.parse(f.read(), filename=str(script_path))
        except Exception:
            return set()

        own_name = script_path.name
        refs = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                # Skip empty strings and overly long strings (not filenames)
                if not val or len(val) > 200:
                    continue
                basename = Path(val).name if '/' in val else val
                if basename in known_files and basename != own_name:
                    refs.add(basename)

        return refs

    def check_syntax(self, script_path: Path) -> bool:
        return self.syntax_error(script_path) is None

    def syntax_error(self, script_path: Path) -> Optional[str]:
        """FIX_53 (2026-09-17): the ONE definition of "does this file parse", and the reason when it
        does not (`line N: <msg>`), or None when it parses.

        Was `python -m py_compile` in a subprocess. A COMPILE is strictly stricter than a PARSE, and
        that difference stopped launches: pygments' `tests/examplefiles/python/switch_case.py` is a
        module-scope `match` whose every `case` body is a bare `return` — `ast.parse` accepts it,
        `compile()` raises `'return' outside function`, so the circuit called the file broken while
        the venv's own `ast.parse` called it fine (I-47, second half; measured 2026-09-17). Every
        other walker in the engine — the validator, the artifact scanner, the intent file, the runner
        tracker, count_disk_py_files — defines parsable as `ast.parse`; this was the one outlier and
        the only one that could stop a launch.

        Parsed from BYTES, never from `errors='replace'` text: bytes are what the interpreter reads,
        a `# -*- coding:` declaration is honoured, and a file that is not valid UTF-8 is reported as
        the error it is instead of being silently patched with U+FFFD.

        The F12 rung-0 bytecode breach that PYTHONPYCACHEPREFIX was written to dodge cannot recur:
        nothing is compiled, so no `.pyc` is produced anywhere."""
        try:
            ast.parse(script_path.read_bytes(), filename=str(script_path))
            return None
        except SyntaxError as e:
            return f"line {e.lineno}: {e.msg}"
        except (ValueError, UnicodeDecodeError) as e:
            # a null byte / undecodable source — unparsable for the same reason, reported the same way
            return f"{type(e).__name__}: {e}"
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'syntax_error', _e)
            return f"{type(_e).__name__}: {_e}"

    def compute_content_hash(self, script_path: Path) -> str:
        """Compute SHA256 hash of script content."""
        try:
            with open(script_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except Exception:
            return ""
            
    def scan_script(self, script_path: Path) -> ScriptNode:
        """
        Fully analyze a single file (Python or other).
        
        Args:
            script_path: Path to the file
            
        Returns:
            ScriptNode with complete analysis
        """
        is_python = script_path.suffix == '.py'
        
        try:
            relative_path = str(script_path.relative_to(self.project_root))
        except ValueError:
            relative_path = str(script_path.relative_to(self.repo_path))
        
        # Determine subdir (top-level folder within repo) for grouping
        subdir = None
        try:
            rel_to_repo = script_path.relative_to(self.repo_path)
            if len(rel_to_repo.parts) > 1:
                # File is in a subdirectory - use top-level dir for grouping
                subdir = rel_to_repo.parts[0]
        except ValueError:
            pass
        
        # Use FULL relative path as unique name to avoid collisions
        # Strip .py extension for Python files, keep extension for others
        try:
            rel_to_repo = script_path.relative_to(self.repo_path)
            if is_python:
                # Remove .py extension: repair-cheatsheet/repair_cheatsheet/__init__.py -> repair-cheatsheet/repair_cheatsheet/__init__
                name = str(rel_to_repo.with_suffix(''))
            else:
                # Keep extension: repair-cheatsheet/pyproject.toml stays as-is
                name = str(rel_to_repo)
        except ValueError:
            name = script_path.stem if is_python else script_path.name
        
        node = ScriptNode(
            name=name,
            path=script_path,
            relative_path=relative_path,
            subdir=subdir,
        )
        
        if not script_path.exists():
            node.connected = False
            node.import_error = "File not found"
            return node
            
        # File metadata
        try:
            node.last_modified = script_path.stat().st_mtime
            node.content_hash = self.compute_content_hash(script_path)
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_script', _e)
            pass
        
        # Non-Python files: always "connected" (no imports to check)
        if not is_python:
            node.syntax_valid = True
            node.connected = True
            node.imports = set()
            return node
            
        # Python files: full AST analysis
        # Syntax check
        _syn_err = self.syntax_error(script_path)
        node.syntax_valid = _syn_err is None
        if not node.syntax_valid:
            # FIX_53 (owner Q5 / I-47, 2026-09-17): a file the target ships IN ORDER to be
            # unparsable (a lexer / parser fixture, matched BY PATTERN) is not a wiring break.
            # It keeps its node and its place on the graph; only its breakage is expected.
            # Anything else is a genuine break and still stops the launch, now naming the line.
            try:
                _rel_posix = script_path.relative_to(self.repo_path).as_posix()
            except ValueError:
                _rel_posix = node.relative_path.replace('\\', '/')
            if _syntax_fixture_path(_rel_posix):
                node.syntax_fixture = True
                node.connected = True
                node.import_error = None
                node.imports = set()
                return node
            node.connected = False
            node.import_error = f"Syntax error: {_syn_err}"
            return node

        # Parse imports — single pass resolves AND validates
        local_names, resolved = self.parse_imports(script_path)
        node.imports = local_names
        node.resolved_imports = resolved

        # Naming-drift data type tracker (plan 2026-09-29 §E "one scan, no second scan"): the file's §B
        # names are read off the tree parse_imports JUST built (`_naming_tree`) — no further open, no
        # further parse (proof §F.3). A collector that cannot be imported or fails is reported and the
        # node's names are None, so the daemon's tracker says NOT MEASURED — never a silent empty baseline.
        try:
            from naming_drift_detector import collect_names as _collect_names
            node.names = _collect_names(getattr(self, '_naming_tree', None))
        except Exception as _e:
            logging.getLogger(__name__).warning("ast_scanner: naming-drift names not collected for %s "
                                                "(%r)", relative_path, _e)
            node.names = None
        self._naming_tree = None

        # Connectivity: every local_name must have resolved to a path.
        # Unresolved local imports are those added to local_names but with no resolved_path.
        # (Guarded externals were never added to local_names, so they can't break connectivity.)
        missing = [ri.module_name for ri in resolved
                   if ri.module_name in local_names and ri.resolved_path is None]
        # owner 2026-10-07 04:45 ("if we know a wire's wrong … fix it rather than run the app"): an absolute
        # import that names one of the repo's OWN top-level packages but resolved to nothing is a wrong wire
        # (M-68: every wrapped target's links went missing and every node still read "connected"). The
        # node is not connected, so the launch's wiring gate stops and names it.
        missing += [ri.raw_import for ri in resolved
                    if not ri.is_local and not ri.is_guarded and not ri.raw_import.startswith('.')
                    and (ri.raw_import.split('.')[0] in self._own_packages
                         or (self._package_name and ri.raw_import.split('.')[0] == self._package_name))]
        if missing:
            node.connected = False
            node.import_error = f"Missing local modules: {', '.join(missing)}"
        else:
            node.connected = True
            node.import_error = None

        # File references (Path / "file.sh", open("file.json"), etc.) — graph edges only,
        # not import dependencies. Added AFTER connectivity check so they don't break it.
        file_refs = self.parse_file_references(script_path, self._known_filenames)
        # Normalize file refs to node-name format: strip .py extension so they
        # match node names (e.g., "cli.py" -> "cli", "__init__.py" -> "__init__")
        normalized_refs = set()
        for ref in file_refs:
            if ref.endswith('.py'):
                normalized_refs.add(ref[:-3])
            else:
                normalized_refs.add(ref)
        node.imports.update(normalized_refs)

        return node
        
    def detect_cycles(self, import_map: Dict[str, List[str]]) -> List[List[str]]:
        """
        Detect circular dependencies in the import graph.
        
        Args:
            import_map: Dictionary mapping script names to their imports
            
        Returns:
            List of cycles (each cycle is a list of script names)
        """
        cycles = []
        visited = set()
        rec_stack = set()
        
        def dfs(node: str, path: List[str]) -> None:
            if node in rec_stack:
                # Found cycle
                cycle_start = path.index(node)
                cycles.append(path[cycle_start:] + [node])
                return
                
            if node in visited:
                return
                
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in import_map.get(node, []):
                if neighbor in import_map:  # Only follow known nodes
                    dfs(neighbor, path.copy())
                    
            rec_stack.discard(node)
            
        for node in import_map:
            if node not in visited:
                dfs(node, [])
                
        # Deduplicate cycles (same cycle can be found from different starting points)
        unique_cycles = []
        seen = set()
        for cycle in cycles:
            normalized = tuple(sorted(cycle[:-1]))  # Exclude the repeated start
            if normalized not in seen:
                seen.add(normalized)
                unique_cycles.append(cycle)
                
        return unique_cycles
        
    # ── FIX_39: the per-directory cadence ────────────────────────────────────────────────────

    def set_view(self, viewed_dirs) -> None:
        """The directories the user is looking at (from the dash, through poll_config.json).

        Empty = the user is at the root, so the ROOT directory is the viewed one. A viewed directory
        is re-read on every cycle; every other directory on the period its file count earns."""
        self._viewed_dirs = {str(d).strip('/') for d in (viewed_dirs or ()) if str(d).strip('/')}

    def _dir_key(self, script_path: Path) -> str:
        """The repo-relative directory a script lives in ('' for the repo root)."""
        try:
            rel = script_path.relative_to(self.repo_path)
        except ValueError:
            return ''
        parent = str(rel.parent)
        return '' if parent == '.' else parent

    def _is_viewed(self, dir_key: str) -> bool:
        """EXACTLY the directory the user selected — never its whole subtree.

        The owner's words are "the viewed DIRECTORY at full rate" and "break the target into
        manageable pieces". A prefix match undoes both: selecting `pygments` on the sdist would put
        343 of 403 files back on the 2.5 s ping, which is the machine-overheating this fix exists to
        stop. A subdirectory earns full rate by being drilled into, like any other directory."""
        if not self._viewed_dirs:
            return dir_key == ''            # at the root, the root's own files are the live view
        return dir_key in self._viewed_dirs

    def _dir_period_cycles(self, n_files: int) -> int:
        """FIX_46's row: the period a directory of n live files earns. The constants live in the ONE
        cadence table (gearbox.py); a tree without the coordinator falls back to them here, once."""
        try:
            import gearbox as _cadence
            return int(_cadence.dir_period_cycles(n_files))
        except Exception:
            per = -(-max(0, int(n_files)) // 8)
            return min(max(per, 1), 240)

    def _mtime_moved(self, script_path: Path) -> bool:
        """A stat, never a read: has this file changed since the last cadence check? Populates the
        cadence's OWN mtime memory; self.changed_files is left exactly as it was."""
        key = str(script_path)
        try:
            now = script_path.stat().st_mtime
        except OSError:
            self._cadence_mtimes.pop(key, None)
            return True
        was = self._cadence_mtimes.get(key)
        self._cadence_mtimes[key] = now
        return was is None or now != was

    def _cadence_plan(self, scripts: List[Path], force_refresh: bool) -> Dict[str, bool]:
        """Which directories get re-read this cycle, and the table the dash's band prints."""
        by_dir: Dict[str, int] = {}
        for sp in scripts:
            by_dir[self._dir_key(sp)] = by_dir.get(self._dir_key(sp), 0) + 1
        order = sorted(by_dir)
        due: Dict[str, bool] = {}
        cadence: Dict[str, Dict[str, Any]] = {}
        base_s = 2.5
        try:
            import gearbox as _cadence
            base_s = float(_cadence.CADENCE_BASE_S)
        except Exception:
            pass
        for idx, d in enumerate(order):
            n = by_dir[d]
            viewed = self._is_viewed(d)
            period = 1 if viewed else self._dir_period_cycles(n)
            phase = 0 if period <= 1 else (idx % period)
            is_due = bool(force_refresh or period <= 1 or (self._cycle % period) == phase)
            due[d] = is_due
            if is_due:
                self._cadence_last[d] = self._cycle
            cadence[d or '.'] = {
                'files': n, 'period_cycles': period, 'period_s': round(period * base_s, 2),
                'phase': phase, 'viewed': viewed, 'due_this_cycle': is_due,
                'last_scan_cycle': self._cadence_last.get(d),
            }
        self.scan_cadence = cadence
        return due

    def get_full_graph(self, force_refresh: bool = False) -> CircuitGraph:
        """
        Build complete circuit graph with current connection states.
        
        Args:
            force_refresh: Force cache invalidation
            
        Returns:
            CircuitGraph with all nodes, edges, and import relationships

        FIX_39: the graph returned is always WHOLE. What is on a cadence is the RE-READING: a
        directory off its turn re-uses the ScriptNode from the last time it was read, and any file
        whose mtime moved is re-read whatever its directory's cadence.
        """
        scripts = self.discover_scripts()
        self._import_roots = self._scan_scope().import_roots(self.repo_path, scripts)
        self._own_packages = {p.parent.name for p in scripts
                              if p.name == '__init__.py' and not (p.parent.parent / '__init__.py').exists()}
        nodes = []

        # Build known filenames set for file reference detection
        self._known_filenames = {p.name for p in scripts}

        # S1: this tick's changed_files = files new, changed (content differs) or deleted THIS tick,
        # empty when nothing moved. The first tick after launch reports none — its full pass already
        # covers every file (the mypy/vulture/CRC/sys.path first passes run on their own).
        first_pass = not self._cycle
        self.changed_files = []
        current_keys = {str(p) for p in scripts}
        self._drop_deleted_files(current_keys, first_pass)

        self._cycle += 1
        due_by_dir = self._cadence_plan(scripts, force_refresh)
        reused = 0

        for script_path in scripts:
            cache_key = str(script_path)
            cached = self._script_cache.get(cache_key)
            known = cache_key in self._cadence_mtimes
            moved = self._mtime_moved(script_path)
            rescan = bool(force_refresh or cached is None or moved
                          or due_by_dir.get(self._dir_key(script_path), True))

            if not rescan:
                # `rescan` is already True whenever `cached is None` (above), so this branch only
                # ever runs on a real cached node — the cast states that, it does not assume it.
                node = cast(ScriptNode, cached)
                reused += 1
                node.change_tags = self.get_change_tags(node.name).copy()
                nodes.append(node)
                continue

            node = self.scan_script(script_path)
            self._script_cache[cache_key] = node

            # Detect line-level changes and add tags. A re-read file is checked against its
            # stored line hashes (none stored = new file); a touch with no content change is
            # not a change.
            content_differs = self._file_content_differs(script_path)
            if content_differs:
                changed_lines = self._detect_changed_lines(script_path, node.name)
                if changed_lines:
                    self._add_change_tag(node.name, changed_lines)
                # S1: a file first seen after launch, or whose content moved, is changed this tick
                if not first_pass:
                    self.changed_files.append(node.name)
            elif not known and not first_pass:
                self.changed_files.append(node.name)  # new file whose hashes were already on record
            
            # Attach current change tags to node
            node.change_tags = self.get_change_tags(node.name).copy()
            
            nodes.append(node)

        # The whole graph is still returned every frame; "rescan" now means the launch pass or a
        # tick where something changed, so the daemon's AST RESCAN line no longer fires every cycle.
        self.rescan_triggered = bool(first_pass or self.changed_files)

        self.scan_cadence['_summary'] = {
            'cycle': self._cycle, 'scripts': len(scripts),
            'rescanned': len(scripts) - reused, 'reused': reused,
            'viewed_dirs': sorted(self._viewed_dirs) or ['.'],
        }
        
        # Build edges from import relationships (resolve short names to full paths)
        edges = self._resolve_edges(nodes)
                    
        # Build import map
        import_map = {n.name: list(n.imports) for n in nodes}
        
        # Detect circular dependencies
        cycles = self.detect_cycles(import_map)
        
        # Build subdirectory info
        subdirs = self._build_subdir_info(nodes, edges)
        
        # Persist change tags and line hashes (for daemon restart continuity)
        self._save_persisted_change_tags()
        
        return CircuitGraph(
            nodes=nodes,
            edges=edges,
            import_map=import_map,
            cycles=cycles,
            subdirs=subdirs,
            scan_timestamp=datetime.now().isoformat()
        )
    
    def _resolve_edges(self, nodes: List['ScriptNode']) -> List[Tuple[str, str]]:
        """Resolve import names to full node names for edge building.
        
        Handles both direct matches (full path names) and relative imports
        within subdirectories (e.g., 'core' -> 'reconstructor/core' when
        importing from within reconstructor/).
        
        Also handles package imports: 'from reconstructor import X' resolves
        to 'reconstructor/__init__' since that's where the package exports live.
        
        Args:
            nodes: List of ScriptNode objects with imports
            
        Returns:
            List of (source, target) edges with fully resolved names
        """
        script_names = {n.name for n in nodes}
        
        # Build lookup: simple name -> {subdir: full_name}
        name_by_stem: Dict[str, Dict[str, str]] = {}
        for n in nodes:
            if '/' in n.name:
                stem = n.name.split('/')[-1]
                subdir = n.name.rsplit('/', 1)[0]
                if stem not in name_by_stem:
                    name_by_stem[stem] = {}
                name_by_stem[stem][subdir] = n.name
            else:
                name_by_stem[n.name] = {'': n.name}  # Root level
        
        # Build package lookup: package_name -> package/__init__ node
        package_init = {}
        for n in nodes:
            if n.name.endswith('/__init__'):
                pkg_name = n.name.rsplit('/', 1)[0]
                package_init[pkg_name] = n.name
        
        edges = []
        for node in nodes:
            node_subdir = node.name.rsplit('/', 1)[0] if '/' in node.name else ''

            for imp in node.imports:
                target = None

                # Normalize: strip .py if present (file refs may still slip through)
                clean_imp = imp[:-3] if imp.endswith('.py') else imp

                # Priority matches Python's import resolution:
                # 1. Package import (package/__init__) takes precedence over same-name module
                if clean_imp in package_init:
                    target = package_init[clean_imp]
                # 2. Exact match as full node name (when not a package)
                elif clean_imp in script_names:
                    target = clean_imp
                # 3. Resolve within same subdir
                elif clean_imp in name_by_stem and node_subdir in name_by_stem[clean_imp]:
                    target = name_by_stem[clean_imp][node_subdir]
                # 4. Root level fallback
                elif clean_imp in name_by_stem and '' in name_by_stem[clean_imp]:
                    target = name_by_stem[clean_imp]['']
                # 5. Stem-only search across ALL subdirs (broadest fallback)
                elif clean_imp in name_by_stem:
                    # Pick the first available subdir match
                    target = next(iter(name_by_stem[clean_imp].values()))

                if target and target != node.name:  # Skip self-edges
                    edges.append((node.name, target))

        return edges

    def _build_subdir_info(self, nodes: List[ScriptNode], edges: List[Tuple[str, str]]) -> Dict[str, SubdirInfo]:
        """Build subdirectory information from scanned nodes.
        
        Groups scripts by subdirectory and computes:
        - Scripts in each subdir
        - External imports (from parent dir)
        - Internal edges (within subdir)
        
        Args:
            nodes: List of all scanned ScriptNode objects
            edges: List of all edges (from, to)
            
        Returns:
            Dict mapping subdir name to SubdirInfo
        """
        subdirs: Dict[str, SubdirInfo] = {}
        
        # Group nodes by subdir
        root_scripts = set()  # Scripts in repo root (no subdir)
        for node in nodes:
            if node.subdir:
                if node.subdir not in subdirs:
                    subdirs[node.subdir] = SubdirInfo(
                        name=node.subdir,
                        relative_path=node.subdir,
                        scripts=[],
                        external_imports=[],
                        internal_edges=[]
                    )
                subdirs[node.subdir].scripts.append(node.name)
            else:
                root_scripts.add(node.name)
        
        # Update script counts
        for subdir_info in subdirs.values():
            subdir_info.script_count = len(subdir_info.scripts)
        
        # Analyze edges for each subdir
        for subdir_name, subdir_info in subdirs.items():
            subdir_scripts = set(subdir_info.scripts)
            external_imports = set()
            internal_edges = []
            
            for (src, dst) in edges:
                if src in subdir_scripts:
                    if dst in subdir_scripts:
                        # Internal edge (both in same subdir)
                        internal_edges.append((src, dst))
                    elif dst in root_scripts:
                        # External import (from parent dir)
                        external_imports.add(dst)
            
            subdir_info.external_imports = list(external_imports)
            subdir_info.internal_edges = internal_edges
        
        return subdirs
        
    def get_node_status_dict(self) -> Dict[str, Optional[bool]]:
        """
        Get simple node status dictionary for dashboard compatibility.
        
        Returns:
            Dictionary mapping script names to connection status
        """
        graph = self.get_full_graph()
        return {node.name: node.connected for node in graph.nodes}
        
    def get_import_map(self) -> Dict[str, List[str]]:
        """
        Get import relationships for dashboard compatibility.
        
        Returns:
            Dictionary mapping script names to list of imports
        """
        graph = self.get_full_graph()
        return graph.import_map
        
    def format_status_report(self) -> str:
        """
        Generate human-readable status report.
        
        Returns:
            Multi-line status report string
        """
        graph = self.get_full_graph()
        lines = [
            f"Circuit Scan Report - {graph.scan_timestamp}",
            f"Repository: {self.repo_path}",
            f"Scripts found: {len(graph.nodes)}",
            "-" * 40
        ]
        
        for node in graph.nodes:
            status = "CONNECTED" if node.connected else "BROKEN"
            imports_str = ",".join(sorted(node.imports)) if node.imports else ""
            
            if node.connected:
                lines.append(f"{status} {node.relative_path}: OK IMPORTS[{imports_str}]")
            else:
                error = node.import_error or "Unknown error"
                lines.append(f"{status} {node.relative_path}: {error} IMPORTS[{imports_str}]")
                
        # Report cycles if any
        if graph.cycles:
            lines.append("-" * 40)
            lines.append(f"WARNING: Circular dependencies detected ({len(graph.cycles)}):")
            for cycle in graph.cycles:
                lines.append(f"  {' -> '.join(cycle)}")
                
        all_connected = all(n.connected for n in graph.nodes)
        lines.append("-" * 40)
        lines.append(f"CIRCUIT STATUS: {'ALL CONNECTED' if all_connected else 'BREAKS DETECTED'}")
        
        return "\n".join(lines)


# Convenience function for quick scanning
def scan_repo(repo_path: str) -> CircuitGraph:
    """
    Quick scan of a repository.
    
    Args:
        repo_path: Path to repository
        
    Returns:
        CircuitGraph with full analysis
    """
    scanner = CircuitScanner(repo_path)
    return scanner.get_full_graph()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AST-based circuit scanner")
    parser.add_argument("repo", nargs="?", default="test_circuit_repo",
                        help="Repository path to scan")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    args = parser.parse_args()
    
    # Find repo path relative to script location
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    if Path(args.repo).is_absolute():
        repo_path = args.repo
    else:
        repo_path = project_root / args.repo
        
    scanner = CircuitScanner(str(repo_path), str(project_root))
    
    if args.json:
        import json
        graph = scanner.get_full_graph()
        output = {
            "scan_timestamp": graph.scan_timestamp,
            "nodes": [
                {
                    "name": n.name,
                    "relative_path": n.relative_path,
                    "connected": n.connected,
                    "imports": list(n.imports),
                    "syntax_valid": n.syntax_valid,
                    "import_error": n.import_error,
                    "content_hash": n.content_hash,
                }
                for n in graph.nodes
            ],
            "edges": graph.edges,
            "import_map": graph.import_map,
            "cycles": graph.cycles,
        }
        print(json.dumps(output, indent=2))
    else:
        print(scanner.format_status_report())
