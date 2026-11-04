"""
Detect sys.path manipulation, relative imports, path hacks, and structural
issues in Python codebases.

Categories:
  A. sys.path hacks (insert/append/extend)
  B. Relative path construction (Path("."), Path(".."), __file__ traversal)
  C. Structural issues (missing __init__.py, empty packages, duplicate names)
  + PYTHONPATH references in config/shell/env files
  D. Shadowed stdlib modules, wildcard imports, dependency drift
"""
import logging
import ast
import re
import sys
from pathlib import Path
from typing import Any, List, Dict, Optional, Set, Tuple
from dataclasses import dataclass


# ─────────────────────────────────────────────────────────────────────────────
# Stdlib module names (for shadow detection)
# ─────────────────────────────────────────────────────────────────────────────

def _get_stdlib_names() -> Set[str]:
    """Get stdlib module names for the running Python version."""
    # Python 3.10+ has sys.stdlib_module_names
    if hasattr(sys, 'stdlib_module_names'):
        return set(sys.stdlib_module_names)
    # Fallback: common stdlib modules that are frequently shadowed
    return {
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
        'asyncore', 'atexit', 'base64', 'bdb', 'binascii', 'binhex',
        'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk',
        'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections',
        'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
        'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv',
        'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm', 'decimal',
        'difflib', 'dis', 'distutils', 'doctest', 'email', 'encodings',
        'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
        'fnmatch', 'formatter', 'fractions', 'ftplib', 'functools', 'gc',
        'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip', 'hashlib',
        'heapq', 'hmac', 'html', 'http', 'idlelib', 'imaplib', 'imghdr',
        'imp', 'importlib', 'inspect', 'io', 'ipaddress', 'itertools',
        'json', 'keyword', 'lib2to3', 'linecache', 'locale', 'logging',
        'lzma', 'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes',
        'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis', 'nntplib',
        'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'parser',
        'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
        'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint',
        'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
        'pydoc', 'queue', 'quopri', 'random', 're', 'readline', 'reprlib',
        'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
        'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site',
        'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'sqlite3',
        'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct',
        'subprocess', 'sunau', 'symtable', 'sys', 'sysconfig', 'syslog',
        'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
        'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token',
        'tokenize', 'trace', 'traceback', 'tracemalloc', 'tty', 'turtle',
        'turtledemo', 'types', 'typing', 'unicodedata', 'unittest', 'urllib',
        'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref', 'webbrowser',
        'winreg', 'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc',
        'zipapp', 'zipfile', 'zipimport', 'zlib',
    }

_STDLIB_NAMES = _get_stdlib_names()

# ─────────────────────────────────────────────────────────────────────────────
# Expected external packages = the target's DECLARED dependencies
# ─────────────────────────────────────────────────────────────────────────────
# FIX_16 (F-PH-EXT1, 2026-09-10): the old module-global expected-external set (an empty set literal)
# was never populated anywhere in the tree, so the "unguarded external import" measurement and the
# missing-package suppression silently never ran (a silent zero). The set is now per scan —
# `declared_dependencies(repo_path)` below — passed into every reader; when a target declares
# nothing the measurement is published as NOT MEASURED (a `not_measured` row), never as an
# empty list. Step 3 (the intent file's packaging facts, Items 3 + 8) rides Item 8's run.


@dataclass
class PathHack:
    """Represents a detected path manipulation or structural issue."""
    file: str
    line: int
    type: str
    details: str
    # FIX_49 / FIX_50 (2026-09-17, owner Q9 / Q10): the DISPOSITION of this hack — data, from
    # `system_scripts/rule_dispositions.json`'s `path_hacks` section, resolved per (type, CONTEXT)
    # by `engine_utils.path_hack_disposition` and stamped by the circuit daemon. The detector never
    # decides it (step 17 keeps policy out of detectors): 'deciding' = an infraction as today,
    # 'context' = INFORMATIONAL — published with its `warning`, never counted.
    disposition: str = "deciding"
    warning: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# A + B: AST-based per-file detection
# ─────────────────────────────────────────────────────────────────────────────

class PathHackDetector(ast.NodeVisitor):
    """AST visitor to detect path manipulation patterns."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.hacks: List[PathHack] = []

    # ── imports ──────────────────────────────────────────────────────────

    def visit_ImportFrom(self, node):
        """Detect relative imports and wildcard imports."""
        if node.level > 0:
            self.hacks.append(PathHack(
                file=self.filepath,
                line=node.lineno,
                type='relative_import',
                details=f"Relative import: {'.' * node.level}{node.module or ''}"
            ))

        # --- D: Wildcard imports (from X import *) ---
        if node.names and any(alias.name == '*' for alias in node.names):
            module = ('.' * node.level) + (node.module or '')
            self.hacks.append(PathHack(
                file=self.filepath,
                line=node.lineno,
                type='wildcard_import',
                details=f"from {module} import * — pollutes namespace, breaks traceability"
            ))

        self.generic_visit(node)

    # ── calls ────────────────────────────────────────────────────────────

    def visit_Call(self, node):
        """Detect sys.path manipulation, Path('.'), __file__ traversal, os.environ access."""
        # --- A: sys.path.insert / append / extend ---
        if self._is_sys_path_method(node):
            method = node.func.attr
            path_arg = self._extract_sys_path_arg(node, method)
            self.hacks.append(PathHack(
                file=self.filepath,
                line=node.lineno,
                type=f'sys_path_{method}',
                details=f"sys.path.{method}({path_arg or '...'})"
            ))

        # --- B: Path(".") / Path("..") / Path("../…") / Path("./…") ---
        if self._is_path_call(node) and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                val = first_arg.value
                if val in ('.', '..') or val.startswith('./') or val.startswith('../'):
                    self.hacks.append(PathHack(
                        file=self.filepath,
                        line=node.lineno,
                        type='relative_path',
                        details=f'Path("{val}") — relative, should resolve to absolute'
                    ))

        # --- B: Path(__file__) ---
        if self._is_path_call(node) and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id == '__file__':
                self.hacks.append(PathHack(
                    file=self.filepath,
                    line=node.lineno,
                    type='file_traversal',
                    details='Path(__file__) — __file__ traversal'
                ))

        # --- B: os.path.dirname(__file__) ---
        if self._is_os_path_dirname(node) and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id == '__file__':
                self.hacks.append(PathHack(
                    file=self.filepath,
                    line=node.lineno,
                    type='file_traversal',
                    details='os.path.dirname(__file__) — __file__ traversal'
                ))

        # --- B: os.path.abspath / os.path.join with __file__ ---
        if self._is_os_path_method(node, ('abspath', 'join', 'realpath')):
            for arg in node.args:
                if self._tree_contains_name(arg, '__file__'):
                    self.hacks.append(PathHack(
                        file=self.filepath,
                        line=node.lineno,
                        type='file_traversal',
                        details=f'{ast.unparse(node)[:80]} — __file__ traversal'
                    ))
                    break

        # --- B: Bare "." / ".." in os.makedirs / os.path.* calls ---
        if self._is_os_call(node, ('makedirs', 'mkdir', 'chdir')):
            for arg in node.args:
                if self._is_dot_string(arg):
                    self.hacks.append(PathHack(
                        file=self.filepath,
                        line=node.lineno,
                        type='relative_path',
                        details=f'{ast.unparse(node)[:80]} — relative "." path'
                    ))
                    break
        if self._is_os_path_method(node, ('dirname', 'abspath', 'join', 'realpath')):
            for arg in node.args:
                if self._is_dot_string(arg):
                    self.hacks.append(PathHack(
                        file=self.filepath,
                        line=node.lineno,
                        type='relative_path',
                        details=f'{ast.unparse(node)[:80]} — relative "." path'
                    ))
                    break

        # --- B: "." / ".." as keyword arg with path-like name ---
        _PATH_KWARG_NAMES = {'path', 'dir', 'directory', 'cwd', 'target_dir',
                             'working_copy_dir', 'base_dir', 'root', 'dest', 'src'}
        for kw in node.keywords:
            if kw.arg and kw.arg.lower() in _PATH_KWARG_NAMES and self._is_dot_string(kw.value):
                # Downgrade to informational if inside __main__ or function body
                in_safe_ctx = _is_import_guarded(node)  # reuses same parent-walk logic
                hack_type = 'relative_path_idiom' if in_safe_ctx else 'relative_path'
                self.hacks.append(PathHack(
                    file=self.filepath,
                    line=node.lineno,
                    type=hack_type,
                    details=f'{kw.arg}="{kw.value.value}" — relative path in call'
                ))

        # --- B: "." / ".." as positional arg to path-like methods ---
        if isinstance(node.func, ast.Attribute):
            _PATH_METHOD_NAMES = {'resolve_path', 'validate_path',
                                  'set_path', 'chdir', 'open'}
            # Note: sanitize_path excluded — passing "." to a sanitizer is correct
            if node.func.attr in _PATH_METHOD_NAMES:
                for arg in node.args:
                    if self._is_dot_string(arg):
                        self.hacks.append(PathHack(
                            file=self.filepath,
                            line=node.lineno,
                            type='relative_path',
                            details=f'.{node.func.attr}("{arg.value}") — relative path arg'
                        ))
                        break

        # --- B: "or '.'" fallback pattern (e.g. dirname(x) or ".") ---
        # Handled in visit_BoolOp below

        # --- os.environ['PYTHONPATH'] via method call ---
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Subscript) and
                self._is_os_environ(node.func.value.value) and
                self._subscript_is(node.func.value, 'PYTHONPATH')):
                self.hacks.append(PathHack(
                    file=self.filepath,
                    line=node.lineno,
                    type='pythonpath_access',
                    details="os.environ['PYTHONPATH'] access"
                ))

        self.generic_visit(node)

    # ── subscript ────────────────────────────────────────────────────────

    def visit_Subscript(self, node):
        """Detect os.environ['PYTHONPATH'] reads AND writes (F-PH1, 2026-09-05:
        the label follows the AST context — a Store is an assignment, a Del a
        deletion, anything else a read)."""
        if self._is_os_environ(node.value) and self._subscript_is(node, 'PYTHONPATH'):
            if isinstance(node.ctx, ast.Store):
                kind, verb = 'pythonpath_write', 'Assigning'
            elif isinstance(node.ctx, ast.Del):
                kind, verb = 'pythonpath_delete', 'Deleting'
            else:
                kind, verb = 'pythonpath_read', 'Reading'
            self.hacks.append(PathHack(
                file=self.filepath,
                line=node.lineno,
                type=kind,
                details=f"{verb} os.environ['PYTHONPATH']"
            ))
        self.generic_visit(node)

    # ── attribute chains (catch .parent.parent on Path(__file__)) ────────

    def visit_Attribute(self, node):
        """Detect __file__ parent-chain traversal like Path(__file__).parent.parent."""
        chain = self._unwind_parent_chain(node)
        if chain and chain >= 2:
            # Two or more .parent calls — likely directory traversal
            try:
                source = ast.unparse(node)
                if '__file__' in source and len(source) <= 100:
                    self.hacks.append(PathHack(
                        file=self.filepath,
                        line=node.lineno,
                        type='file_traversal',
                        details=f'{source} — __file__ directory traversal'
                    ))
            except Exception:
                pass
        self.generic_visit(node)

    # ── "or '.'" fallback detection ─────────────────────────────────────

    def visit_BoolOp(self, node):
        """Detect 'expr or "."' fallback patterns — standard Python idiom, informational."""
        if isinstance(node.op, ast.Or) and len(node.values) >= 2:
            last = node.values[-1]
            if self._is_dot_string(last):
                try:
                    source = ast.unparse(node)
                    if len(source) <= 100:
                        self.hacks.append(PathHack(
                            file=self.filepath,
                            line=node.lineno,
                            type='relative_path_idiom',
                            details=f'{source} — or "." fallback (standard idiom)'
                        ))
                except Exception:
                    pass
        self.generic_visit(node)

    # ── default arg "." detection ────────────────────────────────────────

    def visit_FunctionDef(self, node):
        """Detect function defaults that use '.' or '..' as path arguments."""
        for default in node.args.defaults + node.args.kw_defaults:
            if default and self._is_dot_string(default):
                # Find which parameter this default belongs to
                try:
                    source = ast.unparse(default)
                    self.hacks.append(PathHack(
                        file=self.filepath,
                        line=node.lineno,
                        type='relative_path',
                        details=f'Default arg "{source}" in {node.name}() — relative path default'
                    ))
                except Exception:
                    pass
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_dot_string(node) -> bool:
        """Check if an AST node is a string constant "." or ".."."""
        return (isinstance(node, ast.Constant) and
                isinstance(node.value, str) and
                node.value in ('.', '..'))

    @staticmethod
    def _is_os_call(node, methods: tuple) -> bool:
        """Check if node is os.makedirs/os.mkdir/os.chdir(...)."""
        func = node.func
        return (isinstance(func, ast.Attribute) and func.attr in methods and
                isinstance(func.value, ast.Name) and func.value.id == 'os')

    @staticmethod
    def _is_sys_path_method(node) -> bool:
        """Check if node is sys.path.insert/append/extend()."""
        if not isinstance(node.func, ast.Attribute):
            return False
        if node.func.attr not in ('insert', 'append', 'extend'):
            return False
        val = node.func.value
        return (isinstance(val, ast.Attribute) and
                isinstance(val.value, ast.Name) and
                val.value.id == 'sys' and val.attr == 'path')

    @staticmethod
    def _extract_sys_path_arg(node, method: str):
        if not node.args:
            return None
        idx = 1 if method == 'insert' and len(node.args) > 1 else 0
        if idx < len(node.args):
            try:
                return ast.unparse(node.args[idx])
            except Exception:
                pass
        return None

    @staticmethod
    def _is_path_call(node) -> bool:
        """Check if node is Path(…) or pathlib.Path(…)."""
        func = node.func
        if isinstance(func, ast.Name) and func.id == 'Path':
            return True
        if (isinstance(func, ast.Attribute) and func.attr == 'Path' and
            isinstance(func.value, ast.Name) and func.value.id == 'pathlib'):
            return True
        return False

    @staticmethod
    def _is_os_path_dirname(node) -> bool:
        func = node.func
        return (isinstance(func, ast.Attribute) and func.attr == 'dirname' and
                isinstance(func.value, ast.Attribute) and func.value.attr == 'path' and
                isinstance(func.value.value, ast.Name) and func.value.value.id == 'os')

    @staticmethod
    def _is_os_path_method(node, methods: tuple) -> bool:
        func = node.func
        return (isinstance(func, ast.Attribute) and func.attr in methods and
                isinstance(func.value, ast.Attribute) and func.value.attr == 'path' and
                isinstance(func.value.value, ast.Name) and func.value.value.id == 'os')

    @staticmethod
    def _is_os_environ(node) -> bool:
        return (isinstance(node, ast.Attribute) and
                isinstance(node.value, ast.Name) and
                node.value.id == 'os' and node.attr == 'environ')

    @staticmethod
    def _subscript_is(node, key: str) -> bool:
        return (isinstance(node.slice, ast.Constant) and
                node.slice.value == key)

    @staticmethod
    def _tree_contains_name(node, name: str) -> bool:
        """Check if any Name node with the given id exists in the subtree."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == name:
                return True
        return False

    @staticmethod
    def _unwind_parent_chain(node) -> int:
        """Count consecutive .parent attribute accesses. Returns count or 0."""
        count = 0
        cur = node
        while isinstance(cur, ast.Attribute) and cur.attr == 'parent':
            count += 1
            cur = cur.value
        return count


# ─────────────────────────────────────────────────────────────────────────────
# Per-file scanning
# ─────────────────────────────────────────────────────────────────────────────

def scan_file_for_path_hacks(filepath: Path) -> List[PathHack]:
    """Scan a single Python file for path manipulation patterns."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()

        tree = ast.parse(source, filename=str(filepath))
        _link_parents(tree)
        detector = PathHackDetector(str(filepath))
        detector.visit(tree)

        return detector.hacks
    except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
        logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_file_for_path_hacks', _e)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# C: Structural issue detection (repo-level, not per-file)
# ─────────────────────────────────────────────────────────────────────────────

NOT_MEASURED_KEY = '(measurements)'   # FIX_16: the results key that carries measurement status rows, never a file


def declared_dependencies(repo_path: Path) -> Set[str]:
    """The target's declared dependencies as import-ish names — see `declared_dependencies_with_source`."""
    return declared_dependencies_with_source(repo_path)[0]


def declared_dependencies_with_source(repo_path: Path) -> Tuple[Set[str], str]:
    """(declared set, where it came from). FIX_16 step 3 (Item 8, 2026-09-15): the PRIMARY source is the intent
    file's packaging facts (`system_scripts/intent_<repoid>.json`, `source: packaging`, `fact: dependencies` — the
    artifact scanner's reading of pyproject / setup / requirements, Item 3); the detector's own parse of
    `pyproject.toml` `[project.dependencies]` + `requirements*.txt` is the FALLBACK when the intent file carries
    none. Same normalisation either way (lower, `-` → `_`); runs ONCE per scan. Empty set = declares nothing."""
    try:
        _ss = str(Path(__file__).resolve().parent)
        if _ss not in sys.path:
            sys.path.insert(0, _ss)
        import intent_file as _intent  # type: ignore
        from_intent = _intent.declared_dependency_names(_intent.read(repo_path))
        if from_intent:
            return from_intent, "intent file (packaging facts)"
    except Exception as _e:
        logging.getLogger(__name__).warning("intent file not read for declared dependencies: %r", _e)
    parsed = _parse_declared_dependencies(repo_path)
    return parsed, ("packaging parse (pyproject / requirements*.txt)" if parsed else "none declared")


def _parse_declared_dependencies(repo_path: Path) -> Set[str]:
    """The detector's own parse (FIX_16, 2026-09-10): package names from `pyproject.toml` `[project.dependencies]` /
    `dependencies = [...]` and from `requirements*.txt`, lower-cased with `-` → `_` (the same normalisation
    `_check_dependency_drift` always used)."""
    declared: Set[str] = set()
    pyproject = repo_path / 'pyproject.toml'
    if pyproject.exists():
        try:
            with open(pyproject, 'r', encoding='utf-8') as f:
                content = f.read()
            # Simple regex to extract dependency names from [project.dependencies]
            # Handles: "requests>=2.0", "flask", "python-dateutil~=2.8"
            in_deps = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == '[project.dependencies]' or stripped.startswith('dependencies = ['):
                    in_deps = True
                    continue
                if in_deps:
                    if stripped.startswith('[') and not stripped.startswith('["'):
                        break
                    if stripped == ']':
                        in_deps = False
                        continue
                    # Extract package name: "requests>=2.0" -> "requests"
                    match = re.match(r'["\']?([a-zA-Z0-9_-]+)', stripped)
                    if match:
                        # Normalize: python-dateutil -> python_dateutil (import name)
                        declared.add(match.group(1).lower().replace('-', '_'))
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'declared_dependencies', _e)
            pass
    for req_file in ['requirements.txt', 'requirements-dev.txt', 'requirements_dev.txt']:
        req_path = repo_path / req_file
        if req_path.exists():
            try:
                with open(req_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith('-'):
                            continue
                        match = re.match(r'([a-zA-Z0-9_-]+)', line)
                        if match:
                            declared.add(match.group(1).lower().replace('-', '_'))
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'declared_dependencies', _e)
                pass
    return declared


def scan_structural_issues(repo_path: Path) -> Dict[str, List[PathHack]]:
    """Detect structural packaging issues in a repository.

    Checks:
    - Directories with .py files but no __init__.py
    - Packages with only __init__.py (empty source packages)
    - Duplicate package names across the repo tree
    - Imports of packages not present in the repo
    """
    results: Dict[str, List[PathHack]] = {}

    # FIX_16: the expected-external set is the target's declared dependencies, read ONCE per scan and
    # passed to every reader (no module global). Declares nothing → the unguarded-external measurement
    # is published as NOT MEASURED — true or NOT MEASURED, never a silent zero.
    declared_deps, declared_from = declared_dependencies_with_source(repo_path)
    if not declared_deps:
        results.setdefault(NOT_MEASURED_KEY, []).append(PathHack(
            file=NOT_MEASURED_KEY,
            line=0,
            type='not_measured',
            details=("imports of outside packages with no fallback (unguarded_external): NOT MEASURED — no declared dependencies "
                     "(no [project.dependencies] / requirements*.txt in the target, none in the intent file)")
        ))
    else:
        # FIX_16 step 3 (2026-09-15): the measurement's feed, published as a status row (never a hack, never counted)
        results.setdefault(NOT_MEASURED_KEY, []).append(PathHack(
            file=NOT_MEASURED_KEY,
            line=0,
            type='measured',
            details=(f"imports of outside packages with no fallback (unguarded_external): MEASURED against {len(declared_deps)} declared dependenc"
                     f"{'y' if len(declared_deps) == 1 else 'ies'} from the {declared_from}: "
                     + ", ".join(sorted(declared_deps)))
        ))

    # Collect all directories that contain .py files
    dirs_with_py: Dict[Path, Set[str]] = {}  # dir -> set of .py filenames
    package_names: Dict[str, List[Path]] = {}  # name -> [paths]

    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        parent = py_file.parent
        if parent not in dirs_with_py:
            dirs_with_py[parent] = set()
        dirs_with_py[parent].add(py_file.name)

    for dir_path, py_files in dirs_with_py.items():
        try:
            rel = str(dir_path.relative_to(repo_path))
        except ValueError:
            continue
        if rel == '.':
            rel = '(root)'

        # --- Missing __init__.py ---
        has_init = '__init__.py' in py_files
        real_files = {f for f in py_files if f != '__init__.py' and f != 'conftest.py'}

        # Directories that don't need __init__.py
        _NO_INIT_OK = {'tests', 'test', 'scripts', 'utils', 'bin', 'tools', 'examples'}
        dir_leaf = dir_path.name
        needs_init = dir_leaf not in _NO_INIT_OK and not dir_leaf.startswith('test_')

        if not has_init and len(real_files) > 0 and needs_init:
            # Directory has source .py files but isn't a package
            results.setdefault(rel, []).append(PathHack(
                file=rel,
                line=0,
                type='missing_init',
                details=f"Directory has {len(real_files)} .py files but no __init__.py"
            ))

        # --- Empty source package (skip test dirs) ---
        dir_name = dir_path.name
        is_test_dir = dir_name in ('tests', 'test') or dir_name.startswith('test_')
        if has_init and len(real_files) == 0 and not is_test_dir:
            # Check if __init__.py has substantial code (not just re-exports)
            init_path = dir_path / '__init__.py'
            init_has_code = False
            try:
                code_lines = [l for l in init_path.read_text().splitlines()
                              if l.strip() and not l.strip().startswith('#')]
                init_has_code = len(code_lines) > 10
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_structural_issues', _e)
                pass
            # Check if directory has subpackages (subdirs with .py files)
            has_subpackages = any(
                sub_dir in dirs_with_py
                for sub_dir in dir_path.iterdir()
                if sub_dir.is_dir() and not sub_dir.name.startswith('.')
            )
            if not init_has_code and not has_subpackages:
                results.setdefault(rel, []).append(PathHack(
                    file=rel,
                    line=0,
                    type='empty_package',
                    details="Package has __init__.py but no source modules"
                ))

        # --- Track package names for duplicate detection ---
        if has_init:
            pkg_name = dir_path.name
            package_names.setdefault(pkg_name, []).append(dir_path)

    # --- Duplicate package names (test packages published too, tagged) ---
    for pkg_name, paths in package_names.items():
        is_test_pkg = pkg_name in ('tests', 'test') or pkg_name.startswith('test_')  # EXCISED cut 3 batch 5 (2026-09-06, line read): was a `continue` (name mute); now a published fact
        if len(paths) > 1:
            locations = []
            for p in paths:
                try:
                    locations.append(str(p.relative_to(repo_path)))
                except ValueError:
                    locations.append(str(p))
            # Report under a synthetic key
            key = f"(duplicate:{pkg_name})"
            results.setdefault(key, []).append(PathHack(
                file=key,
                line=0,
                type='duplicate_package',
                details=f"Package '{pkg_name}' exists at: {', '.join(locations)}" + (" (test package)" if is_test_pkg else "")
            ))

    # --- Missing referenced packages ---
    # Collect all top-level imports across the repo and flag those that don't
    # resolve to a local package or file (and aren't stdlib/known third-party).
    local_packages = {p.name for paths_list in package_names.values() for p in paths_list}
    local_modules = set()
    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        try:
            rel_path = py_file.relative_to(repo_path)
            if len(rel_path.parts) == 1:
                local_modules.add(py_file.stem)
        except ValueError:
            pass
    local_names = local_packages | local_modules

    # If the repo root is itself a package (has __init__.py), its own name is
    # used in self-referential imports like `from mypkg.module import X`.
    # Detect that name and add it to local_names so those aren't flagged.
    root_init = repo_path / '__init__.py'
    if root_init.exists():
        import collections as _collections
        _pkg_candidates: _collections.Counter = _collections.Counter()
        for _pf in list(repo_path.glob('*.py')):  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `[:10]` sample removed
            try:
                _tree = ast.parse(_pf.read_text(), filename=str(_pf))
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_structural_issues', _e)
                continue
            for _n in ast.walk(_tree):
                if (isinstance(_n, ast.ImportFrom) and _n.module
                        and _n.level == 0 and '.' in _n.module):
                    _top = _n.module.split('.')[0]
                    if not (repo_path / _top).is_dir():
                        _pkg_candidates[_top] += 1
        if _pkg_candidates:
            _best, _count = _pkg_candidates.most_common(1)[0]
            if _count >= 1:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was `>= 3`
                local_names.add(_best)

    # Scan top-level __init__.py for imports of missing local packages
    # Skip stdlib and relative imports — only flag things that look like
    # local siblings that don't exist
    if root_init.exists():
        try:
            with open(root_init, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(root_init))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    top_mod = node.module.split('.')[0]
                    if (top_mod not in local_names and top_mod not in _STDLIB_NAMES
                            and top_mod not in declared_deps):
                        results.setdefault('__init__.py', []).append(PathHack(
                            file='__init__.py',
                            line=node.lineno,
                            type='missing_package',
                            details=f"Imports '{node.module}' — package not found in repo"
                        ))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        top_mod = alias.name.split('.')[0]
                        if (top_mod not in local_names and top_mod not in _STDLIB_NAMES
                                and top_mod not in declared_deps):
                            results.setdefault('__init__.py', []).append(PathHack(
                                file='__init__.py',
                                line=node.lineno,
                                type='missing_package',
                                details=f"Imports '{alias.name}' — package not found in repo"
                            ))
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_structural_issues', _e)
            pass

    # --- Unconnected __init__.py / re-export-only detection ---
    # Build sets of imported names, tracking WHERE each import originates:
    #   init_only_imports  — names imported exclusively from __init__.py files
    #   consumer_imports   — names imported from real consumer modules
    imported_names: Set[str] = set()
    init_imported: Set[str] = set()      # imported from __init__.py
    consumer_imported: Set[str] = set()  # imported from non-__init__.py
    # Track which __init__.py files import which prefixes (for self-import filtering)
    init_import_sources: Dict[str, Set[str]] = {}  # prefix -> set of importer package paths

    def _add_import(dotted: str, is_init_file: bool, importer_pkg: str = ''):
        """Register all prefix paths for a dotted import."""
        parts = dotted.split('.')
        for i in range(len(parts)):
            prefix = '.'.join(parts[:i+1])
            imported_names.add(prefix)
            if is_init_file:
                init_imported.add(prefix)
                init_import_sources.setdefault(prefix, set()).add(importer_pkg)
            else:
                consumer_imported.add(prefix)

    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        is_init = (py_file.name == '__init__.py')
        # Compute the dotted package path of the importing file
        try:
            _file_rel = py_file.relative_to(repo_path)
            _importer_pkg = '.'.join(p for p in _file_rel.parent.parts if p != '.')
        except ValueError:
            _importer_pkg = ''
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        _add_import(alias.name, is_init, _importer_pkg)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    _add_import(node.module, is_init, _importer_pkg)
                elif isinstance(node, ast.ImportFrom) and node.level > 0:
                    # Resolve relative imports to absolute dotted paths
                    # e.g. "from .core import X" in pkg/__init__.py -> "pkg.core"
                    try:
                        file_rel = py_file.relative_to(repo_path)
                        pkg_parts = [p for p in file_rel.parent.parts if p != '.']
                        up = node.level - 1
                        if up <= len(pkg_parts):
                            base_parts = pkg_parts[:len(pkg_parts) - up]
                            if node.module:
                                resolved = '.'.join(base_parts + node.module.split('.'))
                                _add_import(resolved, is_init, _importer_pkg)
                            else:
                                # "from . import X" — each name is a sub-module
                                base = '.'.join(base_parts)
                                for alias in node.names:
                                    full = f"{base}.{alias.name}" if base else alias.name
                                    _add_import(full, is_init, _importer_pkg)
                    except ValueError:
                        pass
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_structural_issues', _e)
            continue

    # Check each package with __init__.py
    for dir_path, py_files in dirs_with_py.items():
        if '__init__.py' not in py_files:
            continue
        try:
            rel_dir = dir_path.relative_to(repo_path)
        except ValueError:
            continue

        # Skip test directories
        rel_parts = rel_dir.parts
        if any(p in ('tests', 'test') or p.startswith('test_') for p in rel_parts):
            continue
        # Skip root package
        if str(rel_dir) == '.':
            continue

        # Build the dotted package path: "detection/core_checks" -> "detection.core_checks"
        dotted = '.'.join(rel_parts)

        # Also check just the leaf name (for top-level packages)
        leaf = rel_parts[-1] if rel_parts else ''

        if dotted not in imported_names and leaf not in imported_names:
            rel_str = str(rel)
            results.setdefault(rel_str, []).append(PathHack(
                file=rel_str,
                line=0,
                type='unconnected_init',
                details=f"Package '{dotted}' has __init__.py but is never imported"
            ))
        elif (dotted in init_imported or leaf in init_imported) and \
             dotted not in consumer_imported and leaf not in consumer_imported:
            # Check if the ONLY __init__.py importers are within the package itself
            # (a package's own __init__.py importing its submodules is normal, not re-export)
            sources = init_import_sources.get(dotted, set()) | init_import_sources.get(leaf, set())
            external_init_importers = {
                src for src in sources
                if not src.startswith(dotted + '.') and src != dotted
            }
            if external_init_importers:
                # Imported from an __init__.py OUTSIDE this package but no consumer uses it
                rel_str = str(rel)
                results.setdefault(rel_str, []).append(PathHack(
                    file=rel_str,
                    line=0,
                    type='reexport_only',
                    details=f"Package '{dotted}' is re-exported in __init__.py but no consumer imports it"
                ))

    # --- D: Shadowed stdlib modules ---
    # Check if any .py file or package dir shares a name with a stdlib module
    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        stem = py_file.stem
        if stem == '__init__' or stem == 'conftest' or stem == 'setup':
            continue
        if stem in _STDLIB_NAMES:
            try:
                rel_str = str(py_file.relative_to(repo_path))
            except ValueError:
                continue
            results.setdefault(rel_str, []).append(PathHack(
                file=rel_str,
                line=0,
                type='shadowed_stdlib',
                details=f"'{stem}.py' shadows stdlib module '{stem}' — will break 'import {stem}'"
            ))

    # --- Broken imports: imports that don't resolve to actual files ---
    _check_broken_imports(repo_path, local_names, results, declared_deps)

    # --- Circular imports: modules that import each other ---
    _check_circular_imports(repo_path, results, declared_deps)

    # --- D: Dependency drift (imports vs declared deps) ---
    # FIX_16: reuses the ONE parse above (no second read of the packaging files)
    _check_dependency_drift(repo_path, imported_names, results, declared_deps)

    # --- Naming drift: inconsistent project names across pyproject.toml files ---
    _check_naming_drift(repo_path, results)

    return results


def _link_parents(tree):
    """Add _parent attribute to all AST nodes for upward traversal."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node


def _is_import_guarded(node) -> bool:
    """Check if an import node is safely guarded (won't crash on ImportError).

    Returns True if the import is inside:
    - try/except block
    - if TYPE_CHECKING: block
    - function/method body (lazy import)
    - if __name__ == "__main__": block
    """
    current = getattr(node, '_parent', None)
    while current is not None:
        # Inside try/except
        if isinstance(current, ast.Try):
            return True
        # Python 3.11+ TryStar (except*)
        if hasattr(ast, 'TryStar') and isinstance(current, getattr(ast, 'TryStar')):
            return True
        # Inside if TYPE_CHECKING:
        if isinstance(current, ast.If):
            test = current.test
            if isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING':
                return True
            if isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING':
                return True
        # Inside function/method body (lazy import)
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        # Inside if __name__ == "__main__":
        if isinstance(current, ast.If):
            test = current.test
            if (isinstance(test, ast.Compare) and
                isinstance(test.left, ast.Name) and test.left.id == '__name__' and
                len(test.comparators) == 1 and
                isinstance(test.comparators[0], ast.Constant) and
                test.comparators[0].value == '__main__'):
                return True
        current = getattr(current, '_parent', None)
    return False


def _check_broken_imports(repo_path: Path, local_names: Set[str],
                           results: Dict[str, List[PathHack]],
                           declared_deps: Optional[Set[str]] = None):
    """Detect imports that reference modules/files that don't exist in the repo.

    For each Python file, check absolute and relative imports:
    - Absolute: 'from orchestrator.core.foo import X' — does core/foo.py exist?
    - Relative: 'from ..bar import X' — does the resolved path exist?

    Guarded imports (try/except, TYPE_CHECKING, lazy) are classified as
    'broken_import_guarded' (AMBER) vs bare 'broken_import' (RED).

    Only checks imports whose top-level matches a local package (skips stdlib,
    third-party, and the target's declared dependencies — FIX_16: `declared_deps`,
    per scan; a declared dependency imported without a guard is `unguarded_external`).
    """
    declared_deps = declared_deps or set()
    # Build a set of all existing module paths (dotted) for fast lookup
    existing_modules: Set[str] = set()
    repo_name = repo_path.name  # e.g. "orchestrator"

    _py_files = [f for f in repo_path.rglob("*.py") if not _should_skip(f)]
    # owner 2026-10-07: the same import roots the scanner and the runner use (M-68) — a wrapper folder that
    # holds packages is where `from charlie_work.x import y` resolves; from the repo root alone every such
    # import read "target module not found" (14 false criticals on a target with a nested package)
    try:
        import scan_scope as _ss_roots
        _roots = _ss_roots.import_roots(repo_path, _py_files)
    except Exception as _e:
        logging.getLogger(__name__).warning("import roots unavailable, repo root only: %r", _e)
        _roots = [repo_path]
    for py_file in _py_files:
      for _root in _roots:
        try:
            rel = py_file.relative_to(_root)
        except ValueError:
            continue
        # "core/gates/__init__.py" -> "core.gates"
        # "core/pipeline_validator.py" -> "core.pipeline_validator"
        parts = list(rel.parts)
        if parts[-1] == '__init__.py':
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1].replace('.py', '')
        if parts:
            dotted = '.'.join(parts)
            existing_modules.add(dotted)
            # Also add with repo name prefix (from orchestrator.core.X)
            existing_modules.add(f"{repo_name}.{dotted}")
        # Add all parent package prefixes
        for i in range(1, len(parts)):
            prefix = '.'.join(parts[:i])
            existing_modules.add(prefix)
            existing_modules.add(f"{repo_name}.{prefix}")

    # Also add the repo name itself
    existing_modules.add(repo_name)

    # Detect self-referential package name (repo dir name may differ from
    # the import name, e.g. dir "manager_review_n_triage_S15_READYTOSHIP"
    # but imports use "manager_review_n_triage")
    pkg_name: str | None = None
    if (repo_path / '__init__.py').exists():
        import collections as _collections
        _pkg_cands: _collections.Counter = _collections.Counter()
        for _pf in list(repo_path.glob('*.py')):  # EXCISED cut 3 batch 2 (2026-09-06, agreed): `[:10]` sample removed
            try:
                _t = ast.parse(_pf.read_text(), filename=str(_pf))
            except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
                logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", '_check_broken_imports', _e)
                continue
            for _n in ast.walk(_t):
                if (isinstance(_n, ast.ImportFrom) and _n.module
                        and _n.level == 0 and '.' in _n.module):
                    _top = _n.module.split('.')[0]
                    if not (repo_path / _top).is_dir():
                        _pkg_cands[_top] += 1
        if _pkg_cands:
            _best, _cnt = _pkg_cands.most_common(1)[0]
            if _cnt >= 1:  # EXCISED cut 3 batch 2 (2026-09-06, agreed)
                pkg_name = _best
                existing_modules.add(pkg_name)
                # Re-add all module paths with the real package name prefix
                for py_file in repo_path.rglob("*.py"):
                    if _should_skip(py_file):
                        continue
                    try:
                        rel = py_file.relative_to(repo_path)
                    except ValueError:
                        continue
                    parts = list(rel.parts)
                    if parts[-1] == '__init__.py':
                        parts = parts[:-1]
                    else:
                        parts[-1] = parts[-1].replace('.py', '')
                    if parts:
                        existing_modules.add(f"{pkg_name}.{'.'.join(parts)}")
                    for i in range(1, len(parts)):
                        existing_modules.add(f"{pkg_name}.{'.'.join(parts[:i])}")

    # Now scan every Python file for broken imports
    seen_broken: Set[str] = set()  # avoid duplicate reports

    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        try:
            rel = py_file.relative_to(repo_path)
            rel_str = str(rel)
        except ValueError:
            continue

        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(py_file))
            _link_parents(tree)
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", '_check_broken_imports', _e)
            continue

        for node in ast.walk(tree):
            # --- Absolute imports: from orchestrator.core.foo import X ---
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                top_mod = node.module.split('.')[0]
                # Expected external: not broken, but flag if unguarded
                if top_mod in declared_deps:
                    if not _is_import_guarded(node):
                        dedup_key = f"{rel_str}:ext:{node.module}"
                        if dedup_key not in seen_broken:
                            seen_broken.add(dedup_key)
                            results.setdefault(rel_str, []).append(PathHack(
                                file=rel_str,
                                line=node.lineno,
                                type='unguarded_external',
                                details=(
                                    f"from {node.module} import ... — "
                                    f"external package '{top_mod}' imported without try/except guard"
                                )
                            ))
                    continue
                # Only check imports that target local packages
                if top_mod not in local_names and top_mod != repo_name and top_mod != pkg_name:
                    continue
                # Check if the full dotted path resolves
                if node.module not in existing_modules:
                    dedup_key = f"{rel_str}:{node.module}"
                    if dedup_key not in seen_broken:
                        seen_broken.add(dedup_key)
                        guarded = _is_import_guarded(node)
                        hack_type = 'broken_import_guarded' if guarded else 'broken_import'
                        suffix = " (guarded)" if guarded else ""
                        results.setdefault(rel_str, []).append(PathHack(
                            file=rel_str,
                            line=node.lineno,
                            type=hack_type,
                            details=f"from {node.module} import ... — target module not found{suffix}"
                        ))

            # --- Absolute: import orchestrator.core.foo ---
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top_mod = alias.name.split('.')[0]
                    # Expected external: not broken, but flag if unguarded
                    if top_mod in declared_deps:
                        if not _is_import_guarded(node):
                            dedup_key = f"{rel_str}:ext:{alias.name}"
                            if dedup_key not in seen_broken:
                                seen_broken.add(dedup_key)
                                results.setdefault(rel_str, []).append(PathHack(
                                    file=rel_str,
                                    line=node.lineno,
                                    type='unguarded_external',
                                    details=(
                                        f"import {alias.name} — "
                                        f"external package '{top_mod}' imported without try/except guard"
                                    )
                                ))
                        continue
                    if top_mod not in local_names and top_mod != repo_name and top_mod != pkg_name:
                        continue
                    if alias.name not in existing_modules:
                        dedup_key = f"{rel_str}:{alias.name}"
                        if dedup_key not in seen_broken:
                            seen_broken.add(dedup_key)
                            guarded = _is_import_guarded(node)
                            hack_type = 'broken_import_guarded' if guarded else 'broken_import'
                            suffix = " (guarded)" if guarded else ""
                            results.setdefault(rel_str, []).append(PathHack(
                                file=rel_str,
                                line=node.lineno,
                                type=hack_type,
                                details=f"import {alias.name} — target module not found{suffix}"
                            ))

            # --- Relative imports: from ..foo import X ---
            elif isinstance(node, ast.ImportFrom) and node.level > 0:
                try:
                    file_rel = py_file.relative_to(repo_path)
                    pkg_parts = [p for p in file_rel.parent.parts if p != '.']
                    up = node.level - 1
                    if up > len(pkg_parts):
                        # Escapes package boundary
                        module_str = '.' * node.level + (node.module or '')
                        dedup_key = f"{rel_str}:{module_str}"
                        if dedup_key not in seen_broken:
                            seen_broken.add(dedup_key)
                            guarded = _is_import_guarded(node)
                            hack_type = 'broken_import_guarded' if guarded else 'broken_import'
                            suffix = " (guarded)" if guarded else ""
                            results.setdefault(rel_str, []).append(PathHack(
                                file=rel_str,
                                line=node.lineno,
                                type=hack_type,
                                details=(
                                    f"from {module_str} import ... — "
                                    f"relative import escapes package boundary{suffix}"
                                )
                            ))
                    else:
                        base_parts = pkg_parts[:len(pkg_parts) - up]
                        if node.module:
                            resolved = '.'.join(base_parts + node.module.split('.'))
                        else:
                            # "from . import X" — check each name
                            for alias in node.names:
                                base = '.'.join(base_parts)
                                resolved = f"{base}.{alias.name}" if base else alias.name
                                if resolved not in existing_modules:
                                    dedup_key = f"{rel_str}:.{alias.name}"
                                    if dedup_key not in seen_broken:
                                        seen_broken.add(dedup_key)
                                        guarded = _is_import_guarded(node)
                                        hack_type = 'broken_import_guarded' if guarded else 'broken_import'
                                        suffix = " (guarded)" if guarded else ""
                                        results.setdefault(rel_str, []).append(PathHack(
                                            file=rel_str,
                                            line=node.lineno,
                                            type=hack_type,
                                            details=(
                                                f"from {'.' * node.level} import {alias.name} "
                                                f"— target module not found{suffix}"
                                            )
                                        ))
                            continue
                        if resolved not in existing_modules:
                            module_str = '.' * node.level + (node.module or '')
                            dedup_key = f"{rel_str}:{module_str}"
                            if dedup_key not in seen_broken:
                                seen_broken.add(dedup_key)
                                guarded = _is_import_guarded(node)
                                hack_type = 'broken_import_guarded' if guarded else 'broken_import'
                                suffix = " (guarded)" if guarded else ""
                                results.setdefault(rel_str, []).append(PathHack(
                                    file=rel_str,
                                    line=node.lineno,
                                    type=hack_type,
                                    details=(
                                        f"from {module_str} import ... — "
                                        f"target module not found{suffix}"
                                    )
                                ))
                except ValueError:
                    pass


def _check_circular_imports(repo_path: Path, results: Dict[str, List[PathHack]],
                            declared_deps: Optional[Set[str]] = None):
    """Detect circular import dependencies between modules in the repo.

    Builds a directed import graph from AST analysis, finds strongly connected
    components (cycles) using iterative Tarjan's algorithm, then reports a
    representative shortest cycle for each SCC.

    Classification:
    - circular_import (RED): cycle has bare top-level imports (will cause
      ImportError or None-attribute bugs depending on import order)
    - circular_import_guarded (AMBER): all edges guarded (try/except,
      TYPE_CHECKING, lazy) — architecturally fragile but won't crash
    """
    from collections import deque

    repo_name = repo_path.name

    # ── Step 1: Map every .py file to its dotted module path ──────────
    file_to_module: Dict[str, str] = {}   # str(path) -> dotted module
    existing_modules: Set[str] = set()
    py_files_ordered: List[Path] = []

    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        try:
            rel = py_file.relative_to(repo_path)
        except ValueError:
            continue
        parts = list(rel.parts)
        if parts[-1] == '__init__.py':
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1].replace('.py', '')
        if not parts:
            continue
        dotted = '.'.join(parts)
        file_to_module[str(py_file)] = dotted
        existing_modules.add(dotted)
        py_files_ordered.append(py_file)

    def _resolve(dotted_import: str):
        """Resolve a dotted import string to a module in existing_modules."""
        if dotted_import in existing_modules:
            return dotted_import
        # Strip repo-name prefix: orchestrator.core.X -> core.X
        if dotted_import.startswith(repo_name + '.'):
            stripped = dotted_import[len(repo_name) + 1:]
            if stripped in existing_modules:
                return stripped
        # Walk up: core.tracing.setup -> core.tracing -> core
        parts = dotted_import.split('.')
        for i in range(len(parts) - 1, 0, -1):
            prefix = '.'.join(parts[:i])
            if prefix in existing_modules:
                return prefix
            if prefix.startswith(repo_name + '.'):
                stripped = prefix[len(repo_name) + 1:]
                if stripped in existing_modules:
                    return stripped
        return None

    # ── Step 2: Build directed import graph + edge metadata ───────────
    graph: Dict[str, Set[str]] = {m: set() for m in existing_modules}
    # (from_mod, to_mod) -> (is_guarded, rel_file, lineno)
    edge_meta: Dict[Tuple[str, str], Tuple[bool, str, int]] = {}

    for py_file in py_files_ordered:
        from_mod = file_to_module[str(py_file)]
        try:
            source = py_file.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(py_file))
            _link_parents(tree)
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", '_check_circular_imports', _e)
            continue

        try:
            rel_str = str(py_file.relative_to(repo_path))
        except ValueError:
            continue

        for node in ast.walk(tree):
            targets: List[str] = []

            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                if node.module.split('.')[0] not in (declared_deps or set()):   # FIX_16: declared externals are never cycle edges
                    targets.append(node.module)

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split('.')[0] not in (declared_deps or set()):
                        targets.append(alias.name)

            elif isinstance(node, ast.ImportFrom) and node.level > 0:
                try:
                    file_rel = py_file.relative_to(repo_path)
                    pkg_parts = [p for p in file_rel.parent.parts if p != '.']
                    up = node.level - 1
                    if up <= len(pkg_parts):
                        base = pkg_parts[:len(pkg_parts) - up]
                        if node.module:
                            targets.append('.'.join(base + node.module.split('.')))
                        else:
                            for a in node.names:
                                b = '.'.join(base)
                                targets.append(f"{b}.{a.name}" if b else a.name)
                except ValueError:
                    pass

            if not targets:
                continue

            guarded = _is_import_guarded(node)

            for t in targets:
                to_mod = _resolve(t)
                if to_mod and to_mod != from_mod:
                    graph.setdefault(from_mod, set()).add(to_mod)
                    key = (from_mod, to_mod)
                    if key not in edge_meta:
                        edge_meta[key] = (guarded, rel_str, getattr(node, 'lineno', 0))

    # ── Step 3: Find SCCs with iterative Tarjan's ─────────────────────
    idx = [0]
    stack: List[str] = []
    on_stack: Set[str] = set()
    index_of: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    sccs: List[List[str]] = []

    for start in list(graph.keys()):
        if start in index_of:
            continue

        # Iterative DFS frame: (node, neighbor_iterator)
        work: List[Tuple[str, Any]] = [(start, iter(graph.get(start, [])))]
        index_of[start] = lowlink[start] = idx[0]
        idx[0] += 1
        stack.append(start)
        on_stack.add(start)

        while work:
            v, it = work[-1]
            pushed = False

            for w in it:
                if w not in index_of:
                    # Tree edge — push w
                    index_of[w] = lowlink[w] = idx[0]
                    idx[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(graph.get(w, []))))
                    pushed = True
                    break
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_of[w])

            if not pushed:
                # v is fully explored
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[v])

                if lowlink[v] == index_of[v]:
                    comp: List[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    if len(comp) > 1:
                        sccs.append(comp)

    # ── Step 4: For each SCC, find shortest cycle and report ──────────
    seen_scc: Set[frozenset] = set()

    for scc in sccs:
        scc_key = frozenset(scc)
        if scc_key in seen_scc:
            continue
        seen_scc.add(scc_key)

        # BFS for shortest cycle through the SCC
        cycle = _shortest_cycle_in_scc(scc, graph)

        # Classify: any unguarded edge → RED, all guarded → AMBER
        has_unguarded = False
        for i in range(len(cycle)):
            src = cycle[i]
            dst = cycle[(i + 1) % len(cycle)]
            meta = edge_meta.get((src, dst))
            if meta and not meta[0]:
                has_unguarded = True
                break

        hack_type = 'circular_import' if has_unguarded else 'circular_import_guarded'
        cycle_str = ' → '.join(cycle) + ' → ' + cycle[0]

        # Get file/line from first edge
        first_edge = edge_meta.get((cycle[0], cycle[1])) if len(cycle) > 1 else None
        line = first_edge[2] if first_edge else 0

        report_key = f"(circular:{cycle[0]})"
        results.setdefault(report_key, []).append(PathHack(
            file=report_key,
            line=line,
            type=hack_type,
            details=f"Circular dependency: {cycle_str}"
        ))


def _shortest_cycle_in_scc(scc: List[str],
                            graph: Dict[str, Set[str]]) -> List[str]:
    """BFS from first node in SCC to find shortest cycle back to itself."""
    from collections import deque

    scc_set = set(scc)
    start = scc[0]

    # Seed BFS with direct neighbors of start (within the SCC)
    queue: deque = deque()
    for neighbor in graph.get(start, []):
        if neighbor in scc_set and neighbor != start:
            queue.append([start, neighbor])

    visited: Set[str] = set()

    while queue:
        path = queue.popleft()
        node = path[-1]

        # Does this node have an edge back to start?
        if start in graph.get(node, set()):
            return path  # cycle found

        if node in visited:
            continue
        visited.add(node)

        for neighbor in graph.get(node, []):
            if neighbor in scc_set and neighbor not in visited and neighbor != start:
                queue.append(path + [neighbor])

    return scc  # fallback: return entire SCC


def _check_dependency_drift(repo_path: Path, imported_names: Set[str],
                            results: Dict[str, List[PathHack]],
                            declared_deps: Optional[Set[str]] = None):
    """Check for mismatches between declared dependencies and actual imports.

    Flags:
    - Declared deps that nothing in the codebase imports (stale dep)
    - Top-level imports that aren't declared and aren't stdlib or local

    FIX_16 (2026-09-10): the declared set comes in from `declared_dependencies(repo_path)` — the
    parse that used to live here, run ONCE per scan by `scan_structural_issues`; a caller that
    passes nothing gets the same parse.
    """
    if declared_deps is None:
        declared_deps = declared_dependencies(repo_path)

    if not declared_deps:
        return  # No dependency files found, skip

    # Normalize imported names to lowercase for comparison
    imported_top_level = {name.split('.')[0].lower() for name in imported_names}

    # Common packages where install name != import name
    INSTALL_TO_IMPORT = {
        'python_dotenv': 'dotenv',
        'pillow': 'pil',
        'scikit_learn': 'sklearn',
        'pyyaml': 'yaml',
        'beautifulsoup4': 'bs4',
        'python_dateutil': 'dateutil',
        'attrs': 'attr',
        'opencv_python': 'cv2',
        'pymongo': 'pymongo',
        'protobuf': 'google',
    }

    # Find stale deps (declared but never imported)
    # Known tooling deps (add-ons, test runners, build tools) — published as context on the infraction, never excluded
    INDIRECT_DEPS = {
        'setuptools', 'wheel', 'pip', 'pytest', 'mypy', 'ruff', 'black', 'isort',
        'flake8', 'pylint', 'pre_commit', 'tox', 'nox', 'coverage', 'twine',
        'build', 'flit', 'hatch', 'maturin', 'cython', 'sphinx',
    }
    for dep in sorted(declared_deps):
        tooling = dep in INDIRECT_DEPS  # EXCISED cut 3 batch 5 (2026-09-06, line read): was a `continue` (name mute) — published as context on the infraction
        # Check both the package name and its known import alias
        import_name = INSTALL_TO_IMPORT.get(dep, dep)
        if dep not in imported_top_level and import_name not in imported_top_level:
            key = '(dep-drift)'
            results.setdefault(key, []).append(PathHack(
                file=key,
                line=0,
                type='stale_dependency',
                details=f"Declared dep '{dep}' is never imported — may be stale" + (" (known build/test tooling: used by the runner, not imported)" if tooling else "")
            ))


def _check_naming_drift(repo_path: Path, results: Dict[str, List[PathHack]]):
    """Detect inconsistent project naming across pyproject.toml files.

    Flags:
    - Multiple pyproject.toml files with different project names
    - Directory name vs project name mismatches
    - Project names using different naming conventions
    """
    project_names: Dict[str, str] = {}  # relative pyproject path -> project name
    dir_vs_name: List[Tuple[str, str, str]] = []  # (pyproject_rel, dir_name, project_name)

    for toml_file in repo_path.rglob("pyproject.toml"):
        if _should_skip(toml_file):
            continue
        try:
            with open(toml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            # Extract project name
            match = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
            if match:
                proj_name = match.group(1)
                rel = str(toml_file.relative_to(repo_path))
                project_names[rel] = proj_name
                # Compare project name to containing directory
                parent_dir = toml_file.parent.name
                if parent_dir == repo_path.name:
                    parent_dir = '(root)'
                dir_vs_name.append((rel, parent_dir, proj_name))
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", '_check_naming_drift', _e)
            continue

    if len(project_names) <= 1:
        return  # Single or no pyproject.toml — no drift possible

    # Detect inconsistent naming conventions across pyproject.toml files
    # Normalize names for comparison: lowercase, replace - and _ with nothing
    name_families: Dict[str, List[Tuple[str, str]]] = {}  # normalized stem -> [(path, raw_name)]
    for rel_path, raw_name in project_names.items():
        # Strip common prefixes/suffixes to find the conceptual "stem"
        normalized = raw_name.lower().replace('-', '_')
        name_families.setdefault(normalized, []).append((rel_path, raw_name))

    # If all project names are completely different (no shared stems),
    # flag them as naming drift
    unique_names = list(project_names.values())
    if len(set(unique_names)) > 1:
        locations = [f"  {path}: '{name}'" for path, name in project_names.items()]
        key = '(naming-drift)'
        results.setdefault(key, []).append(PathHack(
            file=key,
            line=0,
            type='naming_drift',
            details=(
                f"{len(project_names)} pyproject.toml files with different project names:\n"
                + '\n'.join(locations)
            )
        ))

    # Also flag directory-name vs project-name mismatches
    for rel_path, dir_name, proj_name in dir_vs_name:
        if dir_name == '(root)':
            continue
        # Normalize both for comparison
        dir_norm = dir_name.lower().replace('-', '_')
        proj_norm = proj_name.lower().replace('-', '_')
        # Check if project name contains the directory name or vice versa
        if dir_norm not in proj_norm and proj_norm not in dir_norm:
            key = '(naming-drift)'
            results.setdefault(key, []).append(PathHack(
                file=rel_path,
                line=0,
                type='naming_drift',
                details=(
                    f"Directory '{dir_name}' vs project name '{proj_name}' — "
                    f"no naming relationship"
                )
            ))


# ─────────────────────────────────────────────────────────────────────────────
# Config / shell / env file scanning (text-based)
# ─────────────────────────────────────────────────────────────────────────────

_CONFIG_EXTENSIONS = {
    '.toml', '.cfg', '.ini', '.yaml', '.yml', '.json',
    '.sh', '.bash', '.zsh', '.fish',
    '.env', '.envrc',
    '.mk',
}

_CONFIG_FILENAMES = {
    'Makefile', 'Dockerfile', 'Vagrantfile',
    '.env', '.envrc', '.bashrc', '.zshrc', '.profile', '.bash_profile',
}

_PYTHONPATH_RE = re.compile(r'pythonpath', re.IGNORECASE)

# Tool config keys where "pythonpath" is a legitimate setting, not an env-var hack.
# e.g. [tool.pytest.ini_options] pythonpath = ["."]
#      [mypy]                   pythonpath = "src"
_TOOL_PYTHONPATH_RE = re.compile(
    r'^\s*pythonpath\s*=',  # key = value assignment (TOML/INI style)
    re.IGNORECASE
)


def _should_skip(path: Path) -> bool:
    """Check if a path should be skipped during scanning.

    F-CIRC-WALK (2026-09-05, evening): the whitelist published through
    scan_scope is consulted FIRST — a whitelisted file or dir (venv by size,
    docs/, detritus) is outside the scan surface for this walker too.
    """
    try:
        import scan_scope  # system_scripts/, on sys.path when the daemon runs
        if scan_scope.excluded(path):
            return True
    except Exception:
        pass
    path_str = str(path)
    return ('__pycache__' in path_str
            or '/.git/' in path_str
            or '.egg-info/' in path_str
            or '/site-packages/' in path_str
            or '/.venv/' in path_str
            or '/venv/' in path_str
            or '/.tox/' in path_str
            or '/node_modules/' in path_str
            or '.mypy_cache/' in path_str
            or '.pytest_cache/' in path_str
            or '.ruff_cache/' in path_str
            or '/.atomic_backups/' in path_str
            or '/.detritus_backup/' in path_str
            or '/.backup/' in path_str
            or '/backups/' in path_str
            or '/__backup__/' in path_str
            or '/build/' in path_str
            or '/dist/' in path_str
            or path.name == 'circuit_state.json'
            or path.name == '.monitor_state.json'
            or path.name == '.noai_state.json'
            or path.name == 'baseline.json')


def scan_config_file_for_pythonpath(filepath: Path) -> List[PathHack]:
    """Scan a non-Python file for PYTHONPATH references.

    Skips tool configuration keys (pytest/mypy pythonpath = ...)
    which are legitimate settings, not env-var hacks.
    """
    is_toml_or_ini = filepath.suffix in ('.toml', '.cfg', '.ini')
    hacks = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, start=1):
                if _PYTHONPATH_RE.search(line):
                    # Skip tool config keys like: pythonpath = ["."]
                    # These are standard pytest/mypy settings, not env-var hacks.
                    if is_toml_or_ini and _TOOL_PYTHONPATH_RE.match(line):
                        continue
                    detail = line.strip()
                    if len(detail) > 120:
                        detail = detail[:117] + '...'
                    hacks.append(PathHack(
                        file=str(filepath),
                        line=lineno,
                        type='pythonpath_config',
                        details=f"PYTHONPATH in config: {detail}"
                    ))
    except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
        logging.getLogger(__name__).warning("reported, not swallowed (cut 3): %s: %r", 'scan_config_file_for_pythonpath', _e)
        pass
    return hacks


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def scan_repo_for_path_hacks(repo_path: Path) -> Dict[str, List[PathHack]]:
    """Scan entire repository for path hacks and structural issues.

    Checks:
    A. sys.path manipulation (AST)
    B. Relative path construction, __file__ traversal (AST)
    B. Relative imports (AST)
    C. Structural: missing __init__.py, empty packages, duplicate names, missing refs
    +  PYTHONPATH in config/shell/env files (text search)
    """
    results: Dict[str, List[PathHack]] = {}

    # Per-file scanning (A + B + PYTHONPATH config)
    for item in repo_path.rglob("*"):
        if item.is_dir() or _should_skip(item):
            continue

        rel_path = str(item.relative_to(repo_path))
        hacks: List[PathHack] = []

        if item.suffix == '.py':
            hacks = scan_file_for_path_hacks(item)
        elif item.suffix in _CONFIG_EXTENSIONS or item.name in _CONFIG_FILENAMES:
            hacks = scan_config_file_for_pythonpath(item)

        if hacks:
            results[rel_path] = hacks

    # Structural scanning (C)
    structural = scan_structural_issues(repo_path)
    for key, hacks in structural.items():
        results.setdefault(key, []).extend(hacks)

    return results
