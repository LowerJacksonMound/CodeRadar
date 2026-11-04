"""
GRANULARIZE HARNESS - I/O Function Tracker
AST-based scanner that finds functions performing I/O operations
and classifies them as async or sync.

Definition: An I/O function is any function (async or sync) that contains
detected I/O patterns in its body. Both async and sync must have I/O to count.
No free passes — being async alone doesn't qualify.

Two-pass approach:
    Pass 1: Detect direct I/O patterns via NodeVisitor (with generic_visit
            for proper recursion into nested defs/classes).
    Pass 2: Propagate I/O status through await chains — async functions
            that await a known I/O function inherit I/O status.
            Sync-to-sync calls do NOT propagate (prevents tracePoint etc.
            from cascading everywhere).

Uniqueness: keyed by file + line + name to prevent duplicates.
"""

import ast
import logging
from pathlib import Path
from datetime import datetime
from typing import Set, Union

# Type alias for function definition nodes
FuncNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

logger = logging.getLogger(__name__)

# Skip directories
def _scope_excluded(path) -> bool:
    """F-CIRC-WALK (2026-09-05): consult the launch whitelist published via
    system_scripts/scan_scope; no scope published => nothing excluded."""
    try:
        import scan_scope
        return bool(scan_scope.excluded(path))
    except Exception:
        return False


def _scan_scope():
    """FIX_15 (2026-09-10): the ONE scan surface (system_scripts/scan_scope.py) — the walk itself is
    iter_live_py: whitelist, engine hard-skips, containment (no symlink, nothing outside the root)."""
    try:
        import scan_scope
    except ImportError:
        import sys as _sys
        from pathlib import Path as _P
        _sys.path.insert(0, str(_P(__file__).resolve().parents[1]))
        import scan_scope
    return scan_scope


SKIP_DIRS = {'__pycache__', '.venv', 'venv', '.git', '.tox', 'node_modules',
             '.mypy_cache', 'tests', 'test'}  # cut 3 batch 5 addendum: no longer a gate anywhere in this module (kept for callers that read it)

# ── I/O pattern detection ────────────────────────────────────────────────────

# Builtin function names that are I/O (print handled separately — see below)
IO_BUILTINS = {'open'}

# Attribute names on any object that indicate I/O
IO_ATTRS = {
    # File I/O
    'read_text', 'read_bytes', 'write_text', 'write_bytes',
    'readline', 'readlines', 'writelines',
    'import_module',
    # Filesystem checks
    'exists', 'is_file', 'is_dir',
    # Stream I/O
    'write', 'flush',
    # Network I/O
    'urlopen',
    'open_connection', 'start_server',
    'connect_read_pipe', 'connect_write_pipe',
    # Subprocess I/O
    'Popen', 'check_output', 'check_call',
    'create_subprocess_exec', 'create_subprocess_shell',
    'communicate',
    # Async I/O bridging
    'run_in_executor', 'to_thread',
    # Note: queue get/put detected separately via await context
    # Database I/O
    'execute', 'executemany', 'fetchone', 'fetchall', 'fetchmany',
    # System I/O
    'disk_usage', 'cpu_percent', 'virtual_memory',
    # Logging setup
    'basicConfig', 'addHandler',
}

# Module-qualified calls: module.attr(...)
# Maps module name → I/O category
IO_MODULES = {
    # File
    'aiofiles': 'file_io', 'shutil': 'file_io', 'importlib': 'file_io',
    # Network
    'requests': 'network_io', 'httpx': 'network_io', 'aiohttp': 'network_io',
    'urllib': 'network_io', 'urllib3': 'network_io', 'socket': 'network_io',
    'grpc': 'network_io', 'openai': 'network_io', 'anthropic': 'network_io',
    # Subprocess
    'subprocess': 'subprocess_io', 'asyncio': 'subprocess_io',
    # System
    'psutil': 'system_io',
    # Database
    'sqlite3': 'database_io', 'psycopg2': 'database_io', 'pymysql': 'database_io',
    'sqlalchemy': 'database_io', 'asyncpg': 'database_io', 'aiosqlite': 'database_io',
    'motor': 'database_io', 'pymongo': 'database_io',
}

# Specific attr calls that map to categories (when module isn't clear)
IO_ATTR_CATEGORIES = {
    'read_text': 'file_io', 'read_bytes': 'file_io',
    'write_text': 'file_io', 'write_bytes': 'file_io',
    'readline': 'file_io', 'readlines': 'file_io', 'writelines': 'file_io',
    'import_module': 'file_io',
    'exists': 'file_io', 'is_file': 'file_io', 'is_dir': 'file_io',
    'write': 'file_io', 'flush': 'file_io',
    'basicConfig': 'file_io', 'addHandler': 'file_io',
    'urlopen': 'network_io', 'open_connection': 'network_io', 'start_server': 'network_io',
    'connect_read_pipe': 'network_io', 'connect_write_pipe': 'network_io',
    'Popen': 'subprocess_io', 'check_output': 'subprocess_io', 'check_call': 'subprocess_io',
    'create_subprocess_exec': 'subprocess_io', 'create_subprocess_shell': 'subprocess_io',
    'communicate': 'subprocess_io', 'run_in_executor': 'subprocess_io', 'to_thread': 'subprocess_io',
    'execute': 'database_io', 'executemany': 'database_io',
    'fetchone': 'database_io', 'fetchall': 'database_io', 'fetchmany': 'database_io',
    'disk_usage': 'system_io', 'cpu_percent': 'system_io', 'virtual_memory': 'system_io',
}


# ── Print detection ──────────────────────────────────────────────────────────

def _is_print_with_file_redirect(call_node: ast.Call) -> bool:
    """Check if a print() call has a file= keyword (e.g. file=sys.stderr).

    Plain print() to stdout is NOT counted as I/O — it's a console wrapper.
    Only print(file=...) counts because it redirects to a specific stream.
    """
    if not (isinstance(call_node.func, ast.Name) and call_node.func.id == 'print'):
        return False
    return any(kw.arg == 'file' for kw in call_node.keywords)


# ── Logging handler detection ────────────────────────────────────────────────

_LOGGING_HANDLER_NAMES = {
    'StreamHandler', 'FileHandler', 'RotatingFileHandler',
    'TimedRotatingFileHandler', 'SocketHandler', 'DatagramHandler',
    'SysLogHandler', 'NTEventLogHandler', 'SMTPHandler',
    'MemoryHandler', 'HTTPHandler', 'WatchedFileHandler',
    'QueueHandler', 'NullHandler',
}


# ── Direct I/O detection ────────────────────────────────────────────────────

def _detect_io_direct(func_node: ast.AST) -> list[str]:
    """Walk a function body and return sorted list of I/O categories found.

    Uses ast.walk() for full recursive traversal of the function body.
    Only detects DIRECT I/O patterns — transitive (via await) is handled
    in the two-pass scan.
    """
    categories: Set[str] = set()

    for node in ast.walk(func_node):
        # ── Call nodes ────────────────────────────────────────────────
        if isinstance(node, ast.Call):
            func = node.func

            # Bare name: open(...)
            if isinstance(func, ast.Name):
                if func.id in IO_BUILTINS:
                    categories.add('file_io')
                # Logging handler constructors: StreamHandler(sys.stderr)
                if func.id in _LOGGING_HANDLER_NAMES:
                    categories.add('file_io')

            # print(file=sys.stderr) — only with file= redirect
            if _is_print_with_file_redirect(node):
                categories.add('file_io')

            # Attribute: obj.method(...)
            if isinstance(func, ast.Attribute):
                attr = func.attr

                # Known I/O attribute
                if attr in IO_ATTRS:
                    cat = IO_ATTR_CATEGORIES.get(attr, 'file_io')
                    categories.add(cat)

                # Module-qualified: subprocess.run(...), requests.get(...)
                if isinstance(func.value, ast.Name):
                    mod = func.value.id
                    if mod in IO_MODULES:
                        categories.add(IO_MODULES[mod])

                # Logging handler constructors via module: logging.StreamHandler()
                if attr in _LOGGING_HANDLER_NAMES:
                    categories.add('file_io')

        # ── Awaited queue ops: await queue.get() / await queue.put() ──
        elif isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and call.func.attr in ('get', 'put'):
                categories.add('subprocess_io')

        # ── Lazy imports of I/O modules inside function body ──────────
        elif isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split('.')[0]
                if mod in IO_MODULES:
                    categories.add(IO_MODULES[mod])
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or '').split('.')[0]
            if mod in IO_MODULES:
                categories.add(IO_MODULES[mod])

    return sorted(categories)


# ── Await-chain extraction ───────────────────────────────────────────────────

def _get_awaited_names(func_node: ast.AST) -> Set[str]:
    """Extract function/method names that are awaited inside an async function body.

    Only tracks ``await func()`` and ``await obj.method()`` — NOT plain sync calls.
    This prevents lightweight sync helpers (tracePoint, print wrappers) from
    propagating I/O status to every caller.
    """
    names: Set[str] = set()
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Await):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        func = value.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


# ── NodeVisitor-based function collector ─────────────────────────────────────

class _FunctionCollector(ast.NodeVisitor):
    """Collect all FunctionDef/AsyncFunctionDef nodes with proper recursion.

    Uses generic_visit() to recurse into nested functions, classes, and
    closures — ensuring nothing is missed regardless of nesting depth.
    Skips __dunder__ methods.
    """

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.functions: list[tuple[str, FuncNode]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if not (node.name.startswith('__') and node.name.endswith('__')):
            self.functions.append((self.rel_path, node))
        self.generic_visit(node)  # recurse for nested defs

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if not (node.name.startswith('__') and node.name.endswith('__')):
            self.functions.append((self.rel_path, node))
        self.generic_visit(node)  # recurse for nested defs


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan_io_functions(repo_path: Path) -> dict:
    """Scan repository for functions with I/O patterns.

    Two-pass approach:
        Pass 1: Find functions with direct I/O patterns, build set of I/O
                function names.
        Pass 2: Async functions that await a known I/O function inherit I/O
                status. Sync-to-sync calls do NOT propagate.

    Rules:
        - Both async and sync must have I/O (direct or transitive) to be counted
        - Keyed by (file, line, name) for uniqueness
        - Skips __dunder__ methods, test files, and test directories
    """
    # ── Collect all function nodes across all files ───────────────────────
    all_funcs: list[tuple[str, FuncNode]] = []
    total_all_functions = 0  # every function seen, I/O or not

    # EXCISED cut 3 batch 5 addendum (2026-09-06, owner: conftest/tests per alt review 8, dunder names = lexical prior):
    # the SKIP_DIRS name gate ('tests', 'venv', '.git', …; alt-8 adjudication AGREE→EXCISE) and the test-file-name gate
    # (test_*.py / *_test.py / conftest.py; alt-8 EXCISE 'silence via test file filter') are gone — the whitelist is
    # the one discovery; test-species files are measured like any other live source. FIX_15 (2026-09-10): the walk IS
    # that discovery (iter_live_py — contained, never through a symlink).
    for py_file in _scan_scope().iter_live_py(repo_path):
        try:
            source = py_file.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(py_file))
        except Exception as exc:
            logger.debug("Skipping %s: %s", py_file, exc)
            continue

        try:
            rel = str(py_file.relative_to(repo_path))
        except ValueError:
            rel = py_file.name

        collector = _FunctionCollector(rel)
        collector.visit(tree)
        all_funcs.extend(collector.functions)
        total_all_functions += len(collector.functions)

    logger.debug("Collected %d functions across repo", total_all_functions)

    # ── Pass 1: direct I/O detection ─────────────────────────────────────
    direct_io: dict[str, list[str]] = {}  # func_name → io_categories
    for rel, node in all_funcs:
        cats = _detect_io_direct(node)
        if cats:
            direct_io[node.name] = cats
            is_async = isinstance(node, ast.AsyncFunctionDef)
            logger.debug(
                "  DIRECT I/O: %s:%d %s [%s] (%s)",
                rel, node.lineno, node.name,
                "async" if is_async else "sync",
                ", ".join(cats),
            )

    logger.debug("Pass 1: %d functions with direct I/O", len(direct_io))

    # ── Pass 2: transitive I/O via await chains ──────────────────────────
    # Only async functions that await a known I/O function inherit I/O status.
    # Sync-to-sync calls (like tracePoint) do NOT propagate.
    io_names: Set[str] = set(direct_io.keys())
    changed = True
    while changed:
        changed = False
        for _rel, node in all_funcs:
            if node.name in io_names:
                continue
            if not isinstance(node, ast.AsyncFunctionDef):
                continue  # only async inherits via await
            awaited = _get_awaited_names(node)
            overlap = awaited & io_names
            if overlap:
                io_names.add(node.name)
                logger.debug(
                    "  TRANSITIVE I/O: %s:%d %s (awaits: %s)",
                    _rel, node.lineno, node.name,
                    ", ".join(sorted(overlap)),
                )
                changed = True

    logger.debug(
        "Pass 2: %d total I/O functions (%d transitive)",
        len(io_names), len(io_names) - len(direct_io),
    )

    # ── Build results ────────────────────────────────────────────────────
    files_data: dict[str, dict] = {}
    seen: set[tuple[str, int, str]] = set()
    totals = {
        'total_all_functions': total_all_functions,
        'total_files': 0,
        'total_functions': 0,
        'async_count': 0,
        'sync_count': 0,
    }

    for rel, node in all_funcs:
        if node.name not in io_names:
            continue

        key = (rel, node.lineno, node.name)
        if key in seen:
            continue
        seen.add(key)

        # Use direct categories if available, else inherit from callees
        io_categories = direct_io.get(node.name, ['transitive_io'])

        entry = {
            'name': node.name,
            'lineno': node.lineno,
            'io_types': io_categories,
        }

        if rel not in files_data:
            files_data[rel] = {
                'async_functions': [],
                'sync_functions': [],
                'async_count': 0,
                'sync_count': 0,
            }

        is_async = isinstance(node, ast.AsyncFunctionDef)
        if is_async:
            files_data[rel]['async_functions'].append(entry)
            files_data[rel]['async_count'] += 1
            totals['async_count'] += 1
        else:
            files_data[rel]['sync_functions'].append(entry)
            files_data[rel]['sync_count'] += 1
            totals['sync_count'] += 1

        totals['total_functions'] += 1
        logger.debug(
            "  COUNTED: %s:%d %s [%s] (%s)",
            rel, node.lineno, node.name,
            "async" if is_async else "sync",
            ", ".join(io_categories),
        )

    totals['total_files'] = len(files_data)

    return {
        'files': files_data,
        'totals': totals,
        'last_scan': datetime.now().isoformat(),
    }


# === CLI ===

if __name__ == '__main__':
    import sys

    # Use -v for debug output showing every detected function
    if '-v' in sys.argv:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        sys.argv.remove('-v')
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 2:
        print("Usage: python io_tracker.py <repo_path> [-v]")
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    if not target.is_dir():
        print(f"Error: {target} is not a directory")
        sys.exit(1)

    print(f"Scanning: {target}")
    print("=" * 50)

    results = scan_io_functions(target)
    totals = results['totals']

    print(f"\nI/O Functions: {totals['total_functions']} total "
          f"— {totals['async_count']} async, {totals['sync_count']} sync "
          f"(of {totals['total_all_functions']} total functions scanned)")
    print(f"Files with I/O: {totals['total_files']}")

    for path, info in sorted(results['files'].items()):
        a = info['async_count']
        s = info['sync_count']
        print(f"\n  {path} ({a} async, {s} sync):")
        for fn in info.get('async_functions', []):
            io = ', '.join(fn['io_types'])
            print(f"    async  {fn['name']}:{fn['lineno']}  ({io})")
        for fn in info.get('sync_functions', []):
            io = ', '.join(fn['io_types'])
            print(f"    sync   {fn['name']}:{fn['lineno']}  ({io})")

    print(f"\nScan complete: {results['last_scan']}")
