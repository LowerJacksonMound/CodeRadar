#!/usr/bin/env python3
"""
entry_point_wrapper.py - Captures Python execution entry point and import chain.

This wrapper runs a Python script while capturing:
- The actual entry point (__main__ module)
- All imported files from the workspace (including dynamic imports)
- SHA256 hashes of all executed code
- Exception traces if the script fails

Usage: python3 entry_point_wrapper.py <script_to_run> [args...]

Output: Writes entry_point_info.json to current directory with execution metadata.

SECURITY NOTE: This script executes arbitrary Python code via exec(). It should
only be used with trusted scripts from your own workspace. Do not use this to
run untrusted code from external sources.
"""

import sys
import os
import hashlib
import json
import importlib
import importlib.util
import traceback
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Optional, Set, Dict, List, Any

# Will be populated during execution
EXECUTION_INFO: Dict[str, Any] = {
    "entry_point": None,
    "entry_point_hash": None,
    "entry_point_abspath": None,
    "imported_files": [],
    "file_hashes": {},
    "capture_timestamp": None,
    "python_version": sys.version,
    "working_directory": os.getcwd(),
    "exception_info": None,  # NEW: Capture exceptions
    "exit_code": 0,
    # Item 10 (2026-09-15): a test RUNNER run (`-m pytest` / `-m unittest` / the pytest console script) is
    # recorded as a runner — its proof goes to runner_info.json, never to entry_point_info.json (owner
    # ruling 2026-09-15: a runner may overwrite NOTHING; the app's proof survives a pytest run).
    "runner": None,        # "pytest" | "unittest" | None
    "test_path": None,     # what the runner was pointed at (target-relative), "" = its cwd
    # Fix plan 2026-10-23 C2: what this proof did NOT record, said in the file itself.
    #   failed_imports — modules the import system located (find_spec answered with a file) that were
    #                    NOT in sys.modules when the proof was last saved: they failed to load, or the
    #                    program removed them. Never listed under imported_files.
    #   omitted        — .py files seen and dropped: outside CODERADAR_TARGET, or under site-packages /
    #                    lib/python / /usr/lib / /System. `count` is every drop; `files` is capped.
    # A path missing from imported_files is therefore NOT "the run did not touch it" — read these two.
    "failed_imports": [],
    "omitted": {"count": 0, "by_reason": {}, "files": [], "truncated": False},
}
#: How many omitted paths are kept by name (the count is always complete).
OMITTED_FILES_CAP = 400
RUNNERS = ("pytest", "unittest")

# Track which files we've already recorded
_recorded_files: Set[str] = set()

# Plan item 8 (2026-09-05): only files under the TARGET are proof; set in run_script
# (CODERADAR_TARGET env, else the entry script's directory).
TARGET_ROOT: Optional[str] = None

# B10 / Q-H1-3 (2026-10-01): the ONE place the state dir is read. The live run never sets it, so the
# daemons read the files beside this script as before; a proof or a lane harness that drives this wrapper
# on a scratch repo sets CR_STATE_DIR to its own tmp dir and leaves the run of record untouched. The
# variable is CONSUMED here (popped), so the target's own code and children never see it.
_STATE_DIR = Path(os.environ.pop("CR_STATE_DIR", "") or Path(__file__).parent)

# Running state file location (in system_scripts dir, or CR_STATE_DIR)
RUNNING_STATE_FILE = _STATE_DIR / "running.json"

# Output location
OUTPUT_FILE = _STATE_DIR / "entry_point_info.json"
# Item 10: the runner's OWN record — the circuit daemon reads it for `via_runner`, the runner dataflows
# and the field below the graph; entry_point_info.json is the app's and stays the app's.
RUNNER_OUTPUT_FILE = _STATE_DIR / "runner_info.json"


def compute_file_hash(filepath: str) -> str:
    """Compute SHA256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return f"sha256:{hashlib.sha256(f.read()).hexdigest()}"
    except Exception as e:
        return f"error:{str(e)}"


def is_workspace_file(filepath: Optional[str]) -> bool:
    """Check if file is within the workspace (not stdlib/site-packages)."""
    if not filepath:
        return False
    path = Path(filepath).resolve()
    # Exclude standard library and site-packages
    path_str = str(path)
    if 'site-packages' in path_str or 'lib/python' in path_str:
        return False
    if path_str.startswith('/usr/lib') or path_str.startswith('/System'):
        return False
    # Must be a .py file
    if not path_str.endswith('.py'):
        return False
    return True


def _omit(abspath: str, reason: str) -> None:
    """C2: a .py file seen and not recorded, counted by reason and named up to the cap."""
    om = EXECUTION_INFO["omitted"]
    om["count"] += 1
    om["by_reason"][reason] = om["by_reason"].get(reason, 0) + 1
    if len(om["files"]) < OMITTED_FILES_CAP:
        om["files"].append({"file": abspath, "reason": reason})
    else:
        om["truncated"] = True


def record_import(filepath: Optional[str]) -> None:
    """Record an imported file if it's in the workspace."""
    if not filepath or filepath in _recorded_files:
        return
    _recorded_files.add(filepath)
    if not is_workspace_file(filepath):
        if str(filepath).endswith('.py'):
            _omit(str(filepath), "stdlib or site-packages")
        return

    abspath = str(Path(filepath).resolve())
    if TARGET_ROOT and not abspath.startswith(TARGET_ROOT.rstrip(os.sep) + os.sep):
        _omit(abspath, "outside CODERADAR_TARGET")
        return  # engine / stdlib / elsewhere — not the target's proof

    EXECUTION_INFO["imported_files"].append(abspath)
    EXECUTION_INFO["file_hashes"][abspath] = compute_file_hash(abspath)
    try:
        save_execution_info()   # plan item 8: proof is visible WHILE the script runs
    except Exception:
        pass


class ImportTracker:
    """Meta path finder that never finds anything: each time the import system asks it (every
    import that is not already in sys.modules), it first sweeps sys.modules for the modules that
    finished loading since the last sweep, and records their files."""

    def find_module(self, name: str, path=None):
        return None  # Let normal import proceed

    def find_spec(self, name: str, path, target=None):
        sweep_loaded_modules()
        # A module a test fixture drops from sys.modules before the next import would miss the
        # sweep: ask the finders behind this one where it will load from, record that file, and
        # still return None so the normal machinery loads it exactly as it would have.
        global _finding
        if not _finding:
            _finding = True
            try:
                behind = sys.meta_path[sys.meta_path.index(self) + 1:] if self in sys.meta_path else []
                for finder in behind:
                    fs = getattr(finder, "find_spec", None)
                    spec = fs(name, path, target) if fs else None
                    if spec is not None:
                        if getattr(spec, "has_location", False):
                            record_import(spec.origin)
                            # C2: remembered until a sweep sees it loaded; still absent from
                            # sys.modules at save time → `failed_imports`.
                            if spec.origin and str(spec.origin).endswith(".py"):
                                _pending_imports[name] = str(spec.origin)
                        break
            except Exception:
                pass
            finally:
                _finding = False
        return None


_swept_modules: Set[str] = set()
_sweeping = False
_finding = False
#: C2: module name → file the import system located, until a sweep finds it in sys.modules.
_pending_imports: Dict[str, str] = {}


def _failed_imports() -> List[Dict[str, str]]:
    """C2: every located-but-never-loaded module as of now (recomputed at each save, so a module
    still loading at an intermediate save drops off the list once it is in sys.modules)."""
    return [{"module": name, "file": origin,
             "why": "located by the import system but not in sys.modules when the proof was saved — "
                    "it failed to load, or the program removed it"}
            for name, origin in sorted(_pending_imports.items()) if name not in sys.modules]


def sweep_loaded_modules() -> None:
    """Record every module in sys.modules not yet seen (O1, MCPW lane B follow-up, 2026-09-28).

    The proof used to come from a Python replacement of `builtins.__import__` (and of
    `importlib.import_module`). That wrapper's frame sat in every ImportError traceback the target
    saw, so a target that reads its own traceback changed outcome under CR: flask's `locate_app`
    tests `tb_next` to tell "module not found" from "module raised ImportError", and
    `test_locate_app_suppress_raise` failed only under the wrapper (run 178). The target's import
    statements now run on the unmodified builtins — no CR frame in any traceback — and the SAME
    files are recorded from sys.modules: at every new import (ImportTracker above), and once more
    before every save (the finally blocks). A module that failed to load is dropped from
    sys.modules by the import system, so it is recorded only if a sweep ran while it was loading."""
    global _sweeping
    if _sweeping:
        return
    _sweeping = True
    try:
        for name, module in list(sys.modules.items()):
            _pending_imports.pop(name, None)   # C2: it loaded (or is loading) — not a failure
            if name in _swept_modules:
                continue
            _swept_modules.add(name)
            record_import(getattr(module, '__file__', None))
    finally:
        _sweeping = False


def install_import_hook() -> None:
    """Install import tracking — a sys.meta_path finder that sweeps sys.modules (see
    `sweep_loaded_modules`). builtins.__import__ and importlib.import_module are left as they are,
    so no CR frame appears in the target's tracebacks. Modules already loaded when the hook goes
    in are marked seen (the wrapper's own imports, never the target's)."""
    _swept_modules.update(sys.modules)
    sys.meta_path.insert(0, ImportTracker())


def save_execution_info(output_path: Optional[str] = None) -> None:
    """Save execution info to JSON file."""
    if output_path is None:
        output_path = str(RUNNER_OUTPUT_FILE if EXECUTION_INFO.get("runner") else OUTPUT_FILE)

    if not _sweeping:
        sweep_loaded_modules()   # O1: the modules loaded since the last new import
    EXECUTION_INFO["failed_imports"] = _failed_imports()   # C2: as of this save
    EXECUTION_INFO["capture_timestamp"] = datetime.now().isoformat()

    with open(output_path, 'w') as f:
        json.dump(EXECUTION_INFO, f, indent=2)


def set_running_state(script_name: str, running: bool = True, runner: Optional[str] = None,
                      test_path: Optional[str] = None) -> None:
    """Write or clear the running state file.
    
    Supports multiple concurrent scripts by storing a dict keyed by PID.
    Uses file locking to prevent race conditions.
    """
    pid = str(os.getpid())
    lock_file = RUNNING_STATE_FILE.with_suffix('.lock')
    
    # Create lock file and acquire exclusive lock
    with open(lock_file, 'w') as lock_f:
        fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
        try:
            # Read existing state
            state = {}
            if RUNNING_STATE_FILE.exists():
                try:
                    with open(RUNNING_STATE_FILE, 'r') as f:
                        content = f.read().strip()
                        if content:
                            state = json.loads(content)
                            # Handle legacy single-script format
                            if isinstance(state, dict) and 'script' in state and 'pid' in state:
                                state = {str(state['pid']): state}
                except Exception:
                    state = {}
            
            if running:
                # Add this script to running list
                state[pid] = {
                    "script": script_name,
                    "start_time": datetime.now().isoformat(),
                    "pid": os.getpid(),
                    "source": "wrapper",
                    "runner": runner,                 # Item 10: "pytest" | "unittest" | None
                    "test_path": test_path if runner else None,
                }
                with open(RUNNING_STATE_FILE, 'w') as f:
                    json.dump(state, f)
            else:
                # Remove this script from running list
                if pid in state:
                    del state[pid]
                if state:
                    with open(RUNNING_STATE_FILE, 'w') as f:
                        json.dump(state, f)
                elif RUNNING_STATE_FILE.exists():
                    RUNNING_STATE_FILE.unlink()
        finally:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)


def format_exception_info(exc_type, exc_value, exc_tb) -> Dict[str, Any]:
    """Format exception information for JSON output."""
    tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
    return {
        "type": exc_type.__name__ if exc_type else "Unknown",
        "message": str(exc_value) if exc_value else "",
        "traceback": ''.join(tb_lines),
        "traceback_lines": [line.rstrip() for line in tb_lines],
    }


def run_script(script_path: str, script_args: List[str]) -> int:
    """Run the target script and capture entry point info.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    script_path_obj = Path(script_path).resolve()

    if not script_path_obj.exists():
        print(f"Error: Script not found: {script_path_obj}", file=sys.stderr)
        return 1

    # Plan item 8 (2026-09-05): leave no trace in the target (no __pycache__ from
    # this execution), and run the script the way `python script.py` would.
    global TARGET_ROOT
    sys.dont_write_bytecode = True
    # I-153 (d), owner 2026-09-21: `sys.dont_write_bytecode` binds THIS interpreter only. A script
    # of the target that spawns its own python would write bytecode into the target regardless, so
    # the environment carries the statement too and every descendant inherits it.
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    TARGET_ROOT = str(Path(os.environ.get("CODERADAR_TARGET") or script_path_obj.parent).resolve())
    sys.path.insert(0, str(script_path_obj.parent))
    EXECUTION_INFO["target_root"] = TARGET_ROOT
    EXECUTION_INFO["executed_at"] = datetime.now().isoformat()

    # Record entry point
    EXECUTION_INFO["entry_point"] = script_path_obj.name
    EXECUTION_INFO["entry_point_abspath"] = str(script_path_obj)
    EXECUTION_INFO["entry_point_hash"] = compute_file_hash(str(script_path_obj))

    # Add entry point to file hashes
    EXECUTION_INFO["file_hashes"][str(script_path_obj)] = EXECUTION_INFO["entry_point_hash"]
    _recorded_files.add(str(script_path_obj))

    # Install import tracking
    install_import_hook()

    # Item 10: the pytest / py.test console script run as a script IS a runner run.
    runner = "pytest" if script_path_obj.stem in ("pytest", "py.test") else None
    test_path = _runner_test_path(script_args, TARGET_ROOT) if runner else None
    # I-99 (run 136) — I-55's OTHER HALF, the same one-flag fix on the other
    # call site. I-55 put `-p no:cacheprovider` on the `-m pytest` path (run_module) only; the
    # CONSOLE-SCRIPT path came through here and still wrote `.pytest_cache/` into the target, which
    # is what the teardown's byte-identity check then had to be cleaned up by hand for. `test_path`
    # is read from the caller's OWN arguments above, so the flag can never be mistaken for the path
    # the runner was pointed at. Owner 2026-09-15: a runner may overwrite NOTHING.
    run_args = list(script_args)
    if runner == "pytest" and "no:cacheprovider" not in run_args:
        run_args += ["-p", "no:cacheprovider"]
    if runner == "pytest":
        run_args += _pytest_results_args()
    # M-21 (2026-09-28): the target's own ini `addopts` is where report writers live (arrow's tox.ini:
    # `--junitxml=junit.xml --cov-report=xml`); a runner may overwrite NOTHING, so it is emptied unless
    # the caller passed its own `addopts` override.
    if runner == "pytest" and not any(a.startswith("addopts=") for a in run_args):
        run_args += ["-o", "addopts="]

    # Set up sys.argv for the script
    sys.argv = [str(script_path_obj)] + run_args
    EXECUTION_INFO["runner"], EXECUTION_INFO["test_path"] = runner, test_path

    # Set running state BEFORE execution, and publish the proof now (the runner's to runner_info.json)
    set_running_state(script_path_obj.name, running=True, runner=runner, test_path=test_path)
    save_execution_info()

    # Execute the script
    # SECURITY NOTE: This executes arbitrary code. Only use with trusted scripts.
    script_globals = {
        '__name__': '__main__',
        '__file__': str(script_path_obj),
        '__builtins__': __builtins__,
    }

    exit_code = 0
    try:
        with open(script_path_obj, 'rb') as f:
            code = compile(f.read(), script_path_obj, 'exec')
        exec(code, script_globals)
    except SystemExit as e:
        # Script called sys.exit() - this is normal
        exit_code = e.code if isinstance(e.code, int) else (1 if e.code else 0)
        EXECUTION_INFO["exit_code"] = exit_code
    except Exception:
        # Capture exception details
        exc_type, exc_value, exc_tb = sys.exc_info()
        EXECUTION_INFO["exception_info"] = format_exception_info(exc_type, exc_value, exc_tb)
        EXECUTION_INFO["exit_code"] = 1
        exit_code = 1

        # Re-raise to show the error to the user
        raise
    finally:
        # Clear running state and save execution info
        set_running_state(script_path_obj.name, running=False)
        save_execution_info()

    return exit_code


PYTEST_RESULTS_FILE = _STATE_DIR / "pytest_results.json"


def _pytest_results_args() -> List[str]:
    """owner 2026-10-07: every pytest run CodeRadar starts records each test's outcome to the engine's state dir
    (cr_pytest_results, loaded from this folder) — never into the target. The plugin's dir goes on sys.path."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.append(here)
    os.environ["CR_PYTEST_RESULTS"] = str(PYTEST_RESULTS_FILE)
    return ["-p", "cr_pytest_results"]


def _runner_test_path(args: List[str], target_root: Optional[str]) -> str:
    """Item 10: what the runner was pointed at — the first argument resolving under the target, as a
    target-relative path (a unittest dotted name is tried as a file too); "" when none (the runner's cwd)."""
    root = Path(target_root or os.getcwd()).resolve()
    for tok in args:
        if tok.startswith("-"):
            continue
        cands = [tok]
        if "." in tok and "/" not in tok and not tok.endswith(".py"):
            cands.append(tok.replace(".", "/") + ".py")
        for c in cands:
            p = Path(c)
            if not p.is_absolute():
                p = root / c
            try:
                p = p.resolve()
                if p.exists():
                    return p.relative_to(root).as_posix()
            except (OSError, ValueError, RuntimeError):
                continue
    return ""


def _import_roots(target_root: str) -> List[str]:
    """M-68 (2026-10-07): the target root first, then each wrapper folder that holds the target's packages
    — the same roots the scanner resolves imports from (scan_scope.import_roots over the same walk), so a
    `-m charlie_work.x` under a wrapper folder runs as it would from inside that folder."""
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("_cr_scan_scope", Path(__file__).with_name("scan_scope.py"))
        _ss = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_ss)
        root = Path(target_root)
        return [str(p) for p in _ss.import_roots(root, _ss.iter_live_py(root))]
    except Exception as e:
        print(f"[entry_point_wrapper] import-root walk failed, target root only: {e!r}", file=sys.stderr)
        return [target_root]


def run_module(module_name: str, module_args: List[str]) -> int:
    """Run `python -m module_name` under the same proof capture as run_script.

    TARGET_ROOT = CODERADAR_TARGET (else cwd) and is put first on sys.path so
    the target's own package resolves ahead of any installed copy.
    """
    import runpy
    global TARGET_ROOT
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"   # I-153 (d): every descendant inherits it too
    TARGET_ROOT = str(Path(os.environ.get("CODERADAR_TARGET") or os.getcwd()).resolve())
    sys.path[0:0] = _import_roots(TARGET_ROOT)
    EXECUTION_INFO["target_root"] = TARGET_ROOT
    EXECUTION_INFO["executed_at"] = datetime.now().isoformat()

    # The hook goes in BEFORE the spec lookup: find_spec("pkg.__main__")
    # imports the parent package, and every submodule it pulls in must be
    # recorded (first -m test recorded 2 of tqdm's files, not its package).
    install_import_hook()

    origin = None
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            if spec.submodule_search_locations:   # a package: its __main__
                main_spec = importlib.util.find_spec(module_name + ".__main__")
                origin = main_spec.origin if main_spec is not None else spec.origin
            else:
                origin = spec.origin
    except Exception:
        origin = None
    EXECUTION_INFO["entry_point"] = f"-m {module_name}"
    EXECUTION_INFO["entry_point_abspath"] = origin
    if origin and os.path.isfile(origin):
        EXECUTION_INFO["entry_point_hash"] = compute_file_hash(origin)
        EXECUTION_INFO["file_hashes"][str(Path(origin).resolve())] = EXECUTION_INFO["entry_point_hash"]
        _recorded_files.add(str(Path(origin).resolve()))

    # Item 10 (2026-09-15): `-m pytest` / `-m unittest` is a RUNNER run — the running name is the runner
    # (its origin is site-packages' __main__.py, not a script of the target), the record is its own.
    runner = module_name if module_name in RUNNERS else None
    # I-55 (2026-09-17, FIX_47 lane): pytest writes `.pytest_cache/` into the rootdir it picks — inside
    # the target — and teardown's byte-identity check then needs a hand cleanup. The wrapper already sets
    # `sys.dont_write_bytecode`; the runner's own cache is the same class of residue, and the same rule
    # holds (owner 2026-09-15: a runner may overwrite NOTHING). `test_path` is read from the caller's
    # OWN arguments, so the flag can never be mistaken for the path the runner was pointed at.
    test_path = _runner_test_path(module_args, TARGET_ROOT) if runner else None
    run_args = list(module_args)
    if runner == "pytest" and "no:cacheprovider" not in run_args:
        run_args += ["-p", "no:cacheprovider"]
    if runner == "pytest":
        run_args += _pytest_results_args()
    # M-21 (2026-09-28): the target's ini `addopts` emptied, as in run_script
    if runner == "pytest" and not any(a.startswith("addopts=") for a in run_args):
        run_args += ["-o", "addopts="]
    sys.argv = [origin or module_name] + run_args
    EXECUTION_INFO["runner"], EXECUTION_INFO["test_path"] = runner, test_path
    running_name = runner if runner else (Path(origin).name if origin else module_name)
    set_running_state(running_name, running=True, runner=runner, test_path=test_path)
    save_execution_info()

    exit_code = 0
    try:
        runpy.run_module(module_name, run_name="__main__", alter_sys=True)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else (1 if e.code else 0)
        EXECUTION_INFO["exit_code"] = exit_code
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        EXECUTION_INFO["exception_info"] = format_exception_info(exc_type, exc_value, exc_tb)
        EXECUTION_INFO["exit_code"] = 1
        exit_code = 1
        raise
    finally:
        set_running_state(running_name, running=False)
        save_execution_info()
    return exit_code


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 entry_point_wrapper.py <script> [args...]", file=sys.stderr)
        print("", file=sys.stderr)
        print("Runs a Python script while capturing entry point and import info.", file=sys.stderr)
        print("", file=sys.stderr)
        print("SECURITY NOTE: This script executes arbitrary code via exec().", file=sys.stderr)
        print("Only use with trusted scripts from your own workspace.", file=sys.stderr)
        return 1

    # `-m pkg.mod [args]` (2026-09-05): most packages are run as modules; the
    # same import hook, running state and proof record apply.
    if sys.argv[1] == "-m":
        if len(sys.argv) < 3:
            print("usage: entry_point_wrapper.py -m <module> [args...]", file=sys.stderr)
            return 2
        return run_module(sys.argv[2], sys.argv[3:])
    script_path = sys.argv[1]
    script_args = sys.argv[2:]

    try:
        return run_script(script_path, script_args)
    except Exception:
        # Exception was already captured in run_script, just exit with error
        return 1


if __name__ == "__main__":
    sys.exit(main())
