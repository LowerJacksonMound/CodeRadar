"""cr_test_trace — pytest plugin CodeRadar loads into the TARGET's own test run (M-150, 2026-10-08; owner: run the
target's functions at scan time as a counterfeit detector).

Loaded with `-p cr_test_trace` from a temp copy of the target. For every test it records the source functions the
test body calls DIRECTLY (caller line, file, name, first line) and, for each such call, the lines that executed and the
line it returned from. A passing test's record is dropped; a failing test's record is written to $CR_TRACE_OUT with the
failing line, the exception and the deepest source frame of a crash. Nothing here judges — test_blame.py reads it.
Test files (tests/, test_*.py, conftest.py) are never "source".
"""
from __future__ import annotations

import copy
import functools
import inspect
import json
import os
import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

_ROOT = pathlib.Path(os.environ.get("CR_TRACE_ROOT", ".")).resolve()
_OUT = os.environ.get("CR_TRACE_OUT", "cr_test_trace.json")
_rows: List[Dict[str, Any]] = []
_state: Dict[str, Any] = {"test_code": None, "calls": [], "frames": {}}
# M-151 step 2: real argument sets per source function, seen anywhere under a test (corpus for the probe plan).
_PLAN = os.environ.get("CR_PROBE_PLAN")
_PROBE_OUT = os.environ.get("CR_PROBE_OUT")
_KEEP = 4                                    # argument sets kept per function (distinct by repr)
_corpus: Dict[Tuple[str, int], List[Tuple[Any, ...]]] = {}
_seen: Dict[Tuple[str, int], set] = {}
_live: Dict[Tuple[str, int], Any] = {}       # (file, first line) → the function object itself
_direct_pass: set = set()                    # (file, first line) called directly by a test that PASSED


@functools.lru_cache(maxsize=None)
def _rel(path: str) -> Optional[str]:
    # Cached per co_filename: with a probe plan, _global asks this on EVERY call event under a test, and an uncached
    # resolve() (a realpath walk) per call made a 0.7 s suite outrun the 300 s blame timeout (live tree 1, 2026-10-10).
    try:
        rel = pathlib.Path(path).resolve().relative_to(_ROOT)
    except (ValueError, OSError):
        return None
    if rel.suffix != ".py" or rel.name.startswith("test_") or rel.name == "conftest.py" or "tests" in rel.parts:
        return None
    return rel.as_posix()


def _local(frame, event, arg):
    rec = _state["frames"].get(id(frame))
    if rec is None:
        return None
    if event == "line":
        rec["lines"].add(frame.f_lineno)
    elif event == "return":
        rec["returned_at"] = frame.f_lineno
    return _local


def _record(frame, rel: str) -> None:
    key = (rel, frame.f_code.co_firstlineno)
    if len(_corpus.get(key, ())) >= _KEEP:
        return
    try:
        info = inspect.getargvalues(frame)
        names = list(info.args) + ([info.varargs] if info.varargs else [])
        vals = tuple(info.locals[n] for n in info.args)
        sig = repr(vals)
        if sig in _seen.setdefault(key, set()):
            return
        snap = copy.deepcopy(vals)
    except Exception:
        return
    _seen[key].add(sig)
    _corpus.setdefault(key, []).append(snap)
    if key not in _live:
        fn = frame.f_globals.get(frame.f_code.co_name)
        if getattr(fn, "__code__", None) is not frame.f_code and info.args and info.args[0] in ("self", "cls"):
            owner = info.locals[info.args[0]]
            owner = owner if isinstance(owner, type) else type(owner)
            fn = inspect.getattr_static(owner, frame.f_code.co_name, None)
            fn = getattr(fn, "__func__", fn)
        if getattr(fn, "__code__", None) is frame.f_code:
            _live[key] = fn


def _global(frame, event, arg):
    if event != "call" or _state["test_code"] is None:
        return None
    rel_any = _rel(frame.f_code.co_filename) if _PLAN else None
    if rel_any is not None:
        _record(frame, rel_any)
    back = frame.f_back
    if back is None or back.f_code is not _state["test_code"]:
        return None
    rel = rel_any if _PLAN else _rel(frame.f_code.co_filename)
    if rel is None:
        return None
    rec = {"caller_line": back.f_lineno, "file": rel, "name": frame.f_code.co_name,
           "first": frame.f_code.co_firstlineno, "lines": set(), "returned_at": None}
    _state["calls"].append(rec)
    _state["frames"][id(frame)] = rec
    return _local


def pytest_runtest_call(item):
    fn = getattr(item, "function", None)
    _state["test_code"] = getattr(fn, "__code__", None)
    _state["calls"] = []
    _state["frames"] = {}
    sys.settrace(_global)


def pytest_runtest_teardown(item):
    sys.settrace(None)
    _state["test_code"] = None


def pytest_runtest_makereport(item, call):
    sys.settrace(None)
    if call.when == "call" and call.excinfo is None:
        _direct_pass.update((c["file"], c["first"]) for c in _state["calls"])
    if call.when != "call" or call.excinfo is None or call.excinfo.typename in ("Skipped", "XFailed", "Exit"):
        return
    code = getattr(getattr(item, "function", None), "__code__", None)
    if code is None:
        return
    failing_line = None
    crash = None
    for entry in call.excinfo.traceback:
        raw = entry.frame.code.raw
        if raw is code:
            failing_line = entry.lineno + 1
        elif failing_line is not None:
            rel = _rel(str(entry.path))
            if rel is not None:   # the deepest source frame below the test wins
                crash = {"file": rel, "name": raw.co_name, "first": raw.co_firstlineno, "line": entry.lineno + 1}
    _rows.append({
        "test": item.nodeid, "test_file": str(pathlib.Path(code.co_filename).resolve()), "test_first": code.co_firstlineno,
        "failing_line": failing_line, "exc": call.excinfo.typename, "message": str(call.excinfo.value)[:400],
        "crash": crash,
        "calls": [{**c, "lines": sorted(c["lines"])} for c in _state["calls"]],
    })


def pytest_sessionfinish(session, exitstatus):
    try:
        with open(_OUT, "w", encoding="utf-8") as f:
            json.dump(_rows, f)
    except OSError:
        pass
    if _PLAN and _PROBE_OUT:
        try:
            from cr_probe_plan import run_plan   # same directory as this module
            plan = json.loads(pathlib.Path(_PLAN).read_text(encoding="utf-8"))
            plan["_direct_pass"] = sorted(_direct_pass)
            results = run_plan(plan, _corpus, _live, _ROOT)
        except Exception as e:   # the probes never take the trace down; reported, never silent
            results = {"error": repr(e)}
        try:
            with open(_PROBE_OUT, "w", encoding="utf-8") as f:
                json.dump(results, f, default=repr)
        except OSError:
            pass
