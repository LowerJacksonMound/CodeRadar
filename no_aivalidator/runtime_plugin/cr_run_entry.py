"""cr_run_entry — runs the target's own headless entry point under CodeRadar's call recorder, then the probe plan
(M-153, 2026-10-08; owner: run the target's functions at scan time; Pong format: every run-against game has a
deterministic `--headless` run). Usage (cwd = a temp copy of the target):
    python cr_run_entry.py <module> [args...]
Env: CR_TRACE_ROOT, CR_PROBE_PLAN, CR_PROBE_OUT. Records real argument sets for every source function the run reaches
(the same recorder the test run uses), runs `python -m <module> args…` in-process, then executes the plan.
"""
from __future__ import annotations

import json
import pathlib
import runpy
import sys

import cr_test_trace as _t


def _tracer(frame, event, arg):
    if event == "call":
        rel = _t._rel(frame.f_code.co_filename)
        if rel is not None:
            _t._record(frame, rel)
    return None


def main() -> None:
    module, args = sys.argv[1], sys.argv[2:]
    sys.argv = [module, *args]
    sys.settrace(_tracer)
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except SystemExit:
        pass
    except Exception:   # a crash ends the recording; what was recorded still counts
        pass
    finally:
        sys.settrace(None)
    if _t._PLAN and _t._PROBE_OUT:
        from cr_probe_plan import run_plan
        try:
            plan = json.loads(pathlib.Path(_t._PLAN).read_text(encoding="utf-8"))
            plan["_direct_pass"] = []
            results = run_plan(plan, _t._corpus, _t._live, _t._ROOT)
        except Exception as e:
            results = {"error": repr(e)}
        pathlib.Path(_t._PROBE_OUT).write_text(json.dumps(results, default=repr), encoding="utf-8")


if __name__ == "__main__":
    main()
