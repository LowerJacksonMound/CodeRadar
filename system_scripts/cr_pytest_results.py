"""cr_pytest_results.py — a pytest plugin the wrapper loads (`-p cr_pytest_results`) on every pytest run it
starts (owner 2026-10-07 ~06:45: pytest is a data-type tracker; its panel shows the last run's results).

It records every test's outcome — passed / failed / error / skipped / xfailed / xpassed, the test's file and
line, and for a failure the short reason — and writes them ONCE at session end to CodeRadar's own state dir
(`CR_PYTEST_RESULTS`, set by the wrapper), never into the target: a runner may overwrite NOTHING.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

_ROWS: list = []
_STARTED = time.time()


def _where(item_or_report) -> tuple:
    loc = getattr(item_or_report, "location", None) or ("", None, "")
    path, line, _name = (list(loc) + ["", None, ""])[:3]
    return str(path), (line + 1 if isinstance(line, int) else None)


def _reason(report) -> str:
    crash = getattr(getattr(report, "longrepr", None), "reprcrash", None)
    if crash is not None and getattr(crash, "message", None):
        return str(crash.message).splitlines()[0][:300]
    text = str(getattr(report, "longreprtext", "") or getattr(report, "longrepr", "") or "")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return (lines[-1] if lines else "")[:300]


def pytest_runtest_logreport(report):
    xfail = hasattr(report, "wasxfail")
    if report.when == "call":
        outcome = ("xfailed" if report.skipped and xfail else "xpassed" if report.passed and xfail
                   else report.outcome)
    elif report.failed:                       # setup / teardown blew up: an error, not a test failure
        outcome = "error"
    elif report.when == "setup" and report.skipped:
        outcome = "xfailed" if xfail else "skipped"
    else:
        return
    path, line = _where(report)
    row = {"test": report.nodeid, "file": path, "line": line, "outcome": outcome,
           "duration_s": round(float(getattr(report, "duration", 0.0) or 0.0), 3)}
    if outcome in ("failed", "error"):
        row["reason"] = _reason(report)
    _ROWS.append(row)


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("CR_PYTEST_RESULTS")
    if not out:
        return
    counts: dict = {}
    for r in _ROWS:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    doc = {"finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "duration_s": round(time.time() - _STARTED, 2),
           "exit_status": int(exitstatus), "rootdir": str(getattr(session.config, "rootpath", "")),
           "args": list(getattr(session.config, "args", []) or []), "counts": counts,
           "collected": int(getattr(session, "testscollected", 0) or 0), "tests": _ROWS}
    p = Path(out)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    os.replace(tmp, p)
