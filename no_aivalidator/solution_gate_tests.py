"""Solution gate, stage 3 "app tests" (owner 2026-10-08).

With the attempt applied (stage 2), the repo's own test suite runs, and only tests the attempt BROKE count:
  * a baseline run of the suite on the code as scanned — once per tree state, cached (`gate_baseline_<repo_id>.json`
    beside the return channel, keyed by a hash of every .py file's bytes), so ten rows cost one baseline;
  * the run with the attempt in place;
  * a test that passed in the baseline and fails / errors now, or a test module that collected before and does not
    now, fails the stage. A test already failing in the baseline is not the attempt's fault and is reported as
    pre-existing, never as the attempt's.
A repo with no test files is `not_measured` (nothing to run) and the attempt passes on stages 1-2.
Runs: `python -m pytest -q -p no:cacheprovider --junitxml=<tmp>` with cwd = the target, a fresh interpreter, a timeout.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

SUITE_TIMEOUT_S = 300
_SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}


def _py_files(root: Path) -> List[Path]:
    return sorted(p for p in root.rglob("*.py") if not (set(p.relative_to(root).parts[:-1]) & _SKIP_DIRS))


def has_tests(root: Path) -> bool:
    return any(p.name.startswith("test_") or p.name.endswith("_test.py") for p in _py_files(root))


def tree_hash(root: Path) -> str:
    h = hashlib.blake2b(digest_size=8)   # 16 hex: the cache key, no truncation
    for p in _py_files(root):
        h.update(str(p.relative_to(root)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def run_suite(root: Path) -> Dict[str, Any]:
    """{"outcomes": {test id: passed|failed|error|skipped}, "collect_errors": [module …], "status": "ran"|"timeout"
    |"crashed", "tail": str} for one run of the target's suite."""
    with tempfile.TemporaryDirectory(prefix="cr_gate_tests_") as tmp:
        xml = Path(tmp) / "junit.xml"
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={xml}"],
                                  cwd=str(root), capture_output=True, text=True, timeout=SUITE_TIMEOUT_S,
                                  stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        except subprocess.TimeoutExpired:
            return {"outcomes": {}, "collect_errors": [], "status": "timeout",
                    "tail": f"the suite was still running after {SUITE_TIMEOUT_S} s"}
        tail = (proc.stdout or proc.stderr)[-3000:]
        if not xml.exists():
            return {"outcomes": {}, "collect_errors": [], "status": "crashed", "tail": tail}
        outcomes: Dict[str, str] = {}
        collect: List[str] = []
        messages: Dict[str, str] = {}
        for case in ET.parse(xml).getroot().iter("testcase"):
            tid = f"{case.get('classname', '')}::{case.get('name', '')}"
            kids = {c.tag: c for c in case}
            if "error" in kids and not case.get("classname"):
                collect.append(case.get("name", ""))   # a module that failed to collect: pytest names it, no class
                continue
            if "failure" in kids:
                outcomes[tid] = "failed"
                messages[tid] = (kids["failure"].get("message") or kids["failure"].text or "")[-600:]
            elif "error" in kids:
                outcomes[tid] = "error"
                messages[tid] = (kids["error"].get("message") or kids["error"].text or "")[-600:]
            elif "skipped" in kids:
                outcomes[tid] = "skipped"
            else:
                outcomes[tid] = "passed"
        return {"outcomes": outcomes, "collect_errors": collect, "messages": messages, "status": "ran", "tail": tail}


def baseline(root: Path, cache: Path) -> Dict[str, Any]:
    """The suite's result on the tree as it stands now, from the cache when the tree has not changed."""
    key = tree_hash(root)
    try:
        doc = json.loads(cache.read_text(encoding="utf-8"))
        if doc.get("tree") == key:
            return doc
    except (OSError, ValueError):
        pass
    doc = {"tree": key, **run_suite(root)}
    try:
        cache.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    return doc


def stage_tests(root: Path, base: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"stage": "tests", "verdict": "not_measured", "detail": "", "probe": {}}
    if not has_tests(root):
        out["detail"] = "the repo has no test files — nothing to run"
        return out
    if base.get("status") != "ran":
        out["detail"] = f"the baseline suite did not run ({base.get('status')}): {str(base.get('tail', ''))[-200:]}"
        return out
    now = run_suite(root)
    if now["status"] != "ran":
        out.update(verdict="fail", detail=f"with the attempt applied the suite {now['status']}: "
                                          f"{(now['tail'].strip().splitlines() or [''])[-1]}",
                   probe={"status": now["status"], "tail": now["tail"]})
        return out
    before, after = base.get("outcomes") or {}, now["outcomes"]
    broke = sorted(t for t, o in after.items() if o in ("failed", "error") and before.get(t) in ("passed", None))
    lost = sorted(set(now["collect_errors"]) - set(base.get("collect_errors") or []))
    vanished = sorted(t for t, o in before.items() if o == "passed" and t not in after and not lost)
    pre = sorted(t for t, o in before.items() if o in ("failed", "error"))
    if broke or lost:
        first = (broke or lost)[0]
        why = (now.get("messages") or {}).get(first, "").strip().splitlines()
        out.update(verdict="fail",
                   detail=(f"{len(broke)} test(s) pass without the attempt and fail with it" if broke else
                           f"{len(lost)} test module(s) no longer collect")
                          + f" — first: {first}" + (f": {why[-1]}" if why else ""),
                   probe={"newly_failing": broke, "collect_lost": lost, "pre_existing_failures": pre,
                          "messages": {t: (now.get("messages") or {}).get(t, "") for t in broke}})
        return out
    out.update(verdict="pass",
               detail=f"{sum(1 for o in after.values() if o == 'passed')} test(s) pass, none newly failing"
                      + (f"; {len(pre)} already failing before the attempt, not counted" if pre else "")
                      + (f"; {len(vanished)} no longer collected" if vanished else ""),
               probe={"pre_existing_failures": pre, "vanished": vanished})
    return out
