#!/usr/bin/env python3
"""FIX-B (run 186) unit proof — RCA-001 narrowed (`file_validation._rca_intra_file_sweep`).

Owner ruling 2026-09-28 (misses M-1 six `_resolve`, M-3 arrow `humanize`). Each fixture builds the
real rows with `validate_file_async` (the sweep held back), sets the callee's failure to the shape
under test, then runs the REAL sweep and reads whether the caller carries an RCA-001 observation.

  1  `self`/`cls` are not params to forward               -> no RCA-001
  2  `mod.name` / `opts.path` rooted in a REAL param is forwarding -> no RCA-001;
     `self.cache` forwards nothing (M-new-2, fpB2)       -> RCA-001 fires
  3  callee failed ONLY on the similarity family (NAI-230) -> no RCA-001;
     callee failed on NAI-230 AND a behavioural rule       -> RCA-001 still fires
  4  nested closure reading the enclosing scope (M-3)      -> no RCA-001
  5  `B.helper` failed, module `helper` passed (collision) -> no RCA-001
  M-1 six `_resolve` shape, M-3 arrow `humanize` shape      -> no RCA-001
  TRUE positive: caller receives params, calls a genuinely failing callee without them -> RCA-001

Not a gate (the gate count stays 17); run: `.venv_new/bin/python system_scripts/fpB_rca_narrow_proof.py`.
"""
from __future__ import annotations

import ast
import asyncio
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import no_aivalidator.noai_validator.file_validation as fv  # noqa: E402
from no_aivalidator.noai_validator.collector import FunctionCollector  # noqa: E402
from no_aivalidator.noai_validator.validator import NoAIMathValidator  # noqa: E402

BEHAVIOURAL = {"tag": "NAI-054", "line": 0, "description": "statement repeated (fixture)", "magnitude": 1}
SIMILAR = {"tag": "NAI-230", "line": 0, "description": "similar structure cluster (fixture)", "magnitude": 9}

# (name, source, {(callee_name, callee_line_marker): failure obs list}, caller name, expect RCA-001)
CASES: List[Tuple[str, str, Dict[str, list], str, bool]] = [
    ("1 self-only params", '''
def broken(a):
    return a

class Box:
    def run(self):
        x = self.cfg
        return broken(1)
''', {"broken": [BEHAVIOURAL]}, "run", False),
    ("2 attribute forwarding", '''
def broken(a):
    return a

def resolve(mod):
    if mod:
        return broken(mod.name)
    return None
''', {"broken": [BEHAVIOURAL]}, "resolve", False),
    ("3a similarity-only callee", '''
def broken(a):
    return a

def load(path):
    if path:
        return broken(1)
    return None
''', {"broken": [SIMILAR]}, "load", False),
    ("3b similarity + behavioural callee", '''
def broken(a):
    return a

def load(path):
    if path:
        return broken(1)
    return None
''', {"broken": [SIMILAR, BEHAVIOURAL]}, "load", True),
    ("4 nested closure reads enclosing", '''
def humanize(other, granularity):
    delta = other * 2
    def gather():
        return delta + granularity
    if granularity:
        return gather()
    return None
''', {"gather": [BEHAVIOURAL]}, "humanize", False),
    ("5 class-qualified callee key", '''
def helper():
    return 1

class B:
    def helper(self):
        return 2

def go(x):
    if x:
        return helper()
    return None
''', {"B.helper": [BEHAVIOURAL]}, "go", False),
    ("M-1 six _resolve shape", '''
class MovedModule:
    def __init__(self, name, old, new=None):
        self.mod = new or name

    def _resolve(self):
        return _import_module(self.mod)

def _import_module(name):
    __import__(name)
    return name
''', {"_import_module": [SIMILAR]}, "_resolve", False),
    ("M-3 arrow humanize shape", '''
class Arrow:
    def humanize(self, other=None, locale="en_us", granularity="auto"):
        delta = int(other or 0)
        sign = -1 if delta < 0 else 1
        def gather_timeframes(_delta, _frame):
            return sign * _delta, _frame
        if granularity == "auto":
            return "just now"
        return gather_timeframes(delta, "week")
''', {"gather_timeframes": [BEHAVIOURAL]}, "humanize", False),
    ("M-new-2 TRUE positive (self.cache is not path)", '''
def broken(a):
    return a

class Store:
    def m(self, path):
        if not path:
            return None
        return broken(self.cache)
''', {"broken": [BEHAVIOURAL]}, "m", True),
    ("2b attribute of a real param `opts.path`", '''
def broken(a):
    return a

class Store:
    def m(self, opts):
        if not opts:
            return None
        return broken(opts.path)
''', {"broken": [BEHAVIOURAL]}, "m", False),
    ("TRUE positive (receives params, never forwards)", '''
def parse_rows(text):
    return text.split()

def load_table(path, sep):
    if not path or not sep:
        return []
    return parse_rows("")
''', {"parse_rows": [BEHAVIOURAL]}, "load_table", True),
]


def _rows(src: str) -> tuple:
    saved = fv._rca_intra_file_sweep
    fv._rca_intra_file_sweep = lambda results, *_a: results  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fixture.py"
            p.write_text(src, encoding="utf-8")
            rows = asyncio.run(fv.validate_file_async(NoAIMathValidator(), p))
    finally:
        fv._rca_intra_file_sweep = saved  # type: ignore[assignment]
    tree = ast.parse(src)
    col = FunctionCollector(src)
    col.visit(tree)
    return rows, col, tree


def _run(src: str, fail: Dict[str, list], caller: str) -> tuple:
    rows, col, tree = _rows(src)
    quals = {(i.node.name, i.node.lineno): (f"{i.parent_class}.{i.node.name}" if i.parent_class else i.node.name)
             for i in col.functions if hasattr(i.node, "name")}
    for r in rows:
        q = quals.get((r.function_name, r.line))
        key = q if q in fail else (r.function_name if r.function_name in fail else None)
        if key is not None:   # a qualified key ("B.helper") hits only that def; a bare key any same-named def
            r.triggered_patterns = [dict(o, line=r.line) for o in fail[key]]
            # the callee's verdict is the Ranker's over the fixture observations, as in production
            r.passed = fv._VR.decide("observations", r.triggered_patterns, species="").passed
    if all(r.passed for r in rows if r.function_name != caller):
        raise AssertionError("fixture marked no callee failed — the case would be vacuous")
    crow = next(r for r in rows if r.function_name == caller)
    crow.passed, crow.triggered_patterns = True, []
    out = fv._rca_intra_file_sweep(rows, col, tree, NoAIMathValidator())
    c = next(r for r in out if r.function_name == caller)
    hit = [o for o in (c.triggered_patterns or []) if isinstance(o, dict) and o.get("tag") == "RCA-001"]
    return bool(hit), c


def main() -> int:
    problems: List[str] = []
    for name, src, fail, caller, expect in CASES:
        got, row = _run(src, fail, caller)
        bad = got is not expect
        print(f"  {'BAD' if bad else 'ok '}  {name:<48} RCA-001={'yes' if got else 'no ':<3} "
              f"(expected {'yes' if expect else 'no'}) passed={row.passed}")
        if bad:
            problems.append(name)
    print("\nFIX-B RCA-001 narrow unit proof:", "PASS" if not problems else f"FAIL {problems}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
