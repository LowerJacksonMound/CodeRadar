"""test_blame.py — NAI-254: the target's own test fails, and the value it rejects comes from one function (M-150,
2026-10-08; owner: run the target's functions at scan time as a counterfeit detector — security deferred).

A project probe that RUNS the target's test suite once, in a temp copy, with the cr_test_trace plugin loaded
(no_aivalidator/runtime_plugin). For each failing test:
  crash        the test raised inside source code → the deepest source frame is blamed, at the line that raised.
  failing_test an assertion failed → the ACTUAL side of the failing statement (`assert <actual> == <expected>`, the
               first argument of `self.assertEqual(...)`, the body of `with pytest.raises(...)`), plus the assignments
               that built the names it reads, is matched against the source calls the test made from those lines. One
               function → it is blamed (variant `failing_test`, deciding). Several → each is observed as
               `failing_test_shared` (context: the test alone cannot say which one is wrong).
Lines: the dynamic slice of the blamed call — of the lines that EXECUTED in it, the return it left from, the
assignments that built what it returned (transitively), and the if/elif/while tests that enclose those and ran. That is
"the statements the wrong value was built from" (owner 2026-10-07 line precision). Nothing is ranked here; the Ranker
weighs the row. Collection errors, setup errors and skips are not failures of a function.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_PLUGIN_DIR = Path(__file__).resolve().parent.parent / "runtime_plugin"
_SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
_TIMEOUT_S = 300
_ASSERT_METHODS = ("assertEqual", "assertEquals", "assertAlmostEqual", "assertTrue", "assertFalse", "assertIs",
                   "assertIsNone", "assertIsNotNone", "assertIn", "assertGreater", "assertLess", "assertGreaterEqual",
                   "assertLessEqual", "assertCountEqual", "assertDictEqual", "assertListEqual")


def _has_tests(root: Path) -> bool:
    return any(p.name.startswith("test_") or p.name.endswith("_test.py") for p in root.rglob("*.py")
               if not (set(p.relative_to(root).parts) & _SKIP_DIRS))


def run_traced(root: Path, plan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run the target's suite once in a temp copy with the trace plugin (and, given a plan, the runtime probes after
    the suite — runtime_probes.py). {"status", "rows", "probes"}."""
    if not _has_tests(root):
        return {"status": "no_tests", "rows": [], "probes": {}}
    with tempfile.TemporaryDirectory(prefix="cr_blame_") as tmp:
        copy = Path(tmp) / root.name
        shutil.copytree(root, copy, ignore=shutil.ignore_patterns(*_SKIP_DIRS, "*.pyc"))
        out = Path(tmp) / "trace.json"
        probes_out = Path(tmp) / "probes.json"
        extra: Dict[str, str] = {}
        if plan is not None:
            (Path(tmp) / "plan.json").write_text(json.dumps(plan, default=repr), encoding="utf-8")
            extra = {"CR_PROBE_PLAN": str(Path(tmp) / "plan.json"), "CR_PROBE_OUT": str(probes_out)}
        env = {**os.environ, **extra, "CR_TRACE_ROOT": str(copy), "CR_TRACE_OUT": str(out), "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": os.pathsep.join([str(_PLUGIN_DIR), str(copy), os.environ.get("PYTHONPATH", "")])}
        try:
            subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "cr_test_trace"],
                           cwd=str(copy), env=env, capture_output=True, text=True, timeout=_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "rows": [], "probes": {}}
        if not out.exists():
            return {"status": "crashed", "rows": [], "probes": {}}
        probes = json.loads(probes_out.read_text(encoding="utf-8")) if probes_out.exists() else {}
        rows = json.loads(out.read_text(encoding="utf-8"))
        for r in rows:   # paths inside the temp copy → paths relative to the target
            try:
                r["test_rel"] = Path(r["test_file"]).resolve().relative_to(copy.resolve()).as_posix()
            except ValueError:
                r["test_rel"] = None
        return {"status": "ran", "rows": rows, "probes": probes}


def _fn_by_first(tree: ast.AST, first: int) -> Optional[ast.AST]:
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and min([n.lineno] + [d.lineno for d in n.decorator_list]) == first:
            return n
    return None


def _span(n: ast.AST) -> Set[int]:
    return set(range(n.lineno, (getattr(n, "end_lineno", None) or n.lineno) + 1))


def _innermost_stmt(fn: ast.AST, line: int) -> Optional[ast.stmt]:
    hits = [n for n in ast.walk(fn) if isinstance(n, ast.stmt) and n is not fn and line in _span(n)]
    return min(hits, key=lambda n: len(_span(n))) if hits else None


def _actual(stmt: ast.stmt) -> ast.AST:
    """The side of a failing statement that holds the value under test."""
    if isinstance(stmt, ast.Assert):
        t = stmt.test
        return t.left if isinstance(t, ast.Compare) else t
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute) \
            and stmt.value.func.attr in _ASSERT_METHODS and stmt.value.args:
        return stmt.value.args[0]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return ast.Module(body=stmt.body, type_ignores=[])
    return stmt


def _feeding_lines(test_fn: ast.AST, stmt: ast.stmt, expr: ast.AST) -> Set[int]:
    """The lines of `expr`, plus every earlier assignment in the test that built a name it reads (transitively)."""
    lines: Set[int] = set()
    for n in ast.walk(expr):
        if hasattr(n, "lineno"):
            lines |= _span(n)
    want = {n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    done: Set[str] = set()
    assigns = [a for a in ast.walk(test_fn) if isinstance(a, (ast.Assign, ast.AnnAssign, ast.AugAssign))
               and a.lineno < stmt.lineno]
    while want - done:
        name = sorted(want - done)[0]
        done.add(name)
        for a in assigns:
            targets = a.targets if isinstance(a, ast.Assign) else [a.target]
            if any(isinstance(x, ast.Name) and x.id == name for t in targets for x in ast.walk(t)) and a.value is not None:
                lines |= _span(a)
                want |= {x.id for x in ast.walk(a.value) if isinstance(x, ast.Name)}
    return lines


def dynamic_slice(fn: ast.AST, executed: Set[int], returned_at: Optional[int]) -> List[int]:
    """Of the lines that ran: the return left from, the assignments that built what it returns (transitively), and the
    if/elif/while tests enclosing those that ran."""
    stmts = [n for n in ast.walk(fn) if isinstance(n, ast.stmt) and n is not fn and n.lineno in executed]
    ret = next((n for n in stmts if isinstance(n, ast.Return) and returned_at in _span(n)), None)
    if ret is None:
        return sorted({returned_at} & executed) if returned_at else []
    keep: List[ast.stmt] = [ret]
    want = {x.id for x in ast.walk(ret) if isinstance(x, ast.Name)} | \
           {f"self.{x.attr}" for x in ast.walk(ret) if isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name)}
    for n in sorted((s for s in stmts if s.lineno < ret.lineno and isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign))),
                    key=lambda s: s.lineno, reverse=True):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        names = {t.id for tg in targets for t in ast.walk(tg) if isinstance(t, ast.Name)} | \
                {f"self.{t.attr}" for tg in targets for t in ast.walk(tg) if isinstance(t, ast.Attribute)}
        if names & want and n.value is not None:
            keep.append(n)
            want |= {x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)}
    lines = {s.lineno for s in keep}
    for br in (s for s in stmts if isinstance(s, (ast.If, ast.While))):
        body = set().union(*(_span(b) for b in br.body)) if br.body else set()
        orelse = set().union(*(_span(b) for b in br.orelse)) if br.orelse else set()
        if any(s.lineno in body or s.lineno in orelse for s in keep):
            lines.add(br.lineno)
    return sorted(lines)


def observations(trees_by_rel: Dict[str, ast.AST], root: Path,
                 traced: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    traced = traced if traced is not None else run_traced(root)
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def emit(rel: str, first: int, obs: Dict[str, Any]) -> None:
        tree = trees_by_rel.get(rel)
        fn = _fn_by_first(tree, first) if tree is not None else None
        if fn is None:
            return
        bucket = out.setdefault(str((root / rel).resolve()), {}).setdefault(f"{fn.name}@{fn.lineno}", [])
        if obs["variant"] != "failing_test_shared" or not bucket:
            bucket.append(obs)

    for r in traced.get("rows", []):
        test = f"`{r['test']}` fails ({r['exc']}: {r['message']})"
        crash = r.get("crash")
        if crash:
            emit(crash["file"], crash["first"], {
                "tag": "NAI-254", "line": crash["line"], "lines": [crash["line"]], "variant": "crash", "test": r["test"],
                "description": f"{test} — raised inside `{crash['name']}` at line {crash['line']}: the function breaks "
                               f"on the input its own test gives it"})
            continue
        test_tree = trees_by_rel.get(r.get("test_rel") or "")
        test_fn = _fn_by_first(test_tree, r["test_first"]) if test_tree is not None else None
        stmt = _innermost_stmt(test_fn, r["failing_line"]) if (test_fn is not None and r.get("failing_line")) else None
        if stmt is None:
            continue
        feed = _feeding_lines(test_fn, stmt, _actual(stmt))
        hit = [c for c in r["calls"] if c["caller_line"] in feed and not (c["name"].startswith("__") and c["name"].endswith("__"))]
        blamed: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for c in hit:
            blamed.setdefault((c["file"], c["first"]), []).append(c)
        sole = not list(blamed)[1:]
        for (rel, first), calls in blamed.items():
            tree = trees_by_rel.get(rel)
            fn = _fn_by_first(tree, first) if tree is not None else None
            if fn is None:
                continue
            lines: Set[int] = set()
            for c in calls:
                lines |= set(dynamic_slice(fn, set(c["lines"]), c["returned_at"]))
            if not lines:
                lines = {fn.lineno}
            emit(rel, first, {
                "tag": "NAI-254", "line": min(lines), "lines": sorted(lines),
                "variant": "failing_test" if sole else "failing_test_shared", "test": r["test"],
                **({} if sole else {"context": True}),
                "description": f"{test} — the value it rejects is `{calls[0]['name']}`'s result"
                               + ("" if sole else " (with other functions on the same line; the test alone cannot say "
                                                  "which is wrong)")
                               + f"; built on line(s) {', '.join(map(str, sorted(lines)))}"})
    return out
