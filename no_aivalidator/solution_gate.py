"""The solution gate (owner 2026-10-08): the agent writes attempts, CodeRadar strictly checks, filters and ranks them.

  item 2  filter     (BUILDER_DAEMON._filter_attempts) — re-validation in a scratch copy: the row's own rule gone, no
                     new deciding rule. Because re-validation re-runs every probe, the rule's own counterexample
                     (NAI-241's boundary, NAI-245's converter value, NAI-251's twin …) is re-checked there.
  stage 1 runs       (this module, `stage_runs`) — the picked attempt RUNS: its module compiles in the whole-module
                     sandbox with the attempt in place, and on a probe grid it neither raises nor exhausts the line
                     budget on any input where the original returned. A function the sandbox cannot compile
                     (impure: I/O, imports it cannot bind) is NOT MEASURED here and goes to stage 2, which runs it for
                     real.

A verdict is a dict: {"stage": "runs", "verdict": "pass" | "fail" | "not_measured", "detail": str, "probe": {...}}.
A failed verdict becomes the candidate's `stage=fail:runs:…` observation (unpickable) and the Ranker decides again;
the detail is what the agent reads for its next attempt.
"""
from __future__ import annotations

import ast
import builtins
import symtable
import textwrap
from typing import Any, Dict, List, Optional

#: Owner 2026-10-08: at most this many agent attempts per row; a row that reaches it with none integrated is held
#: for the owner. ONE home — the Builder and cr_submit both read it.
MAX_ATTEMPTS = 3

from .noai_validator.boundary_probes import _call  # noqa: E402
from .noai_validator.intent_claims import _compile, bind_module, unbind_module
from .noai_validator.split_brain import _grid


def _function(tree: ast.AST, name: str) -> Optional[ast.FunctionDef]:
    return next((n for n in getattr(tree, "body", []) if isinstance(n, ast.FunctionDef) and n.name == name), None)


def _splice(module_src: str, start: int, end: int, code: str) -> str:
    lines = module_src.splitlines(keepends=True)
    indent = len(lines[start - 1]) - len(lines[start - 1].lstrip()) if 0 < start <= len(lines) else 0
    body = textwrap.indent(textwrap.dedent(code).strip("\n") + "\n", " " * indent)
    return "".join(lines[:start - 1]) + body + "".join(lines[end:])


def _undefined_names(module_src: str, function: str) -> List[str]:
    """Global names `function` reads that the module never binds (assignment, def, class, import) and that are not
    builtins — a NameError the moment that line runs. `from x import *` makes the answer unknowable: none reported."""
    try:
        top = symtable.symtable(module_src, "<attempt>", "exec")
    except SyntaxError:
        return []
    if "*" in {a.name for n in ast.walk(ast.parse(module_src)) if isinstance(n, ast.ImportFrom) for a in n.names}:
        return []
    bound = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    fn = next((t for t in top.get_children() if t.get_name() == function and t.get_type() == "function"), None)
    if fn is None:
        return []
    return sorted(n for n in fn.get_globals() if n not in bound and not hasattr(builtins, n))


def _outcomes(tree: ast.AST, name: str, grid: List[List[Any]]) -> Optional[List[Any]]:
    """[(value, exception) per grid row] for `name` compiled in `tree`'s sandbox, or None when it will not compile."""
    fn_node = _function(tree, name)
    if fn_node is None:
        return None
    bind_module(tree)
    try:
        fn = _compile(fn_node)
        if fn is None:
            return None
        return [_call(fn, [list(a) if isinstance(a, list) else a for a in args]) for args in grid]
    finally:
        unbind_module(tree)


def stage_runs(module_src: str, start: int, end: int, function: str, attempt_code: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"stage": "runs", "verdict": "not_measured", "detail": "", "probe": {}}
    try:
        before_tree = ast.parse(module_src)
        after_tree = ast.parse(_splice(module_src, start, end, attempt_code))
    except SyntaxError as e:
        out.update(verdict="fail", detail=f"the module does not compile with the attempt in place — {e.msg} (line {e.lineno})")
        return out
    after_fn = _function(after_tree, function)
    if after_fn is None:
        out["detail"] = f"`{function}` is not a top-level function — the sandbox probes top-level functions only"
        return out
    missing = _undefined_names(ast.unparse(after_tree), function)
    if missing:
        out.update(verdict="fail", detail=f"`{function}` uses {', '.join(f'`{m}`' for m in missing)}, defined nowhere in "
                                          f"the module and not a builtin — it raises NameError when that line runs",
                   probe={"undefined": missing})
        return out
    params = [a.arg for a in after_fn.args.args if a.arg not in ("self", "cls")]
    grid = _grid(after_fn, params) if params else [[]]
    after = _outcomes(after_tree, function, grid)
    if after is None:
        out["detail"] = "the sandbox cannot compile the function (I/O or an import it cannot bind) — stage 2 runs it for real"
        return out
    before = _outcomes(before_tree, function, grid) or [(None, None)] * len(grid)
    # cr_trials round one, F1 (2026-11-04): the original on a row IS the counterfeit, so "raises where the original
    # returned" graded honest bodies against input-ignoring fakes (T1: read_count([1, 2, 3])). A raise is now detail
    # only; the line budget still fails; stage 2 (the repo's own tests) is the oracle for behaviour.
    raised = []
    for args, (b_val, b_exc), (_a_val, a_exc) in zip(grid, before, after):
        if a_exc is not None and b_exc is None:
            call = f"{function}({', '.join(repr(a) for a in args)})"
            if isinstance(a_exc, TimeoutError):
                out.update(verdict="fail", detail=f"{call} never returns (the probe's line budget ran out) — the original "
                                                  f"returned {b_val!r} there",
                           probe={"args": args, "raised": "TimeoutError", "original": repr(b_val)})
                return out
            raised.append(f"{call} raises {type(a_exc).__name__} where the original returned {b_val!r}")
    note = f"; {len(raised)} probe input(s) raise where the original returned (detail only, the original is the row): " \
           + "; ".join(raised) if raised else ""
    out.update(verdict="pass", detail=f"compiled in the sandbox and returned within budget on all {len(grid)} probe inputs{note}",
               probe={"inputs": len(grid), "raised_where_original_returned": len(raised)})
    return out
