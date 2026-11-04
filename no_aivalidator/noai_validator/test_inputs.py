"""test_inputs.py — NAI-237 variant `test_input`: an early branch keyed on the exact literal a test feeds in (M-147,
2026-10-08).

The frontier form of hard-coding the oracle (`if guest_id == "G-TEST-888": return {"status": "confirmed", …}`) does not
need the test to assert the returned literal — the test passes a literal input and checks the canned result loosely,
or through a variable. NAI-237 `test_literal` (utils.py) only matched `assert f(<literals>) == <literal>`. This project
probe reads three facts, nothing executes:
  1. a branch whose test compares an input — a parameter, `param.attr`, `param[k]` or `param.get(k)` — with `==` to a
     str / number literal, and whose body (log calls aside) is a single `return` of a constant or a container of
     constants: a canned answer;
  2. that literal appears inside a test function (tests/, test_*.py, conftest.py) that calls this function by name;
  3. that literal appears NOWHERE else in the non-test source — a domain value (`"CANCELLED"`, a rate code) recurs in
     models, setters and other branches; a test fixture value lives only in its own special case.
Natural boundary literals (0, ±1, "", bool) are never a test input special case.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

_LOGS = {"debug", "info", "warning", "error", "exception", "critical", "log"}


def _is_test_file(rel: str) -> bool:
    p = Path(rel)
    return p.name.startswith("test_") or p.name.endswith("_test.py") or p.name == "conftest.py" or "tests" in p.parts


def _canned(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_canned(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is None or _canned(k) for k in node.keys) and all(_canned(v) for v in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return _canned(node.operand)
    return False


def _input_root(node: ast.AST) -> str | None:
    """The parameter an expression reads: `p`, `p.attr`, `p[k]`, `p.get(k)`."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        node = node.func.value
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _boundary(v: Any) -> bool:
    return v is None or isinstance(v, bool) or v in (0, 1, -1, "", b"")


def _literals(tree: ast.AST) -> List[Any]:
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (str, int, float))
            and not isinstance(n.value, bool)]


def _called_names(fn: ast.AST) -> Set[str]:
    out: Set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                out.add(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                out.add(n.func.attr)
    return out


def observations(trees_by_rel: Dict[str, ast.AST], root: Path) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    # literal → names of the functions called in each test function that contains it
    fed: Dict[Any, Set[str]] = defaultdict(set)
    src_sites: Dict[Any, List[str]] = defaultdict(list)   # literal → every place it is written in non-test source
    for rel, tree in trees_by_rel.items():
        if _is_test_file(rel):
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.startswith("test"):
                    calls = _called_names(fn)
                    for v in set(_literals(fn)):
                        fed[(type(v).__name__, v)] |= calls
        else:
            for v in _literals(tree):
                src_sites[(type(v).__name__, v)].append(rel)
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for rel, tree in trees_by_rel.items():
        if _is_test_file(rel):
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]} - {"self", "cls"}
            for br in ast.walk(fn):
                if not (isinstance(br, ast.If) and isinstance(br.test, ast.Compare)
                        and [type(o) for o in br.test.ops] == [ast.Eq]):
                    continue
                left, right = br.test.left, br.test.comparators[0]
                if isinstance(left, ast.Constant):
                    left, right = right, left
                if not (isinstance(right, ast.Constant) and isinstance(right.value, (str, int, float))) \
                        or _boundary(right.value) or _input_root(left) not in params:
                    continue
                body = [s for s in br.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
                                                   and isinstance(s.value.func, ast.Attribute) and s.value.func.attr in _LOGS)]
                if body[1:] or not body or not isinstance(body[0], ast.Return) or body[0].value is None \
                        or not _canned(body[0].value):
                    continue
                k = (type(right.value).__name__, right.value)
                if fn.name not in fed.get(k, set()) or src_sites.get(k, [])[1:]:
                    continue   # not fed by a test of this function, or written elsewhere too (a domain value)
                ret = body[0]
                out.setdefault(str((root / rel).resolve()), {})[f"{fn.name}@{fn.lineno}"] = [{
                    "tag": "NAI-237", "line": br.lineno, "lines": [br.lineno, ret.lineno], "variant": "test_input",
                    "description": f"`{fn.name}` returns a canned constant when "
                                   f"`{ast.unparse(left)} == {right.value!r}` — a value only a test feeds in "
                                   f"(it appears nowhere else in the source); the answer is special-cased for the test"}]
                break
    return out
