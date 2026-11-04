"""Wave 3 #6 (owner 2026-10-08, frontier-model counterfeit list): phantom wiring — NAI-252.

A well-made service is written in its own module, imported into an entry point and instantiated — so the wiring LOOKS
done — but no live data ever reaches it: nothing calls any of its methods and the instance goes nowhere.

Measured project-wide, once per scan (an instance in one file, its methods called from another):
  * a project class with at least one public method (a data holder with none is not a service);
  * instantiated in non-test code and bound to a name (`svc = Service()`, `self.svc = Service()`);
  * the binding is never used for anything but sitting there: no attribute read on it, and it is never passed,
    returned, yielded, stored in a container, or the subject of `with` / a decorator;
  * and nowhere in the project — tests included — is any of the class's public method names called.
Never measured (a framework may call the methods): a class with a base class other than `object`, a class with a
decorated method, `__call__` / `__enter__` / `__iter__` / `__await__`, or an instance built inside a decorator list.
The row sits on the function that builds the instance (or, at module level, on the service's first public method).
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

_Fn = Union[ast.FunctionDef, ast.AsyncFunctionDef]

_PROTOCOL = {"__call__", "__enter__", "__aenter__", "__iter__", "__aiter__", "__await__", "__next__", "__getitem__"}


def _is_test(rel: str) -> bool:
    parts = Path(rel).parts
    return any(p in ("tests", "test") for p in parts[:-1]) or Path(rel).name.startswith("test_") \
        or Path(rel).name.endswith("_test.py") or Path(rel).name == "conftest.py"


def _services(trees_by_rel: Dict[str, ast.AST]) -> Dict[str, Tuple[str, ast.ClassDef, Sequence[_Fn]]]:
    out: Dict[str, Tuple[str, ast.ClassDef, Sequence[_Fn]]] = {}
    seen: Set[str] = set()
    for rel, tree in trees_by_rel.items():
        for n in getattr(tree, "body", []):
            if not isinstance(n, ast.ClassDef):
                continue
            if n.name in seen:          # two project classes share the name: which one is built is unknowable
                out.pop(n.name, None)
                continue
            seen.add(n.name)
            if any(not (isinstance(b, ast.Name) and b.id == "object") for b in n.bases) or n.decorator_list:
                continue
            methods = [m for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if any(m.decorator_list for m in methods) or any(m.name in _PROTOCOL for m in methods):
                continue
            public = [m for m in methods if not m.name.startswith("_")]
            if public:
                out[n.name] = (rel, n, public)
    return out


def _called_attrs(trees_by_rel: Dict[str, ast.AST]) -> Set[str]:
    """Every name used as `<anything>.<name>(...)`, as `getattr(x, "<name>")`, or as a bare reference `x.<name>`
    passed somewhere (a bound method handed out as a callback) — project-wide, tests included."""
    names: Set[str] = set()
    for tree in trees_by_rel.values():
        for n in ast.walk(tree):
            if isinstance(n, ast.Attribute):
                names.add(n.attr)
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "hasattr"):
                match n.args:
                    case [_, ast.Constant(value=str(attr)), *_]:
                        names.add(attr)
    return names


def _parents(tree: ast.AST) -> Dict[int, ast.AST]:
    return {id(c): p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}


def _scope(node: ast.AST, parents: Dict[int, ast.AST]) -> Optional[ast.AST]:
    cur = parents.get(id(node))
    while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        cur = parents.get(id(cur))
    return cur


def _target_key(t: ast.AST) -> Optional[str]:
    if isinstance(t, ast.Name):
        return t.id
    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
        return f"self.{t.attr}"
    return None


def _uses(binding: str, region: ast.AST, assign: ast.AST) -> bool:
    """Is the binding used for anything at all in `region` (outside the assignment that creates it)?"""
    for n in ast.walk(region):
        if n is assign:
            continue
        if binding.startswith("self."):
            if isinstance(n, ast.Attribute) and n.attr == binding[5:] and isinstance(n.value, ast.Name) \
                    and n.value.id == "self" and not isinstance(n.ctx, ast.Store):
                return True
        elif isinstance(n, ast.Name) and n.id == binding and not isinstance(n.ctx, ast.Store):
            return True
    return False


def observations(trees_by_rel: Dict[str, ast.AST], root: Path) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    services = _services(trees_by_rel)
    if not services:
        return {}
    called = _called_attrs(trees_by_rel)
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(dict)
    for rel, tree in trees_by_rel.items():
        if _is_test(rel):
            continue
        parents = _parents(tree)
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                    and isinstance(n.value.func, ast.Name) and n.value.func.id in services):
                continue
            keys = [k for k in (_target_key(t) for t in n.targets) if k]
            if not keys or any(not isinstance(t, (ast.Name, ast.Attribute)) for t in n.targets):
                continue
            cls_name = n.value.func.id
            srel, _cls, public = services[cls_name]
            if any(m.name in called for m in public):
                continue
            scope = _scope(n, parents)
            if scope is None:
                continue
            if keys[0].startswith("self."):
                cls_scope = parents.get(id(scope))
                while cls_scope is not None and not isinstance(cls_scope, (ast.ClassDef, ast.Module)):
                    cls_scope = parents.get(id(cls_scope))
                region = cls_scope if isinstance(cls_scope, ast.ClassDef) else scope
            else:
                region = scope
            if any(_uses(k, region, n) for k in keys):
                continue
            if isinstance(scope, ast.Module):
                # a module-level instance can be imported by name elsewhere; any reference to it disqualifies
                if any(isinstance(x, ast.Name) and x.id == keys[0] for t in trees_by_rel.values() if t is not tree
                       for x in ast.walk(t)) or any(isinstance(x, ast.alias) and x.name == keys[0]
                                                    for t in trees_by_rel.values() for x in ast.walk(t)):
                    continue
                host_rel, host = srel, public[0]
            elif isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                host_rel, host = rel, scope
            else:
                continue
            methods = ", ".join(f"`{m.name}`" for m in public)
            out[str((root / host_rel).resolve())][f"{host.name}@{host.lineno}"] = [{
                "tag": "NAI-252", "line": n.lineno if host_rel == rel else host.lineno,
                "lines": [n.lineno] if host_rel == rel else [host.lineno], "variant": "phantom_wiring",
                "service": f"{srel}::{cls_name}", "built_at": f"{rel}:{n.lineno}",
                "description": f"`{ast.unparse(n).splitlines()[0]}` ({rel}:{n.lineno}) builds the {cls_name} service, "
                               f"but no data ever reaches it: none of its methods ({methods}) is called anywhere in the "
                               f"project and the instance is never used, passed, returned or stored — the wiring is "
                               f"only an import and a constructor"}]
    return dict(out)
