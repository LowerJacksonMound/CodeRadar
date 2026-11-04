"""hook_stubs.py — a base class's empty method that subclasses inherit is a hook, not a placeholder (M-146, 2026-10-08).

`class BaseService: def run(self): pass` (or `raise NotImplementedError`), subclassed elsewhere in the project, is the
template-method / interface idiom: the base declares the hook, concrete classes may override it. The per-function
stub rules (NAI-004 pass-only, NAI-120 docstring-only, NAI-043 NotImplementedError placeholder, NAI-003/030 unused
parameter) cannot see the subclasses — they live in other files. This project probe names every method of a class
that some other class in the scan inherits from (by bare base name, resolved within the scan), and whose body is
only a docstring / `pass` / `...` / `raise NotImplementedError`. It emits one `inherited_hook` context fact per such
method; validator.py turns the stub rules on that function into context. A stub on a class nobody inherits from stays
a stub. Merged per file like NAI-251/252.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List, Set


def _is_stub(fn: ast.AST) -> bool:
    body = list(getattr(fn, "body", []))
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    # a log line before the raise / pass (`self.logger.warning("… not implemented")`) is still the stub
    body = [s for s in body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
                                     and isinstance(s.value.func, ast.Attribute)
                                     and s.value.func.attr in ("debug", "info", "warning", "error", "exception"))]
    if not body:
        return True
    if body[1:]:
        return False
    s = body[0]
    if isinstance(s, ast.Pass):
        return True
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis:
        return True
    if isinstance(s, ast.Raise) and s.exc is not None:
        exc = s.exc.func if isinstance(s.exc, ast.Call) else s.exc
        return isinstance(exc, ast.Name) and exc.id == "NotImplementedError"
    return False


def _base_names(cls: ast.ClassDef) -> Set[str]:
    out: Set[str] = set()
    for b in cls.bases:
        if isinstance(b, ast.Name):
            out.add(b.id)
        elif isinstance(b, ast.Attribute):
            out.add(b.attr)
    return out


def observations(trees_by_rel: Dict[str, ast.AST], root: Path) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    classes = [(rel, c) for rel, t in trees_by_rel.items() for c in ast.walk(t) if isinstance(c, ast.ClassDef)]
    inherited: Set[str] = set()
    for _, c in classes:
        inherited |= _base_names(c)
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for rel, c in classes:
        if c.name not in inherited:
            continue
        subs = sorted(o.name for _, o in classes if c.name in _base_names(o))
        for fn in c.body:
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and not fn.name.startswith("__") and _is_stub(fn):
                out.setdefault(str((root / rel).resolve()), {})[f"{fn.name}@{fn.lineno}"] = [{
                    "tag": "HOOK", "line": fn.lineno, "context": True, "role": "inherited_hook",
                    "description": f"`{c.name}.{fn.name}` is an empty hook on a base class inherited by "
                                   f"{', '.join(subs)} — the interface, not a placeholder"}]
    return out
