"""The stub / whitelist consult (Item 3; owner ruling 13 and 2026-09-09: everything the artifact scanner discovers
goes on the whitelist — stubs are unimplemented and may change; they are NOT intent sources).

A WHOLE FILE is a stub when every def / class body in it is one of SPECIES_DICT `stubs` shapes and the file holds
nothing else executable (imports, a docstring, `__all__`, constant assignments allowed): `pass_only`, `ellipsis_body`,
`docstring_only`, `not_implemented_error`, `abstract_shell`, `empty_class`; a `.pyi` file is `pyi_stub_file` by
construction. One stub function among real code is the per-function rules' business (NAI-004 / 120 / 214 / 142) and
never reaches here — the consult names FILES, never functions.
"""
from __future__ import annotations

import ast
from typing import Optional

STUB_KINDS = ("pyi_stub_file", "pass_only", "ellipsis_body", "docstring_only", "not_implemented_error", "abstract_shell", "empty_class")


def _body_kind(body: list) -> Optional[str]:
    """The stub kind of one def / class body, None when the body does real work."""
    stmts = list(body)
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) and isinstance(stmts[0].value.value, str):
        doc, stmts = True, stmts[1:]
    else:
        doc = False
    if not stmts:
        return "docstring_only" if doc else None
    if len(stmts) != 1:
        return None
    s = stmts[0]
    if isinstance(s, ast.Pass):
        return "pass_only"
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis:
        return "ellipsis_body"
    if isinstance(s, ast.Raise):
        exc = s.exc
        name = exc.func if isinstance(exc, ast.Call) else exc
        if isinstance(name, ast.Name) and name.id == "NotImplementedError":
            return "not_implemented_error"
    return None


def _is_declaration_class(c: ast.ClassDef) -> bool:
    """An ABC / Protocol / abstractmethod-bearing class is a DECLARATION the per-function rules judge (NAI-214 abstract
    shells, NAI-004 / 120 / 142 with @overload / Protocol / ABC context) — never the consult's whole-file stub. Found on
    the sweep of every archived target (2026-09-10): the NAI-214 plant of run 79 is exactly such a file."""
    for b in c.bases:
        name = b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
        if name in ("ABC", "Protocol", "ABCMeta"):
            return True
    for k in c.keywords:
        if k.arg == "metaclass":
            return True
    for m in c.body:
        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in m.decorator_list:
                dn = d.id if isinstance(d, ast.Name) else d.attr if isinstance(d, ast.Attribute) else ""
                if dn in ("abstractmethod", "overload"):
                    return True
    return False


def file_stub_kind(tree: ast.AST, rel: str) -> Optional[str]:
    """The stub kind of a whole file, or None. Reason strings are the kind names — the whitelist entry reads
    `stub:<kind>`. A file holding a declaration class (ABC / Protocol / abstractmethod) is never a whole-file stub."""
    if rel.endswith(".pyi"):
        return "pyi_stub_file"
    if any(isinstance(s, ast.ClassDef) and _is_declaration_class(s) for s in getattr(tree, "body", [])):
        return None
    kinds: set = set()
    n_defs = 0
    for s in getattr(tree, "body", []):
        if isinstance(s, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant):
            continue
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            v = getattr(s, "value", None)
            if v is None or isinstance(v, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set)):
                continue
            return None
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n_defs += 1
            k = _body_kind(s.body)
            if k is None:
                return None
            kinds.add(k)
            continue
        if isinstance(s, ast.ClassDef):
            n_defs += 1
            members = [m for m in s.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if not members:
                k = _body_kind(s.body)
                if k is None:
                    return None
                kinds.add("empty_class")
                continue
            for m in members:
                k = _body_kind(m.body)
                if k is None:
                    return None
                kinds.add("abstract_shell" if k == "not_implemented_error" else k)
            continue
        return None
    if n_defs == 0:
        return None
    return sorted(kinds)[0] if len(kinds) == 1 else "abstract_shell" if "abstract_shell" in kinds else sorted(kinds)[0]
