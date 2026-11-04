"""NAI-008 `cycle` variant (owner 2026-10-08, option B): an import written inside a function body that dodges an import
cycle — hoisting it to the module top would close a loop through module-level imports.

A project fact, measured once per directory from the trees parsed once by validate_directory_async; the per-file pass
merges each file's share (the NAI-251/252 route). The per-function NAI-008 check observes every inline import as
`plain` (context); this module adds the `cycle` observation, which rule_dispositions.json's NAI-008 context row makes
deciding. The graph is the target's own: an edge A → M for every import A executes at load time (module-level
statements, class bodies, top-level if/try — never function bodies or `if TYPE_CHECKING:`), plus the package
`__init__` modules an import of a dotted name runs. The prescription is structural, never "hoist": hoisting this import
is exactly what breaks the app.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _dotted(rel: str) -> str:
    parts = list(Path(rel).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _index(trees_by_rel: Dict[str, ast.AST]) -> Dict[str, str]:
    """dotted name → rel, keyed by the full path name AND every unique suffix (src/ layouts, a scan root above the
    package). An ambiguous suffix is dropped, never guessed."""
    seen: Dict[str, Set[str]] = defaultdict(set)
    for rel in trees_by_rel:
        parts = _dotted(rel).split(".")
        for i in range(len(parts)):
            if parts[i:] and parts[i:] != [""]:
                seen[".".join(parts[i:])].add(rel)
    return {name: next(iter(rels)) for name, rels in seen.items() if len(rels) == 1}


def _targets(node: ast.AST, rel: str, index: Dict[str, str]) -> Set[str]:
    """Rels of every first-party module this import statement runs, package __init__ modules included."""
    is_pkg = Path(rel).name == "__init__.py"
    here = _dotted(rel).split(".")
    names: List[str] = []
    if isinstance(node, ast.Import):
        names = [a.name for a in node.names]
    elif isinstance(node, ast.ImportFrom):
        if node.level:
            base = here if is_pkg else here[:-1]
            base = base[:len(base) - (node.level - 1)] if node.level > 1 else base
            mod = ".".join(base + ([node.module] if node.module else []))
        else:
            mod = node.module or ""
        names = [mod] + [f"{mod}.{a.name}" for a in node.names if a.name != "*"]
    out: Set[str] = set()
    for name in names:
        parts = name.split(".")
        for i in range(1, len(parts) + 1):   # importing a.b.c runs a/__init__, a/b/__init__, then a/b/c
            hit = index.get(".".join(parts[:i]))
            if hit is not None:
                out.add(hit)
    out.discard(rel)
    return out - _ancestors(rel, index)


def _ancestors(rel: str, index: Dict[str, str]) -> Set[str]:
    """The package __init__ modules Python has already started before `rel`'s own code runs — an import that only
    reaches back through them re-runs nothing, so they are never a cycle edge out of `rel`."""
    parts = _dotted(rel).split(".")
    return {index[".".join(parts[:i])] for i in range(1, len(parts)) if ".".join(parts[:i]) in index}


def _is_type_checking(test: ast.AST) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
           (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _load_time_imports(tree: ast.AST) -> List[ast.AST]:
    """Import statements executed when the module loads: never inside a function, never under `if TYPE_CHECKING:`."""
    out: List[ast.AST] = []
    stack = list(getattr(tree, "body", []))
    while stack:
        n = stack.pop()
        if isinstance(n, _SCOPES):
            continue
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            out.append(n)
            continue
        if isinstance(n, ast.If) and _is_type_checking(n.test):
            stack.extend(n.orelse)
            continue
        stack.extend(c for c in ast.iter_child_nodes(n) if isinstance(c, ast.stmt) or isinstance(c, ast.excepthandler))
    return out


def _path_back(graph: Dict[str, Set[str]], start: str, goal: str, skip: Set[str]) -> Optional[List[str]]:
    """Shortest load-time import chain start → … → goal that never passes through `skip` (goal's own packages,
    already initialised while goal loads), or None."""
    if start in skip:
        return None
    prev: Dict[str, Optional[str]] = {start: None}
    queue = [start]
    while queue:
        cur = queue.pop(0)
        if cur == goal:
            chain = [cur]
            while prev[chain[-1]] is not None:
                chain.append(prev[chain[-1]])   # type: ignore[arg-type]
            return chain[::-1]
        for nxt in sorted(graph.get(cur, ())):
            if nxt not in prev and nxt not in skip:
                prev[nxt] = cur
                queue.append(nxt)
    return None


def observations(trees_by_rel: Dict[str, ast.AST], root: Path) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """{abs file path: {"name@line": [NAI-008 cycle observation]}} — one per function whose own body imports a
    first-party module that leads back to this module through load-time imports."""
    index = _index(trees_by_rel)
    graph: Dict[str, Set[str]] = {rel: set() for rel in trees_by_rel}
    for rel, tree in trees_by_rel.items():
        for imp in _load_time_imports(tree):
            graph[rel] |= _targets(imp, rel, index)
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(dict)
    for rel, tree in trees_by_rel.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for stmt in fn.body:   # the same statements NAI-008 observes: direct body imports
                if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    continue
                chain = None
                skip = _ancestors(rel, index)
                for target in sorted(_targets(stmt, rel, index)):
                    chain = _path_back(graph, target, rel, skip)
                    if chain:
                        break
                if not chain:
                    continue
                loop = " → ".join([rel] + chain)
                out[str((root / rel).resolve())][f"{fn.name}@{fn.lineno}"] = [{
                    "tag": "NAI-008", "line": stmt.lineno, "lines": [stmt.lineno], "variant": "cycle",
                    "func_name": fn.name, "import_type": type(stmt).__name__, "cycle": [rel] + chain,
                    "description": f"`{ast.unparse(stmt)}` ({rel}:{stmt.lineno}) is imported inside `{fn.name}` "
                                   f"because importing it at the top would close an import cycle: {loop}. The function "
                                   f"works around the module structure instead of fixing it — move what both modules "
                                   f"share into a third module (or invert the dependency), then import at the top"}]
                break
    return dict(out)
