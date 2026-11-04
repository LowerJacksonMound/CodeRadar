"""Proxy predicates — content only (Item 3, 2026-09-10; SPECIES_DICT `proxies`).

A proxy is a `.py` file that stands in for running the source: a demo, a runner / harness, a path-hack script, a git
script, an entry shim, an assertion-only file, a setup script, a package marker. Each predicate reads the file's own
AST; the whole-set facts (`in_degree` = importers within the target, `referenced_elsewhere` = a def / class of the
file is named by another file) are measured ONCE by the scanner and handed in — a predicate that needs one and gets
None does not fire. "Top level" = the module body plus the body of an `if __name__ == "__main__":` block.

Every structural comparison here is a species predicate, not a rank: `preranker_allowlist.json` carries the class-B
rows (ITEM_03) and the hunter ledger the early-outs. Order of `matches` = the precedence `species.classify` uses.
"""
from __future__ import annotations

import ast
from typing import Callable, List, Optional, Tuple

_RUNNER_CALLS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "os.system", "os.execv", "os.execve", "os.execvp", "os.execvpe", "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "runpy.run_path", "runpy.run_module", "pytest.main", "unittest.main",
})
_GIT_MODULES = frozenset({"git", "pygit2", "dulwich"})
_TEST_MODULES = frozenset({"unittest", "pytest"})
_SUBPROCESS_CALLS = frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"})


def _dotted(node: ast.AST) -> str:
    """`a.b.c` for a Name / Attribute chain, '' otherwise."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _top_level(tree: ast.AST) -> List[ast.stmt]:
    """The module body, with the statements of an `if __name__ == "__main__":` block spliced in at its place."""
    out: List[ast.stmt] = []
    for s in getattr(tree, "body", []):
        if isinstance(s, ast.If) and _is_main_guard(s.test):
            out.extend(s.body)
        else:
            out.append(s)
    return out


def _is_main_guard(test: ast.AST) -> bool:
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = [test.left] + list(test.comparators)
    names = {n.id for n in sides if isinstance(n, ast.Name)}
    consts = {c.value for c in sides if isinstance(c, ast.Constant)}
    return "__name__" in names and "__main__" in consts


def _launched_directly(tree: ast.AST) -> bool:
    """The `role` fact by CONTENT (FIX_50 step 6 / owner Q10, I-15): the module body carries an
    `if __name__ == "__main__":` block, so this file is RUN as a script rather than imported. Read
    off the module body only — a guard nested inside a def is not how a file is launched."""
    return any(isinstance(s, ast.If) and _is_main_guard(s.test) for s in getattr(tree, "body", []))


def _top_level_calls(tree: ast.AST) -> List[ast.Call]:
    calls: List[ast.Call] = []
    for s in _top_level(tree):
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
            calls.append(s.value)
        elif isinstance(s, (ast.Assign, ast.AnnAssign)) and isinstance(getattr(s, "value", None), ast.Call):
            calls.append(s.value)  # type: ignore[arg-type]  # FIX_54 ast-pos
    return calls


def _imported_modules(tree: ast.AST) -> set:
    mods: set = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods.update(a.name.split(".")[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.add(n.module.split(".")[0])
    return mods


def _sys_path_mutation(s: ast.stmt) -> bool:
    """`sys.path.insert/append/extend(...)`, `sys.path[...] = ...`, `os.environ['PYTHONPATH'] = ...`."""
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
        d = _dotted(s.value.func)
        return d in ("sys.path.insert", "sys.path.append", "sys.path.extend")
    if isinstance(s, ast.Assign):
        for t in s.targets:
            if isinstance(t, ast.Subscript):
                base = _dotted(t.value)
                if base == "sys.path":
                    return True
                if base == "os.environ" and isinstance(t.slice, ast.Constant) and t.slice.value == "PYTHONPATH":
                    return True
    return False


def _first_arg_is_git(call: ast.Call) -> bool:
    if not call.args:
        return False
    a = call.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value.split()[:1] == ["git"]
    if isinstance(a, (ast.List, ast.Tuple)) and a.elts:
        e = a.elts[0]
        return isinstance(e, ast.Constant) and e.value == "git"
    return False


def _constant_only_args(call: ast.Call) -> bool:
    def _const(x: ast.AST) -> bool:
        if isinstance(x, ast.Constant):
            return True
        if isinstance(x, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) or (isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Constant)) for v in x.values)
        if isinstance(x, (ast.List, ast.Tuple, ast.Set)):
            return all(_const(e) for e in x.elts)
        if isinstance(x, ast.Dict):
            return all(k is not None and _const(k) and _const(v) for k, v in zip(x.keys, x.values))
        return False
    return all(_const(a) for a in call.args) and all(_const(k.value) for k in call.keywords)


# ── the predicates: each returns a reason string when it fires, '' otherwise ──────────────────────

def pathhack(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """A sys.path / PYTHONPATH mutation at top level PRECEDING an import, and nothing imports this file.
    (The same mutation inside an imported file stays the path-hack detector's infraction, never a species.)

    FIX_50 step 6 / owner Q10 (I-15), built 2026-09-21: an ENTRY script may hack its path, so it is
    NOT a proxy for running the source — it IS the run of the source. The role is measured here by
    CONTENT, this module's own doctrine: a file nothing imports that carries an
    `if __name__ == "__main__":` guard is LAUNCHED, never imported. The file stays scanned and the
    later predicates still decide it, so its real role rides the precedence order (`runner`,
    `entry_shim`, … or no species at all) instead of `pathhack`. The path hack itself is untouched:
    it stays the detector's infraction, disposed of per (rule, context) by FIX_50's `role == entry`
    row in `rule_dispositions.json`."""
    if in_degree != 0:
        return ""
    if _launched_directly(tree):
        return ""
    seen_mutation = False
    for s in _top_level(tree):
        if _sys_path_mutation(s):
            seen_mutation = True
        elif seen_mutation and isinstance(s, (ast.Import, ast.ImportFrom)):
            return "sys.path / PYTHONPATH mutated at top level before an import; nothing imports this file"
    return ""


def git(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """Imports git / pygit2 / dulwich, or a subprocess call whose first argument starts `git`; not imported."""
    if in_degree != 0:
        return ""
    mods = _imported_modules(tree) & _GIT_MODULES
    if mods:
        return f"imports {', '.join(sorted(mods))}; nothing imports this file"
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _dotted(n.func) in _SUBPROCESS_CALLS and _first_arg_is_git(n):
            return "a subprocess call whose first argument is `git`; nothing imports this file"
    return ""


def runner(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """A top-level call to subprocess / os.system / os.exec* / runpy / pytest.main / unittest.main; not imported."""
    if in_degree != 0:
        return ""
    for c in _top_level_calls(tree):
        d = _dotted(c.func)
        if d in _RUNNER_CALLS or (d.startswith("os.exec")):
            return f"top-level `{d}(…)` — a wrapper that invokes other scripts; nothing imports this file"
    return ""


def entry_shim(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """No def / class; the body is imports and at most one call expression (`main()`, `sys.exit(main())`, `cli()`)."""
    body = _top_level(tree)
    if not body or any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for s in body):
        return ""
    calls = [s for s in body if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)]
    rest = [s for s in body if not isinstance(s, (ast.Import, ast.ImportFrom)) and s not in calls
            and not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]   # a docstring is not a statement of the shim
    if calls and len(calls) <= 1 and not rest:
        return f"imports and one call `{_dotted(calls[0].value.func) or '…'}(…)`, no def / class"  # type: ignore[attr-defined]  # FIX_54 ast-pos
    return ""


def demo(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """Every top-level call has only constant arguments (≥ 1 such call) and no def / class of the file is referenced
    by another file — a scripted showcase performing canned output."""
    if referenced_elsewhere is not False:
        return ""
    calls = _top_level_calls(tree)
    if not calls or not all(_constant_only_args(c) for c in calls):
        return ""
    return f"{len(calls)} top-level call(s), constant arguments only; no def / class referenced elsewhere"


def assertion_only(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """No test-framework import; every top-level def asserts and none returns a value; not imported."""
    if in_degree != 0:
        return ""
    if _imported_modules(tree) & _TEST_MODULES:
        return ""
    defs = [s for s in _top_level(tree) if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not defs:
        return ""
    for d in defs:
        has_assert = any(isinstance(x, ast.Assert) for x in ast.walk(d))
        valued_return = any(isinstance(x, ast.Return) and x.value is not None for x in ast.walk(d))
        if not has_assert or valued_return:
            return ""
    return f"{len(defs)} top-level def(s), every one asserts and none returns a value; no test framework; nothing imports this file"


def setup(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """A top-level `setup(` call from setuptools / distutils."""
    mods = _imported_modules(tree)
    if not (mods & {"setuptools", "distutils"}):
        return ""
    for c in _top_level_calls(tree):
        if _dotted(c.func) in ("setup", "setuptools.setup", "distutils.core.setup"):
            return "top-level `setup(…)` from setuptools / distutils"
    return ""


def package_marker(tree: ast.AST, rel: str, in_degree: Optional[int], referenced_elsewhere: Optional[bool]) -> str:
    """`__init__.py` whose body is only imports, `__all__` and `__version__` (or a docstring)."""
    if not rel.endswith("__init__.py"):
        return ""
    for s in getattr(tree, "body", []):
        if isinstance(s, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant):
            continue
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            targets = s.targets if isinstance(s, ast.Assign) else [s.target]
            if all(isinstance(t, ast.Name) and t.id in ("__all__", "__version__", "__author__") for t in targets):
                continue
        return ""
    return "__init__.py: imports / __all__ / __version__ only"


PREDICATES: Tuple[Tuple[str, Callable[..., str]], ...] = (
    ("pathhack", pathhack), ("git", git), ("runner", runner), ("entry_shim", entry_shim),
    ("demo", demo), ("assertion_only", assertion_only), ("setup", setup), ("package_marker", package_marker),
)


def matches(tree: ast.AST, rel: str, *, in_degree: Optional[int] = None,
            referenced_elsewhere: Optional[bool] = None) -> List[Tuple[str, str]]:
    """Every proxy kind whose predicate fires, in precedence order, with its reason."""
    out: List[Tuple[str, str]] = []
    for kind, pred in PREDICATES:
        why = pred(tree, rel, in_degree, referenced_elsewhere)
        if why:
            out.append((kind, why))
    return out
