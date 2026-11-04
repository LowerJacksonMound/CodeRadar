"""gate.py — G0, the SHARED REWRITER GATE (S5-1, 2026-09-17; packet REWRITER_GATE_PACKET §B).

The owner's sentence, after the T6 hand check (43 CORRECT · 12 WRONG · 0 UNSURE):

    Unattended repair must preserve observable behavior. First-vs-last, value-vs-raise,
    mutate-vs-copy are the same test. Intent-changing variants go through the client.

The twelve WRONG rows were not twelve bugs; they were one missing gate. This module is that gate:
ONE check every rewrite passes before it is offered, called from the ONE publish choke point
(`repair_generators.candidates_of`). A rewrite that fails is never dropped — it is offered
WITHHELD, with the gate's sentence, so the row stays visible and the shape lane can still render it.

Two parts, per the packet:

(i)  GENERIC POST-CONDITIONS on the rewritten span — five named checks, AST only (`ast`), each with
     one reason sentence in the owner's voice:
        output_trips_rule         the rewrite must not itself be an infraction        (#53)
        side_effect_call_removed  a side-effecting call may not be deleted            (#73 #74)
        value_return_lost         a returned value may not become a bare return/raise (#21)
        fallback_to_raise         a documented fallback may not become a raise        (#57 #75)
        live_store_removed        the LAST-LIVE store survives, never the dead first  (#30 #33)
     Every check is a DELTA check: it compares the before-span with the after-span and fires only on
     what the rewrite CHANGED, so untouched code in a long span can never withhold a repair.

(ii) PER-VARIANT APPLICABILITY PREDICATES — `PREDICATES[(rule_id, variant)] = callable`, declared
     beside the variant by the lane that owns it. G0 ships the interface plus the four the owner ruled
     explicitly (NAI-091 `shallow_copy`, `*_not_implemented`, NAI-006, NAI-131). Every other variant
     defaults to pass; a lane adds its own (see the lane contract in S5-1_G0_GATE_REPORT).

Narrowings recorded by the 55-row fixture proof (`system_scripts/gate_proof.py`) — each one is a case
where the packet's wording, taken literally, would have withheld a row the owner scored CORRECT:

  1. `side_effect_call_removed` — "a method on a parameter" is NOT side-effecting per se: the
     alias-chain fix (NAI-021S/071, rows #25 #62, both CORRECT) moves `param.append/extend` onto a
     fresh copy on purpose. Narrowed to: a removed call on a parameter fires only when NO call of the
     same method name survives anywhere in the after-span. Parameter mutation proper is NAI-091's
     predicate, not a generic post-condition.
  2. `value_return_lost` — the packet says "a `return <expr>` in before becomes bare `return`". Taken
     literally that withholds #40 (`__init__` returning its argument, NAI-183) and #59 (a real setter
     echoing its argument, NAI-131), both CORRECT. Narrowed: a lost value-return is material unless it
     is an ECHO — a bare name the function also assigns to `self.<attr>` — or the function is
     `__init__`; and the rewrite must have introduced a bare `return` or a `raise` in its place (so the
     unreachable-code and return-in-finally fixes, which simply delete a return, stay clear).
  3. NAI-131's predicate — the packet's "has no value-return in the pre-state" cannot be read
     literally: NAI-131 only fires BECAUSE the setter returns a value, and #59 (CORRECT) returns its
     argument. Read as the owner's distinction between a setter and a builder: a real setter assigns to
     `self.<attr>` and every value it returns is an echo of what it just stored, never a computed
     product (#21's escape-string builder returns `OSC + '2;' + title + BEL` — a product).

`check()` never raises: a span that will not parse, or a predicate that throws, is the Builder's
`parse=fail` business, not the gate's — the rewrite passes through untouched (fail-open), because the
gate's job is to withhold WRONG repairs, never to lose right ones to its own accident.
"""
from __future__ import annotations

import ast
import json
import os
import re
import textwrap
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

OWNER_SENTENCE = ("Unattended repair must preserve observable behavior. First-vs-last, value-vs-raise, "
                  "mutate-vs-copy are the same test.")

# Modules whose names carry an effect outside the function (packet §B (i)).
EFFECT_MODULES: Tuple[str, ...] = ("os", "sys", "io", "subprocess", "ctypes", "socket", "shutil")
# ctypes / foreign-function roots: a call through one of these is a call into another process's world.
FOREIGN_ROOTS: Tuple[str, ...] = ("ctypes", "windll", "cdll", "oledll", "pydll", "WinDLL", "CDLL",
                                  "kernel32", "user32", "msvcrt")
# The Win32-style handle shape the owner named: _GetConsoleScreenBufferInfo, _FillConsoleOutputCharacterA…
HANDLE_NAME = re.compile(r"^_?(Get|Set|Fill|Write|Read)[A-Z]\w*$")
# Names that say the unit's contract IS the in-place mutation (owner's ruling 3 on NAI-091).
INPLACE_CONTRACT = re.compile(r"^(push|append_to|add|mark|extend)(_|$)|^(mark|add|extend|append)_\w+$")
_STUB_DOCSTRING_OK = True


# ── the verdict ─────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GateVerdict:
    """ok=False withholds the rewrite. `reason` is the sentence that rides into decision.why and the
    mirror's withheld block; `rule` names the check (or `predicate:<rule_id>:<variant>`) that spoke."""
    ok: bool
    reason: Optional[str]
    rule: str = ""


@dataclass(frozen=True)
class Rewrite:
    """What the gate is shown: the rewrite's identity, its span, and the module it lives in.
    `module_src` is context only (imports) — "" is legal and the gate falls back to the span.

    S7-T2 (I-126): `eager` is the TARGET-WIDE fact `module_src` cannot carry — which of the target's
    modules run at import time. It is computed once per Builder cycle (`eager_closure`, cached) and
    attached at the ONE choke point, `repair_generators.candidates_of`. `None` = NOT MEASURED, and a
    predicate that needs it withholds nothing (the gate's fail-open rule, inherited whole)."""
    rule_id: str = ""
    role: str = ""
    variant: str = ""
    file: str = ""
    span: str = ""
    before_src: str = ""
    after_src: str = ""
    module_src: str = ""
    eager: Optional["EagerClosure"] = None


# ── the eager import closure (S7-T2, I-126 / packet Q3) ─────────────────────────────────────────
#
# THE SEAM. `NAI-008 · import_hoist_fix` is right iff the enclosing module does NOT run at import
# time (T3's run 155: right 5 times, wrong 6 times on ONE target, for a reason the detector never
# measured). "Does this module run at import time" is a fact about the WHOLE target, not about the
# span or even the module — `Rewrite.module_src` cannot answer it — so it is measured here, once:
#
#   root      <pkg>/__init__.py for every top-level package in the target (a package root), or the
#             measured entry file when the target ships no package at all.
#   edge      a MODULE-LEVEL import statement: one that runs when the module is imported. An import
#             inside any function body (`def __getattr__` included) does not carry reachability, and
#             neither does one under `if TYPE_CHECKING:`. A class body, an `if`/`try`/`with`/`for` at
#             module level DO run, so those are followed.
#   closure   the transitive closure of those edges from the root: the EAGER files, each with the
#             path that reached it, plus every module NAME imported anywhere along the way (so
#             "the hoisted name is already eager" can be asked).
#
# Computed ONCE per Builder cycle and cached (`_CLOSURES`, keyed by target root + a cycle token:
# the Builder's own state-file mtime live — that file is rewritten every cycle — and a file
# mtime/size signature offline). `set_target_root()` is the explicit seam: a proof, or any caller
# that already knows the target, hands the root in and nothing is discovered. NOT MEASURED (no root,
# an unreadable tree) yields None and the predicate withholds nothing — the gate's job is to withhold
# wrong repairs, never to lose right ones to its own accident.

_SKIP_DIRS: FrozenSet[str] = frozenset({
    "__pycache__", ".archive", ".git", ".hg", ".svn", ".venv", "venv", ".venv_new", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "node_modules", "build", "dist", "site-packages",
})
# The two files in THIS tree that already carry `target_repo`: the Builder's state (rewritten every
# cycle — its mtime IS the cycle) and the validator's. Read, never written, by the gate.
_STATE_FILE = Path(__file__).resolve().parents[2] / "system_scripts" / "BUILDER_STATE.json"
_NOAI_STATE_FILE = Path(__file__).resolve().parents[2] / "system_scripts" / "NOAI_VALIDATION_STATE.json"


@dataclass(frozen=True, eq=False)
class EagerClosure:
    """What runs at `import <pkg>`. `files` maps a TARGET-RELATIVE path (the spelling a row id uses)
    to the import chain that reached it, in package-relative spellings — the way the reason says it;
    `names` is every module name the closure imports at module level."""
    roots: Tuple[str, ...] = ()
    files: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    names: FrozenSet[str] = frozenset()

    def path_to(self, file: str) -> Tuple[str, ...]:
        """The chain root → … → file, or () when this file is lazy."""
        return tuple(self.files.get(_norm_rel(file), ()))

    def is_eager(self, file: str) -> bool:
        return _norm_rel(file) in self.files

    def has_name(self, module: str) -> bool:
        """Is this module already pulled in at import time? `os.path` counts when `os` is in."""
        return module in self.names or module.split(".")[0] in self.names


def _norm_rel(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


_ROOT_OVERRIDE: Optional[str] = None
_CLOSURES: Dict[Tuple[str, object], Optional["EagerClosure"]] = {}


def set_target_root(root: Optional[str]) -> None:
    """The explicit seam: hand the gate the target it is judging. `None` restores discovery; `""`
    says NOT MEASURED on purpose (a proof that wants the same verdict whatever a live run left)."""
    global _ROOT_OVERRIDE
    _ROOT_OVERRIDE = None if root is None else str(root)


def target_root() -> str:
    """The target the Builder is on: the override when one is set, else the `target_repo` the state
    files this tree already writes carry — a fact read off a file the build writes, so no new
    plumbing lands in a file another lane owns. "" when nothing says."""
    if _ROOT_OVERRIDE is not None:
        return _ROOT_OVERRIDE
    for state in (_STATE_FILE, _NOAI_STATE_FILE):
        try:
            doc = json.loads(state.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        repo = str(doc.get("target_repo") or "") if isinstance(doc, dict) else ""
        if repo and Path(repo).is_dir():
            return repo
    return ""


def _iter_py(root: Path) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, _filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        out.extend(sorted(Path(dirpath).glob("*.py")))
    return out


def _cycle_token(root: Path) -> object:
    """One cheap value that changes when the cycle (or the target's bytes) change. Live that is the
    Builder state file's mtime — it is rewritten every cycle, which IS "once per Builder cycle".
    Offline (a fixture tree, an explicit root) it is a mtime/size signature over the tree's .py."""
    if _ROOT_OVERRIDE is None:
        try:
            return ("cycle", _STATE_FILE.stat().st_mtime_ns)
        except OSError:
            pass
    sig: List[Tuple[str, int, int]] = []
    for path in _iter_py(root):
        try:
            st = path.stat()
        except OSError:
            continue
        sig.append((str(path), st.st_mtime_ns, st.st_size))
    return ("tree", tuple(sorted(sig)))


def _package_roots(root: Path) -> List[Path]:
    """Every TOP-LEVEL package in the target: a directory with `__init__.py` whose parent has none."""
    roots: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        if "__init__.py" in filenames:
            dirnames[:] = []                      # a sub-package is reached through its parent
            if not (here.parent / "__init__.py").is_file():
                roots.append(here / "__init__.py")
    return sorted(roots)


def _is_type_checking(test: ast.expr) -> bool:
    """`if TYPE_CHECKING:` / `if t.TYPE_CHECKING:` — the body never runs at import time."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return False
    return _dotted(test).split(".")[-1] == "TYPE_CHECKING"


def module_level_imports(tree: ast.AST) -> List[ast.stmt]:
    """Every import statement that RUNS when the module is imported: the module body walked through
    `if` / `try` / `with` / `for` / class bodies, never into a `def` (or `async def`), never into an
    `if TYPE_CHECKING:` body. This is the whole definition of an eager edge."""
    out: List[ast.stmt] = []

    def walk(body: Sequence[ast.stmt]) -> None:
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue                           # a function body runs when it is CALLED
            if isinstance(st, (ast.Import, ast.ImportFrom)):
                out.append(st)
                continue
            if isinstance(st, ast.If):
                if not _is_type_checking(st.test):
                    walk(st.body)
                walk(st.orelse)
                continue
            for attr in ("body", "orelse", "finalbody"):
                sub = getattr(st, attr, None)
                if isinstance(sub, list):
                    walk([s for s in sub if isinstance(s, ast.stmt)])
            for handler in getattr(st, "handlers", []) or []:
                if isinstance(handler, ast.ExceptHandler):
                    walk(handler.body)

    walk(list(getattr(tree, "body", [])))
    return out


def imported_names(imp: ast.stmt, pkg_parts: Sequence[str]) -> List[str]:
    """The dotted module names one import statement pulls in, relative imports resolved against the
    package the statement lives in."""
    if isinstance(imp, ast.Import):
        return [a.name for a in imp.names]
    if not isinstance(imp, ast.ImportFrom):
        return []
    base = imp.module or ""
    if imp.level:
        parts = list(pkg_parts)
        for _ in range(imp.level - 1):      # level 1 is this package; each further dot drops one
            parts = parts[:-1]
        prefix = ".".join(parts + ([base] if base else []))
    else:
        prefix = base
    if not prefix:
        return []
    return [prefix] + [f"{prefix}.{a.name}" for a in imp.names if a.name != "*"]


def _closure_from(root_file: Path, tree_root: Path) -> Tuple[Dict[str, Tuple[str, ...]], set]:
    """BFS from ONE package root through module-level edges only."""
    parent = root_file.parent.parent                    # the directory the package sits in
    pkg = root_file.parent.name
    start = str(root_file.relative_to(parent)).replace("\\", "/")
    chains: Dict[Path, Tuple[str, ...]] = {root_file: (start,)}
    names: set = set()
    queue: List[Path] = [root_file]
    while queue:
        cur = queue.pop(0)
        try:
            tree = ast.parse(cur.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError):
            continue
        pkg_parts = list(cur.relative_to(parent).parts[:-1])
        for imp in module_level_imports(tree):
            for dotted in imported_names(imp, pkg_parts):
                names.add(dotted)
                names.add(dotted.split(".")[0])
                if dotted.split(".")[0] != pkg:
                    continue                        # only the target's own package has files to walk
                base = parent.joinpath(*dotted.split("."))
                for cand in (Path(str(base) + ".py"), base / "__init__.py"):
                    if cand.is_file() and cand not in chains:
                        chains[cand] = chains[cur] + (str(cand.relative_to(parent)).replace("\\", "/"),)
                        queue.append(cand)
    out: Dict[str, Tuple[str, ...]] = {}
    for path, chain in chains.items():
        try:
            out[_norm_rel(str(path.relative_to(tree_root)))] = chain
        except ValueError:
            continue
    return out, names


def eager_closure(root: str = "", *, entry: str = "") -> Optional["EagerClosure"]:
    """The target's eager closure, computed once per Builder cycle and cached. `entry` is the
    measured entry file (target-relative), used as the root when the target ships no package.
    None = NOT MEASURED."""
    root = root or target_root()
    if not root:
        return None
    tree_root = Path(root)
    if not tree_root.is_dir():
        return None
    key = (str(tree_root.resolve()), _cycle_token(tree_root))
    if key in _CLOSURES:
        return _CLOSURES[key]
    try:
        roots = _package_roots(tree_root)
        if not roots and entry:
            candidate = tree_root / _norm_rel(entry)
            if candidate.is_file():
                roots = [candidate]
        files: Dict[str, Tuple[str, ...]] = {}
        names: set = set()
        for root_file in roots:
            part, got = _closure_from(root_file, tree_root)
            for rel, chain in part.items():
                files.setdefault(rel, chain)
            names |= got
        out: Optional[EagerClosure] = (
            EagerClosure(roots=tuple(_norm_rel(str(r.relative_to(tree_root))) for r in roots),
                         files=files, names=frozenset(names)) if roots else None)
    except OSError:
        out = None
    _CLOSURES.clear()                              # a cache of one: only the live cycle matters
    _CLOSURES[key] = out
    return out


# ── small AST helpers ───────────────────────────────────────────────────────────────────────────

def _parse(src: str) -> Optional[ast.AST]:
    """Parse a span. Spans are cut from the file, so a method arrives indented — dedent first."""
    for text in (src, textwrap.dedent(src)):
        try:
            return ast.parse(text)
        except SyntaxError:
            continue
    return None


def _target_func(tree: ast.AST) -> Optional[ast.AST]:
    """The span's own function — the first def at the top of the span (a nested def is its own scope)."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def _func_name(tree: ast.AST) -> str:
    fn = _target_func(tree)
    return getattr(fn, "name", "") if fn is not None else ""


def _params(tree: ast.AST) -> set:
    fn = _target_func(tree)
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    a = fn.args
    names = {p.arg for p in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)}
    for extra in (a.vararg, a.kwarg):
        if extra is not None:
            names.add(extra.arg)
    return names - {"self", "cls"}


def _dotted(node: ast.AST) -> str:
    """`a.b.c` for an attribute chain rooted in a name; "" otherwise."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _unreachable(tree: ast.AST) -> set:
    """Nodes that cannot run: everything after a `return` / `raise` / `break` / `continue` in the same
    block. A call that never executes has no effect, so deleting it (NAI-002 / NAI-140's dead-code
    family) is not a lost side effect — narrowing 1b, found on NAI-140's plant."""
    dead: set = set()
    for node in ast.walk(tree):
        for attr in ("body", "orelse", "finalbody"):
            stmts = getattr(node, attr, None)
            if not isinstance(stmts, list):
                continue
            terminal = False
            for st in stmts:
                if terminal:
                    dead.update(id(x) for x in ast.walk(st))
                if isinstance(st, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    terminal = True
    return dead


def _callees(tree: ast.AST) -> Dict[str, int]:
    """callee spelling → how many times it is CALLED (reachably) in this span."""
    dead = _unreachable(tree)
    out: Dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) not in dead:
            key = _dotted(node.func) or (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if key:
                out[key] = out.get(key, 0) + 1
    return out


def _counts(tree: ast.AST, pred: Callable[[ast.AST], bool]) -> int:
    return sum(1 for n in ast.walk(tree) if pred(n))


def _returns(tree: ast.AST, *, value: bool) -> List[ast.Return]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Return) and ((n.value is not None) is value)]


@lru_cache(maxsize=64)
def _imported_names(module_src: str, before_src: str) -> Dict[str, str]:
    """name → the module it came from, for `import x`, `import x as y`, `from m import n`."""
    out: Dict[str, str] = {}
    for src in (module_src, before_src):
        tree = _parse(src) if src else None
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    out[(a.asname or a.name).split(".")[0]] = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    out[a.asname or a.name] = node.module.split(".")[0]
    return out


@lru_cache(maxsize=64)
def _foreign_bindings(module_src: str) -> frozenset:
    """Module-level names bound from a ctypes handle: `_GetStdHandle = windll.kernel32.GetStdHandle`."""
    out: set = set()
    tree = _parse(module_src) if module_src else None
    if tree is None:
        return frozenset()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            root = _dotted(node.value if not isinstance(node.value, ast.Call) else node.value.func).split(".")[0]
            if root in FOREIGN_ROOTS:
                out.add(node.targets[0].id)
    return frozenset(out)


def _is_stub_body(body: Sequence[ast.stmt]) -> bool:
    """Empty / declared-only: `pass`, `...`, a docstring, or `raise NotImplemented[Error]` (owner ruling 2)."""
    for st in body:
        if isinstance(st, ast.Pass):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
            if st.value.value is Ellipsis or isinstance(st.value.value, str):
                continue
            return False
        if isinstance(st, ast.Raise):
            name = _dotted(st.exc.func) if isinstance(st.exc, ast.Call) else _dotted(st.exc) if st.exc else ""
            if name.split(".")[-1] in ("NotImplemented", "NotImplementedError"):
                continue
            return False
        return False
    return True


def _store_events(tree: ast.AST) -> List[Tuple[int, int, str, str]]:
    """(lineno, col, name, value-dump) for every plain `name = <expr>` in the span, in source order —
    the tuple leads with the position so plain `sorted()` IS source order (no key, nothing picked)."""
    out: List[Tuple[int, int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            out.append((node.lineno, node.col_offset, node.targets[0].id, ast.dump(node.value)))
    return sorted(out)


def _load_lines(tree: ast.AST, name: str) -> List[int]:
    return sorted(n.lineno for n in ast.walk(tree)
                  if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load))


# ── (i) the five generic post-conditions ────────────────────────────────────────────────────────

def output_trips_rule(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """The rewrite may not itself be an infraction — NAI-032's `total = total` (#53).

    A delta check over the detectors' own patterns: a pattern fires only when the rewrite INTRODUCED
    it (count in after > count in before). Lanes extend `_OUTPUT_PATTERNS` when a variant's family
    needs another post-detector; the pattern bodies are ports of the detector's own test."""
    for rid, what, pred in _OUTPUT_PATTERNS:
        if _counts(after, pred) > _counts(before, pred):
            return (f"gate: the rewrite trips {rid} itself ({what}) — a repair may not be a new "
                    f"infraction.")
    return None


def _p_self_assignment(n: ast.AST) -> bool:
    # redundancy_checks._check_self_assignment (NAI-064): x = x
    if not isinstance(n, ast.Assign) or len(n.targets) != 1:
        return False
    t, v = n.targets[0], n.value
    if isinstance(t, ast.Name) and isinstance(v, ast.Name):
        return t.id == v.id
    if isinstance(t, ast.Attribute) and isinstance(v, ast.Attribute):
        return bool(_dotted(t)) and _dotted(t) == _dotted(v)
    return False


def _p_algebraic_identity(n: ast.AST) -> bool:
    # math_checks._check_algebraic_identity (NAI-032): x + 0, x - 0, x * 1, x / 1
    if not isinstance(n, ast.BinOp):
        return False
    zero = isinstance(n.op, (ast.Add, ast.Sub))
    one = isinstance(n.op, (ast.Mult, ast.Div))
    want = 0 if zero else 1 if one else None
    if want is None:
        return False
    return any(isinstance(side, ast.Constant) and side.value is not True and side.value is not False
               and side.value == want for side in (n.left, n.right))


# (rule id, what the detector calls it, the pattern) — a lane appends its family's post-detector here.
_OUTPUT_PATTERNS: List[Tuple[str, str, Callable[[ast.AST], bool]]] = [
    ("NAI-064", "self-assignment", _p_self_assignment),
    ("NAI-032", "algebraic identity", _p_algebraic_identity),
]


def side_effect_call_removed(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """A call whose callee carries an effect outside this function may not be deleted (#73 #74).

    Side-effect-bearing callees: a ctypes / foreign-function handle, a `_Get*`/`_Set*`/`_Fill*`-style
    handle, anything the module imports from os / sys / io / subprocess / ctypes / socket / shutil,
    and (narrowing 1) a method on a parameter whose method name survives nowhere in the after-span."""
    b_calls, a_calls = _callees(before), _callees(after)
    removed = [k for k, n in b_calls.items() if n > a_calls.get(k, 0)]
    if not removed:
        return None
    imported = _imported_names(rw.module_src, rw.before_src)
    foreign = _foreign_bindings(rw.module_src)
    params = _params(before)
    a_methods = {k.split(".")[-1] for k in a_calls}
    for callee in removed:
        head, last = callee.split(".")[0], callee.split(".")[-1]
        if HANDLE_NAME.match(last) or HANDLE_NAME.match(callee):
            return (f"gate: `{callee}` is a side-effecting call — deleting it changes what the "
                    f"program does, not what it says.")
        if head in FOREIGN_ROOTS or head in foreign or callee in foreign:
            return (f"gate: `{callee}` calls out through a foreign handle — its result may be "
                    f"discarded, its effect may not.")
        if imported.get(head) in EFFECT_MODULES:
            return (f"gate: `{callee}` comes from `{imported.get(head)}` — the call's effect leaves "
                    f"this function, so the call stays.")
        if head in params and last not in a_methods and "." in callee:
            return (f"gate: `{callee}` mutates the caller's `{head}` and nothing in the rewrite does "
                    f"it any more — the effect was the function's purpose.")
    return None


def value_return_lost(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """A `return <expr>` may not become a bare `return` or a `raise` (#21; #61 #70's family).

    Narrowing 2: the lost return must be MATERIAL — not an echo of what the function just stored on
    `self`, and not `__init__`'s — and the rewrite must have put a bare return or a raise in its place."""
    lost = _lost_value_returns(before, after)
    if not lost:
        return None
    name = _func_name(before)
    if name in ("__init__", "__init_subclass__"):
        return None
    echoes = _echoed_names(before)
    material = [r for r in lost if not (isinstance(r.value, ast.Name) and r.value.id in echoes)]
    if not material:
        return None
    gained_bare = len(_returns(after, value=False)) > len(_returns(before, value=False))
    gained_raise = _counts(after, lambda n: isinstance(n, ast.Raise)) > _counts(before, lambda n: isinstance(n, ast.Raise))
    if not (gained_bare or gained_raise):
        return None
    became = "a bare `return`" if gained_bare else "a raise"
    expr = ast.unparse(material[0].value) if hasattr(ast, "unparse") and material[0].value else "a value"
    return (f"gate: `return {expr}` would become {became} — value-vs-raise is the same test; a caller "
            f"that reads the value would see None.")


def _lost_value_returns(before: ast.AST, after: ast.AST) -> List[ast.Return]:
    a_dumps = [ast.dump(r.value) for r in _returns(after, value=True) if r.value is not None]
    lost: List[ast.Return] = []
    for r in _returns(before, value=True):
        d = ast.dump(r.value) if r.value is not None else ""
        if d in a_dumps:
            a_dumps.remove(d)
        else:
            lost.append(r)
    return lost


def _echoed_names(tree: ast.AST) -> set:
    """Names the function stores on `self` — `self.width = width` makes `return width` an echo."""
    out: set = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Name):
            for t in n.targets:
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                    out.add(n.value.id)
    return out


def fallback_to_raise(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """A deliberate fallback may not become a raise, or vanish (#57 #75, and Part C's two reverts).

    Two shapes: `with suppress(...)` around the body, and an `except …:` handler that RETURNS a value
    (the documented fallback). Either one thinning out is the gate's business."""
    if _suppressors(before) > _suppressors(after):
        return ("gate: the `suppress(...)` that is this function's whole behaviour would be removed — "
                "a deliberate suppression is the contract, not a defect.")
    b_fb, a_fb = _fallback_handlers(before), _fallback_handlers(after)
    if b_fb > a_fb:
        raised = _counts(after, lambda n: isinstance(n, ast.Raise)) > _counts(before, lambda n: isinstance(n, ast.Raise))
        tail = "becomes a raise" if raised else "would be removed"
        return (f"gate: the documented fallback `except …: return …` {tail} — the fallback IS the "
                f"behaviour the caller relies on.")
    return None


def _suppressors(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and _dotted(item.context_expr.func).split(".")[-1] == "suppress":
                    n += 1
    return n


def _fallback_handlers(tree: ast.AST) -> int:
    return sum(1 for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)
               and any(isinstance(s, ast.Return) and s.value is not None for s in ast.walk(node)))


def live_store_removed(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """Of two stores to one name with no read between them, the LIVE one is the second; a rewrite
    that keeps the first and deletes the second promotes a value the program never used (#30 #33).

    Fires only on that pair: the later store gone from the after-span while the earlier one survives.

    NARROWING 4 (FIX_62, S5-3 lane B, 2026-09-17) — a store whose own right side READS the name is not
    an overwrite of the earlier write, it CONSUMES it (`total = sum(items)` then `total = total + 0`).
    The read lives on the later store's own row, so "no read between" was true by arithmetic and the
    check called a no-op the live store. NAI-006 would not call that pair an immediate overwrite either.
    Without this, FIX_62's right repair — deleting the statement the identity reduces to `total = total`
    — is withheld by the gate; with it, #30 and #33 (`width = 8`, a constant right side) still are."""
    a_stores = {(name, dump) for _l, _c, name, dump in _store_events(after)}
    by_name: Dict[str, List[Tuple[int, int, str, str]]] = {}
    for ev in _store_events(before):
        by_name.setdefault(ev[2], []).append(ev)
    for name, evs in by_name.items():
        loads = _load_lines(before, name)
        for first, second in zip(evs, evs[1:]):
            between = [ln for ln in loads if first[0] < ln < second[0]]
            after_read = [ln for ln in loads if ln > second[0]]
            if between or not after_read:
                continue   # not an immediate overwrite, or nothing reads the pair — no live store here
            if _reassigns(before, second[0], second[1], name):
                continue   # narrowing 4: the later store reads the earlier one; it overwrites nothing
            if (name, second[3]) not in a_stores and (name, first[3]) in a_stores:
                return (f"gate: the live store `{name} = {_short(second[3], before, second[0])}` would be "
                        f"deleted and the dead first write kept — last-live survives.")
    return None


def _reassigns(tree: ast.AST, lineno: int, col: int, name: str) -> bool:
    """Narrowing 4: True when the store at (lineno, col) reads `name` on its own right side."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and n.lineno == lineno and n.col_offset == col:
            return any(isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Load)
                       for x in ast.walk(n.value))
    return False


def _short(dump: str, tree: ast.AST, lineno: int) -> str:
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and n.lineno == lineno and hasattr(ast, "unparse"):
            try:
                return ast.unparse(n.value)
            except Exception:
                break
    return "…"


def _defs(tree: ast.AST) -> "Dict[str, ast.FunctionDef | ast.AsyncFunctionDef]":
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def docstring_displaced(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """R1 (2026-09-30): a function that has a docstring before the rewrite must still have that docstring
    as its first statement after it. A line inserted ABOVE the docstring (NAI-021S's `new_payload = …` on
    screen_rounds, a 2026-09-30 target) leaves the string as a dead expression and `__doc__` None —
    the program's own documentation is lost and help()/doctest/argparse-from-__doc__ readers change."""
    a_defs = _defs(after)
    for name, bf in _defs(before).items():
        doc = ast.get_docstring(bf, clean=False)
        af = a_defs.get(name)
        if doc is None or af is None:
            continue
        if ast.get_docstring(af, clean=False) != doc:
            return (f"gate: `{name}`'s docstring would no longer be its first statement — the rewrite inserts "
                    f"above it, so `{name}.__doc__` becomes None. A head-of-body insertion goes after the docstring.")
    return None


_COPY_CTORS = ("list", "dict", "set")


def copy_type_contradicted(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """R1 (2026-09-30): a rewrite that builds `x = list(p)` / `dict(p)` / `set(p)` (or `… if p is not None
    else …`) from a parameter must build the type the function USES x as. `new_payload = list(payload)` on a
    dict payload copies its keys, and every `new_payload["rounds"]` then raises TypeError — seven rows marked
    apply: yes on a 2026-09-30 target did exactly that. The uses are read by the same evidence
    NAI-021S's generator reads (`strict._kind_evidence`: a str key, a type-only method, a slice …); any
    evidence for another type withholds. A copy whose type the code never shows is not withheld HERE —
    the generator declines that case itself."""
    from .strict import _kind_evidence   # lazy: strict → core → package; the gate is imported first
    b_defs = _defs(before)
    for name, af in _defs(after).items():
        params = {a.arg for a in af.args.args}
        bf = b_defs.get(name)
        for st in ast.walk(af):
            match st:
                case ast.Assign(targets=[ast.Name(id=x)], value=value):
                    v = value.body if isinstance(value, ast.IfExp) else value
                case _:
                    continue
            match v:
                case ast.Call(func=ast.Name(id=kind), args=[ast.Name(id=src)], keywords=[]) \
                        if kind in _COPY_CTORS and src in params:
                    pass
                case _:
                    continue
            if bf is not None and any(ast.dump(y) == ast.dump(st) for y in ast.walk(bf)):
                continue     # the copy was already in the code — not this rewrite's claim
            other = [(k, w) for k, w in _kind_evidence(af, x, {x}) if k != kind]
            if other:
                k, w = other[0]
                return (f"gate: the rewrite builds `{x} = {kind}({src})` but the function uses `{x}` as a "
                        f"{k} — {w}. Copying a {k} with {kind}() changes the value every later use reads.")
    return None


CHECKS: Tuple[Tuple[str, Callable[[Rewrite, ast.AST, ast.AST], Optional[str]]], ...] = (
    ("output_trips_rule", output_trips_rule),
    ("side_effect_call_removed", side_effect_call_removed),
    ("value_return_lost", value_return_lost),
    ("fallback_to_raise", fallback_to_raise),
    ("live_store_removed", live_store_removed),
    ("docstring_displaced", docstring_displaced),          # R1 2026-09-30
    ("copy_type_contradicted", copy_type_contradicted),    # R1 2026-09-30
)


# ── (ii) per-variant applicability predicates ───────────────────────────────────────────────────

PredicateFn = Callable[[Rewrite, ast.AST, ast.AST], Optional[str]]

#: THE LANE CONTRACT. A lane declares its variant's applicability here:
#:      PREDICATES[("NAI-006", "keep_last")] = _my_predicate
#: or with the decorator `@predicate("NAI-006", "keep_last")`. The callable is handed
#: (Rewrite, before_tree, after_tree) and returns None to let the rewrite through, or the sentence
#: (starting "gate: ") that withholds it. A variant with no entry passes — G0 never withholds a
#: variant nobody has ruled on. `rule_id` may be "*" to bind a predicate to a variant NAME across
#: rules (the `*_not_implemented` family lives in two rules); an exact (rule_id, variant) wins.
PREDICATES: Dict[Tuple[str, str], PredicateFn] = {}


def predicate(rule_id: str, variant: str) -> Callable[[PredicateFn], PredicateFn]:
    def _register(fn: PredicateFn) -> PredicateFn:
        PREDICATES[(rule_id, variant)] = fn
        return fn
    return _register


def predicate_for(rule_id: str, variant: str) -> Optional[PredicateFn]:
    return PREDICATES.get((rule_id, variant)) or PREDICATES.get(("*", variant))


BY_DESIGN = "no-fix-by-design"   # the mark `check()` reads to let this sentence outrank a generic check


def no_fix_by_design(rule_id: str, why: str = "") -> str:
    """The hook FIX_61 (lane C) asked for: a predicate that answers with this sentence withholds every
    rewrite of a rule the registry (or the manifest field lane C designs) declares unrepairable."""
    return f"gate: withheld: {BY_DESIGN} — {rule_id}" + (f": {why}" if why else "")


@predicate("NAI-091", "shallow_copy")
def _nai091_shallow_copy(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """Owner ruling 3: applicable only when ALL hold — (1) the parameter is mutated, (2) the function
    already returns that collection (or the copy is added AND returned), (3) nothing in the unit treats
    in-place mutation as the contract (no `push` / `mark_*` / `append_to` name)."""
    name = _func_name(before)
    if INPLACE_CONTRACT.match(name):
        return (f"gate: `{name}` says in-place mutation IS the contract — copying the parameter would "
                f"leave the caller's object untouched; mutate-vs-copy is the same test.")
    mutated = _mutated_params(before)
    if not mutated:
        return None   # nothing of the caller's is mutated: not this variant's shape, let it be
    returned = {r.value.id for r in _returns(before, value=True) if isinstance(r.value, ast.Name)}
    returned |= {r.value.id for r in _returns(after, value=True) if isinstance(r.value, ast.Name)}
    if not (mutated & returned):
        target = sorted(mutated)[0]
        return (f"gate: `{target}` is mutated in place and never returned — the copy is discarded and "
                f"the function's only effect with it.")
    return None


def _mutated_params(tree: ast.AST) -> set:
    """Parameters the span mutates: `p.append(...)`-style calls and `p[k] = v`."""
    params, out = _params(tree), set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
            if n.func.value.id in params and n.func.attr in (
                    "append", "extend", "insert", "add", "update", "pop", "remove", "clear", "sort", "setdefault"):
                out.add(n.func.value.id)
        elif isinstance(n, (ast.Assign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id in params:
                    out.add(t.value.id)
    return out


def _not_implemented(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """Owner ruling 2: the arm the rewrite stubs out must already be EMPTY / declared-only (`pass`,
    `...`, a reserved stub, `raise NotImplemented`). A value-producing arm is out of scope —
    identical-branch detection licenses collapsing, not raising."""
    gained = _counts(after, _is_notimplemented_raise) - _counts(before, _is_notimplemented_raise)
    if gained <= 0:
        return None
    live = [b for b in _branch_bodies(before) if not _is_stub_body(b)]
    if not live:
        return None
    return ("gate: the branch this would stub out already does work — `NotImplementedError` in place of "
            "a value-producing arm is a new behaviour, not a repair; only an empty or declared-only body "
            "qualifies.")


PREDICATES[("*", "else_not_implemented")] = _not_implemented
PREDICATES[("*", "later_not_implemented")] = _not_implemented
PREDICATES[("*", "branch_not_implemented")] = _not_implemented


def _is_notimplemented_raise(n: ast.AST) -> bool:
    if not isinstance(n, ast.Raise) or n.exc is None:
        return False
    name = _dotted(n.exc.func) if isinstance(n.exc, ast.Call) else _dotted(n.exc)
    return name.split(".")[-1] in ("NotImplementedError", "NotImplemented")


def _branch_bodies(tree: ast.AST) -> List[List[ast.stmt]]:
    out: List[List[ast.stmt]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.If):
            out.append(list(n.body))
            if n.orelse and not (len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If)):
                out.append(list(n.orelse))
    return out


def _nai006_last_live(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """Owner ruling 1: of the dead/live pair only the FIRST write may be deleted. The generic
    `live_store_removed` says the same thing in the general case; this is the variant's own word."""
    return live_store_removed(rw, before, after)


PREDICATES[("NAI-006", "keep_first")] = _nai006_last_live
PREDICATES[("NAI-006", "keep_last")] = _nai006_last_live


def _dict_key(k: ast.expr) -> Tuple[str, object]:
    # a Constant keys by its VALUE so Python's own equality binds (1 == True == 1.0, 0 == False);
    # anything else keys by its text
    return ("const", k.value) if isinstance(k, ast.Constant) else ("expr", ast.dump(k))


def _dict_effect(d: ast.Dict) -> Dict[Tuple[str, object], str]:
    """What the literal evaluates to, key → the LAST value written for it (`**x` entries skipped —
    no rewriter here touches them)."""
    out: Dict[Tuple[str, object], str] = {}
    for k, v in zip(d.keys, d.values):
        if k is not None:
            out[_dict_key(k)] = ast.dump(v)
    return out


def _dict_literal_value_changed(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """FIX_63 (I-115; the FIX_56 ruling on dict literals): a dict literal is a sequence of stores into
    one object, and Python keeps the LAST value for a repeated key. `live_store_removed` reads store
    statements, not keys in a literal, so this is the gate's own word for NAI-175 / NAI-177: the literal
    must evaluate to the same mapping after the repair as before. Deleting the last entry promotes a value
    the program never held — an intent change, the client's (the shape lane)."""
    dicts_before = [n for n in ast.walk(before) if isinstance(n, ast.Dict)]
    dicts_after = [n for n in ast.walk(after) if isinstance(n, ast.Dict)]
    if len(dicts_before) != len(dicts_after):
        return (f"gate: the repair changed the number of dict literals ({len(dicts_before)} → "
                f"{len(dicts_after)}); a duplicate-key repair edits entries, never literals.")
    for b, a in zip(dicts_before, dicts_after):
        was, now = _dict_effect(b), _dict_effect(a)
        for key, val in was.items():
            if key not in now:
                return (f"gate: key `{key[1]!r}` left the literal at line {b.lineno} — the mapping the "
                        f"program evaluated no longer has it.")
            if now[key] != val:
                kept = next(ast.unparse(v) for k, v in zip(a.keys, a.values) if k is not None and _dict_key(k) == key)
                return (f"gate: the live (last) value for key `{key[1]!r}` at line {b.lineno} was "
                        f"deleted and `{kept}` promoted — Python keeps the last value for a repeated "
                        f"key, so the literal now evaluates to something the program never held.")
    return None


PREDICATES[("NAI-175", "keep_first")] = _dict_literal_value_changed
PREDICATES[("NAI-175", "keep_last")] = _dict_literal_value_changed
PREDICATES[("NAI-177", "keep_first")] = _dict_literal_value_changed
PREDICATES[("NAI-177", "keep_last")] = _dict_literal_value_changed


@predicate("NAI-131", "drop_value")
def _nai131_real_setter(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """Owner: "Prefix is not a setter." A real setter assigns to `self.<attr>`, and what it returns is
    an echo of what it stored — never a computed product (narrowing 3)."""
    name = _func_name(before)
    stores_self = any(isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" for t in n.targets)
        for n in ast.walk(before))
    if not stores_self:
        return (f"gate: `{name}` stores nothing on `self` — the `set_` prefix is not a setter, and the "
                f"value it returns is its public product.")
    echoes = _echoed_names(before) | {"self"}
    product = [r for r in _returns(before, value=True)
               if not (isinstance(r.value, ast.Name) and r.value.id in echoes)
               and not (isinstance(r.value, ast.Attribute) and _dotted(r.value).startswith("self."))]
    if product:
        expr = ast.unparse(product[0].value) if hasattr(ast, "unparse") and product[0].value else "a value"
        return (f"gate: `{name}` returns `{expr}` — a computed product, not an echo of what it stored; "
                f"the return is the API.")
    return None


def _hoisted_modules(before: ast.AST, after: ast.AST) -> List[str]:
    """The TOP-LEVEL module names the rewrite moved out of the body and INTO module scope: every
    module-level import of the after-span the before-span did not already have there. (NAI-008's
    after-span is `hoisted imports + "" + the import-free def`, so the delta is exactly the hoist.)"""
    was = {n for imp in module_level_imports(before) for n in imported_names(imp, ())}
    now = {n for imp in module_level_imports(after) for n in imported_names(imp, ())}
    return sorted({n.split(".")[0] for n in (now - was)})


@predicate("NAI-008", "import_hoist_fix")
def _nai008_eager_module(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """S7-T2 (owner 2026-09-21, HAND_CHECK_S6 point 1; I-126, packet Q3). The same hoist is RIGHT on a
    lazily-imported module and WRONG on one that runs at import time — T3's run 155 went 5 for 11 on
    one target for exactly this reason, and click's own suite (`test_imports.py::test_light_imports`)
    allowlists ~26 stdlib names at `import click`. So:

      the enclosing module is EAGER (reachable from a package root through module-level imports only)
      AND the hoisted module is not already in that eager closure   →   withheld.

    A lazy module (B7–B11: `_termui_impl`, `shell_completion`) is offered; a name already imported at
    import time is offered on both, because hoisting it adds nothing to what the package pulls in.
    NOT MEASURED — no closure, no file — withholds nothing (the gate's fail-open rule)."""
    closure = rw.eager if rw.eager is not None else eager_closure()
    if closure is None or not rw.file or not closure.is_eager(rw.file):
        return None
    fresh = [m for m in _hoisted_modules(before, after) if not closure.has_name(m)]
    if not fresh:
        return None
    chain = " → ".join(closure.path_to(rw.file))
    names = ", ".join(f"`{m}`" for m in fresh)
    return (f"gate: eager: {chain} — this module already runs at import time, so hoisting {names} to "
            f"module scope adds it to what importing the package costs; the deferred import is the "
            f"contract, not an oversight.")


@predicate("NAI-078", "log_and_return")
def _nai078_log_and_return(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """S7-T2 (owner 2026-09-21, HAND_CHECK_S6 Part B; packet Q2). The owner walked six standing
    `log_and_return` patches on click and scored all six WRONG: `LookupError` is the documented
    unknown-codec fallback, `Exception` around `readable`/`writable`/`seekable` is a capability probe,
    `OSError`/`UnsupportedOperation` means "this fd is not a console", and `strptime`'s `ValueError` is
    the walk-the-formats loop. An expected control-flow exception is not a swallowed bug, and the patch
    adds the in-handler `import logging` that NAI-008 exists to flag. Under the S5 principle —
    unattended repair must preserve observable behavior; intent-changing variants go through the
    client — a new log line plus a new in-handler import is intent-changing on EVERY target, not only
    on click. Withheld always; the row falls to prescribed / `no_vetted_fix`, and the candidate stays
    on the row (never dropped) so the shape lane can still render it."""
    return ("gate: intent-changing: adds a log line and an in-handler import "
            "(owner 2026-09-21, HAND_CHECK_S6 Part B)")


@predicate("NAI-078", "narrow_and_log")
def _nai078_narrow_and_log(rw: Rewrite, before: ast.AST, after: ast.AST) -> Optional[str]:
    """S7-T2 follow-up (owner 2026-09-21, the same ruling, on a MEASUREMENT of what the generator
    emits rather than on its name). `safety.fix_fallback_return`'s `narrow_and_log` runs the SAME
    `_log_into` helper unconditionally over every handler BEFORE it narrows anything, so its diff
    carries the identical two rows `log_and_return` carries — `import logging` and
    `logging.getLogger(__name__).debug(…, exc_info=True)` — inserted directly above the same
    untouched fallback `return`; the `except:` → `except Exception:` narrowing is added ON TOP of
    that, never instead of it. Measured on the generator's own output:

        log_and_return   inserts  ['import logging', 'logging.getLogger(__name__).debug(…)']
        narrow_and_log   inserts  ['except Exception:', 'import logging', 'logging.getLogger(…)']

    It is a strict SUPERSET of `log_and_return`, so the log-paired-with-the-return the owner ruled
    intent-changing is present verbatim in both — same class, same sentence, withheld on every
    target. The narrowing ALONE would be behaviour-preserving, but it is not offered alone; peeling
    the log out of the generator is a change this ruling did not ask for once the measurement showed
    the log line is emitted here (branch (b) of the follow-up does not apply)."""
    return ("gate: intent-changing: `narrow_and_log` adds the same log line and in-handler import "
            "before the fallback return, and narrows the handler on top "
            "(owner 2026-09-21, HAND_CHECK_S6 Part B)")


# ── the gate ────────────────────────────────────────────────────────────────────────────────────

def failures(rw: Rewrite) -> List[Tuple[str, str]]:
    """Every check (and the variant's predicate) that would withhold this rewrite, in order.
    Empty = the rewrite is publishable. Never raises."""
    before, after = _parse(rw.before_src), _parse(rw.after_src)
    if before is None or after is None:
        return []        # a span that will not parse is the Builder's parse=fail, not the gate's
    out: List[Tuple[str, str]] = []
    for name, fn in CHECKS:
        try:
            reason = fn(rw, before, after)
        except Exception:
            reason = None          # fail-open: the gate never loses a right repair to its own accident
        if reason:
            out.append((name, reason))
    # A finite-set candidate arrives as `<role>:<variant>` and carries a variant (NAI-078's
    # `log_and_return`); a SINGLE-candidate rewriter has only its role (NAI-008's `import_hoist_fix`),
    # which is the name the hand check, the ledger and `selected_role` all call its variant. S7-T2: so
    # the role is the SECOND key tried — a predicate may be declared beside either spelling, and no
    # existing key's meaning moves.
    variant = rw.variant or rw.role
    pred = predicate_for(rw.rule_id, rw.variant) or predicate_for(rw.rule_id, rw.role)
    if pred is not None:
        try:
            reason = pred(rw, before, after)
        except Exception:
            reason = None
        if reason:
            out.append((f"predicate:{rw.rule_id}:{variant}", reason))
    return out


def check(rw: Rewrite) -> GateVerdict:
    """THE gate. ok=False → the rewrite is offered WITHHELD with `reason` in decision.why.

    FIX_61 (a): a no-fix-by-design answer outranks a generic post-condition. Both are true of a
    declared row (NAI-017's `drop_suppress` also thins a fallback out), but they say different
    things — "this rewrite would change behaviour" vs "this rule has no unattended repair at all" —
    and the second is the prior statement, so it is the sentence the row publishes."""
    failed = failures(rw)
    if not failed:
        return GateVerdict(ok=True, reason=None, rule="")
    rule, reason = next(((r, w) for r, w in failed if BY_DESIGN in w), failed[0])
    return GateVerdict(ok=False, reason=reason, rule=rule)


# ── S9-T1, the I-150 FOLLOW-UP (owner ruling 2026-09-21): G0 over a PRESCRIPTION ─────────────────
#
# THE GAP THIS CLOSES. `check()` / `failures()` need BOTH trees, and a prescribed solution's
# `after_src` is a SHAPE — a template carrying `<placeholders>` that is not Python and never parses
# — so G0 has never been able to judge one. That is why I-150's damaging offer reached run 162's
# client with nothing between it and a seat that trusts it. This is the same gate over the half that
# DOES parse: the site's own bytes, plus the module the span was cut from. Nothing about `check()`,
# `failures()` or `PREDICATES` moves; a prescribed role with no entry here passes, exactly as before.

#: The lane contract for a prescription, keyed (rule_id, prescribed role). Same callable shape as
#: PREDICATES; the `after` tree is the BEFORE tree (there is no parsable after), so a predicate here
#: reads the site, never a rewrite.
PRESCRIPTION_PREDICATES: Dict[Tuple[str, str], PredicateFn] = {}


def prescription_check(rw: Rewrite) -> GateVerdict:
    """G0 asked about a PRESCRIBED solution. ok=False → the prescription is offered WITHHELD, the
    candidate is unpickable and the sentence rides into the row's `decision.why`, exactly as a
    withheld rewrite's does. Never raises: the gate is never the reason a right solution is lost."""
    before = _parse(rw.before_src)
    if before is None:
        return GateVerdict(ok=True, reason=None, rule="")     # parse=fail is the Builder's, not the gate's
    fn = PRESCRIPTION_PREDICATES.get((rw.rule_id, rw.role))
    if fn is None:
        return GateVerdict(ok=True, reason=None, rule="")
    try:
        reason = fn(rw, before, before)
    except Exception:
        reason = None
    if not reason:
        return GateVerdict(ok=True, reason=None, rule="")
    return GateVerdict(ok=False, reason=reason, rule=f"prescription:{rw.rule_id}:{rw.role}")


def _class_defining(module_src: str, class_name: str, method_name: str) -> bool:
    """True when `module_src` defines `class <class_name>` and that class body defines
    `def <method_name>`. The SHAPE of the site — a class name and a method name, never a line
    number, because line numbers drift with every edit above them."""
    tree = _parse(module_src)
    if tree is None:
        return False                 # NOT MEASURED — withhold nothing (the gate's fail-open rule)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            if any(isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name == method_name
                   for m in node.body):
                return True
    return False


#: I-150's sibling, the ONE site the owner ruled on: `click.utils._KeepOpenFile.__exit__`.
_KEEPOPEN_MODULE, _KEEPOPEN_CLASS, _KEEPOPEN_METHOD = "click/utils.py", "_KeepOpenFile", "__exit__"

#: the sentence the row publishes, the owner's own (2026-09-21), with the two tests named.
_KEEPOPEN_REASON = (
    "gate: keep-open / no-op context manager; rewrite would close what the wrapper is bound to "
    "leave open (owner 2026-09-21; applying reddens 2 tests: "
    "tests/test_utils/test_open_file.py::test_open_file, "
    "tests/test_utils/test_open_file.py::test_open_file_ignore_errors_stdin)")


def _nai120_keepopen_exit(rw: Rewrite, before: ast.AST, _after: ast.AST) -> Optional[str]:
    """Owner ruling, 2026-09-21, narrowed to the SITE: withhold `solution_NAI-120` on
    `click.utils._KeepOpenFile.__exit__` and on nothing else.

    FOUR facts, all of them the site's own shape and none of them a line number:
      1. the file is `click/utils.py`;
      2. the span's own def is named `__exit__`;
      3. the module defines `class _KeepOpenFile` and that class body defines `__exit__` —
         the class+method shape, which survives every edit above it;
      4. the body is still the no-op it is (`_is_stub_body`). If someone gives this `__exit__` real
         work, this is no longer the site the owner ruled on and the withhold lifts itself.

    The DETECTOR is untouched: NAI-120 still fires here, the row still publishes, and it publishes
    withheld with this sentence. An empty `__exit__` anywhere else still fires AND is still offered
    the repair — nothing here reaches another site, another rule or another solution."""
    if not rw.file.replace("\\", "/").endswith(_KEEPOPEN_MODULE):
        return None
    fn = _target_func(before)
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name != _KEEPOPEN_METHOD:
        return None
    if not _class_defining(rw.module_src, _KEEPOPEN_CLASS, _KEEPOPEN_METHOD):
        return None
    if not _is_stub_body(fn.body):
        return None
    return _KEEPOPEN_REASON


PRESCRIPTION_PREDICATES[("NAI-120", "solution_NAI-120")] = _nai120_keepopen_exit
