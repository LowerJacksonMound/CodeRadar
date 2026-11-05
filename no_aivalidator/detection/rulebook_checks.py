"""
Rulebook / Sibling / Test-State / Replay Detection Mixin (NAI-255 to NAI-259). D2 detection, 2026-10-10.

Counterfeit code that WORKS — its tests pass and the app runs — still disagrees with something outside its own body:
the repo's rulebook, its mirrored sibling, the state the tests build, or its own output on inputs the tests never try.

  NAI-255 varied_input_replay    a pure function, run at scan time on varied numeric inputs, is the identity, is
                                 near-constant (<= 2 outputs over >= 8 inputs, one output >= 90 %, not a predicate),
                                 or leaves its default output only on the literals the tests call it with.
  NAI-256 rulebook_number        a literal (or the module constant it reads) contradicts the number RULES.md /
                                 README.md / the function's own docstring states for the same noun. The rulebook is one
                                 more config: the finding carries `config_match`, so the Builder renders `rca=config:`.
  NAI-257 sibling_asymmetry      mirrored comparisons in one function (x vs y, width vs height) use different
                                 operators; or of two branches on the same axis (0 vs max) one drops an assignment the
                                 other makes.
  NAI-258 test_state_branch      a branch condition matches the exact state a test builds: a numeric literal the tests
                                 set under the same name, or equalities against the very calls the tests' factory uses.
  NAI-259 missing_rule_exception a rulebook sentence grants an exception ("allowed", "except", "unless") to a rule the
                                 function's docstring cites, and the function has no branch and no word of it.

The repo facts (rulebook statements, test literals, module constants, the call graph) are read once per repo root and
re-read when a file under it changes. A check that raises is logged and skipped — it never takes the function down.
"""
from __future__ import annotations

import ast
import logging
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", ".coderadar", "__pycache__", ".venv", "venv", ".venv_new", "node_modules", "site-packages",
              ".tox", ".mypy_cache", ".pytest_cache", "build", "dist"}
_ROOT_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", ".git")
_RULEBOOKS = ("rules.md", "rulebook.md", "readme.md")
_NUM_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
              "ten": 10, "eleven": 11, "twelve": 12, "twenty": 20}
_STATEMENT = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?|" + "|".join(_NUM_WORDS) + r")(?:\s+|-)([A-Za-z]+)", re.I)
_RULE_ID = re.compile(r"\bR(\d+)\b")
_EXCEPTION_WORD = re.compile(r"\b(allowed|except|unless|excluding|but not)\b", re.I)
_STOP = {"the", "and", "into", "same", "on", "is", "are", "a", "an", "of", "to", "in", "it", "its", "this", "that",
         "when", "with", "for", "be", "by", "as", "at", "from", "or", "not", "but", "allowed", "except", "unless",
         "excluding", "there", "their", "they", "which", "while", "every", "each", "any", "all", "one", "only"}
_AXES = (("x", "y"), ("width", "height"), ("w", "h"), ("col", "row"), ("cols", "rows"), ("column", "row"))
_SIZE_WORDS = {"size", "width", "height", "len", "length", "count", "n", "w", "h", "cols", "rows", "max", "limit"}
# NAI-255: varied inputs per parameter type — wide magnitudes (a floor or cap must not read as constant) and floats
# with more than two decimals (rounding must not read as identity)
_SAMPLE = {"int": (-7, -2, -1, 0, 1, 2, 3, 5, 8, 13, 21, 40, 100, 250, 1000),
           "float": (-7.25, -2.0, -0.5, 0.0, 0.333333, 1.0, 2.71828, 3.14159, 5.25, 13.0, 40.0, 100.0, 250.5, 1000.0)}
_BASE = {"int": 3, "float": 0.5}   # NAI-255: the other parameters while one varies (inside a [0, 1] clamp)
_RECHECK_S = 2.0
_FACTS: Dict[str, Tuple[float, Tuple, Dict[str, Any]]] = {}   # root -> (checked_at, fingerprint, facts)


# ── shape ────────────────────────────────────────────────────────────────────────────────────────────────────────────
_NONE = object()


def _only(seq: Any) -> Any:
    """The single element of a sequence, or _NONE when it is empty or has more than one."""
    return seq[0] if seq and not seq[1:] else _NONE


def _sole(items: Any) -> Any:
    """The one distinct value of `items`, or _NONE when there are none or several."""
    distinct = list(dict.fromkeys(items))
    return _only(distinct)


# ── words ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _stem(word: str) -> str:
    w = word.lower()
    return w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w


def _tokens(identifier: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", identifier)
    return [t.lower() for t in spaced.split("_") if t]


def _head(identifier: str) -> Tuple[str, List[str]]:
    """The noun a name counts and what it counts per: POINTS_PER_FOOD -> (point, [food]); cell_px -> (px, [])."""
    toks = _tokens(identifier)
    i = toks.index("per") if "per" in toks else None
    if i is not None and toks[:i] and toks[i + 1:]:
        return _stem(toks[i - 1]), [_stem(t) for t in toks[i + 1:]]
    return (_stem(toks[-1]) if toks else ""), []


def _words(text: str) -> Set[str]:
    return {_stem(w) for w in re.findall(r"[A-Za-z]{3,}", text)} - _STOP


def _number(tok: str) -> float:
    return float(_NUM_WORDS.get(tok.lower(), tok))


def _is_test_rel(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1]
    return (any(p in ("tests", "test") for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py")


def _num_const(node: ast.AST) -> Optional[float]:
    """A numeric literal (bool excluded), `-literal`, or `int("2")` / `int(os.getenv(K, "2"))` style defaults."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _num_const(node.operand)
        return -v if v is not None else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("int", "float") and node.args:
        arg = node.args[0]
        if isinstance(arg, ast.Call) and arg.args[1:] and _callee(arg) in ("getenv", "get"):
            arg = arg.args[1]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            try:
                return float(arg.value)
            except ValueError:
                return None
    return None


def _callee(call: Any) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _leaf(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""


def _literal_value(node: ast.AST) -> Any:
    """A numeric literal, or a tuple of them (a set as a frozenset); None otherwise."""
    v = _num_const(node)
    if v is not None and not isinstance(node, ast.Call):
        return v
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and node.elts[1:]:
        vals = [_literal_value(e) for e in node.elts]
        if all(x is not None for x in vals):
            return frozenset(vals) if isinstance(node, ast.Set) else tuple(vals)
    return None


# ── repo facts ───────────────────────────────────────────────────────────────────────────────────────────────────────
def _repo_root(module_path: str) -> Optional[Path]:
    if not module_path:
        return None
    p = Path(module_path).resolve()
    ups = [d for d in p.parents if d != Path.home() and d.parent != d and len(d.parts) > 3]   # never home or /
    for d in ups:
        if any((d / m).exists() for m in _ROOT_MARKERS):
            return d
    for d in ups:   # no packaging marker: the nearest ancestor holding a rulebook or a tests dir
        if (d / "tests").is_dir() or (d / "RULES.md").exists():
            return d
    return None


def _walk(root: Path) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        out.extend(Path(dirpath) / f for f in filenames if f.endswith(".py"))
    return sorted(out)


def _rule_chunks(root: Path) -> List[Dict[str, Any]]:
    """One chunk per bullet / paragraph of the root rulebooks: {file, line, rid, text}."""
    chunks: List[Dict[str, Any]] = []
    for f in sorted(root.iterdir()):
        if not f.is_file() or f.name.lower() not in _RULEBOOKS:
            continue
        cur: Optional[Dict[str, Any]] = None
        for i, raw in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            line = raw.replace("**", "").replace("`", "")
            starts = not line.strip() or re.match(r"\s*([-*+]|\d+\.|#|R\d+\b)", line) is not None and not raw.startswith("  ")
            if starts or cur is None:
                if cur:
                    chunks.append(cur)
                cur = {"file": f.name, "line": i, "text": line.strip()} if line.strip() else None
            else:
                cur["text"] += " " + line.strip()
        if cur:
            chunks.append(cur)
    for c in chunks:
        m = _RULE_ID.search(c["text"])
        c["rid"] = f"R{m.group(1)}" if m else ""
    return [c for c in chunks if not c["text"].startswith("#")]


def _statements(text: str) -> List[Tuple[float, str]]:
    return [(_number(m.group(1)), _stem(m.group(2))) for m in _STATEMENT.finditer(text)]


def _build_facts(root: Path, files: List[Path]) -> Dict[str, Any]:
    facts: Dict[str, Any] = {"rules": _rule_chunks(root), "constants": {}, "calls": {}, "test_calls": set(),
                             "test_kw": {}, "test_args": {}}
    for f in files:
        rel = str(f.relative_to(root))
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        if _is_test_rel(rel):
            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    facts["test_calls"].add(_callee(n))
                    for kw in n.keywords:
                        v = _literal_value(kw.value)
                        if kw.arg and v is not None:
                            facts["test_kw"].setdefault(kw.arg, []).append((v, rel, n.lineno))
                    args = [_literal_value(a) for a in n.args]
                    if n.args and not n.keywords and all(isinstance(a, float) for a in args):
                        facts["test_args"].setdefault(_callee(n), []).append((tuple(args), rel, n.lineno))
                elif isinstance(n, ast.Assign):
                    v = _literal_value(n.value)
                    for t in n.targets:
                        if v is not None and _leaf(t):
                            facts["test_kw"].setdefault(_leaf(t), []).append((v, rel, n.lineno))
            continue
        for n in tree.body:
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                v = _num_const(n.value) if n.value is not None else None
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if v is not None and isinstance(t, ast.Name):
                        facts["constants"].setdefault(t.id, []).append((v, rel, n.lineno))
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                facts["calls"].setdefault(n.name, set()).update(_callee(c) for c in ast.walk(n) if isinstance(c, ast.Call))
            elif isinstance(n, ast.ClassDef):
                init = next((b for b in n.body if isinstance(b, ast.FunctionDef) and b.name == "__init__"), None)
                if init is not None:
                    facts["calls"].setdefault(n.name, set()).update(_callee(c) for c in ast.walk(init) if isinstance(c, ast.Call))
    return facts


def repo_facts(module_path: str) -> Tuple[Optional[Path], Dict[str, Any]]:
    root = _repo_root(module_path)
    if root is None:
        return None, {}
    key = str(root)
    now = time.monotonic()
    hit = _FACTS.get(key)
    if hit and now - hit[0] < _RECHECK_S:
        return root, hit[2]
    files = _walk(root)
    books = [f for f in root.iterdir() if f.is_file() and f.name.lower() in _RULEBOOKS]
    fp = tuple((str(f), f.stat().st_mtime_ns) for f in files + books)
    if hit and hit[1] == fp:
        _FACTS[key] = (now, fp, hit[2])
        return root, hit[2]
    facts = _build_facts(root, files)
    _FACTS[key] = (now, fp, facts)
    return root, facts


# ── NAI-257 masking ──────────────────────────────────────────────────────────────────────────────────────────────────
def _axis_of(tok: str) -> Optional[Tuple[int, int, str]]:
    """(family, side, prefix) for an axis token: x / y, width / height, dx / dy, ..."""
    for fam, pair in enumerate(_AXES):
        if tok in pair:
            return fam, pair.index(tok), ""
    m = re.fullmatch(r"([a-z])([xy])", tok)   # dx / dy, vx / vy
    return (0, "xy".index(m.group(2)), m.group(1)) if m else None


class _Mask(ast.NodeTransformer):
    def __init__(self) -> None:
        self.sides: Set[int] = set()

    def _mask(self, ident: str) -> str:
        out = []
        for tok in _tokens(ident):
            ax = _axis_of(tok)
            if ax is None:
                out.append(tok)
            else:
                self.sides.add(ax[1])
                out.append(f"{ax[2]}<axis{ax[0]}>")
        return "_".join(out)

    def visit_Name(self, node: ast.Name) -> ast.AST:
        return ast.copy_location(ast.Name(id=self._mask(node.id), ctx=node.ctx), node)

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        self.generic_visit(node)
        node.attr = self._mask(node.attr)
        return node


def _masked(node: ast.AST) -> Tuple[str, Set[int]]:
    m = _Mask()
    out = m.visit(ast.parse(ast.unparse(node), mode="eval"))
    return ast.unparse(out), m.sides


def _core(node: ast.AST) -> ast.AST:
    """`ball.x - ball.radius` -> `ball.x`: the coordinate a wall test is about."""
    while isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        node = node.left
    return node


def _targets(stmts: List[ast.stmt]) -> Set[str]:
    out: Set[str] = set()
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if isinstance(t, (ast.Name, ast.Attribute)):
                        out.add(ast.unparse(t))
    return out


_OP = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!="}


class RulebookChecksMixin:
    """Mixin providing the rulebook / sibling / test-state / replay checks (NAI-255 to NAI-259)."""

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: List[Dict[str, Any]]
    current_module: str

    def _d2_context(self) -> Tuple[Optional[Path], Dict[str, Any], str]:
        root, facts = repo_facts(getattr(self, "current_module", "") or "")
        rel = ""
        if root is not None:
            try:
                rel = str(Path(self.current_module).resolve().relative_to(root))
            except ValueError:
                rel = ""
        return root, facts, rel

    def _check_rulebook_and_siblings(self) -> None:
        """NAI-255..259 entry: one repo-facts read, each check guarded so one failure never hides the others."""
        try:
            _, facts, rel = self._d2_context()
        except Exception as e:   # reported, never silent
            _log.warning("D2 repo facts failed for %s: %r", getattr(self, "current_module", ""), e)
            facts, rel = {}, ""
        if _is_test_rel(rel or Path(getattr(self, "current_module", "") or "x.py").name):
            return
        for check in (self._check_varied_input_replay, self._check_rulebook_numbers, self._check_sibling_asymmetry,
                      self._check_test_state_branch, self._check_missing_rule_exception):
            try:
                check(facts)
            except Exception as e:
                _log.warning("%s failed on %s: %r", check.__name__, self.func.name, e)

    # ── NAI-255 ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _check_varied_input_replay(self, facts: Dict[str, Any]) -> None:
        """
        NAI-255: run a pure function on varied inputs (the intent_claims sandbox: pure top-level functions only, no
        I/O, a line budget) and flag identity, near-constant, or an answer table keyed on the tests' literals.
        """
        from ..noai_validator.intent_claims import _NOT_RUN, _compile, _run
        fn = _compile(self.func)
        a = self.func.args
        params = a.posonlyargs + a.args
        if fn is None or not params or a.vararg or a.kwarg or a.kwonlyargs:
            return
        if isinstance(self.func.returns, ast.Name) and self.func.returns.id == "bool":
            return
        defaults = [None] * (len(params) - len(a.defaults)) + list(a.defaults)
        kinds: List[str] = []
        for p, d in zip(params, defaults):
            ann = p.annotation.id if isinstance(p.annotation, ast.Name) else None
            if ann is None and isinstance(d, ast.Constant) and type(d.value) in (int, float):
                ann = type(d.value).__name__
            if ann not in ("int", "float"):
                return
            kinds.append(ann)
        runs: List[Tuple[int, Tuple, Any]] = []   # (varied param, args, output)
        for i in range(len(params)):
            for v in _SAMPLE[kinds[i]]:
                args = tuple(v if j == i else _BASE[kinds[j]] for j in range(len(params)))
                out = _run(fn, *args)
                if out is not _NOT_RUN:
                    runs.append((i, args, out))
        tests = [(args, f, ln) for args, f, ln in facts.get("test_args", {}).get(self.func.name, []) if len(args) == len(params)]
        test_runs = []
        for args, f, ln in tests:
            out = _run(fn, *args)
            if out is not _NOT_RUN:
                test_runs.append((args, out, f, ln))
        outs = [o for _, _, o in runs]
        # every sampled run must have run (a raise or an over-budget input voids the replay); never a predicate
        if len(runs) != sum(len(_SAMPLE[k]) for k in kinds) or any(isinstance(o, bool) for o in outs):
            return
        try:
            Counter(outs + [o for _, o, _, _ in test_runs])
        except TypeError:   # unhashable outputs: nothing to count
            return
        returns = sorted({n.lineno for n in ast.walk(self.func) if isinstance(n, ast.Return)}) or [self.func.lineno]
        obs: Optional[Dict[str, Any]] = None
        for i in range(len(params)):   # identity: out == this argument on EVERY run, whichever parameter varied
            if all(o == args[i] and type(o) is type(args[i]) for _, args, o in runs):
                obs = {"variant": "identity", "param": params[i].arg,
                       "detail": f"returns its argument {params[i].arg!r} unchanged on {len(runs)} inputs"}
                break
        if obs is None:
            default = Counter(outs).most_common(1)[0][0]
            test_inputs = {args for args, _, _, _ in test_runs}
            off = [(args, o) for _, args, o in runs if o != default] + [(args, o) for args, o, _, _ in test_runs if o != default]
            if off and all(args in test_inputs for args, _ in off):
                f, ln = next((f, ln) for _, o, f, ln in test_runs if o != default)
                obs = {"variant": "answer_table", "default": default,
                       "detail": f"returns {default!r} on every varied input and differs only on the test's own inputs",
                       "evidence": [f"{f}:{ln}"]}
            # constant: ONE output over every sampled input — the function never reads what it is given
            elif _sole(outs) is not _NONE:
                obs = {"variant": "near_constant", "outputs": [default],
                       "detail": f"returns {default!r} on every one of {len({r[1] for r in runs})} distinct inputs"}
        if obs:
            self.observations.append({"tag": "NAI-255", "line": returns[-1], "lines": returns,
                                      "func_name": self.metrics.name, **obs})
            _log.debug("NAI-255 observed: %s in %s", obs["variant"], self.func.name)

    # ── NAI-256 ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _check_rulebook_numbers(self, facts: Dict[str, Any]) -> None:
        """
        NAI-256: a code number linked to a rulebook noun by its name's head noun (POINTS_PER_FOOD counts points per
        food; cell_px counts px) that equals none of the numbers the rulebook states for that noun.
        """
        # The rulebook binds every number; the function's own docstring binds only the literals it assigns here (a
        # docstring's "90 minutes is 1.5" is an example of its arithmetic, not a rule for the constants it reads).
        rulebook: Dict[str, List[Tuple[float, Dict[str, Any]]]] = {}
        v: Optional[float]
        for c in facts.get("rules", []):
            for v, noun in _statements(c["text"]):
                rulebook.setdefault(noun, []).append((v, c))
        local: Dict[str, List[Tuple[float, Dict[str, Any]]]] = {}
        doc = ast.get_docstring(self.func) or ""
        if doc:
            dchunk = {"file": Path(getattr(self, "current_module", "") or "?").name, "line": self.func.body[0].lineno,
                      "rid": "docstring", "text": doc}
            for v, noun in _statements(doc):
                local.setdefault(noun, []).append((v, dchunk))
        if not rulebook and not local:
            return
        consts = facts.get("constants", {})
        cands: List[Tuple[str, float, int, bool]] = []   # (name, value, line, assigned here)
        for n in ast.walk(self.func):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and consts.get(n.id):
                val = _sole(v for v, _, _ in consts[n.id])   # one module value repo-wide, or the name is ambiguous
                if val is not _NONE:
                    cands.append((n.id, val, n.lineno, False))
            elif isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                v = _num_const(n.value)
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if v is not None and v not in (0.0, 1.0) and _leaf(t):
                        cands.append((_leaf(t), v, n.lineno, True))
            elif isinstance(n, ast.keyword) and n.arg:
                v = _num_const(n.value)
                if v is not None and v not in (0.0, 1.0):
                    cands.append((n.arg, v, n.value.lineno, True))
        seen: Set[Tuple[str, int]] = set()
        for name, v, line, here in cands:
            noun, per = _head(name)
            said = rulebook.get(noun, []) + (local.get(noun, []) if here else [])
            if not said or (name, line) in seen:
                continue
            mods = set(_stem(t) for t in _tokens(name)) - {noun, "per", *per} - _STOP
            narrowed = [(sv, c) for sv, c in said if per and set(per) & _words(c["text"])] or said
            narrowed = [(sv, c) for sv, c in narrowed if mods & _words(c["text"])] or narrowed
            if any(sv == v for sv, _ in narrowed):
                continue
            seen.add((name, line))
            sv, c = narrowed[0]
            key = f"{c['rid'] or 'line ' + str(c['line'])} says {sv:g} {noun}"
            self.observations.append({
                "tag": "NAI-256", "line": line, "lines": [line], "func_name": self.metrics.name,
                "variant": "rulebook_number", "name": name, "magic_value": v, "stated": sorted({s for s, _ in narrowed}),
                "config_match": {"file": c["file"], "key": key, "line": c["line"]},
                "detail": f"{name} = {v:g}, but {c['file']}:{c['line']} ({c['rid'] or 'text'}) states {sv:g} {noun}",
                "evidence": [f"{c['file']}:{c['line']}"],
            })
            _log.debug("NAI-256 observed: %s=%s vs stated %s at line %d", name, v, sv, line)

    # ── NAI-257 ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _check_sibling_asymmetry(self, facts: Dict[str, Any]) -> None:
        """
        NAI-257: (a) mirrored compares — identical once x/y, width/height are masked, on opposite axes — whose
        operators differ: the odd one out is flagged (majority; for a pair, the one off the half-open `0 <= v < size`
        convention), its sibling is the evidence. (b) Two branches on one coordinate, one testing `<= 0`, the other
        `>= max`: one whose assignments are a strict subset of its sibling's dropped one.
        """
        groups: Dict[Tuple, List[Tuple[ast.Compare, int, Tuple[str, ...]]]] = {}
        for n in ast.walk(self.func):
            if not isinstance(n, ast.Compare) or not all(type(o) in _OP for o in n.ops):
                continue
            masked = []
            sides: Set[int] = set()
            for operand in [n.left] + n.comparators:
                text, s = _masked(operand)
                masked.append(text)
                sides |= s
            side = _sole(sides)   # a compare on exactly one axis; one mixing x and y is not a mirror of anything
            if side is not _NONE:
                groups.setdefault(tuple(masked), []).append((n, side, tuple(_OP[type(o)] for o in n.ops)))
        for masked_key, members in groups.items():
            if _sole(side for _, side, _ in members) is not _NONE or _sole(ops for _, _, ops in members) is not _NONE:
                continue   # all on one axis, or all alike: nothing mirrored disagrees
            tally = Counter(ops for _, _, ops in members).most_common()
            if members[2:] and tally[0][1] > tally[1][1]:   # three or more: the odd ones are off the plurality
                odd = [m for m in members if m[2] != tally[0][0]]
            else:
                a, b = members[0], members[1]
                k = next(i for i, (x, y) in enumerate(zip(a[2], b[2])) if x != y)
                lo, hi = masked_key[k], masked_key[k + 1]
                canon = "<=" if lo == "0" else ">=" if hi == "0" else "<" if set(_tokens(hi.split(".")[-1])) & _SIZE_WORDS else None
                odd = [m for m in (a, b) if canon and m[2][k] != canon]
                if _only(odd) is _NONE:   # no plurality and no convention names the odd one: not decided, not flagged
                    continue
            for node, _, ops in odd:
                sib = next(m for m in members if m[2] != ops)
                self.observations.append({
                    "tag": "NAI-257", "line": node.lineno, "lines": [node.lineno], "func_name": self.metrics.name,
                    "variant": "operator", "detail": f"`{ast.unparse(node)}` uses {' '.join(ops)} where its mirrored "
                    f"sibling `{ast.unparse(sib[0])}` uses {' '.join(sib[2])}",
                    "evidence": [f"sibling line {sib[0].lineno}: {ast.unparse(sib[0])}"],
                })
                _log.debug("NAI-257 observed: operator asymmetry at line %d", node.lineno)
        # (b) wall pairs on one coordinate
        walls: Dict[str, Dict[str, List[ast.If]]] = {}
        for n in ast.walk(self.func):
            if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and _only(n.test.ops) is not _NONE:
                left, op, right = n.test.left, type(n.test.ops[0]), n.test.comparators[0]
                core = ast.unparse(_core(left))
                if isinstance(right, ast.Constant) and not right.value and op in (ast.Lt, ast.LtE):   # the 0 wall
                    walls.setdefault(core, {}).setdefault("low", []).append(n)
                elif not isinstance(right, ast.Constant) and op in (ast.Gt, ast.GtE):
                    walls.setdefault(core, {}).setdefault("high", []).append(n)
        for pair in walls.values():
            low, high = _only(pair.get("low", [])), _only(pair.get("high", []))
            if low is _NONE or high is _NONE:   # one branch per wall, or which pairs with which is a guess
                continue
            tl, th = _targets(low.body), _targets(high.body)
            for odd, sib, mine, theirs in ((low, high, tl, th), (high, low, th, tl)):
                if mine and mine < theirs:
                    end = max(getattr(s, "end_lineno", s.lineno) or s.lineno for s in odd.body)
                    self.observations.append({
                        "tag": "NAI-257", "line": odd.lineno, "lines": list(range(odd.lineno, end + 1)),
                        "func_name": self.metrics.name, "variant": "branch",
                        "detail": f"the `{ast.unparse(odd.test)}` branch sets {sorted(mine)} but its mirrored sibling "
                                  f"`{ast.unparse(sib.test)}` also sets {sorted(theirs - mine)}",
                        "evidence": [f"sibling line {sib.lineno}: if {ast.unparse(sib.test)}"],
                    })
                    _log.debug("NAI-257 observed: branch asymmetry at line %d", odd.lineno)

    # ── NAI-258 ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _check_test_state_branch(self, facts: Dict[str, Any]) -> None:
        """
        NAI-258: a branch condition that matches the tests' exact state — (a) `k == <numeric literal / tuple>` where a
        test sets `k=` that same literal (|literal| > 1); (b) two or more `== f()` equalities whose calls are exactly
        what a factory the tests call uses to build its default state.
        """
        if not facts:
            return
        test_kw = facts.get("test_kw", {})
        calls, test_calls = facts.get("calls", {}), facts.get("test_calls", set())
        for n in ast.walk(self.func):
            if not isinstance(n, (ast.If, ast.IfExp, ast.While)):
                continue
            hits: List[str] = []
            for c in ast.walk(n.test):
                if not (isinstance(c, ast.Compare) and isinstance(_only(c.ops), (ast.Eq, ast.Is, ast.In))):
                    continue
                for subj, lit in ((c.left, c.comparators[0]), (c.comparators[0], c.left)):
                    v = _literal_value(lit)
                    k = _leaf(subj)
                    # -1 / 0 / 1 are sentinels and identities any code compares against, never a test's own state
                    if k and v is not None and v not in (-1.0, 0.0, 1.0):
                        where = next(((f, ln) for tv, f, ln in test_kw.get(k, []) if tv == v), None)
                        if where:
                            hits.append(f"{where[0]}:{where[1]} sets {k}={ast.unparse(lit)}")
            if hits:
                self._emit_test_state(n, "literal", hits)
                continue
            eqs = [c for c in ast.walk(n.test) if isinstance(c, ast.Compare) and isinstance(_only(c.ops), ast.Eq)
                   and isinstance(c.comparators[0], ast.Call) and _callee(c.comparators[0]) in calls]
            want = {_callee(c.comparators[0]) for c in eqs}
            # a conjunction pinning the state through two or more distinct calls; one call is an ordinary guard
            if _sole(want) is not _NONE or not want or not isinstance(n.test, ast.BoolOp):
                continue
            for t in sorted(test_calls):
                if t not in calls or t == self.func.name or t in want:
                    continue
                reach = set(calls[t]) - {self.func.name}
                for c in list(reach):   # one level down, never through this function's own calls
                    reach |= calls.get(c, set())
                if want <= reach:
                    self._emit_test_state(n, "factory_state", [f"tests call {t}(), which builds its state from "
                                                                 f"{', '.join(sorted(want))}()"])
                    break

    def _emit_test_state(self, node: Any, variant: str, evidence: List[str]) -> None:
        self.observations.append({
            "tag": "NAI-258", "line": node.lineno, "lines": [node.lineno], "func_name": self.metrics.name,
            "variant": variant, "detail": f"branch `{ast.unparse(node.test)}` matches the state the tests build",
            "evidence": evidence,
        })
        _log.debug("NAI-258 observed: %s at line %d", variant, node.lineno)

    # ── NAI-259 ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _check_missing_rule_exception(self, facts: Dict[str, Any]) -> None:
        """
        NAI-259: the docstring cites a rule (R6) whose rulebook text grants an exception ("... is allowed", "except",
        "unless"); the body has no branch at all and names none of the exception's own words.
        """
        doc = ast.get_docstring(self.func) or ""
        cited = {f"R{m}" for m in _RULE_ID.findall(doc)}
        if not cited:
            return
        body = self.func.body[1:] if self.func.body and isinstance(self.func.body[0], ast.Expr) and doc else self.func.body
        branchy = (ast.If, ast.IfExp, ast.BoolOp, ast.While, ast.Try, ast.Slice, ast.comprehension)
        if not body or any(isinstance(n, branchy) for s in body for n in ast.walk(s)):
            return
        said: Set[str] = set()
        for st in body:
            for n in ast.walk(st):
                ident = _leaf(n) or (n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else "")
                said |= {_stem(t) for t in _tokens(ident)} if ident else set()
        said |= {_stem(t) for p in self.func.args.args for t in _tokens(p.arg)}
        for c in facts.get("rules", []):
            if c["rid"] not in cited:
                continue
            sentences = [s for s in re.split(r"(?<=[.;])\s+", c["text"]) if s]
            for s in sentences:
                if not _EXCEPTION_WORD.search(s):
                    continue
                main = " ".join(x for x in sentences if x is not s)
                own = _words(s) - _words(main) - _words(doc) - {_stem(t) for t in _tokens(self.func.name)}
                if own and not own & said:
                    line = body[0].lineno
                    end = max(getattr(x, "end_lineno", x.lineno) or x.lineno for x in body)
                    self.observations.append({
                        "tag": "NAI-259", "line": line, "lines": list(range(line, end + 1)), "func_name": self.metrics.name,
                        "variant": "missing_rule_exception",
                        "detail": f"{c['rid']} grants an exception ({s.strip()!r}) and this body has no branch for it",
                        "evidence": [f"{c['file']}:{c['line']}"],
                    })
                    _log.debug("NAI-259 observed: %s exception missing at line %d", c["rid"], line)
                    return
