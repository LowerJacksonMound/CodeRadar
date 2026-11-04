"""
Utility functions for the NoAI Validator.

Contains fingerprinting, duplicate detection, and symmetry analysis utilities.
"""

import ast
import asyncio
import hashlib
import logging
import tokenize
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union

_F = TypeVar('_F', bound=Callable[..., Any])

from .core import FunctionMetrics

logger = logging.getLogger(__name__)

__all__ = [
    "read_source",
    "fingerprint_function",
    "fingerprint_all_functions",
    "check_duplicate_functions",
    "check_suspicious_symmetry_229",       # FIX_17 (2026-09-10): renamed — the utils.code_analysis twin never collides again
    "symmetry_229_observation",
    "normalized_fingerprint",
    "check_normalized_duplicates_230",     # FIX_17: renamed likewise
    "normalized_duplicates_230_observations",
]

# Flow tracer integration (optional)
try:
    from flow_tracer import trace as _flow_trace, emit_trace, set_workflow
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False
    def _flow_trace(func: _F) -> _F: return func
    def emit_trace(*args: Any, **kwargs: Any) -> None: pass
    def set_workflow(*args: Any, **kwargs: Any) -> None: pass

def trace(func: _F) -> _F:
    return _flow_trace(func)  # type: ignore[no-any-return]


def read_source(filepath: Path) -> str:
    """A1 (2026-10-01, Q-H3b-4 / Q-H3b-5): read a target source the way Python does.

    `tokenize.open` honours a UTF-8 BOM and a PEP 263 coding declaration (default UTF-8) with
    universal newlines, so a BOM never reaches the parser as U+FEFF and a `# -*- coding: latin-1 -*-`
    file decodes. Raises OSError (unreadable), SyntaxError (unknown or conflicting coding cookie) or
    UnicodeDecodeError (bytes outside the declared codec); every caller reports those — a file this
    cannot decode is NOT MEASURED, never dropped.
    """
    with tokenize.open(filepath) as f:
        return f.read()


@trace
def fingerprint_function(node_or_metrics: Union[ast.FunctionDef, ast.AsyncFunctionDef, FunctionMetrics]) -> str:
    """
    Generate a structural fingerprint for a function.
    
    The fingerprint captures the structure of the function without
    considering specific names or values, allowing detection of
    structurally similar functions.
    
    Args:
        node_or_metrics: Either an AST node or FunctionMetrics object
    """
    parts = []
    
    # Handle FunctionMetrics
    if isinstance(node_or_metrics, FunctionMetrics):
        metrics = node_or_metrics
        parts.append(f"P{metrics.params}")
        # Build fingerprint from metrics
        for _ in range(metrics.returns):
            parts.append("R")
        for _ in range(metrics.yields):
            parts.append("Y")
        for _ in range(metrics.branches):
            parts.append("I")
        for _ in range(metrics.loops):
            parts.append("F")  # Approximate as for loops
        for _ in range(metrics.calls):
            parts.append("c")
        for _ in range(metrics.assigns):
            parts.append("a")
        for _ in range(metrics.comparisons):
            parts.append("=")
        
        structure = "".join(parts)
        return hashlib.sha256(structure.encode()).hexdigest()[:16]
    
    # Handle AST node
    node = node_or_metrics
    
    # Capture parameter structure
    params = len(node.args.args)
    parts.append(f"P{params}")
    
    # Capture structural elements
    for child in ast.walk(node):
        if isinstance(child, ast.Return):
            parts.append("R")
        elif isinstance(child, ast.Yield):
            parts.append("Y")
        elif isinstance(child, ast.If):
            parts.append("I")
        elif isinstance(child, ast.For):
            parts.append("F")
        elif isinstance(child, ast.While):
            parts.append("W")
        elif isinstance(child, ast.Try):
            parts.append("T")
        elif isinstance(child, ast.With):
            parts.append("C")
        elif isinstance(child, ast.Call):
            parts.append("c")
        elif isinstance(child, ast.Assign):
            parts.append("a")
        elif isinstance(child, ast.Compare):
            parts.append("=")
    
    structure = "".join(parts)
    
    # Hash for consistent length (SHA256 truncated for fingerprint)
    return hashlib.sha256(structure.encode()).hexdigest()[:16]


@trace
async def fingerprint_all_functions(filepath: Path) -> Dict[str, List[Tuple[str, str, int]]]:
    """
    Generate fingerprints for all functions in a file (async I/O).

    Returns:
        Dict mapping fingerprint -> [(func_name, fingerprint, line_number), ...]
    """
    logger.debug("Fingerprinting all functions in: %s", filepath)
    fingerprints: Dict[str, List[Tuple[str, str, int]]] = {}

    try:
        source = await asyncio.to_thread(read_source, filepath)   # A1: BOM / PEP 263 cookie honoured
        tree = ast.parse(source)
    except (SyntaxError, OSError, UnicodeDecodeError):
        return fingerprints

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fp = fingerprint_function(node)
            line = getattr(node, 'lineno', 0)

            if fp not in fingerprints:
                fingerprints[fp] = []
            fingerprints[fp].append((node.name, fp, line))

    logger.debug("Fingerprinted %s: %d unique fingerprints", filepath, len(fingerprints))
    return fingerprints

# Backward-compatible alias
fingerprint_all_functions_async = fingerprint_all_functions


@trace
def check_duplicate_functions(
    fingerprints: Dict[str, List[Tuple[str, str, int]]]
) -> List[Tuple[str, str, str]]:
    """
    Check for duplicate functions based on fingerprints.
    
    Returns:
        List of (rule_id, severity, message) tuples for detected duplicates.
    """
    issues = []
    
    for fp, funcs in fingerprints.items():
        if len(funcs) > 1:
            names = [f[0] for f in funcs]
            issues.append((
                "NAI-228",  # A1 renumber 2026-09-06: was NAI-090 (detection NAI-090 = single-letter vars); context inherited
                "HIGH",
                f"Duplicate function structure: {', '.join(names)}"
            ))
    
    return issues


def _repetition_229(node: ast.FunctionDef) -> Optional[Tuple[int, str, int]]:
    """FIX_17 (2026-09-10): the measurement behind NAI-229 — (count, statement type, statements) for the most
    repeated top-level statement type of the body; None for an empty body. The count is the MAGNITUDE the
    per-(rule, context) disposition table reads (owner ruling 2026-09-10); no threshold lives here
    (EXCISED cut 2, 2026-09-05: was `>= 4` / `count >= 4 and count / len(stmt_types) > 0.8`)."""
    stmt_types = [type(child).__name__ for child in node.body]
    if not stmt_types:
        return None
    from collections import Counter
    most_common, count = Counter(stmt_types).most_common(1)[0]
    return count, most_common, len(stmt_types)


def check_suspicious_symmetry_229(node: ast.FunctionDef) -> List[Tuple[str, str, str]]:
    """
    Check for suspicious structural symmetry in a function.

    Detects patterns like repeated similar blocks that may indicate
    copy-paste or generated code.

    FIX_17 (2026-09-10): renamed `_229` so the `utils.code_analysis.symmetry` twin never collides again;
    the route consumes `symmetry_229_observation` (the observation form carrying its magnitude).
    """
    issues = []
    rep = _repetition_229(node)
    if rep is not None:
        count, most_common, _total = rep
        issues.append((
            "NAI-229",  # A1 renumber: was NAI-091 (detection NAI-091 = in-place param mutation); live caller: file_validation (FIX_17)
            "MEDIUM",
            f"Suspicious repetitive structure: {count}x {most_common}"
        ))

    return issues


def disabled_case_236_observations(functions: List[Any]) -> Dict[str, Dict[str, Any]]:
    """owner 2026-10-07 (blind tree 1 L3, M-90): NAI-236 disabled_case — a function whose body is its twin's body with ONE
    extra leading `if <name / attribute / subscript> == <literal>: return <constant>` in front: the real logic is in
    the file, switched off for one named case (the ghost paddle: `if paddle["side"] == "right": return False` then the
    same `return _overlaps(...)` as left_paddle_blocks). Keyed `name@line` like NAI-230. The twin (the function
    without the guard) is never flagged — only the one carrying the extra case."""
    def _body(fn: Any) -> list:
        b = list(getattr(fn, "body", []) or [])
        if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant) \
                and isinstance(b[0].value.value, str):
            b = b[1:]                                   # the docstring is not behaviour
        return b

    def _guard(stmt: Any) -> Optional[str]:
        if not (isinstance(stmt, ast.If) and not stmt.orelse and [type(x) for x in stmt.body] == [ast.Return]):
            return None
        t, r = stmt.test, stmt.body[0].value
        if not (isinstance(t, ast.Compare) and [type(o) for o in t.ops] in ([ast.Eq], [ast.NotEq], [ast.Is])
                and isinstance(t.comparators[0], ast.Constant) and isinstance(r, ast.Constant)):
            return None
        return f"if {ast.unparse(t)}: return {ast.unparse(r)}"   # one line: the panel shows it inline

    nodes = [getattr(f, "node", f) for f in functions]
    params = {id(n): [a.arg for a in n.args.args] for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    rest_of = {id(n): ast.dump(ast.Module(body=_body(n), type_ignores=[])) for n in nodes if id(n) in params}
    out: Dict[str, Dict[str, Any]] = {}
    for n in nodes:
        if id(n) not in params:
            continue
        b = _body(n)
        guard = _guard(b[0]) if b else None
        if not guard or not b[1:]:
            continue
        tail = ast.dump(ast.Module(body=b[1:], type_ignores=[]))
        for twin in nodes:
            if twin is n or params.get(id(twin)) != params[id(n)]:
                continue
            if rest_of.get(id(twin)) == tail:
                out[f"{n.name}@{n.lineno}"] = {
                    "tag": "NAI-236", "line": b[0].lineno, "twin": twin.name, "guard": guard,
                    "description": f"{n.name} is {twin.name} with one case switched off: `{guard}`"}
                break
    return out


def test_gaming_237_observations(functions: List[Any]) -> Dict[str, Dict[str, Any]]:
    """owner 2026-10-07 (blind tree 1 L4, M-90): NAI-237 test_gaming — code written to pass its check, not to work. Fires only
    on evidence in the same file, so an ordinary guard clause (`if mpg == 0: return 0`) stays quiet:
      * test_literal — `if <param> == <literal>: return <value>` where a test calls this function with that literal in
        that parameter's position and asserts exactly that value back;
      * call_counter — the function bumps a module-level counter (`_calls["n"] += 1`, `global n; n += 1`) and an `if`
        that reads the same counter returns a constant: the answer changes with how many times it was called."""
    nodes = [getattr(f, "node", f) for f in functions]
    fns = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return _test_gaming_237(fns, _asserted_calls(fns))


def _asserted_calls(fns: List[Any]) -> Dict[str, List[Tuple[tuple, Any]]]:
    """{called function name: [(literal args, asserted literal result)]} from `assert f(<literals>) == <literal>` in
    test functions."""
    asserted: Dict[str, List[Tuple[tuple, Any]]] = {}
    for t in fns:
        if not t.name.startswith("test"):
            continue
        for a in ast.walk(t):
            if not (isinstance(a, ast.Assert) and isinstance(a.test, ast.Compare)
                    and [type(o) for o in a.test.ops] == [ast.Eq]):
                continue
            call, want = a.test.left, a.test.comparators[0]
            if isinstance(want, ast.Call) and isinstance(call, ast.Constant):
                call, want = want, call
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and isinstance(want, ast.Constant)
                    and all(isinstance(x, ast.Constant) for x in call.args)):
                asserted.setdefault(call.func.id, []).append((tuple(x.value for x in call.args), want.value))
    return asserted


def _other_table_row(fn: Any, this: ast.AST, params: List[str], keyed: Set[int]) -> bool:
    """Another `if <same params> == <literals>: return <constant>` branch exists besides `this` — the branches are rows
    of a lookup table written as ifs (a mapping), where each row is the rule, not a special case."""
    for x in ast.walk(fn):
        if (x is not this and isinstance(x, ast.If) and [type(b) for b in x.body] == [ast.Return]
                and isinstance(x.body[0].value, ast.Constant)):
            g = _literal_guards(x.test, params)
            if g is not None and set(g) == keyed:
                return True
    return False


def _boundary(v: Any) -> bool:
    """A natural boundary value — zero, ±1, empty, None, a bool — that a correct guard clause tests for."""
    return v is None or isinstance(v, bool) or v in (0, 1, -1, "", b"")


def _literal_guards(test: ast.AST, params: List[str]) -> Optional[Dict[int, Any]]:
    """`p == lit` or `p1 == lit1 and p2 == lit2 …` over parameters → {param index: literal}; anything else → None."""
    parts = test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) else [test]
    out: Dict[int, Any] = {}
    for t in parts:
        if not (isinstance(t, ast.Compare) and [type(o) for o in t.ops] == [ast.Eq] and isinstance(t.left, ast.Name)
                and t.left.id in params and isinstance(t.comparators[0], ast.Constant)):
            return None
        out[params.index(t.left.id)] = t.comparators[0].value
    return out


def test_gaming_237_project_observations(trees_by_rel: Dict[str, ast.AST], root: Any) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """NAI-237 test_literal across files (M-143, 2026-10-08): real apps keep their tests in tests/, so the literal a
    test asserts is matched against every non-test file's function of that name. Same-file pairs stay with the
    per-file pass; this emits only for a test in ANOTHER file. Merged per file like NAI-251/252."""
    from pathlib import Path as _P
    by_rel = {rel: [n for n in ast.walk(t) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
              for rel, t in trees_by_rel.items()}
    asserted_in = {rel: _asserted_calls(fns) for rel, fns in by_rel.items()}
    out: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for rel, fns in by_rel.items():
        if _P(rel).name.startswith("test_") or "tests" in _P(rel).parts or _P(rel).name == "conftest.py":
            continue
        names = {n.name for n in fns}
        other: Dict[str, List[Tuple[tuple, Any]]] = {}
        for trel, calls in asserted_in.items():
            if trel == rel:
                continue
            for name, hits in calls.items():
                if name in names:
                    other.setdefault(name, []).extend(hits)
        if not other:
            continue
        for k, obs in _test_gaming_237([n for n in fns if not n.name.startswith("test")], other,
                                       counters=False).items():
            out.setdefault(str((_P(root) / rel).resolve()), {})[k] = [obs]
    return out


def _test_gaming_237(fns: List[Any], asserted: Dict[str, List[Tuple[tuple, Any]]],
                     counters: bool = True) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for n in fns:
        if n.name.startswith("test"):
            continue
        params = [a.arg for a in n.args.args]
        locals_ = set(params) | {t.id for x in ast.walk(n) if isinstance(x, ast.Assign)
                                 for t in x.targets if isinstance(t, ast.Name)}
        counter_names = set()
        for x in ast.walk(n):
            if isinstance(x, ast.AugAssign):
                base = x.target.value if isinstance(x.target, ast.Subscript) else x.target
                if isinstance(base, ast.Name) and base.id not in locals_:
                    counter_names.add(base.id)
        for x in ast.walk(n):
            if not (isinstance(x, ast.If) and [type(b) for b in x.body] == [ast.Return]
                    and isinstance(x.body[0].value, ast.Constant)):
                continue
            ret = x.body[0].value.value
            t = x.test
            guards = _literal_guards(t, params)
            if guards and not counters and all(_boundary(v) for v in guards.values()):
                guards = None   # cross-file: `if n == 0: return 0` asserted by a test is a domain boundary, not a special case
            if guards and _other_table_row(n, x, params, set(guards)):
                guards = None   # one row of a lookup table (`if style == "ale": return 7` / `"lager": 14` …), not a special case
            if guards:
                hit = [args for args, want in asserted.get(n.name, [])
                       if want == ret and all(i < len(args) and args[i] == lit for i, lit in guards.items())]
                if hit:
                    cond = " and ".join(f"{params[i]} == {lit!r}" for i, lit in sorted(guards.items()))
                    out[f"{n.name}@{n.lineno}"] = {
                        "tag": "NAI-237", "line": x.lineno, "lines": [x.lineno, x.body[0].lineno],
                        "variant": "test_literal",
                        "description": f"{n.name} returns {ret!r} when {cond} — exactly what its test "
                                       f"asserts for {n.name}{hit[0]!r}; the answer is special-cased, not computed"}
                    break
            if not counters:
                continue
            read = {y.id for y in ast.walk(t) if isinstance(y, ast.Name)}
            if counter_names & read:
                out[f"{n.name}@{n.lineno}"] = {
                    "tag": "NAI-237", "line": x.lineno, "variant": "call_counter",
                    "description": f"{n.name} counts its own calls in module-level `{sorted(counter_names & read)[0]}` and "
                                   f"returns {ret!r} once the count says so — the answer depends on how often it was called"}
                break
    return out


def sibling_divergence_238_observations(functions: List[Any]) -> Dict[str, Dict[str, Any]]:
    """owner 2026-10-07 08:15 (blind tree 2 blind L5 misses, M-97): NAI-238 sibling_divergence — two functions with the
    same parameters whose bodies are identical except for ONE operator, ONE constant, a swapped pair of names, or one
    added / dropped `not`. With no docstring there is no stated intent, so this never decides: the owner's ruling is
    "flagged for review by the ranker" (disposition `context`, shown as a review note). Recorded on BOTH siblings —
    which one is wrong is the reviewer's call (inc/dec is a real pair)."""
    nodes = [getattr(f, "node", f) for f in functions]
    fns = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("test")]

    def _body(fn: Any) -> list:
        b = list(fn.body)
        if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant) \
                and isinstance(b[0].value.value, str):
            b = b[1:]
        return b

    class _FoldNeg(ast.NodeTransformer):
        # `-4.0` parses as UnaryOp(USub, 4.0); fold it to the constant -4.0 so a sign flip is ONE constant difference
        def visit_UnaryOp(self, node):
            self.generic_visit(node)
            if isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) \
                    and isinstance(node.operand.value, (int, float)):
                return ast.copy_location(ast.Constant(value=-node.operand.value), node)
            return node

    def _flat(fn: Any) -> list:
        # operator nodes (Add / Sub / LtE / Not …) are compared through their parent's `op` / `ops`, not as nodes
        skip = (ast.operator, ast.cmpop, ast.unaryop, ast.boolop, ast.expr_context)
        import copy as _copy
        folded = _FoldNeg().visit(ast.Module(body=_copy.deepcopy(_body(fn)), type_ignores=[]))   # keeps line numbers
        return [x for x in ast.walk(folded) if not isinstance(x, skip)]

    def _diff(a: Any, b: Any) -> Optional[str]:
        fa, fb = _flat(a), _flat(b)
        if not fa or [type(x) for x in fa] != [type(x) for x in fb]:
            # one side has an extra `not` (UnaryOp(Not) wrapping the same expression)
            for x, y in ((a, b), (b, a)):
                gx, gy = _flat(x), _flat(y)
                if len(gx) == len(gy) + 2 and any(isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not) for n in gx):
                    stripped = ast.Module(body=[ast.parse(ast.unparse(st).replace("not ", "", 1)).body[0]
                                                for st in _body(x)], type_ignores=[])
                    if ast.dump(stripped) == ast.dump(ast.Module(body=_body(y), type_ignores=[])):
                        return f"`{x.name}` adds a `not` that `{y.name}` does not have"
            return None
        diffs, where = [], []
        for x, y in zip(fa, fb):
            n_before = len(diffs)
            if hasattr(x, "op") and type(x.op) is not type(y.op):
                diffs.append(f"`{ast.unparse(x)}` vs `{ast.unparse(y)}`")
            if isinstance(x, ast.Compare) and [type(o) for o in x.ops] != [type(o) for o in y.ops]:
                diffs.append(f"`{ast.unparse(x)}` vs `{ast.unparse(y)}`")
            if isinstance(x, ast.Constant) and x.value != y.value:
                diffs.append(f"`{x.value!r}` vs `{y.value!r}`")
            if isinstance(x, ast.Name) and x.id != y.id:
                diffs.append(f"`{x.id}` vs `{y.id}`")
            if len(diffs) != n_before:
                where.append((getattr(x, "lineno", None), getattr(y, "lineno", None)))
        uniq = list(dict.fromkeys(diffs))
        names = [d for d in uniq if d.count("`") == 4 and "(" not in d and " " not in d.strip("`").split("` vs `")[0]]
        # the shape: exactly ONE difference, or exactly a swapped pair of names (a vs b, then b vs a)
        if [type(x) for x in fa] == [type(x) for x in fb] and uniq:
            if uniq[1:] == []:
                _LINES[0] = next(iter(where), (None, None))
                return uniq[0]
            if names == uniq and names[2:] == [] and names[0].split(" vs ")[::-1] == names[1].split(" vs "):
                _LINES[0] = next(iter(where), (None, None))
                return f"arguments swapped ({uniq[0]})"
        return None

    _LINES: List[Tuple[Optional[int], Optional[int]]] = [(None, None)]   # the differing statement in a and in b
    out: Dict[str, Dict[str, Any]] = {}
    for i, a in enumerate(fns):
        pa = [x.arg for x in a.args.args]
        for b in fns[i + 1:]:
            if [x.arg for x in b.args.args] != pa or not _body(a) or not _body(b):
                continue
            _LINES[0] = (None, None)
            d = _diff(a, b)
            if d:
                la, lb = _LINES[0]
                for me, other, ln in ((a, b, la), (b, a, lb)):
                    out.setdefault(f"{me.name}@{me.lineno}", {
                        "tag": "NAI-238", "line": ln or me.lineno, "sibling": other.name, "differs_by": d,
                        "description": f"{me.name} and {other.name} take the same arguments and differ only by {d} — "
                                       f"one of them is likely wrong; no docstring says which"})
    return out


def symmetry_229_observation(node: ast.FunctionDef) -> Optional[Dict[str, Any]]:
    """FIX_17 (2026-09-10): NAI-229 as an OBSERVATION for the per-function observations stage —
    `{tag, line, magnitude, statement, statements, ratio, description}`. `magnitude` is the context fact the
    disposition table reads (context by default; deciding above the table's N for non-test files)."""
    rep = _repetition_229(node)
    if rep is None:
        return None
    count, most_common, total = rep
    return {
        "tag": "NAI-229", "line": node.lineno, "magnitude": count, "statement": most_common,
        "statements": total, "ratio": round(count / total, 3),
        "description": f"repetitive structure: {count}x {most_common} of {total} statements",
    }


@trace
def normalized_fingerprint(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> str:
    """
    Generate a normalized fingerprint that ignores ordering.
    
    Useful for detecting functions that are similar but may have
    reordered statements.
    """
    parts = []
    
    for child in ast.walk(node):
        if isinstance(child, (ast.Return, ast.Yield, ast.If, ast.For, 
                             ast.While, ast.Try, ast.With, ast.Call,
                             ast.Assign, ast.Compare)):
            parts.append(type(child).__name__)
    
    # Sort for order-independence
    parts.sort()
    structure = ",".join(parts)
    
    return hashlib.md5(structure.encode()).hexdigest()[:16]


def _duplicate_groups_230(fingerprints: Dict[str, List[str]]) -> List[List[str]]:
    """FIX_17 (2026-09-10): the groups behind NAI-230 — every normalized fingerprint shared by more than one
    function, as its member list. A group's size is the MAGNITUDE the disposition table reads."""
    return [list(funcs) for funcs in fingerprints.values() if len(funcs) > 1]


def check_normalized_duplicates_230(
    fingerprints: Dict[str, List[str]]
) -> List[Tuple[str, str, str]]:
    """
    Check for duplicates using normalized fingerprints.

    Returns:
        List of (rule_id, severity, message) tuples.

    FIX_17 (2026-09-10): renamed `_230` so the `utils.code_analysis.fingerprint` twin never collides again;
    the route consumes `normalized_duplicates_230_observations` (the observation form carrying its magnitude).
    """
    issues = []

    for funcs in _duplicate_groups_230(fingerprints):
        issues.append((
            "NAI-230",  # A1 renumber: was NAI-092 (detection NAI-092 = shell=True); live caller: file_validation (FIX_17)
            "MEDIUM",
            f"Similar function structure (normalized): {', '.join(funcs)}"
        ))

    return issues


def normalized_duplicates_230_observations(fingerprints: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
    """FIX_17 (2026-09-10): NAI-230 as OBSERVATIONS keyed by group member — every member of a duplicate group
    gets `{tag, magnitude (= the group's size), group, description}`; the caller adds the member's line and
    appends it to that function's observations. Computed ONCE per file (a whole-set fact, THE ASYNC LAW)."""
    out: Dict[str, Dict[str, Any]] = {}
    for funcs in _duplicate_groups_230(fingerprints):
        group = sorted(funcs)
        for member in funcs:
            out[member] = {
                "tag": "NAI-230", "magnitude": len(group), "group": group,
                "description": f"similar function structure (normalized): {', '.join(group)}",
            }
    return out


# ── AST helpers shared by the module-level checks (plan item 4, 2026-09-05) ──

def module_scope_nodes(tree: ast.AST):
    """Yield every node in MODULE scope: descends through if / try / with / for
    blocks but never into function, class or lambda bodies (those belong to the
    per-function pipeline)."""
    stack = list(ast.iter_child_nodes(tree))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def base_name(expr: ast.AST) -> str:
    """Dotted-tail name of a base-class / decorator expression: `ABC`, `abc.ABC`,
    `Generic[T]`, `dataclass(frozen=True)` -> 'ABC' / 'ABC' / 'Generic' / 'dataclass'."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Subscript):
        return base_name(expr.value)
    if isinstance(expr, ast.Call):
        return base_name(expr.func)
    return ""


def is_sys_path(expr: ast.AST) -> bool:
    """`sys.path` attribute expression."""
    return (isinstance(expr, ast.Attribute) and expr.attr == "path"
            and isinstance(expr.value, ast.Name) and expr.value.id == "sys")


def is_os_environ(expr: ast.AST) -> bool:
    """`os.environ` attribute expression."""
    return (isinstance(expr, ast.Attribute) and expr.attr == "environ"
            and isinstance(expr.value, ast.Name) and expr.value.id == "os")
