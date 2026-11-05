"""point_claims.py — what a docstring says about ONE specific case, against the body's shape (M-144, 2026-10-08).

The general claim forms (claim_forms.py) state properties of every result and need the module sandbox to run the
function. Frontier-model logic flaws more often contradict a POINT statement — "equal to `grace_days` is still inside",
"strictly positive", "zero occupied days yields 0", "`rate` is a fraction", "exactly once", "timezone-aware" — in
functions that take objects or call helpers from other modules, which the sandbox cannot run. Each form here pairs one
way of stating a case with the body shape that contradicts it, read from the AST only (nothing executes). Like
boundary_probes' threshold check it OBSERVES: each contradiction carries the stated claim and the statement that breaks
it, reported through intent_claims as NAI-102; the Ranker weighs it.

  inclusive_pair   "`a` equal to `b` is (still) inside / included / allowed / on time" — the body compares a with b
                   strictly (`a < b`): the equal case falls outside. (And "… is outside / excluded" vs `<=`.)
  sign_predicate   a yes/no function whose docstring ties True to a sign of a parameter ("strictly positive",
                   "non-negative", "negative") — its returned comparison of that parameter with 0, evaluated on
                   -1 / 0 / 1, gives a different truth table (inverted condition, or the zero case on the wrong side).
  negated_namesake `is_X` / `has_X` / `can_X` returns `not <…>.X` — the opposite of the very fact it is named after.
  zero_yields      "zero / no `p` yields / returns V" — the body's `if p == 0` (or `not p`) branch returns something
                   other than V.
  fraction_scaled  "`p` is a fraction / rate (0.08 = 8%)" — the body multiplies `p` by 100 (percent vs fraction).
  aware_stripped   "timezone-aware" / "in UTC" — the body strips tzinfo (`.replace(tzinfo=None)`) or reads a naive
                   clock (`datetime.now()` / `utcnow()` with no tz): the naive neighbouring task.
  once_accumulates "exactly once / idempotent / without a second post" for a key parameter — the body accumulates
                   into a store keyed by that parameter and never tests whether the key was already seen.
  sign_discarded   "a negative `p` is a reversal / refund / credit / reduces …" — the body takes `abs(p)`.
"""
from __future__ import annotations

import ast
import operator
import re
from typing import Any, Dict, List, Optional, Set

_INSIDE = r"(?:still\s+)?(?:inside|within|included|allowed|eligible|on\s+time|valid|in\s+(?:the\s+)?(?:window|range|grace))"
_OUTSIDE = r"(?:outside|excluded|not\s+(?:included|allowed|eligible|inside|within)|late|expired)"
_STRICT_TWIN = {ast.Lt: ast.LtE, ast.Gt: ast.GtE, ast.LtE: ast.Lt, ast.GtE: ast.Gt}
_NEG_MEANING = r"(?:reversal|refund|credit|chargeback|reduces?|decreases?|lowers?|subtracts?|must\s+reduce)"
_NEG_EXEMPT = r"(?:treated\s+as|absolute|magnitude|ignored|rejected|raises?|clamped|as\s+zero|not\s+allowed)"


def _params(func: ast.FunctionDef) -> List[str]:
    return [a.arg for a in func.args.args if a.arg not in ("self", "cls")]


def _phrase(p: str) -> str:
    """`occupied_days` is written `occupied_days`, ``occupied_days`` or "occupied days" in prose."""
    return r"`{0,2}" + r"[\s_]".join(map(re.escape, p.split("_"))) + r"`{0,2}"


def _own(func: ast.FunctionDef):
    stack: List[ast.AST] = list(func.body)
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(n))


def _bad(kind: str, says: str, expected: str, node: ast.stmt | ast.expr, got: Optional[str] = None) -> Dict[str, Any]:
    return {"claim": kind, "says": says, "expected": expected, "got": got if got is not None else f"`{ast.unparse(node)}`",
            "probe": "shape", "line": node.lineno, "lines": [node.lineno]}


def _name(n: ast.AST) -> Optional[str]:
    return n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) else None


def _inclusive_pair(func, low, ps, out):
    for a in ps:
        for b in ps:
            if a == b:
                continue
            m = re.search(rf"{_phrase(a)}\s+(?:equal\s+to|==|that\s+equals)\s+{_phrase(b)}\s+(?:is|are|counts?\s+as)\s+({_INSIDE}|{_OUTSIDE})", low)
            if not m:
                continue
            inside = re.fullmatch(_INSIDE, m.group(1)) is not None
            for c in (x for x in _own(func) if isinstance(x, ast.Compare) and len(x.ops) == 1):
                l, r, op = _name(c.left), _name(c.comparators[0]), c.ops[0]
                if {l, r} != {a, b} or type(op) not in _STRICT_TWIN:
                    continue
                strict = isinstance(op, (ast.Lt, ast.Gt))
                if inside == strict:   # inside wants the equal case True (<=); outside wants it False (<)
                    out.append(_bad("inclusive_pair", m.group(0).strip(),
                                    f"`{ast.unparse(c.left)} {('<=' if isinstance(op, ast.Lt) else '>=') if strict else ('<' if isinstance(op, ast.LtE) else '>')} {ast.unparse(c.comparators[0])}`", c))


_SIGNS = [   # (prose, truth on -1, 0, 1)
    (r"strictly\s+positive|greater\s+than\s+zero|above\s+zero", (False, False, True)),
    (r"non-?negative|zero\s+or\s+(?:more|positive)|at\s+least\s+zero", (False, True, True)),
    (r"strictly\s+negative|less\s+than\s+zero|below\s+zero", (True, False, False)),
]


_OPS = {ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
        ast.Eq: operator.eq, ast.NotEq: operator.ne}


def _is_zero(n: ast.AST) -> bool:
    """The literal zero — the sign boundary a sign claim is about (a structural fact, not a threshold)."""
    return isinstance(n, ast.Constant) and not isinstance(n.value, bool) and n.value in (0,)


def _returns_bool(func) -> bool:
    ann = ast.unparse(func.returns) if func.returns is not None else ""
    return ann == "bool" or re.match(r"(is|has|can|should|needs?|must|within|allows?)_", func.name) is not None


def _sign_predicate(func, low, ps, out):
    if not _returns_bool(func):
        return
    rets = [x for x in _own(func) if isinstance(x, ast.Return) and isinstance(x.value, ast.Compare)
            and len(x.value.ops) == 1]
    for p in ps:
        if not re.search(_phrase(p), low):
            continue
        want = next((t for pat, t in _SIGNS if re.search(rf"(?:{pat})", low)), None)
        if want is None:
            continue
        for r in rets:
            c = r.value
            if _name(c.left) == p and _is_zero(c.comparators[0]):
                fn = _OPS.get(type(c.ops[0]))
                if fn is None:
                    continue
                got = tuple(fn(v, 0) for v in (-1, 0, 1))
                if got != want:
                    exp = {(False, False, True): f"{p} > 0", (False, True, True): f"{p} >= 0",
                           (True, False, False): f"{p} < 0"}[want]
                    out.append(_bad("sign_predicate", next(m.group(0) for pat, _ in _SIGNS
                                                           for m in [re.search(pat, low)] if m), f"`{exp}`", c))


def _negated_namesake(func, out):
    m = re.match(r"(?:is|has|can)_(\w+)$", func.name)
    if not m:
        return
    for r in (x for x in _own(func) if isinstance(x, ast.Return)):
        v = r.value
        if isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not) and _name(v.operand) == m.group(1):
            out.append(_bad("negated_namesake", f"`{func.name}` answers whether it is {m.group(1).replace('_', ' ')}",
                            f"`{ast.unparse(v.operand)}`", r))


def _zero_yields(func, low, ps, out):
    for p in ps:
        m = re.search(rf"\b(?:zero|no)\s+{_phrase(p)}\s+(?:yields?|returns?|gives?|is|means?)\s+([\w.`]+)", low)
        if not m:
            continue
        stated = m.group(1).strip("`.")
        if stated in ("zero", "nothing", "none", "0.0"):
            stated = "0"
        if not re.fullmatch(r"0", stated) and stated not in ps:
            continue   # a word, not a value or a parameter ("… is no fee", "… is retained") — nothing checkable
        for n in (x for x in _own(func) if isinstance(x, ast.If)):
            t = n.test
            zero = (isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], (ast.Eq, ast.LtE))
                    and _name(t.left) == p and _is_zero(t.comparators[0])) \
                or (isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not) and _name(t.operand) == p)
            if not zero or not n.body or not isinstance(n.body[0], ast.Return) or n.body[0].value is None:
                continue
            rv = n.body[0].value
            inner = rv.args[0] if isinstance(rv, ast.Call) and getattr(rv.func, "id", "") in ("float", "int") and rv.args else rv
            if stated == "0":
                ok = _is_zero(inner)
            else:
                ok = _name(inner) == stated or not isinstance(inner, (ast.Name, ast.Attribute, ast.Constant))
            if not ok:
                out.append(_bad("zero_yields", m.group(0).strip(), f"`{stated}`", n.body[0]))


def _fraction_scaled(func, low, ps, out):
    for p in ps:
        if not re.search(rf"{_phrase(p)}\s+is\s+a\s+(?:fraction|ratio|decimal\s+rate)|{_phrase(p)}\s+is\s+a\s+rate\s*\(0\.\d+", low):
            continue
        for b in (x for x in _own(func) if isinstance(x, ast.BinOp) and isinstance(x.op, ast.Mult)):
            names = {_name(y) for y in ast.walk(b)}
            hundred = any(isinstance(y, ast.Constant) and y.value in (100, 100.0) for y in (b.left, b.right))
            if p in names and hundred:
                out.append(_bad("fraction_scaled", f"`{p}` is a fraction", f"`{p}` used as given (no `* 100`)", b))


def _aware_stripped(func, low, out):
    if not re.search(r"timezone[- ]aware|tz[- ]aware|\baware\b|\bin utc\b|utc[- ]based", low):
        return
    for n in _own(func):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "replace" and any(k.arg == "tzinfo" and isinstance(k.value, ast.Constant) and k.value.value is None
                                                for k in n.keywords):
                out.append(_bad("aware_stripped", "timezone-aware", "keep tzinfo", n))
            elif n.func.attr == "utcnow" or (n.func.attr == "now" and not n.args and not n.keywords):
                out.append(_bad("aware_stripped", "timezone-aware", "`datetime.now(timezone.utc)`", n))


def _once_accumulates(func, low, ps, out):
    if not re.search(r"exactly\s+once|idempotent|at\s+most\s+once|only\s+once|without\s+a\s+second|"
                     r"repeat(?:ing|ed)?\s+(?:an?\s+)?(?:id|key|call|request)\s+(?:returns|is|does)", low):
        return
    keyed = [p for p in ps if re.search(rf"{_phrase(p)}", low)] or ps
    tested: Set[str] = set()
    for n in _own(func):   # `if key in store` / `store.get(key)` used as a test / `if store[key]`
        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops):
            tested |= {_name(c) for c in n.comparators if _name(c)}
        if isinstance(n, (ast.If, ast.IfExp, ast.While)):
            tested |= {_name(c.func.value) for c in ast.walk(n.test) if isinstance(c, ast.Call)
                       and isinstance(c.func, ast.Attribute) and c.func.attr == "get" and _name(c.func.value)}
    for n in _own(func):
        if not isinstance(n, ast.Assign):
            continue
        target = next(iter(n.targets))
        if n.targets[1:] or not isinstance(target, ast.Subscript):
            continue
        store, key = _name(target.value), _name(target.slice)
        if key not in keyed or store in tested:
            continue
        acc = isinstance(n.value, ast.BinOp) and isinstance(n.value.op, ast.Add) and any(
            isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "get"
            and _name(c.func.value) == store for c in ast.walk(n.value))
        if acc:
            out.append(_bad("once_accumulates", "exactly once per key",
                            f"return the first result when `{key}` is already in `{store}`", n))
    for n in _own(func):
        if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Subscript) and _name(n.target.slice) in keyed \
                and _name(n.target.value) not in tested:
            out.append(_bad("once_accumulates", "exactly once per key",
                            f"return the first result when `{_name(n.target.slice)}` is already in `{_name(n.target.value)}`", n))


def _sign_discarded(func, low, ps, out):
    for p in ps:
        m = re.search(rf"\bnegative\s+{_phrase(p)}\s+(?:is|means|marks|represents)?\s*[^.]*?\b{_NEG_MEANING}", low)
        if not m or re.search(_NEG_EXEMPT, m.group(0)):
            continue
        for n in _own(func):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "abs" and n.args and _name(n.args[0]) == p:
                out.append(_bad("sign_discarded", m.group(0).strip(), f"`{p}` signed", n))


_NEGATING = {"not", "no", "non", "none", "never", "missing", "without", "lacks", "lacking", "absent", "denied", "deny",
             "skip", "skipping", "skipped", "ignore", "ignoring", "off", "disabled", "unset", "empty", "zero", "nothing"}
_BLOCKERS = {"unsettled", "pending", "outstanding", "unresolved", "unpaid", "open", "remaining", "lingering", "blocking",
             "failed", "errors", "unprocessed", "unread", "overdue"}
_LOG_CALLS = {"debug", "info", "warning", "error", "exception", "critical", "log"}


def _words(text: str) -> List[str]:
    return [w for w in re.split(r"[^a-z]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", text).lower()) if w]


def _absent_test(test: ast.AST) -> Optional[tuple]:
    """A test that says some thing is ABSENT → (the thing's words, the test). `not x.flag` / `not flag`, `a != "LIT"`,
    `count == 0` / `not count`."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        n = _name(test.operand) or (_name(test.operand.func) if isinstance(test.operand, ast.Call) else None)
        return (set(_words(n)), test) if n else None
    if isinstance(test, ast.Compare) and not test.ops[1:]:
        op, r = test.ops[0], test.comparators[0]
        if isinstance(op, ast.NotEq) and isinstance(r, ast.Constant) and isinstance(r.value, str) and r.value:
            return set(_words(r.value)), test
        if isinstance(op, ast.Eq) and _is_zero(r) and _name(test.left) \
                and set(_words(_name(test.left) or "")) & _BLOCKERS:
            # zero of a BLOCKING count (unsettled / pending / outstanding …): a branch that then complains about them is
            # backwards; zero of an ordinary quantity (`volume == 0` → "volume must be positive") is a correct guard
            return set(_words(_name(test.left) or "")) - _BLOCKERS, test
    return None


def _branch_narrative(func, out):
    """branch_narrative: the branch's own words (log / raise message, the counter it increments) affirm the very thing
    its test says is absent — `if not guest.loyalty_member: log("meets loyalty criteria")`, `if status != "CANCELLED":
    cancelled_segments += 1`, `if unsettled == 0: log("blocked by unresolved departures")`: the condition is inverted."""
    for br in (x for x in _own(func) if isinstance(x, ast.If)):
        got = _absent_test(br.test)
        if not got:
            continue
        thing, test = got
        thing -= {"is", "has", "can", "should", "get", "the", "a", "of", "count", "num", "total", "flag", "status", "self"}
        if not thing:
            continue
        said: List[str] = []
        for n in (y for s in br.body for y in ast.walk(s)):
            if isinstance(n, ast.AugAssign) and _name(n.target) and not (set(_words(_name(n.target) or "")) & _NEGATING) \
                    and set(_words(_name(n.target) or "")) & thing:
                said.append(f"`{ast.unparse(n)}`")
            msg = None
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _LOG_CALLS and n.args:
                msg = n.args[0]
            elif isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call) and n.exc.args:
                msg = n.exc.args[0]
            if msg is not None:
                text = msg.value if isinstance(msg, ast.Constant) and isinstance(msg.value, str) else \
                    " ".join(v.value for v in ast.walk(msg) if isinstance(v, ast.Constant) and isinstance(v.value, str))
                ws = _words(text)
                if ws and not (set(ws) & _NEGATING) and set(ws) & thing:
                    said.append(repr(text))
        if said:
            out.append(_bad("branch_narrative", f"the branch says {said[0]}", "the opposite test", test,
                            got=f"`{ast.unparse(test)}`"))


def contradictions(func: ast.FunctionDef, doc: str) -> List[Dict[str, Any]]:
    low = " ".join(doc.lower().split())
    out: List[Dict[str, Any]] = []
    _negated_namesake(func, out)   # the name is the claim — no docstring needed
    _branch_narrative(func, out)   # the branch's own words are the claim
    if not low:
        return out
    ps = _params(func)
    _inclusive_pair(func, low, ps, out)
    _sign_predicate(func, low, ps, out)
    _zero_yields(func, low, ps, out)
    _fraction_scaled(func, low, ps, out)
    _aware_stripped(func, low, out)
    _once_accumulates(func, low, ps, out)
    _sign_discarded(func, low, ps, out)
    return out
