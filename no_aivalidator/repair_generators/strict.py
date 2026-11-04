"""Strict family (no_aivalidator/noai_validator/strict_checks.py) — item 4, 2026-09-08.

No fix by design: NAI-021S (owner ruling 2026-09-08). NAI-021S is a different rule from NAI-021
(core family) — the two stay distinct rows.

Set 4b-40 (2026-09-10, app copy 2, run 94 — portion I's first): NAI-009S, NAI-016S, NAI-017S, NAI-022S,
NAI-023S declared no-fix-by-design. The strict predicates run FIRST on the daemon route
(`validator.py:254` — the first matching predicate in `STRICT_CHECKS` order returns the row before any AST
detector runs), so a strict row carries the strict id and nothing else (only a NAI-071 mutable default
rides, `_mutable_default_observations`). Every one of the five is a shape whose whole body is the
counterfeit — a literal returned under unread parameters, a bare `return param`, a canned dict, a
delegator that never reads its parameters, a copy chain — and what the function was meant to compute is
the dev's, never a rewrite's. `meaning_source` of NAI-009S corrected: it is emitted by
`strict_checks.py:is_naive_constant_ignore`, not by the core detector `_check_unused_parameters`.
Fact found offline (2026-09-10): NAI-023S decides when its chain holds an identity comprehension
(`[item for item in x]`) — the extractor records no identity edge for a comprehension, so NAI-021S's
trace (`graph.is_identity_chain`) is quiet and the AST-only twin takes the row; a chain of `list()` /
`[:]` / bare assignment alone is NAI-021S's row (run 74's fact).

Set 4b-41 (2026-09-10, app copy 2, run 95 — the family's last): NAI-024S, NAI-025S, NAI-026S declared
no-fix-by-design. Dead-zero arithmetic, self-cancelling arithmetic and the loop identity accumulator are
each a shape that reads its input and then throws it away; the value the dev meant to produce is not
in the code, so no rewrite can restore it — removing the cancellation invents a result, keeping it keeps
the counterfeit. FAMILY `strict` CLOSED: 9 no-fix-by-design (021S from the first batch; 009S / 016S /
017S / 022S / 023S on 4b-40; 024S / 025S / 026S here), no rewriter — every strict row is the Ranker's
proof of a counterfeit body, never a repair site.
"""
from __future__ import annotations

from . import no_fix, prescribed, rewriter, unbuilt
import ast
import itertools

from ._ast_edit import body_after_docstring, func_node, head_insert_stmt, replace_cols, snippet_pad
from ._finite import fresh_name
from .core import _Variants, _own_scope, _rows

_LIST_MUTATORS = frozenset({"append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse"})
_DICT_MUTATORS = frozenset({"update", "setdefault", "pop", "popitem", "clear"})
_MUTABLE_DEFAULTS = {"list": "[]", "dict": "{}", "set": "set()"}
# R1 (2026-09-30): methods that exist on ONE builtin container only — the evidence `_kind_evidence` reads.
# A method two of them share (`pop`, `clear`, `remove`, `update`, `copy`, `__len__` …) is no evidence.
_ONLY_ON: dict[str, frozenset] = {
    "list": frozenset({"append", "extend", "insert", "sort", "reverse", "index"}),
    "dict": frozenset({"setdefault", "popitem", "get", "items", "keys", "values", "fromkeys"}),
    "set": frozenset({"add", "discard", "difference_update", "intersection_update",
                      "symmetric_difference_update", "issubset", "issuperset", "isdisjoint"}),
}
_ANNOTATION_KIND = {"list": "list", "List": "list", "dict": "dict", "Dict": "dict", "set": "set", "Set": "set"}


def _mutated(func: "ast.FunctionDef | ast.AsyncFunctionDef", names: set) -> bool:
    """The parameter (through `names`) is changed in place: a mutating method call, a subscript store /
    delete, or an augmented assignment. (Unchanged from the pre-R1 test, which ALSO took the kind from it.)"""
    muts = _LIST_MUTATORS | _DICT_MUTATORS | _ONLY_ON["set"] - {"issubset", "issuperset", "isdisjoint"}
    for n in _own_scope(func):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.value.id in names and n.func.attr in muts:
            return True
        if isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)) and isinstance(n.value, ast.Name) \
                and n.value.id in names:
            return True
        if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id in names:
            return True
    return False


def _empty_ctor(node: "ast.AST | None") -> "str | None":
    """`[]` / `list()` → "list", `{}` / `dict()` → "dict", `set()` → "set"; anything else None."""
    if isinstance(node, ast.List) and not node.elts:
        return "list"
    if isinstance(node, ast.Dict) and not node.keys:
        return "dict"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _MUTABLE_DEFAULTS \
            and not node.args and not node.keywords:
        return node.func.id
    return None


def _literal_kind(node: "ast.AST | None") -> "str | None":
    """The container a literal / bare constructor call builds (empty or not), else None."""
    if isinstance(node, (ast.List, ast.ListComp)):
        return "list"
    if isinstance(node, (ast.Dict, ast.DictComp)):
        return "dict"
    if isinstance(node, (ast.Set, ast.SetComp)):
        return "set"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _MUTABLE_DEFAULTS:
        return node.func.id
    return None


def _kind_evidence(func: "ast.FunctionDef | ast.AsyncFunctionDef", p: str, names: set) -> list:
    """R1 (2026-09-30): every piece of evidence in the code for the builtin type of parameter `p` (read
    through `names`, p plus its aliases), as (kind, where) pairs. Only evidence ONE type satisfies counts:
      dict — a str (or f-string) subscript key, a dict-only method, a `{}` / `dict()` default, a dict annotation;
      list — a slice or negative-int subscript, a list-only method, a `[]` / `list()` default, a list annotation,
             `+=` of a list;
      set  — a set-only method, a `set()` default, a set annotation, `|=` of a set.
    A non-negative int key is NOT evidence (a dict with int keys takes it too); nor is a name key."""
    out: list = []
    arg = next((a for a in func.args.args if a.arg == p), None)
    ann = getattr(arg, "annotation", None)
    if isinstance(ann, ast.Subscript):
        ann = ann.value
    if isinstance(ann, ast.Attribute):
        ann = ast.Name(id=ann.attr)
    if isinstance(ann, ast.Name) and ann.id in _ANNOTATION_KIND:
        out.append((_ANNOTATION_KIND[ann.id], f"annotation `{ann.id}`"))
    params = [a.arg for a in func.args.args]
    default_of = dict(zip(reversed(params), reversed(func.args.defaults)))   # defaults align to the LAST params
    if p in default_of:
        k = _literal_kind(default_of[p])
        if k:
            out.append((k, f"default `{ast.unparse(default_of[p])}`"))
    for n in _own_scope(func):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in names:
            key = n.slice
            if isinstance(key, ast.Slice):
                out.append(("list", f"slice `{ast.unparse(n)}` (line {n.lineno})"))
            elif isinstance(key, (ast.Constant, ast.JoinedStr)) and (isinstance(key, ast.JoinedStr) or isinstance(key.value, str)):
                out.append(("dict", f"str key `{ast.unparse(n)}` (line {n.lineno})"))
            elif isinstance(key, ast.UnaryOp) and isinstance(key.op, ast.USub) and isinstance(key.operand, ast.Constant) \
                    and type(key.operand.value) is int:
                out.append(("list", f"negative index `{ast.unparse(n)}` (line {n.lineno})"))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.value.id in names:
            for k, meths in _ONLY_ON.items():
                if n.func.attr in meths:
                    out.append((k, f"`.{n.func.attr}()` (line {n.lineno})"))
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id in names:
            k = _literal_kind(n.value)
            if k == "list" and isinstance(n.op, ast.Add):
                out.append(("list", f"`{ast.unparse(n)}` (line {n.lineno})"))
            elif k in ("set", "dict") and isinstance(n.op, ast.BitOr):
                out.append((k, f"`{ast.unparse(n)}` (line {n.lineno})"))
    return out


def fix_alias_chain(broken_code: str) -> _Variants:
    """NAI-021S finite set (the owner's form, hand check #4, 2026-09-16): a function that mutates a parameter in
    place and returns it (or an alias of it) — `new_sequence`: the result is built as a NEW list / dict from
    the parameter (`new_<p> = list(<p>)`; with a mutable default, the default becomes None and
    `new_<p> = list(<p>) if <p> is not None else []`), every later use of the parameter and its aliases reads the
    new name, and the new sequence is returned — nothing is returned by alias. When no parameter is mutated in
    place (a pure alias chain has no finite answer without the intent) the list carries ONE named entry instead,
    `no_rewrite_shape` — "no rewrite; emit this shape" (I-78, owner ruling 2026-09-29 (b)): the function's own
    signature over the prescription's shape, `result = ...` computed from the parameter per the intent, then
    `return result`. The row keeps one kind (rewriter); the shape rides its own variant list."""
    func = func_node(broken_code)
    if not func or not func.args.args:
        return []
    params = [a.arg for a in func.args.args]
    # aliases: `x = <param or alias>` in the body
    alias_of: dict[str, str] = {}
    for st in func.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and isinstance(st.value, ast.Name):
            src = st.value.id
            root = alias_of.get(src, src)
            if root in params:
                alias_of[st.targets[0].id] = root
    ret_names = [n.value.id for n in _own_scope(func) if isinstance(n, ast.Return) and isinstance(n.value, ast.Name)]
    roots = {alias_of.get(r, r) for r in ret_names}
    roots = {r for r in roots if r in params}
    if len(roots) != 1:
        return _no_rewrite_shape(broken_code, func, params, None)
    p = roots.pop()
    names = {p} | {a for a, r in alias_of.items() if r == p}
    # R1 (2026-09-30): the copy's type comes from EVIDENCE in the code, never a default. Before this a
    # subscript store or `+=` on the parameter said "list" — `payload["rounds"] = clean` built
    # `new_payload = list(payload)` (the dict's KEYS) and every later `new_payload["rounds"]` raised
    # TypeError (a 2026-09-30 target, 7 rows of 7 marked apply: yes). Each piece of evidence names
    # ONE kind; evidence that fits more than one type (`pop`, `clear`, `remove`, `update`, an int or name
    # key) names none. No evidence, or two kinds → decline into the shape, with the reason stated.
    if not _mutated(func, names):
        return _no_rewrite_shape(broken_code, func, params, p)
    evidence = _kind_evidence(func, p, names)
    match sorted({k for k, _ in evidence}):
        case [kind]:
            pass
        case []:
            return _no_rewrite_shape(broken_code, func, params, p, why=(
                f"`{p}` is mutated in place and returned, but nothing in the code says what type it is "
                f"(no str key, list-only or dict-only method, annotation or default) — a copy of an "
                f"unknown type is a guess, so no copy is built"))
        case _:
            return _no_rewrite_shape(broken_code, func, params, p, why=(
                f"`{p}` is mutated in place and returned, but the code's evidence disagrees on its type ("
                + "; ".join(f"{k}: {w}" for k, w in evidence) + ") — no copy is built"))
    pad = snippet_pad(broken_code)
    lines = broken_code.splitlines()
    first = head_insert_stmt(func, lines, pad)
    if first is None:    # no row after the docstring that holds a statement alone — nowhere safe to insert
        return _no_rewrite_shape(broken_code, func, params, p, why=(
            f"`{p}` is mutated in place and returned, but the body has no statement on a row of its own after "
            f"the docstring to put the copy above"))
    # every read of p / its aliases must be renamed: one inside a nested def or lambda would keep reading
    # the caller's object while the body mutates the copy
    own_ids = {id(n) for n in _own_scope(func)}
    if any(isinstance(n, ast.Name) and n.id in names and id(n) not in own_ids
           and n.lineno >= func.body[0].lineno for n in ast.walk(func)):
        return _no_rewrite_shape(broken_code, func, params, p, why=(
            f"`{p}` is mutated in place and returned, but a nested def or lambda also reads it — renaming the "
            f"body's uses to a copy would leave that one reading the caller's object"))
    idx = params.index(p)  # type: ignore[arg-type]  # FIX_54 ast-pos
    defaults = func.args.defaults
    d_i = idx - (len(params) - len(defaults))
    default = defaults[d_i] if d_i >= 0 else None
    mutable_default = default is not None and _empty_ctor(default) == kind
    new = fresh_name(func, f"new_{p}")
    # rename every occurrence of p / its aliases in the body (not the signature), bottom-up by position
    body_names = [n for n in _own_scope(func) if isinstance(n, ast.Name) and n.id in names
                  and n.lineno >= func.body[0].lineno]
    for n in sorted(body_names, key=lambda n: (n.lineno, n.col_offset), reverse=True):
        replace_cols(lines, n.lineno - 1, pad + n.col_offset, pad + n.end_col_offset, new)  # type: ignore[operator]  # FIX_54 ast-pos
    # alias assignments `x = p` become `x = new_p` (renamed above); an alias that is itself returned still returns new_p
    ind = lines[first.lineno - 1][: first.col_offset + pad]
    told = f" ({evidence[0][1]})"
    after_doc = " (after the docstring)" if len(body_after_docstring(func)) < len(func.body) else ""
    if mutable_default:
        replace_cols(lines, default.lineno - 1, pad + default.col_offset, pad + default.end_col_offset, "None")  # type: ignore[operator,union-attr]  # FIX_54 ast-pos
        lines.insert(first.lineno - 1, f"{ind}{new} = {kind}({p}) if {p} is not None else {_MUTABLE_DEFAULTS[kind]}")
        what = (f"`{p}={ast.unparse(default)}` → `{p}=None`; `{new} = {kind}({p}) if {p} is not None else {_MUTABLE_DEFAULTS[kind]}` "  # type: ignore[arg-type]  # FIX_54 ast-pos
                f"built first{after_doc}; every use of `{p}` reads `{new}`; `{new}` returned — a new {kind}{told}, never the caller's object")
    else:
        lines.insert(first.lineno - 1, f"{ind}{new} = {kind}({p})")
        what = (f"`{new} = {kind}({p})` built first{after_doc}; every use of `{p}` reads `{new}`; `{new}` "
                f"returned — a new {kind}{told}, never the caller's object")
    after = "\n".join(lines)
    # R1 (2026-09-30): the rewrite must resolve the finding it answers. `new_p = dict(p)` (no default to
    # replace) is itself a copy-constructor hop, so NAI-021S's own reading still sees an identity chain and
    # re-flags the function on the next scan — step 19's "meaning" criterion, which the plant only met through
    # its `… if p is not None else []` form. A rewrite the rule still fires on (or that cannot be checked) is
    # not offered; the shape is, with that reason.
    still = _still_alias_chain(after)
    if still:
        return _no_rewrite_shape(broken_code, func, params, p, why=(
            f"`{p}` is mutated in place and returned as a {kind}{told}, but a `{new} = {kind}({p})` copy would "
            f"not resolve the finding: {still}"))
    return [("new_sequence", after, what)]


def _still_alias_chain(after: str) -> str:
    """'' when NAI-021S's own predicate is quiet on the rewritten function; else why it is not."""
    try:
        from ..noai_validator.strict_checks import is_alias_identity_chain
    except Exception as e:      # fail closed: a rewrite whose meaning cannot be checked is not offered
        return f"NAI-021S's predicate could not be loaded to check the rewrite ({type(e).__name__})"
    fn = func_node(after)
    if fn is None:
        return "the rewrite has no function to check"
    try:
        fires = is_alias_identity_chain(fn)  # type: ignore[arg-type]
    except Exception as e:
        return f"NAI-021S's predicate raised on the rewrite ({type(e).__name__})"
    return ("a copy constructor is itself an identity hop to NAI-021S, so the rule still fires on the copy — "
            "the function changes its parameter's CONTENTS, which the rule's name-level data flow does not "
            "count as a transformation") if fires else ""


#: A method's receiver is never the value the shape computes from.
_RECEIVERS = frozenset({"self", "cls"})


def _no_rewrite_shape(broken_code: str, func: "ast.FunctionDef | ast.AsyncFunctionDef", params: list,
                      root: str | None, why: str | None = None) -> _Variants:
    """I-78 (owner ruling 2026-09-29 (b)): NAI-021S's named "no rewrite; emit this shape" entry, for a flagged
    alias chain with no parameter mutated in place (`chain`, `wrap_stream`, `convert_osc` — run 123). It is the
    prescription the row carried before it became a rewriter (FIX_41's `def f(param): result = <compute from
    param per the intent's expected output>; return result`), written in the function's OWN terms: its real
    signature (and docstring, when it has one), `result = ...` — the one value the intent must supply, spelled
    as Python's own placeholder so the shape parses — computed from the returned parameter (or the first
    non-receiver parameter when the return is not one), then `return result`.
    R1 (2026-09-30): also the DECLINE of `new_sequence` when the mutated parameter's type has no evidence or
    contradicting evidence — `why` then states that reason in the shape's text (the old text, "no parameter is
    mutated in place", would be false there)."""
    target = root
    for name in params:
        if target is None and name not in _RECEIVERS:
            target = name
    first = func.body[0]
    if target is None or first.lineno == func.lineno:
        return []        # no parameter to compute from, or a one-line def whose body shares the signature line
    has_doc = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
    keep = first.end_lineno if has_doc else first.lineno - 1
    ind = " " * (snippet_pad(broken_code) + first.col_offset)
    shape = list(itertools.islice(broken_code.splitlines(), keep))
    shape.append(f"{ind}result = ...  # compute the return from `{target}` per the intent's expected output")
    shape.append(f"{ind}return result")
    lead = (f"no rewrite; emit this shape — {why}" if why else
            "no rewrite; emit this shape — no parameter is mutated in place, so there is no new sequence to build")
    what = (f"{lead}: "
            f"replace the alias chain with the transformation the intent calls for, `result` computed from "
            f"`{target}` (per the intent's expected output for this function), not a renamed copy of it")
    return [("no_rewrite_shape", "\n".join(shape), what)]


# P5 (orchestrator ruling 2026-09-29, I-81 / C1): NAI-025S's shape carries the operators of the fire it
# answers — the self-cancelling operator the check flagged (`-` / `^` / `%`) in its comment, and, when the
# flagged value feeds a comparison (`noise == 0`, `if x - x > 0`), THAT comparison operator in the `if`.
# The finding's text is the check's fixed description, so both are read off the flagged function's source
# by the check's own walk (strict_checks.has_self_canceling_arithmetic). No readable comparison → the
# fixed `>=` fallback, and the comment says it stands in.
_NAI025S_TEXT = ("Replace `x - x` / `x ^ x` / `x % x` with the comparison the branch was meant to make: the "
                 "parameter-derived value against the quantity the intent names.")
_NAI025S_FALLBACK_SHAPE = ("if derived_from_param >= <intended quantity>:   # `>=` stands in for the comparison "
                           "the branch was meant to make, in place of `x - x` / `x ^ x` / `x % x`\n    ...")
_CANCEL_SYM = {"Sub": "-", "BitXor": "^", "Mod": "%"}
_CMP_SYM = {"Eq": "==", "NotEq": "!=", "Lt": "<", "LtE": "<=", "Gt": ">", "GtE": ">="}


def _nai025s_ops(broken_code: str) -> tuple:
    """(cancel_sym, cmp_sym) of the fire has_self_canceling_arithmetic matched — "" for either not read."""
    import textwrap
    try:
        tree = ast.parse(textwrap.dedent(broken_code or ""))
    except (SyntaxError, ValueError):
        tree = ast.Module(body=[], type_ignores=[])
    func = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    body, args = (func.body, func.args.args) if func is not None else ([], [])
    scope: ast.AST = func if func is not None else tree     # a hit exists only inside the function
    derived = {a.arg for a in args}
    for stmt in body:               # the check's param-derived tracking, verbatim in effect
        match stmt:
            case ast.Assign(targets=[ast.Name(id=tid)], value=ast.Call() as val) if any(
                    isinstance(x, ast.Name) and x.id in derived for x in ast.walk(val)):
                derived.add(tid)
            case ast.Assign(targets=[ast.Name(id=tid)], value=ast.Name(id=vid)) if vid in derived:
                derived.add(tid)
    hit = next((n for n in (ast.walk(func) if func is not None else ()) if isinstance(n, ast.BinOp)
                and type(n.op).__name__ in _CANCEL_SYM and isinstance(n.left, ast.Name)
                and isinstance(n.right, ast.Name) and n.left.id == n.right.id and n.left.id in derived), None)
    bound, cmps = set(), set()
    for s in (ast.walk(scope) if hit is not None else ()):
        match s:
            case ast.Assign(targets=[ast.Name(id=tid)], value=v) if v is hit:
                bound.add(tid)
    for c in (ast.walk(scope) if hit is not None else ()):
        match c:
            case ast.Compare(left=left, ops=[op], comparators=[right]) if type(op).__name__ in _CMP_SYM and any(
                    x is hit or (isinstance(x, ast.Name) and x.id in bound) for x in (left, right)):
                cmps.add(_CMP_SYM[type(op).__name__])
    cancel = _CANCEL_SYM[type(hit.op).__name__] if hit is not None else ""
    match sorted(cmps):
        case [one]:
            return cancel, one
    return cancel, ""


def nai025s_prescription(broken_code: str = "", failure_reason: str = "") -> tuple:
    """NAI-025S's (text, shape) with the fired operators; the `>=` fallback where none is read."""
    cancel, cmp_ = _nai025s_ops(broken_code)
    return _NAI025S_TEXT, (
        _NAI025S_FALLBACK_SHAPE if cancel == "" else
        f"if derived_from_param >= <intended quantity>:   # `>=` stands in for the comparison the branch was "
        f"meant to make, in place of `x {cancel} x`\n    ..." if cmp_ == "" else
        f"if derived_from_param {cmp_} <intended quantity>:   # the flagged branch's own `{cmp_}`, now against "
        f"the quantity the intent names, in place of `x {cancel} x`\n    ...")


_SRC = "no_aivalidator/noai_validator/strict_checks.py"

GENERATORS = [
        rewriter("NAI-021S", f"{_SRC}:is_alias_identity_chain", "alias_chain_fix", fix_alias_chain,
               "FINITE SET (1 candidate, the owner's form — hand check #4, 2026-09-16) for a function that mutates a parameter in place and returns it or an alias of it: `new_sequence` — the result is built as a new list / dict from the parameter, every later use reads the new name, the new sequence is returned; nothing is returned by alias. When no parameter is mutated in place (a pure alias chain has no finite answer without the intent) the ONE entry is `no_rewrite_shape` — no rewrite; emit this shape (I-78, owner ruling 2026-09-29 (b); the prescription FIX_41 carried): replace the alias chain with the transformation the dev's intent calls for — the function's own signature, `result = ...` computed from the parameter per the intent's expected output, `return result` — not a renamed copy of it.",
               "2026-09-16", "FIX_43 (b) run 123 (owner rulings 2026-09-15/16)"),
    # set 4b-40 (2026-09-10) — five no-fix-by-design; the strict row carries the strict id alone
        prescribed("NAI-009S", f"{_SRC}:is_naive_constant_ignore",
               "Replace the literal return with a computation that reads every parameter; the value returned must depend on the inputs the signature promises.",
               "def f(a, b):\n    <use a and b>\n    return <value computed from a, b>"),
        prescribed("NAI-016S", f"{_SRC}:is_exact_identity",
               "Replace `return param` with the transformation the name and the intent promise, applied to param.",
               "def f(param):\n    return <transform>(param)"),
        prescribed("NAI-017S", f"{_SRC}:is_canned_static_dict",
               "Replace the canned dict with one whose status / score / id fields are computed from the parameters (or fetched from the intent's external system), never literals.",
               "def f(params):\n    computed = <derive each field from params>\n    return {\"status\": computed.status, \"score\": computed.score}"),
        prescribed("NAI-022S", f"{_SRC}:is_param_ignored_delegator",
               "Pass the declared parameters into the delegated call (or drop the parameters the callee cannot take) so the call's result depends on this function's inputs.",
               "def f(a, b):\n    return callee(a, b)"),
        prescribed("NAI-023S", f"{_SRC}:is_sophisticated_identity_chain",
               "Replace the list() / [:] / identity-comprehension hops with the per-item transformation the intent calls for; a copy is not a transform.",
               "def f(items):\n    return [<transform>(x) for x in items]"),
    # set 4b-41 (2026-09-10) — the family's last three, no-fix-by-design; strict row, strict id alone
        prescribed("NAI-024S", f"{_SRC}:has_dead_zero_arithmetic",
               "Remove the `* 0` so the input-derived value carries through to the result, with the factor the intent specifies or none.",
               "value = derived_from_param * <factor per the intent>\nreturn value"),
        prescribed("NAI-025S", f"{_SRC}:has_self_canceling_arithmetic", _NAI025S_TEXT, _NAI025S_FALLBACK_SHAPE,
               shape_for=nai025s_prescription),
        prescribed("NAI-026S", f"{_SRC}:is_for_loop_identity_accumulator",
               "Replace the copy loop with the per-item work the intent calls for (transform, filter or aggregate each item); if the intent needs only a copy, return `list(param)` and say so in the docstring.",
               "def f(items):\n    out = []\n    for x in items:\n        out.append(<transform>(x))\n    return out"),
]
