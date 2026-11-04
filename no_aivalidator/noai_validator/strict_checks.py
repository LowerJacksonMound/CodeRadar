"""
Strict Yes/No Detectors — Pure AST Predicates.

Each function is a single deterministic predicate:
  "Does this AST node match exactly this structure?" → Yes = FAIL

No scores, no thresholds, no confidence, no fuzzy anything.
"""
import ast
import logging

_log = logging.getLogger(__name__)


def is_naive_constant_ignore(func: ast.FunctionDef) -> bool:
    """NAI-009S: Param declared but never used + returns constant/literal."""
    if len(func.body) != 1 or not isinstance(func.body[0], ast.Return):
        return False
    params = {arg.arg for arg in func.args.args}
    if not params:
        return False
    ret = func.body[0].value
    is_constant = isinstance(ret, ast.Constant) or \
                  (isinstance(ret, ast.Name) and ret.id not in params)
    if is_constant:
        _log.debug("NAI-009S matched: %s — params %s ignored, returns constant", func.name, params)
    return is_constant


def is_exact_identity(func: ast.FunctionDef) -> bool:
    """NAI-016S: Single return of the exact input parameter, nothing else."""
    if len(func.body) != 1 or not isinstance(func.body[0], ast.Return):
        return False
    ret = func.body[0].value
    if not isinstance(ret, ast.Name):
        return False
    params = [arg.arg for arg in func.args.args]
    matched = len(params) == 1 and ret.id == params[0]
    if matched:
        _log.debug("NAI-016S matched: %s — identity passthrough of '%s'", func.name, params[0])
    return matched


def is_canned_static_dict(func: ast.FunctionDef) -> bool:
    """NAI-017S: Returns a static dict literal while ignoring all parameters."""
    if len(func.body) != 1 or not isinstance(func.body[0], ast.Return):
        return False
    ret = func.body[0].value
    if not isinstance(ret, ast.Dict):
        return False
    params = {arg.arg for arg in func.args.args}
    if not params:
        return False
    keys = {k.value if isinstance(k, ast.Constant) else None for k in ret.keys}
    canned_keys = {"status", "risk_score", "transaction_id", "approved", "score"}
    matched = bool(keys & canned_keys)
    if matched:
        _log.debug("NAI-017S matched: %s — canned dict with keys %s, params %s ignored",
                   func.name, keys & canned_keys, params)
    return matched


# is_dead_simple_body (NAI-019S) DELETED cut 2 (2026-09-05): a name-word heuristic gated on `len(body) <= 2`
# in the proof layer (EXCISION_LIST class X). Name/body disagreement returns as an observation via §S.7.


def is_alias_identity_chain(func: ast.FunctionDef) -> bool:
    """NAI-021S: All data flow from params to return is identity-preserving (alias chain).

    Catches workaround patterns like:
        def enrich(data):
            temp = list(data)
            processed = temp[:]
            validated = processed
            return validated
    Every hop is a copy/alias — no real transformation occurs.
    """
    if len(func.body) < 1:  # EXCISED cut 2 (2026-09-05): was `len(func.body) < 3` — EXCISION_LIST class A
        return False
    if not func.args.args:
        return False
    has_return = any(isinstance(n, ast.Return) and n.value is not None
                     for n in ast.walk(func))
    if not has_return:
        return False

    try:
        from utils.code_analysis.extractor import MetricsExtractor as FlowExtractor
        from utils.code_analysis.graph import is_identity_chain
    except ImportError:
        _log.debug("NAI-021S: utils.code_analysis not available, skipping")
        return False

    extractor = FlowExtractor(func)
    metrics = extractor.metrics
    matched = is_identity_chain(metrics)
    if matched:
        _log.debug("NAI-021S matched: %s — alias identity chain detected", func.name)
    return matched


def _own_scope_nodes(func: ast.FunctionDef):
    """Every node of `func`'s own body — a nested def / lambda / class is another scope and is not walked."""
    stack: list[ast.AST] = list(func.body)
    while stack:
        n = stack.pop()
        yield n
        for c in ast.iter_child_nodes(n):
            if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                stack.append(c)


def alias_identity_chain_lines(func: ast.FunctionDef) -> list[int]:
    """T-09 (R7, 2026-09-30): the lines NAI-021S fired on — every `return <value>` of the function's own
    scope, plus every assignment that writes a link of the alias chain (a variable the return traces
    back through on its way to a parameter). Before this the check returned a bare bool, so all
    NAI-021S rows published finding_lines: []. Read off the same flow graph the predicate decides on."""
    lines: set[int] = set()
    chain: set[str] = set()
    try:
        from utils.code_analysis.extractor import MetricsExtractor as FlowExtractor
        metrics = FlowExtractor(func).metrics
        incoming: dict[str, list[str]] = {}
        for e in metrics.data_flow_edges:
            incoming.setdefault(e.target, []).append(e.source)
        todo = [v for v in metrics.return_sources if v not in metrics.params_declared]
        while todo:
            v = todo.pop()
            if v in chain:
                continue
            chain.add(v)
            todo.extend(s for s in incoming.get(v, []) if s not in metrics.params_declared)
    except ImportError:
        pass   # the predicate cannot fire without the flow graph either; the return lines still publish
    for n in _own_scope_nodes(func):
        if isinstance(n, ast.Return) and n.value is not None:
            lines.add(n.lineno)
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(isinstance(t, ast.Name) and t.id in chain
                   for tgt in targets for t in ast.walk(tgt)):
                lines.add(n.lineno)
    return sorted(lines)


def is_sophisticated_identity_chain(func: ast.FunctionDef) -> bool:
    """NAI-023S: Copy/alias chain through list(), slicing, and identity comprehensions.

    Catches workaround patterns like:
        def enrich(data):
            temp = list(data)
            processed = temp[:]
            normalized = [item for item in processed]
            return normalized
    Every hop is list()/[:]/[x for x in y]/bare assignment — no real transformation.
    """
    if len(func.body) < 2:
        return False
    params = {arg.arg for arg in func.args.args}
    if not params:
        return False

    # Track which names are "tainted" (copies of params)
    tainted: set[str] = set(params)

    IDENTITY_OPS = True  # flag — all assignments so far are identity-preserving

    for stmt in func.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if not isinstance(target, ast.Name):
                IDENTITY_OPS = False
                continue
            val = stmt.value
            if _is_identity_expr(val, tainted):
                tainted.add(target.id)
            else:
                IDENTITY_OPS = False
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None and _is_identity_expr(stmt.value, tainted):
                continue
            else:
                IDENTITY_OPS = False
        else:
            IDENTITY_OPS = False

    if not IDENTITY_OPS:
        return False

    # Must have a return that traces back to a param
    for stmt in func.body:
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            if _is_identity_expr(stmt.value, tainted):
                _log.debug("NAI-023S matched: %s — sophisticated identity chain detected",
                           func.name)
                return True
    return False


def _is_identity_expr(node: ast.expr, tainted: set[str]) -> bool:
    """Check if an expression is an identity-preserving operation on tainted names."""
    # Bare name: x
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    # list(x), set(x), tuple(x), sorted(x)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"list", "set", "tuple", "sorted", "dict"}
            and len(node.args) == 1 and not node.keywords):
        return _is_identity_expr(node.args[0], tainted)
    # x[:] or x[:]
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        sl = node.slice
        if sl.lower is None and sl.upper is None and sl.step is None:
            return _is_identity_expr(node.value, tainted)
    # [item for item in x] — identity list comprehension
    if (isinstance(node, ast.ListComp) and len(node.generators) == 1):
        gen = node.generators[0]
        if (not gen.ifs and isinstance(gen.target, ast.Name)
                and isinstance(node.elt, ast.Name)
                and node.elt.id == gen.target.id
                and isinstance(gen.iter, ast.Name)
                and gen.iter.id in tainted):
            return True
    return False


def has_dead_zero_arithmetic(func: ast.FunctionDef) -> bool:
    """NAI-024S: Param is read but zeroed out — dead math that cancels input.

    Catches direct and transitive zero patterns:
        Direct:   volume_adj = amount * 0.0
        Transitive: factor = len(category) * 0; score = amount * factor
    The param is "used" but its contribution is zeroed out.
    """
    params = {arg.arg for arg in func.args.args}
    if not params:
        return False

    # Pass 1: Track names derived from params (e.g. amount = transaction.get(...))
    param_derived: set[str] = set(params)
    # Pass 1b: Track names that are known-zero (assigned from expr * 0, x - x, etc.)
    known_zero: set[str] = set()

    for stmt in func.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                val = stmt.value
                # x = param.get(...) or x = param[...]
                if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                    if isinstance(val.func.value, ast.Name) and val.func.value.id in param_derived:
                        param_derived.add(target.id)
                elif isinstance(val, ast.Subscript):
                    if isinstance(val.value, ast.Name) and val.value.id in param_derived:
                        param_derived.add(target.id)
                # Track known-zero assignments: x = expr * 0, x = 0 * expr, x = y - y
                if isinstance(val, ast.BinOp):
                    if isinstance(val.op, ast.Mult):
                        if _is_zero(val.left) or _is_zero(val.right):
                            known_zero.add(target.id)
                    elif isinstance(val.op, ast.Sub):
                        if (isinstance(val.left, ast.Name) and isinstance(val.right, ast.Name)
                                and val.left.id == val.right.id):
                            known_zero.add(target.id)

    # Pass 2: Any param-derived value multiplied by zero (direct or transitive) is dead math.
    # Real code never multiplies its inputs by zero.
    for node in ast.walk(func):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            left, right = node.left, node.right
            # Direct: param_derived * 0
            if _is_zero(right) and _mentions_names(left, param_derived):
                _log.debug("NAI-024S matched: %s — param-derived * 0 (direct)",
                           func.name)
                return True
            if _is_zero(left) and _mentions_names(right, param_derived):
                _log.debug("NAI-024S matched: %s — 0 * param-derived (direct)",
                           func.name)
                return True
            # Transitive: param_derived * known_zero_var
            if _mentions_only_names(right, known_zero) and _mentions_names(left, param_derived):
                _log.debug("NAI-024S matched: %s — param-derived * known_zero_var '%s' (transitive)",
                           func.name, right.id if isinstance(right, ast.Name) else "?")
                return True
            if _mentions_only_names(left, known_zero) and _mentions_names(right, param_derived):
                _log.debug("NAI-024S matched: %s — known_zero_var * param-derived (transitive)",
                           func.name)
                return True

    return False


def _is_zero(node: ast.expr) -> bool:
    """Check if a node is the literal 0 or 0.0."""
    return isinstance(node, ast.Constant) and node.value in (0, 0.0)


def _mentions_names(node: ast.expr, names: set[str]) -> bool:
    """Check if an expression references any of the given names."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False


def _mentions_only_names(node: ast.expr, names: set[str]) -> bool:
    """Check if a node is a bare Name that is in the given set."""
    return isinstance(node, ast.Name) and node.id in names


def has_self_canceling_arithmetic(func: ast.FunctionDef) -> bool:
    """NAI-025S: Self-canceling arithmetic — x - x, x ^ x, x % x always yield 0.

    Catches workaround patterns like:
        def validate(data):
            length = len(data)
            unique = len(set(data))
            noise = unique - unique   # always 0
            if length > 0:
                return True
            return True if noise == 0 else False
    The param is "used" but a self-canceling op makes all branches dead.
    """
    params = {arg.arg for arg in func.args.args}
    if not params:
        return False

    # Track param-derived names
    param_derived: set[str] = set(params)
    for stmt in func.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                val = stmt.value
                if isinstance(val, ast.Call):
                    if _mentions_names(val, param_derived):
                        param_derived.add(target.id)
                elif isinstance(val, ast.Name) and val.id in param_derived:
                    param_derived.add(target.id)

    # Look for x - x, x ^ x, x % x where x is param-derived
    for node in ast.walk(func):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Sub, ast.BitXor, ast.Mod)):
            if (isinstance(node.left, ast.Name) and isinstance(node.right, ast.Name)
                    and node.left.id == node.right.id
                    and node.left.id in param_derived):
                _log.debug("NAI-025S matched: %s — self-canceling '%s - %s' (param-derived)",
                           func.name, node.left.id, node.right.id)
                return True
    return False


def is_for_loop_identity_accumulator(func: ast.FunctionDef) -> bool:
    """NAI-026S: Loop identity accumulator — buf=[]; for/while: buf.append(x).

    Catches workaround patterns using for-loops, while-loops, identity listcomps,
    slices, bare assignments, and no-op branching (if/else that does nothing).
        def enrich(data):
            temp = []
            for item in data:
                temp.append(item)
            # or: while i < len(data): temp.append(data[i]); i += 1
            result = temp[:]
            return result
    """
    if len(func.body) < 1:  # EXCISED cut 2 (2026-09-05): was `len(func.body) < 3` — EXCISION_LIST class A
        return False
    params = {arg.arg for arg in func.args.args}
    if not params:
        return False

    tainted: set[str] = set(params)
    empty_lists: set[str] = set()
    # Track counter variables (i = 0) — these are scaffolding, not real computation
    counters: set[str] = set()

    all_identity = True

    for stmt in func.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if not isinstance(target, ast.Name):
                all_identity = False
                continue
            val = stmt.value
            # buf = [] — empty list init
            if isinstance(val, ast.List) and len(val.elts) == 0:
                empty_lists.add(target.id)
            # i = 0 — counter init
            elif isinstance(val, ast.Constant) and val.value == 0:
                counters.add(target.id)
            elif _is_identity_expr(val, tainted):
                tainted.add(target.id)
            else:
                all_identity = False

        elif isinstance(stmt, ast.For):
            if not _is_for_loop_append(stmt, tainted, empty_lists):
                all_identity = False

        elif isinstance(stmt, ast.While):
            if not _is_while_loop_copy(stmt, tainted, empty_lists, counters):
                # Check if it's a no-op while (identity operations only)
                if not _is_noop_while(stmt, tainted, counters):
                    all_identity = False

        elif isinstance(stmt, ast.Return):
            if stmt.value is not None and isinstance(stmt.value, ast.Name):
                if stmt.value.id in tainted:
                    continue
            all_identity = False

        else:
            all_identity = False

    if not all_identity:
        return False

    for stmt in func.body:
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            if isinstance(stmt.value, ast.Name) and stmt.value.id in tainted:
                _log.debug("NAI-026S matched: %s — loop identity accumulator chain detected",
                           func.name)
                return True
    return False


def _is_for_loop_append(
    for_node: ast.For, tainted: set[str], empty_lists: set[str]
) -> bool:
    """Check if a for-loop is `for x in tainted: buf.append(x)` and taint buf.

    Side effect: if matched, moves buf from empty_lists to tainted.
    """
    # for <loop_var> in <iter>:
    if not isinstance(for_node.target, ast.Name):
        return False
    if not isinstance(for_node.iter, ast.Name):
        return False
    if for_node.iter.id not in tainted:
        return False
    # Body must be exactly: buf.append(loop_var)
    if len(for_node.body) != 1:
        return False
    stmt = for_node.body[0]
    if not isinstance(stmt, ast.Expr):
        return False
    call = stmt.value
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "append":
        return False
    if len(call.args) != 1 or call.keywords:
        return False
    if not isinstance(call.args[0], ast.Name):
        return False
    if call.args[0].id != for_node.target.id:
        return False
    # The object being appended to
    if not isinstance(call.func.value, ast.Name):
        return False
    buf_name = call.func.value.id
    if buf_name not in empty_lists:
        return False

    # Match! Taint the buffer.
    empty_lists.discard(buf_name)
    tainted.add(buf_name)
    return True


def _is_while_loop_copy(
    while_node: ast.While, tainted: set[str], empty_lists: set[str],
    counters: set[str],
) -> bool:
    """Check if a while-loop is `while i < len(tainted): buf.append(tainted[i]); i += 1`.

    Side effect: if matched, moves buf from empty_lists to tainted.
    """
    # Body should contain: buf.append(tainted[i]) and i += 1
    # Possibly with other scaffolding
    append_buf = None
    has_increment = False

    for stmt in while_node.body:
        # buf.append(source[i])
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if (isinstance(call.func, ast.Attribute) and call.func.attr == "append"
                    and len(call.args) == 1 and not call.keywords
                    and isinstance(call.func.value, ast.Name)):
                buf_name = call.func.value.id
                arg = call.args[0]
                # arg should be tainted[i] (subscript on tainted)
                if (isinstance(arg, ast.Subscript)
                        and isinstance(arg.value, ast.Name)
                        and arg.value.id in tainted):
                    if buf_name in empty_lists:
                        append_buf = buf_name
                    continue
                # or arg is just a Name in tainted (for x in tainted variant)
                if isinstance(arg, ast.Name) and arg.id in tainted:
                    if buf_name in empty_lists:
                        append_buf = buf_name
                    continue
        # i += 1
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
            if (isinstance(stmt.target, ast.Name) and stmt.target.id in counters
                    and isinstance(stmt.value, ast.Constant) and stmt.value.value == 1):
                has_increment = True
                continue

    if append_buf and has_increment:
        empty_lists.discard(append_buf)
        tainted.add(append_buf)
        return True
    return False


def _is_noop_while(
    while_node: ast.While, tainted: set[str], counters: set[str],
) -> bool:
    """Check if a while-loop only does no-op operations on tainted data.

    Catches patterns like:
        while j < len(layer):
            if j % 2 == 0: pass
            else: layer[j] = layer[j]
            j += 1
    """
    for stmt in while_node.body:
        # i += 1 — counter increment, fine
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
            if (isinstance(stmt.target, ast.Name) and stmt.target.id in counters
                    and isinstance(stmt.value, ast.Constant) and stmt.value.value == 1):
                continue
        # if/else with only pass or self-assignment
        if isinstance(stmt, ast.If):
            if _is_noop_branch(stmt, tainted):
                continue
        return False
    return True


def _is_noop_branch(if_node: ast.If, tainted: set[str]) -> bool:
    """Check if an if/else only contains pass or self-assignments like x[i] = x[i]."""
    for branch_body in [if_node.body, if_node.orelse]:
        for stmt in branch_body:
            if isinstance(stmt, ast.Pass):
                continue
            # x[i] = x[i] — self-assignment (compare ignoring Store/Load ctx)
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                val = stmt.value
                if _ast_structurally_equal(target, val):
                    continue
            return False
    return True


def _ast_structurally_equal(a: ast.AST, b: ast.AST) -> bool:
    """Compare two AST nodes ignoring ctx (Store vs Load)."""
    if type(a) != type(b):
        return False
    if isinstance(a, ast.Name):
        return a.id == b.id  # type: ignore[attr-defined]  # FIX_54 ast-pos
    if isinstance(a, ast.Constant):
        return a.value == b.value  # type: ignore[attr-defined]  # FIX_54 ast-pos
    if isinstance(a, ast.Subscript):
        return (_ast_structurally_equal(a.value, b.value)  # type: ignore[attr-defined]  # FIX_54 ast-pos
                and _ast_structurally_equal(a.slice, b.slice))  # type: ignore[attr-defined]  # FIX_54 ast-pos
    if isinstance(a, ast.Attribute):
        return (a.attr == b.attr  # type: ignore[attr-defined]  # FIX_54 ast-pos
                and _ast_structurally_equal(a.value, b.value))  # type: ignore[attr-defined]  # FIX_54 ast-pos
    return ast.dump(a) == ast.dump(b)


def is_param_ignored_delegator(func: ast.FunctionDef) -> bool:
    """NAI-022S: Has params, none read in body, delegates to function call and returns result.

    Catches split-fake patterns like:
        def fetch_external_validation(record_id):
            result = _make_gateway_result()
            return result
    The param exists only for show — never read, never forwarded.
    """
    # Hardened 2026-09-05 (F-022S). A registered/decorated callable conforms to
    # a signature the framework imposes (Django checks: "must accept
    # app_configs ... **kwargs is required for future expansion"); a `*args` /
    # `**kwargs` catch-all is that convention made explicit. Neither is a
    # split-fake. `self`/`cls` are the receiver, not inputs.
    if func.decorator_list:
        return False
    if func.args.vararg or func.args.kwarg:
        return False
    params = {arg.arg for arg in func.args.args} - {'self', 'cls'}
    if not params:
        return False
    if len(func.body) < 2:
        return False

    body_module = ast.Module(body=func.body, type_ignores=[])
    read_names: set[str] = set()
    for node in ast.walk(body_module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            read_names.add(node.id)

    if params & read_names:
        return False

    has_call = any(isinstance(node, ast.Call) for node in ast.walk(body_module))
    if not has_call:
        return False

    has_return_value = any(
        isinstance(node, ast.Return) and node.value is not None
        for node in ast.walk(body_module)
    )
    if not has_return_value:
        return False

    _log.debug("NAI-022S matched: %s — params %s declared but never read, "
               "delegates to call and returns result", func.name, params)
    return True


# Registry: rule_id → (predicate, description)
STRICT_CHECKS = [
    ("NAI-009S", is_naive_constant_ignore,
     "Params declared but never used, returns constant"),
    ("NAI-016S", is_exact_identity,
     "Identity passthrough — returns exact input unchanged"),
    ("NAI-017S", is_canned_static_dict,
     "Returns canned static dict, ignores all parameters"),
    # NAI-019S is_dead_simple_body REMOVED from the proof layer (cut 2, 2026-09-05; EXCISION_LIST class X):
    # a name-word heuristic with a `len(body) <= 2` gate is not a proof. The function stays for reuse as an observation.
    ("NAI-021S", is_alias_identity_chain,
     "Alias identity chain — all data flow is copy/alias, no real transformation"),
    ("NAI-022S", is_param_ignored_delegator,
     "Params declared but never read, delegates to call and returns result"),
    ("NAI-023S", is_sophisticated_identity_chain,
     "Sophisticated identity chain — copy/alias through list()/[:]/comprehension"),
    ("NAI-024S", has_dead_zero_arithmetic,
     "Dead zero arithmetic — param-derived values multiplied/added by zero"),
    ("NAI-025S", has_self_canceling_arithmetic,
     "Self-canceling arithmetic — x - x / x ^ x / x % x always yields zero"),
    ("NAI-026S", is_for_loop_identity_accumulator,
     "For-loop identity accumulator — buf=[]; for x in param: buf.append(x) chain"),
]


# T-09 (R7, 2026-09-30): strict checks that can name the lines they fired on. The validator's strict branch
# publishes one {"tag": rule_id, "line": n} observation per line, which the daemon's `_finding_lines` reads.
STRICT_FINDING_LINES = {
    "NAI-021S": alias_identity_chain_lines,
}


def strict_finding_observations(rule_id: str, func: ast.FunctionDef) -> list[dict]:
    """The line observations for a strict check that failed `func` ([] for a check with no line reader)."""
    reader = STRICT_FINDING_LINES.get(rule_id)
    if reader is None:
        return []
    try:
        lines = reader(func)
    except Exception as e:   # a line reader never turns a proven verdict into a crash
        _log.debug("%s line reader failed on %s: %s", rule_id, func.name, e)
        return []
    return [{"tag": rule_id, "line": ln, "func_name": func.name} for ln in lines]
