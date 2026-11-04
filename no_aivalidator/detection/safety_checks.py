"""
Safety Gap Detection Mixin (NAI-070 to NAI-079, NAI-091 to NAI-099, NAI-160 to NAI-166, NAI-200).

Detect missing error handling, unsafe patterns, security issues,
defensive coding gaps, and dangerous runtime manipulation.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, Set, List, Optional, Iterator, TYPE_CHECKING
import logging

_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
# A getenv default that is a place to connect to: a URL, a loopback / any-address host, or an absolute path.
_ENV_FALLBACK = re.compile(r"^[a-z][a-z0-9+.-]*://|^(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?(/|$)|^(/|~/)", re.I)

_log = logging.getLogger(__name__)


# ── NAI-094's two object predicates (R4, owner 2026-09-21, run 164) ───────────────────────────
# The same two lines as `noai_validator.utils.is_sys_path` / `is_os_environ`, which the MODULE-
# scope half of NAI-094 runs. They are not imported from there: `noai_validator` imports this
# package (validator.py -> detection.base), so the import would close a cycle. The guard against
# the two copies drifting is a TEST, not an import — `nai094_entry_proof` part 6 runs one table
# of shapes through BOTH halves and fails if a single verdict differs.
def _is_sys_path(expr: ast.AST) -> bool:
    """`sys.path` attribute expression."""
    return (isinstance(expr, ast.Attribute) and expr.attr == "path"
            and isinstance(expr.value, ast.Name) and expr.value.id == "sys")


def _is_os_environ(expr: ast.AST) -> bool:
    """`os.environ` attribute expression."""
    return (isinstance(expr, ast.Attribute) and expr.attr == "environ"
            and isinstance(expr.value, ast.Name) and expr.value.id == "os")


# ── NAI-094 save/restore pair recognizer (owner's ruling (b), 2026-09-21, run 164 follow-up,
# T2b) ──────────────────────────────────────────────────────────────────────────────────────
# PER-FUNCTION half only (this module). The MODULE-scope half (`noai_validator.validator.
# validate_module`) is untouched: a module-level os.environ write still fires unconditionally —
# there is no enclosing function to save/restore across.
#
# Reading (i) was built (measured against `CliRunner.isolation`, `src/click/testing.py::399`):
# an os.environ write inside a `try` does not fire when that same `try`'s `finally` restores
# os.environ from a name the function bound from an os.environ READ before the write —
# `os.environ.get(k)` / `os.environ[k]` / `dict(os.environ)` / `os.environ.copy()`, including a
# per-key save into a dict (`saved[k] = os.environ.get(k)`, `isolation`'s own shape at L567).
# Both legs of a recognized pair are silent: the try-body write AND the finally's restoring
# write/delete. No dataflow beyond name binding is performed (name binding = "this Name was
# assigned from an os.environ read" / "this Name is read back in the finally"); a `finally`
# that writes an unrelated, unsaved key is not a restore and the try-body write still fires.
def _is_environ_read_expr(expr: ast.AST) -> bool:
    """`os.environ.get(k[, d])` / `os.getenv(k[, d])` / `dict(os.environ)` / `os.environ.copy()`
    / a bare subscript read `os.environ[k]` — the shapes a save can be bound from."""
    if isinstance(expr, ast.Subscript):
        return _is_os_environ(expr.value)
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Attribute) and func.attr in ("get", "copy") and _is_os_environ(func.value):
            return True
        if isinstance(func, ast.Name) and func.id == "getenv":
            return True
        if isinstance(func, ast.Name) and func.id == "dict" and expr.args and _is_os_environ(expr.args[0]):
            return True
    return False


def _saved_env_names(scope: ast.AST) -> Set[str]:
    """Names the function bound from an os.environ read, either directly (`old = os.environ.get(k)`)
    or per-key into a mapping (`old_env[key] = os.environ.get(key)`, `isolation`'s own shape)."""
    names: Set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Assign) or not _is_environ_read_expr(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                names.add(target.value.id)
    return names


def _reads_saved_name(expr: ast.AST, saved: Set[str]) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in saved
    if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name):
        return expr.value.id in saved
    return False


def _is_environ_write_or_delete(node: ast.AST) -> bool:
    """Every WRITE shape the rule fires on, plus `del os.environ[k]` (a restore leg, never a
    fire on its own — the boundary NAI-094 leaves as CLEAN, measured and unmoved by T2b)."""
    if isinstance(node, ast.Assign):
        return any(isinstance(t, ast.Subscript) and _is_os_environ(t.value) for t in node.targets)
    if isinstance(node, ast.AugAssign):
        return isinstance(node.target, ast.Subscript) and _is_os_environ(node.target.value)
    if isinstance(node, ast.Delete):
        return any(isinstance(t, ast.Subscript) and _is_os_environ(t.value) for t in node.targets)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in ("setdefault", "update", "pop", "clear") and _is_os_environ(node.func.value)
    return False


def _finally_restores_from(finalbody: List[ast.stmt], saved: Set[str]) -> bool:
    """True when some statement in a `finally` clause writes or deletes `os.environ` sourced
    from one of `saved` — directly (`os.environ[k] = old[k]`), via a saved-mapping loop
    (`for key, value in old_env.items(): ... os.environ[key] = value` / `del os.environ[key]`,
    `isolation`'s own shape at L577-L584), or `os.environ.clear()` + `.update(saved)`."""
    for stmt in finalbody:
        for node in ast.walk(stmt):
            if isinstance(node, ast.For):
                it = node.iter
                if (isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute)
                        and it.func.attr == "items" and isinstance(it.func.value, ast.Name)
                        and it.func.value.id in saved):
                    for inner in ast.walk(node):
                        if _is_environ_write_or_delete(inner):
                            return True
            elif isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Subscript) and _is_os_environ(t.value) for t in node.targets):
                    if _reads_saved_name(node.value, saved):
                        return True
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "update" and _is_os_environ(node.func.value):
                    if node.args and _reads_saved_name(node.args[0], saved):
                        return True
    return False


def _environ_pair_exempt_lines(func_node: ast.AST) -> Set[int]:
    """Line numbers of os.environ write/delete statements that are one leg of a recognized
    save/restore pair inside `func_node` — exempt from the NAI-094 fire (per-function half only).
    A write is exempt only when its own enclosing `try` has BOTH a `finally` and a name bound
    from an os.environ read that the `finally` restores from; an unrestored write, or a `finally`
    that writes a different/unsaved key, is never exempted."""
    exempt: Set[int] = set()
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        saved = _saved_env_names(node)
        if not saved or not _finally_restores_from(node.finalbody, saved):
            continue
        for stmt in list(node.body) + list(node.finalbody):
            for sub in ast.walk(stmt):
                if _is_environ_write_or_delete(sub):
                    exempt.add(getattr(sub, "lineno", 0))
    return exempt


class SafetyChecksMixin:
    """Mixin providing safety gap detection checks."""
    if TYPE_CHECKING:  # FIX_31 (2026-09-15): what the composed AIFakeDetector supplies to every check mixin — typing only, no runtime effect
        imported_names: Dict[str, str]
        module_level_names: Set[str]
        module_attr_names: Set[str]
        enclosing_names: Set[str]
        class_bases: Optional[List[str]]
        @staticmethod
        def _own_scope(root: ast.AST) -> Iterator[ast.AST]: ...
        def _has_decorator(self, *names: str) -> bool: ...
        def _class_is_protocol(self) -> bool: ...

    # Type declarations for mixin attributes (defined in AIFakeDetector.__init__)
    metrics: Any
    func: ast.FunctionDef
    observations: list[dict[str, Any]]
    _definitions: Any

    def _check_bare_except(self) -> None:
        """
        NAI-070: Detect bare except clauses.

        Pattern: except:  (catches SystemExit, KeyboardInterrupt too)
        Should be: except Exception:
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    self.observations.append({
                        "tag": "NAI-070",
                        "line": node.lineno,
                        "handler_type": "bare_except",
                    })
                    _log.debug("NAI-070 observed: bare except at line %d", node.lineno)
                    return

    def _check_mutable_default_arg(self) -> None:
        """
        NAI-071: Detect mutable default arguments.

        Pattern: def f(x=[]), def f(x={})
        """
        m = self.metrics

        for default in self.func.args.defaults + self.func.args.kw_defaults:
            if default is None:
                continue

            if isinstance(default, ast.List):
                self.observations.append({
                    "tag": "NAI-071",
                    "line": default.lineno,
                    "mutable_type": "list",
                    "form": "literal",
                })
                _log.debug("NAI-071 observed: mutable list default at line %d", default.lineno)
                return
            if isinstance(default, ast.Dict):
                self.observations.append({
                    "tag": "NAI-071",
                    "line": default.lineno,
                    "mutable_type": "dict",
                    "form": "literal",
                })
                _log.debug("NAI-071 observed: mutable dict default at line %d", default.lineno)
                return
            if isinstance(default, ast.Set):
                self.observations.append({
                    "tag": "NAI-071",
                    "line": default.lineno,
                    "mutable_type": "set",
                    "form": "literal",
                })
                _log.debug("NAI-071 observed: mutable set default at line %d", default.lineno)
                return
            if isinstance(default, ast.Call):
                if isinstance(default.func, ast.Name):
                    if default.func.id in ('list', 'dict', 'set'):
                        self.observations.append({
                            "tag": "NAI-071",
                            "line": default.lineno,
                            "mutable_type": default.func.id,
                            "form": "constructor_call",
                        })
                        _log.debug("NAI-071 observed: mutable %s() default at line %d", default.func.id, default.lineno)
                        return

    def _check_hardcoded_secrets(self) -> None:
        """
        NAI-072: Detect hardcoded credentials/secrets.

        Pattern: password = "...", api_key = "...", secret = "..."

        Uses dynamic definitions if available.
        """
        m = self.metrics

        secret_patterns = {'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
                          'token', 'auth', 'credential', 'private_key', 'secret_key'}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        for pattern in secret_patterns:
                            if pattern.lower() in name_lower:
                                if isinstance(node.value, ast.Constant):
                                    if isinstance(node.value.value, str) and len(node.value.value) > 0:
                                        self.observations.append({
                                            "tag": "NAI-072",
                                            "line": node.lineno,
                                            "variable_name": target.id,
                                            "matched_pattern": pattern,
                                            "value_type": "string_literal",
                                        })
                                        _log.debug("NAI-072 observed: hardcoded secret '%s' at line %d", target.id, node.lineno)
                                        return

    def _check_sql_injection_risk(self) -> None:
        """
        NAI-073: Detect SQL injection risks.

        Pattern: f"SELECT ... {var}" or "SELECT ...".format(var)

        Uses word boundary matching to avoid false positives on words like
        "selected", "created", "inserted" etc.
        """
        m = self.metrics

        # Word boundary patterns for SQL keywords
        sql_keyword_patterns = [
            re.compile(r'\bselect\b', re.IGNORECASE),
            re.compile(r'\binsert\b', re.IGNORECASE),
            re.compile(r'\bupdate\b', re.IGNORECASE),
            re.compile(r'\bdelete\b', re.IGNORECASE),
            re.compile(r'\bdrop\b', re.IGNORECASE),
            re.compile(r'\bcreate\b', re.IGNORECASE),
            re.compile(r'\balter\b', re.IGNORECASE),
        ]

        def _contains_sql_keyword(text: str) -> bool:
            """Check if text contains SQL keyword with word boundaries."""
            return any(pattern.search(text) for pattern in sql_keyword_patterns)

        for node in ast.walk(self.func):
            if isinstance(node, ast.JoinedStr):
                has_sql = False
                has_interpolation = False
                for value in node.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        if _contains_sql_keyword(value.value):
                            has_sql = True
                    if isinstance(value, ast.FormattedValue):
                        has_interpolation = True

                if has_sql and has_interpolation:
                    self.observations.append({
                        "tag": "NAI-073",
                        "line": node.lineno,
                        "injection_vector": "f_string",
                    })
                    _log.debug("NAI-073 observed: SQL f-string interpolation at line %d", node.lineno)
                    return

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                    if isinstance(node.func.value, ast.Constant):
                        if isinstance(node.func.value.value, str):
                            if _contains_sql_keyword(node.func.value.value):
                                self.observations.append({
                                    "tag": "NAI-073",
                                    "line": node.lineno,
                                    "injection_vector": "str_format",
                                })
                                _log.debug("NAI-073 observed: SQL .format() interpolation at line %d", node.lineno)
                                return

    def _check_unguarded_json_parse(self) -> None:
        """
        NAI-074: Detect json.loads()/json.load() without try-except.

        Mathematical basis: Presence in call set, absence from try block
        """
        m = self.metrics

        json_calls: list[ast.Call] = []
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('loads', 'load'):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'json':
                            json_calls.append(node)

        if not json_calls:
            self.observations.append({"tag": 'NAI-074', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not json_calls'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        has_try = False
        for node in ast.walk(self.func):
            if isinstance(node, ast.Try):
                has_try = True
                break

        if not has_try and json_calls:
            method = json_calls[0].func.attr if isinstance(json_calls[0].func, ast.Attribute) else 'loads'
            self.observations.append({
                "tag": "NAI-074",
                "line": json_calls[0].lineno,
                "json_method": method,
                "call_count": len(json_calls),
                "has_try_except": False,
            })
            _log.debug("NAI-074 observed: unguarded json.%s at line %d", method, json_calls[0].lineno)

    def _check_unguarded_file_ops(self) -> None:
        """
        NAI-075: Detect file operations without context manager.

        Pattern: open() not in with statement
        """
        m = self.metrics

        parent_of: dict[int, ast.AST] = {}
        for node in ast.walk(self.func):
            for child in ast.iter_child_nodes(node):
                parent_of[id(child)] = node

        # Body-shape hardening 2026-09-06 (F-075a/b, IG-16): a `with` whose own
        # context-expression is the open() call itself is guarded (as before);
        # a `with` whose context-expression is a bare Name is ALSO guarded when
        # that name was earlier assigned an open() call's result — the handle
        # is entered by name (`fh = open(...); with fh:` / `with fh as f:`)
        # rather than inline, but __exit__ still runs on every exit path.
        #
        # F-075e: every scan below (and the main open()-call scan) is restricted
        # to this function's OWN scope (`_own_scope`, IG-7/IG-9) — an open() call
        # that lives inside a nested `def`/`lambda` body executes in THAT scope,
        # not this function's; a returned closure (werkzeug SharedDataMiddleware
        # `_opener`: `return lambda: (open(filename, "rb"), ...)`) is a different
        # scope's execution being handed to the caller, exactly the own-scope
        # reasoning already applied to NAI-160/NAI-200 (`_own_scope`).
        with_call_ids: set[int] = set()
        with_bound_names: set[str] = set()
        for node in self._own_scope(self.func):
            if isinstance(node, ast.With):
                for item in node.items:
                    if isinstance(item.context_expr, ast.Call):
                        if isinstance(item.context_expr.func, ast.Name) and item.context_expr.func.id == 'open':
                            with_call_ids.add(id(item.context_expr))
                    elif isinstance(item.context_expr, ast.Name):
                        with_bound_names.add(item.context_expr.id)

        # Body-shape hardening 2026-09-06 (F-075c): the assigned name is later
        # the target of a `.close()` call reached inside a `try` statement's
        # except-handlers or finally-block — exception-handling machinery
        # built for guaranteed-or-conditional cleanup, structurally different
        # from a call with no cleanup reachable anywhere in the function.
        closed_in_handler_names: set[str] = set()
        for node in self._own_scope(self.func):
            if isinstance(node, ast.Try):
                handler_stmts = list(node.finalbody)
                for h in node.handlers:
                    handler_stmts.extend(h.body)
                for stmt in handler_stmts:
                    for n in ast.walk(stmt):
                        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                and n.func.attr == 'close' and isinstance(n.func.value, ast.Name)):
                            closed_in_handler_names.add(n.func.value.id)

        # Body-shape hardening 2026-09-06 (F-075d): the assigned name is later
        # the target of a bare `return <name>` — the handle's ownership is
        # transferred to the caller, who then owns closing it (same reasoning
        # already applied to NAI-200's honest rows that hand back an open
        # file directly).
        returned_names: set[str] = set()
        for node in self._own_scope(self.func):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Name):
                returned_names.add(node.value.id)

        for node in self._own_scope(self.func):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open'):
                continue
            if id(node) in with_call_ids:
                continue

            parent = parent_of.get(id(node))
            if isinstance(parent, ast.Return):
                continue  # `return open(...)` — direct pass-through of the handle

            assigned_name = None
            if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
                assigned_name = parent.targets[0].id
            elif isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
                assigned_name = parent.target.id

            if assigned_name is not None and (
                assigned_name in with_bound_names
                or assigned_name in closed_in_handler_names
                or assigned_name in returned_names
            ):
                continue

            self.observations.append({
                "tag": "NAI-075",
                "line": node.lineno,
                "operation": "open",
                "has_context_manager": False,
            })
            _log.debug("NAI-075 observed: unguarded open() at line %d", node.lineno)
            return

    # ------------------------------------------------------------------
    # NAI-076 to NAI-079: Extended safety checks
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_guard_names(test_node) -> set:
        """Extract variable names from an if-test that act as zero/empty guards."""
        names: set[str] = set()
        if isinstance(test_node, ast.Name):
            names.add(test_node.id)
        elif isinstance(test_node, ast.Compare):
            if isinstance(test_node.left, ast.Name):
                names.add(test_node.left.id)
        elif isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not):
            # if not x:  →  guard on x
            if isinstance(test_node.operand, ast.Name):
                names.add(test_node.operand.id)
        elif isinstance(test_node, ast.BoolOp):
            # if a or b < 1:  →  recurse into each value
            for value in test_node.values:
                names.update(SafetyChecksMixin._collect_guard_names(value))
        # Recognize math.isclose(x, 0) as guard on x
        elif isinstance(test_node, ast.Call):
            if isinstance(test_node.func, ast.Attribute):
                if test_node.func.attr == 'isclose' and test_node.args:
                    if isinstance(test_node.args[0], ast.Name):
                        names.add(test_node.args[0].id)
            elif isinstance(test_node.func, ast.Name):
                if test_node.func.id == 'isclose' and test_node.args:
                    if isinstance(test_node.args[0], ast.Name):
                        names.add(test_node.args[0].id)
        return names

    def _numeric_expr(self, e: ast.AST) -> bool:
        """IG-11 (2026-09-06): the left operand of `%` is a NUMBER by a visible fact — a numeric literal, arithmetic, len() /
        int() / float() / abs() / round(), a range() / enumerate() loop variable, or a name last bound to one of those here."""
        if isinstance(e, ast.Constant):
            return isinstance(e.value, (int, float, complex)) and not isinstance(e.value, bool)
        if isinstance(e, ast.BinOp):
            return isinstance(e.op, (ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Pow, ast.Mod)) or (isinstance(e.op, ast.Add) and self._numeric_expr(e.left))
        if isinstance(e, ast.UnaryOp):
            return self._numeric_expr(e.operand)
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Name):
            return e.func.id in ('len', 'int', 'float', 'abs', 'round', 'sum', 'min', 'max', 'ord', 'hash', 'pow', 'divmod')
        if isinstance(e, ast.Name):
            last = None
            for n in self._own_scope(self.func):
                if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == e.id and isinstance(n.iter, ast.Call) \
                        and isinstance(n.iter.func, ast.Name) and n.iter.func.id in ('range', 'enumerate'):
                    return True
                if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == e.id and isinstance(n.op, (ast.Sub, ast.Mult, ast.Div, ast.FloorDiv)):
                    return True
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == e.id for t in n.targets) and (last is None or n.lineno > last.lineno):
                    last = n
            return last is not None and self._numeric_expr(last.value)
        return False

    def _check_division_by_variable(self) -> None:
        """
        NAI-076: Detect division by a variable that could be zero.

        Pattern: x / y where y is a Name (not a nonzero constant) and
        the division is not inside an IfExp guard or preceded by a
        zero-check.
        """
        m = self.metrics

        # Collect all variable names that appear in if-guards
        guarded_names: set[str] = set()
        # Also collect variables assigned safe nonzero values inside guards
        safe_assigned: set[str] = set()
        # FACT E: identity set of BOTH nodes (outer Div/FloorDiv AND its inner Mod
        # operand) belonging to a `(expr % N) / N` mod-normalize idiom — ast.walk
        # visits the inner Mod as its own independent divisor-by-name check, so
        # exempting only the outer node would leave the inner one firing on N.
        mod_normalize_exempt: set[int] = set()

        for node in ast.walk(self.func):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv)) \
                    and isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.Mod) \
                    and isinstance(node.left.right, ast.Name) and isinstance(node.right, ast.Name) \
                    and node.left.right.id == node.right.id:
                mod_normalize_exempt.add(id(node))
                mod_normalize_exempt.add(id(node.left))
            if isinstance(node, ast.If):
                guarded_names.update(self._collect_guard_names(node.test))
                # FACT C: an `if <test>: raise ...` is a raise-guard — every name
                # appearing anywhere in the test (however nested, e.g. inside a
                # call like `np.any(scl == 0.0)`) is ruled safe past this point,
                # not just the narrow shapes _collect_guard_names recognizes.
                if any(isinstance(s, ast.Raise) for s in node.body):
                    for sub in ast.walk(node.test):
                        if isinstance(sub, ast.Name):
                            guarded_names.add(sub.id)
                # Check if body assigns a safe (nonzero) value to a variable
                # Pattern: if span == 0: width = 1.0
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                if isinstance(stmt.value, ast.Constant):
                                    if stmt.value.value not in (0, 0.0, None):
                                        safe_assigned.add(target.id)
            elif isinstance(node, ast.IfExp):
                guarded_names.update(self._collect_guard_names(node.test))
            elif isinstance(node, ast.For):
                # FACT A: a for-loop target bound by iterating a literal Tuple/List
                # of nonzero numeric constants can never be zero within this loop.
                if isinstance(node.target, ast.Name) and isinstance(node.iter, (ast.Tuple, ast.List)):
                    elts = node.iter.elts
                    if elts and all(
                        isinstance(e, ast.Constant) and isinstance(e.value, (int, float)) and not isinstance(e.value, bool) and e.value != 0
                        for e in elts
                    ):
                        safe_assigned.add(node.target.id)

        # Combine: either directly guarded or assigned safe value in guard branch
        all_safe = guarded_names | safe_assigned

        for node in ast.walk(self.func):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                # FACT E: `(expr % N) / N` — a mod-normalize idiom. If N were 0 the
                # modulo would already fail identically, so neither the modulo nor
                # the division here is the first place a zero divisor bites. Both
                # nodes of the idiom were pre-identified above (ast.walk visits the
                # inner Mod as its own independent check, not just the outer Div).
                if id(node) in mod_normalize_exempt:
                    continue
                if isinstance(node.op, ast.Mod) and not self._numeric_expr(node.left):
                    continue   # IG-11: `"…" % x` / `template % ctx` is formatting — `%` is division only on a number by a visible fact
                divisor = node.right
                if isinstance(divisor, ast.Name):
                    # FACT F: self-division (`x / x`) — the divisor cannot represent
                    # an unguarded *second* quantity when it is the same name as the
                    # dividend; it either both-are-zero (defined, e.g. 0/0 handled
                    # upstream) or both are nonzero. Not the counterfeit shape.
                    if isinstance(node.left, ast.Name) and node.left.id == divisor.id:
                        continue
                if isinstance(divisor, ast.Constant):
                    if divisor.value == 0 or divisor.value == 0.0:
                        self.observations.append({
                            "tag": "NAI-076",
                            "line": node.lineno,
                            "divisor_type": "literal_zero",
                            "divisor_value": 0,
                        })
                        _log.debug("NAI-076 observed: division by literal zero at line %d", node.lineno)
                        return
                    continue
                if isinstance(divisor, ast.Name) and divisor.id not in all_safe:
                    # FACT B: the division is lexically inside a `for _ in
                    # range(..., name, ...)` loop (or comprehension generator)
                    # whose range() call bounds on the divisor's own name — if
                    # name == 0 that range is empty and this division never runs.
                    if self._range_bound_encloses(node, divisor.id):
                        continue
                    self.observations.append({
                        "tag": "NAI-076",
                        "line": node.lineno,
                        "divisor_type": "variable",
                        "divisor_name": divisor.id,
                        "has_guard": False,
                    })
                    _log.debug("NAI-076 observed: division by unguarded variable '%s' at line %d", divisor.id, node.lineno)
                    return
                if isinstance(divisor, ast.Call):
                    # Division by len(x) — risky if collection can be empty
                    if isinstance(divisor.func, ast.Name) and divisor.func.id == 'len':
                        if divisor.args and isinstance(divisor.args[0], ast.Name):
                            coll_name = divisor.args[0].id
                            if coll_name not in all_safe:
                                self.observations.append({
                                    "tag": "NAI-076",
                                    "line": node.lineno,
                                    "divisor_type": "len_call",
                                    "collection_name": coll_name,
                                    "has_guard": False,
                                })
                                _log.debug("NAI-076 observed: division by len(%s) at line %d", coll_name, node.lineno)
                                return

    def _range_bound_encloses(self, div_node: ast.AST, name: str) -> bool:
        """FACT B helper: is div_node lexically inside a for-loop (or comprehension
        generator) of the form `for _ in range(..., name, ...)` — i.e. a loop whose
        iteration count is bounded by `name`, so `name == 0` makes the loop body
        (and thus div_node) unreachable? Identity-based containment via ast.walk."""
        def _is_range_call_on_name(it: ast.AST) -> bool:
            return isinstance(it, ast.Call) and (
                (isinstance(it.func, ast.Name) and it.func.id == 'range')
            ) and any(isinstance(a, ast.Name) and a.id == name for a in it.args)

        for container in ast.walk(self.func):
            if isinstance(container, (ast.For, ast.AsyncFor)):
                if _is_range_call_on_name(container.iter):
                    if any(inner is div_node for inner in ast.walk(container)):
                        return True
            elif isinstance(container, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for gen in container.generators:
                    if _is_range_call_on_name(gen.iter):
                        if any(inner is div_node for inner in ast.walk(container)):
                            return True
        return False

    def _check_unguarded_dict_access(self) -> None:
        """
        NAI-077: Detect direct dict subscript access without .get() or 'in' check.

        Pattern: d['key'] where d is a loop variable or parameter,
        and that specific key is not checked via 'if key in d' or d.get(key).
        Key-aware: using .get() on one key doesn't make raw [] on another safe.
        """
        m = self.metrics
        param_names = {arg.arg for arg in self.func.args.args}

        # Collect (variable, key) pairs that are safely accessed
        safe_keys: set[tuple[str, str]] = set()
        for node in ast.walk(self.func):
            # d.get('key') patterns — marks (d, key) as safe
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
                    if isinstance(node.func.value, ast.Name) and node.args:
                        if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            safe_keys.add((node.func.value.id, node.args[0].value))
            # 'if key in d' patterns
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, ast.In) and isinstance(comparator, ast.Name):
                        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                            safe_keys.add((comparator.id, node.left.value))

        # Collect loop targets and params as risky dict sources
        risky_targets: set[str] = set(param_names)
        for node in ast.walk(self.func):
            if isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    risky_targets.add(node.target.id)
                elif isinstance(node.target, ast.Tuple):
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            risky_targets.add(elt.id)

        if not risky_targets:
            self.observations.append({"tag": 'NAI-077', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not risky_targets'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # Intent of this rule is its own docstring: KEY-AWARE — "using .get() on
        # one key doesn't make raw [] on another safe". The evidence is therefore
        # an INCONSISTENCY on the same dict: some keys guarded, this one not. A
        # function that guards nothing on a dict has stated an input contract
        # (rows have "name"); that is honest code, not counterfeit code (measured false
        # hit on an honest list-append loop, runs 1-4, 2026-09-05).
        guarded_vars = {var for var, _key in safe_keys}
        if not guarded_vars:
            self.observations.append({"tag": 'NAI-077', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not guarded_vars'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # Collect subscripts that are assignment targets (dict writes, not reads)
        write_targets: set[int] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        write_targets.add(id(target))
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Subscript):
                    write_targets.add(id(node.target))

        for node in ast.walk(self.func):
            if isinstance(node, ast.Subscript):
                # Skip dict writes — assigning to d['key'] never raises KeyError
                if id(node) in write_targets:
                    continue
                if isinstance(node.value, ast.Name) and node.value.id in risky_targets \
                        and node.value.id in guarded_vars:
                    if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                        key = node.slice.value
                        var = node.value.id
                        if (var, key) not in safe_keys:
                            self.observations.append({
                                "tag": "NAI-077",
                                "line": node.lineno,
                                "dict_name": var,
                                "key": key,
                                "has_get_or_in_check": False,
                            })
                            _log.debug("NAI-077 observed: unguarded dict access %s[%r] at line %d", var, key, node.lineno)
                            return

    def _check_silent_error_swallowing(self) -> None:
        """
        NAI-078: Detect except blocks that silently return a fallback value.

        Pattern: except: return <constant>  (no logging, no re-raise)
        This hides root-cause errors behind dummy data.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.ExceptHandler):
                body = node.body
                if not body:
                    self.observations.append({"tag": 'NAI-078', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not body'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
                    continue
                # Check: does body consist of only a return with a constant/collection?
                # Wave 3 (owner 2026-10-08, frontier list #4): log lines before the return do not handle the error —
                # `logger.warning(e); return {"status": "SUCCESS"}` is the same fake success with a note attached.
                *pre, last = body
                logged = bool(pre) and all(isinstance(st, ast.Expr) and isinstance(st.value, ast.Call)
                                           and (getattr(st.value.func, "attr", "") in _LOG_METHODS
                                                or getattr(st.value.func, "id", "") == "print") for st in pre)
                if logged and isinstance(last, ast.Return) and isinstance(last.value, (ast.Constant, ast.List, ast.Dict,
                                                                                         ast.Tuple, ast.Set)) \
                        and not (isinstance(last.value, ast.Constant) and last.value.value is None):
                    self.observations.append({
                        "tag": "NAI-078",
                        "line": node.lineno,
                        "swallow_type": "logged_fallback_return",
                        "return_type": type(last.value).__name__,
                    })
                    return
                if len(body) == 1 and isinstance(body[0], ast.Return):
                    ret = body[0].value
                    if ret is None:
                        continue  # return None is fine
                    if isinstance(ret, (ast.Constant, ast.List, ast.Dict, ast.Tuple, ast.Set)):
                        self.observations.append({
                            "tag": "NAI-078",
                            "line": node.lineno,
                            "swallow_type": "fallback_return",
                            "return_type": type(ret).__name__,
                        })
                        _log.debug("NAI-078 observed: silent fallback return at line %d", node.lineno)
                        return
                # Also catch: except: pass (silent suppression)
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    # NAI-017 may already catch this, but flag as safety issue too
                    self.observations.append({
                        "tag": "NAI-078",
                        "line": node.lineno,
                        "swallow_type": "bare_pass",
                    })
                    _log.debug("NAI-078 observed: bare pass in except at line %d", node.lineno)
                    return

    def _check_hardcoded_paths(self) -> None:
        """
        NAI-079: Detect hard-coded file/directory path literals.

        Pattern: string constants containing path separators used in
        file operations (os.path.join, open, Path, etc.)
        """
        m = self.metrics

        # Plan item 4 (2026-09-05): before, a relative path was only seen inside
        # os.path.* helpers and an absolute one only inside open() — so
        # open("../config/settings.ini") PASSed. Now any path-taking call
        # (os.path helpers, file operations, open / Path constructors) with a
        # string literal that is absolute (/…, ~…, C:\…) or climbs (`..`) is the
        # observation. A plain relative segment ("data/x.csv") is not.
        path_funcs = {'join', 'abspath', 'dirname', 'exists', 'isfile', 'isdir',
                      'expanduser', 'realpath', 'relpath',
                      'listdir', 'makedirs', 'mkdir', 'remove', 'unlink', 'rename', 'chdir',
                      'read_text', 'write_text', 'read_bytes', 'write_bytes', 'glob', 'rglob'}
        path_ctors = {'open', 'Path', 'PurePath', 'PosixPath', 'WindowsPath'}

        def _path_kind(val: str):
            if '/' not in val and '\\' not in val:
                return None
            if val.startswith(('/', '~')) or (len(val) > 2 and val[1] == ':' and val[2] in '\\/'):
                return 'absolute'
            if '..' in val.replace('\\', '/').split('/'):
                return 'relative'
            return None

        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                fname = func.attr
            elif isinstance(func, ast.Name):
                fname = func.id
            else:
                continue
            if fname not in path_funcs and fname not in path_ctors:
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    kind = _path_kind(arg.value)
                    if kind:
                        self.observations.append({
                            "tag": "NAI-079",
                            "line": arg.lineno,
                            "path_type": kind,
                            "path_value": arg.value,
                            "path_func": fname,
                        })
                        _log.debug("NAI-079 observed: hard-coded %s path at line %d", kind, arg.lineno)
                        return

    # ------------------------------------------------------------------
    # NAI-091 to NAI-096: Extended safety (repurposed from Dark Arts range)
    # ------------------------------------------------------------------

    def _check_inplace_param_mutation(self) -> None:
        """
        NAI-091: Detect in-place mutation of function parameters.

        Patterns detected:
        - param[key] = val  (direct subscript on param)
        - param.append(...)  (mutating method on param)
        - param += [...]  (augmented assignment on param)
        - for item in param: item[key] = val  (mutation via loop iterator)
        Mutating caller's data is a side-effect that violates caller expectations.
        """
        m = self.metrics
        param_names = {arg.arg for arg in self.func.args.args}
        if 'self' in param_names:
            param_names.discard('self')
        if 'cls' in param_names:
            param_names.discard('cls')
        if not param_names:
            self.observations.append({"tag": 'NAI-091', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not param_names'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        mutating_attrs = {'append', 'extend', 'insert', 'pop', 'remove',
                          'clear', 'update', 'add', 'discard'}

        # Track loop variables that iterate over parameters:
        # "for show in data" where data is a param → show is a param-derived var
        param_iterators: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.For):
                if isinstance(node.iter, ast.Name) and node.iter.id in param_names:
                    if isinstance(node.target, ast.Name):
                        param_iterators.add(node.target.id)
                    elif isinstance(node.target, ast.Tuple):
                        for elt in node.target.elts:
                            if isinstance(elt, ast.Name):
                                param_iterators.add(elt.id)

        # All names whose mutation means param mutation
        mutable_names = param_names | param_iterators
        # IG-11 (2026-09-06): a parameter REBOUND in this function (`abis = list(abis)`, `methods = set(methods)`) is a local
        # from that line on — mutating the local is not mutating the caller's object.
        rebound_at: dict[str, int] = {}
        for _n in self._own_scope(self.func):
            if isinstance(_n, ast.Assign):
                for _t in _n.targets:
                    if isinstance(_t, ast.Name) and _t.id in param_names:
                        rebound_at[_t.id] = min(rebound_at.get(_t.id, _n.lineno), _n.lineno)
            # NAI-091 body-shape fact (2026-09-06, slice-3 honest band): a `for` loop target that
            # reuses a parameter's name, iterating over something OTHER than that parameter, shadows
            # it with a fresh local for the rest of the loop — the same rebind as IG-11's `=`, just
            # via a loop target (requests/cookies.py remove_cookie_by_name: `for domain, path, name
            # in clearables:` shadows the domain/path/name PARAMETERS before `cookiejar.clear(domain,
            # path, name)` — that call mutates cookiejar with the loop's local triples, not the
            # caller's original domain/path/name).
            if isinstance(_n, ast.For) and not (isinstance(_n.iter, ast.Name) and _n.iter.id in param_names):
                _for_targets = _n.target.elts if isinstance(_n.target, ast.Tuple) else [_n.target]
                for _t in _for_targets:
                    if isinstance(_t, ast.Name) and _t.id in param_names:
                        rebound_at[_t.id] = min(rebound_at.get(_t.id, _n.lineno), _n.lineno)
        def _is_local_now(name: str, line: int) -> bool:
            return name in rebound_at and rebound_at[name] < line

        # NAI-091 body-shape fact (2026-09-06, slice-3 honest band): the plant hands the caller's
        # OTHER argument straight through unmodified — `table[key] = value`, `items.append(value)` —
        # the subscript key (or a mutating call's argument) is itself a bare, unrebound parameter
        # name. Every labeled-honest row instead computes what to store: a literal/local key
        # (`ctx_args["resilient_parsing"]`, `memo[dir_real]`), a call result
        # (`context.update(self.ensure_sync(func)())`), or a no-argument drain (`c.pop()`,
        # `events.pop(0)`). That is real logic deciding the key/content, not blind passthrough of
        # caller data — the family's actual target.
        def _bare_unrebound_param(node: ast.AST, line: int) -> bool:
            return isinstance(node, ast.Name) and node.id in param_names and not _is_local_now(node.id, line)

        # Algorithm work-variable names where mutation-by-parameter is conventional
        _ALGO_WORK_PARAMS = frozenset({
            'visited', 'seen', 'cache', 'memo', 'memoize', 'dp', 'table',
            'parent', 'parents', 'dist', 'distances', 'colors', 'color',
            'rec_stack', 'stack', 'queue', 'open_set', 'closed_set',
            'in_degree', 'out_degree', 'result', 'results', 'output',
            'acc', 'accumulator', 'counts', 'freq', 'frequency',
            'state', 'env', 'context', 'config',
        })

        for node in ast.walk(self.func):
            # param[key] = value  OR  loop_var[key] = value (subscript assignment)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if isinstance(target.value, ast.Name) and target.value.id in mutable_names:
                            src = target.value.id
                            if _is_local_now(src, node.lineno):
                                continue
                            # Skip algorithm work-variables (visited, cache, etc.)
                            if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `src in _ALGO_WORK_PARAMS` removed
                                continue
                            if not _bare_unrebound_param(target.slice, node.lineno):
                                continue
                            via = " (via loop iterator)" if src in param_iterators else ""
                            param = src if src in param_names else next(
                                (p for p in param_names
                                 for n2 in ast.walk(self.func)
                                 if isinstance(n2, ast.For)
                                 and isinstance(n2.iter, ast.Name) and n2.iter.id == p
                                 and isinstance(n2.target, ast.Name) and n2.target.id == src),
                                src)
                            self.observations.append({
                                "tag": "NAI-091",
                                "line": node.lineno,
                                "param_name": param,
                                "mutation_type": "subscript_assignment",
                                "via_iterator": src in param_iterators,
                            })
                            _log.debug("NAI-091 observed: subscript mutation of param '%s' at line %d", param, node.lineno)
                            return

            # param += [...] (augmented assignment — in-place list/dict extend)
            # Only flag when RHS is a collection literal/constructor (list, set, dict),
            # not arithmetic like `index += index & -index` (int rebind, not mutation)
            if isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and node.target.id in param_names and not _is_local_now(node.target.id, node.lineno):
                    if isinstance(node.op, (ast.Add, ast.BitOr)):
                        rhs = node.value
                        rhs_is_collection = isinstance(rhs, (ast.List, ast.Set, ast.Dict, ast.Tuple))
                        if not rhs_is_collection and isinstance(rhs, ast.Call):
                            if isinstance(rhs.func, ast.Name):
                                rhs_is_collection = rhs.func.id in ('list', 'set', 'dict', 'frozenset')
                        if rhs_is_collection:
                            self.observations.append({
                                "tag": "NAI-091",
                                "line": node.lineno,
                                "param_name": node.target.id,
                                "mutation_type": "augmented_assignment",
                                "via_iterator": False,
                            })
                            _log.debug("NAI-091 observed: augmented assignment on param '%s' at line %d", node.target.id, node.lineno)
                            return

            # param.append(...) / param.update(...) etc.
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in mutating_attrs:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id in mutable_names:
                            src = node.func.value.id
                            if _is_local_now(src, node.lineno):
                                continue
                            _call_args = list(node.args) + [kw.value for kw in node.keywords]
                            if not any(_bare_unrebound_param(a, node.lineno) for a in _call_args):
                                continue
                            param = src if src in param_names else next(
                                (p for p in param_names
                                 for n2 in ast.walk(self.func)
                                 if isinstance(n2, ast.For)
                                 and isinstance(n2.iter, ast.Name) and n2.iter.id == p
                                 and isinstance(n2.target, ast.Name) and n2.target.id == src),
                                src)
                            self.observations.append({
                                "tag": "NAI-091",
                                "line": node.lineno,
                                "param_name": param,
                                "mutation_type": "method_call",
                                "method_name": node.func.attr,
                                "via_iterator": src in param_iterators,
                            })
                            _log.debug("NAI-091 observed: .%s() mutation on param '%s' at line %d", node.func.attr, param, node.lineno)
                            return

    def _check_unsafe_subprocess(self) -> None:
        """
        NAI-092: Detect subprocess calls with shell=True or os.system().

        Pattern: subprocess.call(..., shell=True), os.system(...)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                func = node.func
                # os.system(...)
                if isinstance(func, ast.Attribute):
                    if func.attr == 'system':
                        if isinstance(func.value, ast.Name) and func.value.id == 'os':
                            self.observations.append({
                                "tag": "NAI-092",
                                "line": node.lineno,
                                "call_type": "os_system",
                            })
                            _log.debug("NAI-092 observed: os.system() at line %d", node.lineno)
                            return

                    # subprocess.call/run/Popen(..., shell=True)
                    if func.attr in ('call', 'run', 'Popen', 'check_call', 'check_output'):
                        if isinstance(func.value, ast.Name) and func.value.id == 'subprocess':
                            for kw in node.keywords:
                                if kw.arg == 'shell':
                                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                        self.observations.append({
                                            "tag": "NAI-092",
                                            "line": node.lineno,
                                            "call_type": "subprocess_shell_true",
                                            "subprocess_method": func.attr,
                                        })
                                        _log.debug("NAI-092 observed: subprocess.%s(shell=True) at line %d", func.attr, node.lineno)
                                        return

    def _check_unsafe_deserialization(self) -> None:
        """
        NAI-093: Detect unsafe deserialization (pickle, yaml.load without SafeLoader).

        Pattern: pickle.load/loads(), yaml.load() without Loader=SafeLoader
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # pickle.load / pickle.loads
                if node.func.attr in ('load', 'loads'):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
                        self.observations.append({
                            "tag": "NAI-093",
                            "line": node.lineno,
                            "module": "pickle",
                            "method": node.func.attr,
                        })
                        _log.debug("NAI-093 observed: pickle.%s() at line %d", node.func.attr, node.lineno)
                        return

                # yaml.load() without Loader kwarg
                if node.func.attr == 'load':
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'yaml':
                        has_loader = any(
                            kw.arg == 'Loader' for kw in node.keywords
                        )
                        if not has_loader:
                            self.observations.append({
                                "tag": "NAI-093",
                                "line": node.lineno,
                                "module": "yaml",
                                "method": "load",
                                "has_loader_kwarg": False,
                            })
                            _log.debug("NAI-093 observed: yaml.load() without Loader at line %d", node.lineno)
                            return

    def _check_sys_path_manipulation(self) -> None:
        """
        NAI-094: Detect runtime sys.path manipulation and os.environ mutation.

        Patterns (the WRITE, in either family):
        - sys.path.insert(...) / .append(...) / .extend(...)
        - sys.path += [...]  |  sys.path[...] = ...
        - os.environ["KEY"] = "value"  |  os.environ["KEY"] += "value"
        - os.environ.update(...) / os.environ.setdefault(...)
        Fragile import resolution and environment side effects.

        CLEAN, and therefore what the prescription is locked to (R4, owner 2026-09-21):
        every NON-MUTATING shape of the same object — `os.environ.get(k)` / `os.environ.get(k, d)`
        / `os.getenv(k[, d])` (the same callable: `os.getenv` IS `environ.get`) / `k in os.environ`
        / a subscript READ `os.environ[k]` / `list(sys.path)`. The rule measures the write and
        nothing else, so the read shapes are not rivals — they are one verdict, `no write`.

        R4 / run 164: this half and the MODULE-scope half (`noai_validator.validator.
        validate_module`) are now the same predicate. Before run 164 this half knew only
        `insert` / `append` and the environ subscript assignment, so `sys.path.extend(...)`,
        `sys.path += [...]` and `sys.path[...] = ...` were a FIRE at module scope and CLEAN
        inside a function body — one rule id, two verdicts on the same statement, and an
        escape hatch a "repair" could take by moving the line into a function. `os.environ[k]
        += v` was the same hatch in one scope: the same `__setitem__` as `os.environ[k] = v`,
        which fires, spelled with two more characters. `nai094_entry_proof` part 6 holds the
        two halves to the same table.

        T2b / run 164 follow-up (owner's ruling (b), 2026-09-21): a save/restore PAIR RECOGNIZER,
        per-function half only. `CliRunner.isolation` (`src/click/testing.py::399`) saves
        `os.environ` per key into `old_env` before its `try`-body write, and its own `finally`
        restores from `old_env` — two halves of one lifecycle, not an import-time side effect.
        An os.environ write inside a `try` whose `finally` restores os.environ from a name bound
        from an os.environ read is CLEAN, both legs; a write with no such restore, or a `finally`
        that writes a different/unsaved key, still fires exactly as before. See
        `_environ_pair_exempt_lines` above.
        """
        m = self.metrics
        environ_exempt = _environ_pair_exempt_lines(self.func)

        def _emit(node: ast.AST, target: str, method: str) -> None:
            self.observations.append({
                "tag": "NAI-094",
                "line": getattr(node, "lineno", 0),
                "manipulation_target": target,
                "method": method,
            })
            _log.debug("NAI-094 observed: %s %s at line %d", target, method,
                       getattr(node, "lineno", 0))

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in ('insert', 'append', 'extend'):
                    if _is_sys_path(func.value):
                        _emit(node, "sys.path", func.attr)
                        return
                # os.environ.update(...) / os.environ.setdefault(...)
                if isinstance(func, ast.Attribute) and func.attr in ('setdefault', 'update'):
                    if _is_os_environ(func.value):
                        if getattr(node, "lineno", 0) not in environ_exempt:
                            _emit(node, "os.environ", func.attr)
                            return

            # sys.path += [...]  |  os.environ["KEY"] += "value"
            if isinstance(node, ast.AugAssign):
                if _is_sys_path(node.target):
                    _emit(node, "sys.path", "augmented_assignment")
                    return
                if isinstance(node.target, ast.Subscript) and _is_os_environ(node.target.value):
                    if getattr(node, "lineno", 0) not in environ_exempt:
                        _emit(node, "os.environ", "subscript_augmented_assignment")
                        return

            # sys.path[...] = [...]  |  os.environ["KEY"] = "value"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if _is_sys_path(target.value):
                            _emit(node, "sys.path", "subscript_assignment")
                            return
                        if _is_os_environ(target.value):
                            if getattr(node, "lineno", 0) not in environ_exempt:
                                _emit(node, "os.environ", "subscript_assignment")
                                return

    def _check_float_equality(self) -> None:
        """
        NAI-095: Detect equality comparison on floats.

        Pattern: float_var == float_var or x == 0.1
        Floating point equality is unreliable due to representation errors.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        left = node.left
                        right = comparator
                        # At least one side is a float literal
                        left_float = isinstance(left, ast.Constant) and isinstance(left.value, float)
                        right_float = isinstance(right, ast.Constant) and isinstance(right.value, float)
                        if left_float or right_float:
                            self.observations.append({
                                "tag": "NAI-095",
                                "line": node.lineno,
                                "comparison_op": type(op).__name__,
                                "left_is_float": left_float,
                                "right_is_float": right_float,
                            })
                            _log.debug("NAI-095 observed: float equality comparison at line %d", node.lineno)
                            return

    def _check_assert_for_validation(self) -> None:
        """
        NAI-096: Detect assert used for runtime input validation.

        Pattern: assert <param_check> where param is a function argument.
        Asserts are stripped with python -O, so they must not be used
        for validation that should always run.
        """
        m = self.metrics
        # Hardened 2026-09-05 (F-096): `self`/`cls` are the receiver, not an
        # input to validate — the measured false hit was `param_name=self`
        # (click ×58). A verification function's asserts are its purpose.
        param_names = {arg.arg for arg in self.func.args.args} - {'self', 'cls'}
        if not param_names or m.name.startswith('test_'):  # RESTORED cut 3 batch 4 (2026-09-06): the `test_` prefix is the RUNNER's collection convention (pytest collects by it) — a fact about how the function is executed, not the author's claim; removing it produced 280 false verdicts on two honest repos
            return

        # Body-shape hardening 2026-09-06 (F-096b): an internal precondition/sanity
        # assert reads as an unconditional statement placed BEFORE any real work —
        # the first executable statement of the function (after a leading docstring),
        # not nested inside any if/try/for/with. A guard clause of that shape also
        # checks exactly one relationship on exactly one parameter; an assert buried
        # inside conditional logic, or reached only after other statements already
        # ran, is a mid-body sanity check on an established invariant, not input
        # validation standing in for a real check at the boundary.
        body = self.func.body
        first_idx = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            first_idx = 1
        if first_idx >= len(body) or not isinstance(body[first_idx], ast.Assert):
            return
        node = body[first_idx]
        hit_names = {name_node.id for name_node in ast.walk(node.test)  # type: ignore[attr-defined]  # FIX_54 ast-pos
                     if isinstance(name_node, ast.Name) and name_node.id in param_names}
        if len(hit_names) != 1:
            return
        param_name = next(iter(hit_names))
        self.observations.append({
            "tag": "NAI-096",
            "line": node.lineno,
            "param_name": param_name,
        })
        _log.debug("NAI-096 observed: assert validates param '%s' at line %d", param_name, node.lineno)

    def _check_unguarded_external_calls(self) -> None:
        """
        NAI-097: Detect function calling multiple external/imported names with
        no try-except anywhere in the body.

        Pattern: function calls 2+ names that aren't locally defined, with no
        error handling. Errors from downstream will bubble up unhandled.
        """
        m = self.metrics

        # If function already has try/except, it has some error handling
        for node in ast.walk(self.func):
            if isinstance(node, ast.Try):
                return  # has error handling, skip

        # Collect names defined locally in this function
        local_names: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        local_names.add(target.id)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node is not self.func:
                    local_names.add(node.name)
            if isinstance(node, ast.ClassDef):
                local_names.add(node.name)

        # Collect external function calls (names not defined locally, not builtins)
        builtins = {'print', 'len', 'range', 'int', 'str', 'float', 'list', 'dict',
                    'set', 'tuple', 'type', 'isinstance', 'hasattr', 'getattr',
                    'setattr', 'enumerate', 'zip', 'map', 'filter', 'sorted',
                    'reversed', 'any', 'all', 'min', 'max', 'sum', 'abs', 'round',
                    'open', 'super', 'repr', 'bool', 'bytes', 'id', 'input',
                    'iter', 'next', 'hash', 'hex', 'oct', 'bin', 'chr', 'ord',
                    'format', 'vars', 'dir', 'help', 'callable',
                    'object', 'property', 'staticmethod', 'classmethod',
                    'frozenset', 'complex', 'memoryview', 'bytearray', 'slice',
                    'Exception', 'ValueError', 'TypeError', 'KeyError',
                    'IndexError', 'AttributeError', 'RuntimeError',
                    'NotImplementedError', 'StopIteration', 'FileNotFoundError',
                    'IOError', 'OSError', 'ZeroDivisionError', 'OverflowError',
                    'breakpoint', 'globals', 'locals', 'exec', 'eval',
                    'compile', 'delattr', 'issubclass', 'pow', 'divmod', 'ascii'}

        # Also safe: module-level names (classes/functions in same file) and imports
        known_names = local_names | builtins | self.module_level_names | set(self.imported_names.keys())

        external_calls: list[str] = []
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                    if name not in known_names:
                        external_calls.append(name)

        if len(external_calls) >= 1:  # EXCISED cut 2 (2026-09-05): was `len(external_calls) >= 2` — EXCISION_LIST class A
            self.observations.append({
                "tag": "NAI-097",
                "line": self.func.lineno,
                "external_calls": external_calls,
                "call_count": len(external_calls),
                "has_try_except": False,
            })
            _log.debug("NAI-097 observed: %d unguarded external calls at line %d", len(external_calls), self.func.lineno)

    def _check_risky_single_call(self) -> None:
        """
        NAI-200: Detect inherently risky single calls without error handling.

        Pattern: function contains a risky operation (file I/O, dynamic import,
        network call, etc.) but has no try/except. These operations can fail
        for reasons outside the code's control.
        
        Unlike NAI-097 (requires 2+ external calls), this flags single calls
        that are inherently dangerous without error handling.
        """
        m = self.metrics

        # If function already has try/except, it has some error handling
        # (Body-shape hardening 2026-09-06 (F-200a): scanned in the function's OWN
        # scope only — a try/except lexically inside a nested def/lambda belongs
        # to that closure's own execution, not this function's; same reasoning as
        # NAI-160's F-160b / NAI-091's precedent.)
        scope_nodes = list(self._own_scope(self.func))
        for node in scope_nodes:
            if isinstance(node, ast.Try):
                return  # has error handling, skip

        param_names = {arg.arg for arg in self.func.args.args} - {'self', 'cls'}

        # Body-shape hardening 2026-09-06 (F-200b): a risky call whose result is
        # never bound to anything and is immediately chained into `.close()` in
        # the same expression (`open(x, mode).close()`) is the documented
        # early-probe idiom (test whether the path can be opened, without keeping
        # or using the handle) — same reasoning as NAI-160's F-160c.
        closed_immediately: set[int] = set()
        for node in scope_nodes:
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'close' and isinstance(node.func.value, ast.Call)):
                closed_immediately.add(id(node.func.value))

        # Body-shape hardening 2026-09-06 (F-200c): a call reached only as a
        # `with` statement's own context-expression already has deterministic
        # cleanup via `__exit__` on every exit path — a structural difference
        # from a bare unguarded call, independent of whether an explicit
        # try/except is also present.
        with_wrapped: set[int] = set()
        with_bound_names: set[str] = set()
        for node in scope_nodes:
            if isinstance(node, ast.With):
                for item in node.items:
                    if isinstance(item.context_expr, ast.Call):
                        with_wrapped.add(id(item.context_expr))
                    if isinstance(item.optional_vars, ast.Name):
                        with_bound_names.add(item.optional_vars.id)

        # Body-shape hardening 2026-09-06 (F-200d): a conditional (`if`) whose
        # test references the same name later passed into the risky call is a
        # validation gate over that value before the call, regardless of the
        # exact predicate (isinstance, isfile, a None-check, ...) — same
        # statement-kind reasoning already applied by NAI-160's if-guard fact
        # and NAI-201's F-201b.
        guarded_names: set[str] = set()
        for node in scope_nodes:
            if isinstance(node, ast.If):
                for n in ast.walk(node.test):
                    if isinstance(n, ast.Name):
                        guarded_names.add(n.id)

        def _sink_arg_ok(node: ast.Call) -> bool:
            # Body-shape hardening 2026-09-06 (F-200e): when the call's own
            # first argument is a bare Name, it must be one of THIS function's
            # own parameters (not a local variable built up by the function's
            # own logic, e.g. `path = os.path.join(...)`) and must not already
            # be covered by an F-200d guard — mirrors the external_names /
            # param_names restriction NAI-160/NAI-201 already apply to sink
            # detection. A non-Name argument (an attribute access, a call
            # result, a literal, ...) is left as before — no row in this
            # family's evidence needs a broader restriction there.
            if not node.args:
                return True
            arg = node.args[0]
            # Body-shape hardening 2026-09-06 (F-200f): an argument built from a
            # with-bound resource name anywhere within the argument expression
            # (e.g. `yaml.safe_load(f.read())` where `f` is a with-item target)
            # is downstream of that with-block's own deterministic cleanup for
            # the SAME resource, not a standalone unguarded call.
            for n in ast.walk(arg):
                if isinstance(n, ast.Name) and n.id in with_bound_names:
                    return False
            if not isinstance(arg, ast.Name):
                return True
            if arg.id not in param_names:
                return False
            return arg.id not in guarded_names

        # High-risk patterns:
        # - open() calls (IOError, FileNotFoundError)
        # - importlib.import_module() (ImportError, ModuleNotFoundError)
        # - json.load/loads() (JSONDecodeError)
        # - socket/network operations
        risky_calls: list[str] = []

        # configparser-specific attribute names (excluding 'get' and 'read' — too common on dicts/lists)
        configparser_attrs = {'getint', 'getfloat', 'getboolean'}

        for node in scope_nodes:
            if not isinstance(node, ast.Call):
                continue
            if id(node) in closed_immediately or id(node) in with_wrapped:
                continue
            # Direct risky builtins
            if isinstance(node.func, ast.Name):
                if node.func.id == 'open':
                    if _sink_arg_ok(node):
                        risky_calls.append('open()')
            # Method calls on known risky modules
            elif isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                # importlib.import_module
                if attr == 'import_module':
                    if _sink_arg_ok(node):
                        risky_calls.append('import_module()')
                # json.load/loads
                elif attr in ('load', 'loads') and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == 'json' and _sink_arg_ok(node):
                        risky_calls.append(f'json.{attr}()')
                # yaml.safe_load/load
                elif attr in ('safe_load', 'load') and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == 'yaml' and _sink_arg_ok(node):
                        risky_calls.append(f'yaml.{attr}()')
                # configparser operations
                elif attr in configparser_attrs and isinstance(node.func.value, ast.Name):
                    risky_calls.append(f'{node.func.value.id}.{attr}()')
                # csv.reader / csv.DictReader
                elif attr in ('reader', 'DictReader') and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == 'csv':
                        risky_calls.append(f'csv.{attr}()')

        if risky_calls:
            self.observations.append({
                "tag": "NAI-200",
                "line": self.func.lineno,
                "risky_calls": list(set(risky_calls)),
                "call_count": len(set(risky_calls)),
                "has_try_except": False,
            })
            _log.debug("NAI-200 observed: %d risky I/O calls without try/except at line %d", len(set(risky_calls)), self.func.lineno)

    def _check_print_only_output(self) -> None:
        """
        NAI-098: Detect functions that use print() as primary output.

        Pattern: function calls print() but has no return statement (or returns None).
        Using print for output instead of returning structured data makes
        the function untestable and uncomposable.
        """
        m = self.metrics

        has_print = False
        has_return_value = False

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'print':
                    has_print = True
            if isinstance(node, ast.Return):
                if node.value is not None:
                    # Has a return with an actual value
                    has_return_value = True

        if has_print and not has_return_value:
            self.observations.append({
                "tag": "NAI-098",
                "line": self.func.lineno,
                "has_print": True,
                "has_return_value": False,
            })
            _log.debug("NAI-098 observed: print-only output at line %d", self.func.lineno)

    def _check_magic_numbers(self) -> None:
        """
        NAI-099: Detect magic numbers in function bodies.

        Pattern: numeric constants (int/float) that are not 0, 1, -1, 2, 100,
        or common values, used in assignments or expressions (including BinOp).
        """
        m = self.metrics
        # Values that are NOT magic (commonly understood)
        # Hardened 2026-09-05 (F-099 / F-099b). Sources: ruff PLR2004
        # magic-value-comparison — "unnamed numerical constants ('magic')
        # values in COMPARISONS", excluding 0, 1, "", "__main__" and
        # sys.version comparisons; pylint R2004 (same scope, extension). A
        # constant in arithmetic (`(f - 32.0) * 5.0 / 9.0`) or a `return 7` is
        # a formula term or a value, not a magic comparison — neither linter
        # flags it and neither does this rule now.
        safe_values = {0, 1, -1, 0.0, 1.0, True, False}  # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): was {0, 1, -1, 2, 10, 100, 0.0, 1.0, 0.5, True, False, 1000, 1024, 60, 24, 365} — 0/1/-1/booleans are the DEFINITION of 'not magic' (ruff PLR2004); 2/10/100/0.5/1000/1024/60/24/365 were chosen; the value is emitted, the ranker decides

        def _is_version_probe(expr: ast.expr) -> bool:
            txt = ast.dump(expr)
            return "'version'" in txt or "'version_info'" in txt

        for node in ast.walk(self.func):
            if not isinstance(node, ast.Compare):
                continue
            if _is_version_probe(node.left) or any(_is_version_probe(c) for c in node.comparators):
                continue
            sides = [node.left, *node.comparators]
            magic = None
            for side in sides:
                if isinstance(side, ast.Constant) and isinstance(side.value, (int, float)) \
                        and not isinstance(side.value, bool) and side.value not in safe_values:
                    magic = side.value
                    break
            if magic is None:
                continue
            other = next((ast.unparse(x) for x in sides if not isinstance(x, ast.Constant)), '')
            # Check for config file duplication
            config_match = None
            artifact_values = getattr(self, 'artifact_values', None)
            if artifact_values:
                val_str = str(magic)
                for (cfg_file, cfg_key), cfg_val in artifact_values.items():
                    if cfg_val.strip() == val_str:
                        config_match = {"file": cfg_file, "key": cfg_key}
                        break
            self.observations.append({
                "tag": "NAI-099",
                "line": node.lineno,
                "magic_value": magic,
                "context": f"{other} compared with {magic}" if other else None,
                "config_match": config_match,
            })
            _log.debug("NAI-099 observed: magic comparison value %s at line %d", magic, node.lineno)
            return

    # ------------------------------------------------------------------
    # NAI-160 to NAI-166: Extended security/safety checks
    # ------------------------------------------------------------------

    def _check_missing_input_validation(self) -> None:
        """
        NAI-160: Detect functions accepting external input with zero sanitization (CWE-20).

        Pattern: Function takes string params and uses them directly in file ops,
        SQL, subprocess, eval, or exec without any validation/sanitization.
        """
        m = self.metrics
        param_names = {arg.arg for arg in self.func.args.args}
        param_names -= {'self', 'cls'}
        if not param_names:
            self.observations.append({"tag": 'NAI-160', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not param_names'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # Body-shape hardening 2026-09-06 (F-160b): restrict sink/validation
        # scanning to the function's OWN scope (IG-7/IG-9 `_own_scope`) — a sink
        # call lexically inside a nested def/lambda body runs only when THAT
        # closure is later invoked by whoever holds it, not each time this
        # function itself runs; attributing it to this function's own body
        # conflates two different scopes' execution (same precedent as NAI-091).
        # Body-shape hardening 2026-09-06 (F-160c): a sink call whose result is
        # never bound to anything and is immediately chained into `.close()` in
        # the same expression (`open(x, mode).close()`) is the documented
        # early-probe idiom — it tests whether the path can be opened without
        # keeping or using the handle — and is excluded from risky_sinks.
        closed_immediately: set[int] = set()
        for node in self._own_scope(self.func):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'close' and isinstance(node.func.value, ast.Call)):
                closed_immediately.add(id(node.func.value))

        # Risky sinks where unvalidated input causes security issues
        risky_sinks: set[str] = set()
        for node in self._own_scope(self.func):
            if isinstance(node, ast.Call):
                if id(node) in closed_immediately:
                    continue
                # Direct calls: open(), eval(), exec(), compile()
                if isinstance(node.func, ast.Name):
                    if node.func.id in ('open', 'eval', 'exec', 'compile'):
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in param_names:
                                risky_sinks.add(arg.id)
                # Method calls: os.system(), subprocess.run(), cursor.execute()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('system', 'popen', 'execute', 'run'):
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in param_names:
                                risky_sinks.add(arg.id)
                    # f-string or .format() with param in SQL-like context
                    if node.func.attr == 'format':
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in param_names:
                                risky_sinks.add(arg.id)

        if not risky_sinks:
            self.observations.append({"tag": 'NAI-160', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not risky_sinks'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # Check if there's any validation (isinstance, if not, regex, strip, etc.)
        # (own scope only, same reasoning as the risky_sinks scan above)
        has_validation = False
        for node in self._own_scope(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ('isinstance', 'validate', 'sanitize', 'escape'):
                        has_validation = True
                        break
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('strip', 'replace', 'match', 'search',
                                           'validate', 'sanitize', 'escape', 'quote'):
                        has_validation = True
                        break
            if isinstance(node, ast.If):
                # Body-shape hardening 2026-09-06 (F-160): a conditional whose test
                # inspects the same name that reaches the sink is a validation gate
                # regardless of its exact comparison shape — `if not X:`, `if not
                # <call>(X):` (e.g. `if not os.path.isfile(name):`), or `if X not in
                # {...}:` (a membership/whitelist guard) are all statement-kind
                # conditionals over the sink's own input, not merely unrelated
                # branching. Broadened from requiring `test` to be exactly
                # `UnaryOp(Not, Name)` to: the test references a risky-sink name
                # anywhere within it.
                if any(isinstance(n, ast.Name) and n.id in risky_sinks for n in ast.walk(node.test)):
                    has_validation = True
                    break
            if isinstance(node, ast.Try):
                # A sink argument used inside a try-guarded block is handled for
                # failure (OSError/TypeError/etc.) at the point of use — a
                # statement-kind wrapper around the sink, not silent passthrough.
                if any(isinstance(n, ast.Name) and n.id in risky_sinks for stmt in node.body for n in ast.walk(stmt)):
                    has_validation = True
                    break

        if not has_validation:
            self.observations.append({
                "tag": "NAI-160",
                "line": self.func.lineno,
                "risky_sinks": list(risky_sinks),
                "has_validation": False,
            })
            _log.debug("NAI-160 observed: missing input validation at line %d", self.func.lineno)

    def _check_http_without_timeout(self) -> None:
        """
        NAI-161: Detect HTTP requests without timeout parameter.

        Pattern: requests.get/post/put/delete/patch/head() without timeout=
        Can hang indefinitely if server doesn't respond.
        """
        m = self.metrics

        http_methods = {'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request'}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in http_methods:
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'requests':
                        has_timeout = any(
                            kw.arg == 'timeout' for kw in node.keywords
                        )
                        if not has_timeout:
                            self.observations.append({
                                "tag": "NAI-161",
                                "line": node.lineno,
                                "http_method": node.func.attr,
                                "has_timeout": False,
                            })
                            _log.debug("NAI-161 observed: requests.%s() without timeout at line %d", node.func.attr, node.lineno)
                            return

    def _check_no_cert_validation(self) -> None:
        """
        NAI-162: Detect verify=False in HTTP requests (disables TLS certificate validation).

        Pattern: requests.get(..., verify=False)
        Allows MITM attacks by accepting any certificate.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'requests':
                    for kw in node.keywords:
                        if kw.arg == 'verify':
                            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                self.observations.append({
                                    "tag": "NAI-162",
                                    "line": node.lineno,
                                    "verify_value": False,
                                })
                                _log.debug("NAI-162 observed: verify=False at line %d", node.lineno)
                                return

    def _check_hardcoded_bind_all(self) -> None:
        """
        NAI-163: Detect hardcoded bind to 0.0.0.0 (all interfaces).

        Pattern: .bind(('0.0.0.0', port)) or host='0.0.0.0'
        Exposes service to all network interfaces, including public.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value == '0.0.0.0':
                    self.observations.append({
                        "tag": "NAI-163",
                        "line": node.lineno,
                        "bind_address": "0.0.0.0",
                    })
                    _log.debug("NAI-163 observed: hardcoded bind to 0.0.0.0 at line %d", node.lineno)
                    return

    def _check_insecure_temp_file(self) -> None:
        """
        NAI-164: Detect insecure temporary file creation.

        Pattern: tempfile.mktemp() is vulnerable to race conditions (TOCTOU).
        Should use tempfile.mkstemp() or tempfile.NamedTemporaryFile().
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == 'mktemp':
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'tempfile':
                        self.observations.append({
                            "tag": "NAI-164",
                            "line": node.lineno,
                            "method": "mktemp",
                        })
                        _log.debug("NAI-164 observed: tempfile.mktemp() at line %d", node.lineno)
                        return

    def _check_trojan_source_bidi(self) -> None:
        """
        NAI-165: Detect Unicode bidirectional control characters (trojan source).

        Bidi override chars can make code appear different from what executes.
        Checks string constants for hidden bidi control characters.
        """
        m = self.metrics

        # Unicode bidi control characters
        bidi_chars = {
            '\u200f',  # RIGHT-TO-LEFT MARK
            '\u200e',  # LEFT-TO-RIGHT MARK
            '\u202a',  # LEFT-TO-RIGHT EMBEDDING
            '\u202b',  # RIGHT-TO-LEFT EMBEDDING
            '\u202c',  # POP DIRECTIONAL FORMATTING
            '\u202d',  # LEFT-TO-RIGHT OVERRIDE
            '\u202e',  # RIGHT-TO-LEFT OVERRIDE
            '\u2066',  # LEFT-TO-RIGHT ISOLATE
            '\u2067',  # RIGHT-TO-LEFT ISOLATE
            '\u2068',  # FIRST STRONG ISOLATE
            '\u2069',  # POP DIRECTIONAL ISOLATE
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for char in bidi_chars:
                    if char in node.value:
                        self.observations.append({
                            "tag": "NAI-165",
                            "line": node.lineno,
                            "bidi_char_codepoint": f"U+{ord(char):04X}",
                        })
                        _log.debug("NAI-165 observed: bidi control character U+%04X at line %d", ord(char), node.lineno)
                        return

    def _check_raise_not_implemented(self) -> None:
        """
        NAI-166: Detect 'raise NotImplemented' (should be NotImplementedError).

        NotImplemented is a singleton for binary ops, not an exception.
        Raising it causes TypeError, not the intended NotImplementedError.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Raise):
                exc = node.exc
                if isinstance(exc, ast.Name) and exc.id == 'NotImplemented':
                    self.observations.append({
                        "tag": "NAI-166",
                        "line": node.lineno,
                        "raised_name": "NotImplemented",
                    })
                    _log.debug("NAI-166 observed: raise NotImplemented at line %d", node.lineno)
                    return

    # ------------------------------------------------------------------
    # NAI-172, NAI-173: Exception ordering and return in finally
    # ------------------------------------------------------------------

    def _check_except_clause_ordering(self) -> None:
        """
        NAI-172: Detect except clauses where parent exception is caught before child.

        Pattern: except Exception: ... except ValueError: ...
        The ValueError handler is unreachable because Exception catches it first.
        """
        m = self.metrics

        exception_hierarchy = {
            'Exception': 0,
            'BaseException': -1,
            'ArithmeticError': 1,
            'LookupError': 1,
            'OSError': 1,
            'ValueError': 2,
            'TypeError': 2,
            'KeyError': 2,
            'IndexError': 2,
            'AttributeError': 2,
            'RuntimeError': 2,
            'IOError': 2,
            'FileNotFoundError': 3,
            'PermissionError': 3,
            'IsADirectoryError': 3,
            'ZeroDivisionError': 3,
            'OverflowError': 3,
            'FloatingPointError': 3,
            'StopIteration': 2,
            'StopAsyncIteration': 2,
            'ImportError': 2,
            'ModuleNotFoundError': 3,
            'UnicodeError': 3,
            'UnicodeDecodeError': 4,
            'UnicodeEncodeError': 4,
            'ConnectionError': 3,
            'TimeoutError': 3,
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Try):
                handler_names: list[str] = []
                for handler in node.handlers:
                    if handler.type is None:
                        handler_names.append('BaseException')
                    elif isinstance(handler.type, ast.Name):
                        handler_names.append(handler.type.id)
                    else:
                        handler_names.append('')

                for i in range(len(handler_names) - 1):
                    parent = handler_names[i]
                    child = handler_names[i + 1]
                    if parent in exception_hierarchy and child in exception_hierarchy:
                        if exception_hierarchy[parent] < exception_hierarchy[child]:
                            self.observations.append({
                                "tag": "NAI-172",
                                "line": node.lineno,
                                "parent_exception": parent,
                                "child_exception": child,
                                "parent_level": exception_hierarchy[parent],
                                "child_level": exception_hierarchy[child],
                            })
                            _log.debug("NAI-172 observed: %s caught before %s at line %d", parent, child, node.lineno)
                            return

    def _check_return_in_finally(self) -> None:
        """
        NAI-173: Detect return statement in finally block.

        A return in finally silently swallows any exception that was being
        propagated, making debugging extremely difficult.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Try) and node.finalbody:
                for child in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])):
                    if isinstance(child, ast.Return):
                        self.observations.append({
                            "tag": "NAI-173",
                            "line": child.lineno,
                            "in_finally": True,
                        })
                        _log.debug("NAI-173 observed: return in finally at line %d", child.lineno)
                        return

    # ------------------------------------------------------------------
    # NAI-152, NAI-158, NAI-159, NAI-167
    # ------------------------------------------------------------------

    def _check_mutable_class_level_variables(self) -> None:
        """
        NAI-152: Mutable class-level variables shared across instances.

        Detects methods that mutate class-level mutable attributes (lists, dicts,
        sets) without first copying them to the instance.  Also detects __init__
        methods that mutate self.xxx without ever assigning it, indicating the
        attribute lives on the class and is shared across all instances.
        """
        m = self.metrics
        if not m.is_method:
            self.observations.append({"tag": 'NAI-152', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not m.is_method'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        mutable_methods = {'append', 'extend', 'update', 'insert', 'add',
                           'remove', 'pop', 'clear', 'setdefault'}

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in mutable_methods:
                    obj = node.func.value
                    if isinstance(obj, ast.Attribute):
                        # self.__class__.items.append(...)
                        if isinstance(obj.value, ast.Attribute):
                            if isinstance(obj.value.value, ast.Name) and obj.value.value.id == 'self':
                                if obj.value.attr == '__class__':
                                    self.observations.append({
                                        "tag": "NAI-152",
                                        "line": node.lineno,
                                        "access_pattern": "self.__class__",
                                        "attribute": obj.attr,
                                        "mutating_method": node.func.attr,
                                    })
                                    _log.debug("NAI-152 observed: self.__class__.%s.%s() at line %d", obj.attr, node.func.attr, node.lineno)
                                    return
                        # type(self).attr.append(...)
                        if isinstance(obj.value, ast.Call):
                            if isinstance(obj.value.func, ast.Name) and obj.value.func.id == 'type':
                                if obj.value.args and isinstance(obj.value.args[0], ast.Name):
                                    if obj.value.args[0].id == 'self':
                                        self.observations.append({
                                            "tag": "NAI-152",
                                            "line": node.lineno,
                                            "access_pattern": "type(self)",
                                            "attribute": obj.attr,
                                            "mutating_method": node.func.attr,
                                        })
                                        _log.debug("NAI-152 observed: type(self).%s.%s() at line %d", obj.attr, node.func.attr, node.lineno)
                                        return

        # In __init__: find self.xxx mutated but never assigned — likely class-level
        if self.func.name == '__init__':
            assigned_attrs: set[str] = set()
            mutated_attrs: set[str] = set()

            for node in ast.walk(self.func):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):   # IG-11: `self.x: T = …` assigns the attribute too
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                        if isinstance(target, ast.Attribute):
                            if isinstance(target.value, ast.Name) and target.value.id == 'self':
                                assigned_attrs.add(target.attr)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in mutable_methods:
                        obj = node.func.value
                        if isinstance(obj, ast.Attribute):
                            if isinstance(obj.value, ast.Name) and obj.value.id == 'self':
                                # Body-shape hardening 2026-09-06 (F-152a): `self.__dict__.update(...)` (etc.) is the
                                # reflective, always-instance-scoped namespace-update idiom (dynamically exporting
                                # attributes onto THIS instance — jinja2 TemplateModule.__init__, numpy
                                # poly1d.__init__) — never a class-level shared attribute, regardless of whether
                                # `__dict__` itself was ever separately assigned (it structurally can't be, the
                                # normal way `assigned_attrs` looks for). Exempt the literal name `__dict__` only;
                                # an ordinary attribute name (the plants' `self.items`/`self.registry`) is unaffected.
                                if obj.attr != '__dict__':
                                    mutated_attrs.add(obj.attr)

            shared_mutated = mutated_attrs - assigned_attrs
            if shared_mutated:
                self.observations.append({
                    "tag": "NAI-152",
                    "line": self.func.lineno,
                    "access_pattern": "__init__",
                    "shared_mutated_attrs": list(shared_mutated),
                })
                _log.debug("NAI-152 observed: shared mutated attrs in __init__ at line %d", self.func.lineno)

    _SINK_BUILTINS = frozenset({'open', 'eval', 'exec', 'compile', '__import__'})
    _SINK_MODULES = {
        'os': frozenset({'system', 'popen', 'remove', 'unlink', 'rename', 'replace', 'rmdir', 'removedirs', 'chmod', 'chown',
                         'startfile', 'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execle', 'execlp', 'spawnl', 'spawnv'}),
        'subprocess': frozenset({'run', 'call', 'check_call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput'}),
        'shutil': frozenset({'rmtree', 'move', 'copy', 'copy2', 'copyfile', 'copytree'}),
        'pickle': frozenset({'load', 'loads'}), 'marshal': frozenset({'load', 'loads'}),
        'yaml': frozenset({'load', 'unsafe_load', 'full_load'}),
        'urllib.request': frozenset({'urlopen', 'urlretrieve'}),
        'builtins': frozenset({'open', 'eval', 'exec', 'compile', '__import__'}),
    }

    def _sink_callee(self, call: ast.Call) -> 'str | None':
        """'module.name' when the callee resolves, through this module's imports, to a sink the language / stdlib defines."""
        f = call.func
        imported = self.imported_names or {}
        if isinstance(f, ast.Name):
            src = imported.get(f.id)
            if src is None:
                if f.id in self._SINK_BUILTINS and f.id not in self.module_level_names:
                    return f'builtins.{f.id}'
                return None
            return f'{src}.{f.id}' if f.id in self._SINK_MODULES.get(src, ()) else None
        if isinstance(f, ast.Attribute):
            chain = [f.attr]; n = f.value
            while isinstance(n, ast.Attribute):
                chain.append(n.attr); n = n.value
            if not isinstance(n, ast.Name):
                return None
            chain.append(n.id); chain.reverse()          # ['urllib', 'request', 'urlopen'] / ['os', 'remove'] / ['request', 'urlopen']
            for k in range(len(chain) - 1, 0, -1):        # longest dotted prefix that is an imported name
                key = '.'.join(chain[:k]); src = imported.get(key)
                if src is None:
                    continue
                # `import os` → src 'os' == key; `import urllib.request` → key == src; `from os import path` → key 'path', src 'os' → 'os.path'
                mod = src if (key == src or src.endswith('.' + key)) else f'{src}.{key}'
                rest = chain[k:]
                mod = '.'.join([mod] + rest[:-1]) if len(rest) > 1 else mod
                return f'{mod}.{rest[-1]}' if rest[-1] in self._SINK_MODULES.get(mod, ()) else None
        return None

    def _check_missing_input_validation_extended(self) -> None:
        """
        NAI-158: Missing input validation at system boundaries (CWE-20, extends NAI-160).

        Extends NAI-160 by checking public API functions with boundary-named
        parameters (path, file, url, query, command, etc.) that lack any
        validation, sanitization, or type checking.
        """
        m = self.metrics

        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name.startswith('_') or m.params <= 0` removed
            return
        if False:  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): name/table mute `m.name.startswith('test_') or m.name in ('setUp', 'tearDown', 'setup',` removed
            return

        param_names = {arg.arg for arg in self.func.args.args
                       if arg.arg not in ('self', 'cls')}

        # Hardened 2026-09-05 (F-158): CWE-20 is about untrusted data reaching a
        # SINK. A framework-typed handler param (`request`, `event`, `ctx`) is
        # not a sink; a name is not a flow. The rule now fires only when a
        # boundary-named param is passed into a sink call (file open, path
        # construction, subprocess/shell, SQL execute, eval/exec, HTTP fetch,
        # HTML render) with no validation in the function — Bandit judges
        # sinks, not parameter names.
        boundary_keywords = {'path', 'file', 'filename', 'filepath', 'url', 'uri',
                             'query', 'payload', 'command', 'cmd', 'sql', 'html',
                             'template', 'user_input'}

        boundary_params: set[str] = set()
        for param in param_names:
            param_lower = param.lower()
            for kw in boundary_keywords:
                if kw in param_lower:
                    boundary_params.add(param)
                    break

        if not boundary_params:
            self.observations.append({"tag": 'NAI-158', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not boundary_params'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # IG-3 (owner ruling 2026-09-06): the sink table is what the rule MEASURES ("a boundary name reaching a SINK"; the
        # hardening note: Bandit judges sinks, not parameter names). Cut 3 batch 4 voted it out as a name mute, after
        # which EVERY call receiving a boundary-named param counted — `str(path)` fired. Restored in lexical-fact form:
        # only sinks the language or its standard library define, resolved through this module's imports
        # (`os.remove`, never any `.remove`); framework sinks (`send_file`, `mark_safe`, `.get`/`.post`/`.request`) are
        # out until they carry their own evidence.
        reaching: set[str] = set()
        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            if self._sink_callee(node) is None:
                continue
            for arg in list(node.args) + [k.value for k in node.keywords]:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in boundary_params:
                        reaching.add(sub.id)
        boundary_params = reaching
        if not boundary_params:
            self.observations.append({"tag": 'NAI-158', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not boundary_params'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        has_validation = False
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ('isinstance', 'validate', 'sanitize', 'escape',
                                         'check', 'verify'):
                        has_validation = True
                        break
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('strip', 'replace', 'match', 'search',
                                           'validate', 'sanitize', 'escape', 'quote',
                                           'startswith', 'endswith', 'isdigit', 'isalnum',
                                           'resolve', 'abspath', 'normpath'):
                        has_validation = True
                        break
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    has_validation = True
                    break
                if isinstance(test, ast.Compare):
                    if isinstance(test.left, ast.Name) and test.left.id in boundary_params:
                        has_validation = True
                        break
            if isinstance(node, ast.Assert):
                has_validation = True
                break
            if isinstance(node, ast.ExceptHandler):
                has_validation = True
                break

        if not has_validation:
            self.observations.append({
                "tag": "NAI-158",
                "line": self.func.lineno,
                "boundary_params": list(boundary_params),
                "has_validation": False,
            })
            _log.debug("NAI-158 observed: missing boundary validation at line %d", self.func.lineno)

    def _check_deprecated_api_usage(self) -> None:
        """
        NAI-159: Stale library / deprecated API usage.

        Detects calls to well-known deprecated Python APIs that AI models
        often generate because they were prevalent in training data.
        """
        m = self.metrics

        deprecated_apis: dict[tuple[str, str], str] = {
            ('os', 'popen'): 'subprocess.run()',
            ('os', 'system'): 'subprocess.run()',
            ('imp', 'load_module'): 'importlib.import_module()',
            ('imp', 'find_module'): 'importlib.util.find_spec()',
            ('collections', 'MutableMapping'): 'collections.abc.MutableMapping',
            ('collections', 'MutableSequence'): 'collections.abc.MutableSequence',
            ('collections', 'Mapping'): 'collections.abc.Mapping',
            ('collections', 'Sequence'): 'collections.abc.Sequence',
            ('collections', 'Iterable'): 'collections.abc.Iterable',
            ('collections', 'Callable'): 'collections.abc.Callable',
            ('logging', 'warn'): 'logging.warning()',
        }

        deprecated_methods: dict[str, str] = {
            'iteritems': '.items()',
            'itervalues': '.values()',
            'iterkeys': '.keys()',
            'has_key': 'in operator',
            'xrange': 'range()',
            'raw_input': 'input()',
            'assertEquals': 'assertEqual',
            'assertNotEquals': 'assertNotEqual',
            'assertRegexpMatches': 'assertRegex',
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        key = (node.func.value.id, attr)
                        if key in deprecated_apis:
                            self.observations.append({
                                "tag": "NAI-159",
                                "line": node.lineno,
                                "module": key[0],
                                "method": attr,
                                "replacement": deprecated_apis[key],
                            })
                            _log.debug("NAI-159 observed: deprecated %s.%s() at line %d", key[0], attr, node.lineno)
                            return
                    if attr in deprecated_methods:
                        self.observations.append({
                            "tag": "NAI-159",
                            "line": node.lineno,
                            "method": attr,
                            "replacement": deprecated_methods[attr],
                        })
                        _log.debug("NAI-159 observed: deprecated .%s() at line %d", attr, node.lineno)
                        return
                if isinstance(node.func, ast.Name):
                    if node.func.id in deprecated_methods:
                        self.observations.append({
                            "tag": "NAI-159",
                            "line": node.lineno,
                            "function": node.func.id,
                            "replacement": deprecated_methods[node.func.id],
                        })
                        _log.debug("NAI-159 observed: deprecated %s() at line %d", node.func.id, node.lineno)
                        return

    _NETWORK_MODULES = frozenset({'socket', 'ssl', 'http', 'httplib', 'urllib', 'urllib2', 'urllib3', 'requests', 'httpx', 'aiohttp',
                                  'websocket', 'websockets', 'ftplib', 'smtplib', 'poplib', 'imaplib', 'telnetlib', 'xmlrpc', 'grpc',
                                  'boto3', 'botocore', 'paramiko', 'pika', 'redis', 'pymongo', 'psycopg2', 'asyncio', 'selectors'})

    def _network_receiver(self, expr: ast.AST, hints) -> bool:
        """IG-10 (2026-09-06): `.send()` / `.fetch()` / `.connect()` / `.request()` is a network call only when the receiver resolves
        to a network object by a visible fact — an imported network module, or a name / attribute carrying a network word
        (sock, conn, session, client, pool, transport …). A blinker signal's .send() or a module-local static .fetch() is not."""
        root = expr
        while isinstance(root, (ast.Attribute, ast.Call, ast.Subscript)):
            root = root.func if isinstance(root, ast.Call) else root.value
        if not isinstance(root, ast.Name):
            return False
        if root is expr or (isinstance(expr, ast.Name)):   # a bare name: resolve it through its last binding in this function (`s = socket.socket()`)
            last = None
            for n in self._own_scope(self.func):
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == root.id for t in n.targets) and (last is None or n.lineno > last.lineno):
                    last = n
            if last is not None and last.value is not expr and self._network_receiver(last.value, hints):
                return True
        src = self.imported_names.get(root.id, '') if isinstance(self.imported_names, dict) else ''
        if root.id in self._NETWORK_MODULES or (isinstance(src, str) and src.split('.')[0] in self._NETWORK_MODULES):
            return True
        words = [root.id.lower()]; e = expr
        while isinstance(e, (ast.Attribute, ast.Call, ast.Subscript)):
            if isinstance(e, ast.Attribute):
                words.append(e.attr.lower())
            e = e.func if isinstance(e, ast.Call) else e.value
        net_words = set(hints) | {'sock', 'socket', 'pool', 'transport', 'channel', 'ws', 'websocket', 'proxy', 'tunnel'}
        # whole words only (split on '_'): `ThreadedStream` is not a stream socket, `http_conn` is a connection
        return any(tok in net_words for w in words for tok in w.split('_') if tok)

    def _check_environmental_context_blindness(self) -> None:
        """
        NAI-167: Environmental context blindness — missing env config, retries, timeouts.

        AI-generated code hardcodes URLs/connection strings instead of reading
        from environment variables, and omits retry logic and timeouts for
        external service calls.
        """
        m = self.metrics

        has_hardcoded_conn = False
        has_env_lookup = False
        has_network_call = False
        has_timeout = False
        has_retry_logic = False

        # Unambiguous network attrs — always indicate network I/O
        network_attrs = {'request', 'connect', 'urlopen', 'fetch', 'send'}
        # Ambiguous attrs that are also common dict/object methods —
        # only count as network calls when object looks like an HTTP client
        _AMBIGUOUS_NETWORK_ATTRS = {'get', 'post', 'put', 'delete', 'patch'}
        _HTTP_OBJECT_HINTS = {'requests', 'session', 'sess', 'client', 'http',
                              'httpx', 'urllib', 'aiohttp', 'conn', 'connection',
                              'resp', 'response', 'api'}
        connection_funcs = {'connect', 'create_engine', 'Connection',
                            'MongoClient', 'Redis', 'StrictRedis'}
        url_prefixes = ('http://', 'https://', 'ftp://', 'amqp://',
                        'redis://', 'mongodb://', 'postgresql://',
                        'mysql://', 'sqlite:///')

        for node in ast.walk(self.func):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if any(node.value.startswith(p) for p in url_prefixes):
                    has_hardcoded_conn = True

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('getenv', 'get') and isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ('os', 'environ'):
                            has_env_lookup = True
                    if node.func.attr in network_attrs and self._network_receiver(node.func.value, _HTTP_OBJECT_HINTS):
                        has_network_call = True   # IG-10: the receiver must resolve to a network object by a visible fact
                    elif node.func.attr in _AMBIGUOUS_NETWORK_ATTRS:
                        # Only flag get/post/etc when object looks like an HTTP client
                        if isinstance(node.func.value, ast.Name):
                            if node.func.value.id.lower() in _HTTP_OBJECT_HINTS:
                                has_network_call = True
                    for kw in node.keywords:
                        if kw.arg in ('timeout', 'connect_timeout', 'read_timeout'):
                            has_timeout = True
                        if kw.arg in ('retries', 'max_retries', 'retry', 'backoff'):
                            has_retry_logic = True
                if isinstance(node.func, ast.Name):
                    if node.func.id in connection_funcs:
                        has_network_call = True
                    if node.func.id == 'getenv':
                        has_env_lookup = True

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is self.func:
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name) and dec.id in ('retry', 'retrying', 'backoff'):
                        has_retry_logic = True
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                        if dec.func.id in ('retry', 'retrying', 'backoff'):
                            has_retry_logic = True

        # Wave 3 (owner 2026-10-08, frontier list #9): `os.getenv("DATABASE_URL", "postgres://localhost/test")` — the
        # lookup exists, but its literal default quietly becomes the config wherever the variable is unset.
        for node in ast.walk(self.func):
            if not (isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) in ("getenv", "get")):
                continue
            recv = getattr(node.func, "value", None)
            if isinstance(node.func, ast.Attribute) and not (
                    (isinstance(recv, ast.Name) and recv.id in ("os", "environ"))
                    or (isinstance(recv, ast.Attribute) and recv.attr == "environ")):
                continue
            default = node.args[1] if node.args[1:] else next((k.value for k in node.keywords if k.arg == "default"), None)
            if isinstance(default, ast.Constant) and isinstance(default.value, str) and _ENV_FALLBACK.search(default.value):
                self.observations.append({
                    "tag": "NAI-167",
                    "line": node.lineno,
                    "blindness_type": "env_literal_fallback",
                    "variant": "env_literal_fallback",
                    "fallback": default.value,
                })
                return

        if has_hardcoded_conn and not has_env_lookup:
            self.observations.append({
                "tag": "NAI-167",
                "line": self.func.lineno,
                "blindness_type": "hardcoded_connection",
                "has_env_lookup": False,
            })
            _log.debug("NAI-167 observed: hardcoded connection string at line %d", self.func.lineno)
            return

        if has_network_call and not has_timeout and not has_retry_logic:
            self.observations.append({
                "tag": "NAI-167",
                "line": self.func.lineno,
                "blindness_type": "missing_resilience",
                "has_timeout": False,
                "has_retry_logic": False,
            })
            _log.debug("NAI-167 observed: network call without timeout/retry at line %d", self.func.lineno)

    # ------------------------------------------------------------------
    # NAI-201: Unsafe type coercion on external data
    # ------------------------------------------------------------------

    def _check_unsafe_type_coercion(self) -> None:
        """
        NAI-201: Detect int()/float()/bool() on external data without guard.

        Pattern: int(param), float(item.get('key')), bool(x) where x comes
        from a parameter or loop variable iterating over a parameter, and
        the call is not wrapped in try/except or preceded by isinstance().
        Crashes with ValueError/TypeError on malformed data.
        """
        m = self.metrics
        param_names = {arg.arg for arg in self.func.args.args}
        param_names -= {'self', 'cls'}
        if not param_names:
            self.observations.append({"tag": 'NAI-201', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not param_names'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        # Track loop variables iterating over parameters
        param_iterators: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.For):
                if isinstance(node.iter, ast.Name) and node.iter.id in param_names:
                    if isinstance(node.target, ast.Name):
                        param_iterators.add(node.target.id)
                    elif isinstance(node.target, ast.Tuple):
                        for elt in node.target.elts:
                            if isinstance(elt, ast.Name):
                                param_iterators.add(elt.id)

        external_names = param_names | param_iterators

        # Check for any try/except in the function (coarse guard)
        has_try = any(isinstance(n, ast.Try) for n in ast.walk(self.func))
        if has_try:
            return

        # Collect names guarded by isinstance()
        isinstance_guarded: set[str] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == 'isinstance' and node.args:
                    if isinstance(node.args[0], ast.Name):
                        isinstance_guarded.add(node.args[0].id)

        # Body-shape hardening 2026-09-06 (F-201b): a conditional (`if`) or
        # precondition (`assert`) whose test inspects the same name that reaches
        # the coercion call is a validation gate over that name's shape/state
        # before conversion, regardless of the exact predicate — same statement-
        # kind reasoning already applied to NAI-160's if/try guards: `if number:`,
        # `if x is None: x = 0`, `if pattern.fullmatch(value) is None: raise ...`,
        # and `assert len(x) == 6` are all conditionals over the coerced name's
        # own value, not unrelated branching elsewhere in the function.
        for node in ast.walk(self.func):
            if isinstance(node, (ast.If, ast.Assert)):
                for n in ast.walk(node.test):
                    if isinstance(n, ast.Name) and n.id in external_names:
                        isinstance_guarded.add(n.id)

        # Body-shape hardening 2026-09-06 (F-201c): unlike int()/float(), bool()
        # cannot raise ValueError/TypeError on arbitrary input — it always
        # succeeds via __bool__/__len__ or falls back to True. It structurally
        # cannot exhibit the crash-on-malformed-data pattern this family targets,
        # so it is not one of the coercion callees examined.
        coercion_funcs = {'int', 'float'}

        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id in coercion_funcs):
                continue
            if not node.args:
                self.observations.append({"tag": 'NAI-201', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not node.args'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
                continue

            arg = node.args[0]
            flagged = False

            # Direct: int(param) / float(loop_var)
            if isinstance(arg, ast.Name) and arg.id in external_names:
                if arg.id not in isinstance_guarded:
                    flagged = True

            # Via .get(): int(d.get('key'))
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                if arg.func.attr == 'get':
                    if isinstance(arg.func.value, ast.Name) and arg.func.value.id in external_names:
                        if arg.func.value.id not in isinstance_guarded:
                            flagged = True

            # Subscript: int(d['key'])
            if isinstance(arg, ast.Subscript):
                if isinstance(arg.value, ast.Name) and arg.value.id in external_names:
                    if arg.value.id not in isinstance_guarded:
                        flagged = True

            if flagged:
                self.observations.append({
                    "tag": "NAI-201",
                    "line": node.lineno,
                    "coercion_func": node.func.id,
                    "arg_type": type(arg).__name__,
                    "has_try_except": False,
                })
                _log.debug("NAI-201 observed: unsafe %s() coercion at line %d", node.func.id, node.lineno)
                return

    # ------------------------------------------------------------------
    # NAI-204: Sync function calling asyncio.run() anti-pattern
    # ------------------------------------------------------------------

    def _check_sync_calling_async(self) -> None:
        """
        NAI-204: Detect sync functions that call asyncio.run() or
        loop.run_until_complete().

        The inverse of NAI-018 (async-no-await). A sync function invoking
        asyncio.run() causes RuntimeError if an event loop is already
        running, and RuntimeWarning otherwise.
        """
        m = self.metrics

        if m.is_async:
            return  # Only flag sync functions

        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # asyncio.run(...)
            if isinstance(func, ast.Attribute) and func.attr == 'run':
                if isinstance(func.value, ast.Name) and func.value.id == 'asyncio':
                    self.observations.append({
                        "tag": "NAI-204",
                        "line": node.lineno,
                        "call_type": "asyncio_run",
                    })
                    _log.debug("NAI-204 observed: asyncio.run() in sync func at line %d", node.lineno)
                    return
            # loop.run_until_complete(...)
            if isinstance(func, ast.Attribute) and func.attr == 'run_until_complete':
                self.observations.append({
                    "tag": "NAI-204",
                    "line": node.lineno,
                    "call_type": "run_until_complete",
                })
                _log.debug("NAI-204 observed: run_until_complete() in sync func at line %d", node.lineno)
                return

    # ------------------------------------------------------------------
    # NAI-210: threading inside synchronous pipeline
    # ------------------------------------------------------------------

    def _check_threading_in_sync(self) -> None:
        """
        NAI-210: Detect threading.Thread() inside a synchronous function.

        Spawning threads inside a sync pipeline creates race conditions,
        non-deterministic data mutation, and makes debugging nearly impossible.
        """
        m = self.metrics

        # Skip async functions — they have their own concurrency model
        if isinstance(self.func, ast.AsyncFunctionDef):
            return

        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            # threading.Thread(...)
            if isinstance(fn, ast.Attribute) and fn.attr == 'Thread':
                if isinstance(fn.value, ast.Name) and fn.value.id == 'threading':
                    self.observations.append({
                        "tag": "NAI-210",
                        "line": node.lineno,
                        "call_form": "threading.Thread",
                    })
                    _log.debug("NAI-210 observed: threading.Thread() at line %d", node.lineno)
                    return
            # Thread(...) if imported directly
            if isinstance(fn, ast.Name) and fn.id == 'Thread':
                self.observations.append({
                    "tag": "NAI-210",
                    "line": node.lineno,
                    "call_form": "Thread",
                })
                _log.debug("NAI-210 observed: Thread() at line %d", node.lineno)
                return

    # ------------------------------------------------------------------
    # NAI-206: cwd-sensitive path construction
    # ------------------------------------------------------------------

    def _check_lru_cache_on_side_effect(self) -> None:
        """
        NAI-203: Detect @lru_cache / @cache on functions with side effects.

        Caching a side-effectful function (file I/O, print, logging, network,
        subprocess) means repeated calls silently skip the real work.
        """
        m = self.metrics
        decorators = getattr(self.func, 'decorator_list', [])
        has_cache = False
        for dec in decorators:
            if isinstance(dec, ast.Name) and dec.id in ('lru_cache', 'cache'):
                has_cache = True
            elif isinstance(dec, ast.Attribute) and dec.attr in ('lru_cache', 'cache'):
                has_cache = True
            elif isinstance(dec, ast.Call):
                fn = dec.func
                if isinstance(fn, ast.Name) and fn.id in ('lru_cache', 'cache'):
                    has_cache = True
                elif isinstance(fn, ast.Attribute) and fn.attr in ('lru_cache', 'cache'):
                    has_cache = True
        if not has_cache:
            self.observations.append({"tag": 'NAI-203', "line": self.func.lineno, "context": True, "measured": "nothing", "reason": 'not has_cache'})  # EXCISED cut 3 batch 4 (2026-09-06, owner: majority decides): silence → measured-nothing context
            return

        _SIDE_EFFECT_NAMES = {'print', 'open', 'input', 'exit', 'quit'}
        _SIDE_EFFECT_ATTRS = {'write', 'send', 'post', 'put', 'delete', 'patch',
                              'run', 'call', 'Popen', 'system', 'popen'}
        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            # print(), open(), etc.
            if isinstance(fn, ast.Name) and fn.id in _SIDE_EFFECT_NAMES:
                self.observations.append({
                    "tag": "NAI-203",
                    "line": node.lineno,
                    "side_effect_type": "builtin_call",
                    "side_effect_name": fn.id,
                })
                _log.debug("NAI-203 observed: cached func calls %s() at line %d", fn.id, node.lineno)
                return
            # obj.write(), requests.post(), subprocess.run(), etc.
            if isinstance(fn, ast.Attribute) and fn.attr in _SIDE_EFFECT_ATTRS:
                self.observations.append({
                    "tag": "NAI-203",
                    "line": node.lineno,
                    "side_effect_type": "method_call",
                    "side_effect_name": fn.attr,
                })
                _log.debug("NAI-203 observed: cached func calls .%s() at line %d", fn.attr, node.lineno)
                return
            # logging.info() etc
            if isinstance(fn, ast.Attribute) and fn.attr in ('info', 'warning', 'error', 'debug', 'critical'):
                if isinstance(fn.value, ast.Name) and fn.value.id in ('logging', 'logger', 'log'):
                    self.observations.append({
                        "tag": "NAI-203",
                        "line": node.lineno,
                        "side_effect_type": "logging_call",
                        "side_effect_name": fn.attr,
                    })
                    _log.debug("NAI-203 observed: cached func calls logging.%s() at line %d", fn.attr, node.lineno)
                    return

    def _check_cwd_sensitive_path(self) -> None:
        """
        NAI-206: Detect os.getcwd() used in path construction.

        Behavior changes depending on which directory the script is
        launched from — a portability / deployment bug.
        """
        m = self.metrics

        # Body-shape hardening 2026-09-06: build a parent map once so the three
        # facts below can look at how each os.getcwd() call's result is actually
        # used, not just that the call exists somewhere in the function.
        parent_of: dict[int, ast.AST] = {}
        for node in ast.walk(self.func):
            for child in ast.iter_child_nodes(node):
                parent_of[id(child)] = node

        def _ancestors(start: ast.AST, limit: int = 6):
            cur = start
            for _ in range(limit):
                p = parent_of.get(id(cur))
                if p is None:
                    return
                yield cur, p
                cur = p

        def _is_excluded(call_node: ast.Call) -> bool:
            assigned_name = None
            for child, p in _ancestors(call_node):
                # F-206a: the call is directly the entire value of a `return`
                # statement — relaying the cwd itself, not combining it with
                # other segments to construct a new path.
                if isinstance(p, ast.Return) and p.value is child:
                    return True
                # F-206b: reached only as the fallback (non-first) operand of a
                # boolean `or` — a graceful-degradation idiom triggered when a
                # primary value is missing, not the primary/unconditional path
                # source.
                if isinstance(p, ast.BoolOp) and isinstance(p.op, ast.Or) and child in p.values[1:]:
                    return True
                if isinstance(p, ast.Assign) and len(p.targets) == 1 and isinstance(p.targets[0], ast.Name):
                    assigned_name = p.targets[0].id
                    break
                if not isinstance(p, ast.Call):
                    break  # no evidenced fact for climbing through anything else

            if assigned_name is None:
                return False

            # F-206c: every later use of the assigned name is as the sole
            # argument to os.chdir() — a directory-CHANGE (restore) operation,
            # not path construction.
            uses = [n for n in ast.walk(self.func)
                    if isinstance(n, ast.Name) and n.id == assigned_name and isinstance(n.ctx, ast.Load)]
            if not uses:
                return False
            return all(
                isinstance(parent_of.get(id(u)), ast.Call)
                and isinstance(parent_of[id(u)].func, ast.Attribute)  # type: ignore[attr-defined]  # FIX_54 ast-pos
                and parent_of[id(u)].func.attr == 'chdir'  # type: ignore[attr-defined]  # FIX_54 ast-pos
                for u in uses
            )

        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == 'getcwd':
                if isinstance(func.value, ast.Name) and func.value.id == 'os':
                    if _is_excluded(node):
                        continue
                    self.observations.append({
                        "tag": "NAI-206",
                        "line": node.lineno,
                        "call": "os.getcwd",
                    })
                    _log.debug("NAI-206 observed: os.getcwd() at line %d", node.lineno)
                    return
