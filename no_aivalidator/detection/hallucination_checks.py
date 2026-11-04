"""
Hallucination Detection Mixin (NAI-050 to NAI-058).

Detect AI-invented imports, calls to undefined names, misspellings.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any, Dict, Set, List, Optional, Iterator, TYPE_CHECKING

import logging

_log_init = logging.getLogger(__name__)

try:
    from signature_engine.builtins_registry import PYTHON_BUILTINS
    from signature_engine.dunders import DUNDER_METHODS, is_fake_dunder
    from signature_engine.hallucinations import (
        HALLUCINATED_FUNCTIONS,
        HALLUCINATION_MODULE_PATTERNS,
        MISSPELLED_BUILTINS,
        MISSPELLED_MODULES,
    )
    from signature_engine.packages import COMMON_PACKAGES
    from signature_engine.stdlib import STDLIB_MODULES
    _REGISTRIES_LOADED = True
except ImportError as _e:
    # EXCISED cut 3 round 1 (2026-09-06, owner + reviewers unanimous): the empty-registry fallback silently turned every hallucination check into a no-op —
    # a silence before the ranker. A missing registry is REPORTED (the health check step 7 verifies it loads).
    raise ImportError(f"hallucination_checks: signature_engine registries unavailable ({_e}) — NOT MEASURED, refusing to run silently") from _e
    # (fallback registry stubs removed — unreachable after the raise)

_log = logging.getLogger(__name__)



_REAL_BUILTIN_METHODS: frozenset = frozenset(
    n for t in (str, bytes, bytearray, list, dict, set, frozenset, tuple, int, float, complex,
                bool, range, slice, memoryview, type, object)
    for n in dir(t) if not n.startswith('__')
)


def dunder_names_in_tree(tree: ast.AST) -> Dict[str, int]:
    """NAI-058 fact (body-shape stage 2, 2026-09-06; FIX_34 2026-09-10): every dunder-shaped name's
    occurrences in ONE parsed module (a def name, an attribute reference in Load or Store context, or a
    class-level alias assign like `__nonzero__ = __bool__`). A name this project defines-and-uses in more
    than one place across the checked file's own directory subtree — a cross-module protocol hook, a
    duplicate ndarray-subclassing implementation, an aliased legacy name — reads as a project fact rather
    than a single self-talking def; a name that occurs exactly once anywhere in the subtree earns no
    exemption. FIX_34 (THE ASYNC LAW): this is a pure per-tree count; the subtree sum is a whole-set fact
    `file_validation._dunder_counts_by_dir` computes ONCE per directory validation from the trees parsed
    once up front — the per-dirpath rglob and its process-lifetime cache are gone, and the detector reads
    `self.dunder_counts` instead of walking anything."""
    counts: Dict[str, int] = {}
    for n in ast.walk(tree):
        if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name.startswith('__') and n.name.endswith('__') and len(n.name) > 4):
            counts[n.name] = counts.get(n.name, 0) + 1
        elif (isinstance(n, ast.Attribute)
                and n.attr.startswith('__') and n.attr.endswith('__') and len(n.attr) > 4):
            counts[n.attr] = counts.get(n.attr, 0) + 1
        elif isinstance(n, ast.ClassDef):
            for st in n.body:
                if isinstance(st, ast.Assign) and st.targets and isinstance(st.targets[0], ast.Name):
                    nm = st.targets[0].id
                    if nm.startswith('__') and nm.endswith('__') and len(nm) > 4:
                        counts[nm] = counts.get(nm, 0) + 1
    return counts


def _is_sentinel_only_branch_body(body: list) -> bool:
    """NAI-053 fact (body-shape stage, 2026-09-06): a single-statement branch body
    whose only value-bearing content is Python's own singleton constants (True /
    False / None) or a bare reference to names already bound before the branch (an
    echo / pass-through / re-raise built from existing locals) carries no authored
    information — with >=3 branches assigning from a 2-3 value sentinel domain a
    repeat is forced (pigeonhole), and an echoed name was never independently
    chosen per branch. A bare `pass` is likewise always identical to any other
    `pass`. None of this hides a REAL duplicate: a branch that introduces a fresh
    literal (an int / str / bytes / float — a made-up business value, e.g. the
    plant's `weight = 1` / `return "pass"`) is never sentinel-only and still counts.
    """
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Return):
        exprs = [stmt.value] if stmt.value is not None else []
    elif isinstance(stmt, ast.Assign):
        exprs = [stmt.value]
    elif isinstance(stmt, ast.AugAssign):
        exprs = [stmt.value]
    elif isinstance(stmt, ast.AnnAssign):
        exprs = [stmt.value] if stmt.value is not None else []
    elif isinstance(stmt, ast.Raise):
        exprs = [e for e in (stmt.exc, stmt.cause) if e is not None]
    elif isinstance(stmt, ast.Expr):
        exprs = [stmt.value]
    else:
        return False
    if not exprs:
        return False
    for expr in exprs:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Constant) and sub.value is not True and sub.value is not False and sub.value is not None:
                return False
    return True

class HallucinationChecksMixin:
    """Mixin providing hallucination detection checks."""
    if TYPE_CHECKING:  # FIX_31 (2026-09-15): what the composed AIFakeDetector supplies to every check mixin — typing only, no runtime effect
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
    project_index: Any
    imported_names: dict[str, str]
    current_module: str
    module_level_names: set[str]

    def _check_undefined_calls(self) -> None:
        """
        NAI-050: Detect calls to undefined names.

        Build a symbol table from:
        - Parameters
        - Assignments
        - Imports (with cross-file resolution via ProjectIndexer)
        - Class/function definitions

        Flag calls to names not in the symbol table.
        """
        m = self.metrics

        defined_names: set[str] = set()

        defined_names |= m.params_declared
        defined_names.add('self')
        defined_names.add('cls')

        for node in ast.walk(self.func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined_names.add(target.id)
                    elif isinstance(target, ast.Tuple):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                defined_names.add(elt.id)

            # NAI-050 gap (2026-09-06, found alongside IG-13): an annotated assignment
            # (`get_console_width: Optional[Callable[...]] = getattr(...)`) is a definition too,
            # same as a bare Assign — the symbol table skipped ast.AnnAssign entirely.
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                defined_names.add(node.target.id)

            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for gen in node.generators:
                    if isinstance(gen.target, ast.Name):
                        defined_names.add(gen.target.id)

            if isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    defined_names.add(node.target.id)
                elif isinstance(node.target, ast.Tuple):
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            defined_names.add(elt.id)

            if isinstance(node, ast.With):
                for item in node.items:
                    if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                        defined_names.add(item.optional_vars.id)

            if isinstance(node, ast.ExceptHandler):
                if node.name:
                    defined_names.add(node.name)

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node != self.func:
                    defined_names.add(node.name)

        # IG-9 (2026-09-06): scoping facts — a closure sees its enclosing function's names; a walrus binds its target; every
        # name in a for / comprehension target is bound (tuples too); a nested def's or lambda's parameters are bound inside it.
        defined_names |= self.enclosing_names
        for node in ast.walk(self.func):
            if isinstance(node, ast.NamedExpr):
                defined_names.add(node.target.id)
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for gen in node.generators:
                    defined_names |= {n.id for n in ast.walk(gen.target) if isinstance(n, ast.Name)}
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                defined_names |= {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)}
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and node is not self.func:
                a = node.args
                defined_names |= {x.arg for x in a.args + a.posonlyargs + a.kwonlyargs} | {x.arg for x in (a.vararg, a.kwarg) if x}
        safe_names = PYTHON_BUILTINS | defined_names

        safe_names |= set(self.imported_names.keys())
        safe_names |= self.module_level_names
        # IG-13 (2026-09-06): the project-wide definition set (every name any module in this
        # project defines, INCLUDING names that only reach a module through a wildcard or
        # relative `import *` — see project_attr_names / _wildcard_export_names in
        # file_validation.py) is as safe as a name this file imports by hand.
        safe_names |= self.module_attr_names

        undefined_calls: set[str] = set()

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                    if call_name not in safe_names:
                        if call_name not in COMMON_PACKAGES and call_name not in STDLIB_MODULES:
                            if call_name[0].isupper() and call_name.isalnum():
                                continue

                            if self.project_index is not None:
                                defn = self.project_index.resolve_call(
                                    call_name,
                                    self.current_module,
                                    self.imported_names
                                )
                                if defn is not None:
                                    continue

                            undefined_calls.add(call_name)

        if undefined_calls:
            self.observations.append({
                "tag": "NAI-050",
                "line": self.func.lineno,
                "func_name": m.name,
                "undefined_calls": sorted(undefined_calls),
            })
            _log.debug("NAI-050 observed: undefined calls in %s at line %d", m.name, self.func.lineno)

    def _check_misspelled_builtins(self) -> None:
        """
        NAI-051: Detect misspelled builtin names.

        AI commonly makes typos like 'lenght', 'pritn', 'retrun'.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                    if call_name in MISSPELLED_BUILTINS:
                        correct = MISSPELLED_BUILTINS[call_name]
                        self.observations.append({
                            "tag": "NAI-051",
                            "line": node.lineno,
                            "func_name": m.name,
                            "misspelled": call_name,
                            "correction": correct,
                        })
                        _log.debug("NAI-051 observed: misspelled builtin '%s' at line %d", call_name, node.lineno)
                        return

            if isinstance(node, ast.Name):
                name = node.id
                if name in MISSPELLED_BUILTINS:
                    correct = MISSPELLED_BUILTINS[name]
                    self.observations.append({
                        "tag": "NAI-051",
                        "line": node.lineno,
                        "func_name": m.name,
                        "misspelled": name,
                        "correction": correct,
                    })
                    _log.debug("NAI-051 observed: misspelled name '%s' at line %d", name, node.lineno)
                    return

    def _check_redundant_nesting(self) -> None:
        """
        NAI-052: Detect redundant nested conditions.

        Pattern: if x: if x:  (same condition nested)
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                outer_cond = ast.dump(node.test)

                if node.body and isinstance(node.body[0], ast.If):
                    inner_if = node.body[0]
                    inner_cond = ast.dump(inner_if.test)

                    if outer_cond == inner_cond:
                        self.observations.append({
                            "tag": "NAI-052",
                            "line": node.lineno,
                            "func_name": m.name,
                            "pattern": "identical_nested_if",
                            "condition_dump": outer_cond,
                        })
                        _log.debug("NAI-052 observed: redundant nested if in %s at line %d", m.name, node.lineno)
                        return

                for elif_node in node.orelse:
                    if isinstance(elif_node, ast.If):
                        elif_cond = ast.dump(elif_node.test)
                        if elif_cond == outer_cond:
                            self.observations.append({
                                "tag": "NAI-052",
                                "line": elif_node.lineno,
                                "func_name": m.name,
                                "pattern": "identical_elif",
                                "condition_dump": outer_cond,
                            })
                            _log.debug("NAI-052 observed: redundant elif in %s at line %d", m.name, elif_node.lineno)
                            return

    def _check_repetitive_branches(self) -> None:
        """
        NAI-053: Detect if/elif chains with identical bodies.

        Mathematical basis: Hash equality of body AST dumps
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.If):
                branch_hashes: dict[str, int] = {}

                # NAI-053 fact (2026-09-06): sentinel-only bodies (bare `pass`, or True /
                # False / None / an echoed existing name with no fresh literal) never count
                # toward a collision — see _is_sentinel_only_branch_body.
                if not _is_sentinel_only_branch_body(node.body):
                    if_body_hash = hashlib.md5(
                        ast.dump(ast.Module(body=node.body, type_ignores=[])).encode()
                    ).hexdigest()[:8]
                    branch_hashes[if_body_hash] = branch_hashes.get(if_body_hash, 0) + 1

                current = node
                while current.orelse:
                    if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                        elif_node = current.orelse[0]
                        if not _is_sentinel_only_branch_body(elif_node.body):
                            elif_hash = hashlib.md5(
                                ast.dump(ast.Module(body=elif_node.body, type_ignores=[])).encode()
                            ).hexdigest()[:8]
                            branch_hashes[elif_hash] = branch_hashes.get(elif_hash, 0) + 1
                        current = elif_node
                    else:
                        if current.orelse and not _is_sentinel_only_branch_body(current.orelse):
                            else_hash = hashlib.md5(
                                ast.dump(ast.Module(body=current.orelse, type_ignores=[])).encode()
                            ).hexdigest()[:8]
                            branch_hashes[else_hash] = branch_hashes.get(else_hash, 0) + 1
                        break

                for hash_val, count in branch_hashes.items():
                    if count > 1:
                        self.observations.append({
                            "tag": "NAI-053",
                            "line": node.lineno,
                            "func_name": m.name,
                            "identical_branch_count": count,
                            "body_hash": hash_val,
                        })
                        _log.debug("NAI-053 observed: %d repetitive branches in %s at line %d", count, m.name, node.lineno)
                        return

    def _check_duplicate_statements(self) -> None:
        """
        NAI-054: Detect consecutive identical statements (copy-paste).

        Mathematical basis: Sequential AST dump comparison
        """
        m = self.metrics

        body = self.func.body

        if len(body) < 2:
            return

        prev_hash: str | None = None
        consecutive_count = 1

        for stmt in body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if isinstance(stmt.value.value, str):
                    continue
            # cr_trials round three, step 4 (2026-11-04): a bare call statement repeated (`count_down(s)` twice,
            # `conn.ping()` twice) is an effect performed twice on purpose; copy-paste is a repeated ASSIGNMENT or block.
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                prev_hash = None
                consecutive_count = 1
                continue

            stmt_hash = hashlib.md5(ast.dump(stmt).encode()).hexdigest()[:12]

            if stmt_hash == prev_hash:
                consecutive_count += 1
                if consecutive_count >= 2:
                    self.observations.append({
                        "tag": "NAI-054",
                        "line": stmt.lineno,
                        "func_name": m.name,
                        "consecutive_count": consecutive_count,
                        "stmt_hash": stmt_hash,
                    })
                    _log.debug("NAI-054 observed: %d duplicate statements in %s at line %d", consecutive_count, m.name, stmt.lineno)
                    return
            else:
                consecutive_count = 1

            prev_hash = stmt_hash

    def _check_hallucinated_function_calls(self) -> None:
        """
        NAI-055: Detect calls to commonly hallucinated function/method names.

        AI models frequently invent methods from other languages (e.g., .contains(),
        .to_string(), .is_empty()) that don't exist in Python.
        """
        m = self.metrics

        # Hardened 2026-09-05 (F-055): a method name that exists on ANY Python
        # builtin type (`set.add`, `dict.update`, `list.extend`) cannot be a
        # hallucinated method — the receiver's type is unknown statically, so
        # only names that exist on NO builtin type (`.contains`, `.push`,
        # `.to_string`, `.is_empty`) are judged.
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
                if method_name in _REAL_BUILTIN_METHODS:
                    continue
                # IG-10 (2026-09-06): a name THIS MODULE defines, a method the STDLIB defines, or a call on an imported module
                # is a fact, not a hallucination (`self.to_dict()`, `proc.wait()`, `queue.put()`, `select.select()`).
                from .base import STDLIB_METHOD_NAMES
                if method_name in self.module_attr_names or method_name in STDLIB_METHOD_NAMES:
                    continue
                if isinstance(node.func.value, ast.Name) and (node.func.value.id in self.imported_names or node.func.value.id in STDLIB_MODULES):
                    continue
                if method_name in HALLUCINATED_FUNCTIONS:
                    self.observations.append({
                        "tag": "NAI-055",
                        "line": node.lineno,
                        "func_name": m.name,
                        "method_name": method_name,
                    })
                    _log.debug("NAI-055 observed: hallucinated method '.%s()' in %s at line %d", method_name, m.name, node.lineno)
                    return

    def _check_misspelled_module_imports(self) -> None:
        """
        NAI-056: Detect misspelled module names in imports.

        AI models frequently misspell standard library module names
        (e.g., 'colelctions' instead of 'collections').
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_module = alias.name.split('.')[0]
                    if top_module in MISSPELLED_MODULES:
                        correct = MISSPELLED_MODULES[top_module]
                        self.observations.append({
                            "tag": "NAI-056",
                            "line": node.lineno,
                            "func_name": m.name,
                            "misspelled_module": top_module,
                            "correction": correct,
                        })
                        _log.debug("NAI-056 observed: misspelled module '%s' at line %d", top_module, node.lineno)
                        return
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_module = node.module.split('.')[0]
                if top_module in MISSPELLED_MODULES:
                    correct = MISSPELLED_MODULES[top_module]
                    self.observations.append({
                        "tag": "NAI-056",
                        "line": node.lineno,
                        "func_name": m.name,
                        "misspelled_module": top_module,
                        "correction": correct,
                    })
                    _log.debug("NAI-056 observed: misspelled module '%s' at line %d", top_module, node.lineno)
                    return

    def _check_hallucinated_module_imports(self) -> None:
        """
        NAI-057: Detect imports of commonly hallucinated module names.

        AI models invent plausible-sounding modules like 'data_processing',
        'file_handler', 'error_handler' that don't exist.
        """
        m = self.metrics

        for node in ast.walk(self.func):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_module = alias.name.split('.')[0]
                    if top_module in HALLUCINATION_MODULE_PATTERNS:
                        self.observations.append({
                            "tag": "NAI-057",
                            "line": node.lineno,
                            "func_name": m.name,
                            "hallucinated_module": top_module,
                        })
                        _log.debug("NAI-057 observed: hallucinated module '%s' at line %d", top_module, node.lineno)
                        return
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_module = node.module.split('.')[0]
                if top_module in HALLUCINATION_MODULE_PATTERNS:
                    self.observations.append({
                        "tag": "NAI-057",
                        "line": node.lineno,
                        "func_name": m.name,
                        "hallucinated_module": top_module,
                    })
                    _log.debug("NAI-057 observed: hallucinated module '%s' at line %d", top_module, node.lineno)
                    return

    def _check_fake_dunder_methods(self) -> None:
        """
        NAI-058: Detect fake/invented dunder method names.

        AI models sometimes invent plausible-sounding dunder methods like
        '__serialize__', '__validate__', '__convert__' that aren't real Python dunders.
        """
        m = self.metrics

        if not (m.name.startswith('__') and m.name.endswith('__') and len(m.name) > 4):
            return

        if not is_fake_dunder(m.name):
            return

        # NAI-058 fact (body-shape stage 2, 2026-09-06): a dunder-shaped name this
        # project defines or references in more than one place (across the checked
        # file's own directory subtree) is a project fact, not an invented name —
        # see dunder_names_in_tree / file_validation._dunder_counts_by_dir. A singleton stays reported.
        # FIX_34 (b) (2026-09-10): the subtree counts arrive as the whole-set fact the directory validation
        # computed once (`self.dunder_counts`); a single-file validation carries none — then the exemption is
        # not measurable and the singleton stays reported.
        if self.dunder_counts is not None and self.dunder_counts.get(m.name, 0) > 1:  # type: ignore[attr-defined]  # FIX_54 ast-pos
            return

        self.observations.append({
            "tag": "NAI-058",
            "line": self.func.lineno,
            "func_name": m.name,
            "dunder_name": m.name,
        })
        _log.debug("NAI-058 observed: fake dunder '%s' at line %d", m.name, self.func.lineno)

    def _check_invented_constants(self) -> None:
        """
        NAI-059: Access to commonly hallucinated constant/enum names.

        AI models invent plausible-sounding constants like STATUS_ACTIVE,
        MODE_VERBOSE, TYPE_DEFAULT that don't exist in the referenced module.
        Detects attribute access on known modules for undefined constants.
        """
        m = self.metrics

        # Common hallucinated constant patterns (module.CONSTANT style)
        HALLUCINATED_CONSTANTS = {
            'STATUS_ACTIVE', 'STATUS_INACTIVE', 'STATUS_PENDING',
            'MODE_VERBOSE', 'MODE_DEBUG', 'MODE_SILENT',
            'TYPE_DEFAULT', 'TYPE_CUSTOM', 'TYPE_STANDARD',
            'ERROR_NONE', 'ERROR_GENERIC', 'ERROR_UNKNOWN',
            'RESULT_SUCCESS', 'RESULT_FAILURE', 'RESULT_ERROR',
            'FLAG_ENABLED', 'FLAG_DISABLED',
            'PRIORITY_HIGH', 'PRIORITY_LOW', 'PRIORITY_NORMAL',
        }

        for node in ast.walk(self.func):
            if isinstance(node, ast.Attribute):
                attr = node.attr
                if attr in HALLUCINATED_CONSTANTS:
                    # Check if it's accessed on a module-like name
                    if isinstance(node.value, ast.Name):
                        obj_name = node.value.id
                        # Skip if it's accessing self/cls attributes
                        if obj_name not in ('self', 'cls'):
                            self.observations.append({
                                "tag": "NAI-059",
                                "line": node.lineno,
                                "func_name": m.name,
                                "object_name": obj_name,
                                "constant_name": attr,
                            })
                            _log.debug("NAI-059 observed: possibly hallucinated constant '%s.%s' at line %d", obj_name, attr, node.lineno)
                            return
