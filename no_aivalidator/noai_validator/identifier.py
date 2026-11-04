"""
Function type identification based on metrics and heuristics.

Classifies functions into types like VALIDATOR, TRANSFORMER, etc.
"""

import ast
import logging
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

from .core import FunctionType, FunctionMetrics
from .canonicals import DEFAULT_CANONICALS  # cut 2b: R(role) for name/body deficits (observation only)

logger = logging.getLogger(__name__)

__all__ = ["VariableTracker", "FunctionIdentifier"]

# Flow tracer integration (optional)
_F = TypeVar('_F', bound=Callable[..., Any])

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


class VariableTracker:
    """Tracks variable usage within a function."""
    
    def __init__(self, node: ast.FunctionDef):
        self.node = node
        self.assigned: Set[str] = set()
        self.referenced: Set[str] = set()
        self.global_vars: Set[str] = set()
        self.nonlocal_vars: Set[str] = set()
        self._analyze()

    def _analyze(self) -> None:
        """Analyze variable usage in the function."""
        for child in ast.walk(self.node):
            if isinstance(child, ast.Name):
                if isinstance(child.ctx, ast.Store):
                    self.assigned.add(child.id)
                elif isinstance(child.ctx, (ast.Load, ast.Del)):   # IG-11: `del x` is a use of x
                    self.referenced.add(child.id)
            elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                for target in getattr(child, 'targets', [child.target] if hasattr(child, 'target') else []):
                    if isinstance(target, ast.Name):
                        self.assigned.add(target.id)
            elif isinstance(child, ast.Global):
                self.global_vars.update(child.names)
            elif isinstance(child, ast.Nonlocal):
                self.nonlocal_vars.update(child.names)

    @property
    def unused_vars(self) -> Set[str]:
        """Variables assigned but never referenced (excluding global/nonlocal)."""
        return self.assigned - self.referenced - {'_'} - self.global_vars - self.nonlocal_vars

    def get_dead_variables(self) -> Set[str]:
        """Alias for unused_vars (used by detection checks)."""
        return self.unused_vars
    
    @property
    def undefined_vars(self) -> Set[str]:
        """Variables referenced but never assigned (may be globals/params)."""
        # Get parameter names
        params = {arg.arg for arg in self.node.args.args}
        params.update(arg.arg for arg in self.node.args.posonlyargs)
        params.update(arg.arg for arg in self.node.args.kwonlyargs)
        if self.node.args.vararg:
            params.add(self.node.args.vararg.arg)
        if self.node.args.kwarg:
            params.add(self.node.args.kwarg.arg)
        
        return self.referenced - self.assigned - params


class FunctionIdentifier:
    """
    Identifies the type of a function based on its metrics and structure.
    
    Uses a voting system where different heuristics vote for function types.
    """
    
    def __init__(
        self, 
        metrics: FunctionMetrics, 
        node: Optional[ast.FunctionDef] = None,
        var_tracker: Optional[VariableTracker] = None
    ):
        self.metrics = metrics
        self.node = node
        self.var_tracker = var_tracker or (VariableTracker(node) if node else None)
    
    # ── cut 2b (2026-09-06; RULES_HARDENING §S.7 — the owner's needs_nothing.txt) ─────────────────────────────
    # Structure first. Roles are constraints on the name-free feature vector φ(f), multi-label; the feasible set
    # T(f) comes from structure alone; an empty T(f) is UNTYPED, never a failure. A NAME is a weak prior: it never
    # selects a canonical; when the body lacks what the name's role requires, that is a name/body DISAGREEMENT,
    # published as the HR-NAME context observation for the ranker. The 15 vote weights and the winner-by-count
    # are gone (they were the pre-ranker ranker the census exempted as "cut 2b").
    _NAME_PRIORS: Tuple[Tuple[Tuple[str, ...], FunctionType], ...] = (
        (("handle", "on_", "process", "do_"), FunctionType.HANDLER),
        (("parse",), FunctionType.PARSER),
        (("format", "to_string", "render"), FunctionType.FORMATTER),
        (("convert", "to_", "from_", "as_"), FunctionType.CONVERTER),
        (("decorator",), FunctionType.DECORATOR),
        (("is_", "has_", "can_", "should_"), FunctionType.PREDICATE),
        (("valid", "check_", "verify"), FunctionType.VALIDATOR),
        (("make_", "create_", "build_"), FunctionType.FACTORY),
        (("iter_", "stream_"), FunctionType.GENERATOR),
        (("get_",), FunctionType.GETTER),
        (("set_",), FunctionType.SETTER),
    )
    _PRECEDENCE: Tuple[FunctionType, ...] = (
        FunctionType.GENERATOR, FunctionType.CONTEXT_MANAGER, FunctionType.INITIALIZER, FunctionType.DESTRUCTOR,
        FunctionType.DUNDER, FunctionType.EVENT_LOOP, FunctionType.DECORATOR, FunctionType.SETTER, FunctionType.GETTER,
        FunctionType.PREDICATE, FunctionType.VALIDATOR, FunctionType.FACTORY, FunctionType.MAPPER,
        FunctionType.ACCUMULATOR, FunctionType.HANDLER, FunctionType.TRANSFORMER,
    )
    _REQ_FEATURES = (("requires_params", "params"), ("requires_return", "return"), ("requires_yield", "yield"),
                     ("requires_branch", "branch"), ("requires_loop", "loop"), ("requires_call", "call"),
                     ("requires_assign", "assign"), ("requires_comparison", "comparison"))
    _REQ_COMPOUND = (("requires_loop_or_comprehension", ("loop", "comprehension")),
                     ("requires_comparison_or_call", ("comparison", "call")),
                     ("requires_return_or_yield", ("return", "yield")),
                     ("requires_return_or_side_effect", ("return", "side_effect")))

    def _body_features(self) -> Dict[str, Any]:
        """Name-free facts read from the node (§S.7 item 1 φ additions; first cut = AST presence, nested bodies included)."""
        f: Dict[str, Any] = {"returns_value": False, "returns_boolish": False, "returns_constructed": False,
                             "returns_inner_def": False, "stores_to_self": False, "raises_or_asserts": False,
                             "while_true": False, "decorators": [], "annotation": ""}
        node = self.node
        if node is None:
            return f
        inner_defs = {n.name for n in ast.walk(node)
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not node}
        for d in getattr(node, "decorator_list", []) or []:
            f["decorators"].append(ast.unparse(d))
        if getattr(node, "returns", None) is not None:
            f["annotation"] = ast.unparse(node.returns)  # type: ignore[arg-type]  # FIX_54 ast-pos
        bool_ann = f["annotation"].strip() == "bool"
        for n in ast.walk(node):
            if isinstance(n, ast.Return) and n.value is not None:
                v = n.value
                if not (isinstance(v, ast.Constant) and v.value is None):
                    f["returns_value"] = True
                if (isinstance(v, (ast.Compare, ast.BoolOp)) or (isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not))
                        or (isinstance(v, ast.Constant) and isinstance(v.value, bool)) or bool_ann):
                    f["returns_boolish"] = True
                if isinstance(v, ast.Call):
                    f["returns_constructed"] = True
                if isinstance(v, ast.Name) and v.id in inner_defs:
                    f["returns_inner_def"] = True
            elif isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in ("self", "cls"):
                        f["stores_to_self"] = True
            elif isinstance(n, (ast.Raise, ast.Assert)):
                f["raises_or_asserts"] = True
            elif isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True:
                f["while_true"] = True
        return f

    def _present(self) -> Set[str]:
        """P(f): the features the body shows (presence, never magnitude)."""
        m = self.metrics
        p: Set[str] = set()
        if m.params >= 1: p.add("params")
        if m.returns >= 1: p.add("return")
        if m.yields >= 1: p.add("yield")
        if m.branches >= 1: p.add("branch")
        if m.loops >= 1: p.add("loop")
        if m.calls >= 1: p.add("call")
        if m.assigns >= 1: p.add("assign")
        if m.comparisons >= 1: p.add("comparison")
        if m.comprehensions >= 1: p.add("comprehension")
        if m.has_side_effects: p.add("side_effect")
        return p

    def _deficit(self, role: FunctionType, present: Set[str]) -> List[str]:
        """R(role) \\ P(f): the canonical's requirements the body does not show (delegation leniencies mirror
        _check_hard_requirements). Empty = the body satisfies the role's canonical."""
        canon = DEFAULT_CANONICALS.get(role)
        if canon is None:
            return []
        reqs = canon.hard_reqs
        missing: List[str] = []
        for flag, feat in self._REQ_FEATURES:
            if getattr(reqs, flag, False) and feat not in present:
                if feat == "return" and getattr(reqs, "allows_method_delegation", False) and "call" in present:
                    continue
                if feat == "call" and getattr(reqs, "allows_call_delegation", False):
                    continue
                if feat == "comparison" and getattr(reqs, "allows_call_delegation", False) and "call" in present:
                    continue
                missing.append(feat)
        for flag, feats in self._REQ_COMPOUND:
            if getattr(reqs, flag, False) and not any(x in present for x in feats):
                missing.append("|".join(feats))
        return missing

    @trace
    def identify(self) -> Tuple[FunctionType, Dict[str, Any]]:
        """Structure-first role inference (§S.7). Returns (primary structural role — UNKNOWN when untyped, roles):
        roles = {"structural": [...], "declared": [(role, established_by)], "name": [...], "untyped": bool,
                 "hr_name": observation | None}. No weights, no winner-by-count."""
        m = self.metrics
        func_name = self.node.name if self.node else m.name
        name_lower = (func_name or "").lower()
        f = self._body_features()
        decos = [d.lower() for d in f["decorators"]]
        present = self._present()
        T: List[FunctionType] = []

        def has(role: FunctionType, cond: bool) -> None:
            if cond:
                T.append(role)
        has(FunctionType.GENERATOR, m.yields >= 1)
        has(FunctionType.CONTEXT_MANAGER, any("contextmanager" in d for d in decos)
            or func_name in ("__enter__", "__exit__", "__aenter__", "__aexit__"))
        has(FunctionType.INITIALIZER, func_name == "__init__")
        has(FunctionType.DESTRUCTOR, func_name == "__del__")
        has(FunctionType.DUNDER, bool(func_name) and func_name.startswith("__") and func_name.endswith("__")
            and func_name not in ("__init__", "__del__"))
        has(FunctionType.EVENT_LOOP, f["while_true"] and m.loops >= 1)
        has(FunctionType.DECORATOR, m.params >= 1 and f["returns_inner_def"])
        has(FunctionType.SETTER, m.params >= 1 and (f["stores_to_self"] or any(d.endswith(".setter") for d in decos)))
        has(FunctionType.GETTER, (m.params == 0 and m.returns >= 1 and m.assigns == 0) or "property" in decos)
        has(FunctionType.PREDICATE, m.params >= 1 and f["returns_boolish"])
        has(FunctionType.VALIDATOR, m.params >= 1 and f["raises_or_asserts"] and m.returns >= 1)
        has(FunctionType.FACTORY, m.returns >= 1 and f["returns_constructed"])
        has(FunctionType.MAPPER, m.comprehensions >= 1 and m.returns >= 1)
        has(FunctionType.ACCUMULATOR, m.params >= 1 and m.loops >= 1 and m.returns >= 1)
        has(FunctionType.HANDLER, m.params >= 1 and m.calls >= 1 and m.has_side_effects)
        has(FunctionType.TRANSFORMER, m.params >= 1 and m.returns >= 1)
        # Declared roles (§S.7 item 6): a decorator the code itself carries ESTABLISHES the role — its canonical is checked.
        # (A return annotation like `-> Iterator` is not used: `return iter(x)` satisfies it without a yield — §S.7 item 7.)
        declared: List[Tuple[FunctionType, str]] = []
        if any("contextmanager" in d for d in decos):
            declared.append((FunctionType.CONTEXT_MANAGER, "decorator"))
        if "property" in decos:
            declared.append((FunctionType.GETTER, "decorator"))
        if any(d.endswith(".setter") for d in decos):
            declared.append((FunctionType.SETTER, "decorator"))
        # Name priors (§S.7 item 4): weak priors, never a canonical; a deficit is a name/body disagreement.
        name_roles = [role for subs, role in self._NAME_PRIORS if any(s in name_lower for s in subs)]
        deficits = {r.name: d for r in name_roles if (d := self._deficit(r, present))}
        disagreements: List[str] = []
        nr = set(name_roles)
        if ({FunctionType.PREDICATE, FunctionType.VALIDATOR} & nr) and not f["returns_boolish"] and m.returns >= 1 and f["returns_constructed"]:
            disagreements.append("predicate-name, factory body (β=0, ρ≥1, γ)")
        if FunctionType.FACTORY in nr and not f["returns_value"] and (m.has_side_effects or f["stores_to_self"]):
            disagreements.append("factory-name, mutates and returns None (γ=0, μ≥1)")
        if ({FunctionType.HANDLER, FunctionType.SETTER} & nr) and m.params == 0:
            disagreements.append("handler/setter-name, arity 0 after the receiver")
        if FunctionType.GENERATOR in nr and m.yields == 0 and m.returns >= 1:
            disagreements.append("iter/stream-name, returns instead of yielding (y=0, ρ≥1)")
        primary = next((r for r in self._PRECEDENCE if r in T), FunctionType.UNKNOWN)
        hr_name: Optional[Dict[str, Any]] = None
        if deficits or disagreements:
            hr_name = {"tag": "HR-NAME", "line": (getattr(self.node, "lineno", 0) if self.node else 0), "context": True,
                       "func_name": func_name, "name_roles": [r.name for r in name_roles],
                       "structural_roles": [r.name for r in T], "deficits": deficits, "disagreements": disagreements}
        roles: Dict[str, Any] = {"structural": [r.name for r in T], "declared": declared,
                                 "name": [r.name for r in name_roles], "untyped": not T, "hr_name": hr_name}
        logger.debug("Identified %s: structural=%s declared=%s name=%s", m.name, roles["structural"],
                     [(r.name, b) for r, b in declared], roles["name"])
        return primary, roles
