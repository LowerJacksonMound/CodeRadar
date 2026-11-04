"""
Core data structures for function metrics.

Provides the FunctionMetrics dataclass and shared types used throughout
the code analysis module.
"""

from dataclasses import dataclass, field


# Canonical severity levels (uppercase, ordered by severity)
SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"

# Type alias for issue tuples: (rule_id, severity, message)
Issue = tuple[str, str, str]


@dataclass
class DataFlowEdge:
    """A single edge in the intra-function data flow graph.

    Tracks not just THAT data flows from source to target,
    but HOW — identity-preserving (copy/alias) or transforming.
    """
    source: str       # variable being read
    target: str       # variable being written
    operation: str    # "identity" or "transform"
    detail: str       # e.g. "direct_assign", "copy_constructor:list", "call:process"


@dataclass
class FunctionMetrics:
    """
    Metrics for a single function.

    Attributes:
        name: Function name
        params: Number of parameters
        returns: Number of return statements
        branches: Number of if/elif statements
        loops: Number of for/while loops
        calls: Number of function calls
        assigns: Number of assignments
        nested_depth: Maximum nesting depth
        comprehensions: Number of list/dict/set comprehensions and generator expressions
        is_async: Whether function is async
        is_generator: Whether function is a generator (uses yield)
        vars_assigned: Set of variable names that are assigned
        vars_used: Set of variable names that are used (read)
        params_declared: Set of parameter names declared in function signature
    """

    name: str = ""
    params: int = 0
    returns: int = 0
    branches: int = 0
    loops: int = 0
    calls: int = 0
    assigns: int = 0
    nested_depth: int = 0
    comprehensions: int = 0
    is_async: bool = False
    is_generator: bool = False

    # Data flow tracking
    vars_assigned: set[str] = field(default_factory=set)
    vars_used: set[str] = field(default_factory=set)
    params_declared: set[str] = field(default_factory=set)
    global_vars: set[str] = field(default_factory=set)  # vars declared with `global`
    nonlocal_vars: set[str] = field(default_factory=set)  # vars declared with `nonlocal`

    # Edge-annotated data flow (the "signal analysis" layer)
    data_flow_edges: list[DataFlowEdge] = field(default_factory=list)
    return_sources: set[str] = field(default_factory=set)  # vars read in return stmt

    def to_tuple(self) -> tuple[int, int, int, int, int, int, int, int, bool, bool]:
        """
        Convert metrics to a tuple for fingerprinting.

        Returns a tuple of the structural metrics (excludes name and variable sets).
        """
        return (
            self.params,
            self.returns,
            self.branches,
            self.loops,
            self.calls,
            self.assigns,
            self.nested_depth,
            self.comprehensions,
            self.is_async,
            self.is_generator,
        )

    def is_trivial(self) -> bool:
        """
        Check if the function is trivial (simple getter/setter/pass).

        A function is considered trivial if it has:
        - No branches, loops, or comprehensions
        - At most 1 return statement
        - At most 1 assignment
        - At most 1 call
        """
        return (
            self.branches == 0
            and self.loops == 0
            and self.comprehensions == 0
            and self.returns <= 1
            and self.assigns <= 1
            and self.calls <= 1
        )
