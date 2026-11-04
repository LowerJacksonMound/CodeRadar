"""
Code analysis utilities for duplicate detection, symmetry analysis, and data-flow graphs.

Main modules:
- duplicate: Fingerprint-based duplicate detection (NAI-012, NAI-231 — was NAI-091 before the A1 renumber 2026-09-06)
- fingerprint: Structural and normalized function fingerprinting
- graph: DFS/BFS and data-flow dependency analysis
- symmetry: AI signature detection via structural symmetry patterns
"""

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("code-analysis")
except Exception:
    __version__ = "0.0.0-dev"

# Core types and constants
from utils.code_analysis.core import (
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
    SEVERITY_WARNING,
    DataFlowEdge,
    FunctionMetrics,
    Issue,
)

# Metrics extraction
from utils.code_analysis.extractor import MetricsExtractor

# Duplicate detection
from utils.code_analysis.duplicate import (
    check_duplicate_functions,
    check_duplicate_functions_strict,
)

# Fingerprinting
from utils.code_analysis.fingerprint import (
    check_normalized_duplicates,
    fingerprint_all_functions,
    fingerprint_function,
    normalized_fingerprint,
)

# Graph algorithms
from utils.code_analysis.graph import (
    bfs_shortest_path,
    build_data_flow_graph,
    build_dependency_graph,
    dfs_reachability,
    find_all_paths,
    find_cycles,
    find_undefined_uses,
    find_unused_assignments,
    is_identity_chain,
    reverse_graph,
    topological_sort,
)

# Symmetry detection
from utils.code_analysis.symmetry import (
    check_arithmetic_symmetry,
    check_suspicious_symmetry,
)


__all__ = [
    # Version
    "__version__",
    # Core types and constants
    "FunctionMetrics",
    "MetricsExtractor",
    "Issue",
    "SEVERITY_INFO",
    "SEVERITY_WARNING",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    # Duplicate detection
    "check_duplicate_functions",
    "check_duplicate_functions_strict",
    # Fingerprinting
    "fingerprint_function",
    "fingerprint_all_functions",
    "normalized_fingerprint",
    "check_normalized_duplicates",
    # Graph algorithms
    "dfs_reachability",
    "bfs_shortest_path",
    "build_dependency_graph",
    "build_data_flow_graph",
    "reverse_graph",
    "topological_sort",
    "find_all_paths",
    "find_cycles",
    "find_unused_assignments",
    "find_undefined_uses",
    "is_identity_chain",
    # Symmetry detection
    "check_suspicious_symmetry",
    "check_arithmetic_symmetry",
]
