"""
Semantic Analysis - Advanced Python code quality toolkit.

Provides def-use chains, control flow graph analysis, parameter usage tracking,
fast static filters, naming convention checks, API compliance, module handling,
false-positive reduction, and optional external tool integration.
"""

import logging

__version__ = "0.1.0"

logger = logging.getLogger(__name__)

# Core analyzers (existing)
from .def_use_chains import (
    DefUseAnalyzer, DefUseIssue,
    analyze_file as defuse_analyze_file,
    analyze_directory as defuse_analyze_directory,
)
# Keep legacy aliases for backward compat with cli.py / daemon imports
analyze_file = defuse_analyze_file
analyze_directory = defuse_analyze_directory

from .module_handling import (
    ModuleAnalyzer, ModuleIssue,
    analyze_file as module_analyze_file,
    analyze_directory as module_analyze_directory,
)

# New analyzers
from .cfg_analysis import (
    analyze_file as cfg_analyze_file,
    analyze_directory as cfg_analyze_directory,
)
from .parameter_usage import (
    analyze_file as param_analyze_file,
    analyze_directory as param_analyze_directory,
)
# (fast_static_filters / prefix_pattern_checks archived 2026-09-07 — every check exists in the detection mixins / the structure-first identifier; .archive/archived_20260907)
from .api_compliance import (
    analyze_file as api_analyze_file,
    analyze_directory as api_analyze_directory,
)

# (FalsePositiveFilter / async runner archived — cut 3 batch 2, 2026-09-06: dormant pre-ranker filter)

# (Vulture / Pylint tool wrappers archived — last plan 1R, 2026-10-10: unused; vulture runs as a tracker)

# (async analysis runner archived — cut 3 batch 2, 2026-09-06: dormant, carried the FalsePositiveFilter floors)

__all__ = [
    "__version__",
    # Legacy compat
    "DefUseAnalyzer", "DefUseIssue", "analyze_file", "analyze_directory",
    "ModuleAnalyzer", "ModuleIssue",
    # Individual analyzers
    "defuse_analyze_file", "defuse_analyze_directory",
    "module_analyze_file", "module_analyze_directory",
    "cfg_analyze_file", "cfg_analyze_directory",
    "param_analyze_file", "param_analyze_directory",
    "fast_analyze_file", "fast_analyze_directory",
    "prefix_analyze_file", "prefix_analyze_directory",
    "api_analyze_file", "api_analyze_directory",
    # False-positive reduction
    # Tool integration
    # Async runner
]


# (analyze / analyze_and_report archived 2026-10-10 — they called the async runner archived 2026-09-06; nothing called them)
