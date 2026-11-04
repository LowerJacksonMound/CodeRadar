"""
Module: rca_main
Status: Phase 1&2 Integrated
"""

import logging

# Instrumentation: use shared infrastructure when available, fall back to stdlib
try:
    from shared.instrumentation.logger import get_logger
    from shared.instrumentation.tracing import get_tracer
    from shared.config.manager import get_module_config

    logger = get_logger("rca_main")
    tracer = get_tracer("rca_main")
    config = get_module_config("rca_main")

    logger.info(
        f"Initializing rca_main",
        config={k: v for k, v in config.__dict__.items() if not k.startswith('_')}
    )
except ImportError:
    # Standalone mode — shared infrastructure not wired yet
    logger = logging.getLogger("rca_main")
    tracer = None
    config = None

# Core components
# RootCauseReport ARCHIVED 2026-09-10 (FIX_32 §4.3: one analyzer); should_exclude_path ARCHIVED 2026-09-10
# (FIX_14: the ONE walk is live_py_files); gather_context_handler ARCHIVED 2026-09-10 (FIX_33 §4.4).
from rca_main.rca_unit import RootCauseUnit, CallerTracer
from rca_main.context_calculator import ContextLinesCalculator, ContextRecommendation
from rca_main.context_gathering_manager import ContextManager
from rca_main.onion_peeler import OnionPeeler, SolutionChain, peel_and_fix, peel_and_fix_async
from rca_main.origin_tracer import TraceContext, CrashArtifact, trace_me, run_with_tracing
from rca_main.import_graph import ImportGraphBuilder
from rca_main.caller_map import CallerMapBuilder
from rca_main.session_state import (
    RootCauseSessionState,
    RootCauseSessionManager,
    RootCauseSession,
)
from rca_main.constants import live_py_files

# Workflow handlers (for executor.py integration)
from rca_main.rca_unit import rca_main_handler
from rca_main.context_calculator import rca_lite_handler

__all__ = [
    # Instrumentation
    'logger', 'tracer', 'config',
    # Core
    'RootCauseUnit', 'CallerTracer',
    'ContextLinesCalculator', 'ContextRecommendation',
    'ContextManager',
    'OnionPeeler', 'SolutionChain', 'peel_and_fix', 'peel_and_fix_async',
    'TraceContext', 'CrashArtifact', 'trace_me', 'run_with_tracing',
    'ImportGraphBuilder',
    'CallerMapBuilder',
    'RootCauseSessionState', 'RootCauseSessionManager', 'RootCauseSession',
    'live_py_files',
    # Workflow handlers
    'rca_main_handler',
    'rca_lite_handler',
]
