"""
Module: cheatsheets
Status: Phase 1&2 Integrated
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

try:
    from shared.instrumentation.logger import get_logger
    from shared.instrumentation.tracing import get_tracer
    from shared.config.manager import get_module_config
except ImportError:
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

    def get_tracer(name: str) -> Any:
        return None

    def get_module_config(name: str) -> SimpleNamespace:
        return SimpleNamespace()

# Initialize module instrumentation
logger = get_logger("cheatsheets")
tracer = get_tracer("cheatsheets")
config = get_module_config("cheatsheets")

# Log module initialization
try:
    logger.info(
        "Initializing cheatsheets",
        config={k: v for k, v in config.__dict__.items() if not k.startswith('_')}
    )
except TypeError:
    logger.info("Initializing cheatsheets")

# ---------------------------------------------------------------------------
# Hub (orchestrator's primary import)
# ---------------------------------------------------------------------------
# (CheatsheetHub archived 2026-09-07 — the Builder runs in the daemon; .archive/archived_20260907)

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
# (cheatsheet_builder.py archived 2026-09-08 — item 1 / FIX 12: the class was a husk
# (no disk I/O, no candidates, web-search internals gone); the live Builder is
# no_aivalidator/BUILDER_DAEMON.py::CheatsheetBuilder, the fourth gearbox child.
# .archive/archived_20260908/no_aivalidator/cheatsheets/cheatsheet_builder.py)

# ---------------------------------------------------------------------------
# Reviewer → parses and safety-scans only (item 2 / FIX 11, 2026-09-08). The verdict classes
# (CheatsheetReviewer, CheatsheetGate, ReviewStatus, …) and cheatsheet_schema.py are archived
# at .archive/archived_20260908/no_aivalidator/cheatsheets/ — THE RANKER is the one decision point.
# ---------------------------------------------------------------------------
from .cheatsheet_reviewer import (
    CodeAnalyzer,
    SecurityVisitor,
    PLACEHOLDER_REGEX,
    TRUNCATION_REGEX,
)

# ---------------------------------------------------------------------------
# Intelligence subpackage
# ---------------------------------------------------------------------------
from .cheatsheet_intelligence import (
    SolutionCandidate,
    SolutionRanker,
    ProjectProfile,
    KnowledgeBase,
    CheatSheet,
)

__all__ = [
    # Instrumentation
    'logger',
    'tracer',
    'config',

    # Builder: archived 2026-09-08 (see above) — no re-export

    # Reviewer → parses and safety-scans only; no verdict (2026-09-08)
    'CodeAnalyzer',
    'SecurityVisitor',
    'PLACEHOLDER_REGEX',
    'TRUNCATION_REGEX',

    # Intelligence
    'SolutionCandidate',
    'SolutionRanker',
    'ProjectProfile',
    'KnowledgeBase',
    'CheatSheet',
]
