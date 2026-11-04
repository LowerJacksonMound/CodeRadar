"""
Detritus Cleaner & Artifact Scout - Production Grade

Safely identifies and holdings unreachable Python files in a repository.
"""

from detritus_cleaner.models import (
    FileStatus,
    FileMetadata,
    HoldingManifest,
    DetritusConfig,
    CleanseResult,
    DetritusCleanerError,
    ManifestCorruptedError,
    HoldingError,
    ValidationError,
)
from detritus_cleaner.core import DetritusCleaner
from detritus_cleaner.holding import HoldingManager
from detritus_cleaner.graph import ImportGraphBuilder
from detritus_cleaner.utils import run_async, setup_logging

# Hub
from detritus_cleaner.hub import (
    DetritusHub,
    HubResult,
    HubEvent,
    HubEventType,
    HubOperation,
)

# High-level API
from detritus_cleaner.workflows import (
    run_pre_game_optimization,
    validate_cleaning,
    clean,
    post_scan_validation_handler,
)

__version__ = "2.0.0"

__all__ = [
    # Core classes
    "DetritusCleaner",
    "HoldingManager",
    "ImportGraphBuilder",

    # Models & Config
    "DetritusConfig",
    "CleanseResult",
    "FileStatus",
    "FileMetadata",
    "HoldingManifest",

    # Exceptions
    "DetritusCleanerError",
    "ManifestCorruptedError",
    "HoldingError",
    "ValidationError",

    # High-level API
    "run_pre_game_optimization",
    "validate_cleaning",

    # Workflow handlers
    "clean",
    "post_scan_validation_handler",

    # Hub
    "DetritusHub",
    "HubResult",
    "HubEvent",
    "HubEventType",
    "HubOperation",

    # Utilities
    "run_async",
    "setup_logging",
]
