"""
NoAI Math Validator - Zero-AI Code Authenticity Verification System

A production-grade validation system for detecting AI-generated counterfeit code
using a two-layer validation approach:
- Layer 1: Hard Requirements (structural invariants)
- Layer 2: AI Fake Detector (pattern matching)

Fully async implementation with support for file, directory, and in-memory validation.
"""

from typing import Any, Optional

__version__ = "8.0.0"
__author__ = "NoAI Team"
__license__ = "MIT"

# Core validator
from .validator import NoAIMathValidator

# Configuration
from .config import DEFAULT_CONFIG, CONFIG_TYPES

# Core types - these are now always available
from .core import (
    FunctionType,
    FunctionMetrics,
    ValidationResult,
    ValidationLayer,
    HardRequirements,
    CanonicalDefinition,
    AuthorshipSignature,
    ModuleResult,
)

# Model types - these are now always available
from .models import (
    StringValidationResult,
    FunctionInfo,
    LambdaMetrics,
    ComprehensionInfo,
    ParseError,
)


__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",

    # Core validator
    "NoAIMathValidator",

    # Configuration
    "DEFAULT_CONFIG",
    "CONFIG_TYPES",

    # Core types
    "FunctionType",
    "FunctionMetrics",
    "ValidationResult",
    "ValidationLayer",
    "HardRequirements",
    "CanonicalDefinition",
    "AuthorshipSignature",
    "ModuleResult",

    # Model types
    "StringValidationResult",
    "FunctionInfo",
    "LambdaMetrics",
    "ComprehensionInfo",
    "ParseError",

    # Factory functions
    "create_validator",
    "configure",
    "setup_logging",
]


# Convenience factory functions
def create_validator(config: Optional[dict[str, Any]] = None) -> NoAIMathValidator:
    """
    Create a NoAIMathValidator instance with optional configuration.

    Args:
        config: Optional configuration dictionary

    Returns:
        Configured NoAIMathValidator instance

    Example:
        >>> validator = create_validator({'max_files': 100})
        >>> results = await validator.validate_file_async(Path('test.py'))
    """
    return NoAIMathValidator(config=config)


# Module-level configuration
def configure(config: dict[str, Any]) -> None:
    """
    Configure module-level defaults.

    Args:
        config: Configuration dictionary

    Example:
        >>> configure({'enable_cache': True, 'max_files': 500})
    """
    from .config import DEFAULT_CONFIG
    DEFAULT_CONFIG.update(config)


# Logging setup helper
def setup_logging(level: str = "INFO", format: Optional[str] = None) -> None:
    """
    Setup logging for the noai_validator module.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Optional custom log format

    Example:
        >>> setup_logging('DEBUG')
    """
    import logging

    if format is None:
        format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format,
    )

    # Set level for all noai_validator loggers
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, level.upper()))
