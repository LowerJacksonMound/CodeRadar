"""
Core types for noai_validator.

Re-exports shared types from sibling packages and defines
validation-specific types used throughout the noai_validator module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

# Re-export shared types from signature_engine
from signature_engine.core import (
    FunctionType,
    HardRequirements,
    CanonicalDefinition,
    AuthorshipSignature,
)


@dataclass
class FunctionMetrics:
    """Metrics extracted from a Python function AST node."""
    name: str = ""
    params: int = 0
    returns: int = 0
    yields: int = 0
    branches: int = 0
    loops: int = 0
    calls: int = 0
    assigns: int = 0
    comparisons: int = 0
    complexity: int = 0
    comprehensions: int = 0
    has_side_effects: bool = False
    lines: int = 0
    docstring_lines: int = 0
    comment_lines: int = 0
    body_is_pass: bool = False
    body_is_ellipsis: bool = False
    body_is_raise_not_implemented: bool = False
    returns_literal_only: bool = False
    returns_input_unchanged: bool = False
    is_property: bool = False
    is_method: bool = False
    is_async: bool = False
    params_used: Set[str] = field(default_factory=set)
    params_declared: Set[str] = field(default_factory=set)


class ValidationLayer(Enum):
    """Which validation layer produced the result."""
    HARD_REQUIREMENTS = auto()
    AI_FAKE_DETECTOR = auto()


@dataclass
class ValidationResult:
    """Result of validating a single function."""
    function_name: str
    function_type: FunctionType
    passed: bool
    failure_layer: Optional[ValidationLayer] = None
    failure_reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metrics: Optional[FunctionMetrics] = None
    triggered_patterns: List[Any] = field(default_factory=list)
    file_path: Optional[str] = None  # Source file path
    line: int = 0  # Source line of the validated node (0 for file/module-level results)
    end_line: int = 0  # Last source line of the validated node (repair span, owner 2026-09-05)
    verdict_source: str = ""  # "ranker" when VerdictRanker decided (cut 1, 2026-09-06); "" = not routed
    species: str = ""         # the file's species FACT (owner decisions 1+5, 2026-09-06): "test" by content, "" otherwise; the path is a published prior, never the decider
    withheld: str = ""        # "species:test" when the ranker WITHHELD its verdict — a published PASS that is not a clean pass (evidence stays, as context)


@dataclass
class ModuleResult:
    """Result of validating all functions in a single module/file."""
    module_path: str
    function_results: List[ValidationResult] = field(default_factory=list)
    cross_function_issues: List[Tuple[str, str, str]] = field(default_factory=list)
    unresolved_symbols: List[str] = field(default_factory=list)
    duplicate_fingerprints: Dict[str, List[str]] = field(default_factory=dict)
    imported_symbols: List[str] = field(default_factory=list)

    @property
    def total_functions(self) -> int:
        """Total number of validated functions."""
        return len(self.function_results)

    @property
    def passed_functions(self) -> int:
        """Number of functions that passed validation."""
        return sum(1 for r in self.function_results if r.passed)

    @property
    def failed_functions(self) -> int:
        """Number of functions that failed validation."""
        return sum(1 for r in self.function_results if not r.passed)


__all__ = [
    "FunctionType",
    "FunctionMetrics",
    "ValidationResult",
    "ValidationLayer",
    "HardRequirements",
    "CanonicalDefinition",
    "AuthorshipSignature",
    "ModuleResult",
]
