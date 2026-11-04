"""
Core data structures for signatures detection.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)


class FunctionType(Enum):
    """Function classification types."""
    VALIDATOR = auto()
    PREDICATE = auto()
    PROCESSOR = auto()
    HANDLER = auto()
    FACTORY = auto()
    INITIALIZER = auto()
    DESTRUCTOR = auto()
    GETTER = auto()
    SETTER = auto()
    GENERATOR = auto()
    DECORATOR = auto()
    ORCHESTRATOR = auto()
    UTILITY = auto()
    DUNDER = auto()
    CONTEXT_MANAGER = auto()
    ASYNC_HANDLER = auto()
    RENDERER = auto()
    EVENT_LOOP = auto()
    MUTATION = auto()
    TRANSFORMER = auto()
    ACCUMULATOR = auto()
    MAPPER = auto()
    PARSER = auto()
    FORMATTER = auto()
    CONVERTER = auto()
    UNKNOWN = auto()


@dataclass
class HardRequirements:
    """Hard requirements for function classification."""
    requires_params: bool = False
    requires_return: bool = False
    requires_yield: bool = False
    requires_call: bool = False
    requires_comparison_or_call: bool = False
    requires_loop: bool = False
    requires_branch: bool = False
    requires_assign: bool = False
    requires_comparison: bool = False
    requires_loop_or_comprehension: bool = False
    requires_return_or_yield: bool = False
    requires_return_or_side_effect: bool = False
    allows_method_delegation: bool = False
    allows_call_delegation: bool = False
    min_calls: int = 0
    max_args: Optional[int] = None
    max_complexity: Optional[int] = None


@dataclass
class CanonicalDefinition:
    """Canonical definition for a function type."""
    func_type: FunctionType
    hard_reqs: HardRequirements
    description: str


@dataclass
class AuthorshipSignature:
    """Signature detection signature."""
    name: str
    severity: str
    description: str
    category: str
    pattern: str | None = None
    metric: str | None = None
    threshold: float = 1.0
    multiline: bool = False
    tags: list[str] = field(default_factory=list)
    _compiled_pattern: re.Pattern[str] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def _get_compiled_pattern(self) -> re.Pattern[str] | None:
        """Get or compile the regex pattern.

        The re.MULTILINE flag is always used so ^ and $ match line boundaries.
        When self.multiline is True, re.DOTALL is also added so . matches newlines,
        enabling patterns that span multiple lines.
        """
        if self.pattern is None:
            return None
        if self._compiled_pattern is None:
            flags = re.MULTILINE
            if self.multiline:
                flags |= re.DOTALL
            self._compiled_pattern = re.compile(self.pattern, flags)
        return self._compiled_pattern

    def matches(self, code: str) -> bool:
        """Check if this signature matches the given code."""
        compiled = self._get_compiled_pattern()
        if compiled is None:
            return False
        result = bool(compiled.search(code))
        _trace("signature '%s' match=%s", self.name, result)
        return result

    def to_dict(self) -> dict[str, Any]:
        """Convert signature to dictionary."""
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "category": self.category,
            "pattern": self.pattern,
            "metric": self.metric,
            "threshold": self.threshold,
            "multiline": self.multiline,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorshipSignature":
        """Create signature from dictionary."""
        _trace("AuthorshipSignature.from_dict name=%s", data.get("name"))
        return cls(
            name=data["name"],
            severity=data["severity"],
            description=data["description"],
            category=data["category"],
            pattern=data.get("pattern"),
            metric=data.get("metric"),
            threshold=data.get("threshold", 1.0),
            multiline=data.get("multiline", False),
            tags=data.get("tags", []),
        )


if __name__ == "__main__":
    print("signature_engine.core — Types and enums")
    print(f"  FunctionType members: {[ft.name for ft in FunctionType]}")
    print(f"  HardRequirements fields: {[f.name for f in HardRequirements.__dataclass_fields__.values()]}")
    print(f"  CanonicalDefinition fields: {[f.name for f in CanonicalDefinition.__dataclass_fields__.values()]}")
    print(f"  AuthorshipSignature fields: {[f.name for f in AuthorshipSignature.__dataclass_fields__.values()]}")
    print("  All types OK")
