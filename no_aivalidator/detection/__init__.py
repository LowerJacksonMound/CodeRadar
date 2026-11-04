"""
Module: no_aivalidator.detection
Multi-layer AI-generated code detection checks.

FIX_25 (2026-09-15): the lazy exports below are REPOINTED to this package (they named the old `gauntlet`
package tree, dropped by RENAME_01 on 2026-09-09 — every one would have raised ModuleNotFoundError). The
lazy package API is kept (one place to look for the detector classes); the prune alternative was not
needed — repoint proved possible and costs nothing.
"""
from __future__ import annotations

import importlib
import logging
from typing import Any

_log = logging.getLogger(__name__)
_log.debug("Initializing %s", __name__)

# Lazy imports to break circular dependency (detection.base imports detection.core_checks etc.);
# resolved on first attribute access, e.g. `from no_aivalidator.detection import AIFakeDetector`.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "AIFakeDetector": ("no_aivalidator.detection.base", "AIFakeDetector"),
    "CoreChecksMixin": ("no_aivalidator.detection.core_checks", "CoreChecksMixin"),
    "StructuralChecksMixin": ("no_aivalidator.detection.structural_checks", "StructuralChecksMixin"),
    "MathChecksMixin": ("no_aivalidator.detection.math_checks", "MathChecksMixin"),
    "AdvancedChecksMixin": ("no_aivalidator.detection.advanced_checks", "AdvancedChecksMixin"),
    "HallucinationChecksMixin": ("no_aivalidator.detection.hallucination_checks", "HallucinationChecksMixin"),
    "RedundancyChecksMixin": ("no_aivalidator.detection.redundancy_checks", "RedundancyChecksMixin"),
    "SafetyChecksMixin": ("no_aivalidator.detection.safety_checks", "SafetyChecksMixin"),
    "StyleChecksMixin": ("no_aivalidator.detection.style_checks", "StyleChecksMixin"),
    "SemanticChecksMixin": ("no_aivalidator.detection.semantic_checks", "SemanticChecksMixin"),
    "ExtendedSemanticChecksMixin": ("no_aivalidator.detection.extended_semantic_checks", "ExtendedSemanticChecksMixin"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        module = importlib.import_module(module_path)
        return getattr(module, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AIFakeDetector",
    "CoreChecksMixin",
    "StructuralChecksMixin",
    "MathChecksMixin",
    "AdvancedChecksMixin",
    "HallucinationChecksMixin",
    "RedundancyChecksMixin",
    "SafetyChecksMixin",
    "StyleChecksMixin",
    "SemanticChecksMixin",
    "ExtendedSemanticChecksMixin",
]
