"""
signature_engine - Python code signatures detection and analysis toolkit.

Detects hallucinated modules, misspelled builtins, and AI-generated code patterns.
"""

import logging
import os

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)

# Core types
from .builtins_registry import (
    BUILTIN_CONSTANTS,
    BUILTIN_DETAILS,
    BUILTIN_EXCEPTIONS,
    BUILTIN_FUNCTIONS,
    BUILTIN_TYPES,
    PYTHON_BUILTINS,
    BuiltinInfo,
    get_builtin_category,
    get_builtin_info,
    is_builtin,
    is_builtin_constant,
    is_builtin_exception,
    is_builtin_function,
    is_builtin_type,
)

# Canonicals
from .canonicals import (
    DEFAULT_CANONICALS,
    FUNCTION_TYPE_PREFIXES,
    get_canonical,
    get_requirements,
    infer_function_type,
    merge_canonicals,
    validate_against_canonical,
)
from .core import (
    CanonicalDefinition,
    AuthorshipSignature,
    FunctionType,
    HardRequirements,
)
from .dunders import (
    ASYNC_DUNDERS,
    ATTRIBUTE_DUNDERS,
    BINARY_NUMERIC_DUNDERS,
    BUFFER_DUNDERS,
    CALLABLE_DUNDERS,
    CLASS_ATTR_DUNDERS,
    CLASS_DUNDERS,
    COMPARISON_DUNDERS,
    CONTAINER_DUNDERS,
    CONTEXT_MANAGER_DUNDERS,
    COPY_PICKLE_DUNDERS,
    DESCRIPTOR_DUNDERS,
    DUNDER_CATEGORIES,
    DUNDER_DETAILS,
    DUNDER_METHODS,
    INPLACE_NUMERIC_DUNDERS,
    LIFECYCLE_DUNDERS,
    MATCH_DUNDERS,
    MODULE_DUNDERS,
    REFLECTED_NUMERIC_DUNDERS,
    REPR_DUNDERS,
    SLOT_DUNDERS,
    UNARY_NUMERIC_DUNDERS,
    DunderInfo,
    get_dunder_category,
    get_dunder_info,
    get_dunders_by_category,
    is_dunder,
    is_dunder_pattern,
    is_fake_dunder,
)

# Signature detection
from .authorship_rules import (
    DEFAULT_AUTHORSHIP_SIGNATURES,
    filter_signatures,
    get_signature_by_name,
    get_signatures_by_category,
    get_signatures_by_severity,
    get_signatures_by_tag,
    merge_signatures,
)
from .hallucinations import (
    HALLUCINATED_FUNCTIONS,
    HALLUCINATION_MODULE_PATTERNS,
    MISSPELLED_BUILTINS,
    MISSPELLED_MODULES,
    find_similar_builtin,
    get_all_typos,
    get_correct_builtin,
    get_correct_module,
    is_hallucinated_function,
    is_hallucinated_module,
    is_misspelled_builtin,
    is_misspelled_module,
)
from .packages import (
    COMMON_PACKAGES,
    IMPORT_NAME_MAPPING,
    PACKAGE_CATEGORIES,
    get_import_name,
    get_package_category,
    get_packages_by_category,
    is_common_package,
)
from .signatures import (
    AUTHORSHIP_SIGNATURES,
    AuthorshipSignatureDatabase,
    MatchResult,
    ScanResult,
    get_signature_database,
    reset_signature_database,
)

# Registries
from .stdlib import (
    ALL_KNOWN_MODULES,
    LEGACY_STDLIB_MODULES,
    STDLIB_MODULES,
    get_module_status,
    is_known_module,
    is_legacy_module,
    is_stdlib_module,
)

_trace("signature_engine v%s loaded", __version__)

__all__ = [
    "__version__",
    "FunctionType", "HardRequirements", "CanonicalDefinition", "AuthorshipSignature",
    "STDLIB_MODULES", "LEGACY_STDLIB_MODULES", "ALL_KNOWN_MODULES",
    "PYTHON_BUILTINS", "BUILTIN_FUNCTIONS", "BUILTIN_CONSTANTS",
    "BUILTIN_EXCEPTIONS", "BUILTIN_TYPES", "BUILTIN_DETAILS", "BuiltinInfo",
    "COMMON_PACKAGES", "DUNDER_METHODS", "DunderInfo", "DUNDER_DETAILS",
    "DUNDER_CATEGORIES",
    "MISSPELLED_BUILTINS", "MISSPELLED_MODULES",
    "HALLUCINATION_MODULE_PATTERNS", "HALLUCINATED_FUNCTIONS",
    "PACKAGE_CATEGORIES", "IMPORT_NAME_MAPPING",
    "is_stdlib_module", "is_legacy_module", "is_known_module", "get_module_status",
    "is_builtin", "is_builtin_function", "is_builtin_exception",
    "is_builtin_type", "is_builtin_constant", "get_builtin_info", "get_builtin_category",
    "is_dunder", "is_dunder_pattern", "is_fake_dunder",
    "get_dunder_category", "get_dunder_info", "get_dunders_by_category",
    "is_common_package", "get_package_category", "get_import_name", "get_packages_by_category",
    "is_misspelled_builtin", "get_correct_builtin",
    "is_hallucinated_module", "is_misspelled_module", "get_correct_module",
    "is_hallucinated_function", "get_all_typos", "find_similar_builtin",
    "DEFAULT_CANONICALS", "FUNCTION_TYPE_PREFIXES", "merge_canonicals",
    "get_canonical", "infer_function_type", "get_requirements", "validate_against_canonical",
    "DEFAULT_AUTHORSHIP_SIGNATURES", "merge_signatures", "filter_signatures",
    "get_signature_by_name", "get_signatures_by_category",
    "get_signatures_by_severity", "get_signatures_by_tag",
    "AuthorshipSignatureDatabase", "get_signature_database", "reset_signature_database",
    "AUTHORSHIP_SIGNATURES", "MatchResult", "ScanResult",
]
