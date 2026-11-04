"""
Configuration constants for NoAI Validator v8.

NO SCOPES OR SCORES — all detection is pure yes/no AST predicates.
Config values are boolean feature flags and a few None-able settings only.
FIX_26 (2026-09-15): the ten dead magnitude keys (nine with zero consumers + the module-import ceiling, whose
only consumer was an excised gate) are gone — magnitudes are context, thresholds are out; the list is
in .archive/archived_20260915/NOTES.md.
"""

# Default configuration
DEFAULT_CONFIG = {
    "max_files": None,
    "async_requires_await": True,
    "docstring_style": None,
    "include_snippets": False,
    "parallel_workers": None,
    "detect_circular_imports": True,
    "enable_cache": True,
    "show_progress": True,
    "vuln_check_enabled": True,
    "include_fix_suggestions": True,
    # v8: Feature flags
    "enable_agent_detection": True,     # Agentic risk patterns
    "enable_pii_detection": True,       # Privacy leak detection
}

# Config value type specifications
CONFIG_TYPES = {
    "max_files": (int, type(None)),
    "async_requires_await": bool,
    "docstring_style": (str, type(None)),
    "include_snippets": bool,
    "parallel_workers": (int, type(None)),
    "detect_circular_imports": bool,
    "enable_cache": bool,
    "show_progress": bool,
    "vuln_check_enabled": bool,
    "include_fix_suggestions": bool,
    # v8: Feature flags
    "enable_agent_detection": bool,
    "enable_pii_detection": bool,
}
