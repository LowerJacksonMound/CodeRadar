"""
Signature detection signatures for identifying AI-generated code patterns.

Contains patterns that indicate potentially signaturesulent, low-quality,
or hallucinated code.
"""

import logging
import os

from signature_engine.core import AuthorshipSignature

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)

# Signature Severity Levels
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

# Signature Categories
CATEGORY_HALLUCINATION = "hallucination"
CATEGORY_TYPO = "typo"
CATEGORY_PLACEHOLDER = "placeholder"
CATEGORY_STUB = "stub"
CATEGORY_QUALITY = "quality"
CATEGORY_SECURITY = "security"
CATEGORY_PATTERN = "pattern"
CATEGORY_STYLE = "style"
CATEGORY_LOGIC = "logic"


# Default Signature Signatures
DEFAULT_AUTHORSHIP_SIGNATURES: list[AuthorshipSignature] = [
    # ============================================
    # AI AUTHORSHIP CLAIMS (L10-L13)
    # ============================================
    AuthorshipSignature(
        name="ai_authorship_claim",
        severity=SEVERITY_CRITICAL,
        description="AI authorship claim in comment or string",
        category="ai_claim",
        pattern=r"(?i)(?:generated|created|written|produced|built|assisted|optimized|designed)\s+(?:by|using|with|via)\s+(?:ai|gpt|claude|grok|copilot|chatgpt|llm|gemini|bard|openai|anthropic)",
        tags=["ai_claim", "comment"],
    ),
    AuthorshipSignature(
        name="ai_optimization_claim",
        severity=SEVERITY_CRITICAL,
        description="AI optimization/efficiency claim",
        category="ai_claim",
        pattern=r"(?i)ai[- ](?:optimized|enhanced|powered|driven|assisted|generated)\s+(?:\w+\s+)*(?:logic|code|implementation|algorithm|solution)",
        tags=["ai_claim", "comment"],
    ),
    AuthorshipSignature(
        name="ai_model_reference",
        severity=SEVERITY_CRITICAL,
        description="Direct reference to AI model in source",
        category="ai_claim",
        pattern=r"(?i)(?:this|the)\s+(?:script|module|code|function|implementation)\s+(?:was|is)\s+(?:generated|created|written|produced)\s+(?:by|using|with)",
        tags=["ai_claim", "comment"],
    ),
    AuthorshipSignature(
        name="ai_buzzword_docstring",
        severity=SEVERITY_HIGH,
        description="AI-typical buzzword phrasing in docstring or comment",
        category="ai_claim",
        pattern=r"(?i)(?:comprehensive\s+edge[- ]case\s+handling|robust\s+(?:statistical|implementation)|perfect\s+for\s+(?:data|production)|ensures?\s+correctness.*(?:security|efficiency))",
        tags=["ai_claim", "docstring"],
    ),

    # ============================================
    # HALLUCINATION PATTERNS
    # ============================================
    AuthorshipSignature(
        name="hallucinated_import",
        severity=SEVERITY_HIGH,
        description="Import of commonly hallucinated module",
        category=CATEGORY_HALLUCINATION,
        pattern=r"^(?:from|import)\s+(?:utils|helpers?|common|shared|data_utils|file_utils|string_utils)\b",
        tags=["import", "module"],
    ),
    AuthorshipSignature(
        name="hallucinated_method",
        severity=SEVERITY_MEDIUM,
        description="Call to commonly hallucinated method",
        category=CATEGORY_HALLUCINATION,
        pattern=r"\.(to_string|to_int|to_float|contains|is_empty|first|last|prepend|append_all)\s*\(",
        tags=["method", "call"],
    ),
    AuthorshipSignature(
        name="fake_stdlib_import",
        severity=SEVERITY_HIGH,
        description="Import of fake standard library module",
        category=CATEGORY_HALLUCINATION,
        pattern=r"^(?:from|import)\s+(?:data_processing|file_handler|error_handler|config_utils)\b",
        tags=["import", "stdlib"],
    ),

    # ============================================
    # TYPO PATTERNS
    # ============================================
    AuthorshipSignature(
        name="misspelled_print",
        severity=SEVERITY_HIGH,
        description="Misspelled print function",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:pritn|pirnt|prit|prnt|prin)\s*\(",
        tags=["builtin", "function"],
    ),
    AuthorshipSignature(
        name="misspelled_len",
        severity=SEVERITY_HIGH,
        description="Misspelled len function",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:lenght|lenth|legth|legnth)\s*\(",
        tags=["builtin", "function"],
    ),
    AuthorshipSignature(
        name="misspelled_return",
        severity=SEVERITY_CRITICAL,
        description="Misspelled return keyword",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:retrun|reutrn|retrn|retunr)\s+",
        tags=["keyword"],
    ),
    AuthorshipSignature(
        name="misspelled_import",
        severity=SEVERITY_HIGH,
        description="Misspelled import keyword",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:improt|imoprt|ipmort|imprort)\s+",
        tags=["keyword"],
    ),
    AuthorshipSignature(
        name="misspelled_except",
        severity=SEVERITY_HIGH,
        description="Misspelled except keyword",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:excpet|exept|excep|excetp)\s*:",
        tags=["keyword"],
    ),
    AuthorshipSignature(
        name="misspelled_true_false",
        severity=SEVERITY_CRITICAL,
        description="Misspelled True/False constants",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:Ture|ture|TURE|Fasle|fasle|flase|FLASE|Flase)\b",
        tags=["constant"],
    ),
    AuthorshipSignature(
        name="misspelled_self",
        severity=SEVERITY_HIGH,
        description="Misspelled self parameter",
        category=CATEGORY_TYPO,
        pattern=r"\bdef\s+\w+\s*\(\s*(?:slef|sefl|selef)\s*[,)]",
        tags=["parameter"],
    ),
    AuthorshipSignature(
        name="misspelled_lambda",
        severity=SEVERITY_HIGH,
        description="Misspelled lambda keyword",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:lamda|lamba|labmda|lamdba)\s+",
        tags=["keyword"],
    ),
    AuthorshipSignature(
        name="misspelled_async_await",
        severity=SEVERITY_HIGH,
        description="Misspelled async/await keywords",
        category=CATEGORY_TYPO,
        pattern=r"\b(?:aysnc|aync|asycn|awiat|awit)\s+",
        tags=["keyword", "async"],
    ),

    # ============================================
    # PLACEHOLDER PATTERNS
    # ============================================
    AuthorshipSignature(
        name="todo_placeholder",
        severity=SEVERITY_MEDIUM,
        description="TODO placeholder without implementation",
        category=CATEGORY_PLACEHOLDER,
        pattern=r"#\s*TODO[:\s].*(?:implement|add|fix|complete|finish)",
        tags=["comment", "todo"],
    ),
    AuthorshipSignature(
        name="fixme_placeholder",
        severity=SEVERITY_MEDIUM,
        description="FIXME placeholder",
        category=CATEGORY_PLACEHOLDER,
        pattern=r"#\s*FIXME[:\s]",
        tags=["comment", "fixme"],
    ),
    AuthorshipSignature(
        name="placeholder_comment",
        severity=SEVERITY_MEDIUM,
        description="Generic placeholder comment",
        category=CATEGORY_PLACEHOLDER,
        pattern=r"#\s*(?:placeholder|stub|temp|temporary|dummy)\b",
        tags=["comment"],
    ),
    AuthorshipSignature(
        name="pass_only_function",
        severity=SEVERITY_MEDIUM,
        description="Function body is only pass statement",
        category=CATEGORY_STUB,
        pattern=r"def\s+\w+\s*\([^)]*\)\s*(?:->[^\n]*)?\s*:\s*\n\s+pass\s*$",
        multiline=True,
        tags=["function", "stub"],
    ),
    AuthorshipSignature(
        name="ellipsis_body",
        severity=SEVERITY_LOW,
        description="Function/class body is only ellipsis",
        category=CATEGORY_STUB,
        pattern=r"(?:def|class)\s+\w+[^\n]*:\s*\n\s+\.\.\.\s*$",
        multiline=True,
        tags=["stub"],
    ),
    AuthorshipSignature(
        name="notimplemented_error",
        severity=SEVERITY_MEDIUM,
        description="Raises NotImplementedError",
        category=CATEGORY_STUB,
        pattern=r"raise\s+NotImplementedError",
        tags=["exception", "stub"],
    ),

    # ============================================
    # QUALITY PATTERNS
    # ============================================
    AuthorshipSignature(
        name="bare_except",
        severity=SEVERITY_HIGH,
        description="Bare except clause catches all exceptions",
        category=CATEGORY_QUALITY,
        pattern=r"except\s*:",
        tags=["exception", "antipattern"],
    ),
    AuthorshipSignature(
        name="pokemon_exception",
        severity=SEVERITY_HIGH,
        description="Catching Exception or BaseException",
        category=CATEGORY_QUALITY,
        pattern=r"except\s+(?:Exception|BaseException)\s*:",
        tags=["exception", "antipattern"],
    ),
    AuthorshipSignature(
        name="silent_exception",
        severity=SEVERITY_HIGH,
        description="Exception caught and silently ignored",
        category=CATEGORY_QUALITY,
        # F-SIG1 (2026-09-05): [^\n]* not .* — under DOTALL `.*` spanned from an
        # earlier `except` to a later `: pass` (a class body), blaming the
        # function after `class XError(Exception): pass`.
        pattern=r"except[^\n]*:[ \t]*\n[ \t]+pass[ \t]*$",
        multiline=True,
        tags=["exception", "antipattern"],
    ),
    AuthorshipSignature(
        name="mutable_default_arg",
        severity=SEVERITY_MEDIUM,
        description="Mutable default argument",
        category=CATEGORY_QUALITY,
        pattern=r"def\s+\w+\s*\([^)]*(?:\[\]|\{\})\s*[,)]",
        tags=["function", "antipattern"],
    ),
    AuthorshipSignature(
        name="global_statement",
        severity=SEVERITY_LOW,
        description="Use of global statement",
        category=CATEGORY_QUALITY,
        pattern=r"^\s+global\s+\w+",
        tags=["statement", "antipattern"],
    ),
    AuthorshipSignature(
        name="eval_usage",
        severity=SEVERITY_CRITICAL,
        description="Use of eval() function",
        category=CATEGORY_SECURITY,
        pattern=r"\beval\s*\(",
        tags=["security", "dangerous"],
    ),
    AuthorshipSignature(
        name="exec_usage",
        severity=SEVERITY_CRITICAL,
        description="Use of exec() function",
        category=CATEGORY_SECURITY,
        pattern=r"\bexec\s*\(",
        tags=["security", "dangerous"],
    ),
    AuthorshipSignature(
        name="shell_injection",
        severity=SEVERITY_CRITICAL,
        description="Potential shell injection (shell=True)",
        category=CATEGORY_SECURITY,
        pattern=r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True",
        tags=["security", "injection"],
    ),
    AuthorshipSignature(
        name="sql_string_format",
        severity=SEVERITY_CRITICAL,
        description="Potential SQL injection via string formatting",
        category=CATEGORY_SECURITY,
        pattern=r"(?:execute|query)\s*\(\s*[\"'].*%s.*[\"']\s*%",
        tags=["security", "injection"],
    ),
    AuthorshipSignature(
        name="hardcoded_password",
        severity=SEVERITY_CRITICAL,
        description="Hardcoded password or secret",
        category=CATEGORY_SECURITY,
        pattern=r"(?:password|secret|api_key|token|credential)\s*=\s*[\"'][^\"']+[\"']",
        tags=["security", "credential"],
    ),

    # ============================================
    # PATTERN ANTI-PATTERNS
    # ============================================
    AuthorshipSignature(
        name="god_class",
        severity=SEVERITY_MEDIUM,
        description="Class with too many methods",
        category=CATEGORY_PATTERN,
        metric="method_count",
        threshold=20.0,
        tags=["class", "design"],
    ),
    AuthorshipSignature(
        name="god_function",
        severity=SEVERITY_MEDIUM,
        description="Function with too many lines",
        category=CATEGORY_PATTERN,
        metric="function_lines",
        threshold=100.0,
        tags=["function", "design"],
    ),
    AuthorshipSignature(
        name="deep_nesting",
        severity=SEVERITY_MEDIUM,
        description="Code with excessive nesting",
        category=CATEGORY_PATTERN,
        metric="nesting_depth",
        threshold=5.0,
        tags=["nesting", "complexity"],
    ),
    AuthorshipSignature(
        name="too_many_params",
        severity=SEVERITY_LOW,
        description="Function with too many parameters",
        category=CATEGORY_PATTERN,
        metric="param_count",
        threshold=7.0,
        tags=["function", "complexity"],
    ),
    AuthorshipSignature(
        name="high_cyclomatic",
        severity=SEVERITY_MEDIUM,
        description="High cyclomatic complexity",
        category=CATEGORY_PATTERN,
        metric="cyclomatic_complexity",
        threshold=15.0,
        tags=["complexity"],
    ),

    # ============================================
    # STYLE PATTERNS
    # ============================================
    AuthorshipSignature(
        name="mixed_quotes",
        severity=SEVERITY_INFO,
        description="Inconsistent quote style (single and double quotes mixed on same line)",
        category=CATEGORY_STYLE,
        pattern=r"""^(?!.*\bf['\"])(?!.*\{.*['"].*\}).*(?:\"[^\"]*\".*'[^']*'|'[^']*'.*\"[^\"]*\")""",
        tags=["style", "quotes"],
    ),
    AuthorshipSignature(
        name="trailing_whitespace",
        severity=SEVERITY_INFO,
        description="Trailing whitespace",
        category=CATEGORY_STYLE,
        pattern=r"[ \t]+$",
        tags=["style", "whitespace"],
    ),
    AuthorshipSignature(
        name="missing_docstring",
        severity=SEVERITY_INFO,
        description="Public function without docstring",
        category=CATEGORY_STYLE,
        pattern=r"def\s+(?!_)\w+\s*\([^)]*\)\s*(?:->.*)?:\s*\n\s+(?![\"'])",
        tags=["style", "documentation"],
    ),
    AuthorshipSignature(
        name="star_import",
        severity=SEVERITY_LOW,
        description="Star import pollutes namespace",
        category=CATEGORY_STYLE,
        pattern=r"from\s+\w+\s+import\s+\*",
        tags=["import", "antipattern"],
    ),

    # ============================================
    # LOGIC PATTERNS
    # ============================================
    AuthorshipSignature(
        name="comparison_to_none",
        severity=SEVERITY_LOW,
        description="Comparison to None using == instead of is",
        category=CATEGORY_LOGIC,
        pattern=r"(?:==|!=)\s*None\b",
        tags=["comparison", "style"],
    ),
    AuthorshipSignature(
        name="comparison_to_true_false",
        severity=SEVERITY_LOW,
        description="Comparison to True/False using ==",
        category=CATEGORY_LOGIC,
        pattern=r"==\s*(?:True|False)\b",
        tags=["comparison", "style"],
    ),
    AuthorshipSignature(
        name="useless_comparison",
        severity=SEVERITY_MEDIUM,
        description="Comparison of identical values",
        category=CATEGORY_LOGIC,
        pattern=r"\b(\w+)\s*(?:==|!=|<|>|<=|>=)\s*\1\b",
        tags=["comparison", "logic"],
    ),
    AuthorshipSignature(
        name="unreachable_code",
        severity=SEVERITY_HIGH,
        description="Code after return/raise is unreachable",
        category=CATEGORY_LOGIC,
        # Only match return/raise at same indentation as the next statement
        # (excludes conditional returns like `if x: return y` followed by code)
        # Uses [^\n]* instead of .* because DOTALL makes . match newlines
        pattern=r"^([ \t]+)(?:return|raise)\s+[^\n]*\n\1(?!except|finally|elif|else)\S",
        multiline=True,
        tags=["control_flow", "logic"],
    ),
    AuthorshipSignature(
        name="constant_condition",
        severity=SEVERITY_MEDIUM,
        description="If condition is always True or False",
        category=CATEGORY_LOGIC,
        pattern=r"if\s+(?:True|False|1|0)\s*:",
        tags=["condition", "logic"],
    ),
    AuthorshipSignature(
        name="empty_if_body",
        severity=SEVERITY_MEDIUM,
        description="If statement with empty body",
        category=CATEGORY_LOGIC,
        pattern=r"if\s+[^\n]*:[ \t]*\n[ \t]+pass[ \t]*(?:\n\s*else|\n\s*elif)?",  # F-SIG1: no cross-line .*
        multiline=True,
        tags=["condition", "logic"],
    ),
    AuthorshipSignature(
        name="redundant_return_none",
        severity=SEVERITY_INFO,
        description="Explicit return None at end of function",
        category=CATEGORY_LOGIC,
        pattern=r"return\s+None\s*\n\s*$",
        multiline=True,
        tags=["return", "style"],
    ),
]


def get_signatures_by_category(category: str) -> list[AuthorshipSignature]:
    """Get all signatures signatures in a category."""
    result = [s for s in DEFAULT_AUTHORSHIP_SIGNATURES if s.category == category]
    _trace("get_signatures_by_category(%s) -> %d results", category, len(result))
    return result


def get_signatures_by_severity(severity: str) -> list[AuthorshipSignature]:
    """Get all signatures signatures with a given severity."""
    result = [s for s in DEFAULT_AUTHORSHIP_SIGNATURES if s.severity == severity]
    _trace("get_signatures_by_severity(%s) -> %d results", severity, len(result))
    return result


def get_signatures_by_tag(tag: str) -> list[AuthorshipSignature]:
    """Get all signatures signatures with a given tag."""
    result = [s for s in DEFAULT_AUTHORSHIP_SIGNATURES if tag in s.tags]
    _trace("get_signatures_by_tag(%s) -> %d results", tag, len(result))
    return result


def get_signature_by_name(name: str) -> AuthorshipSignature | None:
    """Get a signatures signature by name."""
    for sig in DEFAULT_AUTHORSHIP_SIGNATURES:
        if sig.name == name:
            _trace("get_signature_by_name(%s) -> found", name)
            return sig
    _trace("get_signature_by_name(%s) -> not found", name)
    return None


def merge_signatures(
    base: list[AuthorshipSignature],
    additional: list[AuthorshipSignature],
) -> list[AuthorshipSignature]:
    """Merge two lists of signatures signatures.

    Additional signatures are appended to base.
    Duplicate names in additional override base.
    """
    # Create dict of base signatures by name
    result_dict = {sig.name: sig for sig in base}

    # Add/override with additional signatures
    for sig in additional:
        result_dict[sig.name] = sig

    return list(result_dict.values())


def filter_signatures(
    signatures: list[AuthorshipSignature],
    categories: list[str] | None = None,
    severities: list[str] | None = None,
    tags: list[str] | None = None,
    exclude_categories: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> list[AuthorshipSignature]:
    """Filter signatures by various criteria."""
    _trace("filter_signatures: %d input, categories=%s, severities=%s, tags=%s",
           len(signatures), categories, severities, tags)
    result = signatures

    if categories:
        result = [s for s in result if s.category in categories]

    if severities:
        result = [s for s in result if s.severity in severities]

    if tags:
        result = [s for s in result if any(t in s.tags for t in tags)]

    if exclude_categories:
        result = [s for s in result if s.category not in exclude_categories]

    if exclude_tags:
        result = [s for s in result if not any(t in s.tags for t in exclude_tags)]

    _trace("filter_signatures: %d results after filtering", len(result))
    return result


if __name__ == "__main__":
    print("signature_engine.signatures — Signature definitions")
    print(f"  Total default signatures: {len(DEFAULT_AUTHORSHIP_SIGNATURES)}")
    cats: dict = {}
    for sig in DEFAULT_AUTHORSHIP_SIGNATURES:
        cats[sig.category] = cats.get(sig.category, 0) + 1
    for cat, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
        print(f"    {cat}: {count}")
    print(f"  get_signatures_by_category('hallucination'): {len(get_signatures_by_category('hallucination'))}")
    print(f"  get_signatures_by_severity('critical'): {len(get_signatures_by_severity('critical'))}")
