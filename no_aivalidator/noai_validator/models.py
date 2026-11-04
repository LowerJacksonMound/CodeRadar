"""
Data models for the NoAI Validator.

Contains dataclasses for function info, parse errors, and validation results.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = [
    "FunctionInfo",
    "LambdaMetrics",
    "ComprehensionInfo",
    "ParseError",
    "StringValidationResult",
]


@dataclass
class FunctionInfo:
    """Information about a function extracted during AST traversal.
    
    Attributes:
        node: The AST node representing the function definition.
        class_context: True if this function is a method within a class.
        decorators: List of decorator names applied to this function.
        source_segment: The raw source code of the function if available.
        nesting_depth: How deeply nested this function is (0 for top-level).
        parent_class: Name of containing class if class_context is True.
    """
    node: ast.FunctionDef
    class_context: bool = False
    decorators: List[str] = field(default_factory=list)
    source_segment: Optional[str] = None
    parent_bases: List[str] = field(default_factory=list)  # base-class names of the enclosing class (2026-09-05)
    nesting_depth: int = 0
    parent_class: Optional[str] = None


@dataclass
class LambdaMetrics:
    """Metrics for a lambda expression.
    
    Attributes:
        node: The AST Lambda node.
        arg_count: Number of arguments the lambda accepts.
        body_complexity: Estimated complexity of the lambda body.
        is_identity: True if lambda is identity (lambda x: x).
        is_constant: True if lambda returns a constant value.
    """
    node: ast.Lambda
    arg_count: int = 0
    body_complexity: int = 1
    is_identity: bool = False
    is_constant: bool = False


@dataclass
class ComprehensionInfo:
    """Information about a comprehension expression.
    
    Attributes:
        node: The AST node (ListComp, SetComp, DictComp, or GeneratorExp).
        nesting_level: Depth of nested comprehensions.
        filter_count: Number of if-clauses in the comprehension.
        generator_count: Number of for-clauses in the comprehension.
    """
    node: ast.AST  # ListComp, SetComp, DictComp, GeneratorExp
    nesting_level: int = 0
    filter_count: int = 0
    generator_count: int = 1


@dataclass
class ParseError:
    """Record of a parse error encountered during validation.
    
    Attributes:
        filepath: Path to the file that failed to parse.
        error_type: Type of error (e.g., 'SyntaxError', 'UnicodeDecodeError').
        message: Human-readable error description.
        line: Line number where error occurred, if available.
        column: Column offset where error occurred, if available.
    """
    filepath: Path
    error_type: str
    message: str
    line: Optional[int] = None
    column: Optional[int] = None


@dataclass
class StringValidationResult:
    """Result of validating code from a string.
    
    Attributes:
        passed: True if code passed all validations.
        failure_reason: Description of why validation failed, if applicable.
        results: List of ValidationResult objects for each function.
        warnings: List of warning messages generated during validation.
    """
    passed: bool
    failure_reason: Optional[str] = None
    results: List[Any] = field(default_factory=list)  # List[ValidationResult]
    warnings: List[str] = field(default_factory=list)



