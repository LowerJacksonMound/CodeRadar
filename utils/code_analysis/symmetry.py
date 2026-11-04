"""
Symmetry detection for AI-generated code signatures.

Provides functions to detect suspicious structural patterns that are
commonly found in AI-generated code, such as identical branches,
repeated loop bodies, and arithmetic progressions.
"""

import ast
import logging
from typing import Optional, Union

from utils.code_analysis.core import SEVERITY_INFO, SEVERITY_MEDIUM, SEVERITY_WARNING, Issue

logger = logging.getLogger(__name__)


def check_suspicious_symmetry(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> list[Issue]:
    """
    Check for suspicious structural symmetry patterns in a function.

    Detects:
    - NAI-092: If/else branches that are structurally identical
    - NAI-233 (was NAI-093, A1 renumber 2026-09-06): All if/elif branches that are identical
    - NAI-234 (was NAI-094): Multiple loops with identical bodies
    - NAI-235 (was NAI-096): Multiple comprehensions with identical structure

    Args:
        func_node: The function AST node to analyze

    Returns:
        List of (rule_id, severity, message) tuples for detected issues
    """
    logger.debug("check_suspicious_symmetry: analyzing %s", func_node.name)
    issues: list[Issue] = []

    # Check for identical if/else branches
    issues.extend(_check_if_else_symmetry(func_node))

    # Check for identical if/elif branches
    issues.extend(_check_if_elif_symmetry(func_node))

    # Check for identical loop bodies
    issues.extend(_check_loop_symmetry(func_node))

    # Check for identical comprehensions
    issues.extend(_check_comprehension_symmetry(func_node))

    if issues:
        logger.debug("check_suspicious_symmetry: %s produced %d issues", func_node.name, len(issues))
    return issues


def _normalize_ast(node: ast.AST) -> str:
    """
    Create a normalized string representation of an AST node.

    This is used to compare structural equality of code blocks.
    """
    return ast.dump(node)


def _structural_normalize_ast(node: ast.AST) -> str:
    """
    Create a structurally normalized AST string that ignores variable names.

    All Name nodes are replaced with a generic placeholder so that
    code with different variable names but identical structure compares equal.
    """
    import copy

    class _NameNormalizer(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.Name:
            return ast.Name(id="_", ctx=node.ctx)

        def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
            return ast.Attribute(
                value=self.visit(node.value),
                attr=node.attr,
                ctx=node.ctx,
            )

    copied = copy.deepcopy(node)
    normalized = _NameNormalizer().visit(copied)
    return ast.dump(normalized)


def _check_if_else_symmetry(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> list[Issue]:
    """Check for if/else branches that are structurally identical."""
    issues: list[Issue] = []

    for node in ast.walk(func_node):
        if isinstance(node, ast.If) and node.orelse:
            # Skip elif chains (handled separately)
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                continue

            # Compare if body with else body
            if_body = [_normalize_ast(stmt) for stmt in node.body]
            else_body = [_normalize_ast(stmt) for stmt in node.orelse]

            if if_body == else_body and len(if_body) > 0:
                issues.append(
                    (
                        "NAI-232",  # A1 renumber: was NAI-092 (detection NAI-092 = shell=True)
                        SEVERITY_WARNING,
                        f"If/else branches in function '{func_node.name}' are "
                        f"structurally identical (line {node.lineno})",
                    )
                )

    return issues


def _check_if_elif_symmetry(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> list[Issue]:
    """Check for all if/elif branches that are identical."""
    issues: list[Issue] = []

    for node in ast.walk(func_node):
        if isinstance(node, ast.If):
            # Collect all branches in the if/elif chain
            branches: list[list[ast.stmt]] = []
            current = node

            while True:
                branches.append(current.body)
                if current.orelse:
                    if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                        current = current.orelse[0]
                    else:
                        # Final else branch
                        branches.append(current.orelse)
                        break
                else:
                    break

            # Only check if we have 3+ branches (if/elif/elif or if/elif/else)
            if len(branches) >= 3:
                normalized = [tuple(_normalize_ast(stmt) for stmt in branch) for branch in branches]

                # Check if all branches are identical
                if len(set(normalized)) == 1 and len(normalized[0]) > 0:
                    issues.append(
                        (
                            "NAI-233",  # A1 renumber: was NAI-093 (detection NAI-093 = unsafe deserialization)
                            SEVERITY_WARNING,
                            f"All {len(branches)} if/elif branches in function "
                            f"'{func_node.name}' are identical (line {node.lineno})",
                        )
                    )

    return issues


def _check_loop_symmetry(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> list[Issue]:
    """Check for multiple loops with identical bodies."""
    issues: list[Issue] = []

    # Collect all loop bodies at the top level of the function
    loop_bodies: list[tuple[int, list[str]]] = []

    for node in func_node.body:
        if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            normalized_body = [_structural_normalize_ast(stmt) for stmt in node.body]
            loop_bodies.append((node.lineno, normalized_body))

    # Check for duplicates - report each duplicate pair only once
    if len(loop_bodies) >= 2:
        seen: dict[tuple[str, ...], int] = {}
        reported_pairs: set[tuple[int, int]] = set()
        for lineno, body in loop_bodies:
            body_tuple = tuple(body)
            if body_tuple in seen and len(body) > 0:
                pair_key = (seen[body_tuple], lineno)
                if pair_key not in reported_pairs:
                    issues.append(
                        (
                            "NAI-234",  # A1 renumber: was NAI-094 (detection NAI-094 = sys.path / os.environ mutation)
                            SEVERITY_WARNING,
                            f"Multiple loops in function '{func_node.name}' have identical "
                            f"bodies (lines {seen[body_tuple]} and {lineno})",
                        )
                    )
                    reported_pairs.add(pair_key)
            else:
                seen[body_tuple] = lineno

    return issues


def _check_comprehension_symmetry(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> list[Issue]:
    """Check for multiple comprehensions with identical structure."""
    issues: list[Issue] = []

    # Collect comprehensions
    comprehensions: list[tuple[int, str, str]] = []

    for node in ast.walk(func_node):
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            lineno = getattr(node, "lineno", 0)
            comp_type = type(node).__name__
            normalized = _normalize_ast(node)
            comprehensions.append((lineno, comp_type, normalized))

    # Check for duplicates of the same type
    if len(comprehensions) >= 2:
        seen: dict[tuple[str, str], int] = {}
        for lineno, comp_type, normalized in comprehensions:
            key = (comp_type, normalized)
            if key in seen:
                issues.append(
                    (
                        "NAI-235",  # A1 renumber: was NAI-096 (detection NAI-096 = assert as validation)
                        SEVERITY_INFO,
                        f"Multiple {comp_type}s in function '{func_node.name}' have "
                        f"identical structure (lines {seen[key]} and {lineno})",
                    )
                )
            else:
                seen[key] = lineno

    return issues


def check_arithmetic_symmetry(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> Optional[Issue]:
    """
    Check for arithmetic progression or symmetric patterns.

    Detects patterns in:
    - Numeric sequences in lists/tuples
    - Sequential comparison values in if/elif chains
    - Uniform string length patterns in if/elif chains
    (NAI-013)

    Args:
        func_node: The function AST node to analyze

    Returns:
        Issue tuple if suspicious pattern found, None otherwise
    """
    logger.debug("check_arithmetic_symmetry: analyzing %s", func_node.name)
    # Check if/elif comparison values first
    result = _check_comparison_patterns(func_node)
    if result is not None:
        logger.debug("check_arithmetic_symmetry: %s comparison pattern hit -> %s", func_node.name, result[0])
        return result

    # Check numeric sequences in lists/tuples
    sequences = _extract_numeric_sequences(func_node)
    logger.debug("check_arithmetic_symmetry: %s has %d numeric sequences", func_node.name, len(sequences))

    for lineno, nums in sequences:
        if len(nums) >= 3:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 4 — three terms define an arithmetic progression
            # Check for arithmetic progression
            if _is_arithmetic_progression(nums):
                return (
                    "NAI-013",
                    SEVERITY_MEDIUM,
                    (
                        f"Arithmetic progression pattern detected in function "
                        f"'{func_node.name}' at line {lineno}: {nums[:5]}..."
                        if len(nums) > 5
                        else f"Arithmetic progression pattern detected in function "
                        f"'{func_node.name}' at line {lineno}: {nums}"
                    ),
                )

            # Check for geometric progression
            if _is_geometric_progression(nums):
                return (
                    "NAI-013",
                    SEVERITY_MEDIUM,
                    (
                        f"Geometric progression pattern detected in function "
                        f"'{func_node.name}' at line {lineno}: {nums[:5]}..."
                        if len(nums) > 5
                        else f"Geometric progression pattern detected in function "
                        f"'{func_node.name}' at line {lineno}: {nums}"
                    ),
                )

            # Check for symmetric pattern (palindrome)
            if _is_symmetric(nums):
                return (
                    "NAI-013",
                    SEVERITY_MEDIUM,
                    f"Symmetric pattern detected in function "
                    f"'{func_node.name}' at line {lineno}: {nums}",
                )

    return None


def _check_comparison_patterns(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> Optional[Issue]:
    """
    Check for arithmetic progressions in if/elif comparison values.

    Looks at if/elif chains where conditions compare against sequential
    numeric or string values.
    """
    for node in ast.walk(func_node):
        if not isinstance(node, ast.If):
            continue

        # Collect comparison values from if/elif chain
        numeric_values: list[Union[int, float]] = []
        string_values: list[str] = []
        current: Optional[ast.If] = node
        lineno = node.lineno

        while current is not None:
            val = _extract_comparison_value(current.test)
            if val is not None:
                if isinstance(val, (int, float)):
                    numeric_values.append(val)
                elif isinstance(val, str):
                    string_values.append(val)

            # Follow elif chain
            if (
                current.orelse
                and len(current.orelse) == 1
                and isinstance(current.orelse[0], ast.If)
            ):
                current = current.orelse[0]
            else:
                break

        # Check numeric comparison values for arithmetic progression
        if len(numeric_values) >= 3:
            if _is_arithmetic_progression(numeric_values):
                return (
                    "NAI-013",
                    SEVERITY_MEDIUM,
                    f"Arithmetic progression pattern detected in function "
                    f"'{func_node.name}' at line {lineno}: "
                    f"comparison values {numeric_values}",
                )

        # Check string comparison values for uniform length
        if len(string_values) >= 3:
            lengths = [len(s) for s in string_values]
            if len(set(lengths)) == 1 and lengths[0] > 0:
                return (
                    "NAI-013",
                    SEVERITY_MEDIUM,
                    f"String length symmetry pattern detected in function "
                    f"'{func_node.name}' at line {lineno}: "
                    f"all comparison strings have length {lengths[0]}",
                )

    return None


def _extract_comparison_value(
    test: ast.AST,
) -> Optional[Union[int, float, str]]:
    """
    Extract the constant value from a comparison test node.

    Handles patterns like:
    - x == 1
    - x == "foo"
    """
    if not isinstance(test, ast.Compare):
        return None

    if len(test.comparators) != 1:
        return None

    # Check for == comparison
    if not isinstance(test.ops[0], ast.Eq):
        return None

    comparator = test.comparators[0]
    if isinstance(comparator, ast.Constant):
        if isinstance(comparator.value, (int, float, str)):
            return comparator.value

    return None


def _extract_numeric_sequences(
    func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> list[tuple[int, list[Union[int, float]]]]:
    """Extract sequences of numeric literals from the function."""
    sequences: list[tuple[int, list[Union[int, float]]]] = []

    for node in ast.walk(func_node):
        nums: list[Union[int, float]] = []
        lineno = getattr(node, "lineno", 0)

        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, (int, float)):
                    nums.append(elt.value)
                else:
                    # Non-numeric element, save what we have and reset
                    if len(nums) >= 4:
                        sequences.append((lineno, nums))
                    nums = []

            if len(nums) >= 4:
                sequences.append((lineno, nums))

        elif isinstance(node, ast.Call):
            # Check for range() calls with suspicious patterns
            if isinstance(node.func, ast.Name) and node.func.id == "range":
                if len(node.args) >= 2:
                    args = []
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                            args.append(arg.value)

                    if len(args) >= 2:
                        start, stop = args[0], args[1]
                        step = args[2] if len(args) > 2 else 1
                        if step != 0 and abs(stop - start) // abs(step) >= 4:
                            nums = list(range(start, stop, step))
                            if len(nums) >= 4:
                                sequences.append((lineno, nums))

    return sequences


def _is_arithmetic_progression(nums: list[Union[int, float]]) -> bool:
    """Check if numbers form an arithmetic progression."""
    if len(nums) < 3:
        return False

    diff = nums[1] - nums[0]
    if diff == 0:
        return False  # Not interesting if all same

    for i in range(2, len(nums)):
        if abs((nums[i] - nums[i - 1]) - diff) > 1e-9:
            return False

    return True


def _is_geometric_progression(nums: list[Union[int, float]]) -> bool:
    """Check if numbers form a geometric progression."""
    if len(nums) < 3:
        return False

    if nums[0] == 0:
        return False

    ratio = nums[1] / nums[0]
    if ratio == 1:
        return False  # Not interesting

    for i in range(2, len(nums)):
        if nums[i - 1] == 0:
            return False
        if abs((nums[i] / nums[i - 1]) - ratio) > 1e-9:
            return False

    return True


def _is_symmetric(nums: list[Union[int, float]]) -> bool:
    """Check if numbers form a symmetric (palindrome) pattern."""
    if len(nums) < 4:
        return False

    return nums == nums[::-1]


if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Detect suspicious structural symmetry in Python functions."
    )
    parser.add_argument("file", type=str, help="Python file to analyze")
    args = parser.parse_args()

    path = args.file
    try:
        source = open(path, encoding="utf-8").read()
        tree = ast.parse(source, filename=path)
    except (OSError, SyntaxError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    total_issues = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            issues = check_suspicious_symmetry(node)
            arith = check_arithmetic_symmetry(node)
            if arith:
                issues.append(arith)
            for rule_id, severity, message in issues:
                print(f"  [{rule_id}] {severity}: {message}")
                total_issues += 1

    if total_issues == 0:
        print(f"No symmetry issues in {path}")
    else:
        print(f"\n{total_issues} issue(s) found in {path}")
