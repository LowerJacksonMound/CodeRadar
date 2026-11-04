"""
Structural fingerprinting for function analysis.

Provides functions to generate structural fingerprints for functions,
enabling duplicate detection that ignores variable names.
"""

import ast
import copy
import hashlib
import logging
from collections import defaultdict
from pathlib import Path
from typing import Union

import aiofiles

from utils.code_analysis.core import FunctionMetrics
from utils.code_analysis.extractor import MetricsExtractor, collect_method_ids

logger = logging.getLogger(__name__)


def fingerprint_function(metrics: FunctionMetrics) -> str:
    """
    Generate a structural fingerprint from FunctionMetrics.

    The fingerprint is a string representation of the function's structural
    metrics, ignoring variable names and function names.

    Format: p{params}_r{returns}_b{branches}_l{loops}_c{calls}_a{assigns}_d{depth}
    Optional suffixes: _async, _gen, _comp{n}

    Args:
        metrics: The FunctionMetrics object to fingerprint

    Returns:
        A string fingerprint representing the function's structure
    """
    fp = (
        f"p{metrics.params}_r{metrics.returns}_b{metrics.branches}"
        f"_l{metrics.loops}_c{metrics.calls}_a{metrics.assigns}"
        f"_d{metrics.nested_depth}"
    )

    if metrics.comprehensions > 0:
        fp += f"_comp{metrics.comprehensions}"
    if metrics.is_async:
        fp += "_async"
    if metrics.is_generator:
        fp += "_gen"

    return fp


async def fingerprint_all_functions(file_path: Path) -> dict[str, list[str]]:
    """
    Generate fingerprints for all functions in a Python file.

    Args:
        file_path: Path to the Python file to analyze

    Returns:
        Dictionary mapping fingerprints to lists of function names
    """
    logger.debug("fingerprint_all_functions: reading %s", file_path)
    try:
        async with aiofiles.open(file_path, encoding="utf-8") as f:
            source = await f.read()
    except (OSError, UnicodeDecodeError):
        logger.debug("fingerprint_all_functions: read error for %s", file_path)
        return {}

    result = _fingerprint_from_source(source)
    logger.debug("fingerprint_all_functions: %d unique fingerprints from %s", len(result), file_path)
    return result


def _fingerprint_from_source(source: str) -> dict[str, list[str]]:
    """
    Generate fingerprints from Python source code.

    Args:
        source: The Python source code string

    Returns:
        Dictionary mapping fingerprints to lists of function names
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        logger.debug("_fingerprint_from_source: SyntaxError, returning empty")
        return {}

    method_ids = collect_method_ids(tree)

    fingerprints: dict[str, list[str]] = defaultdict(list)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            class_context = id(node) in method_ids
            extractor = MetricsExtractor(node, class_context=class_context)
            fp = fingerprint_function(extractor.metrics)
            fingerprints[fp].append(node.name)
            logger.debug("_fingerprint_from_source: %s -> %s", node.name, fp)

    return dict(fingerprints)


def normalized_fingerprint(func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> str:
    """
    Generate a normalized fingerprint that ignores variable names.

    This creates a hash based on the AST structure with all names normalized,
    allowing detection of functions that are structurally identical but use
    different variable names.

    Args:
        func_node: The function AST node to fingerprint

    Returns:
        A hex string representing the normalized structural fingerprint

    FIX_47 (2026-09-17, I-03): the measurement is taken on a COPY. `_ASTNormalizer` is an
    `ast.NodeTransformer`, and `NodeTransformer.generic_visit` rewrites a node's list fields
    IN PLACE (`old_value[:] = new_values`) — so fingerprinting a caller's live tree renamed
    that tree's arguments and Name nodes to `_var_0`, `_var_1`, … behind the caller's back.
    The route's RCA-001 split-fake sweep ran after this stage and its callee names could
    therefore never match the failed rows (set 4b-26, run 80). Reading may not write: the
    hex is unchanged (normalization is a pure function of structure), the caller's tree is not.
    """
    normalizer = _ASTNormalizer()
    normalized = normalizer.visit(copy.deepcopy(func_node))
    ast_str = ast.dump(normalized)
    return hashlib.sha256(ast_str.encode()).hexdigest()


class _ASTNormalizer(ast.NodeTransformer):
    """
    AST transformer that normalizes variable names.

    Replaces all local variable names with generic placeholders while
    preserving the structure of the AST.
    """

    def __init__(self) -> None:
        self.name_map: dict[str, str] = {}
        self.counter = 0

    def _normalize_name(self, name: str) -> str:
        """Get or create a normalized name for a variable."""
        if name not in self.name_map:
            self.name_map[name] = f"_var_{self.counter}"
            self.counter += 1
        return self.name_map[name]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Normalize function definition, keeping structure but normalizing names."""
        # Normalize function name
        new_node = ast.FunctionDef(
            name="_func",
            args=self.visit(node.args),
            body=[self.visit(stmt) for stmt in node.body],
            decorator_list=[],  # Ignore decorators for structural comparison
            returns=self.visit(node.returns) if node.returns else None,
            type_comment=None,
        )
        return ast.fix_missing_locations(new_node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        """Normalize async function definition."""
        new_node = ast.AsyncFunctionDef(
            name="_func",
            args=self.visit(node.args),
            body=[self.visit(stmt) for stmt in node.body],
            decorator_list=[],
            returns=self.visit(node.returns) if node.returns else None,
            type_comment=None,
        )
        return ast.fix_missing_locations(new_node)

    def visit_arg(self, node: ast.arg) -> ast.arg:
        """Normalize argument names."""
        return ast.arg(
            arg=self._normalize_name(node.arg),
            annotation=self.visit(node.annotation) if node.annotation else None,
            type_comment=None,
        )

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """Normalize variable names."""
        return ast.Name(
            id=self._normalize_name(node.id),
            ctx=node.ctx,
        )

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        """Keep constants but normalize their representation."""
        # Normalize numeric constants to type indicators
        # bool check must precede int because bool is a subclass of int
        if isinstance(node.value, bool):
            return node
        elif isinstance(node.value, int):
            return ast.Constant(value=0)
        elif isinstance(node.value, float):
            return ast.Constant(value=0.0)
        elif isinstance(node.value, str):
            return ast.Constant(value="")
        elif isinstance(node.value, bytes):
            return ast.Constant(value=b"")
        elif node.value is None:
            return node
        return node

    def visit_alias(self, node: ast.alias) -> ast.alias:
        """Normalize import aliases."""
        return ast.alias(
            name=node.name,  # Keep module names
            asname=self._normalize_name(node.asname) if node.asname else None,
        )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        """Normalize exception handler names."""
        return ast.ExceptHandler(
            type=self.visit(node.type) if node.type else None,
            name=self._normalize_name(node.name) if node.name else None,
            body=[self.visit(stmt) for stmt in node.body],
        )

    def generic_visit(self, node: ast.AST) -> ast.AST:
        """Default visitor for other nodes."""
        return super().generic_visit(node)


async def check_normalized_duplicates(file_path: Path) -> dict[str, list[str]]:
    """
    Find functions with identical normalized structure in a file.

    Args:
        file_path: Path to the Python file to analyze

    Returns:
        Dictionary mapping normalized fingerprints to lists of function names
        (only includes entries with multiple functions)
    """
    logger.debug("check_normalized_duplicates: reading %s", file_path)
    try:
        async with aiofiles.open(file_path, encoding="utf-8") as f:
            source = await f.read()
    except (OSError, UnicodeDecodeError):
        logger.debug("check_normalized_duplicates: read error for %s", file_path)
        return {}

    result = _check_normalized_from_source(source)
    logger.debug("check_normalized_duplicates: %d duplicate groups in %s", len(result), file_path)
    return result


def _check_normalized_from_source(source: str) -> dict[str, list[str]]:
    """
    Find normalized duplicates from Python source code.

    Args:
        source: The Python source code string

    Returns:
        Dictionary mapping normalized fingerprints to lists of function names
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
        logger.warning("reported, not swallowed (cut 3): %s: %r", '_check_normalized_from_source', _e)
        return {}

    fingerprints: dict[str, list[str]] = defaultdict(list)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fp = normalized_fingerprint(node)
            fingerprints[fp].append(node.name)

    # Only return fingerprints with multiple functions (actual duplicates)
    return {fp: names for fp, names in fingerprints.items() if len(names) > 1}


if __name__ == "__main__":
    import argparse
    import sys

    # Enable logging for CLI
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Generate structural fingerprints for functions in a Python file."
    )
    parser.add_argument("file", type=Path, help="Python file to analyze")
    parser.add_argument(
        "--normalized", action="store_true",
        help="Show normalized fingerprints (for duplicate detection)"
    )
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    source = args.file.read_text()

    if args.normalized:
        # Use sync helper for normalized duplicates
        dups = _check_normalized_from_source(source)
        if not dups:
            print(f"✓ No normalized duplicates in {args.file}")
        else:
            print(f"Normalized duplicates in {args.file}:")
            for fp, names in dups.items():
                print(f"  {fp[:16]}... -> {', '.join(names)}")
    else:
        # Use sync helper for fingerprints
        fingerprints = _fingerprint_from_source(source)
        print(f"Fingerprints for {args.file} ({len(fingerprints)} functions):")
        for fp, names in fingerprints.items():
            print(f"  {fp} -> {', '.join(names)}")
