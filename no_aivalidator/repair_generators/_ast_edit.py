"""Shared AST-edit helpers for the rewriters (moved from cheatsheet_intelligence/knowledge_base.py,
item 4, 2026-09-08). A rewriter locates the construct by AST and edits the ORIGINAL lines in
place by column, so formatting and comments survive; textwrap.dedent is used only to parse."""
from __future__ import annotations

import ast
import textwrap
from typing import Any, List, Optional


def func_node(code: str) -> Optional["ast.FunctionDef | ast.AsyncFunctionDef"]:
    """Parse the snippet and return the first function def, or None."""
    try:
        tree = ast.parse(textwrap.dedent(code))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
    except SyntaxError:
        pass
    return None


def snippet_pad(code: str) -> int:
    """Columns textwrap.dedent stripped: the common indent of a function block is its first
    non-blank line's indent, so dedented col_offsets + pad = original columns."""
    for line in code.splitlines():
        if line.strip():
            return len(line) - len(line.lstrip())
    return 0


def body_after_docstring(func: "ast.FunctionDef | ast.AsyncFunctionDef") -> List[Any]:  # callers read .test / .value off the statement they matched (was `List[Node]`, an undefined name)
    body = list(func.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


def head_insert_stmt(func: "ast.FunctionDef | ast.AsyncFunctionDef", lines: List[str],
                     pad: int = 0) -> Optional[ast.stmt]:
    """R1 (2026-09-30): THE statement a rewriter inserts above when it adds a line at the head of a
    function body — the first statement AFTER the docstring, so the docstring stays the body's first
    statement (a line inserted above it turns the docstring into a dead expression and `__doc__` into
    None). None when no row is safe to insert at: the body is only a docstring, the statement shares the
    `def` line (`def f(x): return x`) or the signature's closing line, or it shares the docstring's last
    line (`\"\"\"doc\"\"\"; x = 1`) — i.e. anything but whitespace precedes it on its row of `lines` (the
    snippet's own lines; `pad` = snippet_pad). A rewriter that gets None declines; it never falls back
    to `func.body[0]`."""
    after_doc = body_after_docstring(func)
    first = next(iter(after_doc), None)
    if first is None or first.lineno <= func.lineno:
        return None
    doc = func.body[0] if len(after_doc) < len(func.body) else None
    if doc is not None and first.lineno <= (doc.end_lineno or doc.lineno):
        return None
    row = first.lineno - 1
    if row >= len(lines) or lines[row][: pad + first.col_offset].strip():
        return None
    return first


def replace_cols(lines: List[str], row: int, start: int, end: int, text: str) -> None:
    """Replace lines[row][start:end] with text (row 0-based, columns absolute)."""
    lines[row] = lines[row][:start] + text + lines[row][end:]
