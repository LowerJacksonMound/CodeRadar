"""Where the fix goes — the statements a whole-function rule's evidence lives on (owner 2026-10-07 line precision;
M-142, 2026-10-08). A rule that judges the whole function (an unused parameter, a dead value, a constant return)
used to report only the `def` line; the infraction row, the Ranker and the agent then had no statement to look at.
These helpers name the statements: the function's own `return`s (where the result is assembled without the value),
where a dead value is stored, and a branch that names an unused parameter as a string (`if method == "occupants":`
while `occupants` is never read). Nested defs, lambdas and classes are not this function's statements.
"""
from __future__ import annotations

import ast
from typing import Iterable, Iterator, List, Set

_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _own_nodes(func: ast.AST) -> Iterator[ast.AST]:
    stack = list(ast.iter_child_nodes(func))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, _NESTED):
            stack.extend(ast.iter_child_nodes(n))


def return_lines(func: ast.AST) -> List[int]:
    return sorted({n.lineno for n in _own_nodes(func) if isinstance(n, ast.Return)})


def store_lines(func: ast.AST, names: Iterable[str]) -> List[int]:
    want: Set[str] = set(names)
    return sorted({n.lineno for n in _own_nodes(func)
                   if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id in want})


def literal_name_lines(func: ast.AST, names: Iterable[str]) -> List[int]:
    want: Set[str] = set(names)
    return sorted({n.lineno for n in _own_nodes(func)
                   if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value in want})


def unused_param_lines(func: ast.AST, names: Iterable[str]) -> List[int]:
    """An unused parameter: the returns built without it, and any branch that names it as a string."""
    names = list(names)
    return sorted(set(return_lines(func)) | set(literal_name_lines(func, names)))


def dead_value_lines(func: ast.AST, names: Iterable[str]) -> List[int]:
    """A dead value: where it is stored, and the returns it never reaches."""
    return sorted(set(store_lines(func, names)) | set(return_lines(func)))
