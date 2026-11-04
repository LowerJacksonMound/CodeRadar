"""
Cheatsheet Reviewer — under cheatsheets: parses and safety-scans a possible solution (what remains after item 2 / FIX 11, 2026-09-08).

Only SecurityVisitor + CodeAnalyzer.analyze live here now. The Builder daemon runs
CodeAnalyzer.analyze on every candidate BEFORE the Ranker decides and turns the result
into observation tokens (safety=clean | safety=<issue>, quality=<note>); nothing here
issues a verdict. The reviewer's verdict machinery (ReviewStatus, CheatsheetReviewer,
CheatsheetGate, ReviewResult, GateDecision, configs, helpers) is archived at
.archive/archived_20260908/no_aivalidator/cheatsheets/cheatsheet_reviewer.py — THE RANKER
is the one decision point (owner ruling).
"""

from __future__ import annotations

import ast
import logging
import re
import sys
import textwrap
from typing import Any, Callable, Final, TypeVar


# =============================================================================
# CONSTANTS
# =============================================================================

# (HASH_SIGNATURE_LIMIT / STRATEGY_TYPE_LIMIT / MAX_EXTRACTION_DEPTH / MAX_PARTITION_DEPTH archived with the reviewer, 2026-09-08)

# =============================================================================
# INSTRUMENTATION
# =============================================================================

_F = TypeVar("_F", bound=Callable[..., Any])

# Typed defaults defined first so mypy always sees proper signatures.
def trace(func: _F) -> _F:
    return func

def trace_as_workflow(name: str) -> Callable[[_F], _F]:
    def decorator(func: _F) -> _F:
        return func
    return decorator

try:
    from flow_tracer import trace, trace_as_workflow  # type: ignore[no-redef]
except ImportError:
    pass

try:
    from shared.instrumentation.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    class _KwargsLogger(logging.LoggerAdapter):
        _STANDARD_KEYS = frozenset({'exc_info', 'stack_info', 'stacklevel', 'extra'})
        def process(self, msg, kwargs):
            extra_kw = {k: v for k, v in list(kwargs.items())
                        if k not in self._STANDARD_KEYS}
            for k in extra_kw:
                kwargs.pop(k)
            if extra_kw:
                parts = ", ".join(f"{k}={v}" for k, v in extra_kw.items())
                msg = f"{msg} [{parts}]"
            return msg, kwargs

    logger = _KwargsLogger(logging.getLogger(__name__), {})


# Public API — the Reviewer: parse + safety scan, no verdict.
__all__ = [
    "SecurityVisitor",
    "CodeAnalyzer",
    "PLACEHOLDER_REGEX",
    "TRUNCATION_REGEX",
]


# =============================================================================
# CONSTANTS & PATTERNS
# =============================================================================

# Pre-compiled regex patterns
def _compile_patterns(patterns: list[str]) -> re.Pattern[str]:
    """Compile multiple patterns into a single regex."""
    return re.compile('|'.join(f'(?:{p})' for p in patterns), re.IGNORECASE)


PLACEHOLDER_REGEX: Final = _compile_patterns([
    r'TODO[:\s]', r'FIXME[:\s]', r'XXX[:\s]', r'HACK[:\s]',
    r'your[_\s]?code[_\s]?here', r'implement[_\s]?this',
    r'placeholder', r'example[_\s]?code', r'\.\.\.\s*#',
    r'pass\s*#\s*(TODO|FIXME|placeholder)', r'raise\s+NotImplementedError',
    r'<your[_\s]', r'\[insert\s', r'lorem\s+ipsum',
])

TRUNCATION_REGEX: Final = _compile_patterns([
    r'\.{3,}$', r'\[truncated\]', r'\[continued\]', r'\[more\]',
    r'<truncated>', r'…$', r'\[\.\.\.\]$',
])


# =============================================================================
# STATIC ANALYSIS (AST)
# =============================================================================

class SecurityVisitor(ast.NodeVisitor):
    """
    AST Visitor to detect unsafe code patterns and AI artifacts.
    More reliable than regex for code analysis.

    Fix C1+C2+C3: Tiered severity model.
    - "Security:" issues → ERRORS (reject the cheatsheet)
    - "Warning:" issues  → WARNINGS (flag but allow)
    - "Quality:" issues  → WARNINGS (flag but allow)

    Common builtins (open, getattr, hasattr, etc.) and standard-library
    modules (sys, requests, http) are common in repair cheatsheets and
    should not cause rejection.
    """

    # --- Tier 1: TRUE DANGERS (→ Security error, causes rejection) ---
    BANNED_FUNCTIONS: Final = frozenset({
        'eval', 'exec', 'compile', '__import__',
    })

    DANGEROUS_OS_METHODS: Final = frozenset({
        'system', 'popen', 'remove', 'rmdir', 'removedirs',
        'unlink', 'execl', 'execle', 'execlp', 'execlpe',
        'execv', 'execve', 'execvp', 'execvpe', 'spawnl',
    })

    DANGEROUS_MODULES: Final = frozenset({
        'pickle', 'shelve', 'marshal', 'ctypes',
    })

    # --- Tier 2: WORTH FLAGGING (→ Warning, does NOT reject) ---
    # Warn tier (renamed 2026-09-08 with FIX 11's close: the reviewer's middle verdict is gone;
    # these lists only feed "Warning:" observations the Ranker reads as context).
    WARN_TIER_FUNCTIONS: Final = frozenset({
        'globals', 'locals', 'breakpoint', 'exit', 'quit',
    })

    WARN_TIER_MODULES: Final = frozenset({
        'os', 'subprocess', 'shutil', 'socket', 'ftplib',
    })

    # Common builtins that are FINE in repair code (no flag at all):
    # open, input, help, getattr, hasattr, setattr, delattr, vars
    # sys, requests, urllib, http — standard library, common in fixes

    # --- Tier 3: PLACEHOLDER FUNCTIONS (→ Quality warning) ---
    PLACEHOLDER_FUNCTIONS: Final = frozenset({
        'do_something', 'process_data', 'handle_error',
        'perform_action', 'execute_task', 'run_operation',
        'process_input', 'handle_request', 'main_logic',
    })

    # Dunder attributes that are common and safe in Python code
    SAFE_DUNDERS: Final = frozenset({
        '__init__', '__str__', '__repr__', '__len__', '__iter__',
        '__next__', '__enter__', '__exit__', '__call__', '__name__',
        '__class__', '__dict__', '__doc__', '__module__', '__file__',
        '__all__', '__slots__', '__getitem__', '__setitem__',
        '__delitem__', '__contains__', '__hash__', '__eq__',
        '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
        '__add__', '__sub__', '__mul__', '__truediv__',
        '__bool__', '__int__', '__float__', '__abs__',
        '__new__', '__del__', '__get__', '__set__',
        '__post_init__', '__annotations__', '__bases__',
        '__mro__', '__subclasses__', '__wrapped__',
    })

    # Dunder attributes that infraction scrutiny
    DANGEROUS_DUNDERS: Final = frozenset({
        '__builtins__', '__import__', '__subclasshook__',
        '__reduce__', '__reduce_ex__', '__getstate__',
        '__setstate__',
    })

    def __init__(self) -> None:
        self.issues: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for security issues."""
        # Direct function calls: eval(), exec()
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in self.BANNED_FUNCTIONS:
                self.issues.append(
                    f"Security: Banned function '{name}' detected"
                )
            elif name in self.WARN_TIER_FUNCTIONS:
                self.issues.append(
                    f"Warning: Flagged function '{name}' detected"
                )
            elif name in self.PLACEHOLDER_FUNCTIONS:
                self.issues.append(
                    f"Quality: Generic placeholder function '{name}' detected"
                )

        # Attribute calls: os.system(), subprocess.run()
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                method = node.func.attr

                if module == 'os' and method in self.DANGEROUS_OS_METHODS:
                    self.issues.append(
                        f"Security: Dangerous call 'os.{method}' detected"
                    )
                elif module == 'subprocess':
                    self.issues.append(
                        f"Warning: Subprocess call 'subprocess.{method}' detected"
                    )
                elif module == 'sys' and method in {'exit', 'setprofile', 'settrace'}:
                    self.issues.append(
                        f"Warning: System call 'sys.{method}' detected"
                    )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Check imports — tier-based: dangerous → error, flagged → warning."""
        for alias in node.names:
            if alias.name in self.DANGEROUS_MODULES:
                self.issues.append(
                    f"Security: Dangerous import '{alias.name}'"
                )
            elif alias.name in self.WARN_TIER_MODULES:
                self.issues.append(
                    f"Warning: Flagged import '{alias.name}'"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check 'from X import Y' — tier-based."""
        if node.module:
            if node.module in self.DANGEROUS_MODULES:
                self.issues.append(
                    f"Security: Dangerous import from '{node.module}'"
                )
            elif node.module in self.WARN_TIER_MODULES:
                self.issues.append(
                    f"Warning: Flagged import from '{node.module}'"
                )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check dunder access — only flag dangerous ones, ignore common safe ones."""
        if node.attr.startswith('__') and node.attr.endswith('__'):
            if node.attr in self.DANGEROUS_DUNDERS:
                self.issues.append(
                    f"Security: Dangerous dunder access '{node.attr}' detected"
                )
            elif node.attr not in self.SAFE_DUNDERS:
                # Unknown dunder — flag as warning, not error
                self.issues.append(
                    f"Warning: Unusual dunder access '{node.attr}' detected"
                )
        self.generic_visit(node)


class CodeAnalyzer:
    """Performs single-pass static analysis on code snippets."""

    @staticmethod
    @trace
    def analyze(
        code: str, max_length: int = 10_000
    ) -> tuple[bool, list[str], list[str]]:
        """
        Analyze code for syntax, security, and quality issues.

        Returns:
            (is_valid_syntax, security_issues, quality_issues)
        """
        logger.debug("CodeAnalyzer.analyze called", code_len=len(code) if code else 0)

        if not code or not code.strip():
            return False, [], ["Empty code"]

        if len(code) > max_length:
            return False, [], [f"Code too long ({len(code)} > {max_length} chars)"]

        # Parse AST — dedent so indented snippets extracted from source pass
        code = textwrap.dedent(code)
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, [], [
                f"Syntax error at line {e.lineno}: {e.msg}"
            ]
        except RecursionError:
            return False, [], ["Code structure too deeply nested"]
        except Exception as e:
            return False, [], [f"Parse error: {type(e).__name__}: {str(e)}"]

        # Run security visitor
        visitor = SecurityVisitor()
        try:
            visitor.visit(tree)
        except RecursionError:
            return False, [], ["AST too deeply nested"]
        except Exception as e:
            logger.exception("Unexpected error during AST analysis")
            return False, [], [f"Analysis error: {type(e).__name__}"]

        security_issues = [i for i in visitor.issues if i.startswith("Security:")]
        # Fix C1+C2+C3: "Warning:" tier goes to quality_issues (warnings, not errors)
        quality_issues = [
            i for i in visitor.issues
            if i.startswith("Quality:") or i.startswith("Warning:")
        ]

        # Regex checks for patterns in comments/strings (AST doesn't catch these)
        if PLACEHOLDER_REGEX.search(code):
            quality_issues.append("Contains placeholder patterns (TODO, FIXME, etc)")

        if TRUNCATION_REGEX.search(code):
            quality_issues.append("Code appears truncated")

        # Fix R9: Result summary
        logger.debug(
            "CodeAnalyzer.analyze result",
            valid_syntax=True,
            n_security=len(security_issues),
            n_quality=len(quality_issues),
        )
        return True, security_issues, quality_issues


# ── FIX_42 (owner ruling 2026-09-15, packet §F): the five STATIC observations ─────────────────────
# Intent first, then every entity's observations, the Ranker decides once. The Reviewer reads the
# candidate's after_code AGAINST the row's before_code and states five facts as observation tokens —
# never a verdict, never a threshold that decides. SolutionRanker weighs them (below the intent block).
#   flow=        control-flow paths of the candidate vs the original
#   complexity=  loop nesting depth + per-iteration / whole-input allocation vs the original
#   idiom=       a hand-rolled loop the stdlib provides (any/all/sorted/max/min/Counter/dict.get/comprehension)
#   deps=        imports the candidate ADDS (stdlib / third-party) + syntax newer than the original needs
#   defensive=   input guards the candidate adds or removes (None / empty / missing_file / type / key)
# A side that does not parse reads `unreadable:<side>` on every token (the Builder's parse= token
# already carries the reason for the after side).
# A prescription's shape parses once its `<placeholders>` are names (FIX_43 (b), Call A) — its placeholder-only
# statements are prose: `opaque:N` rides every token of a side that has them.

STATIC_OBSERVATION_ORDER: Final[tuple[str, ...]] = ("flow", "complexity", "idiom", "deps", "defensive", "readability", "traps")   # FIX_43a: + readability, traps
_STDLIB_NAMES: Final[frozenset[str]] = frozenset(getattr(sys, "stdlib_module_names", ()))
_LOOP_NODES: Final[tuple[type, ...]] = (ast.For, ast.AsyncFor, ast.While)
_COMP_NODES: Final[tuple[type, ...]] = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_COPY_CALLS: Final[frozenset[str]] = frozenset({"list", "dict", "set", "tuple", "sorted", "copy", "deepcopy", "reversed"})
_IDIOM_BUILTINS: Final[frozenset[str]] = frozenset({"any", "all", "sorted", "max", "min", "sum", "Counter", "enumerate", "zip"})
_CMP_TEXT: Final[dict[type, str]] = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!="}
_MISSING_FILE_EXC: Final[frozenset[str]] = frozenset({"FileNotFoundError", "OSError", "IOError", "PermissionError"})
# syntax features by the Python version that introduced them (the after side is read for what it NEEDS)
_SYNTAX_VERSION: Final[tuple[tuple[str, str], ...]] = (
    ("Match", "3.10"), ("TryStar", "3.11"), ("TypeAlias", "3.12"), ("TypeVar", "3.12"), ("ParamSpec", "3.12"),
    ("TypeVarTuple", "3.12"), ("NamedExpr", "3.8"),
)


# ---- FIX_43 (b), Call A (owner ruling 2026-09-16, RANKER_METHODS_RULING_2026-09-15.md): a prescription's SHAPE is
# read as code. Every `<placeholder>` (nested too) and a bare `...` in a parameter list is a plain name; a statement
# that is ENTIRELY a placeholder is opaque prose — it is replaced by `pass` so the block still parses and counted, and
# every token of that side carries `opaque:N` (the reading of a partly-prose side is partial; the Ranker's tables
# weigh `opaque` like `unreadable`). A shape whose every statement is code (NAI-127's) reads exactly like code.
_PLACEHOLDER_NAME: Final[str] = "placeholder"
# a placeholder starts right after `<` with a non-space, non-`=` character and ends right before `>` with a
# non-space character — so `a < b and c > d`, `<=` and `->` are never taken for one
_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(r"<(?=[^\s=<>])[^<>]*?(?<=\S)>")
_DEF_HEADER_RE: Final[re.Pattern[str]] = re.compile(r"^(\s*(?:async\s+)?def\s+\w+\s*\()(.*)(\)\s*(?:->\s*[^:]+)?:\s*(?:#.*)?)$")
_BLOCK_HEADER_RE: Final[re.Pattern[str]] = re.compile(r"^\s*(if|elif|else|for|while|with|try|except|finally|def|async|class|match|case)\b.*:\s*(#.*)?$")


def _collapse(text: str) -> str:
    prev = None
    while prev != text:   # nested placeholders collapse inside-out
        prev = text
        text = _PLACEHOLDER_RE.sub(_PLACEHOLDER_NAME, text)
    return text


def _def_params(params: str) -> str:
    """A def header's parameter list with `...` as a name and every repeated name made distinct (`(<param>, ...)` →
    `(placeholder, placeholder_2)`), so the header parses."""
    seen: dict[str, int] = {}
    out: list[str] = []
    for raw in params.split(","):
        item = raw.strip()
        if not item:
            continue
        if item == "...":
            item = _PLACEHOLDER_NAME
        name = re.match(r"\*{0,2}(\w+)", item)
        if name:
            n = name.group(1)
            seen[n] = seen.get(n, 0) + 1
            if seen[n] > 1:
                item = item.replace(n, f"{n}_{seen[n]}", 1)
        out.append(item)
    return ", ".join(out)


def _shape_to_code(code: str) -> tuple[str, int]:
    """The shape with its placeholders as names and its placeholder-only statements as `pass`; the count of those.
    Also read: a `...`-prose line (`... <first read of x> ...`) is opaque; a block header the shape leaves without a
    body (`if math.isclose(<a>, <b>):` as the whole shape) gets `pass` so the header's facts can be read."""
    opaque = 0
    out: list[str] = []
    lines = code.splitlines()
    for i, line in enumerate(lines):
        body = line.split("#", 1)[0] if "#" in line and not line.lstrip().startswith("#") else line
        stripped = body.strip()
        indent = line[: len(line) - len(line.lstrip())]
        collapsed = _collapse(stripped)
        if stripped and ((stripped.startswith("<") and collapsed == _PLACEHOLDER_NAME)
                         or (stripped.startswith("...") and stripped.endswith("...") and len(stripped) > 3)):
            opaque += 1
            out.append(indent + "pass")
            continue
        text = _collapse(line)
        m = _DEF_HEADER_RE.match(text)
        if m:
            text = m.group(1) + _def_params(m.group(2)) + m.group(3)
        out.append(text)
        if _BLOCK_HEADER_RE.match(body):
            nxt = next((l for l in lines[i + 1:] if l.strip()), None)
            if nxt is None or len(nxt) - len(nxt.lstrip()) <= len(indent):
                out.append(indent + "    pass")   # a header-only shape: the block it opens is left to the repair agent
    return "\n".join(out), opaque


def _parse_side(code: str) -> ast.AST | None:
    """The side's tree, or None when it cannot be read (an observation, not a failure). A side that does not parse as
    written but does once its `<placeholders>` are names (a prescription's shape) is read that way, with the count of
    its placeholder-only statements on the tree as `_opaque` (FIX_43 (b), Call A)."""
    if code is None or not code.strip():
        return None
    text = textwrap.dedent(code)
    try:
        tree = ast.parse(text)
        tree._opaque = 0   # type: ignore[attr-defined]
        return tree
    except (SyntaxError, ValueError, RecursionError):
        pass
    if not (_PLACEHOLDER_RE.search(text) or "..." in text or _BLOCK_HEADER_RE.search(text)):
        return None
    shaped, opaque = _shape_to_code(text)
    try:
        tree = ast.parse(shaped)
    except (SyntaxError, ValueError, RecursionError):
        return None
    tree._opaque = opaque   # type: ignore[attr-defined]
    return tree


def _walk_with_loop_depth(tree: ast.AST):
    """Yield (node, loop_depth) over the tree; a nested def / lambda / class is another row (not descended)."""
    stack: list[tuple[ast.AST, int, bool]] = [(tree, 0, True)]
    while stack:
        node, nest, top = stack.pop()
        yield node, nest
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and not top:
                continue
            inner = nest + (1 if isinstance(child, _LOOP_NODES + _COMP_NODES) else 0)
            stack.append((child, inner, False))


_CMP_FLIP: Final[dict[type, type]] = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}


def _is_threshold(node: ast.AST) -> bool:
    """A comparison side that is a threshold: a number, or a constant-style NAME (MAX_RETRIES)."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        node = node.operand
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
    return bool(name) and name.isupper()


def _flow_facts(tree: ast.AST) -> dict[str, Any]:
    """Path facts of one side: returns / raises inside loops, terminal statement, branch and loop
    counts, break/continue, the comparison operators used as loop bounds."""
    facts: dict[str, Any] = {"return_in_loop": 0, "raise_in_loop": 0, "branches": 0, "loops": 0,
                             "break_continue": 0, "terminal": False, "bounds": set()}
    bodies = [n.body for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [getattr(tree, "body", [])]
    for body in bodies:
        if body and isinstance(body[-1], (ast.Return, ast.Raise)):
            facts["terminal"] = True
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._cr_parent = parent  # type: ignore[attr-defined]
    for node, nest in _walk_with_loop_depth(tree):
        if isinstance(node, ast.Return) and nest:
            facts["return_in_loop"] += 1
        elif isinstance(node, ast.Raise) and nest:
            facts["raise_in_loop"] += 1
        elif isinstance(node, ast.If):
            facts["branches"] += 1
        elif isinstance(node, _LOOP_NODES):
            facts["loops"] += 1
            test = node.test if isinstance(node, ast.While) else None
            if isinstance(test, ast.Compare):
                for op in test.ops:
                    facts["bounds"].add(_CMP_TEXT.get(type(op), "?"))
            it = getattr(node, "iter", None)
            if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id == "range":
                for a in it.args:
                    if isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Sub)):
                        facts["bounds"].add("range+1" if isinstance(a.op, ast.Add) else "range-1")
        elif isinstance(node, (ast.Break, ast.Continue)):
            facts["break_continue"] += 1
        # M-128 (owner 2026-10-08): a threshold is a bound wherever it sits — an `if` test, a return, an assignment,
        # a comprehension filter — not only a `while` test; and a `range(... ± 1)` argument wherever the range is.
        # The operator is normalised so the constant / upper-case name is on the right (`50 <= t` reads `>=`).
        if isinstance(node, ast.Compare) and not isinstance(getattr(node, "_cr_parent", None), ast.While):
            sides = [node.left, *node.comparators]
            for j, op in enumerate(node.ops):
                if type(op) not in _CMP_TEXT:
                    continue
                lhs, rhs = sides[j], sides[j + 1]
                if _is_threshold(rhs):
                    facts["bounds"].add(_CMP_TEXT[type(op)])
                elif _is_threshold(lhs):
                    facts["bounds"].add(_CMP_TEXT[_CMP_FLIP.get(type(op), type(op))])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "range" \
                and not isinstance(getattr(node, "_cr_parent", None), _LOOP_NODES):
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Sub)) \
                        and isinstance(arg.right, ast.Constant) and arg.right.value in {1}:
                    facts["bounds"].add("range+1" if isinstance(arg.op, ast.Add) else "range-1")
    return facts


def _flow_token(before: ast.AST | None, after: ast.AST | None) -> str:
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    b, a = _flow_facts(before), _flow_facts(after)
    changes: list[str] = []
    if a["return_in_loop"] and not b["return_in_loop"]:
        changes.append("return_moved_into_loop")
    elif b["return_in_loop"] and not a["return_in_loop"]:
        changes.append("return_moved_out_of_loop")
    if a["raise_in_loop"] and not b["raise_in_loop"]:
        changes.append("raise_moved_into_loop")
    if b["terminal"] and not a["terminal"]:
        changes.append("terminal_lost")
    elif a["terminal"] and not b["terminal"]:
        changes.append("terminal_added")
    if a["loops"] != b["loops"]:
        changes.append("loop_added" if a["loops"] > b["loops"] else "loop_removed")
    if a["branches"] != b["branches"]:
        d = a["branches"] - b["branches"]
        changes.append(f"branch_added:{d}" if d > 0 else f"branch_removed:{-d}")
    if a["break_continue"] != b["break_continue"]:
        changes.append("early_exit_added" if a["break_continue"] > b["break_continue"] else "early_exit_removed")
    if a["bounds"] != b["bounds"]:
        changes.append("bound_changed:" + "/".join(sorted(b["bounds"]) or ["-"]) + "→" + "/".join(sorted(a["bounds"]) or ["-"]))
    return "+".join(changes) if changes else "same_paths"


def _complexity_facts(tree: ast.AST) -> tuple[int, int, int]:
    """(max loop nesting, copy calls inside a loop, whole-value copies at loop depth 0)."""
    nest_max, copies_in_loop, copies_top = 0, 0, 0
    for node, nest in _walk_with_loop_depth(tree):
        nest_max = max(nest_max, nest)
        is_copy = (isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in _COPY_CALLS)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in ("copy", "deepcopy"))))
        is_slice_copy = (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
                         and node.slice.lower is None and node.slice.upper is None and node.slice.step is None)
        if is_copy or is_slice_copy:
            if nest:
                copies_in_loop += 1
            else:
                copies_top += 1
    return nest_max, copies_in_loop, copies_top


def _complexity_token(before: ast.AST | None, after: ast.AST | None) -> str:
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    (bn, bl, bt), (an, al, at) = _complexity_facts(before), _complexity_facts(after)
    parts: list[str] = []
    if an != bn:
        parts.append(f"deeper:{an}" if an > bn else f"shallower:{an}")
    if al > bl:
        parts.append("copies_in_loop")
    if at > bt:
        parts.append("copies_input")
    return "+".join(parts) if parts else "same"


def _hand_rolled(tree: ast.AST) -> set[str]:
    """Hand-rolled forms of things the stdlib provides, by the builtin's name."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            body = node.body
            # flag loop: for x in xs: if cond: flag = True; break   → any / all
            for st in body:
                if isinstance(st, ast.If) and any(isinstance(b, ast.Assign) and isinstance(b.value, ast.Constant)
                                                  and isinstance(b.value.value, bool) for b in st.body):
                    found.add("any")
                # running max / min: if x > best: best = x  (the assigned value is one operand of the test)
                if isinstance(st, ast.If) and isinstance(st.test, ast.Compare) and len(st.test.ops) == 1 \
                        and isinstance(st.test.ops[0], (ast.Gt, ast.Lt, ast.GtE, ast.LtE)):
                    operands = {getattr(st.test.left, "id", None), getattr(st.test.comparators[0], "id", None)} - {None}
                    if any(isinstance(b, ast.Assign) and isinstance(b.value, ast.Name) and b.value.id in operands
                           and getattr(b.targets[0], "id", None) in operands for b in st.body):
                        found.add("max" if isinstance(st.test.ops[0], (ast.Gt, ast.GtE)) else "min")
                # manual count: if k in d: d[k] += 1 else: d[k] = 1
                if isinstance(st, ast.If) and isinstance(st.test, ast.Compare) and len(st.test.ops) == 1 \
                        and isinstance(st.test.ops[0], ast.In) and st.orelse \
                        and any(isinstance(b, ast.AugAssign) and isinstance(b.target, ast.Subscript) for b in st.body):
                    found.add("Counter")
            # build-by-append: the loop body is one append (or one guarded append)  → comprehension
            only = body[0] if len(body) == 1 else None
            if isinstance(only, ast.If) and len(only.body) == 1 and not only.orelse:
                only = only.body[0]
            if isinstance(only, ast.Expr) and isinstance(only.value, ast.Call) \
                    and isinstance(only.value.func, ast.Attribute) and only.value.func.attr in ("append", "add"):
                found.add("comprehension")
            # accumulate by += over the loop → sum
            if len(body) == 1 and isinstance(body[0], ast.AugAssign) and isinstance(body[0].op, ast.Add) \
                    and isinstance(body[0].value, ast.Name):
                found.add("sum")
            # nested loop with a swap → sorted
            for inner in body:
                if isinstance(inner, (ast.For, ast.While)) and any(
                        isinstance(b, ast.Assign) and isinstance(b.targets[0], ast.Tuple) and isinstance(b.value, ast.Tuple)
                        for st2 in inner.body for b in ([st2] + (st2.body if isinstance(st2, ast.If) else []))):
                    found.add("sorted")
        # try: v = d[k] except KeyError: v = default  → dict.get
        if isinstance(node, ast.Try) and any(h.type is not None and getattr(h.type, "id", "") == "KeyError" for h in node.handlers) \
                and any(isinstance(b, ast.Assign) and isinstance(b.value, ast.Subscript) for b in node.body):
            found.add("dict.get")
    return found


def _builtins_used(tree: ast.AST) -> set[str]:
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _IDIOM_BUILTINS:
                used.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
                used.add("dict.get")
        elif isinstance(node, _COMP_NODES):
            used.add("comprehension")
    return used


def _idiom_token(before: ast.AST | None, after: ast.AST | None) -> str:
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    hb, ha = _hand_rolled(before), _hand_rolled(after)
    ub, ua = _builtins_used(before), _builtins_used(after)
    parts: list[str] = []
    replaced = sorted((hb - ha) & ua)            # the candidate replaced a hand-rolled form with the builtin
    reimplemented = sorted(ha - hb)              # the candidate hand-rolls something the original did not
    if replaced:
        parts.append("builtin_used:" + ",".join(replaced))
    if reimplemented:
        parts.append("reimplements:" + ",".join(reimplemented))
    return "+".join(parts) if parts else "same"


def _imports_of(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    names.discard(_PLACEHOLDER_NAME)   # FIX_43 (b): a shape's `import <mod>` names no module
    return names


def _syntax_needs(tree: ast.AST) -> str:
    """The newest Python the tree's syntax needs ("" when nothing version-specific is used)."""
    present = {type(n).__name__ for n in ast.walk(tree)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and getattr(node, "type_params", None):
            present.add("TypeVar")
    needs = [v for name, v in _SYNTAX_VERSION if name in present]
    return max(needs, key=lambda v: tuple(int(x) for x in v.split("."))) if needs else ""


def _deps_token(before: ast.AST | None, after: ast.AST | None) -> str:
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    added = sorted(_imports_of(after) - _imports_of(before))
    third = [n for n in added if n not in _STDLIB_NAMES]
    parts: list[str] = []
    if not added:
        parts.append("none_added")
    elif not third:
        parts.append("stdlib_only")
    else:
        parts.append("third_party:" + ",".join(third))
    nb, na = _syntax_needs(before), _syntax_needs(after)
    if na and (not nb or tuple(int(x) for x in na.split(".")) > tuple(int(x) for x in nb.split("."))):
        parts.append(f"needs_py:{na}")
    return "+".join(parts)


def _guard_kinds(tree: ast.AST) -> set[str]:
    kinds: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            t = node.test
            if isinstance(t, ast.Compare) and any(isinstance(c, ast.Constant) and c.value is None for c in t.comparators):
                kinds.add("None")
            elif isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not) and isinstance(t.operand, ast.Name):
                kinds.add("empty")
            elif isinstance(t, ast.Compare) and isinstance(t.left, ast.Call) and getattr(t.left.func, "id", "") == "len":
                kinds.add("empty")
            elif isinstance(t, ast.Call) and getattr(t.func, "id", "") == "isinstance":
                kinds.add("type")
            elif isinstance(t, ast.Call) and getattr(t.func, "attr", "") in ("exists", "isfile", "is_file"):
                kinds.add("missing_file")
            elif isinstance(t, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in t.ops):
                kinds.add("key")
        elif isinstance(node, ast.ExceptHandler) and node.type is not None:
            names = [getattr(e, "id", getattr(e, "attr", "")) for e in (node.type.elts if isinstance(node.type, ast.Tuple) else [node.type])]
            if any(n in _MISSING_FILE_EXC for n in names):
                kinds.add("missing_file")
            if "KeyError" in names:
                kinds.add("key")
            if "TypeError" in names:
                kinds.add("type")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and len(node.args) == 2:
            kinds.add("key")
    return kinds


def _risky_calls(tree: ast.AST) -> tuple[set[str], bool]:
    """(the risky calls of one side by name — the reviewer's own lists: BANNED_FUNCTIONS by bare name, the
    DANGEROUS_OS_METHODS under `os.` — , whether the side calls a placeholder). FIX_43 (b), Call A/#15."""
    risky: set[str] = set()
    placeholder_call = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name):
            if f.id in SecurityVisitor.BANNED_FUNCTIONS:
                risky.add(f.id)
            elif f.id == _PLACEHOLDER_NAME:
                placeholder_call = True
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "os" \
                and f.attr in SecurityVisitor.DANGEROUS_OS_METHODS:
            risky.add(f"os.{f.attr}")
    return risky, placeholder_call


def _defensive_token(before: ast.AST | None, after: ast.AST | None) -> str:
    """Method 4: guards added / removed (FIX_42) and, since FIX_43 (b) (owner 2026-09-16, hand-check #15), what became
    of the before side's risky calls — `removes_risky_call:x`, `keeps_risky_call:x`, `adds_risky_call:x`, or
    `risky_call_unknown:x` when the after side calls a placeholder where x stood. Facts; the Ranker weighs them."""
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    gb, ga = _guard_kinds(before), _guard_kinds(after)
    parts: list[str] = []
    if ga - gb:
        parts.append("adds_guard:" + ",".join(sorted(ga - gb)))
    if gb - ga:
        parts.append("removes_guard:" + ",".join(sorted(gb - ga)))
    (rb, _), (ra, ph) = _risky_calls(before), _risky_calls(after)
    gone = sorted(rb - ra)
    if gone:
        parts.append(("risky_call_unknown:" if ph else "removes_risky_call:") + ",".join(gone))
    if rb & ra:
        parts.append("keeps_risky_call:" + ",".join(sorted(rb & ra)))
    if ra - rb:
        parts.append("adds_risky_call:" + ",".join(sorted(ra - rb)))
    return "+".join(parts) if parts else "same"


# ---- FIX_43 part (a) (owner ruling 2026-09-15 late, RANKER_METHODS_RULING_2026-09-15.md): the two methods the
# five did not cover — method 5 readability / cyclomatic complexity, method 7 mutable defaults & scope traps.
# Facts of the after side against the before side; the Ranker weighs them by the seven-method table.
_BLOCK_NODES: Final[tuple[type, ...]] = tuple(
    n for n in (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try,
                getattr(ast, "TryStar", None), getattr(ast, "Match", None), ast.FunctionDef, ast.AsyncFunctionDef)
    if n is not None)
_CONVENTIONAL_SHORT: Final[frozenset[str]] = frozenset({"_", "i", "j", "k", "n", "x", "y", "z", "e", "f", "s", "m", "a", "b"})
_MUTABLE_CTORS: Final[frozenset[str]] = frozenset({"list", "dict", "set", "bytearray", "deque", "defaultdict", "OrderedDict"})
import builtins as _builtins
_BUILTIN_NAMES: Final[frozenset[str]] = frozenset(n for n in dir(_builtins) if not n.startswith("_"))


def _bound_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Every name the code BINDS (assignment targets, loop targets, parameters, def/class names, with-as,
    comprehension targets, walrus), with its line — the names a reader must learn."""
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            out.append((node.id, node.lineno))
        elif isinstance(node, ast.arg):
            out.append((node.arg, node.lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((node.name, node.lineno))
    return out


def _is_cryptic(name: str) -> bool:
    """A simple, honest heuristic: a single letter outside the conventional loop / maths letters, a letter+digits
    name (a1, tmp2), or four+ letters with no vowel (rslt, cnfg). Nothing else is called cryptic."""
    if name.startswith("_") and name != "_":
        name = name.lstrip("_")
    low = name.lower()
    if len(low) == 1:
        return low not in _CONVENTIONAL_SHORT
    if re.fullmatch(r"[a-z]{1,3}\d+", low):
        return True
    return len(low) >= 4 and low.isalpha() and not any(c in "aeiouy" for c in low)


def _readability_facts(tree: ast.AST) -> tuple[int, int, set[str]]:
    """(max block nesting depth, branch count ≈ cyclomatic complexity − 1, names bound)."""
    depth_max = 0
    def walk(node: ast.AST, depth: int) -> None:
        nonlocal depth_max
        depth_max = max(depth_max, depth)
        for child in ast.iter_child_nodes(node):
            walk(child, depth + (1 if isinstance(child, _BLOCK_NODES) else 0))
    walk(tree, 0)
    branches = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler)):
            branches += 1
        elif isinstance(node, ast.BoolOp):
            branches += max(0, len(node.values) - 1)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            branches += sum(1 + len(g.ifs) for g in node.generators)
        elif getattr(ast, "Match", None) is not None and isinstance(node, ast.Match):
            branches += len(node.cases)
    return depth_max, branches, {n for n, _ in _bound_names(tree)}


def _readability_token(before: ast.AST | None, after: ast.AST | None) -> str:
    """Method 5 (readability / cyclomatic complexity): nesting depth delta, branch-count delta, cryptic names the
    after side introduces. `same` when nothing moved; `unreadable:<side>` when a side does not parse."""
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    (bd, bb, bn), (ad, ab, an) = _readability_facts(before), _readability_facts(after)
    parts: list[str] = []
    if ad != bd:
        parts.append(f"deeper:{ad}" if ad > bd else f"flatter:{ad}")
    if ab != bb:
        parts.append(f"more_branches:{ab - bb}" if ab > bb else f"fewer_branches:{bb - ab}")
    cryptic = sorted(n for n in (an - bn) if _is_cryptic(n))
    if cryptic:
        parts.append("cryptic_names:" + ",".join(cryptic))
    return "+".join(parts) if parts else "same"


def _trap_facts(tree: ast.AST) -> set[str]:
    """Method 7: the Python-specific traps of one side, as `kind:name` facts —
    mutable_default (a list/dict/set literal or constructor as a parameter default), late_binding_closure (a lambda
    or nested def inside a loop that reads the loop variable without binding it as a default), global_mutation
    (`global x` declared and x assigned in the same function), shadowed_builtin (a bound name that is a builtin)."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            pos = a.posonlyargs + a.args
            for param, default in zip(pos[len(pos) - len(a.defaults):], a.defaults):
                if _is_mutable_default(default):
                    found.add(f"mutable_default:{param.arg}")
            for param, kw_default in zip(a.kwonlyargs, a.kw_defaults):
                if kw_default is not None and _is_mutable_default(kw_default):
                    found.add(f"mutable_default:{param.arg}")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                declared = {n for st in ast.walk(node) if isinstance(st, ast.Global) for n in st.names}
                stored = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
                for name in sorted(declared & stored):
                    found.add(f"global_mutation:{name}")
        if isinstance(node, _LOOP_NODES):
            targets = {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)} if hasattr(node, "target") else set()
            for inner in ast.walk(node):
                if inner is node or not isinstance(inner, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                bound_as_default = {p.arg for p in inner.args.args + inner.args.kwonlyargs}
                reads = {n.id for n in ast.walk(inner) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
                for name in sorted((reads & targets) - bound_as_default):
                    found.add(f"late_binding_closure:{name}")
    for name, _ in _bound_names(tree):
        if name in _BUILTIN_NAMES:
            found.add(f"shadowed_builtin:{name}")
    return found


def _is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _MUTABLE_CTORS


def _traps_token(before: ast.AST | None, after: ast.AST | None) -> str:
    """Method 7 (mutable defaults & scope traps): the after side's traps, plus `removed:<trap>` for a trap the before
    side had and the after side does not. `none` when neither; `unreadable:<side>` when a side does not parse.
    Facts only — no trap makes a candidate unpickable (owner, 2026-09-15 late)."""
    if before is None or after is None:
        return "unreadable:" + ("before" if before is None else "after")
    tb, ta = _trap_facts(before), _trap_facts(after)
    parts = sorted(ta) + [f"removed:{t}" for t in sorted(tb - ta)]
    return "+".join(parts) if parts else "none"


_STATIC_READERS: Final[dict[str, Callable[[ast.AST | None, ast.AST | None], str]]] = {
    "flow": _flow_token, "complexity": _complexity_token, "idiom": _idiom_token,
    "deps": _deps_token, "defensive": _defensive_token,
    "readability": _readability_token, "traps": _traps_token,   # FIX_43a
}


def observe_pair(before_code: str, after_code: str) -> list[str]:
    """FIX_42 + FIX_43a: the seven static observation tokens of a candidate's after_code against the row's
    before_code, in STATIC_OBSERVATION_ORDER (flow, complexity, idiom, deps, defensive, readability, traps).
    Facts only — the Ranker weighs them by the owner's seven-method table; nothing here decides."""
    before, after = _parse_side(before_code), _parse_side(after_code)
    # FIX_43 (b), Call A: N placeholder-only statements on a side make every reading of it partial — said on each token
    opaque = sum(getattr(t, "_opaque", 0) for t in (before, after) if t is not None)
    suffix = f"+opaque:{opaque}" if opaque else ""
    tokens: list[str] = []
    for name in STATIC_OBSERVATION_ORDER:
        try:
            tokens.append(f"{name}={_STATIC_READERS[name](before, after)}{suffix}")
        except Exception as e:  # the reader failing is itself the observation
            tokens.append(f"{name}=reader_raised:{type(e).__name__}")
    return tokens


setattr(CodeAnalyzer, 'observe_pair', staticmethod(observe_pair))  # the Reviewer's entry point beside analyze()
