"""
API/Spec Compliance Checks.
Validates code against expected API patterns and specifications.
"""

import ast
import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


@dataclass
class APIIssue:
    file: str
    line: int
    code: str
    message: str
    api: str = ""


@dataclass
class MethodSpec:
    """Specification for a method."""
    name: str
    params: list[str] = field(default_factory=list)
    required_params: list[str] = field(default_factory=list)
    return_type: str | None = None
    raises: list[str] = field(default_factory=list)


@dataclass
class ClassSpec:
    """Specification for a class/interface."""
    name: str
    methods: dict[str, MethodSpec] = field(default_factory=dict)
    required_methods: list[str] = field(default_factory=list)
    parent: str | None = None


# Built-in protocol specifications
BUILTIN_SPECS = {
    "Iterator": ClassSpec(
        name="Iterator",
        required_methods=["__iter__", "__next__"],
        methods={
            "__iter__": MethodSpec("__iter__", ["self"], return_type="Iterator"),
            "__next__": MethodSpec("__next__", ["self"]),
        }
    ),
    "Iterable": ClassSpec(
        name="Iterable",
        required_methods=["__iter__"],
        methods={
            "__iter__": MethodSpec("__iter__", ["self"], return_type="Iterator"),
        }
    ),
    "ContextManager": ClassSpec(
        name="ContextManager",
        required_methods=["__enter__", "__exit__"],
        methods={
            "__enter__": MethodSpec("__enter__", ["self"]),
            "__exit__": MethodSpec("__exit__", ["self", "exc_type", "exc_val", "exc_tb"]),
        }
    ),
    "Hashable": ClassSpec(
        name="Hashable",
        required_methods=["__hash__"],
        methods={
            "__hash__": MethodSpec("__hash__", ["self"], return_type="int"),
        }
    ),
    "Comparable": ClassSpec(
        name="Comparable",
        required_methods=["__eq__", "__lt__"],
        methods={
            "__eq__": MethodSpec("__eq__", ["self", "other"], return_type="bool"),
            "__lt__": MethodSpec("__lt__", ["self", "other"], return_type="bool"),
        }
    ),
}

# Common anti-patterns
DUNDER_REQUIRED_SIGNATURES: dict[str, dict[str, list[str] | str | None]] = {
    "__init__": {"params": ["self"], "returns": None},
    "__str__": {"params": ["self"], "returns": "str"},
    "__repr__": {"params": ["self"], "returns": "str"},
    "__len__": {"params": ["self"], "returns": "int"},
    "__bool__": {"params": ["self"], "returns": "bool"},
    "__hash__": {"params": ["self"], "returns": "int"},
    "__eq__": {"params": ["self", "other"], "returns": "bool"},
    "__ne__": {"params": ["self", "other"], "returns": "bool"},
    "__lt__": {"params": ["self", "other"], "returns": "bool"},
    "__le__": {"params": ["self", "other"], "returns": "bool"},
    "__gt__": {"params": ["self", "other"], "returns": "bool"},
    "__ge__": {"params": ["self", "other"], "returns": "bool"},
    "__getitem__": {"params": ["self", "key"]},
    "__setitem__": {"params": ["self", "key", "value"], "returns": None},
    "__delitem__": {"params": ["self", "key"], "returns": None},
    "__contains__": {"params": ["self", "item"], "returns": "bool"},
    "__iter__": {"params": ["self"]},
    "__next__": {"params": ["self"]},
    "__call__": {"params": ["self"]},  # Can have more
    "__enter__": {"params": ["self"]},
    "__exit__": {"params": ["self", "exc_type", "exc_val", "exc_tb"]},
    "__aenter__": {"params": ["self"]},
    "__aexit__": {"params": ["self", "exc_type", "exc_val", "exc_tb"]},
}


class APIComplianceChecker(ast.NodeVisitor):
    """Check API compliance."""

    def __init__(self, filename: str, specs: dict[str, ClassSpec] | None = None):
        self.filename = filename
        self.specs = specs or BUILTIN_SPECS
        self.issues: list[APIIssue] = []
        self._current_class: str | None = None
        logger.debug("TRACE: APIComplianceChecker initialized for %s", filename)
        self._class_methods: dict[str, set[str]] = {}  # class_name -> method names

    def _add(self, node: ast.AST, code: str, message: str, api: str = ""):
        self.issues.append(APIIssue(
            file=self.filename,
            line=getattr(node, "lineno", 0),
            code=code,
            message=message,
            api=api
        ))

    def _get_base_names(self, node: ast.ClassDef) -> list[str]:
        """Extract base class names."""
        names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(base.attr)
            elif isinstance(base, ast.Subscript):  # Generic[T]
                if isinstance(base.value, ast.Name):
                    names.append(base.value.id)
        return names

    def _check_dunder_signature(self, node: ast.FunctionDef, _class_name: str):
        """Check dunder method signatures."""
        if not (node.name.startswith("__") and node.name.endswith("__")):
            return
        
        if node.name not in DUNDER_REQUIRED_SIGNATURES:
            return
        
        spec = DUNDER_REQUIRED_SIGNATURES[node.name]
        expected_params = list(spec["params"]) if isinstance(spec["params"], list) else []

        # Get actual params
        actual_params = [arg.arg for arg in node.args.args]

        # Check minimum params
        min_expected = len(expected_params)
        if len(actual_params) < min_expected:
            self._add(node, "API010",
                      f"'{node.name}' expects at least {min_expected} params, got {len(actual_params)}",
                      api=node.name)

        # Check return type if specified
        expected_return = spec.get("returns")
        if expected_return is not None and isinstance(expected_return, str):
            if node.returns is None:
                self._add(node, "API011",
                          f"'{node.name}' should return {expected_return} (missing annotation)",
                          api=node.name)
            elif isinstance(node.returns, ast.Name):
                if node.returns.id != expected_return:
                    self._add(node, "API012",
                              f"'{node.name}' should return {expected_return}, annotated as {node.returns.id}",
                              api=node.name)
        
        # Check __init__ doesn't return value
        if node.name == "__init__":
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and child.value is not None:
                    self._add(child, "API013",
                              "__init__ should not return a value",
                              api="__init__")

    def _check_protocol_compliance(self, node: ast.ClassDef, methods: set[str]):
        """Check if class properly implements protocols."""
        bases = self._get_base_names(node)
        
        for base_name in bases:
            if base_name in self.specs:
                spec = self.specs[base_name]
                for required in spec.required_methods:
                    if required not in methods:
                        self._add(node, "API020",
                                  f"Class '{node.name}' implements {base_name} but missing '{required}'",
                                  api=base_name)

        # Check for common protocol implications
        if "__iter__" in methods and "__next__" not in methods:
            # Iterator vs Iterable - just info
            pass
        
        if "__eq__" in methods and "__hash__" not in methods:
            # If __eq__ defined, __hash__ should be explicitly set to None or defined
            self._add(node, "API021",
                      f"Class '{node.name}' defines __eq__ but not __hash__ (objects will be unhashable)",
                      api="Hashable")
        
        if "__enter__" in methods and "__exit__" not in methods:
            self._add(node, "API022",
                      f"Class '{node.name}' defines __enter__ but not __exit__ (incomplete context manager)",
                      api="ContextManager")
        
        if "__exit__" in methods and "__enter__" not in methods:
            self._add(node, "API022",
                      f"Class '{node.name}' defines __exit__ but not __enter__ (incomplete context manager)",
                      api="ContextManager")

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self._class_methods[node.name] = set()
        
        # First pass: collect methods
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._class_methods[node.name].add(item.name)
        
        # Check protocol compliance
        self._check_protocol_compliance(node, self._class_methods[node.name])
        
        # Visit children
        self.generic_visit(node)
        
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if self._current_class:
            self._check_dunder_signature(node, self._current_class)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call):
        # Check common API misuse patterns
        
        # dict.get() with mutable default
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if len(node.args) >= 2:
                default = node.args[1]
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    self._add(node, "API030",
                              "dict.get() with mutable default (creates shared mutable)",
                              api="dict.get")
        
        # str.format() vs f-string (info only)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                pass  # Could suggest f-string, but that's style
        
        # open() without encoding
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            has_encoding = any(
                kw.arg == "encoding" for kw in node.keywords
            )
            # Check if mode suggests text
            mode_arg = None
            if len(node.args) >= 2:
                mode_arg = node.args[1]
            else:
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode_arg = kw.value
                        break
            
            is_binary = False
            if mode_arg and isinstance(mode_arg, ast.Constant):
                is_binary = "b" in str(mode_arg.value)
            
            if not has_encoding and not is_binary:
                self._add(node, "API031",
                          "open() without explicit encoding (platform-dependent)",
                          api="open")

        # subprocess with shell=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "call", "Popen", "check_output"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            self._add(node, "API032",
                                      f"subprocess.{node.func.attr}() with shell=True (security risk)",
                                      api="subprocess")

        self.generic_visit(node)


async def load_specs_from_file(filepath: Path) -> dict[str, ClassSpec]:
    """Load custom specs from JSON file."""
    logger.debug("load_specs_from_file called: %s", filepath)
    content = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
    data = json.loads(content)

    specs = {}
    for name, spec_data in data.items():
        methods = {}
        for method_name, method_data in spec_data.get("methods", {}).items():
            methods[method_name] = MethodSpec(
                name=method_name,
                params=method_data.get("params", []),
                required_params=method_data.get("required_params", []),
                return_type=method_data.get("return_type"),
                raises=method_data.get("raises", [])
            )
        specs[name] = ClassSpec(
            name=name,
            methods=methods,
            required_methods=spec_data.get("required_methods", []),
            parent=spec_data.get("parent")
        )
    return specs


async def analyze_file(filepath: Path, specs: dict[str, ClassSpec] | None = None) -> list[APIIssue]:
    """Analyze API compliance in a file."""
    logger.debug("analyze_file called: %s", filepath)
    try:
        source = await asyncio.to_thread(filepath.read_text, encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError) as e:
        return [APIIssue(str(filepath), 0, "API000", f"Parse error: {e}")]

    checker = APIComplianceChecker(str(filepath), specs)
    checker.visit(tree)
    logger.debug("analyze_file done: %s — %d issues", filepath, len(checker.issues))
    return checker.issues


async def analyze_directory(directory: Path, pattern: str = "**/*.py",
                      specs: dict[str, ClassSpec] | None = None,
                      files: list[Path] | None = None) -> list[APIIssue]:
    """Analyze all Python files in directory.

    files: optional pre-filtered file list (e.g. whitelist-filtered discovery
    output from the validator daemon). None = legacy full-glob behavior.
    """
    logger.debug("analyze_directory called: %s pattern=%s files=%s",
                 directory, pattern, "None" if files is None else len(files))
    if files is None:
        from semantic_analysis._scope import contained_glob  # FIX_15: contained, never a bare glob
        files = await asyncio.to_thread(contained_glob, directory, pattern)
    results: list[APIIssue] = []
    for filepath in files:
        results.extend(await analyze_file(filepath, specs))
    return results


if __name__ == "__main__":
    import sys

    async def _main():
        target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
        spec_file = Path(sys.argv[2]) if len(sys.argv) > 2 else None
        specs = BUILTIN_SPECS.copy()
        if spec_file and spec_file.exists():
            specs.update(await load_specs_from_file(spec_file))
        if target.is_file():
            issues = await analyze_file(target, specs)
        else:
            issues = await analyze_directory(target, specs=specs)
        for issue in issues:
            api_info = f" ({issue.api})" if issue.api else ""
            print(f"{issue.file}:{issue.line}: [{issue.code}]{api_info} {issue.message}")
        print(f"\nTotal: {len(issues)} API compliance issues")

    asyncio.run(_main())
