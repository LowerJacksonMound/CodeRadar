"""
Python builtins registry.

Complete list of Python built-in functions, types, constants, and exceptions.
"""

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)


@dataclass
class BuiltinInfo:
    """Information about a Python builtin."""
    name: str
    category: str
    description: str
    signature: str | None = None
    deprecated: bool = False


# Built-in Functions
BUILTIN_FUNCTIONS: frozenset[str] = frozenset({
    # Basic I/O
    "print",
    "input",
    "open",

    # Type Constructors
    "int",
    "float",
    "complex",
    "str",
    "bytes",
    "bytearray",
    "bool",
    "list",
    "tuple",
    "set",
    "frozenset",
    "dict",
    "memoryview",
    "range",
    "slice",
    "object",
    "type",
    "super",
    "property",
    "classmethod",
    "staticmethod",

    # Numeric Operations
    "abs",
    "divmod",
    "pow",
    "round",
    "sum",
    "min",
    "max",

    # Sequence Operations
    "len",
    "sorted",
    "reversed",
    "enumerate",
    "zip",
    "map",
    "filter",
    "all",
    "any",

    # Object Inspection
    "id",
    "hash",
    "dir",
    "vars",
    "isinstance",
    "issubclass",
    "callable",
    "hasattr",
    "getattr",
    "setattr",
    "delattr",

    # String Operations
    "repr",
    "ascii",
    "chr",
    "ord",
    "format",

    # Binary/Hex Operations
    "bin",
    "hex",
    "oct",

    # Iterators
    "iter",
    "next",
    "aiter",
    "anext",

    # Code Execution
    "eval",
    "exec",
    "compile",
    "__import__",

    # Memory/Debugging
    "globals",
    "locals",
    "breakpoint",

    # Misc
    "help",
    "copyright",
    "credits",
    "license",
    "quit",
    "exit",
})

# Built-in Constants
BUILTIN_CONSTANTS: frozenset[str] = frozenset({
    "True",
    "False",
    "None",
    "NotImplemented",
    "Ellipsis",
    "__debug__",
    "__name__",
    "__doc__",
    "__package__",
    "__loader__",
    "__spec__",
    "__path__",
    "__file__",
    "__cached__",
    "__builtins__",
})

# Built-in Exceptions
BUILTIN_EXCEPTIONS: frozenset[str] = frozenset({
    # Base classes
    "BaseException",
    "BaseExceptionGroup",
    "Exception",
    "GeneratorExit",
    "KeyboardInterrupt",
    "SystemExit",

    # Arithmetic errors
    "ArithmeticError",
    "FloatingPointError",
    "OverflowError",
    "ZeroDivisionError",

    # Lookup errors
    "LookupError",
    "IndexError",
    "KeyError",

    # Name errors
    "NameError",
    "UnboundLocalError",

    # Attribute errors
    "AttributeError",

    # Import errors
    "ImportError",
    "ModuleNotFoundError",

    # OS errors
    "OSError",
    "BlockingIOError",
    "ChildProcessError",
    "ConnectionError",
    "BrokenPipeError",
    "ConnectionAbortedError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "FileExistsError",
    "FileNotFoundError",
    "InterruptedError",
    "IsADirectoryError",
    "NotADirectoryError",
    "PermissionError",
    "ProcessLookupError",
    "TimeoutError",

    # Type errors
    "TypeError",

    # Value errors
    "ValueError",
    "UnicodeError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeTranslateError",

    # Runtime errors
    "RuntimeError",
    "NotImplementedError",
    "RecursionError",

    # Syntax errors
    "SyntaxError",
    "IndentationError",
    "TabError",

    # System errors
    "SystemError",
    "MemoryError",

    # Reference errors
    "ReferenceError",

    # Buffer errors
    "BufferError",

    # EOF/Stop errors
    "EOFError",
    "StopIteration",
    "StopAsyncIteration",

    # Assertion
    "AssertionError",

    # Warnings
    "Warning",
    "BytesWarning",
    "DeprecationWarning",
    "EncodingWarning",
    "FutureWarning",
    "ImportWarning",
    "PendingDeprecationWarning",
    "ResourceWarning",
    "RuntimeWarning",
    "SyntaxWarning",
    "UnicodeWarning",
    "UserWarning",

    # Exception groups (Python 3.11+)
    "ExceptionGroup",
})

# Built-in Types (classes)
BUILTIN_TYPES: frozenset[str] = frozenset({
    "int",
    "float",
    "complex",
    "str",
    "bytes",
    "bytearray",
    "bool",
    "list",
    "tuple",
    "set",
    "frozenset",
    "dict",
    "range",
    "slice",
    "memoryview",
    "object",
    "type",
    "property",
    "classmethod",
    "staticmethod",
    "super",
    "enumerate",
    "filter",
    "map",
    "reversed",
    "zip",
})

# All Python Builtins
PYTHON_BUILTINS: frozenset[str] = (
    BUILTIN_FUNCTIONS | BUILTIN_CONSTANTS | BUILTIN_EXCEPTIONS | BUILTIN_TYPES
)

# Detailed builtin information
BUILTIN_DETAILS: dict[str, BuiltinInfo] = {
    "len": BuiltinInfo("len", "sequence", "Return the length of an object", "len(obj) -> int"),
    "print": BuiltinInfo("print", "io", "Print objects to stream", "print(*args, sep=' ', end='\\n', file=None, flush=False)"),
    "range": BuiltinInfo("range", "iterator", "Create an immutable sequence of numbers", "range(stop) or range(start, stop[, step])"),
    "open": BuiltinInfo("open", "io", "Open a file", "open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None)"),
    "isinstance": BuiltinInfo("isinstance", "type", "Check if object is instance of class", "isinstance(obj, classinfo) -> bool"),
    "getattr": BuiltinInfo("getattr", "attribute", "Get named attribute from object", "getattr(obj, name[, default])"),
    "setattr": BuiltinInfo("setattr", "attribute", "Set named attribute on object", "setattr(obj, name, value)"),
    "hasattr": BuiltinInfo("hasattr", "attribute", "Check if object has attribute", "hasattr(obj, name) -> bool"),
    "enumerate": BuiltinInfo("enumerate", "iterator", "Return an enumerate object", "enumerate(iterable, start=0)"),
    "zip": BuiltinInfo("zip", "iterator", "Aggregate elements from iterables", "zip(*iterables, strict=False)"),
    "map": BuiltinInfo("map", "iterator", "Apply function to every item", "map(func, *iterables)"),
    "filter": BuiltinInfo("filter", "iterator", "Filter elements by function", "filter(func, iterable)"),
    "sorted": BuiltinInfo("sorted", "sequence", "Return sorted list", "sorted(iterable, *, key=None, reverse=False)"),
    "sum": BuiltinInfo("sum", "numeric", "Sum of iterable items", "sum(iterable, /, start=0)"),
    "min": BuiltinInfo("min", "numeric", "Return minimum value", "min(iterable, *[, key, default]) or min(arg1, arg2, *args[, key])"),
    "max": BuiltinInfo("max", "numeric", "Return maximum value", "max(iterable, *[, key, default]) or max(arg1, arg2, *args[, key])"),
    "abs": BuiltinInfo("abs", "numeric", "Return absolute value", "abs(x) -> number"),
    "round": BuiltinInfo("round", "numeric", "Round number", "round(number[, ndigits]) -> number"),
    "int": BuiltinInfo("int", "type", "Convert to integer", "int(x=0) or int(x, base=10)"),
    "float": BuiltinInfo("float", "type", "Convert to float", "float(x=0.0)"),
    "str": BuiltinInfo("str", "type", "Convert to string", "str(object='') or str(object=b'', encoding='utf-8', errors='strict')"),
    "list": BuiltinInfo("list", "type", "Create a list", "list() or list(iterable)"),
    "dict": BuiltinInfo("dict", "type", "Create a dictionary", "dict() or dict(mapping) or dict(iterable) or dict(**kwargs)"),
    "set": BuiltinInfo("set", "type", "Create a set", "set() or set(iterable)"),
    "tuple": BuiltinInfo("tuple", "type", "Create a tuple", "tuple() or tuple(iterable)"),
    "bool": BuiltinInfo("bool", "type", "Convert to boolean", "bool(x=False)"),
    "bytes": BuiltinInfo("bytes", "type", "Create bytes object", "bytes() or bytes(int) or bytes(iterable) or bytes(string, encoding)"),
    "type": BuiltinInfo("type", "type", "Get type of object or create new type", "type(object) or type(name, bases, dict)"),
    "object": BuiltinInfo("object", "type", "Base class for all classes", "object()"),
    "super": BuiltinInfo("super", "type", "Return proxy object for parent class", "super() or super(type, object-or-type)"),
    "callable": BuiltinInfo("callable", "inspection", "Check if object is callable", "callable(obj) -> bool"),
    "dir": BuiltinInfo("dir", "inspection", "List of names in scope or object attributes", "dir([object]) -> list"),
    "vars": BuiltinInfo("vars", "inspection", "Return __dict__ of object", "vars([object]) -> dict"),
    "id": BuiltinInfo("id", "inspection", "Return identity of object", "id(obj) -> int"),
    "hash": BuiltinInfo("hash", "inspection", "Return hash value of object", "hash(obj) -> int"),
    "repr": BuiltinInfo("repr", "string", "Return canonical string representation", "repr(obj) -> str"),
    "ascii": BuiltinInfo("ascii", "string", "Return ASCII representation", "ascii(obj) -> str"),
    "chr": BuiltinInfo("chr", "string", "Return character for Unicode code point", "chr(i) -> str"),
    "ord": BuiltinInfo("ord", "string", "Return Unicode code point for character", "ord(c) -> int"),
    "format": BuiltinInfo("format", "string", "Format a value", "format(value[, format_spec]) -> str"),
    "bin": BuiltinInfo("bin", "numeric", "Convert to binary string", "bin(number) -> str"),
    "hex": BuiltinInfo("hex", "numeric", "Convert to hex string", "hex(number) -> str"),
    "oct": BuiltinInfo("oct", "numeric", "Convert to octal string", "oct(number) -> str"),
    "iter": BuiltinInfo("iter", "iterator", "Return iterator object", "iter(object[, sentinel])"),
    "next": BuiltinInfo("next", "iterator", "Get next item from iterator", "next(iterator[, default])"),
    "aiter": BuiltinInfo("aiter", "iterator", "Return async iterator", "aiter(async_iterable)"),
    "anext": BuiltinInfo("anext", "iterator", "Get next item from async iterator", "anext(async_iterator[, default])"),
    "eval": BuiltinInfo("eval", "code", "Evaluate Python expression", "eval(expression[, globals[, locals]])"),
    "exec": BuiltinInfo("exec", "code", "Execute Python code", "exec(object[, globals[, locals]])"),
    "compile": BuiltinInfo("compile", "code", "Compile source to code object", "compile(source, filename, mode, flags=0, dont_inherit=False, optimize=-1)"),
    "__import__": BuiltinInfo("__import__", "code", "Import a module", "__import__(name, globals=None, locals=None, fromlist=(), level=0)"),
    "globals": BuiltinInfo("globals", "scope", "Return global symbol table", "globals() -> dict"),
    "locals": BuiltinInfo("locals", "scope", "Return local symbol table", "locals() -> dict"),
    "breakpoint": BuiltinInfo("breakpoint", "debug", "Enter debugger", "breakpoint(*args, **kws)"),
    "input": BuiltinInfo("input", "io", "Read line from input", "input([prompt]) -> str"),
    "help": BuiltinInfo("help", "help", "Invoke built-in help system", "help([object])"),
    "all": BuiltinInfo("all", "logic", "Return True if all elements are truthy", "all(iterable) -> bool"),
    "any": BuiltinInfo("any", "logic", "Return True if any element is truthy", "any(iterable) -> bool"),
    "divmod": BuiltinInfo("divmod", "numeric", "Return quotient and remainder", "divmod(a, b) -> (quotient, remainder)"),
    "pow": BuiltinInfo("pow", "numeric", "Return power with optional modulo", "pow(base, exp[, mod])"),
    "reversed": BuiltinInfo("reversed", "iterator", "Return reversed iterator", "reversed(seq)"),
    "slice": BuiltinInfo("slice", "sequence", "Create a slice object", "slice(stop) or slice(start, stop[, step])"),
    "property": BuiltinInfo("property", "descriptor", "Create a property", "property(fget=None, fset=None, fdel=None, doc=None)"),
    "classmethod": BuiltinInfo("classmethod", "descriptor", "Convert function to class method", "@classmethod"),
    "staticmethod": BuiltinInfo("staticmethod", "descriptor", "Convert function to static method", "@staticmethod"),
    "issubclass": BuiltinInfo("issubclass", "type", "Check if class is subclass", "issubclass(cls, classinfo) -> bool"),
    "delattr": BuiltinInfo("delattr", "attribute", "Delete named attribute", "delattr(obj, name)"),
    "complex": BuiltinInfo("complex", "type", "Create complex number", "complex(real=0, imag=0) or complex(string)"),
    "frozenset": BuiltinInfo("frozenset", "type", "Create immutable set", "frozenset() or frozenset(iterable)"),
    "bytearray": BuiltinInfo("bytearray", "type", "Create mutable bytes array", "bytearray() or bytearray(int) or bytearray(iterable)"),
    "memoryview": BuiltinInfo("memoryview", "type", "Create memory view", "memoryview(obj)"),
}


def is_builtin(name: str) -> bool:
    """Check if a name is a Python builtin."""
    result = name in PYTHON_BUILTINS
    _trace("is_builtin(%s) -> %s", name, result)
    return result


def is_builtin_function(name: str) -> bool:
    """Check if a name is a builtin function."""
    result = name in BUILTIN_FUNCTIONS
    _trace("is_builtin_function(%s) -> %s", name, result)
    return result


def is_builtin_exception(name: str) -> bool:
    """Check if a name is a builtin exception."""
    result = name in BUILTIN_EXCEPTIONS
    _trace("is_builtin_exception(%s) -> %s", name, result)
    return result


def is_builtin_type(name: str) -> bool:
    """Check if a name is a builtin type."""
    result = name in BUILTIN_TYPES
    _trace("is_builtin_type(%s) -> %s", name, result)
    return result


def is_builtin_constant(name: str) -> bool:
    """Check if a name is a builtin constant."""
    result = name in BUILTIN_CONSTANTS
    _trace("is_builtin_constant(%s) -> %s", name, result)
    return result


def get_builtin_info(name: str) -> BuiltinInfo | None:
    """Get detailed information about a builtin."""
    result = BUILTIN_DETAILS.get(name)
    _trace("get_builtin_info(%s) -> %s", name, "found" if result else "not found")
    return result


def get_builtin_category(name: str) -> str | None:
    """Get the category of a builtin."""
    if name in BUILTIN_FUNCTIONS:
        _trace("get_builtin_category(%s) -> function", name)
        return "function"
    if name in BUILTIN_EXCEPTIONS:
        _trace("get_builtin_category(%s) -> exception", name)
        return "exception"
    if name in BUILTIN_TYPES:
        _trace("get_builtin_category(%s) -> type", name)
        return "type"
    if name in BUILTIN_CONSTANTS:
        _trace("get_builtin_category(%s) -> constant", name)
        return "constant"
    _trace("get_builtin_category(%s) -> None", name)
    return None


if __name__ == "__main__":
    import sys

    print("signature_engine.builtins_registry — Python builtins registry")
    print(f"  Builtin functions: {len(BUILTIN_FUNCTIONS)}")
    print(f"  Builtin constants: {len(BUILTIN_CONSTANTS)}")
    print(f"  Builtin exceptions: {len(BUILTIN_EXCEPTIONS)}")
    print(f"  Builtin types: {len(BUILTIN_TYPES)}")
    print(f"  Total builtins: {len(PYTHON_BUILTINS)}")
    print(f"  Detailed entries: {len(BUILTIN_DETAILS)}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        print(f"\nLookup: '{name}'")
        print(f"  is_builtin: {is_builtin(name)}")
        print(f"  category: {get_builtin_category(name)}")
        info = get_builtin_info(name)
        if info:
            print(f"  info: {info}")
