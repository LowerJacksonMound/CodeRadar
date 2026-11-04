"""
Python dunder (double underscore) methods registry.

Complete list of magic methods with their expected signatures and categories.
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
class DunderInfo:
    """Information about a dunder method."""
    name: str
    category: str
    signature: str
    description: str
    returns: str | None = None


# Object Lifecycle Methods
LIFECYCLE_DUNDERS: frozenset[str] = frozenset({
    "__new__",
    "__init__",
    "__del__",
    "__init_subclass__",
    "__set_name__",
})

# Representation Methods
REPR_DUNDERS: frozenset[str] = frozenset({
    "__repr__",
    "__str__",
    "__bytes__",
    "__format__",
    "__hash__",
    "__bool__",
    "__sizeof__",
})

# Comparison Methods
COMPARISON_DUNDERS: frozenset[str] = frozenset({
    "__lt__",
    "__le__",
    "__eq__",
    "__ne__",
    "__gt__",
    "__ge__",
})

# Attribute Access Methods
ATTRIBUTE_DUNDERS: frozenset[str] = frozenset({
    "__getattr__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__dir__",
})

# Descriptor Methods
DESCRIPTOR_DUNDERS: frozenset[str] = frozenset({
    "__get__",
    "__set__",
    "__delete__",
    "__objclass__",
})

# Container Methods
CONTAINER_DUNDERS: frozenset[str] = frozenset({
    "__len__",
    "__length_hint__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__missing__",
    "__iter__",
    "__reversed__",
    "__contains__",
})

# Numeric Methods - Unary
UNARY_NUMERIC_DUNDERS: frozenset[str] = frozenset({
    "__neg__",
    "__pos__",
    "__abs__",
    "__invert__",
    "__complex__",
    "__int__",
    "__float__",
    "__index__",
    "__round__",
    "__trunc__",
    "__floor__",
    "__ceil__",
})

# Numeric Methods - Binary
BINARY_NUMERIC_DUNDERS: frozenset[str] = frozenset({
    "__add__",
    "__sub__",
    "__mul__",
    "__matmul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__divmod__",
    "__pow__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__xor__",
    "__or__",
})

# Numeric Methods - Reflected
REFLECTED_NUMERIC_DUNDERS: frozenset[str] = frozenset({
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rmatmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rdivmod__",
    "__rpow__",
    "__rlshift__",
    "__rrshift__",
    "__rand__",
    "__rxor__",
    "__ror__",
})

# Numeric Methods - In-place
INPLACE_NUMERIC_DUNDERS: frozenset[str] = frozenset({
    "__iadd__",
    "__isub__",
    "__imul__",
    "__imatmul__",
    "__itruediv__",
    "__ifloordiv__",
    "__imod__",
    "__ipow__",
    "__ilshift__",
    "__irshift__",
    "__iand__",
    "__ixor__",
    "__ior__",
})

# Context Manager Methods
CONTEXT_MANAGER_DUNDERS: frozenset[str] = frozenset({
    "__enter__",
    "__exit__",
    "__aenter__",
    "__aexit__",
})

# Callable Methods
CALLABLE_DUNDERS: frozenset[str] = frozenset({
    "__call__",
})

# Class Methods
CLASS_DUNDERS: frozenset[str] = frozenset({
    "__class_getitem__",
    "__mro_entries__",
    "__subclasshook__",
    "__instancecheck__",
    "__subclasscheck__",
    "__prepare__",
})

# Async Methods
ASYNC_DUNDERS: frozenset[str] = frozenset({
    "__await__",
    "__aiter__",
    "__anext__",
})

# Copy/Pickle Methods
COPY_PICKLE_DUNDERS: frozenset[str] = frozenset({
    "__copy__",
    "__deepcopy__",
    "__getnewargs__",
    "__getnewargs_ex__",
    "__getstate__",
    "__setstate__",
    "__reduce__",
    "__reduce_ex__",
})

# Slot Methods
SLOT_DUNDERS: frozenset[str] = frozenset({
    "__slots__",
})

# Buffer Protocol Methods
BUFFER_DUNDERS: frozenset[str] = frozenset({
    "__buffer__",
    "__release_buffer__",
})

# Match Statement Methods (Python 3.10+)
MATCH_DUNDERS: frozenset[str] = frozenset({
    "__match_args__",
})

# Module Attributes
MODULE_DUNDERS: frozenset[str] = frozenset({
    "__name__",
    "__doc__",
    "__package__",
    "__loader__",
    "__spec__",
    "__path__",
    "__file__",
    "__cached__",
    "__builtins__",
    "__all__",
    "__version__",
    "__author__",
})

# Class Attributes
CLASS_ATTR_DUNDERS: frozenset[str] = frozenset({
    "__dict__",
    "__class__",
    "__bases__",
    "__mro__",
    "__qualname__",
    "__module__",
    "__annotations__",
    "__weakref__",
    "__abstractmethods__",
})

# All Dunder Methods
# IG-10 (2026-09-06): the dunders the LANGUAGE defines, read from the interpreter (builtin types, object, iterators, paths)
# plus the data-model names no builtin carries — `__next__`, `__replace__`, `__post_init__`, `__fspath__` were missing from the
# hand-written categories and honest iterators / dataclasses / path-likes were called fake.
def _language_dunders() -> frozenset[str]:
    import pathlib, types as _types
    ts: tuple = (object, int, float, complex, bool, str, bytes, bytearray, list, tuple, dict, set, frozenset, type, range, slice,
          memoryview, property, staticmethod, classmethod, super, enumerate, zip, map, filter, reversed, type(iter([])),
          type(iter({})), type((x for x in ())), BaseException, pathlib.PurePath, _types.SimpleNamespace, _types.FunctionType,  # type: ignore[var-annotated]  # FIX_54 ast-pos
          _types.ModuleType, _types.GeneratorType, _types.CoroutineType, _types.AsyncGeneratorType)
    out = {n for t in ts for n in dir(t) if n.startswith('__') and n.endswith('__')}
    out |= {'__post_init__', '__set_name__', '__init_subclass__', '__class_getitem__', '__mro_entries__', '__prepare__',
            '__missing__', '__length_hint__', '__aiter__', '__anext__', '__await__', '__aenter__', '__aexit__', '__fspath__',
            '__replace__', '__buffer__', '__release_buffer__', '__getnewargs__', '__getnewargs_ex__', '__copy__', '__deepcopy__',
            '__set__', '__get__', '__delete__', '__objclass__', '__wrapped__', '__subclasshook__', '__instancecheck__',
            '__subclasscheck__', '__index__', '__round__', '__trunc__', '__floor__', '__ceil__', '__divmod__', '__rdivmod__',
            '__matmul__', '__rmatmul__', '__imatmul__', '__complex__', '__bytes__', '__format__', '__sizeof__', '__dir__',
            '__reduce__', '__reduce_ex__', '__getstate__', '__setstate__', '__del__', '__next__', '__reversed__', '__contains__'}
    return frozenset(out)


LANGUAGE_DUNDERS: frozenset[str] = _language_dunders()

DUNDER_METHODS: frozenset[str] = (
    LANGUAGE_DUNDERS |
    LIFECYCLE_DUNDERS |
    REPR_DUNDERS |
    COMPARISON_DUNDERS |
    ATTRIBUTE_DUNDERS |
    DESCRIPTOR_DUNDERS |
    CONTAINER_DUNDERS |
    UNARY_NUMERIC_DUNDERS |
    BINARY_NUMERIC_DUNDERS |
    REFLECTED_NUMERIC_DUNDERS |
    INPLACE_NUMERIC_DUNDERS |
    CONTEXT_MANAGER_DUNDERS |
    CALLABLE_DUNDERS |
    CLASS_DUNDERS |
    ASYNC_DUNDERS |
    COPY_PICKLE_DUNDERS |
    SLOT_DUNDERS |
    BUFFER_DUNDERS |
    MATCH_DUNDERS |
    MODULE_DUNDERS |
    CLASS_ATTR_DUNDERS
)

# Dunder category mapping
DUNDER_CATEGORIES: dict[str, frozenset[str]] = {
    "lifecycle": LIFECYCLE_DUNDERS,
    "repr": REPR_DUNDERS,
    "comparison": COMPARISON_DUNDERS,
    "attribute": ATTRIBUTE_DUNDERS,
    "descriptor": DESCRIPTOR_DUNDERS,
    "container": CONTAINER_DUNDERS,
    "unary_numeric": UNARY_NUMERIC_DUNDERS,
    "binary_numeric": BINARY_NUMERIC_DUNDERS,
    "reflected_numeric": REFLECTED_NUMERIC_DUNDERS,
    "inplace_numeric": INPLACE_NUMERIC_DUNDERS,
    "context_manager": CONTEXT_MANAGER_DUNDERS,
    "callable": CALLABLE_DUNDERS,
    "class": CLASS_DUNDERS,
    "async": ASYNC_DUNDERS,
    "copy_pickle": COPY_PICKLE_DUNDERS,
    "slot": SLOT_DUNDERS,
    "buffer": BUFFER_DUNDERS,
    "match": MATCH_DUNDERS,
    "module": MODULE_DUNDERS,
    "class_attr": CLASS_ATTR_DUNDERS,
}

# Detailed dunder information
DUNDER_DETAILS: dict[str, DunderInfo] = {
    # Lifecycle
    "__new__": DunderInfo("__new__", "lifecycle", "(cls, *args, **kwargs)", "Create new instance", "instance"),
    "__init__": DunderInfo("__init__", "lifecycle", "(self, *args, **kwargs)", "Initialize instance", "None"),
    "__del__": DunderInfo("__del__", "lifecycle", "(self)", "Called when instance is about to be destroyed", "None"),
    "__init_subclass__": DunderInfo("__init_subclass__", "lifecycle", "(cls, **kwargs)", "Called when class is subclassed", "None"),
    "__set_name__": DunderInfo("__set_name__", "lifecycle", "(self, owner, name)", "Called when descriptor is assigned to attribute", "None"),

    # Representation
    "__repr__": DunderInfo("__repr__", "repr", "(self)", "Official string representation", "str"),
    "__str__": DunderInfo("__str__", "repr", "(self)", "Informal string representation", "str"),
    "__bytes__": DunderInfo("__bytes__", "repr", "(self)", "Bytes representation", "bytes"),
    "__format__": DunderInfo("__format__", "repr", "(self, format_spec)", "Formatted string representation", "str"),
    "__hash__": DunderInfo("__hash__", "repr", "(self)", "Hash value for object", "int"),
    "__bool__": DunderInfo("__bool__", "repr", "(self)", "Truth value testing", "bool"),
    "__sizeof__": DunderInfo("__sizeof__", "repr", "(self)", "Size in bytes", "int"),

    # Comparison
    "__lt__": DunderInfo("__lt__", "comparison", "(self, other)", "Less than comparison", "bool"),
    "__le__": DunderInfo("__le__", "comparison", "(self, other)", "Less than or equal comparison", "bool"),
    "__eq__": DunderInfo("__eq__", "comparison", "(self, other)", "Equality comparison", "bool"),
    "__ne__": DunderInfo("__ne__", "comparison", "(self, other)", "Inequality comparison", "bool"),
    "__gt__": DunderInfo("__gt__", "comparison", "(self, other)", "Greater than comparison", "bool"),
    "__ge__": DunderInfo("__ge__", "comparison", "(self, other)", "Greater than or equal comparison", "bool"),

    # Attribute Access
    "__getattr__": DunderInfo("__getattr__", "attribute", "(self, name)", "Called when attribute not found", "any"),
    "__getattribute__": DunderInfo("__getattribute__", "attribute", "(self, name)", "Called for every attribute access", "any"),
    "__setattr__": DunderInfo("__setattr__", "attribute", "(self, name, value)", "Called when attribute is set", "None"),
    "__delattr__": DunderInfo("__delattr__", "attribute", "(self, name)", "Called when attribute is deleted", "None"),
    "__dir__": DunderInfo("__dir__", "attribute", "(self)", "List of attributes", "list[str]"),

    # Descriptor
    "__get__": DunderInfo("__get__", "descriptor", "(self, obj, objtype=None)", "Get attribute value", "any"),
    "__set__": DunderInfo("__set__", "descriptor", "(self, obj, value)", "Set attribute value", "None"),
    "__delete__": DunderInfo("__delete__", "descriptor", "(self, obj)", "Delete attribute", "None"),

    # Container
    "__len__": DunderInfo("__len__", "container", "(self)", "Return length", "int"),
    "__length_hint__": DunderInfo("__length_hint__", "container", "(self)", "Estimated length", "int"),
    "__getitem__": DunderInfo("__getitem__", "container", "(self, key)", "Get item by key/index", "any"),
    "__setitem__": DunderInfo("__setitem__", "container", "(self, key, value)", "Set item by key/index", "None"),
    "__delitem__": DunderInfo("__delitem__", "container", "(self, key)", "Delete item by key/index", "None"),
    "__missing__": DunderInfo("__missing__", "container", "(self, key)", "Called when key not found in dict", "any"),
    "__iter__": DunderInfo("__iter__", "container", "(self)", "Return iterator", "Iterator"),
    "__reversed__": DunderInfo("__reversed__", "container", "(self)", "Return reversed iterator", "Iterator"),
    "__contains__": DunderInfo("__contains__", "container", "(self, item)", "Membership test", "bool"),

    # Context Manager
    "__enter__": DunderInfo("__enter__", "context_manager", "(self)", "Enter context", "any"),
    "__exit__": DunderInfo("__exit__", "context_manager", "(self, exc_type, exc_val, exc_tb)", "Exit context", "bool|None"),
    "__aenter__": DunderInfo("__aenter__", "context_manager", "(self)", "Async enter context", "Awaitable"),
    "__aexit__": DunderInfo("__aexit__", "context_manager", "(self, exc_type, exc_val, exc_tb)", "Async exit context", "Awaitable[bool|None]"),

    # Callable
    "__call__": DunderInfo("__call__", "callable", "(self, *args, **kwargs)", "Call instance as function", "any"),

    # Async
    "__await__": DunderInfo("__await__", "async", "(self)", "Return iterator for await", "Iterator"),
    "__aiter__": DunderInfo("__aiter__", "async", "(self)", "Return async iterator", "AsyncIterator"),
    "__anext__": DunderInfo("__anext__", "async", "(self)", "Return next item from async iterator", "Awaitable"),

    # Numeric - Binary
    "__add__": DunderInfo("__add__", "binary_numeric", "(self, other)", "Addition", "same type"),
    "__sub__": DunderInfo("__sub__", "binary_numeric", "(self, other)", "Subtraction", "same type"),
    "__mul__": DunderInfo("__mul__", "binary_numeric", "(self, other)", "Multiplication", "same type"),
    "__matmul__": DunderInfo("__matmul__", "binary_numeric", "(self, other)", "Matrix multiplication", "same type"),
    "__truediv__": DunderInfo("__truediv__", "binary_numeric", "(self, other)", "True division", "float"),
    "__floordiv__": DunderInfo("__floordiv__", "binary_numeric", "(self, other)", "Floor division", "int"),
    "__mod__": DunderInfo("__mod__", "binary_numeric", "(self, other)", "Modulo", "same type"),
    "__divmod__": DunderInfo("__divmod__", "binary_numeric", "(self, other)", "Divmod", "tuple"),
    "__pow__": DunderInfo("__pow__", "binary_numeric", "(self, other[, modulo])", "Power", "same type"),
    "__lshift__": DunderInfo("__lshift__", "binary_numeric", "(self, other)", "Left shift", "int"),
    "__rshift__": DunderInfo("__rshift__", "binary_numeric", "(self, other)", "Right shift", "int"),
    "__and__": DunderInfo("__and__", "binary_numeric", "(self, other)", "Bitwise AND", "int"),
    "__xor__": DunderInfo("__xor__", "binary_numeric", "(self, other)", "Bitwise XOR", "int"),
    "__or__": DunderInfo("__or__", "binary_numeric", "(self, other)", "Bitwise OR", "int"),

    # Numeric - Unary
    "__neg__": DunderInfo("__neg__", "unary_numeric", "(self)", "Unary negation", "same type"),
    "__pos__": DunderInfo("__pos__", "unary_numeric", "(self)", "Unary positive", "same type"),
    "__abs__": DunderInfo("__abs__", "unary_numeric", "(self)", "Absolute value", "same type"),
    "__invert__": DunderInfo("__invert__", "unary_numeric", "(self)", "Bitwise NOT", "int"),
    "__complex__": DunderInfo("__complex__", "unary_numeric", "(self)", "Convert to complex", "complex"),
    "__int__": DunderInfo("__int__", "unary_numeric", "(self)", "Convert to int", "int"),
    "__float__": DunderInfo("__float__", "unary_numeric", "(self)", "Convert to float", "float"),
    "__index__": DunderInfo("__index__", "unary_numeric", "(self)", "Convert to integer for slicing", "int"),
    "__round__": DunderInfo("__round__", "unary_numeric", "(self[, n])", "Round to n digits", "int|float"),
    "__trunc__": DunderInfo("__trunc__", "unary_numeric", "(self)", "Truncate to integer", "int"),
    "__floor__": DunderInfo("__floor__", "unary_numeric", "(self)", "Floor to integer", "int"),
    "__ceil__": DunderInfo("__ceil__", "unary_numeric", "(self)", "Ceiling to integer", "int"),

    # Copy/Pickle
    "__copy__": DunderInfo("__copy__", "copy_pickle", "(self)", "Shallow copy", "same type"),
    "__deepcopy__": DunderInfo("__deepcopy__", "copy_pickle", "(self, memo)", "Deep copy", "same type"),
    "__getnewargs__": DunderInfo("__getnewargs__", "copy_pickle", "(self)", "Args for __new__ when unpickling", "tuple"),
    "__getnewargs_ex__": DunderInfo("__getnewargs_ex__", "copy_pickle", "(self)", "Args and kwargs for __new__", "tuple[tuple, dict]"),
    "__getstate__": DunderInfo("__getstate__", "copy_pickle", "(self)", "State for pickling", "dict"),
    "__setstate__": DunderInfo("__setstate__", "copy_pickle", "(self, state)", "Restore from pickled state", "None"),
    "__reduce__": DunderInfo("__reduce__", "copy_pickle", "(self)", "Pickle reduction", "tuple"),
    "__reduce_ex__": DunderInfo("__reduce_ex__", "copy_pickle", "(self, protocol)", "Pickle reduction with protocol", "tuple"),

    # Numeric - Reflected
    "__radd__": DunderInfo("__radd__", "reflected_numeric", "(self, other)", "Reflected addition", "same type"),
    "__rsub__": DunderInfo("__rsub__", "reflected_numeric", "(self, other)", "Reflected subtraction", "same type"),
    "__rmul__": DunderInfo("__rmul__", "reflected_numeric", "(self, other)", "Reflected multiplication", "same type"),
    "__rmatmul__": DunderInfo("__rmatmul__", "reflected_numeric", "(self, other)", "Reflected matrix multiplication", "same type"),
    "__rtruediv__": DunderInfo("__rtruediv__", "reflected_numeric", "(self, other)", "Reflected true division", "float"),
    "__rfloordiv__": DunderInfo("__rfloordiv__", "reflected_numeric", "(self, other)", "Reflected floor division", "int"),
    "__rmod__": DunderInfo("__rmod__", "reflected_numeric", "(self, other)", "Reflected modulo", "same type"),
    "__rdivmod__": DunderInfo("__rdivmod__", "reflected_numeric", "(self, other)", "Reflected divmod", "tuple"),
    "__rpow__": DunderInfo("__rpow__", "reflected_numeric", "(self, other)", "Reflected power", "same type"),
    "__rlshift__": DunderInfo("__rlshift__", "reflected_numeric", "(self, other)", "Reflected left shift", "int"),
    "__rrshift__": DunderInfo("__rrshift__", "reflected_numeric", "(self, other)", "Reflected right shift", "int"),
    "__rand__": DunderInfo("__rand__", "reflected_numeric", "(self, other)", "Reflected bitwise AND", "int"),
    "__rxor__": DunderInfo("__rxor__", "reflected_numeric", "(self, other)", "Reflected bitwise XOR", "int"),
    "__ror__": DunderInfo("__ror__", "reflected_numeric", "(self, other)", "Reflected bitwise OR", "int"),

    # Numeric - In-place
    "__iadd__": DunderInfo("__iadd__", "inplace_numeric", "(self, other)", "In-place addition", "self"),
    "__isub__": DunderInfo("__isub__", "inplace_numeric", "(self, other)", "In-place subtraction", "self"),
    "__imul__": DunderInfo("__imul__", "inplace_numeric", "(self, other)", "In-place multiplication", "self"),
    "__imatmul__": DunderInfo("__imatmul__", "inplace_numeric", "(self, other)", "In-place matrix multiplication", "self"),
    "__itruediv__": DunderInfo("__itruediv__", "inplace_numeric", "(self, other)", "In-place true division", "self"),
    "__ifloordiv__": DunderInfo("__ifloordiv__", "inplace_numeric", "(self, other)", "In-place floor division", "self"),
    "__imod__": DunderInfo("__imod__", "inplace_numeric", "(self, other)", "In-place modulo", "self"),
    "__ipow__": DunderInfo("__ipow__", "inplace_numeric", "(self, other)", "In-place power", "self"),
    "__ilshift__": DunderInfo("__ilshift__", "inplace_numeric", "(self, other)", "In-place left shift", "self"),
    "__irshift__": DunderInfo("__irshift__", "inplace_numeric", "(self, other)", "In-place right shift", "self"),
    "__iand__": DunderInfo("__iand__", "inplace_numeric", "(self, other)", "In-place bitwise AND", "self"),
    "__ixor__": DunderInfo("__ixor__", "inplace_numeric", "(self, other)", "In-place bitwise XOR", "self"),
    "__ior__": DunderInfo("__ior__", "inplace_numeric", "(self, other)", "In-place bitwise OR", "self"),

    # Class
    "__class_getitem__": DunderInfo("__class_getitem__", "class", "(cls, item)", "Parameterize generic class", "GenericAlias"),
    "__mro_entries__": DunderInfo("__mro_entries__", "class", "(self, bases)", "MRO entry resolution", "tuple"),
    "__subclasshook__": DunderInfo("__subclasshook__", "class", "(cls, subclass)", "Customize issubclass()", "bool|NotImplemented"),
    "__instancecheck__": DunderInfo("__instancecheck__", "class", "(cls, instance)", "Customize isinstance()", "bool"),
    "__subclasscheck__": DunderInfo("__subclasscheck__", "class", "(cls, subclass)", "Customize issubclass()", "bool"),
    "__prepare__": DunderInfo("__prepare__", "class", "(metacls, name, bases, **kwds)", "Prepare class namespace", "dict"),

    # Slot
    "__slots__": DunderInfo("__slots__", "slot", "", "Declare fixed set of attributes", "tuple|list|set"),

    # Buffer Protocol
    "__buffer__": DunderInfo("__buffer__", "buffer", "(self, flags)", "Return buffer object", "memoryview"),
    "__release_buffer__": DunderInfo("__release_buffer__", "buffer", "(self, buffer)", "Release buffer", "None"),

    # Match Statement (Python 3.10+)
    "__match_args__": DunderInfo("__match_args__", "match", "", "Positional match pattern names", "tuple[str, ...]"),

    # Module Attributes
    "__name__": DunderInfo("__name__", "module", "", "Module or class name", "str"),
    "__doc__": DunderInfo("__doc__", "module", "", "Documentation string", "str|None"),
    "__package__": DunderInfo("__package__", "module", "", "Package name", "str|None"),
    "__loader__": DunderInfo("__loader__", "module", "", "Module loader", "Loader"),
    "__spec__": DunderInfo("__spec__", "module", "", "Module spec", "ModuleSpec|None"),
    "__path__": DunderInfo("__path__", "module", "", "Package path", "list[str]"),
    "__file__": DunderInfo("__file__", "module", "", "Module file path", "str|None"),
    "__cached__": DunderInfo("__cached__", "module", "", "Cached bytecode path", "str|None"),
    "__builtins__": DunderInfo("__builtins__", "module", "", "Built-in namespace", "dict|module"),
    "__all__": DunderInfo("__all__", "module", "", "Public names for star import", "list[str]"),
    "__version__": DunderInfo("__version__", "module", "", "Module version string", "str"),
    "__author__": DunderInfo("__author__", "module", "", "Module author", "str"),

    # Class Attributes
    "__dict__": DunderInfo("__dict__", "class_attr", "", "Instance attribute dictionary", "dict"),
    "__class__": DunderInfo("__class__", "class_attr", "", "Class of instance", "type"),
    "__bases__": DunderInfo("__bases__", "class_attr", "", "Base classes", "tuple"),
    "__mro__": DunderInfo("__mro__", "class_attr", "", "Method resolution order", "tuple"),
    "__qualname__": DunderInfo("__qualname__", "class_attr", "", "Qualified name", "str"),
    "__module__": DunderInfo("__module__", "class_attr", "", "Module where defined", "str"),
    "__annotations__": DunderInfo("__annotations__", "class_attr", "", "Type annotations", "dict"),
    "__weakref__": DunderInfo("__weakref__", "class_attr", "", "Weak reference support", "weakref"),
    "__abstractmethods__": DunderInfo("__abstractmethods__", "class_attr", "", "Set of abstract methods", "frozenset"),
}


def is_dunder(name: str) -> bool:
    """Check if a name is a valid dunder method."""
    result = name in DUNDER_METHODS
    _trace("is_dunder(%s) -> %s", name, result)
    return result


def is_dunder_pattern(name: str) -> bool:
    """Check if a name follows the dunder pattern (__name__)."""
    result = name.startswith("__") and name.endswith("__") and len(name) > 4
    _trace("is_dunder_pattern(%s) -> %s", name, result)
    return result


def get_dunder_category(name: str) -> str | None:
    """Get the category of a dunder method."""
    for category, dunders_set in DUNDER_CATEGORIES.items():
        if name in dunders_set:
            _trace("get_dunder_category(%s) -> %s", name, category)
            return category
    _trace("get_dunder_category(%s) -> None", name)
    return None


def get_dunder_info(name: str) -> DunderInfo | None:
    """Get detailed information about a dunder method."""
    result = DUNDER_DETAILS.get(name)
    _trace("get_dunder_info(%s) -> %s", name, "found" if result else "not found")
    return result


def get_dunders_by_category(category: str) -> frozenset[str]:
    """Get all dunders in a category."""
    result = DUNDER_CATEGORIES.get(category, frozenset())
    _trace("get_dunders_by_category(%s) -> %d dunders", category, len(result))
    return result


def is_fake_dunder(name: str) -> bool:
    """Check if a name looks like a dunder but isn't a real one."""
    result = is_dunder_pattern(name) and not is_dunder(name)
    _trace("is_fake_dunder(%s) -> %s", name, result)
    return result


if __name__ == "__main__":
    import sys

    print("signature_engine.dunders — Dunder method registry")
    print(f"  Known dunders: {len(DUNDER_METHODS)}")
    print(f"  Categories: {len(DUNDER_CATEGORIES)}")
    for cat, dunders in sorted(DUNDER_CATEGORIES.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"    {cat}: {len(dunders)}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        print(f"\nLookup: '{name}'")
        print(f"  is_dunder: {is_dunder(name)}")
        print(f"  category: {get_dunder_category(name)}")
        info = get_dunder_info(name)
        if info:
            print(f"  info: {info}")
        print(f"  is_fake_dunder: {is_fake_dunder(name)}")
