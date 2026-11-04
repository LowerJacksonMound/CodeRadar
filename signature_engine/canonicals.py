"""
Canonical function definitions for code analysis.

Defines expected structures and requirements for different function types.
"""

import logging
import os

from signature_engine.core import CanonicalDefinition, FunctionType, HardRequirements

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)

# Default canonical definitions for each function type
DEFAULT_CANONICALS: dict[FunctionType, CanonicalDefinition] = {
    FunctionType.VALIDATOR: CanonicalDefinition(
        func_type=FunctionType.VALIDATOR,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
            requires_comparison_or_call=True,
        ),
        description="Validates input and returns bool or raises exception",
    ),
    FunctionType.PREDICATE: CanonicalDefinition(
        func_type=FunctionType.PREDICATE,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
            requires_comparison_or_call=True,
        ),
        description="Returns boolean based on condition check",
    ),
    FunctionType.PROCESSOR: CanonicalDefinition(
        func_type=FunctionType.PROCESSOR,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Transforms input data and returns result",
    ),
    FunctionType.HANDLER: CanonicalDefinition(
        func_type=FunctionType.HANDLER,
        hard_reqs=HardRequirements(
            requires_params=True,
            allows_method_delegation=True,
            allows_call_delegation=True,
        ),
        description="Handles events, requests, or callbacks",
    ),
    FunctionType.FACTORY: CanonicalDefinition(
        func_type=FunctionType.FACTORY,
        hard_reqs=HardRequirements(
            requires_return=True,
            requires_call=True,
        ),
        description="Creates and returns new objects",
    ),
    FunctionType.INITIALIZER: CanonicalDefinition(
        func_type=FunctionType.INITIALIZER,
        hard_reqs=HardRequirements(
            # F-HR1 (2026-09-05): a parameterless `__init__(self)` that sets
            # defaults is ordinary Python (click ×109, httpie ×47, ddt ×76);
            # "requires parameters" was never a property of initializers.
            requires_params=False,
        ),
        description="Initializes object state (__init__)",
    ),
    FunctionType.DESTRUCTOR: CanonicalDefinition(
        func_type=FunctionType.DESTRUCTOR,
        hard_reqs=HardRequirements(),
        description="Cleans up resources (__del__)",
    ),
    FunctionType.GETTER: CanonicalDefinition(
        func_type=FunctionType.GETTER,
        hard_reqs=HardRequirements(
            requires_return=True,
        ),
        description="Returns attribute or computed value",
    ),
    FunctionType.SETTER: CanonicalDefinition(
        func_type=FunctionType.SETTER,
        hard_reqs=HardRequirements(
            requires_params=True,
        ),
        description="Sets attribute value",
    ),
    FunctionType.GENERATOR: CanonicalDefinition(
        func_type=FunctionType.GENERATOR,
        hard_reqs=HardRequirements(
            requires_yield=True,
        ),
        description="Yields values lazily",
    ),
    FunctionType.DECORATOR: CanonicalDefinition(
        func_type=FunctionType.DECORATOR,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Wraps and modifies functions/classes",
    ),
    FunctionType.ORCHESTRATOR: CanonicalDefinition(
        func_type=FunctionType.ORCHESTRATOR,
        hard_reqs=HardRequirements(
            # min_calls=2 EXCISED cut 2 (2026-09-05): a count gate in the hard-requirement layer (EXCISION_LIST class A)
            allows_call_delegation=True,
        ),
        description="Coordinates multiple operations or services",
    ),
    FunctionType.UTILITY: CanonicalDefinition(
        func_type=FunctionType.UTILITY,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Stateless helper function",
    ),
    FunctionType.DUNDER: CanonicalDefinition(
        func_type=FunctionType.DUNDER,
        hard_reqs=HardRequirements(),
        description="Magic method (__xxx__)",
    ),
    FunctionType.CONTEXT_MANAGER: CanonicalDefinition(
        func_type=FunctionType.CONTEXT_MANAGER,
        hard_reqs=HardRequirements(
            requires_yield=True,
        ),
        description="Manages resource lifecycle via with statement",
    ),
    FunctionType.ASYNC_HANDLER: CanonicalDefinition(
        func_type=FunctionType.ASYNC_HANDLER,
        hard_reqs=HardRequirements(
            allows_method_delegation=True,
            allows_call_delegation=True,
        ),
        description="Async event or request handler",
    ),
    FunctionType.RENDERER: CanonicalDefinition(
        func_type=FunctionType.RENDERER,
        hard_reqs=HardRequirements(
            requires_return=True,
        ),
        description="Produces output representation (HTML, JSON, etc.)",
    ),
    FunctionType.EVENT_LOOP: CanonicalDefinition(
        func_type=FunctionType.EVENT_LOOP,
        hard_reqs=HardRequirements(
            requires_loop=True,
        ),
        description="Main event processing loop",
    ),
    FunctionType.MUTATION: CanonicalDefinition(
        func_type=FunctionType.MUTATION,
        hard_reqs=HardRequirements(
            requires_params=True,
        ),
        description="Modifies object state in place",
    ),
    FunctionType.TRANSFORMER: CanonicalDefinition(
        func_type=FunctionType.TRANSFORMER,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Transforms input data into a different shape or structure",
    ),
    FunctionType.ACCUMULATOR: CanonicalDefinition(
        func_type=FunctionType.ACCUMULATOR,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
            requires_loop_or_comprehension=True,
        ),
        description="Aggregates or reduces a collection into a result",
    ),
    FunctionType.MAPPER: CanonicalDefinition(
        func_type=FunctionType.MAPPER,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Applies a transformation to each element, returning a new collection",
    ),
    FunctionType.PARSER: CanonicalDefinition(
        func_type=FunctionType.PARSER,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Parses structured input (text, bytes, tokens) into data objects",
    ),
    FunctionType.FORMATTER: CanonicalDefinition(
        func_type=FunctionType.FORMATTER,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Formats data into a string or output representation",
    ),
    FunctionType.CONVERTER: CanonicalDefinition(
        func_type=FunctionType.CONVERTER,
        hard_reqs=HardRequirements(
            requires_params=True,
            requires_return=True,
        ),
        description="Converts data from one type or encoding to another",
    ),
    FunctionType.UNKNOWN: CanonicalDefinition(
        func_type=FunctionType.UNKNOWN,
        hard_reqs=HardRequirements(),
        description="Unclassified function type",
    ),
}

# Function name prefixes that suggest types
FUNCTION_TYPE_PREFIXES: dict[str, FunctionType] = {
    # Validators
    "validate_": FunctionType.VALIDATOR,
    "check_": FunctionType.VALIDATOR,
    "verify_": FunctionType.VALIDATOR,
    "ensure_": FunctionType.VALIDATOR,
    "assert_": FunctionType.VALIDATOR,

    # Predicates
    "is_": FunctionType.PREDICATE,
    "has_": FunctionType.PREDICATE,
    "can_": FunctionType.PREDICATE,
    "should_": FunctionType.PREDICATE,
    "will_": FunctionType.PREDICATE,
    "does_": FunctionType.PREDICATE,
    "are_": FunctionType.PREDICATE,

    # Getters
    "get_": FunctionType.GETTER,
    "fetch_": FunctionType.GETTER,
    "load_": FunctionType.GETTER,
    "read_": FunctionType.GETTER,
    "retrieve_": FunctionType.GETTER,
    "find_": FunctionType.GETTER,
    "lookup_": FunctionType.GETTER,

    # Setters
    "set_": FunctionType.SETTER,
    "update_": FunctionType.SETTER,
    "write_": FunctionType.SETTER,
    "save_": FunctionType.SETTER,
    "store_": FunctionType.SETTER,
    "put_": FunctionType.SETTER,

    # Factories
    "create_": FunctionType.FACTORY,
    "make_": FunctionType.FACTORY,
    "build_": FunctionType.FACTORY,
    "generate_": FunctionType.FACTORY,
    "construct_": FunctionType.FACTORY,
    "new_": FunctionType.FACTORY,

    # Processors
    "process_": FunctionType.PROCESSOR,
    "normalize_": FunctionType.PROCESSOR,
    "clean_": FunctionType.PROCESSOR,
    "sanitize_": FunctionType.PROCESSOR,

    # Transformers
    "transform_": FunctionType.TRANSFORMER,

    # Mappers
    "map_": FunctionType.MAPPER,
    "remap_": FunctionType.MAPPER,

    # Parsers
    "parse_": FunctionType.PARSER,
    "deserialize_": FunctionType.PARSER,
    "decode_": FunctionType.PARSER,

    # Formatters
    "format_": FunctionType.FORMATTER,
    "serialize_": FunctionType.FORMATTER,
    "encode_": FunctionType.FORMATTER,

    # Converters
    "convert_": FunctionType.CONVERTER,
    "to_": FunctionType.CONVERTER,

    # Handlers
    "handle_": FunctionType.HANDLER,
    "on_": FunctionType.HANDLER,
    "do_": FunctionType.HANDLER,
    "execute_": FunctionType.HANDLER,
    "run_": FunctionType.HANDLER,
    "perform_": FunctionType.HANDLER,

    # Renderers
    "render_": FunctionType.RENDERER,
    "display_": FunctionType.RENDERER,
    "show_": FunctionType.RENDERER,
    "draw_": FunctionType.RENDERER,
    "print_": FunctionType.RENDERER,
    "output_": FunctionType.RENDERER,

    # Mutations
    "add_": FunctionType.MUTATION,
    "remove_": FunctionType.MUTATION,
    "delete_": FunctionType.MUTATION,
    "insert_": FunctionType.MUTATION,
    "append_": FunctionType.MUTATION,
    "clear_": FunctionType.MUTATION,
    "reset_": FunctionType.MUTATION,
    "modify_": FunctionType.MUTATION,
    "change_": FunctionType.MUTATION,

    # Initializers
    "init_": FunctionType.INITIALIZER,
    "initialize_": FunctionType.INITIALIZER,
    "setup_": FunctionType.INITIALIZER,
    "configure_": FunctionType.INITIALIZER,

    # Destructors
    "cleanup_": FunctionType.DESTRUCTOR,
    "teardown_": FunctionType.DESTRUCTOR,
    "destroy_": FunctionType.DESTRUCTOR,
    "dispose_": FunctionType.DESTRUCTOR,
    "close_": FunctionType.DESTRUCTOR,
    "shutdown_": FunctionType.DESTRUCTOR,
}


def get_canonical(func_type: FunctionType) -> CanonicalDefinition | None:
    """Get the canonical definition for a function type."""
    result = DEFAULT_CANONICALS.get(func_type)
    _trace("get_canonical(%s) -> %s", func_type.name, "found" if result else "not found")
    return result


def infer_function_type(name: str) -> FunctionType:
    """Infer the function type from its name based on prefix."""
    # Check for dunder
    if name.startswith("__") and name.endswith("__"):
        _trace("infer_function_type(%s) -> DUNDER", name)
        return FunctionType.DUNDER

    # Check prefixes
    name_lower = name.lower()
    for prefix, func_type in FUNCTION_TYPE_PREFIXES.items():
        if name_lower.startswith(prefix):
            _trace("infer_function_type(%s) -> %s (prefix=%s)", name, func_type.name, prefix)
            return func_type

    _trace("infer_function_type(%s) -> UNKNOWN", name)
    return FunctionType.UNKNOWN


def get_requirements(func_type: FunctionType) -> HardRequirements:
    """Get the hard requirements for a function type."""
    canonical = DEFAULT_CANONICALS.get(func_type)
    _trace("get_requirements(%s) -> %s", func_type.name, "found" if canonical else "default")
    if canonical:
        return canonical.hard_reqs
    return HardRequirements()


def merge_canonicals(
    base: dict[FunctionType, CanonicalDefinition],
    overrides: dict[FunctionType, CanonicalDefinition],
) -> dict[FunctionType, CanonicalDefinition]:
    """Merge two canonical definition dictionaries.

    Overrides take precedence over base definitions.
    """
    result = dict(base)
    result.update(overrides)
    return result


def validate_against_canonical(
    func_type: FunctionType,
    has_params: bool = False,
    has_return: bool = False,
    has_yield: bool = False,
    has_call: bool = False,
    has_comparison: bool = False,
    has_loop: bool = False,
    call_count: int = 0,
) -> list[str]:
    """Validate function characteristics against canonical requirements.

    Returns a list of violations (empty if valid).
    """
    _trace("validate_against_canonical(%s)", func_type.name)
    canonical = DEFAULT_CANONICALS.get(func_type)
    if not canonical:
        return []

    reqs = canonical.hard_reqs
    violations = []

    if reqs.requires_params and not has_params:
        violations.append(f"{func_type.name} requires parameters")

    if reqs.requires_return and not has_return:
        violations.append(f"{func_type.name} requires return statement")

    if reqs.requires_yield and not has_yield:
        violations.append(f"{func_type.name} requires yield statement")

    if reqs.requires_call and not has_call:
        violations.append(f"{func_type.name} requires function call")

    if reqs.requires_comparison_or_call and not (has_comparison or has_call):
        violations.append(f"{func_type.name} requires comparison or function call")

    if reqs.requires_loop and not has_loop:
        violations.append(f"{func_type.name} requires loop")

    if reqs.min_calls > 0 and call_count < reqs.min_calls:
        violations.append(f"{func_type.name} requires at least {reqs.min_calls} calls")

    _trace("validate_against_canonical(%s) -> %d violations", func_type.name, len(violations))
    return violations


if __name__ == "__main__":
    import sys

    print("signature_engine.canonicals — Function type canonical definitions")
    print(f"  Canonical definitions: {len(DEFAULT_CANONICALS)}")
    print(f"  Prefix mappings: {len(FUNCTION_TYPE_PREFIXES)}")
    for ft, canon in DEFAULT_CANONICALS.items():
        reqs = get_requirements(ft)
        print(f"    {ft.name}: {canon.description[:60]}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        ft = infer_function_type(name)
        print(f"\nInferred type for '{name}': {ft.name}")
        canon = get_canonical(ft)  # type: ignore[assignment]  # FIX_54 ast-pos
        if canon:
            print(f"  Description: {canon.description}")
            violations = validate_against_canonical(ft, has_params=True, has_return=True)
            print(f"  Violations (params+return): {len(violations)}")
