"""
AI Fake Detector - Base class and orchestration.

Part of NoAIMath Validator system (noai_validator).

Fully async implementation per app rationale.
"""

import ast
import asyncio
import logging
from typing import Any, List, Tuple, Optional, Dict, Set, TYPE_CHECKING

# Configure module logger
logger = logging.getLogger(__name__)

from .core_checks import CoreChecksMixin
from .structural_checks import StructuralChecksMixin
from .math_checks import MathChecksMixin
from .advanced_checks import AdvancedChecksMixin
from .hallucination_checks import HallucinationChecksMixin
from .redundancy_checks import RedundancyChecksMixin
from .safety_checks import SafetyChecksMixin
from .style_checks import StyleChecksMixin
from .semantic_checks import SemanticChecksMixin
from .extended_semantic_checks import ExtendedSemanticChecksMixin
from .rulebook_checks import RulebookChecksMixin
# TODO: darkarts_checks.py not yet extracted from monolithic detector.py
# from .darkarts_checks import DarkArtsChecksMixin

if TYPE_CHECKING:
    from orchestrator.core.data.signatures import ArtifactDefinitions
    pass  # FIX_34 (2026-09-10): ProjectIndexer archived (indexer.py, 0 callers); `project_index` stays a None-able seam
    from ..core import FunctionMetrics


def _stdlib_method_names() -> frozenset:
    """IG-10 (2026-09-06): names of methods / attributes the standard library defines on its everyday classes — a lexical
    fact read from the interpreter, never a guess. A call `.wait()` / `.put()` / `.join()` / `.as_string()` is not hallucinated."""
    import subprocess, threading, queue, socket, io, collections, pathlib, datetime, re as _re, logging, argparse, email.message, \
        http.client, asyncio, concurrent.futures, multiprocessing, select as _select, tempfile, zipfile, tarfile, decimal, fractions, uuid, enum
    types: tuple = (subprocess.Popen, threading.Thread, threading.Event, threading.Condition, threading.Lock().__class__, threading.Semaphore,
             queue.Queue, queue.LifoQueue, socket.socket, io.IOBase, io.TextIOBase, io.BufferedIOBase, io.BytesIO, io.StringIO,
             collections.deque, collections.OrderedDict, collections.Counter, collections.defaultdict, collections.ChainMap,
             pathlib.PurePath, pathlib.Path, datetime.datetime, datetime.date, datetime.timedelta, _re.Pattern, _re.Match,
             logging.Logger, logging.Handler, argparse.ArgumentParser, email.message.Message, http.client.HTTPConnection,
             http.client.HTTPResponse, asyncio.Future, asyncio.Task, asyncio.Queue, asyncio.Event, asyncio.AbstractEventLoop,
             concurrent.futures.Future, concurrent.futures.Executor, multiprocessing.Process, tempfile.SpooledTemporaryFile,
             zipfile.ZipFile, tarfile.TarFile, decimal.Decimal, fractions.Fraction, uuid.UUID, enum.Enum, BaseException, type(iter([])))
    out: set = set()
    for t in types:
        out.update(n for n in dir(t) if not n.startswith('__'))
    out.update(n for n in dir(_select) if not n.startswith('__'))
    return frozenset(out)


STDLIB_METHOD_NAMES: frozenset = _stdlib_method_names()


class AIFakeDetector(
    CoreChecksMixin,
    StructuralChecksMixin,
    MathChecksMixin,
    AdvancedChecksMixin,
    HallucinationChecksMixin,
    RedundancyChecksMixin,
    SafetyChecksMixin,
    StyleChecksMixin,
    SemanticChecksMixin,
    ExtendedSemanticChecksMixin,
    RulebookChecksMixin,
    # DarkArtsChecksMixin,  # TODO: not yet extracted
):
    """
    Detects AI-generated counterfeit code patterns.

    Philosophy: AI fakes violate mathematical invariants:
    1. Inputs must influence outputs
    2. Computation must be captured
    3. Iteration must accumulate
    4. Functions must have returns OR side effects

    Supports dynamic definitions via ArtifactDefinitions for
    configurable pattern matching without code changes.
    """

    # Class-level definitions cache (shared across instances)
    _definitions: Optional['ArtifactDefinitions'] = None

    @classmethod
    def set_definitions(cls, definitions: 'ArtifactDefinitions') -> None:
        """
        Set dynamic artifact definitions for pattern matching.

        This allows updating detection patterns at runtime without
        modifying code - similar to "signature definition" updates.

        Args:
            definitions: ArtifactDefinitions loaded from signatures.json
        """
        cls._definitions = definitions
        logger.info("Artifact definitions updated (%d patterns loaded)",
                   len(definitions.patterns) if hasattr(definitions, 'patterns') else 0)

    @classmethod
    def get_definitions(cls) -> Optional['ArtifactDefinitions']:
        """Get current artifact definitions (if set)."""
        return cls._definitions

    def __init__(
        self,
        metrics: 'FunctionMetrics',
        func_node: ast.FunctionDef,
        project_index: Optional[Any] = None,   # FIX_34: the indexer is archived; a future cross-file index plugs in here
        imported_names: Optional[Dict[str, str]] = None,
        current_module: str = "",
        module_level_names: Optional[Set[str]] = None,
        artifact_values: Optional[Dict] = None,
        noreturn_names: Optional[Set[str]] = None,
        enclosing_names: Optional[Set[str]] = None,
        module_attr_names: Optional[Set[str]] = None,
        dunder_counts: Optional[Dict[str, int]] = None,
    ):
        self.metrics = metrics
        self.func = func_node
        self.noreturn_names: Set[str] = set(noreturn_names or ())   # IG-6: defs in this module annotated NoReturn / Never (lexical fact)
        self.observations: List[Dict[str, Any]] = []  # raw AST observations (no severity)
        # Cross-file resolution support
        self.project_index = project_index
        self.imported_names = imported_names or {}
        self.current_module = current_module
        self.module_level_names = module_level_names or set()
        # Config artifact values for cross-file correlation (NAI-099 extension)
        self.artifact_values = artifact_values or {}
        # Base-class names of the enclosing class (set by the validator; rules
        # hardening 2026-09-05 — Protocol / ABC / subclass awareness)
        self.class_bases: List[str] = []
        # IG-9 (2026-09-06): names bound in every ENCLOSING function scope (a closure sees them) — a scoping fact of the language.
        self.enclosing_names: Set[str] = set(enclosing_names or ())
        # IG-10 (2026-09-06): every method / function / attribute name THIS MODULE defines — a name the module defines is not hallucinated.
        self.module_attr_names: Set[str] = set(module_attr_names or ())
        # FIX_34 (b) (2026-09-10): the NAI-058 whole-set fact for this file's directory subtree, computed once per
        # directory validation and handed in — never walked from inside a check. None = not measured (single file).
        self.dunder_counts: Optional[Dict[str, int]] = dunder_counts
        logger.debug("AIFakeDetector initialized for function: %s", func_node.name)

    # ── context helpers shared by every check mixin (2026-09-05) ──────────
    @staticmethod
    def _own_scope(root: ast.AST):
        """IG-7 / IG-9 (2026-09-06): the nodes of ROOT's OWN scope — a nested def / lambda / class body is another scope
        and is never walked as if it were this function's body (its returns, assignments and branches are its own)."""
        stack = list(ast.iter_child_nodes(root))
        while stack:
            n = stack.pop()
            yield n
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            stack.extend(ast.iter_child_nodes(n))

    def _has_decorator(self, *names: str) -> bool:
        """True when the function carries any decorator whose terminal name is in *names*
        (`@overload`, `@typing.overload`, `@pytest.mark.parametrize(...)` all resolve)."""
        for d in self.func.decorator_list:
            node = d.func if isinstance(d, ast.Call) else d
            name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ''
            if name in names:
                return True
        return False

    def _class_has_bases(self) -> bool:
        return any(b and b != 'object' for b in (self.class_bases or []))

    def _class_is_protocol(self) -> bool:
        return any(b in ('Protocol', 'ABC', 'ABCMeta') for b in (self.class_bases or []))

    async def run_all_checks(self) -> List[Dict[str, Any]]:
        """
        Run all AI fake detection checks.

        Async implementation - groups checks into batches and yields
        control periodically for cooperative multitasking.
        """
        logger.debug("Starting all checks for function: %s", self.func.name)

        # === CORE CHECKS (NAI-002 to NAI-025) ===
        self._check_unreachable_after_return()
        self._check_unused_parameters()
        self._check_pass_only_function()
        self._check_canned_return()  # NAI-212 (plan item 4, 2026-09-05)
        self._check_redundant_else_after_return()
        self._check_variable_immediate_overwrite()
        self._check_nested_function_never_called()
        self._check_reimport_inside_function()
        self._check_input_output_disconnect()
        self._check_discarded_collection()
        self._check_dead_computation()
        self._check_side_effect_free()
        self._check_meaningless_operations()
        self._check_fake_iteration()
        self._check_return_input_unchanged()
        self._check_exception_swallow()
        self._check_async_no_await()
        self._check_sync_calling_async()
        self._check_constant_returns()
        self._check_test_fakes()
        self._check_logging_only()
        self._check_discarded_calls()
        self._check_self_comparisons()
        self._check_loop_patterns()
        self._check_noop_operations()
        self._check_pre_increment_decrement()
        self._check_shadowing_builtins()
        self._check_duplicate_dict_keys()
        self._check_duplicate_dict_keys_semantic()

        # Yield control after core checks batch
        await asyncio.sleep(0)

        # === STRUCTURAL CHECKS (NAI-026 to NAI-029) ===
        self._check_identical_branches()
        self._check_mutation_theater()
        self._check_unreachable_code()
        self._check_constant_conditions()
        self._check_inverse_operations()
        self._check_loop_else_without_break()

        # === MATHEMATICAL DETECTION (NAI-030 to NAI-039) ===
        self._check_data_flow_disconnect()
        self._check_variable_liveness()
        self._check_algebraic_identity()
        self._check_comprehension_identity()
        self._check_docstring_only_body()
        self._check_dunder_fakes()
        self._check_redundant_comparisons()
        self._check_loop_overwrite_pattern()
        self._check_constant_conditional()

        # Yield control after math checks batch
        await asyncio.sleep(0)

        # === ADVANCED DETECTION (NAI-040 to NAI-049) ===
        self._check_subtree_duplication()
        self._check_param_shadow()
        self._check_exception_alias_unused()
        self._check_placeholder_strings()
        self._check_infinite_loop_patterns()
        self._check_return_type_inconsistency()
        self._check_closure_no_capture()
        self._check_assert_side_effects()
        self._check_identical_method_bodies()

        # === PHASE 1: HALLUCINATION DETECTION (NAI-050 to NAI-058) ===
        self._check_undefined_calls()
        self._check_misspelled_builtins()
        self._check_redundant_nesting()
        self._check_repetitive_branches()
        self._check_duplicate_statements()
        self._check_hallucinated_function_calls()
        self._check_misspelled_module_imports()
        self._check_hallucinated_module_imports()
        self._check_fake_dunder_methods()
        self._check_invented_constants()

        # Yield control after hallucination checks batch
        await asyncio.sleep(0)

        # === PHASE 2B: ENHANCED REDUNDANCY (NAI-060 to NAI-069) ===
        self._check_double_negation()
        self._check_bool_comparison()
        self._check_len_zero_comparison()
        self._check_redundant_or_chain()
        self._check_self_assignment()
        self._check_redundant_type_conversion()
        self._check_nested_ternary()
        self._check_empty_string_concat()
        self._check_while_true_immediate_break()
        self._check_fstring_no_placeholders()
        self._check_unnecessary_list_wrapping()

        # === PHASE 3: SAFETY GAP DETECTION (NAI-070 to NAI-079, NAI-091 to NAI-099, NAI-200) ===
        self._check_bare_except()
        self._check_mutable_default_arg()
        self._check_hardcoded_secrets()
        self._check_sql_injection_risk()
        self._check_unguarded_json_parse()
        self._check_unguarded_file_ops()
        self._check_division_by_variable()
        self._check_unguarded_dict_access()
        self._check_silent_error_swallowing()
        self._check_hardcoded_paths()
        self._check_inplace_param_mutation()
        self._check_unsafe_subprocess()
        self._check_unsafe_deserialization()
        self._check_sys_path_manipulation()
        self._check_float_equality()
        self._check_assert_for_validation()
        self._check_unguarded_external_calls()
        self._check_print_only_output()
        self._check_magic_numbers()
        self._check_risky_single_call()
        self._check_unsafe_type_coercion()
        self._check_cwd_sensitive_path()
        self._check_lru_cache_on_side_effect()
        self._check_threading_in_sync()

        # === EXTENDED SECURITY (NAI-160 to NAI-167) ===
        self._check_missing_input_validation()
        self._check_http_without_timeout()
        self._check_no_cert_validation()
        self._check_hardcoded_bind_all()
        self._check_insecure_temp_file()
        self._check_trojan_source_bidi()
        self._check_raise_not_implemented()
        self._check_except_clause_ordering()
        self._check_return_in_finally()
        self._check_mutable_class_level_variables()
        self._check_missing_input_validation_extended()
        self._check_deprecated_api_usage()
        self._check_environmental_context_blindness()

        # Yield control after safety checks batch
        await asyncio.sleep(0)

        # === PHASE 4: STYLE/STRUCTURE (NAI-080 to NAI-095) ===
        self._check_generic_naming()
        self._check_numbered_variables()
        self._check_excessive_params()
        self._check_deep_nesting()
        self._check_function_length()
        # NAI-085 STRUCK from verdicts (run 19, 2026-09-05): a design smell, not counterfeit
        self._check_repeated_attribute_access()
        self._check_loop_invariant()
        self._check_string_concat_loop()
        self._check_append_loop_to_comprehension()
        self._check_single_letter_vars()
        self._check_comment_code_ratio()
        self._check_hyper_descriptive_naming()
        self._check_repeated_lookups_in_loop()
        self._check_concat_in_loop_extended()
        self._check_commented_out_code()
        self._check_god_class_method()
        # NAI-184 STRUCK from verdicts (run 19, 2026-09-05): a design smell, not counterfeit
        self._check_cyclomatic_complexity()
        self._check_cognitive_complexity()
        self._check_comment_to_code_ratio_source()
        self._check_membership_test_on_list()
        self._check_noqa_type_ignore_overuse()
        self._check_structural_over_engineering()
        self._check_compulsive_modularization()
        self._check_commented_out_code_blocks()

        # === PHASE 5: DARK ARTS DETECTION (NAI-091 to NAI-099) ===
        # TODO: darkarts_checks.py not yet extracted - these fall back to monolithic detector.py
        # self._check_parameter_integrity()
        # self._check_semantic_density()
        # self._check_obfuscation_patterns()

        # Yield control before semantic checks
        await asyncio.sleep(0)

        # === PHASE 6: SEMANTIC ANALYSIS (NAI-100 to NAI-119) ===
        self._check_param_return_disconnect()
        self._check_magic_number_return()
        self._check_docstring_code_mismatch()
        self._check_boolean_logic_inversion()
        self._check_name_operation_mismatch()
        self._check_no_transform_passthrough()
        self._check_missing_normalization()
        self._check_return_type_name_mismatch()
        self._check_opposite_operation()
        self._check_hardcoded_collection_return()
        self._check_string_concat_in_loop()
        self._check_inconsistent_naming()
        self._check_validation_missing_error()
        self._check_cross_language_confusion()
        self._check_phantom_api_methods()
        self._check_hallucinated_packages()
        self._check_hedging_comments()

        # Yield control before extended semantic checks
        await asyncio.sleep(0)

        # === PHASE 7: EXTENDED SEMANTIC ANALYSIS (NAI-120 to NAI-150) ===
        # Fast static filters
        self._check_empty_function_body()
        self._check_excessive_parameters()
        self._check_assert_tuple()
        self._check_none_comparison()
        self._check_init_return()
        self._check_eval_exec()
        self._check_mutable_default_nested()

        # Prefix pattern checks
        self._check_getter_return()
        self._check_setter_return()
        self._check_boolean_prefix_return()
        self._check_process_without_iteration()
        self._check_filter_without_conditional()
        self._check_sort_without_comparison()
        self._check_count_without_accumulator()
        self._check_answer_table()
        self._check_search_without_comparison()
        self._check_build_without_return()

        # CFG analysis
        self._check_cfg_issues()

        # Def-use chains
        self._check_use_before_def()
        self._check_unused_variables()
        self._check_import_reassignment()

        # Test quality checks
        self._check_mock_everything_test()
        self._check_tautological_test()
        self._check_happy_path_only_test()
        self._check_assertion_free_test_with_calls()
        self._check_copy_paste_test_proliferation()
        self._check_boundary_value_blindness()
        self._check_silent_error_suppression_in_test()

        # D2 (2026-10-10): code that works but disagrees with its rulebook, its mirrored sibling, the tests' state
        # or its own output on varied inputs (NAI-255 to NAI-259)
        self._check_rulebook_and_siblings()

        logger.debug("Completed all checks for function: %s, found %d observations",
                    self.func.name, len(self.observations))
        if self.observations:
            logger.info("Function %s has %d observations: %s",
                       self.func.name, len(self.observations),
                       [obs.get("tag", "?") for obs in self.observations])

        return self.observations

    async def run_all_checks_sync(self) -> List[Dict[str, Any]]:
        """
        ENTIRE APP IS ASYNC: Convert synchronous wrapper to async.
        """
        return await self.run_all_checks()


if __name__ == "__main__":
    import ast
    import asyncio
    import sys

    if len(sys.argv) < 2:
        print("Usage: python base.py <file.py>")
        sys.exit(1)

    source = open(sys.argv[1], encoding="utf-8").read()
    tree = ast.parse(source, filename=sys.argv[1])

    async def _main() -> None:
        from no_aivalidator.noai_validator.extractor import MetricsExtractor
        total = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ext = MetricsExtractor(node, class_context=False, source=source)  # type: ignore[arg-type]  # FIX_54 ast-pos
                detector = AIFakeDetector(metrics=ext.metrics, func_node=node)  # type: ignore[arg-type]  # FIX_54 ast-pos
                observations = await detector.run_all_checks()
                if observations:
                    print(f"  {node.name}: {len(observations)} observation(s)")
                    for obs in observations:
                        print(f"    [{obs.get('tag', '?')}] line {obs.get('line', '?')}: {obs}")
                total += len(observations)
        print(f"\n{total} total observation(s) in {sys.argv[1]}")

    asyncio.run(_main())
