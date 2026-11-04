"""File-level family (no_aivalidator/noai_validator/file_validation.py: FRN / GRF / IGR / NAI-2xx file rows) — item 4, 2026-09-08.

Every row is `unbuilt` (the honest placeholder) until this family is worked.
Set 4b-24 (2026-09-10, portion D's first): FRN-001, GRF-001, GRF-002, GRF-003, IGR-001 no-fix-by-design with the fact
that none decides a row — each is a `warnings` line on a row (F-WARN-UNPUB), never a rule id; the GRF constructs are
decided by their AST neighbours (dead store → NAI-010 / 031 / 147; identity chain → NAI-021S; an undefined-name read
alone passes). Facts: all five are appended by `validate_directory_async` after the per-function verdicts.
Set 4b-25 (2026-09-10): NAI-208 (what the broken line meant — a `<file>` row through the Builder's body-less path) and
NAI-214 (what an abstract shell should become — a `<class>` row; `meaning_source` corrected to `_check_abstract_shells`)
no-fix-by-design; NAI-202 / 205 / 226 no-fix-by-design with the fact that they never decide (warning lines: a dead
function, a package `__getattr__`, a nested def's depth).
Set 4b-26 (2026-09-10, portion D's last): RCA-001 no-fix-by-design with the fact that it never decides today — the fingerprint
stage normalizes the tree's names in place before the sweep, so callee names never match failed rows (the pinned
split-fake question made concrete; declared as it stands). **SUPERSEDED by FIX_47 (2026-09-17, owner Q7): RCA-001
DECIDES rows again — the fingerprint stage no longer renames the caller's tree (I-03 closed in
`utils/code_analysis/fingerprint.py`) and the sweep emits an RCA-001 OBSERVATION the Ranker's observations stage
weighs, instead of overriding the row after its verdict. The row below stays a PRESCRIPTION (FIX_41): which
parameters should reach the callee is still the dev's.** NAI-227, NAI-IM01, SYM-002 no-fix-by-design with the
fact that they never decide on the daemon route (a lambda count and a symmetry line are warnings; the import helper
emits nothing for an unresolvable absolute import). FAMILY `file_level` CLOSED: 14 no-fix-by-design, no rewriter —
the family's deciding rows are `<file>` (NAI-208), `<class>` (NAI-214) and the RCA-001 flip.
"""
from __future__ import annotations

from . import no_fix, prescribed, unbuilt

GENERATORS = [
        # 4b fact (kept, FIX_41): never decides a row: the id is written into the row's `warnings` (F-WARN-UNPUB) by `validate_directory_async`, and rule ids are built from `triggered_patterns` + `failure_reason` only — an INFO line naming how many RootCause candidate files were identified for a failing row; nothing to repair in the row itself (set 4b-24, 2026-09-10)
    prescribed("FRN-001", "no_aivalidator/noai_validator/file_validation.py:validate_directory_async",
               "Nothing to write on this row: the line names how many root-cause candidate files were identified; use it to order the repair of the failing rows it counts.",
               ""),
        # 4b fact (kept, FIX_41): never decides a row: the id is written into the row's `warnings` (F-WARN-UNPUB) by `validate_directory_async`, and rule ids are built from `triggered_patterns` + `failure_reason` only — a MEDIUM line naming an assignment the data-flow graph finds never read; the row itself is decided by NAI-010 / NAI-031 / NAI-147 (probed 2026-09-10), whose reading holds: whether the dead store was meant to be used, or its right side dropped, is the dev's (set 4b-24, 2026-09-10)
    prescribed("GRF-001", "no_aivalidator/noai_validator/file_validation.py:validate_directory_async (graph analysis)",
               "Read the dead store where the intent needs its value, or delete the assignment together with its right side when the computation is not wanted (the row's own NAI-010 / NAI-031 / NAI-147 decision).",
               "value = compute()\nreturn use(value)"),
        # 4b fact (kept, FIX_41): never decides a row: the id is written into the row's `warnings` (F-WARN-UNPUB) by `validate_directory_async`, and rule ids are built from `triggered_patterns` + `failure_reason` only — a HIGH line naming a name the graph finds used before any definition; a function that only reads an undefined name passes on the route (probed 2026-09-10); what the name should hold is the dev's (set 4b-24, 2026-09-10)
    prescribed("GRF-002", "no_aivalidator/noai_validator/file_validation.py:validate_directory_async (graph analysis)",
               "Define the name before its first use: bind it from the parameter, the module or the import the intent points to.",
               "name = <source per the intent>\n...\nuse(name)"),
        # 4b fact (kept, FIX_41): never decides a row: the id is written into the row's `warnings` (F-WARN-UNPUB) by `validate_directory_async`, and rule ids are built from `triggered_patterns` + `failure_reason` only — a HIGH line for a copy / alias identity chain the graph finds; the row itself is NAI-021S's (strict; probed 2026-09-10); what the function should transform is the dev's (set 4b-24, 2026-09-10)
    prescribed("GRF-003", "no_aivalidator/noai_validator/file_validation.py:validate_directory_async (graph analysis)",
               "Replace the copy / alias chain with the transformation the intent calls for (the row's NAI-021S prescription).",
               "def f(param):\n    return <transform>(param)"),
        # 4b fact (kept, FIX_41): never decides a row: the id is written into the row's `warnings` (F-WARN-UNPUB) by `validate_directory_async`, and rule ids are built from `triggered_patterns` + `failure_reason` only — an INFO line naming how many files import a failing row's module; a fact about the tree, nothing to repair (set 4b-24, 2026-09-10)
    prescribed("IGR-001", "no_aivalidator/noai_validator/file_validation.py:validate_directory_async (ImportGraphBuilder)",
               "Nothing to write: the line counts how many files import a failing module; repair that module first, its importers inherit the fix.",
               ""),
        # 4b fact (kept, FIX_41): never decides a row: the id is a `warnings` line on the row (F-WARN-UNPUB), never a rule id — a LOW line on a function the module never calls or references; whether it is dead, an entry point, or meant for a caller elsewhere is the dev's (set 4b-25, 2026-09-10)
    prescribed("NAI-202", "no_aivalidator/noai_validator/file_validation.py:_run_dead_function_scan",
               "Call the function from the code path that needs it, register it as an entry point when the intent names it as one, or delete it when neither applies.",
               ""),
        # 4b fact (kept, FIX_41): never decides a row: the id is a `warnings` line on the row (F-WARN-UNPUB), never a rule id — a module-level `__getattr__` in an `__init__.py` (dynamic attribute dispatch); whether the package should dispatch dynamically is the dev's design (set 4b-25, 2026-09-10)
    prescribed("NAI-205", "no_aivalidator/noai_validator/file_validation.py:_validate_file_from_ast",
               "Replace the module-level `__getattr__` with explicit names in the package `__init__` (an import per public name, or `__all__`); where the intent requires lazy dispatch, document each name it serves.",
               "from .module import name1, name2\n__all__ = [\"name1\", \"name2\"]"),
        # 4b fact (kept, FIX_41): a file that does not parse — a `<file>` row (line 0) carrying the SyntaxError; what the dev meant the broken line to say is theirs, and nothing mechanical exists without a tree. The row goes through the Builder's body-less path (`_file_facts` None → the declaration publishes; run 79, the first `<file>` row) (set 4b-25, 2026-09-10)
    prescribed("NAI-208", "no_aivalidator/noai_validator/file_validation.py:validate_file_async",
               "Fix the syntax error at the reported line so the file parses; until it parses no rule can read it and no other solution can be offered.",
               ""),
        # 4b fact (kept, FIX_41): an ABC (`ABC` base or `metaclass=ABCMeta`) with abstract methods, no concrete method and no subclass anywhere in the scanned trees — a `<class>` row; whether the shell should be implemented, subclassed elsewhere or removed is the dev's. `meaning_source` corrected: the catalogue named the helper `_is_stub_method_body`, the row is built by `_check_abstract_shells` (set 4b-25, 2026-09-10)
    prescribed("NAI-214", "no_aivalidator/noai_validator/file_validation.py:_check_abstract_shells",
               "Give the abstract shell a concrete subclass implementing every abstract method the intent needs, or remove the ABC when nothing is meant to implement it.",
               "class Concrete(Shell):\n    def method(self, ...):\n        <implementation>"),
        # 4b fact (kept, FIX_41): never decides a row: the id is a `warnings` line on the row (F-WARN-UNPUB), never a rule id — a LOW line on a nested def naming its depth; nesting is the dev's structure (set 4b-25, 2026-09-10)
    prescribed("NAI-226", "no_aivalidator/noai_validator/file_validation.py:_validate_file_from_ast",
               "Flatten the deeply nested def: lift the inner function to module level (passing what it closed over as parameters) or inline it at its single call site.",
               "def helper(<closed-over values>, ...):\n    ...\n\ndef outer(...):\n    return helper(<values>, ...)"),
        # 4b fact (kept, FIX_41): never decides a row: the id is a `warnings` line (F-WARN-UNPUB), never a rule id — `NAI-227: lambda_count=N` on the module's first row (the count of lambdas in the file; the magnitude gate was excised on cut 2); how many lambdas a module holds is the dev's (set 4b-26, 2026-09-10)
    prescribed("NAI-227", "no_aivalidator/noai_validator/file_validation.py:_validate_file_from_ast",
               "Nothing to write on the count itself; where a lambda carries logic, name it as a def.",
               "def <named>(x):\n    return <the lambda's body>"),
        # 4b fact (kept, FIX_41): never decides a row on the daemon route: `_validate_imports` (a name not in the validator's stdlib / packages tables) produced no NAI-IM01 line for an unresolvable absolute import in the probe of 2026-09-10 — the module row carried NAI-215 / NAI-223 instead, and an unresolvable RELATIVE import is NAI-217's row (declared on set 4b-03); the `<module>` decision at file_validation.py:1013 is reached only when that helper emits — declared with the fact. Which module was meant is the dev's anyway (set 4b-26, 2026-09-10)
    prescribed("NAI-IM01", "no_aivalidator/noai_validator/validator.py:_validate_imports",
               "Import the module the intent names: fix the spelling, use the right package, or add the dependency to the project's declared requirements.",
               "from <correct.module> import <name>"),
        # 4b fact (kept, FIX_41): the split-fake flip: a function that PASSED, calls a function that FAILED in the same file, and forwards none of its own parameters to it, is flipped to FAIL — which parameters should reach the callee, or whether the callee's failure is the caller's at all, is the dev's. NEVER DECIDES a row today (found 2026-09-10, set 4b-26): the fingerprint stage (`_normalized_fingerprint`, the NORM-FP line just before the sweep) has already renamed the tree's identifiers IN PLACE (`_var_0`, `_var_1`, …), so the sweep's callee names never match the failed rows' names and the flip cannot fire — a probe with a detector-failed helper and a non-forwarding caller passed on the route, while the same sweep on an un-normalized tree flipped it. THE FLOWCHART's pinned alignment question (owner 2026-09-09) made concrete; declared as it stands, nothing re-routed (set 4b-26, 2026-09-10). RE-ROUTED AND LIVE since FIX_47 (2026-09-17, owner Q7, run 136): the sweep reads the un-normalized tree and emits the RCA-001 OBSERVATION `{tag, line, description, callee, magnitude}`; the Ranker's `observations` stage decides the row (layer AI_FAKE_DETECTOR, `verdict_source: ranker`) and this prescription is what it then has to pick
    prescribed("RCA-001", "no_aivalidator/noai_validator/file_validation.py:_rca_intra_file_sweep",
               "Forward the caller's own parameters into the failed callee (or stop calling it) so the caller's result depends on its inputs; the flip itself re-routes as Ranker evidence under Q7.",
               "def caller(a, b):\n    return callee(a, b)"),
        # 4b fact (kept, FIX_41): never decides a row: the id is a `warnings` line (F-WARN-UNPUB), never a rule id — an arithmetic progression of three or more literals, or sequential comparison values in an if / elif chain (the NAI-013 shape), written as `SYM-002 (severity): …`; the helper's own rule id is discarded at file_validation.py:728 and the line always says SYM-002. Which values the dev meant is theirs (set 4b-26, 2026-09-10)
    prescribed("SYM-002", "no_aivalidator/noai_validator/file_validation.py:validate_directory_async (utils.code_analysis.symmetry.check_arithmetic_symmetry)",
               "Replace the literal progression with the rule that generates it (a range, a formula or a named table) so the sequence's meaning is in the code.",
               "THRESHOLDS = range(<start>, <stop>, <step>)"),
]
