"""utils/code_analysis (duplicate / symmetry) and noai utils — NAI-012 / 013 / 229 / 230 are dormant in the disposition table but deciding, so they carry rows — item 4, 2026-09-08.

Every row is `unbuilt` (the honest placeholder) until this family is worked.
Set 4b-34 (2026-09-10, app copy 3; portion G's `code_analysis` entry): NAI-012, NAI-013, NAI-229, NAI-230, NAI-231
no-fix-by-design, each with the fact that it NEVER DECIDES A ROW today (read on the route, proven offline on the
validator's own file path): NAI-231 (`check_duplicate_functions_strict`, file_validation.py:766-770) and the
symmetry family are `warnings` lines — warnings never enter a row's rule ids (F-WARN-UNPUB; rule ids come from
`triggered_patterns` and `failure_reason`); NAI-013's own id is discarded at file_validation.py:728-730 and the
line always says SYM-002 (declared on set 4b-26); NAI-012 is emitted only by `utils/code_analysis/duplicate.py`,
which the route never calls — file_validation.py:20 imports the noai-utils twin, whose line says NAI-228 (a
warning on each duplicate's row); NAI-229 (noai utils `check_suspicious_symmetry`) and NAI-230
(`check_normalized_duplicates`) have no live caller (health-check smoke only; FIX_17, row 7 R-B, is where they
would be wired). The entry condition — a `controls` file carrying the NAI-231 / NAI-228 / SYM-002 lines with
every row PASSED — was met offline before the run (`repair_plant_duplicates_control.py`). Beyond the route facts,
the meaning admits no rewrite in any case: which of two structurally identical functions is the copy, and what
the sequence of literals stands for, are the dev's.
Set 4b-35 (2026-09-10, app copy 3): NAI-232, NAI-233, NAI-234, NAI-235 no-fix-by-design, each a `warnings` line
from `utils.code_analysis.symmetry.check_suspicious_symmetry` (file_validation.py:733-737) that never becomes a
rule id — FAMILY `code_analysis` CLOSED: 9 no-fix-by-design, no rewriter, none deciding a row today. Facts read
offline: identical if / else and if / elif branches are DECIDED by NAI-026 (`variant=identical_branches`), so
the 232 / 233 constructs are NAI-026 rows and cannot be controls; identical loop bodies and identical
comprehensions PASS on their own (the set's controls file); two consecutive identical loops are NAI-054's row
instead. `meaning_source` corrected for 233 / 234 / 235 to the emitting helpers (the catalogue named the
dispatcher `check_suspicious_symmetry` for all three).
"""
from __future__ import annotations

from . import no_fix, prescribed, unbuilt

GENERATORS = [
        # 4b fact (kept, FIX_41): never decides a row: the emitter is `utils/code_analysis/duplicate.check_duplicate_functions`, called only by health-check step 1's smoke — the route (file_validation.py:20, :557) imports the noai-utils twin, whose line says NAI-228 and lands in each duplicate's `warnings` (never a rule id). The meaning would admit no rewrite anyway: which of two structurally identical functions is the copy, and whether both were meant, is the dev's (set 4b-34, 2026-09-10)
    prescribed("NAI-012", "utils/code_analysis/duplicate.py:check_duplicate_functions",
               "Keep one of the two identical functions and route every caller to it; when both names are part of the intent, make one delegate to the other.",
               "def b(*args, **kw):\n    return a(*args, **kw)"),
        # 4b fact (kept, FIX_41): never decides a row: the helper's id is discarded at file_validation.py:728-730 and the line is published as `SYM-002 (<severity>): …` in the row's `warnings` (declared as SYM-002 on set 4b-26); an arithmetic / geometric / symmetric run of three or more literals, or sequential comparison values in an if / elif chain — what the sequence stands for is the dev's (set 4b-34, 2026-09-10)
    prescribed("NAI-013", "utils/code_analysis/symmetry.py:check_arithmetic_symmetry",
               "Replace the literal progression with the rule that generates it (a range, a formula or a named table) so the sequence's meaning is in the code.",
               "THRESHOLDS = range(<start>, <stop>, <step>)"),
        # 4b fact (kept, FIX_41): a body whose most repeated top-level statement type reaches the table's magnitude (FIX_17, 2026-09-10: wired into file_validation as a per-function observation carrying `magnitude`; context by default, deciding above N for non-test files — the first per-(rule, context) row) — which of the repeated statements is the padding and what the function was meant to do is the dev's; no mechanical rewrite (set 4b-34 declared it uncalled; FIX_17 gave it its live caller)
    prescribed("NAI-229", "no_aivalidator/noai_validator/utils.py:symmetry_229_observation",
               "Replace the repeated statements with a loop or a data table over the values they differ in; a body that was only padding gets the real implementation the intent calls for.",
               "for value in (<v1>, <v2>, ...):\n    <the one statement>"),
        # 4b fact (kept, FIX_41): a function whose normalized fingerprint is shared by a group of the table's magnitude in the same file (FIX_17, 2026-09-10: wired into file_validation once per file, each member's row carrying `magnitude` = the group size; context by default, deciding above N for non-test files) — which member is the copy and which was meant is the dev's; no mechanical rewrite (set 4b-34 declared it uncalled; FIX_17 gave it its live caller)
    prescribed("NAI-230", "no_aivalidator/noai_validator/utils.py:normalized_duplicates_230_observations",
               "Collapse the fingerprint-identical group into one function parameterised by what the copies differ in, and route callers to it.",
               "def shared(x, <difference>):\n    ..."),
        # 4b fact (kept, FIX_41): never decides a row: `_check_dup_strict` runs over the file's normalized fingerprints and its line is appended to `results[0].warnings` (file_validation.py:766-770) — the file's FIRST row, the module row when that row is published, else the first function — never a rule id (F-WARN-UNPUB). Which of the identical functions is the copy is the dev's (set 4b-34, 2026-09-10)
    prescribed("NAI-231", "utils/code_analysis/duplicate.py:check_duplicate_functions_strict",
               "Keep one of the identical functions and route every caller to it; when both names are part of the intent, make one delegate to the other.",
               "def b(*args, **kw):\n    return a(*args, **kw)"),
        # 4b fact (kept, FIX_41): never decides a row: `check_suspicious_symmetry`'s issues are appended to the row's `warnings` (file_validation.py:733-737), never a rule id (F-WARN-UNPUB); the construct — an if / else whose two bodies dump identically — is NAI-026's row (structural, `variant=identical_branches`, portion I), which decides it. Which branch the dev meant to differ is theirs (set 4b-35, 2026-09-10)
    prescribed("NAI-232", "utils/code_analysis/symmetry.py:_check_if_else_symmetry",
               "Make the two branches differ as the condition intends, or drop the if and keep the single body when the condition does not matter (the row's NAI-026 decision).",
               "if cond:\n    <arm A>\nelse:\n    <arm B, different>"),
        # 4b fact (kept, FIX_41): never decides a row: a `warnings` line (file_validation.py:733-737); three or more if / elif (/ else) branches whose bodies all dump identically — NAI-026 decides the row, and NAI-232 rides on the same chain's last if / else. `meaning_source` corrected to the emitting helper `_check_if_elif_symmetry` (the catalogue named the dispatcher). Which branch was meant to differ is the dev's (set 4b-35, 2026-09-10)
    prescribed("NAI-233", "utils/code_analysis/symmetry.py:_check_if_elif_symmetry",
               "Make each if / elif branch do what its condition selects, or collapse the chain to the single body when the conditions do not matter (the row's NAI-026 decision).",
               "if c1:\n    <arm 1>\nelif c2:\n    <arm 2, different>"),
        # 4b fact (kept, FIX_41): never decides a row: a `warnings` line (file_validation.py:733-737); two top-level loops whose bodies are identical once names are normalized — a construct that PASSES on its own (proven offline and in a controls file); NAI-054 takes the row only when the loops are consecutive statements. Whether the second loop was meant to be the first, or to do something else, is the dev's. `meaning_source` corrected to `_check_loop_symmetry` (set 4b-35, 2026-09-10)
    prescribed("NAI-234", "utils/code_analysis/symmetry.py:_check_loop_symmetry",
               "Merge the two identical loops into one, or make the second loop do the work the intent meant it to.",
               "for item in items:\n    <work>"),
        # 4b fact (kept, FIX_41): never decides a row: a `warnings` line of severity INFO (file_validation.py:733-737); two comprehensions of the same kind that dump identically — a construct that PASSES on its own (proven offline and in a controls file). Which of the two was meant is the dev's. `meaning_source` corrected to `_check_comprehension_symmetry` (set 4b-35, 2026-09-10)
    prescribed("NAI-235", "utils/code_analysis/symmetry.py:_check_comprehension_symmetry",
               "Keep one of the two identical comprehensions, bound once and reused, or make the second differ as the intent meant.",
               "values = [<expr> for x in xs]\nuse(values)\nuse(values)"),
        # owner 2026-10-07 (blind tree 1 L3, M-90): a function equal to its twin but for one leading literal-guarded constant return.
    prescribed("NAI-236", "no_aivalidator/noai_validator/utils.py:disabled_case_236_observations",
               "Delete the guard that switches the real check off for the one named case, so this function behaves like its twin; if the case truly needs different handling, compute it rather than returning a constant.",
               "def <fn>(<args>):\n    return <the twin's real check>",
               dated="2026-10-07", by="owner"),
        # owner 2026-10-07 (blind tree 1 L4, M-90): a branch returning exactly what the file's test asserts, or a call counter that changes the answer.
    prescribed("NAI-237", "no_aivalidator/noai_validator/utils.py:test_gaming_237_observations",
               "Remove the branch that returns the test's expected value and any call counter that changes the answer; compute the result from the inputs so every call with the same arguments gets the same, real answer.",
               "def <fn>(<args>):\n    return <computed from the inputs>",
               dated="2026-10-07", by="owner"),
        # owner 2026-10-07 ~10:00: a function that breaks a relation its own signature sets up (bound / unit).
    prescribed("NAI-239", "no_aivalidator/noai_validator/relation_probes.py:observations",
               "Fix the step the counterexample exposes: a fill must reach (and never pass) its capacity — apply losses or efficiency before clamping to the room left; a temperature enters a product as a difference from its reference, never as an absolute °C; only like units add.",
               "def <fn>(<args>):\n    return <the same steps in the order that keeps the relation>",
               dated="2026-10-07", by="owner"),
        # owner 2026-10-07: no branch handles the boundary value itself (an if / elif pair on `<` and `>`).
    prescribed("NAI-241", "no_aivalidator/noai_validator/boundary_probes.py:observations",
               "Make one branch own the boundary: change `<` / `>` to `<=` or `>=` on the side the value belongs to, or end the chain with an `else` so every input returns a value.",
               "if x < c:\n    return a\nreturn b   # x == c now has an answer",
               dated="2026-10-07", by="owner"),
        # owner 2026-10-07: a declared case the function never handles (falls through to None).
    prescribed("NAI-243", "no_aivalidator/noai_validator/boundary_probes.py:partial_case_observations",
               "Handle every case the module declares: add the missing branch, or end the chain with an explicit default (or raise ValueError naming the unknown case) so no declared case falls through to None.",
               "if kind == \"dry\":\n    ...\nelif kind == \"reefer\":\n    ...\nelif kind == \"tank\":\n    ...",
               dated="2026-10-07", by="owner"),
        # M-150 (2026-10-08): the target's own test fails on this function's result (run at scan time).
    prescribed("NAI-254", "no_aivalidator/noai_validator/test_blame.py:observations",
               "Make the function return what its failing test expects, by fixing the statement(s) named in `lines` (the ones the rejected value was built from) — never by editing the test or special-casing the test's input.",
               "def <fn>(<args>):\n    <the corrected statement that builds the value the test asserts>\n    return <value>",
               dated="2026-10-08", by="owner"),
        # M-148 (2026-10-08): the function supplies the corner itself — an empty default it indexes, a .get() it dereferences.
    prescribed("NAI-242", "no_aivalidator/noai_validator/corner_guards.py:static_observations",
               "Test the value before using it: return the documented result (or raise a ValueError naming the missing key) when the list is empty or the lookup found nothing; keep the default only if every later use is safe on it.",
               "recipients = payload.get(\"recipients\", [])\nif not recipients:\n    return []\nfirst = recipients[0]",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, condition / boundary).
    prescribed("NAI-244", "no_aivalidator/noai_validator/top10_wave2.py:_shadowed",
               "Order the chain from the narrowest test to the widest (`>= 90` before `>= 60`; `isinstance(v, bool)` before `isinstance(v, int)`), so every branch can be reached.",
               "if score >= 90:\n    return \"A\"\nelif score >= 60:\n    return \"D\"",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, units / scale).
    prescribed("NAI-245", "no_aivalidator/noai_validator/top10_wave2.py:_unit_factor",
               "Use the conversion factor for the direction the name says: one <a> in <b> units (e.g. ms→s divides by 1000, minutes→hours divides by 60, °C→°F is `c * 9 / 5 + 32`).",
               "def ms_to_s(ms):\n    return ms / 1000",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, sentinel / missing data).
    prescribed("NAI-246", "no_aivalidator/noai_validator/top10_wave2.py:sentinel_aggregate",
               "Drop the marker before aggregating: filter `r != MISSING` (and divide by the count of real values), or raise if a value is missing.",
               "valid = [r for r in readings if r != MISSING]\nreturn sum(valid) / len(valid)",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, sentinel / missing data).
    prescribed("NAI-247", "no_aivalidator/noai_validator/top10_wave2.py:_truthy",
               "Test for the missing value itself: `if p is None: p = K` (or `p = K if p is None else p`), so 0 stays 0.",
               "if factor is None:\n    factor = 1.0",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, sentinel / missing data).
    prescribed("NAI-248", "no_aivalidator/noai_validator/top10_wave2.py:_seeded",
               "Seed the running extreme from the data (the first item, or `max(xs)` / `min(xs)` with `default=`), or from `-math.inf` / `math.inf`.",
               "best = xs[0]\nfor x in xs[1:]:\n    best = max(best, x)",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, formula / constant).
    prescribed("NAI-249", "no_aivalidator/noai_validator/top10_wave2.py:_formula_shapes",
               "Write the formula with the grouping it needs: `x ** (1 / n)`, `(a + b) / 2`, `(f - 32) * 5 / 9`; use `math.pi` / `math.e` for the constants.",
               "return (a + b) / 2",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-08 (top-10 wave 2, condition / boundary).
    prescribed("NAI-250", "no_aivalidator/noai_validator/top10_wave2.py:_leap",
               "Use the full Gregorian rule: `y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)`, or `calendar.isleap(y)`.",
               "return calendar.isleap(year)",
               dated="2026-10-08", by="owner"),
        # owner 2026-10-07 (tests are inspected as part of the codebase): every assert reads only mocks.
    # owner 2026-10-10 (D2 detection: counterfeit code that works — tests pass, the app runs).
    prescribed("NAI-255", "no_aivalidator/detection/rulebook_checks.py:_check_varied_input_replay",
               "Compute the result from the inputs the way the docstring and rulebook describe; do not return the argument unchanged, a fixed value, or a table keyed on the values the tests pass.",
               "return 1 + foods_eaten // FOODS_PER_LEVEL",
               dated="2026-10-10", by="owner"),
    prescribed("NAI-256", "no_aivalidator/detection/rulebook_checks.py:_check_rulebook_numbers",
               "Use the number the rulebook states for this quantity (the cited RULES.md / README.md line); if the rulebook is the one that is wrong, change the rulebook in the same change.",
               "POINTS_PER_FOOD = 10   # RULES.md R4: eating food scores 10 points",
               dated="2026-10-10", by="owner"),
    prescribed("NAI-257", "no_aivalidator/detection/rulebook_checks.py:_check_sibling_asymmetry",
               "Make the odd comparison or branch match its mirrored sibling (the same operator for the same bound, the same assignments on the opposite wall) unless the rulebook says that side differs.",
               "return 0 <= x < size and 0 <= y < size",
               dated="2026-10-10", by="owner"),
    prescribed("NAI-258", "no_aivalidator/detection/rulebook_checks.py:_check_test_state_branch",
               "Delete the branch that recognises the tests' setup state and apply the general rule to every input, including the one the tests build.",
               "return rng.choice(free_cells(body, size))",
               dated="2026-10-10", by="owner"),
    prescribed("NAI-259", "no_aivalidator/detection/rulebook_checks.py:_check_missing_rule_exception",
               "Add the branch the cited rule's exception describes, so the excepted case gets the allowed outcome instead of the general one.",
               "body = self._body if growing else self._body[:-1]\nreturn cell in body",
               dated="2026-10-10", by="owner"),
    # owner 2026-10-08 (wave 3 #1, harness tampering).
    prescribed("NAI-253", "no_aivalidator/noai_validator/harness_tamper.py:observations",
               "Remove the tampering and fix what it was hiding: restore the real clock / report outcome / exit status / assert method, delete the unconditional skip (or make it a skipif with the real condition), then make the code under test pass on its own.",
               "# conftest.py — the hook that forced reports to passed is deleted; the failing test is fixed in the code it tests",
               dated="2026-10-08", by="owner"),
    # owner 2026-10-08 (wave 3 #6, phantom wiring).
    prescribed("NAI-252", "no_aivalidator/noai_validator/phantom_wiring.py:observations",
               "Wire the service for real: pass the live data into it where it is produced (call its method with the order / event / record the caller holds) and use what it returns — or, if the feature is not wanted, remove the constructor and the import instead of leaving an idle instance.",
               "def handle_order(order, analytics):\n    analytics.record(order)   # the live data reaches the service",
               dated="2026-10-08", by="owner"),
    # owner 2026-10-08 (wave 3 #7, split-brain twins).
    prescribed("NAI-251", "no_aivalidator/noai_validator/split_brain.py:observations",
               "Keep ONE implementation: decide which copy is right (the docstring, the tests and the callers say which), make the other module import it instead of carrying its own body, and delete the stale copy.",
               "# helpers/legacy_formatters.py\nfrom app.utils.formatters import format_price  # one implementation, no clone",
               dated="2026-10-08", by="owner"),
    # owner 2026-10-08 (wave 3, frontier #3): every assert is `is not None` / isinstance / hasattr / callable.
    prescribed("NAI-150", "no_aivalidator/detection/extended_semantic_checks.py:_check_assertion_free_test_with_calls",
               "Assert on the value itself: compare the result with the expected answer for this input (equality, a field, a length), so the test fails when the code returns the wrong thing; keep the type check only alongside it.",
               "def test_place_order():\n    result = place_order(7)\n    assert result[\"items\"] == [7]",
               dated="2026-10-08", by="owner"),
    prescribed("NAI-129", "no_aivalidator/detection/extended_semantic_checks.py:_check_mock_everything_test",
               "Assert on the real result: call the code under test and check what it returns or changes; keep mocks for the collaborators only, and add at least one assert that would fail if the code under test were wrong.",
               "def test_charge():\n    bank = FakeBank()\n    charge(bank, 5)\n    assert bank.soc == 5   # the real effect, not that a mock was called",
               dated="2026-10-07", by="owner"),
]
