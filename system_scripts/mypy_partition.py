"""mypy_partition — the ONE rule that splits mypy's `: error:` lines into real type errors and
--strict annotation notes (plan item 11, 2026-09-05; B5 / Q-H2-2 / Q-H0-1, 2026-10-01).

Before B5 the rule was a closure inside `circuit_daemon.run_mypy_scan` (`_is_note`), so the circuit
badge counted 27 type errors + 61 notes while the dashboard's per-directory drill-down and
`cr_data_types.issues` — reading the same 88 lines — counted 88 "errors" by a different split
(external-import suppression only). Every reader now imports this module:

  * `circuit_daemon.run_mypy_scan`   — `type_errors` / `annotation_notes` and `errors_by_dir`
  * `proof_dashboard.update_mypy_panel` — the badge and the drill-down
  * `coderadar_mcp.read_tools.cr_data_types` — `issues` (type errors) with `notes` beside it

Pure: no file, no config, no side effect — importable from the daemon (bare, sys.path[0] is
system_scripts), the dashboard, and the MCP package (`system_scripts.mypy_partition`) alike.

A line is a NOTE when its trailing `[code]` is in ANNOTATION_NOISE. A line with no code, or any
other code, is a TYPE ERROR. The rule reads the line's tail only, so it holds for mypy's raw
`path:line: error: msg  [code]` and for the mirror's `rel:line: msg  [code]` alike.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Tuple

#: mypy error codes that are missing-annotation / untyped-use noise under --strict, not type errors.
ANNOTATION_NOISE = frozenset({
    "no-untyped-def", "no-untyped-call", "no-any-return", "type-arg",
    "untyped-decorator", "var-annotated", "import-untyped",
    "import-not-found", "unused-ignore", "no-any-unimported",
})

_CODE_RE = re.compile(r"\[([a-z][a-z0-9-]*)\]\s*$")


def is_note(line: str) -> bool:
    """True when `line` ends in an annotation-noise `[code]`."""
    m = _CODE_RE.search(line)
    return m is not None and m.group(1) in ANNOTATION_NOISE


def partition(lines: Iterable[str]) -> Tuple[List[str], List[str]]:
    """(type_error_lines, note_lines) — order preserved, every input line in exactly one list."""
    errors: List[str] = []
    notes: List[str] = []
    for line in lines:
        (notes if is_note(line) else errors).append(line)
    return errors, notes
