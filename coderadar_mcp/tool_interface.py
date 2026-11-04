"""THE interface — every MCP tool of RELEASE_FORM_MCP_PACKET_2026-09-17 §B.

One module, written and agreed BEFORE any lane touches the engine (FIX_43b's interface-first
pattern: the ONE reading is fixed in the original, serially, then the lanes fill it in).

Each tool carries four things and nothing else:
  * `name`             — the tool the client calls
  * `input_schema`     — the arguments, as `Field`s
  * `output_schema`    — the record returned, as `Field`s
  * `source_of_record` — the file it reads or writes, by the name the app publishes it under
  * `writes`           — the files its handler writes, all in CodeRadar's own tree; `()` for a read tool
plus a one-line `contract`.

**No tool is implemented here.** `HANDLERS` is the registry the lanes fill:
  T2 → `read_tools.py`    (cr_status, cr_infractions, cr_row, cr_wiring, cr_data_types, cr_intent)
  T3 → `write_tools.py`   (cr_report_outcome, cr_apply, cr_run_module)
  T4 → `session_tools.py` (cr_watch, cr_attach, cr_stop, cr_hand_back)
The server module (`server.py`) is T2's. Nothing in this file is edited by a lane.

House style: dataclasses (41 live modules import `dataclasses`; one uses `TypedDict`,
none uses pydantic), stdlib only, `from __future__ import annotations`.

Every field name below was read off a REAL published file of run 136:
`.archive/runs/<run 136 target>/state_during_run/noai_state_mirror.json`,
`.../BUILDER_STATE.json`, `system_scripts/.monitor_state.json`,
`system_scripts/circuit_state.json`, `system_scripts/intent_<repo_id>.json`,
`.archive/runs/<run 136 target>/tester_report.json`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

# ─────────────────────────────────────────────────────────────────────────────
# Vocabulary fixed by the 2026-09-17 rulings
# ─────────────────────────────────────────────────────────────────────────────

#: Q4 / the run-53 ruling. A tester line is `confirmed` or `failed` — there is no
#: `refuted`, no `unmeasured`, no failure kind anywhere (owner 2026-09-09).
OUTCOMES: tuple[str, ...] = ("confirmed", "failed")

#: Q7. `possible` is the new word for indigo — an import edge not yet proven by a flow.
#: I-198 (owner 2026-09-28, option 2): `live_via_tests` — a target with NO app entry proof (a
#: library) whose edge the test runner loaded. Its own state and colour, never counted as `live`;
#: once any app proof exists the state is not used and Item 10 holds unchanged.
EDGE_STATES: tuple[str, ...] = ("possible", "live", "severed", "live_via_tests")

#: FIX_41. The two kinds a mirror repair row can carry.
SOLUTION_KINDS: tuple[str, ...] = ("rewriter", "prescribed")

#: Q9. `cr_infractions` pages by file; 50 rows is the default page.
PAGE_SIZE_DEFAULT: int = 50

#: I-152 / Q1 (owner 2026-09-21, built session 10). A row whose every candidate the prescription
#: seam refuses as un-renderable publishes the APPLY STATE *not selectable*: `selected_role ""`,
#: `apply "no"`, `withheld_by` naming the seam below — and the ROW IS NOT FLIPPED TO WITHHELD,
#: because withholding it would drop a real smell from the bucket count (`failed == repairs +
#: no_vetted_fix`). The seam is named, not G0: G0 judges a rewrite, and this is the prescription
#: half. The same three strings are spelled in `no_aivalidator/BUILDER_DAEMON.py`'s selector,
#: which publishes them, and are READ here — the engine never imports this package.
NOT_SELECTABLE_BY: str = "gate.prescription_check"
#: Fix A (owner ruling 2026-09-28, run 187, the six diagnosis §2 / ledger M-1·M-2): `apply "yes"`
#: is published ONLY for a row whose solution renders a CONCRETE diff at the site (a rewriter). A
#: row whose selected solution is a prescribed shape (`solution_kind "prescribed"` — the rule's
#: template, `cr_apply` answers `kind "shape"`, `diff null`) publishes `apply "review"` with
#: `apply_reason` below: still visible, ranked after every `yes` row, never counted as `yes`, and
#: not for an unattended seat to apply blindly. Label only — the row stays in `repairs`, so
#: `failed == repairs + no_vetted_fix` is unmoved. Order = rank: yes, review, no.
APPLY_STATES: tuple[str, ...] = ("yes", "review", "no")
APPLY_REVIEW_REASON: str = "template only — no diff rendered at this site"
#: M-20 (run 187, six: 77 vs 516). The scope of `monitor.summary.mypy_errors`, the number
#: `finished` and cr_status read (and cr_data_types publishes as `finished_input`): every mypy
#: `: error:` line INCLUDING the `--strict` annotation notes, less the suppressed ones
#: (external-import errors). The tracker's `total_errors` is a different scope — real type errors
#: only, notes excluded (plan item 11). B5 (2026-10-01, Q-H0-1): `cr_data_types.issues` is that
#: second scope now (type errors, `notes` beside it; `read_tools.ISSUES_TYPE_ERRORS_SCOPE`).
ISSUES_SCOPE: str = "(mypy error lines incl. annotation notes, less suppressed)"
#: R4 / R9 (2026-09-30): the dash mirror `system_scripts/.monitor_state.json` keys R4 added or
#: re-scoped, as every reader in this package must take them. A tracker chosen at launch whose tool
#: is missing or failed publishes status "NOT MEASURED — <reason>" with null counts — null is
#: NOT MEASURED, never 0. Documentation only; nothing reads this dict at run time.
MONITOR_MIRROR_KEYS: dict[str, str] = {
    "monitor.target_repo": "str — the absolute target the daemon measured (T-13: what the one-target guard checks)",
    "monitor.trackers": "dict — circuit_state's `trackers` verbatim: {chosen: [token], not_run: [token], not_measured: {token: reason}}",
    "monitor.dead_code.status": "str — the vulture tracker's status: `measured`, `not run — nothing measured` (not chosen at launch) or `NOT MEASURED — <reason>`",
    "monitor.functions.status": "str — the io tracker's status, same three forms as dead_code.status",
    "monitor.mypy.total_errors": "int|None — real type errors only (= mypy.type_errors); null unless mypy measured",
    "monitor.mypy.type_errors": "int|None — real type errors only; null unless mypy measured",
    "monitor.mypy.annotation_notes": "int|None — the --strict annotation notes kept apart from the type errors; null unless mypy measured",
    "monitor.mypy.error_lines": "int — the mirror's own raw count: every `: error:` line less the suppressed ones (= type_errors + annotation_notes = summary.mypy_errors when measured); the old meaning of total_errors",
    "monitor.summary.mypy_errors": "int|None — the `finished` input, scope ISSUES_SCOPE; null when mypy was not measured",
    "monitor.summary.sync_needs_review": "int|None — null when the io tracker was not measured",
    "monitor.summary.dead_code_items": "int|None — null when vulture was not measured",
    "monitor.summary.dead_code_actionable": "int|None — null when vulture was not measured",
}
NOT_SELECTABLE_REASON: str = (
    "not selectable: no candidate on this row renders unattended — its shape carries "
    "placeholders only a decision can fill")

#: The `finished` predicate (Q5, B7-5): zero infractions · zero data-type issues ·
#: zero severed links. Withheld rows do NOT count — verified on run 136:
#: repairs 156 + no_vetted_fix 8 = 164 = summary.failed, while withheld 85 is a
#: disjoint list, so `failed` already excludes them.
FINISHED_PREDICATE: tuple[str, ...] = (
    "noai_mirror.summary.failed == 0",
    "monitor.summary.mypy_errors == 0",
    "monitor.summary.severed_links == 0",
)

#: The angle-bracket placeholder of a prescribed shape (I-75), e.g. `<real.package.module>`.
PLACEHOLDER_RE = re.compile(r"<[^<>\n]+>")


# ─────────────────────────────────────────────────────────────────────────────
# The schema primitives
# ─────────────────────────────────────────────────────────────────────────────

_PY_TYPES: dict[str, tuple[type, ...]] = {
    "str": (str,),
    "int": (int,),
    "float": (float, int),
    "bool": (bool,),
    "list": (list, tuple),
    "dict": (dict,),
    "any": (object,),
}


@dataclass(frozen=True)
class Field:
    """One argument or one published key. `type` is a name in `_PY_TYPES`; a trailing
    `|None` makes the value nullable. `required` is about presence, never about value."""

    name: str
    type: str
    doc: str
    required: bool = True
    default: Any = None
    choices: tuple[Any, ...] = ()

    @property
    def nullable(self) -> bool:
        return self.type.endswith("|None")

    @property
    def base_type(self) -> str:
        return self.type[: -len("|None")] if self.nullable else self.type

    def accepts(self, value: Any) -> str | None:
        """None when `value` fits, else the reason it does not."""
        if value is None:
            return None if (self.nullable or not self.required) else f"{self.name}: null not allowed"
        want = _PY_TYPES.get(self.base_type)
        if want is None:
            return f"{self.name}: unknown type {self.base_type!r} in the schema"
        if self.base_type == "bool":
            if not isinstance(value, bool):
                return f"{self.name}: want bool, got {type(value).__name__}"
        elif self.base_type == "int" and isinstance(value, bool):
            return f"{self.name}: want int, got bool"
        elif not isinstance(value, want):
            return f"{self.name}: want {self.base_type}, got {type(value).__name__}"
        if self.choices and value not in self.choices:
            return f"{self.name}: {value!r} not one of {list(self.choices)}"
        return None


@dataclass(frozen=True)
class ToolSpec:
    """One MCP tool. `writes` names the files the tool's handler writes — every one in CodeRadar's
    own tree, never the target's code (Q3; A3 2026-10-01, Q-H4-10: six tools write, the read tools
    carry an empty tuple). The ONE tool that records a verdict — the return channel and the
    confirmed ledger — is `cr_report_outcome`."""

    name: str
    contract: str
    input_schema: tuple[Field, ...]
    output_schema: tuple[Field, ...]
    source_of_record: str
    packet_row: str
    writes: tuple[str, ...] = ()
    example_input: dict[str, Any] = field(default_factory=dict)
    example_output: dict[str, Any] = field(default_factory=dict)

    def input_field(self, name: str) -> Field | None:
        return next((f for f in self.input_schema if f.name == name), None)


def validate_payload(spec: ToolSpec, payload: dict[str, Any], which: str = "input") -> list[str]:
    """Check one payload against a tool's schema. Returns the problems, empty when it fits.
    Unknown keys are a problem: the interface is the whole contract, not a prefix of it."""
    schema = spec.input_schema if which == "input" else spec.output_schema
    if not isinstance(payload, dict):
        return [f"{spec.name}.{which}: want dict, got {type(payload).__name__}"]
    problems: list[str] = []
    known = {f.name for f in schema}
    for extra in sorted(set(payload) - known):
        problems.append(f"{spec.name}.{which}: unknown key {extra!r}")
    for f in schema:
        if f.name not in payload:
            if f.required:
                problems.append(f"{spec.name}.{which}: missing required key {f.name!r}")
            continue
        bad = f.accepts(payload[f.name])
        if bad:
            problems.append(f"{spec.name}.{which}: {bad}")
    return problems


# ─────────────────────────────────────────────────────────────────────────────
# The return channel — Item 5's record, verbatim
# ─────────────────────────────────────────────────────────────────────────────

#: The contract `no_aivalidator/BUILDER_DAEMON.py::_parse_channel_line` enforces. A line that
#: is not exactly this is counted under `BUILDER_STATE.summary.tester.unparsed` and never
#: applied — the reader drops nothing silently, but it also repairs nothing.
RETURN_CHANNEL_RECORD: tuple[Field, ...] = (
    Field("digest", "str", "the row's CURRENT solution digest, from the mirror repair row `digest`"),
    Field("replace_span", "str", "the row's `replace_span`, e.g. `colorama/repair_plant_071.py:L4-L6` — the join checks this AS WELL AS the digest"),
    Field("outcome", "str", "`confirmed` or `failed`; anything else makes the line unparsed", choices=OUTCOMES),
    Field("failure_log", "str", "the full failure text; the Builder takes `[:2000]` into `rca_evidence` as `tester_log=` and its first line as `error_message`", required=False, default=""),
    Field("tester", "str", "who measured it — free text, published back on `rows[].tester.tester`", required=False, default=""),
    Field("timestamp", "str", "ISO 8601 UTC; published back on `rows[].tester.timestamp`", required=False, default=""),
    # ── Q1 / I-122, session 7 (the drift fix): the line's own PRE-EDIT IDENTITY. Five ADDITIVE
    # fields, every one optional with an empty default, so a line written by an older caller is
    # unchanged in meaning and `_parse_channel_line` keeps rejecting nothing it accepted before.
    # They exist because the row underneath a line drifts: it is retired within one Builder cycle
    # (I-119), re-keyed by an earlier edit to the same file (I-130), re-digested between apply and
    # report (I-138), and re-decided out of its variant the same cycle the line arrives (I-122).
    # The reader prefers these over the row's: the line is the only record of what the seat held.
    Field("row_key", "str", "the row id the seat was handed, `<file>::<function>::<line>`, as of the APPLY", required=False, default=""),
    Field("rule_ids", "list", "the row's rule ids at apply time — `_rule_outcomes` / `_failed_identities` read them off the LINE first, the row second", required=False, default=[]),
    Field("variant", "str", "the repair variant tried, the Ranker's `decision.pick_role` at apply time (the mirror's `selected_role`) — the fact I-122 lost to the re-decide", required=False, default=""),
    Field("file", "str", "the row's file at apply time; with `function` it is the second half of the join when the span has been re-keyed", required=False, default=""),
    Field("function", "str", "the row's function at apply time", required=False, default=""),
    # ── I-145 / Q2, session 10 (2026-09-22): the id the SEAT PASSED, verbatim after
    # `html.unescape`, beside the id the server resolved (`row_key`). Run 162: the client passed
    # `_termui_impl.py::_pipepager::549` and every record read `::550`, so a seat reconciling its
    # own log against the channel by `row_key` matched nothing. Additive and optional; a line that
    # carries no `given_id` reads exactly as it did, and `_parse_channel_line` ignores it as it
    # ignores every key outside the three that decide.
    Field("given_id", "str", "the row id the SEAT passed to `cr_report_outcome`, after `html.unescape` — equal to `row_key` unless the server re-resolved the id (I-145)", required=False, default=""),
)


#: S4-3 / Q1(a) — the CONFIRMED LEDGER, one record per `confirmed` verdict, appended to
#: `confirmed_ledger_<repo_id>.jsonl` BESIDE the return channel (same directory, the channel's
#: own name with `return_channel_` swapped for `confirmed_ledger_`).
#: Why it exists (run 141): a repair that works REMOVES ITS OWN ROW, so by the Builder's next
#: poll nothing sits at that digest+span and every `confirmed` line orphans. The ledger keeps
#: the row's PRE-REPAIR identity — what the registry row said at report time — so the report
#: writer can count a confirmation the channel can no longer join.
#: Append-only, and the LAST record per (digest, replace_span) wins, mirroring the channel.
#: `failed` writes NOTHING here: a failed row is still an infraction and still joins.
CONFIRMED_LEDGER_RECORD: tuple[Field, ...] = (
    Field("digest", "str", "the row's solution digest at report time — half the channel's join key"),
    Field("replace_span", "str", "the row's `replace_span` at report time — the other half"),
    Field("rule_ids", "list", "the row's rule ids, as the registry row carried them"),
    Field("file", "str", "the row's file, relative to the target"),
    Field("function", "str", "the row's function"),
    Field("line", "int", "the row's line — with file and function, the row id `<file>::<function>::<line>`"),
    Field("given_id", "str", "I-145 / Q2: the row id the SEAT passed, after `html.unescape` — the ledger row carries it beside the resolved identity so a seat can reconcile its own log by the id it holds", required=False, default=""),
    Field("seat", "str", "who measured it — the `tester` of the channel line, the seat that reported"),
    Field("note", "str", "the client's remark; the same text the channel line carries as `failure_log`", required=False, default=""),
    Field("edit_kind", "str", "the client's edit: `diff` (a rewriter hunk) or `shape` (a rendered prescription); empty when the caller did not say", required=False, default="", choices=("", "diff", "shape")),
    Field("timestamp", "str", "ISO 8601 UTC, the channel line's own stamp"),
)


#: THE LEASE (session 7, packet §C.1 — I-119 / I-125 / I-138). `cr_apply` on a `repairs` row
#: appends one record to `apply_lease_<repo_id>.jsonl`, BESIDE the channel and named by the
#: channel's own rule, exactly as the confirmed ledger is. Append-only; the LAST record per
#: `row_key` wins.
#: Why it exists: row identity is positional (`<file>::<function>::<line>`) and the channel's join
#: key is positional too (`digest` + `replace_span`), so the row a seat was handed drifts out from
#: under it — retired within one Builder cycle when the repair works (I-119), re-keyed by an
#: earlier edit to the same file (I-130), re-digested between apply and report (I-138), re-decided
#: out of its variant (I-122), destroyed on a revert (I-125). The lease is the server's memory of
#: WHAT IT HANDED OUT: every record `cr_report_outcome` writes carries the PRE-EDIT identity, not
#: the identity of a row that moved underneath the seat.
APPLY_LEASE_RECORD: tuple[Field, ...] = (
    Field("row_key", "str", "the row id handed out, `<file>::<function>::<line>` — the lease's key"),
    #: I-145 / Q2 (session 10): the id the SEAT PASSED, after `html.unescape`. The lease is filed
    #: under the RESOLVED key — the right key for the server to keep — and the client goes on
    #: holding the id it was given (run 162: `::549` given, `::550` filed). Carrying both is the
    #: fix the owner ruled: an added EXACT key, never a looser match.
    Field("given_id", "str", "the row id the seat passed to `cr_apply`, after `html.unescape`; equal to `row_key` unless the server re-resolved it"),
    Field("digest", "str", "the row's solution digest at APPLY time — the channel's join key, frozen here"),
    Field("replace_span", "str", "the row's RECORDED span, the Builder's key (`<file>:L<a>-L<b>`)"),
    Field("replace_span_live", "str", "the span the edit was actually rendered against — the function's live span in the file as it stood at apply time (I-130's re-base); equal to `replace_span` when nothing had shifted"),
    Field("file", "str", "the row's file, relative to the target"),
    Field("function", "str", "the row's function"),
    Field("line", "int", "the row's line — with file and function, `row_key`"),
    Field("rule_ids", "list", "the row's rule ids at apply time"),
    Field("variant", "str", "the repair variant handed out — the row's `selected_role` (`decision.pick_role`)"),
    Field("solution_kind", "str", "`rewriter` or `prescribed`", choices=SOLUTION_KINDS),
    Field("before_sha256", "str", "sha256 of the bytes the edit REPLACES — the live segment at `replace_span_live`; the row's `before_code` when the file could not be read"),
    Field("after_sha256", "str", "sha256 of the bytes the edit puts there — the row's `after_code` as rendered"),
    Field("timestamp", "str", "ISO 8601 UTC, the moment the lease was handed out"),
)


@dataclass(frozen=True)
class ReturnChannelLine:
    """ONE line of `system_scripts/return_channel_<repo_id>.jsonl`.

    The file is outside the target and outside the snapshot, so byte-identity holds.
    Its absolute path is published in two places and is never guessed:
      * `BUILDER_STATE.json` → `return_channel`
      * every mirror repair row → `return_channel`

    The write is an APPEND of one newline-terminated JSON object. There is no API and no
    signal: `BuilderDaemon._poll_channel` stats the file every cycle, reads only the bytes up
    to the last `\\n` (a half-written line waits for the next poll), `_join_channel` joins the
    line to a row on `digest` AND `replace_span`, and the Ranker re-decides on that cycle.
    A file shorter than the daemon's offset is re-read from byte 0, so never rewrite it.
    """

    digest: str
    replace_span: str
    outcome: str
    failure_log: str = ""
    tester: str = ""
    timestamp: str = ""
    # Q1 / I-122 (session 7): the five ADDITIVE identity fields. Empty-string / empty-list
    # defaults, so `as_line()` of a caller that sets none of them is unchanged in meaning.
    row_key: str = ""
    rule_ids: tuple[str, ...] = ()
    variant: str = ""
    file: str = ""
    function: str = ""
    # I-145 / Q2 (session 10): the id the seat passed, beside the id the server resolved.
    given_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "replace_span": self.replace_span,
            "outcome": self.outcome,
            "failure_log": self.failure_log,
            "tester": self.tester,
            "timestamp": self.timestamp,
            "row_key": self.row_key,
            "rule_ids": list(self.rule_ids),
            "variant": self.variant,
            "file": self.file,
            "function": self.function,
            "given_id": self.given_id,
        }

    def as_line(self) -> str:
        """The exact bytes T3 appends — one compact JSON object, newline-terminated."""
        return json.dumps(self.as_dict(), ensure_ascii=False) + "\n"


def return_channel_line(row: dict[str, Any], outcome: str, note: str = "",
                        tester: str = "coderadar-mcp", given_id: str = "") -> ReturnChannelLine:
    """Build the record from ONE IDENTITY + the client's verdict.

    The identity is a mirror repair row, a `cr_row` record, or — since session 7 — an APPLY
    LEASE record (`APPLY_LEASE_RECORD`), which carries the same five names under the same keys.
    That is the whole of the drift fix at this seam: the line is built from the identity the seat
    was GIVEN, never from a row that drifted underneath it.

    `note` becomes `failure_log`; on a `confirmed` line it is the client's remark and the
    Builder ignores it (item 5 step 6: a confirmed line sets `rows[].tester` only)."""
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {list(OUTCOMES)}, not {outcome!r}")
    digest = row.get("digest")
    span = row.get("replace_span")
    if not (isinstance(digest, str) and digest):
        raise ValueError("row has no digest — a row without a vetted fix cannot be reported on")
    if not (isinstance(span, str) and span):
        raise ValueError("row has no replace_span — the join needs it as well as the digest")
    file_name = str(row.get("file") or "")
    function = str(row.get("function") or "")
    # A lease carries `row_key` and `variant` outright; a mirror row carries neither, so the
    # id is computed the one way it is ever computed and the variant read off `selected_role`
    # (the mirror's name) or `decision.pick_role` (the registry row's).
    key = str(row.get("row_key") or "")
    if not key and file_name and row.get("line") is not None:
        key = row_id(row)
    variant = str(row.get("variant") or row.get("selected_role")
                  or (row.get("decision") or {}).get("pick_role") or "")
    rules = tuple(str(r) for r in (row.get("rule_ids") or row.get("rule_ids_all") or []) if r)
    return ReturnChannelLine(
        digest=digest,
        replace_span=span,
        outcome=outcome,
        failure_log=note or "",
        tester=tester,
        timestamp=datetime.now(timezone.utc).isoformat(),
        row_key=key,
        rule_ids=rules,
        variant=variant,
        file=file_name,
        function=function,
        # I-145 / Q2: the caller's own id when it said one, else the identity's own `given_id`
        # (a lease carries it), else the resolved key — never an invention.
        given_id=str(given_id or row.get("given_id") or key),
    )


def row_id(row: dict[str, Any]) -> str:
    """The ONE id across every tool: `BUILDER_STATE.json`'s own `row_key`,
    `<file>::<function>::<line>`. The mirror does not publish it, so `cr_infractions`
    computes it from the mirror row's `file`, `function` and `line` — which is exactly how
    the Builder keys `rows` (verified on run 136: key == `row_key`)."""
    return f"{row['file']}::{row.get('function', '')}::{row['line']}"


def placeholders_of(shape: str) -> list[dict[str, str]]:
    """The `<…>` tokens of a prescribed shape, in order of appearance, deduplicated.
    `name` is the token without its brackets; `meaning` is the token's own words — the
    prescription writes them to be read (I-75)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for tok in PLACEHOLDER_RE.findall(shape or ""):
        name = tok[1:-1]
        if name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "meaning": name})
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Shared field groups
# ─────────────────────────────────────────────────────────────────────────────

_INFRACTION_ROW = (
    "{id, file, function, line, line_end, replace_span, replace_span_live, span_current, "
    "finding_lines, rule_ids, infraction, solution_kind, digest, has_solution, status, withheld, "
    "species, selected_role, apply, apply_reason, withheld_by, gate_withheld_reasons, "
    "rule_id, variant}"
    # ND2 (2026-10-01): `rule_id` and `variant` are ADDITIVE (the 09-21 channel contract) — `rule_id` the
    # row's one rule id (null when several), `variant` the repair variant (`selected_role`). A naming-drift
    # row (rule_id NAMING_DRIFT, species naming_drift) carries its TIER in `variant` and the §D group
    # under `naming_drift` {key, canonical, spelling, tier, kind, sites, first_seen}.
)

_ERROR = Field("error", "str|None", "null when the call succeeded, else the one-line reason", required=False)


# ─────────────────────────────────────────────────────────────────────────────
# The tools — packet §B, in packet order
# ─────────────────────────────────────────────────────────────────────────────

_SPECS: list[ToolSpec] = [
    # ── §B row 1: start / bind / tear down ──────────────────────────────────
    ToolSpec(
        name="cr_watch",
        contract="Start CodeRadar on `target`: a supervisor (the gearbox) starts every CodeRadar process and runs each launch step (the same gates as `run_proof.sh up`); this returns when ALL GATES PASSED (every step passed) or the time budget runs out. Never edits the target's code; its only writes inside the target are two state files per folder (the state mirrors) under `.coderadar/`, kept after cr_stop as the run's log. A refused call leaves nothing behind.",
        packet_row="cr_watch / cr_attach / cr_stop",
        source_of_record="system_scripts/gearbox.py via ./launch.sh (run_proof.sh `up` semantics); ports from system_scripts/copy_ports.json",
        writes=(".archive/runs/<repo name>/launch.log", ".archive/runs/<repo name>/gearbox.pid",
                ".archive/runs/<repo name>/state_during_run/ (copies of the state files)",
                "and it spawns launch.sh/gearbox, which write system_scripts/{poll_config,launch_progress,BUILDER_STATE}.json "
                "and the two state mirrors under the target's .coderadar/"),
        input_schema=(
            Field("target", "str", "the repo to watch: absolute or `~`; a relative path resolves against the MCP server's working directory — the directory the client was started in, not the dev's shell — and a refusal echoes the absolute path it resolved to (B1 — the target is named here, never at server start)"),
            Field("trackers", "str", "the checkers (trackers) to run, comma-joined from `io` (I/O calls), `mypy` (type errors), `crc` (which functions changed since the baseline), `vulture` (dead code); default `io,mypy`; anything else is refused", required=False, default="io,mypy"),
            Field("tracer", "str", "the file-access watcher (tracer) that sees which files a run opens — `lsof` only over MCP (eslogger needs root and a terminal)", required=False, default="lsof", choices=("lsof",)),
            Field("gate_budget_s", "int|None", "the most seconds to wait for every launch step to pass; null lets CodeRadar work it out (it grows with the number of .py files)", required=False),
        ),
        output_schema=(
            Field("started", "bool", "true only when every gate passed"),
            Field("target", "str", "the target, resolved"),
            Field("repo_id", "str", "the 12-hex repo id the app keys every per-target file with"),
            Field("run", "str|None", "the run dir name under `.archive/runs/` (Lane C, 2026-09-28)"),
            Field("snapshot", "str|None", "the COPY-FIRST snapshot launch.sh made, `~/CodeRadar_snapshots/<name>_<timestamp>` (Lane C)"),
            Field("phase", "str", "`BUILDER_STATE.json.phase` once the wait ends, e.g. `MONITORING`"),
            Field("gates", "list", "one record per gate: {gate, status, seconds}"),
            Field("gate_budget_s", "int", "the ceiling actually used"),
            Field("target_env", "str", "the target's private env (B2): `built` | `reused` | `failed: <reason>` — a failed env never blocks the scan (Q5)", required=False),
            # ── Fix plan 2026-10-23 C4: three ADDITIVE keys — a tracker that did not run is not a zero.
            Field("trackers_ran", "list", "the chosen checkers whose tool ran (off circuit_state.trackers: chosen minus not_measured)", required=False, default=[]),
            Field("trackers_not_requested", "list", "the choosable checkers (io, mypy, crc, vulture) this launch did NOT ask for — they produced no reading at all", required=False, default=[]),
            Field("naming_drift", "str", "the permanent naming-drift tracker: `measured`, or `NOT MEASURED — <why>` until its launch scan completes", required=False, default=""),
            Field("dashboard_url", "str", "http://127.0.0.1:<copy_ports.dashboard>"),
            Field("health_url", "str", "http://127.0.0.1:<copy_ports.health>/health"),
            _ERROR,
        ),
        example_input={"target": "~/code/myrepo"},
        example_output={
            "started": True, "target": "/Users/dev/code/myrepo", "repo_id": "4fd707688a44",
            "run": "myrepo", "snapshot": "/Users/dev/CodeRadar_snapshots/myrepo_20260928_142116",
            "phase": "MONITORING",
            "gates": [{"gate": "circuit READY", "status": "PASS", "seconds": 1.5}],
            "gate_budget_s": 2332, "target_env": "built",
            "dashboard_url": "http://127.0.0.1:8080", "health_url": "http://127.0.0.1:8051/health",
            "error": None,
        },
    ),
    ToolSpec(
        name="cr_attach",
        contract="Bind to a target already under MONITORING in this tree; reads only, starts nothing.",
        packet_row="cr_watch / cr_attach / cr_stop",
        source_of_record="system_scripts/BUILDER_STATE.json + system_scripts/circuit_state.json + system_scripts/running.lock",
        input_schema=(
            Field("target", "str|None", "the repo to bind to (absolute, `~` or relative); null takes the target the tree is already on", required=False),
        ),
        output_schema=(
            Field("attached", "bool", "true when a live MONITORING target was found"),
            Field("target", "str|None", "`BUILDER_STATE.json.target_repo`"),
            Field("repo_id", "str|None", "`BUILDER_STATE.json.repo_id`"),
            Field("phase", "str|None", "`BUILDER_STATE.json.phase`"),
            Field("cycle", "int|None", "`BUILDER_STATE.json.cycle`"),
            Field("since", "str|None", "`BUILDER_STATE.json.last_build`, ISO"),
            Field("dashboard_url", "str|None", "this tree's dashboard"),
            Field("health_url", "str|None", "this tree's health port"),
            _ERROR,
        ),
        example_input={},
        example_output={
            "attached": True, "target": "/Users/dev/code/myrepo", "repo_id": "4fd707688a44",
            "phase": "MONITORING", "cycle": 1, "since": "2026-09-17T07:53:54.940551+00:00",
            "dashboard_url": "http://127.0.0.1:8080", "health_url": "http://127.0.0.1:8051/health",
            "error": None,
        },
    ),
    ToolSpec(
        name="cr_stop",
        contract="Stop CodeRadar: send the stop signal (SIGTERM) to every CodeRadar process — the four background processes (daemons), the supervisor (gearbox), and a launch setup page left open on the dashboard port (`launch_setup.py --port …`; it closes, nothing ran) — then prove nothing is left running or behind (residue zero) and that the target is byte-identical to its snapshot apart from the two kept state files (`run_proof.sh down` semantics). Call cr_data_types BEFORE this and report its mypy and io readings to the dev; the `trackers` line here is only a backstop.",
        packet_row="cr_watch / cr_attach / cr_stop",
        source_of_record="system_scripts/gearbox.py teardown; md5 -r over the copy-first snapshot",
        writes=(".archive/runs/<repo name>/state_during_run/*_at_teardown.json (+ the intent copy)",
                ".archive/runs/<repo name>/<file listings> and teardown_diff.txt",
                ".archive/runs/<repo name>/gearbox.pid (removed)",
                ".archive/naming/rush_track_pool.txt only with mark_pool=True"),
        input_schema=(
            Field("verify_identity", "bool", "check that every file in the target matches the snapshot taken at launch (an md5 compare)", required=False, default=True),
            Field("mark_pool", "bool", "let the stop mark this run's name as used in CodeRadar's pool of run names", required=False, default=False),
            Field("expected_changes", "list", "Q3: the CLIENT's own edit manifest — target-relative paths the client edited. A differing path named here counts under `client_edits`; one not named lands in `unexpected_changes`", required=False, default=None),
        ),
        output_schema=(
            Field("stopped", "bool", "every daemon exited"),
            Field("daemons_exited", "list", "one record per daemon: {name, pid, exit_code, signal}"),
            Field("residue_clean", "bool", "nothing CodeRadar-owned remains in the target beyond the two kept state mirrors"),
            Field("byte_identical", "bool|None", "md5 diff empty; null when `verify_identity` was false. False on any run where the client applied a repair (Q3) — read it beside `unexpected_changes`"),
            Field("files_compared", "int", "how many files the md5 diff covered"),
            Field("client_edits", "int", "differing paths the client's `expected_changes` manifest named"),
            Field("gate_writes", "list", "Problem 5 (2026-10-10): differing paths the manifest did NOT name that the solution gate wrote itself — the file of a row with an integrated attempt in this launch's `gate_<repo_id>.jsonl`; expected, not residue", required=False, default=[]),
            Field("unexpected_changes", "list", "differing paths neither the manifest nor the gate ledger accounts for — the residue the guarantee is about; empty is the pass (the two state mirrors are exempt)"),
            Field("mirrors_kept", "list", "target-relative paths of the state mirrors (`.coderadar/<sub/path>/.noai_state.json` and `.monitor_state.json`) left in the target as the run's log — expected, not residue"),
            Field("run_dir", "str|None", "`.archive/runs/<name>/` the channel and states were copied into"),
            Field("trackers", "str|None", "MCPW-D O1: a one-line backstop of the tracker readings read BEFORE teardown — mypy (import_errors, type_errors = real type errors only, files, + annotation notes, and the `finished` count with its scope — M-20) and io (functions, io_functions, exempt) and wiring (`live N of M edges`, M = every edge, with its possible/severed split — M-19; live ≤ M) — so a client that forgot cr_data_types still has them; null when no circuit state was readable. cr_data_types stays the full reading", required=False),
            Field("teardown_source", "str|None", "C3 (c) / B1 (Q-H4-5): the file `daemons_exited` and `residue_clean` were read from — the gearbox's per-run log `system_scripts/daemon_log/gearbox_<ts>.log`, else this launch's `.archive/runs/<name>/launch.log`, either only when written after this stop's SIGTERM (or after this target's launch started). Null when no log of this run was found: then both readings are NOT MEASURED and `error` says why", required=False),
            # ── Fix plan 2026-10-23 D3: three ADDITIVE keys — a stop is not CLEAR while a finding is open.
            Field("open_findings", "int|None", "rows still open on the counterfeit mirror at teardown (repairs + no_vetted_fix, the lists `finished` counts); null when the mirror could not be read (NOT MEASURED)", required=False),
            Field("open_findings_by", "dict", "{repairs, no_vetted_fix, withheld} behind `open_findings`; withheld rows are listed, never counted", required=False, default={}),
            Field("clear", "bool", "true ONLY when every process is gone, residue was measured clean, the byte check was measured with `unexpected_changes` empty, and `open_findings` is 0. `stopped` is the process fact alone; anything NOT MEASURED is not clear, and `error` says which", required=False, default=False),
            _ERROR,
        ),
        example_input={"verify_identity": True, "expected_changes": ["colorama/repair_plant_071.py"]},
        example_output={
            "stopped": True,
            "daemons_exited": [{"name": "gearbox", "pid": 1234, "exit_code": 0, "signal": "SIGTERM"}],
            "residue_clean": True, "byte_identical": False, "files_compared": 79,
            "client_edits": 1, "unexpected_changes": [],
            "mirrors_kept": [".coderadar/.monitor_state.json", ".coderadar/.noai_state.json"],
            "run_dir": "/Users/dev/coderadar/.archive/runs/myrepo",
            "trackers": "mypy: measured, import_errors 0, total_errors 11 in 3/18 files · io: measured, 895 functions, io_functions 0, exempt 895",
            "teardown_source": "/Users/dev/coderadar/system_scripts/daemon_log/gearbox_20260917_075354.log",
            "error": None,
        },
    ),

    # ── §B row 2: status ────────────────────────────────────────────────────
    ToolSpec(
        name="cr_status",
        contract="Where CodeRadar is now: its phase; the launch (running · ready · failed · no launch · NOT MEASURED, whoever started it); the launch steps (gates); the band (how often it scans · restarts · test runners seen); its health; and `finished` — is the repo clean yet, the one question the dev asks between edits.",
        packet_row="cr_status()",
        source_of_record="dash mirror system_scripts/.monitor_state.json `monitor.summary` + health port http://127.0.0.1:<health>/health; phase/cycle from BUILDER_STATE.json; cadence + runners from circuit_state.json; restarts from the gearbox events",
        input_schema=(),
        output_schema=(
            Field("phase", "str", "`BUILDER_STATE.json.phase`"),
            Field("detail", "str", "`BUILDER_STATE.json.detail` — the daemon's own one-line summary, with ONE clause re-quoted (I-149 / Q8, session 10): `tester confirmed N of M solutions` reads N from the confirmed ledger, the number the ledger, `rule_outcomes` and `cr_hand_back` agree on. Run 162 published `0 of 123` beside seven confirmations, and a reader who quoted the detail line reported zero work done"),
            Field("cycle", "int", "`BUILDER_STATE.json.cycle`"),
            Field("target", "str", "`BUILDER_STATE.json.target_repo`"),
            Field("repo_id", "str", "`BUILDER_STATE.json.repo_id`"),
            Field("run", "str|None", "the run dir name under `.archive/runs/` (Lane C, 2026-09-28)"),
            Field("snapshot", "str|None", "the COPY-FIRST snapshot launch.sh made, `~/CodeRadar_snapshots/<name>_<timestamp>` (Lane C)"),
            Field("launch", "dict", "R5 (2026-09-30): the launch live on this tree or the last one that ran, however it was started (./launch.sh, the setup page, cr_watch) — off system_scripts/launch_progress.json, which every launch writes. {state: running | ready | failed | no launch | NOT MEASURED, reason: str|None (always set for NOT MEASURED and no launch; for failed the launch's own failure detail), step, step_label (failed: the step that failed; running: the current step), overall (the file's raw word: running|done|ready|failed), live: bool|None (a launch.sh or gearbox process of this tree is up; None = process table unreadable), target, copy, purpose (from the choices step; target_note is added when the record names no target), started, updated, seconds: int|None, steps: [{step, label, status, detail, seconds}], source}. A record naming another target is NOT MEASURED for this one."),
            Field("target_guard", "dict", "T-13 (2026-09-30): the one-target guard on each file cr_status reads — {builder|monitor|noai|circuit: {file, verdict: pass | fail | NOT MEASURED, reason}}. NOT MEASURED when the file names no target_repo (the dash mirror did not, before R4) or no target is configured: the file is still read, but nothing proved it is this target's."),
            Field("gates", "dict", "{all_passed: bool|None, seconds: int|None, source: launch.log|launch_progress.json, gates: [{gate, status, seconds}]} — `all_passed` follows `launch.state` (True at ready, False at failed, None otherwise); the per-gate lines come from launch.log only when THIS launch was cr_watch's, else from the launch file's steps"),
            Field("band", "dict", "{cadence: circuit_state.scan_cadence._summary {cycle, scripts, rescanned, reused, viewed_dirs}, restarts: [{child, n, reason, gate, iso}], runners: circuit_state.test_runners {status, presence, execution}}"),
            Field("health", "dict", "{ok: bool, url: str, status: str} from the health port"),
            Field("summary", "dict", "`monitor.summary` verbatim: {broken_imports, path_hacks, mypy_errors, mypy_ran, mypy_rc, mypy_files_checked, sync_needs_review, dead_code_items, dead_code_actionable, severed_links, severed_by_repair}. R4/R9: `mypy_errors`, `sync_needs_review` and `dead_code_*` are null when their tracker was NOT MEASURED (tool missing or failed) — null is never 0; see MONITOR_MIRROR_KEYS"),
            Field("infractions", "dict", "the counterfeit mirror's `summary`: {total_functions, passed, failed, files_scanned, files_not_scanned, repairs, no_vetted_fix, whitelisted, withheld}; `files_not_scanned` = [{file, type, message}] the scan could not judge (a rule crashed, no parse/decode) — never read as clean"),
            Field("rule_outcomes", "dict", "B9 (Q3, 2026-09-20): the counterfeit mirror's `summary.rule_outcomes` — {<rule id>: {confirmed_for: int, failed_against: {<variant>: int}}}; a `confirmed` counts FOR every rule id the ledger record carries, a `failed` against the repair VARIANT and never the rule. `{}` on a mirror written before B9"),
            # ── Session 8 (2026-09-21) — `finished`'s three INPUTS, published beside the verdict.
            # Four ADDITIVE keys and one widened one. No tool, no handler, no parameter moved:
            # 13 tools stay 13. Every value is the dash mirror's own; nothing is computed here.
            Field("severed_by_repair", "int", "I-127 / Q1: red import edges a LEASED repair explains — the sever falls at or after the lease `cr_apply` wrote for that file, and the lease's after-text is what the file reads now. Still red on the wiring, and NOT in `summary.severed_links`, so a client no longer moves `finished` away by repairing something. 0 on a mirror written before session 8"),
            Field("mypy_ran", "bool", "C5: the mypy scan completed (rc in {0, 1}). False is not a clean zero — it is no measurement at all"),
            Field("mypy_rc", "int|None", "I-128 / Q2: mypy's own returncode. `2` is a config/crash abort that checked nothing; null when no scan was attempted, or on a mirror written before session 8"),
            Field("mypy_files_checked", "int", "I-128 / Q2: how many SOURCE FILES that scan actually checked. `mypy_ran true` with 0 here is still not a measurement, and the gate reads `not measured`"),
            Field("finished", "any", "Q5: zero infractions AND zero data-type issues AND zero severed links; withheld rows do NOT count. TRI-STATE since session 8 (Q2): `true`, `false`, or the string `not measured` while any one of the three inputs is unread — `false` is a verdict, and an unread input is not one"),
            Field("finished_reason", "str", "which of the three is not yet zero, which was not measured, or `finished`"),
            Field("finished_source", "str", "where the verdict came from: `mirror` when `monitor.summary.finished` published it (T4), `computed` when this tool derived Q5's formula itself", choices=("mirror", "computed")),
            # ── Session 10 (2026-09-22), I-149 / Q8 — the aggregator. Two ADDITIVE keys; `detail`
            # keeps its name and the Builder's own words stay readable beside it.
            Field("confirmed_from_ledger", "int", "I-149 / Q8: confirmations the confirmed ledger beside the return channel carries, counted once per (digest, replace_span). THE number — `cr_hand_back.confirmed` and `rule_outcomes` agree with it, and `detail` now quotes it"),
            Field("detail_builder", "str", "`BUILDER_STATE.json.detail` VERBATIM, before the I-149 re-quote — so nothing the daemon said is edited away silently"),
            # ── Fix plan 2026-10-23 C1 / C3 / C4: six ADDITIVE keys. Read `open_findings` before anything else.
            Field("open_findings", "int", "rows still open on the counterfeit mirror: repairs + no_vetted_fix (the lists `finished` counts; withheld never counts)", required=False, default=0),
            Field("open_findings_by", "dict", "{repairs, no_vetted_fix, withheld} behind `open_findings`", required=False, default={}),
            Field("infraction_pages", "int|None", "how many pages `cr_infractions()` (default filters) holds right now — the number to page to; null when it could not be computed", required=False),
            Field("trackers_ran", "list", "the chosen checkers whose tool ran (circuit_state.trackers: chosen minus not_measured)", required=False, default=[]),
            Field("trackers_not_requested", "list", "the choosable checkers (io, mypy, crc, vulture) this launch did NOT ask for — no reading exists for them", required=False, default=[]),
            Field("naming_drift", "str", "the permanent naming-drift tracker: `measured`, or `NOT MEASURED — <why>`", required=False, default=""),
            Field("dot_dirs_scanned", "list|None", "repo-relative dot-directories holding .py files that ARE in the scan (`.git`, `__pycache__`, `.cr_pycache`, `.venv`, `venv`, `node_modules` are skipped by name; every other dot-dir is scanned) — read it before reading findings from a vendored tree; null with no target to walk", required=False),
            _ERROR,
        ),
        example_input={},
        example_output={
            "phase": "MONITORING",
            "detail": "cycle 1: 164 findings, 156 with fix, no fix 8 (declined 8), 0 whitelisted; tester confirmed 0 of 156 solutions",
            "cycle": 1, "target": "/Users/dev/code/myrepo", "repo_id": "4fd707688a44",
            "run": "myrepo", "snapshot": "/Users/dev/CodeRadar_snapshots/myrepo_20260928_142116",
            "launch": {"state": "ready", "reason": None, "step": None, "step_label": None, "overall": "ready",
                       "live": True, "target": "/Users/dev/myrepo", "copy": "on", "purpose": "given",
                       "started": 1790817000.0, "updated": 1790817085.0, "seconds": 85,
                       "steps": [{"step": "wiring", "label": "wiring check", "status": "pass", "detail": "every node connected", "seconds": 0.4}],
                       "source": "system_scripts/launch_progress.json"},
            "target_guard": {"builder": {"file": "system_scripts/BUILDER_STATE.json", "verdict": "pass", "reason": None},
                             "monitor": {"file": "system_scripts/.monitor_state.json", "verdict": "pass", "reason": None},
                             "noai": {"file": "system_scripts/.noai_state.json", "verdict": "pass", "reason": None},
                             "circuit": {"file": "system_scripts/circuit_state.json", "verdict": "pass", "reason": None}},
            "gates": {"all_passed": True, "seconds": 85, "source": "launch.log", "gates": [{"gate": "WIRING", "status": "PASS", "seconds": 0.4}]},
            "band": {
                "cadence": {"cycle": 88, "scripts": 64, "rescanned": 13, "reused": 51, "viewed_dirs": ["."]},
                "restarts": [],
                "runners": {"status": "MEASURED", "presence": {}, "execution": {}},
            },
            "health": {"ok": True, "url": "http://127.0.0.1:8051/health", "status": "ok"},
            "summary": {"broken_imports": 0, "path_hacks": 1, "mypy_errors": 586, "mypy_ran": True,
                        "mypy_rc": 1, "mypy_files_checked": 65,
                        "sync_needs_review": 8, "dead_code_items": 0, "dead_code_actionable": 0,
                        "severed_links": 0, "severed_by_repair": 0},
            "infractions": {"total_functions": 359, "passed": 110, "failed": 164, "files_scanned": 66,
                            "repairs": 156, "no_vetted_fix": 8, "whitelisted": 0, "withheld": 85},
            # B9 (Q3): run 144's own two lines — the rule the confirmed repair answered, and the rule
            # ids of the row whose repair failed, counted against that row's VARIANT. NAI-021S carries
            # both at once, which is the ruling: the failed repair took nothing off the confirmation.
            "rule_outcomes": {
                "NAI-021S": {"confirmed_for": 1, "failed_against": {"alias_chain_fix:new_sequence": 1}},
                "NAI-071": {"confirmed_for": 0, "failed_against": {"alias_chain_fix:new_sequence": 1}},
            },
            "severed_by_repair": 0,
            "mypy_ran": True,
            "mypy_rc": 1,
            "mypy_files_checked": 65,
            "finished": False,
            "finished_reason": "164 infractions; 586 data-type issues",
            "finished_source": "computed",
            "confirmed_from_ledger": 0,
            "detail_builder": "cycle 1: 164 findings, 156 with fix, no fix 8 (declined 8), 0 whitelisted; tester confirmed 0 of 156 solutions",
            "error": None,
        },
    ),

    # ── §B row 3: the rows ──────────────────────────────────────────────────
    ToolSpec(
        name="cr_infractions",
        contract="The problems found (rows), paged by file at 50 rows a page; a page never splits a file. Withheld rows (functions in test or helper files that CodeRadar lists but does not judge) come here too and never carry a solution. Every row carries `replace_span_live` — the span read off the LIVE file — and `span_current`; a client renders against `replace_span_live` only. `apply` is `yes` only for a row whose solution renders a CONCRETE diff at the site (a rewriter); a prescribed shape (`solution_kind \"prescribed\"`, `cr_apply` → `kind \"shape\"`, diff null) reads `apply \"review\"` with `apply_reason` \"template only — no diff rendered at this site\" — ranked after every `yes` row, never counted as `yes`, and not to be applied blindly: read the site and decide, or skip it; `no` = nothing to apply. Label only: a `review` row is still in `repairs`, so `failed == repairs + no_vetted_fix` is unmoved.",
        packet_row="cr_infractions(file?, rule?, withheld?, has_solution?, page?)",
        source_of_record="counterfeit-code mirror .noai_state.json — `repairs[]` + `no_vetted_fix[]` + `withheld[]`",
        input_schema=(
            Field("file", "str|None", "target-relative path; exact match, else null for every file", required=False),
            Field("rule", "str|None", "a rule id, e.g. `NAI-021S`; matches a row whose `rule_ids` contains it (`NAMING_DRIFT` = the naming-drift tracker's rows only)", required=False),
            Field("withheld", "bool|None", "true = withheld rows only (listed, not judged), false = exclude them, null = repairs and no_vetted_fix only (the default view)", required=False),
            Field("has_solution", "bool|None", "true = `repairs[]` only, false = `no_vetted_fix[]` only, null = both", required=False),
            Field("page", "int", "1-based", required=False, default=1),
            Field("page_size", "int", "rows per page (default 50)", required=False, default=PAGE_SIZE_DEFAULT),
        ),
        output_schema=(
            Field("rows", "list", f"one record per row: {_INFRACTION_ROW}"),
            Field("page", "int", "the page returned"),
            Field("page_size", "int", "the page size used"),
            Field("pages", "int", "how many pages the filter yields"),
            Field("total", "int", "rows matching the filter, across every page"),
            Field("files", "list", "the target-relative files on THIS page, in order"),
            Field("last_scan", "str", "the mirror's `last_scan`, ISO — how fresh this answer is"),
            Field("naming_drift_status", "str", "ND2: the naming-drift tracker's rows ride here too (rule_id `NAMING_DRIFT`, `variant` = tier T1|T2|T3, `has_solution` false, `apply` \"no\" — the developer renames, CodeRadar never does). \"measured — N group(s) published as rows\" once the launch scan has completed; before that \"NOT MEASURED — <reason>\" and no such row is invented", required=False),
            # ── Fix plan 2026-10-23 C1: the field that replaces the `has_more` guess.
            Field("done", "bool", "true only on the last page (`page >= pages`) or when there is none — stop paging when this is true, never on a missing `has_more`", required=False, default=False),
            _ERROR,
        ),
        example_input={"file": "colorama/repair_plant_071.py", "page": 1},
        example_output={
            "rows": [{
                "id": "colorama/repair_plant_071.py::collect::4",
                "file": "colorama/repair_plant_071.py", "function": "collect", "line": 4, "line_end": 6,
                "replace_span": "colorama/repair_plant_071.py:L4-L6",
                "replace_span_live": "colorama/repair_plant_071.py:L4-L6", "span_current": True,
                "finding_lines": [4],
                "rule_ids": ["NAI-021S", "NAI-071"],
                "infraction": "[HARD_REQUIREMENTS] NAI-021S: Alias identity chain",
                "solution_kind": "rewriter", "digest": "8f9a25700f", "has_solution": True,
                "status": None, "withheld": None, "species": None,
                "selected_role": "alias_chain_fix:new_sequence", "apply": "yes",
                "withheld_by": None, "gate_withheld_reasons": {},
                "rule_id": None, "variant": "alias_chain_fix:new_sequence",
            }],
            "page": 1, "page_size": 50, "pages": 1, "total": 1,
            "files": ["colorama/repair_plant_071.py"],
            "last_scan": "2026-09-17T07:53:54.949008+00:00",
            "naming_drift_status": "NOT MEASURED — launch scan has not completed — the baseline is not built yet",
            "error": None,
        },
    ),

    # ── §B row 4: one row in full ───────────────────────────────────────────
    ToolSpec(
        name="cr_row",
        contract="One problem (row) in full, exactly as CodeRadar's fix builder (the Builder) published it — the fixes it considered, their scores, why it chose one (`decision.why`), what it saw, what happened to each, and the evidence.",
        packet_row="cr_row(id)",
        source_of_record="system_scripts/BUILDER_STATE.json → `rows[<id>]`; a closed row: system_scripts/gate_<repo_id>.jsonl",
        input_schema=(
            Field("id", "str", "the row key `<file>::<function>::<line>` (the `id` cr_infractions gives); HTML-escaped ids are unescaped first, and if the line has moved a unique `(file, function)` match still finds the row"),
        ),
        output_schema=(
            Field("row", "dict|None", "the row verbatim; null when the id is unknown or the row has closed (then `closed` answers). Keys as published: row_key, file, function, line, line_end, replace_span, finding_lines, rule_ids, rule_ids_all, context_ids, species, withheld, failure_layer, infraction, failure_reason, row_hash, fix_order, depth, dependents, cb_context, rca_evidence, exonerated, generators_consulted, candidates_considered, observations, selection, decision{pick_role, why}, no_fix_status, solution_kind, fix, before_code, after_code, digest, tester{confirmed, tester, timestamp}, built_at"),
            Field("return_channel", "str|None", "`BUILDER_STATE.json.return_channel` — where `cr_report_outcome` will write for this row"),
            Field("resolved_by", "str", "how the id was resolved: `row` (exact, after `html.unescape`) or `function` (the unique live `(file, function)` match — two or more candidates are refused, never guessed); empty when nothing resolved", required=False, default="", choices=("", "row", "function")),
            Field("resolved_id", "str", "the id actually read, which differs from the one given when `resolved_by` is `function`", required=False, default=""),
            Field("closed", "dict|None", "Problem 5 (2026-10-10): a row whose attempt integrated leaves BUILDER_STATE on the next rescan, 2–8 s later, so its verdict is answered from the gate ledger — `{row_key, ledger, why, attempts: [{attempt_id, attempt, status (integrated|failed|deferred), stage, verdict, detail, at, stages: [{stage, verdict, detail, at}]}]}`; null while the row is on the board or when the ledger has no record of the id", required=False, default=None),
            _ERROR,
        ),
        example_input={"id": "colorama/repair_plant_071.py::collect::4"},
        example_output={
            "row": {
                "row_key": "colorama/repair_plant_071.py::collect::4",
                "file": "colorama/repair_plant_071.py", "function": "collect", "line": 4, "line_end": 6,
                "replace_span": "colorama/repair_plant_071.py:L4-L6",
                "rule_ids": ["NAI-021S"], "rule_ids_all": ["NAI-021S", "NAI-071"],
                "candidates_considered": 2,
                "selection": {"alias_chain_fix:new_sequence": 66.56, "mutable_default_fix": 64.3},
                "decision": {"pick_role": "alias_chain_fix:new_sequence",
                             "why": "picked alias_chain_fix:new_sequence over 1 other pickable candidate(s) of 2 offered; deciding method: intent alignment & logic soundness"},
                "solution_kind": "rewriter", "digest": "8f9a25700f",
                "tester": {"confirmed": False, "tester": "", "timestamp": ""},
                "built_at": "2026-09-17T07:53:54.940551+00:00",
            },
            "return_channel": "/Users/dev/coderadar/system_scripts/return_channel_4fd707688a44.jsonl",
            "resolved_by": "row", "resolved_id": "colorama/repair_plant_071.py::collect::4",
            "error": None,
        },
    ),

    # ── §B row 5: wiring ────────────────────────────────────────────────────
    ToolSpec(
        name="cr_wiring",
        contract="Nodes and edges with state `possible` | `live` | `severed` (Q7) | `live_via_tests` (I-198: a library with no app entry proof, edge loaded by the test runner — never counted as live) + `severed_since`, plus runners and data flows (Item 10).",
        packet_row="cr_wiring()",
        source_of_record="system_scripts/circuit_state.json (`nodes`, `edges`, `severed_links`, `severed_since`, `dataflows`, `test_runners`, `all_connected`, `cycles`); dash mirror `monitor.wiring` carries only {severed, severed_since, drawn} today",
        input_schema=(
            Field("include_dataflows", "bool", "carry `circuit_state.dataflows` (Item 10's list field)", required=False, default=True),
            Field("state", "str|None", "return only edges in this state", required=False, choices=EDGE_STATES),
        ),
        output_schema=(
            Field("nodes", "list", "{name, relative_path, connected, imports, syntax_valid, syntax_fixture, import_error, subdir, runtime_loaded, runtime_loaded_via}"),
            Field("edges", "list", "{source, target, state, severed_since} — `state` is one of possible|live|severed|live_via_tests, `severed_since` is null unless severed"),
            Field("severed_links", "list", "`circuit_state.severed_links`, each a [source, target] pair"),
            Field("all_connected", "bool", "`circuit_state.all_connected`"),
            Field("cycles", "list", "`circuit_state.cycles`"),
            Field("runners", "dict", "`circuit_state.test_runners` {status, presence, execution}"),
            Field("dataflows", "list", "`circuit_state.dataflows`; empty when `include_dataflows` was false"),
            Field("counts", "dict", "{possible, live, severed, live_via_tests} edge tallies; `live_via_tests` is never part of `live`"),
            Field("live_why", "str|None", "MCPW-D O4b: why `live` is 0 — no app entry proof (runner coverage lights `live_via_tests` on a library, never live), no runtime record yet, or no edges; null when live > 0", required=False),
            _ERROR,
        ),
        example_input={"include_dataflows": True},
        example_output={
            "nodes": [{"name": "colorama/__init__", "relative_path": "colorama/__init__.py", "connected": True,
                       "imports": ["colorama/ansitowin32"], "syntax_valid": True, "syntax_fixture": False,
                       "import_error": None, "subdir": "colorama", "runtime_loaded": True,
                       "runtime_loaded_via": "app+runner"}],
            "edges": [{"source": "colorama/__init__", "target": "colorama/ansitowin32",
                       "state": "live", "severed_since": None}],
            "severed_links": [], "all_connected": True, "cycles": [],
            "runners": {"status": "MEASURED", "presence": {}, "execution": {}},
            "dataflows": [], "counts": {"possible": 28, "live": 1, "severed": 0, "live_via_tests": 0}, "live_why": None, "error": None,
        },
    ),

    # ── §B row 6: the trackers ──────────────────────────────────────────────
    ToolSpec(
        name="cr_data_types",
        contract="The trackers' state for the target (io, mypy, crc, vulture, and naming_drift — the permanent one, chosen on every run) and the one number `finished` reads as `data-type issues`.",
        packet_row="cr_data_types()",
        source_of_record="system_scripts/circuit_state.json (`trackers`, `io_tracker_results`, `mypy_results`, `crc_results`, `vulture_results`, `naming_drift`, `contract_violations`) + dash mirror `monitor.mypy` / `monitor.dead_code` / `monitor.naming_drift`",
        input_schema=(
            Field("tracker", "str|None", "one tracker only; null for all five", required=False, choices=("io", "mypy", "crc", "vulture", "naming_drift")),
        ),
        output_schema=(
            Field("chosen", "list", "`circuit_state.trackers.chosen` — the trackers this run actually ran; `naming_drift` is in it on every run (permanent, like path hacks)"),
            Field("not_run", "list", "`circuit_state.trackers.not_run` — never `naming_drift`"),
            Field("not_measured", "dict", "R4/R9: `circuit_state.trackers.not_measured` {token: reason} — a tracker chosen at launch whose tool is missing or failed; its block's `status` reads \"NOT MEASURED — <reason>\" and its counts are null (never 0). `naming_drift` is here until the launch scan has completed (its block says `ran: false`). Empty when every chosen tracker measured", required=False),
            Field("io", "dict", "`circuit_state.io_tracker_results` {totals, files, details, status}"),
            Field("mypy", "dict", "`circuit_state.mypy_results` {files_checked, passed, failed, total_errors, type_errors, annotation_notes, errors, mypy_ran, mypy_rc, status, …} — `total_errors` = `type_errors` = real type errors only; `annotation_notes` the --strict notes kept apart (the dashboard's mypy tile shows these two)"),
            Field("crc", "dict", "`circuit_state.crc_results` {status, …}"),
            Field("vulture", "dict", "`circuit_state.vulture_results` {files_scanned, total_items, items_by_category, status, …}"),
            Field("pytest", "dict", "owner 2026-10-07: the permanent pytest tracker — the dash mirror's `monitor.pytest` block for the last pytest run CodeRadar started; `ran` false = NOT MEASURED with its `reason`, never 0", required=False),
            Field("naming_drift", "dict", "ND2 (naming-drift plan §D): the permanent tracker's block — `circuit_state.naming_drift`, else the dash mirror's `monitor.naming_drift` — {status, ran, groups, new, pre_existing, by_tier {T1,T2,T3}, accepted, scanned_files, baseline_at, rows [{key, canonical, spelling, tier, kind new|pre_existing, sites [{file, line, col, name_kind}], first_seen}]}. `status` \"measured\" once the launch scan has completed (`ran` true); before that \"NOT MEASURED — <reason>\" with every count null, never 0. T3 rows are reported, never in the headline `new`", required=False),
            Field("contract_violations", "dict", "`circuit_state.contract_violations` {total, recent_count, violations, disabled}"),
            Field("issues", "int|None", "B5 (Q-H0-1): the REAL TYPE ERRORS in the dash mirror's mypy list (`monitor.mypy.errors`) by the ONE split `system_scripts.mypy_partition` — the same rule circuit_daemon counts the badge's `type_errors` with, so this reads 27 beside \"27 type errors\", never 88. The --strict annotation notes in the same list are `notes`; `issues + notes` = `monitor.mypy.error_lines` = `finished_input`. R9: null when mypy was NOT MEASURED (see `not_measured`) or the mirror is absent, never 0"),
            Field("notes", "int|None", "B5: the --strict annotation notes in the same list `issues` was counted from (`[no-untyped-def]`, `[no-untyped-call]`, `[import-untyped]`, …); null when NOT MEASURED, never 0", required=False),
            Field("issues_source", "str", "B5: which published list or key `issues`/`notes` were counted from — `monitor.mypy.errors` (the list, split here), `monitor.mypy.type_errors` (a mirror without the list: the daemon's own split of the same rule) or `NOT MEASURED`", required=False),
            Field("issues_scope", "str", "the scope of `issues` in words — B5: real type errors only; it is NOT the `finished` count", required=False),
            Field("finished_input", "int|None", "B5: the count `finished` still uses, unchanged — `monitor.summary.mypy_errors`: every mypy `: error:` line INCLUDING annotation notes, less suppressed (M-20; = `issues + notes` when measured); null when mypy was NOT MEASURED", required=False),
            Field("finished_scope", "str", "B5: the scope of `finished_input` in words (ISSUES_SCOPE)", required=False),
            Field("issues_split", "dict", "R9: the circuit's own split as the dashboard's mypy tile shows it — {type_errors, annotation_notes} from `circuit_state.mypy_results`; each null when mypy was NOT MEASURED. Same rule as `issues`/`notes`; differs only by the mirror's whitelist/suppression filter", required=False),
            _ERROR,
        ),
        example_input={},
        example_output={
            "chosen": ["io", "mypy", "naming_drift"], "not_run": ["crc", "vulture"],
            "not_measured": {"naming_drift": "launch scan has not completed — the baseline is not built yet"},
            "io": {"totals": {}, "files": [], "details": [], "status": "MEASURED"},
            "mypy": {"files_checked": 9, "passed": 0, "failed": 9, "total_errors": 27,
                     "type_errors": 27, "annotation_notes": 61,
                     "errors": [], "mypy_ran": True, "mypy_rc": 1, "status": "MEASURED"},
            "crc": {"status": "NOT_RUN"},
            "vulture": {"files_scanned": 0, "total_items": 0, "items_by_category": {}, "status": "NOT_RUN"},
            "naming_drift": {"status": "NOT MEASURED — launch scan has not completed — the baseline is not built yet",
                             "ran": False, "groups": None, "pre_existing": None, "new": None,
                             "by_tier": {"T1": None, "T2": None, "T3": None}, "accepted": None,
                             "scanned_files": None, "baseline_at": None, "rows": []},
            "contract_violations": {"total": 0, "recent_count": 0, "violations": [], "disabled": False},
            "issues": 27, "notes": 61, "issues_source": "monitor.mypy.errors",
            "issues_scope": "(real type errors only — the --strict annotation notes are `notes`)",
            "finished_input": 88, "finished_scope": "(mypy error lines incl. annotation notes, less suppressed)",
            "issues_split": {"type_errors": 27, "annotation_notes": 61}, "error": None,
        },
    ),

    # ── §B row 7: intent ────────────────────────────────────────────────────
    ToolSpec(
        name="cr_intent",
        contract="The dev's derived intent — the profile facts the Ranker reads — verbatim from the intent file.",
        packet_row="cr_intent()",
        source_of_record="system_scripts/intent_<repo_id>.json, named by `BUILDER_STATE.json.summary.intent.file`",
        input_schema=(),
        output_schema=(
            Field("target", "str", "the intent file's `target`"),
            Field("repo_id", "str", "the intent file's `repo_id`"),
            Field("generated_at", "str", "ISO"),
            Field("statement", "str|None", "the dev's own statement; null when none was found (Item 8)"),
            Field("facts", "list", "{fact, value, source, evidence, recorded_at} — verbatim"),
            Field("facts_by_source", "dict", "`BUILDER_STATE.summary.intent.facts_by_source`, e.g. {changelog: 3, packaging: 2, readme: 2}"),
            Field("file", "str", "the intent file's absolute path"),
            _ERROR,
        ),
        example_input={},
        example_output={
            "target": "/Users/dev/code/myrepo", "repo_id": "4fd707688a44",
            "generated_at": "2026-09-17T07:09:34.062761+00:00", "statement": None,
            "facts": [{"fact": "package_name", "value": "colorama", "source": "packaging",
                       "evidence": "pyproject.toml", "recorded_at": "2026-09-17T07:09:34.062750+00:00"}],
            "facts_by_source": {"changelog": 3, "packaging": 2, "readme": 2},
            "file": "/Users/dev/coderadar/system_scripts/intent_4fd707688a44.json",
            "error": None,
        },
    ),

    # ── §B row 8: the edit ──────────────────────────────────────────────────
    ToolSpec(
        name="cr_apply",
        contract="Return the edit and WRITE NOTHING TO THE TARGET (Q3): a unified diff from a rewriter's `after_code`, or a shape + placeholders for a prescription (Q8, I-75). The client applies it in its own editor. Since session 7 one APPLY LEASE record is appended beside the channel — outside the target, as the confirmed ledger is — so the server remembers what it handed out (§C.1).",
        packet_row="cr_apply(row)",
        writes=("system_scripts/apply_lease_<repo_id>.jsonl (one appended record per call)",
                "a cr_apply_* temp dir for the dry-run patch, removed before the answer"),
        source_of_record="counterfeit-code mirror .noai_state.json → the `repairs[]` row (before_code, after_code, fix, digest, replace_span, solution_kind, selected_role); writes `system_scripts/apply_lease_<repo_id>.jsonl` beside the return channel",
        input_schema=(
            Field("row", "str", "the row id `<file>::<function>::<line>`; HTML-escaped ids are unescaped first (I-137) and a unique `(file, function)` match resolves a drifted line (I-130)"),
            Field("context_lines", "int", "unified-diff context", required=False, default=3),
        ),
        output_schema=(
            Field("kind", "str", "`diff` for a rewriter, `shape` for a prescription, `none` for a row with no vetted fix. Fix A: a `shape` is the rule's template, never rendered at this site — its row reads `apply \"review\"` in `cr_infractions`; read the site and decide before writing it, never apply it blindly", choices=("diff", "shape", "none")),
            Field("diff", "str|None", "unified diff before_code → after_code, headed with `replace_span`; null unless kind is `diff`"),
            Field("shape", "str|None", "the prescribed `after_code` with its `<placeholders>` intact; null unless kind is `shape`"),
            Field("placeholders", "list", "[{name, meaning}] in order of appearance, deduplicated; empty unless kind is `shape`"),
            Field("reason", "str", "the row's `fix` — why this edit; for kind `none`, the `no_vetted_fix` status"),
            Field("row", "str", "the row id echoed back"),
            Field("file", "str", "target-relative path the client edits"),
            Field("replace_span", "str", "`<file>:L<start>-L<end>` — exactly the span to replace"),
            Field("digest", "str|None", "the solution digest; `cr_report_outcome` needs it and it is null for kind `none`"),
            Field("selected_role", "str|None", "`decision.pick_role`, e.g. `alias_chain_fix:new_sequence`"),
            Field("applies_cleanly", "bool|None", "`patch -p1 --dry-run` on a temp copy: true when the diff applies to the file's CURRENT bytes AT `replace_span_live`, false when it does not; null unless kind is `diff`"),
            # ── session 7, §C.1 / §C.4 / §C.5 — three ADDITIVE keys, no parameter moved.
            Field("replace_span_live", "str", "I-130: the span the diff is RENDERED AGAINST — the function's live span, located by AST in the file as it stands now. Equal to `replace_span` until an earlier edit to the same file shifts the rows below it; the Builder's key stays `replace_span`", required=False, default=""),
            Field("lease", "str", "the apply-lease `.jsonl` appended to — the server's memory of what it handed out; empty when the row carries no solution to lease", required=False, default=""),
            Field("lease_written", "bool", "one `APPLY_LEASE_RECORD` reached that file", required=False, default=False),
            Field("resolved_by", "str", "how the id was resolved: `row` or `function`; empty on a refusal. I-148 (c) / Q4: a FUNCTION OF (id, mirror state) ALONE — `context_lines` and every other rendering argument are read after the resolution and cannot move it, so the same call twice answers the same word", required=False, default="", choices=("", "row", "function")),
            # ── session 10, I-148 (a) / I-145 — three ADDITIVE keys, no parameter moved.
            Field("span_current", "bool|None", "I-148 (a) / Q3: `replace_span` and `replace_span_live` name the same lines. False means the row's recorded span is STALE and the client must render against `replace_span_live`; null when no live span could be read (a `<module>` row, an unreadable file)", required=False),
            Field("given_id", "str", "I-145 / Q2: the row id the caller passed, after `html.unescape` — carried beside `resolved_id` so a client can match the lease and the channel by the id it holds", required=False, default=""),
            Field("resolved_id", "str", "the id the lease was filed under; differs from `given_id` when `resolved_by` is `function`", required=False, default=""),
            # ── Fix plan 2026-10-23 B2: cr_apply is a READ. It never writes the target and it is not a second way in.
            Field("write", "bool", "always false: cr_apply shows the edit and writes nothing; the Builder writes an integrated cr_submit attempt. A row that already has a cr_submit attempt answers `error` here instead of a diff", required=False, default=False),
            _ERROR,
        ),
        example_input={"row": "colorama/repair_plant_071.py::collect::4"},
        example_output={
            "kind": "diff",
            "diff": "--- colorama/repair_plant_071.py:L4-L6\n+++ colorama/repair_plant_071.py:L4-L6\n@@ -1,3 +1,3 @@\n-def collect(items=[]):\n+def collect(items=None):\n",
            "shape": None, "placeholders": [],
            "reason": "`items=[]` → `items=None`; `new_items = list(items) if items is not None else []`",
            "row": "colorama/repair_plant_071.py::collect::4",
            "file": "colorama/repair_plant_071.py",
            "replace_span": "colorama/repair_plant_071.py:L4-L6",
            "digest": "8f9a25700f", "selected_role": "alias_chain_fix:new_sequence",
            "applies_cleanly": True,
            "replace_span_live": "colorama/repair_plant_071.py:L6-L8",
            "lease": "/Users/dev/coderadar/system_scripts/apply_lease_4fd707688a44.jsonl",
            "lease_written": True, "resolved_by": "row",
            "span_current": False,
            "given_id": "colorama/repair_plant_071.py::collect::4",
            "resolved_id": "colorama/repair_plant_071.py::collect::4",
            "error": None,
        },
    ),

    # ── §B row 9: the runner ────────────────────────────────────────────────
    ToolSpec(
        name="cr_run_module",
        contract="Run the target's script or runner THROUGH `entry_point_wrapper.py`, so the run shows on the band and I-53 / I-55 apply.",
        packet_row="cr_run_module(path, args)",
        writes=("system_scripts/running.json, entry_point_info.json / runner_info.json (by the wrapper subprocess)",
                "inside the target ONLY to put back, from the launch snapshot, files the RUN itself wrote (M-21, `target_writes`)"),
        source_of_record="system_scripts/entry_point_wrapper.py — `run_module(module_name, module_args)` for a dotted name, `run_script` for a file path",
        input_schema=(
            Field("path", "str", "a dotted module name (`pytest`, `colorama.tests`) or a target-relative file path"),
            Field("args", "list", "arguments passed through to the runner", required=False, default=[]),
            Field("as_module", "bool|None", "force `-m` (true) or a script run (false); null auto-picks by whether `path` names a file", required=False),
            Field("timeout_s", "int", "kill the run after this many seconds", required=False, default=600),
        ),
        output_schema=(
            Field("exit_code", "int", "the wrapper's return code"),
            Field("stdout", "str", "captured stdout"),
            Field("stderr", "str", "captured stderr"),
            Field("duration_s", "float", "wall seconds"),
            Field("module", "str", "what the wrapper was actually pointed at"),
            Field("args", "list", "the arguments as passed (I-55 appends `-p no:cacheprovider`, M-21 `-o addopts=` unless the caller set its own, to a `-m pytest` run AFTER `test_path` is read)"),
            Field("seen_on_band", "bool", "the tracker saw this pid with a cwd under the target (I-53)"),
            Field("timed_out", "bool", "true when `timeout_s` killed it"),
            Field("interpreter", "str", "the interpreter the run used — the target's private env (B2), else the engine's"),
            Field("target_env", "str", "`built` | `reused` | `failed: <reason>` (+ `degraded` when the engine interpreter ran it, Q5)"),
            Field("layout", "str", "`src` (<target>/src put on the run's path, B3) or `flat`"),
            Field("target_writes", "list", "M-21: files the RUN wrote into the target, each {path, status}: `restored` (put back from the launch snapshot — untouched since launch), `changed` (the client edited it since launch; reported, not touched), `created`, `deleted`; `.coderadar/` excluded; empty = the run left the target as it found it"),
            _ERROR,
        ),
        example_input={"path": "pytest", "args": ["colorama/tests"]},
        example_output={
            "exit_code": 0, "stdout": "5 passed", "stderr": "", "duration_s": 3.1,
            "module": "pytest", "args": ["colorama/tests", "-p", "no:cacheprovider", "-o", "addopts="],
            "seen_on_band": True, "timed_out": False, "error": None,
            "interpreter": ".archive/target_envs/<repo_id>/venv/bin/python", "target_env": "reused",
            "layout": "flat", "target_writes": [],
        },
    ),

    # ── §B row 10: THE ONE WRITE ────────────────────────────────────────────
    ToolSpec(
        name="cr_submit",
        contract="Solution gate (owner 2026-10-08): submit ONE attempt at the row's repair — the whole replacement function, written by the agent. CodeRadar keeps every attempt; the Builder joins them onto the row as candidates (source `agent`) on its next cycle, where they are checked, filtered and ranked with the engine's own candidates. Nothing is applied by this call. A row takes at most `max_attempts` attempts; past the cap it is held for the owner.",
        packet_row="cr_submit(row, code, note)",
        source_of_record="system_scripts/attempts_<repo_id>.jsonl — beside the return channel, named by the channel's own rule",
        writes=("system_scripts/attempts_<repo_id>.jsonl (one appended record per accepted attempt)",),
        input_schema=(
            Field("row", "str", "the row id `<file>::<function>::<line>` — the same id cr_infractions / cr_row / cr_apply use"),
            Field("code", "str", "the complete replacement for the row's function (its `def` line through its last line), dedented"),
            Field("note", "str", "what the attempt changes and why, in a sentence — kept with the attempt", required=False, default=""),
        ),
        output_schema=(
            Field("accepted", "bool", "the attempt was recorded (it still has to pass the gate)"),
            Field("attempt", "int", "this attempt's number on the row, 1-based"),
            Field("max_attempts", "int", "the row's cap"),
            Field("attempt_id", "str", "sha256(row_key + code)[:10] — the id the gate's verdict will name"),
            Field("store", "str", "the absolute .jsonl path appended to"),
            Field("resolved_id", "str", "the `row_key` the attempt was filed under", required=False, default=""),
            _ERROR,
        ),
        example_input={"row": "pub/takings.py::is_free_shipping::12", "code": "def is_free_shipping(total):\n    return total >= 50\n",
                       "note": "docstring says at least 50: > becomes >="},
        example_output={"accepted": True, "attempt": 1, "max_attempts": 3, "attempt_id": "3f9c0d2a1b",
                        "store": "/Users/dev/coderadar/system_scripts/attempts_4fd707688a44.jsonl",
                        "resolved_id": "pub/takings.py::is_free_shipping::12", "error": None},
    ),
    ToolSpec(
        name="cr_report_outcome",
        contract="THE ONE WRITE: append one Item-5 line to the return channel; the Builder polls it next cycle, joins on digest AND replace_span, and the Ranker re-decides. The target is never touched.",
        packet_row="cr_report_outcome(row, outcome, note)",
        source_of_record="Item 5 return channel — system_scripts/return_channel_<repo_id>.jsonl, path read from `BUILDER_STATE.json.return_channel` (echoed on every mirror repair row's `return_channel`)",
        writes=("system_scripts/return_channel_<repo_id>.jsonl (one appended line per call)",
                "system_scripts/confirmed_ledger_<repo_id>.jsonl (one appended record on `confirmed`; `failed` writes none)"),
        input_schema=(
            Field("row", "str", "the row id `<file>::<function>::<line>`; digest and replace_span are read from the identity the seat was GIVEN — the live row, else the apply lease — never supplied by the caller"),
            Field("outcome", "str", "`confirmed` or `failed` — the run-53 ruling; no other word parses", choices=OUTCOMES),
            Field("note", "str", "the failure text; becomes `failure_log` (the Builder takes `[:2000]`). Ignored by the Builder on a `confirmed` line", required=False, default=""),
            Field("tester", "str", "who measured it; becomes `tester` on the line and `seat` in the ledger", required=False, default="coderadar-mcp"),
            Field("edit_kind", "str", "what the client applied — `diff` or `shape`; recorded in the confirmed ledger only, and omitted when the client will not say", required=False, default="", choices=("", "diff", "shape")),
        ),
        output_schema=(
            Field("written", "bool", "the line reached the channel"),
            Field("channel", "str", "the absolute .jsonl path appended to"),
            Field("line", "dict", "the record as written — `RETURN_CHANNEL_RECORD`: {digest, replace_span, outcome, failure_log, tester, timestamp} + the session-7 identity {row_key, rule_ids, variant, file, function}"),
            Field("digest", "str", "the digest the line carries — the PRE-EDIT one from the lease when the live row has drifted or gone"),
            Field("replace_span", "str", "the span the line carries, the second half of the join key"),
            Field("bytes_appended", "int", "length of the newline-terminated line"),
            Field("ledger", "str", "the confirmed ledger appended to; empty on a `failed` verdict, which writes no ledger record"),
            Field("ledger_written", "bool", "a ledger record reached the file (`confirmed` only)"),
            Field("ledger_record", "dict", "the record as written — CONFIRMED_LEDGER_RECORD; `{}` on a `failed` verdict"),
            # ── session 7, §C.2: which identity answered, in the payload, never inferred.
            Field("resolved_by", "str", "`row` — the live row by exact id; `function` — the unique live `(file, function)` match; `lease` — the apply lease, used when the live row is GONE or its digest/rule_ids differ from the lease's (I-119 / I-125 / I-138)", required=False, default="", choices=("", "row", "function", "lease")),
            Field("resolved_id", "str", "the `row_key` the identity was filed under", required=False, default=""),
            Field("given_id", "str", "I-145 / Q2: the id the SEAT passed, after `html.unescape`. It rides on the channel line and in the ledger record too, so a seat reconciling its own log by the id it holds matches without knowing what the server re-resolved", required=False, default=""),
            Field("lease", "str", "the apply-lease file consulted", required=False, default=""),
            _ERROR,
        ),
        example_input={"row": "colorama/repair_plant_071.py::collect::4", "outcome": "failed",
                       "note": "AssertionError: collect() returned an alias"},
        example_output={
            "written": True,
            "channel": "/Users/dev/coderadar/system_scripts/return_channel_4fd707688a44.jsonl",
            "line": {"digest": "8f9a25700f", "replace_span": "colorama/repair_plant_071.py:L4-L6",
                     "outcome": "failed", "failure_log": "AssertionError: collect() returned an alias",
                     "tester": "coderadar-mcp", "timestamp": "2026-09-17T08:10:00.000000+00:00",
                     "row_key": "colorama/repair_plant_071.py::collect::4",
                     "rule_ids": ["NAI-021S", "NAI-071"],
                     "variant": "alias_chain_fix:new_sequence",
                     "file": "colorama/repair_plant_071.py", "function": "collect",
                     "given_id": "colorama/repair_plant_071.py::collect::4"},
            "digest": "8f9a25700f", "replace_span": "colorama/repair_plant_071.py:L4-L6",
            "bytes_appended": 231,
            "ledger": "", "ledger_written": False, "ledger_record": {},
            "resolved_by": "lease",
            "resolved_id": "colorama/repair_plant_071.py::collect::4",
            "given_id": "colorama/repair_plant_071.py::collect::4",
            "lease": "/Users/dev/coderadar/system_scripts/apply_lease_4fd707688a44.jsonl",
            "error": None,
        },
    ),

    # ── §B row 11: hand back ────────────────────────────────────────────────
    ToolSpec(
        name="cr_hand_back",
        contract="Publish the tester report and the finished state (B8-1 / B7-5); the client's working tree IS the repaired copy, so nothing is archived here. The answer's `trackers` line carries the mypy and io readings — REPORT it to the dev with the confirmed/solutions counts (cr_data_types has the full reading).",
        packet_row="cr_hand_back()",
        writes=(".archive/runs/<repo name>/tester_report.json (the report, stamped with the finished state)",),
        source_of_record="tester_report.json (Item 6) + dash mirror `monitor.summary.finished`",
        input_schema=(
            Field("note", "str", "a remark carried into the report", required=False, default=""),
        ),
        output_schema=(
            Field("report_path", "str", "where `tester_report.json` was written"),
            Field("target", "str", "the report's `target`"),
            Field("repo_id", "str", "the report's `repo_id`"),
            Field("run_started", "str", "ISO"),
            Field("run_ended", "str", "ISO"),
            Field("builder_cycles", "int", "cycles the Builder completed"),
            Field("infractions", "int", "rows LIVE at hand-back (a confirmed repair retires its row, so this is lower than a mid-run cr_infractions total by `infractions_retired_confirmed`)"),
            Field("infractions_seen", "int", "MCPW-D O4a: infractions + infractions_retired_confirmed — the population a mid-run cr_infractions total counted", required=False),
            Field("infractions_retired_confirmed", "int", "MCPW-D O4a: rows retired because their repair was confirmed (from the ledger)", required=False),
            Field("solutions", "int", "MCPW-D O3: every solution offered — live rows with a digest + ledger-confirmed ones whose row retired + tester-failed ones whose row dropped the digest; the denominator of confirmed_fraction"),
            Field("confirmed", "int", "rows the tester confirmed — the channel-joined ones PLUS the ones only the confirmed ledger still knows (Q1(a): a repair that works removes its own row)"),
            Field("confirmed_joined", "int", "of those, the ones the Builder joined on digest AND replace_span — `summary.tester.confirmed`, the pre-ledger meaning"),
            Field("confirmed_from_ledger", "int", "of those, the ones carried only by `confirmed_ledger_<repo_id>.jsonl`"),
            Field("confirmed_ledger_rows", "list", "one CONFIRMED_LEDGER_RECORD per ledger-only confirmation — the row's pre-repair identity"),
            Field("confirmed_ledger", "str", "the ledger path, beside the return channel"),
            Field("confirmed_fraction", "float|None", "confirmed / solutions over the SAME population (<= 1, MCPW-D O3); null when the tester never ran"),
            Field("trackers", "str|None", "MCPW-D O1: the mypy + io + wiring readings in one line (same line cr_stop repeats; scopes named per M-19/M-20) — report it to the dev; null when no circuit state was readable", required=False),
            Field("tester_ran", "bool", "any line reached the channel"),
            Field("status", "str", "the report's `status`, e.g. `MEASURED`"),
            Field("per_infraction", "list", "{file, function, line, rule_ids, digest, confirmed}"),
            Field("return_channel_lines", "int", "lines the Builder read"),
            Field("return_channel", "str", "the channel path"),
            Field("orphans", "int", "lines that matched no row AND have no ledger record — a confirmation the ledger carries is not an orphan"),
            Field("orphans_channel", "int", "the Builder's own orphan count, before the ledger is consulted (`summary.tester.orphans`)"),
            Field("unparsed", "int", "lines that were not the contract"),
            Field("builder_state_sha256", "str", "the state the report was taken from"),
            Field("finished", "bool", "the Q5 state at hand-back"),
            _ERROR,
        ),
        example_input={},
        example_output={
            "report_path": "/Users/dev/coderadar/.archive/runs/myrepo/tester_report.json",
            "target": "/Users/dev/code/myrepo", "repo_id": "4fd707688a44",
            "run_started": "2026-09-17T07:53:46.788560+00:00",
            "run_ended": "2026-09-17T08:00:49.440699+00:00",
            "builder_cycles": 1, "infractions": 164, "infractions_seen": 164,
            "infractions_retired_confirmed": 0, "solutions": 156, "confirmed": 0,
            "confirmed_joined": 0, "confirmed_from_ledger": 0, "confirmed_ledger_rows": [],
            "confirmed_ledger": "/Users/dev/coderadar/system_scripts/confirmed_ledger_4fd707688a44.jsonl",
            "confirmed_fraction": None, "tester_ran": False, "status": "MEASURED",
            "trackers": "mypy: measured, import_errors 0, type_errors 7 in 2/18 files · io: measured, 895 functions, io_functions 0, exempt 895 · wiring: live 0 of 12 edges (possible 12, severed 0)",
            "per_infraction": [{"file": "colorama/repair_plant_071.py", "function": "collect",
                                "line": 4, "rule_ids": ["NAI-021S"], "digest": "8f9a25700f",
                                "confirmed": False}],
            "return_channel_lines": 0,
            "return_channel": "/Users/dev/coderadar/system_scripts/return_channel_4fd707688a44.jsonl",
            "orphans": 0, "orphans_channel": 0, "unparsed": 0,
            "builder_state_sha256": "054466c29ae08c3f510f1e58b273b5bf077db427206ab487ea6c8c076794d25a",
            "finished": False, "error": None,
        },
    ),
]

#: name → spec. §B has 11 ROWS; its first row names three tools, so there are 13 tool names.
TOOLS: dict[str, ToolSpec] = {s.name: s for s in _SPECS}

#: The 11 packet rows, so the proof can show the surface is covered exactly once.
PACKET_ROWS: tuple[str, ...] = tuple(dict.fromkeys(s.packet_row for s in _SPECS))


def tool(name: str) -> ToolSpec:
    try:
        return TOOLS[name]
    except KeyError:
        raise KeyError(f"no such tool {name!r}; the surface is {sorted(TOOLS)}") from None


# ─────────────────────────────────────────────────────────────────────────────
# The registry the lanes fill — T1 leaves it empty on purpose
# ─────────────────────────────────────────────────────────────────────────────

#: tool name → the callable that implements it. A lane registers from its OWN module;
#: no two lanes touch the same file, and no lane edits this one.
HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {}


def register_handler(name: str, fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Bind an implementation to a tool of the surface. Refuses an unknown name (a typo in a
    lane must fail at import, not at the first client call) and refuses to overwrite a
    binding (two lanes claiming one tool is a footprint collision, not a merge)."""
    if name not in TOOLS:
        raise KeyError(f"{name!r} is not in the tool surface; the surface is {sorted(TOOLS)}")
    if name in HANDLERS and HANDLERS[name] is not fn:
        raise RuntimeError(f"{name!r} already has a handler ({HANDLERS[name]!r}) — lanes must stay disjoint")
    HANDLERS[name] = fn
    return fn


def unimplemented(name: str) -> dict[str, Any]:
    """What the server answers for a tool whose lane has not landed yet."""
    return {"error": f"{name}: not implemented yet — see RELEASE_FORM_MCP_PACKET_2026-09-17 §C"}
