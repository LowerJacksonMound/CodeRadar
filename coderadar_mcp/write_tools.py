"""T3's file — the WRITE path and the edit.

Owns: cr_report_outcome · cr_apply · cr_run_module
Also T3's, OUTSIDE this package: the return-channel writer binding in the engine.
    — NOT NEEDED. The channel is a file the Builder polls; there is no API to bind to and no
    engine file is touched by this lane (see the report, §"engine files").

`cr_report_outcome` is the only tool in the whole surface that writes anything, and what it
writes is one appended line of `system_scripts/return_channel_<repo_id>.jsonl` — plus, on a
`confirmed` verdict only, one appended record of `confirmed_ledger_<repo_id>.jsonl` beside it
(Q1(a), S4-3). Build the channel record with `tool_interface.return_channel_line(...)` and
append `line.as_line()` — do not re-spell the record here; `BuilderDaemon._parse_channel_line`
rejects anything else and the line is then counted under `BUILDER_STATE.summary.tester.unparsed`.
The ledger record is `tool_interface.CONFIRMED_LEDGER_RECORD`, nothing in the engine polls it,
and it exists because a repair that works removes its own row (run 141): the channel's join key
is destroyed by the very repair the line confirms, so the row's PRE-REPAIR identity is kept here
and `gearbox.write_tester_report` / `cr_hand_back` count the confirmation from it.

`cr_apply` WRITES NOTHING TO THE TARGET (Q3) — and since the fix plan of 2026-10-23 (pass B) it is
a READ: it shows the engine's own candidate edit as a diff so a seat can read it before writing its
attempt, and it is NOT a second way to change the file. ONE ROW, ONE WRITER: a finding is fixed by
`cr_submit`; the Builder gates the attempt and, when it integrates, writes the function into the
target at its LIVE span (`no_aivalidator.solution_gate_integrate.stage_integrates`, called from
`BUILDER_DAEMON._stage_integrates`) and the attempt reads `integrated`. `cr_apply` refuses a row that
already has an attempt on file; `cr_submit` refuses a row whose `cr_apply` bytes have since been
edited by hand (that repair is reported with `cr_report_outcome`, the path for a repair made
outside CodeRadar).

Three facts of the engine govern this module (T1's interface report, verified live in run 138):
  * the join is `digest` AND `replace_span` — the right digest with the wrong span is a silent
    orphan, so both are read OFF THE IDENTITY here and never taken from the caller;
  * the LAST line per digest wins (`_join_channel` keeps `matching[-1]`);
  * there is no trigger — append one newline-terminated line, then wait one Builder cycle.
Never rewrite the channel: a file shorter than the daemon's offset is re-read from byte 0.

─── THE DRIFT FIX (session 7, packet §C — I-119 / 122 / 125 / 130 / 137 / 138) ───────────────
All six issues are one fact: **row identity is positional and so is the channel's join key, so
the row a seat was handed drifts out from under it between `cr_apply` and `cr_report_outcome`.**
It is retired within one Builder cycle when the repair works (I-119: 8 of 18 outcomes lost in
run 155, a window of 30–60 s — shorter than one 3-second suite); it is re-keyed when an earlier
edit to the same file shifts the rows below it (I-130); its digest and rule ids change between
apply and report (I-138); its variant dies with the re-decide (I-122); and a failed-then-reverted
row is retired against bytes that no longer exist, so the negative — the scarcer datum — is lost
(I-125). One cause, one repair, in four parts, all of them here:

  1. THE LEASE (§C.1). `cr_apply` on a `repairs` row appends one `APPLY_LEASE_RECORD` to
     `apply_lease_<repo_id>.jsonl`, beside the channel and named by the channel's own rule, as
     the confirmed ledger is. Append-only; the LAST record per `row_key` wins. It is the
     server's memory of what it handed out. It is outside the target, so byte-identity holds.
  2. THE RESOLUTION ORDER (§C.2). `cr_report_outcome` resolves (a) the live row by exact id,
     (b) the lease by exact id — when the live row is GONE, or when its digest / rule ids differ
     from the lease's (I-138's A1 rematch) — (c) refused with `error` naming what was tried. The
     channel line and the ledger record are built from the identity the seat was GIVEN.
  3. THE RE-BASE (§C.4). The diff and `_applies_cleanly` are rendered against the function's
     LIVE span, located by AST in the file as it stands now; the payload carries both
     `replace_span` (the Builder's key, the row's own) and `replace_span_live`.
  4. THE TOLERANT ID (§C.5). Every tool that takes a row id runs `html.unescape` on it first
     (I-137: `&lt;module&gt;` lost every module-scope row) and, when the exact id is not found,
     resolves a UNIQUE `(file, function)` match among live rows. Two or more candidates are
     refused with the candidates named — never guessed.

13 tools stay 13; no tool parameter changed; every new payload key is additive.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .tool_interface import (
    APPLY_LEASE_RECORD,
    CONFIRMED_LEDGER_RECORD,
    NOT_SELECTABLE_BY,
    NOT_SELECTABLE_REASON,
    OUTCOMES,
    TOOLS,
    placeholders_of,
    register_handler,
    return_channel_line,
    row_id,
)

OWNED: tuple[str, ...] = (
    "cr_apply",
    "cr_run_module",
    "cr_report_outcome",
    "cr_submit",
)

assert all(n in TOOLS for n in OWNED), "T3 claims a tool that is not in the surface"

#: How much of a run's output `cr_run_module` carries back — the TAIL, which is where a
#: failure says what it was. The full streams are on disk in the run's temp files only for
#: the length of the call; the client asks the runner again if it wants more.
TAIL_CHARS: int = 4000

#: Exit code reported when `timeout_s` killed the run (the POSIX `timeout(1)` convention) and
#: when the run could not be started at all (`sh`'s "command not found").
EXIT_TIMED_OUT: int = 124
EXIT_CANNOT_RUN: int = 127

#: Stopwords dropped when a placeholder's own words are matched against the prescription text.
_MEANING_STOPWORDS: frozenset[str] = frozenset(
    ("the", "a", "an", "of", "to", "in", "is", "it", "and", "or", "that", "this", "its")
)


# ─────────────────────────────────────────────────────────────────────────────
# Where the app publishes what this lane reads
# ─────────────────────────────────────────────────────────────────────────────


def _root() -> Path:
    """This tree's root. `CODERADAR_MCP_ROOT` overrides it — the seam the offline proof uses
    to point the three handlers at a fixture tree instead of the live one. Unset in a real
    client, where the package sits in the tree it serves."""
    override = os.environ.get("CODERADAR_MCP_ROOT")
    if override:
        return Path(override).resolve()
    return Path(__file__).resolve().parents[1]


def _sys_scripts() -> Path:
    return _root() / "system_scripts"


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _mirror() -> dict[str, Any] | None:
    """The counterfeit-code mirror the app publishes beside its state, `.noai_state.json`
    (`run_proof.sh`'s `MIRROR_SYS`). Absent between runs."""
    return _read_json(_sys_scripts() / ".noai_state.json")


def _builder_state() -> dict[str, Any] | None:
    return _read_json(_sys_scripts() / "BUILDER_STATE.json")


def _target_root() -> Path | None:
    """The repo under watch: the mirror's `target_repo`, else `BUILDER_STATE.json`'s."""
    for doc in (_mirror(), _builder_state()):
        if doc:
            t = doc.get("target_repo")
            if isinstance(t, str) and t:
                return Path(t)
    return None


def _buckets(mirror: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    return [
        ("repairs", mirror.get("repairs") or []),
        ("no_vetted_fix", mirror.get("no_vetted_fix") or []),
        ("withheld", mirror.get("withheld") or []),
    ]


def _find_row(rid: str) -> tuple[dict[str, Any] | None, str]:
    """The mirror row with this id, and which list it came from. The id is T1's one id
    (`<file>::<function>::<line>`, `BUILDER_STATE`'s own `row_key`); the mirror publishes no
    id, so it is computed the same way for every bucket."""
    mirror = _mirror()
    if not mirror:
        return None, "no mirror"
    for bucket, rows in _buckets(mirror):
        for row in rows:
            if isinstance(row, dict) and row_id(row) == rid:
                return row, bucket
    return None, "not found"


# ─────────────────────────────────────────────────────────────────────────────
# §C.5 — the TOLERANT ID (I-137 / I-130). Never a guess: one candidate or a refusal.
# ─────────────────────────────────────────────────────────────────────────────


def _given_id(rid: str) -> str:
    """The id the CALLER passed, in the one normalised form every record keeps it in:
    `html.unescape` and nothing else (I-137's unescape is a decoding, not a resolution).

    I-145 / Q2 (session 10): the server resolves an id and files its lease under the RESOLVED key,
    which is the right key for the server to keep — but the client goes on holding the id it was
    given. Run 162 passed `_termui_impl.py::_pipepager::549`, `::_tempfilepager::636` and
    `::open_url::799`; the leases, the channel lines and the ledger rows all read `::550`, `::637`
    and `::801`, so a seat reconciling its own log against the channel by `row_key` matched nothing.
    Both ids are carried from here on — an added EXACT key, never a looser match.
    """
    return html.unescape(rid or "")


def _id_parts(rid: str) -> tuple[str, str, str]:
    """`<file>::<function>::<line>` → its three parts. A malformed id yields empty parts and
    resolves by nothing, which is the refusal the caller reports."""
    bits = rid.split("::")
    if len(bits) != 3:
        return "", "", ""
    return bits[0], bits[1], bits[2]


def _candidates(rid: str) -> list[tuple[str, dict[str, Any], str]]:
    """Live rows whose `(file, function)` equal this id's, as `(id, row, bucket)`.
    I-130: an earlier edit to the same file shifts the rows below it, so the LINE of an id a
    client is holding goes stale while its file and function do not."""
    rel, func, _ = _id_parts(rid)
    if not rel:
        return []
    mirror = _mirror()
    out: list[tuple[str, dict[str, Any], str]] = []
    for bucket, rows in _buckets(mirror or {}):
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("file") or "") == rel and str(row.get("function") or "") == func:
                out.append((row_id(row), row, bucket))
    return out


def _resolve_row(rid: str) -> tuple[dict[str, Any] | None, str, str, str, str]:
    """ONE id resolver for every tool that takes a row id (§C.5).

    Returns `(row, bucket, resolved_id, resolved_by, error)`:
      * `html.unescape` FIRST — I-137: a client that round-trips ids through a markup layer
        sends `&lt;module&gt;` and lost every module-scope row to a bare "not found";
      * the exact id → `resolved_by "row"`;
      * else a UNIQUE `(file, function)` match among live rows → `resolved_by "function"`;
      * two or more candidates → refused with the candidates NAMED, never guessed;
      * none → refused, saying both things that were tried.

    I-148 (c) / Q4 (session 10) — DETERMINISTIC BY CONSTRUCTION. The whole order is
    `row → function → lease`: the first two steps are here and the third is
    `cr_report_outcome`'s, which consults the lease only when neither answered or the live row
    has drifted off the lease's digest. This function takes ONE argument, and every value it
    reads is either that argument or the mirror on disk — so `resolved_by` is a function of
    (id, mirror state) ALONE. `context_lines`, and every other rendering argument a caller can
    vary, is read strictly after this call and cannot reach it. Run 162's complaint was that an
    identical retry with only `context_lines` changed answered `function` where the first call
    answered `row`; what moved between the two calls was the MIRROR — a rescan had re-keyed the
    row — and the word the tool answers now says so honestly on both calls.
    """
    plain = _given_id(rid)
    row, bucket = _find_row(plain)
    if row is not None:
        return row, bucket, plain, "row", ""
    if bucket == "no mirror":
        return None, bucket, plain, "", "no mirror"
    cands = _candidates(plain)
    if len(cands) == 1:
        found_id, found_row, found_bucket = cands[0]
        return found_row, found_bucket, found_id, "function", ""
    if len(cands) > 1:
        named = ", ".join(sorted(c[0] for c in cands))
        return None, "ambiguous", plain, "", (
            f"{len(cands)} rows share this file and function and the exact id is not among "
            f"them — say which: {named}")
    rel, func, _ = _id_parts(plain)
    tried = f"exact id {plain!r}" + (f", then (file, function) ({rel!r}, {func!r})" if rel else "")
    return None, "not found", plain, "", f"not found — tried {tried}"


def _parse_span(span: str) -> tuple[str, int, int] | None:
    """`colorama/repair_plant_071.py:L4-L6` → (`colorama/repair_plant_071.py`, 4, 6)."""
    head, sep, tail = span.rpartition(":L")
    if not sep or "-L" not in tail:
        return None
    first, _, last = tail.partition("-L")
    try:
        return head, int(first), int(last)
    except ValueError:
        return None


def _channel_path(row: dict[str, Any] | None) -> str:
    """The channel, from the two places the app publishes it and never guessed: the row's own
    `return_channel`, else `BUILDER_STATE.json.return_channel`."""
    if row:
        ch = row.get("return_channel")
        if isinstance(ch, str) and ch:
            return ch
    state = _builder_state() or {}
    ch = state.get("return_channel")
    return ch if isinstance(ch, str) else ""


#: The one naming rule for the confirmed ledger, mirrored by the engine's reader
#: (`gearbox.confirmed_ledger_path`): the channel's own directory, the channel's own name with
#: `return_channel_` swapped for `confirmed_ledger_`. Neither side ever guesses the other's path.
LEDGER_STEM: str = "confirmed_ledger_"
CHANNEL_STEM: str = "return_channel_"

#: §C.1: the LEASE is named by the SAME rule — the channel's own directory, the channel's own
#: name with `return_channel_` swapped for `apply_lease_`. One naming rule, three files.
LEASE_STEM: str = "apply_lease_"


def _beside_channel(channel: str, stem: str) -> str:
    """`…/return_channel_a32f4c124796.jsonl` + a stem → the sibling file of that stem.
    A channel whose name is not the house name keeps its name with the stem in front, so a
    fixture channel still gets a ledger and a lease of its own beside it."""
    path = Path(channel)
    name = path.name
    if name.startswith(CHANNEL_STEM):
        return str(path.with_name(stem + name[len(CHANNEL_STEM):]))
    return str(path.with_name(stem + name))


def _ledger_path(channel: str) -> str:
    """`…/return_channel_a32f4c124796.jsonl` → `…/confirmed_ledger_a32f4c124796.jsonl`."""
    return _beside_channel(channel, LEDGER_STEM)


#: Solution gate (owner 2026-10-08): the agent's attempts, named by the same rule as the lease and the ledger.
ATTEMPTS_STEM: str = "attempts_"
#: The per-row attempt cap (owner 2026-10-08: 3) lives with the gate (no_aivalidator/solution_gate.MAX_ATTEMPTS),
#: read here so cr_submit and the Builder can never disagree; past it the row is held for the owner.
try:
    from no_aivalidator.solution_gate import MAX_ATTEMPTS
except Exception:   # the engine package not importable from this seat: the owner's ruled value
    MAX_ATTEMPTS = 3


def attempts_path(channel: str) -> str:
    """`…/return_channel_a32f4c124796.jsonl` → `…/attempts_a32f4c124796.jsonl`."""
    return _beside_channel(channel, ATTEMPTS_STEM)


def _lease_path(channel: str) -> str:
    """`…/return_channel_a32f4c124796.jsonl` → `…/apply_lease_a32f4c124796.jsonl`."""
    return _beside_channel(channel, LEASE_STEM)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _lease_record(rid: str, row: dict[str, Any], span_live: str,
                  before_text: str, after_text: str, given_id: str = "") -> dict[str, Any]:
    """`APPLY_LEASE_RECORD`, in that order — the identity `cr_apply` HANDS OUT, frozen at the
    moment it hands it out. Everything the report will need is here because every one of these
    facts can have moved by the time the seat reports: the digest (I-138), the span (I-130), the
    rule ids (I-138), the variant (I-122) and the row itself (I-119 / I-125)."""
    record: dict[str, Any] = {
        "row_key": rid,
        # I-145 / Q2: the id the seat passed, beside the id the server resolved. Equal to
        # `row_key` on every call where nothing had to be re-resolved.
        "given_id": _given_id(given_id) or rid,
        "digest": str(row.get("digest") or ""),
        "replace_span": str(row.get("replace_span") or ""),
        "replace_span_live": span_live or str(row.get("replace_span") or ""),
        "file": str(row.get("file") or ""),
        "function": str(row.get("function") or ""),
        "line": int(row.get("line") or 0),
        "rule_ids": [str(r) for r in (row.get("rule_ids") or []) if r],
        "variant": str(row.get("selected_role") or ""),
        "solution_kind": str(row.get("solution_kind") or "rewriter"),
        "before_sha256": _sha256(before_text),
        "after_sha256": _sha256(after_text),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    assert [f.name for f in APPLY_LEASE_RECORD] == list(record), \
        "the lease record is APPLY_LEASE_RECORD or it is not the contract"
    return record


def _append_lease(channel: str, record: dict[str, Any]) -> tuple[str, bool]:
    """Append one lease record. Append-only, like the channel and the ledger: the LAST record
    per `row_key` wins, and a re-apply of the same row simply supersedes its own earlier lease.
    Returns `(path, written)`; a channel that is not published yet leases nothing, and that is
    said in the payload rather than pretended."""
    if not channel:
        return "", False
    path = _lease_path(channel)
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        return path, False
    return path, True


def _lease_records(channel: str) -> list[dict[str, Any]]:
    """Every lease record on this channel, in the order they were handed out."""
    out: list[dict[str, Any]] = []
    if not channel:
        return out
    try:
        text = Path(_lease_path(channel)).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            doc = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("row_key") and doc.get("digest"):
            out.append(doc)
    return out


def _lease_lookup(channel: str, rid: str) -> dict[str, Any] | None:
    """The LAST lease record for this id, or None. Append-only, so the last write per `row_key`
    wins without the file ever being rewritten (I-119's rule, the ledger's rule).

    The id is TOLERANT in exactly the way `_resolve_row` is, and run 158 launch C is why. The
    lease is filed under the id the server RESOLVED, which is the right key for the server to
    keep — but a client holds the id it was GIVEN, and between its `cr_apply` and its report the
    Builder re-keys the row under it (`pick::18` → `::17`, `stamp::26` → `::25` on one cycle of
    run 158). Filed under `::17`, looked up under `::18`, the seat could not find its own lease
    and the whole repair failed at the last step. So:
      * the exact `row_key`, else
      * a `(file, function)` among the leases that names ONE row — and the lease says whether
        it is one row, because a re-keyed row keeps its DIGEST (the digest is over the content,
        not the position), while two functions of the same name in one file have two. One
        digest → one row, re-keyed; the last record wins. Two or more → refused by answering
        None rather than guessed, and the caller says what it tried.
    `html.unescape` first, for the same reason every other id gets it (I-137).

    I-145 / Q2 (session 10) — THE ORDER, spelled: the RESOLVED key first, an EXACT `given_id`
    second, the tolerant `(file, function)` third. The second step is the new one and it is an
    ADDED EXACT KEY, not a widening: a lease now records the id the seat passed as well as the
    one it was filed under, so `::549` finds the lease filed under `::550` by an equality, not by
    a match that could answer for a row nobody asked about. The third step is unchanged — the
    owner ruled I-145 is not to be fixed by loosening lookup further, and it is not loosened."""
    plain = _given_id(rid)
    records = _lease_records(channel)
    exact = [r for r in records if str(r.get("row_key") or "") == plain]
    if exact:
        return exact[-1]
    as_given = [r for r in records if str(r.get("given_id") or "") == plain]
    if as_given:
        return as_given[-1]
    rel, func, _ = _id_parts(plain)
    if not rel:
        return None
    near = [r for r in records
            if str(r.get("file") or "") == rel and str(r.get("function") or "") == func]
    if len({str(r.get("digest")) for r in near}) == 1:
        return near[-1]
    return None


def _ledger_record(row: dict[str, Any], line: Any, note: str, seat: str,
                   edit_kind: str) -> dict[str, Any]:
    """The row's PRE-REPAIR identity, as the registry row had it at report time — the fact the
    channel's join key loses the moment the repair works (run 141). Shape:
    `tool_interface.CONFIRMED_LEDGER_RECORD`, in that order."""
    rule_ids = [str(r) for r in (row.get("rule_ids") or []) if r]
    record: dict[str, Any] = {
        "digest": line.digest,
        "replace_span": line.replace_span,
        "rule_ids": rule_ids,
        "file": str(row.get("file") or ""),
        "function": str(row.get("function") or ""),
        "line": int(row.get("line") or 0),
        # I-145 / Q2: the seat's own id, so the ledger row can be reconciled by the id the seat
        # holds as well as by the identity the server resolved.
        "given_id": str(line.given_id or ""),
        "seat": seat,
        "note": note or "",
        "edit_kind": edit_kind or "",
        "timestamp": line.timestamp,
    }
    assert [f.name for f in CONFIRMED_LEDGER_RECORD] == list(record), \
        "the ledger record is CONFIRMED_LEDGER_RECORD or it is not the contract"
    return record


# ─────────────────────────────────────────────────────────────────────────────
# cr_apply — the edit, and not one byte written to the target (Q3)
# ─────────────────────────────────────────────────────────────────────────────


def _meaning_of(name: str, prescription: str) -> str:
    """A placeholder's meaning. I-75: a prescription writes its placeholders to be read, and
    the prescription's own text says what they stand for — so the meaning is the clause of the
    row's `fix` that carries the placeholder's own words, and the placeholder name itself when
    no clause does (T1 decision 7 took the name unconditionally; this is the same rule with
    the row's text preferred where it has it)."""
    words = [w for w in "".join(c if c.isalnum() else " " for c in name).lower().split()
             if w and w not in _MEANING_STOPWORDS]
    if not words or not prescription:
        return name
    clauses: list[str] = []
    for part in prescription.replace("—", ";").replace("\n", " ").split(";"):
        for piece in part.replace(". ", ".;").split(".;"):
            piece = piece.strip()
            if piece:
                clauses.append(piece)
    best, best_score = "", 0
    for clause in clauses:
        low = clause.lower()
        score = sum(1 for w in words if w in low)
        if score > best_score:
            best, best_score = clause, score
    need = 2 if len(words) > 1 else 1
    return best.rstrip(".,") if best_score >= need else name


def _placeholders(shape: str, prescription: str) -> list[dict[str, str]]:
    out = placeholders_of(shape)
    for ph in out:
        ph["meaning"] = _meaning_of(ph["name"], prescription)
    return out


def _apply_payload(rid: str, **over: Any) -> dict[str, Any]:
    """Every `cr_apply` answer carries the whole output schema — an error is a complete
    record with `error` set, never a fragment (the schema is the contract, not a prefix of
    it; `tool_interface.unimplemented` is the one exception T1 left)."""
    payload: dict[str, Any] = {
        "kind": "none", "diff": None, "shape": None, "placeholders": [], "reason": "",
        "row": rid, "file": "", "replace_span": "", "digest": None,
        "selected_role": None, "applies_cleanly": None,
        "replace_span_live": "", "lease": "", "lease_written": False, "resolved_by": "",
        # ── session 10: I-148 (a)'s mark and I-145's two ids. Additive, and set on EVERY answer
        # including a refusal, because the schema is the contract and not a prefix of it.
        "span_current": None, "given_id": _given_id(rid), "resolved_id": "",
        # Fix plan 2026-10-23 B2: always false — cr_apply is a read; the Builder is the writer.
        "write": False,
        "error": None,
    }
    payload.update(over)
    return payload


def _span_is_current(recorded: str, live: str) -> bool | None:
    """I-148 (a) / Q3 — do the row's RECORDED span and the LIVE span name the same lines?

    `null` when no live span could be read (a `<module>` row, a prescription, an unreadable file):
    the absence of a measurement is not a `false`, which is a verdict (the `finished` tri-state's
    rule, applied here). Run 162 is the case this exists for: `_termui_impl.py::open_url`
    published `replace_span` L804-L868 — matching neither the original L799-L866 nor the live file
    — beside a correct `replace_span_live` L802-L869, and a client that trusted the recorded field
    would have rewritten 66 lines of somebody else's code. The field cannot be DROPPED (it is half
    the Builder's join key), so it is MARKED.
    """
    if not live or not recorded:
        return None
    return recorded == live


def _decorator_note(segment_lines: list[str], start: int) -> str:
    """I-148 (b) — the sentence a row's `reason` gains when its span STARTS AT A DECORATOR.

    Run 162: for `_pipepager` / `_tempfilepager` the prose said the import goes "above
    `def _pipepager`", while the row's span begins at `@contextlib.contextmanager`; a client that
    followed the prose literally put a statement between the decorator and its `def` and emitted a
    `SyntaxError`. The prose now names what is actually on the first line of the span.
    """
    head = next((ln for ln in segment_lines if ln.strip()), "")
    if not head.lstrip().startswith("@"):
        return ""
    return (f" The span starts at the decorator `{head.strip()}` on line {start}, not at the "
            f"`def` — anything this prose puts ABOVE the function goes above the decorator.")


#: (resolved path, mtime_ns, size) → the parsed module, or None when it does not read or parse.
#: I-148 (a), session 10: `cr_infractions` now reads a LIVE span for every row it publishes, and
#: the click snapshot puts 53 of its 198 rows in one 3 000-line file — the same file parsed 53
#: times a page. The key carries the file's own mtime and size, so an edit between two calls is a
#: different key and no stale tree is ever answered: the cache is a memo of THIS file's bytes, not
#: a snapshot of the target.
_AST_CACHE: dict[tuple[str, int, int], Any] = {}


def _parsed(path: Path) -> Any:
    """The file's module AST, memoised on (path, mtime_ns, size). None when it does not read or
    does not parse — a half-written file is not an error here, it is an absent measurement."""
    try:
        stat = path.stat()
        key = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None
    if key in _AST_CACHE:
        return _AST_CACHE[key]
    try:
        tree: Any = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        tree = None
    if len(_AST_CACHE) > 512:
        _AST_CACHE.clear()
    _AST_CACHE[key] = tree
    return tree


def live_span_of(target: Path | None, rel: str, function: str, line: int,
                 before_code: str) -> str | None:
    """The span a client must render against — `<file>:L<a>-L<b>` off the LIVE file — or None
    when no live span could be READ (no target under watch, a `<module>` row, a file the tree no
    longer holds, a file that does not parse). None is the absence of a measurement, never a
    verdict that the recorded span is wrong.

    I-148 (a) / Q3: one rule, spelled once, so `cr_infractions` and `cr_apply` cannot disagree
    about where a row's bytes are. `cr_apply` has re-based since session 7 (§C.4); the ROW did
    not, which is how run 162's `open_url` published L804-L868 beside a correct L802-L869.
    """
    if target is None or not rel:
        return None
    live = _live_span(target / rel, function, line, before_code)
    if live is None:
        return None
    return f"{rel}:L{live[0]}-L{live[1]}"


def _live_span(path: Path, function: str, line: int, before_code: str) -> tuple[int, int] | None:
    """§C.4 / I-130 — the function's LIVE span in the file as it stands now, by AST.

    Run 155: every hoist shifted the rows below it (`_pipepager` 549→550→552, `open_url`
    799→800→802→804), so `cr_apply`'s unified diff drifted against the live file after any
    earlier edit to the same file and the client had to apply from `before_code` instead. The
    row's recorded span is the Builder's key and stays the Builder's key; the DIFF is rendered
    here, against the function the row names, wherever it now is.

    Same `function` name; the row's `line` picks the NEAREST when the name repeats (the packet's
    rule). Decorators ride along only when the row's own `before_code` starts with one — the row
    says how much of the function it recorded, so nothing is inferred. `<module>` and an unnamed
    function have no AST node of their own and answer None: the recorded span stands.
    """
    if not function or function == "<module>":
        return None
    tree = _parsed(path)
    if tree is None:
        return None
    matches: list[ast.AST] = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function
    ]
    if not matches:
        return None
    node = min(matches, key=lambda n: abs(int(getattr(n, "lineno", 0)) - int(line or 0)))
    start = int(getattr(node, "lineno", 0))
    end = int(getattr(node, "end_lineno", 0) or start)
    decorators = list(getattr(node, "decorator_list", []) or [])
    head = next((ln for ln in (before_code or "").splitlines() if ln.strip()), "")
    if decorators and head.lstrip().startswith("@"):
        start = min([start] + [int(getattr(d, "lineno", start)) for d in decorators])
    if start < 1 or end < start:
        return None
    return start, end


def _applies_cleanly(path: Path, rel: str, start: int, end: int,
                     after_lines: list[str]) -> tuple[bool, str]:
    """Does the edit still fit the file as it is NOW? The span diff is rendered from the
    file's current bytes, so this is a self-check, not a formality: it catches a row whose
    span has drifted off the end of the file and a `patch` that would refuse the hunk.
    `patch --dry-run` over a whole-file diff in a temp copy; an in-memory apply when `patch`
    is not on the box. Nothing is written to the target either way."""
    try:
        current = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"
    if start < 1 or end > len(current) or start > end:
        return False, f"span L{start}-L{end} is outside the file's {len(current)} lines"
    new = current[: start - 1] + after_lines + current[end:]
    whole = "".join(difflib.unified_diff(current, new, fromfile=f"a/{rel}", tofile=f"b/{rel}"))
    if not whole:
        return True, "no change: the file already reads as after_code"
    patch_bin = shutil.which("patch")
    if not patch_bin:
        return True, "in-memory apply (patch(1) not on this box)"
    tmp = Path(tempfile.mkdtemp(prefix="cr_apply_"))
    try:
        dest = tmp / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        (tmp / "edit.patch").write_text(whole, encoding="utf-8")
        proc = subprocess.run([patch_bin, "-p1", "--dry-run", "-i", "edit.patch"],
                              cwd=tmp, capture_output=True, text=True, timeout=60)
        detail = (proc.stdout + proc.stderr).strip().replace("\n", " ")
        return proc.returncode == 0, detail or "patch --dry-run exit 0"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cr_apply(row: str, context_lines: int = 3) -> dict[str, Any]:
    """The edit for one row — a unified diff for a rewriter, a shape + placeholders for a
    prescription (Q8), `none` for a row with no vetted fix (T1 decision 6). WRITES NOTHING.

    The diff is rendered from the file's CURRENT bytes at the row's span, not from the row's
    `before_code`: the client may already have edited around it, and a diff that does not
    describe the file in front of the client is a diff that will not apply.

    I-148 (c) / Q4: the resolution is done FIRST, by `_resolve_row`, which sees the id and the
    mirror and nothing else. `context_lines` is read below, at the render, and can never move
    `resolved_by` — the same call twice answers the same word.
    """
    rec, bucket, rid, how, err = _resolve_row(row)
    given = _given_id(row)
    if rec is None:
        return _apply_payload(row, error=f"cr_apply: row {row!r} — {err or bucket}")
    span = str(rec.get("replace_span") or "")
    rel = str(rec.get("file") or "")
    if bucket != "repairs":
        # `no_vetted_fix` publishes `status` (run 136: `declined`); a withheld row publishes
        # `withheld` (FIX_51, e.g. `species:proxy:package_marker`). Either IS the reason.
        # I-152 (session 10): a row the Builder published as NOT SELECTABLE says so in its own
        # words — the prescription seam's sentence, not a bare status — so the seat is told why
        # there is no offer rather than left to infer it from an empty `kind`.
        reason = str(rec.get("status") or rec.get("withheld") or bucket)
        if str(rec.get("withheld_by") or "") == NOT_SELECTABLE_BY:
            sentences = [v for v in (rec.get("gate_withheld") or {}).values() if v]
            reason = "; ".join([NOT_SELECTABLE_REASON] + sentences)
        return _apply_payload(row, kind="none", reason=reason, file=rel, replace_span=span,
                              replace_span_live=span,
                              selected_role=rec.get("selected_role"),
                              resolved_by=how, resolved_id=rid, given_id=given)

    fix = str(rec.get("fix") or "")
    digest = rec.get("digest")
    selected_role = rec.get("selected_role")
    after_code = str(rec.get("after_code") or "")
    before_code = str(rec.get("before_code") or "")
    channel = _channel_path(rec)

    # Fix plan 2026-10-23 B2 — ONE ROW, ONE WRITER. A row with a cr_submit attempt on file belongs
    # to the Builder; no diff is handed out that a seat could apply by hand beside it.
    filed = _attempts_on(channel, rid)
    if filed:
        return _apply_payload(
            row, kind="none", reason=fix, file=rel, replace_span=span, replace_span_live=span,
            digest=digest, selected_role=selected_role, resolved_by=how, resolved_id=rid, given_id=given,
            error=(f"cr_apply: row {rid} already has {len(filed)} cr_submit attempt(s) on file — the Builder is "
                   f"its writer; read cr_row({rid!r}) for the attempt's status and do not edit by hand"))

    if rec.get("solution_kind") == "prescribed":
        # A shape has no live span to re-base against — the client renders it and decides where
        # it goes — so the lease records the recorded span as the live one and says so.
        lease_path, leased = _append_lease(
            channel, _lease_record(rid, rec, span, before_code, after_code, given_id=given))
        return _apply_payload(
            row, kind="shape", shape=after_code, placeholders=_placeholders(after_code, fix),
            reason=fix, file=rel, replace_span=span, digest=digest,
            selected_role=selected_role, replace_span_live=span,
            # A shape has no live span of its own to compare against, so `span_current` is the
            # not-measured value rather than a `true` nobody read (I-148 a).
            span_current=None,
            lease=lease_path, lease_written=leased, resolved_by=how,
            resolved_id=rid, given_id=given,
        )

    target = _target_root()
    parsed = _parse_span(span)
    if target is None or parsed is None:
        return _apply_payload(row, kind="diff", reason=fix, file=rel, replace_span=span,
                              digest=digest, selected_role=selected_role, resolved_by=how,
                              resolved_id=rid, given_id=given,
                              error="cr_apply: no target under watch" if target is None
                              else f"cr_apply: unreadable replace_span {span!r}")
    _, start, end = parsed
    path = target / rel
    # §C.4 — RE-BASE. The row's span is where the function WAS at scan time; the diff has to
    # describe the file in front of the client, so the span it is rendered at is where the
    # function IS. When nothing has shifted the two are the same string.
    function = str(rec.get("function") or "")
    live = _live_span(path, function, int(rec.get("line") or 0), before_code)
    if live is not None:
        start, end = live
    elif function and function != "<module>":
        # Fix plan 2026-10-23 B3: a named function that cannot be located live is NOT rendered
        # against the recorded span — those are the stale lines run 162 nearly rewrote.
        return _apply_payload(row, kind="diff", reason=fix, file=rel, replace_span=span,
                              digest=digest, selected_role=selected_role, resolved_by=how,
                              span_current=None, resolved_id=rid, given_id=given,
                              error=(f"cr_apply: `{function}` could not be located in {rel} as it stands now "
                                     f"(it does not parse, or the function is gone) — the recorded span {span} "
                                     f"is not verified live and nothing is rendered against it; read "
                                     f"cr_infractions again after the next scan"))
    span_live = f"{rel}:L{start}-L{end}"
    try:
        current = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError as e:
        return _apply_payload(row, kind="diff", reason=fix, file=rel, replace_span=span,
                              digest=digest, selected_role=selected_role,
                              replace_span_live=span_live, resolved_by=how,
                              span_current=_span_is_current(span, span_live),
                              resolved_id=rid, given_id=given,
                              error=f"cr_apply: {type(e).__name__} reading {path}: {e}")
    segment = current[start - 1: end]
    after_lines = after_code.splitlines(keepends=True)
    if segment and after_lines and segment[-1].endswith("\n") and not after_lines[-1].endswith("\n"):
        after_lines[-1] += "\n"
    # The diff is HEADED with the live span: it is the span these bytes are at.
    diff = "".join(difflib.unified_diff(segment, after_lines, fromfile=span_live, tofile=span_live,
                                        n=context_lines))
    clean, detail = _applies_cleanly(path, rel, start, end, after_lines)
    # The verdict is `applies_cleanly` (T1 absorbed the key at the session-3 transplant);
    # `error` carries only the WORDS of a refusal, so a clean render answers error=None.
    error = None if clean else f"cr_apply: the edit does not apply cleanly — {detail}"
    if clean and not diff:
        error = "cr_apply: no change — the file at this span already reads as after_code"
    # §C.1 — THE LEASE, written from the identity just handed out and the bytes just read.
    lease_path, leased = _append_lease(
        channel, _lease_record(rid, rec, span_live, "".join(segment), "".join(after_lines),
                               given_id=given))
    # I-148 (b): the prose names the decorator when the span starts at one.
    return _apply_payload(row, kind="diff", diff=diff,
                          reason=fix + _decorator_note(segment, start),
                          file=rel, replace_span=span,
                          digest=digest, selected_role=selected_role,
                          applies_cleanly=clean, replace_span_live=span_live,
                          span_current=_span_is_current(span, span_live),
                          lease=lease_path, lease_written=leased, resolved_by=how,
                          resolved_id=rid, given_id=given,
                          error=error)


# ─────────────────────────────────────────────────────────────────────────────
# cr_run_module — the target's own runner, THROUGH the wrapper (I-53 / I-55)
# ─────────────────────────────────────────────────────────────────────────────


def _interpreter() -> str:
    venv = _root() / ".venv_new" / "bin" / "python3"
    return str(venv) if venv.exists() else sys.executable


def _target_env(target: Path) -> dict[str, Any]:
    """B2 / R2 + B3 (2026-09-28): the target's PRIVATE env record (CR-built in this tree by
    `system_scripts/target_env.py` at launch) — `python` set only when usable — plus the layout.
    Never raises: an unreadable record reads as `none`, and the run degrades to the engine
    interpreter and says so (Q5)."""
    try:
        from system_scripts import target_env
        rec = target_env.read(target, tree=_root())
        rec["described"] = target_env.describe(rec)
        return rec
    except Exception as e:  # noqa: BLE001 — Q5: degrade, and say so
        return {"status": "failed", "reason": f"record unreadable: {e}", "python": None,
                "described": f"failed: record unreadable: {e}", "layout": "flat", "src_path": None}


def _tail(text: str) -> str:
    if len(text) <= TAIL_CHARS:
        return text
    return f"… [{len(text) - TAIL_CHARS} characters trimmed]\n" + text[-TAIL_CHARS:]


def _on_band(pid: int) -> bool:
    """The band's own record: `entry_point_wrapper.set_running_state` keys
    `system_scripts/running.json` by the wrapper's pid while the run is alive, and the circuit
    daemon reads it for the runner field under the graph. Seeing our pid there is seeing the
    run on the band."""
    state = _read_json(_sys_scripts() / "running.json")
    if not state:
        return False
    return str(pid) in state


def _run_payload(**over: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "exit_code": EXIT_CANNOT_RUN, "stdout": "", "stderr": "", "duration_s": 0.0,
        "module": "", "args": [], "seen_on_band": False, "timed_out": False, "error": None,
        "interpreter": "", "target_env": "", "layout": "", "target_writes": [],
    }
    payload.update(over)
    return payload


def _target_stat(root: Path) -> dict[str, tuple[int, int]]:
    """(size, mtime_ns) of every file in the COPY-FIRST snapshot's own file set
    (`snapshot_files.sh`, the set `cr_stop` compares), CodeRadar's `.coderadar/` mirrors left out."""
    try:
        listed = subprocess.run(["bash", str(_sys_scripts() / "snapshot_files.sh"), str(root)],
                                capture_output=True, text=True, timeout=120).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[str, tuple[int, int]] = {}
    for rel in listed:
        rel = rel[2:] if rel.startswith("./") else rel
        if not rel or rel.split("/", 1)[0] == ".coderadar" \
                or rel.rsplit("/", 1)[-1] in ("coderadar_dash.jsonl", "coderadar_noai.jsonl"):   # view mirrors
            continue
        try:
            st = (root / rel).stat()
        except OSError:
            continue
        out[rel] = (st.st_size, st.st_mtime_ns)
    return out


def _settle_target_writes(root: Path, before: dict[str, tuple[int, int]]) -> list[dict[str, str]]:
    """M-21 (2026-09-28): what the run itself wrote into the target, and the undo. A file the run
    CHANGED whose pre-run (size, mtime) still matched the launch snapshot (tar -p keeps mtimes) gets
    the snapshot's bytes back — `restored`. Anything else is only reported — `changed` (the client
    had edited it since launch, so the snapshot is not its pre-run state), `created`, `deleted` —
    never deleted, never guessed at. Empty when the run left the target as it found it."""
    if not before:
        return []
    from .read_tools import run_and_snapshot   # the same snapshot pick as cr_stop (lazy: read_tools imports this module)
    after = _target_stat(root)
    snap = run_and_snapshot(str(root))[1]
    snap_dir = Path(snap) if snap else None
    out: list[dict[str, str]] = []
    for rel in sorted(set(before) | set(after)):
        b, a = before.get(rel), after.get(rel)
        if b == a:
            continue
        if b is None:
            out.append({"path": rel, "status": "created"})
            continue
        if a is None:
            out.append({"path": rel, "status": "deleted"})
            continue
        src = snap_dir / rel if snap_dir else None
        try:
            ss = src.stat() if src else None
        except OSError:
            ss = None
        if src is not None and ss is not None and (ss.st_size, ss.st_mtime_ns) == b:
            try:
                shutil.copy2(src, root / rel)
                out.append({"path": rel, "status": "restored"})
                continue
            except OSError as e:
                out.append({"path": rel, "status": f"changed (restore failed: {e})"})
                continue
        out.append({"path": rel, "status": "changed"})
    return out


def cr_run_module(path: str, args: list[str] | None = None, as_module: bool | None = None,
                  timeout_s: int = 600) -> dict[str, Any]:
    """Run the target's script or runner THROUGH `entry_point_wrapper.py`, as a subprocess
    with the target as cwd, so the run shows on the band (I-53: the tracker drops a pid whose
    cwd is not under the target) and the wrapper's own rules apply (I-55: `-p
    no:cacheprovider` on a `-m pytest` run, so the runner leaves no cache in the target).
    """
    argv = list(args or [])
    target = _target_root()
    if target is None:
        return _run_payload(module=path, args=argv, error="cr_run_module: no target under watch")
    wrapper = _sys_scripts() / "entry_point_wrapper.py"
    if not wrapper.exists():
        return _run_payload(module=path, args=argv,
                            error=f"cr_run_module: no wrapper at {wrapper}")
    if as_module is None:
        as_module = not (path.endswith(".py") or (target / path).is_file())
    tenv = _target_env(target)
    # B2: the target's code runs on the env CR built for it; no usable env → the engine's
    # interpreter, and the payload says so (Q5).
    interpreter = tenv.get("python") or _interpreter()
    run_meta = {"interpreter": interpreter, "layout": tenv.get("layout") or "flat",
                "target_env": tenv["described"] if tenv.get("python")
                else f"{tenv['described']} — degraded: ran on the engine interpreter (Q5)"}
    cmd = [interpreter, str(wrapper)] + (["-m", path] if as_module else [path]) + argv
    reported = list(argv)
    if as_module and path == "pytest":            # what the wrapper itself adds (I-55, M-21)
        if "no:cacheprovider" not in reported:
            reported += ["-p", "no:cacheprovider"]
        if not any(a.startswith("addopts=") for a in reported):
            reported += ["-o", "addopts="]

    env = dict(os.environ)
    env["CODERADAR_TARGET"] = str(target)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # B3: a src layout puts <target>/src on the run's path (runner, entry proof) — CR sets it
    # for its own child; the I-134 / I-158 hand step in the launching env is retired. Q8 follow-up:
    # the env holds an installed (non-editable) copy of the target for its metadata, so the LIVE
    # import root — <target>/src, else the target root — goes on PYTHONPATH, ahead of site-packages.
    live_root = str(tenv["src_path"]) if tenv.get("layout") == "src" and tenv.get("src_path") else str(target)
    env["PYTHONPATH"] = os.pathsep.join(
        [live_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    env.pop("VIRTUAL_ENV", None)

    before = _target_stat(target)
    out_f = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    err_f = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    started = time.monotonic()
    seen = False
    timed_out = False
    try:
        proc = subprocess.Popen(cmd, cwd=str(target), env=env, stdout=out_f, stderr=err_f)
    except OSError as e:
        out_f.close(); err_f.close()
        return _run_payload(module=path, args=reported, **run_meta,
                            error=f"cr_run_module: {type(e).__name__}: {e}")
    try:
        while True:
            if proc.poll() is not None:
                break
            if not seen:
                seen = _on_band(proc.pid)
            if time.monotonic() - started > timeout_s:
                timed_out = True
                proc.kill()
                proc.wait()
                break
            time.sleep(0.05)
        duration = time.monotonic() - started
        out_f.seek(0); err_f.seek(0)
        stdout, stderr = out_f.read(), err_f.read()
    finally:
        out_f.close(); err_f.close()
    exit_code = EXIT_TIMED_OUT if timed_out else int(proc.returncode or 0)
    writes = _settle_target_writes(target, before)
    return _run_payload(
        exit_code=exit_code, stdout=_tail(stdout), stderr=_tail(stderr),
        duration_s=round(duration, 3), module=path, args=reported, seen_on_band=seen,
        timed_out=timed_out, target_writes=writes, **run_meta,
        error=f"cr_run_module: killed after {timeout_s}s" if timed_out else None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# cr_report_outcome — THE ONE WRITE of the whole surface
# ─────────────────────────────────────────────────────────────────────────────


def _outcome_payload(**over: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "written": False, "channel": "", "line": {}, "digest": "", "replace_span": "",
        "bytes_appended": 0, "ledger": "", "ledger_written": False, "ledger_record": {},
        "resolved_by": "", "resolved_id": "", "given_id": "", "lease": "",
        "error": None,
    }
    payload.update(over)
    return payload


def _drifted(row: dict[str, Any], lease: dict[str, Any]) -> str:
    """Has the row moved off the identity the lease handed out? The words of the difference,
    empty when it has not. I-138's A1: `write_dl` was `7ec8787d56` at `cr_apply` and joined on
    `65884d525a` at `cr_report_outcome`, and the ledger then recorded the wrong rules. Either
    half is enough — a re-digest or a re-rule means the row in front of us is not the one the
    seat measured."""
    said: list[str] = []
    row_digest = str(row.get("digest") or "")
    lease_digest = str(lease.get("digest") or "")
    if row_digest != lease_digest:
        said.append(f"digest {lease_digest or '—'} → {row_digest or '—'}")
    row_rules = [str(r) for r in (row.get("rule_ids") or []) if r]
    lease_rules = [str(r) for r in (lease.get("rule_ids") or []) if r]
    if row_rules != lease_rules:
        said.append(f"rule_ids {lease_rules} → {row_rules}")
    return "; ".join(said)


def cr_report_outcome(row: str, outcome: str, note: str = "",
                      tester: str = "coderadar-mcp", edit_kind: str = "") -> dict[str, Any]:
    """Append ONE Item-5 line to the return channel. The Builder polls the file every cycle,
    joins the line to the row on `digest` AND `replace_span`, and the Ranker re-decides.

    `outcome` is `confirmed` or `failed` and nothing else (the run-53 ruling) — a third word
    is refused here rather than written and counted under `summary.tester.unparsed`.
    `digest` and `replace_span` are read off the registry row at write time and are never
    taken from the caller: the right digest with the wrong span is a silent orphan.

    Q1(a), S4-3: a `confirmed` verdict ALSO appends one record to the confirmed ledger beside
    the channel, keyed by the row's pre-repair identity. Run 141's fact is why — a repair that
    works removes its own row, so the channel line the Builder polls next cycle has nothing to
    join to and every confirmation orphaned. The channel line is written exactly as before
    (the Ranker's input is unchanged); the ledger is the second, additive record, and the
    report writer counts a confirmation from either. A `failed` verdict writes NO ledger
    record: a failed row is still an infraction, still in the mirror, and still joins.

    §C.2 (session 7) — THE RESOLUTION ORDER, and the whole of I-119 / I-125 / I-138:
      (a) the LIVE ROW by exact id (`html.unescape` first, a unique `(file, function)` match
          second — §C.5);
      (b) the APPLY LEASE by exact id — used when the live row is GONE (the Builder retired it
          within one cycle, or a revert destroyed the bytes it was keyed on) OR when its digest
          / rule ids differ from the lease's (A1's rematch, I-138);
      (c) refused with `error` NAMING what was tried.
    The channel line and the ledger record are then built from the identity the seat was GIVEN
    — the lease's digest, span, rule ids and variant — never from a row that drifted underneath
    it. `resolved_by` says which answered, in the payload, so no reader has to infer it.

    I-145 / Q2 (session 10): `given_id` — the id the SEAT passed — rides in the payload, on the
    channel line and in the ledger record, beside `resolved_id`. Run 162 wrote seven good
    outcomes under ids the client had never seen; nothing was lost only because the packet put
    "report with the id you were GIVEN" in the client PROMPT. That contract lives in the server
    now. The `row → function → lease` order above is unchanged: both ids are carried, and the
    lease is matched EXACTLY on each.
    """
    if outcome not in OUTCOMES:
        return _outcome_payload(
            error=f"cr_report_outcome: outcome must be one of {list(OUTCOMES)}, not {outcome!r}")
    rec, bucket, rid, how, err = _resolve_row(row)
    given = _given_id(row)
    # The channel is published on the row and on BUILDER_STATE; a row that is GONE still leaves
    # the state's copy, which is why the lease is findable at all when the row is not.
    channel = _channel_path(rec)
    # The lease is looked up under the id that resolved AND under the id as GIVEN — and the
    # lookup itself is tolerant of a re-key (launch C). A client holding a stale id still gets
    # back the lease `cr_apply` filed for it.
    lease = _lease_lookup(channel, rid) or _lease_lookup(channel, row)
    identity: dict[str, Any] | None = None
    resolved_by = ""
    drift = ""
    if rec is not None and bucket == "repairs":
        drift = _drifted(rec, lease) if lease else ""
        if drift:
            identity, resolved_by = lease, "lease"     # (b) — the row drifted under the seat
        else:
            identity, resolved_by = rec, how           # (a) — `row` or `function`
    elif lease is not None:
        # (b) — the live row is gone (retired on a repair, I-119; or its bytes destroyed by the
        # revert of a failed edit, I-125) or it is no longer a repair row. The lease knows it.
        identity, resolved_by = lease, "lease"
    if identity is None:
        lease_file = _lease_path(channel) if channel else ""
        if rec is not None and bucket != "repairs":
            return _outcome_payload(
                resolved_id=rid, given_id=given, resolved_by=how, channel=channel, lease=lease_file,
                error=f"cr_report_outcome: row {row!r} is in `{bucket}` and carries no solution "
                      f"to report on; no apply lease under {rid!r} either")
        return _outcome_payload(
            resolved_id=rid, given_id=given, channel=channel, lease=lease_file,
            error=f"cr_report_outcome: row {row!r} — {err or bucket}; and no apply lease under "
                  f"{rid!r} in {lease_file or 'no channel published yet'} — nothing was handed "
                  "out for this id")
    # The id the identity is filed under — the lease's own `row_key` when the lease answered,
    # which is not always the id the caller passed (launch C's re-key).
    rid = str(identity.get("row_key") or "") or rid
    try:
        line = return_channel_line(identity, outcome, note, tester, given_id=given)
    except ValueError as e:
        return _outcome_payload(resolved_by=resolved_by, resolved_id=rid, given_id=given,
                                error=f"cr_report_outcome: {e}")
    if not channel:
        return _outcome_payload(digest=line.digest, replace_span=line.replace_span,
                                line=line.as_dict(), resolved_by=resolved_by, resolved_id=rid,
                                given_id=given,
                                error="cr_report_outcome: no return channel published yet")
    text = line.as_line()
    try:
        # APPEND, never rewrite: a channel shorter than the daemon's in-memory offset is
        # re-read from byte 0 and every verdict is replayed.
        with open(channel, "a", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as e:
        return _outcome_payload(channel=channel, line=line.as_dict(), digest=line.digest,
                                replace_span=line.replace_span, resolved_by=resolved_by,
                                resolved_id=rid, given_id=given,
                                error=f"cr_report_outcome: {type(e).__name__}: {e}")
    done = _outcome_payload(written=True, channel=channel, line=line.as_dict(),
                            digest=line.digest, replace_span=line.replace_span,
                            bytes_appended=len(text.encode("utf-8")),
                            resolved_by=resolved_by, resolved_id=rid, given_id=given,
                            lease=_lease_path(channel))
    # A drift is NOT an error: `error` carries refusals only (the §C.2(c) case). The drift is
    # said by `resolved_by: "lease"` — the payload's own word for "the row moved, the lease
    # answered" — and the line itself carries the pre-edit identity it was built from.
    if outcome != "confirmed":
        return done
    ledger = _ledger_path(channel)
    record = _ledger_record(identity, line, note, tester, edit_kind)
    done["ledger"] = ledger
    done["ledger_record"] = record
    try:
        # Append-only, like the channel: the LAST record per (digest, replace_span) wins, and
        # a reader that has already consumed the file reads only what is new.
        with open(ledger, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as e:
        # The channel line is already on disk and is the Ranker's input; the answer says the
        # ledger record is not, in words, rather than pretending the write was whole.
        done["error"] = f"cr_report_outcome: the channel line was written, the ledger record was not ({e})"
        return done
    done["ledger_written"] = True
    return done


# ─────────────────────────────────────────────────────────────────────────────
# The registry (T1): the server dispatches through HANDLERS, never through this module
# ─────────────────────────────────────────────────────────────────────────────

def _attempts_on(channel: str, rid: str) -> list[dict[str, Any]]:
    """Every cr_submit attempt filed for `rid` (the attempts store beside the channel); none without a channel."""
    if not channel:
        return []
    return [r for r in _read_jsonl(attempts_path(channel)) if r.get("row_key") == rid]


def _hand_edited(lease: dict[str, Any], row: dict[str, Any]) -> str:
    """Fix plan 2026-10-23 B2: have the bytes `cr_apply` handed out for this row changed since? The
    lease froze `before_sha256` of the live segment at apply time; the same segment is located now
    (by AST, the rule `_live_span` applies) and hashed again. The words of the difference, or ""
    when the segment reads exactly as it did — then the diff was shown and not applied."""
    target = _target_root()
    rel = str(lease.get("file") or row.get("file") or "")
    if target is None or not rel:
        return "the target or the row's file is unknown, so the handed-out bytes cannot be checked"
    path = target / rel
    parsed = _parse_span(str(lease.get("replace_span_live") or lease.get("replace_span") or ""))
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError as e:
        return f"{rel} cannot be read ({type(e).__name__}), so the handed-out bytes cannot be checked"
    live = _live_span(path, str(lease.get("function") or row.get("function") or ""),
                      int(lease.get("line") or row.get("line") or 0), str(row.get("before_code") or ""))
    if live is not None:
        start, end = live
    elif parsed is not None:
        _, start, end = parsed
    else:
        return f"the span cr_apply rendered against ({lease.get('replace_span_live')!r}) cannot be read back"
    segment = "".join(lines[start - 1:end])
    frozen = str(lease.get("before_sha256") or "")
    # A rewriter lease hashes the live segment (with or without its final newline); a prescribed
    # lease hashes the row's recorded `before_code`, so for it the live text is compared to that.
    if frozen in (_sha256(segment), _sha256(segment.rstrip("\n"))):
        return ""
    if str(lease.get("solution_kind") or "") == "prescribed":
        if segment.rstrip("\n") == str(row.get("before_code") or "").rstrip("\n"):
            return ""
    return (f"the bytes cr_apply handed out for this row ({lease.get('replace_span_live')}) have changed "
            f"since — the edit was applied by hand, or the file moved on")


def cr_submit(row: str, code: str, note: str = "") -> dict[str, Any]:
    """Solution gate, item 1 (owner 2026-10-08): the agent writes new attempts, CodeRadar strictly checks, filters
    and ranks them. This call only RECORDS one attempt beside the return channel; the Builder joins every attempt on
    the row as a candidate (source `agent`) next cycle. It refuses — with `error` naming why — an unknown row, empty
    or unparseable code, code that defines no function, an attempt identical to one already on the row, and a row
    already at its cap.

    THE WRITE (fix plan 2026-10-23 B1, read and confirmed): an attempt the Ranker picks runs stage 1
    (`no_aivalidator.solution_gate.stage_runs`), then stage 2 writes it into the target —
    `no_aivalidator.solution_gate_integrate.stage_integrates`, called from `BUILDER_DAEMON._stage_integrates`
    under the gate lock: the function is located LIVE by AST (B3) and spliced once; a stage-2 or stage-3
    failure restores the original bytes (`revert`). An attempt that passes every stage stays applied and
    `BUILDER_DAEMON._attempt_report` publishes it as `integrated`; the rescan then closes the row and
    `cr_stop` counts the file under `gate_writes`. So: cr_submit files, the Builder writes, the seat edits nothing.

    B2 — one row, one writer: a row whose `cr_apply` bytes were edited by hand since the diff was
    handed out is refused here (that repair is a `cr_report_outcome` matter, outside the gate)."""
    out: dict[str, Any] = {"accepted": False, "attempt": 0, "max_attempts": MAX_ATTEMPTS, "attempt_id": "",
                           "store": "", "resolved_id": "", "error": None}
    found, _bucket, rid, _by, err = _resolve_row(row)
    if found is None:
        out["error"] = err or f"cr_submit: no row {row!r}"
        return out
    out["resolved_id"] = rid
    src = textwrap.dedent(code or "").strip("\n")
    if not src.strip():
        out["error"] = "cr_submit: empty code — send the whole replacement function"
        return out
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        out["error"] = f"cr_submit: the attempt does not parse — {e.msg} (line {e.lineno})"
        return out
    if not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in tree.body):
        out["error"] = "cr_submit: the attempt defines no function — send the whole `def` through its last line"
        return out
    built = ((_builder_state() or {}).get("rows") or {}).get(rid) or {}
    before = textwrap.dedent(str(found.get("before_code") or built.get("before_code") or "")).strip("\n")
    if before and ast.dump(tree) == ast.dump(ast.parse(before)):
        out["error"] = "cr_submit: the attempt is the broken code unchanged — it repairs nothing"
        return out
    channel = _channel_path(found)
    if not channel:
        out["error"] = "cr_submit: the Builder has not published a return channel yet — nothing can be filed"
        return out
    lease = _lease_lookup(channel, rid) or _lease_lookup(channel, row)
    if lease is not None:
        edited = _hand_edited(lease, {**built, **found})
        if edited:
            out["error"] = (f"cr_submit: refused — {edited}; a row repaired by hand is reported with "
                            f"cr_report_outcome, not filed with cr_submit (one row, one writer)")
            return out
    path = attempts_path(channel)
    out["store"] = path
    attempt_id = hashlib.sha256((rid + "\n" + src).encode()).hexdigest()[:10]
    prior = [r for r in _read_jsonl(path) if r.get("row_key") == rid]
    if any(r.get("attempt_id") == attempt_id for r in prior):
        out["error"] = f"cr_submit: attempt {attempt_id} is already on this row — change the code before resubmitting"
        out["attempt_id"] = attempt_id
        return out
    if len(prior) >= MAX_ATTEMPTS:
        out["error"] = f"cr_submit: the row is at its cap of {MAX_ATTEMPTS} attempts — it is held for the owner"
        out["attempt"] = len(prior)
        return out
    record = {"row_key": rid, "attempt": len(prior) + 1, "attempt_id": attempt_id, "code": src,
              "note": note or "", "digest": found.get("digest", ""), "replace_span": found.get("replace_span", ""),
              "rule_ids": list(found.get("rule_ids") or []), "submitted_at": datetime.now(timezone.utc).isoformat(),
              "seat": "coderadar-mcp"}
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as e:
        out["error"] = f"cr_submit: could not append to {path}: {e}"
        return out
    out.update(accepted=True, attempt=record["attempt"], attempt_id=attempt_id)
    return out


def _read_jsonl(path: str) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for raw in text.splitlines():
        try:
            doc = json.loads(raw)
        except ValueError:
            continue
        if isinstance(doc, dict):
            rows.append(doc)
    return rows


register_handler("cr_apply", cr_apply)
register_handler("cr_submit", cr_submit)
register_handler("cr_run_module", cr_run_module)
register_handler("cr_report_outcome", cr_report_outcome)
