"""repair_generators — ONE registry row per deciding rule id (NEW IMPLEMENTATION item 4, 2026-09-08).

Every rule id the disposition table marks `deciding` (system_scripts/rule_dispositions.json)
has exactly one `Generator` row here, of one of three kinds:

    rewriter          a correct-by-construction AST rewrite of the exact construct the rule
                      observed: fn(broken_code) -> (after_code, what_changed), ("", "") to
                      decline. what_changed is derived from the code it rewrote — never canned.
                      FIX_61 (a): such a row may also carry `no_fix_by_design=<reason>` — the rule
                      admits no UNATTENDED repair, so the candidates are still built and offered
                      (shapes for the client) and G0 withholds every one with that reason.
    no_fix_by_design  the rule's `meaning` admits no mechanical rewrite; `reason` says why.
                      Since FIX_41 (owner ruling 2026-09-15) permitted ONLY for a finite-set row
                      ("which one's right": ≥ 2 concrete candidates, FIX_43 makes them a
                      multi-candidate rewriter and the Ranker decides) — listed by id in
                      system_scripts/solution_kinds_pending.json; step 19 fails any other.
    prescribed        no finite candidate set (a body / value / name / policy must be written):
                      the ONE best solution in the owner's words for that rule, keyed to the
                      dev's derived intent — `reason` = the text (what to write in place of the
                      counterfeit code, ≤ 2 sentences), `shape` = the replacement template. The
                      Builder publishes it on the row as the Ranker's single candidate (fix =
                      text, after_code = shape, digest over before + text); the dash and both
                      mirrors show it as the row's solution. FIX_41, 2026-09-15.
    unbuilt           no generator written yet — the honest placeholder, never a silent zero.

One module per emitting family (the catalogue's `where` column): safety, core, redundancy,
hallucination, advanced, strict, structural, math_family, style, semantic, extended_semantic,
file_level, validator_emitted, code_analysis. The Builder (BUILDER_DAEMON._generate) asks
`for_rule(rule_id)`; health-check step 19 (system_scripts/generator_check.py) proves that
every deciding id has a row and runs every rewriter against its planted counterfeit
(system_scripts/generator_plants/<rule_id>.py): parse, differs, what non-empty, and the
rule's own detector goes quiet on the rewrite (the meaning check).

A rule id whose mechanical repair IS another rule's proven rewriter is an ALIAS row: same role, the
same function object (set 4b-05: SEC-004 → NAI-093, SEC-005 → NAI-092); `_collect` refuses a
shared role with a different function.

Owner ruling 2026-09-08 (first batch): 3 new rewriters (NAI-008, NAI-070, NAI-061) + 9
declared no-fix-by-design (NAI-078, 021S, 076, 050, 055, 015, 004, 044, 094), reversible rule
by rule when a mechanical form is found. The three pre-existing rewriters (NAI-071, 092, 093)
moved here from cheatsheet_intelligence/knowledge_base.py. Everything else starts `unbuilt`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

Kind = Literal["rewriter", "no_fix_by_design", "prescribed", "unbuilt"]
KINDS: Tuple[str, ...] = ("rewriter", "no_fix_by_design", "prescribed", "unbuilt")
FIRST_BATCH_DATED = "2026-09-08"
FIRST_BATCH_BY = "item 4 first batch (owner ruling 2026-09-08)"
PRESCRIBED_DATED = "2026-09-15"
PRESCRIBED_BY = "FIX_41 (owner ruling 2026-09-15)"


@dataclass(frozen=True)
class Generator:
    rule_id: str
    kind: Kind
    role: Optional[str]                                   # the candidate role the Ranker sees (rewriters only)
    fn: Optional[Callable[[str], Any]]                    # fn(broken_code) -> (after_code, what_changed) | ("", "")
                                                          # FIX_43 (b) finite set: -> [(variant, after_code, what_changed), ...]
                                                          #   every candidate is offered, the Ranker decides; [] = declined
    reason: str                                           # rewriter: what makes it correct by construction + preconditions
                                                          # no_fix_by_design: why the meaning admits no mechanical rewrite
                                                          # unbuilt: the placeholder text
    meaning_source: str                                   # detector function the rule's meaning is read from
    dated: str
    by: str
    shape: str = ""                                       # prescribed: the replacement shape (a short code template in
                                                          # the rule's own terms; "" when the prescription is prose only)
    no_fix_by_design: str = ""                            # FIX_61 (a) (owner Part C, 2026-09-17): a REWRITER row whose
                                                          # rule admits no unattended mechanical repair — the reason,
                                                          # and the flag (empty = not declared). The candidates are
                                                          # still built and still offered (they are shapes for the
                                                          # client), but G0 withholds every one of them through
                                                          # `gate.no_fix_by_design(rule_id, reason)`, so the row
                                                          # publishes withheld-by-design instead of a repair. Before
                                                          # FIX_61 this was prose only (a module docstring and a
                                                          # manifest's free-text `what`), read by nothing.
    shape_for: Optional[Callable[[str, str], Tuple[str, str]]] = None
                                                          # R4 (owner ruling 2026-09-21, run 164): a PRESCRIBED row whose
                                                          # DETECTOR covers more than one family of counterfeit code
                                                          # resolves (text, shape) from the FIRE ITSELF —
                                                          # `shape_for(broken_code, failure_reason)` -> (text, shape) —
                                                          # so an `os.environ` fire is never handed a `sys.path`
                                                          # rewrite (session 8's T1 finding on NAI-094, click
                                                          # `testing.py:574`). It is NOT a rewriter `fn`: it reads the
                                                          # fire's own words and picks between the rule's prescriptions,
                                                          # it never produces after-code for a row and
                                                          # `candidates_of` still offers nothing for a prescribed row.
                                                          # None = the one text / shape above serves every fire.

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"{self.rule_id}: kind {self.kind!r} not in {KINDS}")
        if self.kind == "rewriter" and (self.fn is None or not self.role):
            raise ValueError(f"{self.rule_id}: a rewriter needs fn and role")
        if self.kind != "rewriter" and (self.fn is not None or self.role):
            raise ValueError(f"{self.rule_id}: only a rewriter carries fn / role")
        if self.kind == "no_fix_by_design" and not self.reason.strip():
            raise ValueError(f"{self.rule_id}: no_fix_by_design requires a non-empty reason")
        if self.kind == "prescribed" and not self.reason.strip():
            raise ValueError(f"{self.rule_id}: prescribed requires a non-empty text")
        if self.kind != "prescribed" and self.shape:
            raise ValueError(f"{self.rule_id}: only a prescribed row carries a shape")
        if self.no_fix_by_design and self.kind != "rewriter":
            raise ValueError(f"{self.rule_id}: the no_fix_by_design flag is a rewriter row's — kind "
                             f"{self.kind!r} already says it in its own word")
        if self.shape_for is not None and self.kind != "prescribed":
            raise ValueError(f"{self.rule_id}: shape_for is a prescribed row's — kind {self.kind!r} "
                             f"has no text / shape to resolve")


def unbuilt(rule_id: str, meaning_source: str) -> Generator:
    """The honest placeholder: publishes as status=unbuilt with this reason in decision.why."""
    return Generator(rule_id, "unbuilt", None, None,
                     reason="no generator written yet — worked family by family after the first batch",
                     meaning_source=meaning_source, dated=FIRST_BATCH_DATED, by=FIRST_BATCH_BY)


def no_fix(rule_id: str, meaning_source: str, reason: str) -> Generator:
    return Generator(rule_id, "no_fix_by_design", None, None, reason=reason,
                     meaning_source=meaning_source, dated=FIRST_BATCH_DATED, by=FIRST_BATCH_BY)


def prescribed(rule_id: str, meaning_source: str, text: str, shape: str,
               dated: str = PRESCRIBED_DATED, by: str = PRESCRIBED_BY,
               shape_for: Optional[Callable[[str, str], Tuple[str, str]]] = None) -> Generator:
    """FIX_41: the one best solution in the owner's words for a rule with no finite candidate set —
    `text` = what to write in place of the counterfeit code, keyed to the dev's intent (≤ 2 sentences);
    `shape` = the replacement template ("" for prose only). Published by the Builder as the row's
    single candidate; asserted by step 19.

    R4 (2026-09-21): `shape_for` = the per-family resolver for a rule whose detector covers more
    than one family (NAI-094: `sys.path` and `os.environ`). `text` / `shape` stay the row's
    DEFAULT — what a fire whose family cannot be read off its own words still gets."""
    return Generator(rule_id, "prescribed", None, None, reason=text, meaning_source=meaning_source,
                     dated=dated, by=by, shape=shape, shape_for=shape_for)


def rewriter(rule_id: str, meaning_source: str, role: str, fn: Callable[[str], Any],
             reason: str, dated: str = FIRST_BATCH_DATED, by: str = FIRST_BATCH_BY,
             no_fix_by_design: str = "") -> Generator:
    # FIX_54 (2026-09-17): `fn` was annotated `Callable[[str], Tuple[str, str]]`, the single-candidate
    # shape. FIX_43 (b) added the finite-set shape — a LIST of (variant, after_code, what_changed) —
    # and `candidates_of` (below) is the ONE reader of both. The annotation is widened to match the
    # field it is stored in (`Generator.fn: Optional[Callable[[str], Any]]`); `candidates_of` does the
    # narrowing, exactly once, as FIX_43 (b) designed.
    return Generator(rule_id, "rewriter", role, fn, reason=reason, meaning_source=meaning_source, dated=dated, by=by,
                     no_fix_by_design=no_fix_by_design)


def _collect() -> Dict[str, Generator]:
    from . import (advanced, code_analysis, core, extended_semantic, file_level, hallucination,
                   math_family, redundancy, safety, semantic, strict, structural, style, validator_emitted)
    reg: Dict[str, Generator] = {}
    roles: Dict[str, str] = {}
    for mod in (safety, core, redundancy, hallucination, advanced, strict, structural, math_family, style,
                semantic, extended_semantic, file_level, validator_emitted, code_analysis):
        for g in mod.GENERATORS:
            if g.rule_id in reg:
                raise ValueError(f"{g.rule_id}: two registry rows ({reg[g.rule_id].by!r} and {g.by!r})")
            if g.kind == "rewriter":
                # One role per mechanical rewrite. A second rule id may share a role ONLY as an alias
                # of the same function object (set 4b-05: SEC-004 = NAI-093's yaml_safe_load_fix,
                # SEC-005 = NAI-092's subprocess_argv_fix — the regex-scan id names the same repair);
                # the Builder dedupes by role, so an infraction carrying both ids sees ONE candidate.
                if g.role in roles and reg[roles[g.role]].fn is not g.fn:
                    raise ValueError(f"role {g.role!r} used by {roles[g.role]} and {g.rule_id} with different functions")
                roles.setdefault(g.role, g.rule_id)  # type: ignore[arg-type]
            reg[g.rule_id] = g
    return reg


REGISTRY: Dict[str, Generator] = _collect()


class Offer(Tuple[str, str, str]):
    """FIX_43 (b)'s `(role, after_code, what_changed)` — plus G0's verdict, carried WITH the candidate
    (S5-1, 2026-09-17). It IS that 3-tuple: every existing reader unpacks it unchanged. A reader that
    knows about the gate reads `withheld_by` ("gate" or ""), `gate_reason` (the sentence) and
    `gate_rule` (the check that spoke) off it. A withheld candidate is never dropped here — the row
    keeps it, the Ranker refuses to pick it (`gate=withheld:` is an unpickable observation), and the
    reason rides into `decision.why` and the mirror's withheld block."""

    withheld_by: str     # "gate" when G0 withheld this candidate, "" otherwise
    gate_reason: str     # the gate's sentence, as it reaches decision.why and the mirror
    gate_rule: str       # the check (or `predicate:<rule>:<variant>`) that spoke

    def __new__(cls, role: str, after: str, what: str,
                withheld_by: str = "", gate_reason: str = "", gate_rule: str = "") -> "Offer":
        self = super().__new__(cls, (role, after, what))
        self.withheld_by = withheld_by
        self.gate_reason = gate_reason
        self.gate_rule = gate_rule
        return self


def candidates_of(g: Generator, broken_code: str, *, file: str = "", span: str = "",
                  module_src: str = "") -> List[Tuple[str, str, str]]:
    """FIX_43 (b) (owner rulings 2026-09-15/16): the ONE reading of a rewriter's return, shared by the Builder's
    consult and by health-check step 19. A single-candidate rewriter returns (after_code, what_changed) — "" declines;
    a finite-set rewriter returns a list of (variant, after_code, what_changed) — every candidate is offered under the
    role `<role>:<variant>` and the Ranker decides between them (nothing here ranks, nothing is unpickable).

    S5-1 (2026-09-17): this is also the ONE publish choke point, so **G0 runs here** — every candidate is
    shown to `gate.check` before it is offered (packet §B, the owner's gate sentence). Nothing is filtered:
    a candidate that fails the gate is offered as an `Offer` carrying `withheld_by="gate"` and the gate's
    sentence. `file` / `span` / `module_src` are the rewrite's context (imports, the span it came from);
    all optional, so a caller that has none — health-check step 19 — sees exactly what it saw before."""
    from .gate import Rewrite, check as gate_check, eager_closure   # local: the gate imports nothing from the registry
    from .core import module_evidence                # FIX_65: the module as purity evidence, set here only
    with module_evidence(module_src):
        out = g.fn(broken_code) if g.fn is not None else ("", "")
    raw: List[Tuple[str, str, str]] = ([(f"{g.role}:{variant}", after, what) for variant, after, what in out if after]
                                       if isinstance(out, list)
                                       else ([(g.role or "", out[0], out[1])] if out[0] else []))
    # S7-T2 (I-126, packet Q3): the ONE target-wide fact a span cannot carry — which of the target's
    # modules run at import time. Asked here, at the one choke point, because here is where the file
    # is known; `eager_closure` computes it ONCE per Builder cycle and answers from its cache after
    # that, so a row-by-row consult costs one dict lookup. None = NOT MEASURED, and the predicate
    # that reads it withholds nothing. Never raises: the gate is never the reason a repair is lost.
    try:
        eager = eager_closure() if raw else None
    except Exception:
        eager = None
    offers: List[Tuple[str, str, str]] = []
    for role, after, what in raw:
        variant = role.split(":", 1)[1] if ":" in role else ""
        verdict = gate_check(Rewrite(rule_id=g.rule_id, role=g.role or "", variant=variant, file=file,
                                     span=span, before_src=broken_code, after_src=after,
                                     module_src=module_src, eager=eager))
        offers.append(Offer(role, after, what) if verdict.ok else
                      Offer(role, after, what, withheld_by="gate",
                            gate_reason=verdict.reason or "", gate_rule=verdict.rule))
    return offers


def gate_note(offer: Tuple[str, str, str]) -> Tuple[str, str]:
    """(check, reason) when G0 withheld this candidate, ("", "") otherwise — the ONE way a caller asks."""
    return (getattr(offer, "gate_rule", "") or "", getattr(offer, "gate_reason", "") or "")


def for_rule(rule_id: str) -> Optional[Generator]:
    """The one row for a rule id, or None (no row — step 19 fails the gate for a deciding id)."""
    return REGISTRY.get(rule_id)


def rewriters() -> List[Generator]:
    return [g for g in REGISTRY.values() if g.kind == "rewriter"]


def prescribed_rows() -> List[Generator]:
    return [g for g in REGISTRY.values() if g.kind == "prescribed"]


def counts_by_kind() -> Dict[str, int]:
    return {k: sum(1 for g in REGISTRY.values() if g.kind == k) for k in KINDS}


__all__ = ["Generator", "Kind", "KINDS", "REGISTRY", "for_rule", "rewriters", "prescribed_rows", "counts_by_kind",
           "unbuilt", "no_fix", "rewriter", "prescribed"]
