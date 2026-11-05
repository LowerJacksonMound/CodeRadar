# RUN 149 — marathon

- item: `REWRITER_GATE_PACKET_2026-09-17.md` §C row **S5-5** — the MERGED proof: G0 (S5-1) + lanes A/B/C
  (FIX_56…62) transplanted into the original, run against T6's OWN edited target
- target: a fresh copy of `/Users/dev/Desktop/between_the_wheels` as it stands after S5-0's back-out —
  43 CORRECT rewrites + 20 rendered shapes applied, the twelve WRONG rows restored to their before-bytes.
  Copied first (`snapshot.md5`, 78 files), never launched on in place. **Left standing** at
  `/Users/dev/Desktop/marathon` for a hand check of the 11.
- name from the head of the original's own reserve (7 → 6); pool line 98 marked used at `cr_stop`
- launched 15:55 UTC · **MONITORING, 5 gates PASS**, gate budget 2318 s · repo_id `d4da70e9348f` · dash :8080
- driver: `obs_run149.py`, ONE TIGHT LOOP (handlers in-process, as runs 144–148):
  `cr_watch` → `cr_status` → `cr_infractions` → `cr_row` ×12 → `cr_apply` ×8 → the client edits →
  `cr_run_module`(suite, entry) → `cr_wiring` → `cr_report_outcome` ×8 → one Builder cycle →
  `cr_status` → `cr_stop(expected_changes)` → `cr_hand_back`

**The claim this run proves:** with G0 and the seven fixes, every one of T6's twelve WRONG repairs is now
either not offered, withheld with a reason, or replaced by a behaviour-preserving repair that the target's
own suite accepts.

## The twelve, as seen — 12 of 12 as expected

Run 141's row ids carry run 141's LINE NUMBERS; in this tree every function below a repaired span has moved,
so the twelve are located by FILE + FUNCTION (which is how the owner's ruling names them) and the line is
whatever this tree says. Three of the twelve sit at a new line: #30 ::26→::24, #53 ::24→::23, #70 ::23→::20,
#71 ::33→::30.

| # | row | expected | as seen | applied |
|---|---|---|---|---|
| 21 | `ansi.py::set_title` | no row | **no row** — `colorama/ansi.py` holds 0 rows; FIX_59 stopped the detector filing it | — |
| 30 | `repair_plant_branches.py::stamp::24` | `keep_second` | `immediate_overwrite_fix:keep_second` (2 offered, no `keep_first`) | ✓ |
| 33 | `repair_plant_chains.py::stamp::21` | `keep_second` | `immediate_overwrite_fix:keep_second` (1 offered) | ✓ |
| 35 | `repair_plant_checks.py::push::12` | withheld, no candidates | **`candidates_considered: 0`, `no_fix_status: declined`** — "param_mutation_fix found nothing to rewrite" | — |
| 53 | `repair_plant_noop.py::tally::23` | `algebraic_identity_fix`, statement deleted | `algebraic_identity_fix`, `total = total + 0` **deleted** | ✓ |
| 57 | `repair_plant_quietly.py::hushed::9` | withheld by design, with the sentence | `withheld_by: gate`, `ranker_none`, *"gate: withheld: no-fix-by-design — NAI-017: …"* | — |
| 61 | `repair_plant_shape.py::pick_label::5` | `body_once` | `identical_branches_fix:body_once` (1 offered; the raise never minted) | ✓ |
| 70 | `repair_plant_typos.py::code_word::20` | `merge_conditions` | `repetitive_branches_fix:merge_conditions` (1 offered) | ✓ |
| 71 | `repair_plant_typos.py::mark_twice::30` | prescribed | `solution_NAI-054`, `kind: prescribed`; the NAI-091 candidate absent | — (shape undetermined) |
| 73 | `win32.py::GetConsoleScreenBufferInfo::118` | `keep_call_effect` | `dead_local_fix:keep_call_effect` (4 offered, `drop_assignment` never minted) | ✓ |
| 74 | `win32.py::FillConsoleOutputCharacter::147` | `keep_call_effect` | `dead_local_fix:keep_call_effect` | ✓ |
| 75 | `winterm.py::enable_vt_processing::178` | `log_and_return` | `fallback_return_fix:log_and_return` | ✓ |

Two dispositions worth naming. **#35 reads `declined`, not `withheld (gate)`** — FIX_58 put the owner's three
conditions at the SOURCE, so `push` never reaches the gate at all; the row leaves the withheld block for
`no_vetted_fix`. That is the fix working, not the gate failing. **#71 was NOT applied**: its prescription is a
shape with two readings — `<statement>   # once` OR `for _ in range(<n>): <statement>` — and which one is
right is the client's call, not a rendering the client can read off the function. Skipped, and said so; the
shape lane is where it belongs.

On #73 / #74 the one gate-withheld candidate left is `dead_store_fix:drop_store` (NAI-031, G0's generic
check, still un-narrowed at the source — pinned as FIX_63's neighbour), and the gate's sentence rides in
`decision.why` beside the pick.

## The client pass — 8 rows, 7 files

`cr_apply` on all eight: `kind=diff`, **`applies_cleanly: true` 8 of 8**. Applied per file in descending span
order. Every edit is behaviour-preserving by inspection: the dead FIRST write goes and the live `width = 8`
survives (#30 #33); `total = total + 0` is deleted, not shipped as `total = total` (#53); identical arms
collapse (#61) and duplicate arms merge into one condition (#70); the Win32 call **stays** and only the unread
`success` name goes (#73 #74); the `return False` fallback is untouched and a DEBUG log is added beside it
(#75). Full before → after: `client_edit_log_run149.json`.

## Run the entry, run the suite

```
cr_run_module  pytest colorama/tests -q   exit 0 in 0.707 s   38 passed, 14 skipped   files_added none
cr_run_module  demos/demo01.py            exit 0 in 0.062 s   2506 bytes of ANSI      files_added none
cr_wiring      64 nodes · 29 edges · {possible 29}   — as on runs 135-140, 148; `live` still unseen
```
The suite is **unmoved from the baseline** (38 passed / 14 skipped, exit 0, measured on the copy before the
launch) — which is the whole claim: eight repairs, and the target's own tests cannot tell.

## Outcomes, teardown, hand-back

`cr_report_outcome(confirmed)` **8 of 8 `written: true`**, inside the same tight loop (run 141's phase-3
finding: a repaired function stops being an infraction, and an outcome can only be taken for a row the mirror
still publishes). One Builder cycle later:

```
cr_status  cycle 3 · finished false (mirror)
  finished_inputs {counterfeit_failed 96, mypy_errors 574, severed_links 0}
  counterfeit_failed 104 → 96 (−8, exactly the eight applied) · repairs 94 → 86 · no_vetted_fix 10
  withheld 84 = 83 species + 1 gate  (the one gate row is #57 `hushed`, the row meant to stay)
cr_stop   stopped true · residue_clean true · byte_identical FALSE (explained) · files_compared 78
          client_edits 7 · unexpected_changes [] · 4 daemons exit 0 (SIGTERM)
cr_hand_back  MEASURED · builder_cycles 3 · infractions 96 · solutions 86
          confirmed 9 · confirmed_from_ledger 9 · orphans 0 · unparsed 0 · return_channel_lines 8
```

**`confirmed_from_ledger` is 9, not 8**, and the ninth is accounted for: an earlier pass at run 149 let two
Builder cycles fall between the edits and the outcomes, 7 of 8 rows were already off the mirror by then, and
only #61 took its verdict. That pass was torn down clean (`residue_clean true, client_edits 7,
unexpected_changes []`) and its whole record is kept at `first_pass_not_tight/`; the ledger is keyed by
`repo_id` and the target path is the same, so its one line (digest `e4bbf00d0c`, span L5-L7 — the ALREADY
repaired 3-line `pick_label`) survives beside run 149's eight. Nothing was removed from the ledger.
`confirmed_joined` is 0 and `orphans_channel` 8 because all eight repaired rows had LEFT the final mirror —
the rules they answered are silent, which is what a repair is for.

## Identity — the teardown's difference set IS the edit log

`identity_proof.json`: **78 files before and after**, none added, none removed; **7 changed**, and the changed
set is EXACTLY the client's edit manifest. Every logged `after` is present verbatim in the final tree; all 7
files `ast.parse` clean; the suite run plainly from the standing target is 38 passed / 14 skipped, exit 0.
`teardown_diff.txt` is the same 7 files and nothing else. Zero mirror files left in the target.
