# RUN 141 — between_the_wheels

- item: `RELEASE_FORM_MCP_PACKET_2026-09-17.md` §C row **T5** — THE END-TO-END PROOF, Claude Code as the MCP client
- target: /Users/dev/Desktop/between_the_wheels (a fresh `limbo` copy — 77 files, 69 .py) — **LEFT STANDING for T6**
- snapshot: /Users/dev/CodeRadar_snapshots/between_the_wheels_20260917_062701
- launched: 06:27:01  gates: 5 PASS (ALL GATES PASSED, budget 2328 s) · repo_id a32f4c124796 · dashboard :8080 · health :8051
- teardown: `RESIDUE CHECK: zero CodeRadar mirror files remain in target` · 4 daemons exit 0 (SIGTERM)
- **byte-identity, Q3 form:** `byte_identical false` BY DESIGN — the client edited the target. 77 files both
  sides, 0 added, 0 removed, **35 changed = exactly the client's manifest**; `cr_stop` reported
  `residue_clean true · client_edits 35 · unexpected_changes []`. Proof: `identity_proof.txt` (exit 0).
- state during run: `.archive/runs/between_the_wheels/state_during_run/`
- health at launch: the launch's own report in `.archive/health/`
- run of record for the client loop; run 142 `the_big_money` is the re-measure on the edited target.

## What run 141 is
The first run in which **something was applied to a target**. The client is Claude Code, speaking the real
stdio MCP protocol to `coderadar-mcp --target /Users/dev/Desktop/between_the_wheels` with the SDK's own
`ClientSession`. Under Q3 the server rendered every edit and wrote none of them; the client decided what to
apply, rendered every prescription's `<placeholders>` itself, and wrote the bytes.

Driver, in five phases (the stack stayed up across all five — `cr_watch` spawns the gearbox with
`start_new_session=True`, so each phase is a fresh client session against the same running stack):

| phase | script | what |
|---|---|---|
| 1 | `obs_run141_phase1.py` | `cr_watch` · `cr_status` · `cr_infractions` ×4 pages · `cr_wiring` · `cr_data_types` · `cr_intent` · the BASELINE runner · `cr_apply` over all 156 rows with a solution |
| 2 | `obs_run141_phase2.py` | the first apply pass measured; **the sequencing lesson** (below) |
| 3 | `obs_run141_phase3.py` | the TIGHT loop: `cr_apply` → edit → `cr_run_module` → `cr_report_outcome`, one session |
| 4 | `obs_run141_phase4.py` | the Builder takes the channel: `finished_inputs` per cycle, `cr_row` ×5 |
| 5 | `obs_run141_phase5.py` | `cr_stop` with the client's manifest, then `cr_hand_back` |

## The read pass (cycle 1)
```
cr_watch   started true · MONITORING · repo_id a32f4c124796 · gate_budget_s 2328
           circuit READY/RUNNING PASS 1.5s · circuit WIRING PASS · NOAI MONITORING PASS 5.6s ·
           CHEATSHEETS MONITORING PASS 1.0s · dashboard HTTP 200 PASS 0.0s
cr_status  finished false · finished_source "mirror" · "not finished: counterfeit_failed=164, mypy_errors=586"
           finished_inputs {counterfeit_failed 164, mypy_errors 586, severed_links 0}
           infractions {total_functions 355, passed 108, failed 164, files_scanned 64,
                        repairs 156, no_vetted_fix 8, whitelisted 0, withheld 83}
cr_infractions  164 rows over 4 pages of 50, paged by file, no file split
cr_wiring  64 nodes · 29 edges · {possible 29, live 0, severed 0} · all_connected true · 0 severed
cr_data_types  chosen [io, mypy] · not_run [crc, vulture] · 586 issues · contract_violations disabled
cr_intent  7 facts {changelog 3, packaging 2, readme 2} · statement null
cr_apply   over ALL 156 rows with a solution in 0.6 s → 57 diff (applies_cleanly TRUE on 57 of 57),
           99 shape (applies_cleanly null, as T3's absorption fixed it)
cr_run_module (BASELINE)  -m pytest colorama/tests -q → exit 0 in 0.843 s · 38 passed, 14 skipped ·
           args [... -p no:cacheprovider] (I-55) · seen_on_band true
```

## What the client applied
**75 rows standing over 35 files — 55 rewriter diffs + 20 prescriptions the client rendered.**
Two more were applied and **backed out** (below), so 77 rows were written in all.
Machine-readable: `client_edit_log.json` (row, file, span, rule_ids, kind, role, digest, the row's `fix`,
before, after, rendering rationale, outcome, reverted), manifest `client_edit_manifest.txt`,
renderings `client_renderings.json`, the applier `client_apply.py`.
Applied per file in DESCENDING span order so no earlier span drifts under a later edit; every edited file
re-parsed with `ast.parse` (0 syntax errors).

**The two rows the client BACKED OUT.** `colorama/ansitowin32.py::isatty::49` and `::closed::62`, both
`fallback_return_fix`, turned a documented fallback into a raise and broke the target's own tests
(`3 failed, 35 passed, 14 skipped`): `isatty_test.py::test_withPycharmNoneOverride` expects `False` and got
`RuntimeError('isatty failed')`; `ansitowin32_test.py::test_closed_shouldnt_raise_on_detached_stream` and
`::test_wrap_shouldnt_raise_on_missing_closed_attr` expect the fallback to answer and got an AttributeError.
The client restored the file from the COPY-FIRST snapshot, re-ran the runner green, and reported both rows
`failed` with the assertion. **This is the tester seat working** (Q4 / B7-3): a vetted rewriter that the
target's own tests refuse.

## The runner, before and after
```
BEFORE  -m pytest colorama/tests -q → exit 0 · 0.843 s · 38 passed, 14 skipped · seen_on_band true
AFTER   -m pytest colorama/tests -q → exit 0 · 0.831 s · 38 passed, 14 skipped · seen_on_band true
(between them: exit 1, 3 failed — the two ansitowin32 rows, backed out)
```

## The outcomes and the re-decide
14 lines on `system_scripts/return_channel_a32f4c124796.jsonl`; 0 refused. 7 `confirmed`, 7 `failed`.
`cr_hand_back` at teardown: `builder_cycles 6 · infractions 98 · solutions 88 · confirmed 0 ·
confirmed_fraction 0.0 · tester_ran true · status MEASURED · return_channel_lines 14 · orphans 7 ·
unparsed 0 · per_infraction 98 · finished false`.

**The re-decide, on the two `failed` rows** (`phase4_redecide.json`):
```
colorama/ansitowin32.py::isatty::49   tester {"confirmed": false} ·
  decision.why "tester failed 8cab17f075: run 141: applied, then BACKED OUT by the client. The target's
  own runner failed — isatty_test.py::IsattyTest::test_withPycharmNoneOverride: RuntimeError('isatty
  failed') where the test asserts False…; picked …"
  role fallback_return_fix:raise_named → fallback_return_fix:re_raise, digest 8cab17f075 → 2891d4b3a3
colorama/ansitowin32.py::closed::62   the same, roles the other way round, 3ba74f0b6d → 2ad90aa8f1
```
The Ranker took the verdict, wrote it into `decision.why`, and picked the OTHER variant of the same finite
set (I-80's tie) — the honest re-decide, not `ranker_none`, because a second candidate was pickable.

**The three `confirmed` rows read back `found: false`** — the repair cleared the infraction and the row left
the mirror. See the finding below.

## `finished_inputs`, cycle by cycle
| cycle | counterfeit_failed | mypy_errors | severed_links | rows |
|---|---|---|---|---|
| 1 (before the edits) | **164** | 586 | 0 | repairs 156 · no_fix 8 · withheld 83 |
| 3 (one Builder cycle after pass 1) | **103** | 577 | 0 | repairs 93 · no_fix 10 · withheld 83 |
| 6 (at teardown) | **98** | 574 | 0 | repairs 88 · no_fix 10 · withheld 83 |

`counterfeit_failed` **dropped 164 → 98 inside the run, 66 fewer, the first 61 within ONE Builder cycle of
the first apply pass** — CodeRadar re-polled the edited files on its own cadence, with no prompting from the
client. `severed_links` stayed 0; `mypy_errors` fell 586 → 574. `finished` stayed false, as it must: two of
the three gates are still non-zero.

## THE FINDING — a `confirmed` verdict cannot join (for the owner)
`cr_report_outcome` takes `digest` + `replace_span` off the LIVE row and the Builder joins on BOTH (T3, by
design — the right digest with a wrong span is a silent orphan). But **a repair that works removes its own
row**: by the time the Builder polls the channel it has re-scanned the file, the function passes, and there
is no row at that digest+span any more. All 7 `confirmed` lines became orphans; all 7 `failed` lines joined
(a failed row is still an infraction, so it is still there). `summary.tester` at teardown:
`{confirmed 0, solutions 88, orphans 7, unparsed 0, channel_lines 14}`.

Runs 138 and 140 saw `confirmed` join **because they applied nothing to the target** — the row stayed put.
Under Q3, where the client edits in place, that no longer holds. This is not a sequencing mistake the client
can avoid by reporting faster (phase 3 reported inside the same second as the runner and still orphaned):
the join key is destroyed by the very repair it is meant to confirm. **B9's per-rule accumulation of tester
outcomes has no `confirmed` to accumulate under Q3** unless the join gains a third form — the row's identity
before the edit, or a channel line the Builder matches against the PREVIOUS cycle's mirror. The owner's call.

Phase 2 also recorded the weaker, real form of the same thing: the client let two Builder cycles pass between
the edits and the outcomes, and **65 of 70 rows were already gone by id** (`file::function::line` — the line
moves under an edit above it). Report inside the cycle, as phase 3 did.

## Teardown
```
cr_stop(verify_identity=true, mark_pool=false, expected_changes=[35 paths])
  stopped true · residue_clean true · byte_identical FALSE · files_compared 77
  client_edits 35 · unexpected_changes []
  circuit_daemon 18230 exit 0 · noai_validator 18239 exit 0 · cheatsheets 18240 exit 0 · dashboard 18241 exit 0
cr_hand_back (AFTER cr_stop — T4 decision 3 / defect (b))  → tester_report.json, 98 per_infraction rows
```
`expected_changes` / `client_edits` / `unexpected_changes` are NEW on `cr_stop` this run — the smallest
change that lets the teardown report the Q3 guarantee honestly instead of a bare `byte_identical: false`.
`session_tools.py` + the three `Field`s in `tool_interface.py`; `mcp_interface_proof.py` re-run: **PASS, exit 0**.

## Files in this run directory
`obs_run141_phase{1,2,3,4,5}.{py,txt}` · `obs_run142.py` (run 142's driver) · `client_apply.py` ·
`client_renderings.json` · `client_edit_log.json` · `client_edit_manifest.txt` · `identity_proof.py|txt|json` ·
`make_hand_check.py` · `phase1_*.json` · `phase2_*.json` · `phase3_*.json` · `phase4_*.json` ·
`phase5_*.json` · `launch.log` · `teardown_{snapshot,target}.md5` · `teardown_diff.txt` · `tester_report.json`

The owner's hand-check list: `BUILD_PLANS_FIXES_2026-09-08/HAND_CHECK_T5_LIST_2026-09-17.md` (77 entries —
Part A the 20 rendered prescriptions, Part B the 55 diffs, Part C the 2 backed out).
