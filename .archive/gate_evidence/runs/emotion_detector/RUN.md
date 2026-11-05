# RUN 153 — emotion_detector

- item: **T2 — B9's accumulation** (`RELEASE_MOUNT_B9_SHAKEDOWN_PACKET_2026-09-20` §C row T2; ruling
  **Q3** of §A, taken as proposed): `summary.rule_outcomes` in the counterfeit-code mirror, read by
  `cr_status`, carried by the tester report. The step-18 REPORT → FAIL flip is deferred and was not built.
- target: a fresh copy of `~/CodeRadar_snapshots/between_the_wheels_20260917_062701` (77 files / 69 .py)
  at `/Users/dev/Desktop/emotion_detector`. Lane tree **copy1** (dashboard 8081 / health 8052).
- name from the head of copy1's reserve (pool line 101); marked used at `cr_stop`
- launched 2026-09-21 ~00:13 local · **MONITORING, 5 gates PASS**, gate budget 2318 s · repo_id `87489ddef445`
- **driver: `obs_run153.py` — the `cr_*` tools are driven through the STDIO / IN-PROCESS DRIVER, NOT a
  mounted MCP client.** The mount is T1's and T3's. ONE TIGHT LOOP (run 151's shape):
  `cr_watch` → `cr_status` (the block published and EMPTY) → `cr_infractions` → `cr_apply` ×3 rewriter
  rows → the client edits → `cr_run_module`(suite) → the third edit backed out → `cr_report_outcome`
  2 confirmed + 1 failed → one Builder cycle → `cr_status` → `cr_stop(expected_changes)` → `cr_hand_back`

**The claim:** the mirror's one writer stages `rule_outcomes` every cycle from the confirmed ledger and
the return channel; a `confirmed` counts FOR every rule id the ledger record carries; a `failed` counts
against the repair VARIANT and never against the rule.

## The three rows, as seen

| row | rule ids | the Ranker's pick | reported |
|---|---|---|---|
| `repair_plant_071.py::collect::4` | NAI-021S, NAI-071 | `alias_chain_fix:new_sequence` | **confirmed** |
| `repair_plant_061.py::label::5` | NAI-061 + 8 context ids | `bool_literal_compare_fix` | **confirmed** |
| `repair_plant_070.py::count_ints::5` | NAI-070 + 10 context ids | `bare_except_fix` | **failed** (edit backed out first) |

- `cr_apply` 3/3 `kind=diff`, `applies_cleanly` true; the client wrote every byte (Q3 of session 3)
- **suite 38 passed / 14 skipped, exit 0** — unmoved from baseline
- `cr_status` at MONITORING: `rule_outcomes` **published and empty** (`{}`), beside `finished`
- one Builder cycle (1 → 3): `counterfeit_failed` **163 → 161** (−2, exactly the two confirmed)
- hand-back MEASURED: infractions 161 · solutions 150 · **confirmed 2 · confirmed_from_ledger 2 ·
  orphans 0** · `confirmed_fraction` 0.0133 · tester_ran true

## What `rule_outcomes` said — read back off the mirror file and the report, 14 rules

```
NAI-021S  confirmed_for 1  failed_against {}            NAI-070  confirmed_for 0  failed_against {"?": 1}
NAI-071   confirmed_for 1  failed_against {}            NAI-114  confirmed_for 0  failed_against {"?": 1}
NAI-061   confirmed_for 1  failed_against {}            NAI-168  confirmed_for 0  failed_against {"?": 1}
NAI-082 / 083 / 084 / 121 / 185 / 186 / 229 / MEASURED-NOTHING  confirmed_for 1  failed_against {"?": 1}
```
`cr_status`'s block and `system_scripts/.noai_state.json`'s `summary.rule_outcomes` are byte-equal, and
`tester_report.json` carries the same 14 rules. Nothing in `rule_dispositions.json` moved.

**The one check the driver marked ✗, and it is the lane's finding for the owner:** the failure landed
under `"?"`, not under `bare_except_fix`. The variant lives in exactly one place — the row's
`decision.pick_role` — and the Builder re-decides a failed row in the SAME cycle the line arrives: the
candidate that failed becomes unpickable, the row turns `ranker_none`, and `pick_role` is None by the
time the mirror is written. The rule ids survive (the join holds on the row's `tester=failed:<digest>`
evidence token); the variant does not. `b9_proof` part 6 proves both readings of this same row. The
brief's instruction for exactly this case was followed: recorded under `"?"`, never dropped, and named
in the lane report's "For the owner".

## Close

`cr_stop(expected_changes=['colorama/repair_plant_061.py', 'colorama/repair_plant_071.py'])`: stopped ·
residue_clean **true** · byte_identical false (client_edits 2, as declared) · files_compared 77 ·
**unexpected_changes []** · 4 daemons exit 0 · "RESIDUE CHECK: zero CodeRadar mirror files remain in
target". `teardown_diff.txt` names those two files and nothing else. Target left standing at
`/Users/dev/Desktop/emotion_detector`. No `BUILDER_STATE.json` / `poll_config.json` left in the tree.
