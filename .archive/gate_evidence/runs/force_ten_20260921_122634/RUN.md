# RUN 158 — force_ten

- item: **T1, THE DRIFT FIX** — `DRIFT_AND_RULE_FIXES_PACKET_2026-09-21.md` §C, points 1–7, under §B's
  Q1 (the channel line gains additive identity fields) and Q4 (driver-driven). One cause for
  I-119 / I-122 / I-125 / I-130 / I-137 / I-138: row identity is positional and so is the channel's
  join key, so the row a seat was handed drifts out from under it between `cr_apply` and
  `cr_report_outcome`. One repair: **the server remembers what it handed out (the APPLY LEASE), and
  every record it writes carries the PRE-EDIT identity.**
- target: a fresh copy of `~/CodeRadar_snapshots/between_the_wheels_20260917_062701` at
  `~/CodeRadar_snapshots/force_ten_20260921_122634` (77 files / 69 .py; the snapshot itself is never
  edited, and each launch below took a new copy of it)
- name from the head of copy1's reserve — pool line 103. Line 102 `mystic_rhythms` is marked
  `# used: copy1 run 158 ABORTED 2026-09-21 (no record)`: it was consumed by a first launch of run
  158 killed at 08:52, of which nothing survived the tree refresh.
- **driver-driven, NOT a mounted MCP client** — `cr_*` through the stdio / in-process driver in this
  run record (`obs_run158.py`, modelled on run 157's `obs_run157.py`); Q4's default, taken. Only
  T1 (run 152) and T3 (runs 154–155) of session 6 mounted.
- repo_id `0cb5ea90e0ac` · dash :8081 / health :8052 · gate budget 2318 s · 5 gates PASS in 84 s
- **`cr_stop` residue_clean true · unexpected_changes [] · client_edits 1** (one file, declared)

## Five launches — the last is the run of record

| launch | why | gates |
|---|---|---|
| A 12:28 | first pass — **found two defects**: (1) `orphans_channel 3` on a run where every outcome landed, because a line whose row the Builder had RETIRED was counted as an orphan (I-138's own complaint); (2) a client cannot back a failed edit out of `cr_row(row).before_code` — the before-code is retired with the row | 5 PASS in 88 s |
| B 12:53 | the orphan clause and the client-side revert fixed — **found the third**: `>= 2 Builder cycles` cannot be had by WAITING. The Builder is event-driven (`_read_validator_state` compares the state file's mtime), so three edits in one batch are ONE re-scan and ONE cycle; B sat out a 1800 s ceiling for a second cycle that could never come | 5 PASS in 86 s |
| C 13:27 | the seat applies in TWO passes, one cycle each — **found the fourth**: `cr_apply` on a stale id files the lease under the id the server RESOLVED, while the client goes on holding the id it was GIVEN. Filed under `pick::17`, looked up under `pick::18`: the seat could not find its own lease and every report but the first was refused | 5 PASS in 85 s |
| D 13:30 | `_lease_lookup` made tolerant of a re-key — 12 of 13 assertions held; the driver's own revert check still re-spelled the lookup instead of calling the engine's | 5 PASS in 84 s |
| **E 13:44 — the run of record** | the driver calls `write_tools._lease_lookup`; **13 of 13** | 5 PASS in 84 s |

All four defects are in `T1_DRIFT_FIX_REPORT_2026-09-21.md`; each is a case in `identity_proof`.

## What the run did (launch E), read back off the record

Three rewriter rows in **one file**, `colorama/repair_plant_branches.py`, applied in two passes so
that two real Builder cycles turn before a single outcome is reported:

| | row (as the seat holds it) | `replace_span` | `replace_span_live` | re-based | lease |
|---|---|---|---|---|---|
| pass 1 | `::guarded::7` | `L7-L11` | `L7-L11` | no | `guarded::7` |
| pass 2 | `::pick::18` | `L17-L22` | `L17-L22` | no (`resolved_by function`) | `pick::17` |
| pass 2 | `::stamp::26` | `L25-L28` | **`L24-L27`** | **yes** | `stamp::25` |

- suite through the wrapper, three times — baseline, after the three edits, after the revert:
  **38 passed / 14 skipped, exit 0** every time.
- cycles: 1 → 2 (5.0 s), 2 → 3 (5.0 s) — **2 turned before anything was reported**; then 3 → 4 after
  the reports. Every one of the three rows was **gone from the mirror under the id the seat held**
  by then (`still_in_mirror_under_the_same_id: false` ×3) — I-119's window, waited out on purpose.
- `cr_report_outcome` ×3: **`written true` ×3, `resolved_by "lease"` ×3**, `resolved_id` the lease's
  own re-keyed key (`pick::17`, `stamp::25`). Two `confirmed` (ledger written), one `failed`
  (no ledger record — S4-3 stands), whose edit was then reverted and the revert **verified against
  the lease's `before_sha256`**.
- `rule_outcomes`: **13 rules, `?` nowhere.** `failed_against` reads
  `immediate_overwrite_fix:keep_second: 1` under each of NAI-006 / 082 / 084 / 114 / 121 / 185 / 229
  / MEASURED-NOTHING — I-122's variant, on the line, surviving the re-decide.

## Close — `cr_stop` then `cr_hand_back`, off the gate's own log

`cr_stop`: stopped · residue_clean **true** · byte_identical false (client_edits 1, as declared) ·
files_compared 77 · **unexpected_changes []** · `teardown_diff.txt` names exactly
`colorama/repair_plant_branches.py`. `cr_hand_back`: status MEASURED · builder_cycles 4 ·
infractions 161 · solutions 151 · confirmed 2 · confirmed_from_ledger 2 · return_channel_lines 3 ·
**orphans 0 · orphans_channel 0** · unparsed 0 · tester_ran true.

Gates at the close: `.archive/health/gates_t1/SUMMARY.txt` — **gates=ok (15/15)**.
`coderadar_mcp/identity_proof.py` is the 15th gate line (`identity`), and its part (vii) reads this
record's `run158.json`.

Pool line 103 marked `# used:` by hand: `cr_stop(mark_pool=True)` marks by the TARGET's basename,
which is `force_ten_20260921_122634` here and is not a pool line.
