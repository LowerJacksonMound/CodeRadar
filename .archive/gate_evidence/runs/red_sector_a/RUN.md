# RUN 144 — red_sector_a

- item: `RELEASE_FORM_CLOSEOUT_PACKET_2026-09-17.md` §B row **S4-3** — the confirmed join, ruling **Q1(a)**
- tree: **copy1** (dashboard :8081, health :8052) · target `/Users/dev/Desktop/red_sector_a`, a fresh `limbo` copy
  (77 files / 69 .py, byte-identical to run 140's base) · name from the head of copy1's own reserved slice (line 89)
- launched 07:58 · repo_id **7cfe2e71fa83** · 5 gates PASS (circuit 1.5 s · WIRING · NOAI 5.6 s · CHEATSHEETS 1.0 s ·
  dashboard 0.0 s), budget 2328 s · driver `obs_run144.py` (handlers called in-process, as runs 138/139 did)
- teardown: `residue_clean true` · `byte_identical FALSE` by design (the client edited one file) · 77 files compared ·
  **`client_edits 1` · `unexpected_changes []`** · 4 daemons exit 0 (SIGTERM) · zero mirror files left in the target

## What run 144 proves
The ledger the ruling asked for, on a live stack: **a confirmation the return channel cannot join is still counted.**

| step | what |
|---|---|
| `cr_apply` | `colorama/repair_plant_shape.py::merge_tags::13` — kind `diff`, `applies_cleanly TRUE`, role `alias_chain_fix:new_sequence`, digest `84e0cae05f`, rules `['NAI-021S']` |
| the client edit | the diff written by the driver at the row's span (client seat, Q3 — the server wrote nothing), `ast.parse` clean |
| `cr_report_outcome(confirmed)` | channel line 269 bytes **and** one ledger record in `system_scripts/confirmed_ledger_7cfe2e71fa83.jsonl` |
| `cr_report_outcome(failed)` | `colorama/repair_plant_071.py::collect::4`, not applied — channel line yes, **`ledger_written false`, no record** |
| one Builder cycle (1 → 3) | the repaired row is **GONE** (164 → 163 rows); `summary.tester {confirmed 0, orphans 1, channel_lines 2}` — run 141's fact again, in miniature |
| the failed row | joined and re-decided: `rca_evidence` gains `tester=failed:8f9a25700f` + `tester_log=…` |
| `cr_stop(expected_changes=['colorama/repair_plant_shape.py'])` | `client_edits 1 · unexpected_changes []` |
| `cr_hand_back` (AFTER `cr_stop`) | **`confirmed 1` (joined 0 · from_ledger 1) · `orphans 0` (`orphans_channel 1`) · `unparsed 0`** |

```
tester_report.json   builder_cycles 3 · infractions 163 · solutions 155
                     confirmed 1 · confirmed_joined 0 · confirmed_from_ledger 1
                     orphans 0 · orphans_channel 1 · unparsed 0 · channel_lines 2
                     confirmed_fraction 0.00645 (1/155) · tester_ran true · finished false
                     per_infraction 163 rows
ledger record        {"digest": "84e0cae05f", "replace_span": "colorama/repair_plant_shape.py:L13-L18",
                      "rule_ids": ["NAI-021S"], "file": "colorama/repair_plant_shape.py",
                      "function": "merge_tags", "line": 13, "seat": "coderadar-mcp run144",
                      "note": "run 144: applied the rewriter diff; the function is repaired",
                      "edit_kind": "diff", "timestamp": "2026-09-17T12:58:31.786710+00:00"}
```

Without the ledger this run would have read `confirmed 0 · orphans 1`, exactly as runs 141 and 142 did.

## Record
`obs_run144.py` · `obs_run144.txt` · `phase1_watch.json` … `phase8_hand_back.json` · `launch.log` ·
`state_during_run/` (the channel and the ledger copied beside it) · `teardown_{snapshot,target}.md5` ·
`teardown_diff.txt` · `tester_report.json`. Pool line 89 `red_sector_a` marked used by hand
(`cr_stop` was called with `mark_pool: false`), 203 lines before and after.
