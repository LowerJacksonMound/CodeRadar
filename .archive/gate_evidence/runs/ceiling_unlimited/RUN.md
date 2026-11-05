# RUN 136 — ceiling_unlimited

- item: FIX_47 + I-53 + I-55
- target: /Users/dev/Desktop/ceiling_unlimited
- snapshot: /Users/dev/CodeRadar_snapshots/ceiling_unlimited_20260917_025231
- launched: 02:53:46  gates: 5 PASS
- teardown: RESIDUE CHECK: zero CodeRadar mirror files remain in target
- byte-identity: 79 files, md5 diff exit 0 (IDENTICAL)
- state during run: /Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2/.archive/runs/ceiling_unlimited/state_during_run/
- frames: /Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2/.archive/frames/run136
- health at launch: /Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2/.archive/runs/ceiling_unlimited/health_at_launch.txt

## Lane record — copy2, FIX_47 (+ riders I-53, I-55), 2026-09-17 — the last pre-break item
Rulings of record: `PRE_VSC_PACKET_2026-09-15.md` §F **Q7 — "RE-ROUTE: RCA-001 becomes evidence into the
Ranker"**; THE FLOWCHART's doctrine (owner 2026-09-09: the Ranker is the last step of every line that ends in
a decision); cut 1 / cut 2 (observations are evidence, the site formats and does not decide). Facts corrected:
**I-03** and the 4b fact of set 4b-26. Plan detailed in place from the stub: `FIX_47_rca_001_reroute.md`.
Bases `.archive/lane_base/` — **every base md5 equalled the original's current md5, 7/7.**

**Built.**
- `utils/code_analysis/fingerprint.py` — **I-03, the root cause.** `normalized_fingerprint` measures a
  `copy.deepcopy` of the node. `_ASTNormalizer` is an `ast.NodeTransformer`, and `NodeTransformer.generic_visit`
  rewrites a node's list fields IN PLACE (`old_value[:] = new_values`), so the fingerprint stage renamed the
  CALLER's own `ast.arg` / `ast.Name` nodes to `_var_0`, `_var_1`, … The hex is unchanged (normalization is a
  pure function of structure); the caller's tree is not touched. Reading may not write.
- `no_aivalidator/noai_validator/file_validation.py` — **FIX_47, the re-route.** `_rca_intra_file_sweep(…, validator)`
  no longer asks the `rule` stage for a verdict and rewrites the row after it. It emits the RCA-001 OBSERVATION
  `{tag, line, description, callee, magnitude}` (FIX_18's / FIX_17's shape), appends it to the row's own
  observations, and re-runs `VerdictRanker.decide("observations", …)`. The verdict, the LAYER
  (`ValidationLayer[_v.layer]`) and the reason (rendered by the one renderer, `validator._format_observation`)
  are all the Ranker's. The token is published on `triggered_patterns` ALWAYS — withheld or not.
- `no_aivalidator/repair_generators/file_level.py` — the 4b fact of set 4b-26 marked SUPERSEDED; the RCA-001 row's
  fact records the re-route. The row stays a PRESCRIPTION (FIX_41); its kind, text and shape are untouched.
- `system_scripts/test_runner_tracker.py` — **I-53.** `proc_cwd(pid)` (the `lsof -a -d cwd -p <pid> -Fn` check
  `run_proof.sh::tree_daemon_pids` already uses) + `_cwd_in_target`; `collect_runner_executions(…, cwd_of=None)`
  drops a ps-proven pid whose cwd is not under the target. `cwd_of` is injected as `ps_lines` and the kernel
  record already are. The wrapper and kernel sources are untouched — both carry their own repo proof.
- `system_scripts/entry_point_wrapper.py` — **I-55.** `run_module` appends `-p no:cacheprovider` to a `-m pytest`
  run. `test_path` is read from the caller's OWN arguments before the flag is added, so the flag can never be
  mistaken for the path the runner was pointed at.
- `system_scripts/health_check.py` — step 2 tier 2 `no_mutation (FIX_47)` (the fingerprint leaves its input
  identical and returns the same hex); step 9 tier 2 `rca_001_observation_to_ranker (FIX_47)` (the whole route
  over a written split-fake fixture: the token, its callee and magnitude, `verdict_source == "ranker"`, the layer,
  the reason, and a control carrying nothing); step 15's runner fixture gains I-53's three cases plus `proc_cwd`
  on this process.
- `system_scripts/fix47_rca_reroute_proof.py` — NEW, the offline proof, four parts. **PASS.**
- Ledger `.archive/PRERANKER_HUNT_2026-09-17.tsv` **+16 rows `RUN_136 2026-09-17`** (V59 ×15, V18 ×1 — all
  KEPT→PLUMBING), copy in `ledger_rows_RUN136.tsv`. **`preranker_allowlist.json` UNCHANGED** — 394 numeric sites,
  DISALLOWED 0, no new literal comparison, no new early-out beyond the one filed row.

**Gates.** Conformance `--conformance BUILD_PLANS_FIXES_2026-09-08` **exit 0** (THROWN-OUT hits: 0). Health
**✓ PASSED Steps 1-20** (`health_prelaunch.txt`, re-run at launch as `health_at_launch.txt`): step 2
`fingerprint does not mutate its input (FIX_47): ✓`; step 9 `RCA-001 observation -> ranker (FIX_47): ✓`; step 17
`394 numeric sites scanned — allowed 394, exempt 0, DISALLOWED 0` / `ledger 2026-09-17: joined 1908 · orphan 517 ·
creep 0` / `orphan rows: 517 (frozen 513, +4)`; step 18 `257 emitted ids / 257 rows` + recall guard
`204 caught in substance, 204 by id; controls 23/23 clean`; step 19 `212 registry rows / 212 deciding ids —
rewriter 65, prescribed 146, no_fix 1, UNBUILT 0` — **unchanged**; step 20 `✓ venv matches what the app needs`;
**`engine mypy: 0 errors in 0 files (202 checked)`**. Launch 02:53:46, `CADENCE CONFLICTS: none`, circuit READY
1.5 s · WIRING every node connected · NOAI MONITORING 5.7 s · CHEATSHEETS 1.0 s · dashboard 200 in 0.0 s —
**ALL GATES PASSED after 85 s** (budget 2332 s). Teardown 03:00:49: 4 daemons exit 0 (SIGTERM),
**RESIDUE CHECK: zero CodeRadar mirror files remain in target**, **79 files IDENTICAL** (md5 diff exit 0), pool
line 157 marked, no process left by cwd, port 8082 free, no `hl_pipe_*` (I-74), no stale `poll_config.json` /
`BUILDER_STATE.json` after teardown.

**Target.** A fresh `limbo` copy (77 files, 69 .py — byte-identical to run 135's base) + the RCA-001 split-fake
plant that has been in `limbo` since set 4b-26 (`colorama/repair_plant_split.py`) + **two new files**:
`colorama/ceiling_unlimited_control.py` (RCA-001's CONTROL — a caller of a callee that PASSES, forwarding its own
parameters) and `colorama/tests/ceiling_unlimited_test.py` (I-53's construct — a runner that dwells long enough to
be seen, inert unless `CEILING_UNLIMITED_DWELL` is set). **79 files, 71 .py.** Certified before launch: 71/71
genuine modules parse, no entry-point name collision, no case collision.

**Live counts.** **164 infractions / 156 with a best solution (57 rewriter + 99 prescribed) / 8 declined**,
withheld 85; validator 110 passed / 164 failed / 359 total, 66 files scanned. The `limbo` base of runs 125, 126,
128, 131, 134 and 135 was **162 / 154 (57 + 97) / 8, withheld 83**. The whole delta is accounted for: **+2
infractions = the two RCA-001 rows the re-route now decides** (+2 prescribed, the same rows), **+2 withheld = the
new test file's rows** (species:test). No other row moved.

**PROOF — FIX_47 (a), the blinding is gone.** Reproduced first with the base engine on a hand probe: at sweep
time the route's collector reported `load_table params=['_var_0','_var_1'] callees=[]`,
`read_config params=['_var_0','_var_1'] callees=['_var_4','_var_6','_var_8']` while the failed rows were
`['load_table','summarise']` — `callees ∩ failed_names` empty by construction, and the caller published a clean
PASS. With the fix the same probe flips. The offline proof's Part 1 prints
`params before ['alpha','beta'] -> after ['alpha','beta']` and the hex identical to a fresh parse.

**PROOF — FIX_47 (b), the token on the row, live (`obs_A_rca001_rows.txt`).** Two rows in the published
`NOAI_VALIDATION_STATE.json` carry the observation, both decided by the Ranker:
```
colorama/repair_plant_split.py::read_config line 12
  passed False · failure_layer AI_FAKE_DETECTOR · verdict_source ranker
  failure_reason  RCA-001 (line 12): Calls failed function 'load_table' without forwarding params ['encoding', 'path']
  rule_ids ['RCA-001']  dispositions {'RCA-001': 'deciding', … every other id 'context'}
  OBSERVATION {"callee": "load_table", "description": "Calls failed function 'load_table' without forwarding
               params ['encoding', 'path']", "line": 12, "magnitude": 1, "tag": "RCA-001"}
```
and `colorama/win32.py::SetConsoleCursorPosition line 129` with
`callee GetConsoleScreenBufferInfo, magnitude 1` — a REAL split-fake shape in the library itself (see the facts
below). **THE CONTROL carries none:** `colorama/ceiling_unlimited_control.py::width_of passed=True
RCA-001 observations=0 rule_ids=[]` and `::pad_to_width passed=True RCA-001 observations=0 rule_ids=[]`.
Frames `B_rca001_plant_row.png` (stamp `frame 3 · 02:58:54.059 · 2 nodes`) and `C_rca001_win32_row.png`
(`frame 3 · 02:59:27.398 · 2 nodes`), no spinner, graph drawn; `A_page_top_band.png`
(`frame 4 · 02:56:55.640 · 2 nodes`) carries the badge `164 counterfeit code infractions · 85 withheld`.

**PROOF — FIX_47 (c), `decision.why` cites it (`obs_B_decision_why.txt`).** The row reaches the Builder, the
registry is consulted on RCA-001, the prescription is offered and THE RANKER picks it:
```
ROW colorama/repair_plant_split.py::read_config::12
  generators_consulted [{"rule_id":"RCA-001","kind":"prescribed","role":"solution_RCA-001", …}]
  candidates_considered 1   selection {"solution_RCA-001": 84.57}
  DECISION.WHY  picked solution_RCA-001 over 0 other pickable candidate(s) of 1 offered; deciding method:
                n/a (one candidate); solution_RCA-001[kind=prescribed, parse=shape, differs=yes, rule=RCA-001,
                flow=same_paths, complexity=same, idiom=same, deps=none_added, defensive=same,
                readability=fewer_branches:1, traps=none, answers=row]; profile: no intent fact matched
```
and the win32 row the same at `selection {"solution_RCA-001": 76.75}`,
`readability=flatter:1+fewer_branches:3`. The registry row's KIND is unchanged — what changed is that the Ranker
is now handed a row to consider at all.

**PROOF — I-53 (`obs_C_i53.txt`).** Two pytest processes alive at once, **identical command lines**
(`… -m pytest colorama/tests/ceiling_unlimited_test.py -p no:cacheprovider -q`), different cwd — pid 80395 inside
the target, pid 80396 in a decoy tree carrying the same relative path.
- BEFORE, the lane's own base matcher (`.archive/lane_base/system_scripts/test_runner_tracker.py`) on **the same
  two real pids**: **both listed** (`pid 80395 [INSIDE] … [ps]`, `pid 80396 [ANOTHER TREE] … [ps]`).
- AFTER, the matcher under proof: **only pid 80395**.
- LIVE, the running circuit daemon: `TEST RUNNER: pytest pid 80395 → colorama/tests/ceiling_unlimited_test.py [ps]`
  at 02:54:41 and 02:54:44 — and **the foreign pid 80396 appears 0 times in the whole daemon log.**
Run 129's band carried two such foreign pids for its whole length (`.archive/runs/one_little_victory/obs_F_I53.txt`).

**PROOF — I-55 (`obs_D_i55.txt`).** `entry_point_wrapper.py -m pytest colorama/tests -q` inside the live target,
with NO hand-added flag: `39 passed, 14 skipped in 0.08s`; the target's file list is **identical before and
after** (89 files during the run, 0 added), no `.pytest_cache`, no `__pycache__`. On an identical copy of the
target's package, the same command through the lane's BASE wrapper left
`.pytest_cache/{.gitignore,CACHEDIR.TAG,README.md,v/cache/nodeids}`; through the fixed wrapper, nothing.
Teardown needed no hand cleanup: **79 files IDENTICAL**.

**Perf.** The fingerprint stage now copies each function node before measuring it. Over this target's 301
function nodes: **28.3 ms in place → 48.2 ms with the copy**, per full pass — against a NOAI gate of 5.7 s on the
same target. Gates passed in 85 s (run 135 on the 77-file base: 82 s).

**Deviations from the plan text.**
1. **The failure LAYER moves** from `HARD_REQUIREMENTS` (the old site's constant) to `AI_FAKE_DETECTOR` (the
   Ranker's rule: `HR-0*` → HARD_REQUIREMENTS, everything else → AI_FAKE_DETECTOR). Recorded in the plan §6 as a
   consequence of the doctrine, not a choice at the site; nothing in the rulings fixes RCA-001 to a layer.
2. **The pytest CONSOLE-SCRIPT path is not changed** (`run_script`, `entry_point_wrapper.py:286-287`). The rider
   names the wrapper's `-m pytest` invocation path; the documented reading was taken. A pytest run as the console
   script through the wrapper still writes `.pytest_cache/`.
3. **The second reading the owner offered for FIX_47 — "names captured before normalization" — was not built.**
   It would have left a measurement that rewrites its caller's tree live for every other consumer of that stage.
   The root cause is fixed once, where it is.
4. **4 ledger rows of this run are orphans of this run.** The first 12 `RUN_136` rows were filed before the mypy
   pass; that pass renamed four locals (`_rc` → `_rc47`, and a typed `_fp_fresh`) and so changed four join keys.
   The ledger is APPEND-ONLY — nothing was rewritten — so 4 corrected rows were appended and the 4 superseded ones
   became orphans: step 17 reads `orphan rows: 517 (frozen 513, +4)` and REPORTs it (creep 0). The status text of
   the corrected rows says so.
5. The graph MCP tools named in `CLAUDE.md` (and the `search_graph` / `trace_path` / `get_code_snippet` names of
   the lane brief) are **not exposed in this session at all**. Navigation used an AST symbol-block extractor (one
   function block at a time) plus AST-level scans for call sites. No whole-file reads of source over 100 lines,
   no grep for symbols.

**Facts for the owner (found, not fixed — candidate pinned rows; the original's `PINNED_ISSUES` not edited).**
1. **The re-route's first find outside a plant.** `colorama/win32.py::SetConsoleCursorPosition(stream_id, position, adjust)` calls `GetConsoleScreenBufferInfo(STDOUT)` — a module constant, not its own `stream_id` — and that callee fails NAI-010 (dead local `success`). RCA-001 therefore decides a row in the LIBRARY itself, not only in the plant. Is "the caller passed the callee's own default instead of its parameter" a true split-fake, or does RCA-001 want that exemption? Today it decides and the prescription is the Ranker's to pick.
2. **The failure layer of an RCA-001 row moved** HARD_REQUIREMENTS → AI_FAKE_DETECTOR, because the layer is now the Ranker's (`HR-0*` → HARD_REQUIREMENTS, else AI_FAKE_DETECTOR). Nothing in the rulings fixes RCA-001 to a layer; confirm or name one.
3. **I-55's other half.** The pytest CONSOLE-SCRIPT path through the wrapper (`run_script`, `entry_point_wrapper.py:286-287`) still writes `.pytest_cache/` into the target. The rider named the `-m pytest` path only.
4. **A gate can be silenced by nesting.** `preranker_hunt` reports **0** V59 `assert` sites inside `health_check._hc_hr_observation` and `._hc_runner_presence`, though both are full of asserts; the same asserts one indent level out ARE reported (166 V59 hits in that file). Nesting a block inside an unannotated inner function also hides it from mypy. This lane kept its asserts at step level for that reason.
5. **The fingerprint stage runs twice per function per file.** `file_validation.py:761` computes `_normalized_fingerprint(node)` only for a `logger.debug` line, and `:775` computes the same thing for the same node. Now that the call copies, that is two copies where one would do. Left alone — unrelated to Q7.
6. **RCA-001 can still never decide on the SYNC path.** `_rca_intra_file_sweep` is called from `_validate_file_from_ast` only; `_validate_ast` (the `validate_string` / `validate_module` path) never runs it. Pre-existing, unchanged by FIX_47.
7. **RCA-001's disposition row carries no `contexts`**, so the `magnitude` fact the new token carries cannot change anything yet. It is there for the per-(rule, context) table when the owner wants it (FIX_17's mechanism).
8. **Ledger orphans +4** (deviation 4): `orphan rows: 517 (frozen 513, +4)`. Whether to re-freeze `preranker_close.json` is the owner's call — it was not changed here.

## Close in the original (2026-09-17) — LANE D
**Bases.** Transplant base of every file below snapshotted to `.archive/archived_20260917/laneD_base/` (8 files —
the 7 pre-existing files plus the ledger) before anything was written. **Every lane BASE md5
(`copy2/.archive/lane_base/`) equalled the original's current md5 — 7/7 — so every file was COPIED WHOLE;
nothing was three-way patched.**

**Files copied whole (md5 after = the lane's, confirmed in place).**
| file | base (= original before) | after |
|---|---|---|
| `utils/code_analysis/fingerprint.py` | d011c5deebdfa025128ec3a520273e38 | e16fc16b9e6652cceefb466e74b16b0c |
| `no_aivalidator/noai_validator/file_validation.py` | 6d856db94c92344d21ad970e9a26482b | 7ee6a30ae068636d7dd278020a785e3f |
| `no_aivalidator/repair_generators/file_level.py` | dcf4ebba982c2108cfbebfbba73fc81e | 229613d50070602dc5a8e7a52a5bd9ad |
| `system_scripts/test_runner_tracker.py` | dad4bacacafe4f6c1113ec387efb060b | b047c70d21967f0682f6fbeefeda2ad7 |
| `system_scripts/entry_point_wrapper.py` | 9df0925f793805e8c5019f7c2b5a8617 | d104e79ea85cd042e0b92091b8e55f0d |
| `system_scripts/health_check.py` | 354641878170fb666ce5c64bebdcebec | c8ce3b7260410d3e174c19003a4ad051 |
| `BUILD_PLANS_FIXES_2026-09-08/FIX_47_rca_001_reroute.md` | 0e42cb5e82efd99e2ddd0eaebe147f51 | b4d34c38fffb88b54fdc2c82e4cb2b41 |
| `system_scripts/fix47_rca_reroute_proof.py` | NEW (absent) | 39b4a27f4fde3e4555f96f768cbbc84e |

UNCHANGED as the lane recorded, verified in place: `system_scripts/preranker_allowlist.json`
cc24d9f1c670c22f53973114214c490e, `system_scripts/rule_dispositions.json` b9bc7a10332e19e4144d3ac7485c8a85,
`system_scripts/circuit_daemon.py` 5d8e7f7498084177f0b4a48ef692b8cf, `no_aivalidator/BUILDER_DAEMON.py`
8d964a1a306d4e0dfd87f342f94c94c7, `no_aivalidator/cheatsheets/cheatsheet_intelligence/knowledge_base.py`
ca8b97221d56db58e19f0535cc3b28a9, `no_aivalidator/noai_validator/validator.py` 23d69e27bb866f91dfd883bb4e5bbd53.

**Ledger — APPEND-ONLY, no `--rekey`.** The original's `.archive/PRERANKER_HUNT_2026-09-17.tsv` was
byte-identical to the lane base (cce2a91653271a992d0675f1a84f684d, 2391 lines) and a byte-prefix of copy2's;
copy2's tail beyond line 2391 was verified byte-identical to `ledger_rows_RUN136.tsv` first, and no `RUN_136`
row was present in the original (0). The 16 `RUN_136 2026-09-17` rows were appended verbatim. 2391 → **2407
lines**, md5 **cb348102d0aec0eeae9d59846c25f58c** — byte-identical to copy2's ledger (`cmp` clean); the first
2391 lines are untouched. Nothing overwritten, nothing re-keyed.

**`preranker_close.json` NOT re-frozen** (c0228fcae2cff0a9cd2bdb3dc4526c27, unchanged): it still names
`PRERANKER_HUNT_2026-09-17.tsv` with `ledger_rows 2389` / `orphan_rows 513`, so step 17 REPORTs
`orphan rows: 517 (frozen 513, +4)` — the lane's deviation 4, the owner's call, not taken here.

**Records.** `.archive/runs/ceiling_unlimited/` (19 files + `state_during_run/`) and `.archive/frames/run136/`
(3 PNGs) copied from copy2, `diff -rq` clean on both, no `hl_pipe_*` (I-74). Pool line 157 of
`.archive/naming/rush_track_pool.txt` marked `ceiling_unlimited  # used: ceiling_unlimited (run 136, FIX_47 +
I-53 + I-55)` **exactly as copy2's line reads**; the whole file is now byte-identical to copy2's, so no other
line changed — 203 lines before and after. Target copied to `RULE_REWRITES_RUN-AGAINSTS_9-09-26/ceiling_unlimited`
(**79 files**, `diff -rq` identical to `~/Desktop/ceiling_unlimited`, which is left in place); no mirror residue
in it (no `.pytest_cache`, no `__pycache__`, no state file).

**Step 18's recall-guard counts did NOT move — the lane's expectation does not hold.** Before the target copy:
`recall guard: 50 archived targets / 204 plants — 204 caught in substance, 204 by id; controls 23/23 clean;
lost families 0`. After it: **the same line, byte for byte.** The guard iterates
`.archive/runs/*/manifest.json` and skips any run without `planted_findings`
(`disposition_check.check`, the `(d) recall guard` block); **run 136 wrote no `manifest.json`** — neither here
nor in copy2 — so `ceiling_unlimited` contributes no target and no plant. 54 manifests on the tree, 50 with
plants, in both trees. Independently, `verify_manifest.resolve_target` prefers the recorded path while it
exists, and `~/Desktop/ceiling_unlimited` does exist, so the run-against copy could not have changed
resolution either. copy2's own `health_prelaunch.txt` and `health_at_launch.txt` both read **50 / 204** as
well: the lane never measured a shift. Nothing was done about it — recorded, not ruled on.

**Gates in the original (merged A+B+C+D).** `.venv_new/bin/python3 -m compileall -q system_scripts
no_aivalidator rca_main utils` **exit 0**. `TERMINOLOGY_CENSUS_2026-09-09.py --conformance
BUILD_PLANS_FIXES_2026-09-08` **exit 0** — `THROWN-OUT hits: 0` (`conformance_merged.txt`).
`.venv_new/bin/python3 system_scripts/fix47_rca_reroute_proof.py` → all four parts, **`FIX_47 + I-53 + I-55
unit proof: PASS`** (exit 0): Part 1 `params before ['alpha','beta'] -> after ['alpha','beta']`; Part 2 the
plant decided `layer=ValidationLayer.AI_FAKE_DETECTOR source='ranker'` with the RCA-001 token and the CONTROL
carrying none; Part 3 the foreign-tree pid and the unreadable cwd both dropped; Part 4 `files added to the
target: none`. `preranker_census.py`: `394 numeric sites scanned; allowed 394; exempt 0; DISALLOWED 0; stale
allowlist entries 0`. No original-tree daemon running before or after (selected by cwd, as `run_proof.sh`
does); copies untouched; no stale `system_scripts/poll_config.json` (absent before and after), no
`gearbox_events.json`, no `BUILDER_STATE.json`.

**Merged health — `health_merged.txt` (`.venv_new/bin/python3 system_scripts/health_check.py`), header
`HEALTH CHECK — Steps 1-20`:**
- `HEALTH CHECK: ✓ PASSED — All measured steps ready` (EXIT=0)
- step 2 `Tier 2: ✓; fingerprint does not mutate its input (FIX_47): ✓`
- step 9 `Tier 2: ✓; determinism + timing (FIX_34): ✓; RCA-001 observation -> ranker (FIX_47): ✓`
- step 17 `394 numeric sites scanned — allowed 394, exempt 0, DISALLOWED 0` / `extended hunter (joined to the
  ledger by file::kind::expr): 1908 sites on the tree — 1908 with a filed status, 0 open, 0 not in the ledger`
  / `ledger 2026-09-17: joined 1908 · orphan 517 (cut 228 · file gone 153 · superseded 12 · BLIND 124) ·
  creep 0` / `orphan rows: 517 (frozen 513, +4)` — **creep 0**, the +4 a REPORT (lane deviation 4)
- step 18 `257 emitted ids / 257 rows — missing 0, strict∩context 0, stale 0, deciding without evidence 199
  (REPORT)`; `recall guard: 50 archived targets / 204 plants — 204 caught in substance, 204 by id; controls
  23/23 clean; lost families 0`
- step 19 `212 registry rows / 212 deciding ids — rewriter 65, prescribed 146, no_fix (pending FIX_43 finite
  set) 1, no_fix (pending another lane) 0, no_fix UNLISTED 0, UNBUILT 0` — **unchanged (212 = 65 / 146 / 1 /
  0)**
- step 15 Tier 2 ✓ carries lanes B and C's units intact beside this lane's runner fixture — `FIX_45/I-54 …
  severed_links (ITEM_11)`, `restarter (FIX_52)`, `syntax_fixture (FIX_53)`
- `engine mypy: 0 errors in 0 files (202 checked)`
- step 20 `✓ venv matches what the app needs`

**No live run.** Every file was copied whole from a tree byte-identical to the original plus these changes, and
run 136 is the live proof (`launch.log`, `tester_report.json`, the three frames, `teardown_diff.txt` empty,
79 files IDENTICAL).

**Not as expected.** One, recorded above and not blocking: step 18's recall-guard counts are unmoved by the
target copy (50 / 204 before and after, and the same in copy2), because run 136 produced no `manifest.json`
with `planted_findings`. The step 17 `+4` orphan REPORT is the lane's own, expected, and left alone.
