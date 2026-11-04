# Fix record — 2026-10-23 (pre-live-trial)

Source: `~/Downloads/CODERADAR_CODE_REVIEW_2026-10-23.md` and `CODERADAR_FIX_PLAN_2026-10-23.md`.
Each item was validated against the tree before it was changed. Verdicts: **confirmed** (as written),
**confirmed, different cause**, or **not reproduced**.

## Pass A — the tree could not start (confirmed)

| Item | Verdict | What was done |
|---|---|---|
| A1 `launch.sh`, `coderadar-mcp.sh`, `run_proof.sh` referenced but absent at root | confirmed (`run_proof.sh` was present under `system_scripts/`; the two root scripts were missing) | Restored `launch.sh`, `coderadar-mcp.sh`, `install_coderadar_mcp.sh`, `replay_gates.sh`, `pyproject.toml`, `README.md`, `HOW_CODERADAR_WORKS.md`, `SPECIES_DICT.json`, `LICENSE`, `.gitignore` from the iCloud copy at `~/Library/Mobile Documents/com~apple~CloudDocs/RELEASE_STAGING/cr/`, whose package directories were byte-identical to this tree (`diff -rq`). |
| A1 `.venv_new` missing | confirmed | Rebuilt with Homebrew Python 3.13: `python3.13 -m venv .venv_new && .venv_new/bin/pip install -e .`. |
| A1 MCP registration pointed at the deleted `CODE_RADAR_REFURBISH` tree | confirmed | `bash install_coderadar_mcp.sh` re-registered `coderadar` at this tree. |
| A2 stale 10 Oct state (`BUILDER_STATE.json`, mirrors, `*_9e25ddf5e68e.*`, locks, `launch_progress.json`) | confirmed | Moved, not deleted, to `.archive/state_before_2026-10-23_repo_9e25ddf5e68e/`. |

## Pass B — the write path (confirmed; the review's premise was half right)

Reading `no_aivalidator/solution_gate_integrate.py` and `BUILDER_DAEMON._stage_integrates` confirmed
that the Builder **does** write an integrated `cr_submit` attempt into the target. The review's "two
writers" risk is real: `cr_apply` also handed a seat a diff to apply by hand, and the seat text still said
"you make every edit".

| Item | Verdict | What was done |
|---|---|---|
| B1 state the write in code | confirmed | `cr_submit` docstring names the exact write path (stage 2, live span, revert on failure, `integrated` status). |
| B2 one row, one writer | confirmed | `cr_apply` answers `write: false` always; refuses a row with a `cr_submit` attempt on file. `cr_submit` refuses a row whose `cr_apply` bytes were hand-edited since (lease `before_sha256` re-hashed at the live span). Seat instructions (`server.py`), the package README and the tool schema say CodeRadar is the only writer. |
| B3 writes use the recorded span | **confirmed, worse than written**: `stage_integrates` spliced at the row's recorded `func_start`/`func_end` with no AST check | `stage_integrates` now locates the function live by AST (same rule as `write_tools._live_span`), re-bases, and answers `deferred` when it cannot locate it; `cr_apply` refuses to render a named function it cannot locate live instead of falling back to the recorded span. |

## Pass C — a seat could not see what it was missing (confirmed)

| Item | Verdict | What was done |
|---|---|---|
| C1 no `has_more`; `pages` only; seats stop on page 1 | confirmed | `cr_infractions.done` (true only on the last page); `cr_status.open_findings`, `open_findings_by`, `infraction_pages`. |
| C2 `entry_point_info.json` omits failed imports and out-of-target files silently | confirmed | `entry_point_wrapper` records `failed_imports` (located by `find_spec` but never in `sys.modules`) and `omitted` (count, by reason, capped file list). |
| C3 findings from `.venv`/`node_modules` reported as the target's | confirmed (only `__pycache__`, `.git`, `.cr_pycache` were skipped by name; FIX_13 asserted the rest were scanned) | `scan_scope._HARD_SKIP_PARTS` now also skips `.venv`, `venv`, `node_modules` by name. `scan_scope.dot_dirs_in_scope()` lists every other dot-dir with scanned `.py` files; `launch.sh` prints it (`[scan-scope]`) and `cr_status.dot_dirs_scanned` carries it. |
| C4 a tracker not requested read as zero | confirmed | `cr_status` and `cr_watch` carry `trackers_ran`, `trackers_not_requested`, `naming_drift`. |

## Pass D — stop and watch (confirmed)

| Item | Verdict | What was done |
|---|---|---|
| D1 syntax breakage after launch | **not reproduced as a crash**: the circuit daemon already catches `SyntaxError` per file (`SYNTAX_BROKEN_FILES`, F-CRC1) and the gearbox wiring gate names it | No code change. |
| D2 `cr_watch` waits the whole gate budget for MONITORING | confirmed | Bounded by `MONITORING_WAIT_S = 120` after ALL GATES PASSED; breaks early if `launch.sh` exits; error says the daemons are still up and to `cr_stop`. |
| D3 `cr_stop` has no verdict; empty hash listing read as a match | confirmed | `open_findings`, `open_findings_by`, `clear`; `set -o pipefail` on the hash listing, missing `md5`/snapshot script/snapshot dir → `byte_identical: null` (NOT MEASURED), never true. `clear` is decided in one place (`_clear_verdict`). |

## Verification

- `health_check.py` steps 1–22: **PASSED** (after classing the new `start < 1` span-domain check as shape `S` in `preranker_allowlist.json`; census 408/408 allowed).
- Proofs that pass: `mcp_interface_proof`, `solution_gate_proof`, `launch_state_proof`.
- Replay proofs that load archived evidence — `read_tools_proof`, `mcp_write_path_proof`, `mcp_confirmed_ledger_proof`, `b9_proof`, `identity_proof`, `gate_proof`: all **PASS** once the evidence was restored (see below). They had failed at fixture load only.
- Evidence restored 2026-10-23 from Google Drive (account levisbikenzi222): `.archive/gate_evidence/` (475 files, nine run folders) from the `CLOSER_ORIG_DOCS/CR_SUPPORTING/CodeRadarSpecs/.archive` upload, and the run-136 target `RUN_AGAINST_DIRS_recall_targets/ceiling_unlimited/` (colorama, 78 files) from the `RUN_AGAINST_DIRS_recall_targets` upload. Neither had ever been inside the `NEW_CODE_RADAR_REFURBISH` Drive folder; they were uploaded beside it on 10 Oct. `.archive/PRERANKER_HUNT_2026-09-09b.tsv` (the census ledger of record) was restored from Drive too.
- Full `replay_gates.sh` on 2026-10-23: 14/17 pass. The three that fail — `nai094`, `census`, `mypy` (85 errors in 22 files) — and `conformance` (NOT MEASURED) were already failing on the last run of the old tree on 2026-10-10 (Drive `gates_after_lastplan_1010/SUMMARY.txt`: nai094, conformance, census, mypy 83 errors). A diff of mypy's error set against the pre-edit iCloud copy shows no error introduced today. Later the same day: `nai094` fixed (its fence asserted `role` both in and not in the Ranker's CONTEXT_FACTS; `role` has been a fact since M-146, so the fence now pins that and pins that no `contexts` row carries NAI-094) — PASS. `census` fixed by restoring the 29 Sept ledger of record from Drive and running the project's own `preranker_ledger_migrate.py --apply` then `--refreeze --apply`, which wrote `.archive/PRERANKER_HUNT_2026-10-23.tsv` (creep 0, orphans frozen at 538) — key-scheme PASS, 408/408 sites allowed. Remaining red: `mypy` (engine typing tally, 85 pre-existing) and `conformance` (needs the unshipped notes folder and script). `finished` failed once because the fresh venv had mypy 2.4.0, which reports the pinned-version fixture as rc 1 instead of the rc 2 abort the proof measures; mypy is now pinned `<2.4` (2.3.1 installed, the version the exit-code contract was verified on) and `finished` passes.
- Live run on a fixture repo through `cr_watch → cr_status → cr_infractions → cr_apply → cr_stop`: see the end of this file.

## Live run — fixture repo, 2026-10-23 14:36–14:39

Fixture: 3 source files (`run.py`, `pkg/orders.py` with two planted counterfeits), plus `.tools/helper.py`
(a dot-dir that IS source) and `.venv/lib/.../vendored/junk.py` (vendored, must not be scanned).
Driven through the MCP handlers in-process (`cr_watch → cr_status → cr_infractions → cr_apply → cr_submit → cr_stop`).

| Step | Observed |
|---|---|
| `cr_watch` | ALL GATES PASSED in 38 s; `phase: MONITORING`; `trackers_ran: [io, mypy]`, `trackers_not_requested: [crc, vulture]`, `naming_drift: measured`. |
| launch log | `[scan-scope] dot-directories in scope: .tools (skipped by name: .cr_pycache, .git, .venv, __pycache__, node_modules, venv, root .coderadar)`. No finding was raised on the `.venv` file. |
| `cr_status` | `open_findings: 2` (`repairs 2, no_vetted_fix 0, withheld 1`), `infraction_pages: 1`, `dot_dirs_scanned: [".tools"]`. |
| `cr_infractions` | `page 1 / pages 1 / total 2 / done: true`; rows on `pkg/orders.py::tally` and `.tools/helper.py::helper`. |
| `cr_apply` | `kind: shape`, `write: false`, span `L12-L14` (live = recorded, file unchanged). |
| `cr_submit` after `cr_apply`, file untouched | first run refused wrongly (the lease hashes a prescribed row's recorded code, not the live segment); fixed in `_hand_edited`, re-verified against the lease on disk: untouched → accepted, hand-edited → refused, restored → accepted. |
| `cr_stop` | `stopped: true`, `residue_clean: true`, `byte_identical: true` (5 files), `gate_writes: []`, `unexpected_changes: []`, **`clear: false`** with `error: "cr_stop: not clear — 2 finding(s) still open"`, `open_findings: 2`. Teardown kept the two state mirrors under `.coderadar/` and copied the run's state to `.archive/runs/trial_repo/state_during_run/`. |

Not exercised live: an attempt reaching stage 2 (`integrated`) — the trial window was too short for the Builder
to gate a filed attempt. The stage-2 re-base (B3) is covered by the unit check in this record and by
`solution_gate_proof.py`, which passes.
