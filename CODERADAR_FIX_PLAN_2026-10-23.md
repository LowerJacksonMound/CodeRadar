# CodeRadar fix plan — 2026-10-23

Addresses every finding in [CODERADAR_CODE_REVIEW_2026-10-23.md](https://drive.google.com/file/d/1J0J_6k1ZKE61Z2T0JrdIRgzrp8qDhJmb/view). No code in this pass.

The copy is [NEW_CODE_RADAR_REFURBISH](https://drive.google.com/drive/folders/1HbzHiks10PmGP10vEjnbT7zuMYUrhNN6). Work stays in that folder. Cartouche and Closer are out of this plan.

One decision, taken from the code already in the folder (server instructions, 2026-10-08; `cr_stop` gate writes, 2026-10-10): **CodeRadar is the only writer.** A finding is fixed by `cr_submit`. The Builder integrates it and writes the file. `cr_apply` may show the diff. It must not be a second way to change the file. If that decision is wrong, say so before pass B. Pass A does not depend on it.

Order is the order a trial needs. Do not start B until A is true on this folder.

## Pass A — this folder can start

Findings 1 and 2, and the missing `snapshot_files.sh` from finding 10.

**A1. Put the start scripts where `cr_watch` looks.**
`coderadar_mcp/session_tools.py` sets `LAUNCH_SH` to `launch.sh` beside `coderadar_mcp`. The same root is where `coderadar-mcp.sh`, `run_proof.sh`, and `system_scripts/snapshot_files.sh` are supposed to be. They are not in this folder. Other copies exist on Drive. Take the 2026-10-10 `launch.sh` (72004 bytes) and the `run_proof.sh` from the same day, not an older duplicate. Confirm each script's paths match this tree before copying them in.

Done when `cr_watch` can exec `launch.sh` from this folder, and `cr_stop`'s identity check can exec `snapshot_files.sh`.

**A2. Get the last trial out of the tree.**
Move these out of `system_scripts/` into a dated archive folder that no daemon reads:

- `BUILDER_STATE.json`
- `circuit_state.json`
- `.monitor_state.json`
- `.noai_state.json`
- `gate_9e25ddf5e68e.jsonl`
- `attempts_9e25ddf5e68e.jsonl`
- `.intent_9e25ddf5e68e.lock`
- `BUILDER_STATE.heartbeat.json`
- `cb_writes_9e25ddf5e68e.json`
- `gate_baseline_9e25ddf5e68e.json`

`launch.sh` must still delete `BUILDER_STATE.json` before a new start. After A2, a start that skips that preflight has nothing to attach to. `cr_attach` on a clean tree says nothing is running.

Done when a fresh listing of `system_scripts/` has no `9e25ddf5e68e` state, and `cr_attach` with no live process refuses.

## Pass B — one change, on the right lines

Findings 3, 4, and 12. Same bug: two texts tell the seat to write, and the lines they name can be the stale ones.

**B1. Confirm the Builder is the writer.**
`cr_submit` in `coderadar_mcp/write_tools.py` only appends an attempt. It does not edit the target. The server text says the Builder then applies it. Read `BUILDER_DAEMON.py` (the 2026-10-10 copy, 159154 bytes) for the path from an attempt to a write and to ledger status `integrated`.

- If that write exists, name the function in a comment at `cr_submit` and leave the behavior.
- If it does not exist, that is the hole. The Builder has to write the integrated function into the live span (`replace_span_live`), once, and set `integrated`. Until that exists, a trial that only calls `cr_submit` fixes nothing.

**B2. Close the other door.**
`cr_apply` stays a read. It returns the diff and the lease, and the payload says `write: false`. It refuses, with a sentence, if this row already has an attempt, and `cr_submit` refuses if a lease for the same row was handed out as something to apply by hand. One row, one writer.

Delete the sentence in the `write_tools.py` header that says the client applies the edit. Make `coderadar_mcp/server.py` instructions, `coderadar_mcp/README.md`, and the `cr_stop` comment say the same thing: CodeRadar writes; the seat does not.

**B3. The span a write uses is the live one.**
The join key may keep `replace_span`. Nothing that writes may use it as the edit range. The Builder write from B1, and the diff from `cr_apply`, both use `replace_span_live`. If `span_current` is false, the payload says the recorded lines are stale and names the live ones. If `replace_span_live` cannot be read, the write is refused. It is not guessed from the recorded span.

Done when one planted bad function, submitted once, changes once, on the lines the function occupies now, and a second `cr_apply` on that row does not offer a hand edit.

## Pass C — a finding cannot sit where the trial will not see it

Findings 5, 6, 7, 13, and 14.

**C1. `cr_status` carries the open count.**
Paging stays. The miss is a seat that stops after page 1. `cr_status` gains `open_findings` (rows still unresolved) and `pages` for `cr_infractions`, taken from the same mirror. `cr_infractions` gains `done: true` only when `page == pages`. The server instructions tell the seat to read `open_findings` before anything else, and to stop paging only when `done` is true. Absence of `has_more` stays. `done` is the field that replaces the guess.

A new row also has to be visible without a poll being remembered. The smallest push that matches this tree: the monitor mirror gains `open_findings`, and the dashboard (already up during a trial) shows that number. No new channel.

**C2. The run proof says what it did not record.**
In `system_scripts/entry_point_wrapper.py`, a module that fails to load is recorded if a sweep runs while it is in `sys.modules`. Also record the failure itself: when `find_spec` sees a module that then disappears before the next sweep, append it under `failed_imports` in `entry_point_info.json`. Do not put it in `imported_files`.

Add `omitted` to that JSON: files seen and dropped because they were outside `CODERADAR_TARGET`, or under `site-packages`, `lib/python`, `/usr/lib`, or `/System`. A trial that treats a missing path as "the run did not touch it" is then reading a lie the file itself contradicts.

**C3. Say which dot-directories were scanned.**
`scan_scope.py` skips an env by shape, and skips `__pycache__`, `.git`, `.cr_pycache`, and `.coderadar`. A `.venv` or `venv` with no `pyvenv.cfg` is still scanned. Skip those two names, and `node_modules`, the same way `.git` is skipped. At the end of launch, write the list of any other dot-directory that remained in scope into the launch log and into `cr_status`. A trial can see a vendored tree before it reads findings from it.

**C4. Trackers that did not run are not a zero.**
`cr_watch` defaults to `io,mypy`. `crc` and `vulture` do not run unless named. `naming_drift` runs on its own and stays `NOT MEASURED` until its scan finishes. Put `trackers_ran`, `trackers_not_requested`, and the naming-drift status on the `cr_watch` result and on `cr_status`. `NOT MEASURED` must not be printable as `0`.

## Pass D — stop, and a stall, say what happened

Findings 8, 9, 10, and 11.

**D1. A syntax error after MONITORING is a finding, not a dead stack.**
`scan_scope.syntax_fixture` already lets a known fixture fail to parse without failing the launch. Any other unparsable file fails the launch. Keep that for the start gate.

Read `circuit_daemon.py` for what happens when a file stops parsing after the stack is in MONITORING. If the daemon exits, change that path so the process stays up and the file is a row the seat can see (`SYNTAX_BROKEN`, file, line). A fixture pattern match stays a fixture, not a row. This is the one read the code review left open. Do it before changing the behavior.

**D2. Do not burn the whole budget after the gates have already passed.**
In `cr_watch`, once the log contains `ALL GATES PASSED`, wait for both phases to read MONITORING. If they do not within a short bound (two minutes, not the rest of the gate budget), return the error that is already written — phase unpublished, daemons still running — and name `cr_stop` as the next call. If `launch.sh` itself exits or prints an abort line, return on that iteration, as the loop already does.

**D3. `cr_stop` is not clean while a finding is open.**
After the process check, read the mirrors that `cr_stop` already keeps. Add `open_findings` to the result. If that count is not zero, set `error` and do not leave the result looking successful: `stopped` may still be true (the processes died), but add `clear: false`. `clear: true` only when the processes are gone, `unexpected_changes` is empty, and `open_findings` is zero.

If the teardown log is missing, residue stays "not measured" and `clear` is false. If no snapshot exists, `byte_identical` stays null and `clear` is false. Same if `md5` or `snapshot_files.sh` cannot be run. A Mac trial keeps `md5 -r`. A failed hash command must not look like a match.

**D4. Every tool the client is shown is bound.**
Diff `tool_interface.TOOLS` against `HANDLERS` after the lane imports in `server.py`. The review left this uncounted. `cr_submit` is bound. For any name that is not: remove it from `TOOLS`, or bind it. Do not leave a listed tool that answers `not implemented in this lane`. The branch in `server.call` can stay for a name that is not on the list.

## Proof, once

On a Mac, from this folder, against a tiny repo with one planted hollow function:

1. `cr_attach` before start refuses. No `9e25ddf5e68e` file is read.
2. `cr_watch` reaches MONITORING, and the result lists `io` and `mypy` as ran and `crc` and `vulture` as not requested.
3. `cr_status` shows `open_findings` of at least 1 without paging.
4. `cr_submit` once. The file changes once, on the live span. `cr_apply` on that row does not offer a hand edit.
5. Break the file's syntax while the stack is up. The daemon is still alive. The row names the file.
6. `cr_stop` before the fix is integrated returns `clear: false` and a non-zero open count.
7. After it is integrated, `cr_stop` returns `clear: true`.

That proof is the end of the plan. A trial of a real repo waits on it.

## What this plan does not do

- It does not change Cartouche or Closer.
- It does not add a tracker, a rule, or a new tool.
- It does not make `eslogger` work. `lsof` stays the only tracer.
- It does not re-page infractions. It makes the open count visible so a short page is not the whole answer.
