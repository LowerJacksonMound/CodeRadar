# CodeRadar code review — 2026-10-23

The copy is [NEW_CODE_RADAR_REFURBISH](https://drive.google.com/drive/folders/1HbzHiks10PmGP10vEjnbT7zuMYUrhNN6). This pass did not change it.

Read from the start call through the stop call: `coderadar_mcp/server.py`, `session_tools.py`, `write_tools.py` (the apply and submit ends), `system_scripts/scan_scope.py`, `system_scripts/entry_point_wrapper.py`, and the folder as it sits. The daemon bodies (`circuit_daemon.py`, `health_check.py`, `gearbox.py`) were not read line by line. Where a finding depends on one of those, it says so.

**A live trial cannot be started from this folder.** The rest would still make the next trial harder after the start script is put back. Nothing below was fixed in this pass.

## How a trial starts, what it reads, what it writes

`cr_watch` (`coderadar_mcp/session_tools.py`, `LAUNCH_SH` and the `Popen` in `cr_watch`) runs `launch.sh` at the tree root:

`launch.sh <target> --tracer lsof --trackers io,mypy`

It then waits on that process's log for `ALL GATES PASSED`, or for an abort line, or for the process to exit. The wait is the gate budget: 2190 seconds plus 2 seconds per `.py` file, capped at 2970. On success it copies state into `.archive/runs/<name>/` and takes a snapshot under `~/CodeRadar_snapshots`.

It reads, once the stack is up, `system_scripts/BUILDER_STATE.json`, `circuit_state.json`, the noai state, and the two mirrors. It writes the run dir, `gearbox.pid`, and the launch log. The daemons write the mirrors under the target at `.coderadar/`. `cr_apply` writes an apply-lease line beside the channel, not the target. `cr_submit` appends an attempt line. `cr_report_outcome` appends the return channel. `cr_stop` writes md5 listings into the run dir and deletes `gearbox.pid`.

`cr_attach` starts nothing. It binds to whatever `BUILDER_STATE.json` already names, and only if both phases say MONITORING and the dashboard answers.

### 1. The start script is not in this folder

**Where:** `coderadar_mcp/session_tools.py`, `LAUNCH_SH = PROJECT_ROOT / "launch.sh"`, exec'd from `cr_watch`. The README also starts from `coderadar-mcp.sh` and `run_proof.sh` at that same root.

**What it does:** The folder listing of `NEW_CODE_RADAR_REFURBISH` is the packages (`coderadar_mcp`, `system_scripts`, `rca_main`, and the rest) and a `.DS_Store`. There is no `launch.sh`, no `coderadar-mcp.sh`, and no `run_proof.sh`. Other copies of those names exist elsewhere on Drive. They are not where this tree looks.

**Trial:** Blocks. `cr_watch` cannot launch. A hand start of `launch.sh` cannot be done from this copy.

### 2. This folder still holds the last trial's state

**Where:** `system_scripts/BUILDER_STATE.json`, `circuit_state.json`, `.monitor_state.json`, `.noai_state.json`, `gate_9e25ddf5e68e.jsonl`, `attempts_9e25ddf5e68e.jsonl`, `.intent_9e25ddf5e68e.lock`. Modified 2026-10-10.

**What it does:** `cr_attach` and `cr_stop` trust `BUILDER_STATE.json` for which repo is live. The comments say `launch.sh` deletes that file before a new start. The script that would delete it is the one missing above. Anything that reads these files is reading repo `9e25ddf5e68e` from 10 October.

**Trial:** Blocks a clean trial from this copy, together with finding 1. After `launch.sh` is restored, leaving these files in the tree still makes a trial harder: a start that skips the preflight attaches to the old repo.

## From a file on disk to a finding, and from a finding to a change

The scan surface is `system_scripts/scan_scope.py`. `walk` (the function that returns every `.py` not excluded) is what the daemons are written against. A file becomes a row in the Builder state. The seat reads it with `cr_infractions` / `cr_row`.

Two ways a row becomes a change, both registered at the bottom of `coderadar_mcp/write_tools.py`:

- `cr_apply` builds a diff from the live span and writes nothing in the target. The header of that file says the client applies it.
- `cr_submit` checks that the attempt parses, is a function, and is not the broken code unchanged, then appends it to an attempts file. It does not edit the target. `server.py` tells the seat that CodeRadar then gates the attempt and applies it. `cr_stop` treats a ledger row whose attempt status is `integrated` as a write the gate itself made.

`cr_report_outcome` is a third write, and it only appends a verdict line. The Builder is supposed to poll that file. There is no trigger.

### 3. Two apply paths

**Where:** `write_tools.py` module docstring (`cr_apply` writes nothing; the client edits) and `cr_submit` at the end of the same file. `server.py` instructions tell the seat to `cr_submit` and say CodeRadar applies it. `session_tools.py` `cr_stop`, the block dated 2026-10-10, counts an integrated attempt as `gate_writes`.

**What it does:** A seat that follows the server text files an attempt and does not edit. A seat that follows the `cr_apply` contract edits the diff itself. A seat that does both changes the file twice. A seat that waits for an integration that the Builder does not perform (this pass did not read the Builder loop that would do that write) changes nothing, and the row stays.

**Trial:** Makes a live trial harder. It does not stop the stack from starting. It is how a finding is missed or applied twice.

### 4. The row's recorded lines are not the lines to edit

**Where:** `write_tools.py` docstring, the drift section. The payload carries `replace_span` (what the Builder stored) and `replace_span_live` (the function's span read off the file now). `cr_report_outcome` joins on digest and `replace_span`.

**What it does:** The id is `file::function::line`. Any edit above the row moves it. The lease remembers the id the seat was given. The diff is re-based onto the live span. The recorded span is still in the payload, and the channel still joins on it. A client that patches `replace_span` writes the wrong lines. That already happened once (the README cites run 162: recorded L804–L868, live L802–L869).

**Trial:** Makes a live trial harder. The wrong-file edit is still one field away.

### 5. Findings are a page the seat has to finish

**Where:** `coderadar_mcp/README.md` and `server.py` `INSTRUCTIONS`, describing `cr_infractions`.

**What it does:** Rows are paged. There is no `has_more`. `pages` is not `total / page_size`, because a page never splits a file. Stopping when a missing flag is false returns page 1 of however many there are. Withheld rows on a real repo have run to twenty pages. Until the seat asks, the row sits in the mirror.

**Trial:** Makes a live trial harder. A finding is easy to miss. It is not pushed when the file changes.

### 6. A module that fails to load can be missing from the run proof

**Where:** `system_scripts/entry_point_wrapper.py`, `sweep_loaded_modules`. `cr_run_module` is what runs a target through this wrapper.

**What it does:** Imports are recorded by sweeping `sys.modules`, not by wrapping `__import__`. A module that fails to load is dropped from `sys.modules`. It is recorded only if a sweep happened to run while it was still loading. The comment in the file says that. The static walk (`scan_scope.py`) is a different set: a file on disk can be a finding, and a file the run actually loaded can be absent from `entry_point_info.json`.

**Trial:** Makes a live trial harder. The "what executed" proof and the "what is on disk" proof can disagree, and a finding can be pinned to the wrong one.

### 7. A dot-directory is in the scan unless it looks like an env

**Where:** `system_scripts/scan_scope.py`, `excluded` and `hard_skipped`.

**What it does:** The only names always skipped are `__pycache__`, `.git`, `.cr_pycache`, and the mirror dir `.coderadar` at the target root. A dot-directory is scanned unless the whitelist names it, or the directory has the shape of a virtualenv or `site-packages`. A `.venv` without `pyvenv.cfg` is source, by the comment on the skip list. Findings from that tree are findings on the wrong files.

**Trial:** Makes a live trial harder. It does not stop a small clean repo.

### 8. An unparsable file stops the launch, unless it matches a fixture pattern

**Where:** `scan_scope.py`, `syntax_fixture`.

**What it does:** A `.py` file shipped so that it will not parse stays in the scan, but its syntax break is reported as a fixture and does not fail the wiring gate. Any other file that does not parse stops the launch and names the node. Patterns come from `system_scripts/syntax_fixture_patterns.json`. If that file is missing, every break is treated as real, and a warning is logged.

**Trial:** Makes a live trial harder if the target has a deliberate broken file that the pattern file does not name. It can also stop a start for a genuine syntax error, which is what the gate says it does. This pass did not read whether a file that breaks after MONITORING kills the daemon or only adds a row.

## What keeps running, or stops, where a person cannot see it

### 9. `cr_watch` can sit for most of an hour with the stack already up

**Where:** `session_tools.py`, the wait loop in `cr_watch`.

**What it does:** The call returns only when the log contains `ALL GATES PASSED` and both phases then read MONITORING, or the budget expires, or the launch process dies, or a stop-line matches. If the gates pass and the phase files never say MONITORING, the daemons are left running and the call returns an error at the end of the budget. The person sees that only when the call returns. `cr_stop` is the thing that will still see those processes.

**Trial:** Makes a live trial harder. The failure is named, but not until the budget is gone, and the processes are still up.

### 10. Stop does not look at open findings

**Where:** `session_tools.py`, `cr_stop`.

**What it does:** It signals the launcher (or, if there is no `gearbox.pid`, every daemon whose command line matches `gearbox.py|circuit_daemon.py|NOAI_VALIDATOR_DAEMON|BUILDER_DAEMON|proof_dashboard.py|launch_setup.py`). It then reads the teardown log for `residue_clean` and compares `md5 -r` of the snapshot to `md5 -r` of the target. Differences are `client_edits`, `gate_writes`, or `unexpected_changes`. The mirrors are excluded on purpose and listed as `mirrors_kept`.

Nothing in that function reads whether a row is still open. A stop with counterfeits still in the mirrors is a successful stop if the processes died and `unexpected_changes` is empty.

If no teardown log is found, residue is reported as not measured, not as a failure. If no snapshot exists under `~/CodeRadar_snapshots`, the byte check is skipped and an error string is set, and `stopped` can still be true.

The hash command is `md5 -r` (`session_tools.py`, the `verify_identity` block). That is the Mac `md5`. A trial not on a Mac cannot run this check. `snapshot_files.sh` is the file list; it is referenced next to `system_scripts` and was not in the root listing either.

**Trial:** Blocks the run this session described, where stop must say that a problem is still open. For a trial whose only done-check is "processes died and bytes match," it does not block, and it will hide an open finding.

### 11. A tool that is listed but not bound fails in one sentence

**Where:** `server.py`, `call`.

**What it does:** The client is shown every tool in `tool_interface.TOOLS`. A name no module registered returns `not implemented in this lane` plus which file was supposed to bind it. `cr_submit` is registered. This branch is what a seat hits for any other name that was declared and not bound. This pass did not diff the 14 declared names against `HANDLERS`.

**Trial:** Makes a live trial harder if a declared tool is unbound. The error is visible. It is not a silent skip.

## Dead paths, trial-only switches, checks that do not match the claim

### 12. `cr_apply` and the server instructions disagree about who writes

This is finding 3, restated as a claim mismatch. The write-tools header says the client writes and CodeRadar does not edit the repo. The server instructions, and the stop path's `gate_writes`, say the Builder writes an integrated repair and the client edits nothing. Both texts are in this copy. A trial brief that quotes one of them is wrong about the other.

**Trial:** Makes a live trial harder. Same as finding 3.

### 13. The execution wrapper's own comment limits what the proof can claim

**Where:** `entry_point_wrapper.py`, the note above `sweep_loaded_modules`, and `is_workspace_file`.

**What it does:** The proof claims the files the run loaded. It records a `.py` file only when the path does not contain `site-packages` or `lib/python` and does not start with `/usr/lib` or `/System`, and only when it is under `CODERADAR_TARGET` (or the entry script's directory). A file the target loaded from anywhere else is dropped. Combined with finding 6, "what the run executed" is smaller than what executed.

The wrapper also `exec`s the target. The file's own security note says it should only be pointed at a trusted script.

**Trial:** Makes a live trial harder when the brief treats `entry_point_info.json` as the full set of files the run touched.

### 14. Trackers a trial might think are always on are not

**Where:** `session_tools.py`, `cr_watch`. The README table of refusals.

**What it does:** The tracer must be `lsof`. `eslogger` is refused (it needs root and a terminal). Trackers must be drawn from `io,mypy,crc,vulture`. The default is `io,mypy`. `naming_drift` is not in that choice; the README says it runs on every launch anyway and reads `NOT MEASURED` until its scan finishes. `crc` and `vulture` do not run unless the seat names them. A trial that expects every checker from the design spec, and calls `cr_watch` with the defaults, does not get them.

**Trial:** Makes a live trial harder. Easy to read a quiet tracker as a clean tree.

## What would have to be true before the next trial

1. `launch.sh`, `coderadar-mcp.sh`, `run_proof.sh`, and `snapshot_files.sh` are in this tree where the tools look, and the 2026-10-10 state files are not what a new start reads.
2. One apply path. Either the client applies `cr_apply` and the Builder does not, or `cr_submit` is the only way in and `cr_apply` cannot also be used on the same row.
3. The seat's instructions and the code agree on that path, including which span field is safe to patch.
4. Stop reports rows still open, and does not come back clean while one is.
5. Someone has decided what `entry_point_info.json` is allowed to omit, and the trial does not treat a missing file there as "the run did not touch it."
