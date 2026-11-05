# seven_cities_of_gold — run 187, FIX-A lane, MOUNTED SEAT (run of record), copy3 (2026-09-28)
Target: `git clone --depth 1 https://github.com/benjaminp/six ~/Desktop/seven_cities_of_gold` @ c8e3940 (the run-177 repo).
Mount: path-first, scratch mcp-config = `install_coderadar_mcp.sh --print` equivalent (stdio → copy3 `coderadar-mcp.sh`,
timeout 3000000), `claude -p` from the target dir, `--strict-mcp-config --allowedTools "mcp__coderadar,mcp__coderadar__*,Edit,Read,Write"
--disallowedTools Bash`; first prompt line = the path. No --dangerously-skip-permissions; ~/.claude.json and settings untouched.
Driver files: `seat/` (seat.sh, cr_mcp.json, prompt.txt, sid, pre_md5.txt, seat.jsonl, seat.times). Wall 16:44:32 → 16:48:09, exit 0, 18 turns.
Seat calls: cr_watch, cr_status, cr_infractions, cr_run_module(pytest), Read, cr_report_outcome ×2, cr_run_module(six.py),
cr_data_types ×2, cr_hand_back, cr_run_module(pytest), cr_stop (plus built-in read-only Grep/Glob/ToolSearch). No cr_apply, no Edit/Write.
cr_infractions: total 47, 1 page — apply yes 0 · review 2 · no 45. The review rows are rows 0 and 1 of the page:
  six.py::_resolve::164 and six.py::exec_module::239, both solution_kind prescribed, apply_reason "template only — no diff rendered at this site".
In-run mirror: repairs 2 (both apply "review", prescribed) + no_vetted_fix 45 = failed 47. Teardown mirror: 0 + 47 = 47. Identity holds both times.
Seat: read both sites, judged both false positives, applied neither, reported both `failed` with note "Not applied — false positive".
Suite: pytest 182 passed / 16 skipped before and after (exit 0 both). cr_stop error null, stopped true, all four processes exited.
Target byte-identical to pre_md5 outside `.coderadar/` (45 files); teardown_diff = the four .coderadar mirrors only. pyc_verdict polluted=no, suite_reading clean.
Trackers line at cr_stop: "mypy: measured, import_errors 8, total_errors 77 in 2/4 files · io: measured, 187 functions, io_functions 0,
exempt 187 · wiring: live 3 of 0" — "live 3 of 0" and the seat's mypy 77-vs-516 remark are filed as candidate misses in FPA_REPORT.
