
## 2026-11-11: intent comes from CLOSER's approved plan (prompt 3, landed by hand, no CLOSER run)
- gearbox tick: when CLOSER has an approved plan whose sha differs from the one applied, its intent and expectation
  become the statement, source "closer"; `closer_holes_<repo id>.json` carries `plan_sha256`. No plan: the launch
  purpose stands.
- `intent_file.submit_statement` takes `source` (default "developer"). `cr_intent` answers `source` and `plan_sha256`.
- Setup page: the purpose box stays, labelled "optional; a CLOSER plan replaces it".
- DONE 2026-11-11: the artifact scanner's intent facts were written into the intent file by
  no_aivalidator/NOAI_VALIDATOR_DAEMON.py (the `_intent.replace_source_facts(repo, [... report.intent_facts])` call
  after the artifact scan, line ~1101). Under this ruling the statement is the plan and its facts come from
  submit_statement, so that write was redundant. Deleted from `run_baseline(self, repo_path)`: the try block around
  the call (its `system_scripts` sys.path insert, the `intent_file` import, the warning) and the
  `intent sources N · facts N` fragment of the ARTIFACTS progress line. The artifact scan itself (stubs, config
  values, the published artifact_report) stays; `intent_file.replace_source_facts` itself stays (health_check uses
  it). Check: `run_baseline`'s source no longer contains `replace_source_facts`. `coderadar_mcp.read_tools_proof`: PASS.
