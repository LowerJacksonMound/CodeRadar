# `coderadar_mcp` — CodeRadar's MCP server

The release form (owner, 2026-09-16; the release-form packet, not shipped).
CodeRadar already publishes everything an agent needs on every run — the counterfeit-code mirror, the dash
mirror `.monitor_state.json`, `BUILDER_STATE.json`, the withheld block, the intent file, the return channel,
the tester report, the health port. This package puts **13 tools** over those files so that **whatever agent
the dev already runs** — Claude Code, Cursor, anything that speaks MCP — is the seat. No editor extension is
built and no new agent is built: the three P4 seats (vis-graph, replacement, tester) collapse into one client
holding `cr_wiring`, `cr_apply`, and `cr_run_module` + `cr_report_outcome`.

One local **stdio** process, no network port beyond the dash's own (Q1). **Registered once, path-first
(R1, 2026-09-28):** the server starts with **no target**; the first `cr_watch(target)` names the repo.
**CodeRadar is the only writer of the repo's code during a run** (fix plan 2026-10-23, pass B): an integrated `cr_submit`
attempt is written by the Builder at the function's live span, once; the seat edits nothing. It writes no `.mcp.json` there. Beyond that, the only files it writes in the repo are its two
state mirrors, `.noai_state.json` (the counterfeit half of the dash) and `.monitor_state.json` (the non-counterfeit half), one pair per directory as it comes into view, **all under one dir at the repo root,
path-mirrored**: `.coderadar/<same/sub/path>/` (the root's pair at `.coderadar/`). They **persist after
`cr_stop`** as a log of the run (owner rulings 2026-09-28) and are reported by `cr_stop` as `mirrors_kept`,
never as residue. `.coderadar/` is never scanned. The location is defined once, in `system_scripts/scan_scope.py`
(`MIRROR_DIR`, `mirror_path`, `mirror_files`, `is_mirror_path`).

## Mount in Claude Code — once

```bash
bash install_coderadar_mcp.sh           # from the CodeRadar tree root
bash install_coderadar_mcp.sh --print   # show the command, change nothing
```

The script runs one `claude mcp add-json --scope user coderadar …` naming this tree's `coderadar-mcp.sh`
(by absolute path, no arguments) and a per-server tool timeout of **3000000 ms** (50 min). After that, in
**any** directory:

```
/mcp__coderadar__scan ~/code/myrepo        # the MCP prompt `scan`, one argument `path` (Q9)
scan ~/code/myrepo                         # plain language works too — the server instructions say how
```

The registered entry, as Claude Code stores it:

```json
{ "type": "stdio", "command": "/path/to/coderadar/coderadar-mcp.sh", "args": [], "timeout": 3000000 }
```

**The timeout, verified on Claude Code 2.1.284 (run 177):** `claude mcp add` has no timeout flag, but a
server entry's `"timeout"` (milliseconds) is honoured and overrides `MCP_TOOL_TIMEOUT` for that server only
— a 12 s test tool under `"timeout": 3000` was cut off with *"timed out after 3s"*; the same tool with no
timeout returned. `claude mcp get coderadar` shows `Timeout: 3000000ms`. It matters because `cr_watch`
**blocks until every gate passes or its budget runs out**, and the budget is derived from the gate timeouts
(`session_tools._gate_budget` over `gearbox.py`'s constants: health 900 + circuit 120 + noai min(120 + 2·n_py, 900)
+ builder cap 900 + dashboard 30 + slack 120): **2190 s + 2 s per .py file, capped at 2970 s — 36.5 to 49.5 min**,
published in the answer as `gate_budget_s`. 50 min covers the cap; a small repo returns in a few minutes.
On an older client that ignores the key, launch it as `MCP_TOOL_TIMEOUT=3000000 claude`. If a call is cut off
anyway (or the seat is new), `cr_attach(target)` binds to the stack once it is MONITORING — do not ask `cr_status`
first, it answers "no target" until the seat is bound.

Other MCP clients: the same entry — command `coderadar-mcp.sh`, no arguments, and the longest tool timeout
the client allows.

### What the server refuses, in one sentence each

| call | answer |
|---|---|
| any tool but `cr_watch`/`cr_attach` before a target is bound | `no target — call cr_watch with the repo path` |
| `cr_watch` on a missing directory | `no such target directory: <path> (resolved to …)` |
| `cr_watch` on a directory with zero `.py` files in the scan scope | `<path> holds zero .py files …` |
| `cr_watch` on CodeRadar's own tree, or anything inside it | `<path> is CodeRadar's own tree (or inside it) …` |
| `cr_watch` on a second, different target while one is live | `this CodeRadar is already watching <A> — call cr_stop first` (Q3) |
| `cr_watch` on the same target again while it is live | not refused — it attaches (`started: false`) |
| `cr_watch` / `cr_attach` while this tree's launch setup page is open on the dash port (no target chosen yet) | `the launch setup page is open on the dash port — no target chosen yet (launch.sh is waiting for Start) — choose the target on the page and cr_attach it once MONITORING, or cr_stop first (the page closes, nothing ran)` (D2 / Q-H1-10; the page server is selected by its process, `launch_setup.py --port …` with cwd = this tree — never its `--emit-shell` / `--submit-purpose` helpers, never a shell whose command line merely names the file) |
| `cr_watch` when the dash or health port is held by anything else | `the dashboard port 8081 is in use by pid N (cmd) …` (B9 / Q4; no auto-port) |
| `tracer` other than `lsof` | refused by the schema (`enum: ["lsof"]`) — eslogger needs root and a TTY (B6) |
| `trackers` outside `io,mypy,crc,vulture` | refused; the default is `io,mypy` (B6). `naming_drift` is permanent — it runs on every launch and is not a choice (`cr_data_types` lists it under `chosen` always, NOT MEASURED until the launch scan has completed) |

`~` expands. A relative path resolves against the MCP server's working directory — the directory the client
was started in (Claude Code: where `claude` was run), not the shell the dev types in; `coderadar-mcp.sh` never
`cd`s. The refusal echoes the absolute path it resolved to (`no such target directory: relative/x (resolved to
/…/relative/x)`). Give an absolute path.

### What the client is told (server `instructions`, B4 + B5)

Every fact trial briefs used to hand-feed now rides in the MCP `instructions` the client reads at connect
(`server.INSTRUCTIONS`): `cr_watch` blocks up to its gate budget (2190 s + 2 s per .py file, cap 2970 s — 36.5–49.5 min; a new seat calls `cr_attach(target)` directly, never `cr_status` first); the seat writes each repair as a whole function and files it with `cr_submit`; the Builder gates it and writes it into the target (`gate_writes` at `cr_stop`) — the seat never edits the target (every other write — run dir, lease, channel, ledger, entry-point-runner state — is named per tool in the table below);
`cr_apply` is a READ (`write: false`) that shows the engine's candidate diff and is never applied by hand; `cr_status` carries `open_findings` / `infraction_pages` / `trackers_ran` / `trackers_not_requested` / `naming_drift` / `dot_dirs_scanned`; `cr_infractions` pages by
`page / pages / total` and answers `done` on the last page; `cr_stop` answers `open_findings` and `clear` (false while any finding is open or anything was NOT MEASURED); lay the entry-point proof with `cr_run_module` BEFORE any `-m pytest` and AGAIN
after the apply pass (I-180); a repeated reading of a row is taken before that row is applied (I-177);
outcomes via `cr_report_outcome` `confirmed|failed`; at the end call cr_stop() then cr_hand_back(). So the
dev's prompt can be just the path.

### Mounting a trial seat without touching the user config

A lane or a trial never runs the install script against the owner's config. It mounts per-session:

```bash
cat > /tmp/cr_mcp.json <<'JSON'
{ "mcpServers": { "coderadar": { "type": "stdio",
  "command": "/path/to/coderadar/coderadar-mcp.sh", "args": [], "timeout": 3000000 } } }
JSON
cd ~/code/myrepo
claude -p "$HOME/code/myrepo" --mcp-config /tmp/cr_mcp.json --strict-mcp-config \
  --allowedTools "mcp__coderadar,mcp__coderadar__*,Edit,Read,Write" --disallowedTools Bash
```

`--allowedTools` is not a sandbox: a tool the user's own settings allow stays usable. Seats pass
`--disallowedTools Bash` — run 177's seat ran `git status` through Bash, which rewrote `.git/index`, the only
byte-identity difference that run had.

`--target` is still accepted by `server.main` as an optional pre-bind (the offline proofs use it, and an
old per-target config keeps working); with it, the server answers about that target from the start.

## The 13 tools

| tool | input | contract |
|---|---|---|
| `cr_watch` | target, trackers?, tracer?, gate_budget_s? | Launch the gearbox on `target` with the same gates as `run_proof.sh up`; return when ALL GATES PASSED or the budget expires (`gate_budget_s`: 2190 s + 2 s per .py file, cap 2970 s). Never edits the target's code; the stack it spawns writes only the two state mirrors under the target's `.coderadar/`. |
| `cr_attach` | target? | Bind to a target already under MONITORING in this tree; reads only, starts nothing. |
| `cr_stop` | verify_identity?, mark_pool?, expected_changes? | Teardown: SIGTERM this tree's daemons — the four, the gearbox, and a launch setup page left open on the dash port (`launch_setup.py --port …`; it closes, nothing ran) — prove residue zero and the target byte-identical to its snapshot (`run_proof.sh down` semantics). |
| `cr_status` | — | Phase, gates, the band (cadence · restarts · runners), health, and `finished` — the one question the dev asks between edits. Its `detail` line quotes `confirmed_from_ledger` (I-149); the daemon's own sentence is beside it as `detail_builder`. |
| `cr_infractions` | file?, rule?, withheld?, has_solution?, page?, page_size? | The rows, paged by file at 50 rows a page (Q9); a page never splits a file. Withheld rows ride here too (FIX_51) and never carry a solution. Every row carries `replace_span_live` + `span_current` (I-148 a) and the apply state `apply` / `selected_role` / `withheld_by` (I-152), plus the additive `rule_id` / `variant` (ND2). The naming-drift tracker's groups ride here as rows too — `rule_id` `NAMING_DRIFT`, tier in `variant`, `apply` "no" (the developer renames) — and `naming_drift_status` says NOT MEASURED before the launch scan has completed. |
| `cr_row` | id | One row in full, verbatim as the Builder published it — candidates offered, scores, `decision.why`, observations, dispositions, evidence. |
| `cr_wiring` | include_dataflows?, state? | Nodes and edges with state `possible` / `live` / `severed` (Q7) + `severed_since`, plus runners and data flows (Item 10). |
| `cr_data_types` | tracker? | The trackers' state for the target (io, mypy, crc, vulture, and naming_drift — the permanent one, chosen on every run; its block is `naming_drift` {status, ran, groups, new, pre_existing, by_tier, accepted, rows}, NOT MEASURED until the launch scan has completed, never 0) and the one number `finished` reads as data-type issues, with `issues_scope`: every mypy `: error:` line incl. `--strict` annotation notes, less suppressed — NOT `mypy.total_errors` (real type errors only). On six (run 187) these read 516 and 77; both are right, they count different things (M-20). The `trackers` line on cr_hand_back/cr_stop names both, and reads wiring as `live N of M edges` over every edge (M-19). |
| `cr_intent` | — | The dev's derived intent — the profile facts the Ranker reads — verbatim from the intent file. |
| `cr_apply` | row, context_lines? | A READ (`write: false`, fix plan 2026-10-23 B2): show the engine's candidate edit — a unified diff from a rewriter's `after_code` rendered at the function's LIVE span, or a shape + placeholders for a prescription (Q8, I-75) — and WRITE NOTHING TO THE TARGET (Q3). It is not applied by hand: a row with a `cr_submit` attempt on file answers `error`, and a function that cannot be located live is not rendered against its recorded span. One **apply lease** is recorded beside the channel. |
| `cr_run_module` | path, args?, as_module?, timeout_s? | Run the target's script or runner THROUGH `entry_point_wrapper.py`, so the run shows on the band and I-53 / I-55 apply. |
| `cr_report_outcome` | row, outcome, note?, tester? | THE ONE WRITE: append one Item-5 line to the return channel; the Builder polls it next cycle, joins on digest AND replace_span, and the Ranker re-decides. The target is never touched. Resolves the row against the live mirror, then against the **apply lease**. |
| `cr_hand_back` | note? | Publish the tester report and the finished state (B8-1 / B7-5); the client's working tree IS the repaired copy, so nothing is archived here. |

Payload facts a client gets wrong exactly once (each one measured on a live seat):

- **`cr_apply` hands back a MULTI-HUNK unified diff and no `before_code` / `after_code`.** The
  payload's `diff` is `difflib.unified_diff(...)` at `context_lines` (default 3), so a change with
  more than six unchanged lines between its parts comes back as two or more `@@` hunks, and the
  output schema carries neither the before text nor the after text. **Apply it hunk-accurately.**
  Reconstructing the span by keeping the `+` and space lines of the whole diff silently drops
  every line the hunks skip — the file is then written short, and on a src-layout target that is a
  collection error, not a test failure.
- **`cr_infractions` paginates with `page` / `pages` / `total` — there is no `has_more`; `done` is the field (fix plan 2026-10-23 C1).** A client
  is done when `done` is true (`page >= pages`), and `cr_status.open_findings` / `infraction_pages` say up front how many rows are open and how many pages hold them; and `pages` is not `ceil(total / page_size)`: a page never splits a
  file, so page sizes vary and there are usually more pages than the arithmetic predicts. Stopping
  on a falsy `has_more` stops after page 1, having read one page of however many there are.
  **`pages` IS the field to page by — there is no `total_pages`** (I-136, built run 156). Run 155's
  198 rows came back as **5** pages sized 39 · 45 · 47 · **53** · 14: page 4 is over `page_size`
  because one file carries 53 rows and a page never splits a file. **Bound the prompt.** The
  withheld bucket is the case: 1171 rows over 20 pages, and a seat asked to quote every withheld
  row spends 20 calls and exhausts its context before it finishes — run 154's first attempt did
  exactly that and had to be killed and relaunched. Ask for a COUNT, or for one page, or for a
  filtered view (`rule=`, `file=`); never "quote every withheld row".
- **Render against `replace_span_live`, never `replace_span`** (I-148 (a), session 10). Every row of
  `cr_infractions` and every `cr_apply` answer carries **both**, plus **`span_current`**:

  | field | what it is |
  |---|---|
  | `replace_span` | the Builder's own key, as the last scan recorded it. Half the channel's join key, so it can never be dropped. It goes stale the moment anything above the row is edited. |
  | `replace_span_live` | the same function's span **read off the live file at read time**, by AST. **This is the one to render against.** |
  | `span_current` | `true` when the two name the same lines, `false` when the recorded span has drifted, `null` when no live span could be read (a `<module>` row, a file the tree no longer holds). `null` is the absence of a measurement, never a `false`. |

  Run 162 is why: `_termui_impl.py::open_url` published `replace_span` **L804-L868**, which matched
  neither the original L799-L866 nor the file on disk, beside a correct `replace_span_live`
  **L802-L869**. A client that trusted the recorded field would have rewritten 66 lines it had
  never read.
- **A row can be an honest smell with nothing to apply** (I-152, session 10). Every row carries
  **`apply`** (`"yes"` / `"review"` / `"no"`), **`apply_reason`**, **`selected_role`**, **`withheld_by`** and
  **`gate_withheld_reasons`**. `apply: "no"` with `withheld_by: "gate.prescription_check"` means the
  detector is right and there is still no offer: every candidate on the row is a prescribed *shape*
  whose placeholders only a decision can fill, so `selected_role` is `""` rather than naming one.
  **The row is still an infraction and still in its bucket** — it is not flipped to withheld, and
  `failed == repairs + no_vetted_fix` is unmoved. A seat picks rows by `apply == "yes"`; picking by
  `has_solution` alone offers it work it cannot do.
- **`apply: "yes"` means a concrete diff at the site; a template is `"review"`** (fix A, owner
  2026-09-28, run 187). Before it, a row whose selected solution was a prescribed *shape* (the
  rule's template: `solution_kind: "prescribed"`, `cr_apply` answers `kind: "shape"`, `diff: null`)
  still read `apply: "yes"`, and run 177 on `six` applied two such templates to false positives.
  Now only a row that renders a concrete diff is `"yes"`; a shape row reads **`apply: "review"`**
  with **`apply_reason: "template only — no diff rendered at this site"`**, pages after every
  `"yes"` row (inside a file too — a page still never splits a file), and is never counted as
  `"yes"`. A client must not apply it blindly: read the site, decide, or leave it. Label only — the
  row stays in `repairs`, so `failed == repairs + no_vetted_fix` is unmoved.
- **Report with the id you were GIVEN — the server now carries both** (I-145, session 10). `cr_apply`
  and `cr_report_outcome` answer with **`given_id`** (the id you passed) beside **`resolved_id`**
  (the id the server filed the lease under), and both ride on the channel line and the ledger
  record. Run 162 passed `::_pipepager::549` and every record read `::550`, so a seat reconciling
  its own log by `row_key` matched nothing. Reconcile on `given_id`.
- **`resolved_by` is a function of (id, mirror state) alone** (I-148 (c), session 10). The order is
  fixed `row → function → lease`, and it is decided before any rendering argument is read: calling
  `cr_apply` twice on one id with different `context_lines` answers the **same** word both times. If
  it changes between two calls, the MIRROR moved under you — a rescan re-keyed the row — and that
  is a fact about the run, not about the call.

## Pre-edit identity — the lease, the resolution order, the additive line fields

**The problem.** Row identity is positional (`<file>::<function>::<line>`) and so is the channel's join key
(`digest` + `replace_span`), so **the row a seat was handed drifts out from under it between `cr_apply` and
`cr_report_outcome`.** Run 155 measured it: a repaired row is retired by the Builder in roughly 30–60 s —
shorter than one 3-second suite — and 8 of 18 outcomes could not be reported at all (I-119); a
failed-then-reverted row is retired against bytes that no longer exist and the negative is lost (I-125); every
earlier edit to the same file shifts the rows below it and `cr_apply`'s hunk headers were not re-based
(I-130); a row's digest and rule ids can change between apply and report (I-138); the variant of a failed
repair dies with the re-decide (I-122); an HTML-escaped id lost every module-scope row (I-137).

**The repair (session 7).** The server remembers what it handed out, and every record it writes carries the
PRE-EDIT identity.

- **The lease.** `cr_apply` on a `repairs` row appends one record to
  `system_scripts/apply_lease_<repo_id>.jsonl` — beside the return channel, named by the channel's own rule,
  exactly as `confirmed_ledger_<repo_id>.jsonl` is. Append-only; the **last record per `row_key` wins**. The
  record is `tool_interface.APPLY_LEASE_RECORD`: `row_key · given_id · digest · replace_span ·
  replace_span_live · file · function · line · rule_ids · variant · solution_kind · before_sha256 ·
  after_sha256 · timestamp`. It is outside the target, so the Q3 guarantee below is untouched.
- **`given_id` — both ids, matched exactly** (I-145, session 10). The lease is filed under the id the server
  RESOLVED, which is the right key for the server to keep; a client holds the id it was GIVEN. The lease now
  records both, and `_lease_lookup` answers on the **resolved key first and an EXACT `given_id` second** —
  an added exact key, never a looser match (the owner's ruling: I-145 is not to be fixed by loosening lookup
  further). `given_id` rides on the channel line and in the ledger record too.
- **The resolution order** in `cr_report_outcome`, and the payload says which answered as `resolved_by`:
  1. **`row`** — the live mirror row by exact id (after `html.unescape`);
  2. **`function`** — the unique live `(file, function)` match when the exact id is not found;
  3. **`lease`** — the apply lease by exact id, used when the live row is **gone** *or* when its `digest` /
     `rule_ids` **differ from the lease's**;
  4. otherwise **refused**, with `error` naming what was tried — an id is never guessed.

  **The order is a function of (id, mirror state) alone** (I-148 (c), session 10). `_resolve_row` takes one
  argument and reads only the mirror on disk; `context_lines` — and every other rendering argument — is read
  after it returns. The same call twice answers the same word, and a word that changes between two calls is
  the mirror having moved, which the payload then says honestly.

  The channel line and the confirmed-ledger record are built from the identity the seat was **given**, never
  from a row that drifted underneath it.
- **The channel line's additive fields.** `RETURN_CHANNEL_RECORD` gains `row_key`, `rule_ids`, `variant`,
  `file`, `function`, all optional with empty defaults, so a line written by an older caller is unchanged in
  meaning and `_parse_channel_line` rejects nothing it accepted before. `BUILDER_DAEMON._join_channel` joins
  on `digest` **and** (`replace_span` exact **or** the line's `file`+`function` equal to the row's *while the
  line's `row_key` is no longer the row's key* — i.e. the row was re-keyed under it); a line naming a span its
  own unmoved row never had is still a silent orphan. `gearbox._failed_identities` and
  `BUILDER_DAEMON._rule_outcomes` read `rule_ids` and `variant` off the **line** first, the row second, and
  `"?"` only when neither has them.
- **The re-based diff.** `cr_apply` renders its diff and runs `_applies_cleanly` against the function's
  **live** span, located by AST in the file as it stands now (same `function` name; the row's `line` picks the
  nearest when the name repeats). The payload carries both `replace_span` — the Builder's key, still the
  row's — and `replace_span_live`. The channel line carries the row's recorded span.

Proof: `python -m coderadar_mcp.identity_proof` (the 15th gate of `replay_gates.sh`), seven parts, the last
of which reads run 158's own record.

## `cr_status` — the `finished` inputs (session 8, I-127 / I-128)

`finished` is the release's own completion signal: **zero infractions · zero data-type issues · zero severed
links.** Shakedown trial 1 (run 155) showed two of its three inputs broken in opposite directions — one that
a repair made *worse*, one that was never measured at all and said so in a whisper. `cr_status` now publishes
the inputs beside the verdict. Five keys, four of them new, all ADDITIVE; the 13 tools are still 13 and no
tool's parameters moved.

| key | type | what it says |
|---|---|---|
| `severed_by_repair` | int | **I-127 / Q1.** Red import edges a **leased** repair explains. `0` on a mirror written before session 8. |
| `mypy_ran` | bool | **C5.** The scan completed (rc ∈ {0, 1}). `false` is not a clean zero — it is no measurement. |
| `mypy_rc` | int \| null | **I-128 / Q2.** mypy's own returncode. `2` is a config/crash abort; `null` when no scan was attempted. |
| `mypy_files_checked` | int | **I-128 / Q2.** How many source files that scan actually checked. |
| `finished` | `true` \| `false` \| `"not measured"` | **Q2.** Tri-state. `false` is a verdict; an unread input is not one. |
| `confirmed_from_ledger` | int | **I-149 / Q8 (session 10).** Confirmations the confirmed ledger carries, counted once per (digest, replace_span) — the number `cr_hand_back` and `rule_outcomes` agree on. |
| `detail_builder` | str | **I-149 / Q8.** `BUILDER_STATE.detail` VERBATIM, so nothing the daemon said is edited away silently. |

- **`confirmed_from_ledger` — one source, the ledger (I-149).** Run 162's `cr_status` said *"tester confirmed
  0 of 123 solutions"* while the same response's `rule_outcomes` showed 7 and `cr_hand_back` read
  `confirmed 7`. Nothing was lost; but `0 of 123` is the number a reader quotes, and it reports that no work
  was done. The Builder computes its clause from `rows[].tester.confirmed`, and **a repair that works removes
  its own row**, taking the flag with it (run 141). The ledger outlives the rows, so `detail`'s one unreliable
  clause is re-quoted from it and every other word the daemon wrote is carried through untouched.
  `confirmed_joined` stays `cr_hand_back`'s own field and is not touched.

- **`severed_by_repair` — an edge severed by a repair is not unfinished business (Q1).** Every import edge
  incident on a file goes `severed` the moment the file's bytes change, and re-promotion needs the flow
  evidence only a re-run gives — so before this, *a client that repaired anything moved `finished` further
  away by repairing it* (run 155: `severed_links` 0 → 16 in three bursts, each dated to a client rewrite).
  The classifier reads the apply lease above — `gearbox.read_apply_lease`, the server's own reader, never a
  second implementation — and buckets an edge `severed_by_repair` when **both** halves hold for one of its
  two files: the pair's `severed_since` is **at or after** that file's lease record's `timestamp`, and the
  lease's `after_sha256` is **what the file reads now** (the window at the lease's `replace_span_live`, or a
  window of the same height elsewhere in the file if a later edit moved it). An edge severed by an edit the
  server never handed out has no lease, so it stays `severed` and stays in `finished`. Repair-severed edges
  are still drawn red by `cr_wiring` and still listed in `monitor.wiring.severed`; what changed is only what
  `finished` counts. Re-promotion proper is unchanged — the next entry run re-measures the file.
- **`mypy_*` — the gate cannot be silenced by the target (Q2).** The tracker forces `--python-version` to the
  **running interpreter's** on every invocation and keeps the target's `[tool.mypy]` otherwise: its excludes
  and the extensions it names are the target's own knowledge, but the stubs mypy resolves are the *engine's*.
  A target
  that pins an older version — click pins `3.10` — makes mypy abort `rc 2` with **0 files checked**, and
  before this that read as `mypy_errors 0` beside a quiet `mypy_ran false`. A scan that checked no files is
  not a measurement whatever its rc, so `finished` then reads `"not measured"`, never `true`.

Proof: `python system_scripts/finished_proof.py` (the 16th gate of `replay_gates.sh`).

## The Q3 guarantee

**CodeRadar writes; the seat does not** (fix plan 2026-10-23, pass B — superseding the Q3 wording that the client edits).
A finding is fixed by `cr_submit`: the Builder gates the attempt and, when it integrates, writes the function into the
target at its live span, once (`solution_gate_integrate.stage_integrates`); `cr_stop` accounts for that file under
`gate_writes`. (CodeRadar's only other files in the target are the two state mirrors, kept after the stop as the
run's log and exempt by name from the difference set below.) `cr_apply` is a read: it renders the engine's candidate
edit — a unified diff from the file's *current* bytes at the function's live span for a rewriter, or the prescribed
shape with its `<placeholders>` and their meanings for a prescription — and returns it with `write: false`; it is not
applied by hand, and `cr_run_module` only puts back files the run itself wrote (M-21). `cr_report_outcome` remains for
a repair made outside CodeRadar; a row whose `cr_apply` bytes were edited by hand is refused by `cr_submit`. What the tools write, all in CodeRadar's own tree (each `ToolSpec.writes` names it; the
interface gate asserts the set — A3, Q-H4-10): `cr_report_outcome` one return-channel line in
`system_scripts/` and one confirmed-ledger record beside it on `confirmed`; `cr_apply` one apply-lease record
beside the same channel; `cr_watch` / `cr_stop` / `cr_hand_back` the run dir `.archive/runs/<repo name>/`
(`launch.log`, `gearbox.pid`, `state_during_run/`, the teardown listings and diff, `tester_report.json`);
`cr_run_module` the entry-point runner's `running.json` / `entry_point_info.json` in `system_scripts/`. The read tools
(`cr_attach`, `cr_status`, `cr_infractions`, `cr_row`, `cr_wiring`, `cr_data_types`, `cr_intent`) write
nothing. So the standing guarantee survives in a new
form: the teardown's difference set is **exactly** the client's edit log and nothing else. Pass the client's
manifest as `cr_stop(expected_changes=[…])` and the teardown says so directly — `residue_clean: true`,
`client_edits: N`, `unexpected_changes: []`. On a run with no edits, `byte_identical` is still `true`.

## The gate on unattended repair

> **Unattended repair must preserve observable behavior. First-vs-last, value-vs-raise, mutate-vs-copy are the
> same test. Intent-changing variants go through the client (the shape lane).**

The owner's sentence (2026-09-17). **G0** — `no_aivalidator/repair_generators/gate.py` — is where it is kept:
`candidates_of` shows every candidate to `gate.check` before offering it, and one that fails publishes
**withheld, with the gate's reason in `decision.why`**, instead of a repair. The row stays visible either way,
so the shape lane can still render what the gate would not apply unattended. Three dispositions, all of them
an answer: not offered at all (the rewriter declined at the source), withheld with a reason (the gate spoke),
or a behaviour-preserving repair. `system_scripts/gate_proof.py` is the regression — the twelve spans the
owner scored WRONG must withhold, the forty-three CORRECT must pass.

**And the same bar on the other side: no offer an unattended seat cannot ACT on** (I-152, owner 2026-09-21,
built session 10). G0 is asked per *candidate*, so until now a row went on publishing as a live offer as long
as any candidate was left — even one no unattended seat could render. Run 163: with `solution_NAI-120`
withheld on `src/click/utils.py::__exit__::237`, `selected_role` fell through to `solution_NAI-004`, a shape
carrying placeholders only a decision can fill, and the row still published with `withheld_by` unset. The
selector now marks such a candidate the way G0 marks a withheld rewrite, so the Ranker cannot pick it; when
every candidate on a row is one of those, the row publishes `selected_role ""`, `apply "no"` and
`withheld_by "gate.prescription_check"` — the prescription seam, named, not G0. A shape whose placeholders
the **site itself** binds (`<name>`, `<params>`, `<existing docstring>`) is still offered: that is the line
between "render it from the row" and "decide what goes there".

## Run the entry, run the suite

> **Run the entry to light the wiring, run the suite to test the repairs.**

The client rule from run 143. The two calls answer different questions and neither stands in for the other.
The app's own entry point — `cr_run_module("demos/demo01.py")` — exercises the import graph, which is what
moves `cr_wiring`'s edges off `possible`. The target's own suite — `cr_run_module("pytest", args=[…],
as_module=True)` — is the only thing that says whether an applied repair preserved behaviour. A client that
means to report `confirmed` runs both, and runs them before it reports.

**Read the wiring COUNTS, not `seen_on_band`** (I-151, run 162). `cr_run_module`'s `seen_on_band` can
answer `false` on a run that did land on the band: the circuit scan has not re-read
`entry_point_info.json` by the time the call returns, and a later `pytest` run on the same target
reported `true` for the same wiring. The reliable reading is `cr_wiring`'s own counts before and
after — run 162 measured `possible 66 → 6` and `live 0 → 60` on the run whose flag said `false`. A
seat that believes the flag concludes its entry run did not land and re-runs it for nothing.

## Two rules that are not optional

- **At the end call cr_stop() then cr_hand_back().** The gearbox's own teardown writes `tester_report.json`
  before its children stop (Item 6), so a hand-back published before cr_stop is overwritten by it (T4 defect
  (b), run 139). Since B12 (Q-H4-3, 2026-10-01) the wrong order is no longer silent: `cr_hand_back` called
  while the tree's daemons are live still writes and answers, but its `error` says the teardown will
  overwrite the report and to call cr_stop() then cr_hand_back() again; after cr_stop it carries the
  teardown's `daemon_failure` record forward, so a re-published report never reads `run_trusted: true`
  over a run that died.
- **The venv is driven with `python -m pip`, never `bin/pip`.** `.venv_new/bin/python3 -m pip install -e .
  --no-deps` installs the console script; `python -m pip show mcp` checks the SDK. No tree has ever used
  `bin/pip` and none may.

One more, for a client that means to report outcomes: **report within the cycle** — *still worth doing, no
longer required*. A repaired function stops being an infraction, and before session 7 `cr_report_outcome`
could only take a verdict for a row the mirror still published (run 141, run 155's 8 lost outcomes). Since the
apply lease it can take a verdict for any row `cr_apply` handed out, whether or not the Builder has retired
it; the payload says `resolved_by: "lease"` when that is what happened. Reporting inside the cycle is still
the cheaper path — it keeps the Ranker's re-decide on the same cycle — but a slow suite no longer costs the
seat its voice.

## Layout

| file | what |
|---|---|
| `tool_interface.py` | T1 — the 13 `ToolSpec`s, input/output schemas, the return-channel record, the confirmed-ledger record, the apply-lease record, `register_handler`. The interface of record; proven by `system_scripts/mcp_interface_proof.py`. |
| `read_tools.py` | T2 — `cr_status`, `cr_infractions`, `cr_row`, `cr_wiring`, `cr_data_types`, `cr_intent`. |
| `write_tools.py` | T3 — `cr_apply`, `cr_run_module`, `cr_report_outcome`. |
| `session_tools.py` | T4 — `cr_watch`, `cr_attach`, `cr_stop`, `cr_hand_back`. |
| `server.py` | the stdio server — path-first start (B1), the client `instructions` (B4/B5), the `scan` prompt (Q9); imports all three lane modules before dispatch, then `13/13 tools bound`. |
| `read_tools_proof.py` | T2's offline + live proof (`python -m coderadar_mcp.read_tools_proof`). |
| `b9_proof.py` | B9's per-rule accumulation, offline on archived runs (`python -m coderadar_mcp.b9_proof`). |
| `identity_proof.py` | the PRE-EDIT IDENTITY — the lease, the resolution order, the re-based diff, the tolerant id, the variant on the line, and run 158 (`python -m coderadar_mcp.identity_proof`). |

Proofs: `system_scripts/mcp_interface_proof.py`, `python -m coderadar_mcp.read_tools_proof`,
`system_scripts/mcp_write_path_proof.py`, `system_scripts/mcp_confirmed_ledger_proof.py`,
`python -m coderadar_mcp.b9_proof`, `python -m coderadar_mcp.identity_proof` — each exits 0.

**Naming a tool in this tree calls it for real** (run 140's `incident_cr_watch`): a scratch script that
mentions `cr_watch` launches a run on a real target. Write proofs that assert against the interface, not
against a live call.
