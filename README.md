# CodeRadar

Finds counterfeit code in a Python repository and hands an AI agent one ranked repair per finding, over MCP. The
third program of the Deterministic Stack, beside [Cartouche](https://github.com/LowerJacksonMound/cartouche) (the
intent lock) and [Closer](https://github.com/LowerJacksonMound/closer) (the gate on new code). Cartouche and Closer
keep counterfeit code from landing; CodeRadar finds what is already in a tree and repairs what it can.

Counterfeit code performs the appearance of work: a function that returns a constant whatever its input, a stub body,
a swallowed failure, a pass-through, a body that reports an effect it never makes, a test that cannot fail. CodeRadar
decides "is X counterfeit, yes or no" deterministically, from four invariants, and the same tree gets the same verdict
every run:

1. Inputs must influence outputs.
2. Computation must be captured.
3. Iteration must accumulate.
4. A function must return a value or have a side effect.

Detection emits raw observations; one ranker decides, from one disposition table. Nothing upstream of the ranker
scores, filters or truncates, so when a verdict is wrong there is exactly one place to look.

## Install

Needs macOS (the file-access tracer is `lsof`), Python 3.12 or newer as `python3` on PATH, and
[Claude Code](https://claude.com/claude-code) as the MCP client, logged in. The install is from a git clone; CodeRadar
runs from its checkout, not from site-packages, and builds its own virtual environment inside the checkout.

```
git clone https://github.com/LowerJacksonMound/CodeRadar.git
cd CodeRadar
bash install_coderadar_mcp.sh
```

The script builds `.venv_new/` from `pyproject.toml` when it is missing (a minute or two), runs the engine's self-test,
and registers the MCP server `coderadar` with Claude Code at user scope, with the long tool timeout `cr_watch` needs
(50 minutes; `cr_watch` blocks until every launch gate passes, 1.5 to 40 minutes on a large repo). `--print` shows the
registration command and changes nothing. A running Claude Code session does not reload the server: after an install,
an edit, or a `git pull`, run `/mcp` and reconnect `coderadar`, or start a new session.

Then open Claude Code in any directory and type `/mcp__coderadar__scan <path to a repo>`, or say "scan ~/code/myrepo".

## Use

The agent drives it through eleven tools; you watch the dashboard the launch opens on `http://127.0.0.1:8080`.

- `cr_watch(target)` starts CodeRadar on one repo: a copy-first snapshot of the target, the self-test, the import map,
  the validator, the fix builder. It returns when every gate passes. Nothing in the target is edited; the only writes
  there are two small state mirrors per folder under `.coderadar/`, kept after the run as its log.
- `cr_status`, `cr_infractions`, `cr_row` read the findings: which function, which rule, the evidence, and the one
  repair offered. Rows in test and helper files are listed but not judged.
- `cr_apply(row)` renders the engine's own candidate as a diff and writes nothing. `cr_submit(row, code)` files the
  agent's whole replacement function; CodeRadar gates it (parse, differs, filter, integrate, the repo's own tests) and
  is the only writer of the target during a run. A row takes at most three attempts.
- `cr_stop` stops every CodeRadar process, proves nothing is left running or behind, and reports the target
  byte-identical to its snapshot apart from the agent's declared edits.
- `cr_wiring` is the visibility graph: which files import which, which edges are live. `cr_data_types`,
  `cr_intent`, `cr_report_outcome`, `cr_run_module`, `cr_attach` and `cr_hand_back` are documented in
  [HOW_CODERADAR_WORKS.md](HOW_CODERADAR_WORKS.md).

## What it catches, measured

Measured on 2026-11-04 against planted counterfeits of Closer's eleven species in three small honest apps, with ten
honest libraries (4,840 function rows: click, jinja2, flask, werkzeug, requests, urllib3, packaging, pathspec,
watchdog, idna) as the guard that no rule change raises noise on real code.

| Species | Detected | Honest repair lands |
|---|---|---|
| hard-coded return, stub body, swallowed failure, pass-through, fake check | yes | yes |
| fake effect (reports a change it never makes) | through the failing test | yes |
| answer table (right only for the inputs its tests use) | yes | refused when the row is noise |
| rigged test (expected value computed by the code under test) | yes | n/a |
| partial (the reached slice works, the rest is silently wrong) | known limit, see below | |
| untested crash path, hollow test | known limit by design | |

Noise floor on the three honest apps: two at zero rows, one at four rows that are shape-identical to real
counterfeits (a zero-parameter constructor returning a literal, a refusal that ignores its argument, a dispatch-table
function that ignores the table's uniform parameter, and that row's propagation), recorded as known limits.

## Known limits

- A partial function is seen only through a failing test, and the row lands on the function the test calls, not the
  function that is wrong. A repair filed on the wrong function is refused, so a wrong attribution cannot land.
- An untested crash path is unobservable statically; the synthetic probe the engine owns raises on honest code as
  readily as on counterfeit code, so it does not decide.
- Tests are proxies for the code and are listed, not judged; a hollow test is reported only when it mirrors the
  implementation.
- Python only. macOS only. One target at a time.

## Reporting a problem

Open an issue on this repository. A precise report carries: the `cr_status` summary line, the row id
(`<file>::<function>::<line>`) and its `rule_ids`, the `cr_row` output for that row, and, for a repair that was
refused, the attempt record (`status`, `stage`, `detail`). The run's own log is `.archive/runs/<name>/` in the
checkout. This project does not take outside code; issues are welcome.

## Status

Private, under measurement. Version 0.1.0. The engine is run from its checkout; see [HOW_CODERADAR_WORKS.md](HOW_CODERADAR_WORKS.md)
for the mechanism and [QUICKSTART.md](QUICKSTART.md) for the first run. The replay gates
(`./replay_gates.sh <name>`, 17 proofs) and the self-test (`system_scripts/health_check.py`, 23 steps) are the
release bar.

## License

PolyForm Noncommercial 1.0.0. Free for non-commercial use; commercial use needs a licence from the author
(contact LowerJacksonMound through GitHub). See LICENSE. A security problem goes through SECURITY.md, not an issue.
