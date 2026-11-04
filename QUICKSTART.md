# CodeRadar in ten minutes

CodeRadar watches one Python repository, finds counterfeit code (code that performs the appearance of work), and hands
an AI agent one repair per finding. You run it through Claude Code; the agent calls the tools; you read the dashboard.

## You need

- macOS. The file-access tracer is `lsof`.
- Python 3.12 or newer as `python3` on PATH (`python3 --version`). If your `python3` is older, set `PYTHON=` to a
  newer one when you run the installer.
- Claude Code installed and logged in (`claude` on PATH). It is the MCP client; the agent that files repairs is a
  Claude session.
- A Python repo to scan, with its tests in a `tests/` folder or configured in `pyproject.toml`. The repo is never
  edited by CodeRadar itself; the agent's accepted repairs are the only writes, and `cr_stop` proves it.

## Install

```
git clone https://github.com/LowerJacksonMound/CodeRadar.git
cd CodeRadar
bash install_coderadar_mcp.sh
```

What the script does, in order: builds `.venv_new/` inside the checkout from `pyproject.toml` if it is missing, runs
the 23-step self-test, registers the MCP server `coderadar` with Claude Code at user scope with a 50-minute tool
timeout. It prints the registration command it ran. `bash install_coderadar_mcp.sh --print` shows the command and
changes nothing.

If Claude Code was already open, run `/mcp` in it and reconnect `coderadar`, or start a new session. A running session
does not reload a server.

## First run, on a repo you do not mind watching

Open Claude Code in any directory and type:

```
/mcp__coderadar__scan ~/code/some-small-repo
```

or say "scan ~/code/some-small-repo". The agent calls `cr_watch`. In about ten seconds on a small repo (longer on a
large one; the call blocks until every launch gate passes, up to 40 minutes) you get:

- a dashboard at `http://127.0.0.1:8080`: the launch steps, then the import map and the findings;
- a copy of the repo in `~/CodeRadar_snapshots/<name>_<timestamp>/`, taken before anything else ran;
- the agent's summary of `cr_status`: how many findings, how many with a repair.

Then the agent reads rows with `cr_infractions` and `cr_row`, and for each row either files a replacement function
with `cr_submit` or leaves it. CodeRadar gates every attempt: it must parse, differ from the counterfeit, pass the
filter (the row's own rule must stop firing; no rule with evidence may start), integrate into the live file, and leave
the repo's own tests no worse. A refused attempt says which stage refused it and why.

When the agent is done it calls `cr_stop`. That stops every CodeRadar process and reports the target byte-identical to
its snapshot apart from the accepted repairs, plus two small state mirrors per folder under `.coderadar/` that are kept
as the run's log.

## Reading a finding

Each row names a file, a function, a line span, the deciding rule and every rule observed, the species, the evidence
and the one repair offered. Rules are `NAI-nnn` ids; each has a row in `system_scripts/rule_dispositions.json` with
its meaning and where it is emitted. A row on a test or helper file is listed as withheld: CodeRadar does not judge
tests, it uses them.

## What it will not do

- Edit your repo on its own. Only an accepted `cr_submit` attempt is written, and only to that function's live span.
- Scan two repos at once. `cr_watch` on a second target answers "cr_stop first".
- Judge anything but Python.
- See a partial implementation unless a test fails on it, or an untested crash path at all. Those are recorded known
  limits; see the README.

## When something is wrong

Run the self-test from the checkout:

```
.venv_new/bin/python system_scripts/health_check.py
```

It prints 23 steps and names the one that failed. For a verdict you disagree with, open an issue with the
`cr_status` summary line, the row id and its `rule_ids`, and the `cr_row` output; for a repair that was refused, add
the attempt record. The run's log is `.archive/runs/<name>/` in the checkout.
