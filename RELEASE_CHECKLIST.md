# RELEASE CHECKLIST

Before a version of this engine is releasable. Written 2026-11-04, in the shape the two gates use. Every box, every time.
The measured record (trial rounds, stress cases, the clean-clone rehearsal) is kept privately by the owner.

## Any change

- [ ] `system_scripts/health_check.py` passes, 23 steps, from `.venv_new` (the installer runs it on a fresh clone).
- [ ] `./replay_gates.sh <name>`: 17 of 17, no known limits. 2026-11-05: the three reds carried as "known limits" since
      2026-10-10 were a crashing proof (read_tools), a gate whose script never existed (conformance, removed) and 137
      mypy errors; all three cleared. The gates read `.archive/gate_evidence/`, which a clone must have (see below).
- [ ] A changed or new observation has a plant that fires without the fix and not with it, and 0 new hits on the ten honest
      libraries (the NAI-260 bar: row-for-row identical before and after).
- [ ] README, QUICKSTART and HOW_CODERADAR_WORKS match the code: tool count, what it catches, known limits.
- [ ] `version` in pyproject.toml and `coderadar_mcp/__init__.py` match; a tag names that version.
- [ ] A changed invariant is a decision recorded in the fix plan, not an edit.

## Rung 0: private and measured (2026-11-04)

- [x] Live trials on real apps, each run recorded: round one 14 of 14 cases (shape species 6 of 7, claim species 0 of 3);
      rounds two to four: T10 and T4 added, T7 and T11 recorded as known limits, F1 to F7 fixed and checked live.
- [x] README and QUICKSTART a stranger can follow; `install_coderadar_mcp.sh` builds `.venv_new` from a clone (00eeb36).
- [x] Clean-clone rehearsal: clone from GitHub, installer under an empty HOME on python 3.14.6, 23-step self-test passed,
      `launch.sh` on the counter app gave exactly the four documented rows.
- [x] Licence PolyForm Noncommercial since the first code commit; pyproject carries it as an SPDX expression.
- [x] SECURITY.md and the README's "Reporting a problem" section present.
- [ ] Second-machine run from a clone (a friend's Mac): every step that needs knowledge not in the files is written in.
- [x] Discussions, wiki, projects off; issues on (2026-11-04). Private vulnerability reporting is offered by GitHub only on a
      public repo: first action after the flip.

## Rung 1: tag and GitHub release, repo still private

- [x] Version 0.1.0 in pyproject.toml and `coderadar_mcp/__init__.py`; annotated tag `v0.1.0` pushed 2026-11-04; draft
      prerelease "CodeRadar 0.1.0" on GitHub with install, verify and known limits.
- [x] Working tree clean at the tag (the two census ledgers the gate reads, 2026-10-23 and 2026-11-04, are tracked; older ones are not).

## Rung 3: public

- [x] Full-history scan 2026-11-04: no secrets (the one `password = "hunter2"` is a fixture plant), no blob over the
      tracked census ledger, no home paths in tracked code (the calibration scripts' hardcoded root fixed the same day).
      Author identity: two owner addresses across 21 commits, ruled to stay.
- [ ] The flip is the owner's action: `gh repo edit LowerJacksonMound/CodeRadar --visibility public --accept-visibility-change-consequences`.
- [ ] After the flip versions only go forward; no tag is ever moved again. Issues open, pull requests not taken.
