# RELEASE CHECKLIST

Before a version of this engine is releasable. Written 2026-11-04, in the shape the two gates use. Every box, every time.
The measured record (trial rounds, stress cases, the clean-clone rehearsal) is kept privately by the owner.

## Any change

- [ ] `system_scripts/health_check.py` passes, 23 steps, from `.venv_new` (the installer runs it on a fresh clone).
- [ ] `./replay_gates.sh <name>`: 17 of 17, or every red named here as a known limit. On 2026-11-04: 15 of 17, the same
      three reds since 2026-10-10 (read_tools, conformance needs the external notes dir, mypy tally), none in the scan or write route.
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
- [ ] GitHub private vulnerability reporting on; discussions, wiki, projects off (repo settings, the owner's).

## Rung 1: tag and GitHub release, repo still private

- [ ] Version bumped in both places; annotated tag pushed; release text: install, verify, known limits.
- [ ] Working tree clean at the tag; `git status` empty.

## Rung 3: public

- [ ] Full-history scan clean; author identity on every commit as intended.
- [ ] The flip is the owner's action: `gh repo edit LowerJacksonMound/CodeRadar --visibility public --accept-visibility-change-consequences`.
- [ ] After the flip versions only go forward; no tag is ever moved again. Issues open, pull requests not taken.
