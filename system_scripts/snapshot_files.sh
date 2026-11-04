#!/bin/bash
# Q10 (B7, MCP-working packet 2026-09-28): the ONE file set of the COPY-FIRST snapshot.
# Prints the sorted ./-relative paths under <root>, skipping:
#   - an env dir, by SHAPE: a directory holding `pyvenv.cfg` or `conda-meta/`
#   - `node_modules`
#   - tool caches: `.mypy_cache`, `.pytest_cache`, `.tox`, `.nox`, `__pycache__`
#   - CodeRadar's OWN output dir `./.coderadar` at the root ONLY (R8 / T-10, 2026-09-30): the state
#     mirrors, never source — same root-only rule as scan_scope.MIRROR_DIR; a deeper `.coderadar` is copied
# launch.sh copies this set and its count check counts this set; run_proof.sh `down` and
# cr_stop compare this set, so a skipped dir never reads as a teardown difference.
# Usage: snapshot_files.sh <root> [--links]   (--links also lists symlinks: the COPY list;
#        without it, regular files only: the VERIFY / teardown list)
set -u
ROOT="${1:?usage: snapshot_files.sh <root> [--links]}"
KIND=(-type f)
[ "${2:-}" = "--links" ] && KIND=( \( -type f -o -type l \) )
cd "$ROOT" || exit 1
find . -type d \( -name node_modules -o -name .mypy_cache -o -name .pytest_cache \
        -o -name .tox -o -name .nox -o -name __pycache__ -o -path ./.coderadar \
        -o -exec sh -c '[ -e "$1/pyvenv.cfg" ] || [ -d "$1/conda-meta" ]' _ {} \; \) -prune \
    -o "${KIND[@]}" -print | sort
