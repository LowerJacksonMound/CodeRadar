"""semantic_analysis._scope — the ONE contained walk for the five analyzers' no-`files=` fallback
(FIX_15, owner 2026-09-08: a walker never follows a symlink or a path resolving outside the target
root; FIX_14: never a private rglob). The live route hands `files=` over (the validator's
whitelist-filtered discovery); this is the fallback for a direct call on a directory."""
from __future__ import annotations

from pathlib import Path


def contained_glob(directory: Path, pattern: str) -> list[Path]:
    """`directory.glob(pattern)` restricted to contained entries. A `**/`-prefixed pattern is the
    recursive walk (scan_scope.iter_contained); any other pattern is the shallow glob filtered by
    scan_scope.contained. Engine hard-skip segments are never yielded."""
    from rca_main.constants import _scan_scope
    ss = _scan_scope()
    directory = Path(directory)
    if pattern.startswith("**/"):
        return [p for p in ss.iter_contained(directory, pattern[3:]) if p.is_file()]
    return [p for p in sorted(directory.glob(pattern))
            if p.is_file() and not ss.hard_skipped(p.relative_to(directory)) and ss.contained(p, directory)]
