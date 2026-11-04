"""Planted constructs for GRF-001 / GRF-003 — set 4b-24 (2026-09-10), portion D's first. A dead store and a copy /
alias identity chain: the data-flow graph writes GRF-001 / GRF-003 as warning lines on these rows, and the rows
themselves are decided by NAI-147 (with 010 / 031) and NAI-021S — the graph ids never decide a row. IGR-001 and
FRN-001 are INFO lines the same stage writes on failing rows (importer count, RootCause candidates); GRF-002's
construct is its own control file (a bare undefined-name read passes). Five no-fix-by-design rows with the fact."""


def dead_store(items):
    unused = 42
    total = sum(items)
    return total * 2


def chain(items):
    held = list(items)
    copied = held[:]
    out = copied
    return out
