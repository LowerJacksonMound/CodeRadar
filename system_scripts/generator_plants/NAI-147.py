"""Planted counterfeit for NAI-147 (a local assigned and never read, own-scope def/use) — step 19, FIX_43 (b).
`result` is in NAI-010's acceptable-name table (so NAI-010 stays quiet); NAI-147 has no such table.
FIX_60 (2026-09-17): NAI-147 mints through `core.dead_local_variants`, so the same pure-callee rule binds it —
`_note` is a module-level def the rewriter is not shown, so the one variant is `keep_call_effect`."""


def _note(v):
    return len(v)


def total(values):
    result = _note(values)
    return sum(values)


PLANT = {"function": "total", "args": [[1, 2, 3]], "call": True}
