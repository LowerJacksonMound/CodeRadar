"""Planted counterfeit for NAI-010 (a local assigned and never read) — step 19, FIX_43 (b).
`tally` is not in the detector's acceptable-name table; the rewrite returns sum(values), as the plant does.
FIX_60 (2026-09-17, the owner's ruling §A on rows #73 #74): `_note` is a MODULE-level def, and the rewriter is
handed the function's own source — so the purity of `_note` is evidence it cannot see, and unseen is not pure.
The plant therefore proves the FIX_60 path: one variant, `keep_call_effect`, the call kept and the unread name
dropped. Equivalent either way here, which is why the plant can prove the rule without changing its answer."""


def _note(v):
    return len(v)


def total(values):
    tally = _note(values)
    return sum(values)


PLANT = {"function": "total", "args": [[1, 2, 3]], "call": True}
