"""Planted counterfeit for NAI-006 (a variable assigned then immediately overwritten) — step 19, FIX_43 (b).
`keep_second` returns b, `keep_second_effect` keeps `_note(a)` as a bare call and returns b — and so does the
plant itself, which is the whole point: the second write is the live one.
FIX_56 (2026-09-17, the owner's ruling §A): `keep_first` is retired and no longer minted, so the plant stops
declaring an expected value for it. It was the only variant here that returned something else — `1`, the dead
first write's value, where the counterfeit returns `2`: the inversion in one line."""


def _note(v):
    return v


def choose(a, b):
    value = _note(a)
    value = b
    return value


PLANT = {"function": "choose", "args": [1, 2], "call": True, "expect": {"keep_second": 2, "keep_second_effect": 2}}
