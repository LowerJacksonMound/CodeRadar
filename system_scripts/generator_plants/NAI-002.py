"""Planted counterfeit for NAI-002 (a statement after a return in the same block) — health-check step 19, FIX_43 (b).
Finite set: `drop_dead` returns n; `terminal_last` runs the statement first and returns n + 1 (the variants differ by design)."""


def tally(n):
    return n
    n = n + 1


PLANT = {"function": "tally", "args": [4], "call": True, "expect": {"drop_dead": 4, "terminal_last": 5}}
