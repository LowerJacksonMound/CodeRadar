"""Planted counterfeit for NAI-028 (statements after an unconditional top-level return) — health-check step 19,
FIX_43 (b). call=True on ([1]): every candidate returns 0 (`exit_last` does the work first, then returns 0)."""


def summarize(values):
    return 0
    total = 0
    for v in values:
        total += v


PLANT = {"function": "summarize", "args": [[1]], "call": True}
