"""Planted counterfeit for NAI-070 (bare except) — health-check step 19.
The handler does not re-raise and does not return a fallback (so NAI-078 stays out of the way)."""


def count_ints(values):
    total = 0
    for v in values:
        try:
            total += int(v)
        except:
            continue
    return total


PLANT = {"function": "count_ints", "args": [["1", "x", "3"]], "call": True}
