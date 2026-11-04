"""Planted counterfeit for NAI-070 (bare except) — planted for run 48 (item 4 first batch).
The handler does not re-raise and does not return a fallback (so NAI-078 stays out of the way)."""


def count_ints(values):
    total = 0
    for v in values:
        try:
            total += int(v)
        except:
            continue
    return total


