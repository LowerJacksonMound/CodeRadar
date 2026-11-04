"""Planted counterfeit for NAI-175 (a literal key repeated in one dict literal) — step 19, FIX_43 (b); FIX_63: `keep_last` only (Python keeps the last value, so `keep_first` changed what the literal evaluates to)."""


def table():
    return {"a": 1, "b": 2, "a": 3}


PLANT = {"function": "table", "args": [], "call": True, "expect": {"keep_last": {"a": 3, "b": 2}}}
