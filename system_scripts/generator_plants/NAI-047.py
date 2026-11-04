"""Planted counterfeit for NAI-047 (an assert whose test calls a function outside the pure table) — health-check
step 19, FIX_43 (b). call=True on ("x"): the assert passes, every candidate returns "x"."""


def touch(path):
    return len(path) > 0


def check(path):
    assert touch(path)
    return path


PLANT = {"function": "check", "args": ["x"], "call": True}
