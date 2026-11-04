"""Planted counterfeit for NAI-062 (`len(x) == 0` as the whole-body if-test) — health-check step 19, set 4b-30.
Exactly the detector's whole-body shape: `if len(x) == 0: return …` then one `return`.
call=True: before and after are called with an empty list; both must return "empty"."""


def describe(items):
    if len(items) == 0:
        return "empty"
    return "full"


PLANT = {"function": "describe", "args": [[]], "call": True}
