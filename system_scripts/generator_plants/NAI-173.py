"""Planted counterfeit for NAI-173 (a return inside finally) — health-check step 19, FIX_43 (b).
call=True on ([1, 2]): before → 0 (the finally's return overrides the try's); both candidates → 2 (expect).
The finally must not mutate the argument: step 19 calls before and after with the same args objects."""


def drain(items):
    try:
        return len(items)
    finally:
        closed = True
        return 0


PLANT = {"function": "drain", "args": [[1, 2]], "call": True, "expect": {"after_try": 2, "drop_return": 2}}
