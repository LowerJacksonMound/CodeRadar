"""Planted counterfeit for NAI-048 (two nested defs with identical bodies) — health-check step 19, FIX_43 (b).
call=True on ([1, 2]): whichever def is kept, the result is [2, 4, 2, 4]."""


def scale(values):
    def double(v):
        return v * 2

    def twice(v):
        return v * 2

    return [double(x) for x in values] + [twice(x) for x in values]


PLANT = {"function": "scale", "args": [[1, 2]], "call": True}
