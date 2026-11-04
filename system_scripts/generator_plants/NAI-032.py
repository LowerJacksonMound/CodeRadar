"""Planted counterfeit for NAI-032 (`total + 0`, an algebraic identity) — health-check step 19, set 4b-32.
Real data flow beside the identity (the sum is the function's work); call=True: widen(3, 4) must return 7
before and after the rewrite."""


def widen(width, extra):
    total = width + extra
    return total + 0


PLANT = {"function": "widen", "args": [3, 4], "call": True}
