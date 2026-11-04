"""Planted counterfeit for NAI-096 (an assert as the function's first statement validating a parameter) —
health-check step 19, set 4b-08. call=True: scale(3) must return 6 before and after the rewrite."""


def scale(n):
    assert n > 0, "n must be positive"
    return n * 2


PLANT = {"function": "scale", "args": [3], "call": True}
