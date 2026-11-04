"""Planted counterfeit for NAI-064 (`x = x`, x a parameter) — health-check step 19, set 4b-30.
call=True: before and after are called with (3, 4); both must return 7."""


def add_up(left, right):
    left = left
    total = left + right
    return total


PLANT = {"function": "add_up", "args": [3, 4], "call": True}
