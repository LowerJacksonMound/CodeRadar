"""Planted counterfeit for NAI-063 (an `or` chain repeating a name) — health-check step 19, set 4b-30.
The repeat is not the chain's last operand, so the chain's value is the same on every path.
call=True: before and after are called with (0, 0, 5); both must return 5."""


def first_set(primary, fallback, default):
    chosen = primary or fallback or primary or default
    return chosen


PLANT = {"function": "first_set", "args": [0, 0, 5], "call": True}
