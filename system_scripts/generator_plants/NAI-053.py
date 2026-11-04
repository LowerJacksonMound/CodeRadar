"""Planted counterfeit for NAI-053 (an if / elif / else chain with two identical non-sentinel bodies) — health-check
step 19, FIX_43 (b). call=True on (1): the first branch is taken, every candidate returns "one"."""


def label(n):
    if n == 1:
        return "one"
    elif n == 2:
        return "two"
    elif n == 3:
        return "one"
    else:
        return "many"


PLANT = {"function": "label", "args": [1], "call": True}
