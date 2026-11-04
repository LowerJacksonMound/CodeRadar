"""Planted counterfeit for NAI-026 (identical if / else bodies, one statement each — NAI-040 needs > 1) — health-check
step 19, FIX_43 (b). call=True on (True, 5): the if branch is taken, every candidate returns 5."""


def choose(flag, value):
    if flag:
        return value
    else:
        return value


PLANT = {"function": "choose", "args": [True, 5], "call": True}
