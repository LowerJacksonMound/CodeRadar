"""Planted counterfeit for NAI-005 (a redundant else after an if that returns) — health-check step 19, set 4b-19.
Exactly the detector's shape: the if body ends in a return, the else is `name = <expr>` then `return name`.
call=True: before and after are called with flag False; the else's value must come back both times."""


def pick(flag, first, second):
    if flag:
        return first
    else:
        value = second * 2
        return value


PLANT = {"function": "pick", "args": [False, 1, 2], "call": True}
