"""Planted counterfeit for NAI-068 (`while True:` with an immediate conditional `break`) — health-check step 19, set 4b-31.
call=True: before and after are called with 3; both must return 3."""


def count_up(limit):
    n = 0
    while True:
        if n >= limit:
            break
        n = n + 1
    return n


PLANT = {"function": "count_up", "args": [3], "call": True}
