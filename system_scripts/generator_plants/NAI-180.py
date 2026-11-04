"""Planted counterfeit for NAI-180 (`for … in list(range(…))`) — health-check step 19, set 4b-31.
call=True: before and after are called with 4; both must return 6."""


def triangle(n):
    total = 0
    for i in list(range(n)):
        total = total + i
    return total


PLANT = {"function": "triangle", "args": [4], "call": True}
