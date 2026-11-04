"""Planted counterfeit for NAI-031 (a local assigned and never read — `count`) — health-check step 19, FIX_43 (b).
call=True on ([1, 2, 3]): every candidate returns 6 (the dead store's right side calls len, so both are offered)."""


def total(values):
    count = len(values)
    result = 0
    for v in values:
        result += v
    return result


PLANT = {"function": "total", "args": [[1, 2, 3]], "call": True}
