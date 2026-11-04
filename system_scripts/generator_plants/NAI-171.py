"""Planted counterfeit for NAI-171 (a for-loop `else:` with no `break` in the loop body) — health-check step 19,
set 4b-42. Exactly the detector's shape: the loop body accumulates, the else block runs after every completion.
call=True: before and after are called on [[1], [2, 3]]; both must return 4 (3 items + the else block's 1)."""


def seal(rows):
    total = 0
    for row in rows:
        total += len(row)
    else:
        total += 1
    return total


PLANT = {"function": "seal", "args": [[[1], [2, 3]]], "call": True}
