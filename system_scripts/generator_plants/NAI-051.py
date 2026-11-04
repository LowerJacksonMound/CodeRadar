"""Planted counterfeit for NAI-051 (a misspelled builtin name) — health-check step 19, set 4b-36.
Exactly the detector's shape: a call to `lenght(`, a name in its MISSPELLED_BUILTINS table (correction `len`),
unbound in the function. call=False: the before-function raises NameError at the first call, so there is nothing
to compare; the rewrite's equivalence is the rule's own reading (the builtin the misspelling names)."""


def widest_row(rows):
    best = 0
    for row in rows:
        if lenght(row) > best:
            best = lenght(row)
    return best


PLANT = {"function": "widest_row", "args": [[[1, 2], [3, 4, 5], [6]]], "call": False}
