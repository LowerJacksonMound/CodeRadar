"""Planted counterfeit for NAI-110 (a JavaScript `.push(` on a Python list) — health-check step 19, set 4b-28.
Exactly the detector's shape with receiver evidence: `names = []` binds the receiver in the function, so the rename
to `.append(` is exact. call=False: the before-code raises AttributeError on the first `.push` (a Python list has no
such method) — the rewrite is the one reading under which the function runs."""


def collect_names(rows):
    names = []
    for row in rows:
        names.push(row)
    return names


PLANT = {"function": "collect_names", "args": [["a", "b"]], "call": False}
