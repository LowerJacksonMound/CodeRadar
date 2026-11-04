"""Planted counterfeit for NAI-022 (a bare call to a known-pure builtin, result dropped) — step 19, FIX_43 (b).
`drop_call` returns the list as given; `assign_back` binds `items = sorted(items)` and returns it sorted."""


def order(items):
    sorted(items)
    return items


PLANT = {"function": "order", "args": [[3, 1, 2]], "call": True, "expect": {"drop_call": [3, 1, 2], "assign_back": [1, 2, 3]}}
