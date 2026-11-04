"""Planted counterfeit for NAI-140 (statements after a terminal, the flow reading) — step 19, FIX_43 (b).
`drop_dead` returns 2; `terminal_last` appends first and returns 3."""


def head(items):
    return len(items)
    items.append(0)


PLANT = {"function": "head", "args": [[1, 2]], "call": True, "expect": {"drop_dead": 2, "terminal_last": 3}}
