"""Planted counterfeit for NAI-170 (`++x`, a no-op in Python) — step 19, FIX_43 (b).
`augmented` returns n + 1; `drop` returns n."""


def bump(n):
    ++n
    return n


PLANT = {"function": "bump", "args": [4], "call": True, "expect": {"augmented": 5, "drop": 4}}
