"""Planted counterfeit for NAI-021S — R1 (2026-09-30): a parameter whose type the code does NOT show.

`store.pop(key)` fits a dict (a key) and a list (an index) alike, and nothing else in the function says
which (the pre-R1 generator read `pop` as "list" — a dict caller would have got `list(store)`, its keys). No str key, no type-only method, no annotation, no default: `new_sequence` must DECLINE
rather than guess (only the never-applied `no_rewrite_shape` is offered, its text stating why). The call
proves the plant itself runs on a dict.
"""


def forget(store, key):
    """Drop `key` in place and hand the store back."""
    store.pop(key)
    return store


PLANT = {"function": "forget", "args": [{"x": 1, "y": 2}, "y"], "call": True, "expect_decline": True}
