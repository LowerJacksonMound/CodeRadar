"""Planted counterfeit for NAI-071 (mutable default argument) — health-check step 19."""


def collect(items=[]):
    items.append(1)
    return items


PLANT = {"function": "collect", "args": [], "call": True}
