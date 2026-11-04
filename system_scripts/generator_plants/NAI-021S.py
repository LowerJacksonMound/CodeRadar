"""Planted counterfeit for NAI-021S (alias identity chain: the parameter mutated in place and returned) — step 19, FIX_43 (b).
The hand check's #4 shape (`repair_plant_071.py::collect`). Called with the default: before returns the shared default list [1];
`new_sequence` returns a fresh [1] (a new list each call, never the default object)."""


def collect(items=[]):
    items.append(1)
    return items


PLANT = {"function": "collect", "args": [], "call": True}
