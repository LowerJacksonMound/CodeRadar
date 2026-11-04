"""Planted counterfeit for NAI-071 (mutable default argument) — planted for run 48 (item 4 first batch)."""


def collect(items=[]):
    items.append(1)
    return items


