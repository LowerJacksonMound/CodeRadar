"""Planted counterfeit for NAI-124 (`== None` where `is None` is meant) — health-check step 19, set 4b-13.
call=True: before and after are called on None; the results must agree (True both ways)."""


def is_unset(value):
    return value == None


PLANT = {"function": "is_unset", "args": [None], "call": True}
