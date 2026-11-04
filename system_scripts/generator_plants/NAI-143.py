"""Planted counterfeit for NAI-143 (a return inside finally) — step 19, FIX_43 (b).
Before: the finally's 0 overrides the try's 5. Both variants let the try's value out: 5."""


def load(text):
    try:
        return int(text)
    finally:
        return 0


PLANT = {"function": "load", "args": ["5"], "call": True, "expect": {"drop_finally_return": 5, "move_after_try": 5}}
