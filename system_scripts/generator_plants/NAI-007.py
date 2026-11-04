"""Planted counterfeit for NAI-007 (a nested def never called, returned or read) — step 19, FIX_43 (b).
`delete_nested` and `call_nested` return x unchanged; `return_nested` is not offered (the body ends in a return)."""


def outer(x):
    def helper():
        return x * 2
    return x


PLANT = {"function": "outer", "args": [3], "call": True}
