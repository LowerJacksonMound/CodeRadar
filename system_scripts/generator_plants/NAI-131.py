"""Planted counterfeit for NAI-131 (a set_* function returning a value other than self) — step 19, FIX_43 (b).
call=False: `return_self` returns the receiver object, which the plant dict cannot name."""


def set_name(self, name):
    self.name = name
    return name


PLANT = {"function": "set_name", "args": [], "call": False}
