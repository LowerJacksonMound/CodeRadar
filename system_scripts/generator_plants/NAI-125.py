"""Planted counterfeit for NAI-125 (`return <value>` in __init__) — step 19, FIX_43 (b).
A module-level def named __init__ so the plant runner can call it; both variants return None.
The receiver is built inside the PLANT dict (the dict is evaluated on its own)."""


def __init__(self, value):
    self.value = value
    return value


PLANT = {"function": "__init__", "args": [type("Obj", (), {})(), 7], "call": True, "expect": {"drop_value": None, "store_attribute": None}}
