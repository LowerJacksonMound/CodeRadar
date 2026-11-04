"""Planted counterfeit for NAI-052 (an identical condition nested directly inside itself) — health-check step 19,
set 4b-36. Exactly the detector's `identical_nested_if` shape with a pure condition (`key in table`, a comparison of
two names). call=True: before and after are called on ({"a": 1}, "a") and must both return 1; the inner header and
its dead `else` go, the body is dedented into the outer."""


def setting_for(table, key):
    if key in table:
        if key in table:
            value = table[key]
            return value
        else:
            return -1
    return None


PLANT = {"function": "setting_for", "args": [{"a": 1}, "a"], "call": True}
