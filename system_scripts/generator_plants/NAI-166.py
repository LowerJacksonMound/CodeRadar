"""Planted counterfeit for NAI-166 (`raise NotImplemented`, the singleton, where NotImplementedError was meant) —
health-check step 19, set 4b-10. call=True: area("circle") must return 3 before and after the rewrite (the
normal path is untouched; only the raise statement changes)."""


def area(shape):
    if shape == "circle":
        return 3
    raise NotImplemented


PLANT = {"function": "area", "args": ["circle"], "call": True}
