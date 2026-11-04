"""Planted counterfeit for NAI-061 (compare to a True/False literal) — health-check step 19.
Exactly the detector's whole-body shape: one `if <compare>: return`, then one `return`."""


def label(flag):
    if flag == True:
        return "on"
    return "off"


PLANT = {"function": "label", "args": [True], "call": True}
