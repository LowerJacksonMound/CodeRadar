"""Planted counterfeit for NAI-061 (compare to a True/False literal) — planted for run 48 (item 4 first batch).
Exactly the detector's whole-body shape: one `if <compare>: return`, then one `return`."""


def label(flag):
    if flag == True:
        return "on"
    return "off"


