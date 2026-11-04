"""Planted counterfeit for NAI-088 (a string literal added to an accumulator by `+=` inside a for loop) —
health-check step 19, set 4b-43. NAI-088 is an alias of NAI-116's join role and carries its own plant because the
NAI-116 plant fires NAI-088 too (the same `+=` shape read by two detectors). `text = ""` directly above, the loop's
only statement `text += "-"`, the loop target read nowhere else. call=True: before and after are called on
["a", "b", "c"]; both must return "---"."""


def dashes(parts):
    text = ""
    for part in parts:
        text += "-"
    return text


PLANT = {"function": "dashes", "args": [["a", "b", "c"]], "call": True}
