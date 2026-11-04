"""Planted counterfeit for NAI-116 (a string built by `+=` inside a for loop) — health-check step 19, set 4b-29.
Exactly the detector's shape with the join role's preconditions: `text = ""` directly above, the loop's only
statement `text += str(part)`, the loop target read nowhere else. call=True: before and after are called on
[1, "b", 2.5]; both must return "1b2.5"."""


def render(parts):
    text = ""
    for part in parts:
        text += str(part)
    return text


PLANT = {"function": "render", "args": [[1, "b", 2.5]], "call": True}
