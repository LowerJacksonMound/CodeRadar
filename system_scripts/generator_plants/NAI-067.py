"""Planted counterfeit for NAI-067 (`<str> + ''`) — health-check step 19, set 4b-31.
The other operand is a `str(...)` call — a str by construction, so dropping the empty literal changes nothing.
call=True: before and after are called with 7; both must return "7"."""


def as_label(value):
    label = str(value) + ""
    return label


PLANT = {"function": "as_label", "args": [7], "call": True}
