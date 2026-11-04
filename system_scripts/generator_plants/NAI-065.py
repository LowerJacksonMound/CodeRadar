"""Planted counterfeit for NAI-065 (`str(str(x))`) — health-check step 19, set 4b-30.
call=True: before and after are called with 42; both must return "42"."""


def as_text(value):
    text = str(str(value))
    return text


PLANT = {"function": "as_text", "args": [42], "call": True}
