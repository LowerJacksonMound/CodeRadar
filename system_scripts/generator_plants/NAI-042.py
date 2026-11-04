"""Planted counterfeit for NAI-042 (`except … as name` never read) — health-check step 19, set 4b-38.
call=True: before and after are called with ("x",) — the handler path; both must return 0."""


def parse_port(text):
    try:
        value = int(text)
    except ValueError as err:
        value = 0
    return value


PLANT = {"function": "parse_port", "args": ["x"], "call": True}
