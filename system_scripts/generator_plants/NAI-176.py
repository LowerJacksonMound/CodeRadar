"""Planted counterfeit for NAI-176 (an f-string with no placeholder) — health-check step 19, set 4b-31.
call=True: before and after are called with 2; both must return "ready: 2"."""


def banner(count):
    prefix = f"ready"
    return prefix + ": " + str(count)


PLANT = {"function": "banner", "args": [2], "call": True}
