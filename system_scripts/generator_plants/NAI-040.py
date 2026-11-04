"""Planted counterfeit for NAI-040 (an if / else whose two blocks are the same, > 1 statement each) — health-check
step 19, FIX_43 (b). call=True on ("a", [1]): the if branch is taken, so every candidate returns [1, "a"]."""


def route(kind, payload):
    if kind == "a":
        data = list(payload)
        data.append(kind)
        return data
    else:
        data = list(payload)
        data.append(kind)
        return data


PLANT = {"function": "route", "args": ["a", [1]], "call": True}
