"""Planted counterfeit for NAI-017 (a bare `except: pass`) — step 19, FIX_43 (b).
Called with "5": every variant returns 5 (the handler is not reached)."""


def parse_int(text):
    try:
        return int(text)
    except:
        pass
    return 0


PLANT = {"function": "parse_int", "args": ["5"], "call": True}
