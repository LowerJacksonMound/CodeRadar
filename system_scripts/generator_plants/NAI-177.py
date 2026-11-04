"""Planted counterfeit for NAI-177 (keys of different types Python treats as equal) — step 19, FIX_43 (b); FIX_63: `keep_last` only (`{True: "yes", 1: "one"}` already IS `{True: "one"}`)."""


def flags():
    return {True: "yes", 1: "one", "k": 0}


PLANT = {"function": "flags", "args": [], "call": True, "expect": {"keep_last": {1: "one", "k": 0}}}
