"""Planted counterfeit for NAI-078 (an except block whose only statement returns a literal fallback) — health-check
step 19, FIX_43 (b). call=True on ("7"): the try succeeds, every candidate returns 7."""


def parse_count(text):
    try:
        return int(text)
    except ValueError:
        return 0


PLANT = {"function": "parse_count", "args": ["7"], "call": True}
