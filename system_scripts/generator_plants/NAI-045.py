"""Planted counterfeit for NAI-045 (a str literal returned on one path, an int literal on another) — health-check
step 19, FIX_43 (b). call=True on (50): before → 100; `all_str` → "100" (expect), `str_is_error` → 100."""


def grade(score):
    if score < 0:
        return "invalid"
    return 100


PLANT = {"function": "grade", "args": [50], "call": True, "expect": {"all_str": "100"}}
