"""Planted counterfeit for NAI-021S — R1 (2026-09-30): a DICT parameter, mutated in place by str key and
handed back, under a docstring (a 2026-09-30 target's `screen_rounds`, with the `{}` default that makes
`new_sequence` a rewrite NAI-021S goes quiet on — the plain-parameter shape is `__screen_rounds_plain`).

The run of 2026-09-30 built `new_payload = list(payload)` for this shape (a dict's KEYS), inserted it ABOVE
the docstring, and marked seven rows apply: yes; step 19 passed it because the only NAI-021S plant was
`collect(items=[])` — a list default, no docstring. Here `new_sequence` must copy with dict(), insert after
the docstring, and return what the original returns on a real dict input.

call=True on ({"rounds": [...], "fouls": 0},): before → the caller's dict, rounds screened and fouls counted;
new_sequence → an equal dict (a copy). The pre-R1 rewrite raises AttributeError (`list.get`) here, and its
docstring check fails.
"""


def screen_rounds(payload={}):
    """Drop fouled rounds (both hands the same) and count them."""
    clean = []
    fouls = payload.get("fouls", 0)
    for left, right in payload.get("rounds", []):
        if left == right:
            fouls += 1
            continue
        clean.append((left, right))
    payload["rounds"] = clean
    payload["fouls"] = fouls
    return payload


PLANT = {"function": "screen_rounds",
         "args": [{"rounds": [["rock", "rock"], ["rock", "paper"], ["spock", "lizard"]], "fouls": 0}],
         "call": True}
