"""Planted counterfeit for NAI-021S — R1 (2026-09-30): a 2026-09-30 target's `screen_rounds` exactly as
shaped (a plain dict parameter, no default, a docstring), the row the 2026-09-30 run broke.

The type is known (str keys say dict), but a `new_payload = dict(payload)` copy is itself a copy-constructor
hop: NAI-021S's own predicate still fires on it, so the "repair" would not resolve the finding and the next
scan re-flags it. `new_sequence` must DECLINE — only the never-applied `no_rewrite_shape` is offered, its text
stating that reason (published as a prescribed shape: apply: review, never yes). The call proves the plant runs.
"""


def screen_rounds(payload):
    """Drop fouled rounds (both hands the same) and count them."""
    clean = []
    fouls = payload["fouls"]
    for left, right in payload["rounds"]:
        if left == right:
            fouls += 1
            continue
        clean.append((left, right))
    payload["rounds"] = clean
    payload["fouls"] = fouls
    return payload


PLANT = {"function": "screen_rounds",
         "args": [{"rounds": [["rock", "rock"], ["rock", "paper"]], "fouls": 0}],
         "call": True, "expect_decline": True}
