"""Planted counterfeit for NAI-089 (the identity append loop: `for item in items: out.append(item)` as the loop's only
statement) — health-check step 19, set 4b-43. `out` is bound in the function to a list literal (the receiver
evidence `append_loop_extend_fix` requires), the loop target is read nowhere else. call=True: before and after are
called on ("h", [1, 2]); both must return ["h", 1, 2]."""


def gather(header, items):
    out = [header]
    for item in items:
        out.append(item)
    return out


PLANT = {"function": "gather", "args": ["h", [1, 2]], "call": True}
