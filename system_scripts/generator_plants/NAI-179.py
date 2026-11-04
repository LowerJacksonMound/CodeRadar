"""Planted counterfeit for NAI-179 (`acc = acc + <value>` inside a for loop — the detector's spelling that NAI-088's
`+=` misses) — health-check step 19, set 4b-43. NAI-179 is an alias of NAI-116's join role: the role was widened on
this set to read the plain-assignment spelling with the same preconditions (`text = ""` directly above, the loop's
only statement, a literal / `str()` / f-string value, the loop target read nowhere else). call=True: before and
after are called on [1, "b", 2.5]; both must return "1b2.5"."""


def glue(parts):
    text = ""
    for part in parts:
        text = text + str(part)
    return text


PLANT = {"function": "glue", "args": [[1, "b", 2.5]], "call": True}
