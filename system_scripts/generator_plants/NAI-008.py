"""Planted counterfeit for NAI-008 (import statement inside function body) — health-check step 19.
The rewriter hoists both stdlib imports to module scope above the def; the equivalence call must
return the same value from the before-module and the after-module."""


def join_parts(a, b):
    import os
    import posixpath as pp
    return pp.join(a, b) + os.sep


PLANT = {"function": "join_parts", "args": ["x", "y"], "call": True}
