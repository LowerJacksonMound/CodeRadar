"""Planted counterfeits for NAI-120 / NAI-122 / NAI-124 / NAI-125 — set 4b-13 (2026-09-10). A function whose
body is only its docstring (what it should do is the author's: no-fix-by-design), a `== None` comparison
(rewritten live: `is None`), a bare except (the construct NAI-122 names; NAI-070 decides it — NAI-122 is its
alias and is never emitted), and an __init__ that returns a value (what the value was meant to become is the
author's: no-fix-by-design). The module-level star import is NAI-126's construct: nothing decides it (the
check is called by nothing), so it stays out of `planted_findings` and is recorded in RUN.md."""
from .ansi import *


def reserved():
    """Reserved for a later release."""


def is_unset(value):
    return value == None


def widths(cells):
    out = []
    for c in cells:
        try:
            out.append(len(c))
        except:
            continue
    return out


class Cursor:
    def __init__(self, column):
        self.column = column
        return column
