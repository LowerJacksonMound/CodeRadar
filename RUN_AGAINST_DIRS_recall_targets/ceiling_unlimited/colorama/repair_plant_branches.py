"""Planted counterfeits for NAI-002 / NAI-003 / NAI-005 / NAI-006 / NAI-007 — set 4b-19 (2026-09-10), the first
set of portion C (`core`). A statement after a raise, a parameter never read, a redundant else after an if that
returns (rewritten live: the else dropped, its two lines dedented), a value overwritten before it is read, and a
nested def never used. What the author meant is theirs for the four declared rows; the else is mechanical."""


def guarded(value):
    if value < 0:
        raise ValueError("negative")
        value = 0
    return value * 2


def render(text, width, colour):
    return text.ljust(width)


def pick(flag, first, second):
    if flag:
        return first
    else:
        value = second * 2
        return value


def stamp(value):
    width = len(str(value))
    width = 8
    return str(value).rjust(width)


def outer(items):
    def helper(x):
        return x * 2
    return len(items)
