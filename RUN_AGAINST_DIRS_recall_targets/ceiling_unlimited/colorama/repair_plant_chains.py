"""Planted counterfeits for NAI-143 / NAI-145 / NAI-146 / NAI-147 / NAI-148 — set 4b-17 (2026-09-10). A return
inside finally, a local read before it is assigned, a local reassigned before its first value is read (NAI-146's
construct — the id is never emitted; NAI-006 decides the row), a local never read, and an imported name
reassigned (the body import also fires NAI-008, whose hoist leaves the reassignment alone). What the author
meant is theirs in every case — no-fix-by-design rows, nothing to rewrite on them."""


def close_quietly(handle):
    try:
        handle.close()
    finally:
        return True


def label_for(code):
    text = prefix + str(code)
    prefix = "C-"
    return text


def stamp(value):
    width = 4
    width = 8
    return str(value).rjust(width)


def total_width(cells):
    widths = [len(c) for c in cells]
    total = sum(len(c) for c in cells)
    return total


def data_dir(name):
    import os
    os = name.strip()
    return os
