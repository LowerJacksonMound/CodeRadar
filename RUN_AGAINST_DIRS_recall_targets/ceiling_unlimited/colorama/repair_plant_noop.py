"""Planted counterfeits for NAI-022 / NAI-023 / NAI-024 / NAI-025 / NAI-170 — set 4b-22 (2026-09-10). A pure call
whose result is dropped, a name compared to itself, a loop that returns on its first item with nothing after it,
an add-zero no-op, and a C-style pre-increment. Which was meant is the author's in every case — five
no-fix-by-design rows, nothing to rewrite. Each carries real data flow beside the construct so strict (NAI-021S)
does not take the row."""


def size(items):
    len(items)
    return sum(items) + 1


def same_side(a):
    if a == a:
        return 1
    return 2


def first_wide(cells):
    for cell in cells:
        return len(cell)


def tally(items):
    total = sum(items)
    total = total + 0
    return total * 2


def bump(count):
    step = ++count
    return step + 1
