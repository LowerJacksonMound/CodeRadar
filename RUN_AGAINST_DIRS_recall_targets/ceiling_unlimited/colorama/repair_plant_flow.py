"""Planted counterfeits for NAI-138 / NAI-140 / NAI-141 / NAI-142 — set 4b-16 (2026-09-10). A build_* that
returns nothing, a statement after a raise, a `while True` nothing ends, and an annotated def that returns on
one path only: what to return, which of the terminal or the code after it is the mistake, what ends the loop,
and what the missing path returns are the author's — four no-fix-by-design rows, nothing to rewrite. NAI-139's
construct lives in repair_plant_tautology.py: a `test_*` def makes its whole file the test species, whose rows
carry every id as context — that file is a control (it passes entirely)."""


def build_label(text):
    print(text)


def checked(value):
    if value < 0:
        raise ValueError("negative")
        value = 0
    return value * 2


def spin(queue):
    while True:
        queue.get()


def sign(n) -> int:
    if n > 0:
        return 1
