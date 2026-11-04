"""Planted counterfeit for NAI-157 — set 4b-18 (2026-09-10), portion B's last. A `test_*` function that catches
the exception it provokes and passes, asserting nothing: what the test should do when the exception arrives is
the author's — a no-fix-by-design row. It asserts nothing on purpose: a `test_*` def that asserts makes its whole
file the test species (every id withheld); one that never asserts reaches a row, and that is the shape this rule
names."""


def test_parse_never_fails():
    try:
        int("x")
    except ValueError:
        pass
