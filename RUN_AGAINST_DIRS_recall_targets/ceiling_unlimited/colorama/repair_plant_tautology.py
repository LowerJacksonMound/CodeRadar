"""NAI-139's construct — set 4b-16 (2026-09-10): a test whose only assert compares against an inline
computation. A `test_*` def makes this whole file the test species: every id is withheld into context and the
file passes — listed as a control in the manifest; the id never decides a row (declared with the fact)."""


def test_double():
    result = 2 * 3
    assert result == 3 * 2
