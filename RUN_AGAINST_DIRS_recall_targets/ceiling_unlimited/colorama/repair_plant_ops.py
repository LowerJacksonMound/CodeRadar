"""Planted counterfeits for NAI-009 / NAI-010 / NAI-011 / NAI-014 / NAI-016 — set 4b-20 (2026-09-10). A lookup that
returns an empty dict whatever its inputs, a local computed and never read, a function that neither returns nor
acts, a comparison written as a statement, and an identity function (NAI-016's construct — on the daemon route its
row is NAI-016S's, strict). What the author meant is theirs in every case — no-fix-by-design rows."""


def lookup(table, key):
    return {}


def total(items):
    count = len(items)
    return sum(items)


def note(value):
    value.strip


def check(a, b):
    a == b
    return a + b


def same(value):
    return value
