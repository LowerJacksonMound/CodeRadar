"""Planted counterfeits for NAI-133 / NAI-134 / NAI-135 / NAI-136 / NAI-137 — set 4b-15 (2026-09-10). Five
functions whose names promise a construct their bodies lack: a process_* without a loop, a filter_* without a
condition, a sort_* without a sort or compare, a count_* without an accumulator, a find_* without a comparison
or lookup call. What each body should do is the author's — five no-fix-by-design rows, nothing to rewrite."""


def process_rows(rows):
    return rows[0]


def filter_rows(rows):
    return list(rows)


def sort_rows(rows):
    return list(reversed(rows))


def count_rows(rows):
    return int(bool(rows))


def find_row(rows, key):
    return rows[key]
