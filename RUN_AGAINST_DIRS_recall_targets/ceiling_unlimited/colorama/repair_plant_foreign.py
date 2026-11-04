"""Planted counterfeits for NAI-105 / NAI-108 / NAI-109 / NAI-110 / NAI-115 — set 4b-28 (2026-09-10), portion E's
second. A convert_* whose loop appends each row unchanged, an item_count that returns a string, an add_* that
removes from the collection whose size it returns, a JavaScript `.toUpperCase()` on a str the function itself
binds, and a get_* that returns a literal list. What the transformation was, which of the name and the value is
wrong, which of the name and the action, and where the data should come from are the author's — four
no-fix-by-design rows; the `.toUpperCase()` row is the one mechanical repair (`cross_language_fix`, receiver
evidence: `label = f"id:{rows[0]}"`)."""


def convert_rows(rows):
    out = []
    for row in rows:
        out.append(row)
    out.reverse()
    return out


def item_count(items):
    items = list(items)
    return "many"


def add_entry(entries, entry):
    entries.remove(entry)
    return len(entries)


def label_upper(rows):
    label = f"id:{rows[0]}"
    return label.toUpperCase()


def get_users(source):
    source = str(source)
    return ["alice", "bob"]
