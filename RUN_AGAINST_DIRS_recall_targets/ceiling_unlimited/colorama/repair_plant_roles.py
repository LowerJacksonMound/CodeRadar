"""Planted counterfeits for NAI-127 / NAI-128 / NAI-130 / NAI-131 / NAI-132 — set 4b-14 (2026-09-10). A bare
`eval` of its parameter (what it should become is the author's), a nested def with a list default (the nested
def is a row of its own — NAI-071 rewrites it there; the enclosing row is declared), a getter that returns
nothing, a setter that returns its value, and an `is_*` function annotated `int`: five no-fix-by-design rows,
nothing to rewrite on them."""


def parse_expr(text):
    return eval(text)


def make_counter():
    def bump(seen=[]):
        seen.append(1)
        return len(seen)
    return bump


class Panel:
    def __init__(self, width):
        self.width = width

    def get_width(self):
        self.refresh()

    def set_width(self, width):
        self.width = width
        return width

    def refresh(self):
        self.width = self.width


def is_ready(flag) -> int:
    return 1 if flag else 0
