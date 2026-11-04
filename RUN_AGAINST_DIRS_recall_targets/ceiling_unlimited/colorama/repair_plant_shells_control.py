"""NAI-202 / NAI-226 constructs — set 4b-25 (2026-09-10): a function the module never references, and a def
nested two deep. Both are warning lines only; the file passes — listed as a control."""


def never_called(x):
    return x * 3


def outer(items):
    def middle(y):
        def inner(z):
            return z + 1
        return inner(y)
    return [middle(i) for i in items]
