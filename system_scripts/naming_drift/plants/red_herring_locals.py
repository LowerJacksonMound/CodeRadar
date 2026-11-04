"""Red herring: locals (i / idx / index) and nested defs are NOT names; __init__ is the language's, not a variant of initialize."""


def walk(items):
    index = 0
    for i, item in enumerate(items):
        idx = i
        index = idx

    def inner(i):
        idx = i
        return idx

    return inner(index)


class Engine:
    def __init__(self):
        self.started = False

    def initialize(self):
        self.started = True
