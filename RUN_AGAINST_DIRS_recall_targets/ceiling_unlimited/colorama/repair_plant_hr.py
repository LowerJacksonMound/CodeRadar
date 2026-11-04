"""Planted counterfeits for HR-001 / HR-002 / HR-003 — set 4b-01 (2026-09-10). Each function DECLARES its
role with a decorator and its body lacks what that role requires: no-fix-by-design rows, nothing to rewrite."""
from contextlib import contextmanager


class Knob:
    @property
    def level(self):
        print("level requested")

    @level.setter
    def level(self):
        print("level set")


@contextmanager
def opened(path):
    handle = open(path)
    handle.close()
