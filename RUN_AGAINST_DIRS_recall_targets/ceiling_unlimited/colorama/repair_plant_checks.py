"""Planted counterfeits for NAI-079 / NAI-091 / NAI-095 / NAI-096 / NAI-098 — set 4b-08 (2026-09-10). An absolute
path literal, a parameter mutated with another parameter, a float equality, an assert standing in for input
validation (the one construct of the set with a mechanical repair: `if not (...): raise AssertionError`), and a
print with nothing returned."""
import os


def hosts_present():
    return os.path.exists("/etc/hosts")


def push(items, value):
    items.append(value)


def near_tenth(x):
    return x == 0.1


def scale(n):
    assert n > 0, "n must be positive"
    return n * 2


def show(message):
    print(message)
