"""Planted counterfeits for NAI-152 / NAI-158 / NAI-159 / NAI-160 / NAI-161 — set 4b-09 (2026-09-10). A class-level
list mutated in __init__ without ever being assigned, a boundary-named parameter reaching open(), a deprecated
exact alias (the one construct of the set with a mechanical repair: logging.warn → logging.warning), a
parameter reaching cursor.execute, and a requests call with no timeout."""
import logging
import requests


class Registry:
    items = []

    def __init__(self):
        self.items.append("first")


def read_file(path):
    return open(path).read()


def warn_twice(message):
    logging.warn(message)
    logging.warn("again: %s", message)


def run_query(cursor, statement):
    return cursor.execute(statement)


def fetch(address):
    return requests.get(address)
