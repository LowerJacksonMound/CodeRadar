"""Planted counterfeit for NAI-159 (a deprecated exact alias: logging.warn) — health-check step 19, set 4b-09.
call=False: the gate emits no log line; parse + meaning check only."""
import logging


def warn_twice(message):
    logging.warn(message)
    logging.warn("again: %s", message)


PLANT = {"function": "warn_twice", "args": ["x"], "call": False}
