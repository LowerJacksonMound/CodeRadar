"""Planted counterfeit for SEC-004 (Loader-less yaml.load, the regex scan's id for NAI-093's site) — health-check
step 19, set 4b-05. call=False: PyYAML is not an engine dependency; parse + meaning check (the regex goes quiet) only."""
import yaml


def read_settings(text):
    return yaml.load(text)


PLANT = {"function": "read_settings", "args": ["a: 1"], "call": False}
