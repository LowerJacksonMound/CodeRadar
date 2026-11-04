"""Planted counterfeit for NAI-093 (Loader-less yaml.load) — health-check step 19.
call=False: PyYAML is not an engine dependency; parse + meaning check only."""
import yaml


def read_doc(text):
    return yaml.load(text)


PLANT = {"function": "read_doc", "args": ["a: 1"], "call": False}
