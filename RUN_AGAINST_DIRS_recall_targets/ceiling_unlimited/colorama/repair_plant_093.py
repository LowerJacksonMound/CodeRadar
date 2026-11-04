"""Planted counterfeit for NAI-093 (Loader-less yaml.load) — planted for run 48 (item 4 first batch).
call=False: PyYAML is not an engine dependency; parse + meaning check only."""
import yaml


def read_doc(text):
    return yaml.load(text)


