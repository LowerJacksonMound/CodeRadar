"""Planted counterfeits for NAI-074 / NAI-075 / NAI-077 — set 4b-07 (2026-09-10). A json.loads with no try, an
open() closed by a plain .close() in the same block (the one construct of the set with a mechanical repair:
`with open(...) as fh:`), and a dict read whose sibling key is guarded while this one is not. NAI-072 and
NAI-073 already sit in repair_plant_secrets.py (runs 59/60)."""
import json


def parse(text):
    return json.loads(text)


def read_all(path):
    fh = open(path)
    data = fh.read()
    fh.close()
    return data


def pick(row):
    label = ""
    if "name" in row:
        label = row["name"]
    return label, row["value"]
