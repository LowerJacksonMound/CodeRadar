"""Planted counterfeit for NAI-162 (a requests call with verify=False) — health-check step 19, set 4b-10.
call=False: the gate makes no HTTP request; parse + meaning check only."""
import requests


def fetch(url):
    return requests.get(url, verify=False)


PLANT = {"function": "fetch", "args": ["https://example.invalid/"], "call": False}
