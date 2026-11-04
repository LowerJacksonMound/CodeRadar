"""Planted counterfeits for NAI-162 / NAI-163 / NAI-164 / NAI-165 / NAI-166 — set 4b-10 (2026-09-10). A requests
call with certificate validation switched off (rewritten live: verify=True), a literal all-interfaces bind
address, a race-prone tempfile.mktemp(), a string carrying a right-to-left override character, and a raise of
the NotImplemented singleton (rewritten live: NotImplementedError)."""
import tempfile

import requests


def fetch(url):
    return requests.get(url, timeout=5, verify=False)


def serve(sock):
    sock.bind(("0.0.0.0", 8080))


def scratch_path():
    return tempfile.mktemp()


def label():
    return "total ‮ latot"


def area(shape):
    if shape == "circle":
        return 3
    raise NotImplemented
