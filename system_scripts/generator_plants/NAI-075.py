"""Planted counterfeit for NAI-075 (open() outside a context manager, closed by a plain .close() in the same
block) — health-check step 19, set 4b-07. call=False: the gate opens no file; parse + meaning check only."""


def read_all(path):
    fh = open(path)
    data = fh.read()
    total = len(data)
    fh.close()
    return data, total


PLANT = {"function": "read_all", "args": ["x"], "call": False}
