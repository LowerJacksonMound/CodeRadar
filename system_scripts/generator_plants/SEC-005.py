"""Planted counterfeit for SEC-005 (the shell flag on a subprocess call, the regex scan's id for NAI-092's site) — health-check step 19,
set 4b-05. call=False: the gate never spawns a process; parse + meaning check (the regex goes quiet) only."""
import subprocess


def run_date():
    return subprocess.run("hostname -s", shell=True, capture_output=True).stdout


PLANT = {"function": "run_date", "args": [], "call": False}
