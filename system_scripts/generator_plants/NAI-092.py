"""Planted counterfeit for NAI-092 (subprocess with shell=True) — health-check step 19.
call=False: the gate never spawns a process; parse + meaning check only."""
import subprocess


def run_echo():
    return subprocess.run("echo hi", shell=True, capture_output=True).stdout


PLANT = {"function": "run_echo", "args": [], "call": False}
