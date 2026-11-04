"""Planted counterfeit for SEC-010 (a Popen through the shell, the regex scan's id for NAI-092's site) — health-check
step 19, set 4b-06. call=False: the gate never spawns a process; parse + meaning check (the regex goes quiet) only."""
import subprocess


def host_name():
    return subprocess.Popen("hostname -s", shell=True)


PLANT = {"function": "host_name", "args": [], "call": False}
