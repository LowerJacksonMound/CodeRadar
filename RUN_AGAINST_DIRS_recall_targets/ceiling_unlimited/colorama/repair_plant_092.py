"""Planted counterfeit for NAI-092 (subprocess with shell=True) — planted for run 48 (item 4 first batch).
call=False: the gate never spawns a process; parse + meaning check only."""
import subprocess


def run_echo():
    return subprocess.run("echo hi", shell=True, capture_output=True).stdout


