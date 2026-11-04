"""Planted counterfeits for SEC-009 / SEC-010 / SEC-011 / SEC-012 / SEC-013 — set 4b-06 (2026-09-10). An os.system
call, a Popen through the shell (the site NAI-092 rewrites), a literal token, a dunder import by name and a
compile of source for execution: what each dynamic call should become, and where a secret comes from, are the
author's design — no-fix-by-design rows except the Popen alias, nothing else to rewrite."""
import os
import subprocess


def clear():
    return os.system("clear")


def host():
    return subprocess.Popen("hostname -s", shell=True)


def credentials():
    token = "abc123def456"
    return token


def plugin_for(name):
    return __import__(name)


def prepare(source):
    return compile(source, "<string>", "exec")
