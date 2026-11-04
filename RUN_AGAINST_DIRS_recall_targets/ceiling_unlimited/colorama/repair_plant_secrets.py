"""Planted counterfeits for SEC-004 / SEC-005 / SEC-006 / SEC-007 / SEC-008 — set 4b-05 (2026-09-10). An unsafe
yaml.load and a subprocess call through the shell (sites NAI-093 / NAI-092 rewrite), then a literal password,
a literal API key and a query built with format: where a secret should come from and how a query is
parametrised are the author's design — no-fix-by-design rows, nothing to rewrite."""
import subprocess
import yaml


def load_settings(text):
    return yaml.load(text)


def list_dir(path):
    return subprocess.run("ls " + path, shell=True, capture_output=True).stdout


def connect(host):
    password = "hunter2"
    api_key = "sk-0123456789abcdef"
    return (host, password, api_key)


def find_user(cursor, sql_name):
    query = "select * from users where name = '{}'".format(sql_name)
    return cursor.execute(query)
