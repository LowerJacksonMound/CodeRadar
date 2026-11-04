"""Planted counterfeits for NAI-167 / NAI-172 / NAI-173 / NAI-200 / NAI-201 — set 4b-11 (2026-09-10). A hardcoded
service URL with no environment lookup, a try whose wide handler shadows the narrow one after it (rewritten
live: the handlers reordered), a return inside finally, a configparser getter with no error handling, and an
int() on a parameter with no guard."""


def endpoint(path):
    return "https://api.example.com/v1/" + path


def parse(text):
    try:
        value = int(text)
    except Exception:
        value = -1
    except ValueError:
        value = 0
    return value


def close_quietly(handle):
    try:
        handle.close()
    finally:
        return True


def port_of(parser):
    return parser.getint("main", "port")


def to_port(value):
    return int(value)
