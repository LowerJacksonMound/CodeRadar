"""Planted counterfeits for NAI-209 / NAI-211 — set 4b-02 (2026-09-10). Each try/except ImportError fallback
binds a name to None: the silent-failure fallback (NAI-209) and the fallback whose name does not match the
import (NAI-211). Whether the dependency is optional, and what should stand in for it, is the author's intent:
no-fix-by-design rows, nothing to rewrite."""
try:
    from json import dumps
except ImportError:
    dumps = None

try:
    from json import loads
except ImportError:
    parse_json = None


def render(payload):
    return dumps(payload)
