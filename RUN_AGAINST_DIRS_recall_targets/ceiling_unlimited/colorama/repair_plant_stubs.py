"""Planted counterfeits for NAI-213 / NAI-217 / NAI-218 — set 4b-03 (2026-09-10). An empty bare class,
an import of a name its module never defines, and an identity lambda: what the class should hold, which
name the import meant, and what the lambda stands in for are the author's intent — no-fix-by-design rows,
nothing to rewrite. Module scope also carries a mutable container (NAI-216) and imports (NAI-215)."""
from .ansi import code_to_chars, clear_display

REGISTRY = {}


class Placeholder:
    pass


identity = lambda x: x


def stamp(value):
    return code_to_chars(value)
