"""Planted counterfeits for NAI-017 / NAI-018 / NAI-019 / NAI-020 / NAI-021 — set 4b-21 (2026-09-10). A broad
`suppress` around a call, an async def that never awaits (NAI-018's construct — nothing decides it: the extractor
never sets is_async, so the row passes; kept out of `planted_findings` and recorded), a branching function whose
every return is the same literal, a test that asserts nothing, and a loop that only prints. What the author meant
is theirs in the four decided rows — no-fix-by-design, nothing to rewrite."""
from contextlib import suppress


def hushed(fn):
    with suppress(Exception):
        fn()


async def fetch(url):
    return url.strip()


def flag(x):
    if x > 1:
        return 0
    return 0


def test_render():
    str(1)


def report(items):
    for item in items:
        print(item)
