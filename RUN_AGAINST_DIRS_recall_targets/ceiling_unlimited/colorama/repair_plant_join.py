"""Planted counterfeits for NAI-116 / NAI-118 — set 4b-29 (2026-09-10), portion E's last. A render_* that builds
its string with `+=` inside a for loop (the join role's exact shape: `text = ""` directly above, the `+=` the loop's
only statement, the loop target read nowhere else) and a validate_* that only ever answers True / False with no
raise and no error call. The first is the one mechanical repair (`join_fix`); whether a validator should raise,
report, or answer with a bool is the author's — no-fix-by-design."""


def render_tags(tags):
    text = ""
    for tag in tags:
        text += str(tag)
    return text


def validate_port(port):
    port = int(port)
    if port > 0:
        return True
    return False
