"""Planted counterfeit for NAI-021S — R1 (2026-09-30): a parameter whose type the code CONTRADICTS.

`tags["merged"] = True` says dict (a str key); `tags.extend(extra)` says list. One function serves both, so
neither `dict(tags)` nor `list(tags)` is right for every caller: `new_sequence` must DECLINE (the rewriter
offers only the never-applied `no_rewrite_shape`, whose text states the conflict). The call proves the
plant itself runs.
"""


def merge_tags(tags, extra):
    """Merge `extra` into `tags` in place and hand the container back."""
    if isinstance(tags, dict):
        tags.update(extra)
        tags["merged"] = True
    else:
        tags.extend(extra)
    return tags


PLANT = {"function": "merge_tags", "args": [{"a": 1}, {"b": 2}], "call": True, "expect_decline": True}
