"""RCA-001's CONTROL — FIX_47 (2026-09-17, owner Q7), beside `repair_plant_split.py`'s split-fake.

A caller of a callee that PASSES, forwarding its own parameters into it. The sweep must find no
failed callee here, so the row carries no RCA-001 observation and the Ranker is handed nothing —
the other half of the plant's reading. Listed as a control."""


def width_of(text, tab_size):
    """The callee: its answer depends on both of its inputs."""
    total = 0
    for ch in text:
        if ch == "\t":
            total += tab_size
        else:
            total += 1
    return total


def pad_to_width(text, tab_size):
    """The caller: forwards its own parameters into the callee and uses the answer."""
    used = width_of(text, tab_size)
    if used >= tab_size:
        return text
    return text + " " * (tab_size - used)
