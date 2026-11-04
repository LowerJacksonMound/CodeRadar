"""Planted counterfeit code for set 4b-43 (family `style`): NAI-087, NAI-088, NAI-089, NAI-179 — one construct per id,
real data flow beside each; NAI-085's shape sits in `repair_plant_flag_control.py` (run 97, app copy 1, the LAST 4b set)."""


def spacer(rows, pad):
    total = 0
    for row in rows:
        width = len(pad)
        total += len(row[:width])
    return total


def dashes(parts):
    text = ""
    for part in parts:
        text += "-"
    return text


def gather(header, items):
    out = [header]
    for item in items:
        out.append(item)
    return out


def glue(parts):
    text = ""
    for part in parts:
        text = text + str(part)
    return text
