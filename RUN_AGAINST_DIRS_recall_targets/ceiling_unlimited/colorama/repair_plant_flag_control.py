"""Control for set 4b-43: NAI-085's shape — a boolean-default parameter switching an `if` — with real data flow
beside it. The detector `_check_flag_argument` was struck from `run_all_checks` at run 19 (2026-09-05), so this file
must stay clean of NAI-085 (and of every other rule)."""


def scale(width, wide=False):
    if wide:
        return width * 2
    return width
