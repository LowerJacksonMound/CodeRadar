"""FIX_17 plant (2026-09-10) — the first per-(rule, context) dispositions.

NAI-229 (repetitive top-level statement structure) and NAI-230 (a normalized-fingerprint group) are context
by default; each DECIDES above the table's magnitude N (229: 18, 230: 8) for a non-test file. This file crosses
both: `weights_table` repeats one statement type twenty times; the eight `scale_*` functions share one
normalized fingerprint. Every other row here stays clean.
"""


def weights_table(base):
    w1 = base + 1
    w2 = base + 2
    w3 = base + 3
    w4 = base + 4
    w5 = base + 5
    w6 = base + 6
    w7 = base + 7
    w8 = base + 8
    w9 = base + 9
    w10 = base + 10
    w11 = base + 11
    w12 = base + 12
    w13 = base + 13
    w14 = base + 14
    w15 = base + 15
    w16 = base + 16
    w17 = base + 17
    w18 = base + 18
    w19 = base + 19
    w20 = base + 20
    return [w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15, w16, w17, w18, w19, w20]


def scale_alpha(value):
    out = value * 2
    if out > 10:
        return out
    return 10


def scale_beta(value):
    out = value * 3
    if out > 20:
        return out
    return 20


def scale_gamma(value):
    out = value * 4
    if out > 30:
        return out
    return 30


def scale_delta(value):
    out = value * 5
    if out > 40:
        return out
    return 40


def scale_epsilon(value):
    out = value * 6
    if out > 50:
        return out
    return 50


def scale_zeta(value):
    out = value * 7
    if out > 60:
        return out
    return 60


def scale_eta(value):
    out = value * 8
    if out > 70:
        return out
    return 70


def scale_theta(value):
    out = value * 9
    if out > 80:
        return out
    return 80
