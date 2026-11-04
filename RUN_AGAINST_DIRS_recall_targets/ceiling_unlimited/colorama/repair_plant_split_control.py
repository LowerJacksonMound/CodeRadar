"""NAI-227 / NAI-IM01 / SYM-002 constructs — set 4b-26 (2026-09-10): a module-level lambda (the lambda count), an
import of a module that does not exist (the import helper emits nothing for it on the route), and an arithmetic
progression (a SYM-002 warning line). Warnings only; the file passes — listed as a control."""
import totally_missing_module_xyz

pick_first = lambda pair: pair[0]


def steps(scale):
    return [scale * v for v in (1, 2, 3, 4)]
