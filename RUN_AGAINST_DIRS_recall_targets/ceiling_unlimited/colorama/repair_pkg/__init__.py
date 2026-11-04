"""NAI-205's construct — set 4b-25 (2026-09-10): a module-level __getattr__ in an __init__.py. A warning line
only; the file passes — listed as a control."""


def __getattr__(name):
    raise AttributeError(name)
