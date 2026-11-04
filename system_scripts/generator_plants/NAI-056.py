"""Planted counterfeit for NAI-056 (a misspelled module name in an import) — health-check step 19, set 4b-36.
Exactly the detector's shape: a function-level `import colections` (MISSPELLED_MODULES, correction `collections`)
with the bound name used once below it. call=False: the before-function raises ModuleNotFoundError, so there is
nothing to compare; the rewrite respells the import and the reference together."""


def ordered_table(name):
    import colections
    table = colections.OrderedDict()
    table[name] = 0
    return table


PLANT = {"function": "ordered_table", "args": ["x"], "call": False}
