"""Planted counterfeit for NAI-091 (a parameter mutated in place with another parameter's value) — health-check
step 19, FIX_43 (b); reshaped by FIX_58 (owner's ruling 3, 2026-09-17).

The plant is now a unit the owner's three conditions ADMIT: the parameter is mutated (1), the function already
returns that collection (2), and nothing here says in-place mutation is the contract (3) — no `push` / `mark_*` /
`add_*` name, no identity test on the argument. The earlier plant was `add_entry(table, key, value)` with no
return: `add_` is the owner's own example of a name whose contract IS the mutation, so under FIX_58 the rewriter
declines it and step 19 would have read "rewriter declined its own plant". G0's step-19 sweep had already flagged
that plant (`shallow_copy` gate-withheld on the name).

call=True on ({}, "k", 1): before → {"k": 1} (the caller's dict, mutated and handed back);
`shallow_copy` → {"k": 1} (a copy, mutated and handed back) — the same value, the caller's dict untouched.
`shallow_copy_returned` is not offered here: the function already returns a value.
"""


def with_entry(table, key, value):
    table[key] = value
    return table


PLANT = {"function": "with_entry", "args": [{}, "k", 1], "call": True}
