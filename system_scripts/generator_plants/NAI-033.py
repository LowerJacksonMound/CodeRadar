"""Planted counterfeit for NAI-033 (`[row for row in rows]`, an identity comprehension) — health-check step 19,
set 4b-32. call=True: copy_rows([1, 2, 3]) must return [1, 2, 3] before and after the rewrite (`list(rows)`)."""


def copy_rows(rows):
    return [row for row in rows]


PLANT = {"function": "copy_rows", "args": [[1, 2, 3]], "call": True}
