"""Planted counterfeit for NAI-060 (`not not x`) — health-check step 19, set 4b-30.
call=True: before and after are called with a non-empty list; both must return True."""


def has_items(items):
    count = len(items)
    return not not count


PLANT = {"function": "has_items", "args": [[1, 2]], "call": True}
