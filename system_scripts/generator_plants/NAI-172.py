"""Planted counterfeit for NAI-172 (an `except Exception:` handler before the `except ValueError:` it shadows) —
health-check step 19, set 4b-11. call=True: parse("12") must return 12 before and after the rewrite (the try
body is untouched; only the handlers change places)."""


def parse(text):
    try:
        value = int(text)
    except Exception:
        value = -1
    except ValueError:
        value = 0
    return value


PLANT = {"function": "parse", "args": ["12"], "call": True}
