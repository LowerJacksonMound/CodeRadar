"""Planted counterfeit code for set 4b-37 (family `hallucination`): NAI-057, NAI-058, NAI-059 — one construct per id,
real data flow beside each (run 91, app copy 1)."""


def read_stage(path):
    try:
        import file_handler
    except ImportError:
        raise
    text = file_handler.read(path)
    return text.strip()


class Bucket:
    def __init__(self, items):
        self.items = list(items)

    def __serialize__(self):
        return {"items": self.items, "count": len(self.items)}


def verbosity(settings, level):
    if settings.MODE_VERBOSE:
        return level + 2
    return level
