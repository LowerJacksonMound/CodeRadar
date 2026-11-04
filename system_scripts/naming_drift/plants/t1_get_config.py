"""T1 plant: get_config (2 sites) vs getConfig (1 site) — the fold alone equates them."""


def get_config(path):
    return {"path": path}


def getConfig(path):
    return get_config(path)


class Settings:
    def __init__(self, path):
        self.get_config = get_config(path)
