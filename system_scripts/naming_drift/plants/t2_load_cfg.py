"""T2 plant: load_config (2 sites) vs load_cfg (1 site) — only the abbreviation map (cfg -> config) equates them."""


def load_config(source):
    return {"source": source}


def load_cfg(source):
    return load_config(source)


class Loader:
    def load_config(self, source):
        return load_config(source)
