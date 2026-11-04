"""T1 plant: max_retries (2 sites) vs maxRetries (1 site)."""

max_retries = 3


def connect(host, max_retries):
    return (host, max_retries)


def reconnect(host, maxRetries):
    return (host, maxRetries)
