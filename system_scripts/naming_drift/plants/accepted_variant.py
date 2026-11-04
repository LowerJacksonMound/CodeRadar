"""Accepted plant: buffer_size (2 sites) vs buf_size (1 site) — buf_size is ruled a legitimate variant in accepted_<repoid>.json, so no row."""

buffer_size = 4096


def allocate(buffer_size):
    return bytearray(buffer_size)


def allocate_small(buf_size):
    return bytearray(buf_size)
