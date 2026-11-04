"""T1 plant: file_path (2 sites) vs filePath (1 site)."""


def read_lines(file_path):
    return open(file_path).read().splitlines()


class Reader:
    def __init__(self, file_path):
        self.file_path = file_path

    def reopen(self, filePath):
        return read_lines(filePath)
