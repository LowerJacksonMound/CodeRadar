"""Pre-existing plant 1: one group, three spellings at launch — tmp_dir (3 sites, canonical), tmpDir (T1), temp_dir (T2)."""

tmp_dir = "/tmp"


class Workspace:
    def __init__(self, tmp_dir):
        self.tmp_dir = tmp_dir

    def relocate(self, tmpDir):
        return tmpDir

    def relocate_slowly(self, temp_dir):
        return temp_dir
