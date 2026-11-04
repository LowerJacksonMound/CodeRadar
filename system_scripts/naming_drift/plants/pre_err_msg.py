"""Pre-existing plant 2: one group, three spellings at launch — err_msg (3 sites, canonical), errMsg (T1), error_message (T2)."""

err_msg = ""


def fail(err_msg):
    return err_msg


def fail_again(errMsg):
    return errMsg


class Failure:
    def __init__(self, err_msg):
        self.error_message = err_msg
