"""T2 plant: message_count (2 sites) vs msg_cnt (1 site) — msg -> message, cnt -> count."""

message_count = 0


class Mailbox:
    def __init__(self):
        self.message_count = 0

    def tally(self, msg_cnt):
        self.message_count = msg_cnt
