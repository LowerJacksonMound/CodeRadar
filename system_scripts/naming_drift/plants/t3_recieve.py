"""T3 plant: receive_message (2 sites) vs recieve_message (1 site) — one token one edit apart, every token >= 4 letters."""


def receive_message(channel):
    return channel


class Inbox:
    def receive_message(self, channel):
        return receive_message(channel)

    def recieve_message(self, channel):
        return receive_message(channel)
