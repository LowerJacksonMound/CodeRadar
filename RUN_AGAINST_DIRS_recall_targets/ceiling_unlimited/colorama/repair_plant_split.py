"""Planted constructs for RCA-001 — set 4b-26 (2026-09-10), portion D's last. The split-fake pair: a helper that
returns canned data whatever its inputs (it fails on its own row: NAI-003 / 009 / 030) and a public function
that delegates to it while forwarding none of its own parameters. RCA-001's sweep would flip the public function
to FAIL — the sweep runs inside the per-file pass before the helper's verdict exists, so today the public
function passes and RCA-001 decides no row (declared with the fact; the pinned split-fake question, untouched)."""


def load_table(path, encoding):
    return {}


def read_config(path, encoding):
    return load_table("fixed", "utf-8") or {"path": path, "encoding": encoding}
