"""I-53's construct — FIX_47 lane (2026-09-17): a runner that stays alive long enough to be seen.

The same RELATIVE path exists in a decoy tree outside the target. `test_runner_tracker._under`
resolves a relative command-line token against the target, so before I-53 both processes matched
this target's band; only the one whose cwd is under the target is this target's event.
The dwell is read from the environment, so the file is inert unless a proof asks for it."""
import os
import time


def test_dwell():
    seconds = float(os.environ.get("CEILING_UNLIMITED_DWELL", "0") or 0)
    if seconds:
        time.sleep(seconds)
    assert seconds >= 0
