"""Allow ``python -m subdivisions`` to run the command-line interface."""

import sys

from subdivisions.cli import main

if __name__ == "__main__":
    sys.exit(main())
