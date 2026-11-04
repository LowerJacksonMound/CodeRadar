"""Print the sample report, then a second one restricted to the commercial zone."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from subdivisions.models import Zone
from subdivisions.report import report_text
from subdivisions.seed import build_demo_registry


def run() -> str:
    registry = build_demo_registry()
    try:
        text = report_text(registry) + "\n\n" + report_text(registry, Zone.COMMERCIAL)
    finally:
        registry.close()
    print(text)
    return text


if __name__ == "__main__":
    run()
