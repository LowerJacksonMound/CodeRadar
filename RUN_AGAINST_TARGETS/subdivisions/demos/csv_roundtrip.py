"""Export the sample parcels to CSV, import them into a fresh database and audit it."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from subdivisions.audit import audit_parcels, summarise
from subdivisions.csvio import read_parcels, write_parcels
from subdivisions.registry import Registry
from subdivisions.seed import sample_parcels
from subdivisions.store import ParcelStore


def run() -> dict[str, int]:
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "parcels.csv"
        written = write_parcels(csv_path, sample_parcels())
        print(f"wrote {written} parcels to {csv_path.name}")

        registry = Registry(ParcelStore(str(Path(tmp) / "registry.db")))
        try:
            added = registry.import_parcels(read_parcels(csv_path))
            print(f"imported {added} parcels")
            findings = audit_parcels(registry.all_parcels())
        finally:
            registry.close()

    for finding in findings:
        print(finding.line())
    summary = summarise(findings)
    print(summary)
    return summary


if __name__ == "__main__":
    run()
