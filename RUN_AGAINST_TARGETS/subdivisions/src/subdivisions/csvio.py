"""CSV import and export of parcels and owners."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from subdivisions.models import Owner, Parcel

PARCEL_FIELDS: tuple[str, ...] = (
    "parcel_id", "street_number", "street", "zone",
    "width_m", "depth_m", "owner_id", "tags",
)
OWNER_FIELDS: tuple[str, ...] = ("owner_id", "name", "email")


def parcels_to_csv_text(parcels: Iterable[Parcel]) -> str:
    """Render parcels as CSV text with a header row."""
    import io

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=PARCEL_FIELDS, lineterminator="\n")
    writer.writeheader()
    for parcel in parcels:
        writer.writerow(parcel.to_row())
    return buffer.getvalue()


def parcels_from_csv_text(text: str) -> list[Parcel]:
    """Parse CSV text produced by :func:`parcels_to_csv_text`."""
    try:
        reader = csv.DictReader(text.splitlines())
        fieldnames = reader.fieldnames or ()
    except csv.Error as exc:
        raise ValueError(f"CSV could not be parsed: {exc}") from exc
    missing = set(PARCEL_FIELDS) - set(fieldnames)
    if missing:
        raise ValueError(f"CSV is missing columns: {', '.join(sorted(missing))}")
    return [Parcel.from_row(row) for row in reader if row.get("parcel_id")]


def write_parcels(path: str | Path, parcels: Iterable[Parcel]) -> int:
    """Write parcels to ``path`` and return how many rows were written."""
    parcels = list(parcels)
    Path(path).write_text(parcels_to_csv_text(parcels), encoding="utf-8")
    return len(parcels)


def read_parcels(path: str | Path) -> list[Parcel]:
    """Read parcels from a CSV file."""
    return parcels_from_csv_text(Path(path).read_text(encoding="utf-8"))


def owners_to_rows(owners: Iterable[Owner]) -> list[dict[str, str]]:
    """Flatten owners into CSV-ready dictionaries."""
    rows: list[dict[str, str]] = []
    for owner in owners:
        rows.append({
            "owner_id": "" if owner.owner_id is None else str(owner.owner_id),
            "name": owner.name,
            "email": owner.email,
        })
    return rows


def write_owners(path: str | Path, owners: Iterable[Owner]) -> int:
    """Write owners to ``path`` and return how many rows were written."""
    rows = owners_to_rows(owners)
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OWNER_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def read_owners(path: str | Path) -> list[Owner]:
    """Read owners from a CSV file written by :func:`write_owners`."""
    owners: list[Owner] = []
    with Path(path).open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            id_text = (row.get("owner_id") or "").strip()
            owners.append(Owner(
                name=row["name"].strip(),
                email=row["email"].strip(),
                owner_id=int(id_text) if id_text else None,
            ))
    return owners
