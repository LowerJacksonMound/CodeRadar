"""Core data types for the subdivisions registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Zone(str, Enum):
    """Zoning designations used by the registry."""

    RESIDENTIAL = "R1"
    DUPLEX = "R2"
    COMMERCIAL = "C1"
    INDUSTRIAL = "M1"
    PARK = "P1"

    @classmethod
    def parse(cls, text: str) -> "Zone":
        """Return the zone whose code or name matches ``text``, ignoring case."""
        key = text.strip().upper()
        for zone in cls:
            if zone.value == key or zone.name == key:
                return zone
        raise ValueError(f"unknown zone: {text!r}")


ZONE_LABELS: dict[Zone, str] = {
    Zone.RESIDENTIAL: "Single-family residential",
    Zone.DUPLEX: "Two-family residential",
    Zone.COMMERCIAL: "Neighbourhood commercial",
    Zone.INDUSTRIAL: "Light industrial",
    Zone.PARK: "Parks and open space",
}


@dataclass
class Owner:
    """A person or company that holds title to one or more parcels."""

    name: str
    email: str
    owner_id: int | None = None

    def display(self) -> str:
        """Return the owner as ``Name <email>``."""
        return f"{self.name} <{self.email}>"


@dataclass
class Parcel:
    """A single lot in the subdivision."""

    parcel_id: str
    street_number: int
    street: str
    zone: Zone
    width_m: float
    depth_m: float
    owner_id: int | None = None
    tags: list[str] = field(default_factory=list)

    @property
    def address(self) -> str:
        """Return the civic address, e.g. ``12 Elm Crescent``."""
        return str(self.street_number) + " " + self.street

    @property
    def area_m2(self) -> float:
        """Return the lot area in square metres, rounded to two decimals."""
        return round(self.width_m * self.depth_m, 2)

    def has_tag(self, tag: str) -> bool:
        """Return True when ``tag`` is attached to this parcel (case-insensitive)."""
        wanted = tag.strip().lower()
        return any(existing.lower() == wanted for existing in self.tags)

    def to_row(self) -> dict[str, str]:
        """Flatten the parcel into a dictionary of strings for CSV or SQL."""
        return {
            "parcel_id": self.parcel_id,
            "street_number": str(self.street_number),
            "street": self.street,
            "zone": self.zone.value,
            "width_m": f"{self.width_m:g}",
            "depth_m": f"{self.depth_m:g}",
            "owner_id": "" if self.owner_id is None else str(self.owner_id),
            "tags": ";".join(self.tags),
        }

    @classmethod
    def from_row(cls, row: dict[str, str]) -> "Parcel":
        """Build a parcel from a dictionary produced by :meth:`to_row`."""
        owner_text = (row.get("owner_id") or "").strip()
        tag_text = (row.get("tags") or "").strip()
        return cls(
            parcel_id=row["parcel_id"].strip(),
            street_number=int(row["street_number"]),
            street=row["street"].strip(),
            zone=Zone.parse(row["zone"]),
            width_m=float(row["width_m"]),
            depth_m=float(row["depth_m"]),
            owner_id=int(owner_text) if owner_text else None,
            tags=[tag for tag in tag_text.split(";") if tag],
        )


def stamp_registered(tags: list[str] = []) -> list[str]:
    """Add the ``registered`` marker to a tag list and hand the list back."""
    tags.append("registered")
    return tags
