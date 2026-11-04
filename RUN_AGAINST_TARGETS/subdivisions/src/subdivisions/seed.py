"""Sample data for demos and tests."""

from __future__ import annotations

from subdivisions.models import Parcel, Zone, stamp_registered
from subdivisions.registry import Registry
from subdivisions.store import ParcelStore

SAMPLE_OWNERS: tuple[tuple[str, str], ...] = (
    ("Geddy Lee", "geddy@example.com"),
    ("Alex Lifeson", "alex@example.com"),
    ("Neil Peart", "neil@example.com"),
    ("Hemispheres Holdings", "title@hemispheres.example.com"),
)


def sample_parcels() -> list[Parcel]:
    """Return a fresh list of sample parcels (owner ids are filled in by :func:`seed_registry`)."""
    parcels = [
        Parcel("SD-001-01", 2, "Elm Crescent", Zone.RESIDENTIAL, 15.0, 32.0,
               tags=stamp_registered(["corner"])),
        Parcel("SD-001-02", 4, "Elm Crescent", Zone.RESIDENTIAL, 12.5, 32.0,
               tags=stamp_registered([])),
        Parcel("SD-001-03", 6, "Elm Crescent", Zone.RESIDENTIAL, 11.0, 30.0,
               tags=stamp_registered([])),
        Parcel("SD-002-01", 1, "Willow Way", Zone.DUPLEX, 16.0, 34.0,
               tags=stamp_registered(["laneway"])),
        Parcel("SD-002-02", 3, "Willow Way", Zone.DUPLEX, 14.0, 34.0,
               tags=stamp_registered([])),
        Parcel("SD-003-01", 100, "Market Street", Zone.COMMERCIAL, 10.0, 40.0,
               tags=stamp_registered(["heritage"])),
        Parcel("SD-003-02", 102, "Market Street", Zone.COMMERCIAL, 8.0, 45.0,
               tags=stamp_registered([])),
        Parcel("SD-004-01", 7, "Foundry Road", Zone.INDUSTRIAL, 30.0, 60.0,
               tags=stamp_registered(["rail spur"])),
        Parcel("SD-004-02", 9, "Foundry Road", Zone.INDUSTRIAL, 24.0, 40.0,
               tags=stamp_registered([])),
        Parcel("SD-005-01", 1, "Common Green", Zone.PARK, 60.0, 80.0,
               tags=stamp_registered(["public"])),
    ]
    return parcels


OWNER_ASSIGNMENTS: dict[str, str] = {
    "SD-001-01": "geddy@example.com",
    "SD-001-02": "alex@example.com",
    "SD-001-03": "neil@example.com",
    "SD-002-01": "geddy@example.com",
    "SD-002-02": "alex@example.com",
    "SD-003-01": "title@hemispheres.example.com",
    "SD-004-01": "title@hemispheres.example.com",
    "SD-004-02": "title@hemispheres.example.com",
}


def seed_registry(registry: Registry) -> int:
    """Load the sample owners and parcels into ``registry``; returns parcels added."""
    owners_by_email = {
        email: registry.register_owner(name, email) for name, email in SAMPLE_OWNERS
    }
    parcels = sample_parcels()
    for parcel in parcels:
        email = OWNER_ASSIGNMENTS.get(parcel.parcel_id)
        if email is not None:
            parcel.owner_id = owners_by_email[email].owner_id
    return registry.import_parcels(parcels)


def build_demo_registry(path: str = ":memory:") -> Registry:
    """Open (or create) a store at ``path`` and seed it with sample data."""
    registry = Registry(ParcelStore(path))
    if registry.store.count_parcels() == 0:
        seed_registry(registry)
    return registry
