"""High-level registry service that sits on top of the SQLite store."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable

from subdivisions.models import Owner, Parcel, Zone
from subdivisions.store import ParcelStore
from subdivisions.validate import (
    normalise_parcel_id,
    validate_owner_fields,
    validate_parcel,
)


class RegistryError(ValueError):
    """Raised when a registry operation is rejected."""


class Registry:
    """Validates and records owners and parcels."""

    def __init__(self, store: ParcelStore) -> None:
        self.store = store

    def close(self) -> None:
        """Release the underlying store."""
        self.store.close()

    # -- owners -------------------------------------------------------------

    def register_owner(self, name: str, email: str) -> Owner:
        """Create an owner, or return the existing one with the same e-mail."""
        problems = validate_owner_fields(name, email)
        if problems:
            raise RegistryError("; ".join(problems))
        existing = self.store.find_owner_by_email(email)
        if existing is not None:
            return existing
        return self.store.add_owner(Owner(name=name.strip(), email=email.strip().lower()))

    def owner_of(self, parcel_id: str) -> Owner | None:
        """Return the owner on title for ``parcel_id`` or None."""
        parcel = self.store.get_parcel(parcel_id)
        if parcel is None or parcel.owner_id is None:
            return None
        return self.store.get_owner(parcel.owner_id)

    # -- parcels ------------------------------------------------------------

    def register_parcel(self, parcel: Parcel) -> Parcel:
        """Validate and record a parcel, normalising its identifier first."""
        parcel.parcel_id = normalise_parcel_id(parcel.parcel_id)
        problems = validate_parcel(parcel)
        if problems:
            raise RegistryError("; ".join(problems))
        if self.store.get_parcel(parcel.parcel_id) is not None:
            raise RegistryError(f"parcel {parcel.parcel_id} already registered")
        try:
            self.store.add_parcel(parcel)
        except sqlite3.IntegrityError as exc:
            raise RegistryError(f"parcel {parcel.parcel_id} rejected: {exc}") from exc
        stored = self.store.get_parcel(parcel.parcel_id)
        assert stored is not None
        return stored

    def import_parcels(self, parcels: Iterable[Parcel]) -> int:
        """Register each parcel, skipping duplicates; returns the number added."""
        added = 0
        for parcel in parcels:
            try:
                self.register_parcel(parcel)
            except RegistryError:
                continue
            added += 1
        return added

    def all_parcels(self, zone: Zone | None = None) -> list[Parcel]:
        """Return every parcel, optionally restricted to one zone."""
        return self.store.list_parcels(zone)

    def find_by_street(self, street: str) -> list[Parcel]:
        """Return parcels whose street name contains ``street`` (case-insensitive)."""
        needle = street.strip().lower()
        return [p for p in self.store.list_parcels() if needle in p.street.lower()]

    def find_by_tag(self, tag: str) -> list[Parcel]:
        """Return parcels carrying ``tag``."""
        matches: list[Parcel] = []
        for parcel in self.store.list_parcels():
            if parcel.has_tag(tag):
                matches.append(parcel)
        return matches

    def transfer(self, parcel_id: str, new_owner_id: int) -> Parcel:
        """Move a parcel onto a new owner's title and return the updated parcel."""
        parcel = self.store.get_parcel(parcel_id)
        if parcel is None:
            raise RegistryError(f"no parcel {parcel_id}")
        if self.store.get_owner(new_owner_id) is None:
            raise RegistryError(f"no owner {new_owner_id}")
        previous = parcel.owner_id
        self.store.assign_owner(parcel_id, new_owner_id)
        updated = self.store.get_parcel(parcel_id)
        assert updated is not None
        return updated

    def holdings(self) -> list[tuple[Owner, list[Parcel]]]:
        """Pair every owner with the parcels they hold, ordered by owner name."""
        result: list[tuple[Owner, list[Parcel]]] = []
        for owner in self.store.list_owners():
            assert owner.owner_id is not None
            result.append((owner, self.store.parcels_for_owner(owner.owner_id)))
        return result

    def unowned(self) -> list[Parcel]:
        """Return parcels with nobody on title."""
        return [p for p in self.store.list_parcels() if p.owner_id is None]
