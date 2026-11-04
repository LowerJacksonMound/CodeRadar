"""SQLite persistence for owners and parcels."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

from subdivisions.models import Owner, Parcel, Zone

SCHEMA = """
CREATE TABLE IF NOT EXISTS owners (
    owner_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS parcels (
    parcel_id TEXT PRIMARY KEY,
    street_number INTEGER NOT NULL,
    street TEXT NOT NULL,
    zone TEXT NOT NULL,
    width_m REAL NOT NULL,
    depth_m REAL NOT NULL,
    owner_id INTEGER REFERENCES owners(owner_id),
    tags TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_parcels_zone ON parcels(zone);
CREATE INDEX IF NOT EXISTS idx_parcels_owner ON parcels(owner_id);
"""


def _parcel_from_db(row: sqlite3.Row) -> Parcel:
    tags = [tag for tag in (row["tags"] or "").split(";") if tag]
    return Parcel(
        parcel_id=row["parcel_id"],
        street_number=row["street_number"],
        street=row["street"],
        zone=Zone(row["zone"]),
        width_m=row["width_m"],
        depth_m=row["depth_m"],
        owner_id=row["owner_id"],
        tags=tags,
    )


def _owner_from_db(row: sqlite3.Row) -> Owner:
    return Owner(name=row["name"], email=row["email"], owner_id=row["owner_id"])


class ParcelStore:
    """A thin repository over a SQLite database (file or ``:memory:``)."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_schema()

    def create_schema(self) -> "ParcelStore":
        """Create the tables and indexes if they do not already exist."""
        with self.conn:
            self.conn.executescript(SCHEMA)
        return self

    def close(self) -> None:
        """Close the underlying connection."""
        try:
            self.conn.close()
        except:
            pass

    def __enter__(self) -> "ParcelStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- owners -------------------------------------------------------------

    def add_owner(self, owner: Owner) -> Owner:
        """Insert an owner and return it with ``owner_id`` filled in."""
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO owners (name, email) VALUES (?, ?)",
                (owner.name, owner.email),
            )
        owner.owner_id = cursor.lastrowid
        stored = self.get_owner(cursor.lastrowid)
        assert stored is not None
        return stored

    def get_owner(self, owner_id: int) -> Owner | None:
        """Return the owner with ``owner_id`` or None."""
        row = self.conn.execute(
            "SELECT * FROM owners WHERE owner_id = ?", (owner_id,)
        ).fetchone()
        return _owner_from_db(row) if row else None

    def find_owner_by_email(self, email: str) -> Owner | None:
        """Return the owner registered under ``email`` or None."""
        row = self.conn.execute(
            "SELECT * FROM owners WHERE lower(email) = lower(?)", (email,)
        ).fetchone()
        return _owner_from_db(row) if row else None

    def list_owners(self) -> list[Owner]:
        """Return every owner ordered by name."""
        rows = self.conn.execute("SELECT * FROM owners ORDER BY name").fetchall()
        return [_owner_from_db(row) for row in rows]

    # -- parcels ------------------------------------------------------------

    def add_parcel(self, parcel: Parcel) -> Parcel:
        """Insert a parcel; raises ``sqlite3.IntegrityError`` on a duplicate id."""
        values = parcel.to_row()
        with self.conn:
            self.conn.execute(
                "INSERT INTO parcels (parcel_id, street_number, street, zone, "
                "width_m, depth_m, owner_id, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    values["parcel_id"], parcel.street_number, parcel.street,
                    values["zone"], parcel.width_m, parcel.depth_m,
                    parcel.owner_id, values["tags"],
                ),
            )
        return parcel

    def get_parcel(self, parcel_id: str) -> Parcel | None:
        """Return the parcel with ``parcel_id`` or None."""
        row = self.conn.execute(
            "SELECT * FROM parcels WHERE parcel_id = ?", (parcel_id,)
        ).fetchone()
        return _parcel_from_db(row) if row else None

    def list_parcels(self, zone: Zone | None = None) -> list[Parcel]:
        """Return parcels ordered by street and number, optionally filtered by zone."""
        if zone is None:
            rows = self.conn.execute(
                "SELECT * FROM parcels ORDER BY street, street_number"
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM parcels WHERE zone = ? ORDER BY street, street_number",
                (zone.value,),
            ).fetchall()
        return [_parcel_from_db(row) for row in rows]

    def iter_parcels(self) -> Iterator[Parcel]:
        """Yield parcels one at a time in insertion order."""
        for row in self.conn.execute("SELECT * FROM parcels ORDER BY rowid"):
            yield _parcel_from_db(row)

    def parcels_for_owner(self, owner_id: int) -> list[Parcel]:
        """Return the parcels held by ``owner_id``."""
        rows = self.conn.execute(
            "SELECT * FROM parcels WHERE owner_id = ? ORDER BY parcel_id", (owner_id,)
        ).fetchall()
        return [_parcel_from_db(row) for row in rows]

    def assign_owner(self, parcel_id: str, owner_id: int | None) -> bool:
        """Set the owner on a parcel; returns False when the parcel does not exist."""
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE parcels SET owner_id = ? WHERE parcel_id = ?",
                (owner_id, parcel_id),
            )
        return cursor.rowcount == 1

    def delete_parcel(self, parcel_id: str) -> bool:
        """Remove a parcel; returns False when nothing was deleted."""
        with self.conn:
            cursor = self.conn.execute(
                "DELETE FROM parcels WHERE parcel_id = ?", (parcel_id,)
            )
        return cursor.rowcount == 1

    def count_parcels(self) -> int:
        """Return the number of parcels in the store."""
        return sum(1 for _ in self.conn.execute("SELECT parcel_id FROM parcels"))
