"""Input validation for parcel identifiers, addresses and owner contact details."""

from __future__ import annotations

import re

from subdivisions.models import Parcel

PARCEL_ID_RE = re.compile(r"^[A-Z]{2}-\d{3}-\d{2}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
MAX_STREET_LENGTH = 60


def is_valid_parcel_id(text: str) -> bool:
    """Return True when ``text`` looks like ``AB-123-45``."""
    return bool(PARCEL_ID_RE.match(text.strip()))


def normalise_parcel_id(text: str) -> str:
    """Upper-case a parcel id and insert the dashes if they were left out."""
    compact = re.sub(r"[\s-]", "", text).upper()
    if len(compact) != 7:
        return text.strip().upper()
    return f"{compact[:2]}-{compact[2:5]}-{compact[5:]}"


def is_valid_email(text: str) -> bool:
    """Return True when ``text`` is a plausible e-mail address."""
    return bool(EMAIL_RE.match(text.strip()))


def parse_street_number(text: str) -> int:
    """Return the street number in ``text``, or 0 when it is not numeric."""
    try:
        number = int(text.strip())
    except ValueError as err:
        number = 0
    return number


def clean_street_name(text: str) -> str:
    """Collapse whitespace and title-case a street name."""
    words = text.split()
    cleaned = " ".join(word.capitalize() for word in words)
    return cleaned[:MAX_STREET_LENGTH]


def validate_parcel(parcel: Parcel) -> list[str]:
    """Return a list of human-readable problems with ``parcel`` (empty when valid)."""
    problems: list[str] = []
    if not is_valid_parcel_id(parcel.parcel_id):
        problems.append(f"parcel id {parcel.parcel_id!r} is malformed")
    if parcel.street_number <= 0:
        problems.append("street number must be positive")
    if not parcel.street.strip():
        problems.append("street name is empty")
    if parcel.width_m <= 0 or parcel.depth_m <= 0:
        problems.append("lot dimensions must be positive")
    if len(parcel.street) > MAX_STREET_LENGTH:
        problems.append("street name is too long")
    return problems


def validate_owner_fields(name: str, email: str) -> list[str]:
    """Return problems with an owner's name and e-mail (empty when valid)."""
    problems: list[str] = []
    if not name.strip():
        problems.append("owner name is empty")
    if not is_valid_email(email):
        problems.append(f"e-mail {email!r} is not valid")
    return problems
