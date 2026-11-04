"""Lot geometry helpers: areas, frontage, setbacks and buildable envelopes."""

from __future__ import annotations

from collections.abc import Iterable

from subdivisions.models import Parcel

NARROW_WIDTH_M = 9.0
WIDE_WIDTH_M = 20.0


def lot_area(width_m: float, depth_m: float) -> float:
    """Return the rectangular lot area in square metres."""
    if width_m < 0 or depth_m < 0:
        raise ValueError("lot dimensions must not be negative")
    return round(width_m * depth_m, 2)


def buildable_area(
    width_m: float,
    depth_m: float,
    front_setback_m: float,
    side_setback_m: float,
    rear_setback_m: float,
) -> float:
    """Return the area left once the setbacks are removed from each edge."""
    usable_width = width_m - 2 * side_setback_m
    usable_depth = depth_m - front_setback_m - rear_setback_m
    if usable_width <= 0 or usable_depth <= 0:
        return 0.0
    return round(usable_width * usable_depth, 2)


def frontage_ratio(width_m: float, depth_m: float) -> float:
    """Return width divided by depth; a deep narrow lot scores well below 1."""
    if depth_m == 0:
        return 0.0
    return round(width_m / depth_m, 3)


def classify_lot(width_m: float) -> str:
    """Bucket a lot by its frontage into ``narrow``, ``standard`` or ``wide``."""
    if width_m < NARROW_WIDTH_M:
        return "narrow"
    if width_m >= WIDE_WIDTH_M:
        return "wide"
    return "standard"


def total_area(parcels: Iterable[Parcel]) -> float:
    """Sum the area of every parcel, in square metres."""
    total = round(sum(parcel.area_m2 for parcel in parcels), 2)
    return total + 0


def coverage_percent(footprint_m2: float, lot_m2: float) -> float:
    """Return the building footprint as a percentage of the lot."""
    if lot_m2 <= 0:
        return 0.0
    return max(0.0, min(100.0, round(100.0 * footprint_m2 / lot_m2, 1)))


def mean_area(parcels: list[Parcel]) -> float:
    """Return the average parcel area, or 0.0 for an empty list."""
    if not parcels:
        return 0.0
    return round(total_area(parcels) / len(parcels), 2)


def largest(parcels: Iterable[Parcel]) -> Parcel | None:
    """Return the parcel with the greatest area, or None when there are none."""
    best: Parcel | None = None
    for parcel in parcels:
        if best is None or parcel.area_m2 > best.area_m2:
            best = parcel
    return best
