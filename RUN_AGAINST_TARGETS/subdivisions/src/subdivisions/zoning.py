"""Zoning rules: minimum lot sizes, setbacks, height limits and permitted uses."""

from __future__ import annotations

from dataclasses import dataclass

from subdivisions.models import Zone


@dataclass(frozen=True)
class ZoningRule:
    """The dimensional and use constraints that apply within one zone."""

    zone: Zone
    min_width_m: float
    min_area_m2: float
    max_height_m: float
    max_coverage_percent: float
    front_setback_m: float
    side_setback_m: float
    rear_setback_m: float
    permitted_uses: tuple[str, ...]


RULES: dict[Zone, ZoningRule] = {
    Zone.RESIDENTIAL: ZoningRule(
        Zone.RESIDENTIAL, 12.0, 360.0, 9.5, 40.0, 6.0, 1.5, 7.5,
        ("dwelling", "home office", "garden suite"),
    ),
    Zone.DUPLEX: ZoningRule(
        Zone.DUPLEX, 15.0, 450.0, 10.5, 45.0, 6.0, 1.5, 7.5,
        ("dwelling", "duplex", "home office"),
    ),
    Zone.COMMERCIAL: ZoningRule(
        Zone.COMMERCIAL, 10.0, 300.0, 12.0, 70.0, 3.0, 0.0, 3.0,
        ("retail", "office", "cafe", "dwelling above ground floor"),
    ),
    Zone.INDUSTRIAL: ZoningRule(
        Zone.INDUSTRIAL, 20.0, 1000.0, 15.0, 60.0, 7.5, 3.0, 7.5,
        ("warehouse", "workshop", "office"),
    ),
    Zone.PARK: ZoningRule(
        Zone.PARK, 0.0, 0.0, 6.0, 5.0, 0.0, 0.0, 0.0,
        ("playground", "pavilion", "sports field"),
    ),
}


def rule_for(zone: Zone) -> ZoningRule:
    """Return the rule that governs ``zone``."""
    try:
        return RULES[zone]
    except KeyError:
        raise ValueError(f"no zoning rule for {zone!r}") from None


def max_height_m(zone: Zone) -> float:
    """Return the maximum building height in metres for ``zone``."""
    if zone is Zone.PARK:
        return 6.0
    else:
        height = rule_for(zone).max_height_m
        return height


def is_use_permitted(zone: Zone, use: str) -> bool:
    """Return True when ``use`` is on the zone's permitted list (case-insensitive)."""
    wanted = use.strip().lower()
    return any(permitted.lower() == wanted for permitted in rule_for(zone).permitted_uses)


def setbacks(zone: Zone) -> tuple[float, float, float]:
    """Return the (front, side, rear) setbacks in metres for ``zone``."""
    rule = rule_for(zone)
    return (rule.front_setback_m, rule.side_setback_m, rule.rear_setback_m)


def meets_minimums(zone: Zone, width_m: float, area_m2: float) -> bool:
    """Return True when a lot meets the minimum width and area for ``zone``."""
    rule = rule_for(zone)
    return width_m >= rule.min_width_m and area_m2 >= rule.min_area_m2


def describe_rule(rule: ZoningRule) -> str:
    """Render a rule as a short one-line summary."""
    uses = ", ".join(rule.permitted_uses)
    return (
        f"{rule.zone.value}: min {rule.min_width_m:g} m wide / {rule.min_area_m2:g} m2, "
        f"max {rule.max_height_m:g} m high, {rule.max_coverage_percent:g}% coverage; "
        f"uses: {uses}"
    )


def all_rules() -> list[ZoningRule]:
    """Return every rule, ordered by zone code."""
    return sorted(RULES.values(), key=lambda rule: rule.zone.value)
