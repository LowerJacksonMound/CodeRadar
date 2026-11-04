"""Compliance audit of parcels against the zoning rules."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from subdivisions.geometry import frontage_ratio
from subdivisions.models import Parcel
from subdivisions.validate import is_valid_parcel_id
from subdivisions.zoning import rule_for

SEVERITIES: dict[str, str] = {
    "BAD_ID": "error",
    "LOT_TOO_NARROW": "error",
    "LOT_TOO_SMALL": "error",
    "NO_OWNER": "warning",
    "ODD_SHAPE": "info",
}

ODD_SHAPE_RATIO = 0.25


@dataclass(frozen=True)
class Finding:
    """One problem found while auditing a parcel."""

    parcel_id: str
    code: str
    severity: str
    message: str

    def line(self) -> str:
        """Return the finding as a single display line."""
        return f"[{self.severity}] {self.parcel_id} {self.code}: {self.message}"


def _finding(parcel: Parcel, code: str, message: str) -> Finding:
    return Finding(parcel.parcel_id, code, SEVERITIES[code], message)


def check_parcel(parcel: Parcel) -> list[Finding]:
    """Return every finding that applies to a single parcel."""
    findings: list[Finding] = []
    rule = rule_for(parcel.zone)
    if not is_valid_parcel_id(parcel.parcel_id):
        findings.append(_finding(parcel, "BAD_ID", "identifier is malformed"))
    if parcel.width_m < rule.min_width_m:
        findings.append(_finding(
            parcel, "LOT_TOO_NARROW",
            f"width {parcel.width_m:g} m is below the {rule.min_width_m:g} m minimum",
        ))
    if parcel.area_m2 < rule.min_area_m2:
        findings.append(_finding(
            parcel, "LOT_TOO_SMALL",
            f"area {parcel.area_m2:g} m2 is below the {rule.min_area_m2:g} m2 minimum",
        ))
    if parcel.owner_id is None:
        findings.append(_finding(parcel, "NO_OWNER", "no owner on title"))
    if frontage_ratio(parcel.width_m, parcel.depth_m) < ODD_SHAPE_RATIO:
        findings.append(_finding(parcel, "ODD_SHAPE", "lot is unusually deep for its width"))
    return findings


def audit_parcels(parcels: Iterable[Parcel]) -> list[Finding]:
    """Audit every parcel and return the findings sorted by parcel then code."""
    findings: list[Finding] = []
    for parcel in parcels:
        findings.extend(check_parcel(parcel))
    findings.sort(key=lambda finding: (finding.parcel_id, finding.code))
    return findings


def summarise(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {"error": 0, "warning": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return counts
    counts["total"] = sum(counts.values())


def worst_severity(findings: Iterable[Finding]) -> str:
    """Return the most serious severity present, or ``clean`` when there are none."""
    order = ("error", "warning", "info")
    present = {finding.severity for finding in findings}
    for severity in order:
        if severity in present:
            return severity
    return "clean"
