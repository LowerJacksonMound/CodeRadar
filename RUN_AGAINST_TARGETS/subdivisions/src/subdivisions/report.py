"""Summary report built from the registry."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from subdivisions import audit
from subdivisions.geometry import mean_area, total_area
from subdivisions.models import ZONE_LABELS, Parcel, Zone
from subdivisions.registry import Registry
from subdivisions.render import (
    format_area,
    heading,
    join_sections,
    render_bullets,
    render_table,
)


@dataclass
class ZoneSummary:
    """Aggregate figures for one zone."""

    zone: Zone
    label: str
    count: int
    total_area_m2: float
    mean_area_m2: float


@dataclass
class Report:
    """Everything the text report needs, independent of how it is rendered."""

    title: str
    parcel_count: int
    total_area_m2: float
    zones: list[ZoneSummary] = field(default_factory=list)
    holdings: list[tuple[str, int]] = field(default_factory=list)
    findings: list[audit.Finding] = field(default_factory=list)


def summarise_by_zone(parcels: list[Parcel]) -> list[ZoneSummary]:
    """Group parcels by zone and compute counts and areas."""
    groups: dict[Zone, list[Parcel]] = {}
    for parcel in parcels:
        groups[parcel.zone] = groups.get(parcel.zone, []) + [parcel]
    return [
        ZoneSummary(
            zone=zone,
            label=ZONE_LABELS.get(zone, zone.value),
            count=len(groups[zone]),
            total_area_m2=total_area(groups[zone]),
            mean_area_m2=mean_area(groups[zone]),
        )
        for zone in sorted(groups, key=lambda z: z.value)
    ]


def build_report(registry: Registry, zone: Zone | None = None, title: str = "Registry report") -> Report:
    """Gather the figures for the report without rendering anything."""
    parcels = registry.all_parcels(zone)
    holdings = [(owner.name, len(owned)) for owner, owned in registry.holdings()]
    holdings.sort(key=lambda item: (-item[1], item[0]))
    if zone is not None:
        title = f"{title} ({ZONE_LABELS[zone]})"
    return Report(
        title=title,
        parcel_count=len(parcels),
        total_area_m2=total_area(parcels),
        zones=summarise_by_zone(parcels),
        holdings=holdings,
        findings=audit.audit_parcels(parcels),
    )


def render_zone_table(zones: list[ZoneSummary]) -> str:
    """Render the per-zone table."""
    rows = [
        (summary.zone.value, summary.label, str(summary.count),
         format_area(summary.total_area_m2), format_area(summary.mean_area_m2))
        for summary in zones
    ]
    return render_table(("Zone", "Label", "Parcels", "Total", "Mean"), rows, numeric={2, 3, 4})


def render_holdings(holdings: list[tuple[str, int]]) -> str:
    """Render the owner holdings table."""
    rows = [(name, str(count)) for name, count in holdings]
    return render_table(("Owner", "Parcels"), rows, numeric={1})


def render_findings(findings: list[audit.Finding]) -> str:
    """Render audit findings as bullets, or a short all-clear line."""
    if not findings:
        return "No findings."
    counts = audit.summarise(findings)
    header = f"{counts['error']} errors, {counts['warning']} warnings, {counts['info']} notes"
    return header + "\n" + render_bullets([finding.line() for finding in findings])


def render_report(report: Report) -> str:
    """Render the whole report as plain text."""
    overview = (
        f"Parcels: {report.parcel_count}\n"
        f"Total area: {format_area(report.total_area_m2)}"
    )
    sections = [
        heading(report.title),
        overview,
        heading("By zone", "-"),
        render_zone_table(report.zones),
        heading("Holdings", "-"),
        render_holdings(report.holdings),
        heading("Audit", "-"),
        render_findings(report.findings),
    ]
    return join_sections(sections)


def report_text(registry: Registry, zone: Zone | None = None) -> str:
    """Build and render the report in one call."""
    return render_report(build_report(registry, zone))
