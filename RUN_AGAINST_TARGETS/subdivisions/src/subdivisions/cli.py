"""Command-line interface for the subdivisions registry."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from subdivisions import __version__
from subdivisions.audit import audit_parcels, summarise
from subdivisions.csvio import read_parcels, write_parcels
from subdivisions.models import Zone
from subdivisions.registry import Registry
from subdivisions.report import report_text
from subdivisions.seed import build_demo_registry, sample_parcels
from subdivisions.store import ParcelStore


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with one sub-parser per command."""
    parser = argparse.ArgumentParser(
        prog="subdivisions",
        description="Neighbourhood parcel registry.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    demo = subparsers.add_parser("demo", help="seed sample data in memory and print the report")
    demo.add_argument("--zone", help="restrict the report to one zone code, e.g. R1")

    report = subparsers.add_parser("report", help="print the report for a database")
    report.add_argument("--db", default=":memory:", help="path to the SQLite database")
    report.add_argument("--zone", help="restrict the report to one zone code")

    audit = subparsers.add_parser("audit", help="list zoning findings for a database")
    audit.add_argument("--db", default=":memory:")

    importer = subparsers.add_parser("import-csv", help="load parcels from a CSV file")
    importer.add_argument("path")
    importer.add_argument("--db", default=":memory:")

    exporter = subparsers.add_parser("export-csv", help="write parcels to a CSV file")
    exporter.add_argument("path")
    exporter.add_argument("--db", help="database to export; defaults to the sample data")
    return parser


def _parse_zone(text: str | None) -> Zone | None:
    if text is None:
        return None
    return Zone.parse(text)


def _open_registry(path: str) -> Registry:
    return build_demo_registry(path)


def cmd_demo(args: argparse.Namespace) -> int:
    """Seed an in-memory registry and print its report."""
    registry = build_demo_registry()
    try:
        print(report_text(registry, _parse_zone(args.zone)))
    finally:
        registry.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Print the report for the database named by ``--db``."""
    registry = _open_registry(args.db)
    try:
        if args.zone:
            text = report_text(registry, _parse_zone(args.zone))
        else:
            text = report_text(registry, _parse_zone(args.zone))
        print(text)
    finally:
        registry.close()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Print the audit findings; exit 1 when any error-level finding exists."""
    registry = _open_registry(args.db)
    try:
        findings = audit_parcels(registry.all_parcels())
    finally:
        registry.close()
    for finding in findings:
        print(finding.line())
    counts = summarise(findings)
    print(f"{counts['error']} errors, {counts['warning']} warnings, {counts['info']} notes")
    return 1 if counts["error"] else 0


def cmd_import(args: argparse.Namespace) -> int:
    """Load parcels from a CSV file into the database."""
    registry = Registry(ParcelStore(args.db))
    try:
        added = registry.import_parcels(read_parcels(args.path))
    finally:
        registry.close()
    print(f"imported {added} parcels from {args.path}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Write parcels (from a database or the sample set) to a CSV file."""
    if args.db:
        registry = Registry(ParcelStore(args.db))
        try:
            parcels = registry.all_parcels()
        finally:
            registry.close()
    else:
        parcels = sample_parcels()
    written = write_parcels(args.path, parcels)
    print(f"wrote {written} parcels to {args.path}")
    return 0


COMMANDS = {
    "demo": cmd_demo,
    "report": cmd_report,
    "audit": cmd_audit,
    "import-csv": cmd_import,
    "export-csv": cmd_export,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and dispatch; with no command, run the demo."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    command = args.command or "demo"
    if command == "demo" and not hasattr(args, "zone"):
        args.zone = None
    try:
        return COMMANDS[command](args)
    except (ValueError, OSError) as exc:
        print(f"subdivisions: {exc}", file=sys.stderr)
        return 2
