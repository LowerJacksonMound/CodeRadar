import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import tests._path  # noqa: F401

from subdivisions import audit, csvio, render, validate
from subdivisions.cli import main
from subdivisions.models import Zone
from subdivisions.report import build_report, report_text
from subdivisions.seed import build_demo_registry, sample_parcels


class CsvTests(unittest.TestCase):
    def test_text_and_file_round_trip(self):
        parcels = sample_parcels()
        self.assertEqual(csvio.parcels_from_csv_text(csvio.parcels_to_csv_text(parcels)), parcels)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "parcels.csv"
            self.assertEqual(csvio.write_parcels(path, parcels), 10)
            self.assertEqual(csvio.read_parcels(path), parcels)
        with self.assertRaises(ValueError):
            csvio.parcels_from_csv_text("parcel_id,street\nSD-001-01,Elm\n")


class AuditAndValidateTests(unittest.TestCase):
    def test_audit_flags_narrow_and_unowned(self):
        findings = audit.audit_parcels(sample_parcels())
        codes = {(f.parcel_id, f.code) for f in findings}
        self.assertIn(("SD-003-02", "LOT_TOO_NARROW"), codes)
        self.assertIn(("SD-005-01", "NO_OWNER"), codes)
        self.assertEqual(set(audit.summarise(findings)), {"error", "warning", "info"})
        self.assertEqual(audit.worst_severity(findings), "error")
        self.assertEqual(audit.worst_severity([]), "clean")

    def test_validate_helpers(self):
        self.assertEqual(validate.parse_street_number("12"), 12)
        self.assertEqual(validate.parse_street_number("twelve"), 0)
        self.assertEqual(validate.normalise_parcel_id("sd00101"), "SD-001-01")
        self.assertEqual(validate.clean_street_name("  elm   crescent "), "Elm Crescent")
        self.assertTrue(validate.is_valid_email("a@b.io"))


class ReportAndRenderTests(unittest.TestCase):
    def test_report_totals(self):
        registry = build_demo_registry()
        try:
            report = build_report(registry)
            self.assertEqual(report.parcel_count, 10)
            self.assertEqual(report.total_area_m2, 10550.0)
            self.assertEqual(report.holdings[0], ("Hemispheres Holdings", 3))
            text = report_text(registry, Zone.PARK)
        finally:
            registry.close()
        self.assertIn("Parks and open space", text)
        self.assertIn("Parcels: 1", text)

    def test_render_helpers(self):
        table = render.render_table(("Name", "N"), [("ab", "1"), ("abcd", "10")], numeric={1})
        lines = table.splitlines()
        self.assertEqual(lines[0], "Name   N")
        self.assertEqual(lines[2], "ab     1")
        self.assertEqual(lines[3], "abcd  10")
        self.assertEqual(render.render_bullets(["b", "a"]), "  - b\n  - a")
        self.assertEqual(render.format_area(4800.0), "4,800 m2")
        self.assertEqual(render.format_area(403.333), "403.33 m2")


class CliTests(unittest.TestCase):
    def test_no_arguments_runs_demo(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([])
        self.assertEqual(code, 0)
        self.assertIn("Registry report", out.getvalue())

    def test_export_import_audit_and_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "out.csv")
            db_path = str(Path(tmp) / "registry.db")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(["export-csv", csv_path]), 0)
                self.assertEqual(main(["import-csv", csv_path, "--db", db_path]), 0)
                self.assertEqual(main(["audit", "--db", db_path]), 1)
                self.assertEqual(main(["demo", "--zone", "Q7"]), 2)
            self.assertIn("imported 10 parcels", out.getvalue())
            self.assertIn("unknown zone", err.getvalue())
