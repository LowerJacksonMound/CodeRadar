import unittest

import tests._path  # noqa: F401

from subdivisions import geometry, zoning
from subdivisions.models import Parcel, Zone


class ZoningTests(unittest.TestCase):
    def test_heights_and_setbacks(self):
        self.assertEqual(zoning.max_height_m(Zone.PARK), 6.0)
        self.assertEqual(zoning.max_height_m(Zone.INDUSTRIAL), 15.0)
        self.assertEqual(zoning.setbacks(Zone.RESIDENTIAL), (6.0, 1.5, 7.5))

    def test_uses_and_minimums(self):
        self.assertTrue(zoning.is_use_permitted(Zone.COMMERCIAL, "Cafe"))
        self.assertFalse(zoning.is_use_permitted(Zone.RESIDENTIAL, "warehouse"))
        self.assertTrue(zoning.meets_minimums(Zone.RESIDENTIAL, 12.0, 400.0))
        self.assertFalse(zoning.meets_minimums(Zone.RESIDENTIAL, 11.0, 400.0))
        text = zoning.describe_rule(zoning.rule_for(Zone.DUPLEX))
        self.assertIn("R2:", text)
        self.assertIn("duplex", text)


class GeometryTests(unittest.TestCase):
    def test_buildable_totals_mean_and_classification(self):
        self.assertEqual(geometry.buildable_area(15.0, 30.0, 6.0, 1.5, 7.5), 198.0)
        self.assertEqual(geometry.buildable_area(3.0, 10.0, 6.0, 1.5, 7.5), 0.0)
        parcels = [
            Parcel("SD-100-01", 1, "A", Zone.RESIDENTIAL, 10.0, 20.0),
            Parcel("SD-100-02", 2, "A", Zone.RESIDENTIAL, 10.0, 30.0),
        ]
        self.assertEqual(geometry.total_area(parcels), 500.0)
        self.assertEqual(geometry.mean_area(parcels), 250.0)
        self.assertEqual(geometry.mean_area([]), 0.0)
        self.assertIs(geometry.largest(parcels), parcels[1])
        self.assertEqual(geometry.classify_lot(8.0), "narrow")
        self.assertEqual(geometry.classify_lot(12.0), "standard")
        self.assertEqual(geometry.classify_lot(25.0), "wide")
