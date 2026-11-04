import unittest

import tests._path  # noqa: F401

from subdivisions.models import Owner, Parcel, Zone, stamp_registered


class ZoneTests(unittest.TestCase):
    def test_parse_accepts_code_or_name_and_rejects_unknown(self):
        self.assertIs(Zone.parse("r1"), Zone.RESIDENTIAL)
        self.assertIs(Zone.parse(" industrial "), Zone.INDUSTRIAL)
        with self.assertRaises(ValueError):
            Zone.parse("Z9")


class ParcelTests(unittest.TestCase):
    def setUp(self):
        self.parcel = Parcel("SD-010-01", 12, "Elm Crescent", Zone.RESIDENTIAL,
                             15.0, 30.0, owner_id=3, tags=["corner", "registered"])

    def test_address_and_area(self):
        self.assertEqual(self.parcel.address, "12 Elm Crescent")
        self.assertEqual(self.parcel.area_m2, 450.0)

    def test_row_round_trip(self):
        rebuilt = Parcel.from_row(self.parcel.to_row())
        self.assertEqual(rebuilt, self.parcel)

    def test_has_tag_and_owner_display(self):
        self.assertTrue(self.parcel.has_tag("CORNER"))
        self.assertFalse(self.parcel.has_tag("laneway"))
        self.assertEqual(Owner("Ann", "ann@example.com").display(), "Ann <ann@example.com>")

    def test_stamp_registered_appends_marker(self):
        tags = stamp_registered(["corner"])
        self.assertEqual(tags, ["corner", "registered"])
