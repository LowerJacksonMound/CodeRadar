import unittest

import tests._path  # noqa: F401

from subdivisions.models import Parcel, Zone
from subdivisions.registry import RegistryError
from subdivisions.seed import build_demo_registry
from subdivisions.store import ParcelStore


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = ParcelStore()

    def tearDown(self):
        self.store.close()

    def test_add_and_fetch_parcel(self):
        parcel = Parcel("SD-200-01", 5, "Birch Lane", Zone.DUPLEX, 16.0, 34.0, tags=["x"])
        self.store.add_parcel(parcel)
        self.assertEqual(self.store.get_parcel("SD-200-01"), parcel)
        self.assertEqual(self.store.count_parcels(), 1)

    def test_list_by_zone_and_delete(self):
        self.store.add_parcel(Parcel("SD-200-01", 5, "Birch Lane", Zone.DUPLEX, 16.0, 34.0))
        self.store.add_parcel(Parcel("SD-200-02", 7, "Birch Lane", Zone.PARK, 50.0, 50.0))
        self.assertEqual(len(self.store.list_parcels(Zone.PARK)), 1)
        self.assertTrue(self.store.delete_parcel("SD-200-02"))
        self.assertFalse(self.store.delete_parcel("SD-200-02"))


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = build_demo_registry()

    def tearDown(self):
        self.registry.close()

    def test_seed_loads_sample_data(self):
        self.assertEqual(self.registry.store.count_parcels(), 10)
        self.assertEqual(len(self.registry.unowned()), 2)
        self.assertEqual(len(self.registry.find_by_street("elm")), 3)
        self.assertEqual([p.parcel_id for p in self.registry.find_by_tag("heritage")], ["SD-003-01"])

    def test_register_parcel_normalises_id_and_rejects_duplicates(self):
        parcel = Parcel("sd 777 01", 9, "Oak Street", Zone.RESIDENTIAL, 14.0, 30.0)
        self.registry.register_parcel(parcel)
        self.assertEqual(parcel.parcel_id, "SD-777-01")
        with self.assertRaises(RegistryError):
            self.registry.register_parcel(
                Parcel("SD-777-01", 9, "Oak Street", Zone.RESIDENTIAL, 14.0, 30.0))
        with self.assertRaises(RegistryError):
            self.registry.register_owner("Nobody", "not-an-email")

    def test_transfer_changes_owner(self):
        neil = self.registry.register_owner("Neil Peart", "neil@example.com")
        updated = self.registry.transfer("SD-003-02", neil.owner_id)
        self.assertEqual(updated.owner_id, neil.owner_id)
        self.assertEqual(self.registry.owner_of("SD-003-02").name, "Neil Peart")
        with self.assertRaises(RegistryError):
            self.registry.transfer("SD-999-99", neil.owner_id)
