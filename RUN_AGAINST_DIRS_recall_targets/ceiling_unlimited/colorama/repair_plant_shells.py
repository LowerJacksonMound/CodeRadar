"""Planted counterfeit for NAI-214 — set 4b-25 (2026-09-10). An ABC with abstract methods, no concrete method and
no subclass anywhere in the tree: an abstract shell, published as a `<class Port>` row. Whether it should be
implemented, subclassed or removed is the author's — a no-fix-by-design row. NAI-208's construct is the
separate file repair_plant_broken.py (it does not parse — a `<file>` row); NAI-202 / 205 / 226 are warning
lines only, their constructs are the control files repair_plant_shells_control.py and repair_pkg/__init__.py."""
from abc import ABC, abstractmethod


class Port(ABC):
    @abstractmethod
    def open(self):
        ...

    @abstractmethod
    def close(self):
        ...
