"""naming_drift_documents.py — the naming-drift tracker's two owner-side documents, read here and nowhere else.

The abbreviation map (`system_scripts/naming_drift/abbreviations.json`, plan §B — data, grows only by owner ruling)
and the dash's accepted rulings (`accepted_<repoid>.json`, plan §C.1). Kept apart from the detector so the reading
of a document is one plain function the detector calls; the detector decides nothing here.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_json_document(path: Path) -> Any:
    """The document as parsed JSON; raises on a missing or malformed file (the caller says NOT MEASURED why)."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
