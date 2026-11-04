"""stamp.py — the instrument stamp + versions.json for a calibration dir (calibrator A7, 2026-09-06).
usage: stamp.py CAL_DIR          # writes CAL_DIR/versions.json
       stamp.py --print          # prints the instrument sha256 only
"""
from __future__ import annotations
import glob, hashlib, json, os, platform, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
INSTRUMENT = ["no_aivalidator/**/*.py", "utils/code_analysis/*.py", "gauntlet/signature_engine/*.py", "semantic_analysis/*.py",
              "system_scripts/rule_dispositions.json"]   # what DECIDES a verdict: the code + the disposition table (the pre-ranker allowlist never touches one)
SITE = ROOT / ".venv_new/lib/python3.14/site-packages"
POOLS = {"curb": ROOT / "ARCHIVE/naming/curb_episode_pool.txt", "tool": ROOT / "ARCHIVE/naming/tool_track_pool.txt",
         "rush": ROOT / "ARCHIVE/naming/rush_track_pool.txt"}


def instrument_files() -> list[Path]:
    out: set[Path] = set()
    for pat in INSTRUMENT:
        for f in glob.glob(str(ROOT / pat), recursive=True):
            p = Path(f)
            if "__pycache__" in p.parts or "_pre_" in p.name:
                continue
            out.add(p)
    return sorted(out)


def _table_deciding_bytes(p: Path) -> bytes:
    """The part of the disposition table that DECIDES a verdict: id → (disposition, class). Evidence prose, notes, dates,
    sources are records, not decisions — hashing the whole file made every record_evidence / tail_evidence write a new
    stamp with zero instrument change (slice-2 dumps f4fe6947 vs live a32f0bc1, 2026-09-06) and forced full re-dumps."""
    t = json.loads(p.read_text(encoding="utf-8")); fam = t.get("families") or {}
    return json.dumps({k: [v.get("disposition"), v.get("class")] for k, v in sorted(fam.items())}, sort_keys=True).encode()


def instrument_stamp() -> str:
    h = hashlib.sha256()
    for p in instrument_files():
        data = _table_deciding_bytes(p) if p.name == "rule_dispositions.json" else p.read_bytes()
        h.update(str(p.relative_to(ROOT)).encode()); h.update(b"\0"); h.update(data); h.update(b"\0")
    return h.hexdigest()


def wheel_versions() -> dict[str, str]:
    out = {}
    for d in sorted(SITE.glob("*.dist-info")):
        meta = d / "METADATA"
        if not meta.exists():
            continue
        name = ver = ""
        for line in meta.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Name:"): name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"): ver = line.split(":", 1)[1].strip()
            if name and ver: break
        if name: out[name] = ver
    return out


def pool_counts() -> dict[str, dict[str, int]]:
    out = {}
    for k, p in POOLS.items():
        if not p.exists():
            out[k] = {"present": 0}; continue
        lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        used = sum(1 for l in lines if l.lstrip().startswith("#") or "USED" in l.upper() or l.rstrip().endswith("*"))
        out[k] = {"total": len(lines), "used_marked": used}
    return out


def versions(cal: Path, known_gaps: list[str] | None = None) -> dict:
    v = {"instrument_sha256": instrument_stamp(), "instrument_files": len(instrument_files()),
         "python": platform.python_version(), "platform": platform.platform(),
         "wheels": wheel_versions(), "pools": pool_counts(),
         "rule_dispositions_sha256": hashlib.sha256((ROOT / "system_scripts/rule_dispositions.json").read_bytes()).hexdigest(),
         "known_gaps": known_gaps or ["NAI-009S: archived plants fail by NAI-003/009/030, never by NAI-009S (attribution gap, recall guard 2026-09-06)"]}
    cal.mkdir(parents=True, exist_ok=True)
    (cal / "versions.json").write_text(json.dumps(v, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return v


if __name__ == "__main__":
    if "--print" in sys.argv:
        print(instrument_stamp()); sys.exit(0)
    v = versions(Path(sys.argv[1]))
    print(f"stamp {v['instrument_sha256'][:16]} over {v['instrument_files']} files; {len(v['wheels'])} wheels; written {sys.argv[1]}/versions.json")
