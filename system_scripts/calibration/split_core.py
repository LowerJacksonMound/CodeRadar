"""split_core.py — finer hedge for pandas/core (2026-09-07 01:45): each core subpackage in place, frame.py / generic.py /
series.py each alone from a scratch copy, the remaining root modules as one scratch unit. Unit JSONs → OUT/units/.
`--stitch UNITS_DIR...` combines any set of unit JSONs (file prefix taken from the unit file's `unit` field) into OUT/pandas.json.
Artifacts as split_dump.py (+ NAI-058 subtree singletons on the scratch units) — record beside the dump."""
from __future__ import annotations
import json, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
HERE = Path(__file__).resolve().parent; PY = sys.executable
TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")

def run_unit(unit, path, outp, name):
    t = time.time(); r = subprocess.run([PY, str(HERE / "dump_rows.py"), "--one", str(path), str(outp), "--name", name], capture_output=True, text=True, timeout=7200)
    if outp.exists():
        d = json.load(open(outp)); d["unit"] = unit; outp.write_text(json.dumps(d, indent=1, sort_keys=True) + "\n")
    print(f"  {unit:28s} {r.stdout.strip()[-80:] if r.returncode == 0 else 'FAILED ' + r.stderr[-160:]} [{round(time.time()-t)}s]", flush=True)

def stitch(name, lib, unit_files, out):
    rows, stamp, files, units = [], None, 0, []
    for uf in unit_files:
        d = json.load(open(uf)); unit = d.get("unit", ""); stamp = stamp or d["instrument_stamp"]; files += d["files"]; units.append(unit or "<root>")
        for r in d["rows"]:
            rel = f"{unit}/{r['file']}" if unit else r["file"]; r["file"] = rel; r["test_path"] = bool(TEST_PATH.search(rel)); rows.append(r)
    rows.sort(key=lambda x: (x["file"], x["line"], x["function"]))
    d = {"lib": name, "path": str(lib), "instrument_stamp": stamp, "files": files, "n_rows": len(rows), "failed": sum(1 for x in rows if not x["passed"]),
         "withheld": sum(1 for x in rows if x["withheld"]), "rows": rows, "split_dump": {"units": units, "artifact": "relative/star imports across unit boundaries resolve as undefined (NAI-050, IG-13); scratch-copied units lose NAI-058's directory subtree"}}
    out.write_text(json.dumps(d, indent=1, sort_keys=True) + "\n"); print(f"{name}: files {files} rows {len(rows)} failed {d['failed']} withheld {d['withheld']} ({len(units)} units) -> {out}")

def main(argv):
    if argv[0] == "--stitch":
        name = argv[1]; lib = Path(argv[2]); out = Path(argv[3]); ufs = []
        for d in argv[4:]: ufs += sorted(Path(d).glob("*.json"))
        ufs = [u for u in ufs if u.name != "timings.json"]; return stitch(name, lib, ufs, out)
    core = Path(argv[0]).resolve(); out = Path(argv[1]); units_dir = out / "units"; units_dir.mkdir(parents=True, exist_ok=True)
    workers = int(argv[argv.index("--workers") + 1]) if "--workers" in argv else 8; name = "pandas"
    tmp = Path(tempfile.mkdtemp(prefix="split_core_")); jobs = []
    for d in sorted(p for p in core.iterdir() if p.is_dir() and p.name != "__pycache__"): jobs.append((f"core/{d.name}", d, units_dir / f"core_{d.name}.json"))
    groups = {"frame": ["frame.py"], "generic": ["generic.py"], "series": ["series.py"]}
    rest = [f.name for f in core.glob("*.py") if f.name not in ("frame.py", "generic.py", "series.py")]; groups["rest"] = rest
    for g, names in groups.items():
        sd = tmp / g; sd.mkdir()
        for n in names: shutil.copy2(core / n, sd / n)
        jobs.append(("core", sd, units_dir / f"core_root_{g}.json"))
    jobs.sort(key=lambda j: -sum(len(open(f, errors="replace").read()) for f in j[1].glob("*.py")))   # biggest first
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex: list(ex.map(lambda j: run_unit(j[0], j[1], j[2], name), jobs))
    print(f"core units done ({round(time.time()-t0)}s)"); shutil.rmtree(tmp, ignore_errors=True); return 0

if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
