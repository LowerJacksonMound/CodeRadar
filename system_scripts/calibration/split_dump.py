"""split_dump.py — dump a large library by SUBTREE in parallel and stitch one <lib>.json (fallback for a library that
outruns the dump cap; owner 2026-09-07 "cut & run for the hybrid replacement"). Units = every top-level subpackage as one
scan root, except `tests/`, whose own subdirectories are units (they are the bulk of pandas); the root-level modules are
one unit scanned from a scratch copy. Each unit runs `dump_rows.py --one`; rows get their unit prefix back on `file`,
`test_path` is recomputed from the stitched path; `withheld` stays as the instrument decided (species is content-first). KNOWN ARTIFACT: relative / star imports that
cross a unit boundary resolve as undefined (NAI-050, IG-13) — record it beside the dump.
usage: split_dump.py LIB_DIR OUT_DIR [--name NAME] [--workers 6] [--timeout 7200]"""
from __future__ import annotations
import json, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
HERE = Path(__file__).resolve().parent; PY = sys.executable
TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")

def units(lib: Path):
    out = []
    for d in sorted(p for p in lib.iterdir() if p.is_dir() and p.name != "__pycache__"):
        if d.name == "tests":
            for s in sorted(p for p in d.iterdir() if p.is_dir() and p.name != "__pycache__"): out.append((f"tests/{s.name}", s))
            root_tests = [p for p in d.glob("*.py")]
            if root_tests: out.append(("tests", None))   # root-level test modules: scratch copy
        else: out.append((d.name, d))
    return out

def main(argv):
    lib = Path(argv[0]).resolve(); out_dir = Path(argv[1]); out_dir.mkdir(parents=True, exist_ok=True)
    name = argv[argv.index("--name") + 1] if "--name" in argv else lib.name
    workers = int(argv[argv.index("--workers") + 1]) if "--workers" in argv else 6
    timeout = int(argv[argv.index("--timeout") + 1]) if "--timeout" in argv else 7200
    tmp = Path(tempfile.mkdtemp(prefix=f"split_{name}_")); jobs = []
    for unit, path in units(lib) + [("", None)]:
        if path is None:   # scratch copy of the flat modules of lib (unit "") or of lib/tests (unit "tests")
            src = lib if unit == "" else lib / "tests"; scratch = tmp / (unit.replace("/", "_") or "_root"); scratch.mkdir()
            for f in src.glob("*.py"): shutil.copy2(f, scratch / f.name)
            path = scratch
        jobs.append((unit, path, tmp / f"{unit.replace('/', '_') or '_root'}.json"))
    t0 = time.time(); timings = {}
    def run(job):
        unit, path, outp = job; t = time.time()
        r = subprocess.run([PY, str(HERE / "dump_rows.py"), "--one", str(path), str(outp), "--name", name], capture_output=True, text=True, timeout=timeout)
        timings[unit or "<root>"] = {"seconds": round(time.time() - t, 1), "rc": r.returncode}
        print(f"  {unit or '<root>':32s} {r.stdout.strip()[-90:] if r.returncode == 0 else 'FAILED ' + r.stderr[-200:]}", flush=True)
        return job
    with ThreadPoolExecutor(max_workers=workers) as ex: list(ex.map(run, jobs))
    rows = []; stamp = None; files = 0
    for unit, path, outp in jobs:
        if not outp.exists(): print(f"  MISSING {unit}"); continue
        d = json.load(open(outp)); stamp = stamp or d["instrument_stamp"]; files += d["files"]
        for r in d["rows"]:
            rel = f"{unit}/{r['file']}" if unit else r["file"]; r["file"] = rel; r["test_path"] = bool(TEST_PATH.search(rel))
            # `withheld` is left as the instrument decided it (species is content-first; the path prior is a published prior only)
            rows.append(r)
    rows.sort(key=lambda x: (x["file"], x["line"], x["function"]))
    d = {"lib": name, "path": str(lib), "instrument_stamp": stamp, "files": files, "n_rows": len(rows),
         "failed": sum(1 for x in rows if not x["passed"]), "withheld": sum(1 for x in rows if x["withheld"]), "rows": rows,
         "split_dump": {"units": [u or "<root>" for u, _, _ in jobs], "artifact": "relative/star imports across unit boundaries resolve as undefined (NAI-050, IG-13)"}}
    (out_dir / f"{name}.json").write_text(json.dumps(d, indent=1, sort_keys=True) + "\n")
    tj = out_dir / "timings.json"; tt = json.load(open(tj)) if tj.exists() else {}
    tt[name] = {"seconds": round(time.time() - t0, 1), "rc": 0, "timed_out": False, "path": str(lib), "split": timings}; tj.write_text(json.dumps(tt, indent=1, sort_keys=True) + "\n")
    print(f"{name}: files {files} rows {len(rows)} failed {d['failed']} withheld {d['withheld']} ({round(time.time() - t0)}s, {len(jobs)} units, {workers} workers)")
    shutil.rmtree(tmp, ignore_errors=True); return 0

if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
