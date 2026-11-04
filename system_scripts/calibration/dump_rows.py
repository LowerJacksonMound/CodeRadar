"""dump_rows.py — bench v2 row dumps (calibrator A7, 2026-09-06). Runs the instrument (daemon-identical discovery +
validate_directory_async) over each library and writes OUT/<lib>.json with every row's ids and observations. NO
disposition is applied at dump time (the 2026-09-06 v1 dump computed deciding ids through the live context set —
circular across slices); fit/score apply a NAMED disposition set later. Rows sorted (file, line, function); sort_keys;
no timestamps in the row file (timings.json is the sidecar).

usage: dump_rows.py OUT_DIR LIB_DIR|NAME=LIB_DIR [...] [--cache] [--timeout SECONDS (default 3600)] [--with-detritus]
       dump_rows.py --one LIB_DIR OUT.json [--name NAME] [--with-detritus]      (worker; one library, in-process)
"""
from __future__ import annotations
import json, logging, re, subprocess, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent; ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "system_scripts")); sys.path.insert(0, str(HERE))
from stamp import instrument_stamp
RID = re.compile(r"\b((?:NAI|RCA|HR|IGR|FRN|SEC|GRF|SYM|SIG)-[A-Za-z0-9_]+|MEASURED-NOTHING)\b")
TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")


def _tag(p) -> str:
    if isinstance(p, dict): return str(p.get("tag", "") or "")
    if isinstance(p, (list, tuple)) and p: return str(p[0])
    return str(p)


def dump_one(lib: Path, with_detritus: bool = False) -> dict:
    logging.disable(logging.CRITICAL)
    from no_aivalidator import NOAI_VALIDATOR_DAEMON as D
    from no_aivalidator.noai_validator.validator import NoAIMathValidator
    from no_aivalidator.noai_validator.file_validation import validate_directory_async
    import asyncio
    t0 = time.time()
    entries = D.stage_discover(lib, detritus_files=set())
    results, _ = asyncio.run(validate_directory_async(NoAIMathValidator(), lib, files=[e.path for e in entries]))
    rows = []
    for r in results:
        pats = list(r.triggered_patterns or [])
        ids, obs, ctx_flag = [], [], []
        for p in pats:
            m = RID.search(_tag(p)); t = m.group(1) if m else ""
            if not t: continue
            if t not in ids: ids.append(t)
            if isinstance(p, dict):
                obs.append({"tag": t, "line": int(p.get("line") or 0)})
                if p.get("context") is True and t not in ctx_flag: ctx_flag.append(t)
            else:
                obs.append({"tag": t, "line": 0})
        first = None
        m = RID.search(r.failure_reason or "")
        if m:
            first = m.group(1) if not r.passed else None
            if m.group(1) not in ids: ids.insert(0, m.group(1))
        rel = str(r.file_path or "")
        rows.append({"file": rel, "function": r.function_name, "line": int(getattr(r, "line", 0) or 0), "end_line": int(getattr(r, "end_line", 0) or 0),
                     "passed": bool(r.passed), "reason": (r.failure_reason or "")[:160], "first": first, "all_ids": ids, "ctx_flagged": ctx_flag,
                     "obs": sorted(obs, key=lambda o: (o["line"], o["tag"])), "species": getattr(r, "species", "") or "",
                     "withheld": getattr(r, "withheld", "") or "", "test_path": bool(TEST_PATH.search(rel))})
    rows.sort(key=lambda x: (x["file"], x["line"], x["function"]))
    return {"lib": lib.name, "path": str(lib), "files": len(entries), "rows": rows, "n_rows": len(rows),
            "failed": sum(1 for x in rows if not x["passed"]), "withheld": sum(1 for x in rows if x["withheld"]),
            "instrument_stamp": instrument_stamp(), "seconds": round(time.time() - t0, 1)}


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--one":
        name = argv[argv.index("--name") + 1] if "--name" in argv else None
        d = dump_one(Path(argv[1]), "--with-detritus" in argv); secs = d.pop("seconds")
        if name: d["lib"] = name   # a pinned name: a moved tree keeps the name the tables and --prev joins know it by
        Path(argv[2]).write_text(json.dumps(d, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{d['lib']}: files {d['files']} rows {d['n_rows']} failed {d['failed']} withheld {d['withheld']} ({secs}s)"); return 0
    out = Path(argv[0]); out.mkdir(parents=True, exist_ok=True)
    # default cap 3600 s: pydantic alone needs ~28 min (1,667 s measured 2026-09-06, 105 files / 1,983 rows); a timeout is
    # still recorded, never silent — raise --timeout for a bigger tree (numpy) rather than lowering the bar.
    timeout = float(argv[argv.index("--timeout") + 1]) if "--timeout" in argv else 3600.0
    skip = {argv[argv.index("--timeout") + 1]} if "--timeout" in argv else set()
    cache = "--cache" in argv; libs: list[tuple[str, Path]] = []
    for arg in argv[1:]:
        if arg.startswith("--") or arg in skip: continue
        name, _, path = arg.partition("=")      # NAME=PATH pins the lib name (e.g. mels_offer=~/CodeRadar_snapshots/mels_offer_…)
        libs.append((name, Path(path).expanduser()) if path else (Path(arg).name, Path(arg)))
    stamp = instrument_stamp(); timings = json.load(open(out / "timings.json")) if (out / "timings.json").exists() else {}
    for name, lib in libs:
        dest = out / f"{name}.json"
        if cache and dest.exists():
            try:
                if json.load(open(dest)).get("instrument_stamp") == stamp:
                    print(f"{name}: cached (stamp unchanged)"); continue
            except Exception:
                pass
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, str(Path(__file__)), "--one", str(lib), str(dest), "--name", name], cwd=str(ROOT), capture_output=True, text=True, timeout=timeout)
            msg = (r.stdout.strip().splitlines() or [""])[-1] if r.returncode == 0 else f"ERROR rc={r.returncode}: {(r.stderr or '').strip().splitlines()[-1:] }"
            timings[name] = {"seconds": round(time.time() - t0, 1), "rc": r.returncode, "timed_out": False, "path": str(lib)}
        except subprocess.TimeoutExpired:
            msg = f"TIMED OUT after {timeout:.0f}s — recorded, never a silent hole"
            timings[name] = {"seconds": round(time.time() - t0, 1), "rc": None, "timed_out": True, "path": str(lib)}
            if dest.exists(): dest.unlink()
        print(f"{name}: {msg}", flush=True)
        json.dump(timings, open(out / "timings.json", "w"), indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
