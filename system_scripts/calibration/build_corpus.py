"""build_corpus.py — calibration corpus builder (calibrator A8, 2026-09-06). Lineage B clone (ARCHIVE/runs/the_group/build_target.py).

One built target per spec: for every family, a package holding EXACTLY ONE plant function in its own module, 2-3 honest
twins (+ one control) in a second module, and a control __init__; an entry module that imports one symbol from every
module and calls them under a __main__ guard (live under rule 16 by construction). Every folder and file name is drawn
from the naming pool (Curb, then Tool tracks). Certification BEFORE the manifest exists (rule 6): stricken-term scan
of every path and every byte, compile() of every module, entry-imports-all assert; a failure exits without pool marks.

usage: build_corpus.py SPEC.py                 # real build: pool names, ~/Desktop/<target>, ARCHIVE/runs/<target>/
       build_corpus.py SPEC.py --dry-run DIR   # placeholder names, no pool marks, builds under DIR (iterate here first)
"""
from __future__ import annotations
import datetime, hashlib, importlib.util, json, re, shutil, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
POOLS = [ROOT / "ARCHIVE/naming/curb_episode_pool.txt", ROOT / "ARCHIVE/naming/tool_track_pool.txt",
         ROOT / "ARCHIVE/naming/rush_track_pool.txt"]   # roll-over order: Curb → Tool → Rush (owner 2026-09-06, rule 1 similar-source clause)
STRICKEN = re.compile(r"t[e3]st", re.I)      # rule 2: the t-word appears nowhere — no path, no byte
RESERVED = {"main", "entry", "build", "system_scripts", "no_aivalidator", "utils", "gauntlet", "rca_main", "semantic_analysis"}


def load_spec(p: Path):
    s = importlib.util.spec_from_file_location("corpus_spec", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)  # type: ignore
    return m


def draw_names(roles: list[str], dry: bool) -> tuple[dict[str, str], list[tuple[Path, str]]]:
    if dry:
        return {r: f"dry_{r}" for r in roles}, []
    names: dict[str, str] = {}; marks: list[tuple[Path, str]] = []; pending = list(roles)
    for pool in POOLS:
        if not pending: break
        lines = pool.read_text(encoding="utf-8").splitlines()
        unused = [l.strip() for l in lines if l.strip() and not l.startswith("#") and "# used:" not in l]
        take = unused[:len(pending)]
        for r, n in zip(pending, take):
            names[r] = n; marks.append((pool, n))
        pending = pending[len(take):]
    assert not pending, f"pools exhausted: {len(pending)} names short (add a pool, rule 1 similar-source clause)"
    vals = list(names.values())
    assert len(set(vals)) == len(vals), "duplicate name drawn"
    assert not any(a != b and b.startswith(a) for a in vals for b in vals), "prefix clash"
    assert not any(v in RESERVED for v in vals), "reserved name drawn"
    return names, marks


def mark_used(marks: list[tuple[Path, str]], target: str, why: str) -> None:
    for pool in {p for p, _ in marks}:
        lines = pool.read_text(encoding="utf-8").splitlines(); mine = {n for p, n in marks if p == pool}
        for i, l in enumerate(lines):
            if l.strip() in mine and "# used:" not in l: lines[i] = l + f"  # used: {target} ({why})"
        pool.write_text("\n".join(lines) + "\n", encoding="utf-8")


def line_of(T: Path, rel: str, needle: str) -> int:
    for i, l in enumerate((T / rel).read_text(encoding="utf-8").splitlines(), 1):
        if needle in l: return i
    raise SystemExit(f"needle not found: {rel}: {needle}")


def certify(T: Path, modules: list[str], entry_rel: str) -> dict:
    hits = []
    for p in sorted(T.rglob("*")):
        rel = str(p.relative_to(T))
        if STRICKEN.search(rel): hits.append(f"path {rel}")
        if p.is_file() and STRICKEN.search(p.read_text(encoding="utf-8", errors="replace")): hits.append(f"content {rel}")
    if hits: raise SystemExit("CERTIFICATION FAILED — stricken term: " + "; ".join(hits[:6]))
    n = 0
    for rel in modules:
        compile((T / rel).read_text(encoding="utf-8"), rel, "exec"); n += 1
    import ast
    tree = ast.parse((T / entry_rel).read_text(encoding="utf-8"))
    imported = {n_.module for n_ in ast.walk(tree) if isinstance(n_, ast.ImportFrom) and n_.module}
    expected = {rel[:-3].replace("/", ".") for rel in modules if rel != entry_rel and not rel.endswith("__init__.py")}
    missing = sorted(expected - imported)
    if missing: raise SystemExit(f"CERTIFICATION FAILED — entry does not import: {missing}")
    return {"stricken_scan": "clean", "compiled": n, "entry_imports_all": True, "modules": len(modules)}


def build(spec_path: Path, dry_dir: Path | None) -> Path:
    spec = load_spec(spec_path); fams = list(spec.FAMILIES)
    roles = ["target", "entry"] + [f"{f.lower().replace('-', '_')}_{k}" for f in fams for k in ("pkg", "plant", "twins")]
    N, marks = draw_names(roles, dry_dir is not None)
    T = (dry_dir / N["target"]) if dry_dir else (Path.home() / "Desktop" / N["target"])
    if T.exists():
        if dry_dir: shutil.rmtree(T)
        else: raise SystemExit(f"ABORT: {T} exists (rule 3: never rebuild in place)")
    def w(rel, text):
        p = T / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text, encoding="utf-8")
    modules, plants, twins, controls, imports, calls = [], [], [], [], [], []
    for f in fams:
        fk = f.lower().replace("-", "_"); pkg, plant, tw = N[f"{fk}_pkg"], N[f"{fk}_plant"], N[f"{fk}_twins"]; F = spec.FAMILIES[f]
        w(f"{pkg}/__init__.py", f'"""{pkg} — {f} package (control)."""\n'); modules.append(f"{pkg}/__init__.py"); controls.append(f"{pkg}/__init__.py")
        P = F["plant"]; body = (P.get("prelude", "") + "\n\n" if P.get("prelude") else "") + P["code"].rstrip() + "\n"
        w(f"{pkg}/{plant}.py", f'"""{f} plant module — exactly one function."""\n' + body); modules.append(f"{pkg}/{plant}.py")
        plants.append({"file": f"{pkg}/{plant}.py", "line": line_of(T, f"{pkg}/{plant}.py", f"# PLANT: {f}"), "accept_any_of": [f], "family": f, "what": P["what"], "fn": P["fn"]})
        imports.append(f"from {pkg}.{plant} import {P['fn']}"); calls.append(P["call"])
        tb = [f'"""{f} honest twins (+ control)."""']
        pre = {t.get("prelude", "") for t in F["twins"] if t.get("prelude")} | ({F["control"].get("prelude", "")} if F["control"].get("prelude") else set())
        tb += sorted(x for x in pre if x)
        for t in F["twins"]: tb += ["", "", t["code"].rstrip()]
        tb += ["", "", F["control"]["code"].rstrip(), ""]
        w(f"{pkg}/{tw}.py", "\n".join(tb)); modules.append(f"{pkg}/{tw}.py")
        for t in F["twins"]:
            twins.append({"file": f"{pkg}/{tw}.py", "line": line_of(T, f"{pkg}/{tw}.py", f"# TWIN: {f}" + (f" {t['tag']}" if t.get("tag") else "")), "family": f, "what": t["what"], "source": t.get("source", ""), "expect": "pass", "fn": t["fn"]})
            imports.append(f"from {pkg}.{tw} import {t['fn']}"); calls.append(t["call"])
        imports.append(f"from {pkg}.{tw} import {F['control']['fn']}"); calls.append(F["control"]["call"])
    entry = N["entry"] + ".py"
    w(entry, '"""Entry — imports one symbol from every module and calls them (rule 16: live by construction)."""\n' + (getattr(spec, "ENTRY_PRELUDE", "") + "\n" if getattr(spec, "ENTRY_PRELUDE", "") else "")
      + "\n".join(imports) + "\n\n\ndef main() -> int:\n    out = []\n" + "".join(f"    {l}\n" for l in getattr(spec, "ENTRY_SETUP", "").splitlines() if l.strip())
      + "".join(f"    out.append({c})\n" for c in calls) + "    if not out:\n        return 1\n    return 0\n\n\nif __name__ == \"__main__\":\n    raise SystemExit(main())\n")
    modules.append(entry); controls.append(entry)
    cert = certify(T, modules, entry)
    sys.path.insert(0, str(ROOT / "system_scripts" / "calibration"))
    from stamp import instrument_stamp
    manifest = {
        "target": str(T), "built": datetime.datetime.now().isoformat(timespec="seconds"), "names": N,
        "source": "dry-run placeholders" if dry_dir else "Curb pool (rule 14), Tool-track roll-over",
        "corpus": {"slice": spec.SLICE, "half": spec.HALF, "spec": spec_path.name, "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(), "seed": spec.SEED},
        "families": fams, "held_out": bool(spec.HELD_OUT), "k_used": None, "instrument_stamp": instrument_stamp(), "certification": cert,
        "entry_point": f"{entry} (main guard; imports every module)", "expect_live_scanned": modules,
        "planted_findings": plants, "honest_twins": twins, "controls": controls, "expect_zero_findings (controls)": controls,
        "post_conditions": ["every plant caught_by_id on its own row", "every twin passes", "every control clean", "certification clean", "teardown byte-identical"],
    }
    run_dir = (dry_dir / "runs" / N["target"]) if dry_dir else (ROOT / "ARCHIVE/runs" / N["target"]); run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    shutil.copy(__file__, run_dir / "build_corpus.py"); shutil.copy(spec_path, run_dir / spec_path.name)
    if not dry_dir: mark_used(marks, N["target"], f"calibration slice {spec.SLICE} half {spec.HALF}")
    n = sum(1 for _ in T.rglob("*") if _.is_file())
    print(f"TARGET={T} ({n} files, {len(plants)} plants, {len(twins)} twins, {len(controls)} controls); MANIFEST={run_dir / 'manifest.json'}")
    return run_dir / "manifest.json"


if __name__ == "__main__":
    sp = Path(sys.argv[1]); dry = Path(sys.argv[sys.argv.index("--dry-run") + 1]) if "--dry-run" in sys.argv else None
    build(sp, dry)
