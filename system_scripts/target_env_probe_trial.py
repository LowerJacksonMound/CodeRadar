#!/usr/bin/env python3
"""M-54 / M-50 trial (2026-10-07): the target env's import probe, proved both ways.

1. A synthetic target: a needed third-party name that is absent is MISSING; a name under `try:` is optional,
   not missing; relative imports and the target's own package are never probed.
A Tk-using target, named by $CR_TK_TARGET ("the gang target" below):
2. The gang target in a Python WITHOUT Tk (Homebrew python@3.13): `tkinter` is missing with `_tkinter` named.
3. The gang target in its built env (Homebrew 3.14 + python-tk@3.14): nothing missing.
Exit 1 on any FAIL. Nothing is built; nothing is written under the target.
"""
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import target_env

GANG = Path(os.environ["CR_TK_TARGET"]).expanduser() if os.environ.get("CR_TK_TARGET") else None
NO_TK = "/opt/homebrew/opt/python@3.13/bin/python3.13"
fails = 0

def check(name, ok, detail=""):
    global fails
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))
    fails += 0 if ok else 1

with tempfile.TemporaryDirectory() as d:
    t = Path(d) / "tgt"; (t / "pkg").mkdir(parents=True)
    (t / "pkg" / "__init__.py").write_text("")
    (t / "pkg" / "a.py").write_text(
        "import json\nimport nonexistent_pkg_xyz_cr.sub\nfrom . import b\nimport pkg.b\nfrom os import path\n"
        "try:\n    import maybe_missing_cr\nexcept ImportError:\n    maybe_missing_cr = None\n"
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import only_for_types_cr\n")
    (t / "pkg" / "b.py").write_text("x = 1\n")
    (t / "top.py").write_text("import pkg\nimport top\n")
    needed, optional = target_env.target_imports(t)
    check("synthetic: needed names", needed == ["json", "nonexistent_pkg_xyz_cr", "os", "typing"], f"{needed}")
    check("synthetic: optional names", optional == ["maybe_missing_cr", "only_for_types_cr"], f"{optional}")
    res = target_env.probe_imports(t, sys.executable)
    check("synthetic: the absent needed name is missing", list(res["missing"]) == ["nonexistent_pkg_xyz_cr"], f"{res['missing']}")
    check("synthetic: the guarded names are optional, not missing",
          set(res["optional_missing"]) == {"maybe_missing_cr", "only_for_types_cr"} and not res["error"], f"{res['optional_missing']} {res['error']}")
    rec = {"status": "built", "imports": res, "base_python": sys.executable}
    check("synthetic: describe() carries the red verdict", "target cannot run in its env: nonexistent_pkg_xyz_cr" in target_env.describe(rec),
          target_env.describe(rec))

if GANG is not None and GANG.is_dir() and Path(NO_TK).exists():
    res = target_env.probe_imports(GANG, NO_TK)
    check("gang in a Tk-less Python: tkinter missing, _tkinter named",
          "tkinter" in res["missing"] and "_tkinter" in res["missing"]["tkinter"], f"{res['missing']} {res['error']}")
    rec = {"status": "built", "imports": res, "base_python": NO_TK}
    check("gang in a Tk-less Python: install hint names python-tk@3.13", target_env.install_hint(rec) == "brew install python-tk@3.13",
          target_env.install_hint(rec))
else:
    check("gang target / python@3.13 present", False, f"{GANG} {NO_TK}")

if GANG is not None and GANG.is_dir():
    rec = target_env.read(GANG, tree=Path(__file__).resolve().parent.parent)
    py = rec.get("python")
    if py:
        res = target_env.probe_imports(GANG, py)
        check("gang in its built env: every needed import resolves", not res["missing"] and not res["error"],
              f"checked={res['checked']} missing={res['missing']} {res['error']}")
    else:
        check("gang built env present (read() gives its python)", False, target_env.describe(rec))

print("TRIAL", "PASS" if not fails else f"FAIL ({fails})")
sys.exit(1 if fails else 0)
