#!/usr/bin/env python3
"""venv_check.py — health-check step 20 (FIX_44, owner 2026-09-15): the venv matches what the app needs.

FAIL when
  * the running interpreter falls outside any installed distribution's Requires-Python,
  * `pip check` reports a broken requirement,
  * a declared dependency (pyproject [project].dependencies) is not installed,
  * a module imported UNGUARDED at MODULE LEVEL by live engine code cannot be imported (the daemon
    dies at import — a launch fact, not a latent one).
INFO (never a fail) for distributions whose tested classifier ceiling is below the running Python,
for unguarded absent imports in files off the daemon route (the standalone harnesses), and for
absent imports that sit inside a function body (call-time — the owner's ruling 2026-09-09: an
uncalled path is not a defect; these are to-dos for when the path is wired). Imports under
`if TYPE_CHECKING:` never execute and are not counted.

Method: importlib.metadata only (Requires-Python, classifiers, packages_distributions), `pip check`
by subprocess, the import walk over the engine packages named in pyproject
[tool.setuptools.packages.find].include through scan_scope.iter_live_py (never the run-against
trees, never .archive, never the plants), stdlib from sys.stdlib_module_names, a guarded import is
one whose enclosing try has an except clause naming ImportError / ModuleNotFoundError / Exception /
bare. No network.
"""
from __future__ import annotations

import ast
import importlib.metadata as md
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_scope import iter_live_py  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PY = tuple(sys.version_info[:3])
PY_STR = ".".join(map(str, PY))
PLANT_DIRS = {"generator_plants", "plants"}
# Standalone harnesses / tools that never ride the daemon route (gearbox → 4 daemons): their
# absent imports are INFO. Kept as an explicit list so a file joining the route flips to FAIL.
OFF_ROUTE = {"system_scripts/mypy_n_contracts_watcher/harness.py"}

_SPEC_OP = re.compile(r"^\s*(>=|<=|==|!=|~=|>|<)\s*([0-9][0-9A-Za-z.*]*)\s*$")


def _ver(s: str) -> Tuple[int, ...]:
    out = []
    for part in s.split("."):
        if part == "*":
            break
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out)


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a2, b2 = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a2 > b2) - (a2 < b2)


def satisfies(requires_python: Optional[str], py: Tuple[int, ...] = PY) -> Tuple[bool, str]:
    """PEP 440 subset sufficient for Requires-Python strings in the wild (>=, >, <=, <, ==, !=, ~=, wildcards)."""
    if not requires_python:
        return True, "unspecified"
    for clause in requires_python.split(","):
        m = _SPEC_OP.match(clause)
        if not m:
            return True, f"unparsed clause {clause.strip()!r} (not enforced)"
        op, raw = m.group(1), m.group(2)
        v = _ver(raw)
        prefix = raw.endswith(".*")
        if op == "!=":
            if prefix and py[: len(v)] == v:
                return False, clause.strip()
            if not prefix and _cmp(py[: len(v)], v) == 0:
                return False, clause.strip()
        elif op == "==":
            if prefix and py[: len(v)] != v:
                return False, clause.strip()
            if not prefix and _cmp(py[: len(v)], v) != 0:
                return False, clause.strip()
        elif op == "~=":
            if _cmp(py, v) < 0 or py[: len(v) - 1] != v[:-1]:
                return False, clause.strip()
        else:
            c = _cmp(py, v)
            ok = {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0}[op]
            if not ok:
                return False, clause.strip()
    return True, requires_python


def _ceiling(dist: md.Distribution) -> Optional[Tuple[int, int]]:
    best = None
    for c in dist.metadata.get_all("Classifier") or []:
        m = re.match(r"Programming Language :: Python :: (3)\.(\d+)$", c)
        if m:
            t = (int(m.group(1)), int(m.group(2)))
            best = t if best is None or t > best else best
    return best


def distributions_report() -> Dict[str, Any]:
    rows, fails, info = [], [], []
    for d in sorted(md.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name, rp = d.metadata["Name"], d.metadata.get("Requires-Python")
        ok, why = satisfies(rp)
        ceil = _ceiling(d)
        row = {"name": name, "version": d.version, "requires_python": rp, "ok": ok, "ceiling": ".".join(map(str, ceil)) if ceil else None}
        rows.append(row)
        if not ok:
            fails.append(f"{name} {d.version} Requires-Python {rp!r} excludes the running Python {PY_STR} ({why})")
        elif ceil and ceil < PY[:2]:
            info.append(f"{name} {d.version} tested through Python {ceil[0]}.{ceil[1]} (running {PY_STR})")
    return {"count": len(rows), "rows": rows, "fails": fails, "info": info}


def pip_check() -> Dict[str, Any]:
    try:
        p = subprocess.run([sys.executable, "-m", "pip", "check", "--disable-pip-version-check"], capture_output=True, text=True, timeout=120)
        out = (p.stdout + p.stderr).strip()
        return {"ok": p.returncode == 0, "output": out}
    except Exception as e:  # pip missing or timed out — measure it, do not guess
        return {"ok": False, "output": f"{type(e).__name__}: {e}"}


def declared_dependencies() -> List[str]:
    try:
        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    except Exception:
        return []
    deps = data.get("project", {}).get("dependencies", []) or []
    return [re.split(r"[<>=!~;\[ ]", dep.strip(), maxsplit=1)[0] for dep in deps if dep.strip()]


def engine_packages() -> List[Path]:
    try:
        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        inc = data["tool"]["setuptools"]["packages"]["find"]["include"]
    except Exception:
        inc = ["no_aivalidator*", "rca_main*", "detritus_cleaner*", "semantic_analysis*", "signature_engine*", "utils*", "system_scripts*"]
    out = []
    for pat in inc:
        top = pat.rstrip("*")
        p = REPO / top
        if p.is_dir():
            out.append(p)
    return out


def _type_checking_only(tree: ast.AST) -> Set[int]:
    """Line numbers of imports under `if TYPE_CHECKING:` — never executed."""
    lines: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            t = node.test
            name = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else None)
            if name == "TYPE_CHECKING":
                for sub in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(sub, (ast.Import, ast.ImportFrom)):
                        lines.add(sub.lineno)
    return lines


def _function_scope(tree: ast.AST) -> Set[int]:
    """Line numbers of imports inside a function body (call-time, not module-level)."""
    lines: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    lines.add(sub.lineno)
    return lines


def _guarded(tree: ast.AST) -> Set[int]:
    """Line numbers of import statements sitting under a try whose handlers catch ImportError."""
    lines: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        catches = False
        for h in node.handlers:
            if h.type is None:
                catches = True
            else:
                names = {n.id for n in ast.walk(h.type) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(h.type) if isinstance(n, ast.Attribute)}
                if names & {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}:
                    catches = True
        if not catches:
            continue
        for sub in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(sub, (ast.Import, ast.ImportFrom)):
                lines.add(sub.lineno)
    return lines


def _local_names(repo: Path, file: Path, pkgs: List[Path]) -> Set[str]:
    names: Set[str] = set()
    for d in (repo, file.parent, *[p for p in file.parents if p != repo and repo in p.parents]):
        try:
            for child in d.iterdir():
                if child.suffix == ".py":
                    names.add(child.stem)
                elif child.is_dir() and not child.name.startswith("."):
                    names.add(child.name)
        except OSError:
            pass
    names |= {p.name for p in pkgs}
    names |= _ENGINE_NAMES
    return names


_ENGINE_NAMES: Set[str] = set()


def _collect_engine_names(pkgs: List[Path]) -> None:
    """Every .py stem and package dir anywhere under the engine packages: the daemons reach them
    through sys.path insertions (the dash's `path_hacks` feed), so they are local, not third-party."""
    for pkg in pkgs:
        for py in iter_live_py(pkg, whitelist=frozenset()):
            _ENGINE_NAMES.add(py.stem)
            for part in py.relative_to(REPO).parts[:-1]:
                _ENGINE_NAMES.add(part)


def import_walk() -> Dict[str, Any]:
    stdlib = set(sys.stdlib_module_names)
    pkgs = engine_packages()
    dist_map = md.packages_distributions()
    third: Dict[str, Dict[str, Any]] = {}
    files = 0
    _collect_engine_names(pkgs)
    for pkg in pkgs:
        for py in iter_live_py(pkg, whitelist=frozenset()):
            rel = py.relative_to(REPO).as_posix()
            if PLANT_DIRS & set(py.relative_to(REPO).parts):
                continue
            files += 1
            try:
                tree = ast.parse(py.read_bytes(), filename=str(py))
            except SyntaxError:
                continue
            guarded = _guarded(tree) | _type_checking_only(tree)
            call_time = _function_scope(tree)
            local = _local_names(REPO, py, pkgs)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    tops = [(a.name.split(".")[0], node.lineno) for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level or not node.module:
                        continue
                    tops = [(node.module.split(".")[0], node.lineno)]
                else:
                    continue
                for top, ln in tops:
                    if top in stdlib or top in local or top == "__future__":
                        continue
                    e = third.setdefault(top, {"present": None, "dist": sorted(dist_map.get(top, [])), "unguarded": [], "guarded": [], "call_time": []})
                    if ln in guarded:
                        e["guarded"].append(f"{rel}:{ln}")
                    elif ln in call_time:
                        e["call_time"].append(f"{rel}:{ln}")
                    else:
                        e["unguarded"].append(f"{rel}:{ln}")
    for top, e in third.items():
        try:
            e["present"] = importlib.util.find_spec(top) is not None
        except (ValueError, ImportError):
            e["present"] = False
    return {"files": files, "packages": [p.name for p in pkgs], "third_party": dict(sorted(third.items()))}


def check() -> Dict[str, Any]:
    r: Dict[str, Any] = {"python": PY_STR, "executable": sys.executable, "fails": [], "info": []}
    dist = distributions_report()
    r["distributions"] = dist["count"]; r["fails"] += dist["fails"]; r["info"] += dist["info"]
    pc = pip_check(); r["pip_check"] = pc
    if not pc["ok"]:
        r["fails"].append(f"pip check: {pc['output'] or 'non-zero exit'}")
    r["declared"] = declared_dependencies()
    installed_lc = {d.metadata["Name"].lower().replace("_", "-") for d in md.distributions()}
    for dep in r["declared"]:
        if dep.lower().replace("_", "-") not in installed_lc:
            r["fails"].append(f"declared dependency {dep!r} (pyproject.toml) is not installed")
    walk = import_walk(); r["import_walk"] = {"files": walk["files"], "packages": walk["packages"]}
    absent_fail, absent_info, guarded_absent = [], [], []
    for top, e in walk["third_party"].items():
        if e["present"]:
            continue
        if e["unguarded"]:
            sites = e["unguarded"]
            if all(s.split(":")[0] in OFF_ROUTE for s in sites):
                absent_info.append(f"{top} absent, imported unguarded only off the daemon route: {', '.join(sites)}")
            else:
                absent_fail.append(f"{top} absent, imported unguarded at module level by live engine code: {', '.join(sites)}")
        elif e["call_time"]:
            absent_info.append(f"{top} absent, imported at call time (latent — to-do when the path is wired): {', '.join(e['call_time'])}")
        else:
            guarded_absent.append(f"{top} absent, guarded (optional): {', '.join(e['guarded'])}")
    r["fails"] += absent_fail; r["info"] += absent_info + guarded_absent
    r["third_party"] = {k: {"present": v["present"], "dist": v["dist"], "unguarded": len(v["unguarded"]), "call_time": len(v["call_time"]), "guarded": len(v["guarded"])} for k, v in walk["third_party"].items()}
    r["passed"] = not r["fails"]
    return r


def main() -> int:
    r = check()
    print(f"python {r['python']} at {r['executable']}; {r['distributions']} distributions; pip check {'clean' if r['pip_check']['ok'] else 'BROKEN'}; "
          f"declared {len(r['declared'])}; import walk {r['import_walk']['files']} files over {', '.join(r['import_walk']['packages'])}; "
          f"third-party names {len(r['third_party'])} (present {sum(1 for v in r['third_party'].values() if v['present'])})")
    for f in r["fails"]:
        print(f"  ✗ {f}")
    for i in r["info"]:
        print(f"  · {i}")
    print("  ✓ venv matches what the app needs" if r["passed"] else "  ✗ venv does NOT match what the app needs")
    if "--json" in sys.argv:
        print(json.dumps(r, indent=1))
    return 0 if r["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
