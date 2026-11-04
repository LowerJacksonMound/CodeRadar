#!/usr/bin/env python3
"""target_env.py — B2 / R2 + B3 (MCP working packet, 2026-09-28): the target's PRIVATE env.

CodeRadar builds (or reuses) one interpreter environment per target, in ITS OWN tree —
`<tree>/.archive/target_envs/<repo_id>/venv/` — never in the target. It is keyed by the
digest of the target's dependency files (pyproject.toml, setup.py, setup.cfg, requirements
files, Pipfile) plus the base interpreter's version: same digest + a live interpreter =
`reused`, anything else = rebuilt.

Deps are installed FROM THE LAUNCH SNAPSHOT (~/CodeRadar_snapshots/<name>_<ts>), never by
building in the target:
  * a static `[project].dependencies` list (plus pytest and the declared test/dev extras and
    dependency groups) is installed by requirement string — nothing of the target is built;
  * requirements*.txt / requirements/{test,tests,dev}*.txt are installed with `-r` from the
    snapshot copy;
  * a target whose deps are only knowable by building it (setup.py, dynamic deps) is
    installed from a scratch COPY of the snapshot (builds never write into the snapshot);
  * the target's own dist is installed from that copy, --no-deps, NON-editable (Q8 follow-up),
    so `importlib.metadata` resolves it; its live code is still imported from the target path
    (the target root, or `<target>/src` for a src layout, precede site-packages). A build that
    fails (e.g. setuptools_scm with no VCS) leaves a metadata-only stub when a static version
    is known, else none — recorded in `target_dist`.

Installer: uv ($CODERADAR_UV, else `uv` on PATH, else ~/.local/bin/uv) when present, else `python -m venv` + pip.

Q5: a build that FAILS never blocks the scan. The record `env.json` always carries
`status` = built | reused | failed, and `reason` when failed; every reader (the run tool,
the entry-point wrapper's launch, the mypy tracker, cr_watch / cr_status) degrades to the
engine interpreter and SAYS so. This module's CLI always exits 0 unless its own arguments
are wrong.

B3: `layout()` — `src` when `<target>/src` holds a package (a dir with `__init__.py`) or a
top-level module, and no top-level package of the same name shadows it; else `flat`. The
src path goes on the path for the run tool, the runner, the entry proof and mypy — the
I-134 / I-158 hand step (`PYTHONPATH=<target>/src` in the launching env) is retired.

    .venv_new/bin/python system_scripts/target_env.py <target> [--snapshot DIR]
    → prints `[target env] ...` lines; writes <tree>/.archive/target_envs/<repo_id>/env.json
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TREE = Path(__file__).resolve().parent.parent
ENVS_REL = Path(".archive") / "target_envs"
UV_BIN = Path(os.environ.get("CODERADAR_UV") or shutil.which("uv") or Path.home() / ".local" / "bin" / "uv")
SCHEMA = 4   # 4: imports probed in the env (M-54); 2: the target's own dist is installed (Q8 follow-up); 3: nested/tox test reqs (MCPW-D O2)
INSTALL_TIMEOUT_S = 900
# Extras / dependency groups whose names say "tests or dev" — installed with pytest.
TEST_GROUP_NAMES = {"test", "tests", "testing", "dev", "typing", "types", "mypy"}   # +typing: MCPW-D O2
DEP_FILE_NAMES = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "tox.ini")
# MCPW-D O2 (run 180): which requirement FILES are test/dev inputs. A file qualifies when a
# name token (split on - _ .) is one of these — `requirements-tests.txt`, `test-requirements.txt`,
# `requirements/dev.txt`, `requirements_typing.txt` — and no token is a docs/release word.
# Typing stubs (`types-*`) usually live in exactly these files, and mypy reads the env they
# build. Docs requirements (sphinx & co.) are never installed.
REQ_FILE_WANT = {"test", "tests", "testing", "dev", "develop", "development", "typing", "types",
                 "mypy", "lint", "linting", "ci", "check", "checks", "base", "main", "install",
                 "runtime", "core", "prod", "requirements", "requirement", "reqs"}
REQ_FILE_SKIP = {"doc", "docs", "documentation", "sphinx", "release", "publish", "deploy",
                 "benchmark", "benchmarks", "bench", "notebook", "notebooks", "examples",
                 "example", "gpu", "cuda", "windows", "win"}


def _req_file_wanted(p: Path) -> bool:
    toks = {t for t in re.split(r"[-_.]+", p.stem.lower()) if t}
    return bool(toks & REQ_FILE_WANT) and not (toks & REQ_FILE_SKIP)


def repo_id(target: Path) -> str:
    """Same scheme as circuit_daemon / gearbox get_repo_id: sha256(resolved path)[:12]."""
    return hashlib.sha256(str(Path(target).resolve()).encode()).hexdigest()[:12]


def env_home(target: Path, tree: Optional[Path] = None) -> Path:
    return (tree or TREE) / ENVS_REL / repo_id(target)


def _record_path(target: Path, tree: Optional[Path] = None) -> Path:
    return env_home(target, tree) / "env.json"


def _env_python(home: Path) -> Path:
    return home / "venv" / "bin" / "python"


# ── B3: layout ───────────────────────────────────────────────────────────────
def layout(target: Path) -> Tuple[str, Optional[Path]]:
    """('src', <target>/src) for a src layout, else ('flat', None). Reads only."""
    target = Path(target)
    src = target / "src"
    if not src.is_dir() or src.is_symlink():
        return "flat", None
    names = set()
    try:
        for child in src.iterdir():
            if child.is_dir() and (child / "__init__.py").is_file():
                names.add(child.name)
            elif child.is_file() and child.suffix == ".py":
                names.add(child.stem)
    except OSError:
        return "flat", None
    if not names:
        return "flat", None
    # A top-level package of the same name means the root, not src, is what imports resolve to.
    if any((target / n / "__init__.py").is_file() for n in names):
        return "flat", None
    return "src", src


def import_roots(target: Path) -> List[str]:
    """The paths the target's live code is imported from: <target>/src first for a src layout."""
    kind, src = layout(target)
    return [str(src)] if kind == "src" and src else []


# ── the record ───────────────────────────────────────────────────────────────
def read(target: Path, tree: Optional[Path] = None) -> Dict[str, Any]:
    """The published record for `target`, or {'status': 'none'} — never raises. `python` is
    set only when the env is usable (built|reused and its interpreter is on disk)."""
    target = Path(target)
    out: Dict[str, Any] = {"status": "none", "python": None}
    try:
        rec = json.loads(_record_path(target, tree).read_text(encoding="utf-8"))
        if isinstance(rec, dict):
            out.update(rec)
    except (OSError, ValueError):
        pass
    py = _env_python(env_home(target, tree))
    if out.get("status") in ("built", "reused") and py.exists():
        out["python"] = str(py)
    else:
        out["python"] = None
        if out.get("status") in ("built", "reused"):
            out["status"] = "failed"
            out["reason"] = f"env interpreter missing at {py}"
    kind, src = layout(target)
    out["layout"] = kind
    out["src_path"] = str(src) if src else None
    return out


def describe(rec: Dict[str, Any]) -> str:
    """`built` | `reused` | `failed: <reason>` | `none` — the one-line form readers publish.
    B4 / Q-H0-6 (2026-10-01, from launch.sh's T-14 reader): a built/reused env whose `target_dist` is not
    `installed …` carries the gap too — `built · target itself not installable (no pyproject/setup.py)` — so every
    reader (MCP, launch light) says it; launch.sh takes the state token before the first ` · `."""
    st = str(rec.get("status") or "none")
    if st == "failed":
        return f"failed: {rec.get('reason') or 'unknown'}"
    parts = [st, target_dist_gap(rec), cannot_run(rec)]   # M-54: a target that cannot import here says so
    return " · ".join(x for x in parts if x)


def target_dist_gap(rec: Dict[str, Any]) -> str:
    """'' when the target dist is installed (or the env was not built); else why the target itself is not in."""
    st = str(rec.get("status") or "none")
    dist = str(rec.get("target_dist") or "")
    if st not in ("built", "reused") or not dist or dist.startswith("installed"):
        return ""
    root = Path(str(rec.get("target") or ""))
    build_files = [n for n in ("pyproject.toml", "setup.py", "setup.cfg") if (root / n).is_file()]
    if build_files == []:
        return "target itself not installable (no pyproject/setup.py)"
    if dist.startswith("stub"):
        return "target itself not built (metadata-only stub)"
    return "target itself not installed (its build failed)"


def _write(target: Path, rec: Dict[str, Any], tree: Optional[Path] = None) -> None:
    path = _record_path(target, tree)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ── the digest ───────────────────────────────────────────────────────────────
def dep_files(root: Path) -> List[Path]:
    root = Path(root)
    found = [root / n for n in DEP_FILE_NAMES if (root / n).is_file()]
    found += sorted(p for p in root.glob("requirements*.txt") if p.is_file())
    found += sorted(p for p in root.glob("*-requirements.txt") if p.is_file())
    for d in ("requirements", "reqs"):
        rq = root / d
        if rq.is_dir():
            found += sorted(p for p in rq.glob("*.txt") if p.is_file())
    return found


def digest(root: Path, base_python: str) -> str:
    h = hashlib.sha256(f"schema={SCHEMA}\npython={_py_version(base_python)}\n".encode())
    for p in dep_files(root):
        h.update(p.relative_to(root).as_posix().encode() + b"\0")
        h.update(p.read_bytes() + b"\0")
    return h.hexdigest()[:16]


def _py_version(py: str) -> str:
    try:
        r = subprocess.run([py, "-c", "import sys; print(sys.version.split()[0])"],
                           capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or "?"
    except (OSError, subprocess.SubprocessError):
        return "?"


# ── what to install ──────────────────────────────────────────────────────────
def _group_reqs(groups: Dict[str, Any], name: str, seen: set) -> List[str]:
    if name in seen or name not in groups:
        return []
    seen.add(name)
    out: List[str] = []
    for item in groups.get(name) or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and "include-group" in item:
            out += _group_reqs(groups, str(item["include-group"]), seen)
    return out


def plan(snap: Path) -> Dict[str, Any]:
    """Read the SNAPSHOT's dep files. Returns {'reqs': [...], 'req_files': [...],
    'build_snapshot': bool, 'sources': [...]}. pytest is always in `reqs`."""
    reqs: List[str] = []
    req_files: List[str] = []
    sources: List[str] = []
    build_snapshot = False
    pp = snap / "pyproject.toml"
    project: Dict[str, Any] = {}
    if pp.is_file():
        import tomllib
        data = tomllib.loads(pp.read_text(encoding="utf-8"))
        project = data.get("project") or {}
        dynamic = set(project.get("dynamic") or [])
        if project and "dependencies" not in dynamic:
            reqs += [str(r) for r in project.get("dependencies") or []]
            sources.append("pyproject:[project].dependencies")
        elif project or (snap / "setup.py").is_file() or (snap / "setup.cfg").is_file():
            build_snapshot = True
        for extra, lst in (project.get("optional-dependencies") or {}).items():
            if extra.lower() in TEST_GROUP_NAMES:
                reqs += [str(r) for r in lst or []]
                sources.append(f"pyproject:extra[{extra}]")
        groups = data.get("dependency-groups") or {}
        for g in groups:
            if g.lower() in TEST_GROUP_NAMES:
                reqs += _group_reqs(groups, g, set())
                sources.append(f"pyproject:group[{g}]")
    elif (snap / "setup.py").is_file() or (snap / "setup.cfg").is_file():
        build_snapshot = True
    # MCPW-D O2: root `requirements*.txt` / `*-requirements.txt` and nested `requirements/*.txt`
    # (`reqs/*.txt`) all pass the same name filter — run 180 skipped
    # `requirements/requirements-tests.txt` (its stem does not START with "test"), so arrow's
    # `types-python-dateutil` never reached the env and mypy reported 3 spurious import errors.
    cands = sorted(snap.glob("requirements*.txt")) + sorted(snap.glob("*-requirements.txt"))
    for d in ("requirements", "reqs"):
        if (snap / d).is_dir():
            cands += sorted((snap / d).glob("*.txt"))
    for p in cands:
        if p.is_file() and _req_file_wanted(p) and str(p) not in req_files:
            req_files.append(str(p))
    # tox.ini [testenv] deps, when trivial: `-r <file>` lines inside the snapshot and plain
    # requirement strings; anything with a tox substitution (`{...}`) or an option is skipped.
    tox = snap / "tox.ini"
    if tox.is_file():
        import configparser
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            cp.read_string(tox.read_text(encoding="utf-8", errors="replace"))
            deps = cp.get("testenv", "deps", fallback="")
        except (configparser.Error, UnicodeError):
            deps = ""
        took = False
        for line in deps.splitlines():
            line = line.split(" #", 1)[0].strip()
            if not line or "{" in line or line.startswith("#"):
                continue
            if line.startswith("-r"):
                f = snap / line[2:].strip()
                if (f.is_file() and f.resolve().is_relative_to(snap.resolve()) and _req_file_wanted(f)
                        and f.resolve() not in {Path(x).resolve() for x in req_files}):
                    req_files.append(str(f))
                    took = True
            elif not line.startswith("-") and re.match(r"^[A-Za-z0-9][A-Za-z0-9._\[\],<>=!~; '\"-]*$", line):
                reqs.append(line)
                took = True
        if took:
            sources.append("tox.ini:[testenv].deps")
    if build_snapshot:
        sources.append("snapshot build (dynamic deps) — the target's own dist removed after")
    sources += [f"-r {Path(f).relative_to(snap).as_posix()}" for f in req_files]
    reqs.append("pytest")
    return {"reqs": reqs, "req_files": req_files, "build_snapshot": build_snapshot,
            "sources": sources, "project_name": str(project.get("name") or "")}


# ── the build ────────────────────────────────────────────────────────────────
def _run(cmd: List[str], cwd: Path, env: Dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True,
                          timeout=INSTALL_TIMEOUT_S)


def _last_line(proc: subprocess.CompletedProcess) -> str:
    """The installer's own words, folded to one line (uv wraps its resolver sentence over
    several lines, so the last line alone reads as a fragment)."""
    text = " ".join(l.strip(" ×╰─▶│") for l in (proc.stderr or proc.stdout or "").splitlines())
    text = " ".join(text.split())
    if not text:
        return f"rc={proc.returncode}"
    return text if len(text) <= 300 else "…" + text[-300:].split(" ", 1)[-1]


_SNAPSHOT_DISTS = r"""
import json, sys
from importlib import metadata
roots = sys.argv[1:]
for d in metadata.distributions():
    try:
        du = json.loads(d.read_text("direct_url.json") or "{}")
    except Exception:
        continue
    if any(r in str(du.get("url", "")) for r in roots):
        ed = bool((du.get("dir_info") or {}).get("editable"))
        print(json.dumps({"name": d.metadata["Name"], "version": d.version, "editable": ed}))
"""


def _snapshot_dists(py: Path, roots: List[str], cwd: Path, env: Dict[str, str]) -> List[Dict[str, Any]]:
    r = _run([str(py), "-c", _SNAPSHOT_DISTS] + roots, cwd, env)
    out = []
    for line in (r.stdout or "").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def _static_name_version(snap: Path) -> Tuple[str, str]:
    """[project].name / static [project].version from the snapshot's pyproject ('' when absent/dynamic)."""
    try:
        import tomllib
        project = tomllib.loads((snap / "pyproject.toml").read_text(encoding="utf-8")).get("project") or {}
    except (OSError, ValueError):
        return "", ""
    dynamic = set(project.get("dynamic") or [])
    return str(project.get("name") or ""), ("" if "version" in dynamic else str(project.get("version") or ""))


def _write_stub_dist(py: Path, name: str, version: str, cwd: Path, env: Dict[str, str]) -> None:
    """A metadata-only dist-info (no code, no .pth): `importlib.metadata` resolves the target's
    name and version while every import still comes from the target path."""
    r = _run([str(py), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], cwd, env)
    purelib = Path((r.stdout or "").strip())
    norm = "".join(c if c.isalnum() or c == "." else "_" for c in name)
    di = purelib / f"{norm}-{version}.dist-info"
    di.mkdir(parents=True, exist_ok=True)
    (di / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
    (di / "INSTALLER").write_text("coderadar-stub\n", encoding="utf-8")
    (di / "RECORD").write_text("", encoding="utf-8")


# ── M-54 (2026-10-07): does the target's code import in the env it was built? ─────────────────
def target_imports(target: Path) -> Tuple[List[str], List[str]]:
    """(needed, optional): the top-level names the target's live .py files (scan_scope's whitelist — the
    launch scan's own scope, step 7) import, read by AST. `optional` are the names imported only under a
    `try:` (an ImportError guard) or `if TYPE_CHECKING:`. Relative imports and the target's own
    packages/modules (a dir or .py of that name under the target or its src/) are left out — they are the
    target, not its needs."""
    import ast
    import scan_scope
    target = Path(target)
    live = sorted(scan_scope.iter_live_py(target))
    # the target's own names at EVERY level (2026-10-07 01:38: a target whose code sits one folder down —
    # `<root>/some_target/sub_pkg/x.py` — imports `sub_pkg`, which the root and src/
    # alone did not name; the probe called it missing and step 8 went red on a target that runs fine)
    local: set = {fp.stem for fp in live}
    for fp in live:
        local.update(fp.relative_to(target).parts[:-1])
    needed: set = set()
    optional: set = set()
    for fp in live:
        try:
            tree = ast.parse(fp.read_text(encoding='utf-8', errors='replace'))
        except (SyntaxError, ValueError, OSError):
            continue
        guarded: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) or (isinstance(node, ast.If) and 'TYPE_CHECKING' in ast.dump(node.test)):
                guarded.update(id(n) for n in ast.walk(node))
        for node in ast.walk(tree):
            names: List[str] = []
            if isinstance(node, ast.Import):
                names = [a.name.split('.')[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split('.')[0]]
            for n in names:
                if n in local or n == '__future__':
                    continue
                (optional if id(node) in guarded else needed).add(n)
    optional -= needed
    return sorted(needed), sorted(optional)


_PROBE_CODE = r"""
import importlib, json, sys
res = {}
for n in json.loads(sys.argv[1]):
    try:
        importlib.import_module(n)
    except BaseException as e:
        res[n] = (type(e).__name__ + ': ' + str(e))[:200]
print('CR_PROBE ' + json.dumps(res))
"""


def probe_imports(target: Path, py: str) -> Dict[str, Any]:
    """M-54: every needed name is IMPORTED in the env's interpreter (`-I`, nothing of the caller's path).
    find_spec is not enough — `tkinter` is found as a package while `import tkinter` dies on the missing
    `_tkinter` C module (Homebrew Python without python-tk). Returns {checked, optional, missing {name: error},
    optional_missing {…}, error}; never raises."""
    needed, optional = target_imports(target)
    out: Dict[str, Any] = {"checked": needed, "optional": optional, "missing": {}, "optional_missing": {},
                           "error": ""}
    if not needed and not optional:
        return out
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON") and k != "VIRTUAL_ENV"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        with tempfile.TemporaryDirectory(prefix="cr_import_probe_") as cwd:
            r = subprocess.run([py, "-I", "-c", _PROBE_CODE, json.dumps(needed + optional)], cwd=cwd, env=env,
                               capture_output=True, text=True, timeout=180)
        line = next((l for l in (r.stdout or "").splitlines() if l.startswith("CR_PROBE ")), None)
        if line is None:
            out["error"] = f"probe gave no verdict (rc={r.returncode}): {_last_line(r)}"[:300]
            return out
        res = json.loads(line[len("CR_PROBE "):])
        out["missing"] = {n: res[n] for n in needed if n in res}
        out["optional_missing"] = {n: res[n] for n in optional if n in res}
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:300]
    return out


def cannot_run(rec: Dict[str, Any]) -> str:
    """'' when every needed import resolved (or nothing was probed); else the red verdict, one line."""
    miss = (rec.get("imports") or {}).get("missing") or {}
    if not miss:
        return ""
    return "target cannot run in its env: " + ", ".join(f"{k} — {v}" for k, v in sorted(miss.items()))


def install_hint(rec: Dict[str, Any]) -> str:
    """What puts the missing import right, when CodeRadar knows: Homebrew Python ships without Tk."""
    miss = (rec.get("imports") or {}).get("missing") or {}
    if any("_tkinter" in str(v) for v in miss.values()):
        ver = ".".join(_py_version(str(rec.get("base_python") or sys.executable)).split(".")[:2])
        return f"brew install python-tk@{ver}"
    return ""


def build(target: Path, snapshot: Optional[Path], base_python: str,
          tree: Optional[Path] = None) -> Dict[str, Any]:
    """Build or reuse the env. Never raises; the returned record is also written to env.json."""
    target = Path(target).resolve()
    home = env_home(target, tree)
    kind, src = layout(target)
    t0 = time.monotonic()
    rec: Dict[str, Any] = {
        "schema": SCHEMA, "target": str(target), "repo_id": repo_id(target),
        "home": str(home), "layout": kind, "src_path": str(src) if src else None,
        "snapshot": str(snapshot) if snapshot else None, "base_python": base_python,
        "installer": "uv" if UV_BIN.exists() else "venv+pip",
        "at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        dig_root = snapshot if snapshot and snapshot.is_dir() else target
        dig = digest(dig_root, base_python)
        rec["digest"] = dig
        prev: Dict[str, Any] = {}
        try:
            prev = json.loads(_record_path(target, tree).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev = {}
        py = _env_python(home)
        if (prev.get("digest") == dig and prev.get("status") in ("built", "reused")
                and py.exists()):
            rec.update({k: prev.get(k) for k in ("installed", "sources", "installer", "built_at",
                                                 "build_seconds", "removed_target_dists", "target_dist")})
            rec.update({"status": "reused", "python": str(py),
                        "seconds": round(time.monotonic() - t0, 2)})
            rec["imports"] = probe_imports(target, str(py))   # M-54: re-probed on every launch, reuse included
            _write(target, rec, tree)
            return rec
        if not snapshot or not snapshot.is_dir():
            raise RuntimeError("no launch snapshot — the launch always takes one (owner 2026-09-30); "
                               "deps are installed only from the snapshot, never by building in the target")
        p = plan(snapshot)
        rec["sources"] = p["sources"]
        if home.exists():
            shutil.rmtree(home / "venv", ignore_errors=True)
        home.mkdir(parents=True, exist_ok=True)
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV")}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        venv = home / "venv"
        with tempfile.TemporaryDirectory(prefix="cr_target_env_") as scratch:
            cwd = Path(scratch)   # never the target; builds happen in the snapshot or uv's cache
            if UV_BIN.exists():
                env["UV_PYTHON_DOWNLOADS"] = "never"
                r = _run([str(UV_BIN), "venv", "--quiet", "--python", base_python, str(venv)], cwd, env)
                if r.returncode != 0:
                    raise RuntimeError(f"uv venv: {_last_line(r)}")
                pip = [str(UV_BIN), "pip", "install", "--quiet", "--python", str(venv / "bin" / "python")]
                pip_un = [str(UV_BIN), "pip", "uninstall", "--quiet", "--python", str(venv / "bin" / "python")]
            else:
                r = _run([base_python, "-m", "venv", str(venv)], cwd, env)
                if r.returncode != 0:
                    raise RuntimeError(f"venv: {_last_line(r)}")
                pip = [str(venv / "bin" / "python"), "-m", "pip", "install", "--quiet",
                       "--disable-pip-version-check"]
                pip_un = [str(venv / "bin" / "python"), "-m", "pip", "uninstall", "-y", "--quiet"]
            # Builds never happen in the snapshot either (its bytes are teardown's reference):
            # a scratch copy of it takes any build/ or *.egg-info a backend writes.
            build_copy = cwd / "snapshot_copy"
            shutil.copytree(snapshot, build_copy, symlinks=True,
                            ignore=shutil.ignore_patterns(".git", "__pycache__", "build", "*.egg-info"))
            args = list(p["reqs"])
            for f in p["req_files"]:
                args += ["-r", f]
            if p["build_snapshot"]:
                args.append(str(build_copy))
            r = _run(pip + args, cwd, env)
            if r.returncode != 0 and p["req_files"]:
                # MCPW-D O2: the wider test/dev file net must not cost a working env — one
                # uninstallable pin in a lint/typing file retries WITHOUT the files, and says so.
                first = _last_line(r)
                args = list(p["reqs"]) + ([str(build_copy)] if p["build_snapshot"] else [])
                r = _run(pip + args, cwd, env)
                if r.returncode == 0:
                    rec["req_files_dropped"] = f"requirement files skipped after install failed: {first}"[:400]
            if r.returncode != 0:
                raise RuntimeError(f"install: {_last_line(r)}")
            # Q8 (follow-up, 2026-09-28): the target's own dist IS installed — from the snapshot copy,
            # --no-deps, NON-editable — so `importlib.metadata` resolves its name and version. Its code
            # is never what runs: the target path precedes site-packages for the run tool, the runner
            # and the entry proof, and mypy checks the explicit live-file list. An editable install
            # (a requirements `-e .`) would put the snapshot on sys.path, so it is replaced.
            vpy = venv / "bin" / "python"
            roots = [str(snapshot), str(build_copy)]
            editable = [d["name"] for d in _snapshot_dists(vpy, roots, cwd, env) if d["editable"]]
            if editable:
                r = _run(pip_un + editable, cwd, env)
                if r.returncode != 0:
                    raise RuntimeError(f"uninstall of the editable target dist {editable}: {_last_line(r)}")
            rec["removed_target_dists"] = editable
            own = [d for d in _snapshot_dists(vpy, roots, cwd, env) if not d["editable"]]
            why = ""
            if not own:
                r = _run(pip + ["--no-deps", str(build_copy)], cwd, env)
                if r.returncode == 0:
                    own = [d for d in _snapshot_dists(vpy, roots, cwd, env) if not d["editable"]]
                else:
                    why = _last_line(r)
            if own:
                rec["target_dist"] = (f"installed {own[0]['name']} {own[0]['version']} "
                                      "(from the snapshot, --no-deps, non-editable)")
            else:
                # Dynamic versions (setuptools_scm with no VCS in the snapshot, …) must not fail
                # the env: a metadata-only stub when a static version is known, else none — said.
                name, version = _static_name_version(snapshot)
                why = why or "no distribution was built"
                if name and version:
                    _write_stub_dist(vpy, name, version, cwd, env)
                    rec["target_dist"] = f"stub {name} {version} (metadata only; build failed: {why})"
                else:
                    rec["target_dist"] = (f"none (build failed and no static version: {why}) — "
                                          "importlib.metadata cannot resolve the target")
            r = _run([str(venv / "bin" / "python"), "-m", "pip", "list", "--format=freeze"]
                     if not UV_BIN.exists() else
                     [str(UV_BIN), "pip", "freeze", "--python", str(venv / "bin" / "python")], cwd, env)
            rec["installed"] = [l for l in (r.stdout or "").splitlines() if l.strip()]
        secs = round(time.monotonic() - t0, 2)
        rec.update({"status": "built", "python": str(_env_python(home)), "seconds": secs,
                    "build_seconds": secs, "built_at": rec["at"]})
        rec["imports"] = probe_imports(target, str(_env_python(home)))   # M-54
        rec["seconds"] = round(time.monotonic() - t0, 2)
    except Exception as e:   # Q5: never blocks the scan — the record says why
        rec.update({"status": "failed", "python": None, "reason": str(e)[:400] or type(e).__name__,
                    "seconds": round(time.monotonic() - t0, 2)})
    _write(target, rec, tree)
    return rec


def main(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("target")
    ap.add_argument("--snapshot", default="")
    ap.add_argument("--base-python", default=sys.executable)
    a = ap.parse_args(argv)
    target = Path(a.target).resolve()
    snap = Path(a.snapshot).resolve() if a.snapshot else None
    rec = build(target, snap, a.base_python)
    n = len(rec.get("installed") or [])
    print(f"[target env] {describe(rec)} in {rec.get('seconds')}s — installer={rec.get('installer')} "
          f"packages={n} home={rec.get('home')}")
    if rec.get("target_dist"):
        print(f"[target env] target dist: {rec['target_dist']}")
    imp = rec.get("imports") or {}
    if imp:
        print(f"[target env] imports: {len(imp.get('checked') or [])} needed tried in the env, "
              f"{len(imp.get('missing') or {})} missing"
              + (f" — {cannot_run(rec)}" if imp.get("missing") else "")
              + (f" · {install_hint(rec)}" if install_hint(rec) else "")
              + (f" · probe error: {imp['error']}" if imp.get("error") else ""))
    print(f"[target env] layout={rec.get('layout')}"
          + (f" (src path {rec.get('src_path')} goes on the path for run_module, runner, entry proof, mypy)"
             if rec.get("layout") == "src" else ""))
    if rec.get("status") == "failed":
        print("[target env] DEGRADED — the scan proceeds; running the target's code and mypy "
              "import resolution fall back to the engine interpreter (Q5)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
