"""scan_scope — ONE scan surface for every walker in the circuit stack.

Owner 2026-09-05 (evening), F-CIRC-WALK / F14-b / PYTHON-ONLY:
  * the whitelist (system_scripts/whitelist_<repoid>.json, built by launch.sh
    before any daemon starts) is the single statement of what is NOT live;
  * every walker — circuit graph, syntax check, path hacks, mypy, CRC, I/O
    tracker, contracts, vulture counts, dashboard walk — consumes it here
    instead of carrying its own name-based skip list;
  * only .py files are ever candidates (PYTHON-ONLY doctrine): a non-.py file
    is never a node, never scanned, never hashed.

Dependency-free on purpose: the harness modules are loaded by file location.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
from pathlib import Path
from typing import List, FrozenSet, Iterator, Optional, Tuple

_log = logging.getLogger(__name__)
_SCRIPT_DIR = Path(__file__).resolve().parent

# Module-level scope for walkers that cannot be re-plumbed with parameters
# (path_hack_detector._should_skip, the harness quartet). Set once per scan by
# the daemon via set_scope(); readers fall back to "no whitelist" when unset.
_SCOPE: Tuple[Optional[Path], FrozenSet[str]] = (None, frozenset())

# Engine-owned / never-source segments. NOT a detritus taxonomy — the whitelist
# is that; these are the dirs the engine itself must never descend for safety.
_HARD_SKIP_PARTS = {"__pycache__", ".git", ".cr_pycache",
                    # Fix plan 2026-10-23 C3 (narrows FIX_13): a `.venv` / `venv` without a `pyvenv.cfg`
                    # and a `node_modules` tree are vendored, never the target's source — findings from
                    # them were findings on the wrong files. Skipped by NAME, the way `.git` is; every
                    # other dot-directory stays in scope and `dot_dirs_in_scope` names it.
                    ".venv", "venv", "node_modules"}
# `.coderadar` (owner ruling 2026-09-28) is CodeRadar's OWN output dir at the target root — the
# state mirrors, never source — so it is skipped at THAT spot only (I-195, 2026-09-28): a path whose
# first segment below the target root is `.coderadar`. A same-named dir deeper in a target is the
# target's own and is scanned. That is not FIX_13's forbidden name test (hiding a code dir because it
# is dotted); it is the engine refusing to read its own logs.

# ── THE mirror location — the ONE place (owner ruling 2026-09-28) ─────────────────────────────────
# The per-folder pair lives under ONE dir at the target root, path-mirrored:
#   <target>/.coderadar/<same/sub/path>/.monitor_state.json  (the non-counterfeit half of the dash)
#   <target>/.coderadar/<same/sub/path>/.noai_state.json     (the counterfeit half)
# the root dir's pair at <target>/.coderadar/.monitor_state.json. Kept after stop as the run's log.
# Every writer (circuit_daemon, BUILDER_DAEMON) and reader (gearbox teardown, cr_stop, run_proof.sh,
# health) goes through these four; a relocation is a change here and nowhere else.
MIRROR_DIR = ".coderadar"
MIRROR_NAMES: Tuple[str, ...] = (".noai_state.json", ".monitor_state.json")


def mirror_path(repo: Path, directory: Path, name: str, create: bool = False) -> Path:
    """Where the mirror `name` for `directory` (a dir of `repo`) lives. `create` makes its parents."""
    root = Path(repo).resolve()
    rel = Path(directory).resolve().relative_to(root)
    path = root / MIRROR_DIR / rel / name
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def mirror_files(repo: Path) -> list:
    """Every mirror file currently in `repo` (absolute paths, sorted)."""
    base = Path(repo) / MIRROR_DIR
    if not base.is_dir() or base.is_symlink():
        return []
    return sorted(p for p in base.rglob("*") if p.name in MIRROR_NAMES and p.is_file()
                  and not p.is_symlink())


def is_mirror_path(rel_posix: str) -> bool:
    """True when the target-relative path is one of the kept mirrors — the ONLY target paths
    the byte-identity accounting (cr_stop, run_proof.sh down) exempts."""
    parts = Path(str(rel_posix).strip().removeprefix("./")).parts
    # owner 2026-10-07 ~05:50: a viewed folder's JSONL dash mirrors (view_mirrors.NAMES) are ours too
    if parts and parts[-1] in ("coderadar_dash.jsonl", "coderadar_noai.jsonl"):
        return True
    return len(parts) >= 2 and parts[0] == MIRROR_DIR and parts[-1] in MIRROR_NAMES

# I-153 (a) — owner 2026-09-21, the upgraded launch-hygiene fix. The bytecode class was
# only ever stated IMPLICITLY, by _HARD_SKIP_PARTS above: a reader of a target's whitelist
# artifact had to infer it. It is now an EXPLICIT pair of whitelist rows that every reader
# of load_whitelist() receives, artifact or no artifact. Bytecode holds no intent — it is
# the compiler's output of the same source the census reads, and stale the moment that
# source is edited — so it is stated, never scanned, and (gearbox.py, unchanged) never
# deleted inside a target.
BYTECODE_WHITELIST_ENTRIES: Tuple[dict, ...] = (
    {"path": "__pycache__/", "reason": "bytecode:engine-hard-skip"},
    {"path": "*.pyc", "reason": "bytecode:engine-hard-skip"},
)
BYTECODE_WHITELIST_PATHS: FrozenSet[str] = frozenset(e["path"] for e in BYTECODE_WHITELIST_ENTRIES)

# B8 (MCP-working packet 2026-09-28): a dir that IS a Python env or a site-packages dir is never
# source — recognised by SHAPE (what it holds / where it sits), never by its name, so FIX_13 (no
# dot-dir excluded by name) stands: `.venv` with a `pyvenv.cfg` is skipped, `.venv` without one is
# scanned like any dir. Results cached per resolved dir for the life of the process.
_ENV_MARKER_FILES = ("pyvenv.cfg",)
_ENV_MARKER_DIRS = ("conda-meta",)
_ENV_DIR_CACHE: dict = {}


def env_dir(d: Path) -> bool:
    """True when directory *d* IS a Python env (holds `pyvenv.cfg` or `conda-meta/`) or IS a
    site-packages dir (`site-packages` / `dist-packages` sitting in `lib/python*/` or `Lib/`)."""
    d = Path(d)
    key = str(d)
    hit = _ENV_DIR_CACHE.get(key)
    if hit is None:
        par = d.parent.name
        hit = (any((d / m).is_file() for m in _ENV_MARKER_FILES)
               or any((d / m).is_dir() for m in _ENV_MARKER_DIRS)
               or (d.name in ("site-packages", "dist-packages")
                   and (fnmatch.fnmatch(par, "python*") or par == "Lib")))
        _ENV_DIR_CACHE[key] = hit
    return hit


def under_env(path: Path, root: Optional[Path]) -> bool:
    """True when some directory from *root* (exclusive) down to *path*'s parent — or *path* itself
    when it is a directory — IS an env / site-packages dir (env_dir). *path* absolute or relative
    to *root*; with no root there is nothing to test against and the answer is False."""
    if root is None:
        return False
    root = Path(root)
    p = Path(path)
    try:
        rel = p.relative_to(root) if p.is_absolute() else p
    except ValueError:
        try:
            rel = p.resolve().relative_to(root.resolve())
            root = root.resolve()
        except (ValueError, OSError):
            return False
    cur = root
    parts = rel.parts
    for i, part in enumerate(parts):
        cur = cur / part
        if i == len(parts) - 1 and not cur.is_dir():
            break
        if env_dir(cur):
            return True
    return False


# FIX_53: the syntax-fixture globs, read once from syntax_fixture_patterns.json (None = not read yet).
_SYNTAX_FIXTURE_PATTERNS: Optional[Tuple[str, ...]] = None


def repo_id(target: Path) -> str:
    """Same scheme as circuit_daemon.get_repo_id / launch.sh: sha256(resolved)[:12]."""
    return hashlib.sha256(str(Path(target).resolve()).encode()).hexdigest()[:12]


def whitelist_path(target: Path) -> Path:
    return _SCRIPT_DIR / f"whitelist_{repo_id(target)}.json"


def load_whitelist(target: Path) -> FrozenSet[str]:
    """Repo-relative whitelisted paths (files; dirs end with '/'). Missing or
    corrupt artifact => the bytecode rows alone (scan surface unchanged, and logged).

    I-153 (a): BYTECODE_WHITELIST_PATHS is unioned in every time, so the bytecode class is
    stated to every reader instead of being inferred from _HARD_SKIP_PARTS. It cannot move a
    live count: neither row can match a `.py` path."""
    wl_file = whitelist_path(target)
    if not wl_file.exists():
        return BYTECODE_WHITELIST_PATHS
    try:
        data = json.loads(wl_file.read_text())
        return BYTECODE_WHITELIST_PATHS | frozenset(
            str(e["path"]) for e in data.get("entries", [])
            if isinstance(e, dict) and e.get("path")
        )
    except Exception as e:  # pragma: no cover
        _log.warning("scan_scope: failed to read %s: %s", wl_file.name, e)
        return BYTECODE_WHITELIST_PATHS


def is_bytecode(rel_posix: str) -> bool:
    """I-153 (a): True when *rel_posix* is the compiler's output rather than source — under a
    `__pycache__` segment, or a `.pyc` / `.pyo` file. The EXPLICIT test, named where a reader
    looks for it; hard_skipped() keeps the engine's own walk-safety statement separate."""
    rel = str(rel_posix or "").replace("\\", "/")
    return bool(rel) and ("__pycache__" in rel.split("/") or rel.endswith((".pyc", ".pyo")))


def is_whitelisted(rel_posix: str, whitelist) -> bool:
    if not whitelist or not rel_posix:
        return False
    if rel_posix in whitelist:
        return True
    for w in whitelist:
        # I-153 (a): a row carrying a glob metacharacter (`*.pyc`) is matched as a pattern;
        # every other row keeps the exact / directory-prefix reading it has always had.
        if ("*" in w or "?" in w or "[" in w) and fnmatch.fnmatch(rel_posix, w):
            return True
        if rel_posix.startswith(w.rstrip("/") + "/"):
            return True
    return False


def set_scope(target: Path, whitelist: Optional[FrozenSet[str]] = None) -> FrozenSet[str]:
    """Publish the scan scope for parameterless walkers. Returns the whitelist."""
    global _SCOPE
    wl = whitelist if whitelist is not None else load_whitelist(target)
    _SCOPE = (Path(target).resolve(), wl)
    return wl


def scope() -> Tuple[Optional[Path], FrozenSet[str]]:
    return _SCOPE


def excluded(path: Path) -> bool:
    """True when *path* (absolute or relative to the published scope root) is
    outside the scan surface: whitelisted, under an engine hard-skip segment,
    or — for files — not a .py file (PYTHON-ONLY), or under a dir that IS a Python env /
    site-packages dir by shape (B8, env_dir). A dot-dir is NOT excluded by its name
    (FIX_13, 2026-09-10) — only the whitelist, a hard-skip segment, or its env shape."""
    root, wl = _SCOPE
    p = Path(path)
    parts = p.parts
    if hard_skipped(p):
        return True
    if p.suffix and p.suffix != ".py":
        return True
    if root is not None:
        try:
            rel = p.resolve().relative_to(root).as_posix() if p.is_absolute() else p.as_posix()
        except ValueError:
            return False
        if under_env(p, root):   # B8: an env / site-packages dir, by shape
            return True
        return is_whitelisted(rel, wl)
    return False


def syntax_fixture(rel_posix: str) -> bool:
    """FIX_53 (owner Q5 / I-47, 2026-09-17): True when *rel_posix* (a repo-relative POSIX path) names a
    .py file a target ships IN ORDER to be unparsable — a lexer / parser test fixture, by PATTERN
    (system_scripts/syntax_fixture_patterns.json).

    This is NOT an exclusion. The file stays in the scan surface: still a node, still walked, still
    hashed. Only its SYNTAX BREAKAGE is expected, so the circuit reports it under SYNTAX_FIXTURE_FILES
    instead of SYNTAX_BROKEN_FILES and the WIRING gate (FIX_36) does not stop the launch on it. A file
    that does not match a pattern and does not parse still stops the launch and names the node.
    Kept apart from excluded() on purpose — whitelisting a fixture OUT of the scan would hide a real
    file, and rule 15's whitelist is the launcher's per-target artifact, never an engine-side list."""
    if not rel_posix:
        return False
    rel = str(rel_posix).replace("\\", "/").lstrip("./")
    for pat in _syntax_fixture_patterns():
        if fnmatch.fnmatch(rel, pat):
            return True
        # `a/**` must also match `a/b` (fnmatch's `**` is not recursive on its own)
        if pat.endswith("/**") and (rel == pat[:-3] or rel.startswith(pat[:-2])):
            return True
    return False


def _syntax_fixture_patterns() -> Tuple[str, ...]:
    """The globs of syntax_fixture_patterns.json, read once. A missing or corrupt file means NO
    patterns (every syntax break is genuine, i.e. today's behaviour) and is logged — never silence."""
    global _SYNTAX_FIXTURE_PATTERNS
    if _SYNTAX_FIXTURE_PATTERNS is None:
        pats: list = []
        f = _SCRIPT_DIR / "syntax_fixture_patterns.json"
        try:
            doc = json.loads(f.read_text())
            pats = [str(e["glob"]) for e in doc.get("patterns", [])
                    if isinstance(e, dict) and e.get("glob")]
        except FileNotFoundError:
            _log.warning("scan_scope: %s missing — no syntax-fixture patterns (every break is genuine)", f.name)
        except Exception as e:  # pragma: no cover
            _log.warning("scan_scope: failed to read %s: %s", f.name, e)
        _SYNTAX_FIXTURE_PATTERNS = tuple(pats)
    return _SYNTAX_FIXTURE_PATTERNS


def hard_skipped(path: Path) -> bool:
    """True when any component of *path* is an engine hard-skip segment. This is the ONLY
    name-based test a walker may keep (FIX_13, 2026-09-10): a dot-dir is IN scope unless the
    whitelist names it — `.git`, `__pycache__`, `.cr_pycache` are the engine's own, never source."""
    p = Path(path)
    if any(seg in _HARD_SKIP_PARTS for seg in p.parts):
        return True
    return _is_root_mirror_dir(p)


def _is_root_mirror_dir(p: Path) -> bool:
    """I-195: True when *p* is the target-root mirror dir or under it. A relative path is read as
    relative to the target root (every walker passes one that way); an absolute path is placed
    against the published scope root, and without one it is never the mirror dir — the mirror dir
    holds only the two .json names, so no .py file a scope-less reader asks about can be in it."""
    if p.is_absolute():
        root = _SCOPE[0]
        if root is None:
            return False
        try:
            p = p.relative_to(root)
        except ValueError:
            try:
                p = p.resolve().relative_to(root)
            except (ValueError, OSError):
                return False
    return bool(p.parts) and p.parts[0] == MIRROR_DIR


def contained(path: Path, root: Path) -> bool:
    """FIX_15 (containment, owner 2026-09-08): True only when *path* lies inside *root* and no
    component from *root* down is a symlink, and the resolved path is under the resolved root.
    A location outside the target does not matter — a walker never follows it; no size or depth
    policy lives here. Works for absolute paths under *root* and for paths relative to it."""
    root = Path(root)
    p = Path(path)
    try:
        rel = p.relative_to(root) if p.is_absolute() else p
    except ValueError:
        return False
    cur = root
    for part in rel.parts:
        cur = cur / part
        if cur.is_symlink():
            return False
    try:
        cur.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def iter_contained(root: Path, pattern: str = "*") -> Iterator[Path]:
    """rglob(*pattern*) under *root* filtered to contained entries (FIX_15): nothing reached through
    a symlink, nothing resolving outside *root*, never an engine hard-skip segment. For non-.py
    walks (mirror fan-out, docs, backup dirs); .py walks use iter_live_py."""
    root = Path(root)
    for p in sorted(root.rglob(pattern)):
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        if hard_skipped(rel):
            continue
        if not contained(p, root):
            continue
        if under_env(rel, root):   # B8: an env / site-packages dir, by shape
            continue
        yield p


def iter_live_py(repo: Path, whitelist: Optional[FrozenSet[str]] = None) -> Iterator[Path]:
    """Every .py file under *repo* that the whitelist does not exclude, in sorted order:
    contained (FIX_15 — no symlink on the way, nothing outside the root), never an engine
    hard-skip segment, every other dot-dir IN scope (FIX_13). The ONE .py walk every walker
    consumes (FIX_13/14/15, 2026-09-10) — rule 15, ONE whitelist, ONE discovery."""
    repo = Path(repo)
    wl = whitelist if whitelist is not None else (
        _SCOPE[1] if _SCOPE[0] is not None and _SCOPE[0] == repo.resolve() else load_whitelist(repo))
    for py in iter_contained(repo, "*.py"):
        rel = py.relative_to(repo)
        if is_whitelisted(rel.as_posix(), wl):
            continue
        if not py.is_file():
            continue
        yield py


def import_roots(repo: Path, py_files) -> list:
    """M-68 (2026-10-07): the dirs an absolute import resolves from — *repo* first, then each
    non-package dir (no __init__.py) under it that directly holds a package. A wrapper folder whose
    children are packages is where `python -m` is run from; `from charlie_work.x import y` resolves
    there. *py_files* is the live .py walk (iter_live_py), so this sees exactly what discovery sees.
    The scanner resolves imports from these; the runner puts them on the run's sys.path."""
    repo = Path(repo)
    roots = []
    for p in py_files:
        p = Path(p)
        if p.name != '__init__.py':
            continue
        parent = p.parent.parent
        if parent != repo and not (parent / '__init__.py').exists() and parent not in roots:
            roots.append(parent)
    return [repo] + sorted(roots)


def dot_dirs_in_scope(repo: Path, whitelist: Optional[FrozenSet[str]] = None) -> List[str]:
    """Fix plan 2026-10-23 C3: the repo-relative dot-directories (first dotted segment on the path)
    that hold at least one .py file the ONE walk (`iter_live_py`) yields — i.e. dot-dirs that ARE
    scanned. `.git`, `__pycache__`, `.cr_pycache`, `.venv`, `venv`, `node_modules` and the root
    `.coderadar` never appear (hard-skipped); an env recognised by shape never appears (B8).
    Written to the launch log and published on `cr_status.dot_dirs_scanned`, so a vendored tree is
    seen BEFORE its findings are read."""
    repo = Path(repo)
    seen = set()
    for py in iter_live_py(repo, whitelist):
        parts = py.relative_to(repo).parts[:-1]
        for i, part in enumerate(parts):
            if part.startswith("."):
                seen.add("/".join(parts[:i + 1]))
                break
    return sorted(seen)


def live_py_count(repo: Path, whitelist: Optional[FrozenSet[str]] = None) -> int:
    return sum(1 for _ in iter_live_py(repo, whitelist))
