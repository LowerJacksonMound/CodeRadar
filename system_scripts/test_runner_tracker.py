#!/usr/bin/env python3
"""test_runner_tracker.py — pytest + unittest as PERMANENT data type trackers (Item 10, 2026-09-15).

Beside the path-hack detector: PRESENCE (imports, fixtures / marks, conftest, TestCase, unittest.main,
runner config files) is read from the scanner's node list — no walker of its own; EXECUTION is read
from the three sources the app already has — the wrapper's running.json stamps (`runner`, `test_path`),
one `ps` snapshot per frame (shared with scan_running_processes), and the kernel tracer's exec events —
deduplicated by PID, wrapper > kernel > ps. A runner's proof is its OWN record (runner_info.json,
written by entry_point_wrapper.py); it never touches entry_point_info.json (owner ruling 2026-09-15:
a runner may overwrite NOTHING). Green reached through a runner is published as `via_runner` — a
warning, never a pass.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

RUNNERS = ("pytest", "unittest")
_RUNNER_CMD_RE = re.compile(r"(^|\s)(-m\s+)?(pytest|py\.test|unittest)(\s|$)")
TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test|conftest)\.py$")
_CONFIG_FILES = (
    ("pytest.ini", "pytest.ini"),
    ("pyproject.toml", "pyproject[tool.pytest]"),
    ("setup.cfg", "setup.cfg[tool:pytest]"),
    ("tox.ini", "tox.ini[pytest]"),
)
_CONFIG_MARK = {
    "pytest.ini": None,
    "pyproject.toml": "[tool.pytest",
    "setup.cfg": "[tool:pytest",
    "tox.ini": "[pytest",
}
_NOT_RUN = "not run — nothing measured"


# ── presence ───────────────────────────────────────────────────────────────────

def _evidence_in_tree(tree: ast.AST, rel: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """pytest / unittest evidence in ONE parsed module: {file, line, kind}."""
    py: List[Dict[str, Any]] = []
    ut: List[Dict[str, Any]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "pytest" or a.name.startswith("pytest."):
                    py.append({"file": rel, "line": n.lineno, "kind": "import"})
                elif a.name == "unittest" or a.name.startswith("unittest."):
                    ut.append({"file": rel, "line": n.lineno, "kind": "import"})
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            if mod == "pytest" or mod.startswith("pytest."):
                py.append({"file": rel, "line": n.lineno, "kind": "import"})
            elif mod == "unittest" or mod.startswith("unittest."):
                ut.append({"file": rel, "line": n.lineno, "kind": "import"})
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in n.decorator_list:
                text = ast.unparse(d)
                if text.startswith("pytest.fixture") or text.startswith("fixture"):
                    py.append({"file": rel, "line": d.lineno, "kind": "fixture"})
                elif text.startswith("pytest.mark"):
                    py.append({"file": rel, "line": d.lineno, "kind": "mark"})
        elif isinstance(n, ast.ClassDef):
            for b in n.bases:
                text = ast.unparse(b)
                if text in ("unittest.TestCase", "TestCase") or text.endswith(".TestCase"):
                    ut.append({"file": rel, "line": n.lineno, "kind": "TestCase"})
        elif isinstance(n, ast.Call):
            if ast.unparse(n.func) == "unittest.main":
                ut.append({"file": rel, "line": n.lineno, "kind": "main_call"})
    if TEST_FILE_RE.search(rel) and rel.rsplit("/", 1)[-1] == "conftest.py":
        py.append({"file": rel, "line": 1, "kind": "conftest"})
    return py, ut


def scan_test_runner_presence(nodes: Iterable[Any], repo: Optional[Path] = None) -> Dict[str, Any]:
    """Presence of pytest / unittest in the scanner's node list (ScriptNode-like: .path / .relative_path,
    or dicts with 'path' / 'relative_path'). Returns the `presence` block of `test_runners`."""
    py_files: List[str] = []
    py_ev: List[Dict[str, Any]] = []
    ut_files: List[str] = []
    ut_ev: List[Dict[str, Any]] = []
    for n in nodes:
        path = getattr(n, "path", None) if not isinstance(n, dict) else n.get("path")
        rel = getattr(n, "relative_path", None) if not isinstance(n, dict) else n.get("relative_path")
        if not path:
            continue
        p = Path(path)
        if p.suffix != ".py":
            continue
        rel = str(rel or p.name).replace(os.sep, "/")
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"), filename=str(p))
        except (SyntaxError, ValueError, OSError):
            continue
        py, ut = _evidence_in_tree(tree, rel)
        if py:
            py_files.append(rel); py_ev.extend(py)
        if ut:
            ut_files.append(rel); ut_ev.extend(ut)
    config: List[Dict[str, str]] = []
    if repo is not None:
        for fname, kind in _CONFIG_FILES:
            f = Path(repo) / fname
            if not f.is_file():
                continue
            mark = _CONFIG_MARK[fname]
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if mark is None or mark in text:
                config.append({"file": fname, "kind": kind})
    return {
        "pytest": {"files": sorted(py_files), "evidence": py_ev},
        "unittest": {"files": sorted(ut_files), "evidence": ut_ev},
        "config": config,
        "scanned_at": datetime.now().isoformat(),
    }


# ── execution ──────────────────────────────────────────────────────────────────

def list_python_processes(own_pid: Optional[int] = None) -> List[Tuple[int, str]]:
    """ONE `ps` per frame: every python process as (pid, command). Extracted from
    circuit_daemon.scan_running_processes (Item 10) so the runner scan and the running scan share it."""
    own = own_pid if own_pid is not None else os.getpid()
    out: List[Tuple[int, str]] = []
    try:
        result = subprocess.run(["ps", "-axww", "-o", "pid,command"], capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return out
    if result.returncode != 0:
        return out
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == own:
            continue
        cmd = parts[1]
        if "python" in cmd.lower():
            out.append((pid, cmd))
    return out


def proc_cwd(pid: int) -> Optional[str]:
    """The process's current working directory, or None when it cannot be read (gone, or not ours).

    I-53 (2026-09-17): the same `lsof -a -d cwd -p <pid> -Fn` check `run_proof.sh` / `launch.sh` use to
    select THIS tree's daemons — the tree is not in a daemon's argv, and a runner's target is not in its
    argv either when the path it was given is relative.
    """
    try:
        r = subprocess.run(["lsof", "-a", "-d", "cwd", "-p", str(pid), "-Fn"],
                           capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return None
    for line in r.stdout.splitlines():
        if line.startswith("n"):
            return line[1:].strip()
    return None


def _cwd_in_target(pid: int, repo: Path, cwd_of: Any) -> bool:
    """I-53: a ps-proven runner is THIS target's only when the PROCESS ITSELF sits under the target."""
    cwd = cwd_of(pid)
    if not cwd:
        return False
    try:
        Path(cwd).resolve().relative_to(Path(repo).resolve())
    except (ValueError, OSError, RuntimeError):
        return False
    return True


def _under(token: str, repo: Path) -> Optional[str]:
    """A command token that resolves to a path under the target → its target-relative path."""
    try:
        p = Path(token)
        if not p.is_absolute():
            p = Path(repo) / token
        p = p.resolve()
        rel = p.relative_to(Path(repo).resolve())
    except (ValueError, OSError, RuntimeError):
        return None
    if not p.exists():
        return None
    return rel.as_posix() or "."


def match_runner_cmd(cmd: str, repo: Path) -> Optional[Tuple[str, str]]:
    """(runner, test_path) when the command line runs pytest / py.test / unittest on something under
    the target; None otherwise. test_path = the first token resolving under the target ('' when the
    runner was given none — its cwd decides)."""
    m = _RUNNER_CMD_RE.search(cmd)
    if not m:
        return None
    runner = "pytest" if m.group(3) in ("pytest", "py.test") else "unittest"
    tokens = cmd.split()
    test_path = ""
    seen_runner = False
    for tok in tokens:
        if not seen_runner:
            if tok in ("pytest", "py.test", "unittest") or tok.endswith("/pytest") or tok.endswith("/py.test"):
                seen_runner = True
            continue
        if tok.startswith("-"):
            continue
        rel = _under(tok, repo)
        if rel is None and runner == "unittest" and "." in tok and "/" not in tok:
            rel = _under(tok.replace(".", "/") + ".py", repo)
        if rel is not None:
            test_path = rel
            break
    return runner, test_path


def collect_runner_executions(running_json: Optional[Dict[str, Any]], ps_lines: Iterable[Tuple[int, str]],
                              kernel_pytest: Optional[Dict[str, Any]], repo: Path,
                              cwd_of: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Runner executions from the three sources, one entry per PID, proof wrapper > kernel > ps.

    `cwd_of` reads a pid's cwd (I-53); it is a parameter for the same reason `ps_lines` and
    `kernel_pytest` are — every source this function joins is handed to it, never fetched inside.
    """
    cwd_of = cwd_of if cwd_of is not None else proc_cwd
    by_pid: Dict[int, Dict[str, Any]] = {}
    for pid_str, info in (running_json or {}).items():
        if not isinstance(info, dict) or not info.get("runner"):
            continue
        try:
            pid = int(info.get("pid", pid_str))
        except (TypeError, ValueError):
            continue
        by_pid[pid] = {"pid": pid, "runner": info["runner"], "command": f"entry_point_wrapper -m {info['runner']}",
                       "test_path": info.get("test_path") or "", "proof": "wrapper",
                       "started_at": info.get("start_time") or ""}
    if kernel_pytest and kernel_pytest.get("pid"):
        try:
            pid = int(kernel_pytest["pid"])
        except (TypeError, ValueError):
            pid = 0
        if pid and pid not in by_pid:
            by_pid[pid] = {"pid": pid, "runner": kernel_pytest.get("runner") or "pytest",
                           "command": str(kernel_pytest.get("command") or "")[:200],
                           "test_path": kernel_pytest.get("test_path") or "", "proof": "kernel",
                           "started_at": kernel_pytest.get("started_at") or ""}
    for pid, cmd in ps_lines:
        if pid in by_pid:
            continue
        hit = match_runner_cmd(cmd, repo)
        if hit is None:
            continue
        runner, test_path = hit
        if not test_path:
            # Found on run 108 launch C: another tree's `pytest` on the same machine matched by name alone. A
            # ps-proven runner is THIS target's only when its command line names something under the target;
            # a bare runner elsewhere is not our event (the wrapper's stamp and the kernel's repo check decide theirs).
            continue
        if not _cwd_in_target(pid, repo, cwd_of):
            # I-53 (run 129 `one_little_victory`, obs_F_I53.txt; fixed FIX_47 lane, 2026-09-17): the command
            # line is not enough. `_under` resolves a RELATIVE token against the target, so another tree's
            # `pytest tests/test_ansi.py` matched whenever THIS target happened to hold `tests/test_ansi.py` —
            # two foreign pids sat in this target's band for the whole of run 129. The process's own cwd is
            # the fact that separates them, as it does for the daemons (`tree_daemon_pids`).
            continue
        by_pid[pid] = {"pid": pid, "runner": runner, "command": cmd[:200], "test_path": test_path,
                       "proof": "ps", "started_at": ""}
    return [by_pid[p] for p in sorted(by_pid)]


# ── the runner's own proof record ──────────────────────────────────────────────

def runner_coverage(proof: Optional[Dict[str, Any]], repo: Path) -> Tuple[set, int, int]:
    """Target files the runner's record proves imported — SHA256 still equal to the recorded hash
    (a stale proof is not a proof). Returns (relative paths, verified, stale)."""
    cov: set = set()
    verified = stale = 0
    root = Path(repo).resolve()
    for abspath, recorded in ((proof or {}).get("file_hashes") or {}).items():
        p = Path(abspath)
        try:
            current = f"sha256:{hashlib.sha256(p.read_bytes()).hexdigest()}"
        except OSError:
            stale += 1
            continue
        if current != recorded:
            stale += 1
            continue
        try:
            cov.add(p.resolve().relative_to(root).as_posix())
        except ValueError:
            continue
        verified += 1
    return cov, verified, stale


def _node_name(rel: str) -> str:
    return rel[:-3] if rel.endswith(".py") else rel


def test_files_in(proof: Optional[Dict[str, Any]], repo: Path) -> List[str]:
    """The test files the runner's record shows imported (target-relative), sorted."""
    root = Path(repo).resolve()
    out = []
    for abspath in (proof or {}).get("imported_files") or []:
        try:
            rel = Path(abspath).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            continue
        if TEST_FILE_RE.search(rel):
            out.append(rel)
    return sorted(set(out))


def runner_dataflows(proof: Optional[Dict[str, Any]], import_map: Dict[str, List[str]], repo: Path) -> List[Dict[str, Any]]:
    """{src: test, dst: source, channel: import, proof: runner} for every test file the runner imported
    and every target module it imports that the runner ALSO imported (the graph shows where pytest runs)."""
    if not proof:
        return []
    root = Path(repo).resolve()
    imported = set()
    for abspath in proof.get("imported_files") or []:
        try:
            imported.add(_node_name(Path(abspath).resolve().relative_to(root).as_posix()))
        except (ValueError, OSError):
            continue
    flows: List[Dict[str, Any]] = []
    for rel in test_files_in(proof, repo):
        src = _node_name(rel)
        for dst in import_map.get(src, []) or []:
            if dst in imported and dst != src:
                flows.append({"src": src, "dst": dst, "channel": "import", "proof": "runner"})
    return flows


def read_json(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def not_run_block() -> Dict[str, Any]:
    """The tracker's block before its first presence scan — published as not measured, never as empty."""
    return {"status": _NOT_RUN, "presence": None,
            "execution": {"entries": [], "sources": {"wrapper": _NOT_RUN, "ps": _NOT_RUN, "kernel": _NOT_RUN}}}


if __name__ == "__main__":
    import sys
    repo = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    from types import SimpleNamespace
    nodes = [SimpleNamespace(path=p, relative_path=p.relative_to(repo).as_posix()) for p in repo.rglob("*.py")]
    print(json.dumps(scan_test_runner_presence(nodes, repo), indent=1))
    print(json.dumps(collect_runner_executions({}, list_python_processes(), None, repo), indent=1))
