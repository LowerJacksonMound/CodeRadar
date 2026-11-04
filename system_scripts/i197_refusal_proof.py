#!/usr/bin/env python3
"""I-197 unit proof — a refused `cr_watch` leaves nothing behind (and says so in its contract).

Each refusal is driven through the REAL `session_tools.cr_watch` with the daemon signaller
replaced by a recorder, then read for: an error sentence, no signal sent, no run dir created
under `.archive/runs/`, and nothing written into the target.

  1  missing target dir                         -> refused, nothing signalled or created
  2  a dir with zero .py files                   -> refused, nothing signalled or created
  3  CodeRadar's own tree                        -> refused, nothing signalled or created
  4  a second target while one is bound and live -> refused, nothing signalled or created
  5  a dash/health port held by a FOREIGN process -> refused, nothing signalled or created
  6  the cr_watch contract no longer claims "never writes inside the target"; it names `.coderadar/`

Not a gate (the gate count stays 17); run: `.venv_new/bin/python system_scripts/i197_refusal_proof.py`.
"""
from __future__ import annotations

import socket
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from coderadar_mcp import session_tools as st  # noqa: E402
from coderadar_mcp import tool_interface as ti  # noqa: E402

RUNS = ROOT / ".archive" / "runs"


def _case(name: str, target: str, patch: Callable[[], Callable[[], None]] | None = None) -> List[str]:
    signalled: List[Any] = []
    saved_signal = st._signal_pids
    st._signal_pids = lambda pids, sig: signalled.append((list(pids), sig))  # type: ignore[assignment]
    undo = patch() if patch else None
    before_runs = {p.name for p in RUNS.iterdir()} if RUNS.is_dir() else set()
    tpath = Path(target)
    if tpath.resolve() == ROOT:
        tpath = Path("/nonexistent")   # CR's own tree is live (archive, venv); signals + run dirs cover it
    before_target = sorted(p.name for p in tpath.rglob("*")) if tpath.is_dir() else None
    try:
        out = st.cr_watch(target)
    finally:
        st._signal_pids = saved_signal  # type: ignore[assignment]
        if undo:
            undo()
    after_runs = {p.name for p in RUNS.iterdir()} if RUNS.is_dir() else set()
    after_target = sorted(p.name for p in tpath.rglob("*")) if tpath.is_dir() else None
    problems = []
    if not out.get("error"):
        problems.append("not refused")
    if signalled:
        problems.append(f"signalled {signalled}")
    if after_runs - before_runs:
        problems.append(f"created run dir(s) {sorted(after_runs - before_runs)}")
    if before_target != after_target:
        problems.append("wrote into the target")
    print(f"  {'BAD' if problems else 'ok '}  {name:<44} {str(out.get('error'))[:90]}")
    return [f"{name}: {p}" for p in problems]


def main() -> int:
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as d:
        empty = Path(d) / "i197_empty"
        empty.mkdir()
        (empty / "README.md").write_text("no python here\n", encoding="utf-8")
        repo = Path(d) / "i197_repo"
        repo.mkdir()
        (repo / "mod.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
        other = Path(d) / "i197_other"
        other.mkdir()

        problems += _case("1 missing target dir", str(Path(d) / "i197_missing"))
        problems += _case("2 zero .py files", str(empty))
        problems += _case("3 CodeRadar's own tree", str(ROOT))

        def _second() -> Callable[[], None]:
            saved = (st._bound_target, st._tree_daemon_pids)
            st._bound_target = lambda: other  # type: ignore[assignment]
            st._tree_daemon_pids = lambda: [999999]  # type: ignore[assignment]
            def undo() -> None:
                st._bound_target, st._tree_daemon_pids = saved  # type: ignore[assignment]
            return undo
        problems += _case("4 second target while bound", str(repo), _second)

        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]

        def _foreign() -> Callable[[], None]:
            saved = (st._ports, st._tree_daemon_pids, st._bound_target)
            st._ports = lambda: {"dashboard": port, "health": port}  # type: ignore[assignment]
            st._tree_daemon_pids = lambda: []  # type: ignore[assignment]
            st._bound_target = lambda: None  # type: ignore[assignment]
            def undo() -> None:
                st._ports, st._tree_daemon_pids, st._bound_target = saved  # type: ignore[assignment]
            return undo
        try:
            problems += _case("5 port held by a foreign process", str(repo), _foreign)
        finally:
            holder.close()

    contract = next(s.contract for s in ti._SPECS if s.name == "cr_watch")
    bad6 = "Never writes inside the target" in contract or ".coderadar/" not in contract
    print(f"  {'BAD' if bad6 else 'ok '}  {'6 cr_watch contract names .coderadar/':<44} {contract[-120:]}")
    if bad6:
        problems.append("6 contract")

    print("\nI-197 refusal proof:", "PASS" if not problems else f"FAIL {problems}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
