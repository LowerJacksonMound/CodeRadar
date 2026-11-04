"""T4's file — the session: launch, bind, tear down, hand back.

Owns: cr_watch · cr_attach · cr_stop · cr_hand_back
Also T4's, OUTSIDE this package: the gearbox launch path, `finished` in the mirror writer,
and `zero_signal` / `circuit_clear` gaining `severed_links` (I-83).

`monitor.summary` publishes seven keys today plus `severed_links`; `finished` is the eighth
T4 adds, with `finished_reason` beside it. `monitor.zero_signal` is the five-name list
['broken_imports', 'path_hacks', 'mypy_errors', 'sync_needs_review', 'dead_code_actionable'] —
I-83 makes it six.

THE ONE RULE OF THIS FILE (Q3): it never writes inside the target. Everything it writes is
engine-side — `.archive/runs/<name>/` and this tree's `system_scripts/`. `cr_watch` runs the
SAME launch as `run_proof.sh up` (`./launch.sh TARGET --tracer lsof --trackers io,mypy`) and
reads the SAME gate definition (`gearbox.gate_states`); `cr_stop` is `run_proof.sh down`'s
teardown — residue zero, then md5 -r over the COPY-FIRST snapshot and the target.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from system_scripts import gearbox

from . import read_tools
from .tool_interface import ISSUES_SCOPE, TOOLS, register_handler

OWNED: tuple[str, ...] = (
    "cr_watch",
    "cr_attach",
    "cr_stop",
    "cr_hand_back",
)

assert all(n in TOOLS for n in OWNED), "T4 claims a tool that is not in the surface"

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
SCRIPT_DIR = PROJECT_ROOT / "system_scripts"
LAUNCH_SH = PROJECT_ROOT / "launch.sh"
BUILDER_STATE = SCRIPT_DIR / "BUILDER_STATE.json"
NOAI_STATE = SCRIPT_DIR / "NOAI_VALIDATION_STATE.json"
CIRCUIT_STATE = SCRIPT_DIR / "circuit_state.json"
MONITOR_MIRROR = SCRIPT_DIR / ".monitor_state.json"
NOAI_MIRROR = SCRIPT_DIR / ".noai_state.json"
GEARBOX_EVENTS = SCRIPT_DIR / "gearbox_events.json"
POOL_FILE = PROJECT_ROOT / ".archive" / "naming" / "rush_track_pool.txt"
SNAPSHOT_ROOT = Path.home() / "CodeRadar_snapshots"
SNAPSHOT_FILES = Path(__file__).resolve().parent.parent / "system_scripts" / "snapshot_files.sh"

#: `run_proof.sh`'s own two budget constants (I-48). Every other term of the gate budget is
#: READ FROM `gearbox` below, so the launcher and this tool cannot drift.
HEALTH_MAX_S = 900.0
BUDGET_SLACK_S = 120.0
#: The four daemons + the coordinator + the setup-page server, selected by cwd — the `pgrep -f`
#: pre-filter the three selectors share (`launch.sh` / `run_proof.sh tree_daemon_pids`, which since D1
#: carry the same argv test in shell); `_runs_daemon` below is the real test.
#: D2 / Q-H1-10 (2026-10-01): + launch_setup.py — a setup page left on the dash port is this tree's too.
DAEMON_PATTERN = "gearbox.py|circuit_daemon.py|NOAI_VALIDATOR_DAEMON|BUILDER_DAEMON|proof_dashboard.py|launch_setup.py"
#: What ends the gate wait: the gearbox's own verdict lines (I-48).
UP_LINE = "ALL GATES PASSED"
#: Fix plan 2026-10-23 D2: once the gearbox has printed UP_LINE the stack is up; both phases
#: reading MONITORING is a state-file write that follows within seconds. This bounds that wait.
MONITORING_WAIT_S = 120.0
STOP_LINES = re.compile(
    r"launch\.sh: ABORT|GATE \[.*\] FAIL|HEALTH CHECK FAILED|exhaust|startup failed|"
    r"gate failed|RuntimeError")
GATE_LINE = re.compile(r"GATE \[([^\]]+)\] (PASS|FAIL-FAST|FAIL|TIMEOUT|ABORTED)\b[^\n]*")
SECONDS_IN_LINE = re.compile(r"([0-9]+(?:\.[0-9]+)?)s")
STARTED_LINE = re.compile(r"started (\S+) PID (\d+)")
#: `terminate_children`'s summary line as the LOG carries it — every gearbox line is prefixed
#: `[gearbox HH:MM:SS] `, so the teardown line is never at the start of its own line (run 139).
STOPPED_LINE = re.compile(r"(\S+): stopped \(([^)]*)\), exit code (-?\d+)")
RESIDUE_OK = "RESIDUE CHECK: zero CodeRadar files remain in target beyond the kept state mirrors"


# ── plumbing ─────────────────────────────────────────────────────────────────

def _load(path: Path) -> dict[str, Any]:
    """A state file as a dict; an absent or half-written file reads as empty, never as a verdict."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except Exception:
        return {}


def _ports() -> dict[str, Any]:
    return _load(SCRIPT_DIR / "copy_ports.json")


def _dashboard_url() -> str:
    return f"http://127.0.0.1:{int(_ports().get('dashboard', 8080))}"


def _health_url() -> str:
    return f"http://127.0.0.1:{int(_ports().get('health', 8051))}/health"


def _run_dir(name: str) -> Path:
    return PROJECT_ROOT / ".archive" / "runs" / name


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


#: C3 (b) / Q-H4-9: the daemons as the gearbox and launch.sh start them — an interpreter running one of
#: these FILES (`python system_scripts/<name>.py …`) or MODULES (`python -m <module>`). `pgrep -f` only
#: pre-filters; the argv is then read and the first positional must be one of these.
#: D2 / Q-H1-10: + the setup-page SERVER (`launch.sh:134` runs it by absolute path, `--port …`), so
#: cr_stop tears a page left on the dash port down (its SIGTERM handler exits 4 and frees the port) and
#: cr_watch / cr_attach name it instead of guessing. The same file's two helper forms are NOT daemons:
#: `--emit-shell` (`launch.sh:145`) and `--submit-purpose` (`:662`) live for milliseconds, hold no port,
#: and a SIGTERM to the second one loses the purpose while the launch goes on to start the gearbox —
#: a `stopped: true` over a run that is coming up. Only the serving form is selected.
SETUP_SERVER = str(SCRIPT_DIR / "launch_setup.py")
DAEMON_FILES = frozenset(str(SCRIPT_DIR / n) for n in ("gearbox.py", "circuit_daemon.py", "proof_dashboard.py")) | {SETUP_SERVER}
DAEMON_MODULES = frozenset(("no_aivalidator.NOAI_VALIDATOR_DAEMON", "no_aivalidator.BUILDER_DAEMON"))
_PY_FLAGS_WITH_VALUE = frozenset(("-X", "-W", "-c", "-m"))
_SETUP_HELPER_FLAGS = ("--emit-shell", "--submit-purpose")
#: The one reason a seat is refused while the page is open and nothing else is live (`_live_target`).
SETUP_PAGE_OPEN = ("the launch setup page is open on the dash port — no target chosen yet "
                   "(launch.sh is waiting for Start)")


def _runs_daemon(argv: list[str]) -> bool:
    """True when argv is a Python interpreter whose script is one of this tree's daemon FILES or
    whose `-m` module is one of its daemon MODULES. A shell, an editor or a `sleep` whose command
    line merely CONTAINS a daemon's name (lane A3's zsh, Q-H4-9) is not a daemon.
    D2: argv[0] is matched case-blind — a macOS framework build re-execs the venv's `python` as
    `…/Python.app/Contents/MacOS/Python`, which is what `ps` reports for EVERY daemon the gearbox
    spawns with `sys.executable` here (measured 2026-10-01; C3's stand-in was `exec -a python`)."""
    if not argv or not re.fullmatch(r"python[0-9.]*(?:\.exe)?", Path(argv[0]).name, re.IGNORECASE):
        return False
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "-m":
            return i + 1 < len(argv) and argv[i + 1] in DAEMON_MODULES
        if arg == "-c" or arg == "-":
            return False
        if arg.startswith("-"):
            i += 2 if arg in _PY_FLAGS_WITH_VALUE else 1
            continue
        # the script: relative paths are the gearbox's (`cwd=PROJECT_ROOT`), launch.sh's are absolute
        script = str((PROJECT_ROOT / arg).resolve())
        if script == SETUP_SERVER and any(a.split("=", 1)[0] in _SETUP_HELPER_FLAGS for a in argv[i + 1:]):
            return False   # the page's helper forms, not the server
        return script in DAEMON_FILES
    return False


def _argv(pid: str) -> list[str]:
    try:
        line = subprocess.run(["ps", "-ww", "-o", "command=", "-p", pid],
                              capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return []
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def _tree_daemon_pids() -> list[int]:
    """This tree's daemons and nothing else — `pgrep -f` then the argv (`_runs_daemon`), then
    `lsof -a -d cwd`, the copy-setup selection `run_proof.sh` uses (the interpreter is shared between
    trees; the cwd is not). C3 (b): the argv test is new — `pgrep -f` matched a SHELL whose command
    line named a daemon file with cwd = this tree, and a new seat was told a launch was in progress."""
    return _daemon_pids(DAEMON_PATTERN)


def _setup_page_pids() -> list[int]:
    """D2 / Q-H1-10: the subset of `_tree_daemon_pids` that is the setup-page SERVER (the page open
    before Start, no target chosen) — so the refusal and cr_stop can say so instead of quoting the
    previous launch's files."""
    return _daemon_pids("launch_setup.py")


def _daemon_pids(pattern: str) -> list[int]:
    pids: list[int] = []
    try:
        found = subprocess.run(["pgrep", "-f", pattern],
                               capture_output=True, text=True, timeout=30).stdout.split()
    except Exception:
        return pids
    for pid in found:
        if not _runs_daemon(_argv(pid)):
            continue
        try:
            cwd = subprocess.run(["lsof", "-a", "-d", "cwd", "-p", pid, "-Fn"],
                                 capture_output=True, text=True, timeout=30).stdout
        except Exception:
            continue
        for line in cwd.splitlines():
            if line.startswith("n") and line[1:] == str(PROJECT_ROOT):
                pids.append(int(pid))
                break
    return pids


def _signal_pids(pids: list[int], sig: int) -> None:
    """C3 (a) / B8: every daemon `Child.launch` starts leads its own process group (pgid == pid), so the
    pattern fallback signals the GROUP — the daemon's own mypy / vulture / tracer stop with it — the
    way `gearbox._signal_group` does: `os.killpg`, then the pid alone when it leads no group (an owner's
    launch.sh gearbox is a `&` job of a script — not a leader; `killpg` raises ProcessLookupError for it
    while it is alive) or when a member may not be signalled. Nothing left to signal is not an error."""
    for pid in pids:
        try:
            os.killpg(pid, sig)
            continue
        except (ProcessLookupError, PermissionError):
            pass
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _gate_budget(target: Path) -> int:
    """The same arithmetic as `run_proof.sh gate_budget_s`, off the SAME gearbox constants:
    health ≤900 + circuit + noai(n_py) + cheatsheets cap + dashboard + slack (I-48)."""
    n_py = 0
    try:
        n_py = int(gearbox._scan_scope().live_py_count(target))
    except Exception:
        n_py = 0
    noai = min(gearbox.NOAI_GATE_BASE_TIMEOUT_S + gearbox.NOAI_GATE_PER_PY_FILE_S * n_py,
               gearbox.NOAI_GATE_TIMEOUT_CAP_S)
    return int(HEALTH_MAX_S + gearbox.CIRCUIT_GATE_TIMEOUT_S + noai
               + gearbox.BUILDER_GATE_TIMEOUT_CAP_S + gearbox.DASHBOARD_GATE_TIMEOUT_S
               + BUDGET_SLACK_S)


def _gate_records(log: Path) -> list[dict[str, Any]]:
    """Every gate verdict the gearbox logged, in order — the same lines `run_proof.sh` greps."""
    out: list[dict[str, Any]] = []
    for m in GATE_LINE.finditer(_text(log)):
        secs = SECONDS_IN_LINE.search(m.group(0))
        out.append({"gate": m.group(1), "status": m.group(2),
                    "seconds": float(secs.group(1)) if secs else None})
    return out


def _named_failure(log: Path) -> str:
    """The gate that stopped the launch, by name — never a bare 'it failed'."""
    bad = [g for g in _gate_records(log) if g["status"] != "PASS"]
    if bad:
        return f"launch step {bad[-1]['gate']}: {bad[-1]['status']}"
    hit = STOP_LINES.search(_text(log))
    return hit.group(0) if hit else "the launch ended without saying whether its steps passed"


def _phase(path: Path) -> str:
    return str(_load(path).get("phase") or "")


def _monitoring(name: str) -> bool:
    """Both published phases MONITORING for this target — `run_proof.sh phase_is_monitoring`."""
    for path in (NOAI_STATE, BUILDER_STATE):
        doc = _load(path)
        if doc.get("phase") != "MONITORING" or name not in str(doc.get("target_repo") or ""):
            return False
    return True


def _finished_state() -> tuple[bool, str, dict[str, Any]]:
    """`finished`, its reason and its three inputs, straight off the dash mirror this tree writes."""
    summary = (_load(MONITOR_MIRROR).get("monitor") or {}).get("summary") or {}
    return (bool(summary.get("finished")), str(summary.get("finished_reason") or ""),
            dict(summary.get("finished_inputs") or {}))


def _bound_target() -> Path | None:
    """The target this tree is on, from the Builder's own state."""
    repo = _load(BUILDER_STATE).get("target_repo")
    return Path(str(repo)) if repo else None


#: B1 (Q-H4-1/2, 2026-10-01): `launch.sh`'s pre-flight deletes BUILDER_STATE.json and the Builder
#: (its only writer) is the gearbox's FOURTH child, so for the whole gate phase of every launch the
#: tree has live daemons and no bound target. The two files every launch writes before any daemon
#: starts name the target: launch.sh's `choices` step (launch.sh:428, before the gearbox starts at
#: :453) and the gearbox's first write, `poll_config.json.target_repo` (gearbox.py:1478-1483).
_CHOICE_TARGET = re.compile(r"(?:^|\s)target=(?P<value>.*?)(?=\s\w+=|$)")


def _progress_doc() -> dict[str, Any]:
    return _load(SCRIPT_DIR / "launch_progress.json")


def _live_target() -> tuple[Path | None, str]:
    """The target of a launch in flight before the Builder publishes: (path, the file that named
    it), or (None, why) — never a guess. Read only while this tree's daemons are live: both files
    are cleared by launch.sh's pre-flight and rewritten by the launch that follows.
    D2 / Q-H1-10: when the only live process is the setup-page server there IS no target yet — the
    page is waiting for Start and both files still hold the PREVIOUS launch's words — so the answer
    is (None, SETUP_PAGE_OPEN), never that stale target."""
    setup = _setup_page_pids()
    if setup and set(_tree_daemon_pids()) <= set(setup):
        return None, SETUP_PAGE_OPEN
    repo = _load(SCRIPT_DIR / "poll_config.json").get("target_repo")
    if repo:
        return Path(str(repo)), "poll_config.json"
    stages = _progress_doc().get("stages") or {}
    hit = _CHOICE_TARGET.search(str((stages.get("choices") or {}).get("detail") or ""))
    if hit and hit.group("value"):
        return Path(hit.group("value")), "launch_progress.json"
    return None, ("no file names the target — BUILDER_STATE.json, poll_config.json and "
                  "launch_progress.json all publish none")


def _launch_phase() -> str:
    """Where the in-flight launch is: the Builder's published phase once it has one, else the
    launch step now running (launch_progress.json, the file every launch writes), else the
    launch file's overall status, else 'unpublished'."""
    phase = _phase(BUILDER_STATE)
    if phase:
        return phase
    doc = _progress_doc()
    stages = doc.get("stages") or {}
    order = [k for k in (doc.get("order") or list(stages)) if isinstance(stages.get(k), dict)]
    for want in ("running", "pending"):
        for key in order:
            if stages[key].get("status") == want:
                return f"launch step {key}"
    overall = str(doc.get("overall") or "")
    return f"launch {overall}" if overall else "unpublished"


def _in_progress_refusal(tool: str, target: Path | None, source: str) -> str:
    """The one sentence refusing a call while a launch is in flight on this tree; the setup page
    (D2 / Q-H1-10) gets its own — its phase would be the previous launch's file."""
    if target is None and source == SETUP_PAGE_OPEN:
        return (f"{tool}: {SETUP_PAGE_OPEN} — choose the target on the page and cr_attach it once "
                f"MONITORING, or cr_stop first (the page closes, nothing ran)")
    where = str(target) if target is not None else f"an unnamed target ({source})"
    return (f"{tool}: a launch is in progress on {where} (phase {_launch_phase()}) — wait for it; "
            f"cr_attach once MONITORING, or cr_stop first")


def _launch_started(target: Path) -> float | None:
    """When THIS target's launch began, off launch_progress.json's step start times (R5's
    guard in read_tools._launch_stages); None when the file is absent or names another target."""
    doc = _progress_doc()
    stages = doc.get("stages") or {}
    hit = _CHOICE_TARGET.search(str((stages.get("choices") or {}).get("detail") or ""))
    try:
        if not hit or Path(hit.group("value")).resolve() != target.resolve():
            return None
    except OSError:
        return None
    starts: list[float] = []
    for stage in stages.values():
        raw = (stage or {}).get("started")
        try:
            starts.append(float(raw if raw is not None else ""))
        except (TypeError, ValueError):
            pass
    return min(starts) if starts else None


def _teardown_log(run_dir: Path | None, target: Path | None, since: float) -> tuple[Path | None, str]:
    """B1 (Q-H4-5): the file carrying THIS run's teardown lines, or (None, why). Every launch
    writes the gearbox's per-run log `daemon_log/gearbox_<ts>.log` (R8/T-19); only a cr_watch
    launch also has `run_dir/launch.log`. A file counts when it was written after this stop's
    SIGTERM (`since`) or, R5's guard, after this target's launch started — a stale log of an
    earlier run is never read as this one's. The gearbox log is preferred; launch.log is the
    fallback. With no named target (`run_dir` None) only the gearbox logs are candidates."""
    started = _launch_started(target) if target is not None else None
    fresh_after = min(since - 1.0, started - 2.0) if started is not None else since - 1.0
    candidates = sorted((SCRIPT_DIR / "daemon_log").glob("gearbox_*.log"),
                        key=lambda p: p.stat().st_mtime if p.exists() else 0.0, reverse=True)
    if run_dir is not None:
        candidates.append(run_dir / "launch.log")
    for path in candidates:
        try:
            if path.stat().st_mtime >= fresh_after:
                return path, path.name
        except OSError:
            continue
    return None, (f"no teardown log of this run — no daemon_log/gearbox_*.log"
                  + (f" or {run_dir.name}/launch.log" if run_dir is not None else "")
                  + f" written since {datetime.fromtimestamp(fresh_after).strftime('%H:%M:%S')}")


# ── B1 path-first: the target is an argument of cr_watch / cr_attach, never of the process ──
#: B6: the tracer is lsof over MCP (eslogger needs root and a TTY for sudo); B6 trackers.
TRACERS = ("lsof",)
TRACKERS = ("io", "mypy", "crc", "vulture")
#: B9 (Q4): how long a port held by this tree's own just-signalled daemons may take to free.
PORT_FREE_WAIT_S = 20


def _refuse_target(target: str) -> tuple[Path | None, str | None]:
    """The resolved target, or the one sentence that refuses it (B1). `~` and relative
    paths resolve against the server's working directory — the client's, when it spawned us."""
    raw = str(target or "").strip()
    if not raw:
        return None, "no target — call cr_watch with the repo path"
    tgt = Path(raw).expanduser()
    if not tgt.is_absolute():
        tgt = Path.cwd() / tgt
    if not tgt.is_dir():
        return None, f"no such target directory: {raw} (resolved to {tgt})"
    tgt = tgt.resolve()
    if tgt == PROJECT_ROOT or PROJECT_ROOT in tgt.parents:
        return None, (f"{tgt} is CodeRadar's own tree (or inside it); CodeRadar never scans "
                      f"itself — point it at the repo you want scanned")
    if PROJECT_ROOT.resolve().is_relative_to(tgt):   # owner 2026-09-30: a folder that contains CodeRadar
        return None, (f"{tgt} contains CodeRadar itself; point it at the repo's own folder, "
                      f"not a folder above it")
    try:
        n_py = int(gearbox._scan_scope().live_py_count(tgt))
    except Exception as exc:
        return None, f"cannot count the .py files under {tgt} ({type(exc).__name__}: {exc})"
    if n_py == 0:
        return None, f"{tgt} holds zero .py files in the scan scope — CodeRadar scans Python repos"
    return tgt, None


def _bind(tgt: Path | str) -> None:
    """Point the read/write tools at this target (B1) — the same `read_tools.configure`
    the old `--target` flag called, keeping whatever tree and state dir are configured."""
    src = read_tools.sources()
    read_tools.configure(target=str(tgt), state_dir=src.state_dir, tree=src.tree)


def _port_holder(port: int) -> str | None:
    """`pid N (command)` of whatever LISTENs on 127.0.0.1:`port`, or None when it is free."""
    try:
        res = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    pids = res.stdout.split()
    if not pids:
        return None
    try:
        cmd = subprocess.run(["ps", "-o", "command=", "-p", pids[0]],
                             capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        cmd = ""
    return f"pid {pids[0]} ({cmd[:160] or 'command unknown'})"


def _foreign_port() -> str | None:
    """I-197: the sentence refusing a dash/health port held by something OTHER than this tree's
    daemons, or None — asked before anything is signalled or created, so a refusal leaves
    nothing behind. A port this tree's own daemons hold is not refused here: the pre-flight
    stops them, and `_busy_port` waits for the release."""
    ports = _ports()
    own = {str(p) for p in _tree_daemon_pids()}
    held = []
    for role, port in (("dashboard", int(ports.get("dashboard", 8080))),
                       ("health", int(ports.get("health", 8051)))):
        h = _port_holder(port)
        if h and h.split()[1] not in own:
            held.append((role, port, h))
    if not held:
        return None
    return "; ".join(f"the {role} port {port} is in use by {h}" for role, port, h in held) + \
        " — stop that process or free the port, then call cr_watch again"


def _busy_port() -> str | None:
    """B9 (Q4): the sentence refusing a busy dash/health port, or None. Waits a bounded
    PORT_FREE_WAIT_S for ports this tree's own signalled daemons are still releasing; no
    auto-port — the dev frees the port or stops the holder."""
    ports = _ports()
    wanted = (("dashboard", int(ports.get("dashboard", 8080))),
              ("health", int(ports.get("health", 8051))))
    deadline = time.monotonic() + PORT_FREE_WAIT_S
    while True:
        held = [(role, port, h) for role, port in wanted if (h := _port_holder(port))]
        if not held or time.monotonic() >= deadline:
            break
        time.sleep(2)
    if not held:
        return None
    return "; ".join(f"the {role} port {port} is in use by {h}" for role, port, h in held) + \
        " — stop that process or free the port, then call cr_watch again"


# ── the tools ────────────────────────────────────────────────────────────────

def cr_watch(target: str, trackers: str = "io,mypy", tracer: str = "lsof",
             gate_budget_s: int | None = None) -> dict[str, Any]:
    """Launch the gearbox on `target` with `run_proof.sh up`'s gates and flags, and return the
    moment the stack is up (both phases MONITORING) or a gate refuses — named."""
    out: dict[str, Any] = {
        "started": False, "target": str(target), "repo_id": "", "phase": "",
        "gates": [], "gate_budget_s": 0, "run": None, "snapshot": None,
        "dashboard_url": _dashboard_url(), "health_url": _health_url(),
        # Fix plan 2026-10-23 C4: which checkers ran, which were never asked for, and the
        # permanent naming-drift tracker's reading — so a quiet tracker is never read as a clean tree.
        "trackers_ran": [], "trackers_not_requested": [], "naming_drift": "",
        "error": None,
    }
    # B6: the tracer is locked to lsof; the trackers are the four the scan knows.
    if tracer not in TRACERS:
        out["error"] = (f"cr_watch: tracer {tracer!r} is not available over MCP — eslogger needs "
                        f"root and a terminal for sudo; the tracer is lsof")
        return out
    asked = [t.strip() for t in str(trackers or "").split(",") if t.strip()]
    unknown = [t for t in asked if t not in TRACKERS]
    if not asked or unknown:
        out["error"] = (f"cr_watch: trackers (the checkers to run) must be a comma list drawn from "
                        f"{','.join(TRACKERS)} (default io,mypy); not recognised: {unknown or [trackers]}")
        return out
    trackers = ",".join(asked)
    # B1: the target is refused in one sentence before anything is signalled or launched.
    tgt_or_none, why = _refuse_target(target)
    if tgt_or_none is None:
        out["error"] = f"cr_watch: {why}"
        return out
    tgt = tgt_or_none
    out["target"] = str(tgt)
    out["run"] = tgt.name  # Lane C: the run dir name under .archive/runs/
    # Q3: a live stack on the SAME target is attached, never relaunched; a DIFFERENT
    # target while this tree's daemons are live is refused — cr_stop first.
    # B1 (Q-H4-1/2): the live pids come FIRST. While they exist the launch they belong to is
    # in flight or MONITORING; its target is the Builder's once published, else the launch's
    # own files (`_live_target`). Nothing is signalled or launched on top of a live tree.
    live = bool(_tree_daemon_pids())
    bound = _bound_target()
    source = BUILDER_STATE.name
    if live and bound is None:
        bound, source = _live_target()
    if live and bound is not None and bound.resolve() == tgt and _monitoring(tgt.name):
        attached = cr_attach(str(tgt))
        attached["started"] = False
        out["snapshot"] = read_tools.run_and_snapshot(str(tgt))[1]
        return {**out, **{k: v for k, v in attached.items() if k in out}}
    if live and bound is not None and bound.resolve() != tgt:
        out["error"] = (f"cr_watch: this CodeRadar is already watching {bound} — call cr_stop "
                        f"first, then cr_watch {tgt}")
        return out
    if live:   # the same target, or one no file names yet, before MONITORING: never relaunched
        out["error"] = _in_progress_refusal("cr_watch", bound, source)
        out["phase"] = _phase(BUILDER_STATE)
        return out
    # I-197: a port someone else holds is refused BEFORE the run dir is made or a daemon signalled.
    foreign = _foreign_port()
    if foreign is not None:
        out["error"] = f"cr_watch: {foreign}"
        return out
    out["repo_id"] = gearbox.get_repo_id(tgt)
    budget = int(gate_budget_s) if gate_budget_s else _gate_budget(tgt)
    out["gate_budget_s"] = budget

    # Pre-flight, as `run_proof.sh up` does it: this tree's daemons only.
    _signal_pids(_tree_daemon_pids(), signal.SIGTERM)
    time.sleep(2)
    # B9 (Q4): a dash/health port someone else holds is refused up front, named.
    busy = _busy_port()
    if busy is not None:
        out["error"] = f"cr_watch: {busy}"
        return out
    # B1 (Q-H4-2): the run dir is made only once every refusal is behind — a refused call leaves
    # nothing behind (it used to be made before the `_busy_port` refusal).
    run_dir = _run_dir(tgt.name)
    (run_dir / "state_during_run").mkdir(parents=True, exist_ok=True)
    log = run_dir / "launch.log"
    _bind(tgt)

    try:
        handle = open(log, "wb")
    except OSError as e:
        out["error"] = f"cr_watch: cannot open the launch log ({e})"
        return out
    with handle:
        proc = subprocess.Popen(
            [str(LAUNCH_SH), str(tgt), "--tracer", tracer, "--trackers", trackers],
            cwd=str(PROJECT_ROOT), stdout=handle, stderr=subprocess.STDOUT,
            start_new_session=True)
    (run_dir / "gearbox.pid").write_text(str(proc.pid), encoding="utf-8")

    deadline = time.monotonic() + budget
    up = False
    while time.monotonic() < deadline:
        body = _text(log)
        if UP_LINE in body:
            up = True
            break
        if STOP_LINES.search(body) or proc.poll() is not None:
            break
        time.sleep(2)

    out["gates"] = _gate_records(log)
    try:   # B2 / Q5: the private env's state, published whatever the gates said
        from system_scripts import target_env
        out["target_env"] = target_env.describe(target_env.read(tgt, tree=PROJECT_ROOT))
    except Exception as e:  # noqa: BLE001
        out["target_env"] = f"failed: record unreadable ({e})"
    if not up:
        out["error"] = f"cr_watch: {_named_failure(log)} (budget {budget}s, log {log})"
        out["phase"] = _phase(BUILDER_STATE)
        out.update(_tracker_coverage())
        return out

    # Both phases MONITORING — the gearbox's gates already said so. Fix plan 2026-10-23 D2: the
    # state-file read is bounded by MONITORING_WAIT_S, not by the rest of the gate budget — the
    # stack is already up, and a phase that never publishes is reported within minutes, not
    # at the end of a 49-minute budget with the daemons still running.
    phase_deadline = min(deadline, time.monotonic() + MONITORING_WAIT_S)
    while time.monotonic() < phase_deadline and not _monitoring(tgt.name):
        if proc.poll() is not None:
            break   # launch.sh left — nothing more will publish
        time.sleep(2)
    out["phase"] = _phase(BUILDER_STATE)
    for src, dst in ((NOAI_STATE, None), (BUILDER_STATE, None), (CIRCUIT_STATE, None),
                     (NOAI_MIRROR, "noai_state_mirror.json"), (MONITOR_MIRROR, "monitor_mirror.json")):
        if src.exists():
            try:
                shutil.copy2(src, run_dir / "state_during_run" / (dst or src.name))
            except OSError:
                pass
    out.update(_tracker_coverage())
    if not _monitoring(tgt.name):
        out["error"] = (f"cr_watch: every launch step passed but CodeRadar did not reach MONITORING "
                        f"(watching your repo) within {int(MONITORING_WAIT_S)}s of ALL GATES PASSED "
                        f"(phase={out['phase'] or 'unpublished'}) — the daemons are still running; "
                        f"call cr_stop, then cr_watch again")
        return out
    out["snapshot"] = read_tools.run_and_snapshot(str(tgt))[1]  # Lane C: launch.sh's COPY-FIRST copy
    out["started"] = True
    return out


def _tracker_coverage() -> dict[str, Any]:
    """Fix plan 2026-10-23 C4: `trackers_ran` / `trackers_not_requested` / `naming_drift` off the
    circuit state, by the one rule `cr_status` uses (`read_tools.tracker_coverage`)."""
    try:
        circuit, c_err = read_tools._load(read_tools._CIRCUIT_FILES)
        monitor, m_err = read_tools._monitor_state()
        ran, not_requested, drift = read_tools.tracker_coverage(circuit if c_err is None else {},
                                                                monitor if m_err is None else {})
    except Exception as e:  # noqa: BLE001 — a reading never fails the launch answer
        return {"trackers_ran": [], "trackers_not_requested": [],
                "naming_drift": f"NOT MEASURED — {type(e).__name__}: {e}"}
    return {"trackers_ran": ran, "trackers_not_requested": not_requested, "naming_drift": drift}


def cr_attach(target: str | None = None) -> dict[str, Any]:
    """Bind to a target already under MONITORING in this tree. Reads only — it starts nothing,
    and it refuses in words when nothing is running."""
    doc = _load(BUILDER_STATE)
    bound = str(doc.get("target_repo") or "")
    out: dict[str, Any] = {
        "attached": False, "target": bound or None, "repo_id": doc.get("repo_id") or None,
        "phase": doc.get("phase") or None, "cycle": doc.get("cycle"),
        "since": doc.get("last_build") or None,
        "dashboard_url": _dashboard_url(), "health_url": _health_url(), "error": None,
    }
    if not bound:
        # B1 (Q-H4-2): during the gate phase daemons are live and the Builder has not published —
        # say so by name, never "nothing is running" over a running launch.
        if _tree_daemon_pids():
            live_tgt, source = _live_target()
            out["target"] = str(live_tgt) if live_tgt is not None else None
            out["error"] = _in_progress_refusal("cr_attach", live_tgt, source)
            return out
        out["error"] = (f"cr_attach: nothing is running in this tree — {BUILDER_STATE.name} "
                        f"publishes no target (run cr_watch first)")
        return out
    if target:
        tgt, why = _refuse_target(target)
        if tgt is None:
            out["error"] = f"cr_attach: {why}"
            return out
        want = str(tgt)
        if want != str(Path(bound).resolve()):
            out["error"] = f"cr_attach: this tree is on {bound}, not {want}"
            return out
    states = gearbox.gate_states()
    if not (states["noai_monitoring"] and states["builder_monitoring"]):
        out["error"] = (f"cr_attach: {bound} is not under MONITORING "
                        f"(phase={out['phase'] or 'unpublished'}, gates={json.dumps(states)})")
        return out
    if not states["dashboard_up"]:
        out["error"] = (f"cr_attach: the phases read MONITORING but the dashboard does not answer "
                        f"on {_dashboard_url()} — the stack is not up")
        return out
    _bind(bound)  # B1: an attach binds the read/write tools to the running target
    out["attached"] = True
    return out


def cr_stop(verify_identity: bool = True, mark_pool: bool = False,
            expected_changes: list[str] | None = None) -> dict[str, Any]:
    """The teardown. SIGTERM the gearbox so its own leave-no-trace path runs, then report what
    it reported: residue zero, and the target byte-identical to its COPY-FIRST snapshot.

    Under the solution gate (owner 2026-10-08; fix plan 2026-10-23, pass B) CodeRadar is the
    writer: an integrated `cr_submit` attempt is written into the target by the Builder, so
    `byte_identical` is false on any run where a repair was integrated — and false alone says
    nothing about whose bytes moved. A path the gate ledger shows the gate itself wrote is counted
    under `gate_writes`; `expected_changes` (a manifest of paths relative to the target) stays for
    a repair a seat made outside the gate and reported with cr_report_outcome, counted under
    `client_edits`; every other differing path is `unexpected_changes`. The guarantee is
    `unexpected_changes == []`: CodeRadar left nothing behind that neither the gate ledger nor the
    manifest accounts for.

    Fix plan 2026-10-23 D3: a stop is not CLEAR while a finding is open. `open_findings` is read
    off the counterfeit mirror before the teardown moves it; `clear` is true only when every
    process is gone, residue was measured clean, the byte check was measured and `unexpected_changes`
    is empty, and `open_findings` is zero. `stopped` stays the process fact on its own. A byte
    check that could not be run (no snapshot, no listing, a failed hash command) leaves
    `byte_identical` null — never a match."""
    out: dict[str, Any] = {
        "stopped": False, "daemons_exited": [], "residue_clean": False,
        "byte_identical": None, "files_compared": 0,
        "client_edits": 0, "gate_writes": [], "unexpected_changes": [], "mirrors_kept": [],
        "open_findings": None, "open_findings_by": {}, "clear": False,
        "run_dir": None, "trackers": None, "teardown_source": None, "error": None,
    }
    # B1 (Q-H4-1): "cr_stop always tears down whatever this CodeRadar runs" — the live pids are
    # read FIRST. During the gate phase BUILDER_STATE.json does not exist yet (launch.sh's pre-flight
    # cleared it; the Builder is the 4th child), so the target is then taken from the launch's own
    # files (`_live_target`); with no file naming it, the live daemons are still torn down and the
    # unnamed parts are said NOT MEASURED. The refusal stays only when nothing is live.
    live = _tree_daemon_pids()
    tgt = _bound_target()
    named_by = BUILDER_STATE.name
    if tgt is None and live:
        tgt, named_by = _live_target()
    if tgt is None and not live:
        out["error"] = (f"cr_stop: nothing to stop — no repo is being watched ({BUILDER_STATE.name} names none) "
                        f"and no CodeRadar process is running")
        return out

    def _note(msg: str) -> None:
        out["error"] = " | ".join(part for part in (out["error"], msg) if part)

    run_dir = _run_dir(tgt.name) if tgt is not None else None
    if tgt is not None and run_dir is not None:
        out["trackers"] = _tracker_line()   # MCPW-D O1: read BEFORE the teardown moves the states
        out["run_dir"] = str(run_dir)
        # D3: the open rows, read off the mirror BEFORE the teardown — the same two lists
        # `finished` counts (repairs + no_vetted_fix; withheld rows never count).
        try:
            mirror_doc = json.loads(NOAI_MIRROR.read_text(encoding="utf-8")) if NOAI_MIRROR.exists() else None
        except (OSError, ValueError):
            mirror_doc = None
        if isinstance(mirror_doc, dict):
            out["open_findings"], out["open_findings_by"] = read_tools.open_findings_of(mirror_doc)
        else:
            _note(f"cr_stop: open findings NOT MEASURED — {NOAI_MIRROR.name} is missing or unreadable")
        if NOAI_MIRROR.exists():
            try:
                shutil.copy2(NOAI_MIRROR, run_dir / "state_during_run" / "noai_state_mirror_at_teardown.json")
            except OSError:
                pass
        if MONITOR_MIRROR.exists():
            try:
                shutil.copy2(MONITOR_MIRROR, run_dir / "state_during_run" / "monitor_mirror_at_teardown.json")
            except OSError:
                pass
        # Lane B O3 (2026-09-28): the derived intent travels with the run's states, so the read_tools
        # gate can replay a seat run without a hand copy. Saved when the file exists.
        intent = SCRIPT_DIR / f"intent_{gearbox.get_repo_id(tgt)}.json"
        if intent.exists():
            try:
                shutil.copy2(intent, run_dir / "state_during_run" / intent.name)
            except OSError:
                pass

    pid_file = run_dir / "gearbox.pid" if run_dir is not None else None
    try:
        gpid = int(_text(pid_file).strip() or 0) if pid_file is not None else 0
    except ValueError:
        gpid = 0
    since = time.time()   # Q-H4-5: a teardown log counts only when written after this moment
    if gpid and _alive(gpid):
        # The launcher ALONE, by pid (its own handler runs the gearbox's leave-no-trace path over
        # the children); the group signal (C3 (a)) is the fallback below, for daemons no launcher owns.
        try:
            os.kill(gpid, signal.SIGTERM)
        except OSError:
            pass
        for _ in range(60):
            if not _alive(gpid):
                break
            time.sleep(1)
    else:
        # An owner's launch (launch.sh / setup page) has no gearbox.pid: every daemon of this tree
        # is signalled and given the same bounded wait the pid path gets (it used to be 5 s flat).
        _signal_pids(live or _tree_daemon_pids(), signal.SIGTERM)
        for _ in range(60):
            if not _tree_daemon_pids():
                break
            time.sleep(1)
    leftover = _tree_daemon_pids()
    out["stopped"] = not leftover
    if leftover:
        out["error"] = f"cr_stop: {len(leftover)} CodeRadar process(es) still running after the stop signal (SIGTERM): {leftover}"

    # B1 (Q-H4-5): the teardown lines come from the file every launch writes (the gearbox's own
    # per-run log), with the freshness guard; `launch.log` only when it is this launch's. Residue
    # that no log of this run reports is said NOT MEASURED, never false-as-fact.
    log, why = _teardown_log(run_dir, tgt, since)
    if log is not None:
        # C3 (c) / B1: the file `daemons_exited` and `residue_clean` were read from, by path; null
        # when no log of this run was found (then `error` says NOT MEASURED and why).
        out["teardown_source"] = str(log)
        body = _text(log)
        pids = {m.group(1): int(m.group(2)) for m in STARTED_LINE.finditer(body)}
        for m in STOPPED_LINE.finditer(body):
            out["daemons_exited"].append({"name": m.group(1), "pid": pids.get(m.group(1)),
                                          "exit_code": int(m.group(3)), "signal": m.group(2)})
        out["residue_clean"] = RESIDUE_OK in body
    else:
        _note(f"cr_stop: whether every process exited and left nothing behind is NOT MEASURED — {why}")
    if tgt is None or run_dir is None:
        _note(f"cr_stop: {len(live)} running CodeRadar process(es) stopped, but no repo was named ({named_by}) — "
              f"so the saved state files and the check that your repo is unchanged are NOT MEASURED")
        return _clear_verdict(out)
    # Owner ruling 2026-09-28: the two state mirrors survive the stop as the run's log.
    name = tgt.name
    out["mirrors_kept"] = [str(p.relative_to(tgt)) for p in gearbox._scan_scope().mirror_files(tgt)]

    if verify_identity:
        # `<name>_<YYYYmmdd_HHMMSS>` only: a bare `<name>_*` also matched another target whose name
        # extends this one (`out_of_the_cradle_q5fixture_…`, run 178) and that sorted last.
        snaps = sorted((p for p in SNAPSHOT_ROOT.glob(f"{name}_*")
                        if re.fullmatch(re.escape(name) + r"_\d{8}_\d{6}", p.name)), key=lambda p: p.name)
        if not snaps:
            _note(f"cr_stop: byte identity NOT MEASURED — no COPY-FIRST snapshot for {name} under {SNAPSHOT_ROOT}")
            return _clear_verdict(out)
        snap = snaps[-1]
        made = []
        if not SNAPSHOT_FILES.exists():
            _note(f"cr_stop: byte identity NOT MEASURED — {SNAPSHOT_FILES} is missing")
            return _clear_verdict(out)
        if shutil.which("md5") is None:
            _note("cr_stop: byte identity NOT MEASURED — `md5` is not on PATH (the hash is Mac `md5 -r`)")
            return _clear_verdict(out)
        for root, dest in ((snap, "teardown_snapshot.md5"), (tgt, "teardown_target.md5")):
            # Q10 (B7): the snapshot's ONE file set (env dirs / node_modules / tool caches skipped).
            # `pipefail`: a listing or hash that fails is a FAILED measurement, never an empty
            # (and therefore matching) side (fix plan 2026-10-23 D3).
            listing = subprocess.run(
                f"set -o pipefail; bash '{SNAPSHOT_FILES}' . | xargs md5 -r", shell=True, cwd=str(root),
                capture_output=True, text=True, executable="/bin/bash")
            if listing.returncode != 0 or not listing.stdout.strip():
                _note(f"cr_stop: byte identity NOT MEASURED — the hash listing of {root} failed "
                      f"(rc {listing.returncode}): {(listing.stderr or '').strip()[-300:] or 'empty listing'}")
                return _clear_verdict(out)
            (run_dir / dest).write_text(listing.stdout, encoding="utf-8")
            made.append(listing.stdout)
        out["files_compared"] = len(made[0].splitlines())
        diff = subprocess.run(["diff", str(run_dir / "teardown_snapshot.md5"),
                               str(run_dir / "teardown_target.md5")],
                              capture_output=True, text=True)
        (run_dir / "teardown_diff.txt").write_text(diff.stdout, encoding="utf-8")
        out["byte_identical"] = diff.returncode == 0  # recomputed below, mirrors exempt
        # Q3: name whose bytes moved. `md5 -r` prints "<hash> <path>"; a path present on one
        # side only, or with a different hash, is a difference. The client's manifest is the
        # only thing allowed to account for one.
        # `removeprefix`, not `lstrip("./")`: lstrip ate the dot of `.git/index` (run 177).
        named = {p.strip().removeprefix("./") for p in (expected_changes or []) if p.strip()}
        sides: list[dict[str, str]] = []
        for side_md5 in made:
            sides.append({line.split(" ", 1)[1].removeprefix("./"): line.split(" ", 1)[0]
                          for line in side_md5.splitlines() if " " in line})
        # The kept mirrors are expected to differ (ruling 2026-09-28) — exempt by THE location
        # helper (scan_scope.is_mirror_path: `.coderadar/**/<mirror name>`), nothing else.
        is_mirror = gearbox._scan_scope().is_mirror_path
        moved = sorted({p for p in set(sides[0]) | set(sides[1])
                        if sides[0].get(p) != sides[1].get(p) and not is_mirror(p)})
        out["byte_identical"] = not moved
        out["client_edits"] = sum(1 for p in moved if p in named)
        # Problem 5 (2026-10-10): under the solution gate the Builder, not the client, applies an
        # integrated repair — the client filed it with cr_submit and edited nothing, so its manifest
        # does not name the file. The gate ledger of this launch does: a moved file whose row has an
        # integrated attempt is the gate's own write, published as `gate_writes`, never unexpected.
        ledger = SCRIPT_DIR / f"gate_{gearbox.get_repo_id(tgt)}.jsonl"
        gated = {key.split("::", 1)[0] for key, attempts in read_tools.gate_verdicts(ledger).items()
                 if any(a["status"] == "integrated" for a in attempts)}
        out["gate_writes"] = [p for p in moved if p not in named and p in gated]
        out["unexpected_changes"] = [p for p in moved if p not in named and p not in gated]

    if mark_pool:
        _mark_pool(name)
    try:                       # `run_proof.sh down`'s last line: the pid file leaves with the run
        if pid_file is not None:
            pid_file.unlink(missing_ok=True)
    except OSError:
        pass
    return _clear_verdict(out)


def _clear_verdict(out: dict[str, Any]) -> dict[str, Any]:
    """Fix plan 2026-10-23 D3 — the one place `clear` is decided. True only when the processes are
    gone, residue was MEASURED clean, the byte check was MEASURED with nothing unexplained, and no
    finding is open. Anything NOT MEASURED is not clear, and the reason is already in `error`."""
    open_n = out.get("open_findings")
    reasons: list[str] = []
    if not out.get("stopped"):
        reasons.append("processes still running")
    if out.get("teardown_source") is None or not out.get("residue_clean"):
        reasons.append("residue not measured clean")
    if out.get("byte_identical") is None:
        reasons.append("byte identity not measured")
    elif out.get("unexpected_changes"):
        reasons.append(f"{len(out['unexpected_changes'])} unexpected change(s)")
    if open_n is None:
        reasons.append("open findings not measured")
    elif open_n:
        reasons.append(f"{open_n} finding(s) still open")
    out["clear"] = not reasons
    if reasons:
        msg = "cr_stop: not clear — " + "; ".join(reasons)
        out["error"] = " | ".join(part for part in (out.get("error"), msg) if part)
    return out


def _unmeasured_part(token: str, block: dict, reason: str) -> str:
    """R9: one tracker's NOT MEASURED reading — the status as the daemon published it (it already
    carries the reason), else built from circuit_state's `trackers.not_measured` reason."""
    status = str(block.get("status") or "")
    return f"{token}: {status if status.startswith('NOT MEASURED') else 'NOT MEASURED — ' + str(reason)}"


def _tracker_line() -> str | None:
    """MCPW-D O1 (run 180): the seat never read cr_data_types, so the mypy/io readings reached
    nobody. cr_stop carries this one line as a backstop; cr_data_types stays the full answer."""
    try:
        dt = read_tools.cr_data_types()
    except Exception:          # a backstop never fails the teardown
        return None
    if dt.get("error"):
        return None
    m, io = dt.get("mypy") or {}, dt.get("io") or {}
    #: R9: R4's {token: reason} for a chosen tracker whose tool is missing or failed — that tracker
    #: says "NOT MEASURED — <reason>" here, never a count and never "not run".
    nm = dt.get("not_measured") or {}
    parts = []
    if "mypy" in nm:
        parts.append(_unmeasured_part("mypy", m, nm["mypy"]))
    elif m:
        # M-20 (run 187, six): two mypy numbers are published and they measure different scopes.
        # `total_errors` here = real type errors only (annotation notes excluded, plan item 11);
        # `finished` / cr_status / cr_data_types.finished_input read `monitor.summary.mypy_errors` = every
        # `: error:` line INCLUDING annotation notes, less the suppressed ones. Name both scopes.
        notes = m.get("annotation_notes")
        parts.append(f"mypy: {m.get('status', '?')}, import_errors {m.get('import_errors', '?')}, "
                     f"type_errors {m.get('type_errors', m.get('total_errors', '?'))} in {m.get('failed', '?')}/"
                     f"{m.get('files_checked', '?')} files"
                     + (f" (+{notes} annotation notes)" if notes is not None else "")
                     + (f"; finished counts {dt['finished_input']} {ISSUES_SCOPE}"
                        if isinstance(dt.get("finished_input"), int) else ""))
    else:
        parts.append("mypy: not run")
    tot = io.get("totals") or {}
    if "io" in nm:
        parts.append(_unmeasured_part("io", io, nm["io"]))
    elif io:
        parts.append(f"io: {io.get('status', '?')}, {tot.get('total_functions', '?')} functions, "
                     f"io_functions {tot.get('io_functions', '?')}, exempt {tot.get('sync_exempt_count', '?')}")
    else:
        parts.append("io: not run")
    # R9: vulture and crc join the line — the trackers line named only mypy and io.
    vu, crc = dt.get("vulture") or {}, dt.get("crc") or {}
    if "vulture" in nm:
        parts.append(_unmeasured_part("vulture", vu, nm["vulture"]))
    elif vu.get("status") == "measured":
        parts.append(f"vulture: measured, {vu.get('total_items', '?')} items in "
                     f"{vu.get('files_scanned', '?')} files")
    else:
        parts.append(f"vulture: {vu.get('status') or 'not run'}")
    if "crc" in nm:
        parts.append(_unmeasured_part("crc", crc, nm["crc"]))
    elif crc.get("status") == "measured" and set(crc) <= {"status"}:
        parts.append("crc: measured — no scan result yet this cycle")    # the dashboard's words
    elif crc.get("status") == "measured":
        parts.append(f"crc: measured, {crc.get('total_functions', '?')} functions, "
                     f"{len(crc.get('violations') or [])} violations")
    else:
        parts.append(f"crc: {crc.get('status') or 'not run'}")
    try:
        w = read_tools.cr_wiring(include_dataflows=False)
        c = w.get("counts") or {}
        if not w.get("error"):
            # M-19 (run 187, six read `live 3 of 0`): the edge states are DISJOINT (possible /
            # live / severed), so `possible` is not the population `live` is drawn from. The
            # denominator is every edge; live <= edges always.
            # I-198: `live via tests` is its own disjoint state — shown only when it lit, never in `live`.
            _vt = c.get('live_via_tests', 0)
            parts.append(f"wiring: live {c.get('live', 0)} of {sum(c.values())} edges "
                         f"(possible {c.get('possible', 0)}, severed {c.get('severed', 0)}"
                         + (f", live via tests {_vt}" if _vt else "") + ")"
                         + (f" — {w['live_why']}" if w.get("live_why") else ""))
    except Exception:
        pass
    return " · ".join(parts)


def _mark_pool(name: str) -> None:
    """I-45: the run name leaves the tree's pool at teardown, marked with who used it."""
    try:
        lines = POOL_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for i, line in enumerate(lines):
        if line.strip().split()[:1] == [name] and "# used:" not in line:
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            lines[i] = f"{name}  # used: {name} (cr_stop, {stamp})"
            POOL_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return


def _run_started(report_path: Path) -> str:
    """When the run began. The gearbox's event feed carries it while the run is up and is deleted
    at teardown (FIX_52), so a hand-back AFTER `cr_stop` recovers it from the report the gearbox's
    own teardown just wrote — never invented, and empty when neither says."""
    live = str(_load(GEARBOX_EVENTS).get("run_started") or "")
    return live or str(_load(report_path).get("run_started") or "")


def cr_hand_back(note: str = "") -> dict[str, Any]:
    """Publish the tester report (Item 6) and the finished state (Q5), and return both.

    At the end call cr_stop() then cr_hand_back() — the hand-back is the last word. The gearbox's
    own teardown writes `tester_report.json` before its children stop (Item 6), so a hand-back
    published before cr_stop is overwritten by it (run 139). Called after the teardown it still
    measures: `BUILDER_STATE.json`, the dash mirror, the return channel and the confirmed ledger
    all outlive the daemons (only the next launch's pre-flight clears them).

    B12 (Q-H4-3, 2026-10-01): the teardown's own report is read first and its `daemon_failure`
    record (S4: `run_trusted` false) is carried into the re-published one, so the hand-back never
    turns an untrustworthy run into a trusted one. Called in the WRONG order — while this tree's
    daemons are still live — the report is written and the numbers answered, but `error` says that
    the teardown will overwrite it and to call cr_stop() then cr_hand_back() again; the loss is
    never silent.

    Q1(a) (S4-3): the report the writer builds now counts a confirmation from the confirmed
    ledger as well as from the channel — `confirmed` = joined + ledger-only, with
    `confirmed_joined` / `confirmed_from_ledger` / `confirmed_ledger_rows` saying which is
    which, and `orphans` counting only the lines neither could account for. The ledger outlives
    the daemons the same way the channel does, so the order of the teardown is unchanged."""
    out: dict[str, Any] = {
        "report_path": "", "target": "", "repo_id": "", "run_started": "", "run_ended": "",
        "builder_cycles": 0, "infractions": 0, "infractions_seen": 0,
        "infractions_retired_confirmed": 0, "solutions": 0, "confirmed": 0,
        "confirmed_joined": 0, "confirmed_from_ledger": 0, "confirmed_ledger_rows": [],
        "confirmed_ledger": "",
        "confirmed_fraction": None, "trackers": None, "tester_ran": False, "status": "NOT MEASURED",
        "per_infraction": [], "return_channel_lines": 0, "return_channel": "",
        "orphans": 0, "orphans_channel": 0, "unparsed": 0, "builder_state_sha256": "",
        "finished": False, "error": None,
    }
    tgt = _bound_target()
    if tgt is None:
        out["error"] = f"cr_hand_back: nothing to hand back — {BUILDER_STATE.name} publishes no target"
        return out
    repo_id = str(_load(BUILDER_STATE).get("repo_id") or gearbox.get_repo_id(tgt))
    report_path = _run_dir(tgt.name) / "tester_report.json"
    # B12: the teardown's report (when cr_stop ran first) is the only carrier of the S4 failure
    # record — re-publishing without it would read `run_trusted: true` over a run that died.
    prior_failure = _load(report_path).get("daemon_failure")
    report = gearbox.write_tester_report(
        tgt, repo_id, _run_started(report_path),
        daemon_failure=dict(prior_failure) if isinstance(prior_failure, dict) else None)
    live = _tree_daemon_pids()
    if live:
        out["error"] = (f"cr_hand_back: called while this tree's daemons are live (pids "
                        f"{', '.join(str(p) for p in live)}) — the gearbox's teardown rewrites "
                        f"{report_path.name}, so this hand-back's finished/note stamp will be "
                        f"lost; call cr_stop() then cr_hand_back() again")

    finished, reason, inputs = _finished_state()
    # The hand-back stamps the finished state onto the report it just published, so the artifact
    # answers Q5 on its own; `note` rides only when the caller gave one (Item 6 shape otherwise).
    report["finished"] = finished
    report["finished_reason"] = reason
    report["finished_inputs"] = inputs
    if note:
        report["note"] = note
    try:
        report_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    except OSError as e:
        out["error"] = f"cr_hand_back: the report was built but not written ({e})"

    for key in ("target", "repo_id", "run_started", "run_ended", "status", "return_channel",
                "confirmed_ledger"):
        out[key] = str(report.get(key) or "")
    for key in ("builder_cycles", "infractions", "infractions_seen", "infractions_retired_confirmed",
                "solutions", "confirmed", "confirmed_joined",
                "confirmed_from_ledger", "return_channel_lines", "orphans", "orphans_channel",
                "unparsed"):
        out[key] = int(report.get(key) or 0)
    out["confirmed_ledger_rows"] = list(report.get("confirmed_ledger_rows") or [])
    out["confirmed_fraction"] = report.get("confirmed_fraction")
    out["tester_ran"] = bool(report.get("tester_ran"))
    out["per_infraction"] = list(report.get("per_infraction") or [])
    out["builder_state_sha256"] = str(report.get("builder_state_sha256") or "")
    out["report_path"] = str(report_path)
    out["finished"] = finished
    out["trackers"] = _tracker_line()   # MCPW-D O1: the seat writes its summary from this answer
    if report.get("error") and not out["error"]:
        out["error"] = f"cr_hand_back: {report['error']}"
    return out


register_handler("cr_watch", cr_watch)
register_handler("cr_attach", cr_attach)
register_handler("cr_stop", cr_stop)
register_handler("cr_hand_back", cr_hand_back)
