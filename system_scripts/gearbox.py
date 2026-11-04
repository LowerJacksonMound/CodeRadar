#!/usr/bin/env python3
"""CodeRadar gearbox — the daemon coordinator.

Invoked by launch.sh (after COPY-FIRST + pre-flight + whitelist stage) as:

    .venv_new/bin/python system_scripts/gearbox.py /path/to/target

Responsibilities (Gearbox dossier, PHASE_REVIEWS.md):
  * Gated sequential start: circuit_daemon -> (READY/RUNNING) -> (WIRING: every node connected, FIX_36) -> NOAI validator
    + dashboard -> (NOAI MONITORING) -> (dashboard HTTP 200). Every gate logged
    with timing; fail-fast if a child dies while a gate is being polled.
  * ONE definition of "up" (gate_states()) shared with the dashboard overlay.
  * Supervision: 1s poll; a child that DIED or that HUNG (FIX_52 — process state
    T/Z, a stalled circuit_state.json, a dashboard whose HTTP gate has been
    failing) STOPS THE RUN (S4, owner 2026-09-29: no restarts — a crashed
    daemon's results cannot be trusted): the failure is recorded (run feed,
    progress file, tester report `run_trusted: false`, terminal), every daemon
    but the dashboard is torn down, the dash shows the red panel until Ctrl-C,
    exit 1. Warn if circuit_state.json goes stale.
  * Leave-no-trace (seam R1/S3): a PERSISTED manifest of every mirror dotfile
    CodeRadar writes into the target (system_scripts/cb_writes_<repoid>.json,
    updated every 30s as writes happen, not at end); on SIGINT/SIGTERM/normal
    exit (and SIGHUP — the terminal closed): SIGTERM children (circuit daemon escalates to SIGKILL after 5s —
    boot-test failure item 12), list the kept state mirrors (owner ruling
    2026-09-28: they are logs of the run and survive teardown), print a
    summary. __pycache__ is NOT deleted — reported as residue instead.
"""

from __future__ import annotations

import hashlib
import json
import re
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent            # system_scripts/
PROJECT_ROOT = SCRIPT_DIR.parent
LOG_DIR = SCRIPT_DIR / "daemon_log"

CIRCUIT_STATE = SCRIPT_DIR / "circuit_state.json"
NOAI_STATE = SCRIPT_DIR / "NOAI_VALIDATION_STATE.json"
CLOSE_REQUEST = SCRIPT_DIR / "close_request.json"   # owner 2026-09-30: the failed overlay's close / back-to-setup
BUILDER_STATE = SCRIPT_DIR / "BUILDER_STATE.json"          # item 1 (2026-09-08): the Builder's own state
# B8 / Q-H1-5 (2026-10-01): the run's process record — the gearbox's pid and every child's pid/pgid, written
# at start and after each launch, removed at the end of the teardown. Outlives a gearbox that was `kill -9`ed
# or crashed, so launch.sh's pre-flight (and a dead-gearbox launch.sh) can PROVE which leftover daemons are
# CodeRadar's own before stopping them, and name them.
PID_FILE = SCRIPT_DIR / "gearbox_pids.json"
# Copy setup (express plan, 2026-09-10): every tree — the original and each app copy —
# carries system_scripts/copy_ports.json; it is the ONLY file that differs between copies.
def _copy_ports() -> dict:
    try:
        with open(SCRIPT_DIR / "copy_ports.json", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}
DASHBOARD_PORT = int(_copy_ports().get("dashboard", 8080))
DASHBOARD_URL = f"http://127.0.0.1:{DASHBOARD_PORT}"

# The mirror dotfiles CodeRadar daemons fan out into the target CB.
# (data type tracker contract, seam R1: "files I write into the target".)
MIRROR_NAMES = (".noai_state.json", ".monitor_state.json")

# S4 (owner 2026-09-29, RULED — "if a daemon crashes unexpectedly, can we really trust whatever results
# it may have generated?"): NO RESTARTS. A daemon that exits or hangs stops the whole run (see the
# supervision loop); FIX_52's restart window, backoff and three strikes are gone.
# A child that is ALIVE but has not written the state file it owns for this long, while the stack is
# past its gates, is HUNG (I-12: today it is only reported). A THIRD threshold beside the dash's 10 s
# (FIX_20) and gearbox's 30 s log warning (I-11) — deliberately much longer than either.
# I-109 (2026-09-21, lane tr1_L4L8): it was a CANDIDATE row for the one cadence table Q6 ruled; it is
# now a DECLARED row of it (`gearbox / hung_state`, and the "thresholds declared" line the table
# prints), so all THREE stale thresholds are declared in one place. Declared, NOT unified — Q6
# forbids an ad-hoc unify and the three answer three different questions.
HUNG_STATE_S = 90.0


def _poll_interval_s() -> float:
    """The circuit daemon's poll interval (poll_config.json `interval_ms`, the dash slider), in seconds."""
    try:
        return float(json.loads((Path(__file__).parent / "poll_config.json").read_text()).get("interval_ms", 2500)) / 1000.0
    except (OSError, ValueError, TypeError, AttributeError):
        return 2.5


# I-108 (MCP-working packet 2026-09-28): the validator and the Builder write their STATE on change, so
# an alive-but-idle daemon was undetectable (hang_reason's point 2). Each now writes a HEARTBEAT —
# a sidecar `<state stem>.heartbeat.json` beside the state it owns, on the cadence of its
# `heartbeat` row in DUTY_CADENCE — from its own poll loop, so a loop that stopped turning stops
# the beat. A sidecar, never a field in the state: the Builder keys on the sha of the validator
# state's bytes, and a beat inside those bytes would re-trigger a build every cycle.
# Stale = older than HUNG_STATE_S (the declared `gearbox / hung_state` row; not a fourth number).
def heartbeat_file(state_file: Path) -> Path:
    state_file = Path(state_file)
    return state_file.with_name(state_file.stem + ".heartbeat.json")


def write_heartbeat(state_file: Path, daemon: str, cycle: int) -> None:
    """Atomic write of {daemon, pid, cycle, ts, at}; never raises (a beat is best-effort)."""
    hb = heartbeat_file(state_file)
    try:
        tmp = hb.with_name(hb.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"daemon": daemon, "pid": os.getpid(), "cycle": int(cycle),
                                   "ts": time.time(),
                                   "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}),
                       encoding="utf-8")
        os.replace(tmp, hb)
    except OSError:
        pass


def heartbeat_age(state_file: Path, now: float | None = None, pid: int | None = None) -> float | None:
    """Seconds since the heartbeat beside *state_file* was written, or None when there is none —
    or, with *pid*, when the beat was written by another process (a previous run's leftover)."""
    hb = heartbeat_file(state_file)
    now = time.time() if now is None else now
    try:
        beat = json.loads(hb.read_text(encoding="utf-8"))
        ts = float(beat["ts"])
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None
    if pid is not None and beat.get("pid") != pid:
        return None
    return max(0.0, now - ts)
GEARBOX_EVENTS = SCRIPT_DIR / "gearbox_events.json"   # the run feed (band + MCP); engine-side, never in the target
SUPERVISE_POLL_S = 1.0
CIRCUIT_GATE_TIMEOUT_S = 120.0
NOAI_GATE_BASE_TIMEOUT_S = 120.0
NOAI_GATE_PER_PY_FILE_S = 2.0
NOAI_GATE_TIMEOUT_CAP_S = 900.0
# Builder gate (item 1, 2026-09-08): base + per failed row the validator published, same cap.
BUILDER_GATE_BASE_TIMEOUT_S = 60.0
BUILDER_GATE_PER_ROW_S = 2.0
BUILDER_GATE_TIMEOUT_CAP_S = 900.0
DASHBOARD_GATE_TIMEOUT_S = 30.0
SIGTERM_GRACE_S = 5.0

_shutdown_requested = False


# ── FIX_46 (owner Q6, 2026-09-15): THE ONE CADENCE TABLE ─────────────────────
# "Not a number. Four daemons, each with responsibilities that run near non-stop; think of each
#  daemon's responsibilities as fan blades. Lined up across all four, the circumference should be
#  FULLY filled with no collisions if the timing is right; where room runs out, collisions land on
#  OPPOSITE daemons."  (PRE_VSC_PACKET_2026-09-15.md §F, Q6)
#
# Every polled duty of every daemon is ONE ROW here, with what it touches, its period and its phase.
# No period and no phase is written down anywhere else: circuit_daemon, the NOAI validator, the
# Builder and the dashboard all read this table. I-11's two stale thresholds are two rows of it —
# DECLARED, not unified (they answer two different questions; the owner ruled "not a number").
# I-109 (2026-09-21): HUNG_STATE_S is the THIRD such threshold and is a row here too, so all three
# stale thresholds are declared in this one place. Three questions, three rows, still not unified.
#
# I-87 (2026-09-21) — THE MIRROR INVARIANT, RESTATED AGAINST THIS TABLE. The plan's words were "no
# two daemons hold the same mirror in the same second", and a 1 Hz lsof sampler observed ZERO holds
# of any state file at run 126: every state write in this app is tmp-and-replace, so a hold is never
# observable and the invariant as WRITTEN cannot fail — it is satisfied vacuously, and it is not a
# test. What actually separates the two mirror writers is THIS TABLE: the circuit daemon writes
# .monitor_state.json on blade 0 / slot 0 and the Builder writes .noai_state.json on blade 2 /
# slot 4 — opposite blades, SLOTS // 2 slots apart, half a turn of the circumference, which the
# table prints in seconds. So the invariant is tested as a CADENCE claim, by cadence_conflicts() over the rows
# below and by the slot offsets the launch log records, and never by counting file holds.
#
# The circumference: CADENCE_BASE_S is one turn; BLADES daemons are spaced evenly around it, so a
# daemon's phase offset in seconds is blade * CADENCE_BASE_S / BLADES. Opposite blades are
# |delta| == BLADES // 2: circuit <-> cheatsheets, noai_validator <-> dashboard.

CADENCE_BASE_S = 2.5            # one TURN of the circumference = the dashboard slider's fastest stop
SLOTS = 8                       # the circumference is divided into 8 angles of 0.3125 s
BLADES = 4                      # four daemons; opposite daemons are BLADES // 2 apart
DAEMON_BLADE = {"circuit": 0, "noai_validator": 1, "cheatsheets": 2, "dashboard": 3}

# FIX_39's per-directory cadence lives here as a row of this table (the three constants it reads).
CADENCE_FILES_PER_CYCLE = 8         # live .py a directory may carry and still be re-read every cycle
CADENCE_MAX_PERIOD_CYCLES = 240     # 240 * 2.5 s = 600 s = the slider's slow end (10 min)


class Duty:
    """One polled responsibility of one daemon — one fan blade.

    period_cycles / phase  = WHICH turn of the circumference this blade comes round on.
    slot                   = WHERE on the circumference it sits (its angle), 0 .. SLOTS-1.
    """

    __slots__ = ("daemon", "duty", "touches", "period_cycles", "phase", "slot", "note")

    def __init__(self, daemon: str, duty: str, touches: tuple, period_cycles, phase, slot, note: str = ""):
        self.daemon = daemon
        self.duty = duty
        self.touches = touches
        self.period_cycles = period_cycles     # int cycles, or None when the row is a threshold
        self.phase = phase                     # int cycle offset, or None
        self.slot = slot                       # int angle on the circumference, or None
        self.note = note

    @property
    def period_s(self):
        return None if self.period_cycles is None else self.period_cycles * CADENCE_BASE_S

    @property
    def offset_s(self) -> float:
        """The blade's angle in seconds from the top of a turn."""
        return 0.0 if self.slot is None else (self.slot % SLOTS) * CADENCE_BASE_S / SLOTS

    @property
    def blade(self) -> int:
        return DAEMON_BLADE.get(self.daemon, 0)


DUTY_CADENCE = (
    # ── circuit daemon (blade 0) ── slot 0 = the top of every turn
    Duty("circuit", "graph_scan", ("circuit_state.json", ".monitor_state.json"), 1, 0, 0,
         "the AST scan + both writes; FIX_39 puts the per-directory re-read on a cadence under it"),
    Duty("circuit", "dir_rescan", ("target .py",), None, None, 0,
         "FIX_39: period = clamp(1, ceil(files / CADENCE_FILES_PER_CYCLE), CADENCE_MAX_PERIOD_CYCLES) "
         "per directory; the VIEWED directory is period 1; the directory's index is its phase"),
    Duty("circuit", "crc", ("baseline.json",), 8, 0, 0, "tracker — was phase 0 with three others"),
    Duty("circuit", "io", (), 8, 2, 0, "tracker — moved off the spike"),
    Duty("circuit", "mypy", (".mypy_cache",), 8, 4, 0, "tracker — moved off the spike"),
    Duty("circuit", "vulture", (), 8, 6, 0, "tracker — moved off the spike"),
    # ── NOAI validator (blade 1) ── a quarter turn behind the circuit's write it reads
    Duty("noai_validator", "validate", ("NOAI_VALIDATION_STATE.json", "circuit_state.json"), 1, 0, 2,
         "reads circuit_state.json (written at slot 0), writes its own state"),
    Duty("noai_validator", "heartbeat", ("NOAI_VALIDATION_STATE.heartbeat.json",), 4, 1, 2,
         "I-108: 10 s — the poll loop's liveness beat (sidecar, never the state bytes); stale past "
         "HUNG_STATE_S reads hung (FIX_52)"),
    # ── cheatsheets / Builder (blade 2, opposite the circuit daemon) ──
    Duty("cheatsheets", "build", ("BUILDER_STATE.json", ".noai_state.json", "NOAI_VALIDATION_STATE.json"), 1, 0, 4,
         "reads NOAI_VALIDATION_STATE.json (written at slot 2), writes BUILDER_STATE.json + the "
         "counterfeit-code mirror; half a turn from the circuit daemon's mirror write"),
    Duty("cheatsheets", "heartbeat", ("BUILDER_STATE.heartbeat.json",), 4, 1, 4,
         "I-108: 10 s — the poll loop's liveness beat (sidecar, never the state bytes); stale past "
         "HUNG_STATE_S reads hung (FIX_52)"),
    # ── dashboard (blade 3, opposite the NOAI validator) ── the two readers close the circumference
    Duty("dashboard", "circuit_interval",
         ("circuit_state.json", "NOAI_VALIDATION_STATE.json", "BUILDER_STATE.json", "poll_config.json"), 1, 0, 6,
         "the graph frame; read-only, and off the angle of every one of the three writers"),
    Duty("dashboard", "verdict_interval",
         ("NOAI_VALIDATION_STATE.json", "BUILDER_STATE.json"), 1, 0, 7,
         "the panels; read-only, one slot behind the frame so the dash never holds two states at once"),
    Duty("dashboard", "frame_stale_floor", ("circuit_state.json",), None, None, None,
         "I-11 row 1: electricity's floor, 10 s — 'has the frame I am looking at arrived?'"),
    # ── gearbox (the coordinator; not a blade — it polls at 1 s and owns the teardown) ──
    Duty("gearbox", "manifest_scan", ("target mirror files",), 12, 0, 1,
         "30 s: the persisted write manifest (seam R1)"),
    Duty("gearbox", "stale_warn", ("circuit_state.json",), 12, 6, 5,
         "I-11 row 2: 30 s — 'has the circuit daemon gone quiet?'; a different question from the dash's "
         "floor, so a different number BY DESIGN (owner Q6: not a number, a table)"),
    Duty("gearbox", "hung_state", ("child state files",), None, None, None,
         "I-109 row 3: HUNG_STATE_S, 90 s (FIX_52) — 'is a child that is ALIVE and past its gates "
         "still writing the state file it owns?'; a threshold, not a poll, so no period / phase / "
         "slot, and the THIRD of the three declared here — declared, not unified (owner Q6)"),
)

# I-11, declared in one place (the two rows above), never unified.
FRAME_STALE_FLOOR_S = 10.0


def duty(daemon: str, name: str):
    """The row for one duty, or None."""
    for d in DUTY_CADENCE:
        if d.daemon == daemon and d.duty == name:
            return d
    return None


def duty_period_cycles(daemon: str, name: str, default: int = 1) -> int:
    d = duty(daemon, name)
    return default if d is None or d.period_cycles is None else int(d.period_cycles)


def duty_phase(daemon: str, name: str, default: int = 0) -> int:
    d = duty(daemon, name)
    return default if d is None or d.phase is None else int(d.phase)


def due(daemon: str, name: str, n_cycles: int) -> bool:
    """True when this duty's blade tooth passes on cycle n (period + phase from the table)."""
    p = duty_period_cycles(daemon, name)
    return p <= 1 or (int(n_cycles) % p) == (duty_phase(daemon, name) % p)


def duty_slot(daemon: str, name: str, default: int = 0) -> int:
    d = duty(daemon, name)
    return default if d is None or d.slot is None else int(d.slot)


def blade_offset_s(daemon: str, name: str = "") -> float:
    """Where on the circumference this duty sits, in seconds from the top of a turn.

    With no duty name: the daemon's FIRST table row — the offset a daemon sleeps once at start-up so
    its near-non-stop poll lands on its own angle instead of on top of the other three.
    """
    for d in DUTY_CADENCE:
        if d.daemon == daemon and (not name or d.duty == name) and d.slot is not None:
            return d.offset_s
    return 0.0


def dir_period_cycles(n_files: int) -> int:
    """FIX_39's row: a directory's re-read period from its live .py count."""
    n = max(0, int(n_files))
    per = -(-n // CADENCE_FILES_PER_CYCLE)          # ceil division, no float
    if per < 1:
        per = 1
    if per > CADENCE_MAX_PERIOD_CYCLES:
        per = CADENCE_MAX_PERIOD_CYCLES
    return per


def cadence_conflicts() -> list:
    """The four-blade invariant. Empty list = the circumference is filled with no collisions.

    For every PAIR of duties that touch a common file or mirror:
      1. same daemon, same period family → they may not share a phase (they would run back to back);
      2. any pair → they may not sit on the same ANGLE (slot) of the circumference;
      3. where room runs out and two such duties MUST share an angle, they sit on OPPOSITE daemons
         (|delta blade| == BLADES // 2) — the owner's remedy, checked, not assumed.

    I-87 (2026-09-21): this function IS the mirror invariant's test. "No two daemons hold the same
    mirror in the same second" cannot be tested by watching holds — every state write is
    tmp-and-replace and a 1 Hz lsof observes zero holds of any state file, so the words as written
    cannot fail. Restated against the table: the two mirror writers (circuit.graph_scan on
    .monitor_state.json, cheatsheets.build on .noai_state.json) and every other pair that touches a
    common file must differ in ANGLE, and where they cannot, sit on opposite blades. A pair that
    breaks it comes back in this list and is printed at launch; an empty list is the invariant held.
    Rows with no period or no slot (the declared thresholds, I-11's two and I-109's third) are not
    polls and are excluded below.
    """
    out: list = []
    rows = [d for d in DUTY_CADENCE if d.period_cycles is not None and d.slot is not None]
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            shared = set(a.touches) & set(b.touches)
            if not shared:
                continue
            what = ",".join(sorted(shared))
            if a.daemon == b.daemon:
                p = min(a.period_cycles, b.period_cycles)
                if p > 1 and (a.phase % p) == (b.phase % p):
                    out.append(f"same daemon {a.daemon}: {a.duty} and {b.duty} share phase "
                               f"{a.phase % p} (mod {p}) on {what}")
                if (a.slot % SLOTS) == (b.slot % SLOTS):
                    out.append(f"same daemon {a.daemon}: {a.duty} and {b.duty} share slot "
                               f"{a.slot % SLOTS} on {what}")
                continue
            if (a.slot % SLOTS) != (b.slot % SLOTS):
                continue                       # different angles — no collision to remedy
            if a.daemon not in DAEMON_BLADE or b.daemon not in DAEMON_BLADE:
                out.append(f"shared slot {a.slot % SLOTS} with the coordinator: "
                           f"{a.daemon}.{a.duty} and {b.daemon}.{b.duty} on {what}")
            elif abs(a.blade - b.blade) != BLADES // 2:
                out.append(f"shared slot {a.slot % SLOTS} and NOT opposite daemons: "
                           f"{a.daemon}.{a.duty} (blade {a.blade}) and "
                           f"{b.daemon}.{b.duty} (blade {b.blade}) on {what}")
    return out


def format_cadence_table() -> list:
    """The table as printed lines — the launch record of every period and phase in the app."""
    lines = [f"CADENCE TABLE (FIX_46) — one turn {CADENCE_BASE_S:g}s / {SLOTS} slots of "
             f"{CADENCE_BASE_S / SLOTS:.4f}s, {BLADES} blades "
             f"({', '.join(f'{k}={v}' for k, v in DAEMON_BLADE.items())})",
             f"{'daemon':<15} {'duty':<18} {'period':>10} {'phase':>6} {'slot':>5} {'at':>8}  touches"]
    for d in DUTY_CADENCE:
        # a row with no period AND no slot is a declared THRESHOLD, not a poll sized by the tree
        # (I-109): the two read differently and the table says which it is.
        per = ("threshold" if d.slot is None else "by size") if d.period_cycles is None \
            else f"{d.period_cycles}c/{d.period_s:g}s"
        ph = "-" if d.phase is None else str(d.phase)
        sl = "-" if d.slot is None else str(d.slot)
        at = "-" if d.slot is None else f"{d.offset_s:.4f}s"
        lines.append(f"{d.daemon:<15} {d.duty:<18} {per:>10} {ph:>6} {sl:>5} {at:>8}  "
                     f"{','.join(d.touches) or '-'}")
    lines.append(f"{'':<15} {'dir_rescan sizing':<18} {'':>10} {'':>6} {'':>5} {'':>8}  "
                 f"{CADENCE_FILES_PER_CYCLE} files/cycle, cap {CADENCE_MAX_PERIOD_CYCLES} cycles "
                 f"({CADENCE_MAX_PERIOD_CYCLES * CADENCE_BASE_S:g}s)")
    lines.append(f"{'':<15} {'thresholds':<18} {'':>10} {'':>6} {'':>5} {'':>8}  "
                 f"dash frame-stale floor {FRAME_STALE_FLOOR_S:g}s · gearbox stale warn "
                 f"{duty_period_cycles('gearbox', 'stale_warn') * CADENCE_BASE_S:g}s · gearbox hung "
                 f"state {HUNG_STATE_S:g}s — I-11's two and I-109's third, three questions, three "
                 f"rows, all DECLARED HERE and NOT unified (owner Q6)")
    _cw = duty("circuit", "graph_scan")
    _bw = duty("cheatsheets", "build")
    if _cw is not None and _bw is not None:
        lines.append(f"{'':<15} {'I-87 invariant':<18} {'':>10} {'':>6} {'':>5} {'':>8}  "
                     f"mirror writers: circuit.{_cw.duty} (blade {_cw.blade}, slot {_cw.slot}, "
                     f"{_cw.offset_s:.4f}s) vs cheatsheets.{_bw.duty} (blade {_bw.blade}, slot "
                     f"{_bw.slot}, {_bw.offset_s:.4f}s) = {abs(_bw.offset_s - _cw.offset_s):.4f}s "
                     f"apart, opposite blades — every write is tmp+replace, so the separation is "
                     f"THIS TABLE's, tested by CADENCE CONFLICTS below, never by counting file holds")
    conf = cadence_conflicts()
    lines.append("CADENCE CONFLICTS: none" if not conf else
                 "CADENCE CONFLICTS: " + str(len(conf)))
    lines.extend(f"  CONFLICT: {c}" for c in conf)
    return lines


MANIFEST_SCAN_INTERVAL_S = duty_period_cycles("gearbox", "manifest_scan") * CADENCE_BASE_S
STALE_STATE_WARN_S = duty_period_cycles("gearbox", "stale_warn") * CADENCE_BASE_S


_RUN_LOG = None   # R8 / T-19: this run's own file, daemon_log/gearbox_<ts>.log — opened by main()


def open_run_log(ts: str) -> Path | None:
    """R8 / T-19 (2026-09-30): the gearbox's own per-run log, daemon_log/gearbox_<ts>.log (the same
    <name>_<ts>.log form as its children's, pruned by launch.sh's pre-flight), so the startup and the
    teardown can be audited after the terminal is gone. A file that cannot be opened is said once and
    the run goes on — the terminal still carries every line."""
    global _RUN_LOG
    path = LOG_DIR / f"gearbox_{ts}.log"
    try:
        _RUN_LOG = open(path, "a", buffering=1, encoding="utf-8")   # line-buffered: survives a kill
    except OSError as e:
        log(f"own run log not written ({e}) — the terminal is the only record of this run")
        return None
    return path


def log(msg: str) -> None:
    """The gearbox's one voice — the terminal, and (R8 / T-19) its own per-run file once main() opened
    it: daemon_log/gearbox_<ts>.log (each child's output goes to its own daemon_log file). P1/A1: it
    NEVER raises. Once the terminal is gone (SIGHUP, a closed pipe) a write raises OSError; that must
    not abort the caller — log() is the first line of the teardown. The dead stream is swapped for
    /dev/null so the interpreter's exit flush is quiet too; the run log keeps every line regardless."""
    global _RUN_LOG
    line = f"[gearbox {datetime.now().strftime('%H:%M:%S')}] {msg}"
    if _RUN_LOG is not None:
        try:
            _RUN_LOG.write(line + "\n")
        except (OSError, ValueError, RuntimeError):   # disk full / closed file — the terminal still has it
            _RUN_LOG = None
    try:
        print(line, flush=True)
    except (OSError, ValueError):   # ValueError: write to a closed file
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
    except RuntimeError:   # a signal handler's log() landing inside a print ("reentrant call") —
        pass               # one line lost, never a RuntimeError the startup path would mistake for a failure


def get_repo_id(repo_path: Path) -> str:
    """Same scheme as circuit_daemon.get_repo_id (sha256 of resolved path, 12 hex)."""
    return hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:12]


# ── The ONE definition of "up" ───────────────────────────────────────────────

def gate_states() -> dict:
    """Return the four launch-gate states — the single definition of "up".

    The dashboard startup overlay (dark_dropdown) reads the SAME fields from
    the same sources; launcher and overlay must never drift:
      circuit_ready      <- circuit_state.json  daemon_phase in {READY, RUNNING}
      noai_monitoring    <- NOAI_VALIDATION_STATE.json  phase == MONITORING
      builder_monitoring <- BUILDER_STATE.json  phase == MONITORING  (item 1, 2026-09-08)
      dashboard_up       <- HTTP 200 on DASHBOARD_URL (port from copy_ports.json; 8080 in the original)
    Any consumer that needs "is the stack up" consumes these four fields.
    """
    circuit_ready = False
    try:
        state = json.loads(CIRCUIT_STATE.read_text())
        circuit_ready = isinstance(state, dict) and state.get("daemon_phase") in ("READY", "RUNNING")
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    noai_monitoring = False
    try:
        state = json.loads(NOAI_STATE.read_text())
        noai_monitoring = isinstance(state, dict) and state.get("phase") == "MONITORING"
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    builder_monitoring = False
    try:
        state = json.loads(BUILDER_STATE.read_text())
        builder_monitoring = isinstance(state, dict) and state.get("phase") == "MONITORING"
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    dashboard_up = False
    try:
        with urllib.request.urlopen(DASHBOARD_URL, timeout=2) as r:
            dashboard_up = r.status == 200
    except Exception:
        pass

    return {
        "circuit_ready": circuit_ready,
        "noai_monitoring": noai_monitoring,
        "builder_monitoring": builder_monitoring,
        "dashboard_up": dashboard_up,
    }


def wiring_breaks() -> list[tuple[str, str]]:
    """Every node circuit_state.json marks not connected, with the scanner's reason (FIX_36,
    owner 2026-09-10: a wiring warning at launch STOPS the launch and names the node). Read once,
    right after the circuit READY/RUNNING gate — the daemon writes READY with the completed
    scan, so the graph is whole by then. Empty list = every node wired. An unreadable state is
    reported as a break, never as silence."""
    try:
        state = json.loads(CIRCUIT_STATE.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        return [("circuit_state.json", f"unreadable: {type(e).__name__}")]
    if state.get("all_connected") is True:
        return []
    breaks = []
    for n in state.get("nodes", []):
        if n.get("connected") is True:
            continue
        rel = n.get("relative_path") or n.get("name") or "?"
        # FIX_53 (owner Q5 / I-47, 2026-09-17): a file the target ships IN ORDER to be unparsable —
        # a lexer / parser test corpus — is not a wiring break. The scanner already marks it
        # (`syntax_fixture`); the path is consulted here too so a state written by an older daemon
        # is read the same way. Everything else behaves exactly as FIX_36 built it.
        if n.get("syntax_fixture") is True or _syntax_fixture(rel):
            log(f"GATE [circuit WIRING] fixture (expected unparsable, by pattern): {rel}")
            continue
        breaks.append((rel, n.get("import_error") or "not connected"))
    return breaks


def _syntax_fixture(rel: str) -> bool:
    """FIX_53: the ONE definition (scan_scope, rule 15). Unavailable => no fixtures, said out loud."""
    try:
        sys.path.insert(0, str(SCRIPT_DIR))
        import scan_scope
        return bool(scan_scope.syntax_fixture(str(rel).replace("\\", "/")))
    except Exception as e:
        log(f"gearbox: scan_scope unavailable for the syntax-fixture consult ({e!r}) — every break is genuine")
        return False


# ── Leave-no-trace manifest (seam R1) ────────────────────────────────────────

class WriteManifest:
    """Persisted record of every file CodeRadar writes into the target CB.

    Persisted AS WRITES ARE DISCOVERED (30s scan cadence), never only at end,
    so a gearbox crash leaves a record the next pre-flight sweep can use.
    """

    def __init__(self, target: Path, repo_id: str):
        self.target = target
        self.path = SCRIPT_DIR / f"cb_writes_{repo_id}.json"
        self.entries: set[str] = set()
        # Adopt entries from a crashed prior run, if any.
        try:
            prior = json.loads(self.path.read_text())
            self.entries.update(prior.get("entries", []))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def scan_target_for_mirrors(self) -> list[Path]:
        """Live scan of the target tree for CodeRadar mirror dotfiles (contained walk, FIX_15)."""
        found: list[Path] = []
        for root, dirs, files in _walk_contained(self.target):
            for name in files:
                if name in MIRROR_NAMES:
                    found.append(Path(root) / name)
        return found

    def record_scan(self) -> int:
        """Scan target for mirror dotfiles, merge into manifest, persist. Returns new-entry count."""
        found = {str(p) for p in self.scan_target_for_mirrors()}
        new = found - self.entries
        if new:
            self.entries |= new
            self.persist()
        return len(new)

    def persist(self, teardown_verified: bool = False, identity: dict | None = None) -> None:
        payload: dict[str, object] = {
            "target": str(self.target),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "entries": sorted(self.entries),
        }
        if identity is not None:
            # Q-H1-6 / rule 8: the stamp says what was MEASURED — true, false (with the differing
            # files), or NOT MEASURED with the reason. `teardown_verified_at` only on a true verdict.
            payload["teardown_verified"] = (
                teardown_verified if identity.get("status") == "MEASURED" else "NOT MEASURED")
            payload["teardown_identity"] = {k: v for k, v in identity.items() if k != "sides"}
        if teardown_verified:
            payload["teardown_verified_at"] = datetime.now(timezone.utc).isoformat()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(self.path)


def _scan_scope():
    """The ONE scan surface (system_scripts/scan_scope.py, beside this file)."""
    try:
        import scan_scope
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import scan_scope
    return scan_scope


def _walk_contained(target: Path):
    """os.walk over *target* that never descends into a directory that is not CONTAINED
    (FIX_15, owner 2026-09-08): a symlinked dir or one resolving outside the target is pruned
    before descent (`followlinks` stays default-off; this adds the resolve check the plan asks for).
    The engine's own mirror files are the only thing these walks look for."""
    contained = _scan_scope().contained
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if contained(Path(root) / d, target)]
        yield root, dirs, files


def kept_mirrors(target: Path) -> list[str]:
    """Owner ruling 2026-09-28: the two state mirrors (`.noai_state.json` = the counterfeit half of
    the dash, `.monitor_state.json` = the non-counterfeit data-type/wiring half) are logs of the run
    in their own right. They SURVIVE teardown; this lists them (contained walk, FIX_15). Nothing
    else CodeRadar-owned may be in the target (the old delete-sweep was removed, I-196)."""
    return [str(p) for p in _scan_scope().mirror_files(target)]  # the ONE location helper


def cr_residue(target: Path, manifest: "WriteManifest", kept: list[str]) -> list[str]:
    """S4 (2026-09-29): the MEASURED residue — CodeRadar files still in *target* beyond the kept mirrors:
    anything under the mirror dir that is not a kept mirror, any mirror name outside it, and any file the
    manifest recorded this run that is still there and not kept. Target-relative, sorted. Read only."""
    ss = _scan_scope()
    keep = {str(Path(k).resolve()) for k in kept}
    found: set[Path] = set()
    base = target / ss.MIRROR_DIR
    if base.is_dir() and not base.is_symlink():
        found.update(p for p in base.rglob("*") if p.is_file() or p.is_symlink())
    try:
        found.update(manifest.scan_target_for_mirrors())
    except OSError as e:
        log(f"RESIDUE CHECK: target walk failed ({e}) — the residue below may be incomplete")
    found.update(Path(e) for e in manifest.entries if Path(e).exists())
    out = set()
    for p in found:
        if str(p.resolve()) in keep:
            continue
        try:
            out.add(p.relative_to(target).as_posix())
        except ValueError:
            out.add(str(p))
    return sorted(out)


def teardown_identity_check(target: Path, repo_id: str, run_stamp: str) -> dict:
    """RUN_AGAINST_RULES rule 8 (Q-H1-6, 2026-10-01): the teardown's BYTE-IDENTITY against THIS run's
    COPY-FIRST snapshot — `teardown_identity.compare`, the one comparison cr_stop shares. The snapshot is
    the newest `<name>_<stamp>` taken at or after the gearbox's own start stamp (launch.sh takes it after
    starting the gearbox); none → NOT MEASURED. The client's edits are read from the apply lease + the
    confirmed ledger for this repo (Q-H4-4); every differing path is named either way. The record files go
    to .archive/runs/<name>/ beside pyc_verdict.json. Never raises — the teardown goes on."""
    try:
        if str(SCRIPT_DIR) not in sys.path:
            sys.path.insert(0, str(SCRIPT_DIR))
        import teardown_identity as ti
        roots = ti.snapshot_roots(target)
        # M-95 (2026-10-07): the snapshot THIS launch took, by the exact path launch.sh recorded in its progress
        # file ("N files copied to <dir> and verified") — the stamp search missed by one second when launch.sh
        # snapshotted just before the gearbox stamped its start. The stamp search stays as the fallback.
        snap = None
        try:
            import launch_progress as _lp
            _doc = _lp.read(_PROGRESS) if _PROGRESS is not None else {}
            _detail = str(((_doc or {}).get("stages") or {}).get("snapshot", {}).get("detail") or "")
            _m = re.search(r"copied to (\S+) and verified", _detail)
            if _m and Path(_m.group(1)).is_dir() and Path(_m.group(1)).name.startswith(target.name + "_"):
                snap = Path(_m.group(1))
        except Exception as _e:
            log(f"TEARDOWN IDENTITY: launch record unreadable ({type(_e).__name__}) — falling back to the stamp search")
        if snap is None:
            snap = ti.find_snapshot(target.name, roots, not_before=run_stamp)
        result = ti.compare(target, snap, ti.expected_from_ledgers(repo_id, SCRIPT_DIR))
        if snap is None:
            result["reason"] = (f"no COPY-FIRST snapshot of {target.name} taken at or after this run's start "
                                f"({run_stamp}) under {', '.join(str(r) for r in roots)}")
        ti.write_records(PROJECT_ROOT / ".archive" / "runs" / target.name, result)
        result["lines"] = ti.verdict_lines(result)
    except Exception as e:   # a reading that could not be taken says so; it never blocks the teardown
        reason = f"comparison aborted: {type(e).__name__}: {e}"
        result = {"status": "NOT MEASURED", "reason": reason, "snapshot": None, "files_compared": 0,
                  "changed": [], "client_edits": [], "verified": None, "sides": ("", ""),
                  "lines": [f"TEARDOWN IDENTITY: NOT MEASURED — {reason}"]}
    return result


def pycache_residue(target: Path) -> list[str]:
    """__pycache__ dirs under target — NOT deleted (reported as residue only). Contained walk
    (FIX_15); `__pycache__` is an engine hard-skip in scan_scope, so it is looked for directly."""
    contained = _scan_scope().contained
    return [str(p) for p in sorted(target.rglob("__pycache__")) if p.is_dir() and contained(p, target)]


def bytecode_files(target: Path) -> list[str]:
    """I-153 (b)/(c): every compiled-bytecode FILE under *target*, target-relative and sorted.
    Counted, never deleted — the teardown's byte-identity depends on the engine leaving a
    target's own bytes alone, so this is a reading and nothing else. Contained walk (FIX_15)."""
    contained = _scan_scope().contained
    out: list[str] = []
    for pat in ("*.pyc", "*.pyo"):
        for p in target.rglob(pat):
            if p.is_file() and contained(p, target):
                out.append(p.relative_to(target).as_posix())
    return sorted(set(out))


def bytecode_verdict(before: list[str], after: list[str]) -> dict:
    """I-153 (c), owner 2026-09-21 — a VERDICT, not a NOTE. Any bytecode file under the target
    at teardown that the LAUNCH reading did not have means something wrote into the target
    while the run was reading it; that run's suite reading is `not clean` and cannot be used to
    judge a repair. Fewer files than at launch is also declared: the engine deletes none, so a
    disappearance is someone else's hand and the reading is equally unsafe."""
    b, a = set(before), set(after)
    added, removed = sorted(a - b), sorted(b - a)
    polluted = bool(added or removed)
    return {
        "pyc_preexisting": len(b),
        "pyc_at_teardown": len(a),
        "added": added,
        "removed": removed,
        "polluted": "yes" if polluted else "no",
        "suite_reading": "not clean" if polluted else "clean",
    }


def no_bytecode_env(base: dict | None = None) -> dict:
    """I-153 (d), owner 2026-09-21: EVERY subprocess CodeRadar spawns carries
    PYTHONDONTWRITEBYTECODE=1, so no child of the engine can write bytecode into a target it is
    reading. PYTHONPYCACHEPREFIX, when the caller has already set one, is passed through
    untouched — the engine's own cache lives under system_scripts/.cr_pycache."""
    env = dict(os.environ if base is None else base)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def pid_file_write(target: Path, children: list) -> None:
    """B8 / Q-H1-5: the run's process record (PID_FILE) — tmp-and-replace, never raises (a record that
    cannot be written is logged; the run goes on). `children` are the launched Child objects."""
    doc = {
        "gearbox": os.getpid(), "pgid": os.getpgid(0), "launcher": os.getppid(),
        "started": datetime.now(timezone.utc).isoformat(), "target": str(target),
        "children": {c.name: {"pid": c.proc.pid, "pgid": c.proc.pid} for c in children if c.proc is not None},
    }
    try:
        tmp = PID_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2))
        os.replace(tmp, PID_FILE)
    except OSError as e:
        log(f"process record {PID_FILE.name} not written ({type(e).__name__}: {e})")


def pid_file_remove() -> None:
    try:
        PID_FILE.unlink(missing_ok=True)
    except OSError as e:
        log(f"process record {PID_FILE.name} not removed ({type(e).__name__}: {e})")


# ── Child process management ────────────────────────────────────────────────

class Child:
    """A supervised daemon. FIX_21 (2026-09-15): every child carries ITS gate — the same check, timeout
    and state file its gated start uses (the dashboard's gate is also its hang test).
    state_file / phase_key: the state file the child owns and the key its phase lives under
    (circuit_state.json `daemon_phase`, the validator / Builder states `phase`); None for the
    dashboard, whose gate is the HTTP probe (no file to guard)."""

    def __init__(self, name: str, cmd: list[str], gate=None, gate_timeout: float = 0.0,
                 state_file: Path | None = None, phase_key: str = "phase", env: dict | None = None):
        self.name = name
        self.cmd = cmd
        self.env = dict(env or {})   # R8 / T-12: extra environment for THIS child (the dash's TARGET_REPO)
        self.proc: subprocess.Popen | None = None
        self.log_path: Path | None = None
        self.gate = gate or (lambda: True)
        self.gate_timeout = gate_timeout
        self.state_file = state_file
        self.phase_key = phase_key
        self.unhealthy_since: float | None = None   # first tick this child looked hung

    def launch(self, ts: str) -> None:
        self.log_path = LOG_DIR / f"{self.name}_{ts}.log"
        log_file = open(self.log_path, "a")
        self.proc = subprocess.Popen(
            self.cmd, stdout=log_file, stderr=subprocess.STDOUT,
            cwd=str(PROJECT_ROOT),
            env=no_bytecode_env() | self.env,   # I-153 (d): no child of the engine writes bytecode (+ this child's extras)
            # B8 / Q-H1-4 (2026-10-01): every child leads its own process group (pgid == its pid), so the
            # teardown can signal the GROUP — the circuit daemon's running mypy/vulture, the tracers — and
            # not only the daemon. A daemon SIGKILLed after the grace left its subprocess.run child alive.
            start_new_session=True,
        )
        log_file.close()  # child inherited the fd

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def pid(self) -> int:
        """The running PID, or -1 when there is no process (a child is always launched before it is
        logged; the fallback keeps the log line honest rather than raising inside it)."""
        return self.proc.pid if self.proc is not None else -1

    def exit_code(self):
        return self.proc.returncode if self.proc is not None else None

    def log_name(self) -> str:
        return self.log_path.name if self.log_path is not None else "(no log)"


class RunEvents:
    """The run's own feed, system_scripts/gearbox_events.json — engine-side, NOT a mirror, never in the
    target. Created at start with `run_started` (the MCP's cr_hand_back reads it), deleted at teardown.
    S4 (owner 2026-09-29): with restarts gone, `events` stays empty; `stopped` carries the one line a
    daemon failure stops the run with, and `failure` its record — the dash's band shows both."""

    def __init__(self, path: Path, run_started: str):
        self.path = path
        self.doc: dict = {"run_started": run_started, "events": [], "stopped": None, "failure": None}
        self.write()

    def write(self) -> None:
        try:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.doc, indent=2))
            tmp.replace(self.path)
        except OSError as e:
            log(f"run events: could not write {self.path.name} ({e}) — the band will not show it")

    def failed(self, failure: dict) -> None:
        self.doc["failure"] = failure
        self.doc["stopped"] = f"{failure['daemon']} {failure['reason']} — the run stopped"
        self.write()

    def remove(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def proc_state(pid: int) -> str:
    """The OS's own process state letter: `T` stopped (SIGSTOP), `Z` zombie, `R`/`S`/`I`/`U` running
    or sleeping, `""` when it cannot be read. macOS and Linux both answer `ps -o state=`."""
    try:
        r = subprocess.run(["ps", "-o", "state=", "-p", str(pid)],
                           capture_output=True, text=True, timeout=5)
        return (r.stdout.strip()[:1] or "")
    except Exception:
        return ""


def hang_reason(c: Child, now: float) -> str | None:
    """FIX_52 (I-12, owner Q13 — "a 4-cylinder car running on 3 goes to the shop"): why this ALIVE
    child is hung, or None. Called ONLY from the supervision loop, i.e. after ALL GATES PASSED, so a
    slow first scan is never read as a hang.

    Two signals, both sound — a state file's mtime is deliberately NOT one of them:

    1. **The OS's process state.** `T` (SIGSTOP'd — I-12's exact case: "Gearbox does not respawn a
       `kill -STOP`ped (not dead) child") or `Z` (zombie, reaped by nobody) is hung at once, with no
       clock: the process cannot be doing its work in either state.
    2. **The state file it owns, for the circuit daemon ONLY.** The circuit daemon rewrites
       `circuit_state.json` every ping — that is the assumption the existing STALE_STATE_WARN_S
       warning already rests on — so an unwritten state IS a stall there. The VALIDATOR and the
       BUILDER write their state **on change** (`NOAI_VALIDATOR_DAEMON` re-writes from
       `stage_output`; `BUILDER_DAEMON._read_validator_state` returns early on unchanged bytes), so a
       quiet tree legitimately leaves their mtimes old and an mtime test there would restart a
       healthy daemon — a false hang now ENDS the run (S4). Recorded as a fact for the owner rather than
       papered over.
    3. **The dashboard** owns no state file: its liveness is the HTTP gate, so it is hung when that
       gate has been failing continuously for HUNG_STATE_S (`unhealthy_since` keeps the clock)."""
    proc = c.proc
    if proc is None or not c.alive():
        return None
    st = proc_state(proc.pid)
    if st == "T":
        return "hung (process STOPPED)"
    if st == "Z":
        return "hung (process is a zombie)"
    if c.state_file is None:
        if c.gate():
            c.unhealthy_since = None
            return None
        if c.unhealthy_since is None:
            c.unhealthy_since = now
            return None
        age = now - c.unhealthy_since
        return f"hung (gate failing for {age:.0f}s)" if age >= HUNG_STATE_S else None
    if c.state_file is not CIRCUIT_STATE:
        # I-108: the validator / Builder state is written on change (2 above) — their HEARTBEAT is not.
        # A beat not yet written by THIS process is not judged (the gate already passed, and the
        # state mtime still never is); the first beat is written before the first poll.
        hb_age = heartbeat_age(c.state_file, pid=proc.pid)
        if hb_age is not None and hb_age >= HUNG_STATE_S:
            return f"hung (no heartbeat for {hb_age:.0f}s)"
        return None
    try:
        age = time.time() - c.state_file.stat().st_mtime
    except OSError:
        return None   # a missing state file is the stale WARNING's business, not a hang
    # owner 2026-09-28: the circuit daemon writes once per poll, and the poll now goes to 10 min — a
    # fixed 90 s read every rate above it as a hang (it restarted then; since S4 it would end the run). The
    # limit is the poll interval plus the old 90 s of slack.
    limit = HUNG_STATE_S + _poll_interval_s()
    return f"hung (no state write for {age:.0f}s)" if age >= limit else None


def _exit_how(code) -> str:
    """'exit code 1' / 'killed by SIGKILL' — Popen reports a signal death as a negative returncode."""
    if code is None:
        return "exited (code unknown)"
    if code < 0:
        try:
            return f"killed by {signal.Signals(-code).name}"
        except ValueError:
            return f"killed by signal {-code}"
    return f"exited (exit code {code})"


def log_tail(path: Path | None, n: int = 12) -> list[str]:
    """The last *n* lines of a daemon's log — the failure panel and the terminal show them."""
    if path is None:
        return []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as e:
        return [f"(log unreadable: {e})"]
    return lines[len(lines) - min(n, len(lines)):]


def daemon_failure(c: Child, reason: str) -> dict:
    """S4 (owner 2026-09-29): a daemon died or hung — the record the run stops on: which daemon, why, and
    the end of its log. Written to the run feed, the progress file, the tester report and the terminal."""
    return {"daemon": c.name, "reason": reason, "pid": c.pid(), "log": c.log_name(),
            "log_tail": log_tail(c.log_path), "at": datetime.now(timezone.utc).isoformat()}


class DaemonFailure(Exception):
    """S4: raised by the supervision loop when a daemon died or hung; carries daemon_failure()'s record."""

    def __init__(self, failure: dict):
        super().__init__(f"{failure['daemon']} {failure['reason']}")
        self.failure = failure


def _report_daemon_failure(failure: dict) -> None:
    """The terminal says what the dash's panel says, at once and plainly."""
    log("=" * 72)
    log(f"DAEMON FAILURE — {failure['daemon']} {failure['reason']}. The run stopped: nothing is restarted,")
    log("and what this run produced is NOT trustworthy (the tester report and verdict say so).")
    log(f"last lines of {failure.get('log') or 'its log'}:")
    for ln in failure.get("log_tail") or ["(no log lines)"]:
        log(f"  | {ln}")
    log("=" * 72)


def _hold_dash_until_ctrl_c(dashboard: Child, why: str) -> None:
    """Keep the dash up until Ctrl-C so a failure can be read — but never wait on a dash that died
    (the wait used to spin forever; now it notices, says so and lets the teardown run)."""
    if not dashboard.alive():
        log("the dashboard is not running — nothing to hold open; tearing down")
        return
    log(why)
    while not _shutdown_requested:
        if CLOSE_REQUEST.exists():   # the overlay's buttons; launch.sh reads which one after the teardown
            log(f"close requested from the overlay ({CLOSE_REQUEST.read_text().strip()}) — tearing down")
            return
        if not dashboard.alive():
            log(f"the dashboard {_exit_how(dashboard.exit_code())} while holding the failure open — tearing down")
            return
        time.sleep(0.5)


def _signal_group(pid: int, sig: int) -> bool:
    """B8 / Q-H1-4: signal the child's whole process group (Child.launch gives it one: pgid == pid), falling
    back to the pid alone when it leads no group. False when nothing of it is left to signal."""
    try:
        os.killpg(pid, sig)
        return True
    except ProcessLookupError:   # no group led by this pid — a live loner (C3 / D1 2026-10-01) or a dead pid
        pass                     # … the pid branch tells them apart: it answers False only when the pid is gone
    except PermissionError:   # a member the engine may not signal — the pid itself is still ours
        pass
    try:
        os.kill(pid, sig)
        return True
    except OSError:
        return False


def terminate_children(children: list[Child]) -> list[str]:
    """SIGTERM all children; circuit daemon (and any holdout) escalates to
    SIGKILL after SIGTERM_GRACE_S (boot-test failure item 12). Returns summary lines.
    B8 / Q-H1-4 (2026-10-01): every signal goes to the child's PROCESS GROUP, so a daemon's own
    subprocesses (the circuit daemon's mypy / vulture, a tracer) stop with it; after the child is
    reaped, whatever is still in its group is SIGKILLed and said so — nothing of a daemon outlives it."""
    lines = []
    for c in children:
        if c.alive() and c.proc is not None:
            _signal_group(c.proc.pid, signal.SIGTERM)
    for c in children:
        if c.proc is None:
            continue
        how = "SIGTERM"
        try:
            c.proc.wait(timeout=SIGTERM_GRACE_S)
        except subprocess.TimeoutExpired:
            _signal_group(c.proc.pid, signal.SIGKILL)
            c.proc.kill()
            c.proc.wait()
            how = f"SIGTERM ignored -> SIGKILL after {SIGTERM_GRACE_S:.0f}s"
        stragglers = ""
        if _signal_group(c.proc.pid, signal.SIGKILL):   # the child is reaped: anything left is its orphan
            stragglers = "; its process group still had members — SIGKILLed with it"
        lines.append(f"  {c.name}: stopped ({how}), exit code {c.proc.returncode}{stragglers}")
    return lines


# ── Gates ────────────────────────────────────────────────────────────────────

def wait_gate(name: str, check, timeout: float, child: Child | None = None,
              poll: float = 0.5) -> bool:
    """Poll check() until True/timeout. Logs PASS/FAIL with timing.
    Fail-fast if the gated child process has exited."""
    log(f"GATE [{name}] waiting (timeout {timeout:.0f}s)...")
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if _shutdown_requested:
            log(f"GATE [{name}] ABORTED by shutdown request after {time.monotonic()-t0:.1f}s")
            return False
        if child is not None and not child.alive():
            log(f"GATE [{name}] FAIL-FAST after {time.monotonic()-t0:.1f}s — "
                f"{child.name} exited (code {child.exit_code()}), log: {child.log_path}")
            return False
        try:
            ok = check()
        except Exception:
            ok = False
        if ok:
            log(f"GATE [{name}] PASS in {time.monotonic()-t0:.1f}s")
            return True
        time.sleep(poll)
    log(f"GATE [{name}] TIMEOUT after {timeout:.0f}s")
    return False


def await_startup(name: str, child: Child, what: str) -> None:
    """P1/A2 (S4 policy — a daemon that crashes cannot be trusted): run a started child's startup gate.
    A child that DIED during its gate stops the run exactly as a death under supervision does — a
    DaemonFailure with the record (daemon, reason, log tail), run_trusted false. Anything else that fails
    the gate (timeout, a shutdown request) keeps the plain startup-failure path (RuntimeError `what`)."""
    if wait_gate(name, child.gate, child.gate_timeout, child=child):
        return
    if not _shutdown_requested and child.proc is not None and not child.alive():
        raise DaemonFailure(daemon_failure(child, f"{_exit_how(child.exit_code())} during its startup gate"))
    raise RuntimeError(what)


# ── The confirmed ledger (S4-3, ruling Q1(a) of 2026-09-17) ──────────────────
#
# Run 141's fact: a repair that WORKS removes its own row, so by the Builder's next poll
# nothing sits at that digest+span and every `confirmed` line orphans — all 7 of them, while
# all 7 `failed` lines joined. The ledger is the second record `cr_report_outcome` writes on a
# `confirmed` verdict: the row's identity BEFORE the repair, in a file beside the channel.
# Nothing polls it and nothing here re-decides — the row is gone, the Ranker has no work. Only
# the report writer reads it, so a confirmation the channel can no longer join is still counted.

def confirmed_ledger_path(channel: Path) -> Path:
    """The ledger beside a channel. The naming rule is one rule, mirrored by the writer
    (`coderadar_mcp.write_tools._ledger_path`): same directory, the channel's own name with
    `return_channel_` swapped for `confirmed_ledger_`."""
    return channel.with_name("confirmed_ledger_" + channel.name.removeprefix("return_channel_"))


def read_confirmed_ledger(path: Path) -> dict:
    """The ledger as {(digest, replace_span): record}. Append-only and the LAST record per key
    wins, mirroring the channel's own `matching[-1]`. A record without both halves of the key is
    not the contract and is left out (it can join nothing either way)."""
    out: dict = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            rec = _jsonl_record(line)
            digest, span = rec.get("digest"), rec.get("replace_span")
            if isinstance(digest, str) and digest and isinstance(span, str) and span:
                out[(digest, span)] = rec
    return out


def apply_lease_path(channel: Path) -> Path:
    """The APPLY LEASE beside a channel (session 7, packet §C.1). The naming rule is one rule,
    mirrored by the writer (`coderadar_mcp.write_tools._lease_path`): same directory, the
    channel's own name with `return_channel_` swapped for `apply_lease_`."""
    return channel.with_name("apply_lease_" + channel.name.removeprefix("return_channel_"))


def read_apply_lease(path: Path) -> dict:
    """The lease as {row_key: record}. Append-only and the LAST record per `row_key` wins,
    mirroring the channel's own `matching[-1]` and the ledger's. It is the server's memory of
    what `cr_apply` handed out, and it is what lets a line whose row has been RETIRED be told
    apart from a line that never named a row at all (I-138)."""
    out: dict = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            rec = _jsonl_record(line)
            key = rec.get("row_key")
            if isinstance(key, str) and key and rec.get("digest"):
                out[key] = rec
    return out


def _jsonl_record(line: str) -> dict:
    """One line of a .jsonl as a dict — `{}` for a blank line or anything that is not the
    contract, which is what `BuilderDaemon._parse_channel_line` does with a line it cannot
    read: nothing is dropped silently, and nothing that is not an object is believed."""
    text = line.strip()
    doc: object = None
    if text:
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            doc = None
    return doc if isinstance(doc, dict) else {}


def _channel_keys(channel: Path, rows: dict, leased: set | None = None) -> tuple[list, list]:
    """Every channel line as (digest, replace_span), and the ones that joined NO row —
    the same join `BuilderDaemon._join_channel` does: a line joins a row when the span is the
    row's and the digest is the row's current one OR one of its `tester=failed:<digest>`
    evidence tokens. Recomputed here rather than trusted from the summary, because the orphan
    count is what the ledger corrects and the correction has to name the lines it covers.

    Session 7 (I-138, run 158 launch A): a line naming a LEASED `row_key` that is no longer a
    live key reports a RETIRED row — the repair removed its own row, which is the success case —
    and is not unjoined in the sense the orphan count means. `BuilderDaemon._join_channel` makes
    the same distinction under the same rule, so the Builder's count and the report's cannot
    disagree. `leased` is read from the lease beside the channel; a channel with no lease file —
    every channel written before session 7, and every archived one replayed since — counts
    exactly as it always did."""
    keys: list = []
    retired: set = set()
    live = set(rows or {})
    held = leased if leased is not None else set(read_apply_lease(apply_lease_path(channel)))
    if channel.exists():
        for line in channel.read_text(encoding="utf-8", errors="replace").splitlines():
            doc = _jsonl_record(line)
            digest, span = doc.get("digest"), doc.get("replace_span")
            row_key = doc.get("row_key")
            if isinstance(digest, str) and digest and isinstance(span, str) and span:
                keys.append((digest, span))
                if (isinstance(row_key, str) and row_key and row_key in held
                        and row_key not in live):
                    retired.add((digest, span))
    known: set = set()
    for row in rows.values():
        span = row.get("replace_span")
        digests = [row.get("digest")] + [
            e[len("tester=failed:"):] for e in (row.get("rca_evidence") or [])
            if isinstance(e, str) and e.startswith("tester=failed:")]
        for d in digests:
            if d and span:
                known.add((d, span))
    return keys, [k for k in keys if k not in known and k not in retired]


# ── B9 — the per-rule accumulation (ruling Q3, 2026-09-20) ───────────────────
#
# P1's pinned question, ruled now that confirmations exist to look at (run 144's ledger, run 149's
# nine, run 151's three): a tester outcome accumulates PER RULE as well as per infraction. One
# block, `summary.rule_outcomes`, derived from the two files that already exist — the confirmed
# ledger and the return channel — and published by the counterfeit-code mirror's ONE writer
# (`BUILDER_DAEMON.stage_mirror`) each cycle. `cr_status` reads it; the tester report carries it.
#
#     {"<rule id>": {"confirmed_for": n, "failed_against": {"<variant>": n}}}
#
# The asymmetry IS the ruling. A `confirmed` counts FOR every rule id the ledger record carries —
# the record is the row's pre-repair identity, and the repair answered all of them. A `failed`
# counts against the repair VARIANT the Ranker picked (`decision.pick_role`), never against the
# rule: P1's open question underneath is that a repair that did not work says nothing about
# whether the infraction was real. So a rule can carry `confirmed_for 1` and a `failed_against`
# entry at the same time, and the second never subtracts from the first.
#
# Nothing here moves a disposition. `rule_dispositions.json` is untouched — this is a published
# record only, and the step-18 REPORT → FAIL flip is deferred (Q3).

#: The variant (or the rule) of a `failed` line whose row the state no longer carries, so neither
#: can be named. Recorded rather than dropped: the line is a fact even when its row is gone.
RULE_OUTCOMES_UNKNOWN = "?"


def _failed_identities(channel: Path, rows: dict) -> list:
    """Every `failed` line of the channel as (rule id, variant) pairs, by the join
    `BuilderDaemon._join_channel` already makes: the span is the row's and the digest is the row's
    current one OR one of its `tester=failed:<digest>` evidence tokens. Append-only, so the LAST
    line per (digest, span) decides — the channel's own `matching[-1]` rule, spelled here for the
    same reason the ledger spells it. A line whose row is gone is counted under `?`/`?`.

    Q1 / I-122 (session 7, the drift fix): the LINE'S OWN `rule_ids` and `variant` are read
    FIRST, the row's second, `?` only when neither has them. That is the whole of I-122 — the
    variant lived in exactly one place, the row's `decision.pick_role`, and a failed row is
    re-decided in the SAME cycle its line arrives: the repair that failed becomes unpickable,
    the row turns `ranker_none`, and by the next mirror write the variant is nowhere. Eleven of
    run 153's fourteen rules read `failed_against {"?": 1}` for that reason. A line written
    before session 7 carries neither field and still falls through to the row and then to `?`,
    so an archived channel replays EXACTLY as it did.
    The row is also looked up by `(file, function)` when the row has been RE-KEYED under the
    line (the line's `row_key` is no longer a live key) — the same widening `_join_channel`
    makes, under the same guard, for the same reason."""
    latest: dict = {}
    order: list = []
    if channel.exists():
        for line in channel.read_text(encoding="utf-8", errors="replace").splitlines():
            doc = _jsonl_record(line)
            digest, span = doc.get("digest"), doc.get("replace_span")
            if isinstance(digest, str) and digest and isinstance(span, str) and span:
                key = (digest, span)
                if key not in latest:
                    order.append(key)
                latest[key] = doc
    identities: dict = {}
    by_place: dict = {}
    live_keys = set(rows or {})
    for key, row in (rows or {}).items():
        # No guard clause here: a `if not span: continue` is a pre-ranker hunter site (V18), so the
        # span is tested where it is USED, in the one condition below (S4-3's cut, same reason).
        span = row.get("replace_span")
        ids = [r for r in (row.get("rule_ids_all") or row.get("rule_ids") or [])
               if isinstance(r, str) and r]
        # The name of the repair that was tried: the Ranker's pick, `<family>:<variant>` for a
        # rewriter and `solution_<RULE>` for a prescribed shape. The mirror publishes the same
        # string as `selected_role`, which is what an offline fixture built from a mirror carries.
        pick = (row.get("decision") or {}).get("pick_role") or row.get("selected_role") or ""
        digests = [row.get("digest")] + [
            e[len("tester=failed:"):] for e in (row.get("rca_evidence") or [])
            if isinstance(e, str) and e.startswith("tester=failed:")]
        for d in digests:
            if d and span:
                identities[(d, span)] = (ids, str(pick) or RULE_OUTCOMES_UNKNOWN)
            if d and row.get("file"):
                by_place[(d, str(row.get("file")), str(row.get("function") or ""))] = (
                    ids, str(pick) or RULE_OUTCOMES_UNKNOWN)
    pairs: list = []
    for key in order:
        doc = latest[key]
        if doc.get("outcome") != "failed":
            continue
        # The (file, function) fallback is guarded exactly as `_join_channel`'s is: it fires
        # only for a line whose own `row_key` is no longer a live key — the row was re-keyed
        # under it. A line naming a span its own live row never had stays an orphan (I-138).
        line_key = str(doc.get("row_key") or "")
        place = ((key[0], str(doc.get("file") or ""), str(doc.get("function") or ""))
                 if line_key and line_key not in live_keys else None)
        row_ids, row_variant = (identities.get(key)
                                or (by_place.get(place) if place else None)
                                or ([], RULE_OUTCOMES_UNKNOWN))
        line_ids = [r for r in (doc.get("rule_ids") or []) if isinstance(r, str) and r]
        line_variant = str(doc.get("variant") or "")
        ids = line_ids or row_ids
        variant = line_variant or row_variant or RULE_OUTCOMES_UNKNOWN
        for rule_id in ids or [RULE_OUTCOMES_UNKNOWN]:
            pairs.append((rule_id, variant))
    return pairs


def rule_outcomes(rows: dict, channel: Path, ledger: Path | None = None) -> dict:
    """B9's block: what the tester has said about each rule, accumulated over the whole ledger and
    the whole channel. The ledger is never pruned (S4-3), so the counts are derived every time and
    the file grows — nothing here writes either file, and nothing re-decides a row."""
    ledger = ledger if ledger is not None else confirmed_ledger_path(channel)
    out: dict = {}

    def entry(rule_id: str) -> dict:
        return out.setdefault(str(rule_id), {"confirmed_for": 0, "failed_against": {}})

    for rec in read_confirmed_ledger(ledger).values():
        ids = [r for r in (rec.get("rule_ids") or []) if isinstance(r, str) and r]
        for rule_id in ids or [RULE_OUTCOMES_UNKNOWN]:
            entry(rule_id)["confirmed_for"] += 1
    for rule_id, variant in _failed_identities(channel, rows):
        against = entry(rule_id)["failed_against"]
        against[variant] = against.get(variant, 0) + 1
    return {rule_id: {"confirmed_for": rec["confirmed_for"],
                      "failed_against": dict(sorted(rec["failed_against"].items()))}
            for rule_id, rec in sorted(out.items())}


# ── Main ─────────────────────────────────────────────────────────────────────

def write_tester_report(target: Path, repo_id: str, run_started: str, *,
                        builder_state: Path | None = None, channel: Path | None = None,
                        out_dir: Path | None = None, ledger: Path | None = None,
                        daemon_failure: dict | None = None) -> dict:
    """Item 6 (2026-09-09): the tester's report — the second half of the scan report — written
    at teardown from BUILDER_STATE.json + the return channel into
    .archive/runs/<target basename>/tester_report.json, the channel copied beside it.
    The measure (owner 2026-09-09): infractions, solutions, confirmed, and confirmed_fraction =
    confirmed / solutions, null when solutions == 0 (never 0.0); per infraction whether the tester
    confirmed its solution — no failure kinds. I-14 (2026-09-15): null ALSO while no tester has run
    (`tester_ran` = a return-channel line exists, or summary.tester counts channel lines) — 0.0 is
    only ever "the tester ran and confirmed nothing", never "not measured". A read failure yields status "NOT MEASURED" and the
    exception text. Returns the report.
    S4-3 (ruling Q1(a), 2026-09-17), additive keys only: `confirmed` is now the channel-joined
    confirmations PLUS the ones only `confirmed_ledger_<repo_id>.jsonl` still knows (a repair that
    works removes its own row, so its `confirmed` line can join nothing — run 141, all 7 orphaned);
    `confirmed_joined` keeps the pre-ledger number, `confirmed_from_ledger` and
    `confirmed_ledger_rows` say what the ledger added, `confirmed_ledger` where it is, and
    `orphans` now counts only lines that neither joined NOR have a ledger record, the Builder's own
    count riding beside it as `orphans_channel`. The ledger is copied beside the channel into
    `state_during_run/`.
    B9 (ruling Q3, 2026-09-20), one additive key: `rule_outcomes`, the same block the counterfeit-code
    mirror publishes as `summary.rule_outcomes` — the same function over the same two files, so the
    report and the mirror cannot disagree.
    S4 (owner 2026-09-29), two additive keys: `run_trusted` is False and `daemon_failure` carries the
    record when the run ended on a daemon that died or hung — its outputs are not trustworthy."""
    builder_state = builder_state or BUILDER_STATE
    channel = channel or (SCRIPT_DIR / f"return_channel_{repo_id}.jsonl")
    ledger = ledger or confirmed_ledger_path(channel)
    out_dir = out_dir or (PROJECT_ROOT / ".archive" / "runs" / target.name)
    run_dir = out_dir / "state_during_run"
    report: dict = {
        "target": str(target), "repo_id": repo_id, "run_started": run_started,
        "run_ended": datetime.now(timezone.utc).isoformat(),
        "builder_cycles": None, "infractions": None, "solutions": None, "confirmed": None,
        "status": "NOT MEASURED", "confirmed_fraction": None, "tester_ran": False, "per_infraction": [],
        "return_channel_lines": 0, "return_channel": str(channel), "builder_state_sha256": None,
        "confirmed_joined": 0, "confirmed_from_ledger": 0, "confirmed_ledger_rows": [],
        "confirmed_ledger": str(ledger),
        "rule_outcomes": {},
        "run_trusted": daemon_failure is None, "daemon_failure": daemon_failure,
    }
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        if ledger.exists():
            shutil.copy2(ledger, run_dir / "confirmed_ledger.jsonl")
        if channel.exists():
            shutil.copy2(channel, run_dir / "return_channel.jsonl")
            report["return_channel_lines"] = sum(
                1 for ln in channel.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
        raw = builder_state.read_bytes()
        report["builder_state_sha256"] = hashlib.sha256(raw).hexdigest()
        state = json.loads(raw)
        summary = state.get("summary") or {}
        tester = summary.get("tester")
        if not isinstance(tester, dict):
            raise ValueError("BUILDER_STATE.json carries no summary.tester")
        solutions = int(summary.get("with_fix") or 0)
        joined = int(tester.get("confirmed") or 0)
        rows_now = state.get("rows") or {}
        # Q1(a): the confirmations the channel could not join, carried by the ledger instead.
        # A ledger record is counted only when the state does NOT already carry that confirmation
        # on a row (the same (digest, replace_span) key), so nothing is counted twice.
        led = read_confirmed_ledger(ledger)
        already = {(r.get("digest"), r.get("replace_span")) for r in rows_now.values()
                   if (r.get("tester") or {}).get("confirmed")}
        from_ledger = [rec for key, rec in led.items() if key not in already]
        confirmed = joined + len(from_ledger)
        # MCPW-D O3 (run 180): `with_fix` counts only the rows still LIVE with a digest, while a
        # repair that works retires its own row — so its ledger confirmation had no seat in the
        # denominator (arrow: 1 solution, 2 confirmed, fraction 2.0). The solutions offered are the
        # live ones PLUS every ledger-confirmed (digest, replace_span) no live row carries; now
        # numerator and denominator count the same population and the fraction is <= 1.
        live_keys = {(r.get("digest"), r.get("replace_span")) for r in rows_now.values()
                     if r.get("digest")}
        solutions_retired = sum(1 for key in led if key not in live_keys)
        # A solution the tester FAILED whose row no longer carries it (withdrawn) was offered too.
        failed_keys: set = set()
        if channel.exists():
            for ln in channel.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    doc = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(doc, dict) and doc.get("outcome") == "failed" and doc.get("digest"):
                    failed_keys.add((doc.get("digest"), doc.get("replace_span")))
        solutions_withdrawn = sum(1 for k in failed_keys if k not in live_keys and k not in led)
        solutions_live = solutions
        solutions = solutions_live + solutions_retired + solutions_withdrawn
        # An orphan is a line that matched no row, does not name a row the Builder has since
        # RETIRED (session 7, I-138 — `_channel_keys`), AND that the ledger does not account for.
        _keys, unjoined = _channel_keys(channel, rows_now)
        orphans = sum(1 for k in unjoined if k not in led)
        # I-14: the tester has run when its channel carries a line (copied above) or the Builder counted one.
        tester_ran = (bool(report["return_channel_lines"]) or bool(int(tester.get("channel_lines") or 0))
                      or bool(led))
        report.update({
            "builder_cycles": state.get("cycle"),
            "infractions": summary.get("findings"),
            "solutions": solutions,
            "solutions_live": solutions_live,
            "solutions_retired_confirmed": solutions_retired,
            "solutions_withdrawn_failed": solutions_withdrawn,
            # MCPW-D O4a: `infractions` is the rows LIVE at teardown; a confirmed repair retires its
            # row, so a mid-run cr_infractions total is higher by exactly those (run 180: 65 + 2 = 67).
            "infractions_retired_confirmed": solutions_retired,
            "infractions_seen": (int(summary.get("findings") or 0) + solutions_retired),
            "confirmed": confirmed,
            "confirmed_joined": joined,
            "confirmed_from_ledger": len(from_ledger),
            "confirmed_ledger_rows": from_ledger,
            "status": "MEASURED",
            "tester_ran": tester_ran,
            "confirmed_fraction": (confirmed / solutions) if (solutions and tester_ran) else None,
            "orphans": orphans, "orphans_channel": int(tester.get("orphans") or 0),
            "unparsed": int(tester.get("unparsed") or 0),
            # B9 (Q3): the per-rule record, derived here from the same ledger and channel the
            # mirror writer derives it from, over the state's rows as they stand at teardown.
            "rule_outcomes": rule_outcomes(rows_now, channel, ledger),
            "per_infraction": [
                {"file": r.get("file"), "function": r.get("function"), "line": r.get("line"),
                 "rule_ids": r.get("rule_ids"), "digest": r.get("digest"),
                 "confirmed": bool((r.get("tester") or {}).get("confirmed"))}
                for r in sorted((state.get("rows") or {}).values(), key=lambda r: (r.get("fix_order", 0), r.get("file", ""), r.get("line", 0)))
                if not r.get("exonerated")
            ],
        })
    except Exception as e:  # never blocks the teardown; the report says what it could not measure
        report["status"] = "NOT MEASURED"
        report["error"] = f"{type(e).__name__}: {e}"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "tester_report.json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    except Exception as e:
        report["write_error"] = f"{type(e).__name__}: {e}"
    return report


# owner 2026-09-29: every step of the opening sequence has its own mention and light on the overlay.
# launch.sh starts the gearbox with `--staged <launch_progress.json>` BEFORE its own target steps
# (snapshot, health check, whitelist scan, target env); the gearbox brings the dash up, waits for those
# steps, then records its own (gearbox, dashboard, circuit, wiring, noai, solutions) in the same file.
_PROGRESS: Path | None = None
_OPEN_TAB: bool = True   # False under --setup-tab: the setup page's tab is already on its way to the dashboard
_PROGRESS_CUR: str = ""


def _progress(stage: str, status: str, detail: str = "", started: float | None = None) -> None:
    """One step's status into launch_progress.json. launch.sh writes the same file at the same time, so
    the write goes through launch_progress.update (locked read-modify-write; never raises)."""
    global _PROGRESS_CUR
    if _PROGRESS is None:
        return
    import launch_progress
    if stage != "-":
        if status == "running":
            _PROGRESS_CUR = stage
        elif stage == _PROGRESS_CUR:
            _PROGRESS_CUR = ""
    launch_progress.update(_PROGRESS, stage, status, detail, started=started, create=False)


def _progress_launch_steps() -> str:
    """Wait for launch.sh's own steps: 'done', 'failed', 'interrupted' (a stop request — launch.sh's record,
    or this gearbox's own signal; B8 / Q-H1-9), or 'orphaned' (launch.sh gone without a word)."""
    while not _shutdown_requested:
        try:
            overall = json.loads(_PROGRESS.read_text()).get("overall") if _PROGRESS else "done"
        except Exception:
            overall = None
        if overall in ("done", "failed", "interrupted"):
            return overall
        if os.getppid() == 1:
            return "orphaned"
        time.sleep(0.25)
    return "interrupted"


def main() -> int:
    global _shutdown_requested, _PROGRESS, _OPEN_TAB

    _t_main = time.time()
    args = sys.argv[1:]
    # owner 2026-09-30: --setup-tab = launched from the setup page, whose tab turns into the dashboard by itself
    _OPEN_TAB = "--setup-tab" not in args
    args = [a for a in args if a != "--setup-tab"]
    if len(args) == 3 and args[1] == "--staged":
        _PROGRESS = Path(args[2]).resolve()
        args = args[:1]
    if len(args) != 1:
        print("usage: gearbox.py /path/to/target [--staged launch_progress.json] [--setup-tab]", file=sys.stderr)
        return 2
    target = Path(args[0]).resolve()
    if not target.is_dir():
        print(f"gearbox: target is not a directory: {target}", file=sys.stderr)
        return 2

    repo_id = get_repo_id(target)
    LOG_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_started = datetime.now(timezone.utc).isoformat()  # item 6: tester_report.run_started
    _run_log_path = open_run_log(ts)   # R8 / T-19: every log() line from here on is also in this file

    log(f"target={target}  repo_id={repo_id}  python={sys.executable}"
        + (f"  run_log={_run_log_path}" if _run_log_path else ""))

    # I-153 (b), owner 2026-09-21: the launch READING of the target's bytecode. A snapshot that
    # ships bytecode was launched blind before this line existed; the number is the baseline the
    # teardown verdict is computed against, and it is a count, never a deletion.
    pyc_at_launch = bytecode_files(target)
    log(f"pyc_preexisting={len(pyc_at_launch)}"
        + (f"  (stale bytecode can shadow an applied repair — first: {pyc_at_launch[0]})" if pyc_at_launch else ""))

    # FIX_46 (owner Q6): the ONE cadence table, printed at launch — every period and phase in the app,
    # with the four-blade invariant checked. A conflict is printed, never hidden.
    for _line in format_cadence_table():
        log(_line)

    def on_signal(signum, frame):
        global _shutdown_requested
        _shutdown_requested = True
        log(f"received signal {signum} — shutting down")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)   # S4: closing the terminal is a shutdown too — full teardown
    pid_file_write(target, [])   # B8 / Q-H1-5: the process record, from before the first child
    log(f"process record -> {PID_FILE.name} (gearbox PID {os.getpid()}; each child's pid/pgid is added as it starts)")
    _progress("gearbox", "pass", "one supervisor now runs every CodeRadar process and stops them all on exit", started=_t_main)

    manifest = WriteManifest(target, repo_id)
    # The run feed (FIX_52, S4): created fresh now — a previous run's failure never shows on this run's
    # band — and deleted at teardown. Engine-side: not a mirror, nothing enters the target.
    events = RunEvents(GEARBOX_EVENTS, run_started)
    failure: dict | None = None      # S4: set when a daemon dies or hangs — the run stops on it
    stack_up = False                 # C2 / Q-H1-7: True once every gate passed — the launch_verdict.json record

    # Pre-flight (owner ruling 2026-09-28): a prior run's mirrors are its log — kept, never swept;
    # this run's daemons overwrite each one as its directory comes into view.
    _prior = kept_mirrors(target)
    log(f"pre-flight: {len(_prior)} state mirror(s) from a prior run kept in target (overwritten as dirs come into view)"
        if _prior else "pre-flight: no state mirrors in target yet")
    manifest.entries.clear()
    manifest.persist()

    # FIX_21 (2026-09-15): each child's gate is defined ONCE here — the gated start reads one lambda,
    # timeout and state file (the NOAI / Builder timeouts are scaled below, before the gate, and stay
    # on the child for the run). NO RESTARTS (owner 2026-09-29 S4): a child that exits or hangs stops
    # the whole run, so the gate is read exactly once per launch.
    children = [
        Child("circuit_daemon",
              [sys.executable, "system_scripts/circuit_daemon.py", str(target)],
              gate=lambda: gate_states()["circuit_ready"], gate_timeout=CIRCUIT_GATE_TIMEOUT_S,
              state_file=CIRCUIT_STATE, phase_key="daemon_phase"),
        Child("noai_validator",
              [sys.executable, "-m", "no_aivalidator.NOAI_VALIDATOR_DAEMON"],
              gate=lambda: gate_states()["noai_monitoring"], gate_timeout=NOAI_GATE_BASE_TIMEOUT_S,
              state_file=NOAI_STATE, phase_key="phase"),
        # Item 1 (2026-09-08): the Builder is the FOURTH child — reads the validator's
        # published infractions, owns BUILDER_STATE.json and the .noai_state.json mirror.
        Child("cheatsheets",
              [sys.executable, "-m", "no_aivalidator.BUILDER_DAEMON"],
              gate=lambda: gate_states()["builder_monitoring"], gate_timeout=BUILDER_GATE_BASE_TIMEOUT_S,
              state_file=BUILDER_STATE, phase_key="phase"),
        Child("dashboard",
              # C2 / Q-H1-10 (2026-10-01): `--setup-tab` is handed on to the dash — the overlay offers "back to
              # setup" only when a setup page is waiting on its tab; an argv / MCP launch has no page to go back to.
              [sys.executable, "system_scripts/proof_dashboard.py", "--port", str(DASHBOARD_PORT)]
              + ([] if _OPEN_TAB else ["--setup-tab"]),
              gate=lambda: gate_states()["dashboard_up"], gate_timeout=DASHBOARD_GATE_TIMEOUT_S,
              state_file=None,
              # R8 / T-12 (2026-09-30): the dash is TOLD the target in its environment — it never has to
              # find it in poll_config / circuit_state, and never falls back to CodeRadar's own tree.
              env={"TARGET_REPO": str(target)}),
    ]
    circuit, noai, builder, dashboard = children
    started: list[Child] = []
    exit_code = 0

    try:
        # ── Gated sequential start ──
        # owner 2026-09-29: the dash comes up BEFORE anything scans, so the viewer watches the full scan
        # from its first file (it used to start last, after the circuit's first pass). The target goes into
        # poll_config first — the dash reads it on import, and the circuit daemon only writes it once it runs.
        # R8 / T-12 (2026-09-30): a failed write FAILS the launch (it used to be logged and the dash came up
        # reading the PREVIOUS run's target, or CodeRadar's own tree). The dash also gets TARGET_REPO in its
        # environment (the Child above), so the two never disagree.
        _progress("dashboard", "running")
        try:
            _pc = SCRIPT_DIR / "poll_config.json"
            _cfg = json.loads(_pc.read_text()) if _pc.exists() else {}
            _cfg["target_repo"] = str(Path(target).resolve())
            _tmp = _pc.with_suffix(".json.tmp")
            _tmp.write_text(json.dumps(_cfg, indent=2))
            os.replace(_tmp, _pc)
        except Exception as e:
            raise RuntimeError(f"poll_config.target_repo write failed ({type(e).__name__}: {e}) — "
                               "the dashboard would read the wrong target; no CodeRadar process was started")
        dashboard.launch(ts)
        started.append(dashboard)
        pid_file_write(target, started)
        log(f"started {dashboard.name} PID {dashboard.pid()} -> {dashboard.log_name()}")
        await_startup("dashboard HTTP 200", dashboard, "dashboard gate failed")
        _progress("dashboard", "pass", DASHBOARD_URL)
        log(f"dashboard up before any scan — open {DASHBOARD_URL}")
        # owner 2026-09-29: start the app → the browser opens on the overlay by itself, so the viewer
        # watches every light from here on
        # owner 2026-09-30: launched from the setup page (--setup-tab) → that tab becomes the dashboard; no second tab
        if sys.platform == "darwin" and _PROGRESS is not None and _OPEN_TAB:
            try:
                subprocess.run(["open", DASHBOARD_URL], check=False, timeout=10)
            except Exception as e:
                log(f"browser open failed ({e}) — open {DASHBOARD_URL} by hand")
        if _PROGRESS is not None:
            log("waiting for launch.sh's steps (snapshot, health check, whitelist scan, target env)...")
            _steps = _progress_launch_steps()
            if _steps == "interrupted":
                # B8 / Q-H1-9: a stop request (Ctrl-C, SIGTERM) during launch.sh's steps is not a failed step
                raise RuntimeError("interrupted by a stop request (Ctrl-C / SIGTERM) during the launch steps — no CodeRadar process was started")
            if _steps != "done":
                # launch.sh's own failed detail names the step and why (e.g. "health check failed: step 17 —
                # …"); keep it rather than overwrite it with a generic line
                import launch_progress
                _why = launch_progress.read(_PROGRESS).get("detail") or f"launch steps {_steps}"
                raise RuntimeError(f"{_why} — no CodeRadar process was started")
            log("launch steps done — starting the daemons")

        _progress("circuit", "running")
        circuit.launch(ts)
        started.append(circuit)
        pid_file_write(target, started)
        log(f"started {circuit.name} PID {circuit.pid()} -> {circuit.log_name()}")
        await_startup("circuit READY/RUNNING", circuit, "circuit daemon gate failed")
        _progress("circuit", "pass", "map of your files drawn; the checkers made their first pass")
        _progress("wiring", "running")

        # FIX_36 (owner 2026-09-10): a wiring warning at launch stops the launch and says which
        # node. Runs 79–97 went through every gate with a node marked BROKEN (the unparseable
        # file planted for NAI-208 on set 4b-25, carried in every tree since) while the dash
        # showed "Circuit wiring disturbance" the whole time — no gate read the wiring state.
        # Nothing else starts; the failure takes the full-teardown path below.
        breaks = wiring_breaks()
        if breaks:
            for node, why in breaks:
                log(f"GATE [circuit WIRING] BROKEN {node}: {why}")
            log(f"GATE [circuit WIRING] FAIL — {len(breaks)} node(s) not connected; "
                f"launch stopped, nothing else starts (target untouched, see teardown)")
            _progress("wiring", "fail", "not connected: " + ", ".join(n for n, _w in breaks))
            raise RuntimeError("circuit wiring gate failed")
        log("GATE [circuit WIRING] PASS — every node connected")
        _progress("wiring", "pass", "every file is on the map")
        # owner 2026-09-30: the builder launches with the validator and builds on its own once the validator's
        # rows land, so no gearbox clock can time the build — the step's time is the builder's own (below).
        _progress("solutions", "pending", "waits for the validator's rows")
        _progress("noai", "running")   # launched below; the current step, should a gate fail

        noai.launch(ts)
        started.append(noai)
        log(f"started {noai.name} PID {noai.pid()} -> {noai.log_name()}")
        # The Builder starts immediately after the validator; only the GATES run in order
        # (dashboard -> circuit -> NOAI -> BUILDER). The Builder waits on its own for the
        # validator's MONITORING phase, so the overlay shows all four lights during the baseline.
        builder.launch(ts)
        started.append(builder)
        pid_file_write(target, started)
        log(f"started {builder.name} PID {builder.pid()} -> {builder.log_name()}")

        # Gate budget from the launcher's ONE discovery (live + markers), not a
        # raw rglob that counts detritus and venv internals (2026-09-05).
        n_py = None
        try:
            import scan_scope
            _wl_doc = json.loads(scan_scope.whitelist_path(target).read_text())
            _sm = _wl_doc.get("summary", {})
            n_py = int(_sm.get("live", 0)) + int(_sm.get("package_markers", 0))
        except Exception:
            n_py = None
        if not n_py:
            # S4 task 10: no second walk ("one scan scans everything" — the whitelist stage IS the scan). An
            # unreadable or zero summary means the stage failed or found nothing live; the gate gets its
            # base budget and the log says so, rather than a fresh walk of the target.
            log("NOAI gate: the whitelist stage's summary is unreadable or counts 0 live .py files — "
                "the gate gets its base budget (no second walk of the target)")
            n_py = 0
        noai_timeout = min(NOAI_GATE_BASE_TIMEOUT_S + NOAI_GATE_PER_PY_FILE_S * n_py,
                           NOAI_GATE_TIMEOUT_CAP_S)
        noai.gate_timeout = noai_timeout   # FIX_21: the scaled budget stays with the child for the run (no restarts)
        log(f"NOAI gate timeout scaled to {noai_timeout:.0f}s ({n_py} live .py files per the whitelist stage)")
        await_startup("NOAI MONITORING", noai, "NOAI validator gate failed")
        _progress("noai", "pass", "every file checked; problems found are listed on the dashboard")
        _progress("solutions", "running", "building the cheat sheets")

        # Builder gate (item 1, 2026-09-08) — only starts after the NOAI gate passed (no deadlock);
        # budget scales with the failed rows the validator just published.
        n_failed = 0
        try:
            n_failed = int(json.loads(NOAI_STATE.read_text()).get("summary", {}).get("failed", 0) or 0)
        except Exception:
            n_failed = 0
        builder_timeout = min(BUILDER_GATE_BASE_TIMEOUT_S + BUILDER_GATE_PER_ROW_S * n_failed,
                              BUILDER_GATE_TIMEOUT_CAP_S)
        builder.gate_timeout = builder_timeout   # FIX_21: stays with the child for the run (no restarts)
        log(f"CHEATSHEETS gate timeout scaled to {builder_timeout:.0f}s ({n_failed} failed rows per the validator state)")
        await_startup("CHEATSHEETS MONITORING", builder, "cheatsheets gate failed")
        # the build time the builder measured itself (its detail ends '— 0.1s'); started is set back by that much
        # so the step shows it. Unreadable → the step says so rather than showing the gate's wait as the build.
        build_secs = None
        try:
            m = re.search(r"— ([0-9.]+)s$", str(json.loads(BUILDER_STATE.read_text()).get("detail", "")))
            build_secs = float(m.group(1)) if m else None
        except Exception:
            build_secs = None
        if build_secs is None:
            _progress("solutions", "pass", "fix suggestions ready · build time NOT MEASURED (the fix builder did not report it)")
        else:
            _progress("solutions", "pass", f"fix suggestions ready · built in {build_secs:.1f}s",
                      started=time.time() - build_secs)
        if _PROGRESS is not None:
            # 'ready' lifts the overlay, so it is said only when the file itself shows every step finished —
            # never on the gearbox's word alone (a light still 'running' under a lifted overlay is a lie)
            import launch_progress
            open_steps = launch_progress.unfinished(launch_progress.read(_PROGRESS))
            if open_steps:
                raise RuntimeError("opening steps not finished: " + ", ".join(open_steps))
            time.sleep(4)          # the all-green list stays on the overlay a moment before it fades
            _progress("-", "ready")

        stack_up = True
        log(f"ALL GATES PASSED — stack is up. Dashboard: {DASHBOARD_URL}")
        log(f"gate_states = {json.dumps(gate_states())}")

        # ── Supervision loop ──
        # S4 (owner 2026-09-29, RULED): a daemon that DIES and a daemon that HANGS are the same event, and
        # neither is restarted — what a crashed daemon produced cannot be trusted. The run stops: the
        # failure is recorded (run feed, progress file, tester report, terminal), every daemon but the
        # dashboard is torn down, and the dash shows the red panel until Ctrl-C.
        # FIX_46: seeded from the table's phases so the two gearbox duties are half a period apart
        # (manifest scan phase 0, stale warning phase 6 of 12 cycles) instead of both at t0.
        last_manifest_scan = time.monotonic() - duty_phase("gearbox", "manifest_scan") * CADENCE_BASE_S
        last_stale_warn = time.monotonic() - duty_phase("gearbox", "stale_warn") * CADENCE_BASE_S
        for c in children:
            c.unhealthy_since = None
        while not _shutdown_requested:
            now_m = time.monotonic()
            for c in children:
                if c.proc is None:
                    continue
                if c.alive():
                    reason = hang_reason(c, now_m)
                    if reason is None:
                        continue
                else:
                    reason = _exit_how(c.exit_code())
                failure = daemon_failure(c, reason)
                break
            if failure is not None:
                raise DaemonFailure(failure)

            now = time.monotonic()
            # FIX_46: the two gearbox duties are two rows of the cadence table — the manifest scan on
            # phase 0 and the stale warning on phase 6 of the same 12-cycle period, so they never land
            # on the same second (they both touch files the circuit daemon is writing).
            if now - last_manifest_scan >= MANIFEST_SCAN_INTERVAL_S:
                try:
                    added = manifest.record_scan()
                except OSError as e:     # S4: a scan error is logged, never a way out of the loop
                    log(f"manifest scan failed ({type(e).__name__}: {e}) — retried next period")
                    added = 0
                if added:
                    log(f"manifest: recorded {added} new mirror write(s) "
                        f"({len(manifest.entries)} total) -> {manifest.path.name}")
                last_manifest_scan = now

            # S4 task 5: the circuit writes once per poll and the slider goes to 10 min — the warning
            # threshold is the poll interval on top of the declared STALE_STATE_WARN_S, as hang_reason does
            stale_warn_s = STALE_STATE_WARN_S + _poll_interval_s()
            try:
                age = time.time() - CIRCUIT_STATE.stat().st_mtime
                if age > stale_warn_s and now - last_stale_warn > stale_warn_s:
                    log(f"WARNING: circuit_state.json stale ({age:.0f}s since last write; "
                        f"the poll is {_poll_interval_s():.0f}s)")
                    last_stale_warn = now
            except FileNotFoundError:
                if now - last_stale_warn > stale_warn_s:
                    log("WARNING: circuit_state.json missing")
                    last_stale_warn = now

            time.sleep(SUPERVISE_POLL_S)

    except DaemonFailure as df:
        failure = df.failure
        exit_code = 1
        _report_daemon_failure(failure)
        events.failed(failure)
        if _PROGRESS is not None:
            if _PROGRESS_CUR:   # P1/A2: died during its startup gate — that step shows failed too
                _progress(_PROGRESS_CUR, "fail", f"{failure['daemon']} {failure['reason']}")
            import launch_progress
            launch_progress.update(_PROGRESS, "-", "failed", f"{failure['daemon']} {failure['reason']} — the run "
                                   f"stopped; close CodeRadar from this overlay (its buttons; owner 2026-09-30)", create=False)
        # every daemon but the dashboard stops NOW (the full teardown below finds them already stopped);
        # the dash stays up with the red panel until Ctrl-C, as the opening sequence's failure path does
        for line in terminate_children([c for c in started if c is not dashboard]):
            log(line)
        _hold_dash_until_ctrl_c(dashboard, "the dashboard stays up with the failure panel — Ctrl-C to close")
    except RuntimeError as e:
        exit_code = 1
        if _shutdown_requested:
            # B8 / Q-H1-9: a stop request (Ctrl-C, SIGTERM, SIGHUP) during a gate or the launch steps is not a
            # failed step: the record says `interrupted`, never `failed`, and the dash is not held open.
            # launch.sh's own `interrupted` record (it names the step and the signal) is kept, not overwritten.
            log(f"startup interrupted: {e}")
            if _PROGRESS is not None:
                import launch_progress
                if launch_progress.read(_PROGRESS).get("overall") != "interrupted":
                    if _PROGRESS_CUR:
                        _progress(_PROGRESS_CUR, "interrupted", "interrupted by a stop request (Ctrl-C / SIGTERM) — not measured")
                    _progress("-", "interrupted", str(e))
        else:
            log(f"startup failed: {e}")
            if _PROGRESS is not None:
                # the overlay names the step that failed, and the dash stays up long enough to read it
                if _PROGRESS_CUR:
                    _progress(_PROGRESS_CUR, "fail", str(e))
                _progress("-", "failed", str(e))
                _hold_dash_until_ctrl_c(dashboard, "the dashboard stays up so the overlay shows the failed step — "
                                                   "Ctrl-C to close")
    finally:
        # ── Leave-no-trace teardown (R1/S3): "like we were never there" ──
        # P1/A1: the steps before the children stop are guarded as one — whatever they raise, the
        # children are stopped (terminate_children sits in the `finally`, never behind them).
        try:
            log("=== TEARDOWN ===")
            # Record any last-moment mirror writes before killing the writers. S4: guarded — an error here
            # once skipped terminate_children and orphaned every daemon.
            try:
                manifest.record_scan()
            except Exception as e:
                log(f"manifest: last scan failed ({type(e).__name__}: {e}) — the teardown goes on")
            # Item 5 + 6 (2026-09-09): BEFORE the children stop, read BUILDER_STATE.json + the
            # tester's return channel (system_scripts/return_channel_<id>.jsonl, outside the target),
            # write .archive/runs/<target>/tester_report.json and copy the channel beside it —
            # the next launch archives the channel away. The Builder writes tmp+replace, so the
            # read is never torn.
            try:
                rep = write_tester_report(target, repo_id, run_started, daemon_failure=failure)
                if rep.get("status") == "MEASURED":
                    cf = rep.get("confirmed_fraction")
                    log(f"tester report: {rep.get('infractions')} infractions, {rep.get('solutions')} solutions, "
                        f"{rep.get('confirmed')} confirmed; "
                        f"confirmed_fraction={'null' if cf is None else f'{cf:.3f}'}"
                        f"{'' if rep.get('tester_ran') else ' (no tester ran)'}; "
                        f"{rep.get('return_channel_lines', 0)} channel line(s) copied -> "
                        f".archive/runs/{target.name}/tester_report.json")
                else:
                    log(f"tester report: NOT MEASURED ({rep.get('error', 'no reason')}) -> .archive/runs/{target.name}/tester_report.json")
            except Exception as e:  # must never block the teardown
                log(f"tester report: skipped ({type(e).__name__}: {e})")
        except Exception as e:
            log(f"teardown: a pre-stop step failed ({type(e).__name__}: {e}) — the children are stopped anyway")
        finally:
            for line in terminate_children(started):
                log(line)
        # owner 2026-10-07 ~05:50: the viewed folders' JSONL dash mirrors sit next to the target's code — they
        # are removed here, after every child is stopped (nothing can rewrite them), before residue + identity
        try:
            import view_mirrors
            _vm_gone = view_mirrors.remove_all(target)
            log(f"VIEW MIRRORS: removed {len(_vm_gone)} from the viewed folders: {_vm_gone}")
        except Exception as e:
            log(f"VIEW MIRRORS: removal failed ({type(e).__name__}: {e}) — they show as residue below")
        # Owner ruling 2026-09-28: the two state mirrors are KEPT as the run's log; they are not
        # residue. S4: the residue is MEASURED (it used to be a fixed empty list and a fixed "zero" line):
        # CodeRadar files still in the target beyond the kept mirrors, plus the bytecode that appeared
        # during the run (below) — so teardown_verified means the target is as we found it.
        kept = kept_mirrors(target)
        pyc = pycache_residue(target)
        _bv = bytecode_verdict(pyc_at_launch, bytecode_files(target))
        residue = cr_residue(target, manifest, kept) + [f"bytecode added: {a}" for a in _bv["added"]]
        log(f"MIRRORS KEPT: {len(kept)} state mirror(s) left in target as the run's log: {kept}")
        if residue:
            log(f"RESIDUE CHECK: {len(residue)} CodeRadar file(s) remain in target beyond the kept mirrors: "
                f"{', '.join(residue)}")
        else:
            log("RESIDUE CHECK: zero CodeRadar files remain in target beyond the kept state mirrors")
        if pyc:
            log(f"NOTE: __pycache__ residue left in place (not CR-owned deletion): {pyc}")
        # I-153 (c): the VERDICT. Not the NOTE above — that one reports directories left alone;
        # this one judges whether anything entered the target while the run was reading it, and
        # so whether this run's suite reading may be used to judge a repair at all. S4: a run that
        # stopped on a daemon failure is not trustworthy either, whatever the bytecode says.
        if failure is not None:
            _bv["run_trusted"] = "no"
            _bv["daemon_failure"] = f"{failure['daemon']} {failure['reason']}"
            _bv["suite_reading"] = "not clean"
            log(f"VERDICT: the run stopped on a daemon failure ({_bv['daemon_failure']}) — NOT trustworthy")
        log(f"VERDICT: polluted={_bv['polluted']}  pyc_preexisting={_bv['pyc_preexisting']}  "
            f"pyc_at_teardown={_bv['pyc_at_teardown']}  suite reading {_bv['suite_reading'].upper()}")
        if _bv["added"]:
            log(f"VERDICT: bytecode ADDED during the run ({len(_bv['added'])}): {_bv['added'][:5]}")
        if _bv["removed"]:
            log(f"VERDICT: bytecode REMOVED during the run ({len(_bv['removed'])}): {_bv['removed'][:5]}")
        try:
            _bvdir = PROJECT_ROOT / ".archive" / "runs" / target.name
            _bvdir.mkdir(parents=True, exist_ok=True)
            (_bvdir / "pyc_verdict.json").write_text(json.dumps(_bv, indent=2))
        except OSError as e:   # a verdict file is a record, never a reason to block a teardown
            log(f"VERDICT: pyc_verdict.json not written ({type(e).__name__}: {e})")
        # C2 / Q-H1-7 (owner ruling 5, 2026-10-01): the LAUNCH verdict beside it — did this launch reach the
        # daemons (`monitoring`), stop on a failed step / gate / daemon before that (`failed`), or get a stop
        # request first (`interrupted`)? launch.sh's pre-flight retention reads it to tell a successful launch's
        # run dir from a failed one (last 10 / last 5, 14 days). `stamp` is this gearbox's own start stamp.
        try:
            _lv = {"launch": "monitoring" if stack_up else ("interrupted" if _shutdown_requested else "failed"),
                   "stamp": ts, "target": str(target), "repo_id": repo_id, "exit_code": exit_code,
                   "daemon_failure": (f"{failure['daemon']} {failure['reason']}" if failure else None)}
            _lvdir = PROJECT_ROOT / ".archive" / "runs" / target.name
            _lvdir.mkdir(parents=True, exist_ok=True)
            (_lvdir / "launch_verdict.json").write_text(json.dumps(_lv, indent=2))
            log(f"launch verdict: {_lv['launch']} -> .archive/runs/{target.name}/launch_verdict.json")
        except OSError as e:
            log(f"launch verdict: launch_verdict.json not written ({type(e).__name__}: {e})")
        # Q-H1-6 / RUN_AGAINST_RULES rule 8 (2026-10-01): teardown_verified is BYTE-IDENTITY against this
        # run's COPY-FIRST snapshot AND zero residue — the residue sweep alone was never enough. The
        # comparison is teardown_identity.compare (shared with cr_stop); no snapshot → NOT MEASURED.
        ident = teardown_identity_check(target, repo_id, ts)
        for line in ident["lines"]:
            log(line)
        measured = ident["status"] == "MEASURED"
        verified = bool(ident["verified"]) and not residue
        manifest.entries.clear()
        manifest.persist(teardown_verified=verified, identity=ident)
        log(f"manifest -> {manifest.path.name} (entries cleared, "
            f"teardown_verified={str(verified).lower() if measured else 'NOT MEASURED'}"
            + (f" — {len(ident['changed'])} changed file(s) named above" if measured and ident["changed"] else "")
            + (f" — residue: {', '.join(residue)}" if measured and residue else "") + ")")
        # FIX_52: the band's feed is this run's only — it leaves with the run.
        events.remove()
        log(f"run events -> {GEARBOX_EVENTS.name} removed"
            + (f" (the run stopped on {failure['daemon']}: {failure['reason']})" if failure else ""))
        pid_file_remove()   # B8 / Q-H1-5: the children are stopped — the process record leaves with them
        log(f"process record -> {PID_FILE.name} removed")
        log("=== TEARDOWN COMPLETE ===")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
