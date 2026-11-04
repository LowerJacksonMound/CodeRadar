#!/usr/bin/env bash
# CodeRadar launcher — ./launch.sh [/path/to/target [--tracer lsof] [--load-proof] [--trackers io,mypy,crc,vulture]]
#
# Lane B (owner 2026-09-30): with NO target argument the launch opens the setup page first
#         (system_scripts/launch_setup.py on the dashboard port) — target path, trackers
#         and an optional purpose are chosen there (the snapshot is always taken — there is no
#         copy choice; --no-copy is refused below); nothing runs until Start. With a target
#         argument the launch runs as before. eslogger is disabled — removed from the MVP:
#         --tracer defaults to lsof and `--tracer eslogger` is refused at the door (the eslogger
#         code paths stay; only the entry is closed).
#
# Item 7 (owner ruling 2026-09-08, built 2026-09-10; --tracer superseded 2026-09-30, see
#         the Lane B note above): the launch CONTROL block. --tracer is lsof only and may be
#         omitted (defaults to lsof); `--tracer eslogger` is refused at the door — no silent
#         fallback anywhere after this point. --no-copy is refused: the snapshot is always taken.
#         --trackers a,b,c chooses the pluggable data type trackers for THIS repo
#         (tokens ⊂ {io, mypy, crc, vulture}; absent = none run; pylint is rejected —
#         its runner is unwired, ruling 11). A bad value aborts with usage
#         BEFORE the snapshot. The block is written to system_scripts/poll_config.json
#         (launch_control) after the pre-flight clears it; the circuit daemon refuses to
#         run without it (daemon_phase ERROR, exit 2 → gearbox fails fast); the overlay
#         and a header chip show the block read-only.
#         (owner 2026-09-30: superseded for --tracer — it now defaults to lsof and eslogger is refused;
#         see the Lane B note above.)
# Step 0  COPY-FIRST (owner doctrine): snapshot the target CB to
#         ~/CodeRadar_snapshots/<basename>_<timestamp>/ and verify it
#         (sorted relative file-list diff + file count) BEFORE anything
#         touches the CB. Abort on any mismatch. Always taken (owner 2026-09-30: no --no-copy).
# Step 1  Pre-flight: pkill the four daemons, clear EVERY piece of state
#         (owner 2026-09-05: every scan is a brand-new scan — CRC baseline,
#         line-hash store, slider prefs included), check :8080.
# Step 1b HEALTH CHECK (owner 2026-09-05 §1a): health_check.py runs BEFORE the
#         filters and aborts the launch on failure; its report is archived.
# Step 2  Whitelist stage (seam S1): DetritusCleaner scan -> persisted
#         system_scripts/whitelist_<repoid>.json BEFORE any daemon starts.
# Step 3  exec gearbox.py (gated start + supervision + leave-no-trace).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$REPO_ROOT/.venv_new/bin/python"
# ── B10 (Q-H1-1 / Q-H0-10, 2026-10-01): the launch's own bytecode and mypy cache land in the engine's
# scratch, never in CR's source dirs. Exported ONCE here so every child — the setup page, the pre-flight
# heredocs, health_check.py, the whitelist stage, target_env.py, the gearbox and the daemons it spawns —
# inherits it: an import writes no .pyc at all; py_compile/compileall (which IGNORE PYTHONDONTWRITEBYTECODE)
# and mypy's cache go under system_scripts/.cr_pycache/launch_<ts>/, the F12/F32 engine-owned cache that
# the pre-flight sweeps. gearbox.no_bytecode_env passes the prefix through to every daemon untouched.
LAUNCH_TS="$(date +%Y%m%d_%H%M%S)"
LAUNCH_T0="$(date +%s)"   # the I-153 (e) reading after the launch steps counts what is newer than this
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX="$REPO_ROOT/system_scripts/.cr_pycache/launch_$LAUNCH_TS"
export MYPY_CACHE_DIR="$PYTHONPYCACHEPREFIX/mypy"
# Item 7: under `sudo ./launch.sh` $HOME is root's — the snapshot root must stay the
# invoking owner's (SUDO_USER), or the COPY-FIRST snapshot lands under /var/root.
if [ -n "${SUDO_USER:-}" ]; then
    OWNER_HOME="$(eval echo "~$SUDO_USER")"
else
    OWNER_HOME="$HOME"
fi
SNAP_ROOT="$OWNER_HOME/CodeRadar_snapshots"

usage() {
    echo "usage: ./launch.sh /path/to/target [--tracer lsof] [--load-proof] [--trackers io,mypy,crc,vulture]" >&2
    echo "       ./launch.sh            (no target: the setup page chooses target and options — owner 2026-09-30)" >&2
    echo "       --tracer defaults to lsof; eslogger is disabled — removed from the MVP (owner 2026-09-30)" >&2
    exit 2
}

# ── Args ─────────────────────────────────────────────────────────────────────
TARGET=""
TRACER=""
# A (owner 2026-10-06, narrow amendment): eslogger as a target-module LOAD PROOF only — lsof stays the
# launch tracer and `--tracer eslogger` stays refused. ONE sudo prompt per launch, here, before anything runs.
LOAD_PROOF=0
LOAD_PROOF_PID=""
TRACKERS=""
BACK_TO_SETUP=0   # owner 2026-09-30: a failed launch's "back to setup" re-enters here — page pre-filled, no new tab
SETUP_ERROR=""    # ... with the reason the last Start stopped, shown on the page
while [ $# -gt 0 ]; do
    case "$1" in
        --no-copy) echo "launch.sh: --no-copy was removed (owner 2026-09-30) — the snapshot is always taken" >&2; exit 2 ;;
        --back-to-setup) BACK_TO_SETUP=1 ;;
        --setup-error) [ $# -ge 2 ] || usage; SETUP_ERROR="$2"; shift ;;
        --tracer) [ $# -ge 2 ] || { echo "launch.sh: ABORT — --tracer needs a value: lsof" >&2; usage; }; TRACER="$2"; shift ;;
        --tracer=*) TRACER="${1#--tracer=}" ;;
        --pmc) echo "launch.sh: --pmc was removed (owner 2026-10-07)" >&2; exit 2 ;;
        --load-proof) LOAD_PROOF=1 ;;
        --trackers) [ $# -ge 2 ] || { echo "launch.sh: ABORT — --trackers needs a value: io,mypy,crc,vulture" >&2; usage; }; TRACKERS="$2"; shift ;;
        --trackers=*) TRACKERS="${1#--trackers=}" ;;
        -*) echo "launch.sh: unknown option: $1" >&2; usage ;;
        *) [ -n "$TARGET" ] && usage; TARGET="$1" ;;
    esac
    shift
done

# ── owner 2026-09-30: eslogger is disabled (removed from the MVP) — the entry is refused, the code stays ──
# Refused here, before the setup page or anything else runs; an omitted --tracer means lsof.
if [ "$TRACER" = "eslogger" ]; then
    echo "launch.sh: ABORT — eslogger is disabled — removed from the MVP (use --tracer lsof, the default)" >&2; exit 2
fi
[ -n "$TRACER" ] || TRACER=lsof

# ── Lane B (owner 2026-09-30): no target argument → the setup page chooses, before anything runs ──
# launch_setup.py serves one page on the dashboard port; Start writes system_scripts/launch_choice.json
# and frees the port. Its values set TARGET/TRACKERS (any flags given here only pre-fill the
# page); the choice file is deleted once read. Closed without Start → exit cleanly, nothing touched.
PURPOSE=""
if [ -z "$TARGET" ]; then
    [ -x "$VENV_PY" ] || { echo "launch.sh: venv python not found at $VENV_PY (run Phase-3 venv setup)" >&2; exit 1; }
    CHOICE_FILE="$REPO_ROOT/system_scripts/launch_choice.json"
    rm -f "$CHOICE_FILE"   # a stale choice from an earlier page is never read
    LAST_CHOICE="$REPO_ROOT/system_scripts/last_launch_choice.json"   # the previous Start, for "back to setup"
    SETUP_PORT="$("$VENV_PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("dashboard", 8080))' "$REPO_ROOT/system_scripts/copy_ports.json" 2>/dev/null || echo 8080)"
    SETUP_ARGS=(--port "$SETUP_PORT" --choice-file "$CHOICE_FILE" --trackers "$TRACKERS")   # the port is always passed in
    [ "$LOAD_PROOF" -eq 1 ] && SETUP_ARGS+=(--load-proof)   # 2026-10-07: the page carries a load-proof tick box
    [ "$BACK_TO_SETUP" -eq 1 ] && [ -f "$LAST_CHOICE" ] && SETUP_ARGS+=(--from-last "$LAST_CHOICE")
    [ -n "$SETUP_ERROR" ] && SETUP_ARGS+=(--error "$SETUP_ERROR")
    echo "[setup] no target given — opening the launch setup page (nothing runs until Start)"
    # the page is opened once the server is listening; the server runs in the foreground
    ( for _ in $(seq 1 50); do
          if "$VENV_PY" -c 'import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$SETUP_PORT" 2>/dev/null; then
              # back to setup: the dashboard's tab is already waiting for this page — no second tab
              [ "$BACK_TO_SETUP" -eq 1 ] && exit 0
              open "http://127.0.0.1:$SETUP_PORT/" >/dev/null 2>&1 || echo "[setup] open the page by hand: http://127.0.0.1:$SETUP_PORT/"
              exit 0
          fi
          sleep 0.2
      done ) &
    SETUP_OPENER=$!
    if [ "$BACK_TO_SETUP" -eq 1 ]; then   # the torn-down dashboard may hold the port for a moment
        for _ in $(seq 1 50); do
            "$VENV_PY" -c 'import socket,sys; s=socket.socket(); sys.exit(1 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 0)' "$SETUP_PORT" 2>/dev/null && break
            sleep 0.2
        done
    fi
    trap ':' INT TERM   # Ctrl-C ends the page server (it exits 4); launch.sh then says so and stops
    SETUP_RC=0
    PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" "$REPO_ROOT/system_scripts/launch_setup.py" "${SETUP_ARGS[@]}" || SETUP_RC=$?
    trap - INT TERM
    kill "$SETUP_OPENER" >/dev/null 2>&1 || true; wait "$SETUP_OPENER" 2>/dev/null || true
    if [ "$SETUP_RC" -eq 3 ]; then
        echo "launch.sh: ABORT — port $SETUP_PORT is in use, so the setup page cannot open; stop the earlier run, or launch with the target on the command line" >&2
        exit 1
    fi
    if [ ! -f "$CHOICE_FILE" ]; then
        echo "[setup] the setup page closed without Start — nothing ran, nothing changed"
        exit 0
    fi
    CHOICE_SH="$(PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" "$REPO_ROOT/system_scripts/launch_setup.py" --emit-shell "$CHOICE_FILE")" || {
        rm -f "$CHOICE_FILE"; echo "launch.sh: ABORT — the setup choice could not be read (see above)" >&2; exit 1; }
    mv -f "$CHOICE_FILE" "$LAST_CHOICE"
    eval "$CHOICE_SH"   # TARGET LOAD_PROOF TRACKERS PURPOSE — each shlex-quoted by launch_setup.py
    # owner 2026-09-30: the setup tab turns into the dashboard by itself — the gearbox opens no second tab
    GEARBOX_TAB=(--setup-tab)
    # owner 2026-09-30: the page is waiting on this tab — a refusal between Start and the gearbox (a missing
    # path, a bad tracker, …) goes back to the page with its reason, never only to the terminal. stderr is
    # copied to a file so the reason can be read; the gearbox's own EXIT trap replaces this one further down.
    SETUP_ERR_LOG="$REPO_ROOT/system_scripts/.launch_setup_err.log"
    : > "$SETUP_ERR_LOG"
    exec 3>&2 2> >(tee -a "$SETUP_ERR_LOG" >&3)
    _back_to_setup_on_refusal() {
        local rc=$?
        exec 2>&3
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 130 ] || [ "$rc" -eq 143 ]; then   # B8 / Q-H1-8: a stop request is not a refusal
            rm -f "$SETUP_ERR_LOG"
            return
        fi
        sleep 0.2   # let tee flush the last line
        local why
        why="$(grep -v '^\s*$' "$SETUP_ERR_LOG" | tail -1 | sed 's/^launch\.sh: ABORT — //')"
        rm -f "$SETUP_ERR_LOG"
        echo "[setup] stopped before the launch (exit $rc) — back to the setup page"
        exec "$REPO_ROOT/launch.sh" --back-to-setup --setup-error "${why:-the launch stopped (exit $rc) — see the terminal}"
    }
    # B8 / Q-H1-8 (2026-10-01): Ctrl-C / SIGTERM between Start and the gearbox QUITS — the stderr copy is
    # removed, the setup page is not re-opened, and the exit code is the signal's (130 / 143). Without this
    # trap a SIGTERM death skipped the EXIT trap's clean-up and left .launch_setup_err.log behind.
    _cancel_before_gearbox() {
        local sig="$1" rc="$2"
        trap - INT TERM EXIT
        exec 2>&3
        rm -f "$SETUP_ERR_LOG"
        echo "[setup] interrupted by $sig before the launch — nothing ran, nothing changed" >&2
        exit "$rc"
    }
    trap '_cancel_before_gearbox Ctrl-C 130' INT
    trap '_cancel_before_gearbox SIGTERM 143' TERM
    trap _back_to_setup_on_refusal EXIT
    echo "[setup] chosen: $TARGET trackers=${TRACKERS:-none} purpose=$([ -n "$PURPOSE" ] && echo given || echo none)"
fi

# ── Item 7: launch control — validated BEFORE the snapshot, nothing touched yet ──
case "$TRACER" in
    lsof) ;;
    *)  echo "launch.sh: ABORT — --tracer must be lsof (eslogger is disabled — removed from the MVP), got '$TRACER'" >&2; usage ;;
esac
if [ "$TRACER" = "eslogger" ] && [ "$(id -u)" -ne 0 ]; then
    echo "launch.sh: ABORT — --tracer eslogger needs root: sudo ./launch.sh $TARGET --tracer eslogger …" >&2; exit 2
fi
if [ "$TRACER" = "lsof" ] && ! command -v lsof >/dev/null 2>&1; then
    echo "launch.sh: ABORT — --tracer lsof but no lsof on PATH" >&2; exit 2
fi
if [ "$LOAD_PROOF" -eq 1 ] && ! sudo -n true >/dev/null 2>&1; then
    echo "[load proof] eslogger needs root once — enter your password (one prompt for this launch):"
    if ! sudo -v; then
        echo "launch.sh: ABORT — --load-proof: sudo was not granted; launch without --load-proof to skip it" >&2; exit 2
    fi
fi
TRACKER_LIST=""
if [ -n "$TRACKERS" ]; then
    IFS=',' read -r -a _toks <<< "$TRACKERS"
    for t in "${_toks[@]}"; do
        case "$t" in
            io|mypy|crc|vulture) TRACKER_LIST="$TRACKER_LIST${TRACKER_LIST:+,}$t" ;;
            pylint) echo "launch.sh: ABORT — --trackers pylint: runner unwired (ruling 11), not a choice" >&2; exit 2 ;;
            "") ;;
            *) echo "launch.sh: ABORT — --trackers token '$t' is not one of io,mypy,crc,vulture" >&2; exit 2 ;;
        esac
    done
fi
echo "[launch] control: tracer=$TRACER trackers=${TRACKER_LIST:-none}"

if [ ! -e "$TARGET" ]; then
    echo "launch.sh: target does not exist: $TARGET" >&2; exit 1
fi
if [ ! -d "$TARGET" ]; then
    echo "launch.sh: target is not a directory: $TARGET" >&2; exit 1
fi
# resolve to absolute AND real (R8 / T-16): `pwd -P` follows every symlink in the path. scan_scope.contained
# rejects anything reached through a symlink, so an unresolved symlinked target scanned 0 files.
TARGET="$(cd "$TARGET" && pwd -P)"
# owner 2026-09-30: CodeRadar's own tree, anything inside it, and any folder that CONTAINS it (its parent folder, home, /)
# are never a target — the last would snapshot and scan CodeRadar along with everything else
CR_REAL="$(cd "$REPO_ROOT" && pwd -P)"
case "$CR_REAL/" in
    "$TARGET"/*) echo "launch.sh: ABORT — $TARGET contains CodeRadar itself; choose the repo's own folder" >&2; exit 1 ;;
esac
case "$TARGET/" in
    "$CR_REAL"/*) echo "launch.sh: ABORT — $TARGET is CodeRadar's own tree (or inside it); CodeRadar never scans itself" >&2; exit 1 ;;
esac

if [ ! -x "$VENV_PY" ]; then
    echo "launch.sh: venv python not found at $VENV_PY (run Phase-3 venv setup)" >&2; exit 1
fi

echo "=== CodeRadar launch ==="
PREFLIGHT_T0="$("$VENV_PY" -c 'import time; print(time.time())')"
echo "Target: $TARGET"

# ── Step 1: Pre-flight ──────────────────────────────────────────────────────
echo "[pre-flight] stopping stale daemons (this tree's only)"
# Copy setup (express plan, 2026-09-10): kill only THIS tree's daemons. The venv interpreter
# resolves to the framework binary in argv and the children are spawned by relative path /
# -m, so the tree is NOT in the command line — but every daemon runs with cwd = its tree
# root (gearbox spawns them there). Select by cwd (proven live 2026-09-10: the original torn
# down beside a running copy, the copy untouched).
tree_daemon_pids() {
    # C2 / Q-H1-10 (2026-10-01): + launch_setup.py — a setup page server left on the dash port is this tree's too
    # D1 (2026-10-01), the MCP side's `_runs_daemon` mirrored in shell: `pgrep -f` only PRE-FILTERS. The argv is
    # read (`ps -o args=`) and the process must be a python interpreter (argv[0] basename python… or Python — the
    # venv link execs the framework binary, which is what ps shows) whose first positional is one of the daemon
    # FILES — relative to the tree as the gearbox spawns them, or absolute as launch.sh starts launch_setup.py — or
    # whose `-m` module is one of the daemon MODULES; `-c` / `-` are refused. Before this, a shell whose command
    # line merely NAMED a daemon file (zsh -c 'sleep 30 # NOAI_VALIDATOR_DAEMON.py') with cwd = the tree was
    # selected, and this pre-flight would have named it and stopped the launch. Then, as before, the cwd must be
    # this tree (the interpreter is shared between trees; the cwd is not).
    local pid script tree
    tree="$(cd "$REPO_ROOT" && pwd -P)"
    for pid in $(pgrep -f 'gearbox.py|circuit_daemon.py|NOAI_VALIDATOR_DAEMON|BUILDER_DAEMON|proof_dashboard.py|launch_setup.py' 2>/dev/null); do
        set -- $(ps -ww -o args= -p "$pid" 2>/dev/null || true)
        [[ "${1:-}" =~ ^(.*/)?[Pp]ython[0-9.]*(\.exe)?$ ]] || continue
        shift
        script=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -m) case "${2:-}" in no_aivalidator.NOAI_VALIDATOR_DAEMON|no_aivalidator.BUILDER_DAEMON) script=module ;; esac; break ;;
                -c|-) break ;;
                -X|-W) shift; if [ $# -gt 0 ]; then shift; fi ;;
                -*) shift ;;
                *) script="$1"; break ;;
            esac
        done
        [ -n "$script" ] || continue
        if [ "$script" != module ]; then
            case "$script" in /*) ;; *) script="$tree/$script" ;; esac
            case "${script##*/}" in gearbox.py|circuit_daemon.py|proof_dashboard.py|launch_setup.py) ;; *) continue ;; esac
            # D3 (2026-10-01), in step with the MCP side (`_runs_daemon`): the page's short-lived helper forms
            # (`--emit-shell`, `--submit-purpose`, with or without `=value`) are never the server — not selected.
            if [ "${script##*/}" = launch_setup.py ]; then case " ${*:2} " in *" --emit-shell"*|*" --submit-purpose"*) continue ;; esac; fi
            [ "$(cd "${script%/*}" 2>/dev/null && pwd -P)" = "$tree/system_scripts" ] || continue
        fi
        if [ "$(lsof -a -d cwd -p "$pid" -Fn 2>/dev/null | sed -n 's/^n//p')" = "$REPO_ROOT" ]; then echo "$pid"; fi
    done
}
# B8 / Q-H1-5 (2026-10-01): the gearbox writes system_scripts/gearbox_pids.json (its pid, each child's
# pid/pgid) and removes it at the end of its teardown. A record whose gearbox is dead is the proof that
# the daemons still running are CodeRadar's own from a crashed / kill -9ed run: those are stopped here
# (SIGTERM to each process group, SIGKILL after 5 s) and NAMED. Anything else this tree's selector finds
# is never stopped silently any more — it is named with the exact command, and the launch stops.
# stop_dead_gearbox_children [expected gearbox pid]: prints one line of what it did; rc 1 = no record
# or its gearbox is alive (nothing touched).
stop_dead_gearbox_children() {
    PIDREC="$REPO_ROOT/system_scripts/gearbox_pids.json" "$VENV_PY" - "${1:-}" <<'PY'
import json, os, signal, sys, time
rec_path = os.environ["PIDREC"]
try:
    rec = json.load(open(rec_path))
except (OSError, ValueError):
    sys.exit(1)
def alive(pid):
    try:
        os.kill(pid, 0); return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
gb = int(rec.get("gearbox") or 0)
expected = sys.argv[1]
if gb and alive(gb) and not (expected and str(gb) == expected):
    print(f"the process record {os.path.basename(rec_path)} belongs to a RUNNING gearbox (PID {gb}, target {rec.get('target')})")
    sys.exit(1)
kids = {n: int(c["pid"]) for n, c in (rec.get("children") or {}).items()}
live = {n: p for n, p in kids.items() if alive(p)}
def sig_group(pid, s):
    try:
        os.killpg(pid, s)
    except ProcessLookupError:
        pass
    except PermissionError:
        os.kill(pid, s)
for p in live.values():
    sig_group(p, signal.SIGTERM)
t0 = time.monotonic()
while any(alive(p) for p in live.values()) and time.monotonic() - t0 < 5:
    time.sleep(0.2)
forced = [n for n, p in live.items() if alive(p)]
for n in forced:
    sig_group(live[n], signal.SIGKILL)
time.sleep(0.2)
try:
    os.remove(rec_path)
except OSError:
    pass
if not live:
    print(f"process record of dead gearbox PID {gb} (target {rec.get('target')}): its {len(kids)} daemon(s) were already gone — record removed")
else:
    names = ", ".join(f"{n} (PID {p}{', SIGKILLed' if n in forced else ''})" for n, p in live.items())
    print(f"stopped {len(live)} daemon(s) of dead gearbox PID {gb} (target {rec.get('target')}): {names} — record removed")
PY
}
PRE_STOPPED="$(stop_dead_gearbox_children 2>/dev/null || true)"
[ -n "$PRE_STOPPED" ] && echo "[pre-flight] $PRE_STOPPED"
sleep 1
LEFTOVER="$(tree_daemon_pids | tr '\n' ' ')"
if [ -n "${LEFTOVER% }" ]; then
    echo "launch.sh: ABORT — CodeRadar process(es) still running from this tree, not stopped (no process record proves they are a dead run's own):" >&2
    ps -o pid=,ppid=,etime=,command= -p "$(echo "${LEFTOVER% }" | tr ' ' ',')" 2>/dev/null | cut -c1-160 | sed 's/^/    /' >&2 || true
    LIVE_GB="$(printf '%s' "$PRE_STOPPED" | sed -n 's/.*RUNNING gearbox (PID \([0-9]*\).*/\1/p')"
    [ -z "$LIVE_GB" ] && LIVE_GB="$(pgrep -f 'gearbox.py' 2>/dev/null | grep -xF -f <(echo "${LEFTOVER% }" | tr ' ' '\n') | head -1 || true)"
    if [ -n "$LIVE_GB" ]; then
        echo "launch.sh: a previous run is still up (gearbox PID $LIVE_GB) — close it (Ctrl-C in its terminal, the overlay's close, or cr_stop) and launch again; by hand:  kill $LIVE_GB   (its own teardown runs)" >&2
    else
        echo "launch.sh: to stop them by hand:  kill ${LEFTOVER% }   (then launch again)" >&2
    fi
    exit 1
fi

echo "[pre-flight] clearing ALL engine state in system_scripts/ (every scan is a brand-new scan)"
# running.json (daemon process table) AND running.lock (its flock) must both be
# cleared — a stale running.json otherwise survives into the next run (fix D0).
# Owner ruling 2026-09-05 (plan item 1): nothing carries over between scans —
#   mypy_n_contracts_watcher/baseline.json  CRC baseline (was judged against the
#                                           previous target: run 4 saw run 1's)
#   daemon_log/change_tags_state.json       line-hash / edit-tag store
#   daemon_log/change_tag_overflow.log      evicted edit tags
#   poll_config.json                        slider prefs (depth / poll rate) —
#                                           the dashboard re-creates it with
#                                           defaults at boot; readers default
#                                           when it is absent
CLEARED=""
for f in circuit_state.json NOAI_VALIDATION_STATE.json BUILDER_STATE.json runtime_coverage.json \
         running.json running.lock entry_point_info.json runner_info.json pytest_results.json .noai_state.json .monitor_state.json \
         poll_config.json NOAI_VALIDATION_STATE.heartbeat.json BUILDER_STATE.heartbeat.json \
         mypy_n_contracts_watcher/baseline.json \
         daemon_log/change_tags_state.json daemon_log/change_tag_overflow.log load_proof.json; do
    if [ -e "$REPO_ROOT/system_scripts/$f" ]; then
        rm -f "$REPO_ROOT/system_scripts/$f"
        CLEARED="$CLEARED $f"
    fi
done
echo "[pre-flight] cleared:${CLEARED:- nothing (already clean)}"

# Item 7: write the launch control block — the ONE carrier from the launcher to the daemons
# (poll_config.json.launch_control). Written right after the pre-flight clears the file, so
# it is the file's first content; every dashboard writer merges into it, never replaces it.
LAUNCH_TRACER="$TRACER" LAUNCH_TRACKERS="$TRACKER_LIST" "$VENV_PY" - "$REPO_ROOT" <<'PY'
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
p = Path(sys.argv[1]) / "system_scripts" / "poll_config.json"
block = {
    "tracer": os.environ["LAUNCH_TRACER"],
    "trackers": [t for t in os.environ["LAUNCH_TRACKERS"].split(",") if t],
    "chosen_at": datetime.now(timezone.utc).isoformat(),
}
cfg = {}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
    except Exception:
        cfg = {}
cfg["launch_control"] = block
p.write_text(json.dumps(cfg, indent=2))
print(f"[launch] control written: {p.name}.launch_control = {json.dumps(block)}")
PY

# .cr_pycache pre-flight (F32, slot 11): engine-owned regenerable bytecode cache
# (the PYTHONPYCACHEPREFIX target of the F12 fix) has no cleaner anywhere and
# only ever grows. Remove it outright — it repopulates during the run, so no
# archive is needed (regenerable engine cache, not evidence).
echo "[pre-flight] clearing engine bytecode cache system_scripts/.cr_pycache/"
rm -rf "$REPO_ROOT/system_scripts/.cr_pycache"

# (poll_config.json is deleted outright above — slider prefs never persist.)

# Per-run gearbox logs pre-flight (F18, slot 13): daemon_log.txt rotates
# (10MB x 5) but the per-run <name>_<ts>[_rN].log copies never did — the dir
# only ever grows. Prune per-run logs older than the previous run (Phase-A
# precedent: stale logs stripped, golden triplet archived) so post-boot the dir
# holds only the current and previous runs' logs.
echo "[pre-flight] pruning per-run gearbox logs older than the previous run"
"$VENV_PY" - "$REPO_ROOT" <<'PY'
import re, sys
from datetime import datetime, timedelta
from pathlib import Path

try:
    log_dir = Path(sys.argv[1]) / "system_scripts" / "daemon_log"
    # R8 / T-19: + gearbox (its own per-run log) and cheatsheets (the Builder child — never pruned before)
    # C2 / Q-H1-12 (2026-10-01): + builder (the cheatsheets child's per-run log under its pre-2026-09-09 name)
    pat = re.compile(r"^(circuit_daemon|dashboard|noai_validator|cheatsheets|builder|gearbox)_(\d{8}_\d{6})(_r\d+)?\.log$")
    runs = {}
    for entry in (log_dir.iterdir() if log_dir.is_dir() else []):
        m = pat.match(entry.name)
        if m:
            runs.setdefault(m.group(2), []).append(entry)
    if not runs:
        print("[pre-flight] per-run logs: none to prune")
    else:
        # Keep the newest run's group; the 120s window guards a boot whose
        # children stamp their <ts> across a second/minute boundary.
        newest = max(datetime.strptime(ts, "%Y%m%d_%H%M%S") for ts in runs)
        pruned = kept = 0
        for ts, files in runs.items():
            if datetime.strptime(ts, "%Y%m%d_%H%M%S") < newest - timedelta(seconds=120):
                for entry in files:
                    entry.unlink()
                    pruned += 1
            else:
                kept += len(files)
        print(f"[pre-flight] per-run logs: pruned {pruned}, kept {kept} (previous run)")
except Exception as e:
    # Pre-flight hygiene must never block a launch.
    print(f"[pre-flight] per-run log prune skipped (error: {e})")
PY

# Per-repo-id artifacts pre-flight (F19/V7, slot 14): whitelist_<id>.json /
# cb_writes_<id>.json have zero deleters (gearbox clears entries, never unlinks),
# so dead-target pairs accumulate forever. Archive any whose repo-id is not the
# current target's -> .archive/ (archive-never-delete doctrine).
# Item 5 (2026-09-09): return_channel_<id>.jsonl (the tester's outcomes) joins the
# regex. The CURRENT target's channel is archived as well: every launch is a brand-new
# scan, so a fresh run starts with an empty channel — archived, never deleted.
# I-171 (2026-09-22, run 175): confirmed_ledger_<id>.jsonl joins the regex ON THE SAME
# TERMS as the channel. The ledger is the channel's other half — the same directory and the
# channel's own name with `return_channel_` swapped for `confirmed_ledger_`
# (gearbox.confirmed_ledger_path), written on a `confirmed` verdict and read only by the
# report writer of the run that wrote it. Until now the channel left the tree at every
# launch while the ledger stayed, so one run's return path had two lifetimes and a reader
# comparing file sets across runs read the asymmetry as a loss (measured at run 172: the
# original's `return_channel_956ac2101390.jsonl` gone, three `confirmed_ledger_*` standing).
# Both halves now leave together — archived under .archive/, never deleted, and copied under
# the run by run_proof.sh `down`, which names both in RUN.md.
echo "[pre-flight] archiving per-repo-id artifacts from other targets"
"$VENV_PY" - "$REPO_ROOT" "$TARGET" <<'PY'
import hashlib, re, sys, time
from pathlib import Path

try:
    repo_root = Path(sys.argv[1])
    target = Path(sys.argv[2]).resolve()
    # Same repo-id scheme as circuit_daemon.get_repo_id: sha256(resolved path)[:12]
    current_id = hashlib.sha256(str(target).encode()).hexdigest()[:12]
    ss = repo_root / "system_scripts"
    archive = repo_root / ".archive"
    pat = re.compile(r"^(whitelist|cb_writes|return_channel|confirmed_ledger|apply_lease|attempts|gate|intent)_([0-9a-f]{12})\.jsonl?$")   # Item 8 (2026-09-15): intent_<id>.json — other targets' archived, the CURRENT target's SURVIVES (authored, never cleared). I-171 (2026-09-22): confirmed_ledger_<id>.jsonl, the channel's other half, on the channel's own terms.
    both_halves = {"return_channel", "confirmed_ledger", "apply_lease", "attempts", "gate"}   # I-171: ONE return path, ONE lifetime — the current id's copy goes too; the lease and the attempts are named beside the channel and share its lifetime (last plan item 1c, 2026-10-10). gate_<id>.jsonl (the solution gate's verdicts on those attempts) shares it too: a verdict says what the gate did to THIS launch's bytes, so one kept across a relaunch read "integrated" on a restored target it never wrote (live tree 1, 2026-10-10)
    moved = 0
    for entry in sorted(ss.iterdir()):
        m = pat.match(entry.name)
        if not m:
            continue
        if m.group(2) == current_id and m.group(1) not in both_halves:
            continue
        archive.mkdir(exist_ok=True)
        dest = archive / entry.name
        if dest.exists():
            dest = archive / f"{entry.stem}_{time.strftime('%Y%m%d_%H%M%S')}{entry.suffix}"
        entry.rename(dest)
        moved += 1
        print(f"[pre-flight] archived {entry.name} -> .archive/{dest.name}")
    if moved == 0:
        print(f"[pre-flight] per-repo-id artifacts: none stale (current id {current_id})")
except Exception as e:
    # Pre-flight hygiene must never block a launch.
    print(f"[pre-flight] per-repo-id artifact archive skipped (error: {e})")
PY

# C2 / Q-H1-11 (2026-10-01): `.intent_<id>.lock` are intent_file's flock files (zero bytes, opened "a+" on
# every use, so regenerable) — one per target ever launched, never removed by anything (21 of them by
# 09-29). No daemon runs at this point, so every one of them goes, named here.
INTENT_LOCKS=""
for f in "$REPO_ROOT"/system_scripts/.intent_*.lock; do
    [ -e "$f" ] || continue
    rm -f "$f" && INTENT_LOCKS="$INTENT_LOCKS $(basename "$f")"
done
echo "[pre-flight] intent locks removed:${INTENT_LOCKS:- none}"

# ── C2 / Q-H1-7 retention (owner ruling 5, 2026-10-01) ──────────────────────────────────────────
# Both ~/CodeRadar_snapshots/ (COPY-FIRST snapshots, `<target>_<stamp>`) and .archive/runs/<name>/ (the
# gearbox's per-target run record) grew without limit (277 snapshots / 758 MB, 157 run dirs / 913 MB on
# 09-30). Kept: the newest 10 SUCCESSFUL launches + the newest 5 FAILED ones, and nothing older than 14
# days — whichever is smaller. A snapshot is "failed" when the EXIT trap below renamed it `_FAILED` /
# `_INTERRUPTED` (its launch never reached the daemons); a run dir's verdict is the gearbox's
# launch_verdict.json (absent on records older than this rule → counted with the successful ones, so the
# cap still bounds them). The CURRENT target's run dir is never touched here (under MCP its launch.log is
# this very launch's stdout). Every deletion is NAMED in this log with its size and age; an error never
# blocks the launch. The block between the markers is what C2's harness runs against a scratch tree.
echo "[pre-flight] retention: snapshots and .archive/runs (keep last 10 successful + last 5 failed, 14 days)"
CR_SNAP_ROOT="$SNAP_ROOT" CR_RUNS_DIR="$REPO_ROOT/.archive/runs" CR_EVIDENCE_DIR="$REPO_ROOT/.archive/gate_evidence/recall" CR_CURRENT_RUN="$(basename "$TARGET")" "$VENV_PY" - <<'PY'
# --- C2 retention block: begin ---
import json, os, re, shutil, sys, time
from datetime import datetime
from pathlib import Path

KEEP_SUCCESSFUL, KEEP_FAILED, KEEP_DAYS = 10, 5, 14   # owner ruling 5 (2026-10-01)
_STAMP = re.compile(r"^(.+)_(\d{8}_\d{6})(_FAILED|_INTERRUPTED)?$")
_NOW = time.time()


def _size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def _stamp_epoch(stamp: str) -> float | None:
    try:
        return datetime.strptime(stamp, "%Y%m%d_%H%M%S").timestamp()
    except ValueError:
        return None


def _newest_mtime(d: Path) -> float:
    best = d.stat().st_mtime
    try:
        for e in d.iterdir():
            best = max(best, e.stat().st_mtime)
    except OSError:
        pass
    return best


def _keep_manifest(path: Path, label: str) -> None:
    """E2: move `<run>/manifest.json` (if it carries `planted_findings`) to the recall guard's permanent root
    before the run dir goes. Raises OSError when the move fails, so the caller leaves the dir in place."""
    if label != "run dir":
        return
    mf = path / "manifest.json"
    if not mf.is_file():
        return
    try:
        planted = bool(json.loads(mf.read_text(encoding="utf-8")).get("planted_findings"))
    except ValueError:
        planted = True   # unreadable, but it claims to be a manifest — keep it for the guard to report (I-105)
    if not planted:
        return
    dest = Path(os.environ["CR_EVIDENCE_DIR"]) / path.name / "manifest.json"
    if dest.is_file():
        print(f"[pre-flight] retention: {path.name}/manifest.json already kept at {dest.parent}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(mf), str(dest))
    print(f"[pre-flight] retention: kept {path.name}/manifest.json → {dest.parent} (recall guard evidence)")


def prune(label: str, entries: list, keep_current: str | None = None) -> list:
    """entries: (path, bucket, when_epoch). Returns the (path, why) removed. The newest KEEP_* of each
    bucket survive, and only while younger than KEEP_DAYS; `keep_current` is never removed."""
    by_bucket: dict = {"successful": [], "failed": []}
    for path, bucket, when in entries:
        by_bucket[bucket].append((when, path))
    cap = {"successful": KEEP_SUCCESSFUL, "failed": KEEP_FAILED}
    cutoff = _NOW - KEEP_DAYS * 86400
    removed, kept = [], {"successful": 0, "failed": 0}
    for bucket, items in by_bucket.items():
        items.sort(reverse=True)   # newest first
        rank = 0
        for when, path in items:
            if keep_current and path.name == keep_current:
                kept[bucket] += 1
                continue
            rank += 1
            age_d = (_NOW - when) / 86400
            if rank > cap[bucket]:
                removed.append((path, f"{bucket} #{rank} > last {cap[bucket]}", age_d))
            elif when < cutoff:
                removed.append((path, f"{bucket}, {age_d:.0f} days > {KEEP_DAYS}", age_d))
            else:
                kept[bucket] += 1
    for path, why, age_d in sorted(removed, key=lambda r: r[0].name):
        size = _size(path)
        try:
            # E2 (2026-10-01): a run dir's manifest.json with `planted_findings` is the recall guard's evidence
            # (health step 18). Retention never deletes gate evidence — the manifest is MOVED to
            # .archive/gate_evidence/recall/<run>/ first (named here); if that move fails the dir stays.
            _keep_manifest(path, label)
            shutil.rmtree(path)
            print(f"[pre-flight] retention: removed {label} {path.name} ({_fmt(size)}, {age_d:.0f} days; {why})")
        except OSError as e:
            print(f"[pre-flight] retention: {label} {path.name} NOT removed ({type(e).__name__}: {e})")
    print(f"[pre-flight] retention: {label}: kept {kept['successful']} successful + {kept['failed']} failed, "
          f"removed {len(removed)}")
    return removed


try:
    snap_root = Path(os.environ["CR_SNAP_ROOT"])
    snaps = []
    if snap_root.is_dir():
        for d in snap_root.iterdir():
            m = _STAMP.match(d.name)
            if not d.is_dir() or d.is_symlink() or not m:
                continue   # not a COPY-FIRST snapshot by name — never touched
            when = _stamp_epoch(m.group(2))
            if when is None:
                continue
            snaps.append((d, "failed" if m.group(3) else "successful", when))
        print(f"[pre-flight] retention: snapshots under {snap_root}: {len(snaps)} launch dir(s), {_fmt(_size(snap_root))}")
        prune("snapshot", snaps)
    else:
        print(f"[pre-flight] retention: snapshots: {snap_root} absent — nothing to keep or remove")
except Exception as e:
    print(f"[pre-flight] retention: snapshots skipped (error: {type(e).__name__}: {e})")

try:
    runs_dir = Path(os.environ["CR_RUNS_DIR"])
    current = os.environ.get("CR_CURRENT_RUN") or None
    runs = []
    if runs_dir.is_dir():
        for d in runs_dir.iterdir():
            if not d.is_dir() or d.is_symlink():
                continue
            bucket, when = "successful", None
            try:
                verdict = json.loads((d / "launch_verdict.json").read_text())
                if verdict.get("launch") in ("failed", "interrupted"):
                    bucket = "failed"
                when = _stamp_epoch(str(verdict.get("stamp") or ""))
            except (OSError, ValueError):
                pass   # no verdict (a record older than this rule): successful bucket, dated by its files
            runs.append((d, bucket, when if when is not None else _newest_mtime(d)))
        print(f"[pre-flight] retention: .archive/runs: {len(runs)} run dir(s), {_fmt(_size(runs_dir))}"
              + (f"; the current target's ({current}) is kept whatever its age" if current else ""))
        prune("run dir", runs, keep_current=current)
    else:
        print("[pre-flight] retention: .archive/runs absent — nothing to keep or remove")
except Exception as e:
    print(f"[pre-flight] retention: .archive/runs skipped (error: {type(e).__name__}: {e})")
# --- C2 retention block: end ---
PY

# Copy setup (express plan, 2026-09-10): the dashboard port is this tree's, from
# system_scripts/copy_ports.json (8080 in the original; 8081.. in the app copies).
DASH_PORT="$("$VENV_PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("dashboard", 8080))' "$REPO_ROOT/system_scripts/copy_ports.json" 2>/dev/null || echo 8080)"
if DASH_PORT="$DASH_PORT" "$VENV_PY" - <<'PY'
import os, socket, sys, time
# B8 / Q-H1-5: a dashboard the pre-flight just stopped may hold the port for a few seconds — wait for it
for _ in range(25):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy = s.connect_ex(("127.0.0.1", int(os.environ["DASH_PORT"]))) == 0
    s.close()
    if not busy:
        sys.exit(0)
    time.sleep(0.2)
sys.exit(1)
PY
then
    echo "[pre-flight] port $DASH_PORT: free"
else
    # B8 / Q-H1-5: name the holder (never stop it — it was not started by this launch) and the command
    HOLDER="$(lsof -nP -iTCP:"$DASH_PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print "    PID " $2 " " $1}' | sort -u | tr '\n' ';' || true)"
    echo "launch.sh: ABORT — port $DASH_PORT is already in use (dashboard cannot bind) — held by:${HOLDER:+ }${HOLDER:-(not visible to lsof — try: sudo lsof -nP -iTCP:$DASH_PORT -sTCP:LISTEN)}" >&2
    [ -n "$HOLDER" ] && echo "launch.sh: if it is a CodeRadar dashboard of an earlier run: kill $(lsof -nP -iTCP:"$DASH_PORT" -sTCP:LISTEN -t 2>/dev/null | sort -u | tr '\n' ' ')  (then launch again); anything else — leave it, change the port in system_scripts/copy_ports.json" >&2
    exit 1
fi

# Lane B (owner 2026-09-30): the setup page's optional purpose goes to the target's intent file HERE —
# after pre-flight (which archives other targets' intent files and keeps the current one's) and before
# the gearbox starts any daemon, so the dashboard's purpose box and the scan both see it.
if [ -n "$PURPOSE" ]; then
    printf '%s' "$PURPOSE" | PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" "$REPO_ROOT/system_scripts/launch_setup.py" --submit-purpose "$TARGET" \
        || echo "[setup] purpose NOT written to the intent file (see above) — enter it on the dashboard"
fi

# ── Overlay first (owner 2026-09-29): the dash comes up BEFORE any step that reads the target ──
# A long step with nothing on screen looks hung (the health check alone is ~80 s), so the gearbox
# starts now — it brings the dashboard up and holds every daemon until the four launch steps below
# finish. Each step reports into system_scripts/launch_progress.json; the overlay gives each its own
# light (snapshot, health check, whitelist scan, target env) beside the daemon lights.
PROGRESS="$REPO_ROOT/system_scripts/launch_progress.json"
CUR_STAGE=""
STAGES_DONE=0
GB_PID=""
FAIL_WHY=""   # a step that knows why it failed says so here before `exit`; the EXIT trap publishes it
STOP_SIG=""   # B8 / Q-H1-9 (2026-10-01): set by the INT/TERM trap — a step cut short is "interrupted", never FAILED
STOP_RC=130
SNAP_DIR=""   # C2 / Q-H1-7: set by step 0; a launch that never reaches the daemons renames it (_mark_snapshot)
# C2 / Q-H1-7 (2026-10-01): a snapshot whose launch stopped before the daemons (a failed step, a broken copy,
# Ctrl-C mid-copy) is renamed `<name>_FAILED` / `<name>_INTERRUPTED` once the gearbox is done with it — so
# "the latest snapshot" (teardown_identity.find_snapshot, run_proof.sh, MCP) never picks a broken copy, and
# the pre-flight retention counts it in the failed bucket (last 5), never among the successful launches.
_mark_snapshot() {   # _mark_snapshot FAILED|INTERRUPTED
    [ -n "$SNAP_DIR" ] && [ -d "$SNAP_DIR" ] || return 0
    if mv "$SNAP_DIR" "${SNAP_DIR}_$1" 2>/dev/null; then
        echo "[launch] snapshot $(basename "$SNAP_DIR") renamed $(basename "$SNAP_DIR")_$1 — this launch never reached the daemons; the next pre-flight's retention counts it as a failed launch" >&2
    else
        echo "[launch] snapshot $SNAP_DIR could not be renamed _$1 — it stays under its stamp name" >&2
    fi
}
progress() {   # progress <stage|-> <status> [detail] — status: pending|running|pass|degraded|red|fail|done|failed|interrupted (red = finished, verdict red, launch goes on)
    # the step list and the locked write live in launch_progress.py — the gearbox writes the same file
    # at the same time; a light that cannot be recorded never stops the launch
    PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" "$REPO_ROOT/system_scripts/launch_progress.py" "$PROGRESS" "$1" "$2" "${3:-}" "${PROG_STARTED:-}" || true
}
rm -f "$PROGRESS" "$PROGRESS.lock"
# owner 2026-09-30: a failed launch is closed from the overlay — its buttons write this file, the gearbox
# sees it and tears down, and the EXIT trap below reads which button it was
CLOSE_REQ="$REPO_ROOT/system_scripts/close_request.json"
rm -f "$CLOSE_REQ"
progress - running
progress choices pass "target=$TARGET tracer=$TRACER trackers=${TRACKER_LIST:-none} purpose=$([ -n "$PURPOSE" ] && echo given || echo none)"   # Lane B (owner 2026-09-30): path + options on the overlay
PROG_STARTED="$PREFLIGHT_T0" progress preflight pass "stopped any earlier CodeRadar run, cleared its saved state, freed port $DASH_PORT"
_stop_load_proof() {
    # A: the recorder stops with every launch exit; closing its pipe ends the root eslogger with it
    [ -n "$LOAD_PROOF_PID" ] || return 0
    kill -TERM "$LOAD_PROOF_PID" 2>/dev/null || true
    wait "$LOAD_PROOF_PID" 2>/dev/null || true
    LOAD_PROOF_PID=""
}
_launch_exit() {
    local rc=$?
    _stop_load_proof
    if [ -n "$STOP_SIG" ] && [ "$STAGES_DONE" -ne 1 ]; then
        # B8 / Q-H1-9: a stop request during a launch step — the step was not measured, nothing failed.
        # The gearbox already has SIGTERM (the trap) and tears down; its record stays `interrupted`.
        echo "[launch] interrupted by $STOP_SIG at step '${CUR_STAGE:-between steps}' — not measured, nothing failed; the gearbox is tearing down" >&2
        [ -n "$CUR_STAGE" ] && progress "$CUR_STAGE" interrupted "interrupted by $STOP_SIG — not measured" || true
        progress - interrupted "interrupted by $STOP_SIG at step '${CUR_STAGE:-between steps}' — nothing failed, nothing measured" || true
        [ -n "$GB_PID" ] && wait "$GB_PID" 2>/dev/null || true
        _mark_snapshot INTERRUPTED   # C2 / Q-H1-7: after the gearbox's teardown (its identity check read the snapshot)
        rm -f "$CLOSE_REQ"
        exit "$STOP_RC"
    fi
    if [ "$STAGES_DONE" -eq 1 ] && [ -z "$STOP_SIG" ] && [ -n "$GB_PID" ] && [ "$rc" -ge 128 ] \
       && ! kill -0 "$GB_PID" 2>/dev/null && [ -f "$REPO_ROOT/system_scripts/gearbox_pids.json" ]; then
        # B8 / Q-H1-5: the gearbox died without a teardown (kill -9, a crash) after the launch steps — its
        # children keep running on the port. The process record it wrote (gearbox_pids.json) proves which
        # pids are CodeRadar's own from THIS run, so launch.sh stops them (by process group) and says so.
        local stopped
        stopped="$(stop_dead_gearbox_children "$GB_PID" 2>&1 || true)"
        echo "launch.sh: the gearbox died (exit $rc) without a teardown — ${stopped:-no process record, nothing stopped}" >&2
        echo "launch.sh: teardown NOT verified (the gearbox's leave-no-trace check did not run) — the next launch's pre-flight reports any leftover" >&2
        progress - failed "the gearbox died (exit $rc) — ${stopped:-its daemons not stopped}; teardown NOT verified" || true
    fi
    if [ "$STAGES_DONE" -ne 1 ] && [ -n "$GB_PID" ]; then
        if [ -n "$FAIL_WHY" ]; then
            [ -n "$CUR_STAGE" ] && progress "$CUR_STAGE" fail "$FAIL_WHY" || true
            progress - failed "$FAIL_WHY" || true
        else
            [ -n "$CUR_STAGE" ] && progress "$CUR_STAGE" fail "stopped (exit $rc) — see the terminal" || true
            progress - failed "launch step '${CUR_STAGE:-?}' failed (exit $rc)" || true
        fi
    fi
    [ -n "$GB_PID" ] && wait "$GB_PID" 2>/dev/null || true
    [ "$STAGES_DONE" -ne 1 ] && _mark_snapshot FAILED   # C2 / Q-H1-7: the daemons never started — a failed launch's copy
    if [ -f "$CLOSE_REQ" ] && grep -q '"setup"' "$CLOSE_REQ"; then
        rm -f "$CLOSE_REQ"
        # C2 / Q-H1-10 (2026-10-01): "back to setup" is the setup PAGE's feature (GEARBOX_TAB is set only on that
        # path). An argv or MCP launch has no page waiting: re-opening the setup server here left it holding the
        # dash port where neither cr_stop nor the pre-flight looked for it — so such a request only closes.
        if [ -n "${GEARBOX_TAB[*]+x}" ]; then   # the array exists only on the page path (bash 3.2, set -u)
            echo "[launch] back to the setup page"
            exec "$REPO_ROOT/launch.sh" --back-to-setup
        fi
        echo "[launch] 'back to setup' requested, but this launch was not started from the setup page — closed instead (launch again with ./launch.sh and no target to use the page)"
    fi
    rm -f "$CLOSE_REQ"
}
if [ -n "${SETUP_ERR_LOG:-}" ]; then exec 2>&3; rm -f "$SETUP_ERR_LOG"; fi   # from here the overlay reports failures
trap _launch_exit EXIT
# B8 / Q-H1-9: a stop request forwards SIGTERM to the gearbox (its teardown) and, during the launch steps,
# ends the launch as "interrupted" through the EXIT trap (exit 130 / 143 — never a FAILED step). After the
# steps (the daemons are up, Ctrl-C is the owner's close) it only forwards, as before. A terminal Ctrl-C
# already reaches the running step (same process group); SIGTERM is passed on to it by hand.
_on_stop() {
    STOP_SIG="$1"; STOP_RC="$2"
    [ -n "$GB_PID" ] && kill -TERM "$GB_PID" 2>/dev/null
    [ "$1" = SIGTERM ] && pkill -TERM -P $$ 2>/dev/null
    [ "$STAGES_DONE" -ne 1 ] && exit "$STOP_RC"
    true
}
trap '_on_stop Ctrl-C 130' INT
trap '_on_stop SIGTERM 143' TERM
if [ "$LOAD_PROOF" -eq 1 ]; then
    # A: the recorder runs from the start, so a target started any time after this is proven from its first
    # import. It runs as the user; only its `sudo -n eslogger` child is root, and that dies with the pipe.
    "$VENV_PY" "$REPO_ROOT/system_scripts/load_recorder.py" --target "$TARGET" \
        --out "$REPO_ROOT/system_scripts/load_proof.json" 2>>"$REPO_ROOT/system_scripts/daemon_log/load_proof.log" &
    LOAD_PROOF_PID=$!
    echo "[load proof] eslogger recording target-module loads (pid $LOAD_PROOF_PID)"
fi
echo "[launch] gearbox started — dashboard first, daemons wait for the launch steps"
"$VENV_PY" "$REPO_ROOT/system_scripts/gearbox.py" "$TARGET" --staged "$PROGRESS" ${GEARBOX_TAB[@]+"${GEARBOX_TAB[@]}"} &
GB_PID=$!

CUR_STAGE=snapshot; progress snapshot running
# ── Step 0: COPY-FIRST snapshot ─────────────────────────────────────────────
# owner 2026-09-30: the snapshot is always taken — there is no --no-copy
if true; then
    TS="$(date +%Y%m%d_%H%M%S)"
    SNAP_DIR="$SNAP_ROOT/$(basename "$TARGET")_${TS}"
    # Snapshot must never land inside the target (S2: CR must not scan its own backup).
    case "$SNAP_DIR/" in
        "$TARGET"/*)
            echo "launch.sh: snapshot dir $SNAP_DIR would be inside the target — refusing" >&2
            exit 1 ;;
    esac
    echo "[step 0] COPY-FIRST: $TARGET -> $SNAP_DIR"
    mkdir -p "$SNAP_DIR"
    # Q10 (B7): the snapshot is the ONE set of system_scripts/snapshot_files.sh — env dirs
    # (pyvenv.cfg / conda-meta/), node_modules, tool caches and CodeRadar's own root .coderadar/
    # (its old state mirrors — R8 / T-10) are not copied, and the count
    # check below counts that same set on both sides.
    SNAP_FILES="$REPO_ROOT/system_scripts/snapshot_files.sh"
    bash "$SNAP_FILES" "$TARGET" --links | (cd "$TARGET" && tar -cf - -n -T -) | tar -xpf - -C "$SNAP_DIR"

    # Verify: sorted relative file lists must be identical, counts must match.
    SRC_LIST="$(bash "$SNAP_FILES" "$TARGET")"
    DST_LIST="$(bash "$SNAP_FILES" "$SNAP_DIR")"
    SRC_COUNT="$(printf '%s\n' "$SRC_LIST" | grep -c . || true)"
    DST_COUNT="$(printf '%s\n' "$DST_LIST" | grep -c . || true)"
    if [ "$SRC_LIST" != "$DST_LIST" ] || [ "$SRC_COUNT" != "$DST_COUNT" ]; then
        echo "[step 0] SNAPSHOT VERIFY FAILED (src $SRC_COUNT files, snap $DST_COUNT files) — ABORTING" >&2
        diff <(printf '%s\n' "$SRC_LIST") <(printf '%s\n' "$DST_LIST") >&2 || true
        exit 1
    fi
    ALL_COUNT="$(cd "$TARGET" && find . -type f | wc -l | tr -d ' ')"
    echo "[step 0] snapshot verified: $SRC_COUNT files, file lists identical ($((ALL_COUNT - SRC_COUNT)) of $ALL_COUNT target files skipped: env dirs / node_modules / tool caches / CodeRadar's own .coderadar/); size $(du -sh "$SNAP_DIR" | cut -f1) vs target $(du -sh "$TARGET" | cut -f1)"
fi
progress snapshot pass "$SRC_COUNT files copied to $SNAP_DIR and verified"; CUR_STAGE=""

CUR_STAGE=health; progress health running
# ── Step 1b: HEALTH CHECK — before the filters (owner ruling 2026-09-05 §1a) ──
# The harness (system_scripts/health_check.py, Steps 1-21 plus 12b, 22 step markers) is the original gate
# of the original flow (cli.py run_health_check). It runs here, before any
# filter or daemon, and a failure aborts the launch. Components with no working
# example (ToleranceCalibrator, plan item 9) are reported NOT MEASURED, never
# as a pass and never as a failure. The full report is archived every launch.
echo "[health check] running health_check.py — aborts on failure"
mkdir -p "$REPO_ROOT/.archive/health"
HEALTH_LOG="$REPO_ROOT/.archive/health/health_$(date +%Y%m%d_%H%M%S).txt"
health_first_fail() {   # <report> <rc> — "step N — <first ✗ line>"; else the first ✗ anywhere; else the last line
    local why
    why="$(awk '
        /^▶ Step / { s = $3; sub(/:$/, "", s) }
        /^[[:space:]]*✗/ { l = $0; sub(/^[[:space:]]*✗[[:space:]]*/, "", l); print (s != "" ? "step " s " — " : "") l; found = 1; exit }
        /✗/ && !/^HEALTH CHECK/ && backup == "" { backup = (s != "" ? "step " s " — " : "") $0 }
        END { if (!found && backup != "") print backup }
    ' "$1" 2>/dev/null || true)"
    [ -n "$why" ] || why="exit $2, no ✗ line — last line: $(grep -v '^[[:space:]]*$' "$1" 2>/dev/null | tail -n 1 || true)"
    printf '%s' "$why"
}
cd "$REPO_ROOT"
HEALTH_RC=0
"$VENV_PY" "$REPO_ROOT/system_scripts/health_check.py" > "$HEALTH_LOG" 2>&1 || HEALTH_RC=$?
if [ "$HEALTH_RC" -eq 0 ]; then
    grep -E "^HEALTH CHECK|^NOT MEASURED" "$HEALTH_LOG" | sed 's/^/[health check] /'
    echo "[health check] PASS — report: $HEALTH_LOG"
elif [ -n "$STOP_SIG" ] || [ "$HEALTH_RC" -eq 130 ] || [ "$HEALTH_RC" -eq 143 ]; then
    # B8 / Q-H1-9: the check was cut short by a stop request — not measured, not a failure (the EXIT trap says so)
    [ -n "$STOP_SIG" ] || { STOP_SIG="a stop signal (exit $HEALTH_RC)"; STOP_RC="$HEALTH_RC"; }
    exit "$STOP_RC"
else
    echo "launch.sh: ABORT — health check FAILED (report: $HEALTH_LOG)" >&2
    grep -E "✗|^HEALTH CHECK" "$HEALTH_LOG" | sed 's/^/[health check] /' >&2 || true
    # the overlay's health light and its closing red line both name the failing step (EXIT trap)
    FAIL_WHY="health check failed: $(health_first_fail "$HEALTH_LOG" "$HEALTH_RC") — report: $HEALTH_LOG"
    exit 1
fi
# the light's line comes from the report: steps run, NOT MEASURED lines, the report file
HEALTH_STEPS="$(grep -c '^▶ Step' "$HEALTH_LOG" || true)"
HEALTH_NM="$(grep -c '^NOT MEASURED:' "$HEALTH_LOG" || true)"
progress health pass "all $HEALTH_STEPS self-test steps pass · $HEALTH_NM NOT MEASURED (each reason is in the report) — report: $(basename "$HEALTH_LOG")"
CUR_STAGE=""

CUR_STAGE=whitelist; progress whitelist running
# ── Step 2: Whitelist stage (S1 — built BEFORE the daemons start) ──────────
echo "[whitelist] running detritus scan (pre-daemon stage, seam S1)"
cd "$REPO_ROOT"
"$VENV_PY" - "$TARGET" <<'PY'
import asyncio, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

target = Path(sys.argv[1]).resolve()
# Same repo-id scheme as circuit_daemon.get_repo_id: sha256(resolved path)[:12]
repo_id = hashlib.sha256(str(target).encode()).hexdigest()[:12]

from collections import Counter
from detritus_cleaner import DetritusCleaner

# Owner 2026-09-05: filter 1 = DETRITUS, filter 2 = ARTIFACTS, ONE whitelist, nothing
# carried over from any previous scan (every scan is a brand-new scan).
cleaner = DetritusCleaner(str(target))
result = asyncio.run(cleaner.scan())
artifacts = sorted(p for p in result.detritus_files if p in cleaner.artifact_species)
detritus = sorted(p for p in result.detritus_files if p not in cleaner.artifact_species)
# owner 2026-09-29: EVERY .py is scanned, recursively — a module no import reaches (loaded by file path,
# run as a script, a plugin, a stray) is NOT whitelisted: we'd never know what's in it. Unreachability is
# recorded as a fact (`unreachable_by_import`), never a reason to skip. The whitelist holds only non-.py
# artifacts, the artifact scanner's known whole-file stubs (stub:<kind>) and the bytecode rows.
unreachable_by_import = list(detritus)
entries = [{"path": p, "reason": f"artifact:{cleaner.artifact_species[p]}"} for p in artifacts]
species = Counter(cleaner.artifact_species[p] for p in artifacts)
# ARTIFACT SCANNER (Item 3, 2026-09-10) — the second scanner, not built on the detritus cleaner: whole-file stubs go
# on the ONE whitelist as stub:<kind> (ruling 13 / 2026-09-09); proxies and tests are NOT whitelisted (scanned,
# withheld by the ranker); the dot-dir intent sources' facts ride in the payload for the intent file (Item 8).
artifact_summary = {"stage": "ARTIFACTS", "status": "NOT MEASURED"}
intent_facts = []
proxies_by_path = {}
tests_kept_live = {}   # Item 10: test-species files withdrawn from filter 1 (rel -> "test")
try:
    sys.path.insert(0, str(Path.cwd()))
    from no_aivalidator.artifact_scanner import analyze as _artifact_analyze
    # The scanner reads EVERY .py the cleaner did not call an artifact — the live set AND filter 1's unreachable
    # modules — because a proxy (a demo, a runner, a git / path-hack script, an assertion-only file) is by its nature
    # a file nothing imports: filter 1 calls it unreachable, the artifact scanner knows it by CONTENT as a proxy for
    # not running the source. Found live on run 103 launch A (2026-09-15): every root proxy plant was whitelisted
    # `detritus:unreachable` before the scanner saw it. A proxy is NOT detritus and NOT whitelisted (the plan): its
    # `detritus:unreachable` entry is withdrawn, it stays live, the ranker withholds its rows under `proxy:<kind>`.
    _candidates = [target / p for p in sorted(set(result.live_files) | set(detritus))]
    _report = asyncio.run(_artifact_analyze(target, files=_candidates))
    _proxies = _report.proxies()
    # Item 10 (2026-09-15): a TEST-species file (pytest / unittest by content — `tests/test_x.py`, `conftest.py`)
    # that no entry imports is not detritus either: a test runner reaches it. It stays live like a proxy —
    # scanned, its rows withheld under species:test and counted by the test-runner tracker, drawn so the
    # inverted triangle can sit above the file pytest is run on (owner ruling 2026-09-15). Found on run 108
    # launch A: every `tests/*.py` of the target was `detritus:unreachable`, so no test file was a node.
    _tests = {rel for rel, f in _report.species.items() if getattr(f, "species", "") == "test"}
    _kept_live = {e["path"]: (_proxies.get(e["path"]) or "test") for e in entries
                  if e["reason"] == "detritus:unreachable" and (e["path"] in _proxies or e["path"] in _tests)}
    entries = [e for e in entries if e["path"] not in _kept_live]
    detritus = [p for p in detritus if p not in _kept_live]
    result.live_files = set(result.live_files) | set(_kept_live)
    result.live_files = set(result.live_files) | set(unreachable_by_import)   # owner 2026-09-29: scanned
    detritus = []
    _stub_entries = [e for e in _report.whitelist_entries() if e["path"] not in {x["path"] for x in entries}]
    entries += _stub_entries
    artifact_summary = _report.summary()
    artifact_summary["proxies_kept_live"] = dict(sorted(_kept_live.items()))
    proxies_by_path = dict(sorted(_proxies.items()))
    tests_kept_live = {k: v for k, v in sorted(_kept_live.items()) if v == "test"}
    intent_facts = [f.as_dict() for f in _report.intent_facts]
    # Item 8 (2026-09-15): the intent-source facts go to the INTENT FILE — replacing only the facts whose source is an
    # intent-source species (a rescan refreshes what a scan found; the developer's statement and every other source stay).
    try:
        sys.path.insert(0, str(Path.cwd() / "system_scripts"))
        import intent_file as _intent
        _idata = _intent.replace_source_facts(target, intent_facts, _intent.INTENT_SOURCE_SPECIES)
        print(f"[intent file] {_intent.path(target).name}: statement {'present' if _idata.get('statement') else 'none'} · "
              f"facts by source {_intent.facts_by_source(_idata)}")
    except Exception as _ie:
        print(f"[intent file] NOT WRITTEN: {type(_ie).__name__}: {_ie}")
    _px = Counter(v.split(":", 1)[1] for v in _proxies.values())
    print("[artifact scanner] proxies: " + (", ".join(f"{k} {v}" for k, v in _px.most_common()) or "none")
          + f" ({sum(1 for v in _kept_live.values() if v != 'test')} proxy + {sum(1 for v in _kept_live.values() if v == 'test')} test file(s) withdrawn from filter 1 — neither is detritus: scanned, withheld; tests tracked, Item 10)"
          + " · stubs: " + (", ".join(f"{k} {v}" for k, v in Counter(_report.stubs.values()).most_common()) or "none")
          + " · intent sources: " + (", ".join(artifact_summary["intent_sources"]) or "none")
          + f" ({len(intent_facts)} facts) · {len(_stub_entries)} stub file(s) added to the whitelist")
except Exception as _e:
    proxies_by_path = {}
    tests_kept_live = {}
    print(f"[artifact scanner] NOT MEASURED: {type(_e).__name__}: {_e}")
# I-156 (2026-09-22, run 175) — THE ARTIFACT CARRIES THE BYTECODE CLASS TOO.
# I-153 (a) made `__pycache__/` and `*.pyc` an explicit pair of whitelist rows and had
# scan_scope.load_whitelist() union them in for every reader of the LOADER, artifact or no
# artifact. The artifact ON DISK still did not carry them, so anyone opening
# whitelist_<id>.json was told nothing about the class and had to infer it from
# scan_scope._HARD_SKIP_PARTS. The rows are written HERE, where the artifact is written,
# read from scan_scope's own table so there is ONE source for both halves, and skipped if
# the scan somehow produced the same path already. They cannot move a live count: neither
# row can match a `.py` path.
bytecode_rows = []
try:
    sys.path.insert(0, str(Path.cwd() / "system_scripts"))
    import scan_scope as _scan_scope
    _have = {e["path"] for e in entries}
    bytecode_rows = [dict(e) for e in _scan_scope.BYTECODE_WHITELIST_ENTRIES if e["path"] not in _have]
    entries += bytecode_rows
    print("[whitelist] bytecode rows (I-156, from scan_scope.BYTECODE_WHITELIST_ENTRIES): "
          + ", ".join(f'{e["path"]} -> {e["reason"]}' for e in _scan_scope.BYTECODE_WHITELIST_ENTRIES)
          + f" — {len(bytecode_rows)} written into the artifact")
except Exception as _be:
    print(f"[whitelist] bytecode rows NOT WRITTEN: {type(_be).__name__}: {_be}")
out = Path("system_scripts") / f"whitelist_{repo_id}.json"
# Owner 2026-09-05 (evening): PYTHON-ONLY. Disclose the composition and refuse a
# target with no Python at all — there is nothing for CodeRadar to judge.
comp = getattr(cleaner, "composition", {}) or {}
n_py = len(result.live_files) + len(result.whitelisted_files) + len(detritus) \
       + sum(1 for p in artifacts if p.endswith(".py"))
n_non_py = comp.get("non_py_files", sum(1 for p in artifacts if not p.endswith(".py")))
payload = {
    "target": str(target),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "entries": entries,
    "summary": {
        "filter1_detritus": len(detritus),
        "filter2_artifacts": len(artifacts),
        "artifact_species": dict(species),
        "venv_dirs_by_size": {k: v for k, v in cleaner.venv_dirs.items()},
        "live": len(result.live_files),
        "package_markers": len(result.whitelisted_files),
        "python_only": {
            "doctrine": "only .py files are live source; every non-.py file is an artifact by construction",
            "py_files": n_py,
            "non_py_files": n_non_py,
        },
        "artifact_scanner": artifact_summary,
    },
    "unreachable_by_import": sorted(unreachable_by_import),   # owner 2026-09-29: a fact — every one is scanned
    "intent_facts": intent_facts,
    "proxies": proxies_by_path,   # Item 3: rel -> proxy:<kind>; the daemon keeps these OUT of its own detritus set (never whitelisted)
    "tests": tests_kept_live,     # Item 10: rel -> "test"; unreachable test-species files kept live the same way (scanned, withheld, tracked)
}
out.write_text(json.dumps(payload, indent=2))
print(f"[python-only] {n_py} .py file(s) = {len(result.live_files)} live + {len(result.whitelisted_files)} markers "
      f"+ {len(detritus)} detritus + {sum(1 for p in artifacts if p.endswith('.py'))} artifact-class .py | "
      f"{n_non_py} non-.py file(s) -> artifact by construction")
print(f"[filter 1 · detritus]  {len(unreachable_by_import)} module(s) no import reaches — all scanned (owner 2026-09-29)")
print(f"[filter 2 · artifacts] {len(artifacts)} file(s): " + (", ".join(f"{k} {v}" for k, v in species.most_common()) or "none"))
for d, b in cleaner.venv_dirs.items():
    print(f"[filter 2 · venv by size] {d}/ = {b / 1e6:.1f} MB -> artifact")
print(f"[whitelist] {out} written: {len(entries)} entries "
      f"({len(result.live_files)} live, {len(result.whitelisted_files)} package markers, "
      f"{len(bytecode_rows)} bytecode rows — I-156)")
if n_py == 0:
    print("launch.sh: ABORT — target has no .py files; CodeRadar scans Python only", file=sys.stderr)
    sys.exit(3)
PY
# The light's numbers come from the whitelist_<id>.json just written — read back, never a second scan.
WL_DETAIL="$(PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" - "$REPO_ROOT/system_scripts" "$TARGET" 2>/dev/null <<'PY' || true
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import target_env
doc = json.loads((Path(sys.argv[1]) / f"whitelist_{target_env.repo_id(Path(sys.argv[2]))}.json").read_text(encoding="utf-8"))
summary = doc.get("summary") or {}
n_py = (summary.get("python_only") or {}).get("py_files", summary.get("live", 0))
print(f"{n_py} Python files to check · {len(doc.get('entries') or [])} other files set aside (not code) · "
      f"{len(doc.get('unreachable_by_import') or [])} unreachable by import (all scanned)")
PY
)"
progress whitelist pass "$WL_DETAIL"; CUR_STAGE=""
# Fix plan 2026-10-23 C3: name every dot-directory whose .py files ARE in the scan, in the launch log,
# before any finding is read from it (`.git`, `__pycache__`, `.cr_pycache`, `.venv`, `venv`, `node_modules`
# and the root `.coderadar` are skipped by name; an env recognised by shape is skipped too). The same list
# rides on cr_status.dot_dirs_scanned.
PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" - "$REPO_ROOT" "$TARGET" <<'PY' || echo "[scan-scope] dot-directories in scope: NOT MEASURED"
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "system_scripts"))
import scan_scope
dots = scan_scope.dot_dirs_in_scope(Path(sys.argv[2]))
print("[scan-scope] dot-directories in scope: " + (", ".join(dots) if dots else "none")
      + " (skipped by name: " + ", ".join(sorted(scan_scope._HARD_SKIP_PARTS)) + ", root .coderadar)")
PY

CUR_STAGE=target_env; progress target_env running
# ── Step 2b: the target's private env (B2 / R2, Q5; B3 layout) — before the daemons ──
# Built or reused in THIS tree (.archive/target_envs/<repo_id>/), deps installed from the
# step-0 snapshot, never by building in the target. A failed build never blocks the scan:
# target_env.py always exits 0 and records `failed: <reason>`; every reader degrades and says so.
cd "$REPO_ROOT"
TE_RC=0
PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" "$REPO_ROOT/system_scripts/target_env.py" "$TARGET" \
    --snapshot "${SNAP_DIR:-}" || TE_RC=$?
# The light says what the record says — a failed build is 'degraded' (the scan proceeds on the engine's
# interpreter, Q5), never a green 'done'.
TE_OUT="$(PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" - "$REPO_ROOT/system_scripts" "$TARGET" 2>/dev/null <<'PY' || echo none
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import target_env
rec = target_env.read(Path(sys.argv[2]).resolve())
state = str(rec.get('status') or 'none')
n_pkgs = len(rec.get('installed') or [])
gap = target_env.target_dist_gap(rec)
imp = rec.get('imports') or {}
checked = len(imp.get('checked') or [])
if state == 'failed':
    verdict, detail = 'degraded', f"failed: {rec.get('reason') or 'unknown'} — the scan runs on the engine’s Python"
elif state not in ('built', 'reused'):
    verdict, detail = 'degraded', f"{state} — the scan runs on the engine’s Python"
elif imp.get('missing'):
    # M-54 (2026-10-07): the target’s own imports are tried in the env it was built — a stdlib module whose C part
    # is missing (`tkinter` without `_tkinter`) is RED: the target cannot run here (run tool, entry proof). The
    # scan proceeds; the light keeps the reason and what puts it right.
    hint = target_env.install_hint(rec)
    verdict = 'red'
    detail = target_env.cannot_run(rec) + (f" · {hint}" if hint else '') + f" · {state} · {n_pkgs} packages"
elif gap.startswith('target itself not installable'):
    # M-50 (2026-10-07): a plain folder of modules has nothing to install — built, every import resolves: green,
    # and the light says why nothing was installed (R8/T-14 kept amber for every non-installed target before)
    verdict = 'pass'
    detail = (f"{state} · {n_pkgs} packages · folder of modules (no pyproject/setup.py — nothing to install)"
              f" · {checked} imports resolve")
elif gap:
    verdict, detail = 'degraded', f"{state} · {n_pkgs} packages · {gap}"
else:
    verdict = 'pass'
    detail = (f"{state} · {n_pkgs} package(s) installed ({rec.get('installer') or '?'}) · "
              f"{rec.get('layout') or '?'} layout · {checked} imports resolve")
if imp.get('error'):
    detail += f" · import probe: {imp['error']}"
print(verdict)
print(detail)
PY
)"
TE_VERDICT="$(printf '%s\n' "$TE_OUT" | sed -n 1p)"
TE_DETAIL="$(printf '%s\n' "$TE_OUT" | sed -n 2p)"
if [ "$TE_RC" -ne 0 ]; then
    echo "[target env] failed: target_env.py rc=$TE_RC — the scan proceeds (Q5)"
    progress target_env degraded "could not build your repo's Python env (target_env.py exit $TE_RC) — the scan goes on with CodeRadar's own Python"
else
    case "$TE_VERDICT" in
        pass|degraded|red) echo "[target env] $TE_VERDICT: $TE_DETAIL"; progress target_env "$TE_VERDICT" "$TE_DETAIL" ;;
        *) progress target_env degraded "could not read the env record ($TE_VERDICT) — the scan goes on with CodeRadar's own Python" ;;
    esac
fi
CUR_STAGE=""

# ── I-153 (e) — B10 (Q-H1-1, 2026-10-01): the pollution reading of CR's OWN tree, taken AFTER the
# launch steps ran their children (health check, whitelist, target_env). It walks the whole tree —
# not only the __pycache__ dirs it knows — and counts every .pyc/.pyo and every .mypy_cache file newer
# than launch start. The engine's own scratch (.cr_pycache, where the env block above sends the
# bytecode), the venv, .archive and the recall targets are outside the reading. A walk that fails is
# NOT MEASURED, never 0. The line goes to the terminal and into the archived health report.
HYG_LINE="$("$VENV_PY" - "$REPO_ROOT" "$LAUNCH_T0" <<'PY' || echo "[launch hygiene] I-153 (e): NOT MEASURED (the walker did not run)"
import os, sys
root, t0 = sys.argv[1], float(sys.argv[2])
skip = {".venv_new", ".archive", ".cr_pycache", ".git", "node_modules"}
pyc, mypy, dirs = [], [], 0
try:
    for d, subdirs, files in os.walk(root):
        subdirs[:] = [s for s in subdirs if s not in skip and not s.endswith("recall_targets")]
        dirs += 1
        in_mypy = ".mypy_cache" in os.path.relpath(d, root).split(os.sep)
        for f in files:
            p = os.path.join(d, f)
            try:
                if os.stat(p).st_mtime < t0:
                    continue
            except OSError:
                continue
            if in_mypy:
                mypy.append(os.path.relpath(p, root))
            elif f.endswith((".pyc", ".pyo")):
                pyc.append(os.path.relpath(p, root))
except Exception as e:
    print(f"[launch hygiene] I-153 (e): NOT MEASURED ({type(e).__name__}: {e})")
    sys.exit(0)
if dirs == 0 or not os.path.isdir(root):   # os.walk yields nothing for a missing root — that is no reading
    print(f"[launch hygiene] I-153 (e): NOT MEASURED (could not walk {root})")
    sys.exit(0)
n = len(pyc) + len(mypy)
verdict = "clean" if n == 0 else "POLLUTED"
line = (f"[launch hygiene] I-153 (e): {verdict} — {len(pyc)} .pyc and {len(mypy)} mypy-cache files written into "
        f"CodeRadar's own tree since launch start ({dirs} dirs walked; .cr_pycache is the engine's scratch, outside the reading)")
if n:
    line += " — first: " + ", ".join((pyc + mypy)[:8])
print(line)
PY
)"
echo "$HYG_LINE"
printf '\n%s\n' "$HYG_LINE" >> "$HEALTH_LOG" 2>/dev/null || true

# ── Step 3: the launch steps are done — the gearbox starts the daemons ──────
STAGES_DONE=1
progress - done
echo "[launch] launch steps done — gearbox starts the daemons"
wait "$GB_PID"
