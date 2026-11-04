#!/usr/bin/env bash
# run_proof.sh — ONE live proof run (owner 2026-09-08: "done = RUN").
#
#   system_scripts/run_proof.sh up   TARGET RUN_NO "ITEM" [--tracer lsof] [launch flags…]
#   system_scripts/run_proof.sh down TARGET RUN_NO "ITEM" [POOL_FILE|-]
#   system_scripts/run_proof.sh all  TARGET RUN_NO "ITEM" [POOL_FILE|-] [HOLD_S] [--tracer lsof] [launch flags…]
#
#   --tracer lsof is the ONLY tracer value and may be omitted (owner 2026-09-30; C2 / B13 2026-10-01).
#        `up` hands the launch flags straight to ./launch.sh, which defaults --tracer to lsof and
#        REFUSES `--tracer eslogger` at the door (exit 2 — eslogger is removed from the MVP; there
#        is no root path and no fallback). Until I-157 the flag was required with no default and
#        run 165's launch A was spent on the missing flag; that is history. The session-10 brief
#        pairs lsof with --trackers io,mypy.
#
#        POOL_FILE defaults to THIS tree's pool (.archive/naming/rush_track_pool.txt).
#
#   THE HAND-MARK IS THE LANE'S OWN STEP (I-155 / SP-2, owner 2026-09-21).
#        The pool's `# used:` line is the LANE's account of what it used, and no script stands in
#        for a step the lane owns. `down` therefore PRINTS the exact line to write and the file to
#        write it in, and the lane writes it by hand. The auto-mark this script carried from run
#        116 to run 164 compared a timestamped directory name against the pool's bare token, so it
#        could never match and declined on every run; it has been retired rather than repaired.
#        Pass `-` when the lane has no pool line to write (a target outside the pool).
#
# up   : pkill the four daemons → ./launch.sh TARGET [flags] → wait for ALL GATES PASSED
#        (abort otherwise) — the wait's ceiling is COMPUTED from the same constants the gearbox
#        scales its gates with (I-48, 2026-09-15, run 116: the fixed 300×2 s ceiling expired before
#        the gearbox had decided on a ~400-file target; see gate_budget_s) → wait for
#        NOAI_VALIDATION_STATE.json AND BUILDER_STATE.json
#        phase == MONITORING → copy the state files into .archive/runs/<target>/state_during_run/
#        → archive the health report of this launch → open http://127.0.0.1:8080 in the
#        browser (owner directive: launch visibly) → print the summaries. The stack stays UP
#        for the item-specific check (frame capture into .archive/frames/run<N>/ is done from
#        the browser). The gearbox PID is left in .archive/runs/<target>/gearbox.pid.
# down : kill -TERM the gearbox → teardown lines from the launch log → md5 -r over the
#        COPY-FIRST snapshot and the target, diff must be empty → the bytecode VERDICT
#        (I-153 c) → archive BOTH HALVES OF THE RETURN PATH under the run (I-171: the channel
#        `return_channel_<id>.jsonl` and its ledger `confirmed_ledger_<id>.jsonl` have ONE
#        lifetime, and RUN.md names both) → print the pool hand-mark step (I-155) → RUN.md.
# all  : up, hold HOLD_S seconds (default 30), down.
#
# Re-created 2026-09-08 (item 1) from the archived
# .archive/archived_20260907/system_scripts/calibration/run_live.sh without the calibration delta.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv_new/bin/python3"
# Copy setup (express plan, 2026-09-10): up/down touch only THIS tree's daemons. The tree is
# not in a daemon's argv (the venv interpreter resolves to the framework binary; children are
# spawned by relative path / -m) but every daemon's cwd is its tree root — select by cwd.
# The dashboard port is this tree's, from system_scripts/copy_ports.json.
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
    tree="$(cd "$ROOT" && pwd -P)"
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
        if [ "$(lsof -a -d cwd -p "$pid" -Fn 2>/dev/null | sed -n 's/^n//p')" = "$ROOT" ]; then echo "$pid"; fi
    done
}
DASH_PORT="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("dashboard", 8080))' "$ROOT/system_scripts/copy_ports.json" 2>/dev/null || echo 8080)"
POOL_DEFAULT="$ROOT/.archive/naming/rush_track_pool.txt"   # I-45: the pool of the tree the script runs in
# I-48 (2026-09-15, run 116): the up-wait ceiling. launch.sh runs the health check first (measured 4–6.5 min on
# 2026-09-15; HEALTH_MAX_S is its ceiling, not an estimate), then the gearbox waits its gates one after the
# other: circuit (fixed) → NOAI (base + per live .py file, capped) → cheatsheets (base + per failed row, capped —
# the failed-row count does not exist before the validator publishes, so the CAP is budgeted) → dashboard
# (fixed). The constants are READ FROM gearbox.py (one source); n_py is the same walk the gearbox falls back
# to (scan_scope.live_py_count). BUDGET_SLACK_S covers respawn backoff and the launcher's pre-flight.
HEALTH_MAX_S=900
BUDGET_SLACK_S=120
gate_budget_s() {   # prints: total_s n_py noai_s circuit_s builder_cap_s dashboard_s
    "$PY" - "$ROOT" "$TARGET" "$HEALTH_MAX_S" "$BUDGET_SLACK_S" <<'PY'
import re, sys
from pathlib import Path
root, target, health, slack = Path(sys.argv[1]), Path(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
src = (root / "system_scripts" / "gearbox.py").read_text(encoding="utf-8")
c = {k: float(v) for k, v in re.findall(r"^([A-Z_]+_S)\s*=\s*([0-9.]+)", src, re.M)}
sys.path.insert(0, str(root / "system_scripts"))
try:
    import scan_scope
    n_py = int(scan_scope.live_py_count(target))
except Exception:
    n_py = 0
noai = min(c["NOAI_GATE_BASE_TIMEOUT_S"] + c["NOAI_GATE_PER_PY_FILE_S"] * n_py, c["NOAI_GATE_TIMEOUT_CAP_S"])
total = health + c["CIRCUIT_GATE_TIMEOUT_S"] + noai + c["BUILDER_GATE_TIMEOUT_CAP_S"] + c["DASHBOARD_GATE_TIMEOUT_S"] + slack
print(int(total), n_py, int(noai), int(c["CIRCUIT_GATE_TIMEOUT_S"]), int(c["BUILDER_GATE_TIMEOUT_CAP_S"]), int(c["DASHBOARD_GATE_TIMEOUT_S"]))
PY
}

MODE="${1:-}"; TARGET="${2:-}"; RUN="${3:-}"; PURPOSE="${4:-}"
[ -n "$MODE" ] && [ -n "$TARGET" ] && [ -n "$RUN" ] && [ -n "$PURPOSE" ] || {
    sed -n '2,23p' "$0" >&2; exit 2; }
TARGET="$(cd "$TARGET" && pwd)" || { echo "run_proof: no such target: $TARGET" >&2; exit 2; }
NAME="$(basename "$TARGET")"
RUNDIR="$ROOT/.archive/runs/$NAME"
FRAMES="$ROOT/.archive/frames/run$RUN"
ST_NOAI="$ROOT/system_scripts/NOAI_VALIDATION_STATE.json"
ST_BUILDER="$ROOT/system_scripts/BUILDER_STATE.json"
ST_CIRCUIT="$ROOT/system_scripts/circuit_state.json"
MIRROR_SYS="$ROOT/system_scripts/.noai_state.json"
PYC_BASE="$RUNDIR/pyc_at_launch.txt"     # I-153 (b): the launch reading `down` judges against

# I-153 (d), owner 2026-09-21: every subprocess CodeRadar spawns into a target carries
# PYTHONDONTWRITEBYTECODE=1. Exported HERE, at the top of the run, so launch.sh, the gearbox and
# every daemon, walker and runner beneath them inherit it — one statement, no per-call copy.
export PYTHONDONTWRITEBYTECODE=1

# I-153: the target's own bytecode, counted and never touched. `find -name` only, no deletion
# anywhere in this script (BSD find; no -newermt, no -printf).
pyc_list() {   # $1 = target dir; prints target-relative paths, sorted
    (cd "$1" && find . \( -name '*.pyc' -o -name '*.pyo' \) -type f | sed 's|^\./||' | sort)
}

phase_is_monitoring() {  # $1 = state file, $2 = target name that must appear in target_repo
    "$PY" -c "import json,sys
try:
    d=json.load(open('$1'))
except Exception:
    sys.exit(1)
sys.exit(0 if d.get('phase')=='MONITORING' and '$2' in str(d.get('target_repo','')) else 1)" 2>/dev/null
}

do_up() {
    shift 4  # remaining args = launch flags
    mkdir -p "$RUNDIR/state_during_run" "$FRAMES"
    cd "$ROOT"
    for pid in $(tree_daemon_pids); do kill "$pid" 2>/dev/null; done; sleep 2
    read -r BUDGET N_PY NOAI_S CIRC_S BUILDER_S DASH_S <<< "$(gate_budget_s)"
    echo "run_proof: gate budget ${BUDGET}s = health ≤${HEALTH_MAX_S} + circuit ${CIRC_S} + noai ${NOAI_S} (n_py=${N_PY}) + cheatsheets ≤${BUILDER_S} + dashboard ${DASH_S} + slack ${BUDGET_SLACK_S}" | tee "$RUNDIR/gate_budget.txt"
    # I-153 (b), owner 2026-09-21: the launch fact. A target that ARRIVES with bytecode is launched
    # knowingly from here on, and when it does the run's own pytest reads its cache out of a scratch
    # prefix so the target's stale bytecode is never consulted. Nothing in the target is deleted.
    pyc_list "$TARGET" > "$PYC_BASE"
    PYC_N=$(wc -l < "$PYC_BASE" | tr -d ' ')
    echo "run_proof: pyc_preexisting=${PYC_N}" | tee -a "$RUNDIR/gate_budget.txt"
    if [ "$PYC_N" -gt 0 ]; then
        export PYTHONPYCACHEPREFIX="$ROOT/system_scripts/.cr_pycache/run$RUN"
        mkdir -p "$PYTHONPYCACHEPREFIX"
        echo "run_proof: pyc_preexisting=${PYC_N} > 0 — PYTHONPYCACHEPREFIX=$PYTHONPYCACHEPREFIX (the target's stale bytecode is not consulted; first: $(head -1 "$PYC_BASE"))" | tee -a "$RUNDIR/gate_budget.txt"
    fi
    T0=$(date +%s)
    ./launch.sh "$TARGET" "$@" > "$RUNDIR/launch.log" 2>&1 &
    GPID=$!
    echo "$GPID" > "$RUNDIR/gearbox.pid"
    echo "run $RUN $NAME: launch pid $GPID (flags: $*)"
    DEADLINE=$((T0 + BUDGET))
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do   # I-48: the gearbox decides first — its own verdict lines end the wait
        grep -q "ALL GATES PASSED\|launch.sh: ABORT\|GATE \[.*\] FAIL\|HEALTH CHECK FAILED\|exhaust\|startup failed\|gate failed\|RuntimeError" "$RUNDIR/launch.log" && break
        kill -0 "$GPID" 2>/dev/null || break
        sleep 2
    done
    T1=$(date +%s)
    if ! grep -q "ALL GATES PASSED" "$RUNDIR/launch.log"; then
        echo "LAUNCH DID NOT PASS THE GATES (after $((T1-T0)) s of a ${BUDGET} s budget):"; tail -8 "$RUNDIR/launch.log"
        kill -TERM "$GPID" 2>/dev/null; exit 1
    fi
    grep -E "GATE \[.*\] (PASS|FAIL)|ALL GATES PASSED" "$RUNDIR/launch.log"
    # I-69 (run 117): the whitelist stage's `[intent file]` line is launch.sh's, not the gearbox's,
    # so it was printed into launch.log and then never archived beside the gearbox lines a close
    # quotes. It is the ledger statement a lane must file BEFORE the launch, so it gets its own
    # archived record here and its own RUN.md line below.
    grep -E "^\[intent file\]" "$RUNDIR/launch.log" > "$RUNDIR/intent_file_line.txt" || true
    if [ -s "$RUNDIR/intent_file_line.txt" ]; then cat "$RUNDIR/intent_file_line.txt"
    else echo "[intent file] NOT PRINTED by this launch (I-69: the line is archived when launch.sh emits it)" | tee "$RUNDIR/intent_file_line.txt"; fi
    echo "gates passed after $((T1-T0)) s (budget ${BUDGET} s)" | tee -a "$RUNDIR/gate_budget.txt"
    HL="$(ls -t "$ROOT"/.archive/health/health_*.txt 2>/dev/null | head -1)"
    [ -n "$HL" ] && cp "$HL" "$RUNDIR/health_at_launch.txt"
    # both phases are MONITORING by the gearbox's own gates; the remaining budget bounds the state-file read
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        phase_is_monitoring "$ST_NOAI" "$NAME" && phase_is_monitoring "$ST_BUILDER" "$NAME" && break
        sleep 2
    done
    T2=$(date +%s); echo "both MONITORING after $((T2-T0)) s"
    cp "$ST_NOAI" "$ST_BUILDER" "$ST_CIRCUIT" "$RUNDIR/state_during_run/" 2>/dev/null
    [ -e "$MIRROR_SYS" ] && cp "$MIRROR_SYS" "$RUNDIR/state_during_run/noai_state_mirror.json"
    "$PY" - "$ST_NOAI" "$ST_BUILDER" <<'PY'
import json, sys
n = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
print("validator summary:", n.get("summary"))
print("cheatsheets summary:", b.get("summary"))
print("cheatsheets detail :", b.get("detail"))
PY
    open "http://127.0.0.1:$DASH_PORT" 2>/dev/null && echo "dashboard opened in the browser for the owner (port $DASH_PORT)"
    echo "stack is UP — do the item check, capture the frame into $FRAMES, then: run_proof.sh down $TARGET $RUN \"$PURPOSE\" POOL|-"
}

do_down() {
    POOL="${5:-$POOL_DEFAULT}"   # I-45: marked by default; `-` = do not mark
    GPID="$(cat "$RUNDIR/gearbox.pid" 2>/dev/null || true)"
    [ -e "$MIRROR_SYS" ] && cp "$MIRROR_SYS" "$RUNDIR/state_during_run/noai_state_mirror_at_teardown.json"
    if [ -n "$GPID" ] && kill -0 "$GPID" 2>/dev/null; then
        kill -TERM "$GPID"
        for _ in $(seq 1 60); do kill -0 "$GPID" 2>/dev/null || break; sleep 1; done
    else
        echo "run_proof: gearbox pid not alive (pid '$GPID') — tearing down by pattern"
        for pid in $(tree_daemon_pids); do kill -TERM "$pid" 2>/dev/null; done; sleep 5
    fi
    grep -E "TEARDOWN COMPLETE|RESIDUE CHECK|residue|stopped|return channel" "$RUNDIR/launch.log" | tail -7
    # C2 / Q-H1-7 (2026-10-01): the newest `<name>_<stamp>` by that exact form — a `_FAILED` / `_INTERRUPTED`
    # copy (launch.sh renames the snapshot of a launch that never reached the daemons) is never the reference
    SNAP="$(ls -d "$HOME/CodeRadar_snapshots/${NAME}_"* 2>/dev/null | grep -E "/${NAME}_[0-9]{8}_[0-9]{6}\$" | sort | tail -1)"
    if [ -z "$SNAP" ]; then echo "run_proof: no COPY-FIRST snapshot for $NAME under ~/CodeRadar_snapshots" >&2; exit 1; fi
    # Q10 (B7): both sides are the snapshot's ONE file set (env dirs / node_modules / tool caches skipped).
    # Owner ruling 2026-09-28: the state mirrors are kept as the run's log — exempt through THE
    # location helper (scan_scope.is_mirror_path), nothing else.
    drop_mirrors() { PYTHONPATH="$ROOT/system_scripts" "$PY" -B -c 'import sys, scan_scope
sys.stdout.writelines(l for l in sys.stdin if not scan_scope.is_mirror_path(l.split(" ", 1)[1].strip()))'; }
    (cd "$SNAP" && bash "$ROOT/system_scripts/snapshot_files.sh" . | xargs md5 -r) | drop_mirrors > "$RUNDIR/teardown_snapshot.md5"
    (cd "$TARGET" && bash "$ROOT/system_scripts/snapshot_files.sh" . | xargs md5 -r) | drop_mirrors > "$RUNDIR/teardown_target.md5"
    PYTHONPATH="$ROOT/system_scripts" "$PY" -B -c 'import sys, scan_scope
print("\n".join("mirror kept: " + str(p) for p in scan_scope.mirror_files(sys.argv[1])))' "$TARGET"
    diff "$RUNDIR/teardown_snapshot.md5" "$RUNDIR/teardown_target.md5" > "$RUNDIR/teardown_diff.txt"; RC=$?
    NFILES=$(wc -l < "$RUNDIR/teardown_snapshot.md5" | tr -d ' ')
    VERDICT=$([ $RC -eq 0 ] && echo IDENTICAL || echo DIFFERS)
    echo "byte-identity: $NFILES files, diff exit $RC ($VERDICT)"
    find "$TARGET" -name "__pycache__" -type d | head -2 | sed 's/^/pycache residue: /'
    # I-153 (c), owner 2026-09-21 — the VERDICT, not a note. Any bytecode file under the target
    # that the LAUNCH reading did not have means something wrote into the target while the run was
    # reading it, and this run's suite reading cannot be used to judge a repair. Nothing is deleted.
    pyc_list "$TARGET" > "$RUNDIR/pyc_at_teardown.txt"
    [ -f "$PYC_BASE" ] || : > "$PYC_BASE"
    PYC_N0=$(wc -l < "$PYC_BASE" | tr -d ' '); PYC_N1=$(wc -l < "$RUNDIR/pyc_at_teardown.txt" | tr -d ' ')
    comm -13 "$PYC_BASE" "$RUNDIR/pyc_at_teardown.txt" > "$RUNDIR/pyc_added.txt"
    comm -23 "$PYC_BASE" "$RUNDIR/pyc_at_teardown.txt" > "$RUNDIR/pyc_removed.txt"
    PYC_ADD=$(wc -l < "$RUNDIR/pyc_added.txt" | tr -d ' '); PYC_DEL=$(wc -l < "$RUNDIR/pyc_removed.txt" | tr -d ' ')
    if [ "$PYC_ADD" -eq 0 ] && [ "$PYC_DEL" -eq 0 ]; then POLLUTED=no; SUITE_READING=clean
    else POLLUTED=yes; SUITE_READING="not clean"; fi
    echo "VERDICT: polluted=$POLLUTED  pyc_preexisting=$PYC_N0  pyc_at_teardown=$PYC_N1  (+$PYC_ADD/-$PYC_DEL)  suite reading $SUITE_READING"
    [ "$PYC_ADD" -gt 0 ] && head -5 "$RUNDIR/pyc_added.txt" | sed 's/^/VERDICT: bytecode ADDED during the run: /'
    [ "$PYC_DEL" -gt 0 ] && head -5 "$RUNDIR/pyc_removed.txt" | sed 's/^/VERDICT: bytecode REMOVED during the run: /'
    # I-171 (2026-09-22, run 175): THE RETURN PATH HAS TWO HALVES AND ONE LIFETIME. A run's
    # outcomes are the channel `return_channel_<id>.jsonl`; the confirmations the channel can no
    # longer join are its ledger `confirmed_ledger_<id>.jsonl` (gearbox.confirmed_ledger_path —
    # the channel's own directory, the channel's own name). Before run 175 only the channel was
    # named anywhere: launch.sh archived it out of the tree at the next launch while the ledger
    # stayed, and this script copied neither under the run. Both are copied here, both are named
    # in RUN.md below, and launch.sh archives both — one lifetime, stated on both sides.
    REPO_ID="$("$PY" -c 'import hashlib,sys,pathlib; print(hashlib.sha256(str(pathlib.Path(sys.argv[1]).resolve()).encode()).hexdigest()[:12])' "$TARGET")"
    CHANNEL_F="$ROOT/system_scripts/return_channel_${REPO_ID}.jsonl"
    LEDGER_F="$ROOT/system_scripts/confirmed_ledger_${REPO_ID}.jsonl"
    RP_LINES=""
    for f in "$CHANNEL_F" "$LEDGER_F"; do
        b="$(basename "$f")"
        if [ -f "$f" ]; then
            cp "$f" "$RUNDIR/$b"
            RP_LINES="${RP_LINES}${RP_LINES:+ · }$b ($(wc -l < "$f" | tr -d ' ') line(s)) -> $RUNDIR/$b"
        else
            RP_LINES="${RP_LINES}${RP_LINES:+ · }$b NOT WRITTEN by this run"
        fi
    done
    echo "return path (I-171): $RP_LINES"
    # I-155 / SP-2 (owner 2026-09-21): the hand-mark IS the lane's step. The auto-mark that stood
    # here compared `basename($TARGET)` — timestamped — against the pool's bare token and so could
    # never match; it declined on runs 161, 164 and the 164 follow-up, and every lane hand-marked
    # anyway. It is retired, not repaired: no proxy script stands in for a step the lane owns.
    if [ "$POOL" != "-" ]; then
        echo "POOL HAND-MARK — the lane's own step (I-155 / SP-2, owner 2026-09-21). This script does NOT write it."
        echo "  file: $POOL"
        echo "  find the line whose token is the pool name of '$NAME' and append, by hand:"
        echo "      # used: $NAME (run $RUN, $PURPOSE)"
        echo "  then read the line back before the report claims it."
    else echo "pool hand-mark not required (POOL = -)"; fi
    {
        echo "# RUN $RUN — $NAME"
        echo
        echo "- item: $PURPOSE"
        echo "- target: $TARGET"
        echo "- snapshot: $SNAP"
        echo "- launched: $(grep -m1 -E 'GATE \[circuit' "$RUNDIR/launch.log" | sed 's/^\[gearbox \([0-9:]*\)\].*/\1/')  gates: $(grep -c 'GATE \[.*\] PASS' "$RUNDIR/launch.log") PASS"
        echo "- teardown: $(grep -E 'RESIDUE CHECK' "$RUNDIR/launch.log" | tail -1 | sed 's/^\[gearbox [0-9:]*\] //')"
        echo "- byte-identity: $NFILES files, md5 diff exit $RC ($VERDICT)"
        echo "- intent file (I-69): $(cat "$RUNDIR/intent_file_line.txt" 2>/dev/null | tail -1)"
        echo "- pyc_preexisting: $PYC_N0"
        echo "- polluted: $POLLUTED (pyc_at_teardown $PYC_N1, +$PYC_ADD/-$PYC_DEL)"
        echo "- suite reading: $SUITE_READING"
        echo "- return path, half 1 of 2 — the channel (I-171): $(basename "$CHANNEL_F") $([ -f "$CHANNEL_F" ] && echo "-> $RUNDIR/$(basename "$CHANNEL_F")" || echo 'NOT WRITTEN by this run')"
        echo "- return path, half 2 of 2 — the ledger (I-171): $(basename "$LEDGER_F") $([ -f "$LEDGER_F" ] && echo "-> $RUNDIR/$(basename "$LEDGER_F")" || echo 'NOT WRITTEN by this run')"
        echo "- pool hand-mark (I-155): the lane's own step — written by hand in $POOL, not by this script"
        echo "- state during run: $RUNDIR/state_during_run/"
        echo "- frames: $FRAMES"
        echo "- health at launch: $RUNDIR/health_at_launch.txt"
    } > "$RUNDIR/RUN.md"
    echo "run $RUN done: $RUNDIR/RUN.md"
    rm -f "$RUNDIR/gearbox.pid"
    exit $RC
}

case "$MODE" in
    up)   do_up "$@" ;;
    down) do_down "$@" ;;
    all)  POOL="${5:-$POOL_DEFAULT}"; HOLD="${6:-30}"; ARGS=("$@"); do_up "$MODE" "$TARGET" "$RUN" "$PURPOSE" "${ARGS[@]:6}"; sleep "$HOLD"; do_down "$MODE" "$TARGET" "$RUN" "$PURPOSE" "$POOL" ;;
    *)    sed -n '2,23p' "$0" >&2; exit 2 ;;
esac
