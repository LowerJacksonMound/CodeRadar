#!/usr/bin/env bash
# run_live.sh TARGET_DIR DUMP_LIB RUN_NO PURPOSE POOL_FILE|-  — one B8 live proof: launch → MONITORING → capture → Chrome → live delta → teardown → md5 → archive → pool mark
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd); CAL=${CAL:-$ROOT/ARCHIVE/health/calibration_20260906_slice3}; PY=$ROOT/.venv_new/bin/python3
TARGET="$1"; DUMP="$2"; RUN="$3"; PURPOSE="$4"; POOL="$5"; NAME=$(basename "$TARGET"); RUNDIR=$ROOT/ARCHIVE/runs/$NAME; mkdir -p "$RUNDIR/state_during_run"
cd "$ROOT"
pkill -f "gearbox.py|circuit_daemon.py|NOAI_VALIDATOR_DAEMON.py|proof_dashboard.py" 2>/dev/null; sleep 2
T0=$(date +%s); ./launch.sh "$TARGET" > "$RUNDIR/launch.log" 2>&1 & GPID=$!
echo "run $RUN $NAME: launch pid $GPID"
for i in $(seq 1 240); do grep -q "ALL GATES PASSED\|launch.sh: ABORT\|GATE \[.*\] FAIL\|HEALTH GATE FAILED\|exhaust" "$RUNDIR/launch.log" && break; sleep 2; done
if ! grep -q "ALL GATES PASSED" "$RUNDIR/launch.log"; then echo "LAUNCH DID NOT PASS THE GATES:"; tail -5 "$RUNDIR/launch.log"; kill -TERM $GPID 2>/dev/null; exit 1; fi
cp "$(ls -t $ROOT/ARCHIVE/health/health_*.txt | head -1)" "$RUNDIR/health_at_launch.txt"
ST=$ROOT/system_scripts/NOAI_VALIDATION_STATE.json
for i in $(seq 1 300); do $PY -c "import json,sys; d=json.load(open('$ST')); sys.exit(0 if d.get('phase')=='MONITORING' and '$NAME' in str(d.get('target_repo','')) else 1)" 2>/dev/null && break; sleep 2; done
T1=$(date +%s); echo "MONITORING after $((T1-T0)) s"
cp "$ST" "$RUNDIR/state_during_run/NOAI_VALIDATION_STATE.json"
$PY -c "import json; d=json.load(open('$ST')); print('summary:', d['summary'])"
open "http://127.0.0.1:8080" 2>/dev/null && echo "dashboard opened in the browser for the owner"
echo "### live delta vs the calibrated dump ($DUMP)"; $PY system_scripts/calibration/live_delta.py "$CAL" --lib "$DUMP" --state "$ST" 2>&1 | tail -4 | tee "$RUNDIR/live_delta.txt"
sleep 20
kill -TERM $GPID; for i in $(seq 1 60); do kill -0 $GPID 2>/dev/null || break; sleep 1; done
grep -E "TEARDOWN COMPLETE|RESIDUE CHECK|residue" "$RUNDIR/launch.log" | tail -3
SNAP=$(ls -td $HOME/CodeRadar_snapshots/${NAME}_* | head -1)
(cd "$SNAP" && find . -type f | sort | xargs md5 -r) > "$RUNDIR/teardown_snapshot.md5"
(cd "$TARGET" && find . -type f | sort | xargs md5 -r) > "$RUNDIR/teardown_target.md5"
diff "$RUNDIR/teardown_snapshot.md5" "$RUNDIR/teardown_target.md5" > "$RUNDIR/teardown_diff.txt"; RC=$?
echo "byte-identity: $(wc -l < "$RUNDIR/teardown_snapshot.md5") files, diff exit $RC ($( [ $RC -eq 0 ] && echo IDENTICAL || echo DIFFERS))"
find "$TARGET" -name "__pycache__" -type d | head -2 | sed 's/^/pycache residue: /'
if [ "$POOL" != "-" ]; then $PY - "$POOL" "$NAME" "$RUN" "$PURPOSE" <<'PY'
import sys; p, name, run, purpose = sys.argv[1:5]
lines = open(p, encoding='utf-8').read().splitlines()
for i, l in enumerate(lines):
    if l.strip().split()[:1] == [name] and '# used:' not in l: lines[i] = f"{name}  # used: {name} (run {run}, {purpose})"; break
open(p, 'w', encoding='utf-8').write('\n'.join(lines) + '\n'); print("pool marked:", name)
PY
fi
echo "run $RUN done: $RUNDIR"
