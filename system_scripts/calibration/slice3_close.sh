#!/usr/bin/env bash
# slice3_close.sh — B7..B10 for slice 3 (2026-09-06): apply the ruling (gate inside), record evidence, dump corpus A, three live proofs, kept-sites delta, freeze, final gate.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd); PY=$ROOT/.venv_new/bin/python; C=$ROOT/system_scripts/calibration
export CAL=$ROOT/ARCHIVE/health/calibration_20260906_slice3; RUSH=$ROOT/ARCHIVE/naming/rush_track_pool.txt
cd "$ROOT"; echo "close start ($(date +%H:%M:%S))"
cp system_scripts/rule_dispositions.json ARCHIVE/rule_dispositions_pre_slice3_ruling_20260906.json
echo "== B7 apply"; $PY $C/apply_dispositions.py "$CAL" > "$CAL/APPLY.txt" 2>&1; tail -3 "$CAL/APPLY.txt"
grep -q "HEALTH CHECK: ✓ PASSED" "$CAL/APPLY.txt" || grep -q "PASSED" "$CAL/APPLY.txt" || { echo "APPLY GATE DID NOT PASS — stopping"; tail -12 "$CAL/APPLY.txt"; exit 1; }
cp "$(ls -t ARCHIVE/health/health_*.txt | head -1)" "$CAL/health_after.txt"
echo "== record evidence"; $PY $C/record_evidence.py "$CAL" --fit fit_k7.json --apply 2>&1 | tail -2
echo "== dump corpus A (third_eye)"; $PY $C/dump_rows.py "$CAL/precision" third_eye=$HOME/Desktop/third_eye 2>&1 | tail -1
draw() { grep -vE '^\s*#|# used:|^\s*$' "$RUSH" | grep -vE "^(${1:-__none__})\b" | head -1 | awk '{print $1}'; }
N1=$(draw); N2=$(draw "$N1"); echo "live-run names from the Rush pool: $N1 (tqdm), $N2 (colorama)"
rm -rf "$HOME/Desktop/$N1" "$HOME/Desktop/$N2"
cp -R "$HOME/CodeRadar_snapshots/mels_offer_20260906_034719" "$HOME/Desktop/$N1"; cp -R "$HOME/CodeRadar_snapshots/chets_shirt_20260905_211140" "$HOME/Desktop/$N2"
echo "== B8 run 37 ($N1 = tqdm)"; bash $C/run_live.sh "$HOME/Desktop/$N1" mels_offer 37 "slice 3 live proof, tqdm" "$RUSH" 2>&1 | grep -E "MONITORING|summary|mismatch|common|byte-identity|TEARDOWN|residue|LAUNCH DID NOT|pool marked|done:" | cut -c1-200
sleep 5
echo "== B8 run 38 ($N2 = colorama)"; bash $C/run_live.sh "$HOME/Desktop/$N2" chets_shirt_20260905_211140 38 "slice 3 live proof, colorama" "$RUSH" 2>&1 | grep -E "MONITORING|summary|mismatch|common|byte-identity|TEARDOWN|residue|LAUNCH DID NOT|pool marked|done:" | cut -c1-200
sleep 5
echo "== B8 run 39 (third_eye = corpus A live)"; bash $C/run_live.sh "$HOME/Desktop/third_eye" third_eye 39 "slice 3 live proof, corpus A live" - 2>&1 | grep -E "MONITORING|summary|mismatch|common|byte-identity|TEARDOWN|residue|LAUNCH DID NOT|done:" | cut -c1-200
echo "== corpus A live plants"; $PY system_scripts/verify_manifest.py ARCHIVE/runs/third_eye/manifest.json --state ARCHIVE/runs/third_eye/state_during_run/NOAI_VALIDATION_STATE.json 2>&1 | grep -E "^third_eye:" | cut -c1-200
echo "== B9 kept sites"; $PY $C/kept_sites_delta.py "$CAL" --families NAI-034 2>&1 | tail -2
echo "== B10 freeze"; $PY $C/freeze_slice.py "$CAL" --slice 3 2>&1 | tail -3
echo "== final gate"; $PY system_scripts/health_check.py > ARCHIVE/health/health_after_slice3_freeze_20260906.txt 2>&1; grep -E "HEALTH CHECK:|recall guard:|deciding without evidence" ARCHIVE/health/health_after_slice3_freeze_20260906.txt | cut -c1-160
echo "close done ($(date +%H:%M:%S))"
