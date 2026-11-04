#!/usr/bin/env bash
# bodyshape_open.sh — body-shape stage re-dump (2026-09-06, NEXT_SESSION_PLAN_2026-09-09 step 4): NEW CAL dir, carry-over of
# slice-3 labels + requests + sdists.json, stamp under the FIXED instrument, then three background dumps into per-job dirs
# (no timings.json race): A = 10 cal libs + 4 sdists, B = held-out 4 + real 2 + pydantic, C = numpy. `--merge` folds them into
# CAL/precision once all three logs say done.  Template: slice3_open.sh.
set -u
ROOT=/Users/ian/Desktop/CODE_RADAR_REFURBISH; PY=$ROOT/.venv_new/bin/python; C=$ROOT/system_scripts/calibration
S3=$ROOT/ARCHIVE/health/calibration_20260906_slice3; CAL=$ROOT/ARCHIVE/health/calibration_20260906_bodyshape
SITE=$ROOT/.venv_new/lib/python3.14/site-packages; SD=$ROOT/ARCHIVE/corpus_sdists; LOG=$ROOT/ARCHIVE/health/calibration_20260906_bodyshape
cd "$ROOT"
case "${1:-}" in
  --jobA) echo "job A start ($(date +%H:%M:%S))"
    $PY $C/dump_rows.py "$CAL/precision_A" --cache $SITE/click $SITE/jinja2 $SITE/flask $SITE/werkzeug $SITE/requests $SITE/urllib3 \
       $SITE/packaging $SITE/pathspec $SITE/watchdog $SITE/idna \
       attrs=$SD/attrs-26.1.0/src rich=$SD/rich-15.0.0/rich more_itertools=$SD/more_itertools-11.1.0/more_itertools tomli_w=$SD/tomli_w-1.2.0/src
    echo "job A done ($(date +%H:%M:%S))"; exit 0;;
  --jobB) echo "job B start ($(date +%H:%M:%S))"
    $PY $C/dump_rows.py "$CAL/precision_B" --cache $SITE/aiofiles $SITE/itsdangerous $SITE/importlib_metadata $SITE/zipp \
       ~/CodeRadar_snapshots/chets_shirt_20260905_211140 mels_offer=~/CodeRadar_snapshots/mels_offer_20260906_034719 $SITE/pydantic
    echo "job B done ($(date +%H:%M:%S))"; exit 0;;
  --jobC) echo "job C start ($(date +%H:%M:%S))"
    $PY $C/dump_rows.py "$CAL/precision_C" --cache $SITE/numpy
    echo "job C done ($(date +%H:%M:%S))"; exit 0;;
  --merge)
    $PY - "$CAL" <<'PYEOF'
import json, shutil, sys, pathlib
cal = pathlib.Path(sys.argv[1]); dst = cal / "precision"; dst.mkdir(exist_ok=True); timings = {}
for job in ("precision_A", "precision_B", "precision_C"):
    d = cal / job
    for f in sorted(d.glob("*.json")):
        if f.name == "timings.json": timings.update(json.load(open(f))); continue
        shutil.move(str(f), str(dst / f.name))
(dst / "timings.json").write_text(json.dumps(timings, indent=1, sort_keys=True) + "\n")
libs = sorted(p.stem for p in dst.glob("*.json") if p.stem != "timings")
print(f"merged {len(libs)} dumps into {dst}: {', '.join(libs)}"); print({k: v["seconds"] for k, v in timings.items()})
PYEOF
    exit 0;;
esac
# default: prepare CAL, stamp, launch the three jobs in the background (nohup)
mkdir -p "$CAL/precision" "$CAL/labels" "$CAL/label_requests" "$CAL/precision_A" "$CAL/precision_B" "$CAL/precision_C"
cp -n "$S3"/labels/*.json "$CAL/labels/"; cp -n "$S3"/label_requests/*.json "$CAL/label_requests/"; cp -n "$S3/sdists.json" "$CAL/sdists.json"
echo "carried over: $(ls $CAL/labels | wc -l | tr -d ' ') label files, $(ls $CAL/label_requests | wc -l | tr -d ' ') request files, sdists.json (slice 3)"
$PY $C/stamp.py "$CAL"; grep -o '"instrument_stamp": "[0-9a-f]\{12\}' "$CAL/versions.json" || head -c 300 "$CAL/versions.json"
for J in A B C; do nohup bash "$C/bodyshape_open.sh" --job$J > "${LOG}_job$J.log" 2>&1 & echo "job $J pid $!"; done
echo "launched ($(date +%H:%M:%S)); logs ${LOG}_job{A,B,C}.log; when all three say done: bash $C/bodyshape_open.sh --merge"
