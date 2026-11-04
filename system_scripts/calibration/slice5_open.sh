#!/usr/bin/env bash
# slice5_open.sh — slice 5 open (2026-09-06): NEW CAL dir, carry-over of the slice-4 labels + requests + sdists.json, stamp under the stage-2 instrument, four background dumps: A cal libs + sdists, B held + real + pydantic, C numpy, D pandas (joins the calibration set, k = 7 of 16). `--merge` folds them; then `--sheets` writes the pandas label sheets for the 50 families.
# slice-3 labels + requests + sdists.json, stamp under the FIXED instrument, then three background dumps into per-job dirs
# (no timings.json race): A = 10 cal libs + 4 sdists, B = held-out 4 + real 2 + pydantic, C = numpy. `--merge` folds them into
# CAL/precision once all three logs say done.  Template: slice3_open.sh.
set -u
ROOT=/Users/ian/Desktop/CODE_RADAR_REFURBISH; PY=$ROOT/.venv_new/bin/python; C=$ROOT/system_scripts/calibration
S3=$ROOT/ARCHIVE/health/calibration_20260906_bodyshape; CAL=$ROOT/ARCHIVE/health/calibration_20260906_slice5
SITE=$ROOT/.venv_new/lib/python3.14/site-packages; SD=$ROOT/ARCHIVE/corpus_sdists; LOG=$ROOT/ARCHIVE/health/calibration_20260906_slice5
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
  --jobD) echo "job D start ($(date +%H:%M:%S))"
    $PY $C/dump_rows.py "$CAL/precision_D" --cache --timeout 7200 $SITE/pandas
    echo "job D done ($(date +%H:%M:%S))"; exit 0;;
  --sheets) OUT=$HOME/Desktop/CALIBRATION_REVIEW_2026-09-06_slice5
    FAM=HR-002,NAI-005,NAI-006,NAI-010,NAI-016,NAI-020,NAI-022,NAI-024,NAI-034,NAI-041,NAI-043,NAI-044,NAI-050,NAI-055,NAI-058,NAI-062,NAI-075,NAI-076,NAI-088,NAI-094,NAI-098,NAI-109,NAI-110,NAI-116,NAI-125,NAI-127,NAI-130,NAI-137,NAI-138,NAI-141,NAI-147,NAI-152,NAI-167,NAI-174,NAI-200,NAI-201,NAI-206,NAI-209,NAI-211,NAI-213,NAI-037,NAI-091,NAI-104,NAI-011,NAI-096,NAI-053,NAI-160,NAI-040,NAI-061,NAI-087
    $PY $C/repo_sheets.py "$CAL" --libs pandas --families "$FAM" --cap 2 --seed 41 --out "$OUT"
    cp "$HOME/Desktop/CALIBRATION_REVIEW_2026-09-06_repos/FAMILY_REFERENCE.md" "$OUT/" 2>/dev/null && echo "FAMILY_REFERENCE.md copied"; exit 0;;
  --jobC) echo "job C start ($(date +%H:%M:%S))"
    $PY $C/dump_rows.py "$CAL/precision_C" --cache $SITE/numpy
    echo "job C done ($(date +%H:%M:%S))"; exit 0;;
  --merge)
    $PY - "$CAL" <<'PYEOF'
import json, shutil, sys, pathlib
cal = pathlib.Path(sys.argv[1]); dst = cal / "precision"; dst.mkdir(exist_ok=True); timings = {}
for job in ("precision_A", "precision_B", "precision_C", "precision_D"):
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
mkdir -p "$CAL/precision" "$CAL/labels" "$CAL/label_requests" "$CAL/precision_A" "$CAL/precision_B" "$CAL/precision_C" "$CAL/precision_D"
cp -n "$S3"/labels/*.json "$CAL/labels/"; cp -n "$S3"/label_requests/*.json "$CAL/label_requests/"; cp -n "$S3/sdists.json" "$CAL/sdists.json"
echo "carried over: $(ls $CAL/labels | wc -l | tr -d ' ') label files, $(ls $CAL/label_requests | wc -l | tr -d ' ') request files, sdists.json (slice 3)"
$PY $C/stamp.py "$CAL"; grep -o '"instrument_stamp": "[0-9a-f]\{12\}' "$CAL/versions.json" || head -c 300 "$CAL/versions.json"
for J in A B C D; do nohup bash "$C/slice5_open.sh" --job$J > "${LOG}_job$J.log" 2>&1 & echo "job $J pid $!"; done
echo "launched ($(date +%H:%M:%S)); logs ${LOG}_job{A,B,C,D}.log; when all four say done: bash $C/slice5_open.sh --merge && bash $C/slice5_open.sh --sheets"
