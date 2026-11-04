#!/usr/bin/env bash
# slice3_open.sh — slice 3 B0 + B2 (2026-09-06): new CAL dir, stamp, carry-over of slice-2 labels + numpy's dump (same stamp),
# re-dump 10 cal libs + 4 sdists (job A) ; held-out 4 + real 2 + pydantic (job B, --held) ; sheets for the 40 unconfirmed families.
set -u
ROOT=/Users/ian/Desktop/CODE_RADAR_REFURBISH; PY=$ROOT/.venv_new/bin/python; C=$ROOT/system_scripts/calibration
S2=$ROOT/ARCHIVE/health/calibration_20260906_slice2; CAL=$ROOT/ARCHIVE/health/calibration_20260906_slice3
SITE=$ROOT/.venv_new/lib/python3.14/site-packages; SD=$ROOT/ARCHIVE/corpus_sdists
UNC=HR-002,NAI-005,NAI-006,NAI-010,NAI-016,NAI-020,NAI-022,NAI-024,NAI-034,NAI-041,NAI-043,NAI-044,NAI-050,NAI-055,NAI-058,NAI-062,NAI-075,NAI-076,NAI-088,NAI-094,NAI-098,NAI-109,NAI-110,NAI-116,NAI-125,NAI-127,NAI-130,NAI-137,NAI-138,NAI-141,NAI-147,NAI-152,NAI-167,NAI-174,NAI-200,NAI-201,NAI-206,NAI-209,NAI-211,NAI-213
cd "$ROOT"
if [ "${1:-}" = "--held" ]; then
  for i in $(seq 1 120); do [ -f "$CAL/versions.json" ] && break; sleep 5; done
  echo "job B: held-out + real + pydantic ($(date +%H:%M:%S))"
  $PY $C/dump_rows.py "$CAL/precision" --cache $SITE/aiofiles $SITE/itsdangerous $SITE/importlib_metadata $SITE/zipp \
     ~/CodeRadar_snapshots/chets_shirt_20260905_211140 mels_offer=~/CodeRadar_snapshots/mels_offer_20260906_034719 $SITE/pydantic
  echo "job B done ($(date +%H:%M:%S))"; exit 0
fi
echo "job A start ($(date +%H:%M:%S))"
mkdir -p "$CAL/precision" "$CAL/labels" "$CAL/label_requests"
cp -n "$S2"/labels/*.json "$CAL/labels/"; cp -n "$S2"/label_requests/*.json "$CAL/label_requests/"
echo "carried over: $(ls $CAL/labels | wc -l | tr -d ' ') label files, $(ls $CAL/label_requests | wc -l | tr -d ' ') request files (slice 2, the 10 calibration libraries)"
$PY $C/stamp.py "$CAL"
$PY - "$CAL" "$SD" <<'PYEOF'
import json, sys, re, pathlib
cal, sd = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
out = {}
for d in sorted(sd.glob("*/")):
    pk = d / "PKG-INFO"; name = ver = ""
    for line in pk.read_text(errors="replace").splitlines():
        if line.startswith("Name:"): name = line.split(":",1)[1].strip()
        elif line.startswith("Version:"): ver = line.split(":",1)[1].strip()
        if name and ver: break
    out[name] = {"version": ver, "sdist_dir": str(d), "source": "pip download --no-binary :all: 2026-09-06 (PyPI)"}
(cal / "sdists.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n"); print("sdists.json:", {k: v["version"] for k, v in out.items()})
PYEOF
# numpy: dumped 2026-09-06 under the CURRENT stamp (b6f453e3…, 62.5 min) — carried over; --cache honours it only if the stamp matches
cp "$S2/precision/numpy.json" "$CAL/precision/numpy.json"
$PY - "$S2" "$CAL" <<'PYEOF'
import json, sys, pathlib
s2, cal = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
t = json.load(open(s2 / "precision/timings.json")); n = t["numpy"]; n["carried_over_from"] = str(s2 / "precision/numpy.json")
(cal / "precision/timings.json").write_text(json.dumps({"numpy": n}, indent=1, sort_keys=True) + "\n"); print("numpy timing carried over:", n["seconds"], "s")
PYEOF
echo "job A: 10 cal libs + 4 sdists + numpy(cached) ($(date +%H:%M:%S))"
$PY $C/dump_rows.py "$CAL/precision" --cache $SITE/click $SITE/jinja2 $SITE/flask $SITE/werkzeug $SITE/requests $SITE/urllib3 \
   $SITE/packaging $SITE/pathspec $SITE/watchdog $SITE/idna \
   attrs=$SD/attrs-26.1.0/src rich=$SD/rich-15.0.0/rich more_itertools=$SD/more_itertools-11.1.0/more_itertools tomli_w=$SD/tomli_w-1.2.0/src \
   $SITE/numpy
echo "job A: sheets for the 40 unconfirmed families on the 5 new calibration libraries ($(date +%H:%M:%S))"
OUT=$HOME/Desktop/CALIBRATION_REVIEW_2026-09-06_slice3
$PY $C/repo_sheets.py "$CAL" --libs attrs,rich,more_itertools,tomli_w,numpy --families "$UNC" --cap 2 --seed 37 --out "$OUT"
cp "$HOME/Desktop/CALIBRATION_REVIEW_2026-09-06_repos/FAMILY_REFERENCE.md" "$OUT/" 2>/dev/null && echo "FAMILY_REFERENCE.md copied"
echo "job A done ($(date +%H:%M:%S))"
