#!/usr/bin/env bash
# slice5_close.sh — slice 5 B3..B10 (copy of bodyshape_close.sh: pandas in the calibration set, runs 43-45) (2026-09-06, NEXT_SESSION_PLAN_2026-09-10 step 4): fit k=7 on the 15 cal libs,
# held-out score, evidence table, RULING.md generated under the owner's standing rule ("Ranker's democracy": context only when
# admitted AND no plant lost in either half — the owner may overrule; backup taken), apply (gate inside), record evidence,
# dump corpus A, three live proofs (runs 40-42), kept-sites delta, freeze --slice 5, final gate.  Template: slice3_close.sh.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd); PY=$ROOT/.venv_new/bin/python; C=$ROOT/system_scripts/calibration
export CAL=$ROOT/ARCHIVE/health/calibration_20260906_slice5; RUSH=$ROOT/ARCHIVE/naming/rush_track_pool.txt
CALLIBS=click,jinja2,flask,werkzeug,requests,urllib3,packaging,pathspec,watchdog,idna,numpy,attrs,rich,more_itertools,tomli_w,pandas
HELD=aiofiles,itsdangerous,importlib_metadata,zipp,pydantic; REAL=chets_shirt_20260905_211140,mels_offer
UNC=HR-002,NAI-005,NAI-006,NAI-010,NAI-016,NAI-020,NAI-022,NAI-024,NAI-034,NAI-041,NAI-043,NAI-044,NAI-050,NAI-055,NAI-058,NAI-062,NAI-075,NAI-076,NAI-088,NAI-094,NAI-098,NAI-109,NAI-110,NAI-116,NAI-125,NAI-127,NAI-130,NAI-137,NAI-138,NAI-141,NAI-147,NAI-152,NAI-167,NAI-174,NAI-200,NAI-201,NAI-206,NAI-209,NAI-211,NAI-213
S2=NAI-037,NAI-091,NAI-104,NAI-011,NAI-096,NAI-053,NAI-160,NAI-040,NAI-061,NAI-087
FAM=$UNC,$S2
cd "$ROOT"; echo "close start ($(date +%H:%M:%S))"
STAGE=${1:-all}
if [ "$STAGE" = all ] || [ "$STAGE" = fit ]; then
  echo "== B3 fit"; $PY $C/fit_dispositions.py "$CAL" --k 7 --cal-libs $CALLIBS --plants archived,corpus_A --families "$FAM" > "$CAL/FIT_k7.txt" 2>&1; head -1 "$CAL/FIT_k7.txt" | cut -c1-200; grep -cE '^\s+(NAI|HR)-' "$CAL/FIT_k7.txt"
  # plant gate (slices 2-3 doctrine): a family the fit ADMITS must carry plants before any ruling — stop here and build specs/slice5_{A,B}.py
  if grep -E "^\s+(NAI|HR)-[0-9]+: admitted" "$CAL/FIT_k7.txt" | grep -q "plants 0 unmasked / 0 masked" && [ "${2:-}" != "--plants-ok" ]; then
    echo "ADMITTED WITHOUT PLANTS — build plants first (specs/slice5_{A,B}.py, build_corpus.py), then rerun: slice5_close.sh fit --plants-ok / apply"
    grep -E "^\s+(NAI|HR)-[0-9]+: admitted" "$CAL/FIT_k7.txt" | cut -c1-160; exit 2
  fi
  echo "== B4 held-out"; $PY $C/score_heldout.py "$CAL" --held-libs $HELD --real $REAL --plants corpus_B --fit fit_k7.json 2>&1 | tail -3
  echo "== B5 evidence table"; $PY $C/evidence_table.py "$CAL" --families "$FAM" --fit fit_k7.json 2>&1 | tail -2
  echo "== B6 ruling (standing rule)"; $PY - "$CAL" <<'PYEOF'
import json, re, sys, pathlib
from datetime import date
cal = pathlib.Path(sys.argv[1]); fit = json.load(open(cal / "fit_k7.json"))["families"]
bt = {}
for line in (cal / "HELDOUT_SCORE.md").read_text().splitlines():
    m = re.match(r"^\|\s*((?:NAI|HR)-\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", line)
    if m: bt[m.group(1)] = dict(planted=int(m.group(2)), raw=int(m.group(3)), cal=int(m.group(4)), by_id=int(m.group(5)))
rows = []; changes = []
cur = {k: (v["disposition"] if isinstance(v, dict) else v) for k, v in json.load(open(pathlib.Path("system_scripts/rule_dispositions.json")))["families"].items()}
for fam in sorted(fit):
    f = fit[fam]; st = f["status"]; b = bt.get(fam, dict(planted=0, raw=0, cal=0, by_id=0)); why = f.get("why", "")
    if cur.get(fam) == "context":
        rows.append(f"| {fam} | context | STANDS — an owner ruling of an earlier slice; fit reads {st} ({why}) — never demoted by a below-k fit |"); continue
    if st == "admitted" and b["cal"] >= b["planted"]:
        disp = "context"; reason = f"admitted ({why}); corpus-B plant {b['cal']}/{b['planted']} caught under context" + (" — no plant in either corpus, nothing to lose" if b["planted"] == 0 and not f.get("plants") else "") + " — no plant lost in either half"; changes.append(fam)
    elif st == "admitted":
        disp = "deciding"; reason = f"admitted by the fit but its held-out corpus-B plant is LOST under context ({b['cal']}/{b['planted']} caught)"
    elif st == "refused": disp = "deciding"; reason = f"refused: {why}"
    elif st == "parked": disp = "deciding"; reason = f"parked: {why}"
    else: disp = "deciding"; reason = f"unconfirmed: {why}"
    rows.append(f"| {fam} | {disp} | {reason} |")
hdr = [f"# RULING — slice 5 ({date.today().isoformat()}): \"Ranker's democracy\", applied under the owner's standing rule", "",
       "by: owner (standing rule of 2026-09-06, applied by the calibrator per NEXT_SESSION_PLAN_2026-09-10 step 4: \"context only when admitted AND no plant lost in either half\"; the owner may overrule — backup `ARCHIVE/rule_dispositions_pre_slice5_ruling_20260906.json`)", "",
       "**Principle:** the evidence sets each family's weight and the ranker decides with those weights; no family is adjudicated by hand, no plant struck by preference. Calibration set = 15 libraries, k = 7; corpora A (fit) / B (held out) as in slices 2-3, under the body-shape-stage instrument stamp.", "",
       "| family | disposition | reason (the evidence) |", "|---|---|---|"]
(cal / "RULING.md").write_text("\n".join(hdr + rows) + "\n"); (cal / "RULING_context.txt").write_text(",".join(changes) + "\n")
print(f"RULING.md: {len(rows)} families; to context: {changes or 'none'}")
PYEOF
fi
if [ "$STAGE" = all ] || [ "$STAGE" = apply ]; then
  CTX=$(cat "$CAL/RULING_context.txt" 2>/dev/null | tr -d '\n')
  cp system_scripts/rule_dispositions.json ARCHIVE/rule_dispositions_pre_slice5_ruling_20260906.json
  echo "== B7 apply"; $PY $C/apply_dispositions.py "$CAL" > "$CAL/APPLY.txt" 2>&1; tail -3 "$CAL/APPLY.txt"
  grep -q "PASSED" "$CAL/APPLY.txt" || { echo "APPLY GATE DID NOT PASS — stopping"; tail -12 "$CAL/APPLY.txt"; exit 1; }
  cp "$(ls -t ARCHIVE/health/health_*.txt | head -1)" "$CAL/health_after.txt"
  echo "== record evidence"; $PY $C/record_evidence.py "$CAL" --fit fit_k7.json --apply 2>&1 | tail -2
  echo "== dump corpus A (fly_by_night)"; $PY $C/dump_rows.py "$CAL/precision" fly_by_night=$HOME/Desktop/fly_by_night 2>&1 | tail -1
  draw() { grep -vE '^\s*#|# used:|^\s*$' "$RUSH" | grep -vE "^(${1:-__none__})\b" | head -1 | awk '{print $1}'; }
  N1=$(draw); N2=$(draw "$N1"); echo "live-run names from the Rush pool: $N1 (tqdm), $N2 (colorama)"
  rm -rf "$HOME/Desktop/$N1" "$HOME/Desktop/$N2"
  cp -R "$HOME/CodeRadar_snapshots/mels_offer_20260906_034719" "$HOME/Desktop/$N1"; cp -R "$HOME/CodeRadar_snapshots/chets_shirt_20260905_211140" "$HOME/Desktop/$N2"
  F='MONITORING|summary|mismatch|common|byte-identity|TEARDOWN|residue|LAUNCH DID NOT|pool marked|done:'
  echo "== B8 run 43 ($N1 = tqdm)"; bash $C/run_live.sh "$HOME/Desktop/$N1" mels_offer 43 "slice 5 live proof, tqdm" "$RUSH" 2>&1 | grep -E "$F" | cut -c1-200
  sleep 5
  echo "== B8 run 44 ($N2 = colorama)"; bash $C/run_live.sh "$HOME/Desktop/$N2" chets_shirt_20260905_211140 44 "slice 5 live proof, colorama" "$RUSH" 2>&1 | grep -E "$F" | cut -c1-200
  sleep 5
  echo "== B8 run 45 (fly_by_night = corpus A live)"; bash $C/run_live.sh "$HOME/Desktop/fly_by_night" fly_by_night 45 "slice 5 live proof, corpus A live" - 2>&1 | grep -E "$F" | cut -c1-200
  echo "== corpus A live plants"; $PY system_scripts/verify_manifest.py ARCHIVE/runs/fly_by_night/manifest.json --state ARCHIVE/runs/fly_by_night/state_during_run/NOAI_VALIDATION_STATE.json 2>&1 | grep -E "^fly_by_night:" | cut -c1-200
  echo "== B9 kept sites"; [ -n "$CTX" ] && $PY $C/kept_sites_delta.py "$CAL" --families "$CTX" 2>&1 | tail -2 || echo "no family moved to context — delta skipped"
  echo "== B10 freeze"; $PY $C/freeze_slice.py "$CAL" --slice 5 2>&1 | tail -3
  echo "== final gate"; $PY system_scripts/health_check.py > ARCHIVE/health/health_after_slice5_freeze_20260906.txt 2>&1; grep -E "HEALTH CHECK:|recall guard:|deciding without evidence" ARCHIVE/health/health_after_slice5_freeze_20260906.txt | cut -c1-160
fi
echo "close done ($(date +%H:%M:%S))"
