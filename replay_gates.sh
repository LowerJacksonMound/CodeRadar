#!/bin/bash
# I-94 / FIX_67: re-run every claimed gate IN THE ORIGINAL rather than trusting a lane's record.
# A lane's gate claim can be wrong in its own tree (run 131: "conformance exit 0" with one thrown-out
# term standing). Every transplant close since has re-run the gates by hand; this is that ritual as
# one command with one verdict line, the way refresh_copies.sh prints deps= beside drift=.
#
#   ./replay_gates.sh [label]      e.g. ./replay_gates.sh after_run151
#
# Seventeen gates, sequential (the stdio proofs share state files), each judged by its EXIT CODE
# only; logs under .archive/health/gates_<label>/<gate>.txt, SUMMARY.txt beside them, and the last
# line printed here is  gates=ok (17/17) <dir>  or  gates=FAIL:<names> <dir>.  Exit 0 only on ok.
#
# T2 (the `finished` inputs, session 8, 2026-09-21): `finished` is the 17th here — the 16th in
# copy2, renumbered by the S8-4a transplant that met it with the Ranker lane's own 16th —
# `system_scripts/finished_proof.py`, the proof of I-127 (`severed_by_repair`: the lease read, the
# bucket, both halves of the rule, the two clocks, the severed input through the daemon's own
# mirror writer) and I-128 (the forced `--python-version`, and `not measured` on an abort), and,
# in its part (ix), of run 161's own record.
#
# T1 (the Ranker's quality, session 8, 2026-09-21): `ranker` is the 16th — `system_scripts/ranker_proof.py`,
# the proof that every failing unit is in exactly ONE published bucket and that `failed` is computed
# FROM the buckets (I-129), that no corrupt span is published as a repair (I-131), that a candidate
# from a rule that is not on the row is refused with both rules named (I-132), and that Q4's two
# rule false positives are silent on the click snapshot's own bytes.
#
# T1 (the drift fix, session 7, 2026-09-21): `identity` is the 15th — `coderadar_mcp/identity_proof.py`,
# the proof of the PRE-EDIT IDENTITY (the apply lease, the resolution order, the re-based diff, the
# tolerant id, the variant on the channel line) and, in its part (vii), of run 158's own record.
#
# T2 (B9, 2026-09-20): the gates run in the tree the SCRIPT lives in, not at a hard-coded path. As
# written the line below cd'd to the original tree by a fixed path, so a lane copy — which carries
# this script, refresh_copies.sh having copied it — ran the ORIGINAL's gates and wrote its logs
# into the original's .archive/health/. In the original the two are the same directory, so its own
# close is unchanged.
set -u
cd "$(cd "$(dirname "$0")" && pwd)" || exit 1
PY=.venv_new/bin/python
label=${1:-$(date +%Y%m%d_%H%M%S)}
out=.archive/health/gates_$label
mkdir -p "$out"
# B10 (Q-H0-10 / Q-H1-2, 2026-10-01): no gate writes bytecode or a mypy cache into CR's source dirs.
# Exported for EVERY gate: an import writes nothing; the compileall gate and any py_compile inside a
# proof (both ignore PYTHONDONTWRITEBYTECODE) compile into the engine's scratch, and the two mypy runs
# (the `mypy` gate, health_check.py's FIX_31 count) cache there too — system_scripts/.cr_pycache/, the
# F12/F32 engine cache that a launch pre-flight sweeps. The gate's own prefix is removed at the end;
# the mypy cache is kept warm between gate runs.
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX="$PWD/system_scripts/.cr_pycache/gates_$label"
export MYPY_CACHE_DIR="$PWD/system_scripts/.cr_pycache/mypy"
mkdir -p "$PYTHONPYCACHEPREFIX" "$MYPY_CACHE_DIR"
gates_t0=$(date +%s)
# The pollution reading below compares against a MARKER FILE (`-newer`), not `-newermt "@epoch"`:
# macOS's BSD find cannot parse the `@epoch` form ("Can't parse date/time"), so the reading was
# NOT MEASURED on every run until gates_after_lanes_1001 (2026-10-01). The marker lives in the
# gate's own scratch prefix, which is removed at the end.
gates_mark="$PYTHONPYCACHEPREFIX/.gates_t0"
touch "$gates_mark"
# Q-H1-3: the live CR state files a gate could overwrite — their mtimes before, compared after.
state_files="system_scripts/running.json system_scripts/running.lock system_scripts/runner_info.json system_scripts/entry_point_info.json system_scripts/daemon_log/change_tags_state.json system_scripts/circuit_state.json system_scripts/poll_config.json"
state_snapshot() { for f in $state_files; do [ -e "$f" ] && printf '%s %s\n' "$f" "$(stat -f %m "$f" 2>/dev/null)"; done; }
state_before=$(state_snapshot)
exec > >(tee "$out/SUMMARY.txt") 2>&1
pass=0; total=0; failed=()

# run <name> <timeout-seconds> <command...>: one gate, one log, one line.
run() {
  local name=$1 limit=$2; shift 2
  local log="$out/$name.txt" t0=$SECONDS
  total=$((total + 1))
  timeout "$limit" "$@" >"$log" 2>&1
  local rc=$?
  printf 'exit=%s\n' "$rc" >>"$log"
  local note
  note=$(quote "$name" "$log")
  if [ "$rc" -eq 0 ]; then
    pass=$((pass + 1)); printf '%-18s exit 0  %4ss  %s\n' "$name" "$((SECONDS - t0))" "$note"
  else
    failed+=("$name"); printf '%-18s exit %-2s %4ss  FAILED  %s\n' "$name" "$rc" "$((SECONDS - t0))" "$note"
  fi
}

# quote <name> <log>: the numbers a close quotes, read back from the gate's own log.
quote() {
  case $1 in
    health)      grep -oE 'creep [0-9]+|engine mypy: [0-9]+ errors in [0-9]+ files \([0-9]+ checked\)|HEALTH CHECK: .*' "$2" | tr '\n' ' ' ;;
    conformance) grep -oE 'THROWN-OUT hits: [0-9]+' "$2" | tail -1 ;;
    census)      grep -oE 'DISALLOWED [0-9]+; stale allowlist entries [0-9]+' "$2" | tail -1 ;;
    mypy)        grep -oE '(Success|Found)[^(]*' "$2" | tail -1 ;;   # mypy's line carries terminal escapes; no anchor
    gate_proof)  grep -oE '[0-9]+/[0-9]+ withheld[^·]*|PASSED|FAILED' "$2" | tail -2 | tr '\n' ' ' ;;
    identity)    grep -oE 'identity proof: (PASS|FAIL).*' "$2" | tail -1 | cut -c1-90 ;;
    ranker)      grep -oE 'ranker proof: (PASS|FAIL).*' "$2" | tail -1 | cut -c1-90 ;;
    naming_drift) grep -oE 'naming-drift proof: (PASS|FAIL).*' "$2" | tail -1 | cut -c1-90 ;;
    finished)    grep -oE 'severed_links [0-9]+ · severed_by_repair [0-9]+|[0-9]+ files checked|finished proof: (PASS|FAIL).*' "$2" | tail -2 | tr '\n' ' ' | cut -c1-90 ;;
    *)           tail -2 "$2" | grep -vE '^exit=' | tail -1 | cut -c1-90 ;;
  esac
}

echo "gates in $(pwd) — $(date '+%Y-%m-%d %H:%M:%S') — $out"
run gate_proof     600 $PY system_scripts/gate_proof.py
run interface      600 $PY system_scripts/mcp_interface_proof.py
run read_tools     600 $PY -m coderadar_mcp.read_tools_proof
run write_path     600 $PY system_scripts/mcp_write_path_proof.py
run confirmed      600 $PY system_scripts/mcp_confirmed_ledger_proof.py
run b9             600 $PY -m coderadar_mcp.b9_proof
run identity       600 $PY -m coderadar_mcp.identity_proof
run ranker         600 $PY system_scripts/ranker_proof.py
run naming_drift   300 $PY system_scripts/naming_drift_proof.py
run finished       600 $PY system_scripts/finished_proof.py
run nai094         600 $PY system_scripts/nai094_entry_proof.py
run fix42          600 $PY system_scripts/fix42_static_observations_proof.py
run fix47          600 $PY system_scripts/fix47_rca_reroute_proof.py
run health        1800 $PY system_scripts/health_check.py
# the conformance census reads the project's own notes folder, named by $CR_CONFORMANCE_DIR (not shipped)
if [ -n "${CR_CONFORMANCE_DIR:-}" ] && [ -f TERMINOLOGY_CENSUS_2026-09-09.py ]; then
  run conformance  300 $PY TERMINOLOGY_CENSUS_2026-09-09.py --conformance "$CR_CONFORMANCE_DIR"
else
  echo "conformance: NOT MEASURED (set CR_CONFORMANCE_DIR; needs TERMINOLOGY_CENSUS_2026-09-09.py)"; failed+=("conformance")
fi
run census         300 $PY system_scripts/preranker_census.py
run compileall     300 $PY -m compileall -q no_aivalidator system_scripts rca_main utils signature_engine detritus_cleaner semantic_analysis coderadar_mcp
run mypy           600 $PY -m mypy no_aivalidator system_scripts rca_main utils signature_engine detritus_cleaner semantic_analysis coderadar_mcp --ignore-missing-imports

# B10 — I-153 (e) for the gate run: the tree reading AFTER every gate. Every .pyc/.pyo and every
# .mypy_cache file under CR's tree (venv, .archive, .cr_pycache, recall targets excluded) newer than
# the run's start is pollution; a non-zero count fails the run; a walk that fails is NOT MEASURED.
pollution=$(find . \( -path ./.venv_new -o -path ./.archive -o -path './*recall_targets' -o -name .cr_pycache -o -name .git \) -prune -o -type f \( -name '*.pyc' -o -name '*.pyo' -o -path '*/.mypy_cache/*' \) -newer "$gates_mark" -print 2>/dev/null)
if [ $? -ne 0 ] && [ -z "$pollution" ]; then
  echo "tree pollution (I-153 e): NOT MEASURED (find failed)"; failed+=("pollution")
elif [ -n "$pollution" ]; then
  echo "tree pollution (I-153 e): POLLUTED — $(printf '%s\n' "$pollution" | wc -l | tr -d ' ') bytecode/mypy-cache files written into CR's tree by the gates: $(printf '%s\n' "$pollution" | head -5 | tr '\n' ' ')"
  failed+=("pollution")
else
  echo "tree pollution (I-153 e): clean — 0 .pyc / mypy-cache files written into CR's tree by the gates (bytecode went to $PYTHONPYCACHEPREFIX)"
fi
# Q-H1-3: the live state files, after. A changed one is NAMED (a gate overwrote the run of record).
state_after=$(state_snapshot)
if [ "$state_before" != "$state_after" ]; then
  echo "live state (Q-H1-3): CHANGED by the gates — $(diff <(printf '%s\n' "$state_before") <(printf '%s\n' "$state_after") | grep '^[<>]' | awk '{print $2}' | sort -u | tr '\n' ' ')"
else
  echo "live state (Q-H1-3): unchanged — none of ${state_files// /, } touched by the gates"
fi
rm -rf "$PYTHONPYCACHEPREFIX"   # the gate's scratch bytecode is regenerable; the mypy cache stays warm

if [ ${#failed[@]} -eq 0 ]; then verdict="gates=ok ($pass/$total)"; else verdict="gates=FAIL:$(IFS=,; echo "${failed[*]}") ($pass/$total)"; fi
echo "$verdict $out"
[ ${#failed[@]} -eq 0 ]
