#!/usr/bin/env python3
"""FIX_47 live observation: the RCA-001 rows in the published state, and decision.why."""
import json, sys
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2")
V = json.loads((ROOT / "system_scripts" / "NOAI_VALIDATION_STATE.json").read_text())
B = json.loads((ROOT / "system_scripts" / "BUILDER_STATE.json").read_text())

print("=== validator summary ===")
s = V.get("summary", {})
print({k: s.get(k) for k in ("total_files", "total_functions", "passed", "failed", "withheld")})

print("\n=== every published row carrying an RCA-001 observation ===")
n = 0
for rel, rows in (V.get("results_by_file") or {}).items():
    for r in rows or []:
        toks = [p for p in (r.get("triggered_patterns") or [])
                if isinstance(p, dict) and p.get("tag") == "RCA-001"]
        if not toks:
            continue
        n += 1
        print(f"\n  {rel}::{r.get('function')} line {r.get('line')}")
        print(f"    passed          : {r.get('passed')}")
        print(f"    failure_layer   : {r.get('failure_layer')}")
        print(f"    verdict_source  : {r.get('verdict_source')}")
        print(f"    failure_reason  : {r.get('failure_reason')}")
        print(f"    rule_ids        : {r.get('rule_ids')}   context_ids: {r.get('context_ids')}")
        print(f"    dispositions    : {r.get('dispositions')}")
        print(f"    OBSERVATION     : {json.dumps(toks[0], sort_keys=True)}")
print(f"\n  rows carrying the RCA-001 observation: {n}")

print("\n=== the CONTROL row (a caller of a passing callee, forwarding its params) ===")
for rel, rows in (V.get("results_by_file") or {}).items():
    if "ceiling_unlimited_control" not in rel:
        continue
    for r in rows or []:
        toks = [p for p in (r.get("triggered_patterns") or [])
                if isinstance(p, dict) and p.get("tag") == "RCA-001"]
        print(f"  {rel}::{r.get('function')} passed={r.get('passed')} "
              f"RCA-001 observations={len(toks)} rule_ids={r.get('rule_ids')}")

print("\n=== decision.why for every RCA-001 row ===")
bs = B.get("summary", {})
print("builder summary:", {k: bs.get(k) for k in ("total", "with_fix", "no_vetted_fix", "withheld", "rewriter", "prescribed")})
for row in B.get("rows") or []:
    if "RCA-001" not in json.dumps(row.get("rule_ids") or []):
        continue
    print(f"\n  {row.get('file')}::{row.get('function')}  rule_ids={row.get('rule_ids')}")
    print(f"    solution_kind      : {row.get('solution_kind')}   pick_role: {(row.get('decision') or {}).get('pick_role')}")
    print(f"    candidates         : {row.get('candidates_considered')}   selection: {row.get('selection')}")
    print(f"    observations       : {json.dumps(row.get('observations') or {})}")
    print(f"    decision.why       : {(row.get('decision') or {}).get('why')}")
    print(f"    fix                : {str(row.get('fix'))[:160]}")
