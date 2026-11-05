# RUN 151 — middletown_dreams

- item: FIX_65 (I-117, the module as purity evidence) — the positive case, planted, applied and tested
- target: a fresh copy of `/Users/dev/Desktop/between_the_wheels` (T6's edited target, 79 files) plus
  **`colorama/repair_plant_evidence.py`** (80 files), at `/Users/dev/Desktop/middletown_dreams`. Run 150
  showed colorama has no dead store whose callee is a module-level def — its two are Win32 handles — so the
  plant supplies three, one function each: `sole` (the module's ONLY top-level `shape`, pure), `shadowed`
  (`outline` defined and then rebound `outline = shape` — bound twice), `loud` (`noisy` prints).
- name from the head of the original's reserve (5 → 4); pool line 100 marked used at `cr_stop`
- launched ~20:36 UTC · **MONITORING, 5 gates PASS**, gate budget 2330 s · repo_id `e02bde6beaec`
- driver: `obs_run151.py`, ONE TIGHT LOOP (run 149's shape): `cr_watch` → `cr_status` → `cr_infractions` →
  `cr_row` ×3 → the A/B offline → `cr_apply` ×3 → the client edits → `cr_run_module`(suite, plant, entry) →
  `cr_wiring` → `cr_report_outcome` ×3 → one Builder cycle → `cr_stop(expected_changes)` → `cr_hand_back`

**The claim:** with the module in hand, the delete is offered — and passed by G0 — only where the callee is
the module's sole pure top-level def; a name bound twice and a helper that prints keep the call.

## The three, as seen — 3 of 3 as expected

| function | span-only (before FIX_65) | with the module | pick (Ranker) | applied |
|---|---|---|---|---|
| `sole::24` | 010 `[keep_call_effect]` · 031 `[keep_effect]` · 147 `[keep_call_effect]` | **010 `[drop_assignment, keep_call_effect]` · 031 `[drop_store, keep_effect]` · 147 `[drop_assignment, keep_call_effect]`** — the module was decisive, all three rules | `dead_local_fix:drop_assignment` (6 cands) | `def sole(items):\n    return len(items)` |
| `shadowed::29` | keep only | keep only — `outline` bound twice is evidence of nothing | `dead_local_fix:keep_call_effect` (3) | `outline(items)` kept as a statement |
| `loud::34` | keep only | keep only — `noisy` prints | `dead_local_fix:keep_call_effect` (3) | `noisy(items)` kept as a statement |

(`noisy` itself has a fourth row on the file — its own print, not this run's business.)

- `cr_apply` 3/3 `applies_cleanly`; the client applied all three (`client_edit_log_run151.json`)
- **suite 38 passed / 14 skipped, exit 0** (unmoved from baseline); the edited plant imports and runs, exit 0;
  entry `demos/demo01.py` exit 0; `cr_wiring` 65 nodes · 29 edges
- `cr_report_outcome(confirmed)` ×3 written; one Builder cycle: **`counterfeit_failed` 108 → 105** (−3, exactly the three)
- counts at MONITORING: 361 functions · 170 passed · 108 failed · repairs 98 · withheld 84 (83 species + 1 gate)

## Close

`cr_stop`: stopped · residue_clean **true** · byte_identical false (client_edits 1 — the plant, as declared) ·
files_compared 80 · unexpected_changes [] · `cr_hand_back`: status MEASURED · builder_cycles 3 · infractions 105 ·
solutions 95 · **confirmed 3 · confirmed_from_ledger 3 · orphans 0** · tester_ran true. Target left standing at
`/Users/dev/Desktop/middletown_dreams`.
