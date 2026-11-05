# RUN 161 — `secret_touch` · target `~/CodeRadar_snapshots/secret_touch_20260921_150336` (click 8.5.0) · copy2 · 2026-09-21

**T2 of session 8 — the `finished` inputs, §D of `RANKER_QUALITY_AND_SHAKEDOWN_2_PACKET_2026-09-21.md`.**

**Driver-driven, NOT a mounted MCP client.** Every `cr_*` call in this record went through the
stdio / in-process driver (`obs_run161.py`), as runs 144–151 and 156–159 did; T3 (run 162) is the
only mounted seat of this packet.

- **Target:** a FRESH copy of `~/CodeRadar_snapshots/how_it_is_20260921_003842` — pristine click
  8.5.0, src layout. `repo_id 480405eb45ce`. It pins `[tool.mypy] python_version = "3.10"`, which
  is I-128's own case.
- **Env (I-134):** `PYTHONPATH=<target>/src`, `PYTHONDONTWRITEBYTECODE=1`.
- **Invocation of record:**

```
cd /Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2 && PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/Users/dev/CodeRadar_snapshots/secret_touch_20260921_150336/src \
    ./system_scripts/run_proof.sh up /Users/dev/CodeRadar_snapshots/secret_touch_20260921_150336 \
    161 "T2 finished inputs: severed_by_repair (I-127/Q1) + forced mypy --python-version \
    (I-128/Q2)" --tracer lsof --trackers io,mypy
#   then: .venv_new/bin/python3 .archive/runs/secret_touch/obs_run161.py <target>
#   then: ./system_scripts/run_proof.sh down …
```

- **Gates:** ALL GATES PASSED after **125 s** of a 2298 s budget. Health check at launch
  **✓ PASSED — Steps 1-20**; step 17 `1955 sites — 1955 with a filed status, 0 open, 0 not in the
  ledger`, `orphan rows: 518 (frozen 518, +0)`; step 18 `257 emitted ids / 257 rows — missing 0,
  stale 0`.
- **`--trackers io,mypy` is required.** Launched without it the control reads `trackers=none` and
  the daemon logs `MYPY: not run — nothing measured (not in --trackers at launch)`; the mypy gate
  is then NOT MEASURED for reasons that have nothing to do with I-128.

## The sequence

1. `cr_attach` → `cr_status` (baseline) → `cr_run_module -m pytest tests -q` (baseline suite).
2. **The entry-point proof.** click ships no entry (run 155 fact 11) and a `-m pytest` run is
   recorded as a RUNNER, to `runner_info.json`; `live_links` reads `entry_point_info.json` and
   nothing else, so with the suite alone **`live` is 0 and nothing can sever**.
   `cr_run_module("click._termui_impl", as_module=True)` puts one module of the package through
   the wrapper as the entry: 13 target files recorded, **60 live edges** one frame later.
3. **The apply pass** — 3 rewriter rows in ONE file, ascending, each through `cr_apply` and so
   each LEASED; the client wrote each from the re-based multi-hunk diff:
   `_resolve_pager_command::423` (26 lines out, 27 in) · `_pipepager::549` (85 / 86) ·
   `_tempfilepager::636` (33 / 34). `applies_cleanly` true and `lease_written` true on all three.
4. **The negative** — one comment line appended to `src/click/decorators.py`, a file no `cr_apply`
   ever touched.
5. Suite again → `cr_status` → the mirror and the lease read by hand → back-out → `cr_stop`.

## The readings (read back from `cr_status`, the dash mirror and the lease)

| | before | after the apply pass |
|---|---|---|
| suite | exit 0 · **1990 passed · 25 skipped · 1 xfailed** | exit 0 · **1990 passed · 25 skipped · 1 xfailed** |
| `severed_links` (the `finished` input) | 0 | **5** |
| `severed_by_repair` | 0 | **5** |
| `wiring.severed` (every red edge) | 0 | **10** |
| `mypy_ran` · `mypy_rc` · `mypy_files_checked` | **true · 1 · 54** | true · 1 · 54 |
| `mypy_errors` | 1313 | 1313 |
| `finished` | **false** (bool) | **false** (bool) |
| `counterfeit_failed` | 198 | 197 |

The split is exact. The 5 `severed_by_repair` edges are the five incident on the LEASED file:
`_termui_impl → _compat`, `→ exceptions`, `→ types`, `→ utils`, and `termui → _termui_impl`. The 5
that stay `severed` are the five incident on `decorators.py`, the UNLEASED edit:
`__init__ → decorators`, `core → decorators`, `decorators → core`, `→ globals`, `→ utils`.
Every one of the ten carries the same `severed_since`; only the lease tells them apart.

**§D.3, answered:** `severed_by_repair >= 1` ✓ · those edges absent from the `finished` input ✓ ·
`mypy_ran true` with `mypy_files_checked > 0` ✓ · `finished` a BOOLEAN ✓ · suite unmoved ✓.

## Teardown

Back-out from the bytes the client kept, in reverse order; all three spans `found_where_written`,
`decorators.py` restored to its recorded sha256. `RESIDUE CHECK: zero CodeRadar mirror files
remain in target`; **byte-identity: 113 files, diff exit 0 (IDENTICAL)**.

## Two launches; this is the second

Launch A ran the same script with a client that rebuilt the span by keeping the `+` and space
lines of the whole diff. `cr_apply` returns a **multi-hunk** diff, so `_pipepager`'s 85-line span
came back **22 lines** and click's collection broke (`exit 2 · 2 errors during collection`) — the
client's defect, not the repair's. `obs_run161.py` now applies the hunks by their `@@` headers
(`apply_hunks`), the same span comes back 86 lines, and the suite is unmoved. Launch A's engine
readings were identical to launch B's (`severed_by_repair 5 · severed_links 5 · mypy_ran true ·
54 files · 1313 errors · finished false`). **Launch B is the run of record.**
