#!/usr/bin/env python3
"""obs_run161.py — RUN 161 `secret_touch`: THE `finished` INPUTS, §D of the session-8 packet, copy2.

**Driver-driven, NOT a mounted MCP client.** Every `cr_*` call in this record goes through the
STDIO / IN-PROCESS DRIVER, as runs 144–151 and 156–159 did; only T1 (run 152) and T3 (runs
154–155, and run 162) mount the server. The packet's own line for this lane, kept.

Target: a FRESH copy of `~/CodeRadar_snapshots/how_it_is_20260921_003842` — pristine click 8.5.0,
src layout, `PYTHONPATH=<target>/src`, `PYTHONDONTWRITEBYTECODE=1` (I-134). It pins
`[tool.mypy] python_version = "3.10"`, which is I-128's own case.

What it measures, §D.3:

  1. An APPLY PASS of >= 3 rows in ONE file, every one of them through `cr_apply` — so every one
     of them LEASED — written by the client from the re-based hunk, in ascending line order so
     no earlier edit moves a later row's span.
  2. THE NEGATIVE, in the same frame: one edit to a file the server NEVER handed out. Its edges
     have no lease, so they must stay `severed` and stay in `finished`'s input.
  3. `cr_status` after: `severed_by_repair >= 1`, those edges absent from `severed_links`,
     `mypy_ran true` with `mypy_files_checked > 0` (the count and the error total quoted), and
     `finished` a BOOLEAN — every one of the three inputs measured.

Then every edit is backed out from the bytes the client kept, so teardown is byte-identical.

Every number is READ BACK off `cr_status`, the dash mirror and the lease file. Nothing is
counted here that the mirror does not already say.
"""
import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.session_tools import cr_watch, cr_attach, cr_stop, cr_hand_back  # noqa: E402
from coderadar_mcp.read_tools import cr_status, cr_infractions, cr_row, cr_wiring   # noqa: E402
from coderadar_mcp.write_tools import cr_apply, cr_run_module                       # noqa: E402

TARGET = Path(sys.argv[1] if len(sys.argv) > 1
              else "/Users/dev/CodeRadar_snapshots/secret_touch_20260921_150336")
RUNDIR = ROOT / ".archive" / "runs" / "secret_touch"
SCRIPTS = ROOT / "system_scripts"
MONITOR_MIRROR = SCRIPTS / ".monitor_state.json"

#: The file the server never hands out — the negative of §D.3. A comment line appended to it
#: changes its bytes and severs every import edge incident on it, exactly as a repair would;
#: the difference, and the only difference, is that no lease covers it.
UNLEASED_FILE = "src/click/decorators.py"
UNLEASED_MARK = "# run 161: an edit the server never handed out (I-127's negative)\n"

#: run 155's readings, for the "moved / unmoved" claims. Written HERE, before the compute.
RUN155 = {
    "suite": "1990 passed · 25 skipped · 1 xfailed",
    "mypy_ran": False, "mypy_rc": 2, "mypy_files_checked": 0,
    "mypy_forced_by_hand": "rc 1 · 65 source files checked · 1285 errors",
    "severed_links_after_the_apply_pass": 16,
}

#: The module run through the wrapper as the ENTRY POINT. Importing it imports the package, so
#: the wrapper's proof covers every file the package's own import chain touches — including the
#: file the apply pass edits and the file the negative edits.
ENTRY_MODULE = "click._termui_impl"

WANT_ROWS = 3          # §D.3's floor: at least three rows, in ONE file, through the lease
CANDIDATES = 8         # offered to `cr_apply` in ascending order until WANT_ROWS are written
CYCLE_WAIT_CEILING_S = 900

out: dict = {}


def save() -> None:
    (RUNDIR / "run161.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")


def read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:                       # never silent: the miss is the observation
        return {"__unreadable__": f"{type(e).__name__}: {e}"}


def jsonl(p: Path) -> list:
    recs = []
    for raw in (p.read_text(encoding="utf-8", errors="replace").splitlines()
                if p.exists() else []):
        raw = raw.strip()
        if raw:
            try:
                recs.append(json.loads(raw))
            except Exception:
                pass
    return recs


def status_facts(label: str) -> dict:
    """The five readings §D.3 asks for, off `cr_status` itself."""
    s = cr_status()
    rec = {"label": label, "cycle": s.get("cycle"),
           "severed_links": (s.get("summary") or {}).get("severed_links"),
           "severed_by_repair": s.get("severed_by_repair"),
           "mypy_ran": s.get("mypy_ran"), "mypy_rc": s.get("mypy_rc"),
           "mypy_files_checked": s.get("mypy_files_checked"),
           "mypy_errors": (s.get("summary") or {}).get("mypy_errors"),
           "finished": s.get("finished"), "finished_type": type(s.get("finished")).__name__,
           "finished_reason": s.get("finished_reason"),
           "finished_inputs": (s.get("summary") or {}).get("finished_inputs"),
           "counterfeit_failed": (s.get("infractions") or {}).get("failed")}
    print(f"\n  cr_status [{label}] cycle {rec['cycle']}")
    print(f"      severed_links {rec['severed_links']} · severed_by_repair "
          f"{rec['severed_by_repair']}")
    print(f"      mypy_ran {rec['mypy_ran']} · mypy_rc {rec['mypy_rc']} · "
          f"mypy_files_checked {rec['mypy_files_checked']} · mypy_errors {rec['mypy_errors']}")
    print(f"      finished {rec['finished']!r} ({rec['finished_type']}) — "
          f"{rec['finished_reason']}")
    return rec


def suite(label: str) -> dict:
    r = cr_run_module("pytest", args=["tests", "-q"], as_module=True, timeout_s=1800)
    tail = [l for l in str(r.get("stdout") or "").strip().splitlines() if l.strip()][-3:]
    rec = {"label": label, "exit_code": r.get("exit_code"), "duration_s": r.get("duration_s"),
           "seen_on_band": r.get("seen_on_band"), "tail": tail, "error": r.get("error")}
    print(f"\n  suite [{label}] exit={rec['exit_code']} in {rec['duration_s']}s")
    for l in tail:
        print(f"      {l}")
    return rec


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_hunks(segment: list, diff: str) -> list:
    """`cr_apply`'s diff, applied to the span's own lines HUNK-ACCURATELY.

    LAUNCH A's defect (measured here, run 161's first launch, and on T1's lane the same day):
    `cr_apply` returns a MULTI-HUNK unified diff — `difflib.unified_diff(..., n=context_lines)`,
    three lines of context — and carries no `after_code`. Keeping every `+` and space line of
    the whole diff therefore DROPS every line the hunks skip: `_pipepager`'s 85-line span came
    back as 22 lines, click's collection broke, and the break was the client's, not the repair's.
    The hunk headers are 1-based against the segment, so each `@@` says where to resume."""
    out: list = []
    pos = 0
    lines = (diff or "").splitlines(keepends=True)
    i = 0
    while i < len(lines):
        m = HUNK_RE.match(lines[i])
        if m is None:
            i += 1
            continue
        start = int(m.group(1)) - 1
        out.extend(segment[pos:start])
        pos = start
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            ln = lines[i]
            if ln.startswith("+"):
                out.append(ln[1:])
            elif ln.startswith("-"):
                pos += 1
            elif ln.startswith(" "):
                out.append(ln[1:])
                pos += 1
            elif ln.startswith("\\"):        # "\ No newline at end of file"
                pass
            i += 1
    out.extend(segment[pos:])
    return out


def span_bounds(span: str) -> tuple:
    head, _, tail = span.rpartition(":L")
    first, _, last = tail.partition("-L")
    return head, int(first), int(last)


def write_edit(span_live: str, diff: str) -> dict:
    """The client's own edit. Under Q3 the client's working tree IS the archive, so what was
    overwritten is kept HERE — that is what backs the edit out at the end, byte for byte."""
    rel, start, end = span_bounds(span_live)
    path = TARGET / rel
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    segment = lines[start - 1:end]
    replaced = "".join(segment)
    new = apply_hunks(segment, diff)
    path.write_text("".join(lines[:start - 1] + new + lines[end:]), encoding="utf-8")
    return {"file": rel, "span_live": span_live, "start": start, "end": end,
            "lines_out": end - start + 1, "lines_in": len(new), "replaced_text": replaced,
            "wrote_text": "".join(new),
            "replaced_sha256": hashlib.sha256(replaced.encode()).hexdigest(),
            "wrote_sha256": hashlib.sha256("".join(new).encode()).hexdigest()}


def back_out(edit: dict) -> dict:
    """The reverse of `write_edit`, from the bytes the client kept. The span it puts them back
    at is where its own text IS now, not where it was — later edits are all BELOW it here, so
    the two are the same, and the check below says so rather than assuming it."""
    path = TARGET / edit["file"]
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = edit["start"]
    height = edit["lines_in"]
    here = "".join(lines[start - 1:start - 1 + height])
    ok = hashlib.sha256(here.encode()).hexdigest() == edit["wrote_sha256"]
    if ok:
        path.write_text("".join(lines[:start - 1]) + edit["replaced_text"]
                        + "".join(lines[start - 1 + height:]), encoding="utf-8")
    return {"file": edit["file"], "span": edit["span_live"], "found_where_written": ok}


def wait_cycles(n: int, why: str) -> dict:
    c0 = cr_status().get("cycle") or 0
    print(f"\nwaiting {n} Builder cycle(s) from {c0} — {why}")
    t0 = time.monotonic()
    deadline = t0 + CYCLE_WAIT_CEILING_S
    cyc = c0
    while time.monotonic() < deadline:
        time.sleep(5)
        cyc = cr_status().get("cycle") or 0
        if cyc >= c0 + n:
            break
    waited = round(time.monotonic() - t0, 1)
    print(f"  cycle {c0} -> {cyc} ({cyc - c0} of {n} wanted) after {waited}s")
    return {"from": c0, "to": cyc, "wanted": n, "got": cyc - c0, "seconds": waited,
            "reached_the_ceiling": cyc - c0 < n, "why": why}


def wait_for_live(why: str) -> dict:
    """Wait until the daemon has turned the entry-point proof into LIVE edges. Read back off
    `cr_wiring`; an edge that is not live was never severable, and nothing would sever."""
    t0 = time.monotonic()
    live = 0
    while time.monotonic() - t0 < CYCLE_WAIT_CEILING_S:
        time.sleep(5)
        w = cr_wiring(include_dataflows=False)
        live = sum(1 for x in w.get("edges", []) if x.get("state") == "live")
        if live:
            break
    waited = round(time.monotonic() - t0, 1)
    print(f"\n{why}: {live} live edge(s) after {waited}s")
    return {"why": why, "seconds": waited, "live_edges": live}


def wait_for_severs(why: str) -> dict:
    """Wait until the circuit daemon has published a frame that carries the edits' severs. The
    condition is the MIRROR's, read back every 5 s; the ceiling is the same one the cycles use."""
    t0 = time.monotonic()
    seen = {}
    while time.monotonic() - t0 < CYCLE_WAIT_CEILING_S:
        time.sleep(5)
        s = cr_status()
        seen = {"severed_links": (s.get("summary") or {}).get("severed_links"),
                "severed_by_repair": s.get("severed_by_repair"),
                "cycle": s.get("cycle")}
        if int(seen.get("severed_by_repair") or 0) >= 1:
            break
    waited = round(time.monotonic() - t0, 1)
    print(f"\n{why}: {seen} after {waited}s")
    return {"why": why, "seconds": waited, **seen}


def pick_rows() -> tuple:
    """>= 3 rewriter rows in ONE file, ASCENDING by line — so every edit is below the one
    before it and no recorded span moves. Chosen by asking `cr_infractions`, never by reading
    the mirror file here."""
    by_file: dict = {}
    page = 1
    while True:
        p = cr_infractions(page=page, has_solution=True)
        for r in p.get("rows", []):
            if r.get("solution_kind") == "rewriter" and r.get("line"):
                by_file.setdefault(r["file"], []).append(r)
        if page >= int(p.get("pages") or 1):
            break
        page += 1
    for rel, rows in sorted(by_file.items(), key=lambda kv: -len(kv[1])):
        rows.sort(key=lambda r: int(r["line"]))
        if len(rows) >= WANT_ROWS:
            return rel, rows[:CANDIDATES], {k: len(v) for k, v in by_file.items()}
    return "", [], {k: len(v) for k, v in by_file.items()}


def main() -> int:
    out["driver"] = ("stdio / in-process driver in a run record — NOT a mounted MCP client "
                     "(the packet's line for T1 and T2; T3/run 162 is the only mounted seat)")
    out["item"] = ("T2, the `finished` inputs (session 8 §D): `severed_by_repair` (I-127 / Q1) "
                   "and the forced mypy `--python-version` (I-128 / Q2)")
    out["target"] = str(TARGET)
    out["run155"] = RUN155
    out["watch"] = w = cr_attach(str(TARGET))
    out["bound_by"] = "cr_attach (run_proof.sh up launched)"
    if not w.get("attached"):
        print(f"cr_attach refused ({w.get('error')}) — falling back to cr_watch")
        out["watch"] = w = cr_watch(str(TARGET))
    save()

    out["status"] = [status_facts("before anything — the baseline reading")]
    save()

    out["suite"] = [suite("baseline, before any edit")]
    save()

    # ── THE ENTRY-POINT PROOF — what makes an import edge LIVE, and so severable ────────────
    # click ships no entry (run 155 fact 11) and a `-m pytest` run is recorded as a RUNNER, to
    # `runner_info.json`; `live_links` reads the ENTRY-POINT proof (`entry_point_info.json`,
    # plan item 8) and nothing else. So one module of the package is run through the wrapper as
    # the entry: importing it imports the package, and the wrapper records the sha256 of every
    # target file that import touched. An edge is `severable` only while BOTH its ends carry
    # that proof — which is exactly why changing a file's bytes severs its edges (I-127).
    out["entry_point_run"] = e = cr_run_module(ENTRY_MODULE, as_module=True, timeout_s=300)
    print(f"\nentry point {ENTRY_MODULE}: exit={e.get('exit_code')} error={e.get('error')}")
    out["entry_point_proof"] = read_json(SCRIPTS / "entry_point_info.json").get("file_hashes", {})
    print(f"  the wrapper recorded {len(out['entry_point_proof'])} target file(s)")
    out["live_wait"] = wait_for_live("the frame that lights the import edges")
    save()

    rel, rows, census = pick_rows()
    out["row_census"] = census
    out["chosen_file"] = rel
    out["chosen"] = [{"id": r["id"], "line": r["line"], "line_end": r.get("line_end"),
                      "function": r.get("function"), "rule_ids": r.get("rule_ids")}
                     for r in rows]
    print(f"\nchosen: {len(rows)} rewriter row(s) in {rel} — "
          f"{', '.join(r['id'] for r in rows)}")
    if len(rows) < WANT_ROWS:
        print("not enough rewriter rows in any one file — stopping before any edit")
        save()
        return 1
    save()

    # ── THE APPLY PASS — every row through `cr_apply`, so every row LEASED ──────────────────
    print(f"\nAPPLY PASS — {WANT_ROWS} rows in {rel}, ascending, each one leased")
    out["applies"] = []
    out["edits"] = []
    for r in rows:
        if len(out["edits"]) >= WANT_ROWS:
            break
        a = cr_apply(r["id"])
        rec = {"row": r["id"], "kind": a.get("kind"), "digest": a.get("digest"),
               "selected_role": a.get("selected_role"),
               "replace_span": a.get("replace_span"),
               "replace_span_live": a.get("replace_span_live"),
               "rebased": a.get("replace_span") != a.get("replace_span_live"),
               "applies_cleanly": a.get("applies_cleanly"),
               "lease": a.get("lease"), "lease_written": a.get("lease_written"),
               "resolved_by": a.get("resolved_by"), "error": a.get("error")}
        out["applies"].append(rec)
        print(f"  {r['id']}")
        print(f"      span {rec['replace_span']} live {rec['replace_span_live']} "
              f"clean={rec['applies_cleanly']} leased={rec['lease_written']}")
        if a.get("kind") == "diff" and a.get("applies_cleanly"):
            e = write_edit(a["replace_span_live"], a.get("diff") or "")
            out["edits"].append(e)
            print(f"      the client wrote it: {e['lines_out']} line(s) out, "
                  f"{e['lines_in']} in")
        else:
            print(f"      NOT written — {rec['error']}")
    out["leased_rows"] = [e["row"] for e in out["applies"] if e["lease_written"]]
    save()

    # ── THE NEGATIVE — one edit to a file the server never handed out ───────────────────────
    print(f"\nTHE NEGATIVE — one edit to {UNLEASED_FILE}, which no `cr_apply` ever touched")
    unleased = TARGET / UNLEASED_FILE
    out["unleased_before_sha256"] = hashlib.sha256(unleased.read_bytes()).hexdigest()
    unleased.write_text(unleased.read_text(encoding="utf-8") + UNLEASED_MARK, encoding="utf-8")
    out["unleased_edit"] = {"file": UNLEASED_FILE, "appended": UNLEASED_MARK.strip(),
                            "leased": UNLEASED_FILE in
                                      [a["replace_span"].split(":L")[0] for a in out["applies"]]}
    print(f"  appended one comment line; leased={out['unleased_edit']['leased']}")
    save()

    # ── the frames that carry the severs ────────────────────────────────────────────────────
    out["wait"] = [wait_for_severs("the first frame that buckets a repair-severed edge")]
    out["cycles"] = [wait_cycles(1, "one more Builder cycle over the edited file")]
    save()

    out["suite"].append(suite("after the apply pass and the unleased edit"))
    out["status"].append(status_facts("after the apply pass — §D.3's reading"))
    save()

    # ── the mirror and the lease, read by hand ──────────────────────────────────────────────
    mirror = read_json(MONITOR_MIRROR).get("monitor", {})
    wiring = mirror.get("wiring", {})
    out["wiring"] = {
        "severed": wiring.get("severed", []),
        "severed_by_repair": wiring.get("severed_by_repair", []),
        "severed_since": wiring.get("severed_since", {}),
    }
    out["mirror_summary"] = {k: mirror.get("summary", {}).get(k) for k in
                             ("severed_links", "severed_by_repair", "mypy_errors", "mypy_ran",
                              "mypy_rc", "mypy_files_checked", "finished", "finished_reason",
                              "finished_inputs")}
    out["mypy_block"] = {k: (mirror.get("mypy") or {}).get(k) for k in
                         ("files_checked", "total_errors", "type_errors", "annotation_notes",
                          "mypy_rc", "mypy_ran", "mypy_config", "mypy_python_version")}
    print(f"\nmirror wiring: severed {len(out['wiring']['severed'])} · "
          f"severed_by_repair {len(out['wiring']['severed_by_repair'])}")
    for p in out["wiring"]["severed_by_repair"]:
        print(f"    BY REPAIR  {p[0]} -> {p[1]}  since "
              f"{out['wiring']['severed_since'].get(f'{p[0]}->{p[1]}')}")
    print(f"mypy: {out['mypy_block']}")

    lease_file = SCRIPTS / f"apply_lease_{w.get('repo_id') or cr_status().get('repo_id')}.jsonl"
    out["leases_on_disk"] = [{k: r.get(k) for k in
                              ("row_key", "digest", "replace_span", "replace_span_live",
                               "file", "variant", "after_sha256", "timestamp")}
                             for r in jsonl(lease_file)]
    out["lease_file"] = str(lease_file)
    print(f"\n{len(out['leases_on_disk'])} lease record(s) in {lease_file.name}")

    # ── §D.3's four answers, stated ─────────────────────────────────────────────────────────
    after = out["status"][-1]
    repair_pairs = {tuple(p) for p in out["wiring"]["severed_by_repair"]}
    open_pairs = {tuple(p) for p in out["wiring"]["severed"]} - repair_pairs
    out["verdict"] = {
        "severed_by_repair_ge_1": int(after["severed_by_repair"] or 0) >= 1,
        "repair_severed_absent_from_the_finished_input":
            after["severed_links"] == len(open_pairs)
            and not (repair_pairs & open_pairs),
        "mypy_ran_true_with_files": bool(after["mypy_ran"])
            and int(after["mypy_files_checked"] or 0) > 0,
        "finished_is_a_boolean": isinstance(after["finished"], bool),
        "suite_unmoved": out["suite"][0]["exit_code"] == out["suite"][-1]["exit_code"],
    }
    print(f"\n§D.3: {json.dumps(out['verdict'])}")

    # the record the 16th gate's live part reads
    (RUNDIR / "run161_cr_status_after.json").write_text(
        json.dumps(cr_status(), indent=1, default=str), encoding="utf-8")
    save()

    # ── BACK OUT — teardown must be byte-identical ──────────────────────────────────────────
    print("\nBACKING OUT — the bytes the client kept, in reverse order")
    out["back_out"] = [back_out(e) for e in reversed(out["edits"])]
    unleased.write_text(unleased.read_text(encoding="utf-8")[:-len(UNLEASED_MARK)],
                        encoding="utf-8")
    out["unleased_after_sha256"] = hashlib.sha256(unleased.read_bytes()).hexdigest()
    out["unleased_restored"] = out["unleased_after_sha256"] == out["unleased_before_sha256"]
    for b in out["back_out"]:
        print(f"  {b['file']} {b['span']} found_where_written={b['found_where_written']}")
    print(f"  {UNLEASED_FILE} restored={out['unleased_restored']}")
    save()

    out["status"].append(status_facts("after the back-out"))
    out["stop"] = cr_stop(verify_identity=True)
    out["hand_back"] = cr_hand_back(note="run 161 — T2, the `finished` inputs (§D)")
    save()
    print("\nrun 161 recorded in run161.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
