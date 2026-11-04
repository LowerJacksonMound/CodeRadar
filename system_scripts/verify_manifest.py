"""verify_manifest.py — the ONE manifest→rows checker (calibrator part A6, 2026-09-06).

Joins a built target's manifest (planted_findings / honest_twins / controls) to validator ROWS from any of
three sources — a live state file, a bench dump, or an in-process run — and reports per plant whether it was
caught BY ID on its own row, caught IN SUBSTANCE (the row failed), merely SEEN AS CONTEXT, or caught BY FILE
(the pre-A6 rule, kept for continuity with RECALL_TABLE.md). One code path for the bench, the health check
(step 18 recall guard) and the launch proof, so the three can never disagree.

usage: verify_manifest.py MANIFEST (--state STATE.json | --dump DUMP.json | --run) [--json OUT]
"""
from __future__ import annotations
import argparse, asyncio, collections, contextlib, io, json, logging, os, re, sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TABLE = ROOT / "system_scripts" / "rule_dispositions.json"

# Every id form the instrument publishes: NAI-021S, HR-001, HR-NAME, NAI-IM01, SIG-print_only, MEASURED-NOTHING, RCA-001 …
# (the daemon's own `_RULE_ID_RE` = \d+[A-Z]? drops the SIG-/HR-NAME/NAI-IM01 forms — F-ID-RE1, 2026-09-06.)
RID = re.compile(r"\b((?:[A-Z]{2,4})-[A-Za-z0-9_]+)\b")


def ids_of(triggered_patterns: Any, failure_reason: str = "") -> List[str]:
    """ALL ids on a row, the failure-reason id first (it names the rule that decided)."""
    ids: List[str] = []
    for p in triggered_patterns or []:
        if isinstance(p, dict):
            tag = str(p.get("tag", "") or "")
        elif isinstance(p, (list, tuple)) and p:
            tag = str(p[0])
        else:
            tag = str(p)
        m = RID.search(tag)
        if m and m.group(1) not in ids:
            ids.append(m.group(1))
    if failure_reason:
        m = RID.search(str(failure_reason))
        if m and m.group(1) not in ids:
            ids.insert(0, m.group(1))
    return ids


def row_ids(triggered_patterns: Any, failure_reason: str = "", species: str = "") -> tuple[List[str], List[str]]:
    """(deciding_ids, context_ids) exactly as the daemon publishes them: observations flagged context=True never decide;
    the ranker's disposition table splits the rest; test species → everything is context."""
    from no_aivalidator.cheatsheets.cheatsheet_intelligence.knowledge_base import VerdictRanker
    pats = list(triggered_patterns or [])
    deciding_pats = [p for p in pats if not (isinstance(p, dict) and p.get("context") is True)]
    all_ids = ids_of(deciding_pats, failure_reason)
    ctx_only = [i for i in ids_of(pats) if i not in all_ids]
    # FIX_17 (2026-09-10): the observations' measured facts (magnitude) reach the per-(rule, context) table
    deciding, context = VerdictRanker().split_ids(all_ids, species, facts_by_id=VerdictRanker.facts_by_id(pats))
    return deciding, list(dict.fromkeys(context + ctx_only))


def _row(file: str, function: str, line: int, end_line: int, passed: bool, reason: str,
         deciding: List[str], context: List[str], species: str = "") -> Dict[str, Any]:
    return {"file": file, "function": function, "line": int(line or 0), "end_line": int(end_line or 0),
            "passed": bool(passed), "reason": (reason or "")[:160], "deciding_ids": deciding, "context_ids": context,
            "species": species}


# ── rows from the three sources ──────────────────────────────────────────────────────────────────────
def rows_from_results(results: list) -> List[Dict[str, Any]]:
    """In-process ValidationResult objects (validate_directory_async output)."""
    rows = []
    for r in results:
        species = getattr(r, "species", "") or ""
        d, c = row_ids(getattr(r, "triggered_patterns", None), getattr(r, "failure_reason", "") or "", species)
        rows.append(_row(str(getattr(r, "file_path", "") or ""), getattr(r, "function_name", ""), getattr(r, "line", 0),
                         getattr(r, "end_line", 0), getattr(r, "passed", True), getattr(r, "failure_reason", "") or "", d, c, species))
    return rows


def rows_from_state(path: Path) -> List[Dict[str, Any]]:
    """NOAI_VALIDATION_STATE.json — uses the row's published rule_ids/context_ids when present (post-migration rows);
    pre-migration rows fall back to the regex over triggered_patterns + failure_reason."""
    state = json.load(open(path, encoding="utf-8"))
    rows = []
    for rel, entries in (state.get("results_by_file") or {}).items():
        for e in entries:
            species = e.get("species", "") or ""
            if "rule_ids" in e and "context_ids" in e:
                d, c = list(e.get("rule_ids") or []), list(e.get("context_ids") or [])
            else:
                d, c = row_ids(e.get("triggered_patterns"), e.get("failure_reason") or "", species)
            rows.append(_row(rel, e.get("function", ""), e.get("line", 0), e.get("end_line", 0), e.get("passed", True),
                             e.get("failure_reason") or "", d, c, species))
    return rows


def rows_from_dump(path: Path) -> List[Dict[str, Any]]:
    """A bench dump: v1 (calibration_bench.py: rows_detail with deciding_anywhere/context, no line) or
    v2 (dump_rows.py: rows with line/end_line/all_ids/species — dispositions applied HERE, never at dump time)."""
    d = json.load(open(path, encoding="utf-8"))
    rows = []
    if "rows_detail" in d:                       # v1
        for x in d["rows_detail"]:
            rows.append(_row(str(x.get("file", "")), x.get("function", ""), x.get("line", 0), x.get("end_line", 0), x.get("passed", True),
                             x.get("reason", "") or (x.get("first") or ""), list(x.get("deciding_anywhere") or []), list(x.get("context") or []),
                             "test" if x.get("test") else ""))
    elif "by_file" in d:                         # recall_bench.py per-target dump
        for f, xs in d["by_file"].items():
            for x in xs:
                dd, cc = row_ids([{"tag": i} for i in x.get("ids", [])], x.get("reason", ""))
                rows.append(_row(f, x.get("function", ""), x.get("line", 0), x.get("end_line", 0), x.get("passed", True), x.get("reason", ""), dd, cc))
    else:                                        # v2
        for x in d.get("rows", []):
            species = x.get("species", "") or ""
            dd, cc = row_ids([{"tag": i, **({"context": True} if i in (x.get("ctx_flagged") or []) else {})} for i in x.get("all_ids", [])],
                             x.get("reason", ""), species)
            rows.append(_row(x["file"], x.get("function", ""), x.get("line", 0), x.get("end_line", 0), x.get("passed", True), x.get("reason", ""), dd, cc, species))
    return rows


def resolve_target(recorded: str) -> Path:
    """Where a planted target lives NOW. The manifest records where it was built; a retired target may since have
    been moved into a recall-targets folder under the CodeRadar root (`*recall_targets/`), or into any folder named
    in $CODERADAR_RECALL_DIRS (os.pathsep-separated). The recorded path wins when it exists; otherwise the newest
    such folder holding a dir of the same name; otherwise the recorded path itself (absent -> NOT MEASURED, exactly
    as before)."""
    p = Path(recorded or "")
    if not recorded or p.exists():
        return p
    extra = [Path(d).expanduser() / p.name for d in os.environ.get("CODERADAR_RECALL_DIRS", "").split(os.pathsep) if d]
    found = sorted([*ROOT.glob(f"*recall_targets/{p.name}"), *(c for c in extra if c.exists())],
                   key=lambda c: c.stat().st_mtime, reverse=True)
    return found[0] if found else p


def run_target(target: Path, detritus: Optional[set] = None) -> List[Dict[str, Any]]:
    """Daemon-identical offline run: stage_discover (the whitelist stage's detritus set) + validate_directory_async."""
    logging.disable(logging.CRITICAL)
    from no_aivalidator import NOAI_VALIDATOR_DAEMON as D
    from no_aivalidator.noai_validator.validator import NoAIMathValidator
    from no_aivalidator.noai_validator.file_validation import validate_directory_async
    if detritus is None:
        detritus = set()
        wl = ROOT / ".archive" / f"whitelist_{D._repo_id(target)}.json"
        if wl.exists():
            try:
                detritus = {e.get("path", "") for e in json.load(open(wl)).get("entries", []) if e.get("path")}
            except Exception:
                detritus = set()
    entries = D.stage_discover(target, detritus_files=detritus)
    validator = NoAIMathValidator()

    async def _route():
        # Item 3 (2026-09-10): the daemon attaches the ARTIFACT SCANNER's whole-set report before the ingest, so the
        # offline run does the same — the recall guard measures the route as it runs live (proxies withheld, the
        # `species` fact on every row). An unreadable stage = no report = the content classifier alone, as the daemon.
        try:
            from no_aivalidator.artifact_scanner import analyze as _artifact_analyze
            validator.artifact_report = await _artifact_analyze(target, files=[e.path for e in entries])
        except Exception:
            validator.artifact_report = None
        return await validate_directory_async(validator, target, files=[e.path for e in entries])
    coro = _route()
    try:
        asyncio.get_running_loop(); running = True
    except RuntimeError:
        running = False
    if running:   # the health check calls this from inside its own event loop — run the validator on a worker thread's loop
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=1) as ex:
            results, _ = ex.submit(asyncio.run, coro).result()
    else:
        results, _ = asyncio.run(coro)
    return rows_from_results(results)


# ── E1 (2026-10-01): the recall guard's process pool over archived targets ──────────────────────────
# Step 18 used to run the 50 archived targets one after another on one core (58.6 s of the 80 s health
# check). Each target now runs in its own spawned worker process — `run_target` exactly as above, rows
# pickled back to the parent, which joins them with `check` in the SAME run-name order as before. Nothing
# is measured less: same targets, same plants, same rows; only the wall-clock changes. No result is cached
# between runs. A worker that raises re-raises in the parent — never a 0.
def pool_workers(n_targets: int) -> int:
    """min(targets, max(2, cores - 2)): the health check keeps two cores for steps 17 and 20, which run alongside."""
    return max(1, min(n_targets, max(2, (os.cpu_count() or 2) - 2)))


def run_target_rows(target: str) -> Dict[str, Any]:
    """Pool worker: one archived target through `run_target`. Everything the engine prints while it runs is
    captured and handed back with the rows, so the parent can emit it in target order instead of letting the
    workers interleave on the health log. The engine is imported lazily from ROOT (on sys.path above)."""
    sys.dont_write_bytecode = True
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rows = run_target(Path(target))
    return {"target": target, "rows": rows, "output": buf.getvalue()}


def run_targets(targets: List[Path]) -> List[Dict[str, Any]]:
    """Rows for every target, returned in the order given, each target run in a spawned worker process
    (`run_target_rows`). An empty list makes no pool. A worker failure (exception, dead worker) is raised
    here for the caller to report; the pending targets are cancelled, nothing is turned into a 0."""
    got: List[Dict[str, Any]] = []
    if targets:
        import concurrent.futures as _cf
        import multiprocessing as _mp
        # The worker is pickled by NAME; the spawned child imports it as system_scripts.verify_manifest (ROOT is
        # on sys.path, which spawn hands to the child), so the reference must be the package-named module object.
        from system_scripts.verify_manifest import run_target_rows as _worker
        os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")   # the children write no .pyc into the tree (gate 18)
        # `run_target` disables logging process-wide; in-process that silenced the engine's chatter for the rest
        # of the health check (steps 19-20 included). The workers do it in their own processes now, so the parent
        # does the same here — the health log stays as it was.
        logging.disable(logging.CRITICAL)
        ex = _cf.ProcessPoolExecutor(max_workers=pool_workers(len(targets)), mp_context=_mp.get_context("spawn"))
        try:
            futs = [ex.submit(_worker, str(t)) for t in targets]
            got = [f.result() for f in futs]
        except BaseException:
            ex.shutdown(wait=True, cancel_futures=True)
            raise
        finally:
            ex.shutdown(wait=True)
    return got


# ── the join ─────────────────────────────────────────────────────────────────────────────────────────
def resolve_row(rows_in_file: List[Dict[str, Any]], line: int) -> Optional[Dict[str, Any]]:
    """The innermost function row whose span holds `line`; else the module row (line 0); else None.
    Two plants in one file can therefore never mask each other."""
    spans = [r for r in rows_in_file if r["line"] and r["end_line"] and r["line"] <= line <= r["end_line"]]
    if spans:
        return min(spans, key=lambda r: (r["end_line"] - r["line"], -r["line"]))
    exact = [r for r in rows_in_file if r["line"] == line]   # slice 3 (2026-09-06): a class-level row (NAI-213) carries end_line 0 on the deciding branch — a row AT the plant's line is the plant's row
    if exact:
        return exact[0]
    # body-shape stage (2026-09-06, IG-16 / NAI-209): module rows now carry the span of their deciding entry instead of
    # line 0, so the module fallback is the "<module>" row wherever it sits (line 0 kept for older dumps).
    mods = [r for r in rows_in_file if r.get("function") == "<module>" or r["line"] == 0]
    return mods[0] if mods else None


def aliases() -> Dict[str, List[str]]:
    """old id → [new ids] from the table's _renumbered block, so an archived manifest that accepts NAI-210 for a
    hallucinated import still matches NAI-217 after the A1 renumber. Read-only continuity, nothing inferred."""
    if not TABLE.exists():
        return {}
    ren = (json.load(open(TABLE, encoding="utf-8")).get("_renumbered") or {}).get("map") or {}
    out: Dict[str, List[str]] = collections.defaultdict(list)
    for new, row in ren.items():
        if row.get("was"):
            out[row["was"]].append(new)
    return dict(out)


def check(manifest: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_file: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for r in rows:
        by_file[r["file"]].append(r)
    al = aliases()
    plants = []; struck = []
    for pf in manifest.get("planted_findings") or []:
        if pf.get("struck"):   # a plant ruled non-counterfeit after the build (corpus correction) — listed, never counted
            struck.append({"file": pf["file"], "line": pf.get("line"), "family": pf.get("family"), "why": pf["struck"]}); continue
        acc = list(pf.get("accept_any_of") or [])
        acc_all = set(acc) | {n for a in acc for n in al.get(a, [])}
        frows = by_file.get(pf["file"], [])
        res = resolve_row(frows, int(pf.get("line") or 0)) if frows else None
        on_row = set(res["deciding_ids"]) if res else set()
        ctx = set(res["context_ids"]) if res else set()
        hit_id = bool(res) and (not res["passed"]) and (bool(acc_all & on_row) if acc_all else True)  # type: ignore[index]  # FIX_54 ast-pos
        # Item 3 (2026-09-10): a plant that sits in a PROXY file (`withheld_as: "proxy:<kind>"` on the manifest entry —
        # run 100's `totem_entry.py` is a path-hack script by the artifact scanner's content predicate) is judged as a
        # proxy, never as the app: the ranker withholds the row, the ids ride as context. That is the plant CAUGHT —
        # by id and in substance — when the row is withheld under exactly that species and carries the accepted id.
        _wa = str(pf.get("withheld_as") or "")
        if _wa and res and res["passed"] and (res.get("species") or "") == _wa and (bool(acc_all & ctx) if acc_all else True):
            hit_id = True
            withheld_hit = True
        else:
            withheld_hit = False
        plants.append({
            "file": pf["file"], "line": pf.get("line"), "what": pf.get("what", ""), "accept": acc, "accept_with_aliases": sorted(acc_all),
            "family": pf.get("family") or "/".join(acc) or "ANY",
            "row": (f"{res['function']}@L{res['line']}-L{res['end_line']}" if res else None), "row_passed": (res["passed"] if res else None),
            "row_deciding_ids": sorted(on_row), "row_context_ids": sorted(ctx),
            "withheld_as": _wa or None, "caught_withheld": withheld_hit,
            "caught_by_id": hit_id,
            "caught_in_substance": (bool(res) and not res["passed"]) or withheld_hit,  # type: ignore[index]  # FIX_54 ast-pos
            "seen_as_context": bool(acc_all & ctx) or (bool(acc_all & on_row) and bool(res) and res["passed"]),  # type: ignore[index]  # FIX_54 ast-pos
            "caught_by_file": any((not r["passed"]) and (bool(acc_all & set(r["deciding_ids"])) if acc_all else True) for r in frows),
            "no_row": res is None,
        })
    controls = []
    for c in manifest.get("expect_zero_findings (controls)") or manifest.get("controls") or []:
        bad = [r for r in by_file.get(c, []) if not r["passed"]]
        controls.append({"file": c, "clean": not bad, "failed_by": [f"{r['function']}: {'/'.join(r['deciding_ids']) or r['reason'][:40]}" for r in bad[:3]]})
    twins = []
    for t in manifest.get("honest_twins") or []:
        frows = by_file.get(t["file"], [])
        res = resolve_row(frows, int(t.get("line") or 0)) if frows else None
        twins.append({"file": t["file"], "line": t.get("line"), "family": t.get("family", ""), "what": t.get("what", ""),
                      "row": (f"{res['function']}@L{res['line']}-L{res['end_line']}" if res else None),
                      "passed": (res["passed"] if res else None), "failed_by": (sorted(res["deciding_ids"]) if res and not res["passed"] else []),
                      "no_row": res is None})
    fam: Dict[str, Dict[str, int]] = collections.defaultdict(lambda: {"planted": 0, "caught_by_id": 0, "caught_in_substance": 0, "seen_as_context": 0, "caught_by_file": 0})
    for p in plants:
        f = fam[p["family"]]; f["planted"] += 1
        for k in ("caught_by_id", "caught_in_substance", "seen_as_context", "caught_by_file"):
            f[k] += int(p[k])
    return {
        "target": manifest.get("target"), "rows": len(rows), "failed_rows": sum(1 for r in rows if not r["passed"]),
        "plants": plants, "struck_plants": struck, "controls": controls, "honest_twins": twins, "families": dict(fam),
        "summary": {"plants": len(plants), "caught_by_id": sum(p["caught_by_id"] for p in plants),
                    "caught_in_substance": sum(p["caught_in_substance"] for p in plants),
                    "seen_as_context": sum(p["seen_as_context"] for p in plants), "caught_by_file": sum(p["caught_by_file"] for p in plants),
                    "no_row": sum(p["no_row"] for p in plants),
                    "controls": len(controls), "controls_clean": sum(c["clean"] for c in controls),
                    "twins": len(twins), "twins_passed": sum(1 for t in twins if t["passed"] is True)},
    }


#: Where step 18's recall guard looks: `disposition_check.check` walks `.archive/runs/*/manifest.json`
#: and skips any run whose manifest carries no `planted_findings` (I-105). E1 (2026-10-01): it ALSO walks
#: the permanent evidence root `.archive/gate_evidence/recall/<run>/manifest.json` — retention sweeps
#: `.archive/runs` (keep 10 + 5, 14 days) and relocates a planted manifest there; a run present in both
#: is ONE target and the gate_evidence copy is the one read.
GUARD_DIR = ROOT / ".archive" / "runs"
EVIDENCE_DIR = ROOT / ".archive" / "gate_evidence" / "recall"


def guard_line(manifest_path: Path, manifest: Dict[str, Any]) -> str:
    """I-105 (2026-09-21): the recall guard is BLIND to a run that writes no manifest — it globs
    `.archive/runs/*/manifest.json`, so a run with no manifest there contributes no archived target
    and no plant, and the counts it publishes stay flat while reading like a measurement.

    Two branches, and the run is told which one it is in:
      GUARDED     — the manifest IS `.archive/runs/<run>/manifest.json` and carries plants, so the
                    guard reads them.
      NOT GUARDED — it carries no plants, or it is not where the guard looks. The guard cannot say
                    this (what is not there raises nothing); the checker can, so it declines OUT
                    LOUD rather than leaving a run to believe its plants were guarded."""
    mf = manifest_path.resolve()
    plants = len(manifest.get("planted_findings") or [])
    roots = {GUARD_DIR.resolve(): "runs", EVIDENCE_DIR.resolve(): "gate_evidence/recall"}
    root_name = roots.get(mf.parent.parent) if mf.name == "manifest.json" else None
    if root_name and plants:
        line = (f"GUARDED: {plants} plant(s) of run `{mf.parent.name}` are read by step 18's recall "
                f"guard — the manifest is {root_name}/{mf.parent.name}/manifest.json")
    else:
        why = ("it carries no `planted_findings`" if not plants else
               f"it is neither {GUARD_DIR}/<run>/manifest.json nor {EVIDENCE_DIR}/<run>/manifest.json")
        line = (f"NOT GUARDED: {plants} plant(s) here are invisible to step 18's recall guard — {why}. "
                f"A run whose plants are meant to be guarded writes them into "
                f"{GUARD_DIR}/<run>/manifest.json (I-105); retention relocates them to {EVIDENCE_DIR}/<run>/")
    print(line)
    return line


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest"); g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--state"); g.add_argument("--dump"); g.add_argument("--run", action="store_true")
    ap.add_argument("--json", dest="json_out")
    a = ap.parse_args(argv)
    m = json.load(open(a.manifest, encoding="utf-8"))
    guard_line(Path(a.manifest), m)
    if a.state: rows = rows_from_state(Path(a.state))
    elif a.dump: rows = rows_from_dump(Path(a.dump))
    else:
        t = resolve_target(m["target"])
        if not t.exists():
            print(f"NOT MEASURED: target {t} is not on disk (nor under a recall-targets folder)"); return 2
        rows = run_target(t)
    res = check(m, rows)
    s = res["summary"]
    print(f"{Path(a.manifest).parent.name}: rows {res['rows']} failed {res['failed_rows']} | plants {s['plants']}: by_id {s['caught_by_id']} "
          f"in_substance {s['caught_in_substance']} as_context {s['seen_as_context']} by_file {s['caught_by_file']} no_row {s['no_row']} | "
          f"controls {s['controls_clean']}/{s['controls']} clean | twins {s['twins_passed']}/{s['twins']} passed")
    for p in res["plants"]:
        mark = "✓id" if p["caught_by_id"] else ("~subst" if p["caught_in_substance"] else ("ctx" if p["seen_as_context"] else "MISS"))
        print(f"  {mark:6s} {p['file']}:{p['line']} {p['what']} accept={'/'.join(p['accept'])} row={p['row']} ids={'/'.join(p['row_deciding_ids']) or '-'}")
    for x in res.get("struck_plants", []): print(f"  struck {x['file']}:{x['line']} {x['family']} — {x['why'][:80]}")
    for c in res["controls"]:
        if not c["clean"]: print(f"  DIRTY control {c['file']}: {'; '.join(c['failed_by'])}")
    for t in res["honest_twins"]:
        if t["passed"] is not True: print(f"  TWIN {'FAILED' if t['passed'] is False else 'NO ROW'} {t['file']}:{t['line']} {t['family']} by {'/'.join(t['failed_by']) or '-'}")
    if a.json_out:
        Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
        json.dump(res, open(a.json_out, "w", encoding="utf-8"), indent=1, sort_keys=True)
        print(f"written {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
