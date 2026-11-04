"""preranker_ledger_migrate.py — the ONE-SHOT, IDEMPOTENT ledger migration to KEY_SCHEME v2.

Owner ruling 2026-09-21 (triage sitting 2, lane L1):

  I-113  the ledger key becomes (file, variety, NORMALISED expression) — whitespace- AND
         bound-name-insensitive, so an edited line keeps its row — AND **every existing row is
         re-keyed under the scheme**, not only rows filed from now on.
  I-07   (packet Q8) orphaned keys are PAIRED when exactly one candidate exists; a rename is NEVER
         auto-applied when 0 or more than 1 candidate exists — those stay orphans, with the reason.

The normalisation itself lives in `preranker_census._norm` (KEY_SCHEME v2) and is what both sides of
step 17's join now use. This script is the migration of the DATA: it rewrites every row of the ledger
of record so that the row a site had under v1 is the row it has under v2.

ONE-SHOT and IDEMPOTENT. The migration is a fixed point of the ledger of record plus the live tree:
running it a second time re-derives the same bytes, finds them identical to the ledger of record, and
writes NOTHING. Prove it with md5 — the two readings are printed and logged.

Three stages, in this order, each counted in the log:

  1. DESCOPE (I-111). The `V93` pattern was tightened on 2026-09-21 so that only the filed shape — a
     suppressor the CODE acts on — matches, instead of every `# type: ignore` line on the tree. A row
     whose site is still in its file but is no longer in its variety's scope is neither creep nor an
     unpoliced decision: it is marked `ENDED→DESCOPED …` once, and `orphan_kinds` reads it under
     `cut` (counted again under `descoped`) rather than under `blind`.
  2. RE-KEY (I-113 / I-07). `preranker_census.rekey_rows`: exact match re-lines the row; a row whose
     site drifted is PAIRED to it when exactly one candidate exists and keeps its status; everything
     else stays an orphan with the reason. Descoped rows are skipped.
  3. FILE (I-100 and the re-key residue). A live site still carrying no row gets one, with a dated
     status naming why it is new. This is what keeps step 17's creep at 0, and it is what makes the
     migration a fixed point: after it, every live key is claimed.

  ./system_scripts/preranker_ledger_migrate.py                  # dry run: derive, compare, write nothing
  ./system_scripts/preranker_ledger_migrate.py --apply          # write the dated ledger if it differs
  ./system_scripts/preranker_ledger_migrate.py --apply --date 2026-09-21
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, re, subprocess, sys, tempfile
import datetime as dt
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LANE = "triage sitting 2 lane L1 / tr2_L1"


def _census():
    spec = importlib.util.spec_from_file_location("preranker_census", HERE / "preranker_census.py")
    mod = importlib.util.module_from_spec(spec)          # type: ignore[arg-type]
    spec.loader.exec_module(mod)                          # type: ignore[union-attr]
    return mod


def hunt(pc) -> Dict[str, list]:
    """The live hunt, run exactly as health-check step 17 runs it — the same script, the same cwd, and
    the same two dash-view-state exclusions (owner ruling 2026-09-17), so the migration and the gate
    are reading one set of sites and not two."""
    tmp = Path(tempfile.mkdtemp()) / "hunt.json"
    subprocess.run([sys.executable, str(HERE / "preranker_hunt.py"), str(tmp)],
                   cwd=str(ROOT), capture_output=True, text=True, timeout=300, check=False)
    hv = json.load(open(tmp))
    def is_dash_state(p: str) -> bool:
        return p == "system_scripts/poll_config.json" or (p.startswith("system_scripts/intent_") and p.endswith(".json"))
    return {k: [s for s in v if not is_dash_state(str(s[0]))] for k, v in hv.items()}


def _norm_v1(t: str) -> str:
    """The SUPERSEDED normalisation (FIX_30): whitespace, parentheses and quotes removed, nothing else.
    Kept here only to classify a newly filed row — it says whether v1 would have found the site a row,
    i.e. whether the site is new to the hunter or new to the key."""
    return re.sub(r"[\s()'\"]", "", t)[:40]


def descope(pc, rows: List[Dict[str, str]], live_keys: set) -> Tuple[set, List[str]]:
    """Stage 1 (I-111). A row is DESCOPED when it has no live site, its variety is one whose pattern
    was tightened on 2026-09-21 (`V93`), and the line it recorded is STILL IN ITS FILE — so the site
    did not go away, the variety stopped claiming it. Marked once; an already-marked row is left
    exactly as it stands, which is what makes stage 1 idempotent."""
    cache: Dict[str, set] = {}
    def lines_of(rel: str) -> set:
        if rel not in cache:
            p = ROOT / rel
            try: cache[rel] = {l.strip()[:90] for l in p.read_text(encoding="utf-8", errors="ignore").split("\n")}
            except OSError: cache[rel] = set()
        return cache[rel]
    marked: set = set(); notes: List[str] = []
    for i, r in enumerate(rows):
        if not r["variety"].startswith("V93"): continue
        if pc._ledger_key(r) in live_keys: continue
        status = str(r.get("status", ""))
        if pc.DESCOPED_MARK in status:
            marked.add(i); continue                       # already migrated — leave it alone
        if r["expr"][:90] not in lines_of(r["file"]): continue
        was = status.replace("orphan:", "")
        r["status"] = (f"{pc.DESCOPED_MARK} (2026-09-21, {LANE}, I-111): the V93 pattern matched every "
                       f"typing suppressor on the tree because the word `ignore` in `# type: ignore` "
                       f"satisfied its honoured half too; tightened to the filed shape, this site is out "
                       f"of the variety's scope. The line is UNCHANGED and still in the file — nothing was "
                       f"cut. Prior status: {was}")
        marked.add(i)
        notes.append(f"[descoped] {r['file']}:{r.get('line', '?')} '{r['expr'][:60]}' (was {was[:40]})")
    return marked, notes


RETIRE_DATE = "2026-09-22"


def retire(pc, rows: List[Dict[str, str]], live: Dict[tuple, List[int]]) -> Tuple[set, Dict[str, Any], List[str]]:
    """Stage 1c — I-110, owner ruling 2026-09-22, "(c) pair first, then retire".

    The pairing pass (I-07 / packet Q8) ran FIRST, in lane L1: 4 paired, 537 with no candidate. What it
    could not place and whose FILE is no longer in the tree now retires, unless a SUCCESSOR carries the
    site (`preranker_census.successor_of`: a live file with the same BASENAME carrying the same variety
    and normalised expression — the module moved and the site moved with it).

    A retired row is KEPT in the TSV as history, with its prior status in the text, and is DROPPED from
    the frozen number and from step 17's orphan count. Rows under `cut`, `superseded` or `BLIND` are not
    `file gone` and are NOT touched by this ruling. Idempotent: a row already carrying the marker is left
    exactly as it stands, which is what makes a second run derive the same bytes."""
    retirable, kept = pc.retirable(rows, live)
    marked: set = set(); already = newly = 0; notes: List[str] = []
    for k, idxs in sorted(retirable.items()):
        for i in idxs:
            r = rows[i]; marked.add(i)
            if pc.is_retired(r): already += 1; continue
            was = str(r.get("status", "")).replace("orphan:", "")
            r["status"] = (f"{pc.RETIRED_MARK} {RETIRE_DATE} ({LANE}, I-110 (c) pair first then retire): the "
                           f"pairing pass had no candidate for this row and `{r['file']}` is no longer in the "
                           f"tree; no live file of that name carries the site. KEPT here as history, dropped "
                           f"from the frozen number and from step 17's orphan count. Prior status: {was}")
            newly += 1
            notes.append(f"[retired] {r['file']}:{r.get('line', '?')} [{k[1].split(' ')[0]}] {r['expr'][:56]}")
    counts = {"retired_keys": len(retirable), "retired_rows_newly": newly, "retired_rows_already": already,
              "kept_back_successor": len(kept),
              "kept_back_detail": [f"{k[0]} [{k[1].split(' ')[0]}] -> {v}" for k, v in sorted(kept.items())]}
    return marked, counts, notes


def file_new(pc, rows: List[Dict[str, str]], fields: List[str], hv: Dict[str, list],
             date: str) -> Tuple[int, Dict[str, int], List[str]]:
    """Stage 3. Every live site that still carries no row gets one, with a dated status naming WHY it is
    new: `nested` — the hunter can now see a block nested inside an inner function (I-100); `re-key` —
    v1 found the site a row and v2 does not, and the pairing pass had 0 or more than 1 candidate, so the
    owner's rule forbids re-keying it by rename (I-07) and the site is filed in its own right."""
    have = {pc._ledger_key(r) for r in rows}
    v1_index = {(r["file"], r["variety"], _norm_v1(r["expr"])) for r in rows}
    kinds: Dict[str, int] = {"nested": 0, "re-key": 0}
    notes: List[str] = []
    added = 0
    for variety in sorted(hv):
        for f, line, expr in sorted(hv[variety], key=lambda s: (str(s[0]), int(s[1]))):
            k = (f, variety, pc._norm(expr)[:pc.KEY_WIDTH])
            if k in have: continue
            have.add(k)
            kind = "re-key" if (f, variety, _norm_v1(expr)) in v1_index else "nested"
            kinds[kind] += 1
            if kind == "nested":
                why = ("I-100: an analysis-path assertion NESTED inside an inner function of a rule "
                       "function. The hunter read only the innermost function's name, so the site was "
                       "SILENCED BY NESTING and reported zero; it now sees nested blocks. A gate reading "
                       "a fixed subject, not a ranking.")
            else:
                why = ("I-113 / I-07: the site's v1 row could not be carried across to KEY_SCHEME v2 with "
                       "exactly one candidate, and the owner's rule (packet Q8) forbids auto-applying a "
                       "rename on 0 or more than 1 — so the site is filed in its own right and its v1 row "
                       "stays an orphan with the reason. Structural, not a ranking.")
            row = {c: "" for c in fields}
            row.update({"variety": variety, "file": f, "line": str(line), "expr": expr,
                        "review": "UNREVIEWED", "status": f"KEPT→STRUCTURAL (filed {date}, {LANE}, {why})"})
            rows.append(row); added += 1
            notes.append(f"[filed {kind}] {f}:{line} [{variety.split(' ')[0]}] {expr[:70]}")
    return added, kinds, notes


def pair_split(pc, rows: List[Dict[str, str]], live: Dict[tuple, List[int]], skip: set) -> Dict[str, int]:
    """I-07 / packet Q8, read as a census rather than as a log line. Of the rows with NO live site (the
    orphaned keys the pairing pass is run over), how many sit in a group with EXACTLY ONE candidate —
    the only case the owner allows a re-key on — how many in a group with NONE, and how many in a group
    that is ambiguous (more than one row, or more than one candidate site, or both). The ambiguous ones
    are reported as a count of ROWS and of GROUPS and are left exactly as they stand: the ruling is
    never to auto-apply a rename on 0 or more than 1."""
    claimed = {k for k in live if any(pc._ledger_key(r) == k for r in rows)}
    unmatched = [i for i, r in enumerate(rows) if i not in skip and pc._ledger_key(r) not in live]
    rows_by: Dict[tuple, List[int]] = {}
    for i in unmatched: rows_by.setdefault((rows[i]["file"], rows[i]["variety"]), []).append(i)
    sites_by: Dict[tuple, List[tuple]] = {}
    for k in live:
        if k in claimed: continue
        sites_by.setdefault((k[0], k[1]), []).append(k)
    one = zero = ambiguous = 0; amb_groups = 0
    for g, idxs in rows_by.items():
        cands = sites_by.get(g, [])
        if len(idxs) == 1 and len(cands) == 1: one += 1
        elif not cands: zero += len(idxs)
        else: ambiguous += len(idxs); amb_groups += 1
    return {"orphaned_keys_paired_over": len(unmatched), "exactly_one_candidate": one,
            "zero_candidates": zero, "more_than_one": ambiguous, "more_than_one_groups": amb_groups}


def migrate(apply: bool = False, date: Optional[str] = None, ledger: Optional[Path] = None) -> Dict[str, Any]:
    pc = _census()
    date = date or dt.date.today().isoformat()
    ledger = ledger or pc.LEDGER
    before_bytes = ledger.read_bytes()
    before_md5 = hashlib.md5(before_bytes).hexdigest()
    hv = hunt(pc)
    live = pc._live_index(hv)
    fields = pc.ledger_fields(ledger)
    rows = pc.read_ledger(ledger)

    before_join = pc.hunter_join(hv, ledger)
    before_kinds = pc.orphan_kinds(pc.read_ledger(ledger), live)

    marked, descope_notes = descope(pc, rows, set(live))
    retired_idx, retire_counts, retire_notes = retire(pc, rows, live)
    marked = marked | retired_idx
    split = pair_split(pc, rows, live, marked)
    counts = pc.rekey_rows(hv, rows, skip=marked)
    added, kinds, file_notes = file_new(pc, rows, fields, hv, date)

    text = pc.ledger_text(rows, fields)
    after_md5 = hashlib.md5(text.encode("utf-8")).hexdigest()
    changed = text.encode("utf-8") != before_bytes
    out_path = ROOT / ".archive" / f"PRERANKER_HUNT_{date}.tsv"
    written: Optional[str] = None
    if changed and apply:
        if out_path.exists() and hashlib.md5(out_path.read_bytes()).hexdigest() == after_md5:
            written = "(already identical)"               # already there, byte for byte
        elif out_path.exists():
            raise FileExistsError(f"{out_path.name} exists and differs — a dated ledger is never overwritten")
        else:
            out_path.write_text(text, encoding="utf-8"); written = out_path.name

    # the AFTER reading is taken off the DERIVED bytes, whether or not they were written — so a dry run
    # and an --apply run report the same numbers and the gate can assert the fixed point without writing.
    derived = Path(tempfile.mkdtemp()) / (out_path.name)
    derived.write_text(text, encoding="utf-8")
    after_join = pc.hunter_join(hv, derived)
    after_kinds = pc.orphan_kinds(pc.read_ledger(derived), live)

    return {"key_scheme": pc.KEY_SCHEME, "key_width": pc.KEY_WIDTH, "source": ledger.name,
            "source_md5": before_md5, "derived_md5": after_md5, "changed": changed,
            "applied": apply, "written": written, "target": out_path.name,
            "derived_text": text,
            "rows_in": len(rows) - added, "rows_out": len(rows), "rows_rekeyed": len(rows) - added,
            "descoped": len(marked) - len(retired_idx), "descope_notes": descope_notes, "pair_split": split,
            "retire": retire_counts, "retire_notes": retire_notes,
            "filed": added, "filed_kinds": kinds, "file_notes": file_notes,
            "before": {k: before_join.get(k) for k in ("hits", "statused", "open", "not_in_ledger", "orphan", "ledger_keys")},
            "before_kinds": {k: v for k, v in before_kinds.items() if k != "blind_rows"},
            "after": {k: after_join.get(k) for k in ("hits", "statused", "open", "not_in_ledger", "orphan", "ledger_keys")},
            "after_kinds": {k: v for k, v in after_kinds.items() if k != "blind_rows"},
            **{k: counts[k] for k in ("relined", "orphaned", "kept_orphan", "paired_expr", "paired_file",
                                      "live_keys", "pair_candidates", "pairings_applied")}}


def report(r: Dict[str, Any]) -> str:
    L: List[str] = []
    a = L.append
    a(f"preranker ledger migration — KEY_SCHEME {r['key_scheme']} (expr normalised, width {r['key_width']}) — {dt.datetime.now().isoformat(timespec='seconds')}")
    a(f"source ledger            : {r['source']}  md5 {r['source_md5']}")
    a(f"derived ledger           : {r['target']}  md5 {r['derived_md5']}  changed={r['changed']}  applied={r['applied']}  written={r['written']}")
    a(f"rows re-keyed under v2   : {r['rows_rekeyed']}  (every existing row, not only rows filed from now on)")
    a(f"  stage 1 descoped       : {r['descoped']}  (I-111 — the V93 pattern tightened past a site still in its file)")
    a(f"  stage 1c RETIRED       : {r['retire']['retired_keys']} keys / {r['retire']['retired_rows_newly']} rows newly "
      f"+ {r['retire']['retired_rows_already']} already (I-110 (c) pair first then retire); "
      f"kept back on a successor: {r['retire']['kept_back_successor']}")
    for d in r["retire"]["kept_back_detail"]: a(f"      kept back: {d}")
    a(f"  stage 2 re-lined       : {r['relined']}  exact match under v2")
    a(f"  stage 2 PAIRED         : {r['paired_expr'] + r['paired_file']}  ({r['paired_expr']} expression drift, {r['paired_file']} file moved) — exactly one candidate (I-07 / packet Q8)")
    a(f"  stage 2 left orphan    : {r['orphaned']} newly orphan + {r['kept_orphan']} already orphan")
    a(f"  stage 3 rows filed     : {r['filed']}  {r['filed_kinds']}")
    a(f"live keys this tree      : {r['live_keys']}")
    a(f"BEFORE (rows not yet migrated, read under v2): {r['before']}")
    a(f"BEFORE orphan kinds      : {r['before_kinds']}")
    a(f"AFTER  (derived v2 ledger): {r['after']}")
    a(f"AFTER  orphan kinds      : {r['after_kinds']}")
    s = r["pair_split"]
    a(f"I-07 pairing verdict     : orphaned keys the pairing ran over {s['orphaned_keys_paired_over']} · "
      f"PAIRED (exactly one candidate) {r['paired_expr'] + r['paired_file']} · "
      f"left orphan, 0 candidates {s['zero_candidates']} · "
      f"left orphan, >1 candidates {s['more_than_one']} rows in {s['more_than_one_groups']} group(s) "
      f"— reported, never applied (packet Q8)")
    for n in r["pairings_applied"]: a(f"  paired: {n}")
    for n in r["pair_candidates"]: a(f"  {n}")
    for n in r["descope_notes"]: a(f"  {n}")
    for n in r["retire_notes"]: a(f"  {n}")
    for n in r["file_notes"]: a(f"  {n}")
    return "\n".join(L)


LAUNCH_WITNESS = "system_scripts/poll_config.json"


def launched_side(pc) -> Tuple[bool, str]:
    """I-104, the owner's 2026-09-22 rider, taken from lane L1's own spec-blind fact 4.

    `poll_config.json` is the dashboard's view state. It is EXCLUDED from the hunter by the 2026-09-17
    dash-view-state ruling, but its three ledger rows are still classified by whether the FILE exists —
    so they read `file gone` on a tree that has never launched and `BLIND` on one that has. That moves
    the four-kind split by 3 and, since this lane retires `file gone` rows, it would move the frozen
    number itself. The side is therefore recorded IN the close file, and every reading of the frozen
    number has to be taken on the same side it was frozen on."""
    live = (pc.ROOT / LAUNCH_WITNESS).exists()
    return live, ("launched — `" + LAUNCH_WITNESS + "` is present, so its three rows read BLIND"
                  if live else
                  "not launched — `" + LAUNCH_WITNESS + "` is absent, so its three rows read `file gone`")


def refreeze(pc, write: bool = False, close_path: Optional[Path] = None) -> Dict[str, Any]:
    """I-104 (re-freeze LAST, after the retirement) + I-142 (the stale counters and the ledger field).

    Derives `preranker_close.json` from THIS tree's own reading — never a hand-set number — so that
    step 17 then reads `orphan rows: N (frozen N, +0)`. Returns the old and new blocks; writes only on
    `write=True`. `close_path` points the derivation at some OTHER close file, which is how the proof
    shows idempotence properly — deriving from an already-derived close reproduces it — without making
    that proof depend on whether the tree has drifted since the freeze."""
    close_path = close_path or pc.CLOSE
    hv = hunt(pc)
    live = pc._live_index(hv)
    j = pc.hunter_join(hv)
    rows = pc.read_ledger()
    kinds = {k: v for k, v in pc.orphan_kinds(rows, live).items() if k != "blind_rows"}
    old = json.loads(close_path.read_text(encoding="utf-8"))
    launched, why = launched_side(pc)
    standing: Dict[str, int] = {}
    for r in rows:
        s = str(r.get("status", "")).replace("orphan:", "")
        head = (pc.RETIRED_MARK if pc.RETIRED_MARK in s else
                pc.DESCOPED_MARK if pc.DESCOPED_MARK in s else
                (s.split("→")[0].split(" ")[0].split("(")[0].strip() or "(none)"))
        standing[head] = standing.get(head, 0) + 1
    new = dict(old)
    new["ledger"] = f".archive/{pc.LEDGER.name}"
    new["ledger_note"] = ("informational ONLY — step 17 resolves the ledger of record with "
                          "`preranker_census.newest_ledger()` (the newest dated `.archive/PRERANKER_HUNT_*.tsv`) "
                          "and never reads this field. It named `PRERANKER_HUNT_2026-09-17.tsv` until "
                          f"2026-09-22 (I-142); it is kept, pointed at the migrated ledger, rather than dropped, "
                          "so a reader can see which file the frozen numbers below were derived from.")
    new["hunter_hits_on_tree"] = j["hits"]
    new["statused"] = j["statused"]
    new["open"] = j["open"]
    new["not_in_ledger"] = j["not_in_ledger"]
    new["ledger_rows"] = len(rows)
    new["orphan_rows"] = j["orphan"]
    new["key_scheme"] = pc.KEY_SCHEME
    # Every field below is a pure function of the tree and the ledger — no clock, no append-on-top — so
    # a second `--refreeze` derives the same bytes and writes nothing. That is what the gate asserts.
    new["frozen_on"] = {"launched_side": launched, "witness": LAUNCH_WITNESS, "why": why,
                        "frozen_at": RETIRE_DATE,
                        "rule": ("read the frozen number on the SAME side of a launch it was frozen on; on the "
                                 "other side the three `" + LAUNCH_WITNESS + "` rows move between `file gone` "
                                 "and `BLIND` and, since `file gone` retires, the total moves with them")}
    new["standing"] = standing
    new["standing_2026_09_06"] = old.get("standing_2026_09_06", old.get("standing"))
    new["orphan_kinds"] = {**kinds, "note": (
        "FIX_48 (owner Q8, 2026-09-17), re-derived 2026-09-22 by triage sitting 2 lane L2 after the I-110 "
        "retirement. `cut + file_gone + superseded + blind == orphan_keys == orphan_rows`. `descoped` "
        "(I-111) is an informational sub-count INSIDE `cut`; `retired` (I-110) is counted BESIDE the four "
        "kinds and is NOT an orphan — those rows are kept in the TSV as history only.")}
    # the reading this lane froze FROM, captured once so the paragraph below reads the same on every run
    new["frozen_from"] = old.get("frozen_from") or {
        "orphan_rows": old.get("orphan_rows"), "hunter_hits_on_tree": old.get("hunter_hits_on_tree"),
        "statused": old.get("statused"), "ledger_rows": old.get("ledger_rows"), "ledger": old.get("ledger"),
        "orphan_kinds": {k: v for k, v in (old.get("orphan_kinds") or {}).items() if k != "note"},
        "note": "the close as it stood before triage sitting 2 lane L2 (I-110 / I-104 / I-142)"}
    was = new["frozen_from"]
    stamp = f"RE-FROZEN {RETIRE_DATE} (triage sitting 2 lane L2"
    prior = str(old.get("refrozen", "")).split(" || " + stamp)[0]   # this lane's paragraph, written once
    new["refrozen"] = (prior +
                       f" || RE-FROZEN {RETIRE_DATE} (triage sitting 2 lane L2, run 171, copy1): after I-110's "
                       f"retirement of {kinds.get('retired', 0)} `file gone` keys with no successor, orphan_rows "
                       f"{was.get('orphan_rows')} → {j['orphan']} and the four kinds re-derived from step 17's own "
                       f"reading of this tree, so step 17 reads +0. I-142's three counters refreshed in the same "
                       f"pass (hunter_hits_on_tree {was.get('hunter_hits_on_tree')} → {j['hits']}, statused "
                       f"{was.get('statused')} → {j['statused']}, ledger_rows {was.get('ledger_rows')} → {len(rows)}), "
                       f"`standing` re-derived beside the 2026-09-06 block, and the `ledger` field pointed at the "
                       f"migrated ledger. Frozen on the {'LAUNCHED' if launched else 'NOT-LAUNCHED'} side.")
    text = json.dumps(new, indent=1, ensure_ascii=False) + "\n"
    changed = text != close_path.read_text(encoding="utf-8")
    if write and changed: close_path.write_text(text, encoding="utf-8")
    return {"old": old, "new": new, "changed": changed, "written": bool(write and changed),
            "live": {"orphan": j["orphan"], "hits": j["hits"], "statused": j["statused"],
                     "open": j["open"], "not_in_ledger": j["not_in_ledger"], "ledger_rows": len(rows)},
            "kinds": kinds, "launched": launched, "delta": j["orphan"] - int(new["orphan_rows"]),
            "md5": hashlib.md5(text.encode("utf-8")).hexdigest()}


# ── the proof the `census` gate runs (gate count stays 17; no gate added, none re-scoped) ──────────
FIXTURE_BEFORE = '''"""a fixture tree for the KEY_SCHEME v2 proof — not engine code."""
def check_batch(rows):
    def _inner_gate(seen):
        assert len(seen) >= 0, 'the inner gate counts what it was given'
        return True
    for item in rows[:20]:
        _inner_gate(item)
    return True
'''
FIXTURE_AFTER = '''"""a fixture tree for the KEY_SCHEME v2 proof — not engine code."""
def check_batch(payload):
    def _inner_gate(observed):
        assert  len(observed)>=0 , 'the inner gate counts what it was given'
        return True
    for entry in payload[:20]:
        _inner_gate(entry)
    return True
'''
FIXTURE_V93 = '''"""a fixture tree for the I-111 proof — not engine code."""
import os
BARE = os.sep  # type: ignore[assignment]
def scan(paths):
    for p in paths:
        if not p:
            continue  # noqa: E501 — skip the empty one
    return True
'''


def _fixture_hunt(text_py: str, text_v93: str) -> Tuple[Path, Dict[str, list]]:
    """Run the REAL hunter over a throwaway tree that holds only the fixture, by giving it that tree as
    its cwd — the hunter roots itself at `.`, so nothing about it is stubbed for the proof."""
    root = Path(tempfile.mkdtemp())
    (root / "system_scripts").mkdir()
    (root / "system_scripts" / "fixture_site.py").write_text(text_py, encoding="utf-8")
    (root / "system_scripts" / "fixture_v93.py").write_text(text_v93, encoding="utf-8")
    out = root / "hunt.json"
    subprocess.run([sys.executable, str(HERE / "preranker_hunt.py"), str(out)],
                   cwd=str(root), capture_output=True, text=True, timeout=120, check=False)
    return root, json.load(open(out))


def key_scheme_proof() -> Tuple[bool, List[str]]:
    """The point of the fix, proved rather than asserted (I-113, I-111, I-100).

    (i)   a hunted line is edited — its bound names renamed and its spacing changed — and re-hunted.
          Under the SUPERSEDED v1 key the edited site is a NEW row and the old row is an ORPHAN;
          under v2 it is THE SAME ROW.
    (ii)  a bare `# type: ignore` is no longer a V93 site and the filed shape still is (I-111).
    (iii) an assert nested inside an inner function of a rule function IS a V59 site (I-100).
    (iv)  the ledger of record is at KEY_SCHEME v2 and the migration is a FIXED POINT of it — running
          it again derives the same bytes — and step 17's creep on this tree is 0."""
    pc = _census()
    L: List[str] = []; ok = True
    def check(label: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and cond
        L.append(f"  {'✓' if cond else '✗'} {label}{(' — ' + detail) if detail else ''}")

    r1, hv1 = _fixture_hunt(FIXTURE_BEFORE, FIXTURE_V93)
    r2, hv2 = _fixture_hunt(FIXTURE_AFTER, FIXTURE_V93)
    V59 = "V59 assert in analysis path"; V19B = "V19b iteration cap"; V93 = "V93 noqa/suppressor honoured"

    L.append("KEY_SCHEME v2 proof — I-113 / I-07 / I-111 / I-100")
    # (iii) I-100 first: without it the fixture has no nested assert to key at all.
    check("I-100 the hunter sees a block nested in an inner function",
          len(hv1.get(V59, [])) == 1 and len(hv2.get(V59, [])) == 1,
          f"V59 on the fixture: before-edit {len(hv1.get(V59, []))}, after-edit {len(hv2.get(V59, []))} "
          f"(the assert is inside `_inner_gate`, itself inside `check_batch`)")
    # (ii) I-111
    v93 = [s for s in hv1.get(V93, []) if "fixture_v93" in str(s[0])]
    bare = [s for s in v93 if "BARE" in str(s[2])]
    honoured = [s for s in v93 if "continue" in str(s[2])]
    check("I-111 a bare `# type: ignore` is not a V93 site", not bare, f"{len(bare)} matched")
    check("I-111 the filed shape (a suppressor on a line that continues) still is",
          len(honoured) == 1, f"{len(honoured)} matched: {honoured[0][2] if honoured else '-'}")

    # (i) I-113: the same two sites, before and after the edit, under both schemes
    sites1 = [(v, s) for v in (V59, V19B) for s in hv1.get(v, [])]
    sites2 = [(v, s) for v in (V59, V19B) for s in hv2.get(v, [])]
    check("the fixture carries the two keyed sites before and after the edit",
          len(sites1) == 2 and len(sites2) == 2, f"{len(sites1)} / {len(sites2)}")
    if len(sites1) == 2 and len(sites2) == 2:
        k1_v1 = {(s[0], v, _norm_v1(s[2])) for v, s in sites1}
        k2_v1 = {(s[0], v, _norm_v1(s[2])) for v, s in sites2}
        k1_v2 = {(s[0], v, pc._norm(s[2])[:pc.KEY_WIDTH]) for v, s in sites1}
        k2_v2 = {(s[0], v, pc._norm(s[2])[:pc.KEY_WIDTH]) for v, s in sites2}
        check("BEFORE the fix (v1 key): the edited line files a NEW row and orphans its own",
              k1_v1 != k2_v1 and len(k2_v1 - k1_v1) == 2 and len(k1_v1 - k2_v1) == 2,
              f"new rows {len(k2_v1 - k1_v1)} · orphaned rows {len(k1_v1 - k2_v1)}")
        check("AFTER the fix (v2 key): the edited line keeps its row",
              k1_v2 == k2_v2 and len(k2_v2 - k1_v2) == 0,
              f"new rows {len(k2_v2 - k1_v2)} · orphaned rows {len(k1_v2 - k2_v2)} · keys {sorted(x[2] for x in k1_v2)}")
        for v, s in sites1:
            after = [s2 for v2, s2 in sites2 if v2 == v][0]
            L.append(f"      [{v.split(' ')[0]}] '{s[2][:52]}' -> '{after[2][:52]}'")
            L.append(f"         v1 {_norm_v1(s[2])!r} vs {_norm_v1(after[2])!r}")
            L.append(f"         v2 {pc._norm(s[2])[:pc.KEY_WIDTH]!r} vs {pc._norm(after[2])[:pc.KEY_WIDTH]!r}")

    # (iv) the ledger of record itself
    note = pc.LEDGER.read_text(encoding="utf-8").splitlines()[0]
    check("the ledger of record carries the v2 join-key note",
          "KEY_SCHEME v2" in note, f"{pc.LEDGER.name}: {note[:72]}…")
    m = migrate(apply=False)
    # IDEMPOTENCE, proved as D(D(x)) == D(x) rather than as D(x) == x. The second form compares the
    # derivation against the ledger ON DISK, so it fails whenever the tree has legitimately moved since
    # the migration ran — an edited line, a deleted site — which is not what "running it twice changes
    # nothing" means and is not a failure the owner asked this gate to raise (coordinator, 2026-09-22).
    _tmp = Path(tempfile.mkdtemp()) / m["target"]
    _tmp.write_text(m["derived_text"], encoding="utf-8")
    _again = migrate(apply=False, ledger=_tmp)
    check("the migration is IDEMPOTENT — deriving from its own output reproduces it byte for byte",
          _again["derived_md5"] == m["derived_md5"],
          f"D(x) md5 {m['derived_md5']} == D(D(x)) md5 {_again['derived_md5']}")
    # creep read off the LEDGER OF RECORD as it stands — not off the derived text, where `file_new` has
    # already filed every unrowed site and creep is 0 by construction.
    _live_join = pc.hunter_join(hunt(pc))
    check("step 17's creep on this tree is 0 against the ledger of record",
          _live_join["not_in_ledger"] == 0,
          f"hits {_live_join['hits']} · statused {_live_join['statused']} · open {_live_join['open']} · "
          f"not_in_ledger {_live_join['not_in_ledger']} · orphan {_live_join['orphan']}")
    L.append(f"  · reading, not asserted: the ledger on disk is md5 {m['source_md5']} and the migration would "
             f"derive {m['derived_md5']} ({'no change' if not m['changed'] else 'a change — run --apply'})")
    L.append(f"  orphan kinds under v2: {m['after_kinds']}")

    # ── I-110 / I-104 / I-142 — the frozen numbers (triage sitting 2 lane L2, 2026-09-22) ──────────
    L.append("FROZEN-NUMBERS proof — I-110 retire · I-104 re-freeze · I-142 the stale counters")
    rows_now = pc.read_ledger()
    live_now = pc._live_index(hunt(pc))
    retirable, kept_back = pc.retirable(rows_now, live_now)
    unmarked = [k for k, idxs in retirable.items() if not pc.is_retired(rows_now[idxs[0]])]
    check("I-110 the retirement is a FIXED POINT — no `file gone` key is left unretired",
          not unmarked, f"{len(retirable)} keys retired, {len(unmarked)} still to retire, "
                        f"{len(kept_back)} kept back on a successor")
    f = refreeze(pc, write=False)
    check("I-110 `file gone` is 0 on this tree",
          f["kinds"].get("file_gone") == 0,
          f"file gone {f['kinds'].get('file_gone')} · retired (beside the four kinds, not an orphan) "
          f"{f['kinds'].get('retired')} · kept back on a successor {len(kept_back)}")
    close = json.loads(pc.CLOSE.read_text(encoding="utf-8"))
    four = sum(int(close["orphan_kinds"].get(x, 0)) for x in ("cut", "file_gone", "superseded", "blind"))
    check("I-104 the frozen four kinds sum to the frozen orphan count",
          four == int(close["orphan_rows"]),
          f"cut {close['orphan_kinds'].get('cut')} + file gone {close['orphan_kinds'].get('file_gone')} + "
          f"superseded {close['orphan_kinds'].get('superseded')} + BLIND {close['orphan_kinds'].get('blind')} "
          f"= {four} == orphan_rows {close['orphan_rows']}")
    check("I-104 the close file records WHICH SIDE OF A LAUNCH it was frozen on",
          isinstance(close.get("frozen_on"), dict) and "launched_side" in close["frozen_on"],
          f"launched_side={close.get('frozen_on', {}).get('launched_side')} witness="
          f"{close.get('frozen_on', {}).get('witness')}")
    # I-142, asserted on what does NOT drift: the ledger field names a dated ledger that exists and is
    # no longer the superseded 2026-09-17 one, and the frozen counters are internally coherent. Whether
    # they still match the tree is a READING below — a later lane that removes a site moves the live
    # hits, and that is not a failure this gate raises (coordinator's ruling, 2026-09-22).
    _named = ROOT / str(close.get("ledger", "")).removeprefix("./")   # NOT lstrip: it eats the leading dot
    check("I-142 the ledger field names a dated ledger that exists, not the superseded 2026-09-17 one",
          _named.exists() and _named.name.startswith("PRERANKER_HUNT_") and "2026-09-17" not in _named.name,
          f"ledger {close.get('ledger')}")
    check("I-142 the frozen counters are internally coherent",
          int(close["statused"]) + int(close["open"]) == int(close["hunter_hits_on_tree"])
          and int(close["not_in_ledger"]) == 0,
          f"statused {close['statused']} + open {close['open']} == hunter_hits_on_tree "
          f"{close['hunter_hits_on_tree']} · frozen creep {close['not_in_ledger']}")
    L.append(f"  · READING (not asserted): frozen vs live — hunter_hits_on_tree {close['hunter_hits_on_tree']}"
             f"/{f['live']['hits']} · statused {close['statused']}/{f['live']['statused']} · ledger_rows "
             f"{close['ledger_rows']}/{f['live']['ledger_rows']} (they were 1356 / 1356 / 2389 before I-142)")
    # the re-freeze, idempotent as D(D(x)) == D(x) — deriving from an already-derived close reproduces
    # it — rather than as D(x) == x, which would fail the moment the tree moved away from the freeze.
    _tc = Path(tempfile.mkdtemp()) / "preranker_close.json"
    _tc.write_text(json.dumps(f["new"], indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    _f2 = refreeze(pc, write=False, close_path=_tc)
    check("I-104 the re-freeze is IDEMPOTENT — deriving from its own output reproduces it byte for byte",
          not _f2["changed"] and _f2["md5"] == f["md5"], f"D(x) md5 {f['md5']} == D(D(x)) md5 {_f2['md5']}")
    # THE FROZEN NUMBER IS A READING, NOT AN ASSERTION (coordinator's ruling, 2026-09-22). The frozen
    # count is the owner's call, so this gate must not fail a later lane for deleting a hunted site and
    # moving the delta. It fails on (a) creep, asserted above against the ledger of record, and on
    # (b) the close file's own kinds not summing to its own frozen number — an internal inconsistency
    # that is nobody's judgement call. The delta itself is printed, with the side it must be read on.
    delta = f["live"]["orphan"] - int(close["orphan_rows"])
    same_side = bool(close.get("frozen_on", {}).get("launched_side")) == f["launched"]
    L.append(f"  · READING (not asserted — the frozen number is the owner's call): "
             f"orphan rows: {f['live']['orphan']} (frozen {close['orphan_rows']}, "
             f"{'+' if delta >= 0 else ''}{delta})"
             + ("" if same_side else
                f"  — NB read on the other side of a launch from the freeze ({LAUNCH_WITNESS}); "
                f"three rows move between `file gone` and `BLIND` across it")
             + ("" if delta == 0 else
                "  — the number has moved since the freeze; re-freeze with "
                "`preranker_ledger_migrate.py --refreeze --apply` or record why it stands"))
    return ok, L


if __name__ == "__main__":
    if "--refreeze" in sys.argv:
        _w = "--apply" in sys.argv
        _r = refreeze(_census(), write=_w)
        _o, _n = _r["old"], _r["new"]
        print(f"re-freeze (I-104 LAST, after I-110's retirement) — write={_w} changed={_r['changed']} written={_r['written']}")
        print(f"  frozen on the {'LAUNCHED' if _r['launched'] else 'NOT-LAUNCHED'} side — {LAUNCH_WITNESS}")
        for _k in ("orphan_rows", "hunter_hits_on_tree", "statused", "ledger_rows", "open", "not_in_ledger"):
            print(f"  {_k:20} {_o.get(_k)} -> {_n.get(_k)}")
        print(f"  orphan_kinds         {({k: v for k, v in (_o.get('orphan_kinds') or {}).items() if k != 'note'})}")
        print(f"                    -> {({k: v for k, v in _r['kinds'].items()})}")
        print(f"  ledger               {_o.get('ledger')} -> {_n.get('ledger')}")
        print(f"  step 17 will read    orphan rows: {_r['live']['orphan']} (frozen {_n['orphan_rows']}, +{_r['delta']})")
        print(f"  close file md5       {_r['md5']}")
        sys.exit(0)
    if "--proof" in sys.argv:
        _ok, _lines = key_scheme_proof()
        print("\n".join(_lines))
        print(f"key-scheme proof: {'PASS' if _ok else 'FAIL'}")
        sys.exit(0 if _ok else 1)
    _date = None
    if "--date" in sys.argv: _date = sys.argv[sys.argv.index("--date") + 1]
    _r = migrate(apply="--apply" in sys.argv, date=_date)
    _txt = report(_r)
    print(_txt)
    # lane-neutral by default (it was `tr2_L1_proof`, the label of the lane that wrote this script, which
    # would have made every later lane's log land in L1's directory); `PRERANKER_MIGRATE_LOG_DIR`
    # overrides it so a lane can keep its own record beside its other proofs without editing this file.
    _dir = os.environ.get("PRERANKER_MIGRATE_LOG_DIR", ".archive/health/preranker_ledger")
    _log = ROOT / _dir / f"migrate_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    _log.parent.mkdir(parents=True, exist_ok=True)
    _log.write_text(_txt + "\n", encoding="utf-8")
    print(f"log -> {_log.relative_to(ROOT)}")
    sys.exit(0)
