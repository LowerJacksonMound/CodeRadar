"""Pre-ranker ranking census — health-check step 17 (owner ruling 2026-09-05, late sitting).

"Every time I've said no ranking before the ranker it has been broken; the health check must scan
all possible areas that may contain disallowed pre-ranker rankers."

Scans every rule-bearing module by syntax tree for numeric decisions: a comparison against a numeric
literal, an identifier vote weight, a truncation of an evidence list. Every site must be on the
explicit ALLOWLIST (a structural fact or plumbing, keyed by file + function + expression so line
shifts cannot hide it) or carry a dated EXEMPTION naming the plan item that removes it. Anything
else is a disallowed pre-ranker ranker and the gate FAILS. Nothing is inferred as allowed.
"""
from __future__ import annotations
import ast, builtins, glob, json, keyword, os, re, sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = Path(__file__).resolve().parent / "preranker_allowlist.json"
# Every module that can turn a measurement into a verdict or a repair choice. The ranker itself
# (knowledge_base.py: SolutionRanker / VerdictRanker) is the ONE place allowed to rank and is not scanned.
SCAN = [
    "no_aivalidator/detection/*.py",
    "no_aivalidator/noai_validator/*.py",          # validator, strict, identifier, file_validation, extractor, indexer, …
    "no_aivalidator/*.py",                         # the daemon
    "no_aivalidator/cheatsheets/*.py",             # builder / hub / reviewer / schema (repair-side gates are listed, not hidden)
    "no_aivalidator/repair_generators/*.py",       # the repair-generator registry: structural preconditions inside rewriters (item 4, 2026-09-08)
    "no_aivalidator/artifact_scanner/*.py",        # the artifact scanner: species predicates by content (Item 3, 2026-09-10) — predicate-bearing, so the census sees it
    "signature_engine/*.py",
    "semantic_analysis/*.py",
]
# Not yet scanned (widen next; listed so nobody assumes coverage): rca_main/*.py, system_scripts/circuit_daemon.py,
# system_scripts/ast_scanner.py, system_scripts/mypy_n_contracts_watcher/*.py, system_scripts/proof_dashboard.py.
NOT_SCANNED = ["rca_main/*.py", "system_scripts/circuit_daemon.py", "system_scripts/ast_scanner.py",
               "system_scripts/mypy_n_contracts_watcher/*.py", "system_scripts/proof_dashboard.py"]
SKIP_ATTR = re.compile(r"lineno|col_offset|end_line|version|argv|port|timeout|interval|retry|sleep|max_workers|chunk|buffer|indent|width")

def _is_num(n): return isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool)
def _name(n):
    if isinstance(n, ast.Name): return n.id
    if isinstance(n, ast.Attribute): return n.attr
    if isinstance(n, ast.Call): return (_name(n.func) or "") + "()"
    if isinstance(n, ast.Subscript): return _name(n.value)
    return ast.unparse(n)[:40]

class _V(ast.NodeVisitor):
    def __init__(self, rel: str, lines: List[str], out: List[Dict[str, Any]]):
        self.rel = rel; self.lines = lines; self.out = out; self.stack: List[ast.AST] = []
    def _enter(self, node): self.stack.append(node); self.generic_visit(node); self.stack.pop()
    visit_FunctionDef = _enter; visit_AsyncFunctionDef = _enter; visit_ClassDef = _enter
    def _func(self):
        for n in reversed(self.stack):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)): return n.name
        return "<module>"
    def _emit(self, node, kind, expr):
        self.out.append({"file": self.rel, "line": node.lineno, "func": self._func(), "kind": kind, "expr": expr,
                         "excised": "EXCISED cut" in self.lines[node.lineno - 1]})
    def visit_If(self, node):
        for cmp in [n for n in ast.walk(node.test) if isinstance(n, ast.Compare)]:
            parts = [cmp.left] + cmp.comparators
            if any(_is_num(p) for p in parts):
                other = " ".join(_name(p) for p in parts if not _is_num(p))
                if not SKIP_ATTR.search(other): self._emit(node, "compare", ast.unparse(cmp))
        self.generic_visit(node)
    def visit_Return(self, node):
        if isinstance(node.value, ast.Compare):
            parts = [node.value.left] + node.value.comparators
            if any(_is_num(p) for p in parts):
                other = " ".join(_name(p) for p in parts if not _is_num(p))
                if not SKIP_ATTR.search(other): self._emit(node, "compare", ast.unparse(node.value))
        self.generic_visit(node)
    def visit_Subscript(self, node):
        if isinstance(node.slice, ast.Slice) and node.slice.upper is not None and _is_num(node.slice.upper) and node.slice.lower is None:
            self._emit(node, "truncate", ast.unparse(node))
        self.generic_visit(node)
    def visit_Call(self, node):
        if _name(node.func) == "most_common()" and node.args and _is_num(node.args[0]):
            self._emit(node, "rank-op", ast.unparse(node))
        self.generic_visit(node)
    def _reason_near(self, lineno: int) -> str:
        for k in range(lineno - 1, min(lineno + 7, len(self.lines))):
            l = self.lines[k]
            if "failure_reason" in l or "warnings" in l or "WHITELISTED" in l or "SyntaxError" in l or "Cannot" in l:
                return re.sub(r"\s+", " ", l.strip())[:70]
        return ""
    def visit_keyword(self, node):
        # a literal verdict written outside the ranker: passed=False / passed=True as a keyword.
        # The nearest reason text is part of the key so two verdicts in one function stay distinct.
        if node.arg == "passed" and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
            self._emit(node.value, "verdict-literal", f"passed={node.value.value} :: {self._reason_near(node.value.lineno)}")
        self.generic_visit(node)
    def visit_Attribute(self, node):
        self.generic_visit(node)
    def visit_AugAssign(self, node):
        if isinstance(node.op, ast.Add) and _is_num(node.value) and "votes" in ast.unparse(node.target):
            self._emit(node, "vote-weight", ast.unparse(node))
        self.generic_visit(node)
    def visit_Assign(self, node):
        u = ast.unparse(node)
        if re.search(r"votes\[.*\]\s*=\s*votes\.get\(.*\)\s*\+\s*\d+", u): self._emit(node, "vote-weight", u)
        for t in node.targets:
            if isinstance(t, ast.Attribute) and t.attr == "passed" and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
                self._emit(node, "verdict-literal", f"{u[:60]} :: {self._reason_near(node.lineno)}")
        self.generic_visit(node)

def census() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for pat in SCAN:
        for f in sorted(glob.glob(str(ROOT / pat))):
            if f.endswith("__init__.py") or "_removed_rankings" in f: continue
            rel = os.path.relpath(f, ROOT); src = open(f).read()
            try: tree = ast.parse(src)
            except SyntaxError as e:
                out.append({"file": rel, "line": e.lineno or 0, "func": "<parse>", "kind": "PARSE-ERROR", "expr": str(e), "excised": False}); continue
            _V(rel, src.split("\n"), out).visit(tree)
    return out

def key(r: Dict[str, Any]) -> str: return f"{r['file']}::{r['func']}::{r['expr']}"

def newest_ledger() -> Path:
    """FIX_30 (2026-09-15): the ledger of record is the NEWEST `.archive/PRERANKER_HUNT_*.tsv` by name
    (a `--rekey` writes a dated file beside the old one, never over it)."""
    found = sorted((ROOT / ".archive").glob("PRERANKER_HUNT_*.tsv"))
    return found[-1] if found else ROOT / ".archive" / "PRERANKER_HUNT_2026-09-09b.tsv"
LEDGER = newest_ledger()
CLOSE = Path(__file__).resolve().parent / "preranker_close.json"
LEDGER_NOTE = ("# ledger of record — join key = (file, variety, NORMALISED expr[:40]) — by EXPRESSION, never by line (owner close 2026-09-06); "
               "the normalisation is whitespace- AND bound-name-insensitive (KEY_SCHEME v2, owner ruling 2026-09-21 / I-113), so re-spacing a line "
               "or renaming a local keeps the row; `line` is informational and refreshed by `preranker_census.py --rekey`; a row with no live site "
               "carries status orphan:<old status> (FIX_30, 2026-09-15)")

# ── I-113 (owner ruling 2026-09-21): the ledger key ───────────────────────────────────────────────
# "rows are keyed on the line's own text, so editing a line orphans its row and files a new one."
# The key stays (file, variety, expression) and stays capped at 40 characters — what changed is the
# NORMALISATION. v1 removed whitespace, parentheses and quotes only, so a mypy pass that renamed four
# locals in `health_check.py` moved four join keys and appended four orphans (I-104's +4, and the
# +2 → +6 lane H1 paid for on 2026-09-21). v2 additionally collapses every BOUND NAME to `~`:
#   kept  — Python keywords and soft keywords, the builtins, an attribute suffix (`x.species` → the
#           `species` half), and a name used as a callable (`read_json(...)`), which is the shape the
#           expression is ABOUT rather than a name the code happens to bind;
#   collapsed — everything else, i.e. the locals, parameters, imported aliases and module-level names
#           an edit renames.
# The cap stays at 40 DELIBERATELY: a longer window is more faithful but less stable, and stability is
# the whole point of the ruling. The scheme is applied to EVERY existing row, not only to rows filed
# from now on — `system_scripts/preranker_ledger_migrate.py` is that one-shot, idempotent migration.
KEY_SCHEME = "v2"
KEY_WIDTH = 40
# I-111 (2026-09-21): the marker a row carries when its variety's pattern was tightened past a site
# that is STILL in the file. Such a row is an orphan by construction, not an unpoliced decision, so
# `orphan_kinds` reads it under `cut` and counts it again under `descoped`.
DESCOPED_MARK = "ENDED→DESCOPED"
# I-110 (owner ruling 2026-09-22, "(c) pair first, then retire"): the marker a row carries when its
# FILE is no longer in the tree and no successor carries the site. The pairing pass (I-07 / packet Q8)
# runs FIRST and is given every chance to re-key the row; only what it could not pair retires. A retired
# row is KEPT in the TSV as history and is DROPPED from the frozen number and from step 17's orphan
# count — it is not an unpoliced decision, it is a decision about a module that no longer exists.
RETIRED_MARK = "retired: file gone"

def is_dash_state(p: str) -> bool:
    """The two dash-view-state files the hunter excludes (owner ruling 2026-09-17). They are launch state,
    not tracked, so their rows must read the same on a tree that has never launched (2026-11-05)."""
    return p == "system_scripts/poll_config.json" or (p.startswith("system_scripts/intent_") and p.endswith(".json"))
_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_KEEP_NAMES = frozenset(keyword.kwlist) | frozenset(getattr(keyword, "softkwlist", [])) | frozenset(dir(builtins))
# A STRING LITERAL is copied through verbatim: its words are text, never names the code binds, and an
# assert message or a reason string is most of what tells two sites in one file apart. The last arm
# matches a literal the hunter's own `expr[:80]` cut in half — both sides of the join cut it the same
# way, so the reading stays consistent.
_STRING = re.compile(r"""[rRbBuUfF]{0,3}(?:'''.*?'''|\"\"\".*?\"\"\"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|'[^']*$|\"[^\"]*$)""", re.S)

def _norm(t: str) -> str:
    """The normalised expression text of the ledger key (I-113, KEY_SCHEME v2).

    Whitespace-insensitive (all whitespace, parentheses and quotes removed, as v1 did) and
    BOUND-NAME-insensitive (every identifier the code binds is written `~`). Two lines that differ
    only in spacing or in the names they bind normalise to one string, so an edited line keeps its
    row instead of orphaning it and filing a new one. String literals pass through untouched."""
    out: List[str] = []
    pos = 0
    def collapse(seg: str) -> str:
        parts: List[str] = []; i = 0
        for m in _IDENT.finditer(seg):
            parts.append(seg[i:m.start()]); word = m.group(0); i = m.end()
            before = seg[:m.start()].rstrip()
            after = seg[m.end():].lstrip()
            if word in _KEEP_NAMES or before.endswith(".") or after.startswith("("):
                parts.append(word)    # a keyword, a builtin, an attribute suffix, or a callable name
            else:
                parts.append("~")     # a bound name — the thing an edit renames
        parts.append(seg[i:])
        return "".join(parts)
    for m in _STRING.finditer(t):
        out.append(collapse(t[pos:m.start()])); out.append(m.group(0)); pos = m.end()
    out.append(collapse(t[pos:]))
    return re.sub(r"[\s()'\"]", "", "".join(out))

def _ledger_key(r: Dict[str, str]) -> tuple: return (r["file"], r["variety"], _norm(r["expr"])[:KEY_WIDTH])
def read_ledger(ledger: Optional[Path] = None) -> List[Dict[str, str]]:
    """Every data row of the ledger (18 columns, tab-separated); leading `# ` comment lines are skipped."""
    import csv, io
    ledger = ledger or LEDGER
    text = "\n".join(l for l in ledger.read_text(encoding="utf-8").splitlines() if not l.startswith("#"))
    return list(csv.DictReader(io.StringIO(text), delimiter="\t"))
def hunter_join(hv: Dict[str, list], ledger: Optional[Path] = None) -> Dict[str, Any]:
    """Join the current-tree hunter hits to the ledger by (file, variety, expr) — never by line (owner close, 2026-09-06).
    statused = the row carries a status (KEPT / CUT / DEFERRED / ENDED / …); open = row exists, no status; not_in_ledger = no row.
    FIX_30: `orphan` = ledger keys with NO live hit (an honest count, informational — creep alone fails the gate); `ledger` = the file joined.

    I-113 (owner ruling 2026-09-21): the expression half of the key is `_norm`ALISED — whitespace- and
    bound-name-insensitive (KEY_SCHEME v2) — on BOTH sides of the join, so a line that was re-spaced or
    whose locals were renamed still joins to its own row instead of orphaning it and filing a new one.
    The scheme is published in the reading as `key_scheme` so a reader can tell which one produced it."""
    ledger = ledger or LEDGER
    idx: Dict[tuple, list] = {}
    for r in read_ledger(ledger):
        idx.setdefault(_ledger_key(r), []).append(r["status"])
    # I-110 (owner ruling 2026-09-22): a RETIRED key stays in the join — if its site ever came back it
    # would still find its own row rather than reading as creep — but it is DROPPED from the orphan
    # count and from the four-kind split. A key counts as retired only when EVERY row behind it is.
    retired_keys = {k for k, sts in idx.items() if sts and all(RETIRED_MARK in str(s) for s in sts)}
    out: Dict[str, Any] = {"hits": 0, "statused": 0, "open": 0, "not_in_ledger": 0, "new_sites": [], "orphan": 0,
                           "ledger": ledger.name, "key_scheme": KEY_SCHEME, "ledger_keys": len(idx),
                           "retired_keys": len(retired_keys)}
    live_keys = set()
    for variety, hits in hv.items():
        for f, line, expr in hits:
            out["hits"] += 1
            k = (f, variety, _norm(expr)[:KEY_WIDTH]); live_keys.add(k)
            sts = idx.get(k)
            if sts is None:
                out["not_in_ledger"] += 1; out["new_sites"].append(f"{f}:{line} [{variety.split(' ')[0]}] {expr[:80]}")
            elif any(sts): out["statused"] += 1
            else: out["open"] += 1
    out["orphan"] = sum(1 for k in idx if k not in live_keys and k not in retired_keys)
    # FIX_48 (owner Q8, 2026-09-17): how many of those orphans a `--rekey` WOULD pair right now, by the
    # same exactly-one-candidate rule (read-only — nothing is written here). Informational beside the
    # orphan count; creep alone still fails the gate.
    try:
        _rows = read_ledger(ledger); _live = _live_index(hv)
        out["pairable"] = len(_pairings(_rows, _live)[0])
        out["orphan_kinds"] = {k: v for k, v in orphan_kinds(_rows, _live).items() if k != "blind_rows"}
    except Exception as e:
        out["pairable"] = None; out["pairable_error"] = f"{type(e).__name__}: {e}"
    return out

def _live_index(hv: Dict[str, list]) -> Dict[tuple, List[int]]:
    """Every live hunter site this run as `{(file, variety, _norm(expr)[:KEY_WIDTH]): [line, …]}` (lines sorted)."""
    live: Dict[tuple, List[int]] = {}
    for variety, hits in hv.items():
        for f, line, expr in hits:
            live.setdefault((f, variety, _norm(expr)[:KEY_WIDTH]), []).append(int(line))
    for k in live: live[k].sort()
    return live

def _pairings(rows: List[Dict[str, str]], live: Dict[tuple, List[int]]) -> Tuple[Dict[int, tuple], List[str]]:
    """FIX_48 (owner Q8, 2026-09-17): pair each ledger row that has NO live site to the site it drifted to,
    but ONLY where exactly one candidate exists — the owner's qualifier, never a guess.

    Q8's reading: a drifted KEPT row is still in the code, just unpoliced (step 17 can no longer join it),
    so drift makes a row BLIND, not less important. Two drift shapes, each needing exactly one candidate:

      (a) THE EXPRESSION CHANGED (I-07's 255 rows) — group unmatched rows and UNCLAIMED live sites by
          `(file, variety)`; pair when the group holds exactly one of each.
      (b) THE FILE MOVED — group by `(variety, normalised expr)` and pair when exactly one unmatched row and
          exactly one unclaimed live site under a DIFFERENT file share it.

    (a) first: a same-file expression drift is a stronger signal than a same-expression move. A site is
    claimed once, so no two rows are ever paired to it. Everything ambiguous (2+ rows or 2+ sites in a
    group) is REPORTED as a candidate and left alone — FIX_30's "never auto-apply a rename otherwise".

    Returns `({row index: live key}, [candidate lines])`; the join key itself is untouched."""
    claimed = {k for k in live if any(_ledger_key(r) == k for r in rows)}
    unmatched = [i for i, r in enumerate(rows) if _ledger_key(r) not in live]
    paired: Dict[int, tuple] = {}
    notes: List[str] = []
    for shape, row_key, site_key in (
        ("expr", lambda r: (r["file"], r["variety"]), lambda k: (k[0], k[1])),
        ("file", lambda r: (r["variety"], _norm(r["expr"])[:KEY_WIDTH]), lambda k: (k[1], k[2])),
    ):
        rows_by: Dict[tuple, List[int]] = {}
        for i in unmatched:
            if i in paired: continue
            rows_by.setdefault(row_key(rows[i]), []).append(i)
        sites_by: Dict[tuple, List[tuple]] = {}
        for k in live:
            if k in claimed: continue
            sites_by.setdefault(site_key(k), []).append(k)
        for g, idxs in sorted(rows_by.items()):
            cands = sites_by.get(g, [])
            if shape == "file":
                cands = [k for k in cands if k[0] != rows[idxs[0]]["file"]] if len(idxs) == 1 else cands
            if not cands: continue
            if len(idxs) == 1 and len(cands) == 1:
                paired[idxs[0]] = cands[0]; claimed.add(cands[0])
            else:
                notes.append(f"pair candidate (not applied) [{shape}] {g}: {len(idxs)} row(s) <-> {len(cands)} site(s)")
    return paired, notes

def ledger_fields(ledger: Optional[Path] = None) -> List[str]:
    """The ledger's own column names, read off its header line (the `# ` note lines are skipped)."""
    ledger = ledger or LEDGER
    return next(l for l in ledger.read_text(encoding="utf-8").splitlines() if not l.startswith("#")).split("\t")

def ledger_text(rows: List[Dict[str, str]], fields: List[str]) -> str:
    """The exact bytes a ledger file carries for these rows: the join-key note, then the TSV."""
    import csv, io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
    w.writeheader(); w.writerows(rows)
    return LEDGER_NOTE + "\n" + buf.getvalue()

def rekey_rows(hv: Dict[str, list], rows: List[Dict[str, str]], skip: Optional[set] = None) -> Dict[str, Any]:
    """The re-key PASS itself, over rows already in memory — extracted from `rekey` so the one-shot
    migration (`preranker_ledger_migrate.py`, I-113) can run the same pass between its own stages
    instead of a second copy of it. Mutates `rows` in place and returns the counts.

    `skip` = row indices the caller has already decided (a descoped row, I-111): they are neither
    paired nor re-orphaned here."""
    skip = skip or set()
    live = _live_index(hv)
    by_var_expr: Dict[tuple, set] = {}
    for (f, variety, e) in live: by_var_expr.setdefault((variety, e), set()).add(f)
    pairable = [r for i, r in enumerate(rows) if i not in skip]
    paired_by_row, pair_candidates = _pairings(pairable, live)
    remap = [i for i in range(len(rows)) if i not in skip]
    paired_map = {remap[j]: k for j, k in paired_by_row.items()}
    taken: Dict[tuple, int] = {}
    relined = orphaned = kept_orphan = paired_expr = paired_file = 0
    renames: List[str] = []; applied: List[str] = []
    for i, r in enumerate(rows):
        if i in skip: continue
        k = _ledger_key(r)
        if k in live:
            j = taken.get(k, 0); lines = live[k]
            r["line"] = str(lines[min(j, len(lines) - 1)]); taken[k] = j + 1; relined += 1
        elif i in paired_map:
            nk = paired_map[i]
            was = str(r.get("status", ""))
            old_expr, old_file = r["expr"], r["file"]
            # every paired row KEEPS its status; an orphan: prefix filed by an earlier re-key is unwound
            if was.startswith("orphan:"): r["status"] = was[len("orphan:"):]
            r["line"] = str(live[nk][0])
            if nk[0] == r["file"]:
                r["expr"] = _expr_of(hv, nk); paired_expr += 1
                applied.append(f"[expr] {old_file} [{nk[1].split(' ')[0]}] '{old_expr[:50]}' -> '{r['expr'][:50]}' (status {r['status']})")
            else:
                r["file"] = nk[0]; paired_file += 1
                applied.append(f"[file] {old_file} -> {nk[0]} [{nk[1].split(' ')[0]}] '{old_expr[:50]}' (status {r['status']})")
        else:
            if str(r.get("status", "")).startswith("orphan:"): kept_orphan += 1
            else: r["status"] = f"orphan:{r.get('status', '')}"; orphaned += 1
            others = by_var_expr.get((k[1], k[2]), set()) - {k[0]}
            if others: renames.append(f"{k[0]} -> {sorted(others)} [{k[1].split(' ')[0]}] {r['expr'][:60]}")
    return {"rows": len(rows), "relined": relined, "orphaned": orphaned, "kept_orphan": kept_orphan,
            "live_keys": len(live), "rename_candidates": renames, "paired_expr": paired_expr,
            "paired_file": paired_file, "pair_candidates": pair_candidates, "pairings_applied": applied,
            "key_scheme": KEY_SCHEME}

def rekey(hv: Dict[str, list], ledger: Optional[Path] = None, date: Optional[str] = None) -> Dict[str, Any]:
    """FIX_30 (2026-09-15): refresh the informational `line` of every ledger row from the live hunt (join by
    expression, never by line); a row whose key has no live site gets `status = orphan:<old status>` (once —
    an already-orphan status is kept); a key that exists live under ANOTHER file with the same variety + expr
    is reported as a rename CANDIDATE, never applied. Writes `.archive/PRERANKER_HUNT_<date>.tsv` beside the
    old ledger (never over it) with the join-key note as its first line. Returns the counts.

    FIX_48 (owner Q8, 2026-09-17): between the exact-match pass and the orphan verdict a PAIRING pass runs —
    a row whose site drifted is re-keyed to it when exactly one candidate exists (see `_pairings`), and
    KEEPS ITS STATUS (an `orphan:` prefix from an earlier re-key is unwound, because the row is no longer
    blind). Only rows with no exact match and no pairing become orphans.

    I-113 (owner ruling 2026-09-21): every key on both sides of this pass is now KEY_SCHEME v2 — the
    normalised expression is whitespace- AND bound-name-insensitive — so a re-spaced line or a renamed
    local re-lines its own row here instead of orphaning it. The pass body lives in `rekey_rows`."""
    import datetime as _dt
    ledger = ledger or LEDGER
    date = date or _dt.date.today().isoformat()
    fields = ledger_fields(ledger)
    rows = read_ledger(ledger)
    counts = rekey_rows(hv, rows)
    out_path = ROOT / ".archive" / f"PRERANKER_HUNT_{date}.tsv"
    if out_path.exists(): raise FileExistsError(f"{out_path.name} exists — never overwritten")
    out_path.write_text(ledger_text(rows, fields), encoding="utf-8")
    counts.update({"source": ledger.name, "written": out_path.name})
    return counts

def orphan_kinds(rows: List[Dict[str, str]], live: Dict[tuple, List[int]]) -> Dict[str, Any]:
    """FIX_48 (owner Q8, 2026-09-17): the orphan count, split into the four kinds it actually holds.

    Q8: "does drift make them less important?" — no: a drifted KEPT row is still in the code, just
    unpoliced, so drift makes it BLIND, not less important. One number of 505 hides exactly that, so
    the number is split and only the last kind is anybody's problem:

      cut        the row's own status already says CUT / ENDED — the site was deliberately excised,
                 OR (I-111, 2026-09-21) the variety's pattern was tightened past a site that is still
                 in the file: a DESCOPED row. `descoped` counts that second group INSIDE `cut`, so the
                 four kinds still sum to `orphan_keys` and step 17's printed line still reconciles.
      file_gone  the row's file is no longer in the tree (a module archived or merged away).
      superseded a live site with the same (variety, expression) carries its OWN ledger row, so the
                 site IS policed; this row is a duplicate of a decision already filed elsewhere.
      blind      a KEPT / DEFERRED decision on a file that still exists, with no live site and no
                 pairing — THE number Q8 is about. Every one of these is listed, not just counted.

    Read-only; nothing is written and no status is changed."""
    live_keys = set(live)
    by_ve: Dict[tuple, set] = {}
    for (f, v, e) in live_keys: by_ve.setdefault((v, e), set()).add(f)
    out: Dict[str, Any] = {"cut": 0, "file_gone": 0, "superseded": 0, "blind": 0, "blind_rows": [],
                           "descoped": 0, "retired": 0}
    seen = set()
    for r in rows:
        k = _ledger_key(r)
        if k in live_keys or k in seen: continue
        status = str(r.get("status", "")).replace("orphan:", "")
        # I-110: a retired key is out of the orphan population altogether — it is counted beside the
        # four kinds, never inside them, so `cut + file_gone + superseded + blind == orphan_keys`
        # stays the arithmetic step 17's printed line reconciles with.
        if RETIRED_MARK in status: out["retired"] += 1; seen.add(k); continue
        seen.add(k)
        if DESCOPED_MARK in status: out["cut"] += 1; out["descoped"] += 1; continue
        if status.startswith(("CUT", "ENDED")): out["cut"] += 1; continue
        if not (ROOT / r["file"]).exists() and not is_dash_state(r["file"]): out["file_gone"] += 1; continue
        if by_ve.get((k[1], k[2])): out["superseded"] += 1; continue
        out["blind"] += 1
        out["blind_rows"].append(f"{r['file']}:{r.get('line', '?')} [{k[1]}] {r['expr'][:70]} — {status[:60]}")
    out["orphan_keys"] = len(seen) - out["retired"]      # I-110: retired keys are not orphans
    return out

def is_retired(r: Dict[str, str]) -> bool:
    """I-110: the row's file is gone, the pairing could not place it, and it has been retired."""
    return RETIRED_MARK in str(r.get("status", ""))

def successor_of(r: Dict[str, str], live: Dict[tuple, List[int]]) -> List[str]:
    """I-110: the live sites that are a SUCCESSOR of a row whose file is gone — the module MOVED and
    the site moved with it. Both halves are required: a live file with the SAME BASENAME, carrying the
    SAME (variety, normalised expression).

    The looser test — "any live site anywhere with the same (variety, normalised expr)" — is what
    `orphan_kinds` uses for `superseded`, and under KEY_SCHEME v2 it is far too loose to decide a
    retirement: a generic shape such as `V18 if not ~: return/continue` normalises identically in 65
    unrelated files, so almost any row would look as though it had a successor. Measured on this tree,
    that test spared 24 of 130 file-gone keys and every one of the 24 was a shape collision, not a move.
    The basename half is what makes the claim "this module is now over there" rather than "this shape
    also occurs over there"."""
    base = os.path.basename(r["file"])
    k = _ledger_key(r)
    return sorted(f for (f, variety, e) in live
                  if f != r["file"] and os.path.basename(f) == base and variety == k[1] and e == k[2])

def retirable(rows: List[Dict[str, str]], live: Dict[tuple, List[int]]) -> Tuple[Dict[tuple, List[int]], Dict[tuple, List[str]]]:
    """I-110, read-only: `({key: [row index, …]} to retire, {key: [successor, …]} kept back)`.

    A key retires when it has no live site, the row `orphan_kinds` DECIDES it on is not already CUT /
    ENDED / descoped (those are not `file gone` and the ruling does not touch them), its FILE is absent
    from the tree, and it has no successor. Keys already retired are returned as retirable again so the
    pass is a pure function of the tree — the writer leaves an already-marked row untouched.

    Retirement is WHOLE-KEY: every row behind a retiring key is marked. A key is one row to every reader
    of this file — `orphan_kinds` classifies on the first non-live row and `hunter_join` drops a key only
    when every row behind it is retired — so retiring some rows of a key and not others would leave the
    orphan count and the four-kind split disagreeing by exactly the half-retired keys."""
    live_keys = set(live)
    by_key: Dict[tuple, List[int]] = {}
    deciding: Dict[tuple, int] = {}
    for i, r in enumerate(rows):
        k = _ledger_key(r)
        by_key.setdefault(k, []).append(i)
        if k not in live_keys and k not in deciding: deciding[k] = i
    retire: Dict[tuple, List[int]] = {}
    kept: Dict[tuple, List[str]] = {}
    for k, i in deciding.items():
        r = rows[i]
        status = str(r.get("status", "")).replace("orphan:", "")
        if RETIRED_MARK in status: retire[k] = by_key[k]; continue     # already retired — idempotent
        if DESCOPED_MARK in status or status.startswith(("CUT", "ENDED")): continue
        if (ROOT / r["file"]).exists(): continue
        succ = successor_of(r, live)
        if succ: kept[k] = succ; continue
        retire[k] = by_key[k]
    return retire, kept

def _expr_of(hv: Dict[str, list], k: tuple) -> str:
    """The live site's expression text as the hunt recorded it (the ledger keeps the full text; the key
    is its normalised 40-char prefix)."""
    for f, line, expr in hv.get(k[1], []):
        if f == k[0] and _norm(expr)[:KEY_WIDTH] == k[2]: return expr
    return k[2]

def check(write_allowlist: bool = False, allow_extra: Dict[str, Dict[str, str]] | None = None) -> Dict[str, Any]:
    rows = census()
    allow: Dict[str, Any] = json.load(open(ALLOWLIST)) if ALLOWLIST.exists() else {"allowed": {}, "exempt": {}}
    if write_allowlist:
        for r in rows:
            k = key(r)
            if k in allow["allowed"] or k in allow["exempt"]: continue
            if allow_extra and k in allow_extra: allow["allowed"][k] = allow_extra[k]; continue
            if r["excised"]: allow["allowed"][k] = {"class": "B-floor", "why": "definedness floor left by cut 2 (was a magnitude gate)"}
        json.dump(allow, open(ALLOWLIST, "w"), indent=1, sort_keys=True)
    disallowed = [r for r in rows if key(r) not in allow["allowed"] and key(r) not in allow["exempt"]]
    exempt_hit = [r for r in rows if key(r) in allow["exempt"]]
    stale = [k for k in list(allow["allowed"]) + list(allow["exempt"]) if k not in {key(r) for r in rows}]
    return {"sites": len(rows), "allowed": len(rows) - len(disallowed) - len(exempt_hit), "exempt": exempt_hit,
            "disallowed": disallowed, "stale_allowlist_entries": stale, "passed": not disallowed,
            "scanned": SCAN, "not_scanned": NOT_SCANNED}

if __name__ == "__main__":
    if "--rekey" in sys.argv:
        import subprocess, tempfile
        tmp = Path(tempfile.mkdtemp()) / "hunt.json"
        subprocess.run([sys.executable, str(Path(__file__).resolve().parent / "preranker_hunt.py"), str(tmp)], cwd=str(ROOT), capture_output=True, text=True, timeout=120)
        hv = json.load(open(tmp)); r = rekey(hv)
        print(f"rekey: {r['source']} -> {r['written']}: {r['rows']} rows, {r['relined']} re-lined, "
              f"{r['paired_expr'] + r['paired_file']} PAIRED ({r['paired_expr']} expression drift, {r['paired_file']} file moved), "
              f"{r['orphaned']} newly orphan, {r['kept_orphan']} already orphan, {r['live_keys']} live keys")
        for a in r["pairings_applied"]: print(f"  paired: {a}")
        for c in r["pair_candidates"]: print(f"  {c}")
        # FIX_48: what the remaining orphans actually are — and the blind ones written out by name.
        ok = orphan_kinds(read_ledger(ROOT / ".archive" / r["written"]), _live_index(hv))
        print(f"  orphans after pairing: {ok['orphan_keys']} = cut {ok['cut']} · file gone {ok['file_gone']} · "
              f"superseded {ok['superseded']} · BLIND {ok['blind']} (a kept decision on a file that still exists)")
        blind_out = ROOT / ".archive" / f"PRERANKER_BLIND_{r['written'].replace('PRERANKER_HUNT_', '')}"
        blind_out.write_text("\n".join(ok["blind_rows"]) + "\n", encoding="utf-8")
        print(f"  blind rows listed -> {blind_out.name}")
        for c in r["rename_candidates"][:10]: print(f"  rename candidate (not applied): {c}")
        sys.exit(0)
    res = check(write_allowlist="--write-allowlist" in sys.argv)
    # ── the KEY_SCHEME proof rides THIS gate (tr2_L1, 2026-09-21) ────────────────────────────────
    # No gate is added and none is re-scoped: the `census` gate of `replay_gates.sh` already runs this
    # file and already reads the ledger, so the proof of the owner's I-113 ruling — and of I-07's
    # pairing rule, I-111's tightened V93 and I-100's nested blocks — is asserted here rather than in
    # an eighteenth script. `--no-key-proof` skips it for a bare census reading.
    key_ok = True
    if "--no-key-proof" not in sys.argv:
        try:
            import importlib.util as _ilu
            _s: Any = _ilu.spec_from_file_location("preranker_ledger_migrate", Path(__file__).resolve().parent / "preranker_ledger_migrate.py")
            _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)  # type: ignore[union-attr]
            key_ok, _lines = _m.key_scheme_proof()
            print("\n".join(_lines))
            print(f"key-scheme proof: {'PASS' if key_ok else 'FAIL'}")
        except Exception as _e:
            key_ok = False
            print(f"key-scheme proof: FAIL — {type(_e).__name__}: {_e}")
    print(f"pre-ranker census: {res['sites']} numeric sites scanned; allowed {res['allowed']}; exempt {len(res['exempt'])}; DISALLOWED {len(res['disallowed'])}; stale allowlist entries {len(res['stale_allowlist_entries'])}")
    for r in res["disallowed"]: print(f"  DISALLOWED {r['file']}:{r['line']} {r['func']} [{r['kind']}] {r['expr']}")
    for r in res["exempt"]: print(f"  exempt     {r['file']}:{r['line']} {r['func']} [{r['kind']}] {r['expr']}")
    sys.exit(0 if (res["passed"] and key_ok) else 1)
