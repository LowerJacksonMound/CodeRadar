"""Rule-disposition table check — health-check step 18 (calibrator part A2 + A5, owner decisions 2026-09-06).

Dispositions are DATA: system_scripts/rule_dispositions.json holds one row per rule family (deciding | context) with
the evidence that earned it. The ranker (knowledge_base.VerdictRanker) READS the table; nothing is inferred.

This script (a) takes an AST census of every rule id the EMITTER modules can publish, (b) fails the gate when an
emitted id has no row, or a strict (proof) family is marked context, (c) reports every deciding family that has no
evidence yet (FAIL once disposition_close.json says so), (d) re-runs the archived planted targets in-process and
fails when a plant of a frozen fully-caught family is no longer caught in substance, (e) reports stale rows, and
(f) surfaces the strict layer's precision from the newest calibration dir every run.

usage:  disposition_check.py            # the check (exit 0/1)
        disposition_check.py --seed     # write the migration seed table ONCE (refuses to overwrite)
        disposition_check.py --json OUT # also dump the check result
        disposition_check.py --no-recall
"""
from __future__ import annotations
import ast, collections, glob, json, os, re, sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
TABLE = HERE / "rule_dispositions.json"
CLOSE = HERE / "disposition_close.json"
KB = ROOT / "no_aivalidator/cheatsheets/cheatsheet_intelligence/knowledge_base.py"
STRICT = ROOT / "no_aivalidator/noai_validator/strict_checks.py"
HARDENING = ROOT / "RULES_HARDENING_2026-09-05.md"
CAL_GLOB = str(ROOT / ".archive/health/calibration_*")

# Every module that can publish a rule id (the census is a FLOOR: a literal id in these files needs a row).
EMITTERS = ["no_aivalidator/detection/*.py", "no_aivalidator/noai_validator/*.py", "utils/code_analysis/*.py"]
ID_RE = re.compile(r"\b((?:NAI|RCA|HR|IGR|FRN|SEC|GRF|SYM)-[A-Z0-9]{2,5}|MEASURED-NOTHING)\b")
WILDCARDS = {"SIG-*"}
DISPOSITIONS = ("deciding", "context")
EVIDENCE_KINDS = ("proof", "ruling", "calibrated", "none (pre-calibration)")


# ── (a) the census ───────────────────────────────────────────────────────────────────────────────────
def _docstring_ids(tree: ast.AST) -> set:
    s = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body \
                and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant) \
                and isinstance(n.body[0].value.value, str):  # type: ignore[attr-defined]  # FIX_54 ast-pos
            s.add(id(n.body[0].value))
    return s


def emitted_ids() -> Dict[str, Dict[str, List[int]]]:
    """id → {relpath: [lines]} for every string literal (docstrings skipped) in the emitter modules;
    'SIG-*' when an f-string part ends with 'SIG-' (the signature scanner builds its ids)."""
    out: Dict[str, Dict[str, List[int]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    for pat in EMITTERS:
        for f in sorted(glob.glob(str(ROOT / pat))):
            if "_removed_rankings" in f:
                continue
            rel = os.path.relpath(f, ROOT)
            try:
                tree = ast.parse(open(f, encoding="utf-8").read())
            except SyntaxError as e:
                out[f"PARSE-ERROR:{rel}"][rel].append(e.lineno or 0); continue
            docs = _docstring_ids(tree)
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
                    for m in ID_RE.findall(n.value):
                        out[m][rel].append(n.lineno)
                if isinstance(n, ast.JoinedStr):
                    for part in n.values:
                        if isinstance(part, ast.Constant) and isinstance(part.value, str) and part.value.endswith("SIG-"):
                            out["SIG-*"][rel].append(n.lineno)
    return {k: dict(v) for k, v in out.items()}


def strict_ids() -> List[str]:
    """STRICT_CHECKS ids by AST (never by import: importing strict_checks pulls the validator and the ranker)."""
    tree = ast.parse(STRICT.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "STRICT_CHECKS" for t in n.targets) and isinstance(n.value, ast.List):
            return [e.elts[0].value for e in n.value.elts if isinstance(e, ast.Tuple) and e.elts and isinstance(e.elts[0], ast.Constant)]  # type: ignore[misc]  # FIX_54 ast-pos
    raise RuntimeError("STRICT_CHECKS not found in strict_checks.py")


def seed_context_ids() -> List[str]:
    """The migration seed frozenset in knowledge_base.py, by AST."""
    tree = ast.parse(KB.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        tgt = None
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name): tgt, val = n.target.id, n.value
        elif isinstance(n, ast.Assign) and n.targets and isinstance(n.targets[0], ast.Name): tgt, val = n.targets[0].id, n.value
        if tgt == "_SEED_CONTEXT_2026_09_06" and isinstance(val, ast.Call) and val.args and isinstance(val.args[0], ast.Set):
            return [e.value for e in val.args[0].elts if isinstance(e, ast.Constant)]  # type: ignore[misc]  # FIX_54 ast-pos
    raise RuntimeError("_SEED_CONTEXT_2026_09_06 not found in knowledge_base.py")


def s5_classes() -> Dict[str, str]:
    """rule id → class from RULES_HARDENING §S.5 (A = magnitude threshold, B = structural precondition)."""
    out: Dict[str, str] = {}
    if not HARDENING.exists():
        _j = HERE / "rule_classes_s5.json"   # the §S.5 table exported 2026-09-07 (the doc was trashed by ruling)
        return json.load(open(_j, encoding="utf-8")) if _j.exists() else out
    in_table = False
    for line in HARDENING.read_text(encoding="utf-8").splitlines():
        if line.startswith("## S.5"): in_table = True; continue
        if in_table and line.startswith("## "): break
        if in_table and line.startswith("| NAI-"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 5:
                cls = cells[4].replace("*", "").strip()
                for rid in re.findall(r"NAI-\d{3}[A-Z]?", cells[0]):
                    out.setdefault(rid, cls)
                # 'NAI-058/059' shorthand
                m = re.match(r"(NAI-\d{3})/(\d{3})", cells[0])
                if m: out.setdefault(f"NAI-{m.group(2)}", cls)
    return out


# ── bench aggregation (precision side) ───────────────────────────────────────────────────────────────
def newest_calibration_dir() -> Path | None:
    dirs = sorted(Path(p) for p in glob.glob(CAL_GLOB) if Path(p).is_dir())
    return dirs[-1] if dirs else None


def precision_from_dir(cal: Path) -> Dict[str, Dict[str, Any]]:
    """Per id: libs hit, rows first/anywhere/alone/in_tests — re-aggregated from the per-library dumps
    (v1 rows_detail or v2 rows). Recall dumps (by_file) and non-library files are skipped."""
    fam: Dict[str, Dict[str, Any]] = collections.defaultdict(lambda: {"libs_hit": set(), "rows": {"first": 0, "anywhere": 0, "alone": 0, "in_tests": 0}})
    libs = 0
    for f in sorted(cal.glob("*.json")):
        try: d = json.load(open(f, encoding="utf-8"))
        except Exception: continue
        rows = d.get("rows_detail") if isinstance(d, dict) else None
        if rows is None and isinstance(d, dict) and "rows" in d and "lib" in d: rows = d["rows"]
        if rows is None: continue
        libs += 1; lib = d.get("lib", f.stem)
        for x in rows:
            if x.get("passed", True): continue
            dec = x.get("deciding_anywhere") if "deciding_anywhere" in x else [i for i in x.get("all_ids", [])]
            for i in dec:
                r = fam[i]; r["libs_hit"].add(lib); r["rows"]["anywhere"] += 1
                if len(dec) == 1: r["rows"]["alone"] += 1
                if x.get("test") or x.get("species") == "test": r["rows"]["in_tests"] += 1
            first = x.get("first")
            if first: fam[first]["rows"]["first"] += 1
    return {i: {"libs_hit": sorted(r["libs_hit"]), "libs_total": libs, "rows": r["rows"]} for i, r in fam.items()}


# ── (seed) the migration table ───────────────────────────────────────────────────────────────────────
RENUMBERED = {  # A1 (2026-09-06): new id → what it was; detection rules keep their numbers (owner decision 6)
    "NAI-215": {"was": "NAI-100", "emitter": "noai_validator/validator.py validate_module", "meaning": "module import count (warning fact)", "collided_with": "detection NAI-100 param not in return path"},
    "NAI-216": {"was": "NAI-101", "emitter": "noai_validator/validator.py validate_module", "meaning": "global mutable state (warning fact)", "collided_with": "detection NAI-101 magic-number return"},
    "NAI-217": {"was": "NAI-210", "emitter": "noai_validator/validator.py validate_module", "meaning": "hallucinated import — from X import Y, Y not defined in X (plan item 4)", "collided_with": "detection NAI-210 threading.Thread in a sync function"},
    "NAI-218": {"was": "NAI-104", "emitter": "noai_validator/validator.py validate_lambda", "meaning": "identity lambda", "collided_with": "detection NAI-104 name implies op not found"},
    "NAI-219": {"was": "NAI-105", "emitter": "noai_validator/validator.py validate_lambda", "meaning": "constant lambda", "collided_with": "detection NAI-105 passthrough"},
    "NAI-220": {"was": "NAI-106", "emitter": "noai_validator/validator.py validate_comprehension", "meaning": "nested comprehension depth (magnitude)", "collided_with": "detection NAI-106 unnormalized string compare", "inherited": "context"},
    "NAI-221": {"was": "NAI-111", "emitter": "noai_validator/validator.py _analyze_comment_density_for_range", "meaning": "comment density (magnitude)", "collided_with": "detection NAI-111 nonexistent library method", "inherited": "context"},
    "NAI-222": {"was": "NAI-112", "emitter": "noai_validator/validator.py _check_type_hint_issues", "meaning": "type-hint ratio (magnitude)", "collided_with": "detection NAI-112 hallucinated package", "inherited": "context"},
    "NAI-223": {"was": "NAI-113", "emitter": "noai_validator/validator.py _find_unused_definitions", "meaning": "unused module-level definition", "collided_with": "detection NAI-113 comment/code ratio", "inherited": "context"},
    "NAI-224": {"was": "NAI-114", "emitter": "noai_validator/validator.py _check_call_graph_issues", "meaning": "call-graph cycle", "collided_with": "detection NAI-114 hyper-descriptive naming", "inherited": "context"},
    "NAI-225": {"was": "NAI-110", "emitter": "noai_validator/validator.py _check_cross_function", "meaning": "call to an undefined function name (warning fact)", "collided_with": "detection NAI-110 cross-language method call"},
    "NAI-226": {"was": "NAI-102", "emitter": "noai_validator/file_validation.py", "meaning": "nested function depth (warning fact)", "collided_with": "detection NAI-102 docstring/code mismatch"},
    "NAI-227": {"was": "NAI-103", "emitter": "noai_validator/file_validation.py", "meaning": "lambda count (warning fact)", "collided_with": "detection NAI-103 inverted boolean"},
    "NAI-228": {"was": "NAI-090", "emitter": "noai_validator/utils.py check_duplicate_functions", "meaning": "duplicate function structure (fingerprint)", "collided_with": "detection NAI-090 single-letter variables", "inherited": "context"},
    "NAI-229": {"was": "NAI-091", "emitter": "noai_validator/utils.py check_suspicious_symmetry_229", "meaning": "repetitive statement structure", "collided_with": "detection NAI-091 in-place parameter mutation", "wired": "FIX_17 2026-09-10: file_validation → per-function observation with magnitude"},
    "NAI-230": {"was": "NAI-092", "emitter": "noai_validator/utils.py check_normalized_duplicates_230", "meaning": "similar function structure (normalized)", "collided_with": "detection NAI-092 shell=True", "wired": "FIX_17 2026-09-10: file_validation → per-function observation with magnitude"},
    "NAI-231": {"was": "NAI-091", "emitter": "utils/code_analysis/duplicate.py check_duplicate_functions_strict", "meaning": "duplicate functions by strict fingerprint", "collided_with": "detection NAI-091 in-place parameter mutation"},
    "NAI-232": {"was": "NAI-092", "emitter": "utils/code_analysis/symmetry.py _check_if_else_symmetry", "meaning": "if/else branches identical", "collided_with": "detection NAI-092 shell=True"},
    "NAI-233": {"was": "NAI-093", "emitter": "utils/code_analysis/symmetry.py _check_if_elif_symmetry", "meaning": "all if/elif branches identical", "collided_with": "detection NAI-093 unsafe deserialization"},
    "NAI-234": {"was": "NAI-094", "emitter": "utils/code_analysis/symmetry.py _check_loop_symmetry", "meaning": "loops with identical bodies", "collided_with": "detection NAI-094 sys.path / os.environ mutation"},
    "NAI-235": {"was": "NAI-096", "emitter": "utils/code_analysis/symmetry.py _check_comprehension_symmetry", "meaning": "comprehensions with identical structure", "collided_with": "detection NAI-096 assert as validation"},
}
KEPT_SHARED = {  # same MEANING at two scopes — one family, one row (renumbering would split a meaning, not a collision)
    "NAI-094": "sys.path / os.environ mutation: detection (function scope) + validator.validate_module (module scope, plan item 4)",
    "NAI-071": "mutable default argument: detection + validator._mutable_default_observations (strict-bypass helper); one rewriter",
}
DORMANT = {  # emitted by no live path — listed so the census cannot mistake them for missing rows, and nobody assumes coverage
    "NAI-012": "utils/code_analysis/duplicate.check_duplicate_functions — health-check step 1 smoke only; the live path is noai utils (NAI-228)",
    "NAI-013": "utils/code_analysis/symmetry.check_arithmetic_symmetry — file_validation publishes it as SYM-002",
    "NAI-019S": "deleted from STRICT_CHECKS at cut 2 (2026-09-05); comments only",
}   # NAI-229 / NAI-230 left this list on FIX_17 (2026-09-10): wired into file_validation as per-function observations
# FIX_17 (2026-09-10, owner ruling): per-(rule, context) rows — the schema the check enforces (mirrors knowledge_base)
CONTEXT_FACTS = ("magnitude", "species", "body_statements", "variant", "role")   # body_statements: owner 2026-10-07 (NAI-230 one-line helper tables)
CONTEXT_OPS = (">=", ">", "<=", "<", "==", "!=", "in", "not_in")
# FIX_49 / FIX_50 (2026-09-17, owner Q9 / Q10): the `path_hacks` section's facts. `role` is the fact the
# route already measures for a file (entry_point_wrapper.py records the entry script; the circuit daemon
# reads it every frame) — the same list engine_utils.PATH_HACK_CONTEXT_FACTS enforces at read time.
PATH_HACK_CONTEXT_FACTS = ("role", "species", "magnitude")
FILE_LEVEL = {"RCA-001", "NAI-208", "NAI-214", "NAI-IM01", "NAI-226", "NAI-227", "NAI-231", "NAI-232", "NAI-233", "NAI-234", "NAI-235",
              "GRF-001", "GRF-002", "GRF-003", "SYM-002", "IGR-001", "FRN-001", "NAI-228", "NAI-223", "NAI-224", "NAI-222", "NAI-225"}
MODULE_LEVEL = {"NAI-215", "NAI-216", "NAI-217", "NAI-209", "NAI-211"}


def _class_of(rid: str, strict: set, s5: Dict[str, str]) -> str:
    if rid in strict: return "strict"
    if rid.startswith("HR-0"): return "hard_requirement"
    if rid in ("HR-NAME", "MEASURED-NOTHING"): return "obs-context"
    if rid.startswith("SIG-") or rid.startswith("SEC-"): return "regex"
    if rid == "NAI-213": return "class"
    if rid in MODULE_LEVEL: return "module"
    if rid in FILE_LEVEL: return "file-level"
    if rid in ("NAI-218", "NAI-219", "NAI-220", "NAI-221"): return "A"
    if rid in s5: return s5[rid]
    return "unclassified (no S.5 row)"


def seed(force: bool = False) -> Path:
    if TABLE.exists() and not force:
        raise SystemExit(f"refusing to overwrite {TABLE} — the table is data; edit rows by ruling, never by re-seeding")
    em = emitted_ids(); strict = set(strict_ids()); ctx = set(seed_context_ids()); s5 = s5_classes()
    cal = newest_calibration_dir(); prec = precision_from_dir(cal) if cal else {}
    split_old = {v["was"] for v in RENUMBERED.values()}
    today = date.today().isoformat()
    fams: Dict[str, Dict[str, Any]] = {}
    ids = set(em) | ctx | WILDCARDS | {"MEASURED-NOTHING", "HR-NAME"}
    for rid in sorted(i for i in ids if not i.startswith("PARSE-ERROR")):
        is_ctx = rid in ctx or rid in WILDCARDS or rid in ("MEASURED-NOTHING", "HR-NAME")
        cls = _class_of(rid, strict, s5)
        row: Dict[str, Any] = {
            "disposition": "context" if is_ctx else "deciding", "class": cls,
            "by": "owner" if is_ctx else "migration", "dated": today,
            "emitted_by": {f: ls for f, ls in em.get(rid, {}).items()},
            "evidence": {"kind": "proof" if rid in strict else ("ruling" if is_ctx else "none (pre-calibration)"),
                         "precision": (prec.get(rid) if (rid in prec and rid not in split_old and rid not in RENUMBERED) else
                                       {"libs_hit": [], "libs_total": 0, "rows": {"first": 0, "anywhere": 0, "alone": 0, "in_tests": 0},
                                        **({"note": "pre-split bench cannot attribute a shared id; re-dump at B2"} if (rid in split_old or rid in RENUMBERED) else {})}),
                         "plants": {"planted": 0, "caught_by_id": 0, "caught_in_substance": 0, "held_out": 0},
                         "sample_labels": [], "sources": ([str(cal.relative_to(ROOT))] if cal else [])},
            "note": "",
        }
        if is_ctx:
            row["evidence"]["sources"] = ["EXCISION_LIST_2026-09-05.md"] + (["RULES_HARDENING_2026-09-05.md §S.7"] if rid == "HR-NAME" else [])
            row["note"] = ("regex signature hit: a regex is not a proof (cut 2)" if rid in WILDCARDS else
                           "a rule that measured nothing says so (cut 3 batch 4)" if rid == "MEASURED-NOTHING" else
                           "name/body disagreement is an observation (cut 2b §S.7)" if rid == "HR-NAME" else
                           "inherited from the shared id at the A1 split — calibrate separately" if rid in RENUMBERED and RENUMBERED[rid].get("inherited") else
                           "cut 2: magnitude = context, never a verdict alone")
            if rid in split_old and rid not in RENUMBERED:
                row["note"] = f"context by the cut-2 ruling on the SHARED id; the detection meaning kept it at the A1 split — calibrate"
        elif rid in strict:
            row["by"] = "owner"; row["note"] = "strict proof layer (strict_checks.STRICT_CHECKS) — never context; calibrated only in the strict slice with the owner's note"
        if rid in RENUMBERED: row["note"] = (row["note"] + "; " if row["note"] else "") + f"A1 renumber: was {RENUMBERED[rid]['was']} ({RENUMBERED[rid]['meaning']})"
        if rid in DORMANT: row["note"] = (row["note"] + "; " if row["note"] else "") + f"DORMANT: {DORMANT[rid]}"
        fams[rid] = row
    table = {
        "_generated": {"by": "system_scripts/disposition_check.py --seed", "dated": today, "emitter_modules": EMITTERS,
                       "sources": ["knowledge_base._SEED_CONTEXT_2026_09_06", "strict_checks.STRICT_CHECKS", "RULES_HARDENING_2026-09-05.md §S.5",
                                   str(cal.relative_to(ROOT)) if cal else "no calibration dir"]},
        "_policy": ("disposition ∈ {deciding, context} only; an id with NO row is deciding and step 18 FAILS; strict rows are never context; "
                    "evidence.kind == 'calibrated' requires libs_hit, plants, 5 sample_labels and sources. Knobs: a family's disposition, an "
                    "instrument-gap fix, a body-shape refinement that is never a magnitude (owner 2026-09-06). FIX_17 (owner ruling 2026-09-10): "
                    "a disposition is per (rule, CONTEXT) — a row keeps one default and may carry `contexts` [{when: {fact: condition}, disposition}] "
                    "over the measured facts magnitude | species (ops >= > <= < == != in not_in); the first row whose conditions all hold wins, else "
                    "the default; strict families carry no contexts; the number is data, never a code literal."),
        "_dormant": DORMANT, "_renumbered": {"dated": "2026-09-06", "map": RENUMBERED, "kept_shared": KEPT_SHARED},
        "families": fams,
    }
    # FIX_49 / FIX_50 (2026-09-17): the `path_hacks` section is HAND-WRITTEN data (owner rulings Q9 / Q10),
    # not seeded from the emitters — a re-seed must carry it forward, never drop it.
    if TABLE.exists():
        try:
            _prev = json.load(open(TABLE, encoding="utf-8")).get("path_hacks")
            if _prev:
                table["path_hacks"] = _prev
        except Exception:
            pass
    TABLE.write_text(json.dumps(table, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return TABLE


# ── (b)-(f) the check ────────────────────────────────────────────────────────────────────────────────
def check(recall: bool = True) -> Dict[str, Any]:
    res: Dict[str, Any] = {"table": str(TABLE.relative_to(ROOT)), "passed": True, "fails": []}
    if not TABLE.exists():
        res["passed"] = False; res["fails"].append(f"table missing: {TABLE} (run disposition_check.py --seed)"); return res
    table = json.load(open(TABLE, encoding="utf-8")); fams = table.get("families") or {}
    dormant = set(table.get("_dormant") or {})
    em = emitted_ids(); strict = set(strict_ids())
    close = json.load(open(CLOSE, encoding="utf-8")) if CLOSE.exists() else {}
    # row sanity
    bad = [(rid, r.get("disposition")) for rid, r in fams.items() if r.get("disposition") not in DISPOSITIONS]
    if bad: res["passed"] = False; res["fails"].append(f"rows with a non-disposition: {bad[:5]}")
    badk = [(rid, r.get("evidence", {}).get("kind")) for rid, r in fams.items() if r.get("evidence", {}).get("kind") not in EVIDENCE_KINDS]
    if badk: res["passed"] = False; res["fails"].append(f"rows with an unknown evidence kind: {badk[:5]}")
    for rid, r in fams.items():
        if r.get("evidence", {}).get("kind") == "calibrated":
            ev = r["evidence"]
            if not (ev.get("precision", {}).get("libs_hit") and ev.get("plants", {}).get("planted") and len(ev.get("sample_labels") or []) >= 5 and ev.get("sources")):
                res["passed"] = False; res["fails"].append(f"{rid}: evidence.kind calibrated without libs_hit / plants / 5 labels / sources")
    # FIX_17 (2026-09-10, owner ruling): per-(rule, context) rows — every context row names only measured facts,
    # known ops and a disposition; a strict family carries none (a proof is never context).
    n_ctx = 0
    for rid, r in fams.items():
        ctxs = r.get("contexts") or []
        if not isinstance(ctxs, list):
            res["passed"] = False; res["fails"].append(f"{rid}: contexts is not a list"); continue
        if ctxs and (r.get("class") == "strict" or rid in strict):
            res["passed"] = False; res["fails"].append(f"{rid}: a strict family cannot carry contexts")
        for i, c in enumerate(ctxs):
            when = (c or {}).get("when") or {}
            unknown = sorted(k for k in when if k not in CONTEXT_FACTS)
            bad_ops = any(isinstance(v, dict) and any(op not in CONTEXT_OPS for op in v) for v in when.values())
            if not when or unknown or bad_ops or (c or {}).get("disposition") not in DISPOSITIONS:
                res["passed"] = False
                res["fails"].append(f"{rid}: context row {i} invalid (facts {CONTEXT_FACTS}, ops {CONTEXT_OPS}, dispositions {DISPOSITIONS}): {c}")
            n_ctx += 1
    res["context_rows"] = n_ctx
    # (g) FIX_49 / FIX_50 (2026-09-17, owner Q9 / Q10): the `path_hacks` section — one row per hack TYPE,
    # same vocabulary as a family (deciding | context), and the same per-(type, CONTEXT) rows over the
    # DISCRETE facts the route already measures. A bad row is a broken table and fails the step.
    ph = table.get("path_hacks") or {}
    ph_rows = {t: r for t, r in ph.items() if not t.startswith("_")}
    ph_ctx = 0
    ph_report: List[str] = []
    for htype, r in sorted(ph_rows.items()):
        d = (r or {}).get("disposition")
        if d not in DISPOSITIONS:
            res["passed"] = False
            res["fails"].append(f"path_hacks/{htype}: disposition {d!r} is not one of {DISPOSITIONS}")
        ctxs = (r or {}).get("contexts") or []
        if not isinstance(ctxs, list):
            res["passed"] = False
            res["fails"].append(f"path_hacks/{htype}: contexts is not a list")
            ctxs = []
        for i, c in enumerate(ctxs):
            when = (c or {}).get("when") or {}
            unknown = sorted(k for k in when if k not in PATH_HACK_CONTEXT_FACTS)
            bad_ops = any(isinstance(v, dict) and any(op not in CONTEXT_OPS for op in v) for v in when.values())
            if not when or unknown or bad_ops or (c or {}).get("disposition") not in DISPOSITIONS:
                res["passed"] = False
                res["fails"].append(f"path_hacks/{htype}: context row {i} invalid "
                                    f"(facts {PATH_HACK_CONTEXT_FACTS}, ops {CONTEXT_OPS}, dispositions {DISPOSITIONS}): {c}")
            ph_ctx += 1
        ph_report.append(f"{htype}: {d}" + (f" + {len(ctxs)} context row(s) [" +
                                            ", ".join(f"{sorted(((c or {}).get('when') or {}))} -> {(c or {}).get('disposition')}"
                                                      for c in ctxs) + "]" if ctxs else ""))
    res["path_hack_rows"] = len(ph_rows)
    res["path_hack_context_rows"] = ph_ctx
    res["path_hack_report"] = ph_report
    # (a) missing rows
    emitted = {i for i in em if not i.startswith("PARSE-ERROR")}
    parse_errors = [i for i in em if i.startswith("PARSE-ERROR")]
    missing = sorted(i for i in emitted if i not in fams and i not in dormant)
    res.update({"emitted": len(emitted), "rows": len(fams), "missing_rows": missing, "parse_errors": parse_errors})
    if missing: res["passed"] = False; res["fails"].append(f"{len(missing)} emitted id(s) with no row: {missing[:10]}")
    if parse_errors: res["passed"] = False; res["fails"].append(f"parse errors: {parse_errors}")
    # (b) strict ∩ context
    overlap = sorted(i for i in strict if fams.get(i, {}).get("disposition") == "context")
    missing_strict = sorted(i for i in strict if i not in fams)
    res["strict_context_overlap"] = overlap
    if overlap: res["passed"] = False; res["fails"].append(f"strict families marked context: {overlap}")
    if missing_strict: res["passed"] = False; res["fails"].append(f"strict families with no row: {missing_strict}")
    # (c) deciding rows without evidence
    unev = sorted(rid for rid, r in fams.items() if r.get("disposition") == "deciding" and r.get("class") != "strict"
                  and r.get("evidence", {}).get("kind") == "none (pre-calibration)" and rid not in dormant
                  # owner 2026-10-07: a blind-tree measurement (scoring/calibrate.py) is evidence too
                  and (r.get("measured_evidence") or {}).get("status") != "measured")
    mode = (close.get("mode") or {}).get("unevidenced_deciding", "REPORT")
    res["deciding_unevidenced"] = unev; res["unevidenced_mode"] = mode
    if unev and mode == "FAIL": res["passed"] = False; res["fails"].append(f"{len(unev)} deciding families without evidence (mode FAIL)")
    # (e) stale rows
    stale = sorted(rid for rid in fams if rid not in emitted and rid not in dormant and rid not in WILDCARDS)
    res["stale_rows"] = stale
    # (d) recall guard
    if recall:
        try:
            import importlib.util as _ilu
            spec: Any = _ilu.spec_from_file_location("verify_manifest", HERE / "verify_manifest.py")
            vm = _ilu.module_from_spec(spec); spec.loader.exec_module(vm)  # type: ignore[union-attr]
            per: list = []
            fam_tot: dict = collections.defaultdict(lambda: {"planted": 0, "caught_in_substance": 0, "caught_by_id": 0})
            ctrl = [0, 0]; absent = []
            # I-105 (owner ruling 2026-09-21): the guard is SIGHTED, not merely audible. It walks EVERY
            # archived run directory rather than only the manifests it can glob, and says out loud which
            # ones contribute nothing — a run that writes no manifest raises nothing, so the silence used
            # to read like a measurement. A run that DOES carry a manifest the guard cannot read fails the
            # check: it claims plants and the guard cannot see them.
            # E1 (2026-10-01): two roots. Retention (launch.sh, keep 10 + 5, 14 days) sweeps `.archive/runs`
            # and relocates a planted manifest to the PERMANENT evidence root
            # `.archive/gate_evidence/recall/<run>/manifest.json`; the guard walks BOTH. A run name present
            # in both is ONE target and the gate_evidence copy is the one read. The I-105 sighted reporting
            # (`not_guarded`, over `.archive/runs`) is unchanged.
            evidence_root = ROOT / ".archive/gate_evidence/recall"
            ev_dirs = sorted(d for d in evidence_root.glob("*") if d.is_dir()) if evidence_root.is_dir() else []
            run_dirs = sorted(d for d in (ROOT / ".archive/runs").glob("*") if d.is_dir())
            not_guarded: list = []; ev_not_guarded: list = []
            targets: dict = {}   # run name -> (manifest, source)
            # one loop over both roots (gate_evidence first, so its copy is the one kept for a name in both)
            walk = [(d, "gate_evidence", ev_not_guarded, f"gate_evidence/recall/{d.name}") for d in ev_dirs] + \
                   [(d, "runs", not_guarded, f"run {d.name}") for d in run_dirs]
            for d, src, skipped, label in walk:
                mf = d / "manifest.json"
                if not mf.is_file():
                    skipped.append({"run": d.name, "why": "no manifest.json"}); continue
                try:
                    m = json.load(open(mf, encoding="utf-8"))
                except Exception as e:
                    skipped.append({"run": d.name, "why": f"manifest unreadable ({type(e).__name__})"})
                    res["passed"] = False
                    res["fails"].append(f"NOT GUARDED: {label} carries a manifest the recall guard cannot read: {e}")
                    continue
                if not m.get("planted_findings"):
                    skipped.append({"run": d.name, "why": "no `planted_findings`"}); continue
                if d.name in targets:
                    continue   # one target — the gate_evidence copy is read
                targets[d.name] = (m, src)
            queue: list = []   # (run name, manifest, source, target path) in run-name order — the order the totals are summed in
            for name in sorted(targets):
                m, src = targets[name]
                t = vm.resolve_target(m.get("target", ""))   # retired targets may live under a recall-targets folder
                if not t.exists(): absent.append(name); continue
                queue.append((name, m, src, t))
            # Every target runs in its own spawned worker (vm.run_targets, one process per core less two); the
            # rows come back here and are joined in run-name order exactly as the sequential loop joined them.
            # A worker failure raises out of run_targets into the except below — reported, never a 0.
            got = vm.run_targets([t for (_, _, _, t) in queue])
            for (name, m, src, t), g in zip(queue, got):
                if g.get("output"):
                    print(g["output"], end="")
                r = vm.check(m, g["rows"]); s = r["summary"]
                per.append({"target": name, "source": src, **s})
                ctrl[0] += s["controls_clean"]; ctrl[1] += s["controls"]
                for f, v in r["families"].items():
                    for k in ("planted", "caught_in_substance", "caught_by_id"): fam_tot[f][k] += v[k]
            n_ev = sum(1 for p in per if p["source"] == "gate_evidence"); n_runs = len(per) - n_ev
            print(f"GUARDED: {len(per)} archived target(s) / {sum(p['plants'] for p in per)} plant(s) read by step 18's "
                  f"recall guard — {n_ev} from gate_evidence, {n_runs} from runs — out of {len(ev_dirs)} gate_evidence "
                  f"dir(s) and {len(run_dirs)} archived run dir(s)")
            if ev_not_guarded:
                print(f"NOT GUARDED: {len(ev_not_guarded)} of {len(ev_dirs)} gate_evidence/recall dir(s) contribute no plant "
                      f"(every name is in `recall.evidence_not_guarded`)")
            if not_guarded:
                no_mf = [x["run"] for x in not_guarded if x["why"] == "no manifest.json"]
                no_pl = [x["run"] for x in not_guarded if x["why"].startswith("no `planted")]
                print(f"NOT GUARDED: {len(not_guarded)} of {len(run_dirs)} archived run dir(s) contribute no plant — "
                      f"{len(no_mf)} with no manifest.json, {len(no_pl)} carrying no `planted_findings`, "
                      f"{len(not_guarded) - len(no_mf) - len(no_pl)} unreadable. A run whose plants are meant to be "
                      f"guarded writes them into .archive/runs/<run>/manifest.json (I-105); every name is in "
                      f"`recall.not_guarded`")
            if absent:
                print(f"NOT GUARDED: {len(absent)} archived run dir(s) name a target that is not on disk")
            res["recall"] = {"targets": len(per), "plants": sum(p["plants"] for p in per), "caught_in_substance": sum(p["caught_in_substance"] for p in per),
                             "caught_by_id": sum(p["caught_by_id"] for p in per), "controls_clean": ctrl[0], "controls": ctrl[1],
                             "families": dict(fam_tot), "absent_targets": absent, "not_measured": not per,
                             "run_dirs": len(run_dirs), "not_guarded": not_guarded,
                             "from_gate_evidence": n_ev, "from_runs": n_runs, "evidence_dirs": len(ev_dirs),
                             "evidence_not_guarded": ev_not_guarded}
            frozen = (close.get("recall") or {}).get("fully_caught_families") or []
            lost = [f for f in frozen if f in fam_tot and fam_tot[f]["caught_in_substance"] < fam_tot[f]["planted"]]
            res["recall"]["lost_families"] = lost
            if lost: res["passed"] = False; res["fails"].append(f"plants LOST in frozen fully-caught families: {lost}")
            if ctrl[1] and ctrl[0] < ctrl[1] and (close.get("recall") or {}).get("controls_clean_required", True):
                res["passed"] = False; res["fails"].append(f"controls dirty: {ctrl[0]}/{ctrl[1]} clean")
        except Exception as e:
            res["recall"] = {"error": f"{type(e).__name__}: {e}", "not_measured": True}
            res["passed"] = False; res["fails"].append(f"recall guard failed to run: {e}")
    else:
        res["recall"] = {"not_measured": True, "why": "--no-recall"}
    # (f) strict precision surfaced every run
    cal = newest_calibration_dir()
    if cal:
        prec = precision_from_dir(cal)
        res["strict_precision"] = {"dir": str(cal.relative_to(ROOT)), **{i: prec[i] for i in sorted(strict) if i in prec}}
    return res


def _print(res: Dict[str, Any]) -> None:
    print(f"disposition table: {res.get('rows', 0)} rows for {res.get('emitted', 0)} emitted ids — missing {len(res.get('missing_rows', []))}, "
          f"strict∩context {len(res.get('strict_context_overlap', []))}, stale {len(res.get('stale_rows', []))}, "
          f"deciding without evidence {len(res.get('deciding_unevidenced', []))} ({res.get('unevidenced_mode', '?')}), "
          f"context rows {res.get('context_rows', 0)} (FIX_17: per-(rule, context))")
    # FIX_49 / FIX_50: the path-hack section, printed every run so a disposition change is visible in the report
    print(f"  path-hack dispositions: {res.get('path_hack_rows', 0)} rows, "
          f"{res.get('path_hack_context_rows', 0)} context row(s) (FIX_49 Q9 / FIX_50 Q10: per-(type, context))")
    for line in res.get("path_hack_report", []):
        print(f"    {line}")
    rc = res.get("recall") or {}
    if rc.get("not_measured"):
        print("  recall guard: STRUCK (owner 2026-09-08) — the planted-set regression guard went with the old calibration; the measure is the tester's confirmations on real repos")
    else:
        print(f"  recall guard: {rc['targets']} archived targets ({rc.get('from_gate_evidence', 0)} from gate_evidence, {rc.get('from_runs', 0)} from runs) "
              f"/ {rc['plants']} plants — {rc['caught_in_substance']} caught in substance, "
              f"{rc['caught_by_id']} by id; controls {rc['controls_clean']}/{rc['controls']} clean; lost families {rc.get('lost_families') or 0}")
        for f, v in sorted(rc.get("families", {}).items()):
            if v["caught_in_substance"] < v["planted"] or v["caught_by_id"] < v["planted"]:
                print(f"    {f}: planted {v['planted']} in_substance {v['caught_in_substance']} by_id {v['caught_by_id']}")
    sp = res.get("strict_precision") or {}
    if sp:
        print(f"  strict precision ({sp.get('dir')}): " + "; ".join(f"{i} {len(v['libs_hit'])}/{v['libs_total']} libs, {v['rows']['anywhere']} rows ({v['rows']['alone']} alone)" for i, v in sp.items() if i != "dir"))
    for f in res.get("fails", []): print(f"  ✗ {f}")
    for i in res.get("missing_rows", [])[:20]: print(f"    missing row: {i}")
    if res.get("stale_rows"): print(f"  ⚠ stale rows (no emitter): {res['stale_rows'][:12]}")


if __name__ == "__main__":
    if "--seed" in sys.argv:
        p = seed(force="--force" in sys.argv); print(f"seeded {p}")
    res = check(recall="--no-recall" not in sys.argv)
    _print(res)
    if "--json" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--json") + 1]); out.parent.mkdir(parents=True, exist_ok=True)
        json.dump(res, open(out, "w", encoding="utf-8"), indent=1, sort_keys=True, default=list); print(f"written {out}")
    sys.exit(0 if res["passed"] else 1)
