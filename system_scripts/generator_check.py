#!/usr/bin/env python3
"""generator_check.py — health-check step 19 (NEW IMPLEMENTATION item 4, 2026-09-08).

Every rule id the disposition table marks `deciding` must have exactly one registry row in
no_aivalidator/repair_generators (rewriter | no_fix_by_design | unbuilt) — a missing row FAILS
the gate. Counts by kind are printed every run (unbuilt LOUDLY, like step 17's hunter). Then
every rewriter runs against its planted counterfeit system_scripts/generator_plants/<rule_id>.py:

    fires      the rule's own detector observes <rule_id> on the plant's function (else the plant
               is not a counterfeit of this rule)
    rewrites   after, what = fn(function source): after parses, after != source, what non-empty
    meaning    the rule's detector re-run on the rewritten function no longer observes <rule_id>
               — "what the rule's meaning calls for" is the rule going quiet on the rewrite
    equivalent when PLANT["call"] is true: the before-module and the after-module (the plant with
               (FIX_43 (b): a finite-set rewriter's every variant is proven; PLANT["expect"] = {variant: result}
                names the result a variant changes by design, else each variant must equal the before result)
               its function span replaced by the rewrite) are exec'd and PLANT["function"] is
               called with PLANT["args"] in both; the results must be equal (import-order
               equivalence for NAI-008, value equivalence for the rest)

    docstring  R1 (2026-09-30): when the plant's function has a docstring, the rewrite keeps it as the
               function's first statement (a line inserted above it makes __doc__ None)
    round trip R1: every call above runs on a FRESH deep copy of PLANT["args"] (the before call used to
               mutate the args the after call then received), so apply → parse → exec → call is proven
               on the plant's own input types, dicts included
    extra      R1: every generator_plants/<rule_id>__<case>.py is proven the same way; PLANT["expect_decline"]
               = True names a case the rewriter must DECLINE (no candidate, or only a shape-only variant that
               is never applied) — e.g. a parameter whose type the code does not show
    sweep      R1: every rewriter's main plant is re-proven with a docstring planted as its function's first
               statement; a rule that stops firing or a rewriter that declines there is n/a, any other
               failure fails the row. (The 2026-09-30 NAI-021S rows passed step 19 because its only plant had
               a list default and no docstring; they broke a dict parameter and displaced a docstring.)

usage: generator_check.py [--json OUT]        exit 0 = PASS
"""
from __future__ import annotations

import ast
import asyncio
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TABLE = ROOT / "system_scripts" / "rule_dispositions.json"
PLANTS = ROOT / "system_scripts" / "generator_plants"
PENDING = ROOT / "system_scripts" / "solution_kinds_pending.json"   # FIX_41: the ids still allowed to be no_fix_by_design


def _plant_module(rule_id: str) -> tuple[str, dict]:
    """`rule_id` is a plant file stem: the rule's main plant (`NAI-021S`) or an extra case (`NAI-021S__dict_docstring`)."""
    src = (PLANTS / f"{rule_id}.py").read_text(encoding="utf-8")
    ns: Dict[str, Any] = {}
    tree = ast.parse(src)
    plant = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PLANT" for t in n.targets))
    exec(compile(ast.Module(body=[plant], type_ignores=[]), f"{rule_id}.py", "exec"), ns)
    return src, ns["PLANT"]


async def _tags(func_src: str, name: str, rid: str = "") -> List[str]:
    """The tags the detector observes on the def named `name` inside func_src (a module).
    A SEC-* id is emitted by the validator's line-regex scan (check_vuln_patterns), not by the
    AST detector — for those the tags are the scan's codes on the module (set 4b-05)."""
    if rid.startswith("SEC-"):
        from no_aivalidator.noai_validator.validator import NoAIMathValidator
        return [code for code, _sev, _msg, _line in NoAIMathValidator().check_vuln_patterns(func_src)]
    if rid.endswith("S"):
        # FIX_43 (b) run 123: a strict id (NAI-nnnS) is emitted by strict_checks.STRICT_CHECKS on the def, not by the
        # AST detector — for those the tags are the predicates that hold on the plant's def.
        from no_aivalidator.noai_validator.strict_checks import STRICT_CHECKS
        tree = ast.parse(func_src)
        node = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
        return [sid for sid, pred, _desc in STRICT_CHECKS if pred(node)]  # type: ignore[arg-type]  # FIX_54 ast-pos
    from no_aivalidator.detection.base import AIFakeDetector
    from no_aivalidator.noai_validator.extractor import MetricsExtractor
    tree = ast.parse(func_src)
    node = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    ext = MetricsExtractor(node, class_context=False, source=func_src)  # type: ignore[arg-type]  # FIX_54 ast-pos
    det = AIFakeDetector(metrics=ext.metrics, func_node=node)  # type: ignore[arg-type]  # FIX_54 ast-pos
    obs = await det.run_all_checks()
    # FIX_43 (b) run 123: a "measured nothing" context row (`context: True`) is the detector's silence, not a
    # firing — the validator never emits it as a rule id, so it is not a tag here either (NAI-007 / NAI-017 write one).
    return [str(o.get("tag", "")) for o in obs if isinstance(o, dict) and not o.get("context")]


def _call(module_src: str, function: str, args: list, label: str) -> Any:
    ns: Dict[str, Any] = {"__name__": f"plant_{label}"}
    exec(compile(module_src, f"<{label}>", "exec"), ns)
    return ns[function](*args)


async def _check_alias(g, canon, done: Dict[str, Any], ff_cls) -> Dict[str, Any]:
    """Set 4b-13 (2026-09-10): a plant-less rewriter row whose fn IS another row's plant-proven function
    is an alias (NAI-122 → NAI-070's bare_except_fix). Accepted when the canonical row's plant passes
    AND the alias id is absent from that plant's before-tags — so "never emitted" is measured at
    every launch. Any other plant-less rewriter keeps the "no plant" failure."""
    rid = g.rule_id
    res: Dict[str, Any] = {"rule_id": rid, "role": g.role, "ok": False, "alias_of": canon.rule_id}
    if canon.rule_id not in done:
        done[canon.rule_id] = await _check_rewriter(canon, ff_cls, done)
    cres = done[canon.rule_id]
    if not cres["ok"]:
        res["error"] = f"alias of {canon.rule_id}, whose plant fails: {cres.get('error')}"
        return res
    src, plant = _plant_module(canon.rule_id)
    before_tags = await _tags(src, plant["function"], rid)
    res["fires"] = rid in before_tags
    if res["fires"]:
        res["error"] = f"alias id {rid} is emitted on {canon.rule_id}'s plant (tags {before_tags}) — not an alias, needs its own plant"
        return res
    res["meaning_quiet"] = cres.get("meaning_quiet")
    res["equivalent"] = cres.get("equivalent")
    res["what"] = f"alias of {canon.rule_id} — proven by {canon.rule_id}'s plant; {rid} absent from its tags"
    res["ok"] = True
    return res


async def _check_rewriter(g, ff_cls, done: Dict[str, Any] | None = None) -> Dict[str, Any]:
    rid = g.rule_id
    res: Dict[str, Any] = {"rule_id": rid, "role": g.role, "ok": False}
    if not (PLANTS / f"{rid}.py").exists():
        from no_aivalidator.repair_generators import rewriters
        canon = next((h for h in rewriters() if h.rule_id != rid and h.fn is g.fn and (PLANTS / f"{h.rule_id}.py").exists()), None)
        if canon is not None:
            return await _check_alias(g, canon, done if done is not None else {}, ff_cls)
        res["error"] = f"no plant: system_scripts/generator_plants/{rid}.py"
        return res
    src, plant = _plant_module(rid)
    res.update(await _prove(g, ff_cls, src, plant))
    if not res.get("ok"):
        return res
    res["ok"] = False
    extras: List[str] = []
    # R1: the docstring sweep — the main plant again, with a docstring as its function's first statement
    doc_src = _with_docstring(src, plant["function"])
    if doc_src is not None:
        sw = await _prove(g, ff_cls, doc_src, plant, sweep=True)
        res["docstring_sweep"] = sw.get("na") or ("ok" if sw.get("ok") else sw.get("error"))
        if not sw.get("ok"):
            res["error"] = f"docstring sweep: {sw.get('error')}"
            return res
        extras.append("+docstring " + ("n/a" if sw.get("na") else "✓"))
    # R1: the extra cases generator_plants/<rid>__<case>.py
    for extra in sorted(PLANTS.glob(f"{rid}__*.py")):
        e_src, e_plant = _plant_module(extra.stem)
        er = await _prove(g, ff_cls, e_src, e_plant)
        res.setdefault("extra", {})[extra.stem] = "ok" if er.get("ok") else er.get("error")
        if not er.get("ok"):
            res["error"] = f"{extra.name}: {er.get('error')}"
            return res
        extras.append(f"+{extra.stem.split('__', 1)[1]} " + ("declined ✓" if e_plant.get("expect_decline") else "✓"))
    if extras:
        res["what"] = f"{res['what']} [{' · '.join(extras)}]"
    res["ok"] = True
    return res


def _fn(tree: ast.AST, name: str):
    return next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)


def _with_docstring(src: str, name: str) -> str | None:
    """R1: the plant with a docstring planted as `name`'s first statement — None when it already has one
    or its body shares a row with the signature (nowhere a docstring can go without reshaping the def)."""
    fn = _fn(ast.parse(src), name)
    if fn is None or ast.get_docstring(fn) is not None:
        return None
    lead = next(iter(fn.body))
    lines = src.splitlines()
    if lead.lineno <= fn.lineno or lines[lead.lineno - 1][: lead.col_offset].strip():
        return None
    ind = lines[lead.lineno - 1][: lead.col_offset]
    lines.insert(lead.lineno - 1, f'{ind}"""Planted by step 19\'s docstring sweep: must stay the first statement."""')
    return "\n".join(lines)


async def _prove(g, ff_cls, src: str, plant: Dict[str, Any], sweep: bool = False) -> Dict[str, Any]:
    """One plant module through the whole check (fires, rewrites, docstring, meaning, round trip).
    `sweep`: the docstring sweep — a rule that stops firing or a rewriter that declines is n/a (`na`), not a fail."""
    from no_aivalidator.BUILDER_DAEMON import SHAPE_ONLY_VARIANTS
    rid = g.rule_id
    res: Dict[str, Any] = {"ok": False}
    ff = ff_cls(src)
    name = plant["function"]
    def_line = next(n.lineno for n in ast.walk(ast.parse(src)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    before, start, end = ff.function_source(name, def_line)
    before_tags = await _tags(src, name, rid)
    res["fires"] = rid in before_tags
    if not res["fires"]:
        if sweep:
            res.update(ok=True, na="n/a (the rule does not fire with a docstring)")
            return res
        res["error"] = f"plant does not fire {rid} (tags {before_tags})"
        return res
    from no_aivalidator.repair_generators import candidates_of
    offered = candidates_of(g, before)   # FIX_43 (b): one candidate, or every candidate of a finite set
    res["variants"] = len(offered)
    applyable = [o for o in offered if (o[0].split(":", 1)[1] if ":" in o[0] else "") not in SHAPE_ONLY_VARIANTS]
    if plant.get("expect_decline"):
        # R1: a case the rewriter must decline — no applyable candidate; the before module still runs
        if applyable:
            res["error"] = (f"expected a decline, but the rewriter offered {[o[0] for o in applyable]} "
                            f"({applyable[0][2][:120]})")
            return res
        if plant.get("call"):
            try:
                res["result"] = repr(_call(src, name, copy.deepcopy(list(plant.get("args") or [])), "before"))[:60]
            except Exception as e:
                res["error"] = f"the decline plant's own call raised {type(e).__name__}: {e}"
                return res
        res["what"] = "declined: " + (offered[0][2][:160] if offered else "no candidate")
        res["ok"] = True
        return res
    if not offered:
        if sweep:
            res.update(ok=True, na="n/a (the rewriter declines with a docstring present)")
            return res
        res["error"] = "rewriter declined its own plant"
        return res
    lines = src.splitlines()
    expect = plant.get("expect") or {}   # finite set: {variant: expected call result} when the variants differ by design
    before_doc = ast.get_docstring(_fn(ast.parse(src), name), clean=False)
    whats: list = []
    for cand_role, after, what in offered:
        variant = cand_role.split(":", 1)[1] if ":" in cand_role else ""
        tag = f"[{variant}] " if variant else ""
        try:
            ast.parse(after)
        except SyntaxError as e:
            res["error"] = f"{tag}rewrite does not parse: {e}"
            return res
        if after.strip() == before.strip() or not what.strip():
            res["error"] = f"{tag}rewrite identical to the source or what_changed empty"
            return res
        after_module = "\n".join(lines[:start - 1] + after.splitlines() + lines[end:])
        try:
            after_fn = _fn(ast.parse(after_module), name)
        except SyntaxError as e:
            res["error"] = f"{tag}the module with the rewrite applied does not parse: {e}"
            return res
        # R1: the docstring stays the function's first statement
        if before_doc is not None and variant not in SHAPE_ONLY_VARIANTS and \
                (after_fn is None or ast.get_docstring(after_fn, clean=False) != before_doc):
            res["error"] = f"{tag}the rewrite displaces `{name}`'s docstring (it is no longer the first statement)"
            return res
        after_tags = await _tags(after_module, name, rid)
        res["meaning_quiet"] = rid not in after_tags
        res["after_tags"] = after_tags
        if not res["meaning_quiet"]:
            res["error"] = f"{tag}{rid} still fires on the rewrite"
            return res
        if plant.get("call"):
            try:
                # R1: each call gets its OWN deep copy of the args — the before call may mutate them
                b = _call(src, name, copy.deepcopy(list(plant.get("args") or [])), "before")
                a = _call(after_module, name, copy.deepcopy(list(plant.get("args") or [])), "after")
            except Exception as e:
                res["error"] = f"{tag}equivalence call raised {type(e).__name__}: {e}"
                return res
            want = expect[variant] if variant in expect else b
            res["equivalent"] = a == want
            res["result"] = repr(b)[:60]
            if not res["equivalent"]:
                res["error"] = f"{tag}before → {b!r}, after → {a!r}" + (f" (expected {want!r})" if variant in expect else "")
                return res
        else:
            res["equivalent"] = None
        whats.append(f"{tag}{what}")
    res["what"] = " | ".join(whats)
    res["ok"] = True
    return res


async def acheck() -> Dict[str, Any]:
    """The check as a coroutine (the health check already runs inside an event loop)."""
    from no_aivalidator.repair_generators import REGISTRY, KINDS, counts_by_kind, rewriters, prescribed_rows
    from no_aivalidator.BUILDER_DAEMON import _FileFacts
    table = json.load(open(TABLE, encoding="utf-8"))
    fams = table.get("families") or {}
    def _decides(r: Dict[str, Any]) -> bool:
        # FIX_17 (2026-09-10): a family decides when its default OR any of its context rows is deciding
        return r.get("disposition") == "deciding" or any((c or {}).get("disposition") == "deciding" for c in (r.get("contexts") or []))
    deciding = sorted(rid for rid, r in fams.items() if _decides(r))
    missing = [rid for rid in deciding if rid not in REGISTRY]
    extra = sorted(rid for rid in REGISTRY if rid not in fams or not _decides(fams[rid]))
    # FIX_41 (owner ruling 2026-09-15): every deciding id carries a SOLUTION KIND — rewriter or prescribed.
    # A no_fix_by_design row is permitted only for an id listed in solution_kinds_pending.json:
    #   finite_set_fix43      the 26 "which one's right" rows (≥ 2 candidates) → FIX_43 multi-candidate rewriters
    #   prescription_pending  ids whose prescription is being written in another lane (emptied at the merge)
    # Any other no_fix_by_design id, and any unbuilt id, FAILS the gate.
    pending = json.load(open(PENDING, encoding="utf-8")) if PENDING.exists() else {}
    finite_set = set(pending.get("finite_set_fix43") or [])
    lane_pending = set(pending.get("prescription_pending") or [])
    no_fix_ids = sorted(g.rule_id for g in REGISTRY.values() if g.kind == "no_fix_by_design")
    unlisted_no_fix = [rid for rid in no_fix_ids if rid not in finite_set and rid not in lane_pending]
    unbuilt_ids = sorted(g.rule_id for g in REGISTRY.values() if g.kind == "unbuilt")
    res: Dict[str, Any] = {
        "deciding": len(deciding), "rows": len(REGISTRY), "missing_rows": missing, "rows_not_deciding": extra,
        "by_kind": counts_by_kind(),
        "unbuilt_ids": unbuilt_ids,
        "no_fix_by_design": {g.rule_id: g.reason for g in REGISTRY.values() if g.kind == "no_fix_by_design"},
        "no_fix_pending_finite_set": sorted(r for r in no_fix_ids if r in finite_set),
        "no_fix_pending_lane": sorted(r for r in no_fix_ids if r in lane_pending and r not in finite_set),
        "no_fix_unlisted": unlisted_no_fix,
        "prescribed": {g.rule_id: g.reason for g in prescribed_rows()},
        "rewriters": {g.rule_id: g.role for g in rewriters()},
        "plants": [], "fails": [],
    }
    if missing:
        res["fails"].append(f"{len(missing)} deciding id(s) with no registry row: {missing[:10]}")
    if extra:
        res["fails"].append(f"{len(extra)} registry row(s) whose id is not a deciding id: {extra[:10]}")
    if unlisted_no_fix:
        res["fails"].append(f"{len(unlisted_no_fix)} no_fix_by_design id(s) not listed as pending (FIX_41: every deciding id "
                            f"carries a solution kind): {unlisted_no_fix[:10]}")
    if unbuilt_ids:
        res["fails"].append(f"{len(unbuilt_ids)} unbuilt id(s) (FIX_41: every deciding id carries a solution kind): {unbuilt_ids[:10]}")
    listed_but_not_no_fix = sorted(r for r in (finite_set | lane_pending) if r in REGISTRY and REGISTRY[r].kind != "no_fix_by_design")
    if listed_but_not_no_fix:
        res["fails"].append(f"{len(listed_but_not_no_fix)} pending id(s) whose row is no longer no_fix_by_design — drop them from "
                            f"solution_kinds_pending.json: {listed_but_not_no_fix[:10]}")

    done: Dict[str, Any] = {}   # set 4b-13: an alias row re-uses its canonical row's result
    for g in rewriters():
        r = done.get(g.rule_id) or await _check_rewriter(g, _FileFacts, done)
        done[g.rule_id] = r
        res["plants"].append(r)
        if not r["ok"]:
            res["fails"].append(f"{g.rule_id} ({g.role}): {r.get('error')}")
    res["passed"] = not res["fails"]
    return res


def check() -> Dict[str, Any]:
    """Standalone entry (no running loop)."""
    return asyncio.run(acheck())


def main() -> int:
    import logging
    logging.getLogger().setLevel(logging.WARNING)  # the detector's per-function INFO lines are noise here
    res = check()
    k = res["by_kind"]
    print(f"generator registry: {res['rows']} rows for {res['deciding']} deciding ids — "
          f"rewriter {k['rewriter']}, prescribed {k.get('prescribed', 0)}, "
          f"no_fix (pending FIX_43 finite set) {len(res['no_fix_pending_finite_set'])}, "
          f"no_fix (pending another lane) {len(res['no_fix_pending_lane'])}, "
          f"no_fix UNLISTED {len(res['no_fix_unlisted'])}, UNBUILT {k['unbuilt']}")
    for p in res["plants"]:
        if p.get("alias_of"):   # set 4b-13: a plant-less alias row, proven by its canonical row's plant
            flag = "≡" if p["ok"] else "✗"
            print(f"  {flag} {p['rule_id']} {p['role']}: {p.get('what', p.get('error', ''))[:120]}")
            continue
        flag = "✓" if p["ok"] else "✗"
        print(f"  {flag} {p['rule_id']} {p['role']}: fires={p.get('fires')} meaning_quiet={p.get('meaning_quiet')} "
              f"equivalent={p.get('equivalent')} — {p.get('what', p.get('error', ''))[:110]}")
    for f in res["fails"]:
        print(f"  ✗ {f}")
    if "--json" in sys.argv:
        Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps(res, indent=1, default=str))
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
