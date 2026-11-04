"""runtime_probes.py — scan-time execution of the target's own functions, step 2 (M-151, 2026-10-08; owner: run the
target's functions at scan time as a counterfeit detector — security deferred).

ONE run of the target's suite (test_blame.run_traced, in a temp copy, with runtime_plugin/cr_test_trace.py) records,
for every source function a test reaches, real argument sets; after the suite, runtime_plugin/cr_probe_plan.py executes
the plan built here against the real imported package. Both NAI-254 (failing tests) and the probes below come from
that one run.

  twins (NAI-251 variant `runtime_diverge`) — same name and parameters in two non-test files (the split-brain shape,
  found without the static shape gate, which misses twins written differently: Decimal vs round, a loop vs sum).
  Both are called on every recorded argument set of either plus nominal inputs; the first input on which they answer
  differently is the observation. The copy a PASSING test calls directly is the one the suite pins; when exactly one
  twin is so pinned the other is the suspect (deciding); otherwise both are observed as context.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple  # noqa: F401

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from .test_blame import _PLUGIN_DIR, _SKIP_DIRS, observations as _blame_observations, run_traced

_GUI = re.compile(r"^\s*(?:import|from)\s+(tkinter|pygame|turtle|curses|pyglet|arcade)\b", re.M)
_ENTRY_TIMEOUT_S = 120


def headless_command(root: Path) -> Optional[List[str]]:
    """The target's own headless run: a README `python -m <module> … --headless …` line (the Pong format asks for
    one), else `python -m <pkg>` for a package with a __main__.py when nothing in the tree imports a GUI toolkit.
    None when neither exists — a GUI app is never launched."""
    readme = next((p for p in root.iterdir() if p.name.lower().startswith("readme")), None) if root.is_dir() else None
    if readme is not None:
        for m in re.finditer(r"python3?\s+-m\s+([A-Za-z_][\w.]*)([^\n`]*?--headless[^\n`]*)", readme.read_text(errors="replace")):
            return [m.group(1), *m.group(2).split()]
    if any(_GUI.search(p.read_text(errors="replace")) for p in root.rglob("*.py")
           if not (set(p.relative_to(root).parts) & _SKIP_DIRS)):
        return None
    if readme is not None:   # no GUI anywhere: the README's own run line is safe to execute as-is
        m = re.search(r"python3?\s+-m\s+([A-Za-z_][\w.]*)([^\n`]*)", readme.read_text(errors="replace"))
        if m:
            return [m.group(1), *m.group(2).split()]
    mains = sorted(p.parent for p in root.glob("*/__main__.py"))
    return [mains[0].name] if mains else None


def run_entry(root: Path, plan: Dict[str, Any]) -> Dict[str, Any]:
    """Run the headless entry point once in a temp copy under the call recorder, then the plan. Probe results or {}."""
    cmd = headless_command(root)
    if not cmd:
        return {}
    with tempfile.TemporaryDirectory(prefix="cr_entry_") as tmp:
        copy = Path(tmp) / root.name
        shutil.copytree(root, copy, ignore=shutil.ignore_patterns(*_SKIP_DIRS, "*.pyc"))
        (Path(tmp) / "plan.json").write_text(json.dumps(plan, default=repr), encoding="utf-8")
        out = Path(tmp) / "probes.json"
        env = {**os.environ, "CR_TRACE_ROOT": str(copy), "CR_PROBE_PLAN": str(Path(tmp) / "plan.json"),
               "CR_PROBE_OUT": str(out), "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": os.pathsep.join([str(_PLUGIN_DIR), str(copy), os.environ.get("PYTHONPATH", "")])}
        try:
            subprocess.run([sys.executable, str(_PLUGIN_DIR / "cr_run_entry.py"), *cmd], cwd=str(copy), env=env,
                           capture_output=True, text=True, timeout=_ENTRY_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return {}
        return json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}


def _module(rel: str) -> str:
    parts = list(Path(rel).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_test(rel: str) -> bool:
    p = Path(rel)
    return p.name.startswith("test_") or p.name == "conftest.py" or "tests" in p.parts or p.name.endswith("_test.py")


def _defs(trees_by_rel: Dict[str, ast.AST]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rel, tree in trees_by_rel.items():
        if _is_test(rel):
            continue

        def walk(body: List[ast.stmt], qual: str, in_class: bool) -> None:
            for n in body:
                if isinstance(n, ast.ClassDef):
                    walk(n.body, f"{qual}{n.name}.", True)
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("__"):
                    deco = {d.id for d in n.decorator_list if isinstance(d, ast.Name)}
                    params = [a.arg for a in n.args.args]
                    static = "staticmethod" in deco
                    method = in_class and not static
                    if method and params and params[0] in ("self", "cls"):
                        params = params[1:]
                    out.append({"file": rel, "first": min([n.lineno] + [d.lineno for d in n.decorator_list]),
                                "line": n.lineno, "name": n.name, "qual": f"{qual}{n.name}", "module": _module(rel),
                                "method": in_class, "static": static or "classmethod" in deco, "params": params,
                                "node": n})
        walk(getattr(tree, "body", []), "", False)
    return out


def _differing_lines(mine: ast.AST, other: ast.AST) -> List[int]:
    """Lines of `mine`'s body whose statement text (after normalising the parameter names) has no match in `other`."""
    def stmts(fn: ast.AST) -> List[Tuple[int, str]]:
        names = [a.arg for a in fn.args.args]   # type: ignore[attr-defined]
        out: List[Tuple[int, str]] = []
        body = fn.body[1:] if ast.get_docstring(fn) else fn.body   # type: ignore[attr-defined]
        for st in (n for b in body for n in ast.walk(b) if isinstance(n, ast.stmt)):
            if isinstance(st, (ast.If, ast.For, ast.While, ast.With, ast.Try)):   # the header only, not the body
                head = getattr(st, "test", None) or getattr(st, "iter", None)
                text = f"{type(st).__name__}:{ast.unparse(head) if head is not None else ''}"
            else:
                text = ast.unparse(st)
            for i, n in enumerate(names):
                text = text.replace(n, f"_p{i}")
            out.append((st.lineno, " ".join(text.split())))
        return out
    theirs = {t for _, t in stmts(other)}
    return sorted({ln for ln, t in stmts(mine) if t not in theirs})


def plan(trees_by_rel: Dict[str, ast.AST]) -> Dict[str, Any]:
    by_key: Dict[Tuple[str, Tuple[str, ...]], List[Dict[str, Any]]] = defaultdict(list)
    for d in _defs(trees_by_rel):
        if d["params"]:
            by_key[(d["name"], tuple(d["params"]))].append(d)
    twins: List[Dict[str, Any]] = []
    for group in by_key.values():
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                if a["file"] == b["file"]:
                    continue
                grid: List[List[Any]] = []
                try:
                    from .split_brain import _grid
                    grid = _grid(a["node"], a["params"])
                except Exception:
                    grid = []
                twins.append({"a": {k: v for k, v in a.items() if k != "node"},
                              "b": {k: v for k, v in b.items() if k != "node"}, "grid": grid})
    # claims (M-153): docstring/name claims (claim_forms) on functions the self-contained sandbox cannot run — they
    # take objects or are methods. Checked in the target's process on the real argument sets the suite produced.
    claims: List[Dict[str, Any]] = []
    try:
        from . import claim_forms as _cf
        from .boundary_probes import _kind
        for d in _defs(trees_by_rel):
            n = d["node"]
            ps = [a.arg for a in n.args.args]
            kinds = {p: ("other" if p in ("self", "cls") else _kind(n, p)) for p in ps}
            if not d["method"] and "other" not in kinds.values():
                continue   # the static sandbox (intent_claims) already checks these
            got = _cf.read(ast.get_docstring(n) or "", ps, kinds) + _cf.read_name(
                n.name, ps, kinds, ast.unparse(n.returns) if n.returns is not None else "")
            if got:
                ints = {a.arg: bool(a.annotation is not None and "int" in ast.unparse(a.annotation)
                                    and "float" not in ast.unparse(a.annotation)) for a in n.args.args}
                claims.append({"ref": {k: v for k, v in d.items() if k != "node"}, "claims": got, "params": ps,
                               "kinds": kinds, "ints": ints})
    except ImportError:
        claims = []
    return {"twins": twins, "claims": claims,
            "claim_forms": str(Path(__file__).resolve().parent / "claim_forms.py")}


def observations(trees_by_rel: Dict[str, ast.AST], root: Path) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    p = plan(trees_by_rel)
    traced = run_traced(root, p)
    probes = dict(traced.get("probes") or {})
    entry = run_entry(root, p)   # the app's own run reaches code no test calls (Pong format: the headless game)
    if entry:
        direct = {tuple(x) for x in probes.get("direct_pass", [])}
        seen = {(h["a"]["file"], h["a"]["first"], h["b"]["file"], h["b"]["first"]) for h in probes.get("twins", [])}
        for h in entry.get("twins", []):
            if (h["a"]["file"], h["a"]["first"], h["b"]["file"], h["b"]["first"]) not in seen:
                h["a_tested"] = (h["a"]["file"], h["a"]["first"]) in direct
                h["b_tested"] = (h["b"]["file"], h["b"]["first"]) in direct
                probes.setdefault("twins", []).append(h)
        have = {(c["ref"]["file"], c["ref"]["first"]) for c in probes.get("claims", [])}
        probes.setdefault("claims", []).extend(c for c in entry.get("claims", [])
                                                if (c["ref"]["file"], c["ref"]["first"]) not in have)
    traced = {**traced, "probes": probes}
    nodes = {(d["file"], d["first"]): d["node"] for d in _defs(trees_by_rel)}
    out = _blame_observations(trees_by_rel, root, traced)
    for hit in (traced.get("probes") or {}).get("claims", []):
        ref = hit["ref"]
        n = nodes.get((ref["file"], ref["first"]))
        if n is None:
            continue
        rets = sorted(x.lineno for x in ast.walk(n) if isinstance(x, ast.Return))
        try:
            from .intent_claims import slice_lines
            lines = slice_lines(n, rets[-1]) if rets else [n.lineno]
        except Exception:
            lines = rets or [n.lineno]
        for b in hit["broken"]:
            out.setdefault(str((root / ref["file"]).resolve()), {}).setdefault(f"{ref['name']}@{ref['line']}", []).append({
                "tag": "NAI-102", "line": (lines or [n.lineno])[0], "lines": lines or [n.lineno],
                "variant": "runtime_claim", "claim": b.get("claim"),
                "description": f"`{ref['name']}` says {b.get('says')}; run on a real call from the target's own suite "
                               f"({b.get('probe')}) it gives {b.get('got')} (expected {b.get('expected')})"})
    for hit in (traced.get("probes") or {}).get("twins", []):
        a, b = hit["a"], hit["b"]
        pinned = [t for t, tested in ((a, hit.get("a_tested")), (b, hit.get("b_tested"))) if tested]
        for t, other in ((a, b), (b, a)):
            suspect = pinned == [other]
            desc = (f"`{t['file']}::{t['name']}` and `{other['file']}::{other['name']}` are the same function in two "
                    f"places but answer differently on {hit['args']}: {hit['a_result'] if t is a else hit['b_result']} "
                    f"here vs {hit['b_result'] if t is a else hit['a_result']} there"
                    + (f"; the suite pins the other copy, so this one is the stale twin" if suspect else
                       "; the suite does not say which copy is right"))
            mine, theirs = nodes.get((t["file"], t["first"])), nodes.get((other["file"], other["first"]))
            diff = _differing_lines(mine, theirs) if mine is not None and theirs is not None else []
            obs = {"tag": "NAI-251", "line": (diff or [t["line"]])[0], "lines": diff or [t["line"]], "variant": "runtime_diverge",
                   "sibling": f"{other['file']}::{other['name']}", "description": desc,
                   **({} if suspect else {"context": True})}
            out.setdefault(str((root / t["file"]).resolve()), {}).setdefault(f"{t['name']}@{t['line']}", []).append(obs)
    return out
