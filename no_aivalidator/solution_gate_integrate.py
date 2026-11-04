"""Solution gate, stage 2 "integrates" (owner 2026-10-08).

The attempt that ran (stage 1) is WRITTEN into the target — the target is always a copy of the original repo, so
CodeRadar writes freely — and the codebase around it must still hold:
  * the changed module and every module that imports it (the circuit graph's importers) still import;
  * the declared entry point (the intent file's `entry_point` facts: `python -m pkg.runner`, `python app.py`) still
    exits the way it did before the change.
Every check runs BEFORE and AFTER the write in a fresh interpreter with a timeout, and only a check that passed before
and fails after counts — a module that never imported (a missing third-party package) is not the attempt's fault.
On a fail the file's original bytes are restored and the verdict names the module or command and its traceback tail.
On a pass the attempt stays applied for stage 3; `revert(applied)` undoes it if stage 3 fails.

The gate never opens a window (problem 4, 2026-10-10: `python -m the_fishbowl` popped a blank tkinter window and
held it for the whole timeout, twice per attempt). Every entry runs with no display: the GUI toolkits' imports fail
and DISPLAY / WAYLAND_DISPLAY are unset. A declared non-interactive form of the same entry (the README's
`--headless` line) runs and is compared; the interactive form stops at its toolkit import. An entry that did not
exit 0 BEFORE the write — interactive, still running at the timeout, or already failing — proves nothing either
way: it is NOT MEASURED, named in the probe, never counted as "runs as before", and not run again after the write.
When entry points were declared and NONE could be measured, the pass also carries `not_measured` (one line per
entry) and its detail opens "pass (entry not measured)"; the Builder copies the field onto the row's attempt.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

IMPORT_TIMEOUT_S = 30
ENTRY_TIMEOUT_S = 60

_IMPORT_SCRIPT = r"""
import importlib, json, sys, traceback
root, names = sys.argv[1], json.loads(sys.argv[2])
sys.path[:0] = [root]
out = {}
for name in names:
    try:
        importlib.import_module(name)
        out[name] = ""
    except BaseException:
        out[name] = traceback.format_exc()[-1500:]
print("\n@@CR_IMPORTS@@" + json.dumps(out))
"""

# The toolkits that put a window on screen; the entry runs with their imports refused (a non-GUI fallback still runs).
GUI_TOOLKITS = ("tkinter", "_tkinter", "turtle", "PyQt5", "PyQt6", "PySide2", "PySide6", "wx", "gi", "kivy",
                "pygame", "pyglet", "arcade", "dearpygui", "webview", "toga")
_NO_DISPLAY_MARK = "@@CR_NO_DISPLAY@@"
# argv: toolkits, then the entry as declared (`-m pkg.mod args…` or `app.py args…`), run as `__main__`.
_ENTRY_SCRIPT = r"""
import os, runpy, sys
toolkits = set(sys.argv[1].split(","))
class NoDisplay:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in toolkits:
            sys.stderr.write("\n@@CR_NO_DISPLAY@@" + name + "\n")
            raise ImportError(f"{name}: CodeRadar's gate runs the entry point with no display")
        return None
sys.meta_path.insert(0, NoDisplay())
entry = sys.argv[2:]
if entry[0] == "-m":
    sys.argv = [entry[1], *entry[2:]]
    runpy.run_module(entry[1], run_name="__main__", alter_sys=True)
else:
    sys.argv = entry
    sys.path[0] = os.path.dirname(os.path.abspath(entry[0]))
    runpy.run_path(entry[0], run_name="__main__")
"""


def module_name(rel: str) -> str:
    p = Path(rel).with_suffix("")
    parts = list(p.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(root: Path, names: List[str]) -> Dict[str, str]:
    """{module: "" when it imports, else the traceback tail} — one fresh interpreter, cwd = the target."""
    if not names:
        return {}
    try:
        proc = subprocess.run([sys.executable, "-I", "-B", "-c", _IMPORT_SCRIPT, str(root), json.dumps(names)],
                              cwd=str(root), capture_output=True, text=True, timeout=IMPORT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {n: f"importing took longer than {IMPORT_TIMEOUT_S} s" for n in names}
    _head, found, payload = proc.stdout.rpartition("@@CR_IMPORTS@@")
    if not found:
        tail = (proc.stderr or proc.stdout)[-1500:]
        return {n: f"the import check itself died: {tail}" for n in names}
    return json.loads(payload.strip())


def entry_commands(intent_facts: List[Dict[str, Any]], root: Path) -> List[List[str]]:
    """The intent file's entry points that name something inside the target, as argv lists for this interpreter."""
    cmds: List[List[str]] = []
    for f in intent_facts or []:
        if f.get("fact") not in ("entry_point", "entry_points"):
            continue
        try:
            argv = shlex.split(str(f.get("value") or ""))
        except ValueError:
            continue
        if argv and re.fullmatch(r"python\d?(\.\d+)?", Path(argv[0]).name):
            argv = argv[1:]
        match argv:
            case ["-m", mod, *_] if (root / Path(*mod.split("."))).with_suffix(".py").exists() \
                    or (root / Path(*mod.split(".")) / "__main__.py").exists():
                cmd = [sys.executable, *argv]
            case [script, *_] if script.endswith(".py") and (root / script).exists():
                cmd = [sys.executable, *argv]
            case _:
                continue
        if cmd not in cmds:
            cmds.append(cmd)
    return cmds


def _run(cmd: List[str], root: Path) -> Tuple[Optional[int], str, str]:
    """(returncode | None at the timeout, output tail, the GUI toolkit it tried to import or "") — with no display."""
    # The gate runs in the live target: no bytecode left behind (I-153 — teardown counts it as residue).
    env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    env.update(PYTHONDONTWRITEBYTECODE="1", MPLBACKEND="Agg")
    try:
        proc = subprocess.run([cmd[0], "-c", _ENTRY_SCRIPT, ",".join(GUI_TOOLKITS), *cmd[1:]], cwd=str(root),
                              capture_output=True, text=True, timeout=ENTRY_TIMEOUT_S, stdin=subprocess.DEVNULL,
                              env=env)
    except subprocess.TimeoutExpired:
        return None, f"still running after {ENTRY_TIMEOUT_S} s", ""
    gui = [ln[len(_NO_DISPLAY_MARK):] for ln in proc.stderr.splitlines() if ln.startswith(_NO_DISPLAY_MARK)]
    err = "\n".join(ln for ln in proc.stderr.splitlines() if not ln.startswith(_NO_DISPLAY_MARK))
    return proc.returncode, (err or proc.stdout)[-1500:], (gui[0] if gui else "")


def _not_measured(rc: Optional[int], tail: str, gui: str) -> str:
    """Why an entry that did not exit 0 before the write says nothing about the attempt."""
    if rc and gui:
        return f"not run: interactive entry (opens a window — `import {gui}`; the gate has no display)"
    if rc is None:
        return f"not run: interactive entry (never exits — {tail} before the attempt)"
    return f"exits {rc} before the attempt: " + (tail.strip().splitlines() or [""])[-1]


def _splice(source: str, start: int, end: int, code: str) -> str:
    lines = source.splitlines(keepends=True)
    indent = len(lines[start - 1]) - len(lines[start - 1].lstrip()) if 0 < start <= len(lines) else 0
    body = textwrap.indent(textwrap.dedent(code).strip("\n") + "\n", " " * indent)
    return "".join(lines[:start - 1]) + body + "".join(lines[end:])


def revert(applied: Dict[str, Any]) -> None:
    """Restore the bytes stage 2 replaced (stage 3's undo)."""
    Path(applied["path"]).write_bytes(applied["original"])


def _live_function_span(source: str, function: str, line: int, expected_code: str) -> Optional[Tuple[int, int]]:
    """Fix plan 2026-10-23 B3: the function's LIVE span in `source`, by AST — the same rule
    `coderadar_mcp.write_tools._live_span` renders with (nearest same-named def to `line`;
    decorators ride along only when the row's own code starts with one). None when the file does
    not parse or no such function exists."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    matches = [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function]
    if not matches:
        return None
    node = min(matches, key=lambda n: abs(int(getattr(n, "lineno", 0)) - int(line or 0)))
    start = int(getattr(node, "lineno", 0))
    end = int(getattr(node, "end_lineno", 0) or start)
    head = next((ln for ln in (expected_code or "").splitlines() if ln.strip()), "")
    if node.decorator_list and head.lstrip().startswith("@"):
        start = min([start] + [int(getattr(d, "lineno", start)) for d in node.decorator_list])
    if start < 1 or end < start:
        return None
    return start, end


def stage_integrates(root: Path, rel: str, start: int, end: int, attempt_code: str,
                     importer_rels: List[str], intent_facts: List[Dict[str, Any]],
                     expected_code: str = "", function: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {"stage": "integrates", "verdict": "fail", "detail": "", "probe": {}, "applied": None}
    path = (root / rel)
    try:
        original = path.read_bytes()
        source = original.decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        out["detail"] = f"cannot read {rel} in the target: {e}"
        return out
    # Fix plan 2026-10-23 B3: THE SPAN A WRITE USES IS THE LIVE ONE. The row's recorded span is the
    # Builder's join key, never the edit range: the function is located by AST in the file as it
    # stands now, and when it cannot be, nothing is written — the attempt is judged again after the
    # rescan rather than spliced onto lines the recorded numbers happen to name (run 162's hazard).
    rebased = ""
    if function and function != "<module>":
        live = _live_function_span(source, function, start, expected_code)
        if live is None:
            out.update(verdict="deferred",
                       detail=f"`{function}` could not be located in {rel} as it stands now (recorded span "
                              f"{start}-{end}); nothing is written against an unverified span — judged on the "
                              f"next cycle, after the rescan")
            return out
        if live != (start, end):
            rebased = f" (re-based from recorded {start}-{end} to live {live[0]}-{live[1]})"
            start, end = live
    lines = source.splitlines(keepends=True)
    span = lines[max(start, 1) - 1:end] if start in range(1, len(lines) + 1) else []
    if not span or end not in range(start, len(lines) + 1):
        out["detail"] = f"the row's span {start}-{end} is outside {rel} ({len(lines)} lines) — the file moved on; rescan"
        return out
    if expected_code and textwrap.dedent("".join(lines[start - 1:end])).strip() != textwrap.dedent(expected_code).strip():
        out.update(verdict="deferred", detail=f"{rel} lines {start}-{end} no longer hold the row's code (another write "
                                              f"moved them) — judged on the next cycle, after the rescan")
        return out
    modules = [module_name(rel)] + [module_name(r if r.endswith(".py") else r + ".py") for r in importer_rels]
    modules = list(dict.fromkeys(m for m in modules if m))
    cmds = entry_commands(intent_facts, root)
    before_imp = _imports(root, modules)
    before_run = [_run(c, root) for c in cmds]
    patched = _splice(source, start, end, attempt_code)
    path.write_text(patched, encoding="utf-8")
    applied = {"path": str(path), "original": original}
    after_imp = _imports(root, modules)
    broken = [m for m in modules if not before_imp.get(m) and after_imp.get(m)]
    if broken:
        revert(applied)
        m = broken[0]
        out["detail"] = (f"`import {m}` worked before the attempt and fails after it"
                         + ("" if m == modules[0] else f" ({m} imports the changed module)")
                         + f": {after_imp[m].strip().splitlines()[-1]}")
        out["probe"] = {"module": m, "traceback": after_imp[m]}
        return out
    shown_cmds = [" ".join(["python", *c[1:]]) for c in cmds]
    unmeasured = [{"command": s, "reason": _not_measured(*r)} for s, r in zip(shown_cmds, before_run) if r[0] != 0]
    for cmd, (rc0, _, _) in zip(cmds, before_run):
        if rc0 is None or rc0:   # not a clean exit before the write — listed as unmeasured above
            continue
        rc1, tail1, _ = _run(cmd, root)
        if rc1 is None or rc1:
            revert(applied)
            shown = " ".join(["python", *cmd[1:]])
            out["detail"] = (f"the entry point `{shown}` exited 0 before the attempt and "
                             + (f"exits {rc1}" if rc1 is not None else tail1) + " after it: "
                             + (tail1.strip().splitlines() or [""])[-1])
            out["probe"] = {"command": shown, "returncode": rc1, "traceback": tail1}
            return out
    not_importable = [m for m in modules if before_imp.get(m)]
    measured = [s for s, r in zip(shown_cmds, before_run) if r[0] == 0]
    if cmds and not measured:
        # An entry point was declared and not one of them could be run: the pass covers the imports only, and it
        # says so in its own field, so it never reads as a full pass (verifier, 2026-10-10: no --headless line).
        out["not_measured"] = [f"entry point `{u['command']}` — {u['reason']}" for u in unmeasured]
    out.update(verdict="pass", applied=applied,
               detail=("pass (entry not measured): " if out.get("not_measured") else "")
                      + f"applied to {rel} L{start}-L{end}{rebased}; {len(modules) - len(not_importable)} module(s) import as before"
                      + (f" ({len(not_importable)} never imported, not counted)" if not_importable else "")
                      + (f"; {len(measured)} entry point(s) run as before" if cmds else "; no entry point declared")
                      + "".join(f"; NOT MEASURED `{u['command']}` — {u['reason']}" for u in unmeasured),
               probe={"modules": modules, "entry_points": measured,
                      **({"entry_points_not_measured": unmeasured} if unmeasured else {})})
    return out
