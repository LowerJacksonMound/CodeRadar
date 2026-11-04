"""R5 proof (2026-09-30) — `cr_status` reports the true state of ANY launch, however it was started.

The finding: cr_status read its launch verdict only from `.archive/runs/<target>/launch.log`, which
only cr_watch writes (it redirects launch.sh into it). A launch made by `./launch.sh` or the setup
page has no launch.log, so `gates.all_passed` came back False — "failed" — after every one of them.
The repair reads `system_scripts/launch_progress.json`, the file every launch writes.

Offline: each case is a scratch tree with faked state files; `read_tools.configure(tree=…)` points
the module at it and `_launch_live` (the process-table probe) and `_health_now` (the port probe)
are replaced, so nothing is launched, probed or stopped. Cases:
  1 launch.sh launch reached ready (no launch.log)       → ready, all_passed True
  2 launch failed at the health step                      → failed, step health, the reason
  3 launch still running (launch.sh steps, then gearbox)  → running, the current step
  4 no launch at all                                      → no launch
  5 MCP (cr_watch) launch: same file + its own launch.log → ready, gates from launch.log
  6 unknown / unprovable states                           → NOT MEASURED with a reason
  7 the real last run's launch_progress.json (copied)     → failed at health, as the overlay said
  8 the one-target guard (T-13): a file naming no target_repo (the dash mirror before R4) is
    NOT MEASURED, not a pass; one naming this target passes; another target's fails and is withheld
Every answer is checked against cr_status's output schema.

    PYTHONDONTWRITEBYTECODE=1 .venv_new/bin/python -m coderadar_mcp.launch_state_proof
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from system_scripts import launch_progress

from . import read_tools as rt
from .tool_interface import TOOLS, validate_payload

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGET = "/Users/dev/the_repo"
CHOICES = f"target={TARGET} tracer=lsof trackers=io,mypy copy=on purpose=given"
ORDER = ["choices", "preflight", "gearbox", "dashboard", "snapshot", "health", "whitelist",
         "target_env", "circuit", "wiring", "noai", "solutions"]
LABELS = {"health": "CodeRadar self-test", "wiring": "check every file is on the map",
          "noai": "check code does what it says"}
FAILS: list[str] = []


def passed_before(step: str) -> dict[str, str]:
    """Every step ahead of `step` in launch order passed."""
    return {k: "pass" for k in ORDER if ORDER.index(k) < ORDER.index(step)}


def check(what: str, ok: bool, seen: Any = None) -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {what}" + ("" if ok else f"   (got {seen!r})"))
    if not ok:
        FAILS.append(what)


def progress(overall: str, statuses: dict[str, str], detail: str = "",
             choices: str | None = CHOICES, t0: float | None = None) -> dict[str, Any]:
    """A launch_progress.json shaped as launch_progress.py writes it (string `started`, float
    `updated`, the `order` list, each stage's label/status/detail/secs)."""
    t0 = t0 if t0 is not None else time.time() - 120
    stages: dict[str, Any] = {}
    for i, key in enumerate(ORDER):
        status = statuses.get(key, "pending")
        stage: dict[str, Any] = {"status": status, "label": LABELS.get(key, key)}
        if status != "pending":
            stage["started"] = str(t0 + i)
            stage["secs"] = 1.0
        if key == "choices" and choices is not None:
            stage["detail"] = choices
        if status == "fail":
            stage["detail"] = detail
        stages[key] = stage
    return {"overall": overall, "order": ORDER, "stages": stages,
            "updated": t0 + 85, "detail": detail}


def tree_with(doc: dict[str, Any] | None, launch_log: str | None = None,
              log_age_s: float = 0.0) -> Path:
    root = Path(tempfile.mkdtemp(prefix="r5_launch_state_"))
    (root / "system_scripts").mkdir()
    (root / ".archive" / "runs" / Path(TARGET).name).mkdir(parents=True)
    if doc is not None:
        (root / "system_scripts" / "launch_progress.json").write_text(json.dumps(doc), "utf-8")
    if launch_log is not None:
        log = root / ".archive" / "runs" / Path(TARGET).name / "launch.log"
        log.write_text(launch_log, "utf-8")
        if log_age_s:
            old = time.time() - log_age_s
            os.utime(log, (old, old))
    return root


def status_of(root: Path, live: bool | None, target: str = TARGET) -> dict[str, Any]:
    rt.configure(target=target, tree=root)
    rt._launch_live = lambda: (live, {True: "pid 1: gearbox.py (faked)",
                                      False: "no CodeRadar launch or supervisor process is running",
                                      None: "the process table could not be read (faked)"}[live])
    out = rt.cr_status()
    problems = validate_payload(TOOLS["cr_status"], out, "output")
    check("output matches cr_status's schema", not problems, problems)
    return out


def main() -> int:
    real_live, real_health = rt._launch_live, rt._health_now
    rt._health_now = lambda: {"ok": False, "error": "not probed (offline proof)"}
    made: list[Path] = []
    try:
        print("1  launch.sh launch reached ready — no launch.log (the finding's case)")
        root = tree_with(progress("ready", {k: "pass" for k in ORDER}))
        made.append(root)
        out = status_of(root, live=True)
        la, g = out["launch"], out["gates"]
        check("launch.state == ready", la["state"] == "ready", la["state"])
        check("gates.all_passed is True (was False before R5)", g["all_passed"] is True, g["all_passed"])
        check("gates come from the launch file", g["source"] == "launch_progress.json", g["source"])
        check("12 steps listed", len(la["steps"]) == 12, len(la["steps"]))
        check("target/copy/purpose parsed from the choices detail",
              (la["target"], la["copy"], la["purpose"]) == (TARGET, "on", "given"),
              (la["target"], la["copy"], la["purpose"]))
        check("seconds measured from the file", la["seconds"] == 85, la["seconds"])
        out = status_of(root, live=False)
        check("ready, stack since stopped: still ready, live False, reason says so",
              out["launch"]["state"] == "ready" and out["launch"]["live"] is False
              and "stopped" in (out["launch"]["reason"] or ""), out["launch"])

        print("2  launch failed at the health step")
        why = ("health check failed: step 17 — DISALLOWED pre-ranker ranker: x.py:1 — report: "
               "/tmp/health.txt")
        st = passed_before("health")
        st["health"] = "fail"
        root = tree_with(progress("failed", st, detail=why))
        made.append(root)
        out = status_of(root, live=True)   # the gearbox holds a failed stack until the overlay closes it
        la = out["launch"]
        check("launch.state == failed", la["state"] == "failed", la["state"])
        check("step == health, label 'CodeRadar self-test'",
              (la["step"], la["step_label"]) == ("health", "CodeRadar self-test"),
              (la["step"], la["step_label"]))
        check("reason is the launch's own failure detail", la["reason"] == why, la["reason"])
        check("gates.all_passed is False", out["gates"]["all_passed"] is False, out["gates"]["all_passed"])

        print("3  launch still running")
        root = tree_with(progress("running", {"choices": "pass", "preflight": "pass",
                                              "gearbox": "running"}))
        made.append(root)
        out = status_of(root, live=True)
        la = out["launch"]
        check("launch.sh steps: state running, step gearbox",
              (la["state"], la["step"]) == ("running", "gearbox"), (la["state"], la["step"]))
        check("gates.all_passed is None while running", out["gates"]["all_passed"] is None,
              out["gates"]["all_passed"])
        st = passed_before("target_env")
        st.update({"target_env": "degraded", "circuit": "pass", "wiring": "pass", "noai": "running"})
        root = tree_with(progress("done", st))
        made.append(root)
        out = status_of(root, live=True)
        la = out["launch"]
        check("handed to the gearbox ('done'): state running, step noai",
              (la["state"], la["step"], la["overall"]) == ("running", "noai", "done"),
              (la["state"], la["step"], la["overall"]))

        print("4  no launch at all")
        root = tree_with(None)
        made.append(root)
        out = status_of(root, live=False)
        la = out["launch"]
        check("launch.state == no launch, with a reason", la["state"] == "no launch" and bool(la["reason"]),
              la)
        check("gates.all_passed is None", out["gates"]["all_passed"] is None, out["gates"]["all_passed"])

        print("5  MCP-started launch (cr_watch): same launch file plus its own launch.log")
        log = ("GATE [circuit WIRING] PASS in 0.4s\nGATE [NOAI SCAN] PASS in 30.2s\n"
               "ALL GATES PASSED — stack is up. Dashboard: http://127.0.0.1:8080\n")
        root = tree_with(progress("ready", {k: "pass" for k in ORDER}), launch_log=log)
        made.append(root)
        out = status_of(root, live=True)
        g = out["gates"]
        check("launch.state == ready", out["launch"]["state"] == "ready", out["launch"]["state"])
        check("gates from this launch's launch.log (2 gate lines)",
              g["source"] == "launch.log" and [x["gate"] for x in g["gates"]] == ["circuit WIRING", "NOAI SCAN"],
              g)
        check("gates.all_passed is True", g["all_passed"] is True, g["all_passed"])
        st = passed_before("health")
        st["health"] = "fail"
        root = tree_with(progress("failed", st, detail="health check failed: step 3"),
                         launch_log=log, log_age_s=86400)
        made.append(root)
        out = status_of(root, live=False)
        g = out["gates"]
        check("a stale launch.log from an older cr_watch launch is NOT read as this launch's",
              g["source"] == "launch_progress.json" and g["all_passed"] is False
              and out["launch"]["state"] == "failed", (g, out["launch"]["state"]))

        print("6  states that cannot be proven → NOT MEASURED with a reason")
        cases = [
            ("'running' in the file but no launch process live",
             tree_with(progress("running", {"choices": "pass", "preflight": "running"})), False),
            ("'running' in the file and the process table unreadable",
             tree_with(progress("running", {"choices": "pass", "preflight": "running"})), None),
            ("an unknown overall word", tree_with(progress("exploded", {"choices": "pass"})), True),
            ("the record is another target's launch",
             tree_with(progress("ready", {k: "pass" for k in ORDER},
                                choices="target=/Users/dev/other_repo tracer=lsof copy=on purpose=none")), True),
            ("launch_progress.json is corrupt", tree_with(None), True),
            ("the file is absent while a launch process is live", tree_with(None), True),
        ]
        (cases[4][1] / "system_scripts" / "launch_progress.json").write_text("{not json", "utf-8")
        for what, root, live in cases:
            made.append(root)
            out = status_of(root, live=live)
            la = out["launch"]
            check(f"{what}: NOT MEASURED + reason",
                  la["state"] == "NOT MEASURED" and bool(la["reason"]), (la["state"], la["reason"]))
            check(f"{what}: all_passed is None", out["gates"]["all_passed"] is None, out["gates"]["all_passed"])
        root = tree_with(progress("ready", {k: "pass" for k in ORDER}, choices="tracer=lsof"))
        made.append(root)
        out = status_of(root, live=True)
        check("a record naming no target: the state stands, target_note says so",
              out["launch"]["state"] == "ready" and "target_note" in out["launch"], out["launch"])

        print("7  the real last run (system_scripts/launch_progress.json, copied, read offline)")
        real = PROJECT_ROOT / "system_scripts" / "launch_progress.json"
        if not real.exists():
            print("  SKIP  no launch_progress.json in the tree")
        else:
            doc = launch_progress.read(real)
            check("the real file reads as a launch record", isinstance(doc.get("stages"), dict), doc)
            doc.setdefault("stages", {})
            root = tree_with(doc)
            made.append(root)
            tgt = next((m.group("value") for m in rt._CHOICE_RE.finditer(
                str(doc["stages"].get("choices", {}).get("detail", ""))) if m.group("key") == "target"),
                TARGET)
            out = status_of(root, live=False, target=tgt)
            la = out["launch"]
            print(f"        overall={doc.get('overall')!r} → state={la['state']!r} step={la['step']!r} "
                  f"reason={str(la['reason'])[:90]!r}")
            want = {"failed": "failed", "ready": "ready"}.get(str(doc.get("overall")))
            if want is not None:
                check(f"the real file's overall {doc.get('overall')!r} is reported as {want!r}",
                      la["state"] == want, la["state"])
            if doc.get("overall") == "failed":
                bad = next((k for k in doc["order"] if doc["stages"].get(k, {}).get("status") == "fail"), None)
                check(f"the real failed step ({bad}) is named", la["step"] == bad, la["step"])

        print("8  the one-target guard on the files cr_status reads (T-13)")
        root = tree_with(progress("ready", {k: "pass" for k in ORDER}))
        made.append(root)
        sysd = root / "system_scripts"
        summary = {"broken_imports": 0, "mypy_errors": 3}
        (sysd / "BUILDER_STATE.json").write_text(json.dumps(
            {"phase": "MONITORING", "target_repo": TARGET, "cycle": 2}), "utf-8")
        (sysd / ".monitor_state.json").write_text(json.dumps({"monitor": {"summary": summary}}), "utf-8")
        (sysd / ".noai_state.json").write_text(json.dumps(
            {"target_repo": "/Users/dev/other_repo", "summary": {"failed": 9}}), "utf-8")
        out = status_of(root, live=True)
        tg = out["target_guard"]
        check("builder naming this target: pass", tg["builder"]["verdict"] == "pass", tg["builder"])
        check("dash mirror naming no target: NOT MEASURED with a reason (was a silent pass)",
              tg["monitor"]["verdict"] == "NOT MEASURED" and bool(tg["monitor"]["reason"]), tg["monitor"])
        check("… and its summary is still read", out["summary"] == summary, out["summary"])
        check("noai state naming another target: fail, rows withheld",
              tg["noai"]["verdict"] == "fail" and out["infractions"] == {}, (tg["noai"], out["infractions"]))
        check("circuit state absent: NOT MEASURED with the read error",
              tg["circuit"]["verdict"] == "NOT MEASURED" and bool(tg["circuit"]["reason"]), tg["circuit"])
        for where, doc in (("top level", {"target_repo": TARGET, "monitor": {"summary": summary}}),
                           ("inside the monitor envelope",
                            {"monitor": {"target_repo": TARGET, "summary": summary}})):
            (sysd / ".monitor_state.json").write_text(json.dumps(doc), "utf-8")
            out = status_of(root, live=True)
            check(f"dash mirror with target_repo ({where}): pass",
                  out["target_guard"]["monitor"]["verdict"] == "pass", out["target_guard"]["monitor"])
        (sysd / ".monitor_state.json").write_text(json.dumps(
            {"target_repo": "/Users/dev/other_repo", "monitor": {"summary": summary}}), "utf-8")
        out = status_of(root, live=True)
        check("dash mirror naming another target: fail, summary withheld",
              out["target_guard"]["monitor"]["verdict"] == "fail" and out["summary"] == {},
              (out["target_guard"]["monitor"], out["summary"]))
    finally:
        rt._launch_live, rt._health_now = real_live, real_health
        for root in made:
            shutil.rmtree(root, ignore_errors=True)

    print()
    if FAILS:
        print(f"R5 launch-state proof: FAIL — {len(FAILS)} check(s): " + "; ".join(FAILS))
        return 1
    print("R5 launch-state proof: PASS — ready, failed (health), running, no launch, an MCP launch, "
          "and NOT MEASURED, all off the file every launch writes; the target guard says NOT MEASURED "
          "when a file names no target")
    return 0


if __name__ == "__main__":
    sys.exit(main())
