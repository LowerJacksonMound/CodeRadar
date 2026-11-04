"""T2's file — the READ tools over the files the app already publishes.

Owns: cr_status · cr_infractions · cr_row · cr_wiring · cr_data_types · cr_intent
Also T2's: `server.py` (the stdio server, Q1).

No other lane edits this module. The schemas and the sources of record are fixed in
`tool_interface.py` and are not re-decided here; what IS decided here is only how a
published file is found and how a published value maps onto a fixed field.

**Nothing in this module writes.** Every tool opens a file the app published, or the
health port, and answers out of it. Stdlib only — the package still imports no engine
module, so the tools run against an archived run's state with no daemon alive.

The published files, all under `<tree>/system_scripts/` (Q1: one server process per
target, and the tree it runs in is the tree that published them):
  * `.monitor_state.json`  — the dash mirror     (`monitor.summary`, `monitor.mypy`, …)
  * `.noai_state.json`     — the counterfeit-code mirror (`repairs`/`no_vetted_fix`/`withheld`)
  * `BUILDER_STATE.json`   — the rows in full, and `return_channel`
  * `circuit_state.json`   — nodes, edges, severed links, trackers, runners, cadence
  * `intent_<repo_id>.json`— the derived intent (named by BUILDER_STATE.summary.intent.file)
  * `copy_ports.json`      — this tree's dashboard and health ports
An ARCHIVED run publishes the same files under `.archive/runs/<name>/state_during_run/`,
where the counterfeit mirror is copied as `noai_state_mirror.json`; `configure(state_dir=…)`
points the tools at such a directory, which is how the offline proof runs.

House style: dataclasses, `from __future__ import annotations`, stdlib only.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .tool_interface import (APPLY_REVIEW_REASON, APPLY_STATES, EDGE_STATES, ISSUES_SCOPE,
                             NOT_SELECTABLE_BY, NOT_SELECTABLE_REASON, PAGE_SIZE_DEFAULT, TOOLS,
                             register_handler, row_id)
#: B5 (2026-10-01, Q-H0-1): the ONE type-error / annotation-note split — the same pure module
#: circuit_daemon and the dashboard's mypy tile import (`session_tools` already imports
#: `system_scripts.gearbox` the same way). `cr_data_types.issues` is counted with it.
from system_scripts.mypy_partition import partition as _mypy_partition

#: B5: the scope `cr_data_types.issues` carries — type errors only; the notes sit beside it.
ISSUES_TYPE_ERRORS_SCOPE: str = "(real type errors only — the --strict annotation notes are `notes`)"

#: The tools this lane owns. `server.py` dispatches through `HANDLERS`, so a tool stays
#: unimplemented until its lane registers it — the surface is complete from day one.
OWNED: tuple[str, ...] = (
    "cr_status",
    "cr_infractions",
    "cr_row",
    "cr_wiring",
    "cr_data_types",
    "cr_intent",
)

assert all(n in TOOLS for n in OWNED), "T2 claims a tool that is not in the surface"


# ─────────────────────────────────────────────────────────────────────────────
# Where the published files are
# ─────────────────────────────────────────────────────────────────────────────

#: The CodeRadar tree this server belongs to — the parent of the package directory.
TREE_ROOT: Path = Path(__file__).resolve().parent.parent

#: Where a LIVE run publishes. An archived run's directory is passed to `configure`.
STATE_DIR: Path = TREE_ROOT / "system_scripts"

#: Each role's file names, live name first, then EVERY name a run record has ever archived that
#: role under — one table, read in order (I-143 / I-124 / Q6, session 10).
#:
#: I-124 (run 153): `cr_status`'s dash summary comes from the TREE's `system_scripts/.monitor_state.json`,
#: and a run directory's own copy is `monitor_mirror.json` — a name that was in NO table, so a
#: proof pointed at an archived run walked past two good runs onto a stale one. I-143 (run 156) is
#: the same reader from the other side: run 156's state had to be archived under the LIVE names
#: because the archived ones were the only ones the reader knew. The fix is the reader, not the
#: writer (`run_proof.sh`'s archive-side naming is not changed — the owner's Q6 default): a run
#: record archived under EITHER name set is read out of one table, and a name that is not in it
#: is a name the reader has never been taught, which is the defect both issues describe.
#: Every name below was READ OFF `.archive/runs/*/state_during_run/` on 2026-09-22, never guessed:
#: the live name first, the during-run archived name next, the at-teardown copy after it, and a
#: post-seat re-read last — newest state never outranks the state the run was measured on.
_MONITOR_FILES = (".monitor_state.json", "monitor_mirror.json", "monitor_mirror_at_teardown.json")
_NOAI_FILES = (".noai_state.json", "noai_state_mirror.json", "noai_state_mirror_at_teardown.json",
               "noai_mirror_after_seat.json")
_BUILDER_FILES = ("BUILDER_STATE.json", "BUILDER_STATE_at_teardown.json")
_CIRCUIT_FILES = ("circuit_state.json", "circuit_state_with_cadence.json")

#: The role every reader outside this module asks for by name — the proof's `_newest_run_state`
#: tests a candidate state directory against THIS table rather than spelling the names again
#: (I-143: two lanes were tripped by one reader that was spelled in three places).
STATE_FILES: dict[str, tuple[str, ...]] = {
    "monitor": _MONITOR_FILES,
    "noai": _NOAI_FILES,
    "builder": _BUILDER_FILES,
    "circuit": _CIRCUIT_FILES,
}

#: Seconds the health port is given to answer. Not a policy number: the port is local
#: and the tool answers `{"ok": false}` rather than hanging a client that is waiting on
#: a status line between two edits.
_HEALTH_WAIT_S = 2.0

#: `severed_since` is keyed `"<source>-><target>"` (ITEM_11 §the mirror, FIX_45).
_SEVERED_KEY = "{0}->{1}"

_STAGE_RE = re.compile(r"GATE \[(?P<gate>[^\]]+)\] (?P<status>PASS|FAIL)(?: in (?P<seconds>[0-9.]+)s)?")
_PASSED_AFTER_RE = re.compile(r"gates passed after (\d+) s")

#: R5 (2026-09-30): every launch — `./launch.sh <target>`, the setup page (`./launch.sh` with no
#: target), or cr_watch — publishes its steps to `system_scripts/launch_progress.json` (launch.sh
#: and the gearbox write it under one lock, `launch_progress.py`). `launch.log` exists ONLY for a
#: cr_watch launch (cr_watch redirects launch.sh into it; the gearbox's own voice is the terminal),
#: so it can never be the verdict of a launch the MCP did not start.
_PROGRESS_FILE = "launch_progress.json"
#: `overall` in that file: `running` (launch.sh's own steps), `done` (launch.sh handed over; the
#: gearbox is bringing the daemons up), `ready` (every gate passed), `failed` (a step failed).
_PROGRESS_LIVE = ("running", "done")
#: the `choices` step detail: `target=<path> tracer=… trackers=… copy=on|off purpose=given|none`.
_CHOICE_RE = re.compile(r"(?:^|\s)(?P<key>\w+)=(?P<value>.*?)(?=\s\w+=|$)")
#: launch states cr_status answers (`launch.state`).
LAUNCH_STATES = ("running", "ready", "failed", "no launch", "NOT MEASURED")


@dataclass(frozen=True)
class Sources:
    """The published files of ONE target, resolved once when the server starts.

    `target` is what `coderadar-mcp --target <repo>` was given. Every read compares it
    with the `target_repo` the file itself carries: a tree that is on another target
    answers with an error, never with another repo's rows (Q1: one process per target).
    """

    tree: Path
    state_dir: Path
    target: str | None
    repo_id: str | None

    def file_for(self, names: tuple[str, ...]) -> Path:
        """The first of `names` that exists, in `state_dir` then in the tree's
        `system_scripts/`; the live name in `state_dir` when none exists yet."""
        for where in (self.state_dir, self.tree / "system_scripts"):
            for name in names:
                candidate = where / name
                if candidate.is_file():
                    return candidate
        return self.state_dir / names[0]

    def ports(self) -> dict[str, Any]:
        data, _ = _read_json(self.tree / "system_scripts" / "copy_ports.json")
        return data

    def health_url(self) -> str:
        port = self.ports().get("health", 8051)
        return f"http://127.0.0.1:{port}/health"

    def run_dir(self) -> Path | None:
        """`.archive/runs/<basename of target>/` — the run's own record, where
        `run_proof.sh up` writes `launch.log` and `gate_budget.txt`."""
        if self.target is None:
            return None
        return self.tree / ".archive" / "runs" / Path(self.target).name


_SOURCES: Sources | None = None


def repo_id_of(target: str) -> str:
    """The 12-hex id the app keys every per-target file with. The algorithm is
    `system_scripts/engine_utils.make_repo_id` — sha256 of the resolved path, 12 chars —
    replicated rather than imported so this package still pulls in no engine module."""
    return hashlib.sha256(str(Path(target).resolve()).encode()).hexdigest()[:12]


def configure(target: str | None = None, state_dir: str | Path | None = None,
              tree: str | Path | None = None) -> Sources:
    """Point the read tools at one target's published files. `server.py` calls this once
    from `--target`; the offline proof calls it with `state_dir=` an archived run.

    There is no environment-variable route on purpose: the target is an argument of the
    process (Q1), so a client can never be served another repo's rows by an exported name.
    """
    global _SOURCES
    root = Path(tree).resolve() if tree is not None else TREE_ROOT
    where = Path(state_dir).resolve() if state_dir is not None else root / "system_scripts"
    resolved = str(Path(target).resolve()) if target is not None else None
    _SOURCES = Sources(
        tree=root,
        state_dir=where,
        target=resolved,
        repo_id=repo_id_of(resolved) if resolved is not None else None,
    )
    return _SOURCES


#: Lane C (2026-09-28): where launch.sh keeps the COPY-FIRST snapshots, `<name>_<timestamp>/`.
SNAPSHOT_ROOT = Path.home() / "CodeRadar_snapshots"


def run_and_snapshot(target: str | None) -> tuple[str | None, str | None]:
    """The run dir name under `.archive/runs/` and the newest COPY-FIRST snapshot for `target`
    (the same pick as `cr_stop` / `run_proof.sh down`), or None for either."""
    if not target:
        return None, None
    name = Path(str(target)).name
    snaps = sorted(SNAPSHOT_ROOT.glob(f"{name}_*"), key=lambda p: p.name)
    return name, (str(snaps[-1]) if snaps else None)


def sources() -> Sources:
    """The configured sources; an unconfigured process reads its own tree's live files."""
    if _SOURCES is None:
        return configure()
    return _SOURCES


# ─────────────────────────────────────────────────────────────────────────────
# Reading a published file
# ─────────────────────────────────────────────────────────────────────────────


def _read_json(path: Path) -> tuple[dict[str, Any], str | None]:
    """The file as a dict, and the reason it is not one. An absent file is not a crash:
    `cr_status` before the first cycle is a legitimate question with a plain answer."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}, f"{path.name} not published yet ({path})"
    except (OSError, ValueError) as exc:
        return {}, f"{path.name} unreadable: {exc}"
    if isinstance(data, dict):
        return data, None
    return {}, f"{path.name}: want a JSON object, got {type(data).__name__}"


def _read_json_any(path: Path) -> Any:
    """A published file whose top level may be a list (the gearbox's event feed is one)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _target_guard(data: dict[str, Any], src: Sources) -> tuple[str, str | None]:
    """`(verdict, reason)` of the one-target guard on a published file: `pass`, `fail` (the file
    is another target's), or `NOT MEASURED` (no target configured, or the file names none — the
    dash mirror named none before R4, 2026-09-30; a guard that cannot look is not a pass).
    `target_repo` is the state files' key (the dash mirror's may sit in its `monitor` envelope);
    the intent file's is `target`."""
    envelope = data.get("monitor")
    published = data.get("target_repo", data.get("target"))
    published = published if published is not None or not isinstance(envelope, dict) \
        else envelope.get("target_repo")
    if src.target is None:
        return "NOT MEASURED", "no target is configured, so no file can be checked against one"
    if published is None:
        return "NOT MEASURED", "the file names no target_repo — whose run it records cannot be checked"
    if str(Path(str(published)).resolve()) == src.target:
        return "pass", None
    return "fail", f"this tree is on {published!r}, not {src.target!r} — start one server per target (Q1)"


def _wrong_target(data: dict[str, Any], src: Sources) -> str | None:
    """The reason this published file is another target's, or None. A file the guard could not
    check is still read (its verdict is published as NOT MEASURED in `cr_status.target_guard`)."""
    verdict, reason = _target_guard(data, src)
    return reason if verdict == "fail" else None


def _load_guarded(names: tuple[str, ...]) -> tuple[dict[str, Any], str | None, dict[str, Any]]:
    """`_load`, plus the guard's own record: `{file, verdict, reason}`."""
    src = sources()
    path = src.file_for(names)
    data, err = _read_json(path)
    if err is not None:
        return {}, err, {"file": str(path), "verdict": "NOT MEASURED", "reason": err}
    verdict, reason = _target_guard(data, src)
    guard = {"file": str(path), "verdict": verdict, "reason": reason}
    return ({}, reason, guard) if verdict == "fail" else (data, None, guard)


def _load(names: tuple[str, ...]) -> tuple[dict[str, Any], str | None]:
    """A published file, target-matched. The pair every tool below starts from."""
    data, err, _guard = _load_guarded(names)
    return data, err


def _monitor_state_guarded() -> tuple[dict[str, Any], str | None, dict[str, Any]]:
    """The dash mirror's inner record. The file is `{"monitor": {...}}` — one envelope
    key — and every field T1 named (`summary`, `mypy`, `dead_code`, `wiring`) lives
    inside it, so the envelope is opened here once rather than at four call sites."""
    data, err, guard = _load_guarded(_MONITOR_FILES)
    inner = data.get("monitor", {})
    return (inner if isinstance(inner, dict) else {}), err, guard


def _monitor_state() -> tuple[dict[str, Any], str | None]:
    inner, err, _guard = _monitor_state_guarded()
    return inner, err


def _text_of(path: Path) -> str:
    """A log file's text, or empty when it is not there."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# cr_status
# ─────────────────────────────────────────────────────────────────────────────


def _launch_live() -> tuple[bool | None, str]:
    """Is a launch process of THIS tree live — launch.sh, or the gearbox it starts (the gearbox
    supervises every daemon until its teardown, so it outlives launch.sh's own steps)?
    `(None, why)` when the process table cannot be read: that is not a "no"."""
    tree = sources().tree.resolve()
    owned = (str(tree / "launch.sh"), str(tree / "system_scripts" / "gearbox.py"))
    try:
        table = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True,
                               timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"the process table could not be read ({e})"
    if table.returncode != 0:
        return None, f"the process table could not be read (ps exited {table.returncode})"
    relative: dict[str, tuple[str, str]] = {}
    for line in table.stdout.splitlines():
        pid, _, command = line.strip().partition(" ")
        argv = command.split() or [""]
        prog = Path(argv[0]).name
        # the program a shell or python runs is its first non-flag argument; a script exec'd by
        # its shebang is argv[0]. An editor or a pager holding launch.sh open runs no script.
        ran_by = prog in ("bash", "sh", "zsh") or prog.lower().startswith("python")
        script = next((a for a in argv[1:] if not a.startswith("-")), "") if ran_by else argv[0]
        if script in owned:
            return True, f"pid {pid}: {command[:160]}"
        if script and not Path(script).is_absolute():
            relative[pid] = (script, command)
    # `./launch.sh …` from inside the tree names no absolute path: its cwd says whose it is
    return _cwd_launch(relative, tree / "launch.sh")


def _cwd_launch(relative: dict[str, tuple[str, str]], launch_sh: Path) -> tuple[bool | None, str]:
    """Whether any process running a RELATIVE script path is running `launch_sh`, by its cwd
    (one `lsof` over every such pid)."""
    pids = ",".join(relative)
    try:
        listing = subprocess.run(["lsof", "-a", "-d", "cwd", "-p", pids, "-Fpn"], capture_output=True,
                                 text=True, timeout=15).stdout if pids else ""
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"the working directories of {len(relative)} process(es) could not be read ({e})"
    pid = ""
    for row in listing.splitlines():
        pid = row[1:] if row.startswith("p") else pid
        script, command = relative.get(pid, ("", ""))
        if row.startswith("n") and script and (Path(row[1:]) / script).resolve() == launch_sh:
            return True, f"pid {pid}: {command[:160]}"
    return False, "no CodeRadar launch or supervisor process is running"


def _as_float(value: Any) -> float | None:
    """A time stamp as launch_progress.py writes it — a float, or a float as a string."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _launch_state() -> dict[str, Any]:
    """The launch that is live on this tree, or the last one that ran, however it was started —
    read off `launch_progress.json`, the file every launch writes. `state` is one of
    LAUNCH_STATES; NOT MEASURED always carries its `reason`."""
    src = sources()
    path = src.file_for((_PROGRESS_FILE,))
    out: dict[str, Any] = {"state": "NOT MEASURED", "reason": None, "step": None,
                           "step_label": None, "overall": None, "live": None, "target": None,
                           "copy": None, "purpose": None, "started": None, "updated": None,
                           "seconds": None, "steps": [], "source": str(path)}
    live, live_why = _launch_live()
    out["live"] = live
    if not path.exists():
        run_dir = src.run_dir()
        log = run_dir / "launch.log" if run_dir is not None else None
        if log is not None and log.exists():
            said = "ALL GATES PASSED" if "ALL GATES PASSED" in _text_of(log) else "no ALL GATES PASSED line"
            out["reason"] = (f"{_PROGRESS_FILE} is absent; only the cr_watch log {log} is on record "
                             f"({said}) — which launch it belongs to is not measured")
        elif live:
            out["reason"] = f"{_PROGRESS_FILE} is absent while a launch process is live ({live_why})"
        elif live is None:
            out["reason"] = f"{_PROGRESS_FILE} is absent and {live_why}"
        else:
            out["state"] = "no launch"
            out["reason"] = f"{_PROGRESS_FILE} is absent and {live_why}"
        return out
    doc, err = _read_json(path)
    if err is not None or not isinstance(doc.get("stages"), dict):
        out["reason"] = err or f"{path} carries no `stages` record"
        return out
    stages: dict[str, Any] = doc["stages"]
    order = [k for k in (doc.get("order") or list(stages)) if isinstance(stages.get(k), dict)]
    for key in order:
        stage = stages[key]
        out["steps"].append({"step": key, "label": str(stage.get("label") or key),
                             "status": str(stage.get("status") or ""),
                             "detail": str(stage.get("detail") or ""),
                             "seconds": _as_float(stage.get("secs"))})
    choices = {m.group("key"): m.group("value")
               for m in _CHOICE_RE.finditer(str((stages.get("choices") or {}).get("detail") or ""))}
    out["target"] = choices.get("target")
    out["copy"] = choices.get("copy")
    out["purpose"] = choices.get("purpose")
    starts = [t for t in (_as_float(stages[k].get("started")) for k in order) if t is not None]
    out["started"] = min(starts) if starts else None
    out["updated"] = _as_float(doc.get("updated"))
    overall = str(doc.get("overall") or "")
    out["overall"] = overall

    if out["target"] is not None and src.target is not None \
            and Path(out["target"]).resolve() != Path(src.target).resolve():
        out["reason"] = (f"the last launch on this tree was for {out['target']} (overall "
                         f"{overall!r}), not {src.target} — this target's launch is not on record")
        return out

    def first(statuses: tuple[str, ...]) -> dict[str, Any] | None:
        return next((st for st in out["steps"] if st["status"] in statuses), None)

    if overall == "failed":
        bad = first(("fail",))
        out["state"] = "failed"
        if bad is not None:
            out["step"], out["step_label"] = bad["step"], bad["label"]
        out["reason"] = str(doc.get("detail") or (bad or {}).get("detail") or "")
    elif overall == "ready":
        out["state"] = "ready"
        if not live:
            out["reason"] = (f"every launch step passed; CodeRadar has since stopped ({live_why})" if live is False
                             else f"every launch step passed; whether CodeRadar still runs is not measured ({live_why})")
    elif overall in _PROGRESS_LIVE:
        now = first(("running",)) or first(("pending",))
        if now is not None:
            out["step"], out["step_label"] = now["step"], now["label"]
        if live:
            out["state"] = "running"
        else:
            out["reason"] = (f"{_PROGRESS_FILE} says {overall!r} at step "
                             f"{out['step'] or '?'} but {live_why} — "
                             + ("the launch ended without recording a verdict" if live is False
                                else "whether it still runs is not measured"))
    else:
        out["reason"] = f"{_PROGRESS_FILE} carries an unknown overall status {overall!r}"
    if out["state"] in ("ready", "failed") and out["started"] is not None and out["updated"] is not None:
        out["seconds"] = int(round(out["updated"] - out["started"]))
    if out["target"] is None and out["state"] != "NOT MEASURED":
        out["target_note"] = ("the launch record names no target (choices step not reached, or a "
                              "file from before 2026-09-30) — whose launch this is is not measured")
    return out


def _launch_stages(launch: dict[str, Any]) -> dict[str, Any]:
    """`{all_passed, seconds, gates:[{gate,status,seconds}], source}` for the launch `launch`
    (`_launch_state()`). `all_passed` is the launch file's verdict — True at `ready`, False at
    `failed`, None while running or when not measured. The per-gate lines come from the run's
    `launch.log` when that log was written by THIS launch (a cr_watch launch), else from the
    launch file's steps; a stale log from an earlier cr_watch launch is never read as this one's."""
    state = launch["state"]
    all_passed = True if state == "ready" else False if state == "failed" else None
    where = sources().run_dir()
    log_path = where / "launch.log" if where is not None else None
    started = launch.get("started")
    try:
        log_fresh = (log_path is not None and started is not None
                     and log_path.stat().st_mtime >= started - 2.0)
    except OSError:
        log_fresh = False
    return _gates_from_log(log_path, all_passed) if log_fresh and log_path is not None else {
        "all_passed": all_passed, "seconds": launch.get("seconds"), "source": _PROGRESS_FILE,
        "gates": [{"gate": st["step"], "status": st["status"].upper(), "seconds": st["seconds"]}
                  for st in launch.get("steps", [])]}


def _gates_from_log(log_path: Path, all_passed: bool | None) -> dict[str, Any]:
    """The per-gate lines of a cr_watch launch's own `launch.log`; `seconds` is the run's
    `gates passed after N s` line when `gate_budget.txt` carries it, else the per-gate sum."""
    log = _text_of(log_path)
    stages: list[dict[str, Any]] = []
    for m in _STAGE_RE.finditer(log):
        seconds = m.group("seconds")
        stages.append({
            "gate": m.group("gate"),
            "status": m.group("status"),
            "seconds": float(seconds) if seconds is not None else None,
        })
    total = sum(s["seconds"] for s in stages if s["seconds"] is not None)
    after = _PASSED_AFTER_RE.search(_text_of(log_path.parent / "gate_budget.txt"))
    return {
        "all_passed": all_passed,
        "seconds": int(after.group(1)) if after is not None else int(total),
        "source": "launch.log",
        "gates": stages,
    }


def _restarts() -> list[dict[str, Any]]:
    """The gearbox's own restart feed (FIX_52). Absent between runs — it is removed at
    teardown, and an empty list is the true answer then."""
    feed = _read_json_any(sources().tree / "system_scripts" / "gearbox_events.json")
    if isinstance(feed, list):
        return feed
    if isinstance(feed, dict):
        events = feed.get("events", feed.get("restarts", []))
        return events if isinstance(events, list) else []
    return []


def _health_now() -> dict[str, Any]:
    """The health port's own word, or `ok: false` with the reason in `status`."""
    url = sources().health_url()
    try:
        with urllib.request.urlopen(url, timeout=_HEALTH_WAIT_S) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # the port is down between runs; that is an answer, not a crash
        return {"ok": False, "url": url, "status": f"unreachable: {type(exc).__name__}"}
    state = body.get("status", "ok") if isinstance(body, dict) else "ok"
    return {"ok": state in ("ok", "healthy", "OK"), "url": url, "status": state}


#: Q2 / I-128 (session 8, 2026-09-21). `finished` answers `true`, `false` or THIS — the third
#: is not a failure to be finished, it is the absence of a measurement, and the two are told
#: apart because a release cannot be judged on an input nobody read.
NOT_MEASURED: str = "not measured"


def _finished_state(monitor: dict[str, Any], mirror: dict[str, Any]) -> dict[str, Any]:
    """Q5 / B7-5 — zero infractions · zero data-type issues · zero severed links.

    `monitor.summary.finished` is T4's to publish; while it is there it IS the answer
    (`finished_source: "mirror"`). Until then the owner-ruled formula is computed here
    (`finished_source: "computed"`): the counterfeit mirror's `summary.failed`, the dash
    mirror's `summary.mypy_errors`, and its `summary.severed_links`, all zero.
    Withheld rows never count: run 136's repairs 156 + no_vetted_fix 8 = 164 = `failed`,
    while `withheld` 85 is a disjoint list (T1's decision 2, verified again on run 137).

    Session 8 (I-128 / Q2): the answer is TRI-STATE — `true`, `false`, or `NOT_MEASURED`
    while any one of the three inputs is unread. Session 8 (I-127 / Q1): the severed input is
    the dash mirror's `severed_links`, which no longer counts an edge a leased repair explains.
    """
    m_summary = monitor.get("summary", {})
    n_summary = mirror.get("summary", {})
    if "finished" in m_summary:
        # Q2 (session 8, 2026-09-21): `finished` is TRI-STATE here. The mirror's own
        # `finished_inputs` already says which of the three gates was NOT MEASURED — an unrun
        # or file-less mypy scan (I-128), a counterfeit mirror not yet published. While any one
        # of them is NOT MEASURED the answer is `"not measured"`, never `true` and never `false`:
        # `false` is a verdict, and no verdict was reached. A mirror written before session 8
        # publishes no `finished_inputs` and reads exactly as it always did.
        inputs = m_summary.get("finished_inputs")
        gates = m_summary.get("finished_gates") or (list(inputs) if isinstance(inputs, dict) else [])
        unread = ([g for g in gates if inputs.get(g) is None] if isinstance(inputs, dict) else [])
        if unread:
            return {
                "finished": NOT_MEASURED,
                "finished_reason": str(m_summary.get("finished_reason")
                                       or "not measured: " + ", ".join(unread)),
                "finished_source": "mirror",
            }
        return {
            "finished": bool(m_summary.get("finished")),
            "finished_reason": str(m_summary.get("finished_reason", "published by the dash mirror")),
            "finished_source": "mirror",
        }
    # Q2: the same honesty on the computed path — a mypy count the mirror does not vouch for
    # (`mypy_ran false`, or `mypy_files_checked 0`) is not a measurement. A mirror that publishes
    # neither key is older than C5 and is read exactly as it was.
    mypy_errors = m_summary.get("mypy_errors")
    if ("mypy_ran" in m_summary and not m_summary.get("mypy_ran")) or \
       ("mypy_files_checked" in m_summary and not int(m_summary.get("mypy_files_checked") or 0)):
        mypy_errors = None
    unmet = []
    unread = []
    for value, said in ((n_summary.get("failed"), "infractions"),
                        (mypy_errors, f"data-type issues {ISSUES_SCOPE}"),   # M-20
                        (m_summary.get("severed_links"), "severed links")):
        if value is None:
            unread.append(f"{said}: not published yet")
        elif int(value) != 0:
            unmet.append(f"{int(value)} {said}")
    if unread:
        return {
            "finished": NOT_MEASURED,
            "finished_reason": "; ".join(unread + unmet),
            "finished_source": "computed",
        }
    return {
        "finished": unmet == [],
        "finished_reason": "; ".join(unmet) if unmet else "finished",
        "finished_source": "computed",
    }


#: I-149 / Q8 — the clause of `BUILDER_STATE.detail` that answers "how much did the tester
#: confirm". The Builder computes it from `rows[].tester.confirmed`, which a repair that WORKS
#: destroys (run 141): the row is retired, the flag goes with it, and the detail line reads zero.
_CONFIRMED_CLAUSE = re.compile(r"tester confirmed (?P<n>\d+) of (?P<of>\d+) solutions")


def _confirmed_from_ledger() -> int:
    """I-149 / Q8 (owner default: one source, the ledger). How many confirmations the confirmed
    ledger beside the return channel carries, counted ONCE per (digest, replace_span) — the
    append-only file's own rule, the last record per key winning, exactly as `cr_hand_back` and
    `gearbox.rule_outcomes` count it.

    Run 162 is why: `cr_status`'s detail line said *"tester confirmed 0 of 123 solutions"* while
    the same response's `rule_outcomes` showed 7 and `cr_hand_back` read `confirmed 7`. Nothing
    was lost — but `0 of 123` is the number a reader quotes, and it says no work was done. The
    ledger is the one source: it outlives the rows, and a confirmation is in it or it did not
    happen. `confirmed_joined` stays `cr_hand_back`'s own field and is not touched here.
    """
    from .write_tools import _ledger_path
    builder, _ = _load(_BUILDER_FILES)
    channel = builder.get("return_channel")
    if not isinstance(channel, str) or not channel:
        return 0
    try:
        text = Path(_ledger_path(channel)).read_bytes().decode("utf-8", "replace")
    except OSError:
        return 0
    keys: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            doc = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("digest"):
            keys.add((str(doc.get("digest")), str(doc.get("replace_span") or "")))
    return len(keys)


def _detail_quoting_ledger(detail: str, confirmed: int) -> str:
    """The Builder's own detail line with its ONE unreliable clause re-quoted from the ledger.
    Every other word the daemon wrote is carried through untouched, and the verbatim line is
    published beside this one as `detail_builder`, so nothing is edited away silently."""
    match = _CONFIRMED_CLAUSE.search(detail or "")
    if match is None or int(match.group("n")) >= confirmed:
        return detail
    return (detail[: match.start()]
            + f"tester confirmed {confirmed} of {match.group('of')} solutions"
            + detail[match.end():])


def cr_status() -> dict[str, Any]:
    builder, b_err, g_builder = _load_guarded(_BUILDER_FILES)
    monitor, _, g_monitor = _monitor_state_guarded()
    mirror, _, g_noai = _load_guarded(_NOAI_FILES)
    circuit, _, g_circuit = _load_guarded(_CIRCUIT_FILES)
    cadence = circuit.get("scan_cadence", {})
    # I-149 / Q8: the ledger's number, read before the detail line is quoted.
    from_ledger = _confirmed_from_ledger()
    launch = _launch_state()   # R5: any launch, however started
    detail_builder = str(builder.get("detail", ""))
    out: dict[str, Any] = {
        "phase": str(builder.get("phase", "")),
        "detail": _detail_quoting_ledger(detail_builder, from_ledger),
        "cycle": int(builder.get("cycle", 0)),
        "target": str(builder.get("target_repo", sources().target or "")),
        "repo_id": str(builder.get("repo_id", sources().repo_id or "")),
        "launch": launch,
        "gates": _launch_stages(launch),
        "target_guard": {"builder": g_builder, "monitor": g_monitor, "noai": g_noai,
                         "circuit": g_circuit},
        "band": {
            "cadence": cadence.get("_summary", {}) if isinstance(cadence, dict) else {},
            "restarts": _restarts(),
            "runners": circuit.get("test_runners", {}),
        },
        "health": _health_now(),
        "summary": monitor.get("summary", {}),
        "infractions": mirror.get("summary", {}),
        "error": b_err,
    }
    # B9 (ruling Q3, 2026-09-20): the per-rule record beside `finished`. The counterfeit mirror's
    # one writer computes it each cycle from the confirmed ledger and the return channel; nothing
    # is derived here. An older mirror carries no such block and answers `{}` — the tool never
    # invents a count it was not published.
    out["rule_outcomes"] = dict(mirror.get("summary", {}).get("rule_outcomes") or {})
    # Session 8 (I-127 / Q1, I-128 / Q2) — the `finished` inputs, at the top level where the
    # verdict is, ADDITIVE and republished from the dash mirror exactly as it wrote them. Nothing
    # is computed here: a mirror that does not carry a key answers the not-measured shape for it
    # (`severed_by_repair` 0, `mypy_rc` null, `mypy_files_checked` 0) rather than an invention.
    _m = monitor.get("summary", {})
    out["severed_by_repair"] = int(_m.get("severed_by_repair") or 0)
    out["mypy_ran"] = bool(_m.get("mypy_ran"))
    out["mypy_rc"] = _m.get("mypy_rc")
    out["mypy_files_checked"] = int(_m.get("mypy_files_checked") or 0)
    # Session 10 (I-149 / Q8): the ledger's number, and the daemon's own sentence verbatim.
    out["confirmed_from_ledger"] = from_ledger
    out["detail_builder"] = detail_builder
    out.update(_finished_state(monitor, mirror))
    out["run"], out["snapshot"] = run_and_snapshot(out.get("target") or None)
    # Fix plan 2026-10-23 C1: the open count, first — a seat that stops after page 1 of
    # cr_infractions still sees how many rows are open and how many pages hold them.
    out["open_findings"], out["open_findings_by"] = open_findings_of(mirror)
    try:
        out["infraction_pages"] = int(cr_infractions(page=1).get("pages") or 0)
    except Exception as e:  # noqa: BLE001 — a page count never fails the status answer
        out["infraction_pages"] = None
        out["error"] = out["error"] or f"infraction_pages NOT MEASURED — {type(e).__name__}: {e}"
    # C4: which checkers ran, which were never asked for, and naming drift's reading.
    out["trackers_ran"], out["trackers_not_requested"], out["naming_drift"] = tracker_coverage(circuit, monitor)
    # C3: the dot-directories whose .py files are IN the scan (`.venv`, `venv`, `node_modules`,
    # `.git`, `__pycache__` are skipped by name since 2026-10-23; any other dot-dir is scanned).
    out["dot_dirs_scanned"] = _dot_dirs_scanned(out.get("target") or "")
    return out


def open_findings_of(mirror: dict[str, Any]) -> tuple[int, dict[str, int]]:
    """Fix plan 2026-10-23 C1 / D3: the rows still open on the counterfeit mirror — `repairs` +
    `no_vetted_fix`, the two lists `finished` counts (`failed == repairs + no_vetted_fix`; withheld
    rows never count). The breakdown carries `withheld` too, so the headline hides nothing."""
    repairs = len(mirror.get("repairs") or []) if isinstance(mirror, dict) else 0
    nvf = len(mirror.get("no_vetted_fix") or []) if isinstance(mirror, dict) else 0
    withheld = len(mirror.get("withheld") or []) if isinstance(mirror, dict) else 0
    return repairs + nvf, {"repairs": repairs, "no_vetted_fix": nvf, "withheld": withheld}


#: The checkers a launch can choose (`cr_watch(trackers=…)`); naming drift and pytest are permanent.
CHOOSABLE_TRACKERS: tuple[str, ...] = ("io", "mypy", "crc", "vulture")


def tracker_coverage(circuit: dict[str, Any], monitor: dict[str, Any]) -> tuple[list[str], list[str], str]:
    """Fix plan 2026-10-23 C4: `(trackers_ran, trackers_not_requested, naming_drift)` off the circuit
    state's `trackers` block. A chosen tracker whose tool failed is in `not_measured` and so NOT in
    `trackers_ran`; a tracker the launch never named is `not_requested` — neither is a zero."""
    block = circuit.get("trackers", {}) if isinstance(circuit, dict) else {}
    block = block if isinstance(block, dict) else {}
    chosen = [t for t in (block.get("chosen") or []) if t in CHOOSABLE_TRACKERS]
    unmeasured = block.get("not_measured") or {}
    ran = [t for t in chosen if t not in unmeasured]
    not_requested = [t for t in CHOOSABLE_TRACKERS if t not in chosen]
    _block, why = naming_drift_reading(circuit if isinstance(circuit, dict) else {},
                                       monitor if isinstance(monitor, dict) else {})
    return ran, not_requested, ("measured" if why is None else f"NOT MEASURED — {why}")


def _dot_dirs_scanned(target: str) -> list[str] | None:
    """Fix plan 2026-10-23 C3: the repo-relative dot-directories holding at least one .py file the
    scan reads, by the one walk the daemons use (`scan_scope.dot_dirs_in_scope`). None when there
    is no target directory to walk."""
    if not target or not Path(target).is_dir():
        return None
    try:
        from system_scripts import scan_scope
        return scan_scope.dot_dirs_in_scope(Path(target))
    except Exception:  # noqa: BLE001 — a listing never fails the status answer
        return None


# ─────────────────────────────────────────────────────────────────────────────
# cr_infractions
# ─────────────────────────────────────────────────────────────────────────────


def _target_dir() -> Path | None:
    """The repo under watch, as a path. `cr_infractions` reads the LIVE file at this root to
    answer `replace_span_live` (I-148 a); between runs there is no target and no live span."""
    target = sources().target
    return Path(target) if target else None


#: B6 (2026-10-01, Q-H4-11 / Q-H2-6): the reason a rewriter row reads `review` when its diff did
#: NOT render at the live site. Same head as `APPLY_REVIEW_REASON` ("no diff rendered at this
#: site") so a seat filtering on the phrase sees both; the tail says why nothing rendered.
APPLY_NOT_RENDERED_REASON: str = "no diff rendered at this site"

#: The render memo: one in-memory render per (file bytes, row). Keyed on the file's stat and the
#: row's own bytes so an edit to the file re-renders and a repeat read is free (the dashboard
#: calls `apply_verdict` on every tick; `cr_infractions` on every page).
_RENDER_MEMO: dict[tuple[Any, ...], tuple[str, str, bool]] = {}
_RENDER_MEMO_CAP = 4096


def _render_at_live_site(target: Path, rel: str, span_live: str, before_code: str,
                         after_code: str) -> tuple[str, str, bool]:
    """Does a CONCRETE diff render at `span_live` off the file as it stands NOW? The same
    arithmetic `write_tools.cr_apply` renders with (§C.4: the live span's segment → `after_code`
    through `difflib.unified_diff`), minus the `patch --dry-run` self-check — this module writes
    nothing, not even a temp copy, and a diff rendered from the file's own bytes applies to those
    bytes by construction. `cr_apply` stays the authority at apply time; this is the ROW's word.

    Answers `(apply, apply_reason, rendered)`: `("yes", "", True)` only when a non-empty diff was
    rendered; `("review", "<APPLY_NOT_RENDERED_REASON> — <why>", False)` otherwise. Memoised on
    the file's stat and the row's bytes.
    """
    from .write_tools import _parse_span
    path = target / rel
    try:
        stat = path.stat()
        key: tuple[Any, ...] = (str(path), stat.st_mtime_ns, stat.st_size, span_live,
                                hashlib.sha1(before_code.encode("utf-8")).hexdigest(),
                                hashlib.sha1(after_code.encode("utf-8")).hexdigest())
    except OSError as e:
        return "review", f"{APPLY_NOT_RENDERED_REASON} — {type(e).__name__} reading {rel}", False
    hit = _RENDER_MEMO.get(key)
    if hit is not None:
        return hit
    verdict = _render_uncached(path, rel, span_live, after_code, _parse_span)
    if len(_RENDER_MEMO) >= _RENDER_MEMO_CAP:
        _RENDER_MEMO.clear()
    _RENDER_MEMO[key] = verdict
    return verdict


def _render_uncached(path: Path, rel: str, span_live: str, after_code: str,
                     parse_span: Any) -> tuple[str, str, bool]:
    import difflib
    if not after_code:
        return "review", f"{APPLY_NOT_RENDERED_REASON} — the row carries no after_code", False
    parsed = parse_span(span_live)
    if parsed is None:
        return "review", f"{APPLY_NOT_RENDERED_REASON} — unreadable span {span_live!r}", False
    _, start, end = parsed
    try:
        current = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError) as e:
        return "review", f"{APPLY_NOT_RENDERED_REASON} — {type(e).__name__} reading {rel}", False
    if start < 1 or end > len(current) or start > end:
        return ("review", f"{APPLY_NOT_RENDERED_REASON} — span L{start}-L{end} is outside the "
                f"file's {len(current)} lines", False)
    segment = current[start - 1: end]
    after_lines = after_code.splitlines(keepends=True)
    if segment and after_lines and segment[-1].endswith("\n") and not after_lines[-1].endswith("\n"):
        after_lines[-1] += "\n"
    diff = "".join(difflib.unified_diff(segment, after_lines, fromfile=span_live, tofile=span_live))
    if not diff:
        return ("review", f"{APPLY_NOT_RENDERED_REASON} — the file at this span already reads as "
                "after_code", False)
    return "yes", "", True


def apply_verdict(row: dict[str, Any], *, has_solution: bool,
                  target: Path | None) -> dict[str, Any]:
    """THE ONE apply verdict — read by `cr_infractions` / `cr_row` (`_row_record`) and by the
    dashboard's repair rows (`proof_dashboard._finding_rows`), so the two cannot disagree about
    what a row SAYS about its repair. B6 (2026-10-01), Q-H4-11 / Q-H2-6.

    `row` is a mirror row or a BUILDER_STATE row (both carry file · function · line · line_end ·
    replace_span · before_code · after_code · solution_kind · withheld_by · status). Answers
    `{apply, apply_reason, replace_span_live, span_current, rendered}`:

      * `"no"`    — no solution, or the Builder published the row NOT SELECTABLE (I-152). The
                    reason is the row's own: its `status` / `withheld`, or the prescription
                    seam's sentences (`gate_withheld`), the same words `cr_apply` answers
                    `kind "none"` with.
      * `"review"`— a prescribed shape (`APPLY_REVIEW_REASON`, Fix A), OR a rewriter whose diff
                    did NOT render at the live site: no target under watch (between runs), an
                    unreadable file, a span outside the file, no after_code, or no change.
                    `rendered` is False and `apply_reason` says which.
      * `"yes"`   — ONLY when a concrete, non-empty diff rendered at `replace_span_live` off the
                    file as it stands now (`_render_at_live_site`). Never inferred from the kind.

    `replace_span_live` / `span_current` are I-148 (a)'s marks, unchanged: the live span by
    `write_tools.live_span_of`, the recorded span when none could be read, and `span_current`
    null (not measured) in that case.
    """
    from .write_tools import live_span_of
    file_name = str(row.get("file", ""))
    line = row.get("line", 0)
    line_end = row.get("line_end", line)
    span = row.get("replace_span")
    recorded = span if span is not None else f"{file_name}:L{line}-L{line_end}"
    before_code = str(row.get("before_code") or "")
    live = live_span_of(target, file_name, str(row.get("function") or ""),
                        int(line or 0), before_code)
    span_live = live if live is not None else recorded
    withheld_by = row.get("withheld_by")
    not_selectable = str(withheld_by or "") == NOT_SELECTABLE_BY
    rendered = False
    if not has_solution or not_selectable:
        apply = "no"
        reason = str(row.get("status") or row.get("withheld") or "")
        if not_selectable:
            sentences = [str(v) for v in (row.get("gate_withheld") or {}).values() if v]
            reason = "; ".join([NOT_SELECTABLE_REASON] + sentences)
    elif str(row.get("solution_kind") or "rewriter") == "prescribed":
        apply, reason = "review", APPLY_REVIEW_REASON
    elif target is None:
        apply = "review"
        reason = f"{APPLY_NOT_RENDERED_REASON} — no target under watch (between runs there is no live site)"
    else:
        apply, reason, rendered = _render_at_live_site(
            target, file_name, span_live, before_code, str(row.get("after_code") or ""))
    return {
        "apply": apply,
        "apply_reason": reason,
        "replace_span_live": span_live,
        "span_current": None if live is None else (live == recorded),
        "rendered": rendered,
    }


def _row_record(row: dict[str, Any], *, has_solution: bool) -> dict[str, Any]:
    """One mirror row in the shape T1 fixed. The mirror publishes no id, so it is
    computed here — `<file>::<function>::<line>`, BUILDER_STATE's own `row_key`.
    A withheld row publishes no span and no infraction text; those read null rather
    than being invented, and its `replace_span` is the mirror's own `<file>:L<a>-L<b>`.

    ── Session 10, I-148 (a) / Q3 — THE MARK. `replace_span` is half the Builder's join key and
    cannot be dropped, so it is MARKED instead: `replace_span_live` is read off the LIVE file at
    read time by the rule `cr_apply` re-bases with (`write_tools.live_span_of` — one rule, one
    spelling, so the two tools cannot disagree about where a row's bytes are), and `span_current`
    says whether the two name the same lines. Run 162's `_termui_impl.py::open_url` published
    L804-L868 — matching neither the original L799-L866 nor the file on disk — beside a correct
    L802-L869, and a client that rendered against the recorded field would have rewritten 66
    lines it had never read. The contract the README now states: render against
    `replace_span_live` ONLY.

    ── Session 10, I-152 / Q1 — THE APPLY STATE. `selected_role`, `apply`, `withheld_by` and
    `gate_withheld_reasons` ride on the published row, so a seat can tell an offer it can act on
    from an honest smell with no applyable candidate. Additive: no row is flipped into the
    withheld bucket, and `failed == repairs + no_vetted_fix` is unmoved.

    ── Fix A (owner ruling 2026-09-28, run 187) — THE ELIGIBILITY GUARD. `apply "yes"` means the
    row's solution renders a CONCRETE diff at the site (a rewriter; `cr_apply` answers
    `kind "diff"`). A prescribed shape (`solution_kind "prescribed"`: the rule's template, which
    `cr_apply` answers as `kind "shape"`, `diff null`) has never touched the site, so no gate or
    measurement has vouched for it there: it publishes `apply "review"` with `apply_reason`,
    stays visible, and ranks after every `yes` row (`_ranked`). Label only — the row is still in
    `repairs`, so the bucket identity is unmoved.
    """
    file_name = str(row.get("file", ""))
    line = row.get("line", 0)
    line_end = row.get("line_end", line)
    span = row.get("replace_span")
    recorded = span if span is not None else f"{file_name}:L{line}-L{line_end}"
    withheld_by = row.get("withheld_by")
    not_selectable = str(withheld_by or "") == NOT_SELECTABLE_BY
    # B6 (2026-10-01): the verdict is RENDERED at the live site by the one function the dashboard
    # reads too (`apply_verdict`), never inferred from `solution_kind`.
    verdict = apply_verdict(row, has_solution=has_solution, target=_target_dir())
    return {
        "id": row_id(row),
        "file": file_name,
        "function": row.get("function"),
        "line": line,
        "line_end": line_end,
        "replace_span": recorded,
        # The span to render against. When no live span could be read the recorded span is all
        # there is, and `span_current` says it was not measured rather than vouching for it.
        "replace_span_live": verdict["replace_span_live"],
        "span_current": verdict["span_current"],
        "finding_lines": row.get("finding_lines", []),
        "rule_ids": row.get("rule_ids", []),
        "infraction": row.get("infraction"),
        "solution_kind": row.get("solution_kind"),
        "digest": row.get("digest"),
        "has_solution": has_solution,
        "status": row.get("status"),
        "withheld": row.get("withheld"),
        "species": row.get("species"),
        # I-152 / Q1: the apply state, published beside the smell rather than inferred from it.
        "selected_role": "" if not_selectable else str(row.get("selected_role") or ""),
        "apply": verdict["apply"],
        "apply_reason": verdict["apply_reason"],
        "withheld_by": withheld_by,
        "gate_withheld_reasons": dict(row.get("gate_withheld") or {}),
        # ND2 (2026-10-01, naming-drift plan §D) — ADDITIVE, the 09-21 channel contract: `rule_id` is the
        # row's one rule id (null when it carries several — read `rule_ids`); `variant` is the repair
        # variant as `write_tools` spells it on a lease (the row's `selected_role`). A naming-drift row
        # publishes the same two keys with its rule and its tier (`_naming_drift_records`).
        "rule_id": _one_rule_id(row.get("rule_ids")),
        "variant": "" if not_selectable else str(row.get("selected_role") or ""),
    }


def _one_rule_id(rule_ids: Any) -> str | None:
    """The row's one rule id, or null when the row carries none or several."""
    ids = [str(r) for r in rule_ids] if isinstance(rule_ids, list) else []
    return ids[0] if len(ids) == 1 else None


# ─────────────────────────────────────────────────────────────────────────────
# naming drift — the permanent data type tracker (ND2, 2026-10-01, plan §D)
# ─────────────────────────────────────────────────────────────────────────────

#: The §D block's key — in circuit_state.json and, beside `path_hacks`, in the dash mirror's `monitor`
#: envelope (circuit_daemon `write_repo_mirror`). Permanent: never `not_run`.
NAMING_DRIFT = "naming_drift"
#: The rule id every naming-drift row carries (rule_dispositions.json: `no_fix_by_design`).
NAMING_DRIFT_RULE = "NAMING_DRIFT"
#: Why the block is NOT MEASURED when it is published with `ran: false` and names no reason itself.
NAMING_DRIFT_NOT_RAN = "launch scan has not completed — the baseline is not built yet"
#: Why no naming-drift row is ever `apply "yes"`: the developer renames, CodeRadar never does.
NAMING_DRIFT_APPLY_REASON = ("observation only — the developer renames; CodeRadar never edits the repo "
                             "(rule_dispositions NAMING_DRIFT = no_fix_by_design)")


def naming_drift_reading(circuit: dict[str, Any], monitor: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """The published `naming_drift` block and why it is NOT MEASURED (None only when it says `ran: true`).
    circuit_state.json is read first, the dash mirror's `monitor` envelope second; an absent block is
    NOT MEASURED with that reason — never an empty measurement, never 0."""
    block: dict[str, Any] = {}
    for src in (circuit, monitor):
        found = src.get(NAMING_DRIFT) if isinstance(src, dict) else None
        if isinstance(found, dict):
            block = found
            break
    if not block:
        return {}, "not published — no `naming_drift` block in circuit_state.json or the dash mirror"
    if not block.get("ran"):
        return block, str(block.get("not_measured_reason") or NAMING_DRIFT_NOT_RAN)
    return block, None


def _naming_drift_stamped(block: dict[str, Any], why: str | None) -> dict[str, Any]:
    """The block as `cr_data_types` publishes it: the §D fields as written, `status` stamped the way
    `circuit_daemon._tracker_status` stamps every tracker — "measured", or "NOT MEASURED — <why>"
    with every count null."""
    if why is not None:
        return {"status": f"NOT MEASURED — {why}", "ran": False, "groups": None, "pre_existing": None,
                "new": None, "by_tier": {"T1": None, "T2": None, "T3": None}, "accepted": None,
                "scanned_files": None, "baseline_at": None, "rows": []}
    return {**block, "status": "measured"}


def _naming_drift_records(circuit: dict[str, Any], monitor: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    """One `cr_infractions` record per naming-drift group, at the group's first site, in `_row_record`'s
    shape plus the additive keys (`rule_id` NAMING_DRIFT, `variant` = tier, `naming_drift` = the §D row).
    The second value is the status line the answer carries: NOT MEASURED with its reason before the launch
    scan has completed (then no record is invented), else how many groups became rows."""
    block, why = naming_drift_reading(circuit, monitor)
    if why is not None:
        return [], f"NOT MEASURED — {why}"
    records: list[dict[str, Any]] = []
    unsited = 0
    for row in block.get("rows") or []:
        sites = [s for s in (row.get("sites") or []) if isinstance(s, dict) and s.get("file")]
        if not sites:
            unsited += 1
            continue
        first = sites[0]
        file_name = str(first["file"])
        line = int(first.get("line") or 0)
        spelling = str(row.get("spelling") or "")
        tier = str(row.get("tier") or "")
        kind = str(row.get("kind") or "")
        span = f"{file_name}:L{line}-L{line}"
        records.append({
            "id": f"{file_name}::{spelling}::{line}",
            "file": file_name,
            "function": spelling,
            "line": line,
            "line_end": line,
            "replace_span": span,
            "replace_span_live": span,
            "span_current": None,            # no live read: a naming-drift row is never rewritten
            "finding_lines": sorted({int(s.get("line") or 0) for s in sites if str(s.get("file")) == file_name}),
            "rule_ids": [NAMING_DRIFT_RULE],
            "infraction": (f"naming drift {tier} ({kind.replace('_', '-')}): `{spelling}` spells the same "
                           f"name as `{row.get('canonical')}` (key `{row.get('key')}`) — "
                           f"{len(sites)} site(s)"),
            "solution_kind": None,
            "digest": None,
            "has_solution": False,
            "status": kind,
            "withheld": False,
            "species": NAMING_DRIFT,
            "selected_role": "",
            "apply": "no",
            "apply_reason": NAMING_DRIFT_APPLY_REASON,
            "withheld_by": None,
            "gate_withheld_reasons": {},
            "rule_id": NAMING_DRIFT_RULE,
            "variant": tier,
            "naming_drift": {k: row.get(k) for k in ("key", "canonical", "spelling", "tier", "kind",
                                                     "sites", "first_seen")},
        })
    status = f"measured — {len(records)} group(s) published as rows (rule {NAMING_DRIFT_RULE})"
    if unsited:
        status += f"; {unsited} group(s) name no site and are not rows"
    return records, status


def _pages_by_file(records: list[dict[str, Any]], page_size: int) -> list[list[dict[str, Any]]]:
    """Q9 / T1's decision 9: the unit is rows at `page_size`, but a page never splits a
    file. A file keeps the position of its FIRST row in the mirror, and every row of that
    file rides with it — the mirror publishes `repairs[]` then `no_vetted_fix[]`, so one
    file's rows are not contiguous there, and grouping only consecutive rows would split
    such a file across two pages. A file with more rows than a page is a page of its own.
    """
    by_file: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        by_file.setdefault(rec["file"], []).append(rec)
    pages: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for rows in by_file.values():
        if current and len(current) + len(rows) > page_size:
            pages.append(current)
            current = []
        current = current + rows
    if current:
        pages.append(current)
    return pages


def _ranked(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fix A: rank by apply state — `yes`, then `review`, then `no` (`APPLY_STATES` order). A page
    never splits a file (Q9), so the sort is stable and file-aware: inside a file its `yes` rows
    come first and its `review` rows after them; files are ordered by their best state, then by
    mirror position. On a one-file target every `review` row sits below every `yes` row."""
    tier = {state: i for i, state in enumerate(APPLY_STATES)}
    best: dict[str, int] = {}
    first: dict[str, int] = {}
    for i, rec in enumerate(records):
        t = tier.get(rec["apply"], len(APPLY_STATES))
        best[rec["file"]] = min(best.get(rec["file"], t), t)
        first.setdefault(rec["file"], i)
    return sorted(records, key=lambda r: (best[r["file"]], first[r["file"]],
                                          tier.get(r["apply"], len(APPLY_STATES))))


def cr_infractions(file: str | None = None, rule: str | None = None,
                   withheld: bool | None = None, has_solution: bool | None = None,
                   page: int = 1, page_size: int | None = None) -> dict[str, Any]:
    mirror, err = _load(_NOAI_FILES)
    size = PAGE_SIZE_DEFAULT if page_size is None else int(page_size)
    if err is not None:
        return {"rows": [], "page": page, "page_size": size, "pages": 0, "total": 0, "done": True,
                "files": [], "last_scan": "", "error": err}

    records: list[dict[str, Any]] = []
    # ND2 (2026-10-01, plan §D): the naming-drift tracker's groups ride here as rows (rule NAMING_DRIFT,
    # tier in `variant`) beside the counterfeit mirror's — never withheld, never with a solution. Before
    # the launch scan has completed none is invented and `naming_drift_status` says NOT MEASURED.
    circuit, _c_err = _load(_CIRCUIT_FILES)
    monitor, _m_err = _monitor_state()
    drift_rows, drift_status = _naming_drift_records(circuit if _c_err is None else {},
                                                     monitor if _m_err is None else {})
    if withheld is not True:
        for row in mirror.get("repairs", []):
            records.append(_row_record(row, has_solution=True))
        for row in mirror.get("no_vetted_fix", []):
            records.append(_row_record(row, has_solution=False))
        records.extend(drift_rows)
    if withheld is True:
        for row in mirror.get("withheld", []):
            records.append(_row_record(row, has_solution=False))

    if file is not None:
        records = [r for r in records if r["file"] == file]
    if rule is not None:
        records = [r for r in records if rule in (r["rule_ids"] or [])]
    if has_solution is not None:
        records = [r for r in records if r["has_solution"] is has_solution]

    pages = _pages_by_file(_ranked(records), size)
    index = page - 1
    rows = pages[index] if index >= 0 and index < len(pages) else []
    files: list[str] = []
    for rec in rows:
        if files[-1:] != [rec["file"]]:
            files.append(rec["file"])
    return {
        "rows": rows,
        "page": page,
        "page_size": size,
        "pages": len(pages),
        "total": len(records),
        # Fix plan 2026-10-23 C1: the field that replaces the guess — true only on the last page
        # (or when there is none). There is still no `has_more`; stop paging when `done` is true.
        "done": index >= len(pages) - 1,
        "files": files,
        "last_scan": str(mirror.get("last_scan", "")),
        "naming_drift_status": drift_status,
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# cr_row
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_key(rows: dict[str, Any], given: str) -> tuple[str, str, str]:
    """§C.5 of the session-7 drift packet — the TOLERANT ID, id resolution only, spelled here
    for `BUILDER_STATE.json`'s `rows` the way `write_tools._resolve_row` spells it for the
    mirror's buckets. Returns `(key, resolved_by, error)`:

      * `html.unescape` FIRST — I-137: `src/click/_winconsole.py::&lt;module&gt;::0` returned
        not found where the literal `<module>` worked, so any client that round-trips ids
        through a markup layer lost EVERY module-scope row;
      * the exact key → `row`;
      * else a UNIQUE `(file, function)` match among the live keys → `function` (I-130: an
        earlier edit to the same file shifts the rows below it, so the LINE of an id a client
        is holding goes stale while its file and function do not);
      * two or more candidates → refused WITH THE CANDIDATES NAMED. Never guessed.
    """
    plain = html.unescape(given or "")
    if plain in rows:
        return plain, "row", ""
    bits = plain.split("::")
    if len(bits) != 3:
        return "", "", (f"no row {given!r} — the id is `<file>::<function>::<line>`, as "
                        "`cr_infractions` returns it")
    rel, func, _ = bits
    cands = sorted(k for k in rows if k.split("::")[:2] == [rel, func])
    if len(cands) == 1:
        return cands[0], "function", ""
    if len(cands) > 1:
        return "", "", (f"{len(cands)} rows share this file and function and the exact id is "
                        f"not among them — say which: {', '.join(cands)}")
    return "", "", (f"no row {plain!r} — tried the exact id, then (file, function) "
                    f"({rel!r}, {func!r}); the id is `<file>::<function>::<line>`, as "
                    "`cr_infractions` returns it")


def gate_verdicts(ledger: str | Path) -> dict[str, list[dict[str, Any]]]:
    """The gate ledger (`gate_<repo_id>.jsonl`, one record per stage, written by the Builder and kept
    for the whole launch) read back per row: `{row_key: [{attempt_id, status, stage, verdict, detail,
    at, stages}]}`, attempts in the order the gate first judged them. `status` is `failed` (a stage
    failed; a stage-3 fail is reverted), `deferred`, `integrated` (stage 2 passed and nothing failed:
    the repair is applied), else the last verdict. ONE reading for `cr_row` on a closed row and for
    `cr_stop`'s account of the gate's own writes."""
    from .write_tools import _read_jsonl
    records = [r for r in _read_jsonl(str(ledger)) if r.get("row_key") and r.get("attempt_id")]
    out: dict[str, list[dict[str, Any]]] = {}
    for key, attempt_id in dict.fromkeys((str(r["row_key"]), str(r["attempt_id"])) for r in records):
        stages = [{"stage": r.get("stage", ""), "verdict": r.get("verdict", ""), "detail": r.get("detail", ""),
                   "at": r.get("at", "")}
                  for r in records if str(r["row_key"]) == key and str(r["attempt_id"]) == attempt_id]
        failed = next((s for s in stages if s["verdict"] == "fail"), None)
        last = failed or stages[-1]
        status = ("failed" if failed else "deferred" if last["verdict"] == "deferred"
                  else "integrated" if any(s["stage"] == "integrates" and s["verdict"] == "pass" for s in stages)
                  else last["verdict"])
        out.setdefault(key, []).append({"attempt_id": attempt_id, "status": status, **last, "stages": stages})
    return out


def _closed_from_gate(channel: Any, given: str) -> tuple[dict[str, Any] | None, str, str]:
    """Problem 5 (2026-10-10, live): an attempt that integrates closes its row on the next rescan,
    2–8 s later, and the row — with the `attempts` field that said "integrated" — leaves
    BUILDER_STATE.json. The gate ledger beside the return channel still holds every verdict, so a
    closed row is answered from it. Returns `(closed, resolved_by, resolved_id)`; `closed` is None
    when the ledger has no record for the id."""
    from .write_tools import _beside_channel, _read_jsonl, attempts_path
    if not isinstance(channel, str) or not channel:
        return None, "", ""
    ledger = _beside_channel(channel, "gate_")
    by_row = gate_verdicts(ledger)
    key, how, _ = _resolve_key(by_row, given)
    if not key:
        return None, "", ""
    numbers = {str(a.get("attempt_id")): a.get("attempt") for a in _read_jsonl(attempts_path(channel))
               if a.get("row_key") == key}
    attempts = [{"attempt_id": a["attempt_id"], "attempt": numbers.get(a["attempt_id"]), **a} for a in by_row[key]]
    integrated = [a for a in attempts if a["status"] == "integrated"]
    closed = {"row_key": key, "ledger": ledger, "attempts": attempts,
              "why": ("the row is closed — it is no longer on the Builder's board; "
                      + (f"attempt {integrated[-1]['attempt_id']} integrated at {integrated[-1]['at']} "
                         "and the rescan closed the row" if integrated
                         else "no attempt on it integrated")
                      + "; every gate verdict below is read from the gate ledger")}
    return closed, how, key


def cr_row(id: str) -> dict[str, Any]:
    builder, err = _load(_BUILDER_FILES)
    if err is not None:
        return {"row": None, "return_channel": None, "resolved_by": "", "resolved_id": "",
                "closed": None, "error": err}
    rows = builder.get("rows", {})
    rows = rows if isinstance(rows, dict) else {}
    channel = builder.get("return_channel")
    key, how, problem = _resolve_key(rows, id)
    row = rows.get(key) if key else None
    if row is None:
        closed, how, key = _closed_from_gate(channel, id)
        if closed is not None:
            return {"row": None, "return_channel": channel, "resolved_by": how, "resolved_id": key,
                    "closed": closed, "error": None}
        return {"row": None, "return_channel": channel, "resolved_by": "", "resolved_id": "",
                "closed": None, "error": problem or f"no row {id!r}"}
    return {"row": row, "return_channel": channel, "resolved_by": how, "resolved_id": key,
            "closed": None, "error": None}


# ─────────────────────────────────────────────────────────────────────────────
# cr_wiring
# ─────────────────────────────────────────────────────────────────────────────


def _edge_state(source: str, target: str, severed: set[tuple[str, str]],
                loaded: dict[str, bool], tested: set[str] | None = None) -> str:
    """Q7 / T1's decision 5. `severed` when the pair is in `severed_links` — and only
    then is `severed_since` non-null. Otherwise `live` when the edge's TARGET is proven
    loaded at runtime (`nodes[].runtime_loaded`), else `possible`: an import edge the
    dash draws indigo, real but not yet proven by a flow. I-198: `tested` is non-empty only
    on a target with no app entry proof — there an edge whose TARGET the runner loaded reads
    `live_via_tests`, its own state, never `live`."""
    if (source, target) in severed:
        return "severed"
    if loaded.get(target) is True:
        return "live"
    if tested and target in tested:
        return "live_via_tests"
    return "possible"


def _live_why(nodes: list[Any], circuit: dict[str, Any], counts: dict[str, int]) -> str | None:
    """MCPW-D O4b (run 180): a bare `live 0` read as "nothing ran" after a green pytest run. The
    live state is the APP's proof only (`runtime_loaded`, an entry run through the wrapper); a
    runner's import coverage marks `runtime_loaded_via: runner` — a warning, never a pass (Item
    10) — so a library proven only by pytest reads 0 by design. Null whenever live > 0."""
    if counts.get("live"):
        return None
    if not circuit.get("edges"):
        return "0 live: the graph has no import edges between target modules"
    via = [str(n.get("runtime_loaded_via") or "") for n in nodes if isinstance(n, dict)]
    runner = sum(1 for v in via if "runner" in v)
    vr = ((circuit.get("execution_proof") or {}).get("via_runner") or {})
    if runner:
        return (f"0 live by design: no APP entry proof — live needs the target run through its own "
                f"entry (cr_run_module on a script or `-m <pkg>`). {runner}/{len(via)} nodes are "
                f"runner-loaded (runtime_loaded_via=runner: pytest/unittest imported them), so "
                f"{counts.get('live_via_tests', 0)} edges read `live_via_tests` — the tests' proof, "
                f"never an app-live edge (Item 10, I-198)")
    if str(vr.get("status", "")).startswith("MEASURED"):
        return ("0 live: a runner ran (execution_proof.via_runner MEASURED) but none of its imports "
                "hash-verified against a graph node, and no APP entry proof exists")
    return ("0 live: no runtime proof on this frame — no APP entry run and no runner record "
            "(execution_proof NOT MEASURED); run the entry or pytest through cr_run_module, then "
            "wait one circuit cycle")


def cr_wiring(include_dataflows: bool = True, state: str | None = None) -> dict[str, Any]:
    circuit, err = _load(_CIRCUIT_FILES)
    empty = {"nodes": [], "edges": [], "severed_links": [], "all_connected": False,
             "cycles": [], "runners": {}, "dataflows": [],
             "counts": dict.fromkeys(EDGE_STATES, 0)}
    if err is not None:
        return {**empty, "error": err}
    if state is not None and state not in EDGE_STATES:
        return {**empty, "error": f"state must be one of {list(EDGE_STATES)}, not {state!r}"}

    nodes = circuit.get("nodes", [])
    loaded = {str(n.get("name", "")): bool(n.get("runtime_loaded")) for n in nodes}
    # I-198: no node the APP loaded = no app entry proof (a library); only then do the runner's
    # nodes light `live_via_tests`. Any app proof leaves `tested` empty — Item 10 unchanged.
    tested: set[str] = set()
    if not any(loaded.values()):
        tested = {str(n.get("name", "")) for n in nodes
                  if "runner" in str(n.get("runtime_loaded_via") or "")}
    severed_pairs = {(str(p[0]), str(p[1])) for p in circuit.get("severed_links", []) if len(p) > 1}
    since = circuit.get("severed_since", {})

    edges: list[dict[str, Any]] = []
    counts = dict.fromkeys(EDGE_STATES, 0)
    for pair in circuit.get("edges", []):
        if len(pair) < 2:
            continue
        source, target = str(pair[0]), str(pair[1])
        edge_state = _edge_state(source, target, severed_pairs, loaded, tested)
        counts[edge_state] = counts[edge_state] + 1
        edges.append({
            "source": source,
            "target": target,
            "state": edge_state,
            "severed_since": since.get(_SEVERED_KEY.format(source, target)) if edge_state == "severed" else None,
        })
    if state is not None:
        edges = [e for e in edges if e["state"] == state]

    return {
        "live_why": _live_why(nodes, circuit, counts),
        "nodes": nodes,
        "edges": edges,
        "severed_links": circuit.get("severed_links", []),
        "all_connected": bool(circuit.get("all_connected", False)),
        "cycles": circuit.get("cycles", []),
        "runners": circuit.get("test_runners", {}),
        "dataflows": circuit.get("dataflows", []) if include_dataflows else [],
        "counts": counts,
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# cr_data_types
# ─────────────────────────────────────────────────────────────────────────────

#: tracker name → the key `circuit_state.json` publishes its result under.
_TRACKER_FILES = {
    "io": "io_tracker_results",
    "mypy": "mypy_results",
    "crc": "crc_results",
    "vulture": "vulture_results",
    # ND2: the permanent tracker's block (plan §D); read through `naming_drift_reading`, not this key alone
    "naming_drift": "naming_drift",
}


def cr_data_types(tracker: str | None = None) -> dict[str, Any]:
    circuit, err = _load(_CIRCUIT_FILES)
    monitor, _ = _monitor_state()
    #: B5: an unreadable state publishes `issues` null (NOT MEASURED), not 0.
    out: dict[str, Any] = {"chosen": [], "not_run": [], "not_measured": {}, "io": {}, "mypy": {},
                           "crc": {}, "vulture": {}, "naming_drift": {}, "pytest": {}, "contract_violations": {},
                           "issues": None, "notes": None, "error": err}
    if err is not None:
        return out
    if tracker is not None and tracker not in _TRACKER_FILES and tracker != "pytest":
        out["error"] = f"tracker must be one of {sorted([*_TRACKER_FILES, 'pytest'])}, not {tracker!r}"
        return out

    trackers = circuit.get("trackers", {})
    out["chosen"] = trackers.get("chosen", [])
    out["not_run"] = trackers.get("not_run", [])
    # R9 (R4's shape): {token: reason} for a chosen tracker whose tool is missing or failed — its
    # block below says "NOT MEASURED — <reason>" with null counts.
    out["not_measured"] = dict(trackers.get("not_measured") or {})
    for name, key in _TRACKER_FILES.items():
        if tracker is None or tracker == name:
            out[name] = circuit.get(key, {})
    # ND2 (2026-10-01, plan §D): naming drift is the PERMANENT tracker — under `chosen` always, never
    # under `not_run`; until the launch scan has completed (`ran: true`) it is NOT MEASURED with its
    # reason in `not_measured` and every count null, never 0. Its block is stamped like the others.
    if NAMING_DRIFT not in out["chosen"]:
        out["chosen"] = [*out["chosen"], NAMING_DRIFT]
    out["not_run"] = [t for t in out["not_run"] if t != NAMING_DRIFT]
    _nd_block, _nd_why = naming_drift_reading(circuit, monitor)
    if _nd_why is not None:
        out["not_measured"][NAMING_DRIFT] = _nd_why
    if tracker is None or tracker == NAMING_DRIFT:
        out[NAMING_DRIFT] = _naming_drift_stamped(_nd_block, _nd_why)
    # owner 2026-10-07: pytest is a permanent tracker too — the last pytest run CodeRadar started, from the
    # dash mirror's `monitor.pytest` block (ran false = NOT MEASURED with its reason, never 0)
    if "pytest" not in out["chosen"]:
        out["chosen"] = [*out["chosen"], "pytest"]
    if tracker is None or tracker == "pytest":
        out["pytest"] = (monitor or {}).get("pytest") or {
            "ran": False, "status": NOT_MEASURED, "reason": "no dash mirror yet"}
    out["contract_violations"] = circuit.get("contract_violations", {})
    #: B5 (2026-10-01, Q-H0-1): `issues` is the REAL TYPE ERRORS in the dash mirror's own mypy
    #: list (`monitor.mypy.errors`), `notes` the --strict annotation notes in the same list, both
    #: by the ONE split (`system_scripts.mypy_partition`) circuit_daemon counts the badge with —
    #: so `issues` reads 27 beside "27 type errors", never 88. `issues + notes` is the list's
    #: length = `monitor.mypy.error_lines` = `summary.mypy_errors`, the number `finished` still
    #: reads (T1 decision 3; the gate's scope is unchanged — I-09/10, mypy is a tracker, not an
    #: engine); that number is published beside them as `finished_input` with its own scope.
    #: io, crc, vulture and the contract violations are REPORTED here; none counts against `finished`.
    #: R9 / C5 / Q2: an unmeasured mypy (no mirror, `mypy_errors` null, `mypy_ran` false, or no file
    #: checked) publishes `issues` and `notes` null (NOT MEASURED; the reason is in `not_measured`),
    #: never 0 and never a TypeError. A missing mirror or key is NOT a zero either.
    _summ = monitor.get("summary") or {}
    _my = monitor.get("mypy") or {}
    _finished_input = _summ.get("mypy_errors")
    _measured = (_finished_input is not None
                 and ("mypy_ran" not in _summ or bool(_summ.get("mypy_ran")))
                 and ("mypy_files_checked" not in _summ or int(_summ.get("mypy_files_checked") or 0) > 0))
    _lines = _my.get("errors")
    if not _measured:
        out["issues"], out["notes"], out["issues_source"] = None, None, "NOT MEASURED"
    elif isinstance(_lines, list):
        _errs, _notes = _mypy_partition(str(line) for line in _lines)
        out["issues"], out["notes"] = len(_errs), len(_notes)
        out["issues_source"] = "monitor.mypy.errors"
    else:
        #: a mirror without the list: the daemon's own split of the same rule, or null
        out["issues"] = _my.get("type_errors")
        out["notes"] = _my.get("annotation_notes")
        out["issues_source"] = "monitor.mypy.type_errors"
    out["issues_scope"] = ISSUES_TYPE_ERRORS_SCOPE
    out["finished_input"] = None if _finished_input is None else int(_finished_input)
    out["finished_scope"] = ISSUES_SCOPE     # M-20: what `finished` counts, in words
    #: R9: the split the dashboard's mypy tile shows — `type_errors` real type errors and
    #: `annotation_notes` the --strict notes, from circuit_state's mypy block (null = NOT MEASURED).
    _mr = circuit.get("mypy_results") or {}
    out["issues_split"] = {"type_errors": _mr.get("type_errors", _mr.get("total_errors")),
                           "annotation_notes": _mr.get("annotation_notes")}
    return out


# ─────────────────────────────────────────────────────────────────────────────
# cr_intent
# ─────────────────────────────────────────────────────────────────────────────


def cr_intent() -> dict[str, Any]:
    src = sources()
    builder, _ = _load(_BUILDER_FILES)
    summary_intent = builder.get("summary", {}).get("intent", {})
    named = summary_intent.get("file")
    #: The intent file is named by the Builder itself (`summary.intent.file`, a bare
    #: file name) and only computed from the repo id when the Builder has not published.
    if named is not None:
        path = src.file_for((str(named),))
    else:
        path = src.file_for((f"intent_{src.repo_id}.json",))
    data, err = _read_json(path)
    if err is not None:
        return {"target": "", "repo_id": "", "generated_at": "", "statement": None,
                "facts": [], "facts_by_source": {}, "file": str(path), "error": err}
    mismatch = _wrong_target(data, src)
    if mismatch is not None:
        return {"target": str(data.get("target", "")), "repo_id": str(data.get("repo_id", "")),
                "generated_at": "", "statement": None, "facts": [], "facts_by_source": {},
                "file": str(path), "error": mismatch}
    return {
        "target": str(data.get("target", "")),
        "repo_id": str(data.get("repo_id", "")),
        "generated_at": str(data.get("generated_at", "")),
        "statement": data.get("statement"),
        "facts": data.get("facts", []),
        "facts_by_source": summary_intent.get("facts_by_source", {}),
        "file": str(path),
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# The registry (T1): a tool answers only once its lane has bound it
# ─────────────────────────────────────────────────────────────────────────────

register_handler("cr_status", cr_status)
register_handler("cr_infractions", cr_infractions)
register_handler("cr_row", cr_row)
register_handler("cr_wiring", cr_wiring)
register_handler("cr_data_types", cr_data_types)
register_handler("cr_intent", cr_intent)
