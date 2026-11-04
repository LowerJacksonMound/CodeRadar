#!/usr/bin/env python3
"""launch_setup.py — the launch setup page (Lane B, owner 2026-09-30: "overlay first").

`./launch.sh` with NO target argument runs this in the foreground before anything else happens: no
daemon is stopped, no state is cleared, nothing is copied. It serves ONE page on the dashboard port
(system_scripts/copy_ports.json "dashboard", default 8080 — the same lookup launch.sh makes), bound to
127.0.0.1. On the page the owner picks the target path (checked as it is typed), the trackers,
an OPTIONAL purpose (the snapshot is always taken — owner 2026-09-30); the launch command it will run is shown live. Start writes
system_scripts/launch_choice.json, replies, and the server shuts down — the port is free again for the
dashboard. The page then waits for the dashboard to answer on the same port and moves there.

owner 2026-09-30: eslogger is disabled (removed from the MVP) — the page shows "tracer: lsof" as
fixed text, never a choice.

Modes:
  launch_setup.py [--port N] [--choice-file F] [--target P] [--load-proof] [--trackers a,b]
        serve the page (the flags only pre-fill it). Exit 0 = a choice was written; 3 = the port is
        busy; 4 = closed without Start (Cancel button, Ctrl-C, SIGTERM).
  launch_setup.py --emit-shell F
        read a choice file and print shell assignments (TARGET TRACKERS PURPOSE) for
        launch.sh to eval. Exit 1 with a one-line reason if the file is missing or malformed.
  launch_setup.py --submit-purpose TARGET
        write the purpose (read from stdin) to the target's intent file through
        intent_file.submit_statement — launch.sh calls this after pre-flight, before any daemon.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCRIPTS_DIR = Path(__file__).resolve().parent
CHOICE_FILE = SCRIPTS_DIR / "launch_choice.json"
TRACKERS = ("io", "mypy", "crc", "vulture")   # launch.sh's accepted set (pylint is unwired, ruling 11)
EXIT_CHOSEN, EXIT_PORT_BUSY, EXIT_CANCELLED = 0, 3, 4


CR_ROOT = SCRIPTS_DIR.parent   # CodeRadar's own tree — never a target (cr_watch's rule)


def _resolve(raw: str) -> Path:
    # R8 / T-16 (2026-09-30): realpath, not abspath — scan_scope.contained rejects anything reached
    # through a symlink, so an unresolved symlinked target scanned 0 files.
    return Path(os.path.realpath(os.path.expanduser(raw.strip())))


def _first_py(root: Path) -> tuple[Path | None, list[str]]:
    """R8 / T-17: the FIRST in-scope .py under *root* (None when there is none) and the folders that
    could not be read on the way — cr_watch's "zero .py files" refusal,
    with the same scope (scan_scope: nothing through a symlink, no engine hard-skip dir, no env dir,
    not the root .coderadar/, not a whitelisted file). Owner 2026-09-29 "one scan scans everything":
    this is never a count and never walks the whole tree — it stops at the first hit (top-down, so a
    repo with a .py at its root answers at once); the launch's whitelist scan stays the one walk."""
    sys.dont_write_bytecode = True   # importing scan_scope never leaves a __pycache__ behind
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    import scan_scope
    wl = scan_scope.load_whitelist(root)
    unreadable: list[str] = []
    for dirpath, dirnames, _files in os.walk(root, followlinks=False,
                                             onerror=lambda err: unreadable.append(str(err.filename))):
        here = Path(dirpath)
        rel_here = here.relative_to(root)
        dirnames[:] = sorted(n for n in dirnames
                             if not (here / n).is_symlink() and not scan_scope.hard_skipped(rel_here / n)
                             and not scan_scope.env_dir(here / n))
        for fp in sorted(here.glob("*.py")):   # the scan's own pattern (scan_scope walks rglob("*.py"))
            if (fp.is_file() and not fp.is_symlink()
                    and not scan_scope.is_whitelisted(fp.relative_to(root).as_posix(), wl)):
                return fp, unreadable
    return None, unreadable



_TRACKER_AVAIL: dict | None = None   # probed once per setup server (each probe starts a python)


def tracker_availability() -> dict:
    """R4: which trackers can measure on this Mac, and if not, why — GET /trackers. The probe is
    the daemon's own (circuit_daemon runs the tools as `<engine python> -m <tool>`, and this page
    runs under that same engine python, launch.sh's .venv_new). io is CodeRadar's own AST scan;
    crc needs the mypy_n_contracts_watcher CRC engine to load. Nothing is installed here."""
    global _TRACKER_AVAIL
    if _TRACKER_AVAIL is not None:
        return _TRACKER_AVAIL
    py = sys.executable

    def _run(args: list) -> tuple:
        try:
            r = subprocess.run([py, *args], capture_output=True, text=True, timeout=20,
                               stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            return r.returncode, (r.stdout or r.stderr or "").strip().splitlines()
        except Exception as e:  # a probe that cannot run is a reason, not a crash
            return -1, [f"{type(e).__name__}: {e}"]

    out = {"io": {"ok": True, "message": "built in (CodeRadar's AST scan)"}}
    # Q-H6-6: the page shows the reason on one line — the venv's NAME and the remedy; the full
    # interpreter path travels as "python" (the label's tooltip), not in the message
    venv = Path(py).parents[1].name if Path(py).parent.name == "bin" and len(Path(py).parents) > 1 else py
    for tool in ("mypy", "vulture"):
        rc, lines = _run(["-m", tool, "--version"])
        out[tool] = ({"ok": True, "message": lines[0] if lines else f"{tool} available"} if rc == 0
                     else {"ok": False, "python": py,
                           "message": f"{tool} not installed in {venv} — pip install {tool}, or leave it off"})
    crc_src = ("import importlib.util as u; s = u.spec_from_file_location('crc_engine', %r); "
               "s.loader.exec_module(u.module_from_spec(s))" % str(SCRIPTS_DIR / "mypy_n_contracts_watcher" / "crc_engine.py"))
    rc, lines = _run(["-c", crc_src])
    out["crc"] = ({"ok": True, "message": "CRC engine loads"} if rc == 0
                  else {"ok": False, "message": "CRC engine does not load: " + (lines[-1] if lines else f"rc {rc}")})
    _TRACKER_AVAIL = out
    return out


def check_path(raw: str) -> dict:
    """What the page shows under the path box. ok = a readable directory cr_watch would also take
    (R8 / T-17: its refusals — a missing directory, CodeRadar's own tree, zero .py files)."""
    raw = (raw or "").strip()
    if raw == "":
        return {"ok": False, "message": "enter the target path"}
    p = _resolve(raw)
    if not p.exists():
        return {"ok": False, "resolved": str(p), "message": "does not exist"}
    if not p.is_dir():
        return {"ok": False, "resolved": str(p), "message": "not a directory"}
    if not os.access(p, os.R_OK | os.X_OK):
        return {"ok": False, "resolved": str(p), "message": "not readable"}
    if p == CR_ROOT or CR_ROOT in p.parents:
        return {"ok": False, "resolved": str(p), "message": "CodeRadar's own tree (or inside it) — CodeRadar "
                "never scans itself; choose the repo you want scanned"}
    # owner 2026-09-30: a folder that CONTAINS CodeRadar (its parent folder, home, /) is never a target either — it would
    # snapshot and scan CodeRadar along with everything else in it
    if CR_ROOT.is_relative_to(p):   # p is CR_ROOT or above it (CR_ROOT itself was refused just above)
        return {"ok": False, "resolved": str(p), "message": "this folder contains CodeRadar itself — choose the "
                "repo's own folder, not a folder above it"}
    # owner 2026-09-29 "one scan scans everything": no .py COUNT here — _first_py stops at the first .py;
    # the launch's whitelist scan stays the one walk
    first_py, unreadable = _first_py(p)
    if first_py is not None:
        return {"ok": True, "resolved": str(p), "message": "folder found"}
    why = "no .py files in the scan scope — CodeRadar scans Python repos"
    if unreadable:
        why += f" ({len(unreadable)} folder(s) could not be read, e.g. {unreadable[0]})"
    return {"ok": False, "resolved": str(p), "message": why}


def validate_choice(doc: dict) -> tuple[dict | None, str]:
    """Normalise a Start body / a choice file. Returns (choice, "") or (None, reason)."""
    doc = doc if isinstance(doc, dict) else {}   # anything else reads as an empty choice: "enter the target path"
    chk = check_path(str(doc.get("path") or ""))
    trackers = doc.get("trackers") or []
    trackers = [t for t in trackers.split(",") if t] if isinstance(trackers, str) else trackers
    unknown = sorted({str(t) for t in trackers} - set(TRACKERS)) if isinstance(trackers, list) else ["(not a list)"]
    if not chk["ok"]:
        return None, f"target path: {chk['message']}"
    if unknown:
        return None, f"unknown tracker(s) {','.join(unknown)} — choose from {','.join(TRACKERS)}"
    purpose = str(doc.get("purpose") or "")
    return {
        "path": chk["resolved"],
        "load_proof": bool(doc.get("load_proof")),   # 2026-10-07: launch.sh --load-proof from the page
        "trackers": [t for t in TRACKERS if t in trackers],   # launch.sh's order, no duplicates
        "purpose": purpose.strip(),
        "chosen_at": doc.get("chosen_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, ""


def write_choice(path: Path, choice: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".launch_choice_", suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(choice, fh, indent=2)
    os.replace(tmp, path)


# ── the page ─────────────────────────────────────────────────────────────────────────────────────────
# Styled like the dashboard's startup overlay: rgba(0,0,0,.85) backdrop, #1f2937 panels, #374151
# borders, monospace, green #22c55e accents. One column at ~720 px, two at ~1440 px.
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeRadar launch setup</title>
<link rel="icon" href="data:,">
<style>
  :root { --bg:#111827; --panel:#1f2937; --border:#374151; --text:#e6edf3; --muted:#9ca3af;
          --dim:#6b7280; --green:#22c55e; --red:#ef4444; --amber:#f59e0b; }
  * { box-sizing: border-box; }
  html, body { margin:0; height:100%; background:var(--bg); color:var(--text);
               font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:10pt; }
  .backdrop { position:fixed; inset:0; background:rgba(0,0,0,.85); overflow:auto; padding:8px;
              display:flex; }
  .card { margin:auto; width:100%; max-width:1180px; background:var(--panel); border:1px solid var(--border);
          border-radius:8px; padding:12px 16px; }
  h1 { font-size:13pt; margin:0 0 10px; color:var(--green); letter-spacing:.04em; }
  h1 .sub { font-size:9pt; color:var(--dim); letter-spacing:0; font-weight:normal; margin-left:10px; }
  .grid { display:grid; grid-template-columns:1fr; gap:10px; }
  @media (min-width: 1100px) { .grid { grid-template-columns: 1fr 1fr; } }
  .panel { border:1px solid var(--border); border-radius:6px; padding:10px 12px; background:rgba(17,24,39,.55); }
  .panel h2 { font-size:9pt; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:0 0 6px; }
  .panel h2.next { margin-top:10px; }
  label { display:block; }
  input[type=text], textarea { width:100%; background:#111827; color:var(--text); border:1px solid var(--border);
          border-radius:4px; padding:8px 10px; font:inherit; }
  input[type=text]:focus, textarea:focus { outline:none; border-color:var(--green); }
  /* Q-H6b-1: exactly two full lines (2 x line-height + 8px top / 1px bottom padding + 2px border); a third line
     scrolls inside. A textarea clips at its padding edge, so any bottom padding deeper than the half-leading
     (~2px here) shows the next line's letter tops — 1px keeps it blank (3px still showed a sliver). */
  textarea { line-height:1.3; padding-bottom:1px; min-height:calc(2.6em + 11px); height:calc(2.6em + 11px); resize:vertical; }
  .status { margin-top:4px; min-height:1.3em; color:var(--dim); overflow-wrap:anywhere; }
  .status.ok { color:var(--green); } .status.bad { color:var(--red); }
  .row { display:flex; flex-wrap:wrap; gap:6px 18px; margin:4px 0 8px; align-items:center; }
  .row label { display:inline-flex; align-items:center; gap:6px; cursor:pointer; }
  input[type=checkbox] { accent-color: var(--green); width:15px; height:15px; }
  .fixed { color:var(--muted); margin-bottom:6px; }
  .fixed b { color:var(--text); font-weight:normal; }
  .hint { color:var(--dim); font-size:8.5pt; margin-top:4px; }
  pre.cmd { margin:0; white-space:pre-wrap; overflow-wrap:normal; background:#111827; border:1px solid var(--border);
            border-radius:4px; padding:8px 10px; color:var(--dim); user-select:all; }
  /* Q-H6-7: the command wraps only between arguments — each one is a no-break span; the path alone may
     also wrap at its own spaces, and break anywhere only when one piece is longer than the whole line */
  pre.cmd .t { white-space:nowrap; }
  pre.cmd .p { white-space:pre-wrap; overflow-wrap:anywhere; }
  pre.cmd.ok { color:var(--green); } pre.cmd.bad { color:var(--red); }
  .hint.why { color:var(--amber); }
  .actions { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:10px; }
  button { font:inherit; border-radius:4px; padding:9px 18px; cursor:pointer; border:1px solid var(--border);
           background:#111827; color:var(--muted); }
  button.start { background:var(--green); border-color:var(--green); color:#052e16; font-weight:bold; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  .msg { color:var(--muted); overflow-wrap:anywhere; }
  .msg.bad { color:var(--red); } .msg.ok { color:var(--green); }
</style></head>
<body><div class="backdrop"><div class="card">
  <h1>CodeRadar &mdash; launch setup<span class="sub">nothing runs until Start</span></h1>
  <div class="grid">
    <div class="panel">
      <h2>Target</h2>
      <label for="path">target path</label>
      <input type="text" id="path" spellcheck="false" autocomplete="off">
      <div class="status" id="path-status">enter the target path</div>
      <h2 class="next">Options</h2>
      <div class="fixed">tracer: <b>lsof</b> &nbsp;·&nbsp; snapshot: <b>always</b> <span class="hint">(the repo is copied before every launch)</span></div>
      <div class="row" id="trackers"><span class="hint" style="margin:0">trackers:</span></div>
      <div class="row"><label title="eslogger (macOS) records which of the target's modules a run really loads, so a link a run exercised goes green instead of purple. Needs root once: the terminal asks for your password right after Start."><input type="checkbox" id="loadproof"> load proof <span class="hint" style="margin:0">— records the modules a run really loads (links go green); the terminal asks for your password once, after Start</span></label></div>
    </div>
    <div class="panel">
      <h2>Purpose <span style="text-transform:none;letter-spacing:0">(optional)</span></h2>
      <textarea id="purpose" rows="2" placeholder="What the target is for — written to its intent file before any daemon starts. Leave empty to skip."></textarea>
      <h2 class="next">Launch command</h2>
      <pre class="cmd" id="cmd"></pre>
      <div class="hint" id="cmd-note"></div>
    </div>
  </div>
  <div class="actions">
    <button class="start" id="start" disabled>Start</button>
    <button id="cancel">Cancel</button>
    <span class="msg" id="msg"></span>
  </div>
</div></div>
<script>
const INIT = __INIT__;
const $ = (id) => document.getElementById(id);
const TRACKERS = INIT.trackers_all;
let pathOk = false, resolved = "", checkSeq = 0, timer = null, done = false;

for (const t of TRACKERS) {
  const l = document.createElement("label");
  l.innerHTML = `<input type="checkbox" value="${t}"> ${t}`;
  $("trackers").appendChild(l);
}
$("path").value = INIT.target || "";
$("loadproof").checked = !!INIT.load_proof;   // A / 2026-10-07: the --load-proof flag, now a tick box
$("purpose").value = INIT.purpose || "";
for (const cb of $("trackers").querySelectorAll("input")) cb.checked = (INIT.trackers || []).includes(cb.value);

async function checkTrackers() {
  // R4: a tracker whose tool is not installed is greyed out with its reason — never offered as if it could measure
  try {
    const j = await (await fetch("/trackers", {cache: "no-store"})).json();
    for (const cb of $("trackers").querySelectorAll("input")) {
      const a = j[cb.value];
      if (!a || a.ok) continue;
      cb.checked = false; cb.disabled = true;
      const l = cb.parentElement;
      l.style.opacity = "0.5"; l.style.cursor = "not-allowed"; l.title = a.python || a.message;
      const why = document.createElement("span");
      why.className = "hint why"; why.textContent = " (" + a.message + ")";
      l.appendChild(why);
    }
  } catch (e) { $("msg").className = "msg bad"; $("msg").textContent = "tracker check failed: " + e; }
  renderCmd();
}
function sq(s) { return /^[A-Za-z0-9_.\/:@%+=,-]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'"; }
function chosenTrackers() { return [...$("trackers").querySelectorAll("input:checked")].map(c => c.value); }
function renderCmd() {
  const p = resolved || $("path").value.trim() || "<target>";
  // Q-H6-7: one no-break span per argument (class t; the path also gets p) so the box never wraps inside
  // a flag — the text nodes between them are the spaces, so copying the box still yields the plain command
  const args = ["./launch.sh", sq(p), "--tracer", "lsof"];
  if ($("loadproof").checked) args.push("--load-proof");
  const tr = chosenTrackers();
  if (tr.length) args.push("--trackers", tr.join(","));
  $("cmd").textContent = "";
  args.forEach((a, i) => {
    if (i) $("cmd").appendChild(document.createTextNode(" "));
    const s = document.createElement("span"); s.className = i === 1 ? "t p" : "t"; s.textContent = a;
    $("cmd").appendChild(s);
  });
  // owner 2026-09-30: the command is red for a target that won't launch, green only when it will
  $("cmd").className = "cmd " + (pathOk ? "ok" : ($("path").value.trim() ? "bad" : ""));
  $("cmd-note").textContent = $("purpose").value.trim()
    ? "purpose: written to the target's intent file before any daemon starts" : "purpose: none (optional)";
  $("start").disabled = !pathOk || done;
}
async function checkPath() {
  const seq = ++checkSeq, raw = $("path").value;
  try {
    const r = await fetch("/check?path=" + encodeURIComponent(raw), {cache: "no-store"});
    const j = await r.json();
    if (seq !== checkSeq) return;
    pathOk = !!j.ok; resolved = j.ok ? j.resolved : "";
    const st = $("path-status");
    st.className = "status " + (j.ok ? "ok" : (raw.trim() ? "bad" : ""));
    st.textContent = (j.resolved && j.resolved !== raw.trim() ? j.resolved + " — " : "") + j.message;
  } catch (e) {
    if (seq !== checkSeq) return;
    pathOk = false; resolved = "";
    $("path-status").className = "status bad"; $("path-status").textContent = "setup server not answering";
  }
  renderCmd();
}
$("path").addEventListener("input", () => { pathOk = false; renderCmd(); clearTimeout(timer); timer = setTimeout(checkPath, 250); });
// owner 2026-09-30: entering the path is how the target is chosen — Enter checks it now and, when it is valid, Starts
$("path").addEventListener("keydown", async (ev) => {
  if (ev.key !== "Enter") return;
  ev.preventDefault(); clearTimeout(timer);
  await checkPath();
  if (pathOk && !done) $("start").click();
});
$("purpose").addEventListener("input", renderCmd);
$("loadproof").addEventListener("change", renderCmd);
$("trackers").addEventListener("change", renderCmd);

function lock(msg, cls) {
  done = true;
  for (const el of document.querySelectorAll("input, textarea, button")) el.disabled = true;
  $("msg").className = "msg " + (cls || ""); $("msg").textContent = msg;
}
async function waitForDashboard() {
  // The dashboard comes up on this same port once launch.sh has run pre-flight and started the gearbox.
  // /_dash-layout is a Dash route — the setup server never answers it, so a hit means the dash is up.
  // If nothing at all answers on the port for DEAD_AFTER_S, the launch died before the dashboard came up.
  const t0 = Date.now(), DEAD_AFTER_S = 30;
  let lastAnswer = Date.now();
  for (;;) {
    try {
      lastAnswer = Date.now();
      const r = await fetch("/_dash-layout", {cache: "no-store"});
      if (r.ok) { location.replace("/"); return; }
      // the setup page came back (the launch stopped before it started): reload it to show why
      const c = await fetch("/check?path=", {cache: "no-store"});
      if ((c.headers.get("content-type") || "").includes("application/json")) { location.reload(); return; }
    } catch (e) {}
    const s = Math.round((Date.now() - t0) / 1000), silent = (Date.now() - lastAnswer) / 1000;
    if (silent > DEAD_AFTER_S) {
      $("msg").className = "msg bad";
      $("msg").textContent = `nothing has answered on port ${INIT.port} for ${Math.round(silent)}s — the launch stopped before the dashboard came up; see the terminal, then run ./launch.sh again`;
      return;
    }
    $("msg").textContent = `started — waiting for the dashboard on port ${INIT.port} (${s}s; the terminal shows each step)`;
    await new Promise(res => setTimeout(res, 1000));
  }
}
$("start").addEventListener("click", async () => {
  if (!pathOk || done) return;
  const body = {path: resolved, load_proof: $("loadproof").checked, trackers: chosenTrackers(),
                purpose: $("purpose").value};
  $("start").disabled = true;
  try {
    const r = await fetch("/start", {method: "POST", headers: {"Content-Type": "application/json"},
                                     body: JSON.stringify(body)});
    const j = await r.json();
    if (!j.ok) { $("msg").className = "msg bad"; $("msg").textContent = j.message; $("start").disabled = false; return; }
    lock("started", "ok");
    waitForDashboard();
  } catch (e) {
    $("msg").className = "msg bad"; $("msg").textContent = "Start not delivered: " + e; $("start").disabled = false;
  }
});
$("cancel").addEventListener("click", async () => {
  try { await fetch("/cancel", {method: "POST"}); } catch (e) {}
  lock("cancelled — nothing ran. Close this tab.", "bad");
});
if (INIT.error) { $("msg").className = "msg bad"; $("msg").textContent = "the last Start stopped: " + INIT.error; }
renderCmd();
if ($("path").value) checkPath();
checkTrackers();
$("path").focus();
</script>
</body></html>
"""


class SetupServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, choice_file: Path, init: dict):
        super().__init__(addr, handler)
        self.choice_file = choice_file
        self.init = init
        self.outcome = EXIT_CANCELLED

    def finish_with(self, outcome: int) -> None:
        self.outcome = outcome
        threading.Thread(target=self.shutdown, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    server: SetupServer

    def log_message(self, fmt, *args):   # quiet — the terminal shows launch.sh's own lines
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, doc: dict) -> None:
        self._send(code, json.dumps(doc).encode(), "application/json")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            page = PAGE.replace("__INIT__", json.dumps(self.server.init).replace("</", "<\\/"))
            self._send(200, page.encode(), "text/html; charset=utf-8")
        elif u.path == "/trackers":
            self._json(200, tracker_availability())
        elif u.path == "/check":
            self._json(200, check_path((parse_qs(u.query).get("path") or [""])[0]))
        else:
            self._json(404, {"ok": False, "message": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/cancel":
            self._json(200, {"ok": True})
            print("[setup] cancelled on the page — nothing ran", flush=True)
            self.server.finish_with(EXIT_CANCELLED)
            return
        if u.path != "/start":
            self._json(404, {"ok": False, "message": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            doc = json.loads(self.rfile.read(min(n, 1_000_000)) or b"{}")
        except (ValueError, json.JSONDecodeError) as e:
            self._json(400, {"ok": False, "message": f"bad request: {e}"})
            return
        choice, why = validate_choice(doc)
        if choice is None:
            self._json(400, {"ok": False, "message": why})
            return
        try:
            write_choice(self.server.choice_file, choice)
        except OSError as e:
            self._json(500, {"ok": False, "message": f"choice not written: {e}"})
            return
        self._json(200, {"ok": True, "port": self.server.server_address[1]})
        print(f"[setup] Start: {choice['path']}", flush=True)
        self.server.finish_with(EXIT_CHOSEN)


def serve(port: int, choice_file: Path, init: dict) -> int:
    try:
        srv = SetupServer(("127.0.0.1", port), Handler, choice_file=choice_file, init=init)
    except OSError as e:
        print(f"[setup] ABORT — port {port} is in use ({e.strerror}); an earlier CodeRadar run may still be up",
              file=sys.stderr, flush=True)
        return EXIT_PORT_BUSY

    def _stop(signum, frame):
        srv.finish_with(EXIT_CANCELLED)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"[setup] launch setup page: http://127.0.0.1:{port}/  (Start launches; Cancel or Ctrl-C quits)",
          flush=True)
    try:
        srv.serve_forever(poll_interval=0.2)
    finally:
        srv.server_close()   # the port is free before this process exits — the dashboard binds it next
    return srv.outcome


def emit_shell(choice_file: Path) -> int:
    try:
        doc = json.loads(choice_file.read_text())
    except FileNotFoundError:
        print(f"launch_setup: no choice file at {choice_file}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as e:
        print(f"launch_setup: choice file unreadable: {e}", file=sys.stderr)
        return 1
    choice, why = validate_choice(doc)
    if choice is None:
        print(f"launch_setup: choice file rejected — {why}", file=sys.stderr)
        return 1
    q = shlex.quote
    print(f"TARGET={q(choice['path'])}")
    print(f"LOAD_PROOF={1 if choice.get('load_proof') else 0}")
    print(f"TRACKERS={q(','.join(choice['trackers']))}")
    print(f"PURPOSE={q(choice['purpose'])}")
    return 0


def submit_purpose(target: str) -> int:
    text = sys.stdin.read().strip()   # launch.sh pipes the purpose in
    if text == "":
        return 0
    sys.path.insert(0, str(SCRIPTS_DIR))
    import intent_file   # noqa: E402 — stdlib-only module beside this one
    data, facts = intent_file.submit_statement(target, text)
    print(f"[setup] purpose written to {intent_file.path(target).name} ({len(facts)} fact(s) from the statement)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=None, help="default: copy_ports.json dashboard (8080)")
    ap.add_argument("--choice-file", type=Path, default=CHOICE_FILE)
    ap.add_argument("--target", default="", help="pre-fill the path box")
    ap.add_argument("--load-proof", action="store_true", help="pre-tick load proof (launch.sh --load-proof)")
    ap.add_argument("--trackers", default="", help="pre-tick trackers, e.g. mypy,vulture")
    ap.add_argument("--error", default="", help="why the previous Start stopped (shown on the page)")
    ap.add_argument("--from-last", type=Path, metavar="LAST_CHOICE",
                    help="pre-fill from the previous Start (a failed launch's 'back to setup')")
    ap.add_argument("--emit-shell", type=Path, metavar="CHOICE_FILE")
    ap.add_argument("--submit-purpose", metavar="TARGET")
    a = ap.parse_args(argv)
    if a.emit_shell:
        return emit_shell(a.emit_shell)
    if a.submit_purpose:
        return submit_purpose(a.submit_purpose)
    if a.port is None:
        ap.error("--port is required to serve the page (launch.sh passes the dashboard port)")
    port = a.port
    init = {"port": port, "target": a.target, "load_proof": a.load_proof,
            "trackers": [t for t in a.trackers.split(",") if t in TRACKERS], "trackers_all": list(TRACKERS),
            "purpose": "", "error": a.error}
    if a.from_last:
        last, _why = validate_choice(json.loads(a.from_last.read_text()))
        init.update({"target": last["path"], "load_proof": last.get("load_proof", False),
                     "trackers": last["trackers"], "purpose": last["purpose"]} if last else {})
    return serve(port, a.choice_file, init)


if __name__ == "__main__":
    sys.exit(main())
