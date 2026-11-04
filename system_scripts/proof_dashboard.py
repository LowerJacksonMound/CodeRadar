import dash
from dash import dcc, html, Input, Output, State, no_update, Patch
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.utils
import networkx as nx
import itertools
import json
import signal
import sys
import os
import tempfile
import math
import logging
import hashlib
import fcntl
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Optional, Tuple, Dict, Set

# Configure verbose DEBUG logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('proof_dashboard')
logger.setLevel(logging.DEBUG)

# Circuit graph view logic (stateless — no global graph state)
from circuit_views import (
    generate_figure,
    get_entry_point_from_proof,
    running_entries,
    circuit_from_state,          # R2: the graph is the circuit daemon's published state, never a target read
    fold_name, in_view, settle_view, drawn_for, FOLDER,   # M-65: the staircases view model (folder PATHS)
    outside_edges,               # item 9: the out-of-view box lines, counted as drawn
    circuit_state_unmeasured,
    missing_from_state,
    _ring_positions,
    ELECTRIC_BLUE,
)

# Enable DEBUG logging for circuit views (visible in terminal)
logging.getLogger("circuit_views").setLevel(logging.DEBUG)

# Optional: dash-auth for production (install with: pip install dash-auth)
# from dash_auth import BasicAuth

# Script directory for infraction verify script
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent  # Project root (parent of system_scripts)

DAEMON_LOG_DIR = SCRIPT_DIR / "daemon_log"
LOGS_DIR = DAEMON_LOG_DIR  # All logs stored in daemon_log
DAEMON_LOG = DAEMON_LOG_DIR / "daemon_log.txt"
RUNNING_STATE_FILE = SCRIPT_DIR / "running.json"
POLL_CONFIG_FILE = SCRIPT_DIR / "poll_config.json"
CIRCUIT_STATE_FILE = SCRIPT_DIR / "circuit_state.json"  # AST scanner state (SINGLE SOURCE OF TRUTH)
NOAI_STATE_FILE = SCRIPT_DIR / "NOAI_VALIDATION_STATE.json"
BUILDER_STATE_FILE = SCRIPT_DIR / "BUILDER_STATE.json"  # item 1 (2026-09-08): the cheatsheets rows (one before/after per infraction)

# Layout thresholds

# Cache for last good circuit state (prevents flicker on transient read failures)



def write_file_locked(filepath: Path, data: dict):
    """Write JSON atomically via temp file + rename (no truncate-before-lock race)."""
    filepath.parent.mkdir(exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=filepath.parent,
        prefix=f".{filepath.stem}_{os.getpid()}_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
        Path(tmp_path).rename(filepath)  # atomic on same filesystem
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def read_file_locked(filepath: Path) -> dict:
    """Read JSON data from file with shared lock."""
    if not filepath.exists():
        return {}
    try:
        with open(filepath, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        return {}


def get_repo_id(repo_path: Path) -> str:
    """Generate a unique ID for a repo path (short hash for log identification)."""
    return hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:12]


def discover_circuit_states() -> Dict[str, Dict]:
    """Find all circuit state files for multi-repo support.

    Returns:
        {repo_id: {'file': Path, 'state': dict, 'name': str}}
        Single-repo mode: returns one entry keyed by repo_id from circuit_state.json
        Multi-repo mode: returns entries from circuit_state_*.json files
    """
    states = {}
    # Check for multi-repo state files (circuit_state_{repo_id}.json)
    for f in sorted(SCRIPT_DIR.glob('circuit_state_*.json')):
        repo_id = f.stem.replace('circuit_state_', '')
        try:
            state = read_file_locked(f)
            if state:
                repo_path = state.get('target_repo', '')
                states[repo_id] = {
                    'file': f,
                    'state': state,
                    'name': Path(repo_path).name if repo_path else repo_id,
                    'repo_path': repo_path,
                }
        except Exception:
            continue

    # If no multi-repo files, use single file
    if not states and CIRCUIT_STATE_FILE.exists():
        try:
            state = read_file_locked(CIRCUIT_STATE_FILE)
            if state:
                repo_id = state.get('repo_id', 'default')
                repo_path = state.get('target_repo', '')
                states[repo_id] = {
                    'file': CIRCUIT_STATE_FILE,
                    'state': state,
                    'name': Path(repo_path).name if repo_path else 'default',
                    'repo_path': repo_path,
                }
        except Exception:
            pass

    return states


TARGET_REASON = ""   # R3 (2026-09-30): why TARGET_REPO is None — shown as "target: NOT MEASURED — <reason>"


def _target_unread(why: str):
    """R3: record why the target is unread and return None — never CodeRadar's own root in its place."""
    global TARGET_REASON
    TARGET_REASON = why
    return None


def get_target_repo_from_config() -> Optional[Path]:
    """Read TARGET_REPO from env var (priority) or shared config file.
    R3 (2026-09-30, T-12): an unreadable target is None with TARGET_REASON set — the old fallback to
    PROJECT_ROOT drew CodeRadar's own code as the target."""
    global TARGET_REASON
    named, source = str(os.getenv('TARGET_REPO') or ''), "env TARGET_REPO"
    if named == '':
        source = f"{POLL_CONFIG_FILE.name} target_repo"
        try:
            named = str(read_file_locked(POLL_CONFIG_FILE).get('target_repo') or '')
        except Exception as e:
            return _target_unread(f"{POLL_CONFIG_FILE.name} unreadable ({e})")
    if named == '':
        return _target_unread(f"no target: env TARGET_REPO unset and {POLL_CONFIG_FILE.name} has no target_repo")
    repo = Path(named)
    if repo.resolve() == PROJECT_ROOT.resolve():
        return _target_unread(f"{source} names CodeRadar's own root ({repo}) — never a target")
    if not repo.is_dir():
        return _target_unread(f"{source} names {repo}, which is not a directory")
    TARGET_REASON = ""
    return repo


def _target_not_measured() -> str:
    """R3: the one line every reader shows while the target is unread."""
    return f"target: NOT MEASURED — {TARGET_REASON}"


def _refresh_target() -> Optional[Path]:
    """R3: while the target is unread, re-read it each call (the gearbox may write poll_config after
    the dash imported); once read, it stays."""
    global TARGET_REPO
    if TARGET_REPO is None:
        TARGET_REPO = get_target_repo_from_config()
    return TARGET_REPO


def set_target_repo_in_config(repo_path: Path):
    """Write TARGET_REPO to shared config file so daemon can detect changes."""
    try:
        config = read_file_locked(POLL_CONFIG_FILE)
        config['target_repo'] = str(repo_path.resolve())
        write_file_locked(POLL_CONFIG_FILE, config)
    except Exception as e:
        print(f"Warning: Could not save target repo to config: {e}")


# Target repo for script discovery - read from shared config
TARGET_REPO = get_target_repo_from_config()


# Item 8 (2026-09-15): the Purpose field → the intent file (system_scripts/intent_<repoid>.json). The dashboard
# writes the file directly through intent_file (never poll_config.json — deleted every launch; the statement is
# per-target and outlives a relaunch).
def _intent_mod():
    import intent_file  # system_scripts is sys.path[0] — the dashboard runs from there
    return intent_file


def _intent_initial() -> tuple[str, str]:
    """(statement text, meta line) from the intent file at layout build — the card pre-fills after a relaunch."""
    if TARGET_REPO is None:
        return "", f"intent file: {_target_not_measured()}"
    try:
        _i = _intent_mod()
        data = _i.read(TARGET_REPO)
        st = data.get("statement") or {}
        meta = (f"{st.get('source', 'developer')} · {str(st.get('submitted_at', ''))[:19]} · facts by source "
                f"{_i.facts_by_source(data)}") if st else f"no statement yet · facts by source {_i.facts_by_source(data)}"
        return str(st.get("text") or ""), meta
    except Exception as e:
        return "", f"intent file: NOT MEASURED ({type(e).__name__})"


_INTENT_TEXT0, _INTENT_META0 = _intent_initial()

_shutdown_flag = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully — raise KeyboardInterrupt for Dash's own handler."""
    global _shutdown_flag
    _shutdown_flag = True
    print(f"\nReceived signal {signum}. Shutting down...")
    raise KeyboardInterrupt

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def _crkey(key: str) -> Dict[str, Any]:
    """I-199: the `data-crkey` attribute assets/details_memory.js keys a <details> open/shut state by."""
    return {'data-crkey': key}


app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    suppress_callback_exceptions=True,  # Suppress stale-browser retries after server restart
    assets_folder=str(SCRIPT_DIR / 'assets'),
    serve_locally=True,
)
app.server.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
logger.info("Dash app initialized with suppress_callback_exceptions=True")

@app.server.after_request
def _no_cache(response):
    """Prevent browsers from caching Dash API responses (layout, dependencies)."""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Remove ETag to prevent 304 Not Modified responses
    response.headers.pop('ETag', None)
    response.headers.pop('Last-Modified', None)
    return response

@app.server.errorhandler(KeyError)
@app.server.errorhandler(IndexError)
def _handle_stale_callback(exc):
    """Stale browser sessions may request callbacks with outdated output keys.
    Return 204 (no content) instead of 500 so the browser silently retries
    with the correct dependency tree after a full page reload."""
    import flask
    if flask.request.path == '/_dash-update-component':
        logger.debug("Ignoring stale callback request: %s", exc)
        return '', 204
    raise exc


def _log_registered_callbacks():
    """Log all registered callback output keys for debugging."""
    logger.info("=" * 60)
    logger.info("REGISTERED CALLBACKS (callback_map keys):")
    for key in sorted(app.callback_map.keys()):
        logger.info(f"  {key}")
    logger.info("=" * 60)


# Register startup hook to log callbacks after layout is set
import atexit
_callbacks_logged = False
def _log_callbacks_once():
    global _callbacks_logged
    if not _callbacks_logged and hasattr(app, 'callback_map'):
        _log_registered_callbacks()
        _callbacks_logged = True

# =============================================================================
# VERIFICATION HELPERS
# =============================================================================
def get_latest_proof_dir():
    """Find the most recently modified proof directory."""
    if not LOGS_DIR.exists():
        return None
    proof_dirs = [d for d in LOGS_DIR.iterdir() if d.is_dir() and d.name.startswith('proof_')]
    if not proof_dirs:
        return None
    return max(proof_dirs, key=lambda d: d.stat().st_mtime)


def check_daemon_health() -> Tuple[bool, str]:
    """Check if daemon is running and healthy.

    Returns:
        Tuple of (is_healthy, status_message)
    """
    # Check if daemon log was updated recently (within last 30 seconds)
    if not DAEMON_LOG.exists():
        return False, "Daemon log not found"

    try:
        log_mtime = DAEMON_LOG.stat().st_mtime
        age_seconds = datetime.now().timestamp() - log_mtime
        if age_seconds > 30:
            return False, f"Daemon stale ({int(age_seconds)}s since last update)"

        # Check for recent errors in log
        with open(DAEMON_LOG, 'r') as f:
            lines = f.readlines()[-5:]
            recent_content = ''.join(lines)
            if 'error' in recent_content.lower() or 'failed' in recent_content.lower():
                return True, "Daemon running (with errors)"

        return True, "Daemon healthy"
    except Exception as e:
        return False, f"Health check failed: {e}"



# =============================================================================
# CIRCUIT GRAPH — view logic in circuit_views.py (stateless, no globals)
# =============================================================================

# ITEM 11 (2026-09-15): the dash keeps NO severed-link memory — the circuit daemon computes the
# transition and publishes `severed_links`; update_circuit reads it (FIX_27's memory deleted by replacement).


# =============================================================================
# LAYOUT - TABBED INTERFACE
# =============================================================================

# ── FIX_46: the dashboard's two slots on the ONE cadence table (gearbox.py) ──────────────────
def _cadence_slot_ms() -> dict:
    """The first-tick offset of each dashboard poll, in ms, from gearbox's table. A tree without the
    coordinator falls back to the table's own values — one site, never a literal in the layout."""
    out = {'circuit_interval': 1875, 'verdict_interval': 2188}
    try:
        import gearbox as _cadence
        for k in list(out):
            d = _cadence.duty('dashboard', k)
            if d is not None and d.slot is not None:
                out[k] = int(round(d.offset_s * 1000))
    except Exception:
        pass
    return out


_CADENCE_SLOT_MS = _cadence_slot_ms()


def _plural(count: int, one: str, many: str = "") -> str:
    """'1 file' / '2 files' — S3 2026-09-29: every count on the dash reads right at 1."""
    return f"{count} {one if count == 1 else (many or one + 's')}"


_TRACKER_NOT_RUN = "not run — nothing measured"   # circuit_daemon._NOT_RUN: not chosen at launch


def _tracker_unmeasured(name: str, results) -> Optional[Tuple[str, str]]:
    """R9: a tracker's published shape that measured nothing -> (tile line, summary badge); None when it
    measured. R4's "NOT MEASURED — <reason>" (chosen, tool missing or failed) is shown as published; the
    "(not in --trackers at launch)" suffix belongs only to a tracker the launch did not choose."""
    d = results if isinstance(results, dict) else {}
    status = d.get('status')
    reason = d.get('not_measured_reason')
    if reason or (isinstance(status, str) and status.startswith('NOT MEASURED')):
        return (f"{name} {status or 'NOT MEASURED — ' + str(reason)}", "NOT MEASURED")
    if status == _TRACKER_NOT_RUN:
        return (f"{name} {status} (not in --trackers at launch)", "not run")
    if status and status != 'measured':
        return (f"{name} {status}", str(status))
    return None


def _unmeasured_colour(badge: str) -> str:
    """R9: NOT MEASURED (chosen, but the tool is missing or failed) is amber; a tracker not chosen stays gray."""
    return '#f59e0b' if badge == 'NOT MEASURED' else '#6b7280'


def _folder_paths(files: Optional[list] = None) -> frozenset:
    """M-65: every folder PATH that holds a live .py file somewhere under it ('a', 'a/b', …) — the paths
    a click or the dropdown may drill to. R2: the circuit state's nodes, no walk of the target."""
    paths: set = set()
    if TARGET_REPO is None:
        return frozenset()
    try:
        target = Path(TARGET_REPO)
        for fp in _live_files(target, files):
            parts = fp.relative_to(target).parts[:-1]
            for k in range(1, len(parts) + 1):
                paths.add('/'.join(parts[:k]))
    except Exception as e:
        logger.warning(f"folder-path walk failed, none drillable: {e}")
    return frozenset(paths)


def _settled_view(view: str, tick=None) -> str:
    """M-65 rule 3: the first stop at or under *view* — a level with exactly one folder and no file is a
    pass-through (the first view and every drill step through it)."""
    t = tick if tick is not None else _TickRead(TARGET_REPO)
    try:
        return settle_view(t.state if not t.unmeasured else {}, view)
    except Exception as e:
        logger.warning(f"view settle failed, the view stays at {view!r}: {e}")
        return view or ''


def _outside_links(imports, keep, node_subdirs, view, tick=None) -> list:
    """owner 2026-09-29: every import crossing the view's edge, one entry per (inside, outside) pair:
    {inside, outside, outward, folder, side}. M-65: the view is a folder PATH; the fold already names every
    out-of-view end as the folder where it branches off the view's path (a sibling or a deeper folder) or as
    a file in an ancestor folder. `folder` is that folder's path (a file's: its own folder, '' for a root
    file). `side`: 'down' under the view, else 'up' — a hint only; the figure places the boxes."""
    seen: dict = {}
    for src, dsts in imports.items():
        for dst in dsts:
            if (src in keep) == (dst in keep):
                continue
            inside, outside = (src, dst) if src in keep else (dst, src)
            seen.setdefault((inside, outside), src in keep)
    out = []
    for (inside, outside), outward in seen.items():
        folder = outside[len(FOLDER):] if outside.startswith(FOLDER) else str(node_subdirs.get(outside) or '')
        side = 'down' if view and folder.startswith(view + '/') else 'up'
        out.append({'inside': inside, 'outside': outside, 'outward': outward, 'folder': folder, 'side': side})
    return out


def _live_files(target: Path, files: Optional[list] = None) -> list:
    """The live .py files of *target*: the tick's list when one is passed (P2), else the circuit daemon's
    published nodes — R2 (2026-09-30): never a walk of the target here."""
    if files is not None:
        return files
    return _TickRead(target).files


def _scanned_top_dirs(files: Optional[list] = None) -> frozenset:
    """M-65: the folder PATHS a live .py file lies under (every ancestor: 'a', 'a/b'); the drillable set and
    the scanned colour's key. R2: the circuit state's nodes; inside a tick, the tick's one list."""
    return _folder_paths(files)


# --- P2 B1 (2026-09-29): ONE walk, ONE read and ONE parse per file per circuit tick, passed down, not patched ---
# S7 got one walk per tick by routing Path.rglob / Path.read_text process-wide through a thread-local tick
# scope. P2 drops that patching: update_circuit builds a `_TickRead` — the one scan_scope.iter_live_py walk
# of the target, one read of each file it yields, and an (initially empty) AST table — and hands it to
# every reader in the tick. R2 (2026-09-30): the walk / read / parse is gone — `_TickRead` now holds the ONE
# read of the circuit daemon's published state per tick (nodes, links, colours, missing modules, the
# scanned-dir colours, the dropdown all come from it). Backup of the walker: proof_dashboard.py.pre_R2.
# The object is a local of the tick and is dropped when the tick returns (owner spec: nothing saved between frames).
class _TickRead:
    """One circuit tick's view of the circuit daemon's PUBLISHED state — R2 (2026-09-30, owner: one scan
    scans everything): no walk, no read, no parse of the target here. `files` = the daemon's nodes as paths
    (the dropdown's and the folder colours' scanned dirs); `parse(depth)` = circuit_views.circuit_from_state.
    `unmeasured` = why the state cannot draw the graph ('' when it can) — the graph then says so."""

    def __init__(self, target, state=None):
        self.state = state if state is not None else read_circuit_state()
        self.unmeasured = circuit_state_unmeasured(self.state)
        if target is None:   # R3: the target is unread — the graph says so instead of drawing anything
            self.target, self.whitelist, self.files = Path('.'), frozenset(), []
            self.unmeasured = self.unmeasured or 'no target read (see the target line)'
            return
        self.target = Path(target)
        self.whitelist = _whitelist_of(self.target)
        _st_target = str(self.state.get('target_repo') or '') if not self.unmeasured else ''
        if _st_target and Path(_st_target).resolve() != self.target.resolve():
            self.unmeasured = f'circuit state is for {_st_target}, not {self.target}'
        self.files: list = ([] if self.unmeasured else
                            [self.target / (str(n.get('name')) + '.py') for n in self.state.get('nodes') or []])

    def parse(self, view=''):
        """The graph in the view at folder path *view* (M-65), from the circuit state only
        (circuit_views.circuit_from_state)."""
        return circuit_from_state(self.state if not self.unmeasured else {}, view=view or '')


_UNREACHABLE_CLAUSE = re.compile(r'\s*·\s*\d+ unreachable by import(?: \(all scanned\))?')


def _connectivity_line(state=None) -> str:
    """R2 (2026-09-30): the overlay's ONE connectivity line, from the circuit state the graph is drawn from —
    connected nodes, links, and the nodes no link reaches all count the same edges, so they cannot disagree."""
    tick = _TickRead(TARGET_REPO, state=state)
    if tick.unmeasured:
        return f"import map: NOT MEASURED — {tick.unmeasured}"
    names = [str(n.get('name')) for n in tick.state.get('nodes') or []]
    edges = list(tick.state.get('edges') or [])
    reached = {str(dst) for _src, dst in edges}
    unreached = [nm for nm in names if nm not in reached]
    n_conn = sum(1 for n in tick.state.get('nodes') or [] if n.get('connected'))
    line = (f"import map: {n_conn}/{len(names)} files connected · {len(edges)} import links · "
            f"{len(unreached)} file(s) no other file imports — entry points and tests are expected here")
    if unreached:   # every one named — no cap
        line += ' (' + ', '.join(nm.split('/')[-1] for nm in unreached) + ')'
    return line


def _launch_step_detail(key: str, st: dict) -> str:
    """R2: the whitelist step's 'N unreachable by import' (the launch's own import walk) is not shown — the
    connectivity answer is the circuit's, on the wiring step, from the same state as the graph."""
    detail = str(st.get('detail') or '')
    if key == 'whitelist':
        return _UNREACHABLE_CLAUSE.sub('', detail)
    if key == 'wiring' and st.get('status') == 'fail':
        # owner 2026-10-07 04:57: a failed wiring check names every broken file and why, first
        try:
            tick = _TickRead(TARGET_REPO)
            broken = [f"{n.get('relative_path') or n.get('name')}: {n.get('import_error') or 'not connected'}"
                      for n in (tick.state.get('nodes') or []) if not n.get('connected')]
        except Exception:
            broken = []
        return ('WRONG WIRE — ' + ' · '.join(broken) + ' — fix it, then relaunch\n' if broken else detail + '\n') \
            + _connectivity_line()
    if key == 'wiring' and st.get('status') in ('pass', 'degraded'):
        return _connectivity_line()
    return detail


_WATCH_BTN = {'fontSize': '8.5pt', 'padding': '1px 10px', 'whiteSpace': 'nowrap', 'lineHeight': '1.4'}
_SLIDER_STOPS = {
    0: (1000, '1.0s'),
    1: (2500, '2.5s'),
    2: (10000, '10s'),
    3: (30000, '30s'),
    4: (60000, '1m'),
    5: (90000, '1m30'),
    6: (120000, '2m'),
    7: (150000, '2m30'),
    8: (180000, '3m'),
    9: (300000, '5m'),     # owner 2026-09-28: a big repo at 2.5s runs the machine hot
    10: (600000, '10m'),
}

# owner 2026-09-29: the notification band takes NO space when it has nothing to say; when it does, it is at
# most ~3.3em tall (a quarter under the 4.5em it had) and scrolls. show_status_band switches the two.
_BAND_SHOWN = {'padding': '2px 12px', 'maxHeight': '3.3em', 'overflowY': 'auto', 'display': 'block'}
_BAND_HIDDEN = {**_BAND_SHOWN, 'display': 'none'}

_OVERLAY_SHOWN = {
    'position': 'fixed', 'top': '0', 'left': '0', 'width': '100%', 'height': '100%',
    'backgroundColor': 'rgba(0, 0, 0, 0.85)', 'zIndex': '9999',
    'display': 'flex', 'overflow': 'auto', 'padding': '16px', 'boxSizing': 'border-box',
    'transition': 'opacity 0.6s ease',
}

# Standardized dial-tile styles (Path Hacks template)
_TILE_TITLE_STYLE = {'fontSize': '10pt', 'color': '#e6edf3'}
_TILE_WINDOW_STYLE = {
    'whiteSpace': 'pre-wrap', 'fontFamily': 'monospace',
    'backgroundColor': '#111', 'padding': '8px',
    'borderRadius': '4px', 'fontSize': '8pt',
    'lineHeight': '1.3', 'maxHeight': '300px', 'overflowY': 'auto',
}
_TILE_CARD_CLASS = 'bg-dark border-secondary'

# DASH_R (run 185): compact finding rows — one line each, no pre-wrap (the tile's pre-wrap stays for the other
# tiles); what does not fit is ellipsised and rides the row's hover title. Tags are short chips.
_ROW_STYLE = {
    'fontSize': '8pt', 'fontFamily': 'monospace', 'marginLeft': '10px', 'lineHeight': '1.35',
    'whiteSpace': 'nowrap', 'overflow': 'hidden', 'textOverflow': 'ellipsis',
}
_CHIP_STYLE = {
    'fontSize': '7pt', 'color': '#9ca3af', 'border': '1px solid #374151', 'borderRadius': '3px',
    'padding': '0px 4px', 'marginLeft': '6px', 'whiteSpace': 'nowrap',
}
_WITHHELD_PAGE = 25
_SERVER_TOKEN = f"{os.getpid()}-{int(time.time())}"   # cr_trials F5 (2026-11-04): this dashboard process; a page from an older one reloads
app.layout = dbc.Container([
    # ── Startup overlay ─────────────────────────────────────────────────
    html.Div(id='startup-overlay', children=[
        html.Div([
            # owner 2026-09-29: the OPENING SEQUENCE — every step has its own mention and light, in run
            # order, from system_scripts/launch_progress.json (launch.sh + gearbox write it). A running step
            # shows its time climbing, so a long one never looks hung.
            html.Div(id='launch-steps', children=[], style={'marginBottom': '4px'}),
            # the four daemon rows below are the older partial list — kept for the fade logic, not shown
            html.Div([
                html.Span(id='startup-light-dashboard', children='\u25cf',
                          style={'color': '#ef4444', 'fontSize': '10pt', 'marginRight': '10px'}),
                html.Span('dashboard', style={'color': '#e6edf3', 'fontFamily': 'monospace',
                           'fontSize': '10pt', 'width': '140px', 'display': 'inline-block'}),
                html.Span(id='startup-state-dashboard', children='starting',
                          style={'color': '#6b7280', 'fontFamily': 'monospace', 'fontSize': '10pt'}),
            ], style={'display': 'none'}),
            html.Div([
                html.Span(id='startup-light-circuit', children='\u25cf',
                          style={'color': '#ef4444', 'fontSize': '10pt', 'marginRight': '10px'}),
                html.Span('circuit daemon', style={'color': '#e6edf3', 'fontFamily': 'monospace',
                           'fontSize': '10pt', 'width': '140px', 'display': 'inline-block'}),
                html.Span(id='startup-state-circuit', children='waiting',
                          style={'color': '#6b7280', 'fontFamily': 'monospace', 'fontSize': '10pt'}),
            ], style={'display': 'none'}),
            html.Div([
                html.Span(id='startup-light-noai', children='\u25cf',
                          style={'color': '#ef4444', 'fontSize': '10pt', 'marginRight': '10px'}),
                html.Span('noai validator', style={'color': '#e6edf3', 'fontFamily': 'monospace',
                           'fontSize': '10pt', 'width': '140px', 'display': 'inline-block'}),
                html.Span(id='startup-state-noai', children='waiting',
                          style={'color': '#6b7280', 'fontFamily': 'monospace', 'fontSize': '10pt'}),
                html.Span(id='startup-elapsed-noai', children='',
                          style={'color': '#9ca3af', 'fontFamily': 'monospace', 'fontSize': '9pt',
                                 'marginLeft': '12px'}),
            ], style={'display': 'none'}),
            # Item 1 (2026-09-08): the fourth light — the Builder daemon (BUILDER_STATE.json)
            html.Div([
                html.Span(id='startup-light-builder', children='\u25cf',
                          style={'color': '#ef4444', 'fontSize': '10pt', 'marginRight': '10px'}),
                html.Span('solutions', style={'color': '#e6edf3', 'fontFamily': 'monospace',
                           'fontSize': '10pt', 'width': '140px', 'display': 'inline-block'}),
                html.Span(id='startup-state-builder', children='waiting',
                          style={'color': '#6b7280', 'fontFamily': 'monospace', 'fontSize': '10pt'}),
            ], style={'display': 'none'}),
            # Item 8 (2026-09-15): the PURPOSE field on the overlay — the developer's statement of what the
            # target is for, submitted before lift (the lift never waits on it); stored in the intent file
            # labelled `developer`, turned into discrete facts by fixed rules, read by the Ranker's profile.
            html.Div(id='overlay-purpose-block', children=[
                html.Div('purpose — what is this code for? (one or two sentences; saved to the intent file)',
                         style={'color': '#9ca3af', 'fontFamily': 'monospace', 'fontSize': '9pt', 'marginBottom': '4px'}),
                dcc.Textarea(id='purpose-input-overlay', value=_INTENT_TEXT0,
                             placeholder='e.g. A command line tool that reads a CSV of orders and writes a JSON report; run with `python -m orders`; tests with pytest',
                             style={'width': '100%', 'maxWidth': '520px', 'boxSizing': 'border-box', 'height': '64px', 'backgroundColor': '#0b0f14', 'color': '#e6edf3',
                                    'border': '1px solid #374151', 'fontFamily': 'monospace', 'fontSize': '9pt'}),
                html.Div([
                    html.Button('save purpose', id='purpose-submit-overlay', n_clicks=0,
                                style={'backgroundColor': '#1f2937', 'color': '#e6edf3', 'border': '1px solid #374151',
                                       'fontFamily': 'monospace', 'fontSize': '9pt', 'padding': '2px 10px'}),
                    html.Span(id='purpose-feedback-overlay', children='',
                              style={'color': '#22c55e', 'fontFamily': 'monospace', 'fontSize': '9pt', 'marginLeft': '10px'}),
                ], style={'marginTop': '4px'}),
            ], style={'marginTop': '12px', 'borderTop': '1px solid #374151', 'paddingTop': '8px'}),
            # owner 2026-09-28: pick the scan interval up front, with a word on why — a big repo scanned every
            # 2.5s runs the machine hot and the user would not know why. Same setting as the dash's Poll Rate
            # slider (it moves that slider, which writes poll_config). Wording is a first draft.
            html.Div(id='overlay-interval-block', children=[
                html.Div([
                    html.Span('scan interval', style={'color': '#9ca3af', 'fontFamily': 'monospace', 'fontSize': '9pt',
                                                      'marginRight': '10px'}),
                    dcc.Dropdown(id='poll-rate-overlay', value=1, clearable=False, searchable=False,
                                 options=[{'label': lbl, 'value': k} for k, (_ms, lbl) in _SLIDER_STOPS.items()],
                                 style={'width': '110px', 'fontSize': '9pt', 'color': '#111'}),
                ], style={'display': 'flex', 'alignItems': 'center'}),
                html.Div(id='poll-rate-guidance', children='',
                         style={'color': '#6b7280', 'fontFamily': 'monospace', 'fontSize': '8.5pt', 'marginTop': '4px'}),
            ], style={'marginTop': '12px', 'borderTop': '1px solid #374151', 'paddingTop': '8px'}),
            # Item 7 (2026-09-10): the launch control, READ-ONLY on the overlay — the block
            # launch.sh wrote (poll_config.launch_control); the overlay carries the choice, it
            # cannot make it (eslogger needs root at daemon start, before any overlay exists).
            html.Div(id='startup-launch-control', children='launch control: reading…',
                     style={'color': '#9ca3af', 'fontFamily': 'monospace', 'fontSize': '9pt',
                            'marginTop': '12px', 'borderTop': '1px solid #374151', 'paddingTop': '8px'}),
            # owner 2026-09-30: the overlay is never auto-removed — the user leaves it with this button, once
            # every step is green (so the purpose they are typing and the text they are reading are not
            # pulled away). Leaving saves the purpose box if it differs from the intent file.
            html.Div([
                html.Div([
                    html.Button('launching — opens when every step is green', id='overlay-dismiss', n_clicks=0,
                                disabled=True,
                                style={'backgroundColor': '#1f2937', 'color': '#6b7280', 'border': '1px solid #374151',
                                       'fontFamily': 'monospace', 'fontSize': '10pt', 'padding': '4px 14px'}),
                ], id='overlay-dismiss-wrap'),
                # owner 2026-09-30: a failed launch is closed here, never by Ctrl-C in the terminal — the buttons write
                # close_request.json; the gearbox tears down and launch.sh either stops or reopens the setup page
                html.Div([
                    html.Span(id='fail-action-msg', children='',
                              style={'color': '#9ca3af', 'fontFamily': 'monospace', 'fontSize': '9pt',
                                     'marginRight': '12px'}),
                    html.Button('back to setup', id='fail-setup', n_clicks=0,
                                style={'backgroundColor': '#1f2937', 'color': '#e5e7eb', 'border': '1px solid #6b7280',
                                       'fontFamily': 'monospace', 'fontSize': '10pt', 'padding': '4px 14px',
                                       'marginRight': '8px', 'cursor': 'pointer'}),
                    html.Button('close CodeRadar', id='fail-close', n_clicks=0,
                                style={'backgroundColor': '#450a0a', 'color': '#fecaca', 'border': '1px solid #ef4444',
                                       'fontFamily': 'monospace', 'fontSize': '10pt', 'padding': '4px 14px',
                                       'cursor': 'pointer'}),
                ], id='launch-fail-actions', style={'display': 'none'}),
            ], style={'marginTop': '12px', 'borderTop': '1px solid #374151', 'paddingTop': '10px',
                      'textAlign': 'right'}),
        ], style={
            'backgroundColor': '#111', 'padding': '20px 24px',
            'borderRadius': '6px', 'border': '1px solid #374151',
            # owner 2026-09-29: fits a half-screen window — never wider than the window, centred by margin
            'margin': 'auto', 'maxWidth': '760px', 'width': '100%', 'boxSizing': 'border-box',
        }),
    ], style=_OVERLAY_SHOWN),
    # max_intervals here is only the initial budget — update_startup_overlay
    # extends it every tick while the NOAI baseline is still progressing, so
    # long baselines cannot strand the overlay (Phase 6 H1).
    dcc.Interval(id='startup-interval', interval=1000, n_intervals=0, max_intervals=120),
    dcc.Store(id='withheld-page'),      # DASH_R (run 185): the WITHHELD block's page (flip_withheld_page)
    dcc.Store(id='noai-panel-sig'),          # DASH_R: last-sent signature per tab (_unchanged)
    dcc.Store(id='pythonpath-sig'),          # DASH_R: the pythonpath tile's last-sent signature
    dcc.Store(id='io-panel-sig'),            # owner 2026-09-28: the io tile's last-sent signature
    dcc.Interval(id='slow-interval', interval=10000, n_intervals=0),  # 10 s: the intent file re-read
    dcc.Store(id='startup-done', data=False),

    # Header - compact, same line
    html.Div([
        # owner 2026-10-07 05:08: the 'Execution Proof Dashboard' title is removed
        # owner 2026-09-28: the intent (purpose) is entered on the overlay only; this reopens it to add to it
        html.Button('intent', id='intent-open', n_clicks=0,
                    title='Reopen the overlay to add to or change the purpose statement (the intent file)',
                    style={'backgroundColor': '#1f2937', 'color': '#e6edf3', 'border': '1px solid #374151',
                           'fontFamily': 'monospace', 'fontSize': '9pt', 'padding': '1px 10px', 'marginRight': '12px'}),
        html.Span(id='live-verdict'),
        # Item 7 (2026-09-10): the launch-control chip — what this run was launched with, read
        # from circuit_state.launch_control + tracer.alive + trackers (read-only).
        # owner 2026-10-07 05:35: the tracer / trackers / outside-runs / eslogger chip was "completely confusing" —
        # hidden; its callback still fills it (nothing else reads it)
        html.Span(id='launch-control-chip', children='', style={'display': 'none'}),
    ], className='mb-2'),

    # Auto-refresh intervals (max_intervals=-1 means unlimited)
    # FIX_46 (owner Q6, 2026-09-15): the dashboard's two polls are two blades of the ONE cadence table
    # (gearbox.DUTY_CADENCE: dashboard/circuit_interval slot 6, dashboard/verdict_interval slot 7). The
    # FIRST tick of each is its slot offset; `take_cadence_slot` then puts it on the full rate, so the two
    # readers keep their angle on the circumference for the life of the page and never land on the angle
    # of any of the three writers (circuit slot 0, validator slot 2, Builder slot 4).
    dcc.Interval(id='verdict-interval', interval=_CADENCE_SLOT_MS['verdict_interval'],
                 n_intervals=0, max_intervals=-1),
    html.Div(id='server-token-page', children=_SERVER_TOKEN, style={'display': 'none'}),
    html.Div(id='server-token-live', children='', style={'display': 'none'}),
    dcc.Interval(id='circuit-interval', interval=_CADENCE_SLOT_MS['circuit_interval'],
                 n_intervals=0, max_intervals=-1),
    dcc.Store(id='poll-rate-store', data=2500),
    dcc.Store(id='interval-toggle', data=False),
    dcc.Store(id='viewport-bounds', data=None),  # Store current viewport
    # owner 2026-10-06: Reverse1 = one view back (this page's memory, nothing saved), and a redraw per view change
    dcc.Store(id='view-history', data=[], storage_type='memory'),
    dcc.Store(id='view-changed', data=None),
    # owner 2026-10-07 01:30: the view's depth (path parts drawn) is owned by the folder click / Reverse1 —
    # 1 inside the root (its folders), 2 inside a folder (its files), one more per folder level
    dcc.Store(id='view-depth', data=1, storage_type='memory'),
    dcc.Store(id='animation-tick', data=0),  # 0-99 counter for dataflow arrow animation
    # FIX_20 + FIX_28 (2026-09-15): ONE store, two readers — written at the END of update_circuit with
    # {n, ts_ms, nodes, edges, stale, since}; the running label and the frame stamp read it.
    dcc.Store(id='frame-ready', data=None),
    # P4 (B3): the frame stamp (`frame-stamp`) moved from a fixed bottom-right corner of the WINDOW — where it
    # sat over the graph's data area and covered a box — into the Circuit Status header row, right-aligned.
    # P4 (B2): the plot area the graph last drew, [width, height] px — read in the page each tick
    # (`graph-size` clientside callback) and passed to generate_figure so labels are sized for it.
    dcc.Store(id='graph-size', data=None),

    # Hidden elements for callbacks that need them
    dcc.Store(id='proof-dir', data=str(get_latest_proof_dir() or '')),
    dcc.Store(id='entry-point-store', data=''),

    # Poll rate control
    dbc.Card([
        dbc.CardBody([
            # owner 2026-09-28: half height — label left, slider right, one row
            html.Div([
            html.Div([
                html.Span('Poll Rate: ', style={'fontSize': '10pt', 'color': '#6b7280'}),
                html.Span(id='poll-rate-display', children='2.5s',
                          style={'fontSize': '10pt', 'color': '#22c55e', 'fontWeight': 'bold'}),
            ], style={'flex': '0 0 130px'}),
            html.Div([
                dcc.Slider(
                    id='poll-rate-slider',
                    # Dash 4.4: in the default 'mouseup' mode a CLICK on the track/mark moves the thumb but never
                    # commits `value` (only a drag does) — owner 2026-09-28 "setting to L3 does nothing". 'drag'
                    # commits every change; no direct-input box (Dash 4 added it; the dash never had one).
                    updatemode='drag',
                    allow_direct_input=False,
                    min=0,
                    max=10,      # owner 2026-09-28: up to 10 min — 200 files every 2.5s runs the machine hot
                    step=1,
                    value=1,
                    marks={
                        0: {'label': '1s', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        1: {'label': '2.5s', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        2: {'label': '10s', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        3: {'label': '30s', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        4: {'label': '1m', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        5: {'label': '1m30', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        6: {'label': '2m', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        7: {'label': '2m30', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        8: {'label': '3m', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        9: {'label': '5m', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                        10: {'label': '10m', 'style': {'color': '#6b7280', 'fontSize': '8pt'}},
                    },
                    included=False,
                )
            ], style={'flex': '1'}),
            ], style={'display': 'flex', 'alignItems': 'center', 'gap': '12px'}),
        ], style={'padding': '4px 12px 0 12px'})
    ], className='bg-dark border-secondary mt-2'),

    # Navigation: a folder click drills, Reverse1 steps back. owner 2026-10-07 05:20: the watchlist is removed
    # — its 'Watchlist:' line, 'Watch These' button and the folder dropdown that fed it. The folder you are in
    # is still re-read every scan (FIX_39, written on each drill); the dropdown stays hidden because it holds
    # the view the callbacks read.
    dbc.Card([
        dbc.CardBody([
            html.Div([
                dbc.Button('Reverse1', id='clear-watch-button', size='sm', color='secondary',
                          style=_WATCH_BTN, title='Go back to previous view'),
                html.Span(id='watchlist-display', children='', style={'display': 'none'}),
                dbc.Button('Watch These', id='watch-button', style={'display': 'none'}),
            ], style={'display': 'flex', 'alignItems': 'center'}),
            html.Div([
                dcc.Dropdown(id='dir-selector', multi=True),
            ], style={'display': 'none'}),
            html.Div(id='watchlist-feedback',
                     style={'fontSize': '8.5pt', 'color': '#6b7280', 'marginTop': '2px'})
        ], style={'padding': '6px 12px'})
    ], className='bg-dark border-secondary mt-2'),

    # FIX_40 (owner 2026-09-15, from the live dash): THE ONE TEXT BAND — the free band between the directory
    # selector and the `Circuit Status` header. It carries EVERY warning / alert (Item 11's severed link, the
    # cycles warning) as TEXT, and Item 10's intermittent-events list (the app running, the test runners, the
    # dataflows) as TEXT — nothing on the dash is ever drawn over the graph, so nothing can hide what is behind
    # it. Literally empty when there is nothing to say. This is Item 10's ONE FIELD moved up here (the field's
    # rules stand: empty until something happens, then a LIST); the bottom-of-page alert banner is gone.
    # S4 (owner 2026-09-29): the daemon-failure panel. A daemon that dies or hangs stops the run (no restarts);
    # this red panel names it, says why and shows its last log lines, and stays until Ctrl-C closes the dash.
    # Its own 2 s poller — the band's interval follows the Poll Rate slider (up to 10 min), far too slow
    # for "the user is told at once".
    dcc.Interval(id='failure-interval', interval=2000, n_intervals=0, max_intervals=-1),
    html.Div(id='daemon-failure-panel', children=[], style={'display': 'none'}),
    html.Div(id='status-band', children=[
        # owner 2026-09-28: small type, and at most ~4 lines tall — older lines scroll
        html.Div(id='alerts-text', children=[],
                 style={'fontSize': '8pt', 'color': '#ef4444', 'fontFamily': 'monospace',
                        'whiteSpace': 'pre-line', 'fontWeight': 'bold', 'lineHeight': '1.35'}),
        html.Div(id='live-events', children='',
                 style={'fontSize': '8pt', 'color': '#f59e0b', 'fontFamily': 'monospace',
                        'whiteSpace': 'pre-line', 'lineHeight': '1.35'}),
    ], style=_BAND_HIDDEN),

    # Multi-repo state
    dcc.Store(id='active-state-file', data=''),  # '' = grid/auto, path = specific repo

    # Multi-repo grid (dynamically shown/hidden)
    html.Div(id='multi-repo-grid-wrapper', children=[
        html.Div(id='repo-grid', children=[],
                 style={'display': 'grid', 'gridTemplateColumns': 'repeat(auto-fill, minmax(400px, 1fr))',
                        'gap': '10px', 'padding': '10px'}),
    ], style={'display': 'none'}),

    # Back button (shown when viewing single repo in multi-repo mode)
    html.Div(id='back-to-grid-bar', children=[
        html.Button('← All Repos', id='back-to-grid-btn',
                    style={'fontSize': '10pt', 'padding': '4px 12px',
                           'backgroundColor': '#374151', 'color': '#e6edf3',
                           'border': '1px solid #6b7280', 'borderRadius': '4px',
                           'cursor': 'pointer', 'marginRight': '15px'}),
        html.Span(id='active-repo-label', children='',
                  style={'fontSize': '11pt', 'color': '#3b82f6', 'fontWeight': 'bold'}),
    ], style={'display': 'none', 'padding': '8px 0'}),

    # Single unified view (no tabs)
    dbc.Card(id='single-repo-card', children=[
        dbc.CardBody([
            html.Div([
                html.Span('Import map',
                          style={'fontSize': '12pt', 'color': '#6b7280'}),
                # Item 10 (owner 2026-09-15): the running label moved to the ONE field (`live-events`) — every
                # intermittent event lists there; nothing lives in the header. FIX_40: that field is the text
                # band ABOVE this card (`status-band`).
                html.Span('(each box is a file or folder; a line means one imports the other · click a folder to open it · Reverse1 goes back one view)',
                          style={'fontSize': '9pt', 'color': '#6b7280', 'marginLeft': '15px', 'fontStyle': 'italic'}),
                dcc.Input(
                    id='script-search',
                    type='text',
                    placeholder='Find script...',
                    style={
                        'marginLeft': '15px', 'width': '180px', 'height': '24px',
                        'fontSize': '9pt', 'backgroundColor': '#222', 'color': '#e6edf3',
                        'border': '1px solid #555', 'borderRadius': '4px', 'padding': '2px 6px',
                        'verticalAlign': 'middle',
                    },
                ),
                html.Span(id='search-feedback', children='',
                          style={'fontSize': '8pt', 'color': '#f59e0b', 'marginLeft': '8px'}),
                # P4 (B3): the frame stamp — in this header row, never over the plot. Still under the startup
                # overlay (9999) until it lifts: the overlay covers the page, and this sits at 9998 in it.
                html.Div(id='frame-stamp', children='',
                         style={'marginLeft': 'auto', 'position': 'relative', 'zIndex': 9998,
                                'fontFamily': 'monospace', 'fontSize': '9pt', 'color': '#e6edf3',
                                'backgroundColor': 'rgba(0,0,0,0.7)', 'padding': '2px 8px', 'borderRadius': '4px',
                                'border': '1px solid #6b7280'}),
            ], style={'display': 'flex', 'alignItems': 'center', 'flexWrap': 'wrap'}),
            dcc.Store(id='node-positions-store', data={}),
            # FIX_28 (2026-09-15): a figure swap longer than 300 ms shows the spinner — a capture then visibly
            # says "busy" instead of showing a half-drawn graph. FIX_20: the container carries `frame-stale`
            # while no frame has arrived within the threshold.
            # FIX_40 (owner 2026-09-15): NO FLASH between frames. dcc.Loading's default overlay_style is
            # {'visibility': 'hidden'} — it HID the previous frame while the next was computed (the flash the
            # owner saw). The previous frame now stays fully visible until the next figure is in (the spinner
            # still marks busy, FIX_28); Plotly then reacts in place (uirevision). DISPLAY ONLY — every frame is
            # still a complete fresh scan; nothing is cached or carried between scans.
            # owner 2026-09-28: the graph's HEIGHT is the viewer's — drag the bottom-right corner (CSS resize);
            # assets/graph_resize.js redraws the plot to fit and remembers the height per browser. Width stays.
            html.Div(id='circuit-graph-container', className='', children=[
                dcc.Loading(type='dot', delay_show=300, color='#f59e0b',
                            overlay_style={'visibility': 'visible', 'opacity': 1},
                            parent_style={'height': '100%'},
                            children=dcc.Graph(
                    id='circuit-graph',
                    style={'height': '100%'},
                    config={
                        'staticPlot': False,  # Enable zoom/pan
                        'displayModeBar': True,
                        'modeBarButtonsToRemove': ['select2d', 'lasso2d', 'autoScale2d'],
                        'scrollZoom': True,
                        'doubleClick': 'reset',
                        'responsive': True,
                    }
                )),
            ], style={'height': '80vh', 'minHeight': '250px', 'resize': 'vertical', 'overflow': 'hidden'}),
            # Item 10 (owner 2026-09-15): THE ONE FIELD — EMPTY (literally nothing) when nothing runs; when code
            # runs anywhere it is LISTED, one line per event: the app running, a test runner running (pytest /
            # unittest → the file it is run on; several files under test are listed, never drawn), and every
            # active dataflow. Not a tile, not a label elsewhere. FIX_40 (owner 2026-09-15): the field lives in
            # the text band ABOVE the graph (`status-band` → `live-events`), never below it, never over it.
        ])
    ], className='bg-dark border-secondary mt-2'),

    # ===== BIFURCATED LAYOUT: Monitor (left) | NoAI Validator (right) =====
    html.Div([

        # ── LEFT HALF: Monitor tiles ──
        html.Div([

            # PATH HACKS
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Span('path hacks', style=_TILE_TITLE_STYLE),
                        html.Button('Export', id='export-path-hacks-btn',
                                    style={'marginLeft': '10px', 'fontSize': '8pt', 'padding': '2px 8px',
                                           'backgroundColor': '#374151', 'color': '#e6edf3',
                                           'border': '1px solid #6b7280', 'borderRadius': '3px',
                                           'cursor': 'pointer'}),
                        dcc.Download(id='download-path-hacks'),
                    ]),
                    html.Div(id='pythonpath-display', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # MYPY
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Span('mypy Type Checks (target repo)', style=_TILE_TITLE_STYLE),
                        html.Span(id='mypy-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                    ]),
                    html.Div(id='mypy-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # I/O
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Span('I/O', style=_TILE_TITLE_STYLE),
                        html.Span(id='io-tracker-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                    ]),
                    html.Div(id='io-tracker-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # CRC FROZEN FUNCTIONS
            dbc.Card(id='crc-card', children=[
                dbc.CardBody([
                    html.Div([
                        html.Span('CRC Frozen Functions', style=_TILE_TITLE_STYLE),
                        html.Span(id='crc-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                        html.Span(id='crc-accept-status', style={'fontSize': '8pt', 'color': '#6b7280',
                                                                  'marginLeft': '10px'}),
                    ]),
                    html.Div(id='crc-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # NAMING DRIFT (ND2, 2026-10-01, PLAN_NAMING_DRIFT_TRACKER §D) — the PERMANENT data type tracker,
            # modelled on the CRC panel: the badge is `new drift N · pre-existing M · accepted A` once the launch
            # scan has completed and "NOT MEASURED — <reason>" before it (never a bare 0); the window is the
            # groups table (canonical · variant · sites · tier · kind) with ACCEPT AS VARIANT / MAKE CANONICAL
            # per row (`accept_naming_drift` writes accepted_<repoid>.json + the reload flag).
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Span('Naming Drift', style=_TILE_TITLE_STYLE),
                        html.Span(id='naming-drift-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                        html.Span(id='naming-drift-accept-status', style={'fontSize': '8pt', 'color': '#6b7280',
                                                                           'marginLeft': '10px'}),
                    ]),
                    html.Div(id='naming-drift-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # PYTEST (owner 2026-10-07 ~06:45) — a PERMANENT data-type tracker: the last pytest run CodeRadar
            # started (cr_run_module "pytest", recorded by the wrapper's cr_pytest_results plugin). Headline =
            # passed · failed · errors; rows = every failed / error test, where it is, and why.
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Span('pytest', style=_TILE_TITLE_STYLE),
                        html.Span(id='pytest-summary', style={'fontSize': '10pt', 'marginLeft': '20px'}),
                    ]),
                    html.Div(id='pytest-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # CONTRACT VIOLATIONS (DISABLED)
            dbc.Card(id='contracts-card', children=[
                dbc.CardBody([
                    html.Div([
                        html.Span('Contract Violations', style=_TILE_TITLE_STYLE),
                        html.Span(' [disabled]', style={'fontSize': '8pt', 'color': '#6b7280'}),
                        html.Span(id='contracts-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                    ]),
                    html.Div(id='contracts-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

            # DEAD CODE DETECTION — the vulture tracker, chosen per launch (--trackers). B4 / Q-H2-3 (2026-10-01):
            # no static "[disabled]" tag — the badge (vulture-summary) says measured / NOT MEASURED — reason /
            # not run (not in --trackers at launch), from the circuit state.
            dbc.Card(id='vulture-card', children=[
                dbc.CardBody([
                    html.Div([
                        html.Span('Dead Code Detection', style=_TILE_TITLE_STYLE),
                        html.Span(id='vulture-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                    ]),
                    html.Div(id='vulture-results', style=_TILE_WINDOW_STYLE),
                ], style={'padding': '12px'})
            ], className=_TILE_CARD_CLASS),

        ], style={'display': 'flex', 'flexDirection': 'column', 'gap': '8px',
                 'minWidth': '0', 'overflow': 'hidden'}),

        # ── RIGHT HALF: NoAI Validator ──
        html.Div([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Span('counterfeit code check', style=_TILE_TITLE_STYLE),
                        html.Span(id='noai-summary',
                                  style={'fontSize': '10pt', 'marginLeft': '20px'}),
                    ]),
                    html.Div(id='noai-validator-panel', style={
                        **_TILE_WINDOW_STYLE,
                        'maxHeight': 'none',
                    }),
                ], style={'padding': '12px', 'height': '100%'})
            ], className=_TILE_CARD_CLASS, style={'height': '100%'}),
        ], style={'display': 'flex', 'flexDirection': 'column',
                 'minWidth': '0', 'overflow': 'hidden'}),

    ], style={
        'display': 'grid',
        'gridTemplateColumns': '1fr 1fr',
        'gap': '12px',
        'marginTop': '8px',
        'alignItems': 'stretch',
    }),

    # FIX_40 (owner 2026-09-15): the bottom-of-page alert banner (`alerts-container`) is GONE — every warning is
    # text in the band above the graph (`status-band` → `alerts-text`); nothing is ever drawn over the graph.


    # crc-accept-btn is referenced by the live CRC callbacks (update_crc_panel
    # shows/hides it via its style Output; accept_crc_new_files consumes clicks).
    # It stays hidden-wrapped, behavior unchanged; the other removed-feature
    # stubs were excised in slot 8.
    html.Div([
        dbc.Button(id='crc-accept-btn', size='sm', color='warning', style={'display': 'none'}),
    ], style={'display': 'none'})

], fluid=True, className='bg-dark', style={'minHeight': '100vh', 'padding': '4px'})

# =============================================================================
# CALLBACKS
# =============================================================================

# ── Startup overlay callback ────────────────────────────────────────────────

_LIGHT_RED = {'color': '#ef4444', 'fontSize': '10pt', 'marginRight': '10px'}
_LIGHT_GREEN = {'color': '#22c55e', 'fontSize': '10pt', 'marginRight': '10px'}
_STATE_PENDING = {'color': '#6b7280', 'fontFamily': 'monospace', 'fontSize': '10pt'}
_STATE_LIVE = {'color': '#22c55e', 'fontFamily': 'monospace', 'fontSize': '10pt'}


_LAUNCH_PROGRESS_FILE = SCRIPT_DIR / "launch_progress.json"
SETUP_TAB_WAITING = False   # C2 / Q-H1-10: set from --setup-tab in __main__ — a setup page waits on this tab
_LAUNCH_STEP_COLOUR = {'pending': '#4b5563', 'running': '#f59e0b', 'pass': '#22c55e', 'degraded': '#fb923c',
                       'fail': '#ef4444', 'red': '#ef4444',   # red: finished, verdict red, launch goes on (M-54)
                       # C2 / owner ruling 8 (2026-10-01): B8's `interrupted` (a stop request cut the step short —
                       # not measured, nothing failed) gets its own word and colour: violet, neither red nor amber
                       'interrupted': '#a78bfa'}


@app.callback(
    Output('launch-steps', 'children'),
    Input('startup-interval', 'n_intervals'),
)
def update_launch_steps(n):
    """owner 2026-09-29: one row per opening-sequence step — light, name, state, seconds (climbing while
    it runs) and what it did. A dash started without launch.sh has no progress file and shows no list."""
    try:
        doc = read_file_locked(_LAUNCH_PROGRESS_FILE) if _LAUNCH_PROGRESS_FILE.exists() else {}
    except Exception as e:
        return [html.Div(f'launch progress unreadable: {type(e).__name__}: {e}', style={'color': '#ef4444'})]
    if not doc:
        return []
    now = time.time()
    mono = {'fontFamily': 'monospace', 'fontSize': '10pt'}
    rows = []
    for i, key in enumerate(doc.get('order') or [], 1):
        st = (doc.get('stages') or {}).get(key) or {}
        status = st.get('status', 'pending')
        secs = st.get('secs')
        if status == 'running' and st.get('started'):
            secs = now - float(st['started'])
        word = {'pending': 'waiting', 'running': 'running', 'pass': 'done', 'degraded': 'degraded',
                'fail': 'FAILED', 'red': 'FAILED', 'interrupted': 'interrupted'}.get(status, status)
        cell = {**mono, 'display': 'inline-block', 'verticalAlign': 'top'}
        rows.append(html.Div([
            html.Div([
                html.Span(f'{i}', style={**cell, 'color': '#6b7280', 'width': '22px', 'textAlign': 'right',
                                         'marginRight': '8px'}),
                html.Span('\u25cf', style={'color': _LAUNCH_STEP_COLOUR.get(status, '#4b5563'), 'fontSize': '10pt',
                                           'marginRight': '10px'}),
                html.Span(st.get('label') or key, style={**cell, 'color': '#e6edf3', 'width': '300px',
                                                         'maxWidth': 'calc(100% - 200px)'}),
                html.Span(word, style={**cell, 'color': _LAUNCH_STEP_COLOUR.get(status, '#6b7280'), 'width': '70px'}),
                html.Span('' if secs is None else f'{secs:.1f}s', style={**cell, 'color': '#9ca3af', 'width': '56px',
                                                                         'textAlign': 'right'}),
            ], style={'whiteSpace': 'nowrap', 'overflow': 'hidden', 'textOverflow': 'ellipsis'}),
            html.Div(_launch_step_detail(key, st), style={**mono, 'fontSize': '8.5pt', 'whiteSpace': 'pre-line',
                                                         'color': '#fca5a5' if status == 'fail' else '#6b7280',
                                                         'marginLeft': '52px', 'overflowWrap': 'anywhere'})
            if _launch_step_detail(key, st) else None,   # R2: connectivity from the circuit state
        ], style={'marginBottom': '5px'}))
    overall = doc.get('overall')
    if overall == 'failed':
        rows.append(html.Div(doc.get('detail') or 'the launch failed', style={**mono, 'color': '#ef4444', 'marginTop': '6px'}))
        if (doc.get('stages') or {}).get('health', {}).get('status') == 'fail':
            # owner 2026-09-30: say whose problem it is — the health check tests CodeRadar, never the repo
            rows.append(html.Div("the health check tests CodeRadar itself, not your repo — your repo was not changed",
                                 style={**mono, 'color': '#fca5a5', 'marginTop': '4px'}))
    elif overall == 'interrupted':
        # C2 / owner ruling 8: the one closing line for a stop request during the launch steps (B8's record:
        # "interrupted by Ctrl-C at step '…' — nothing failed, nothing measured"), in the step's own colour
        rows.append(html.Div(doc.get('detail') or 'the launch was interrupted — nothing failed, nothing measured',
                             style={**mono, 'color': _LAUNCH_STEP_COLOUR['interrupted'], 'marginTop': '6px'}))
    elif overall in ('running', 'done'):
        rows.append(html.Div('starting CodeRadar — each step lights up as it runs',
                             style={**mono, 'color': '#6b7280', 'fontSize': '9pt', 'marginTop': '6px'}))
    return rows


@app.callback(
    Output('startup-light-dashboard', 'style'),
    Output('startup-state-dashboard', 'children'),
    Output('startup-state-dashboard', 'style'),
    Output('startup-light-circuit', 'style'),
    Output('startup-state-circuit', 'children'),
    Output('startup-state-circuit', 'style'),
    Output('startup-light-noai', 'style'),
    Output('startup-state-noai', 'children'),
    Output('startup-state-noai', 'style'),
    Output('startup-elapsed-noai', 'children'),
    Output('startup-light-builder', 'style'),
    Output('startup-state-builder', 'children'),
    Output('startup-state-builder', 'style'),
    Output('startup-launch-control', 'children'),
    Output('startup-overlay', 'style'),
    Output('startup-interval', 'max_intervals'),
    Output('startup-done', 'data'),
    Input('startup-interval', 'n_intervals'),
    State('startup-done', 'data'),
    prevent_initial_call=False,
)
def update_startup_overlay(n, done):
    """Poll daemon state files and update startup lights. All green: stop polling, enable the leave button."""
    # Item 7: the launch control block, read-only, from poll_config.launch_control
    lc_text = _launch_control_text()
    if done:
        # Already dismissed — hide overlay, stop polling
        return (
            _LIGHT_GREEN, 'live', _STATE_LIVE,
            _LIGHT_GREEN, 'ready', _STATE_LIVE,
            _LIGHT_GREEN, 'monitoring', _STATE_LIVE,
            '',
            _LIGHT_GREEN, 'monitoring', _STATE_LIVE,
            lc_text,
            {'display': 'none'},
            0, True,
        )

    # Dashboard is always live (we're rendering this callback)
    dash_light = _LIGHT_GREEN
    dash_text = 'live'
    dash_style = _STATE_LIVE

    # Circuit daemon — read daemon_phase from circuit_state.json
    circ_light = _LIGHT_RED
    circ_text = 'waiting'
    circ_style = _STATE_PENDING
    try:
        state = read_file_locked(CIRCUIT_STATE_FILE)
        phase = state.get('daemon_phase', '')
        _cw = _validate_daemon_repo(state) if state else None   # R3 (T-12): another target's phase is no light
        if _cw:
            phase, circ_text = '', _cw
        if phase == 'RUNNING':
            circ_light = _LIGHT_GREEN
            circ_text = 'running'
            circ_style = _STATE_LIVE
        elif phase == 'READY':
            circ_light = _LIGHT_GREEN
            circ_text = 'ready'
            circ_style = _STATE_LIVE
        elif phase == 'INIT':
            circ_text = 'initializing'
    except Exception:
        pass

    # NOAI validator — read phase from NOAI_VALIDATION_STATE.json
    noai_light = _LIGHT_RED
    noai_text = 'waiting'
    noai_style = _STATE_PENDING
    noai_elapsed = ''
    try:
        noai_state = read_file_locked(NOAI_STATE_FILE)
        noai_phase = noai_state.get('phase', '')
        _nw = _validate_daemon_repo(noai_state) if noai_state.get('target_repo') else None   # R3 (T-12)
        if _nw:
            noai_phase, noai_text = '', _nw
        if noai_phase == 'MONITORING':
            noai_light = _LIGHT_GREEN
            noai_text = 'monitoring'
            noai_style = _STATE_LIVE
        elif noai_phase in ('DETRITUS', 'ARTIFACTS', 'CHEATSHEETS', 'SEMANTICS', 'IMPORT_TOOLS', 'DISCOVERY'):   # ARTIFACTS: Item 3 (2026-09-10)
            detail = noai_state.get('detail', '')
            progress = noai_state.get('progress', 0.0)
            if detail and progress > 0:
                noai_text = detail
            else:
                noai_text = noai_phase.lower()
        elif noai_phase == 'HEALTH_CHECK':
            noai_text = 'health check'
        elif noai_phase == 'WAITING':
            noai_text = 'waiting for circuit'
        # Compute elapsed since last state update — 'last_scan' is the key the
        # validator actually writes on full state (H6); progress-phase writes
        # carry 'timestamp' only, so fall back to it while baselining.
        ts = noai_state.get('last_scan') or noai_state.get('timestamp') or ''
        if ts and noai_phase not in ('MONITORING', ''):
            from datetime import datetime as _dt, timezone as _tz
            try:
                last_update = _dt.fromisoformat(ts)
                age = (_dt.now(_tz.utc) - last_update).total_seconds()
                if age < 60:
                    noai_elapsed = f'{int(age)}s ago'
                else:
                    noai_elapsed = f'{int(age // 60)}m {int(age % 60)}s ago'
            except (ValueError, TypeError):
                pass
    except Exception:
        pass

    # Builder — read phase from BUILDER_STATE.json (item 1, 2026-09-08; the fourth gate
    # in gearbox.gate_states — overlay and gearbox must not drift)
    builder_light = _LIGHT_RED
    builder_text = 'waiting'
    builder_style = _STATE_PENDING
    try:
        b_state = read_file_locked(BUILDER_STATE_FILE)
        b_phase = b_state.get('phase', '')
        _bw = _validate_daemon_repo(b_state) if b_state else None   # R3 (T-12)
        if _bw:
            b_phase, builder_text = '', _bw
        if b_phase == 'MONITORING':
            builder_light = _LIGHT_GREEN
            builder_text = 'monitoring'
            builder_style = _STATE_LIVE
        elif b_phase == 'BUILDING':
            builder_text = b_state.get('detail') or 'building'
        elif b_phase == 'WAITING':
            builder_text = 'waiting for validator'
        elif b_phase == 'STARTING':
            builder_text = 'starting'
    except Exception:
        pass

    # All green — start fade-out. owner 2026-09-29: under launch.sh the overlay stays until the gearbox
    # says 'ready' — every opening step green AND the all-green list held a moment so it is seen (it faded
    # on the four daemon lights, which land within ~5 s of the health check, so the last greens never showed)
    launch_steps_green = True
    try:
        _lp = read_file_locked(_LAUNCH_PROGRESS_FILE) if _LAUNCH_PROGRESS_FILE.exists() else {}
    except Exception:
        _lp = {}
    if _lp:
        # and every step in the file finished (pass/degraded) — the gearbox's 'ready' is not taken on its own
        import launch_progress
        launch_steps_green = _lp.get('overall') == 'ready' and not launch_progress.unfinished(_lp)
    all_ready = launch_steps_green and (circ_light == _LIGHT_GREEN and noai_light == _LIGHT_GREEN
                 and builder_light == _LIGHT_GREEN)
    if all_ready:
        # owner 2026-09-30: no fade — the overlay stays until the user presses 'open the dashboard'
        # (overlay_ready_button enables it on this tick). max_intervals = n stops the polling here.
        return (
            dash_light, dash_text, dash_style,
            circ_light, circ_text, circ_style,
            noai_light, noai_text, noai_style,
            noai_elapsed,
            builder_light, builder_text, builder_style,
            lc_text,
            no_update, n, True,
        )
    else:
        overlay_style = {
            'position': 'fixed', 'top': '0', 'left': '0', 'width': '100%', 'height': '100%',
            'backgroundColor': 'rgba(0, 0, 0, 0.85)', 'zIndex': '9999',
            'display': 'flex', 'overflow': 'auto', 'padding': '16px', 'boxSizing': 'border-box',
            'transition': 'opacity 0.6s ease',
        }
        # Not all-green yet: keep the poller alive by extending max_intervals
        # past the current tick (H1 — a hard 120 strands the overlay over a
        # healthy app when the NOAI baseline outlives ~2 minutes).
        return (
            dash_light, dash_text, dash_style,
            circ_light, circ_text, circ_style,
            noai_light, noai_text, noai_style,
            noai_elapsed,
            builder_light, builder_text, builder_style,
            lc_text,
            overlay_style, n + 120, False,
        )


def _launch_control_text() -> str:
    """Item 7: the overlay's read-only line — the block launch.sh wrote, or the fact it is absent."""
    try:
        cfg = read_file_locked(POLL_CONFIG_FILE)
        lc = cfg.get('launch_control') if isinstance(cfg, dict) else None
    except Exception:
        lc = None
    if not isinstance(lc, dict):
        return 'launch choices: absent — this run was not started by launch.sh, so no choices were recorded'
    trackers = ','.join(lc.get('trackers') or []) or 'none'
    return (f"launch choices: file-access watcher {lc.get('tracer')} "
            f"· checkers {trackers} · chosen {str(lc.get('chosen_at', ''))[:19]}")



# Item 8 (2026-09-15): the Purpose field's two callbacks. A draft typed on the overlay survives the fade (the card
# takes the overlay's value); submit on either button stores the statement (developer), extracts its facts by the
# fixed tables and appends them — feedback `saved · n facts (developer)`.
@app.callback(
    Output('purpose-input-overlay', 'value', allow_duplicate=True),
    Input('startup-interval', 'n_intervals'),
    State('purpose-input-overlay', 'value'),
    prevent_initial_call=True,
)
def load_purpose_from_file(n, current):
    """On the first tick of a page load the card (and the overlay field) take the intent file's statement when the
    page holds none — a reload or a relaunch shows what was stored (the layout's initial value is read once at
    dashboard start, before any statement of this run)."""
    if n is None or n > 2 or (current or '').strip():
        return no_update
    text, _meta = _intent_initial()
    return text if text else no_update


@app.callback(
    Output('purpose-feedback-overlay', 'children'),
    Input('purpose-submit-overlay', 'n_clicks'),
    State('purpose-input-overlay', 'value'),
    prevent_initial_call=True,
)
def on_purpose_submit(n_overlay, overlay_text):
    if not n_overlay:
        return no_update
    text = overlay_text or ''
    if _refresh_target() is None:
        return f"NOT SAVED: {_target_not_measured()}"
    try:
        _i = _intent_mod()
        data, facts = _i.submit_statement(TARGET_REPO, text)
        st = data.get('statement') or {}
        fb = (f"saved · {len(facts)} facts (developer) · facts by source {_i.facts_by_source(data)}"
              if st else f"cleared · no statement · facts by source {_i.facts_by_source(data)}")
        return fb
    except Exception as e:
        return f"NOT SAVED: {type(e).__name__}: {e}"

@app.callback(
    Output('startup-overlay', 'style', allow_duplicate=True),
    Output('purpose-feedback-overlay', 'children', allow_duplicate=True),
    Input('intent-open', 'n_clicks'),
    Input('overlay-dismiss', 'n_clicks'),
    State('purpose-input-overlay', 'value'),
    prevent_initial_call=True,
)
def toggle_intent_overlay(n_open, n_close, overlay_text):
    """owner 2026-09-28: the header `intent` button reopens the overlay (its purpose field).
    owner 2026-09-30: the overlay is left only by its own button (never auto-removed); leaving saves the purpose
    box when it differs from the stored statement, so typed-but-unsaved intent is never dropped."""
    if dash.callback_context.triggered_id == 'intent-open':
        return {**_OVERLAY_SHOWN, 'opacity': '1'}, no_update
    text = (overlay_text or '').strip()
    stored, _meta = _intent_initial()
    if text == stored.strip():
        return {'display': 'none'}, no_update
    if _refresh_target() is None:
        return no_update, f"NOT SAVED: {_target_not_measured()}"
    try:
        _i = _intent_mod()
        data, facts = _i.submit_statement(TARGET_REPO, text)
        fb = f"saved on close · {len(facts)} facts (developer) · facts by source {_i.facts_by_source(data)}"
        return {'display': 'none'}, fb
    except Exception as e:
        # keep the overlay up — the text the user typed is not stored
        return no_update, f"NOT SAVED: {type(e).__name__}: {e}"


# owner 2026-09-30 (Lane A): the purpose status line says whether the saved statement has reached the cheat sheets —
# "applied at cycle N" when BUILDER_STATE.summary.intent.applied_hash is the intent file's current hash
# (`intent_file.content_hash`); "saved" before the builder's first build for this target (that build reads it);
# "saved — applies at the next cycle" when the builder ran under an older intent. Re-read on the depth tick (10s).
# A NOT SAVED line is never overwritten; with no statement stored the line is left as it is.
_APPLIED_SEP = ' ▸ '   # the save message (if any) stays before it; the status after it is replaced each tick


def _intent_applied_status() -> str | None:
    if _refresh_target() is None:
        return f"applied: {_target_not_measured()}"
    try:
        _i = _intent_mod()
        if not _i.read(TARGET_REPO).get('statement'):
            return None
        cur = _i.content_hash(TARGET_REPO)
        b = read_file_locked(BUILDER_STATE_FILE)
        it = (b.get('summary') or {}).get('intent') or {}
        same_target = str(Path(str(b.get('target_repo') or '')).resolve()) == str(Path(str(TARGET_REPO)).resolve())
        if not (same_target and it.get('applied_hash')):
            # owner 2026-09-30: before the builder's first build the statement is simply saved — that build reads it
            return 'saved'
        if it.get('applied_hash') == cur:
            return f"applied at cycle {it.get('applied_cycle')}"
        return 'saved — applies at the next cycle'
    except Exception as e:
        return f"applied: NOT MEASURED ({type(e).__name__})"


@app.callback(
    Output('purpose-feedback-overlay', 'children', allow_duplicate=True),
    Input('slow-interval', 'n_intervals'),
    State('purpose-feedback-overlay', 'children'),
    prevent_initial_call=True,
)
def refresh_intent_applied(_n, current):
    cur = str(current or '')
    if cur.startswith('NOT SAVED'):
        return no_update
    status = _intent_applied_status()
    if status is None:
        return no_update
    new = f"{cur.split(_APPLIED_SEP)[0]}{_APPLIED_SEP}{status}"
    return new if new != cur else no_update


_CLOSE_REQUEST_FILE = SCRIPT_DIR / "close_request.json"   # read by gearbox._hold_dash_until_ctrl_c and launch.sh


@app.callback(
    Output('launch-fail-actions', 'style'),
    Output('overlay-dismiss-wrap', 'style'),
    Output('fail-setup', 'hidden'),
    Input('startup-interval', 'n_intervals'),
)
def show_fail_actions(_n):
    """owner 2026-09-30: a failed launch swaps the leave button for 'back to setup' / 'close CodeRadar'.
    C2 / Q-H1-10 (2026-10-01): 'back to setup' only when a setup page is waiting on this tab — the gearbox
    hands its --setup-tab on to this process (SETUP_TAB_WAITING); an argv or MCP launch has no page to
    go back to (re-opening one left a setup server on the dash port that cr_stop never saw)."""
    import launch_progress
    shown, hidden = {'display': 'block'}, {'display': 'none'}
    if launch_progress.read(_LAUNCH_PROGRESS_FILE).get('overall') == 'failed':
        return shown, hidden, not SETUP_TAB_WAITING
    return hidden, shown, not SETUP_TAB_WAITING


@app.callback(
    Output('fail-action-msg', 'children'),
    Output('fail-setup', 'disabled'),
    Output('fail-close', 'disabled'),
    Input('fail-setup', 'n_clicks'),
    Input('fail-close', 'n_clicks'),
    prevent_initial_call=True,
)
def request_close(_n_setup, _n_close):
    action = 'setup' if dash.callback_context.triggered_id == 'fail-setup' else 'close'
    try:
        _CLOSE_REQUEST_FILE.write_text(json.dumps({'action': action, 'at': datetime.now().isoformat()}))
    except OSError as e:
        return f"NOT SENT: {type(e).__name__}: {e} — Ctrl-C in the terminal closes CodeRadar", False, False
    msg = ('closing — the setup page opens here in a few seconds' if action == 'setup'
           else 'CodeRadar is closing — nothing is left running; this tab can be closed')
    return msg, True, True


# after 'back to setup' this tab waits for the setup page on the same port (its /check answers JSON; the dashboard
# never does) and turns into it — no second tab
app.clientside_callback(
    """
    function(n) {
        if (!n) { return window.dash_clientside.no_update; }
        const poll = async () => {
            try {
                const r = await fetch('/check?path=', {cache: 'no-store'});
                if ((r.headers.get('content-type') || '').includes('application/json')) { location.replace('/'); return; }
            } catch (e) {}
            setTimeout(poll, 1000);
        };
        setTimeout(poll, 1500);
        return window.dash_clientside.no_update;
    }
    """,
    Output('fail-setup', 'title'),
    Input('fail-setup', 'n_clicks'),
    prevent_initial_call=True,
)


@app.callback(
    Output('overlay-dismiss', 'disabled'),
    Output('overlay-dismiss', 'children'),
    Output('overlay-dismiss', 'style'),
    Input('startup-done', 'data'),
    Input('startup-interval', 'n_intervals'),   # 04:57: a failed launch flips the wording without a done
)
def overlay_ready_button(done, _n=None):
    """Enables the overlay's leave button once update_startup_overlay has seen every step green (startup-done).
    A failed launch keeps it disabled — the overlay holds the failure."""
    base = {'fontFamily': 'monospace', 'fontSize': '10pt', 'padding': '4px 14px'}
    if done:
        return False, 'open the dashboard →', {**base, 'backgroundColor': '#14532d', 'color': '#dcfce7',
                                                 'border': '1px solid #22c55e', 'cursor': 'pointer'}
    try:   # owner 2026-10-07 04:57: "launching" was wrong once the launch had stopped
        import launch_progress
        _failed = launch_progress.read(_LAUNCH_PROGRESS_FILE).get('overall') == 'failed'
    except Exception:
        _failed = False
    if _failed:
        return True, 'launch stopped — fix the red step, then relaunch', {
            **base, 'backgroundColor': '#3f1d1d', 'color': '#fca5a5', 'border': '1px solid #ef4444'}
    return True, 'launching — opens when every step is green', {**base, 'backgroundColor': '#1f2937',
                                                                  'color': '#6b7280', 'border': '1px solid #374151'}



@app.callback(
    Output('overlay-purpose-block', 'style'),
    Output('overlay-interval-block', 'style'),
    Input('circuit-interval', 'n_intervals'),
)
def hide_setup_inputs_on_argv_launch(_n):
    """cr_trials F5 (owner 2026-11-04): an argv or MCP launch made every choice before this page existed (cr_watch
    names the target and trackers; there is no purpose to type), so the purpose and scan-interval inputs are
    hidden; they stay for a launch that came from the setup page (SETUP_TAB_WAITING)."""
    block = {'marginTop': '12px', 'borderTop': '1px solid #374151', 'paddingTop': '8px'}
    if SETUP_TAB_WAITING:
        return block, block
    return {'display': 'none'}, {'display': 'none'}


@app.callback(Output('server-token-live', 'children'), Input('circuit-interval', 'n_intervals'))
def serve_token(_n):
    return _SERVER_TOKEN


app.clientside_callback(
    """
    function(live, page) {
        if (live && page && live !== page) { location.reload(); }
        return window.dash_clientside.no_update;
    }
    """,
    Output('server-token-page', 'title'),
    Input('server-token-live', 'children'),
    State('server-token-page', 'children'),
)

@app.callback(
    Output('launch-control-chip', 'children'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_launch_control_chip(n_intervals, active_state_file):
    """Item 7: header chip — what this run was launched with and whether the tracer is alive,
    from circuit_state (launch_control, tracer, trackers). Read-only; never a control."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    if not state:
        return ''
    if state.get(_WRONG_TARGET):
        return state[_WRONG_TARGET]
    if state.get('daemon_phase') == 'ERROR':
        return f"the import map REFUSED to start: {state.get('error_reason', 'no reason published')}"
    lc = state.get('launch_control') or {}
    tr = state.get('tracer') or {}
    trk = state.get('trackers') or {}
    if not lc:
        return 'launch choices: absent'
    alive = 'alive' if tr.get('alive') else 'NOT alive'
    chosen = ','.join(trk.get('chosen') or []) or 'none'
    # B4 / Q-H0-3 (2026-10-01): a chosen tracker that measured nothing is named with its reason (R4 publishes
    # `trackers.not_measured` token -> reason) — the chip never lists it as if it had run.
    nm = trk.get('not_measured') or {}
    nm_text = ''.join(f" · {t} NOT MEASURED ({r})" for t, r in sorted(nm.items())) if isinstance(nm, dict) else ''
    # M-48 / C (owner 2026-10-06): a target run the process table shows but the wrapper did not start is
    # named — the user sees CR noticed it, and that its links are not lit from it (no proof of what ran).
    runs = [r for r in (state.get('outside_runs') or []) if isinstance(r, dict)]
    # A (owner 2026-10-06): a run the eslogger load proof covers is PROVEN — its loads light links
    lp = state.get('load_proof') or {}
    proven_pids = {r.get('pid') for r in (lp.get('runs') or []) if isinstance(r, dict)}
    seen_only = [r for r in runs if r.get('pid') not in proven_pids]
    runs_text = (" · running outside CodeRadar (seen, not proof — links not lit): " + ', '.join(
        f"{r.get('node') or r.get('script')} pid {r.get('pid')}" for r in seen_only)) if seen_only else ''
    if lp.get('status') == 'recording':
        runs_text += f" · load proof: recording · {lp.get('verified', 0)} module(s) proven"
    elif lp.get('status') == 'NOT MEASURED':
        runs_text += f" · load proof NOT MEASURED ({lp.get('reason')})"
    else:   # owner 2026-10-07 05:08: silence read as "eslogger is on" — say it is off on this launch
        runs_text += " · eslogger load proof: off (not started on this launch)"
    return (f"tracer {tr.get('backend') or lc.get('tracer')} · {alive} · "
            f"trackers {chosen}{nm_text}{runs_text}")




# Callback: slider changes -> update display, write config, trigger toggle
@app.callback(
    Output('poll-rate-display', 'children'),
    Output('poll-rate-store', 'data'),
    Output('interval-toggle', 'data'),
    Input('poll-rate-slider', 'value'),
    State('interval-toggle', 'data'),
    prevent_initial_call=False
)
def on_slider_change(value, toggle):
    """Store new rate, write to config file for daemon, toggle to trigger restart."""
    if value is None:
        value = 1
    rate_ms, display = _SLIDER_STOPS.get(int(value), (2500, '2.5s'))
    if dash.callback_context.triggered_id is None:
        # owner 2026-09-28: a page LOAD never writes the rate — the slider's layout default (2.5s) used to
        # overwrite the rate the viewer chose (10m) on every reload; sync_poll_slider sets the thumb
        # from the config, and that change comes back here as a real trigger
        return display, rate_ms, not toggle
    # Write to shared config file so daemon can read it (preserve other config values)
    try:
        config = read_file_locked(POLL_CONFIG_FILE)
        # M-49 (2026-10-06): the rate jumped to 5m / 3m / 30s three times with nobody choosing it — every write
        # now names what moved the slider, so the next jump is attributable from the log alone
        logger.info("poll rate write: %s ms -> %s ms (slider index %s, via %s)", config.get('interval_ms'),
                    rate_ms, value, dash.callback_context.triggered_id)
        config['interval_ms'] = rate_ms
        write_file_locked(POLL_CONFIG_FILE, config)
    except Exception:
        pass  # Don't break UI if file write fails
    return display, rate_ms, not toggle

@app.callback(
    Output('poll-rate-slider', 'value'),
    Output('poll-rate-overlay', 'value'),
    Input('startup-interval', 'n_intervals'),
    prevent_initial_call=False,
)
def sync_poll_slider(n):
    """On page load, put the thumb on the rate the daemons are actually running at (poll_config)."""
    if n:
        return no_update, no_update
    try:
        ms = read_file_locked(POLL_CONFIG_FILE).get('interval_ms')
    except Exception:
        return no_update, no_update
    pos = next((k for k, (v, _) in _SLIDER_STOPS.items() if v == ms), None)
    return (no_update, no_update) if pos is None else (pos, pos)


@app.callback(
    Output('poll-rate-slider', 'value', allow_duplicate=True),
    Input('poll-rate-overlay', 'value'),
    prevent_initial_call=True,
)
def overlay_poll_rate(value):
    """The overlay's interval picker moves the Poll Rate slider; the slider's callback writes the config."""
    logger.info("poll rate: overlay picker -> slider index %s", value)   # M-49: attributable
    return no_update if value is None else value


@app.callback(
    Output('poll-rate-guidance', 'children'),
    Input('startup-interval', 'n_intervals'),
)
def overlay_poll_guidance(n):
    """Say how many files each scan reads (the picker itself is set from the config by sync_poll_slider —
    mirroring it from the slider would loop with overlay_poll_rate, and Dash drops a looped pair).
    R3 (T-15): re-said every startup tick — at tick 0 this run's whitelist is not written yet."""
    # R2/I2 (2026-09-30): the count is the launch scan's (whitelist summary.live) — never a walk of the target here
    _wait = _whitelist_wait()   # R3 (T-15): the previous run's summary.live is not this run's count
    if _wait:
        return (f"Python file count: NOT MEASURED ({_wait}). The whole repo is checked once, "
                "while this screen is up; after that each scan re-reads only the files that changed.")
    try:
        n_files = int(((read_file_locked(SCRIPT_DIR / f"whitelist_{get_repo_id(Path(TARGET_REPO))}.json")
                        .get('summary') or {}).get('live')))
    except Exception as e:
        logger.warning(f"poll guidance: whitelist summary.live unreadable ({e}); file count not shown")
        n_files = None
    if n_files is None:
        return ("Python file count: NOT MEASURED (no launch-scan whitelist yet). The whole repo is checked once, "
                "while this screen is up; after that each scan re-reads only the files that changed.")
    # owner 2026-09-29: the heavy checks run once (this screen's full pass), then only on changed files — the
    # old "a short interval keeps the CPU busy" overstated a per-tick scan that is now a fraction of a second
    # 2026-09-29 review: except mypy — circuit_daemon runs it whole-repo (--no-incremental) on any change
    return (f"{_plural(n_files, 'Python file')}. The whole repo is checked once, while this screen is up; after that each "
            f"scan re-reads only the files that changed. The one exception is the mypy tracker, when chosen: it "
            f"re-checks the whole repo whenever any file changes, which is the heavy part on a big repo. Short: watch an agent "
            f"writing code as it happens. Long: fewer scans on a big repo you're mostly leaving alone. "
            f"You can change it later with the Poll Rate slider.")


app.clientside_callback(
    """
    function(alerts, events) {
        function has(c) {
            if (c === null || c === undefined) { return false; }
            if (Array.isArray(c)) { return c.some(has); }
            if (typeof c === 'string') { return c.trim().length > 0; }
            return true;
        }
        var on = has(alerts) || has(events);
        return {padding: '2px 12px', maxHeight: '3.3em', overflowY: 'auto', display: on ? 'block' : 'none'};
    }
    """,
    Output('status-band', 'style'),
    Input('alerts-text', 'children'),
    Input('live-events', 'children'),
)


# Callback: toggle changes -> apply new rate to intervals
@app.callback(
    Output('verdict-interval', 'interval'),
    Output('verdict-interval', 'n_intervals'),
    Output('verdict-interval', 'max_intervals'),
    Output('circuit-interval', 'interval'),
    Output('circuit-interval', 'n_intervals'),
    Output('circuit-interval', 'max_intervals'),
    Input('interval-toggle', 'data'),
    State('poll-rate-store', 'data'),
    prevent_initial_call=True
)
def apply_new_rate(toggle, rate):
    """Apply new rate: reset counters and restart intervals.

    Reads rate from config file as ground truth (store may be stale due to
    Dash output batching). Falls back to store value, then default.
    """
    # Read ground truth from config file (same file on_slider_change writes to)
    try:
        config = read_file_locked(POLL_CONFIG_FILE)
        file_rate = config.get('interval_ms')
        if file_rate and isinstance(file_rate, (int, float)) and file_rate >= 1000:
            rate = int(file_rate)
    except Exception:
        pass  # Fall through to store value
    if rate is None:
        rate = 2500
    # Reset n_intervals=0, set new interval, max_intervals=-1 (unlimited)
    return rate, 0, -1, rate, 0, -1

@app.callback(
    Output('circuit-interval', 'interval', allow_duplicate=True),
    Input('circuit-interval', 'n_intervals'),
    State('poll-rate-store', 'data'),
    prevent_initial_call=True,
)
def take_cadence_slot_circuit(n, rate):
    """FIX_46: after the slot-offset first tick, run at the full rate — the offset is kept forever."""
    if n != 1:
        return no_update
    return int(rate or 2500)


@app.callback(
    Output('verdict-interval', 'interval', allow_duplicate=True),
    Input('verdict-interval', 'n_intervals'),
    State('poll-rate-store', 'data'),
    prevent_initial_call=True,
)
def take_cadence_slot_verdict(n, rate):
    """FIX_46: the panels' poll takes slot 7 — one slot behind the frame's slot 6."""
    if n != 1:
        return no_update
    return int(rate or 2500)



def _search_match(query: str, names: list):
    """The node a search names, best first (owner 2026-10-07 01:18, "search still wildly off target": `the`
    landed on mac_and_dennis_move_to_THE_suburbs.py). Ranks: the whole name · the file name · the file name
    STARTS with it · the whole name starts with it · anywhere in the file name · anywhere at all; within a
    tier the first node in the graph's own order. The clientside feedback (`search-feedback`) matches the same way."""
    q = query.strip().lower()
    if not q:
        return None
    def _clean(n):
        return n.replace('\U0001f4c1', '').lower()
    def _tail(n):
        return _clean(n).split('/')[-1]
    for rank in (lambda n: _clean(n) == q, lambda n: _tail(n) == q, lambda n: _tail(n).startswith(q),
                 lambda n: _clean(n).startswith(q), lambda n: q in _tail(n), lambda n: q in _clean(n)):
        for n in names:
            if rank(n):
                return n
    return None


# Callback: capture viewport changes
@app.callback(
    Output('viewport-bounds', 'data'),
    Input('circuit-graph', 'relayoutData'),
    prevent_initial_call=True
)
def capture_viewport(relayout_data):
    """Store viewport bounds when user zooms/pans."""
    if not relayout_data:
        return None

    # Extract axis ranges from relayout data
    bounds = {}
    if 'xaxis.range[0]' in relayout_data:
        bounds['x_min'] = relayout_data['xaxis.range[0]']
        bounds['x_max'] = relayout_data['xaxis.range[1]']
        bounds['y_min'] = relayout_data['yaxis.range[0]']
        bounds['y_max'] = relayout_data['yaxis.range[1]']
        return bounds

    return None

def _write_viewed_dirs(dirs) -> None:
    """FIX_39: publish the directories the user is looking at for the circuit daemon's cadence.
    MERGE, never replace (Item 7's rule: a replace erased the launch-control block once)."""
    try:
        config = read_file_locked(POLL_CONFIG_FILE)
        config['viewed_dirs'] = [str(d) for d in (dirs or [])]
        # owner 2026-10-07 ~05:50: every folder viewed this run keeps its JSONL dash mirrors (the circuit daemon
        # writes them); the pre-flight clears this file, so the list is per run
        config['viewed_dirs_seen'] = sorted(set(config.get('viewed_dirs_seen') or []) | set(config['viewed_dirs']))
        write_file_locked(POLL_CONFIG_FILE, config)
    except Exception as e:
        logger.error(f"viewed_dirs write failed (merge only, never replace): {e}")


# Callback: Watch These / Reverse1 — one callback owns the view (folders + depth); nothing is saved
# (2026-09-28: this decorator had drifted onto _write_viewed_dirs, so every Watch These / Reverse1
# click raised TypeError and did nothing)
@app.callback(
    Output('watchlist-feedback', 'children'),
    Output('watchlist-display', 'children'),
    Output('view-depth', 'data'),
    Output('dir-selector', 'value', allow_duplicate=True),
    Output('view-history', 'data'),
    Output('view-changed', 'data'),
    Input('watch-button', 'n_clicks'),
    Input('clear-watch-button', 'n_clicks'),
    Input('circuit-graph', 'clickData'),
    State('dir-selector', 'value'),
    State('view-depth', 'data'),
    State('view-history', 'data'),
    prevent_initial_call=True
)
def update_watchlist(watch_clicks, clear_clicks, click_data,
                     dir_selection, depth_value, history):
    """owner 2026-10-06: every view change redraws the graph now (`view-changed`) — a sideways click between
    folders at the same depth used to wait for the next poll tick, so a drilled view "couldn't navigate". And
    Reverse1 steps back ONE view (`view-history`, this page's memory only, never written anywhere), not to the
    root. The old body follows."""
    out = _update_watchlist(click_data, dir_selection, depth_value)
    if out[2] is no_update and out[3] is no_update:
        return (*out, no_update, no_update)
    hist = list(history or [])
    if out[0] == 'back':
        prev = hist.pop() if hist else {'depth': 1, 'dirs': []}
        _write_viewed_dirs(prev['dirs'])
        return ("\u2713 Back", out[1], prev['depth'], prev['dirs'], hist, time.time())
    hist.append({'depth': int(depth_value or 1), 'dirs': list(dir_selection or [])})
    return (*out, hist[-20:], time.time())


def hist_has_prev(depth) -> bool:
    """A view below the root exists to step back from: the depth is past the root's own (1)."""
    return int(depth or 1) != 1


def _view_depth(view: str) -> int:
    """The layer a view sits on: 1 at the root, one more per folder of its path (M-52's numbering)."""
    return 1 + len([p for p in (view or '').split('/') if p])


def _update_watchlist(click_data, dir_selection, depth_value):
    """Watch These / a folder click = drill in. Reverse1 = the previous view, worked out from the current one.
    # FIX 2026-09-06 (owner): the poll interval no longer shares this callback — a click that landed near a tick was
    attributed to the tick and ignored, which is why Reverse1 looked broken."""
    from dash import ctx
    depth = int(depth_value or 1)
    if ctx.triggered_id is None:
        return no_update, no_update, no_update, no_update

    # --- Reverse1: step back. owner 2026-09-29: no view is saved — each frame is a new scan, and the view
    # on screen (the selected folders + the depth) already says what the previous one was: the same folders
    # one level up, or the root once the first level is left (nothing preselected, # FIX 2026-09-06 (owner)).
    if ctx.triggered_id == 'clear-watch-button':
        if dir_selection or hist_has_prev(depth):  # a step back exists — the wrapper pops the last view
            return 'back', _get_watchlist_display_local(), None, None
        return "Already at root", _get_watchlist_display_local(), no_update, no_update

    # --- a click on the graph: drill into a folder (owner 2026-09-28 — no need to select it in the dropdown
    # first). S3 2026-09-29: this is the ONLY handler of a graph click (the old dropdown toggle raced it and
    # un-selected an already-selected folder). What drills, all resolved to a scanned top folder:
    #   a folder node (its customdata) · a folder label or a sideways box ("other/") · a deeper
    #   out-of-view box ("nodes/transforms/" — its files are the top folder's, one level down).
    # Only a label ending in '/' is a folder or a box: a file node ("nodes/transforms/x.py"), a missing-import
    # mark or a grey (unscanned) folder does nothing.
    if ctx.triggered_id == 'circuit-graph':
        point = next(iter((click_data or {}).get('points') or []), {})
        _custom = point.get('customdata')
        _txt = str(point.get('text') or '')
        # M-65: the node's customdata is the folder's PATH; a label click carries its text ('b/' inside
        # view 'a', or 'a/other/' for a box off the view's path) — resolved against the folder paths
        if isinstance(_custom, str) and _custom.startswith(FOLDER):
            drill = _custom[len(FOLDER):].strip()
        elif _txt.endswith('/'):
            _lbl = _txt.rstrip('/')
            _cur = next((str(v) for v in (dir_selection or []) if v), '')
            drill = next((c for c in ((_cur + '/' + _lbl) if _cur else _lbl, _lbl) if c in _scanned_top_dirs()), None)
        else:
            drill = None
        if drill is None or drill not in _scanned_top_dirs():
            return no_update, no_update, no_update, no_update
        dir_selection = [drill]

    # --- Watch These: drill into selected dirs at depth+1 ---
    selected = [str(v) for v in (dir_selection or []) if v]
    if not selected:
        return "⚠ Select directories first", _get_watchlist_display_local(), no_update, no_update
    # M-65: ONE view at a time — the folder path drilled into; a level with exactly one folder and no file
    # is a pass-through (rule 3), so the view settles on the first real stop under the click
    view = _settled_view(selected[-1])
    selected = [view] if view else []
    if not selected:
        return "⚠ Select directories first", _get_watchlist_display_local(), no_update, no_update

    # cap at the repo's own deepest level (the files); a drill never moves the view UP — the depth walk
    # failing leaves 1 level, which used to send the "drill" to the root while it said "Drilling into"
    new_depth = _view_depth(view)
    _write_viewed_dirs(selected)               # FIX_39: these directories are now at full rate
    names = ', '.join(d + '/' for d in selected)
    if new_depth != depth:                     # the view moves to another level
        return (f"\u2713 Drilling into {_plural(len(selected), 'dir')}: {names}",
                _get_watchlist_display_local(), new_depth, selected)
    # owner 2026-10-06: a click on a folder at the same depth MOVES there (sideways) — say so, not "no deeper"
    return (f"\u2713 Showing {_plural(len(selected), 'dir')}: {names}",
            _get_watchlist_display_local(), no_update, selected)


# FIX 2026-09-06 (owner): the watchlist text's periodic refresh is separate from the button callback —
# S7 (2026-09-29): it rides update_circuit's tick (one walk per tick), no longer its own interval callback.
def _get_watchlist_display_local(dirs: Optional[list] = None, state: Optional[dict] = None):
    """The watchlist text: the target's listed directories. A2 / Q-H2-5 (2026-10-01): from the circuit daemon's
    published state (`_target_dirs`; *state* = the tick's one read when the caller has it) — never a listing of
    the target; an unmeasured state says NOT MEASURED, never "No directories found"."""
    _wait = _whitelist_wait()   # R3 (T-15): nothing of the target's watchlist until this run's whitelist scan
    if _wait:
        return _wait
    if TARGET_REPO is None:   # R11: _whitelist_wait above already said so; never a walk of no target
        return _target_not_measured()
    st = state if state is not None else read_circuit_state()
    _un = circuit_state_unmeasured(st)
    if _un:
        return f"directories: NOT MEASURED — {_un}"
    if dirs is None:
        dirs = _target_dirs(TARGET_REPO, st)
    if dirs:
        return f"{_plural(len(dirs), 'dir')}: {', '.join(d + '/' for d in dirs)}"
    return "No directories found"

@app.callback(
    Output('proof-dir', 'data'),
    Input('verdict-interval', 'n_intervals'),
    prevent_initial_call=True
)
def update_proof_dir(n_intervals):
    """Auto-update to latest proof directory."""
    latest = get_latest_proof_dir()
    return str(latest) if latest else ''

@app.callback(
    Output('live-verdict', 'children'),
    Input('verdict-interval', 'n_intervals'),
    State('proof-dir', 'data')
)
def update_live_verdict(n_intervals, proof_dir):
    """Empty - verification notification removed."""
    return ""




_WRONG_TARGET = '_wrong_target'   # R3: the key a reader returns alone when its state is not this target's


def _validate_daemon_repo(state: dict) -> Optional[str]:
    """R3 (2026-09-30, T-12): was a no-op that returned True. Now: None when *state* names this
    dashboard's target (realpath of its `target_repo` == realpath of TARGET_REPO); otherwise the one
    line the reader shows instead of the state — "state from another target", or the target NOT MEASURED."""
    if _refresh_target() is None:
        return _target_not_measured()
    named = str(state.get('target_repo') or '')
    if named != '' and os.path.realpath(named) == os.path.realpath(str(TARGET_REPO)):
        return None
    if named == '' and state.get('daemon_phase') == 'ERROR' and not state.get('nodes'):
        # C2 / Q-H0-7 (2026-10-01): the circuit daemon's REFUSAL record (T-12: poll_config names no target) —
        # no graph in it, nothing of another target; the readers show its error_reason, not "another target"
        return None
    return f"state from another target ({named or 'the state names no target_repo'})"


def _whitelist_wait() -> Optional[str]:
    """R3 (2026-09-30, T-15): None once THIS launch's whitelist scan has written its file; otherwise why not.
    launch.sh removes launch_progress.json at the start of every launch, so stages.whitelist.status ==
    'pass' in it is this launch's; the file's mtime must also be at or after that stage's start."""
    target = _refresh_target()
    if target is None:
        return _target_not_measured()
    try:
        stage = (read_file_locked(_LAUNCH_PROGRESS_FILE).get('stages') or {}).get('whitelist') or {}
    except Exception as e:
        return f"waiting for this run's sort of Python files from other files (launch_progress.json unreadable: {e})"
    if stage.get('status') != 'pass':
        return f"waiting for this run's sort of Python files from other files (that launch step is {stage.get('status', 'not started')})"
    wl = SCRIPT_DIR / f"whitelist_{get_repo_id(target)}.json"
    try:
        written = wl.stat().st_mtime
    except OSError as e:
        return f"waiting for this run's sort of Python files from other files ({wl.name}: {e.strerror})"
    started = stage.get('started')
    if isinstance(started, (int, float)) and written < started:
        return f"waiting for this run's sort of Python files from other files ({wl.name} predates this launch)"
    return None


def _scan_scope():
    """The ONE scan surface (system_scripts/scan_scope.py, beside this file) — FIX_13 / FIX_15
    (2026-09-10): every walk in the dashboard consumes it; no private dot / name test remains."""
    try:
        import scan_scope
    except ImportError:
        sys.path.insert(0, str(SCRIPT_DIR.resolve()))
        import scan_scope
    return scan_scope


def _whitelist_of(target_repo: Path) -> frozenset:
    """The launcher's whitelist for *target_repo* (relative paths; empty when absent).
    R3 (T-15): empty until THIS launch's whitelist stage has passed (_whitelist_wait) — the previous run's
    file is kept on disk (the owner's `functions` survive regeneration) but never read early."""
    if _whitelist_wait():
        return frozenset()
    try:
        return frozenset(e.get('path') for e in read_file_locked(
            SCRIPT_DIR / f"whitelist_{get_repo_id(target_repo)}.json").get('entries', []) if e.get('path'))
    except Exception:
        return frozenset()


def _target_dirs(target_repo: Path, state: Optional[dict] = None) -> list:
    """Top-level directories of the target the dashboard may list — A2 / Q-H2-5 (2026-10-01): from the
    circuit daemon's PUBLISHED state only (owner 2026-09-29: one scan scans everything; R2 moved the graph
    onto the state and this `iterdir()` of the target root was the listing left behind). A dir is listed
    when a published node (`relative_path`) or a published whitelist entry (`whitelisted_files` — the launch
    scan's excluded files, so a whitelisted dir stays visible as a folder) lies under it; engine hard-skips
    (FIX_13) are dropped by name. An unmeasured state lists nothing — the watchlist text says why itself."""
    _ss = _scan_scope()
    st = state if state is not None else read_circuit_state()
    if circuit_state_unmeasured(st):
        return []
    rels = [str(n.get('relative_path') or n.get('name') or '') for n in st.get('nodes') or []]
    rels += [str(p) for p in st.get('whitelisted_files') or []]
    dirs = {r.split('/', 1)[0] for r in rels if '/' in r}
    return sorted(d for d in dirs if d and not _ss.hard_skipped(Path(d)))


def read_circuit_state(state_file=None) -> dict:
    """Read circuit state from daemon's JSON state file. Fresh read every time."""
    filepath = Path(state_file) if state_file else CIRCUIT_STATE_FILE
    if not filepath.exists():
        return {}
    try:
        state = read_file_locked(filepath)
    except Exception as e:
        logging.warning(f"Error reading circuit state: {e}")
        return {}
    # R3 (T-12): a state that is not this target's is never shown — the reader gets the one line alone.
    wrong = _validate_daemon_repo(state) if state else None
    return {_WRONG_TARGET: wrong} if wrong else state


def _not_this_target(state: dict, *extra) -> Optional[tuple]:
    """R3: the (panel, summary, summary style, *extra) a tracker panel returns when its state is not this
    target's; None when it is."""
    if _WRONG_TARGET in state:   # read_circuit_state puts this key in a state only when it is another target's
        return (html.Div(state[_WRONG_TARGET], style={'color': '#f59e0b', 'fontSize': '9pt', 'fontStyle': 'italic'}),
                "NOT MEASURED", {'fontSize': '10pt', 'color': '#f59e0b', 'marginLeft': '20px'}, *extra)
    return None


def _tracker_not_published(name: str, state: dict, *extra) -> tuple:
    """B4 / Q-H2-1 (2026-10-01): the tile a tracker shows when its reading is not in the published state — no
    circuit state read (`_connectivity_line`'s reason) or the tracker key absent — amber NOT MEASURED, same tuple
    shape as `_not_this_target`; the 'measured — waiting/empty' texts fire only on a published `status == 'measured'`."""
    why = (circuit_state_unmeasured(state) if not state else
           f"not published in circuit state (daemon phase: {state.get('daemon_phase') or 'unknown'})")
    return (html.Div(f"{name}: NOT MEASURED — {why}",
                     style={'color': '#f59e0b', 'fontSize': '9pt', 'fontStyle': 'italic'}),
            "NOT MEASURED", {'fontSize': '10pt', 'color': '#f59e0b', 'marginLeft': '20px'}, *extra)


# FIX_20 (2026-09-15): frame staleness — the ONE threshold is electricity.py's (max(2 * interval, floor));
# a frame that did not arrive says so on the graph instead of leaving the old picture standing.
try:
    from electricity import _STALE_FLOOR_SECONDS as _FRAME_STALE_FLOOR_S, stale_threshold_s as _stale_threshold_s
except Exception:  # electricity.py is beside this file; a missing import must not take the dash down
    _FRAME_STALE_FLOOR_S = 10.0
    _stale_threshold_s = None


def _frame_stale_threshold_s(state_file=None) -> float:
    """electricity.stale_threshold_s — max(2 * poll interval, floor, 2 * (interval + the measured cycle
    `cycle_s` the frame carries)); I-90: scales with the cycle, no cap. The terminal printer's rule."""
    interval_s = 2.5
    try:
        interval_s = float(read_file_locked(POLL_CONFIG_FILE).get('interval_ms', 2500)) / 1000.0
    except Exception:
        pass
    cycle_s = None
    try:
        _st = read_file_locked(Path(state_file) if state_file else CIRCUIT_STATE_FILE) or {}
        _cs = [v for v in (_st.get('cycle_s'), _st.get('cycle_max_s')) if isinstance(v, (int, float))]
        cycle_s = max(_cs) if _cs else None   # I-90: the larger of this frame's cycle and the recent max
    except Exception:
        pass
    if _stale_threshold_s is None:
        return max(2.0 * interval_s, _FRAME_STALE_FLOOR_S)
    return _stale_threshold_s(interval_s, cycle_s)


def frame_freshness(state_file=None, now=None) -> dict:
    """The last frame's age from circuit_state.json's mtime: {stale, mtime, age_s, threshold_s, since}.
    `since` = HH:MM:SS of the last write ('never' when the file is absent). stale is True when the file is
    missing/unreadable or older than the threshold — nothing is inferred from the previous picture."""
    filepath = Path(state_file) if state_file else CIRCUIT_STATE_FILE
    now = time.time() if now is None else now
    threshold = _frame_stale_threshold_s(filepath)
    try:
        mtime = filepath.stat().st_mtime
    except OSError:
        return {"stale": True, "mtime": None, "age_s": None, "threshold_s": threshold, "since": "never"}
    age = now - mtime
    return {"stale": age > threshold, "mtime": mtime, "age_s": round(age, 1), "threshold_s": threshold,
            "since": datetime.fromtimestamp(mtime).strftime('%H:%M:%S')}


def _stale_banner(fig, fresh: dict):
    """FIX_20: the visible STALE mark — red, top-left, on the figure itself so a capture carries it."""
    fig.add_annotation(text=("STALE — no graph yet" if fresh['since'] == 'never'
                             else f"STALE — the map has not been redrawn since {fresh['since']}"),
                       xref='paper', yref='paper', x=0.0, y=1.0, xanchor='left', yanchor='top',
                       showarrow=False, font=dict(color='#ef4444', size=16, family='monospace'),
                       bgcolor='rgba(0,0,0,0.65)', bordercolor='#ef4444', borderwidth=1, borderpad=6)
    return fig


# A2 / Q-H0-8 (2026-10-01): `discover_scripts` (the dashboard's own rglob walk of the target, pre-R2) deleted —
# no caller since R2; the graph, dropdown and watchlist read the circuit daemon's published state.


# --- Dropdown options (from the published circuit state — A2 / Q-H2-5) — S7: computed on update_circuit's tick ---
def _dir_options(current_value, top_dirs: list, files: Optional[list] = None):
    """Rebuild dropdown options from the published circuit state -> (options, value or no_update).
    M-65: the options are every folder PATH a live file lies under (the staircases); the value is the ONE
    view looked at. A value no longer listed is dropped."""
    live = sorted(_scanned_top_dirs(files))   # P2: the tick's walk when it has one
    options = [{'label': d + '/', 'value': d} for d in live]
    valid = set(live)
    if current_value:
        pruned = [v for v in current_value if v in valid]
        if len(pruned) != len(current_value):
            return options, pruned
    return options, no_update


# --- Main graph update callback ---

@app.callback(
    [Output('circuit-graph', 'figure'),
     Output('animation-tick', 'data'),
     Output('node-positions-store', 'data'),
     Output('circuit-graph-container', 'className'),   # FIX_20: 'frame-stale' while no frame arrives
     Output('frame-ready', 'data'),                     # FIX_28: written after the figure is built
     # S7: the dropdown and the watchlist text ride this tick (they were two more walks per tick)
     Output('watchlist-display', 'children', allow_duplicate=True),
     Output('dir-selector', 'options'),
     Output('dir-selector', 'value', allow_duplicate=True)],
    [Input('circuit-interval', 'n_intervals'),
     Input('watch-button', 'n_clicks'),
     Input('clear-watch-button', 'n_clicks'),
     Input('view-depth', 'data'),
     Input('view-changed', 'data')],            # owner 2026-10-06: every view change redraws at once
    [State('dir-selector', 'value'),
     State('active-state-file', 'data'),
     State('animation-tick', 'data'),
     State('script-search', 'value'),
     State('graph-size', 'data')],             # P4 (B2): the plot area the page last drew
    prevent_initial_call='initial_duplicate'   # S7: still fires on load (allow_duplicate outputs need this form)
)
def update_circuit(n_intervals, watch_clicks, clear_clicks, depth_value, view_changed,
                   dir_selection, active_state_file, animation_tick, search_value, graph_size=None):
    """P2 (2026-09-29): one circuit tick = one walk of the target, one read and at most one AST parse per
    file (`_TickRead`, passed down — no pathlib patching), shared by the frame, the dropdown and the
    watchlist text, and dropped when the tick returns.
    A3: a frame error is caught HERE — traceback logged, the previous graph kept with the error written on
    it (`_frame_error`) — and the dropdown and watchlist text still update on that tick."""
    from dash import ctx
    tick = None
    if _refresh_target() is None:   # R3 (T-12): no target, no graph — never CodeRadar's own code in its place
        _nm = _target_not_measured()
        return ({'data': [], 'layout': {'title': {'text': _nm}, 'xaxis': {'visible': False},
                                        'yaxis': {'visible': False}}},
                no_update, no_update, '', no_update, _nm, [], no_update)
    try:
        tick = _TickRead(TARGET_REPO)
        frame = _circuit_frame(n_intervals, watch_clicks, clear_clicks, depth_value,
                               dir_selection, active_state_file, animation_tick, search_value, tick=tick,
                               graph_size=graph_size)
    except Exception as e:
        logger.exception("circuit frame failed; previous graph kept, error shown on it")
        frame = _frame_error(e)
    if ctx.triggered_id not in (None, 'circuit-interval'):
        # a click or the slider: the dropdown and watchlist text are the click callbacks' to write
        return (*frame, no_update, no_update, no_update)
    try:
        _st = tick.state if tick is not None else None   # A2 / Q-H2-5: the tick's one state read, no target listing
        top_dirs = sorted(_scanned_top_dirs(tick.files if tick is not None else None))   # M-65: folder paths
        # item 4 (2026-10-07): the watchlist names the folders of the first view (a wrapper folder is a
        # pass-through, as on the graph), each by its own name — not every folder path
        _first = _settled_view('', tick)
        _watch = [d[len(_first) + 1:] if _first else d for d in top_dirs
                  if (d.rsplit('/', 1)[0] if '/' in d else '') == _first]
        return (*frame, _get_watchlist_display_local(_watch, state=_st),
                *_dir_options(dir_selection, top_dirs, tick.files if tick is not None else None))
    except Exception:
        logger.exception("dropdown / watchlist refresh failed; both keep their last value this tick")
        return (*frame, no_update, no_update, no_update)


def _frame_error(e: BaseException) -> tuple:
    """A3 (P2 2026-09-29): the frame outputs for a tick whose frame raised — the graph keeps its previous
    picture (a Patch touches only the title, which the next good frame's layout replaces) with the error
    written across its top in red; animation, positions and the frame-ready stamp are left as they were;
    the container carries `frame-error`."""
    msg = f"{type(e).__name__}: {e}"
    if len(msg) > 160:
        msg = msg[:157] + '...'
    fig = Patch()
    fig['layout']['title'] = {'text': f"CIRCUIT FRAME ERROR: {msg} (previous graph kept; traceback in the dash log)",
                              # inside the plot, under the STALE mark (FIX_20) and clear of the top legend row
                              'xref': 'paper', 'yref': 'paper', 'x': 0.0, 'xanchor': 'left', 'y': 0.955, 'yanchor': 'top',
                              'font': {'color': '#ef4444', 'size': 13, 'family': 'monospace'}}
    return fig, no_update, no_update, 'frame-error', no_update


_FRAME_SEQ = itertools.count(1)   # frames drawn since this dashboard (this launch) started


def _circuit_frame(n_intervals, watch_clicks, clear_clicks, depth_value,
                   dir_selection, active_state_file, animation_tick, search_value, tick=None,
                   graph_size=None):
    """Watchlist drives the visual. No watchlist → blank. Watchlist → render dirs.
    P2/R2: *tick* (a _TickRead) = the tick's circuit state (the daemon's published graph); None = read it here.
    P4 (B2): *graph_size* = the plot area the page last drew, [w, h] px (`graph-size`); None = nominal."""
    logger.debug(f"update_circuit called: n_intervals={n_intervals}, depth={depth_value}")

    _blank = go.Figure()
    _blank.update_layout(paper_bgcolor='#1a1a1a', plot_bgcolor='#1a1a1a',
                         font=dict(color='#6b7280', size=12),
                         margin=dict(l=20, r=20, t=30, b=20), height=700)

    # the view's depth = path parts drawn: 1 inside the root (its folders), 2 inside a folder (its files)
    # M-65: the view is a folder PATH (the dropdown's one value); the root ('') when nothing is selected.
    # Rule 3: a single-folder, no-file level is never a stop — the first view settles below the wrapper.

    # R2 (2026-09-30, owner: one scan scans everything): the circuit daemon's PUBLISHED state is the source of
    # truth for nodes, links and colours — the dashboard never walks, reads or parses the target for the graph.
    if tick is None:
        tick = _TickRead(TARGET_REPO)
    _wl_exclude = set(tick.whitelist)
    _view = next((str(v) for v in (dir_selection or []) if v), '')
    _view = _settled_view(_view, tick)
    dir_selection = [_view] if _view else []
    nodes, imports, cycles, tags, subdirs, node_subdirs = tick.parse(_view)

    # M-65: the view's MEMBERS are drawn on the ring; everything else the fold produced (a sibling branch,
    # an ancestor's file) is out of view — a box when a member links to it, nothing otherwise
    _keep = {k for k in nodes if in_view(k, node_subdirs, _view)}
    outside_links = _outside_links(imports, _keep, node_subdirs, _view, tick) if len(_keep) != len(nodes) else []
    nodes = {k: v for k, v in nodes.items() if k in _keep}
    node_subdirs = {k: v for k, v in node_subdirs.items() if k in nodes}
    imports = {k: [d for d in v if d in nodes] for k, v in imports.items() if k in nodes}

    _fresh = frame_freshness()   # FIX_20: measured once per frame, before anything is drawn
    if tick.unmeasured:
        # R2: no state, no guess — the graph says the circuit was not measured, and why
        logger.debug(f"circuit state not measured ({tick.unmeasured}), no graph drawn")
        _blank.add_annotation(text=f"import map: NOT MEASURED — {tick.unmeasured}", xref='paper', yref='paper',
                              x=0.5, y=0.5, showarrow=False, font=dict(color='#f59e0b', size=16, family='monospace'))
        _blank.update_xaxes(visible=False)
        _blank.update_yaxes(visible=False)
        if _fresh['stale']:
            _stale_banner(_blank, _fresh)
        return (_blank, animation_tick or 0, {}, 'frame-unmeasured',
                {'n': next(_FRAME_SEQ), 'ts_ms': int(time.time() * 1000), 'nodes': 0, 'edges': 0,
                 'stale': _fresh['stale'], 'since': _fresh['since'], 'unmeasured': tick.unmeasured})
    if not nodes:
        logger.debug("No nodes in the circuit state, returning blank")
        if _fresh['stale']:
            _stale_banner(_blank, _fresh)
        return (_blank, animation_tick or 0, {}, 'frame-stale' if _fresh['stale'] else '',
                {'n': next(_FRAME_SEQ), 'ts_ms': int(time.time() * 1000), 'nodes': 0, 'edges': 0,
                 'stale': _fresh['stale'], 'since': _fresh['since']})


    monitored_names = list(nodes.keys())
    entry = get_entry_point_from_proof(
        RUNNING_STATE_FILE,
        monitored_names=monitored_names,
        repo_path=TARGET_REPO,
    )
    # Item 10: every alive wrapper entry (app + runners) for the figure's triangles; a runner entry
    # gets the test files its record shows imported (the daemon's via_runner block) so a one-file run
    # draws its triangle over that file and a multi-file run draws nothing (listed below the graph).
    _entries = running_entries(RUNNING_STATE_FILE, TARGET_REPO)

    animation_tick = ((animation_tick or 0) + 3) % 100

    watched_names = {k[len(FOLDER):] for k in nodes if k.startswith(FOLDER)}   # M-65: member folder PATHS

    # Read runtime state from daemon — R2: the SAME state the graph was drawn from (one read per tick)
    daemon_state = tick.state
    # Runtime names from daemon may be 'sending.py' or 'kashmir/sending'
    # Dashboard nodes may be 'kashmir/sending.py'
    # Build a set with all possible variants so any format matches
    _raw_runtime = set(daemon_state.get('runtime_coverage', []))
    runtime_loaded = set()
    # Run 19 (2026-09-05): the circuit publishes RELATIVE PATHS. A node is
    # executed-proven iff its own path was recorded — never by stem or tail
    # (the old tail match lit every `__init__.py` in the tree).
    for name in _raw_runtime:
        runtime_loaded.add(name)
        if '/' not in name:
            bare = name[:-3] if name.endswith('.py') else name
            runtime_loaded.add(bare)
            runtime_loaded.add(bare + '.py')
    dataflows = daemon_state.get('dataflows', [])
    # Item 10: a flow's endpoints are DAEMON names ('tests/test_x'); the drawn nodes are path-qualified
    # ('tests/test_x.py') below the root — resolve each endpoint to the drawn name so subdir flows draw.
    def _drawn(nm):
        return drawn_for(nm, nodes)   # M-65: the node, its .py form, or the folder box its path folds into
    dataflows = [{**df, 'src': _drawn(str(df.get('src', ''))), 'dst': _drawn(str(df.get('dst', '')))} for df in dataflows]

    def _missing_drawn():
        """owner 2026-09-29: imports that resolve nowhere, each hung on the node that stands for its
        file at this depth (the file, or its collapsed folder). R2: from the daemon's `import_error` only."""
        try:
            return [{**m, 'src': _drawn(m['file'][:-3] if m['file'].endswith('.py') else m['file'])}
                    for m in missing_from_state(daemon_state)]
        except Exception as e:
            logger.warning(f"missing-import read from circuit state failed, none drawn: {e}")
            return []
    # Item 10: nodes a runner's record proves imported — the same name variants as runtime_loaded
    _via_runner = set()
    for name in daemon_state.get('runner_coverage', []) or []:
        _via_runner.add(name)
        if '/' not in name:
            bare = name[:-3] if name.endswith('.py') else name
            _via_runner.add(bare); _via_runner.add(bare + '.py')
        else:
            _via_runner.add(name[:-3] if name.endswith('.py') else name + '.py')
    _vr_block = ((daemon_state.get('execution_proof') or {}).get('via_runner') or {})
    for _e in _entries:
        if _e.get('runner'):
            _e['test_files'] = list(_vr_block.get('test_files') or [])

    # Merge daemon's node connection status into circuit nodes
    # R2: each drawn node's `connected` IS the daemon's (a folder: every member connected) — circuit_from_state
    # built it from the same state; no name-variant re-lookup (a stem match could borrow another file's colour).
    circuit_nodes = [{'name': k, 'connected': v} for k, v in nodes.items()]

    # Resolve search query to a node name for highlighting
    highlight_node = None
    if search_value:
        query = search_value.strip().lower()
        if query:
            # owner 2026-10-07 04:15: the out-of-view boxes are searchable too (the clientside matches them)
            _boxes = [b for _, _, b in outside_edges(outside_links, set(nodes))]
            highlight_node = _search_match(query, list(nodes.keys()) + list(dict.fromkeys(_boxes)))

    # Merge daemon change tags into dashboard node names
    daemon_change_tags = {}
    for dn in daemon_state.get('nodes', []):
        dn_tags = dn.get('change_tags', [])
        if dn_tags:
            dn_name = dn.get('name', '')
            daemon_change_tags[dn_name] = dn_tags
            daemon_change_tags[dn_name + '.py'] = dn_tags
            if '/' in dn_name:
                stem = dn_name.split('/')[-1]
                daemon_change_tags[stem] = dn_tags
                daemon_change_tags[stem + '.py'] = dn_tags
    # Edit badge follows the DRAWN node by path (plan item 10): a node in a
    # subdir takes the tags of exactly its relative path; the stem-keyed map is
    # the fallback for root-level scripts (two files sharing a stem in different
    # dirs no longer share a badge).
    daemon_tags_by_rel = {}
    for dn in daemon_state.get('nodes', []):
        if dn.get('relative_path') and dn.get('change_tags'):
            daemon_tags_by_rel[str(dn['relative_path'])] = dn['change_tags']
    for node_name in nodes:
        sub = node_subdirs.get(node_name)
        # depth-2+ nodes are already path-qualified ("dir/file.py"); root nodes are stems
        rel_key = node_name if ('/' in node_name or node_name.endswith('.py')) else f"{node_name}.py"
        if rel_key in daemon_tags_by_rel:
            tags[node_name] = daemon_tags_by_rel[rel_key]
        elif node_name in daemon_change_tags and not sub:
            tags[node_name] = daemon_change_tags[node_name]

    # ITEM 11 (2026-09-15): severed links come from the daemon — one source of truth. Each published pair
    # (daemon names) is resolved to the drawn node; the figure draws it red and the banner names it.
    severed_edges = set()
    for _pair in daemon_state.get('severed_links', []) or []:
        if isinstance(_pair, (list, tuple)) and len(_pair) == 2:
            _s, _d = _drawn(str(_pair[0])), _drawn(str(_pair[1]))
            if _s in nodes and _d in nodes:
                severed_edges.add((_s, _d))

    fig, positions = generate_figure(
        circuit_nodes=circuit_nodes, import_map=imports, node_subdirs=node_subdirs,
        change_tags=tags, entry_point=entry,
        runtime_loaded=runtime_loaded,
        dataflows=dataflows,
        animation_tick=animation_tick,
        selected_dirs=dir_selection, watched_names=watched_names,
        highlight_node=highlight_node,
        severed_edges=severed_edges,
        scanned_dirs=_scanned_top_dirs(tick.files if tick is not None else None),   # M-65: folder paths
        runtime_via_runner=_via_runner, running_entries=_entries,   # Item 10
        outside_runs=(daemon_state or {}).get('outside_runs'),      # M-48 / C: seen-only runs, hollow marker
        missing=_missing_drawn(),
        outside_links=outside_links, plot_px=graph_size)


    logger.debug(f"Generated new figure with {len(circuit_nodes)} nodes, {len(positions)} positions")

    # FIX_20: the running label is no longer this callback's — update_running_label owns it (light, per frame).
    if _fresh['stale']:
        _stale_banner(fig, _fresh)
    # FIX_28: the frame-ready store is the LAST thing written; the stamp callback fires after the DOM swap.
    # owner 2026-10-06: the frame number counts every frame of this launch (a poll-rate change rebuilt the
    # interval and set it back to 0), and "nodes" counts everything drawn — the folders too; item 9
    # (2026-10-07): "edges" too — the in-view links plus the out-of-view boxes' lines
    _edges_drawn = sum(len(v) for v in imports.values()) + len(outside_edges(outside_links, set(nodes)))
    frame_ready = {'n': next(_FRAME_SEQ), 'ts_ms': int(time.time() * 1000), 'nodes': len(positions),
                   'edges': _edges_drawn, 'stale': _fresh['stale'], 'since': _fresh['since']}
    return fig, animation_tick, positions, ('frame-stale' if _fresh['stale'] else ''), frame_ready


# --- FIX_20 (2026-09-15): the running label's own light per-frame callback ---
# --- Item 10 (owner 2026-09-15): it renders THE ONE FIELD — every intermittent event; FIX_40: the band above the graph ---
def live_event_lines(entries, daemon_state):
    """The lines of the ONE field (FIX_40: the text band above the graph), in this order: the app running (wrapper entries), the test
    runners running (wrapper entries with `runner`; then ps / kernel-proven ones the wrapper did not stamp),
    the active dataflows. [] when nothing runs — the field is then literally empty."""
    lines = []
    tr = (daemon_state.get('test_runners') or {})
    vr = ((daemon_state.get('execution_proof') or {}).get('via_runner') or {})
    test_files = list(vr.get('test_files') or [])
    stamped_pids = set()
    for e in entries:
        stamped_pids.add(int(e.get('pid') or 0))
        if not e.get('runner'):
            lines.append(f"\u25bc running: {e['script']} (pid {e['pid']})")
    for e in entries:
        if not e.get('runner'):
            continue
        tp = e.get('test_path') or ''
        if tp.endswith('.py') or len(test_files) == 1:
            target = tp if tp.endswith('.py') else test_files[0]
            lines.append(f"\u25bc {e['runner']} \u2192 {target} (pid {e['pid']})")
        elif test_files:
            lines.append(f"\u25bc {e['runner']} \u2192 {tp or '(cwd)'} (pid {e['pid']}) \u2014 files under test: {', '.join(test_files)}")
        else:
            lines.append(f"\u25bc {e['runner']} \u2192 {tp or '(cwd)'} (pid {e['pid']})")
    for x in ((tr.get('execution') or {}).get('entries') or []):
        try:
            pid = int(x.get('pid') or 0)
        except (TypeError, ValueError):
            continue
        if pid in stamped_pids or x.get('proof') == 'wrapper':
            continue
        lines.append(f"\u25bc {x.get('runner')} \u2192 {x.get('test_path') or '(cwd)'} (pid {pid}, {x.get('proof')}-proven, not through the wrapper)")
    for df in (daemon_state.get('dataflows') or []):
        proof = df.get('proof') or ''
        via = 'via runner' if proof == 'runner' else (str(proof) if proof else '')
        lines.append(f"\u21c4 dataflow: {df.get('src')} \u2192 {df.get('dst')} ({df.get('channel')}{', ' + via if via else ''})")
    return lines


@app.callback(
    Output('live-events', 'children'),
    Input('circuit-interval', 'n_intervals'),
    prevent_initial_call=False
)
def update_running_label(n_intervals):
    """Read running.json, keep entries whose PID is alive, not a zombie and whose start time matches
    (circuit_views.running_entries) — a label that survives the process is a false proof. Item 10: the
    field carries every intermittent event (running app, running test runners, active dataflows) and is
    empty when there is none. (FIX_39's scan-cadence lines left the band, owner 2026-09-28.)"""
    if _refresh_target() is None:   # R3 (T-12): running.json is matched against the target — no target, no match
        return _target_not_measured()
    entries = running_entries(RUNNING_STATE_FILE, TARGET_REPO)
    _state = read_circuit_state() or {}
    if _state.get(_WRONG_TARGET):
        return _state[_WRONG_TARGET]
    lines = live_event_lines(entries, _state)
    # owner 2026-09-28: the per-directory scan-cadence lines left the band (noise above the graph); the band now
    # carries only running code / dataflows / alerts and takes no height when there are none
    return '\n'.join(lines) if lines else ''


# --- FIX_28 (2026-09-15): the frame stamp — changes only when a figure has fully rendered ---
app.clientside_callback(
    """
    function(frame) {
        if (!frame) { return ''; }
        var d = new Date(frame.ts_ms);
        function p(n, w) { n = String(n); while (n.length < w) { n = '0' + n; } return n; }
        var ts = p(d.getHours(), 2) + ':' + p(d.getMinutes(), 2) + ':' + p(d.getSeconds(), 2) + '.' + p(d.getMilliseconds(), 3);
        // owner 2026-10-07 01:16 ("moving poll to a new freq stops the counter … back to default it catches up by
        // how many it missed"): the server's frame.n is shared by EVERY open tab, so a tab on a slow rate saw the
        // other tabs' frames land as a jump. This is THIS tab's own count of the frames it drew — it never jumps,
        // and a slow rate simply spaces the frames out. (owner 2026-10-06: a poll-rate change must not reset it.)
        window._crFrame = (window._crFrame || 0) + 1;
        var s = 'frame ' + window._crFrame + ' \\u00b7 ' + ts + ' \\u00b7 ' + frame.nodes + (frame.nodes === 1 ? ' node' : ' nodes');
        if (frame.stale) { s += ' \\u00b7 ' + (frame.since === 'never' ? 'no graph yet' : 'STALE since ' + frame.since + ' (the map has not been redrawn since then)'); }
        return s;
    }
    """,
    Output('frame-stamp', 'children'),
    Input('frame-ready', 'data'),
)


# P4 (B2): the plot area Plotly last drew for the circuit graph, [width, height] px (its _fullLayout._size —
# the figure's box less its margins), read in the page each circuit tick and sent with the next frame
# request, so generate_figure sizes labels and boxes for the plot actually on screen (a drag of the graph's
# corner or a window resize is picked up on the next tick). Unchanged → no_update (no store churn).
app.clientside_callback(
    """
    function(n, prev) {
        var gd = document.getElementById('circuit-graph');
        var plot = gd && (gd.classList.contains('js-plotly-plot') ? gd : gd.querySelector('.js-plotly-plot'));
        var size = plot && plot._fullLayout && plot._fullLayout._size;
        if (!size || !(size.w > 0) || !(size.h > 0)) { return window.dash_clientside.no_update; }
        var now = [Math.round(size.w), Math.round(size.h)];
        if (prev && prev[0] === now[0] && prev[1] === now[1]) { return window.dash_clientside.no_update; }
        return now;
    }
    """,
    Output('graph-size', 'data'),
    Input('circuit-interval', 'n_intervals'),
    State('graph-size', 'data'),
)


# --- Search-to-zoom: find script and zoom the graph to it ---
app.clientside_callback(
    """
    function(search_value, positions) {
        if (!search_value) {
            return '';
        }
        if (!positions || Object.keys(positions).length === 0) {
            return 'No graph loaded';
        }
        var query = search_value.toLowerCase();
        // Strip folder emoji for matching
        function clean(s) {
            return s.replace(/📁/g, '').toLowerCase();
        }
        // Best match, the server's _search_match order: whole name → file name → file name starts with it →
        // whole name starts with it → in the file name → anywhere; within a tier the first in the graph's order
        var keys = Object.keys(positions);
        var tail = function(k) { return clean(k).split('/').pop(); };
        var ranks = [function(k) { return clean(k) === query; },
                     function(k) { return tail(k) === query; },
                     function(k) { return tail(k).indexOf(query) === 0; },
                     function(k) { return clean(k).indexOf(query) === 0; },
                     function(k) { return tail(k).indexOf(query) !== -1; },
                     function(k) { return clean(k).indexOf(query) !== -1; }];
        var bestKey = null;
        for (var r = 0; r < ranks.length && !bestKey; r++) {
            for (var i = 0; i < keys.length; i++) {
                if (ranks[r](keys[i])) { bestKey = keys[i]; break; }
            }
        }
        if (!bestKey) {
            return '\\u2716 not found';
        }
        // owner 2026-10-07 01:12 ("search for 'cha' and [a lone node] is what's received"): no zoom to the match —
        // the view stays as it is and the server paints the matched node's label amber (highlight_node); the
        // old relayout to a 1.2-unit window around the node showed one node, its badges and a line end.
        // owner 04:15 ("search needs to highlight the folder not write the name again"): the hit is painted on
        // the graph (highlight_node); this line says nothing on a match.
        return '';
    }
    """,
    Output('search-feedback', 'children'),
    Input('script-search', 'value'),
    State('node-positions-store', 'data'),
)

# owner 2026-10-07 04:45 ("clear the search field when nav'ing to a new dir"): every view change (a folder
# click, Reverse1, Watch These, Clear — all of them write `view-changed`) empties the search box
app.clientside_callback(
    "function(changed) { return ''; }",
    Output('script-search', 'value', allow_duplicate=True),
    Input('view-changed', 'data'),
    prevent_initial_call=True,
)


# (S3 2026-09-29: the "click a 📁 node toggles it in the dropdown" callback is gone — a graph click has ONE
# handler, update_watchlist, which drills; the two wrote dir-selector on the same click and the last won.)


# =============================================================================
# MULTI-REPO GRID CALLBACKS
# =============================================================================

@app.callback(
    Output('repo-grid', 'children'),
    Output('multi-repo-grid-wrapper', 'style'),
    Output('back-to-grid-bar', 'style'),
    Output('single-repo-card', 'style'),
    Output('active-repo-label', 'children'),
    Input('circuit-interval', 'n_intervals'),
    Input('back-to-grid-btn', 'n_clicks'),
    State('active-state-file', 'data'),
    prevent_initial_call=False
)
def update_multi_repo_view(n_intervals, back_clicks, active_state_file):
    """Render multi-repo grid or single-repo detail view."""
    all_states = discover_circuit_states()

    # Single-repo mode: hide grid, show detail as normal
    if len(all_states) <= 1:
        return [], {'display': 'none'}, {'display': 'none'}, {}, ''

    # Multi-repo mode
    if active_state_file:
        # Detail view: hide grid, show back bar + single-repo card
        # Find the repo name
        repo_name = ''
        for rid, info in all_states.items():
            if str(info['file']) == active_state_file:
                repo_name = info.get('name', rid)
                break
        return (
            [],
            {'display': 'none'},
            {'display': 'flex', 'alignItems': 'center', 'padding': '8px 0'},
            {},
            repo_name,
        )

    # Grid view: show grid, hide single-repo card
    grid_cards = []
    for repo_id, info in all_states.items():
        state = info['state']
        repo_name = info.get('name', repo_id)
        state_file_path = str(info['file'])
        nodes = state.get('nodes', [])
        node_count = len(nodes)
        all_ok = state.get('all_connected', False)
        disconnected = sum(1 for n in nodes if not n.get('connected', False))
        hacks = state.get('path_hacks', {})
        # FIX_16: a `not_measured` row is a measurement status, never a hack — not counted
        hack_count = sum(1 for h in hacks.values() for x in h if x.get('type') not in ('not_measured', 'measured'))   # FIX_16 step 3: `measured` = the feed's status row

        # Status color
        if all_ok:
            status_color = '#22c55e'
            status_text = 'ALL CONNECTED'
        else:
            status_color = '#ef4444'
            status_text = f'{disconnected} DISCONNECTED'

        # Build mini figure
        mini_fig = _build_mini_figure(state)

        card = dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.Span(repo_name,
                              style={'fontSize': '11pt', 'color': '#e6edf3', 'fontWeight': 'bold'}),
                    html.Span(f'  {node_count} scripts',
                              style={'fontSize': '9pt', 'color': '#6b7280', 'marginLeft': '10px'}),
                ]),
                html.Div([
                    html.Span(status_text,
                              style={'fontSize': '9pt', 'color': status_color, 'fontWeight': 'bold'}),
                    html.Span(f'  {hack_count} hacks' if hack_count else '',
                              style={'fontSize': '9pt', 'color': '#f59e0b', 'marginLeft': '10px'}),
                ], style={'marginBottom': '4px'}),
                dcc.Graph(
                    figure=mini_fig,
                    style={'height': '250px'},
                    config={'staticPlot': True, 'displayModeBar': False},
                    id={'type': 'mini-graph', 'index': repo_id},
                ),
                html.Button('Open', id={'type': 'open-repo-btn', 'index': state_file_path},
                            style={'width': '100%', 'marginTop': '4px', 'fontSize': '9pt',
                                   'padding': '4px', 'backgroundColor': '#374151', 'color': '#e6edf3',
                                   'border': '1px solid #6b7280', 'borderRadius': '4px',
                                   'cursor': 'pointer'}),
            ], style={'padding': '10px'})
        ], className='bg-dark border-secondary')

        grid_cards.append(card)

    return (
        grid_cards,
        {'display': 'block'},
        {'display': 'none'},
        {'display': 'none'},
        '',
    )


@app.callback(
    Output('active-state-file', 'data'),
    Input({'type': 'open-repo-btn', 'index': dash.ALL}, 'n_clicks'),
    Input('back-to-grid-btn', 'n_clicks'),
    State('active-state-file', 'data'),
    prevent_initial_call=True
)
def navigate_repo(open_clicks, back_clicks, current_active):
    """Handle repo selection and back-to-grid navigation."""
    ctx = dash.callback_context
    if not ctx.triggered:
        return current_active

    trigger_id = ctx.triggered[0]['prop_id']

    # Back button
    if 'back-to-grid-btn' in trigger_id:
        return ''

    # Open button — extract the state file path from the pattern-matching ID
    try:
        btn_id = json.loads(trigger_id.split('.')[0])
        return btn_id.get('index', '')
    except Exception:
        return current_active


def _build_mini_figure(state):
    """Build a simplified circuit graph figure for the grid view."""
    import plotly.graph_objects as go

    nodes = state.get('nodes', [])
    edges = state.get('edges', [])

    if not nodes:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor='#111', plot_bgcolor='#111',
            xaxis=dict(visible=False), yaxis=dict(visible=False),
            margin=dict(l=0, r=0, t=0, b=0),
            annotations=[dict(text='No data', showarrow=False,
                              font=dict(color='#6b7280', size=14),
                              xref='paper', yref='paper', x=0.5, y=0.5)]
        )
        return fig

    # Simple circular layout
    n = len(nodes)
    positions = {}
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / n
        positions[node['name']] = (math.cos(angle), math.sin(angle))

    # Build node status lookup and runtime set
    _node_status = {}
    for n in nodes:
        conn = n.get('connected')
        _node_status[n['name']] = 'success' if conn is True else ('failed' if conn is False else 'pending')
    _mini_runtime = set(state.get('runtime_coverage', []))
    # I-198: a library (no app-loaded node) draws the edges its tests loaded in their own teal tier
    _mini_tested = set() if _mini_runtime else {
        n['name'] for n in nodes if 'runner' in str(n.get('runtime_loaded_via') or '')}

    # Draw edges — three tiers based on runtime execution
    possible_ex, possible_ey = [], []
    live_ex, live_ey = [], []
    broken_ex, broken_ey = [], []
    tests_ex, tests_ey = [], []
    for edge in edges:
        if len(edge) >= 2 and edge[0] in positions and edge[1] in positions:
            x0, y0 = positions[edge[0]]
            x1, y1 = positions[edge[1]]
            ss = _node_status.get(edge[0], 'pending')
            ds = _node_status.get(edge[1], 'pending')
            both_rt = edge[0] in _mini_runtime and edge[1] in _mini_runtime
            if ss == 'failed' or ds == 'failed':
                broken_ex += [x0, x1, None]; broken_ey += [y0, y1, None]
            elif both_rt and ss == 'success' and ds == 'success':
                live_ex += [x0, x1, None]; live_ey += [y0, y1, None]
            elif edge[0] in _mini_tested and edge[1] in _mini_tested:
                tests_ex += [x0, x1, None]; tests_ey += [y0, y1, None]
            else:
                possible_ex += [x0, x1, None]; possible_ey += [y0, y1, None]

    # Draw nodes
    node_x = [positions[n['name']][0] for n in nodes if n['name'] in positions]
    node_y = [positions[n['name']][1] for n in nodes if n['name'] in positions]
    # I-72 (S7 2026-09-29): was `from dashboard_graphs import GREEN_SHADES` — a module that exists nowhere,
    # so this grid branch raised the moment it ran. A connected node is the circuit's one green.
    node_colors = []
    for n in nodes:
        if n['name'] not in positions:
            continue
        if n.get('connected'):
            node_colors.append('#22c55e')
        else:
            node_colors.append('#ef4444')

    fig = go.Figure()
    # Edges: possible first (behind), then live, then broken on top
    for xs, ys, c, w in [
        (possible_ex, possible_ey, '#ffab91', 0.8),
        (tests_ex, tests_ey, '#14b8a6', 0.8),   # I-198 live via tests (circuit_views.TESTS_TEAL)
        (live_ex, live_ey, 'rgba(0,255,180,0.35)', 0.5),
        (broken_ex, broken_ey, '#ef4444', 0.8),
    ]:
        if xs:
            fig.add_trace(go.Scatter(
                x=xs, y=ys, mode='lines',
                line=dict(width=w, color=c),
                hoverinfo='none'
            ))
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y, mode='markers',
        marker=dict(size=5, color=node_colors),
        hoverinfo='none'
    ))
    fig.update_layout(
        showlegend=False,
        paper_bgcolor='#111', plot_bgcolor='#111',
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        margin=dict(l=5, r=5, t=5, b=5),
    )
    return fig


# ── NoAI panel helpers ──────────────────────────────────────────────────────

# Validator emits long layer names; the panel color/label logic keys on the
# short forms (map, don't string-match the long names — Phase 6 render bug).
_NOAI_LAYER_LABELS = {'HARD_REQUIREMENTS': 'L1', 'AI_FAKE_DETECTOR': 'L2'}

_NOAI_RULE_ID_RE = re.compile(r"\b([A-Z]{2,4}-\d+[A-Z]?)\b")


def _noai_rule_id(triggered_patterns, failure_reason=''):
    """Extract the deciding rule id (e.g. 'NAI-021S') for display.

    Replicates NOAI_VALIDATOR_DAEMON._extract_rule_id inline: patterns may be
    dicts ({'tag': ...}), lists/tuples whose first element is a (possibly
    stringified-dict) string, or plain strings — never render them raw.
    Layer-1 failures carry the id only in failure_reason, which names the rule
    that decided the verdict, so it wins when present.
    """
    if failure_reason:
        m = _NOAI_RULE_ID_RE.search(str(failure_reason))
        if m:
            return m.group(1)
    for p in triggered_patterns or []:
        if isinstance(p, dict):
            tag = p.get('tag', '')
        elif isinstance(p, (list, tuple)) and p:
            tag = str(p[0])
        else:
            tag = str(p)
        m = _NOAI_RULE_ID_RE.search(tag)
        if m:
            return m.group(1)
    return ''


def _noai_rule_ids(triggered_patterns, failure_reason=''):
    """Every rule id a finding carries, deciding id first (F-DISP1, 2026-09-05)."""
    ids = []
    if failure_reason:
        m = _NOAI_RULE_ID_RE.search(str(failure_reason))
        if m:
            ids.append(m.group(1))
    for p in triggered_patterns or []:
        if isinstance(p, dict):
            tag = p.get('tag', '')
        elif isinstance(p, (list, tuple)) and p:
            tag = str(p[0])
        else:
            tag = str(p)
        m = _NOAI_RULE_ID_RE.search(tag)
        if m and m.group(1) not in ids:
            ids.append(m.group(1))
    return ids


def _discovery(target_repo) -> dict:
    """ONE file count from ONE discovery (plan item 11, 2026-09-05): the
    launcher's whitelist stage summary — live files, package markers, files
    excluded by filter 1 (detritus) and filter 2 (artifacts). Every panel that
    mentions a file count cites this; none counts on its own."""
    _wait = _whitelist_wait()   # R3 (T-15): never the previous run's summary
    if _wait:
        return {'live': 0, 'markers': 0, 'excluded': 0, 'measured': False, 'source': None, 'why': _wait}
    try:
        wl_path = SCRIPT_DIR / f"whitelist_{get_repo_id(Path(str(target_repo)))}.json"
        with open(wl_path) as f:
            s = json.load(f).get('summary', {})
        d = {'live': int(s.get('live', 0)), 'markers': int(s.get('package_markers', 0)),
             'excluded': int(s.get('filter1_detritus', 0)) + int(s.get('filter2_artifacts', 0)),
             'measured': True, 'source': 'whitelist'}
    except Exception:
        return {'live': 0, 'markers': 0, 'excluded': 0, 'measured': False, 'source': None}
    # B4 / Q-H2-7 (2026-10-01, replaces I-49's substitution): `live` is ALWAYS the launch scan's whitelist count.
    # When the NOAI daemon's own `summary.files_scanned` differs it is carried beside it as `noai_scanned` and the
    # text says both — two counts of one thing that disagree are never folded into one number.
    try:
        _noai = read_file_locked(NOAI_STATE_FILE)
        _fs = (_noai.get('summary') or {}).get('files_scanned')
        if _noai.get('summary') and _validate_daemon_repo(_noai):
            _fs = None   # R3 (T-12): another target's rescan is not this target's live count
        if isinstance(_fs, int) and _fs > 0 and _fs != d['live']:
            d['noai_scanned'] = _fs
    except Exception:
        pass
    return d


def _discovery_text(target_repo) -> str:
    d = _discovery(target_repo)
    if not d['measured']:
        return f"discovery: not measured — {d['why']}" if d.get('why') else "discovery: not measured"
    text = f"discovery: {d['live']} live, {d['markers']} package markers, {d['excluded']} excluded"
    if d.get('noai_scanned') is not None:   # B4 / Q-H2-7: the disagreement is said, never masked
        text += f" · NOAI scanned {d['noai_scanned']} (≠ {d['live']} live)"
    return text


@app.callback(
    Output('withheld-page', 'data'),
    Input('withheld-prev', 'n_clicks'),
    Input('withheld-next', 'n_clicks'),
    State('withheld-page', 'data'),
    prevent_initial_call=True,
)
def flip_withheld_page(_prev, _next, page):
    """DASH_R (run 185): one page of the WITHHELD block back or forward. The buttons are drawn by the
    panel callback (disabled at either end); the panel re-renders on this store, and clamps it."""
    page = int(page or 0)
    # the panel re-draws the buttons (n_clicks 0) and Dash fires this on their insertion — only a real click
    # (a truthy n_clicks in the trigger) flips; without this the store left None at load and WITHHELD opened itself
    trig = dash.ctx.triggered_id if any(t.get('value') for t in dash.ctx.triggered) else None
    if trig == 'withheld-next':
        return page + 1
    if trig == 'withheld-prev':
        return max(page - 1, 0)
    return no_update


def _unchanged(payload, last_sig):
    """DASH_R (run 185): (unchanged?, signature) for a panel's rendered children. A panel whose rows did not
    change is not re-sent, so a toggle the viewer opened (a file group, "+N more", WITHHELD, the path-hacks
    taxonomy) is not snapped shut by the next circuit tick. The signature lives per browser tab in a store."""
    sig = hashlib.md5(json.dumps(payload, cls=plotly.utils.PlotlyJSONEncoder, sort_keys=True,
                                 default=str).encode('utf-8')).hexdigest()
    return sig == last_sig, sig


def _noai_review_lines(results_by_file: dict) -> list:
    """owner 2026-10-07 08:15: NAI-238 sibling divergence is "flagged for review by the ranker" — a context note, never
    an infraction. One line per sibling pair (both rows carry it), under its own heading, in the review colour."""
    import re as _re
    seen, out = set(), []
    for rel, entries in (results_by_file or {}).items():
        for e in entries if isinstance(entries, list) else []:
            for w in e.get('warnings') or []:
                if not str(w).startswith('NAI-238'):
                    continue
                m = _re.search(r"\):\s*(\S+) and (\S+) take the same arguments and differ only by (.*?) —", str(w))
                if not m:
                    continue
                pair = tuple(sorted((m.group(1), m.group(2))))
                if (rel, pair) in seen:
                    continue
                seen.add((rel, pair))
                out.append(html.Div([
                    html.Span(f"{rel.rsplit('/', 1)[-1]}:{e.get('line') or '?'}", title=rel,
                              style={'color': '#9ca3af', 'marginRight': '8px'}),
                    html.Span(f"{pair[0]} / {pair[1]}", style={'color': '#e6edf3', 'fontWeight': 'bold',
                                                               'marginRight': '8px'}),
                    html.Span(f"— differ only by {m.group(3)}; one of them is likely wrong",
                              style={'color': '#c4b5fd'}),
                    html.Div("→ check which one matches the intent", style={'color': '#a78bfa', 'marginLeft': '16px'}),
                ], style={'fontSize': '9pt', 'fontFamily': 'monospace', 'overflowWrap': 'anywhere',
                          'marginBottom': '6px'}))
    if out:
        out.insert(0, html.Div(f"review ({len(out)}) — not counted as infractions; two near-identical functions differ and CodeRadar could not tell which one is wrong",
                               style={'color': '#a78bfa', 'fontSize': '9pt', 'fontWeight': 'bold',
                                      'marginTop': '8px', 'marginBottom': '4px'}))
    return out

def _withheld_plain(reason) -> str:
    """A withheld row's reason in plain words (`species:proxy:demo` -> `demo file`); an unknown reason as is."""
    r = str(reason or '').strip()
    known = {'species:test': 'test file', 'species:proxy:demo': 'demo file',
             'species:proxy:package_marker': 'package marker (__init__.py)'}
    return known.get(r) or r.replace('species:proxy:', '').replace('species:', '').replace('_', ' ')


_NOAI_PLAIN = {
    # rule id -> (what is wrong, what to do); {fields} come from the row's own measured facts
    "NAI-004": ("the body is only a placeholder (`{body_type}`) — it does nothing, but its result is used",
                "write the real body"),
    "NAI-017": ("an error is caught and silently thrown away (`except{caught}: pass`)",
                "let it propagate, or handle it and say what happens"),
    "NAI-036": ("a condition that is always {always} (`x {op} not x`) — the result does not depend on the input",
                "remove the tautology and compute from the inputs"),
    "NAI-009": ("returns a constant whatever the inputs", "compute the result from the inputs"),
    "NAI-003": ("parameter{s} {unused_params} {is_are} never used — the name promises it, the body ignores it",
                "use it, or drop it from the signature"),
    "NAI-102": ("the docstring says {docstring_claim}, the body {body_does}",
                "make the body match the docstring, or correct the docstring"),
    "NAI-010": ("computes {dead_variables} and then never uses it — the result ignores the work",
                "return the computed value, or drop the dead computation"),
    "NAI-016": ("returns its input unchanged — the name promises a transformation the body never does",
                "do the transformation the name says"),
    "NAI-020": ("a test with no assertion — it can never fail", "assert the behaviour it is meant to check"),
    "NAI-229": ("{description}", "fold the repeated statements into a loop or a table"),
    "NAI-236": ("{description}", "remove the guard so it behaves like its twin"),
    "NAI-237": ("{description}", "compute the answer from the inputs, every call"),
    "NAI-055": ("calls `.{method_name}()`, a method name AI-written code often invents — the object may have no such method",
                "replace it with the library's real method (its documentation names it)"),
    "NAI-087": ("`{target_var}` is set by a call inside the loop that does not depend on the loop — the same work is redone every pass",
                "compute it once, before the loop"),
    "NAI-078": ("an error is caught and hidden — the `except` block hands back a stand-in value, so the caller cannot tell anything went wrong",
                "catch only the error you expect and log it, or let it propagate"),
}


def _noai_plain_facts(text: str) -> dict:
    """The `key=value` facts a rule wrote into its line (`NAI-102 (line 10): func_name=x, docstring_claim=adds, …`)."""
    import re as _re
    facts = {}
    body = text.split("):", 1)[1] if "):" in text else text
    for m in _re.finditer(r"(\w+)=(\[[^\]]*\]|[^,]+(?:,(?!\s*\w+=)[^,]+)*)", body):
        facts[m.group(1)] = m.group(2).strip()
    if "description" not in facts and "):" in text:
        facts["description"] = text.split("):", 1)[1].strip()
    return facts


def _noai_plain_lines(failures: list, withheld: list) -> list:
    """owner 2026-10-07: one line per counterfeit finding, in plain words, with where and what to do."""
    import re as _re
    out = []
    if not failures:
        out.append(html.Div("no counterfeit code found", style={'color': '#22c55e', 'fontSize': '9.5pt'}))
    for item in sorted(failures, key=lambda x: (x.get('file') or '', x.get('line') or 0)):
        raw = str(item.get('infraction') or item.get('failure_reason') or '')
        rid = (_re.search(r"NAI-\d{3}", raw) or _re.search(r"NAI-\d{3}", str(item.get('rule_ids') or '')))
        rid = rid.group(0) if rid else ''
        facts = _noai_plain_facts(raw[raw.find(rid):] if rid else raw)
        tmpl = _NOAI_PLAIN.get(rid)
        if tmpl:
            up = facts.get('unused_params', '')
            n_up = up.count(',') + 1 if up else 0
            fill = {**facts, 's': 's' if n_up > 1 else '', 'is_are': 'are' if n_up > 1 else 'is',
                    'dead_variables': facts.get('dead_variables', '').strip("[]").replace("'", "`"),
                    'unused_params': up.strip("[]").replace("'", "`"),
                    'always': 'true' if facts.get('op') == 'or_not' else 'false',
                    'op': 'or' if facts.get('op') == 'or_not' else 'and',
                    'caught': '' if facts.get('variant') == 'bare_except_pass' else ' Exception'}
            try:
                what, todo = tmpl[0].format(**fill), tmpl[1]
            except (KeyError, IndexError):
                what, todo = (facts.get('description') or raw), tmpl[1]
        else:
            what = facts.get('description') or _re.sub(r"^\[\w+\]\s*", "", raw)
            todo = str(item.get('_fix') or '').strip() or "no fix written for this one yet; the engine detail below has the raw check result"
        f = str(item.get('file') or '?')
        where = f"{f.rsplit('/', 1)[-1]}:{item.get('line') or '?'}"
        out.append(html.Div([
            html.Span(where, title=f"{f}:{item.get('line')}", style={'color': '#9ca3af', 'marginRight': '8px'}),
            html.Span(item.get('function') or '', style={'color': '#e6edf3', 'fontWeight': 'bold', 'marginRight': '8px'}),
            html.Span(f"— {what}", style={'color': '#fca5a5'}),
            html.Div(f"→ {todo}", style={'color': '#86efac', 'marginLeft': '16px'}),
        ], style={'fontSize': '9pt', 'fontFamily': 'monospace', 'overflowWrap': 'anywhere', 'marginBottom': '6px'}))
    n_wh = len({(w.get('file'), w.get('function')) for w in withheld if not str(w.get('function', '')).startswith('<')})
    if n_wh:
        out.append(html.Div(f"{n_wh} test function{'s' if n_wh != 1 else ''} not judged (test code)",
                            style={'color': '#6b7280', 'fontSize': '8.5pt', 'marginTop': '4px'}))
    return out

@app.callback(
    Output('noai-validator-panel', 'children'),
    Output('noai-summary', 'children'),
    Output('noai-panel-sig', 'data'),
    Input('circuit-interval', 'n_intervals'),
    Input('withheld-page', 'data'),
    State('noai-panel-sig', 'data'),
)
def update_noai_validator_panel_guarded(n_intervals, withheld_page, last_sig):
    out = update_noai_validator_panel(n_intervals, withheld_page)
    same, sig = _unchanged(list(out), last_sig)
    return (no_update, no_update, no_update) if same else (*out, sig)


def update_noai_validator_panel(n_intervals, withheld_page=None):
    """Display NoAI Validator counterfeit code infractions."""
    ai_state_file = NOAI_STATE_FILE   # R3 (T-12): the one NOAI path, the same constant every reader uses
    if not ai_state_file.exists():
        return (
            html.Div("Waiting for the counterfeit code check to start...",
                     style={'color': '#6b7280', 'fontStyle': 'italic'}),
            html.Span("Starting", style={'color': '#6b7280'}),
        )


    try:
        state = read_file_locked(ai_state_file)
    except Exception:
        return html.Div("Read error", style={'color': '#ef4444'}), ""

    # ── Progress phases (before results are ready) ──
    phase = state.get('phase', '')
    has_results = bool(state.get('results_by_file'))
    # R3 (T-12): results (and any state that names a target) are this target's or are not shown. A bare
    # progress write carries no target_repo and no findings — its phase line is all it shows.
    _wrong = _validate_daemon_repo(state) if (has_results or state.get('target_repo')) else None
    if _wrong:
        return (html.Div(_wrong, style={'color': '#f59e0b', 'fontStyle': 'italic'}),
                html.Span("NOT MEASURED", style={'color': '#f59e0b'}))
    logging.debug(f"NOAI panel: phase={phase!r}, has_results={has_results}, keys={list(state.keys())[:8]}")
    # If we have results, always show them regardless of phase
    if has_results:
        phase = ''  # Skip progress UI, fall through to results
    if phase and phase.upper() not in ('MONITORING', ''):
        detail = state.get('detail', '')
        progress = state.get('progress', 0.0)
        substeps = state.get('substeps', [])

        # Phase label and color
        # V18 (slot 15): synced to the 8 phases the validator actually emits
        # (NOAI_VALIDATOR_DAEMON writer sites) — no phantom phases, none missing.
        phase_colors = {
            'HEALTH_CHECK': '#3b82f6',
            'WAITING': '#6b7280',
            'DETRITUS': '#eab308',
            'DISCOVERY': '#f59e0b',
            'ARTIFACTS': '#14b8a6',      # Item 3 (2026-09-10): the artifact scanner stage
            'IMPORT_TOOLS': '#06b6d4',
            'SEMANTICS': '#ec4899',
            'CHEATSHEETS': '#a855f7',
            'MONITORING': '#22c55e',
        }
        color = phase_colors.get(phase, '#6b7280')

        children = []

        # Phase header with progress bar
        children.append(html.Div([
            html.Span(phase.replace('_', ' '),
                      style={'color': color, 'fontWeight': 'bold', 'fontSize': '10pt'}),
            html.Span(f"  {progress:.0%}" if progress > 0 else "",
                      style={'color': '#9ca3af', 'fontSize': '9pt', 'marginLeft': '8px'}),
        ]))

        # Progress bar
        if progress > 0:
            children.append(html.Div([
                html.Div(style={
                    'width': f'{progress * 100:.0f}%',
                    'height': '3px',
                    'backgroundColor': color,
                    'borderRadius': '2px',
                    'transition': 'width 0.3s ease',
                })
            ], style={
                'backgroundColor': '#1f2937',
                'borderRadius': '2px',
                'marginTop': '4px',
                'marginBottom': '6px',
                'height': '3px',
            }))

        # Detail text
        if detail:
            children.append(html.Div(detail,
                style={'color': '#9ca3af', 'fontSize': '8pt', 'marginTop': '2px'}))

        # Substeps (health check modules or file scan progress)
        if substeps:
            step_items = []
            for step in substeps:
                if 'module' in step:
                    # Health check module
                    ok = step.get('status') == 'ok'
                    n = step.get('checks', 0)
                    label = step['module']
                    if n > 0:
                        label += f" ({n} checks)"
                    step_items.append(html.Div([
                        html.Span("  ✓ " if ok else "  ✗ ",
                                  style={'color': '#22c55e' if ok else '#ef4444'}),
                        html.Span(label,
                                  style={'color': '#d1d5db' if ok else '#ef4444'}),
                    ], style={'fontSize': '8pt', 'fontFamily': 'monospace'}))
                elif 'file' in step:
                    # File scan progress
                    done = step.get('status') == 'done'
                    step_items.append(html.Div([
                        html.Span("  ✓ " if done else "  ○ ",
                                  style={'color': '#22c55e' if done else '#4b5563'}),
                        html.Span(step['file'],
                                  style={'color': '#d1d5db' if done else '#6b7280'}),
                    ], style={'fontSize': '8pt', 'fontFamily': 'monospace'}))

            children.append(html.Div(step_items,
                style={'marginTop': '6px', 'maxHeight': '250px', 'overflowY': 'auto'}))

        summary_el = html.Span(phase.replace('_', ' ').title(),
                               style={'color': color, 'fontWeight': 'bold'})
        return children, summary_el

    results_by_file = state.get('results_by_file', {})
    summary = state.get('summary', {})

    # Item 1 (2026-09-08): the validator stops at infractions; the one before/after per
    # infraction is the Builder daemon's row, joined here by file::function::line.
    try:
        builder_state = read_file_locked(BUILDER_STATE_FILE) if BUILDER_STATE_FILE.exists() else {}
    except Exception:
        builder_state = {}
    _bwrong = _validate_daemon_repo(builder_state) if builder_state else None
    if _bwrong:   # R3 (T-12): another target's Builder rows would join this target's infractions
        return (html.Div(f"Builder: {_bwrong}", style={'color': '#f59e0b', 'fontStyle': 'italic'}),
                html.Span("NOT MEASURED", style={'color': '#f59e0b'}))
    builder_rows = builder_state.get('rows') or {}
    builder_summary = builder_state.get('summary') or {}
    builder_phase = builder_state.get('phase', '') or ''

    # ── Classify entries per the state / Builder contract ──
    #   whitelisted : owner-exempted (entry.whitelisted flag, or the cheatsheets row
    #                 exonerated) — shown muted, no fix owed
    #   repair      : failed + the cheatsheets row carries the Ranker's pick (digest +
    #                 after_code) — the only real repairs
    #   no vetted fix: failed + no pick — the infraction stands, no repair is offered
    #                 (a row with no candidate shows NOTHING as a solution — owner);
    #                 the reason is BUILDER_STATE.json rows[].decision.why, nowhere else.
    #   withheld    : FIX_51 (owner Q11, 2026-09-15) — the Ranker WITHHELD its verdict on this row
    #                 because of the file's SPECIES (a library's tests; a proxy). It is a published
    #                 PASS that is not a clean pass, so it is neither an infraction nor a solution;
    #                 before this fix it was in the state and on no screen (I-17). Shown in its own
    #                 colour with the reason, and counted nowhere but its own badge span.
    repair_failures = []
    unrepaired_failures = []
    whitelisted_fns = []
    withheld_fns = []
    for rel_path, entries in results_by_file.items():
        for entry in entries:
            brow = builder_rows.get(f"{rel_path}::{entry.get('function', '')}::{entry.get('line')}") or {}
            if entry.get('whitelisted') or brow.get('exonerated'):
                whitelisted_fns.append({'file': rel_path, '_kind': 'whitelisted', **entry})
                continue
            if entry.get('withheld'):
                # FIX_51: collected BEFORE the `passed` guard (a withheld row is published as a pass)
                # and never added to `failures` — the infraction count does not move.
                withheld_fns.append({'file': rel_path, '_kind': 'withheld', **entry})
                continue
            if entry.get('passed', True):
                continue
            if brow.get('digest') and (brow.get('after_code') or brow.get('fix')):
                # FIX_41: a prescribed solution (fix = the text, after_code = the shape, may be prose only)
                # is the Ranker's pick like a rewriter's after-code — the row shows its solution.
                repair_failures.append({'file': rel_path, '_kind': 'repair', '_builder': brow, **entry})
            else:
                unrepaired_failures.append({'file': rel_path, '_kind': 'no_vetted_fix', '_builder': brow, **entry})
    failures = repair_failures + unrepaired_failures

    # Summary badge: infractions, of which N carry a vetted repair (measured only)
    summary_children = []
    if failures:
        summary_children.append(html.Span(
            f"{len(failures)} counterfeit code infraction{'s' if len(failures) != 1 else ''} (code that does not do what its name or docstring says)",
            style={'color': '#ef4444', 'fontWeight': 'bold'}
        ))
        # Owner ruling 2026-09-09: the badge is the NUMBER OF INFRACTIONS and nothing else — one
        # infraction = one solution, so no solution count, and the dash never labels kinds of
        # failure on this line. The tester's measure (confirmed / solutions) lives in
        # BUILDER_STATE.json summary.tester and .archive/runs/<target>/tester_report.json.
    else:
        total = summary.get('total_functions', 0)
        summary_children.append(html.Span(
            f"Clean ({total} functions checked)",
            style={'color': '#22c55e', 'fontWeight': 'bold'}
        ))
    # FIX_51 (owner Q11, 2026-09-15): the withheld rows get their OWN colour on the badge, beside the
    # infraction number and never inside it. A withheld row is not a failure and not an infraction, so
    # this does not label a kind of failure (the owner's 2026-09-09 badge ruling) — it is the second,
    # differently-coloured fact Q11 asked for. The number is the validator's own `summary.withheld`.
    _n_withheld = int(summary.get('withheld', len(withheld_fns)) or 0)
    # owner 2026-10-07 (panel rewrite): the header is the count only; "withheld" and the discovery numbers are the
    # hover — the plain list below says what was not judged in words
    summary_el = html.Span(summary_children, title=(f"{_n_withheld} withheld (not judged) · " if _n_withheld else "")
                           + _discovery_text(TARGET_REPO))

    children = []
    # Item 3 (2026-09-10): the ARTIFACT SCANNER's one header line in the panel body (never on the badge — the badge
    # is the number of infractions and nothing else): species by content, stubs on the whitelist, intent sources.
    _ar = (state.get('artifact_report') or {}).get('summary') or {}
    if _ar:
        _sp = _ar.get('species') or {}
        children.append(html.Div(
            f"artifacts: species {sum(_sp.values())} (proxy {_ar.get('proxies', 0)}, test {_ar.get('tests', 0)}) · "
            f"stubs {sum((_ar.get('stubs') or {}).values())} on the whitelist · "
            f"intent sources {len(_ar.get('intent_sources') or [])} ({_ar.get('intent_facts', 0)} facts)",
            style={'color': '#14b8a6', 'fontSize': '9pt', 'marginBottom': '4px'}
        ))
    elif state.get('results_by_file') and 'artifact_report' in state:
        children.append(html.Div("artifacts: NOT MEASURED (no artifact report)", style={'color': '#6b7280', 'fontSize': '9pt'}))
    def _withheld_block() -> list:
        """FIX_51 (owner Q11, 2026-09-15): the withheld rows, under their own label and in their own
        colour (violet `#a78bfa` — the colour the species chip already uses, because the species IS
        the reason). Each row names the reason the ranker withheld its verdict. Never an infraction,
        never a solution: published, and until now (I-17) on no screen at all.
        DASH_R (run 185): the count stays on the label; the rows sit behind that label's toggle
        (collapsed by default), _WITHHELD_PAGE rows a page, flipped by `withheld-prev` / `withheld-next`
        (their page lives in the `withheld-page` store)."""
        if not withheld_fns:
            return []
        _reasons = sorted({_withheld_plain(w.get('withheld')) for w in withheld_fns if w.get('withheld')})
        _rows = sorted(withheld_fns, key=lambda x: (x['file'], x.get('line') or 0))
        _pages = max(1, -(-len(_rows) // _WITHHELD_PAGE))
        _page = min(max(int(withheld_page or 0), 0), _pages - 1)
        _lo, _hi = _page * _WITHHELD_PAGE, min((_page + 1) * _WITHHELD_PAGE, len(_rows))
        out: list = [html.Summary(
            f"NOT JUDGED — {len(withheld_fns)} function{'s' if len(withheld_fns) != 1 else ''} in files that are "
            f"not app code; listed, never counted as a problem"
            + (f" · {', '.join(_reasons)}" if _reasons else ""),
            style={'color': '#a78bfa', 'fontWeight': 'bold', 'fontSize': '9pt', 'cursor': 'pointer'}
        )]
        _btn = {'fontSize': '8pt', 'padding': '0px 6px', 'marginRight': '6px', 'backgroundColor': '#1f2937',
                'color': '#c4b5fd', 'border': '1px solid #374151', 'borderRadius': '3px'}
        out.append(html.Div([
            html.Button('‹ prev', id='withheld-prev', n_clicks=0, disabled=_page == 0, style=_btn),
            html.Button('next ›', id='withheld-next', n_clicks=0, disabled=_page >= _pages - 1, style=_btn),
            html.Span(f"rows {_lo + 1}–{_hi} of {len(_rows)} · page {_page + 1}/{_pages}",
                      style={'color': '#9ca3af', 'fontSize': '8pt'}),
        ], style={'margin': '4px 0 2px 10px'}))
        _last_file = None
        for w in _rows[_lo:_hi]:
            if w['file'] != _last_file:
                _last_file = w['file']
                out.append(html.Div(w['file'], style={'color': '#818cf8', 'fontSize': '9pt', 'fontFamily': 'monospace',
                                                      'marginTop': '2px', 'fontWeight': 'bold'}))
            _ids = list(w.get('rule_ids') or []) + list(w.get('context_ids') or [])
            out.append(html.Div([
                html.Span(f"L{w.get('line', '?')} ", style={'color': '#9ca3af'}),
                html.Span(w.get('function', '?'), style={'color': '#c4b5fd', 'fontWeight': 'bold'}),
                html.Span(_withheld_plain(w.get('withheld')) or 'not judged', title=str(w.get('withheld') or ''),
                          style={**_CHIP_STYLE, 'color': '#a78bfa'}),
                html.Span(f"  ctx:{'+'.join(_ids)}" if _ids else "",
                          style={'color': '#6b7280', 'fontStyle': 'italic'}),
            ], style=_ROW_STYLE))
        # open once the viewer has used the pager (the store leaves None) — a flip re-renders the panel
        return [html.Details(out, open=withheld_page is not None, style={'marginTop': '10px'},
                             **_crkey('withheld'))]

    if not failures and not whitelisted_fns:
        children.append(html.Div(
            f"All {summary.get('total_functions', 0)} functions passed validation.",
            style={'color': '#22c55e', 'fontSize': '9pt'}
        ))
        children.extend(_withheld_block())   # FIX_51: shown even when nothing failed
        return children, summary_el

    # Group infractions + whitelisted functions by file
    file_groups: dict = {}
    for f in failures:
        file_groups.setdefault(f['file'], []).append(f)
    for w in whitelisted_fns:
        file_groups.setdefault(w['file'], []).append(w)

    # DASH_R (run 185): per file, the top _TOP_N rows by rank, then "+N more" behind a toggle; every file
    # group is a collapsed <details> except the first. Order inside a group: the engine-published severity
    # first (L1, then L2, then none); within one, the engine's order — the Ranker's picks (vetted repair), then no
    # vetted fix, then owner-whitelisted rows, each by line. Tags ride the group summary once (layer counts, whitelisted count); a row keeps a
    # short layer chip, one line (_ROW_STYLE), and the full reason on its hover title.
    _TOP_N = 5

    def _apply_verdict_for(row: dict, *, has_solution: bool) -> dict:
        """B6 (2026-10-01, Q-H2-6 / Q-H4-11): THE ONE apply verdict, read from
        `coderadar_mcp.read_tools.apply_verdict` — the function `cr_infractions` publishes with —
        rendered against the target under watch (`_refresh_target()`). When the package cannot be
        imported the verdict is NOT MEASURED (never `yes`), with the import error as its reason."""
        try:
            if str(PROJECT_ROOT) not in sys.path:
                sys.path.insert(0, str(PROJECT_ROOT))
            from coderadar_mcp.read_tools import apply_verdict as _apply_verdict
        except Exception as _e:
            return {'apply': 'NOT MEASURED', 'apply_reason': f"verdict unread — {type(_e).__name__}: {_e}"}
        try:
            return _apply_verdict(row, has_solution=has_solution, target=_refresh_target())
        except Exception as _e:
            return {'apply': 'NOT MEASURED', 'apply_reason': f"verdict unread — {type(_e).__name__}: {_e}"}

    def _layer_of(item) -> str:
        _raw = item.get('failure_layer') or '?'
        return _NOAI_LAYER_LABELS.get(_raw, _raw)

    def _finding_rows(item) -> list:
        out: list = []
        line = item.get('line', '?')
        func = item.get('function', '?')
        kind = item.get('_kind')

        if kind == 'whitelisted':
            # Owner-exempted — muted row, no infraction, no fix owed (the group summary carries the tag)
            out.append(html.Div([
                html.Span(f"L{line} ", style={'color': '#4b5563'}),
                html.Span(func, style={'color': '#6b7280'}),
                html.Span("exempt", title="marked exempt by the repo owner — not a problem", style={**_CHIP_STYLE, 'color': '#6b7280'}),
            ], style=_ROW_STYLE))
            return out

        layer_label = _layer_of(item)
        reason = item.get('failure_reason', '') or ''
        patterns = item.get('triggered_patterns', [])
        # L1/L2 = red, other = amber
        layer_color = '#ef4444' if layer_label in ('L1', 'L2') else '#f59e0b'

        # Rule IDs — ALL of them (F-DISP1, 2026-09-05): a infraction that fired
        # NAI-211 behind NAI-217 (hallucinated import; was NAI-210) shows both; the deciding id comes first.
        # calibrator A4 (2026-09-06): the row publishes rule_ids (deciding) and context_ids; the regex over
        # triggered_patterns is the PRE-MIGRATION fallback for states written before the split.
        if item.get('rule_ids') is not None or item.get('context_ids') is not None:
            rule_ids = list(item.get('rule_ids') or [])
            ctx_ids = list(item.get('context_ids') or [])
        else:
            rule_ids = _noai_rule_ids(patterns, reason)
            ctx_ids = []
        rule_display = f" {'+'.join(rule_ids)}" if rule_ids else ''
        ctx_display = f" ctx:{'+'.join(ctx_ids)}" if ctx_ids else ''
        species_display = f" [{item.get('species')}{': withheld' if item.get('withheld') else ''}]" if item.get('species') else ''
        end_line = item.get('end_line') or 0
        span = f"L{line}-L{end_line}" if end_line and end_line != line else f"L{line}"
        f_lines = item.get('finding_lines') or []
        if f_lines:
            span += f" @{','.join(str(x) for x in f_lines[:4])}"

        out.append(html.Div([
            html.Span(f"{span} ", style={'color': '#9ca3af'}),
            html.Span(func, style={'color': '#e6edf3', 'fontWeight': 'bold'}),
            html.Span(layer_label, style={**_CHIP_STYLE, 'color': layer_color}),
            html.Span(f"{rule_display} — {reason[:80]}", style={'color': '#d1d5db'}),
            html.Span(ctx_display, style={'color': '#6b7280', 'fontStyle': 'italic'}),      # context ids dimmed, never a verdict
            html.Span(species_display, style={'color': '#a78bfa'}),
        ], title=f"{func} [{layer_label}]{rule_display}{ctx_display}{species_display} — {reason}", style=_ROW_STYLE))

        # The Builder's fix — only for rows the Ranker picked (item 1); a row with
        # no candidate shows nothing as a solution (owner).
        brow = item.get('_builder') or {}
        # Owner ruling 2026-09-09: a row shows its solution and nothing else — no revision,
        # tester labels on the dash (the tester's confirmation lives in BUILDER_STATE.json
        # rows[] and the tester report). A row with no solution shows nothing.
        if kind == 'repair' and brow:
            fix_text = brow.get('fix') or ''
            # FIX_41: a prescribed solution's text IS the solution — shown whole (a rewriter's
            # what-changed line stays truncated; its after-code block below carries the repair).
            shown = fix_text if brow.get('solution_kind') == 'prescribed' else fix_text[:120]
            # B6 (2026-10-01, Q-H2-6): the row carries its APPLY VERDICT — the same word and reason
            # `cr_infractions` publishes, from the ONE function (`coderadar_mcp.read_tools.apply_verdict`):
            # `yes` only when a concrete diff rendered at the live site (green, as before); `review`
            # (amber) for a prescribed template or a rewriter whose diff did not render here; `no`
            # (grey) for a row the Builder published not selectable. Verdict unread = NOT MEASURED, amber.
            _v = _apply_verdict_for({**item, **brow}, has_solution=True)
            _word, _why = _v.get('apply', 'NOT MEASURED'), _v.get('apply_reason', '')
            _vcolor = {'yes': '#22c55e', 'review': '#f59e0b', 'no': '#9ca3af'}.get(_word, '#f59e0b')
            _fixcolor = '#22c55e' if _word == 'yes' else ('#9ca3af' if _word == 'no' else '#f59e0b')
            if fix_text:
                out.append(html.Div([
                    html.Span(f"apply: {_word}", title=_why or 'a concrete diff rendered at the live site',
                              style={**_CHIP_STYLE, 'color': _vcolor, 'marginLeft': '0'}),
                    html.Span(f" fix: {shown}  [{brow.get('decision', {}).get('pick_role', '')} · {brow.get('digest', '')}]"),
                ], style={'color': _fixcolor, 'fontSize': '8pt', 'fontFamily': 'monospace',
                          'marginLeft': '24px', 'fontStyle': 'italic', 'whiteSpace': 'normal'}))
            # Solution gate (verifier, 2026-10-10): an agent attempt that integrated with its entry point NOT MEASURED
            # (no declared entry could run headless) says so on the row — amber, never read as a full pass.
            for _a in brow.get('attempts') or []:
                if _a.get('status') == 'integrated' and _a.get('not_measured'):
                    out.append(html.Div(
                        f"integrated — NOT MEASURED: {'; '.join(_a['not_measured'])}",
                        style={'color': '#f59e0b', 'fontSize': '8pt', 'fontFamily': 'monospace',
                               'marginLeft': '24px', 'fontStyle': 'italic', 'whiteSpace': 'normal'}))
            if _word != 'yes':
                out.append(html.Div(
                    f"{_word} — {_why}" if _why else f"{_word} — verdict unread",
                    style={'color': _vcolor, 'fontSize': '8pt', 'fontFamily': 'monospace',
                           'marginLeft': '24px', 'fontStyle': 'italic', 'whiteSpace': 'normal'}))
            after = brow.get('after_code', '')
            if after and not after.startswith('#'):
                # Multi-line code fix — a code block; pre only here, where the lines ARE the content.
                # Green = a rendered diff; amber = a template / shape to review, not a diff (B6).
                out.append(html.Pre(
                    after,
                    style={'color': _fixcolor, 'fontSize': '8pt', 'fontFamily': 'monospace',
                           'marginLeft': '24px', 'marginTop': '1px', 'marginBottom': '2px',
                           'padding': '2px 6px', 'backgroundColor': '#0d1117',
                           'borderLeft': f'2px solid {_fixcolor}', 'borderRadius': '2px',
                           'whiteSpace': 'pre', 'overflowX': 'auto',
                           'maxHeight': '120px', 'overflowY': 'auto'}
                ))
            # confidence display removed — detection is binary, no scoring
        if kind == 'no_vetted_fix':
            # S7 (owner ruling 4b-02, NAI-211): a rule whose registry row is no_fix reads as a DESIGN fact,
            # never as a failed or unbuilt build. The reason is the Builder's own `decision.why`.
            # R3 (2026-09-30, T-11): EVERY no-fix row says why — its status and the Builder's decision.why
            # (declined, ranker_none, unbuilt, no_generator as well as no_fix_by_design).
            _nfs = brow.get('no_fix_status')
            _why = (brow.get('decision') or {}).get('why')
            if _nfs == 'no_fix_by_design':
                _line = f"no fix by design — {_why or 'the rule declares no fix'}"
            elif _nfs:
                _line = f"no fix ({_nfs}) — {_why or 'the Builder published no reason'}"
            else:
                _line = "no fix — no Builder row for this infraction yet"
            out.append(html.Div(
                _line,
                style={'color': '#9ca3af', 'fontSize': '8pt', 'fontFamily': 'monospace',
                       'marginLeft': '24px', 'fontStyle': 'italic', 'whiteSpace': 'normal'}))
        out.extend(_observation_lines(brow))
        return out

    def _observation_lines(brow) -> list:
        """I-71 (S7 2026-09-29): the Builder's static observations — BUILDER_STATE rows[].observations,
        {candidate: [token, ...]} — shown under the row: the picked candidate's tokens, or, when the
        Ranker picked none, every candidate's, each named. Tokens as published, none dropped."""
        obs = brow.get('observations') or {}
        pick = (brow.get('decision') or {}).get('pick_role')
        lines = []
        for cand, tokens in obs.items():
            if pick and cand != pick:
                continue
            head = "observations" if pick else f"observations ({cand}, not picked)"
            lines.append(html.Div(
                f"{head}: {' · '.join(str(t) for t in tokens)}",
                className='builder-observations',
                style={'color': '#93c5fd', 'fontSize': '8pt', 'fontFamily': 'monospace',
                       'marginLeft': '24px', 'whiteSpace': 'normal'}))
        return lines

    for _gi, filepath in enumerate(sorted(file_groups.keys())):
        items = sorted(file_groups[filepath], key=lambda x: x.get('line') or 0)
        # the engine's own order, no dash-side ranking (pre-ranker census): the Ranker's picks, then
        # no vetted fix, then whitelisted — each by line
        items = ([x for x in items if x.get('_kind') == 'repair']
                 + [x for x in items if x.get('_kind') == 'no_vetted_fix']
                 + [x for x in items if x.get('_kind') == 'whitelisted'])
        # owner 2026-09-28: SEVERITY FIRST — by the engine-published `severity` (L1 = 1, L2 = 2; None last);
        # stable, so within a severity the engine's order above stands. Ledger row filed (V67, DASH_R r2).
        items = sorted(items, key=lambda x: (x.get('severity') is None, x.get('severity') or 0))
        _n_wl = sum(1 for x in items if x.get('_kind') == 'whitelisted')
        _n_inf = len(items) - _n_wl
        _layers: dict = {}
        for x in items:
            if x.get('_kind') != 'whitelisted':
                _layers[_layer_of(x)] = _layers.get(_layer_of(x), 0) + 1
        _summary = [
            html.Span(filepath, style={'color': '#818cf8', 'fontWeight': 'bold'}),
            html.Span(f"  {_n_inf} infraction{'s' if _n_inf != 1 else ''}", style={'color': '#d1d5db'}),
            *[html.Span(f"{lab} {n}", style={**_CHIP_STYLE, 'color': '#ef4444' if lab in ('L1', 'L2') else '#f59e0b'})
              for lab, n in sorted(_layers.items())],
        ]
        if _n_wl:
            _summary.append(html.Span(f"exempt (owner) {_n_wl}", style=_CHIP_STYLE))
        _top, _rest = items[:_TOP_N], items[_TOP_N:]
        _group: list = [html.Summary(_summary, style={'fontSize': '9pt', 'fontFamily': 'monospace',
                                                      'marginTop': '4px', 'cursor': 'pointer'})]
        for item in _top:
            _group.extend(_finding_rows(item))
        if _rest:
            _more: list = [html.Summary(f"+{len(_rest)} more", style={
                'color': '#9ca3af', 'fontSize': '8pt', 'marginLeft': '10px', 'cursor': 'pointer'})]
            for item in _rest:
                _more.extend(_finding_rows(item))
            _group.append(html.Details(_more, **_crkey(f'more:{filepath}')))
        # I-199: keyed so assets/details_memory.js keeps the viewer's open/shut across tabs, flips, re-renders
        children.append(html.Details(_group, open=(_gi == 0), **_crkey(f'grp:{filepath}')))

    children.extend(_withheld_block())   # FIX_51 (owner Q11): its own block, after the infractions
    # owner 2026-10-07 (panel rewrite): the findings in plain lines on top — `file.py:line function — what is wrong —
    # what to do` — and the full engine detail (rule ids, gates, observations) folded underneath, unchanged
    try:
        plain = _noai_plain_lines(failures, withheld_fns)
        plain += _noai_review_lines(results_by_file)
    except Exception as _pe:
        logger.exception("plain counterfeit lines failed; the detail view is shown open instead")
        plain = [html.Div(f"plain view failed ({type(_pe).__name__}) — detail below",
                          style={'color': '#f59e0b', 'fontSize': '9pt'})]
    detail = html.Details([html.Summary("engine detail (rule ids, gates, observations)",
                                        style={'color': '#6b7280', 'fontSize': '8.5pt', 'cursor': 'pointer'}),
                           *children], **_crkey('noai-detail'))
    return [*plain, detail], summary_el


@app.callback(
    Output('pythonpath-display', 'children'),
    Output('pythonpath-sig', 'data'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
    State('pythonpath-sig', 'data'),
)
def update_pythonpath_display_guarded(n_intervals, active_state_file, last_sig):
    out = update_pythonpath_display(n_intervals, active_state_file)
    same, sig = _unchanged(out, last_sig)
    return (no_update, no_update) if same else (out, sig)


def update_pythonpath_display(n_intervals, active_state_file):
    """Display PYTHONPATH with live detection and path hacks."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    if not state:   # B4 / Q-H2-1: never "No data" — the tile line of _tracker_not_published, with the reason
        return _tracker_not_published('path hacks', state)[0]
    if state.get(_WRONG_TARGET):
        return state[_WRONG_TARGET]

    # Skip re-render if path hacks data unchanged

    sys_path = state.get('sys_path', [])
    path_hacks = state.get('path_hacks', {})

    children = []

    # Path hacks — split by severity
    if path_hacks:
        # Categorize all hacks
        RED_TYPES = {'sys_path_insert', 'sys_path_append', 'sys_path_extend',
                     'pythonpath_access', 'pythonpath_read', 'pythonpath_config',
                     'shadowed_stdlib', 'broken_import', 'unguarded_external',
                     'circular_import'}
        AMBER_TYPES = {'relative_path',   # FIX_35 c (2026-09-15): `relative_import` is informational (gray), never structural
                       # FIX_49 (2026-09-17, owner Q9 / I-41): `missing_init` left this set — it is
                       # INFORMATIONAL now, and it says so in rule_dispositions.json `path_hacks`, which
                       # the daemon stamps on the row. The literal sets below stay only as the fallback
                       # for a hack the table has no row for.
                       'empty_package', 'duplicate_package', 'missing_package',
                       'wildcard_import', 'stale_dependency', 'naming_drift',
                       'broken_import_guarded', 'circular_import_guarded'}
        PEACH_TYPES = {'unconnected_init', 'reexport_only'}
        # Everything else (file_traversal, etc.) is gray/informational

        red_items, amber_items, peach_items, gray_items = [], [], [], []
        # FIX_16 (2026-09-10): measurement status rows (`not_measured`) are rendered as their own
        # line — "unguarded external: NOT MEASURED — no declared dependencies" — never counted as a hack.
        measurement_rows = []
        for file in sorted(path_hacks.keys()):
            for hack in path_hacks[file]:
                entry = (file, hack)
                htype = hack.get('type', '')
                if htype in ('not_measured', 'measured'):   # FIX_16 step 3 (2026-09-15): the declared-dependency feed's status
                    measurement_rows.append(hack)
                    continue
                # FIX_49 / FIX_50 (2026-09-17): the DISPOSITION the daemon stamped decides first —
                # `context` is informational (published with its warning, never counted), whatever the
                # type. A state written before the stamp existed carries no disposition and falls
                # through to the literal sets, exactly as before.
                if hack.get('disposition') == 'context':
                    gray_items.append(entry)
                elif htype in RED_TYPES:
                    red_items.append(entry)
                elif htype in AMBER_TYPES:
                    amber_items.append(entry)
                elif htype in PEACH_TYPES:
                    peach_items.append(entry)
                else:
                    gray_items.append(entry)

        # FIX_35 c (2026-09-15): the gray rows (relative imports inside a package, file traversal) are INFORMATIONAL —
        # published, never counted as hacks; `total` = critical + structural + wiring only.
        # FIX_49 / FIX_50 (2026-09-17): a missing __init__.py and an ENTRY script's own path hack join them.
        total = len(red_items) + len(amber_items) + len(peach_items)
        # Count guarded broken imports separately for the summary
        guarded_count = sum(1 for _, h in amber_items
                           if h.get('type') == 'broken_import_guarded')
        children.append(html.Div(
            f"PATH HACKS: {total} detected — {len(red_items)} critical, "
            f"{len(amber_items)} structural ({guarded_count} guarded imports), "
            f"{len(peach_items)} wiring · {len(gray_items)} informational "
            f"(relative imports, missing __init__.py, an entry script's own path hack — not counted)",
            style={'color': '#f59e0b', 'fontWeight': 'bold', 'marginTop': '8px'}
        ))
        # FIX_16: true or NOT MEASURED — the unguarded-external measurement always says which it is
        if measurement_rows:
            for m in measurement_rows:
                children.append(html.Div(m.get('details', 'NOT MEASURED'),
                                         style={'color': '#9ca3af', 'fontSize': '8pt', 'marginTop': '4px'}))
        elif not any(h.get('type') == 'unguarded_external' for _, h in red_items):
            children.append(html.Div(
                "unguarded external imports (0) — measured against the target's declared dependencies",
                style={'color': '#9ca3af', 'fontSize': '8pt', 'marginTop': '4px'}))

        _ph_detail_start = len(children)   # DASH_R: everything below goes behind the toggle
        # Red — split into sub-categories
        if red_items:
            _RED_SUBTYPES = {
                'circular_import': 'circular imports',
                'broken_import': 'BARE broken imports — will crash',
                'unguarded_external': 'unguarded external imports — will crash if pkg missing',
            }
            # Group red items by sub-type
            for subtype, label in _RED_SUBTYPES.items():
                sub = [(f, h) for f, h in red_items if h.get('type') == subtype]
                if sub:
                    children.append(html.Div(
                        f"{label} ({len(sub)}):",
                        style={'color': '#ef4444', 'fontWeight': 'bold',
                               'marginTop': '6px', 'fontSize': '8pt'}))
                    for file, hack in sub:
                        children.append(html.Div(
                            f"  {file}:{hack['line']} - {hack['details']}",
                            style={'color': '#ef4444', 'fontSize': '8pt', 'marginLeft': '10px'}
                        ))

            # Remaining red items (sys.path, PYTHONPATH, shadowed stdlib)
            known_subtypes = set(_RED_SUBTYPES.keys())
            other_red = [(f, h) for f, h in red_items
                         if h.get('type') not in known_subtypes]
            if other_red:
                children.append(html.Div(f"sys.path / PYTHONPATH ({len(other_red)}):",
                                         style={'color': '#ef4444', 'fontWeight': 'bold',
                                                'marginTop': '6px', 'fontSize': '8pt'}))
                for file, hack in other_red:
                    children.append(html.Div(
                        f"  {file}:{hack['line']} - {hack['details']}",
                        style={'color': '#ef4444', 'fontSize': '8pt', 'marginLeft': '10px'}
                    ))

        # Amber — split guarded imports from other structural issues
        if amber_items:
            guarded = [(f, h) for f, h in amber_items
                       if h.get('type') == 'broken_import_guarded']
            circ_guarded = [(f, h) for f, h in amber_items
                           if h.get('type') == 'circular_import_guarded']
            structural = [(f, h) for f, h in amber_items
                         if h.get('type') not in ('broken_import_guarded',
                                                   'circular_import_guarded')]

            if circ_guarded:
                children.append(html.Div(
                    f"circular imports — guarded ({len(circ_guarded)}):",
                    style={'color': '#f59e0b', 'fontWeight': 'bold',
                           'marginTop': '6px', 'fontSize': '8pt'}))
                for file, hack in circ_guarded:
                    children.append(html.Div(
                        f"  {hack['details']}",
                        style={'color': '#f59e0b', 'fontSize': '8pt', 'marginLeft': '10px'}
                    ))

            if guarded:
                children.append(html.Div(
                    f"guarded broken imports ({len(guarded)}) — won't crash, features inactive:",
                    style={'color': '#f59e0b', 'fontWeight': 'bold',
                           'marginTop': '6px', 'fontSize': '8pt'}))
                for file, hack in guarded:
                    children.append(html.Div(
                        f"  {file}:{hack['line']} - {hack['details']}",
                        style={'color': '#f59e0b', 'fontSize': '8pt', 'marginLeft': '10px'}
                    ))

            if structural:
                children.append(html.Div(
                    f"structural / relative paths ({len(structural)}):",
                    style={'color': '#f59e0b', 'fontWeight': 'bold',
                           'marginTop': '6px', 'fontSize': '8pt'}))
                for file, hack in structural:
                    children.append(html.Div(
                        f"  {file}:{hack['line']} - {hack['details']}",
                        style={'color': '#f59e0b', 'fontSize': '8pt', 'marginLeft': '10px'}
                    ))

        # Peach — wiring issues (unconnected init, re-export-only)
        if peach_items:
            children.append(html.Div(f"wiring issues ({len(peach_items)}):",
                                     style={'color': '#ffb07c', 'fontWeight': 'bold',
                                            'marginTop': '6px', 'fontSize': '8pt'}))
            for file, hack in peach_items:
                children.append(html.Div(
                    f"  {file}:{hack['line']} - {hack['details']}",
                    style={'color': '#ffb07c', 'fontSize': '8pt', 'marginLeft': '10px'}
                ))

        # Gray — INFORMATIONAL: relative imports, __file__ references, and (FIX_49 / FIX_50,
        # 2026-09-17) every row the disposition table calls `context`. Each row shows the WARNING
        # the table gives as the reason it is not an infraction — a warning on the row, no
        # infraction, no solution (owner Q9 / Q10).
        if gray_items:
            children.append(html.Div(f"informational — published, never counted ({len(gray_items)}):",
                                     style={'color': '#6b7280', 'fontWeight': 'bold',
                                            'marginTop': '6px', 'fontSize': '8pt'}))
            for file, hack in gray_items:
                _w = hack.get('warning') or ''
                children.append(html.Div(
                    f"  {file}:{hack['line']} - {hack['details']}" + (f"  ⚠ {_w}" if _w else ''),
                    style={'color': '#6b7280', 'fontSize': '8pt', 'marginLeft': '10px'}
                ))

        # DASH_R (run 185): the taxonomy collapses behind ONE toggle; its summary names only the
        # categories that have hits, each with its count. The header line above stays visible.
        _R, _A = '#ef4444', '#f59e0b'
        _ph_cats = [
            ('circular', _R, sum(1 for _, h in red_items if h.get('type') == 'circular_import')),
            ('broken', _R, sum(1 for _, h in red_items if h.get('type') == 'broken_import')),
            ('unguarded ext', _R, sum(1 for _, h in red_items if h.get('type') == 'unguarded_external')),
            ('sys.path', _R, sum(1 for _, h in red_items if h.get('type') not in
                                 ('circular_import', 'broken_import', 'unguarded_external'))),
            ('circular guarded', _A, sum(1 for _, h in amber_items if h.get('type') == 'circular_import_guarded')),
            ('guarded broken', _A, sum(1 for _, h in amber_items if h.get('type') == 'broken_import_guarded')),
            ('structural', _A, sum(1 for _, h in amber_items if h.get('type') not in
                                   ('broken_import_guarded', 'circular_import_guarded'))),
            ('wiring', '#ffb07c', len(peach_items)),
            ('informational', '#6b7280', len(gray_items)),
        ]
        _ph_detail = children[_ph_detail_start:]
        del children[_ph_detail_start:]
        if _ph_detail:
            children.append(html.Details([
                html.Summary([html.Span(f"{lbl} {n}", style={**_CHIP_STYLE, 'color': c}) for lbl, c, n in _ph_cats if n],
                             style={'cursor': 'pointer', 'marginTop': '4px'}),
                *_ph_detail,
            ], **_crkey('path-hacks')))

    # DASH_R (run 185): the sys.path listing is reference, not a finding — collapsed behind its toggle.
    if sys_path:
        _sp_rows = []
        for p in sys_path[:10]:
            _sp_rows.append(html.Div(f"  {p}",
                                    style={'color': '#9ca3af', 'fontSize': '8pt'}))
        children.append(html.Details([
            html.Summary(f"sys.path (first {min(len(sys_path), 10)} of {len(sys_path)})",
                         style={'color': '#6b7280', 'cursor': 'pointer'}),
            *_sp_rows,
        ], style={'marginTop': '6px'}, **_crkey('sys-path')))

    return children


@app.callback(
    Output('download-path-hacks', 'data'),
    Input('export-path-hacks-btn', 'n_clicks'),
    prevent_initial_call=True
)
def export_path_hacks(n_clicks):
    """Export full path hacks list as a text file."""
    state = read_circuit_state()
    if not state:
        return None

    path_hacks = state.get('path_hacks', {})
    if not path_hacks:
        return None

    RED_TYPES = {'sys_path_insert', 'sys_path_append', 'sys_path_extend',
                 'pythonpath_access', 'pythonpath_read', 'pythonpath_config',
                 'shadowed_stdlib', 'broken_import'}
    AMBER_TYPES = {'relative_path',   # FIX_35 c (2026-09-15): `relative_import` is informational (gray), never structural
                   # FIX_49 (2026-09-17, owner Q9 / I-41): `missing_init` is informational — the table says so
                   'empty_package', 'duplicate_package', 'missing_package',
                   'wildcard_import', 'stale_dependency', 'naming_drift',
                   'broken_import_guarded', 'circular_import_guarded'}
    PEACH_TYPES = {'unconnected_init', 'reexport_only'}

    red, amber, peach, gray = [], [], [], []
    for file in sorted(path_hacks.keys()):
        for hack in path_hacks[file]:
            _w = hack.get('warning') or ''
            entry = f"{file}:{hack['line']}  [{hack['type']}]  {hack['details']}" + (f"  ⚠ {_w}" if _w else '')
            htype = hack.get('type', '')
            # FIX_49 / FIX_50: the stamped disposition decides first; the literal sets are the fallback
            if hack.get('disposition') == 'context':
                gray.append(entry)
            elif htype in RED_TYPES:
                red.append(entry)
            elif htype in AMBER_TYPES:
                amber.append(entry)
            elif htype in PEACH_TYPES:
                peach.append(entry)
            else:
                gray.append(entry)

    total = len(red) + len(amber) + len(peach) + len(gray)
    lines = [
        f"Path Hacks Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total: {total} — {len(red)} CRITICAL, {len(amber)} STRUCTURAL, "
        f"{len(peach)} WIRING, {len(gray)} INFORMATIONAL",
        "=" * 70,
    ]

    if red:
        lines += ["", "CRITICAL — sys.path / PYTHONPATH manipulation", "-" * 50] + red
    if amber:
        lines += ["", "STRUCTURAL — relative paths / packaging", "-" * 50] + amber
    if peach:
        lines += ["", "WIRING — unconnected init / re-export-only packages", "-" * 50] + peach
    if gray:
        lines += ["", "INFORMATIONAL — published, never counted (relative imports, __file__ references, "
                      "missing __init__.py, an entry script's own path hack)", "-" * 50] + gray

    content = "\n".join(lines)
    return dcc.send_string(content, filename=f"path_hacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")


# ═══════════════════════════════════════════════════════════════════════════════
# CRC / MYPY / CONTRACTS PANELS
# ═══════════════════════════════════════════════════════════════════════════════

@app.callback(
    Output('crc-results', 'children'),
    Output('crc-summary', 'children'),
    Output('crc-summary', 'style'),
    Output('crc-accept-btn', 'style'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_crc_panel(n_intervals, active_state_file):
    """Display CRC frozen function status."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    _wt = _not_this_target(state, {'display': 'none', 'fontSize': '8pt', 'padding': '2px 8px'})
    if _wt:
        return _wt
    crc = state.get('crc_results', {})

    # Skip re-render if CRC data unchanged

    btn_hidden = {'display': 'none', 'fontSize': '8pt', 'padding': '2px 8px'}
    btn_visible = {'display': 'inline-block', 'fontSize': '8pt', 'padding': '2px 8px'}

    # Item 7 (2026-09-10): a tracker the launch did not choose says so — the disclosure line.
    # R9: "NOT MEASURED — <reason>" is shown as published; the --trackers suffix is only for "not run".
    _crcu = _tracker_unmeasured('CRC', crc)
    if _crcu:
        return (
            html.Div(_crcu[0],
                     style={'color': _unmeasured_colour(_crcu[1]), 'fontSize': '9pt', 'fontStyle': 'italic'}),
            _crcu[1],
            {'fontSize': '10pt', 'color': _unmeasured_colour(_crcu[1]), 'marginLeft': '20px'},
            btn_hidden,
        )
    if not state or crc.get('status') != 'measured':   # B4 / Q-H2-1: no state, or no published measurement
        return _tracker_not_published('CRC', state, btn_hidden)
    if set(crc) <= {'status'}:
        return (
            html.Div("CRC measured — no scan result yet this cycle",
                     style={'color': '#6b7280', 'fontSize': '9pt', 'fontStyle': 'italic'}),
            "measured — waiting",
            {'fontSize': '10pt', 'color': '#6b7280', 'marginLeft': '20px'},
            btn_hidden,
        )

    violations = crc.get('violations', [])
    frozen_count = crc.get('frozen_count', 0)
    current_funcs = crc.get('current_functions', crc.get('total_functions', 0))
    files_on_disk = crc.get('files_on_disk', crc.get('files_in_baseline', 0))
    new_file_count = crc.get('new_file_count', 0)
    new_files = crc.get('new_files', [])
    removed_file_count = crc.get('removed_file_count', 0)
    removed_files = crc.get('removed_files', [])
    has_drift = new_file_count > 0 or removed_file_count > 0

    if violations:
        summary_color = '#ef4444'
        summary_text = f"VIOLATIONS: {len(violations)} frozen function(s) changed"
    elif has_drift:
        summary_color = '#f59e0b'
        parts = []
        if new_file_count > 0:
            parts.append(f"+{new_file_count} new")
        if removed_file_count > 0:
            parts.append(f"-{removed_file_count} removed")
        summary_text = f"OK: {frozen_count} frozen / {current_funcs} funcs ({', '.join(parts)})"
    else:
        summary_color = '#22c55e'
        summary_text = f"OK: {frozen_count} frozen / {current_funcs} total functions"

    summary_style = {'fontSize': '10pt', 'color': summary_color,
                     'marginLeft': '20px', 'fontWeight': 'bold'}

    baseline_files = crc.get('files_in_baseline', 0)
    baseline_funcs = crc.get('total_functions', 0)

    children = []
    children.append(html.Div(
        f"Baseline: {baseline_funcs} functions — {_discovery_text(TARGET_REPO)} — {frozen_count} frozen",
        style={'color': '#9ca3af', 'fontSize': '9pt', 'marginBottom': '6px'}
    ))

    if new_files:
        children.append(html.Div(
            f"New files ({new_file_count} not in baseline):",
            style={'color': '#f59e0b', 'fontSize': '9pt', 'marginTop': '4px', 'fontWeight': 'bold'}
        ))
        new_files_list = []
        for nf in new_files:
            new_files_list.append(html.Div(
                f"  + {nf['file']} ({nf['functions']} funcs)",
                style={'color': '#f59e0b', 'fontSize': '9pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))
        children.append(html.Div(
            new_files_list,
            style={
                'maxHeight': '150px',
                'overflowY': 'auto',
                'backgroundColor': '#111',
                'padding': '8px',
                'borderRadius': '4px',
                'marginTop': '4px',
            }
        ))

    if removed_files:
        children.append(html.Div(
            f"Removed files ({removed_file_count} gone from disk):",
            style={'color': '#ef4444', 'fontSize': '9pt', 'marginTop': '4px', 'fontWeight': 'bold'}
        ))
        removed_files_list = []
        for rf in removed_files:
            removed_files_list.append(html.Div(
                f"  - {rf['file']} ({rf['functions']} funcs)",
                style={'color': '#ef4444', 'fontSize': '9pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))
        children.append(html.Div(
            removed_files_list,
            style={
                'maxHeight': '150px',
                'overflowY': 'auto',
                'backgroundColor': '#111',
                'padding': '8px',
                'borderRadius': '4px',
                'marginTop': '4px',
            }
        ))

    if violations:
        for v in violations:
            children.append(html.Div(
                f"  {v['file']}: {v['message']}",
                style={'color': '#ef4444', 'fontSize': '9pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))

    show_accept = has_drift or len(violations) > 0
    return children, summary_text, summary_style, btn_visible if show_accept else btn_hidden


@app.callback(
    Output('crc-accept-status', 'children'),
    Input('crc-accept-btn', 'n_clicks'),
    State('active-state-file', 'data'),
    prevent_initial_call=True,
)
def accept_crc_new_files(n_clicks, active_state_file):
    """Accept new files into the CRC baseline."""
    import importlib.util
    from pathlib import Path

    script_dir = Path(__file__).parent
    baseline_path = script_dir / "mypy_n_contracts_watcher" / "baseline.json"

    try:
        spec = importlib.util.spec_from_file_location(
            "crc_engine", script_dir / "mypy_n_contracts_watcher" / "crc_engine.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        engine = mod.CRCEngine()

        # Read state to get target repo
        state = read_circuit_state(active_state_file)
        if state.get(_WRONG_TARGET):
            return f"NOT ACCEPTED: {state[_WRONG_TARGET]}"
        target_repo = Path(state.get('target_repo', ''))
        if not target_repo.exists():
            return "Error: target repo not found"

        # Preserve frozen set from old baseline
        old_frozen = set()
        if baseline_path.exists():
            engine.load_baseline(baseline_path)
            if engine.baseline:
                old_frozen = engine.baseline.frozen

        # Re-create baseline from current repo state
        print(f"CRC ACCEPT: Rebuilding baseline for {target_repo}")
        engine.create_baseline([target_repo], baseline_path)

        # Restore frozen functions
        if engine.baseline and old_frozen:
            engine.baseline.frozen = old_frozen
            engine._save_baseline(engine.baseline, baseline_path)

        total = sum(len(f) for f in engine.baseline.functions.values())
        msg = f"{len(engine.baseline.functions)} files, {total} funcs, {len(old_frozen)} frozen kept"
        print(f"CRC ACCEPT: {msg}")
        return msg
    except Exception as e:
        print(f"CRC ACCEPT ERROR: {e}")
        return f"Error: {e}"


# =============================================================================
# NAMING DRIFT — the permanent data type tracker (ND2, 2026-10-01, PLAN_NAMING_DRIFT_TRACKER §D)
# =============================================================================
# The block is `naming_drift` — in circuit_state.json and, beside `path_hacks`, in the dash mirror's
# `monitor` envelope (circuit_daemon `write_repo_mirror`); the panel reads the circuit state first and the
# mirror in SCRIPT_DIR second. `ran: false` = NOT MEASURED (the launch scan has not completed) — never 0.
# Accept is the ONLY input (plan §B): a ruling lands in `naming_drift/accepted_<repoid>.json` (appended,
# never overwritten — rulings last, plan §C.1) and `reload_<repoid>.flag` is touched for the daemon's next tick.

NAMING_DRIFT_DIR = SCRIPT_DIR / 'naming_drift'
ACCEPT_RULINGS = ('variant', 'canonical')   # the two rulings the dash can give (plan §B: accept is the only input)
_ND_NOT_RAN = "launch scan has not completed — the baseline is not built yet"
_ND_TIER_COLOUR = {'T1': '#ef4444', 'T2': '#f59e0b', 'T3': '#9ca3af'}


def naming_drift_paths(target_repo: Path) -> Tuple[Path, Path]:
    """(accepted_<repoid>.json, reload_<repoid>.flag) for *target_repo* — repo id = `get_repo_id`
    (circuit_daemon.py:268's algorithm), the flag path ND1's reader consumes."""
    rid = get_repo_id(Path(target_repo))
    return NAMING_DRIFT_DIR / f"accepted_{rid}.json", NAMING_DRIFT_DIR / f"reload_{rid}.flag"


def read_naming_drift_block(state: dict, state_file=None) -> Tuple[dict, Optional[str]]:
    """The published `naming_drift` block and why it is NOT MEASURED (None only once it says `ran: true`).
    circuit state first; the dash mirror (`.monitor_state.json` beside the state file) second; an absent
    block is NOT MEASURED with that reason — never an empty measurement."""
    block = state.get('naming_drift') if isinstance(state, dict) else None
    if not isinstance(block, dict) or not block:
        mirror_path = (Path(state_file).parent if state_file else SCRIPT_DIR) / '.monitor_state.json'
        try:
            mirror = read_file_locked(mirror_path).get('monitor') or {}
        except Exception:
            mirror = {}
        if not mirror or _validate_daemon_repo(mirror):   # R3: another target's mirror is never read
            mirror = {}
        block = mirror.get('naming_drift') if isinstance(mirror, dict) else None
    published = block if isinstance(block, dict) else {}
    if published == {}:
        return {}, "the naming check has not reported yet (not published in circuit state or the dash mirror)"
    if published.get('ran') is not True:
        return published, str(published.get('not_measured_reason') or _ND_NOT_RAN)
    return published, None


def naming_drift_headline(block: dict) -> str:
    """`new drift N · pre-existing M · accepted A` — the published counts of a block that ran."""
    return (f"new drift {block.get('new')} · pre-existing {block.get('pre_existing')} · "
            f"accepted {block.get('accepted')}")


def write_naming_drift_accept(target_repo: Path, spelling: str, key: str, ruling: str) -> str:
    """The accept WRITER (plan §D dash / §E accept): append ONE entry to accepted_<repoid>.json —
    `{"repo_id", "entries": [{"spelling", "key", "ruling": "variant"|"canonical", "at", "source": "dash"}]}` —
    and touch reload_<repoid>.flag so the daemon re-reads before its next diff. A second accept appends;
    the file is never overwritten. Returns the one status line the panel shows."""
    from datetime import timezone as _tz
    if ruling not in ACCEPT_RULINGS or spelling == '':
        return (f"NOT ACCEPTED: ruling must be one of {ACCEPT_RULINGS} (got {ruling!r}) and the row must "
                f"name a spelling (got {spelling!r})")
    accepted_path, flag_path = naming_drift_paths(target_repo)
    NAMING_DRIFT_DIR.mkdir(parents=True, exist_ok=True)
    previous = read_file_locked(accepted_path) if accepted_path.exists() else {}
    entries = list(previous.get('entries') or []) if isinstance(previous, dict) else []
    stamp = datetime.now(_tz.utc).isoformat()
    entries.append({'spelling': spelling, 'key': key, 'ruling': ruling, 'at': stamp, 'source': 'dash'})
    write_file_locked(accepted_path, {'repo_id': get_repo_id(Path(target_repo)), 'entries': entries})
    flag_path.write_text(stamp + "\n")   # a touch the daemon reads by mtime; the time inside is for a human
    return (f"accepted as {ruling}: {spelling} (key {key}) — {len(entries)} ruling(s) in "
            f"{accepted_path.name}; {flag_path.name} touched")


def _naming_drift_rows(block: dict) -> list:
    """The groups window: the table (one line per published row — a drifted spelling — with its two ACCEPT
    buttons), or the one green line when the block ran and carries no row (after accept)."""
    rows = list(block.get('rows') or [])
    empty_line = html.Div("naming drift measured — no drift group this cycle (every spelling agrees or is accepted)",
                          style={'color': '#22c55e', 'fontSize': '9pt', 'fontStyle': 'italic'})
    return [_naming_drift_table(rows)] if rows else [empty_line]


def _naming_drift_table(rows: list):
    """The groups table: canonical · variant · sites · tier · kind · ruling (two buttons)."""
    cell = {'padding': '2px 6px', 'fontSize': '9pt', 'fontFamily': 'monospace', 'verticalAlign': 'top'}
    head = {'padding': '2px 6px', 'fontSize': '8pt', 'color': '#9ca3af', 'textAlign': 'left'}
    header = html.Tr([html.Th(h, style=head) for h in ('canonical', 'variant', 'sites', 'tier', 'kind', 'ruling')])
    body = []
    for row in rows:
        sites = row.get('sites') or []
        first = sites[0] if sites else {}
        # owner 2026-10-07 06:20: a path only has to say WHERE — the file name and line; the full path is the hover
        where = f"{str(first.get('file', '?')).rsplit('/', 1)[-1]}:{first.get('line', '?')}" if sites else "no site"
        where_full = '\n'.join(f"{x.get('file', '?')}:{x.get('line', '?')}" for x in sites)
        more = f" (+{len(sites) - 1})" if len(sites) > 1 else ""
        tier = str(row.get('tier') or '?')
        kind = str(row.get('kind') or '?').replace('_', '-')
        spelling = str(row.get('spelling') or '')
        key = str(row.get('key') or '')
        buttons = html.Div([
            dbc.Button('accept as variant', size='sm', color='secondary', outline=True,
                       id={'type': 'nd-accept', 'ruling': 'variant', 'index': f"{key}|{spelling}"},
                       style={'fontSize': '8pt', 'padding': '1px 6px', 'marginRight': '4px'}),
            dbc.Button('make canonical', size='sm', color='warning', outline=True,
                       id={'type': 'nd-accept', 'ruling': 'canonical', 'index': f"{key}|{spelling}"},
                       style={'fontSize': '8pt', 'padding': '1px 6px'}),
        ], style={'display': 'flex', 'flexWrap': 'wrap', 'gap': '3px'})
        body.append(html.Tr([
            html.Td(str(row.get('canonical') or ''), style={**cell, 'color': '#22c55e'}),
            html.Td(spelling, style={**cell, 'color': '#f59e0b'}),
            html.Td(f"{where}{more}", title=where_full, style={**cell, 'color': '#9ca3af', 'overflowWrap': 'anywhere'}),
            html.Td(tier, style={**cell, 'color': _ND_TIER_COLOUR.get(tier, '#9ca3af'), 'fontWeight': 'bold'}),
            html.Td(kind, style={**cell, 'color': '#9ca3af'}),
            html.Td(buttons, style=cell),
        ]))
    return html.Table([html.Thead(header), html.Tbody(body)],
                      style={'width': '100%', 'borderCollapse': 'collapse', 'tableLayout': 'auto'})


@app.callback(
    Output('naming-drift-results', 'children'),
    Output('naming-drift-summary', 'children'),
    Output('naming-drift-summary', 'style'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_naming_drift_panel(n_intervals, active_state_file):
    """The naming-drift tile: NOT MEASURED (amber) before the launch scan has completed or when the block
    is not published; the headline + groups table once it ran; the green empty line when it ran and no
    group is open (after accept)."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    _wt = _not_this_target(state)
    if _wt or state == {}:   # R3 another target's state, or no circuit state read at all (B4's tile)
        return _wt or _tracker_not_published('Naming drift', state)
    block, why = read_naming_drift_block(state, sf)
    if why is not None:
        return (
            html.Div(f"Naming drift NOT MEASURED — {why}",
                     style={'color': '#f59e0b', 'fontSize': '9pt', 'fontStyle': 'italic'}),
            "NOT MEASURED",
            {'fontSize': '10pt', 'color': '#f59e0b', 'marginLeft': '20px'},
        )
    new_count = block.get('new')
    colour = '#ef4444' if new_count else ('#f59e0b' if block.get('pre_existing') else '#22c55e')
    children = [html.Div(
        f"Baseline: {block.get('scanned_files')} files at {block.get('baseline_at')} — "
        f"{block.get('groups')} group(s) — T1 {(block.get('by_tier') or {}).get('T1')} · "
        f"T2 {(block.get('by_tier') or {}).get('T2')} · T3 {(block.get('by_tier') or {}).get('T3')} "
        f"(T1 = strongest match, T3 = weakest; T3 is listed but never counted in the headline)",
        style={'color': '#9ca3af', 'fontSize': '9pt', 'marginBottom': '6px'})]
    children.extend(_naming_drift_rows(block))
    return (children, naming_drift_headline(block),
            {'fontSize': '10pt', 'color': colour, 'marginLeft': '20px', 'fontWeight': 'bold'})


@app.callback(
    Output('naming-drift-accept-status', 'children'),
    Input({'type': 'nd-accept', 'ruling': dash.ALL, 'index': dash.ALL}, 'n_clicks'),
    State('active-state-file', 'data'),
    prevent_initial_call=True,
)
def accept_naming_drift(n_clicks, active_state_file):
    """ACCEPT AS VARIANT / MAKE CANONICAL on one groups-table row → `write_naming_drift_accept`
    (CRC's `accept_crc_new_files` is the template: the target comes from the state, never from config)."""
    ctx = dash.callback_context
    btn = ctx.triggered_id if isinstance(ctx.triggered_id, dict) else {}   # the pattern id, already a dict
    if btn == {} or not any(n for n in (n_clicks or []) if n):
        return no_update
    key, _, spelling = str(btn.get('index', '')).partition('|')
    state = read_circuit_state(active_state_file if active_state_file else None)
    if state.get(_WRONG_TARGET):
        return f"NOT ACCEPTED: {state[_WRONG_TARGET]}"
    target_repo = Path(str(state.get('target_repo') or ''))
    if not str(state.get('target_repo') or '') or not target_repo.is_dir():
        return "NOT ACCEPTED: the circuit state names no target repo"
    try:
        msg = write_naming_drift_accept(target_repo, spelling, key, str(btn.get('ruling', '')))
    except Exception as e:
        msg = f"NOT ACCEPTED: {e}"
    print(f"NAMING DRIFT ACCEPT: {msg}")
    return msg


@app.callback(
    Output('mypy-results', 'children'),
    Output('mypy-summary', 'children'),
    Output('mypy-summary', 'style'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_mypy_panel(n_intervals, active_state_file):
    """Display mypy type check results."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    _wt = _not_this_target(state)
    if _wt:
        return _wt
    mypy = state.get('mypy_results', {})

    # Skip re-render if mypy data unchanged

    # Item 7 (2026-09-10): keyed on the published `status` — not chosen at launch is a fact, not a wait.
    # R9: NOT MEASURED (mypy missing or failed) shows its reason — its counts are null, never shown as 0.
    _myu = _tracker_unmeasured('mypy', mypy)
    if _myu:
        return (
            html.Div(_myu[0],
                     style={'color': _unmeasured_colour(_myu[1]), 'fontSize': '9pt', 'fontStyle': 'italic'}),
            _myu[1],
            {'fontSize': '10pt', 'color': _unmeasured_colour(_myu[1]), 'marginLeft': '20px'}
        )
    if not state or mypy.get('status') != 'measured':   # B4 / Q-H2-1: no state, or no published measurement
        return _tracker_not_published('mypy', state)
    if not mypy.get('files_checked'):
        return (
            html.Div(),
            "measured — waiting",
            {'fontSize': '10pt', 'color': '#6b7280', 'marginLeft': '20px'}
        )

    passed = mypy.get('passed', 0)
    failed = mypy.get('failed', 0)
    total_errors = mypy.get('total_errors', 0)

    notes = mypy.get('annotation_notes', 0)
    type_errors = mypy.get('type_errors', total_errors)
    # Plan item 11: annotation noise (missing annotations under --strict) is not
    # a failure — it is reported as notes beside the real type errors.
    if failed > 0:
        summary_el = html.Span([
            # I-96: this tracker measures the TARGET repo, not CodeRadar — the engine's own number is the
            # health check's `engine mypy:` line. Two numbers, two subjects: the text names its subject.
            html.Span(f"target: {_plural(failed, 'file')} with type errors", style={'color': '#ef4444'}),
            html.Span(f" ({_plural(type_errors, 'type error')}", style={'color': '#ef4444'}),
            html.Span(f", {_plural(notes, 'annotation note')})" if notes else ")", style={'color': '#9ca3af'}),
        ])
    elif passed > 0:
        summary_el = html.Span([
            html.Span(f"target: {_plural(passed, 'file')} clean", style={'color': '#22c55e'}),
            html.Span(f" ({_plural(notes, 'annotation note')})" if notes else "", style={'color': '#9ca3af'}),
        ])
    else:
        summary_el = html.Span("No files checked yet", style={'color': '#6b7280'})

    summary_style = {'fontSize': '10pt', 'marginLeft': '20px', 'fontWeight': 'bold'}

    children = []
    _disc = _discovery(TARGET_REPO)   # R3 (T-15): an unmeasured discovery says so, never "of the 0"
    # A2 / Q-H0-2 (2026-10-01): the count sentence names the discovered total only when discovery was measured;
    # otherwise it counts the checked files alone and the NOT MEASURED marker is its own line, never spliced in.
    _of_disc = f" of the {_disc['live']} discovered files" if _disc['measured'] else ""
    children.append(html.Div(
        f"Checked {_plural(mypy.get('files_checked', 0), 'file')}{_of_disc} "
        f"({passed} clean, {failed} with type errors)"
        + (f" — {_plural(type_errors, 'type error')}, {_plural(notes, 'annotation note')}" if (type_errors or notes) else ""),
        style={'color': '#9ca3af', 'fontSize': '9pt', 'marginBottom': '6px'}
    ))
    if not _disc['measured']:
        children.append(html.Div(
            f"discovered files: NOT MEASURED — {_disc.get('why') or 'no whitelist for this run'}",
            style={'color': '#f59e0b', 'fontSize': '9pt', 'fontStyle': 'italic', 'marginBottom': '6px'}
        ))

    # Show errors grouped by directory.
    # B5 (2026-10-01, Q-H2-2): the drill-down splits each directory's published lines by the ONE
    # rule the badge above was counted with — `mypy_partition.is_note`, shared with circuit_daemon
    # and cr_data_types — so the red per-directory numbers sum to `type_errors` and the notes the
    # badge greys out are grey here too. The old copy of MYPY_SUPPRESS (external-import
    # suppression) partitioned the same lines a second way and drew 88 red "errors" beside a badge
    # saying 27; it is gone. Import lines ([import-not-found] / [import-untyped]) are notes.
    import mypy_partition   # system_scripts is sys.path[0] — the dashboard runs from there
    children.extend(_mypy_dir_drilldown(mypy.get('errors_by_dir', {}), mypy_partition.partition))
    if not mypy.get('errors_by_dir') and mypy.get('recent_checks'):
        children.extend(_mypy_flat_fallback(mypy['recent_checks']))

    return children, summary_el, summary_style


def _mypy_dir_counts(errors_by_dir, partition):
    """B5: per directory, (type_error_lines, note_lines, files_with_type_errors) from the published
    lines by the ONE split — the same numbers circuit_daemon publishes as `errors_by_dir[d].type_errors`
    / `annotation_notes` / `files_with_type_errors`, re-derived here from the lines themselves so a
    state written before B5 (no per-dir keys) splits the same way."""
    out = {}
    for dir_name, dir_info in sorted((errors_by_dir or {}).items()):
        err_lines, note_lines, files_with = [], [], 0
        for file_path, errs in sorted((dir_info.get('files') or {}).items()):
            f_errs, f_notes = partition(errs)
            err_lines.extend(f_errs)
            note_lines.extend(f_notes)
            files_with += 1 if f_errs else 0
        out[dir_name] = (err_lines, note_lines, files_with)
    return out


def _mypy_dir_drilldown(errors_by_dir, partition):
    """B5: the mypy tile's per-directory rows — red `N type errors in F files`, grey `M annotation
    notes`; both lists collapsible, headings name their subject, the red column sums to the badge."""
    counts = _mypy_dir_counts(errors_by_dir, partition)
    error_dirs, note_dirs = [], []
    for dir_name, (err_lines, note_lines, files_with) in counts.items():
        if err_lines:
            error_dirs.append(html.Details([
                html.Summary(
                    f"{dir_name}/  — {_plural(len(err_lines), 'type error')} in {_plural(files_with, 'file')}",
                    style={'color': '#ef4444', 'fontSize': '9pt', 'cursor': 'pointer',
                           'fontFamily': 'monospace', 'fontWeight': 'bold'}
                ),
                html.Div([
                    html.Div(f"  {i+1}. {e}",
                             style={'color': '#ef4444', 'fontSize': '8pt',
                                    'fontFamily': 'monospace', 'marginLeft': '14px'})
                    for i, e in enumerate(err_lines)
                ], style={'marginTop': '2px'})
            ], style={'marginBottom': '4px'}))
        if note_lines:
            note_dirs.append(html.Details([
                html.Summary(
                    f"{dir_name}/  — {_plural(len(note_lines), 'annotation note')}",
                    style={'color': '#9ca3af', 'fontSize': '9pt', 'cursor': 'pointer',
                           'fontFamily': 'monospace'}
                ),
                html.Div([
                    html.Div(f"  {i+1}. {e}",
                             style={'color': '#9ca3af', 'fontSize': '8pt',
                                    'fontFamily': 'monospace', 'marginLeft': '14px'})
                    for i, e in enumerate(note_lines)
                ], style={'marginTop': '2px'})
            ], style={'marginBottom': '4px'}))
    children = []
    _total_errs = sum(len(v[0]) for v in counts.values())
    _total_notes = sum(len(v[1]) for v in counts.values())
    if error_dirs:
        children.append(html.Div(
            f"Type errors by directory ({_plural(_total_errs, 'type error')} in {_plural(len(error_dirs), 'dir')}):",
            style={'color': '#ef4444', 'fontSize': '9pt',
                   'marginTop': '4px', 'fontWeight': 'bold'}
        ))
        children.append(html.Div(
            error_dirs,
            style={'maxHeight': '300px', 'overflowY': 'auto', 'marginBottom': '6px'}
        ))
    if note_dirs:
        children.append(html.Div(
            f"Annotation notes by directory ({_plural(_total_notes, 'note')} in {_plural(len(note_dirs), 'dir')} — not type errors):",
            style={'color': '#9ca3af', 'fontSize': '9pt',
                   'marginTop': '8px', 'fontWeight': 'bold'}
        ))
        children.append(html.Div(
            note_dirs,
            style={'maxHeight': '200px', 'overflowY': 'auto', 'marginBottom': '6px'}
        ))
    return children


def _mypy_flat_fallback(recent_checks):
    """The pre-B5 flat file list, shown only while `errors_by_dir` is not populated yet. A failed
    file's count here is `error_count` = every line (errors AND notes), so the label says `lines`."""
    file_lines = []
    for chk in recent_checks:
        if chk.get('passed'):
            icon, color = '\u2713', '#22c55e'
            label = f"  {icon} {chk['file']}: {chk.get('message', '')}"
        else:
            icon, color = '\u2717', '#ef4444'
            ec = chk.get('error_count', 0)
            label = f"  {icon} {chk['file']} ({_plural(ec, 'mypy line')})"
        file_lines.append(html.Div(
            label,
            style={'color': color, 'fontSize': '8pt', 'fontFamily': 'monospace',
                   'marginLeft': '10px'}
        ))
    return [html.Div(file_lines, style={'maxHeight': '200px', 'overflowY': 'auto'})] if file_lines else []


@app.callback(
    Output('vulture-results', 'children'),
    Output('vulture-summary', 'children'),
    Output('vulture-summary', 'style'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_vulture_panel(n_intervals, active_state_file):
    """Display vulture dead code detection results."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    _wt = _not_this_target(state)
    if _wt:
        return _wt
    vulture = state.get('vulture_results', {})

    # Skip re-render if vulture data unchanged

    # R9: the tracker's published status first — R4's "NOT MEASURED — <reason>" (vulture missing or
    # failed) is shown with its reason, never folded into "not run".
    _vu = _tracker_unmeasured('Dead-code detection', vulture)
    if _vu:
        return (
            html.Div(_vu[0], style={'color': _unmeasured_colour(_vu[1]), 'fontSize': '9pt', 'fontStyle': 'italic'}),
            _vu[1],
            {'fontSize': '10pt', 'color': _unmeasured_colour(_vu[1]), 'marginLeft': '20px'}
        )
    if not state or vulture.get('status') != 'measured':   # B4 / Q-H2-1: no state, or no published measurement
        return _tracker_not_published('Dead-code detection', state)
    if not vulture.get('files_scanned'):
        return (
            html.Div("Dead-code detection measured — no files scanned this cycle",
                     style={'color': '#6b7280', 'fontSize': '9pt', 'fontStyle': 'italic'}),
            "measured — empty",
            {'fontSize': '10pt', 'color': '#6b7280', 'marginLeft': '20px'}
        )

    categories = vulture.get('items_by_category', {})

    # Filter out unused_import (ruff/mypy) and unused_attribute (dataclass/constructor false positives)
    _VULTURE_SUPPRESS = {'unused_import', 'unused_attribute'}
    actionable_items = [
        item for item in vulture.get('items', [])
        if item.get('category') not in _VULTURE_SUPPRESS
    ]
    actionable_count = len(actionable_items)

    # Summary badge
    if actionable_count > 0:
        summary_el = html.Span(
            f"{actionable_count} dead code items",
            style={'color': '#f59e0b'}
        )
    else:
        summary_el = html.Span("Clean", style={'color': '#22c55e'})

    summary_style = {'fontSize': '10pt', 'marginLeft': '20px', 'fontWeight': 'bold'}

    children = []

    # Category breakdown
    if categories:
        cat_parts = []
        for cat, count in sorted(categories.items()):
            if cat == 'unused_import':
                continue
            label = cat.replace('_', ' ')
            cat_parts.append(f"{label}: {count}")
        if cat_parts:
            children.append(html.Div(
                " | ".join(cat_parts),
                style={'color': '#9ca3af', 'fontSize': '9pt', 'marginBottom': '6px'}
            ))

    # Group items by file
    file_groups = {}
    for item in actionable_items:
        file_groups.setdefault(item['file'], []).append(item)

    for filepath in sorted(file_groups.keys()):
        items = sorted(file_groups[filepath], key=lambda x: x['line'])
        children.append(html.Div(
            f"  {filepath}:",
            style={'color': '#818cf8', 'fontSize': '9pt', 'fontFamily': 'monospace',
                   'marginTop': '6px', 'fontWeight': 'bold'}
        ))
        for item in items:
            conf = item.get('confidence', 0)
            color = '#ef4444' if conf >= 90 else '#f59e0b' if conf >= 80 else '#6b7280'
            label = item.get('category', '').replace('_', ' ')
            children.append(html.Div(
                f"    L{item['line']}: {label} '{item['name']}' ({conf}%)",
                style={'color': color, 'fontSize': '8pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))

    # Suppressed categories note
    suppressed_parts = []
    import_count = categories.get('unused_import', 0)
    attr_count = categories.get('unused_attribute', 0)
    if import_count > 0:
        suppressed_parts.append(f"{import_count} unused imports")
    if attr_count > 0:
        suppressed_parts.append(f"{attr_count} unused attributes")
    if suppressed_parts:
        children.append(html.Div(
            f"({', '.join(suppressed_parts)} suppressed — false positives)",
            style={'color': '#4b5563', 'fontSize': '8pt', 'fontStyle': 'italic',
                   'marginTop': '8px'}
        ))

    return children, summary_el, summary_style


@app.callback(
    Output('contracts-results', 'children'),
    Output('contracts-summary', 'children'),
    Output('contracts-summary', 'style'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_contracts_panel(n_intervals, active_state_file):
    """Display contract violation status and decorated function list."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    _wt = _not_this_target(state)
    if _wt:
        return _wt
    contracts = state.get('contract_violations', {})
    decorators = state.get('contract_decorators', [])

    # Skip re-render if contracts data unchanged

    if not state or not contracts:   # B4 / Q-H2-1: no state, or nothing published — never "No @contract decorators found"
        return _tracker_not_published('Contract violations', state)
    if contracts.get('disabled', False):
        return (
            html.Div("Contract violations not run — nothing measured.",
                     style={'color': '#6b7280', 'fontSize': '9pt', 'fontStyle': 'italic'}),
            "not run",
            {'fontSize': '10pt', 'color': '#6b7280', 'marginLeft': '20px'}
        )

    total = contracts.get('total', 0)
    violations = contracts.get('violations', [])
    dec_count = len(decorators)

    # Build summary text
    if total > 0:
        summary_color = '#ef4444'
        summary_text = f"{dec_count} contracted | ERRORS: {total} violation(s)"
    elif dec_count > 0:
        summary_color = '#22c55e'
        summary_text = f"{dec_count} contracted | Clean"
    else:
        summary_color = '#6b7280'
        summary_text = "No @contract decorators found"

    summary_style = {'fontSize': '10pt', 'color': summary_color,
                     'marginLeft': '20px', 'fontWeight': 'bold'}

    children = []

    # Show violations first (if any)
    if violations:
        for v in violations:
            vtype = v.get('type', 'violation')
            children.append(html.Div(
                f"  x {v.get('function', '?')}: {vtype} - {v.get('condition', '')}",
                style={'color': '#ef4444', 'fontSize': '9pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))

    # Show decorated functions list
    if decorators:
        children.append(html.Div(
            f"Decorated functions ({dec_count}):",
            style={'color': '#9ca3af', 'fontSize': '9pt', 'marginTop': '6px', 'fontWeight': 'bold'}
        ))
        dec_items = []
        for cd in decorators:
            parts = []
            if cd.get('has_pre'):
                parts.append('pre')
            if cd.get('has_post'):
                parts.append('post')
            label = f"  @contract {cd.get('file', '?')}:{cd.get('lineno', '?')} {cd.get('function', '?')}()"
            if parts:
                label += f" [{', '.join(parts)}]"
            dec_items.append(html.Div(
                label,
                style={'color': '#3b82f6', 'fontSize': '8pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))
        children.append(html.Div(
            dec_items,
            style={
                'maxHeight': '120px',
                'overflowY': 'auto',
                'backgroundColor': '#111',
                'padding': '8px',
                'borderRadius': '4px',
                'marginTop': '4px',
            }
        ))

    return children, summary_text, summary_style


# ═══════════════════════════════════════════════════════════════════════════════
# ASYNC/SYNC I/O TRACKER PANEL
# ═══════════════════════════════════════════════════════════════════════════════

@app.callback(
    Output('io-tracker-results', 'children'),
    Output('io-tracker-summary', 'children'),
    Output('io-tracker-summary', 'style'),
    Output('io-panel-sig', 'data'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
    State('io-panel-sig', 'data'),
)
def update_io_tracker_panel_guarded(n_intervals, active_state_file, last_sig):
    # owner 2026-09-28 ("the entire computer slows down" on zoom): the io tile lists every function — on arrow
    # ~2,700 elements, ~380 KB — and was rebuilt every circuit tick, a ~5 s main-thread stall each time. Like
    # DASH_R's panels it is re-sent only when its content changed.
    out = update_io_tracker_panel(n_intervals, active_state_file)
    same, sig = _unchanged(out, last_sig)
    return (no_update, no_update, no_update, no_update) if same else (*out, sig)


def update_io_tracker_panel(n_intervals, active_state_file):
    """Display I/O function tracker: ALL functions listed, sync first then async."""
    sf = active_state_file if active_state_file else None
    state = read_circuit_state(sf)
    _wt = _not_this_target(state)
    if _wt:
        return _wt
    io_data = state.get('io_tracker_results', {})

    # Skip re-render if I/O data unchanged (but always render first few cycles)

    totals = io_data.get('totals', {})

    # Item 7 (2026-09-10): the tile keys on the tracker's published `status`, never "Pending" —
    # "not run — nothing measured" is a fact of the launch (--trackers), not a wait.
    # R9: "NOT MEASURED — <reason>" is shown as published; the --trackers suffix is only for "not run".
    _iou = _tracker_unmeasured('I/O tracker', io_data)
    if _iou:
        return (
            html.Div(_iou[0],
                     style={'color': _unmeasured_colour(_iou[1]), 'fontSize': '9pt', 'fontStyle': 'italic'}),
            _iou[1],
            {'fontSize': '10pt', 'color': _unmeasured_colour(_iou[1]), 'marginLeft': '20px'},
        )
    if not state or io_data.get('status') != 'measured':   # B4 / Q-H2-1: no state, or no published measurement
        return _tracker_not_published('I/O tracker', state)
    if not totals:
        return (
            html.Div("I/O tracker measured — no functions seen yet this cycle",
                     style={'color': '#6b7280', 'fontSize': '9pt', 'fontStyle': 'italic'}),
            "measured — empty",
            {'fontSize': '10pt', 'color': '#6b7280', 'marginLeft': '20px'},
        )

    total_functions = totals.get('total_functions', 0)
    async_count = totals.get('async_count', 0)
    sync_count = totals.get('sync_count', 0)
    files_data = io_data.get('files', {})

    # Collect all functions across all files, with I/O type info
    async_io_fns = []      # (file, name, lineno, io_types) — has I/O
    async_plain_fns = []   # (file, name, lineno) — no I/O
    sync_needs_review = []  # (file, name, lineno, io_types) — NOT exempt
    sync_exempt_fns = []    # (file, name, lineno, io_types, reason) — sync by design

    for path, info in sorted(files_data.items()):
        for fn in info.get('async_functions', []):
            io_types = fn.get('io_types', [])
            if io_types:
                async_io_fns.append((path, fn.get('name', '?'), fn.get('lineno', 0), io_types))
            else:
                async_plain_fns.append((path, fn.get('name', '?'), fn.get('lineno', 0)))
        for fn in info.get('sync_functions', []):
            io_types = fn.get('io_types', [])
            is_exempt = fn.get('sync_exempt', False)
            exempt_reason = fn.get('exempt_reason', '')
            if is_exempt:
                sync_exempt_fns.append((path, fn.get('name', '?'), fn.get('lineno', 0),
                                        io_types, exempt_reason))
            else:
                sync_needs_review.append((path, fn.get('name', '?'), fn.get('lineno', 0), io_types))

    # Summary pill: "69 functions — 38 async, 0 sync (31 exempt)"
    sync_review_count = len(sync_needs_review)
    sync_exempt_count = len(sync_exempt_fns)
    summary_children = [
        html.Span(f"{total_functions} functions — "),
        html.Span(f"{async_count} async", style={'color': '#22c55e'}),
        html.Span(", "),
    ]
    if sync_review_count > 0:
        summary_children.append(
            html.Span(f"{sync_review_count} sync", style={'color': '#ef4444'}))
    else:
        summary_children.append(
            html.Span("0 sync", style={'color': '#22c55e'}))
    if sync_exempt_count > 0:
        summary_children.append(
            html.Span(f" ({sync_exempt_count} exempt)",
                      style={'color': '#6b7280', 'fontSize': '9pt'}))
    summary_style = {'fontSize': '10pt', 'marginLeft': '20px', 'color': '#9ca3af'}

    items = []

    # ── Sync needing review (red) — only non-exempt sync functions ──
    if sync_needs_review:
        items.append(html.Div(
            f"sync — needs review ({len(sync_needs_review)}):",
            style={'color': '#ef4444', 'fontSize': '9pt', 'fontWeight': 'bold',
                   'marginBottom': '2px'}
        ))
        for path, name, lineno, io_types in sync_needs_review:
            if io_types:
                tag_str = ', '.join(io_types[:3])
                if len(io_types) > 3:
                    tag_str += f' +{len(io_types) - 3}'
                items.append(html.Div([
                    html.Span(f"  {path}:{lineno}  {name}  ",
                               style={'color': '#ef4444'}),
                    html.Span(f"[{tag_str}]",
                               style={'color': '#f59e0b', 'fontSize': '7pt'}),
                ], style={'fontSize': '8pt', 'fontFamily': 'monospace', 'marginLeft': '10px'}))
            else:
                items.append(html.Div(
                    f"  {path}:{lineno}  {name}",
                    style={'color': '#7a4a4a', 'fontSize': '8pt', 'fontFamily': 'monospace',
                           'marginLeft': '10px'}
                ))

    # ── Sync by design (grey, collapsed summary) ──
    # owner 2026-10-07 06:45: I/O shows problems; the by-design list is folded shut, each row `file.py:line name`
    if sync_exempt_fns:
        items.append(html.Details([
            html.Summary(f"sync — by design ({len(sync_exempt_fns)} exempt, not problems)",
                         style={'color': '#6b7280', 'fontSize': '9pt', 'cursor': 'pointer'}),
            *[html.Div([
                html.Span(f"{path.rsplit('/', 1)[-1]}:{lineno}  {name}  ", title=f"{path}:{lineno}",
                          style={'color': '#6b7280'}),
                html.Span(f"[{reason}]", style={'color': '#555', 'fontSize': '7pt'}),
            ], style={'fontSize': '8pt', 'fontFamily': 'monospace', 'marginLeft': '10px'})
              for path, name, lineno, io_types, reason in sync_exempt_fns],
        ], style={'marginTop': '4px' if sync_needs_review else '0px'}))
    if not sync_needs_review:
        items.insert(0, html.Div("no blocking I/O to review", style={'color': '#22c55e', 'fontSize': '9pt',
                                                                     'marginBottom': '4px'}))

    # ── Async section second (green) ──
    if async_io_fns or async_plain_fns:
        items.append(html.Div(
            f"async ({len(async_io_fns) + len(async_plain_fns)}):",
            style={'color': '#22c55e', 'fontSize': '9pt', 'fontWeight': 'bold',
                   'marginTop': '6px' if (sync_needs_review or sync_exempt_fns) else '0px',
                   'marginBottom': '2px'}
        ))
        # I/O-tagged async — bright green with tags
        for path, name, lineno, io_types in async_io_fns:
            tag_str = ', '.join(io_types[:3])
            if len(io_types) > 3:
                tag_str += f' +{len(io_types) - 3}'
            items.append(html.Div([
                html.Span(f"  {path}:{lineno}  {name}  ",
                           style={'color': '#22c55e'}),
                html.Span(f"[{tag_str}]",
                           style={'color': '#f59e0b', 'fontSize': '7pt'}),
            ], style={'fontSize': '8pt', 'fontFamily': 'monospace', 'marginLeft': '10px'}))
        # Non-I/O async — dimmed green
        for path, name, lineno in async_plain_fns:
            items.append(html.Div(
                f"  {path}:{lineno}  {name}",
                style={'color': '#4a7a5a', 'fontSize': '8pt', 'fontFamily': 'monospace',
                       'marginLeft': '10px'}
            ))

    children = []
    if items:
        children.append(html.Div(
            items,
            style={
                'maxHeight': '200px',
                'overflowY': 'auto',
                'backgroundColor': '#111',
                'padding': '8px',
                'borderRadius': '4px',
                'marginTop': '4px',
            }
        ))

    return children, summary_children, summary_style


@app.callback(
    Output('alerts-text', 'children'),
    Input('circuit-interval', 'n_intervals'),
    prevent_initial_call=False
)
def check_alerts(n_intervals):
    """Every warning of the circuit, as TEXT lines in the band above the graph (FIX_40, owner 2026-09-15) —
    nothing pops up over the graph, nothing sits at the page bottom. Reads circuit_state.json (SINGLE SOURCE
    OF TRUTH); [] when there is nothing to say (verified is the default). ALL warnings list, one line each."""
    lines = []
    # FIX_52 / S4: the gearbox's run feed (system_scripts/gearbox_events.json — its own file, because
    # circuit_state.json is rewritten whole every scan). Since S4 nothing restarts; the feed's one line
    # is the stop line of a daemon failure, read first so it is the band's top line. The red panel above
    # carries the detail. Absent file = no failure this run.
    lines.extend(_restart_lines())
    state = read_circuit_state()
    if not state:
        return lines
    if state.get(_WRONG_TARGET):
        return lines + [state[_WRONG_TARGET]]
    # ITEM 11 (2026-09-15): the severed alert raises on the daemon's severed set (the pair named), never on the
    # static all_connected (a never-wired node is stopped at launch by FIX_36's WIRING gate).
    severed = state.get('severed_links') or []
    if severed:
        _pairs = ', '.join(f"{a} → {b}" for a, b in severed[:3]) + (' …' if len(severed) > 3 else '')
        lines.append(html.Div(f"⚠ severed link{'s' if len(severed) > 1 else ''} — {_pairs}",
                              style={'color': '#ef4444'}))
    # owner 2026-09-28: the cycles line is gone from the band — it repeated what the counterfeit column lists
    return lines


def _run_feed() -> dict:
    """The gearbox's run feed (gearbox_events.json); {} when absent or unreadable."""
    try:
        doc = json.loads((Path(__file__).resolve().parent / 'gearbox_events.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _restart_lines():
    """The run feed's stop line — since S4 (no restarts) the one line a daemon failure stops the run with."""
    stopped = _run_feed().get('stopped')
    return [html.Div(f"⚠ {stopped}", style={'color': '#ef4444'})] if stopped else []


@app.callback(
    Output('daemon-failure-panel', 'children'),
    Output('daemon-failure-panel', 'style'),
    Input('failure-interval', 'n_intervals'),
)
def update_daemon_failure_panel(_n):
    """S4 (owner 2026-09-29): the red panel for a daemon that died or hung — which daemon, why, the last
    lines of its log, and that the run's results are not trustworthy. Empty and hidden otherwise."""
    failure = _run_feed().get('failure')
    if not isinstance(failure, dict):
        return [], {'display': 'none'}
    mono = {'fontFamily': 'monospace', 'fontSize': '9pt'}
    tail = failure.get('log_tail') or ['(no log lines)']
    children = [
        html.Div(f"\u2716 CodeRadar process {failure.get('daemon', '?')} {failure.get('reason', 'failed')} — the run stopped",
                 style={**mono, 'fontSize': '11pt', 'fontWeight': 'bold'}),
        html.Div("Nothing was restarted: a CodeRadar process that crashed or hung cannot be trusted, so this run's "
                 "results are NOT trustworthy (the tester report and verdict say so). Press Ctrl-C in the "
                 "terminal to close CodeRadar.", style={**mono, 'margin': '4px 0'}),
        html.Div(f"last lines of {failure.get('log') or 'its log'}:", style={**mono, 'color': '#fca5a5'}),
        html.Pre('\n'.join(tail), style={**mono, 'fontSize': '8pt', 'color': '#fecaca', 'margin': 0,
                                          'maxHeight': '14em', 'overflowY': 'auto', 'whiteSpace': 'pre-wrap',
                                          'backgroundColor': 'rgba(0,0,0,0.35)', 'padding': '6px'}),
    ]
    style = {'backgroundColor': '#450a0a', 'color': '#fee2e2', 'border': '2px solid #ef4444',
             'borderRadius': '6px', 'padding': '10px 14px', 'margin': '6px 0'}
    return children, style

# owner 2026-10-07 06:20: a tracker not chosen at launch has no panel (CRC / dead code); contract violations can
# never be chosen, so its panel never shows
@app.callback(
    Output('crc-card', 'style'),
    Output('vulture-card', 'style'),
    Output('contracts-card', 'style'),
    Input('slow-interval', 'n_intervals'),
)
def hide_unchosen_trackers(_n):
    try:
        chosen = set((_TickRead(TARGET_REPO).state.get('launch_control') or {}).get('trackers') or [])
    except Exception:
        chosen = set()
    show, hide = {}, {'display': 'none'}
    return (show if 'crc' in chosen else hide), (show if 'vulture' in chosen else hide), hide

@app.callback(
    Output('pytest-results', 'children'),
    Output('pytest-summary', 'children'),
    Output('pytest-summary', 'style'),
    Input('circuit-interval', 'n_intervals'),
    State('active-state-file', 'data'),
)
def update_pytest_panel(n_intervals, active_state_file):
    """owner 2026-10-07: the pytest tile — NOT MEASURED (amber) until a pytest run; then the headline and one row
    per failed / error test: `file.py:line  test name — reason` (the full path on hover)."""
    sf = active_state_file if active_state_file else None
    try:
        mirror = read_file_locked((Path(sf).parent if sf else SCRIPT_DIR) / '.monitor_state.json')
        block = (mirror.get('monitor') or {}).get('pytest') or {}
    except Exception:
        block = {}
    if not block.get('ran'):
        why = block.get('reason') or 'no scan results saved yet (no dash mirror yet)'
        return (html.Div(f"pytest NOT MEASURED — {why}",
                         style={'color': '#f59e0b', 'fontSize': '9pt', 'fontStyle': 'italic'}),
                "NOT MEASURED", {'fontSize': '10pt', 'color': '#f59e0b', 'marginLeft': '20px'})
    c = block.get('counts') or {}
    bad = (c.get('failed', 0) or 0) + (c.get('error', 0) or 0)
    headline = f"{c.get('passed', 0)} passed · {c.get('failed', 0)} failed · {c.get('error', 0)} errors"
    extra = [f"{v} {k}" for k, v in sorted(c.items()) if k not in ('passed', 'failed', 'error') and v]
    children = [html.Div(
        f"last run {block.get('finished_at')} · {block.get('collected')} collected · "
        f"{block.get('duration_s')}s · exit {block.get('exit_status')}" + (f" · {', '.join(extra)}" if extra else ""),
        style={'color': '#9ca3af', 'fontSize': '9pt', 'marginBottom': '6px'})]
    for r in block.get('rows') or []:
        where = f"{str(r.get('file') or '?').rsplit('/', 1)[-1]}:{r.get('line')}"
        name = str(r.get('test') or '').rsplit('::', 1)[-1]
        children.append(html.Div([
            html.Span(r.get('outcome', '').upper(), style={'color': '#ef4444', 'fontWeight': 'bold',
                                                         'marginRight': '8px'}),
            html.Span(where, title=f"{r.get('file')}:{r.get('line')}", style={'color': '#9ca3af', 'marginRight': '8px'}),
            html.Span(name, style={'color': '#e6edf3', 'marginRight': '8px'}),
            html.Span(f"— {r.get('reason') or ''}", style={'color': '#fca5a5'}),
        ], style={'fontSize': '9pt', 'fontFamily': 'monospace', 'overflowWrap': 'anywhere', 'marginBottom': '3px'}))
    if not bad:
        children.append(html.Div("every collected test passed", style={'color': '#22c55e', 'fontSize': '9pt'}))
    return (children, headline, {'fontSize': '10pt', 'color': '#ef4444' if bad else '#22c55e',
                                 'marginLeft': '20px', 'fontWeight': 'bold'})

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Execution Proof Dashboard')
    parser.add_argument('target_dir', nargs='?', default=None,
                        help='Directory to monitor (overrides config/env)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port to bind to (default: 8080)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('--setup-tab', action='store_true',
                        help='C2 / Q-H1-10: a setup page is waiting on this tab (the gearbox passes its own '
                             '--setup-tab on) — the failed overlay offers "back to setup" only then')
    args = parser.parse_args()
    SETUP_TAB_WAITING = args.setup_tab

    # Step 1: Set target directory
    if args.target_dir:
        target_path = Path(args.target_dir).resolve()
        if not target_path.exists():
            print(f"Error: Target directory does not exist: {target_path}")
            sys.exit(1)
        set_target_repo_in_config(target_path)
        TARGET_REPO = target_path
        print(f"Target directory set to: {target_path}")

    print(f"Daemon log directory: {DAEMON_LOG_DIR}")
    print(f"Daemon log: {DAEMON_LOG}")
    print(f"Target repo: {TARGET_REPO}" if TARGET_REPO is not None else _target_not_measured())

    # Check daemon health on startup
    healthy, status = check_daemon_health()
    if healthy:
        print(f"Daemon status: {status}")
    else:
        print(f"WARNING: {status}")
        print("  Start the daemon with: python system_scripts/circuit_daemon.py")

    print(f"\nStarting dashboard at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop the server")

    # Log all registered callbacks for debugging
    _log_registered_callbacks()

    try:
        app.run(debug=args.debug, host=args.host, port=args.port)
    except KeyboardInterrupt:
        print("\nShutdown requested. Exiting...")
        sys.exit(0)
