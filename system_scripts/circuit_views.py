#!/usr/bin/env python3
"""
circuit_views.py — Stateless circuit graph views.

No global state. Each call builds a local graph and returns a figure.
DEBUG logging to terminal for pipeline visibility.
"""

import hashlib
import logging
import math
import re
import os
import json
import subprocess
from pathlib import Path

from typing import Dict, List, Tuple

import networkx as nx
import plotly.graph_objects as go


# ─── owner 2026-09-29: imports that cannot resolve — "broken when called" ────────────────────────
# A module is MISSING when its top-level name is none of: the stdlib, a top-level module/package of
# the target (or the target's own folder name — a root package imports itself by it), or a package
# installed in the target's private env. At module level it breaks the file on load (red); inside a
# function it breaks only when that function is called (red-orange). The line goes to a marker node
# named after the missing module, so an agent can read which file, which import and where it sits.
MISSING_MARK = '\u2715 '                  # marker node prefix: "✕ plugins.ghost_sink"
BROKEN_WHEN_CALLED = '#f97316'             # red-orange


logger = logging.getLogger("circuit_views")

ELECTRIC_BLUE = '#00bfff'


def _build_flow_edge_set(dataflows):
    """Build set of (src, dst) pairs with active dataflows."""
    return {(df["src"], df["dst"]) for df in dataflows}


def _add_flow_arrows(fig, dataflows, positions, animation_tick=0, marker_size=9, color=None):
    """Draw directional arrow markers moving along dataflow edges (Item 10: `color` overrides the
    live-connection blue — amber for a runner's flows)."""
    if not dataflows:
        return
    phase_offset = (animation_tick % 100) / 100.0
    ax, ay, angles = [], [], []
    _N = 4
    for df in dataflows:
        src, dst = df["src"], df["dst"]
        if src not in positions or dst not in positions:
            continue
        sx, sy = positions[src]
        dx, dy = positions[dst]
        edge_angle = math.degrees(math.atan2(dy - sy, dx - sx))
        for i in range(_N):
            phase = (i / _N + phase_offset) % 1.0
            ax.append(sx + (dx - sx) * phase)
            ay.append(sy + (dy - sy) * phase)
            angles.append(edge_angle)
    if ax:
        fig.add_trace(go.Scatter(
            x=ax, y=ay, mode="markers",
            marker=dict(size=marker_size, color=(color or ELECTRIC_BLUE),
                        # Plotly marker.angle is CLOCKWISE; the edge angle is
                        # counter-clockwise (atan2) — negate so the triangle
                        # points from src to dst (plan item 10, 2026-09-05).
                        symbol="triangle-right", angle=[-a for a in angles],
                        opacity=0.9, line=dict(width=0.5, color="white")),
            hoverinfo="skip", showlegend=False,
        ))
# Owner rulings 2026-09-05 — colours are STATES, never a per-directory rainbow:
#   directories: exactly two colours — scanned (holds live source) vs
#                whitelisted (artifacts + detritus; still drawn, not scanned)
#   script nodes: indigo (static import connection) / green (live connection
#                seen) / red (live connection went out)
NODE_INDIGO = '#6366f1'
TESTS_TEAL = '#14b8a6'             # I-198: "live via tests" edge — a library's tests' proof, never green;
                                   # not amber, which already means a runner's WARNING (Item 10)
SCANNED_DIR_COLOR = '#38bdf8'      # sky blue  — scanned directory
LEGEND_MARGIN_PX = 24              # FIX_40 / I-51: room for one 10-px legend line + its 4-px shift, top and bottom
WHITELISTED_DIR_COLOR = '#6b7280'  # grey      — whitelisted, visible, not scanned

BLUE_SHADES = [
    '#6366f1',  # 1  indigo               — the base
    '#22d3ee',  # 2  cyan                 — cool, unmistakable
    '#a78bfa',  # 3  soft violet          — warm purple
    '#38bdf8',  # 4  sky blue             — bright, airy
    '#f472b6',  # 5  pink                 — totally distinct
    '#2dd4bf',  # 6  teal                 — green-leaning
    '#c084fc',  # 7  orchid               — rich purple
    '#60a5fa',  # 8  cornflower           — classic blue
    '#fb923c',  # 9  tangerine            — warm pop
    '#34d399',  # 10 emerald              — green accent
]
DARK_PINK = '#e91e63'
PINK_SHADES = ['#f06292', '#ec407a', '#e91e63', '#d81b60', '#c2185b', '#ad1457', '#ff80ab', '#ff4081', '#f48fb1', '#ce93d8']
NON_PY_EXTS = {'.toml', '.json', '.yaml', '.yml', '.cfg', '.ini',
               '.txt', '.md', '.log', '.lock', '.sh'}


# =============================================================================
# State parsing — pure function, no I/O. R2 (2026-09-30): the graph reads the circuit daemon's published
# state only; the target-reading parser and import resolver (parse_circuit_from_watchlist, missing_imports
# and their readers) are removed — backup: circuit_views.py.pre_R2.
# =============================================================================

def circuit_state_unmeasured(state) -> str:
    """R2 (2026-09-30): why the circuit daemon's published state cannot draw the graph — '' when it can."""
    if isinstance(state, dict) and '_wrong_target' in state:   # read_circuit_state's other-target line, as is
        return str(state['_wrong_target'])
    has_state = isinstance(state, dict) and bool(state)
    has_graph = has_state and isinstance(state.get('nodes'), list) and isinstance(state.get('edges'), list)
    return ('' if has_graph else 'the import map has not been drawn yet (circuit state absent or unreadable)' if not has_state else
            'the import map has no files in it yet (circuit state has no nodes/edges; phase: %s)' % (state.get('daemon_phase') or 'unknown'))


FOLDER = '\U0001f4c1'   # the one-character mark a folder node's name starts with ('\U0001f4c1a/b')


def fold_name(name: str, view: str = '') -> str:
    """M-65 (owner 2026-10-07, "4 different staircases to different destinations"): the name a daemon node
    ('a/b/c', no suffix) is DRAWN with in the view at folder path *view* ('' = the root).
    In the view: a file directly in *view* is 'a/b/c.py' (a root file: its stem). Deeper than the view: folded
    into the first folder under *view* on its path ('\U0001f4c1a/b/sub'). Off the view's path: folded to the
    branch point — the first folder off the view's path ('\U0001f4c1a/other') — or, for a file sitting in an
    ancestor folder, the file itself ('a/main.py' / 'main'). A folder node's name is its PATH, so a click on
    it drills to that path (not to a top folder)."""
    parts = name.split('/')
    dirs, pp = parts[:-1], [p for p in (view or '').split('/') if p]
    c = 0
    while c < len(dirs) and c < len(pp) and dirs[c] == pp[c]:
        c += 1
    if len(dirs) > c:                       # deeper than the view (c == len(pp)) or off its path (c < len(pp))
        return FOLDER + '/'.join(dirs[:c + 1])
    return name if len(parts) == 1 else name + '.py'


def in_view(drawn: str, node_subdirs: dict, view: str = '') -> bool:
    """A drawn node is a MEMBER of the view at *view*: a folder directly under it, or a file directly in it.
    Everything else the fold produced is out of view — drawn only as a box when a member links to it."""
    if drawn.startswith(FOLDER):
        path = drawn[len(FOLDER):]
        return (path.rsplit('/', 1)[0] if '/' in path else '') == (view or '')
    return str(node_subdirs.get(drawn) or '') == (view or '')


def settle_view(state, view: str = '') -> str:
    """M-65 rule 3: a level holding exactly one folder and no file is a pass-through — the first view and
    every drill step through it, it is never a stop. Returns the first view at or under *view* that is one."""
    for _ in range(64):   # a path can only be so deep; never an unbounded walk
        nodes, _i, _c, _t, _s, subs = circuit_from_state(state, view=view)
        members = [n for n in nodes if in_view(n, subs, view)]
        if len(members) == 1 and members[0].startswith(FOLDER):
            view = members[0][len(FOLDER):]
            continue
        return view or ''
    return view or ''


def drawn_for(name: str, drawn_names) -> str:
    """The drawn node that stands for daemon node *name* ('a/b/c' or 'a/b/c.py') among *drawn_names*: the
    node itself, its '.py' form, or the folder node whose path is the longest prefix of it; *name* when none."""
    nm = name[:-3] if name.endswith('.py') else name
    for cand in (nm, nm + '.py', name):
        if cand in drawn_names:
            return cand
    best = ''
    for d in drawn_names:
        if d.startswith(FOLDER):
            path = d[len(FOLDER):]
            if nm.startswith(path + '/') and len(path) > len(best):
                best = path
    return FOLDER + best if best else name


def circuit_from_state(state, view: str = ''):
    """R2 (2026-09-30, owner: one scan scans everything): the graph's nodes, links and node colours come ONLY
    from the circuit daemon's published state — never from a read of the target. Same 6-tuple as the old
    reader: (nodes {drawn: connected}, imports {drawn: [drawn]}, cycles, tags, subdirs, node_subdirs).
    M-65: *view* is the folder PATH looked at ('' = the root); every daemon node is drawn under `fold_name`
    — a folded folder is connected only when every member is, its edges aggregated from the members' edges
    (import and file-level alike); `node_subdirs` maps a file to its folder path and a folder node to its own
    path (a root file has no entry)."""
    drawn: Dict[str, str] = {}
    nodes: Dict[str, object] = {}
    node_subdirs: Dict[str, str] = {}
    for n in state.get('nodes') or []:
        name = str(n.get('name'))       # the daemon names every node; a nameless one is drawn as 'None', not hidden
        d = fold_name(name, view)
        drawn[name] = d
        if d.startswith(FOLDER):
            node_subdirs[d] = d[len(FOLDER):]
        elif '/' in name:
            node_subdirs[d] = name.rsplit('/', 1)[0]
        c = n.get('connected')
        prev = nodes.get(d, True)
        nodes[d] = None if (prev is None or c is None) else (bool(prev) and bool(c))
    imports: Dict[str, list] = {}
    for e in state.get('edges') or []:
        src, dst = e                    # a malformed edge raises -> the frame shows CIRCUIT FRAME ERROR, not a gap
        s, t = drawn.get(str(src)), drawn.get(str(dst))
        if s and t and s != t and t not in imports.get(s, []):
            imports.setdefault(s, []).append(t)
    logger.debug("circuit state: %d nodes, %d edges drawn from %d daemon nodes / %d daemon edges in view %r",
                 len(nodes), sum(len(v) for v in imports.values()), len(drawn), len(state.get('edges') or []),
                 view)
    return nodes, imports, list(state.get('cycles') or []), {}, {}, node_subdirs


_MISSING_LOCAL_RE = re.compile(r'Missing local modules: (.+)$')


def missing_from_state(state) -> list:
    """R2: the missing-module markers from the daemon's own `import_error` ('Missing local modules: a, b')."""
    out: list[dict] = []
    for n in state.get('nodes') or []:
        m = _MISSING_LOCAL_RE.match(str(n.get('import_error') or ''))   # ast_scanner.py: the daemon's own words
        out.extend({'file': str(n.get('name')) + '.py', 'module': mod.strip(), 'line': None, 'lazy': False}
                   for mod in (m.group(1).split(',') if m else []))
    return out


# =============================================================================
# Figure generation — builds local graph, returns figure. No global state.
# =============================================================================

# S5b / P4: the out-of-view box layout's scale — gaps (data units), one label line (px), one label character at
# 11 px (px), the least gap between two labels (px). P4 (B2): the nominal plot AREA (px, width x height) — the
# plot at a 1440-px window (the graph's 80vh box less its margins); the dash sends the plot area it really drew
# (`graph-size`) and that replaces it — this is only the first frame's size, before the page has measured one.
_BOX_GAP, _BOX_PAD, _PLOT_PX, _LINE_PX, _CHAR_PX, _LABEL_GAP_PX = 0.12, 0.12, (1347, 740), 16, 7, 8
# the three change-tag badges under a file node (data units, as they were drawn) and the 18-px badge's half
_BADGE_TOP, _BADGE_STEP, _BADGE_HALF_PX = 0.18, 0.12, 9
_FOLDER_PX = 28   # a folder box; a script circle is 30 px (owner 2026-10-06: the 45-px box was "way too dissimilar")
_BADGE_FOOT = _BADGE_TOP + 2 * _BADGE_STEP     # the lowest badge's centre, under its node


_LABEL_LINE_CHARS = 18   # owner 2026-10-07 01:30 ("wrap at underscores"): the longest line a label keeps


def _wrap_label(text: str) -> List[str]:
    """owner 2026-10-07 01:30 (label placement rule, M-58): a label that does not fit under its node breaks
    into lines at its underscores — the `_` stays at the end of the line it closes — so the whole name is
    always on screen and never leaves the field. Greedy: a token joins the line while the line stays within
    _LABEL_LINE_CHARS; a token longer than that is a line of its own. ''.join(lines) == text."""
    tokens = [t + '_' for t in text.split('_')]
    tokens[-1] = tokens[-1][:-1]
    lines: List[str] = []
    cur = ''
    for t in tokens:
        room = _LABEL_LINE_CHARS - len(cur)       # characters this line can still take
        if cur and len(t) not in range(room + 1):
            lines.append(cur)
            cur = ''
        cur += t
    if cur:
        lines.append(cur)
    return lines


def _flip_crowded_labels(notes, boxes, pos, texts, r, plot) -> bool:
    """Owner 2026-10-06 (an 8-node view's top labels ran into each other): walking the labels in order, one
    whose box meets a box already kept is moved to ABOVE its node (anchored on the node's top edge). `notes`
    and `boxes` are updated in place, in the same order; True when anything moved."""
    ux, uy = 2 * r / plot[0], 2 * r / plot[1]
    kept: List[Tuple[float, float, float, float]] = []
    moved = False
    for i, (note, (x, y_top, w, h)) in enumerate(zip(notes, boxes)):
        rect = (x - w / 2 * ux, y_top - h * uy, x + w / 2 * ux, y_top)
        if any(rect[0] < k[2] and k[0] < rect[2] and rect[1] < k[3] and k[1] < rect[3] for k in kept):
            node = next(n for n in pos if pos[n][0] == note['x']
                        and texts.get(n, ('',))[0] == note['text'].replace('<br>', ''))
            r_px = texts[node][2]
            nx_, ny_ = pos[node]
            note.update(y=ny_, yanchor='bottom', yshift=r_px + 3)
            boxes[i] = (nx_, ny_ + (r_px + 3 + h) * uy, w, h)
            rect = (nx_ - w / 2 * ux, ny_ + (r_px + 3) * uy, nx_ + w / 2 * ux, ny_ + (r_px + 3 + h) * uy)
            moved = True
        kept.append(rect)
    return moved


def _plot_size(plot_px):
    """P4 (B2): the plot area (width, height px) the labels are sized for — the one the dash measured
    (`graph-size`: [w, h]), or the nominal one when it sent none or something that is not two positive
    numbers."""
    try:
        w, h = (float(v) for v in plot_px)
    except (TypeError, ValueError):
        return _PLOT_PX
    return (w, h) if min(w, h) > 0 else _PLOT_PX


def _label_margins(notes, boxes) -> Dict[str, int]:
    """Pixel room around the plot for the labels — only the OUTERMOST nodes' labels can reach past the
    drawing: half the label width of the leftmost / rightmost nodes, the hanging labels of the lowest nodes,
    the raised labels (or the 45-px folder box's half) of the highest. Pixels only — never data units."""
    if not notes:
        return {'l': 24, 'r': 24, 't': 24, 'b': 24}
    xs = [n['x'] for n in notes]
    ys = [n['y'] for n in notes]
    tol = 0.05 * max(max(xs) - min(xs), max(ys) - min(ys), 1e-9)
    # 2026-10-07: a label shifted inward (xshift) to stay in the field reaches that much less past its node
    left = [w / 2 - n.get('xshift', 0) for n, (_x, _y, w, _h) in zip(notes, boxes) if n['x'] <= min(xs) + tol]
    right = [w / 2 + n.get('xshift', 0) for n, (_x, _y, w, _h) in zip(notes, boxes) if n['x'] >= max(xs) - tol]
    low = [h for n, (_x, _y, _w, h) in zip(notes, boxes)
           if n.get('yanchor') == 'top' and n['y'] <= min(ys) + tol]
    high = [h for n, (_x, _y, _w, h) in zip(notes, boxes) if n.get('yanchor') == 'bottom']
    return {'l': int(max(left + [24])), 'r': int(max(right + [24])),
            't': int(max(high + [24])), 'b': int(max(low + [24]))}


def _ring_texts(nodes, view: str = ''):
    """P4 (B4): {node: (text, font px, marker radius px)} — the label each ring node is drawn with. A folder:
    its name + '/' at 11 px on a _FOLDER_PX square; any other node: at 12 px on a 30-px circle, a missing module's
    name without its mark, a file's the shortest tail of its path no other ring file ends with (its file name,
    unless two share one — the drill line names the view's folder; the node's hover keeps the full path)."""
    tails: Dict[str, int] = {}
    for n in nodes:
        if not n.startswith('\U0001f4c1') and not n.startswith(MISSING_MARK):
            parts = n.split('/')
            for k in range(1, len(parts) + 1):
                tail = '/'.join(parts[len(parts) - k:])
                tails[tail] = tails.get(tail, 0) + 1
    # item 3 (2026-10-07): a folder off the view's path (a sibling branch) is named by its own folder name,
    # not its whole path — lengthened upward only when two such boxes would read the same
    off_tails: Dict[str, int] = {}
    for n in nodes:
        if n.startswith('\U0001f4c1'):
            path = n[len(FOLDER):]
            if not (view and path.startswith(view + '/')):
                parts = path.split('/')
                for k in range(1, len(parts) + 1):
                    tail = '/'.join(parts[len(parts) - k:])
                    off_tails[tail] = off_tails.get(tail, 0) + 1
    out = {}
    for n in nodes:
        if n.startswith('\U0001f4c1'):
            path = n[len(FOLDER):]
            # M-65: a folder under the view is named from the view down ('sub/', 'sub/deeper/')
            if view and path.startswith(view + '/'):
                shown = path[len(view) + 1:]
            else:
                parts = path.split('/')
                k = 1
                while k < len(parts) and off_tails['/'.join(parts[len(parts) - k:])] > 1:
                    k += 1
                shown = '/'.join(parts[len(parts) - k:])
            out[n] = (shown + '/', 11, _FOLDER_PX / 2)
        elif n.startswith(MISSING_MARK):
            out[n] = (n.removeprefix(MISSING_MARK), 12, 15)
        else:
            parts = n.split('/')
            k = 1
            while k < len(parts) and tails['/'.join(parts[len(parts) - k:])] > 1:
                k += 1
            out[n] = ('/'.join(parts[len(parts) - k:]), 12, 15)
    return out


def _hits(a, b):
    """Two (x0, x1, y0, y1) boxes overlap."""
    return a[0] < b[1] and b[0] < a[1] and a[2] < b[3] and b[2] < a[3]


def _clear_of(rects, side, span, floor, gap):
    """S5b: how far from the centre a side's boxes must start so no rect whose span crosses theirs (the
    side's boxes run from span[0] to span[1] across it) reaches them — never nearer than floor."""
    out = [floor]
    for x0, x1, y0, y1 in rects:
        lo, hi, far = {'up': (x0, x1, y1), 'down': (x0, x1, -y0),
                       'right': (y0, y1, x1), 'left': (y0, y1, -x0)}[side]
        if lo < span[1] + gap and hi > span[0] - gap:
            out.append(far + gap)
    return max(out)


def _rows(feet, width, gap):
    """S5b: split one side's boxes — (index, along) in order — into lines no longer than width, greedily."""
    rows, cur, used = [], [], -gap
    for i, a in feet:
        if cur and used + gap + a > width:
            rows.append(cur)
            cur, used = [], -gap
        cur.append(i)
        used += gap + a
    if cur:
        rows.append(cur)
    return rows


def _view_key(selected_dirs, folders, depths):
    """S5b (owner 2026-09-29): the Plotly uirevision of one VIEW — the selected folders and the view's depth.
    A zoom holds across refresh ticks of the same view and resets on every drill-in and every Reverse1.
    The depth is read off the frame itself: the folders drawn collapsed and the depths the drawn nodes sit
    at — a depth change that alters either redraws the view; one that alters neither draws the same view.
    Derived from the current frame only; nothing is kept between frames."""
    view = (sorted(selected_dirs or []), sorted(folders), sorted(set(depths)))
    return 'circuit-zoom:' + hashlib.sha1(repr(view).encode()).hexdigest()


def _ring_positions(nodes):
    """All nodes evenly on one ring whose radius grows with the node count (owner 2026-09-29).
    Returns (pos, view_range)."""
    k = len(nodes)
    # a lone node has no ring: the radius factor min(1, k - 1) is 0 for it, so it sits at the centre
    radius = (0.9 + 0.09 * max(0, k - 4)) * min(1, max(0, k - 1))
    # owner 2026-10-06: turned half a side clockwise, so every shape stands on a flat edge — 4 is a square, not
    # a diamond, 3 a triangle on its base, 2 a level segment — and the bottom nodes' badges hang free
    start = -math.pi / 2 - (math.pi / k if k > 1 else 0)
    pos = {n: (radius * math.cos(start + 2 * math.pi * i / k),
               radius * math.sin(start + 2 * math.pi * i / k)) for i, n in enumerate(nodes)}
    return pos, max(1.2, radius + 0.7)


def outside_edges(outside_links, drawn) -> List[Tuple[str, str, str]]:
    """M-65 / item 9 (2026-10-07): the lines an out-of-view box draws, one (src, dst, box) per distinct
    pair — the box is the 📁 node of the folder the link leaves the view for. A link whose inside end is
    not drawn, or whose outside end is a root file (no folder), draws nothing. generate_figure draws
    exactly these; the frame counter counts exactly these."""
    out, seen = [], set()
    for lk in outside_links or []:
        inside, folder = lk.get('inside'), lk.get('folder') or ''
        if inside not in drawn or not folder:
            continue
        fnode = '\U0001f4c1' + folder
        src, dst = (inside, fnode) if lk.get('outward') else (fnode, inside)
        if (src, dst) not in seen:
            seen.add((src, dst))
            out.append((src, dst, fnode))
    return out


def generate_figure(circuit_nodes, import_map, node_subdirs,
                    change_tags=None, entry_point=None,
                    runtime_loaded=None, dataflows=None,
                    animation_tick=0, selected_dirs=None,
                    watched_names=None,
                    highlight_node=None,
                    severed_edges=None,
                    scanned_dirs=None,
                    runtime_via_runner=None, running_entries=None, outside_runs=None,
                    missing=None, outside_links=None, plot_px=None):
    """Build a local graph and return a Plotly figure. Fully stateless.

    Args:
        circuit_nodes: list of dicts with 'name' and 'connected'
        import_map: dict {src: [dst, ...]}
        node_subdirs: dict {name: subdir_or_None}
        change_tags: dict {name: [tag_dicts]}
        entry_point: list of running script names
        runtime_loaded: set of runtime-loaded module names
        dataflows: list of dataflow dicts
        animation_tick: int for animation frame
        selected_dirs: list of selected dir names from dropdown
        watched_names: set of watched directory names
        scanned_dirs: set of top-level dir names that hold live (non-whitelisted)
            source; every other dir is drawn in the whitelisted colour. None =
            unknown, every dir is drawn as scanned.
        runtime_via_runner: Item 10 — node names a test RUNNER's record proves imported
            (hash-verified): drawn with a 3-px amber ring and the hover "executed via
            <runner> — proxy, not the app"; green reached this way is a warning, never a pass.
        running_entries: Item 10 — [{script, pid, runner, test_path, test_files}] alive
            wrapper entries. An app entry puts the inverted triangle over its script; a
            runner entry puts it over THE FILE THE RUNNER IS RUN ON (owner 2026-09-15) when
            that is one file — several files under test are LISTED in the field below the
            graph, never drawn.
        outside_runs: M-48 / C (owner 2026-10-06) — the daemon's `outside_runs`: target runs seen in the
            process table, not started by the wrapper. A HOLLOW amber triangle over the node (or its
            collapsed folder), hover "running outside CodeRadar — seen, not proof"; never green.
        plot_px: P4 (B2) — the plot area the dash last drew, [width, height] px (`graph-size`);
            the labels and boxes are sized for it. None = the nominal 1347 x 740 (`_PLOT_PX`).
    """
    _blank = dict(paper_bgcolor='#1a1a1a', plot_bgcolor='#1a1a1a',
                  font=dict(color='#6b7280', size=12),
                  margin=dict(l=20, r=20, t=30, b=20), height=700)

    if not circuit_nodes:
        logger.debug("figure: no nodes — blank")
        fig = go.Figure()
        fig.update_layout(**_blank)
        return fig, {}

    # M-53 (owner 2026-10-06): "dir's should be boxes - scripts circles - that's it - the dir's should be a
    # diff color than the nodes - but otherwise treated the same way". An out-of-view folder is a real folder
    # node (the root view's 📁 kind): on the same shape, labelled, clickable to drill, and joined to the files
    # it links with ordinary edges coloured by the same live / possible / broken rule. The 09-29 edge boxes
    # and their arrows are gone.
    if outside_links:
        drawn = {nd.get('name') for nd in circuit_nodes}
        import_map = {k: list(v) for k, v in (import_map or {}).items()}
        added = set()
        for src, dst, fnode in outside_edges(outside_links, drawn):
            if fnode not in drawn and fnode not in added:
                circuit_nodes = list(circuit_nodes) + [{'name': fnode, 'connected': True}]
                added.add(fnode)
            if dst not in import_map.setdefault(src, []):
                import_map[src].append(dst)
        outside_links = None

    # Build local graph
    g = nx.DiGraph()
    for nd in circuit_nodes:
        name = nd.get('name', '')
        conn = nd.get('connected')
        status = 'success' if conn is True else ('failed' if conn is False else 'pending')
        g.add_node(name, status=status)

    if import_map:
        for src, dsts in import_map.items():
            for dst in dsts:
                if src in g and dst in g:
                    g.add_edge(src, dst)

    # Severed edges: imports that existed before but were removed.
    # Add them back into the graph so they render as red.
    _severed_edge_set = set()
    if severed_edges:
        for src, dst in severed_edges:
            if src in g and dst in g:
                g.add_edge(src, dst)
                _severed_edge_set.add((src, dst))

    # owner 2026-09-29: an import that resolves nowhere is a BROKEN connection — to a marker node named
    # after the missing module. `lazy` (inside a function) = broken when called: red-orange.
    _missing_edges: Dict[tuple, bool] = {}
    for m in missing or []:
        src, mark = m.get('src'), MISSING_MARK + str(m.get('module'))
        if src in g:
            g.add_node(mark, status='missing')
            g.add_edge(src, mark)
            _missing_edges[(src, mark)] = bool(m.get('lazy'))

    graph_nodes = list(g.nodes())
    graph_edges = list(g.edges())
    statuses = {n: g.nodes[n].get('status', 'pending') for n in graph_nodes}
    logger.debug("figure: %d nodes, %d edges", len(graph_nodes), len(graph_edges))

    # Layout — sort by (subdir, name) so same-dir nodes are adjacent
    nodes = sorted(graph_nodes, key=lambda n: (node_subdirs.get(n) or '~', n))

    def _depth(n):
        if n.startswith('\U0001f4c1'):
            return 1 + n.count('/')                    # a folded folder: its path's depth (M-65)
        sub = node_subdirs.get(n)
        return 0 if not sub else 2 + str(sub).count('/')

    # owner 2026-09-29: ONE ring for every node (was concentric rings by depth, 2026-09-05) — root files
    # sat inside the folder ring. The (subdir, name) order above already keeps each folder contiguous.
    # M-53 (owner 2026-10-06): "anything that's not whitelisted out should be counted as a node and then
    # formed into the shape that their sum requires" — the out-of-view folders are nodes now (above), so the
    # ONE shape below already counts them: 1 a node, 2 a segment, 3 a triangle, 4 a square, 5+ a ring.
    pos, view_range = _ring_positions(nodes)

    # Init
    change_tags = change_tags or {}
    running_scripts = entry_point if isinstance(entry_point, list) else ([entry_point] if entry_point else [])
    runtime_loaded = set(runtime_loaded or set())
    # owner 2026-09-29: a script carrying a current dataflow ran (lsof proof) — its node and lines go green
    for _df in dataflows or []:
        for _n in (_df.get('src'), _df.get('dst')):
            if _n:
                runtime_loaded.update({_n, _n + '.py'})
    via_runner = set(runtime_via_runner or ())   # Item 10

    _selected = set(selected_dirs or [])
    _view = next((str(v) for v in (selected_dirs or []) if v), '')   # M-65: the folder path looked at
    watched_set = set(watched_names or [])
    watchlist_active = bool(watched_set)

    # Dir colours — owner ruling 2026-09-05: exactly two. Every scanned folder
    # = SCANNED_DIR_COLOR; every other folder (whitelisted: artifacts + detritus,
    # still visible) = WHITELISTED_DIR_COLOR. No per-directory shades.
    _scanned = set(scanned_dirs) if scanned_dirs is not None else set(watched_set)
    dir_colors = {}
    if watchlist_active:
        for d in sorted(watched_set):
            dir_colors[d] = SCANNED_DIR_COLOR if d in _scanned else WHITELISTED_DIR_COLOR

    _color_idx = [0]  # mutable counter for cycling shades

    # Red = a LIVE link that dropped (plan item 10 / owner ruling 2026-09-05):
    # only edges the caller reports as severed (live in the previous poll of
    # this scope, not live now) — never a depth change, never a link that was
    # merely potential. A failed endpoint on a never-live edge stays indigo;
    # its failure is reported by the circuit's syntax / import panels.
    _severed_nodes: set[str] = set()
    if severed_edges:
        for src, dst in severed_edges:
            _severed_nodes.add(src)
            _severed_nodes.add(dst)

    # owner 2026-09-29: both ends of a line wear its state — a broken line makes both nodes red, a
    # broken-when-called line both dark orange; the worst state a node touches wins (red > dark orange >
    # green > its own colour). The missing-module marker is an ordinary node in that colour.
    _broken_nodes = {x for (a, b), lz in _missing_edges.items() if not lz for x in (a, b)}
    _called_nodes = {x for (a, b), lz in _missing_edges.items() if lz for x in (a, b)}

    def _color(node):
        if node in _severed_nodes or node in _broken_nodes:
            return '#ef4444'
        if node in _called_nodes:
            return BROKEN_WHEN_CALLED
        # Folder nodes (📁prefix) — get their dir's blue shade
        if node.startswith('\U0001f4c1'):
            dir_name = node.replace('\U0001f4c1', '').strip()
            # F-DASH-DEPTH (2026-09-05): executed proof is not limited to the
            # current depth — a collapsed folder holding a module that ran
            # (SHA256-verified import) lights green like the module would.
            if any(isinstance(r, str) and r.startswith(dir_name + '/') for r in runtime_loaded):
                return '#22c55e'
            if dir_name in dir_colors:
                return dir_colors[dir_name]
            return SCANNED_DIR_COLOR if dir_name in _scanned else WHITELISTED_DIR_COLOR

        # Non-Python files — handled separately (split circle)
        if any(node.endswith(e) for e in NON_PY_EXTS):
            c = PINK_SHADES[_color_idx[0] % len(PINK_SHADES)]
            _color_idx[0] += 1
            return c

        # Script node coloring: red > green > blue
        # Red: on a severed connection (this node or its peer failed)
        if node in _severed_nodes:
            return '#ef4444'

        # Green: live connection recorded by monitor — or reached through a test runner (Item 10:
        # then the amber ring + hover mark it a warning, never a pass)
        if node in runtime_loaded or node in via_runner:
            return '#22c55e'

        # Indigo: statically connected / no live connection seen yet. Owner
        # ruling 2026-09-05: node colours are indigo / green / red — never a
        # per-directory shade.
        return NODE_INDIGO

    fig = go.Figure()

    # --- Edges ---
    # Three states:
    #   peach-orange = "potential connection"  (import exists, never seen live)
    #   green        = "live connection"       (live connection detected — permanent)
    #   red          = "severed"               (potential or live segment broken — endpoint failed)
    # Dataflow (blue) is an overlay on top; when dataflow stops, segment returns to green.
    #   teal         = "live via tests"        (I-198: a library — no app-loaded node at all — whose
    #                                            both ends the test runner loaded; never green)
    green_x, green_y = [], []
    red_x, red_y = [], []
    possible_x, possible_y = [], []
    tests_x, tests_y = [], []
    _library = not runtime_loaded

    def _ran(n: str) -> bool:
        """A file node ran if its own path was recorded; a collapsed folder ran if any module under it
        did (owner 2026-09-29: folder lines never went green — the test was by node name only)."""
        if n in runtime_loaded:
            return True
        if n.startswith('\U0001f4c1'):
            dn = n.replace('\U0001f4c1', '').strip()
            return any(isinstance(r, str) and r.startswith(dn + '/') for r in runtime_loaded)
        return False

    miss_x: list = []
    miss_y: list = []
    lazy_x: list = []
    lazy_y: list = []
    for s, d in graph_edges:
        if (s, d) in _missing_edges:
            xs_, ys_ = (lazy_x, lazy_y) if _missing_edges[(s, d)] else (miss_x, miss_y)
            xs_ += [pos[s][0], pos[d][0], None]
            ys_ += [pos[s][1], pos[d][1], None]
            continue
        if s not in pos or d not in pos:
            continue
        x0, y0 = pos[s]
        x1, y1 = pos[d]
        ss, ds = statuses.get(s, 'pending'), statuses.get(d, 'pending')
        severed = (s, d) in _severed_edge_set          # live link dropped (item 10)
        ever_live = _ran(s) and _ran(d)
        if severed:
            # Endpoint broken — red regardless of potential or live
            red_x.extend([x0, x1, None]); red_y.extend([y0, y1, None])
        elif ever_live:
            # Live connection detected — green forever after
            green_x.extend([x0, x1, None]); green_y.extend([y0, y1, None])
        elif _library and s in via_runner and d in via_runner:
            # I-198: the tests' proof on a library — its own colour, never green
            tests_x.extend([x0, x1, None]); tests_y.extend([y0, y1, None])
        else:
            # Import exists but never seen live — potential (peach-orange)
            possible_x.extend([x0, x1, None]); possible_y.extend([y0, y1, None])

    # Draw order: potential (behind) → live via tests → green → red (on top)
    INDIGO = '#6366f1'  # match node color for potential connections
    # S5 2026-09-29: every decorative trace (edge lines, flow lines, arrow heads, half-circle fills) is
    # hoverinfo 'skip', not 'none' — 'none' hides the label but the trace still takes hovers and clicks, and
    # an edge ends at a node's centre, so a click on a folder node hit the line and never drilled
    for xs, ys, c, w in [
        (possible_x, possible_y, INDIGO, 2),
        (tests_x, tests_y, TESTS_TEAL, 3),
        (green_x, green_y, '#10b981', 3),
        (red_x, red_y, '#ef4444', 3),
        (miss_x, miss_y, '#ef4444', 3),
        (lazy_x, lazy_y, BROKEN_WHEN_CALLED, 3),
    ]:
        if xs:
            fig.add_trace(go.Scatter(x=xs, y=ys, line=dict(width=w, color=c),
                                      mode='lines', hoverinfo='skip', showlegend=False))

    # --- Dataflow overlay ---
    # Item 10: a runner's import flow (proof "runner") is drawn AMBER and DASHED, its arrows amber —
    # the graph shows where pytest runs, in the warning colour, never in the live-connection blue.
    _runner_flows = [df for df in (dataflows or []) if df.get('proof') == 'runner']
    dataflows = [df for df in (dataflows or []) if df.get('proof') != 'runner']
    if _runner_flows:
        _rx, _ry = [], []
        for df in _runner_flows:
            if df['src'] in pos and df['dst'] in pos:
                x0, y0 = pos[df['src']]; x1, y1 = pos[df['dst']]
                _rx.extend([x0, x1, None]); _ry.extend([y0, y1, None])
        if _rx:
            fig.add_trace(go.Scatter(x=_rx, y=_ry, line=dict(width=3, color='#f59e0b', dash='dash'),
                                      mode='lines', hoverinfo='skip', showlegend=False))
        _add_flow_arrows(fig, _runner_flows, pos, animation_tick=animation_tick, marker_size=9, color='#f59e0b')
    if dataflows:
        flow_set = _build_flow_edge_set(dataflows)
        flow_x, flow_y = [], []
        for s, d in graph_edges:
            if s not in pos or d not in pos:
                continue
            if (s, d) in flow_set or (d, s) in flow_set:
                x0, y0 = pos[s]; x1, y1 = pos[d]
                flow_x.extend([x0, x1, None]); flow_y.extend([y0, y1, None])
        edge_set = {(s, d) for s, d in graph_edges} | {(d, s) for s, d in graph_edges}
        for df in dataflows:
            src, dst = df['src'], df['dst']
            if src in pos and dst in pos and (src, dst) not in edge_set and (dst, src) not in edge_set:
                x0, y0 = pos[src]; x1, y1 = pos[dst]
                flow_x.extend([x0, x1, None]); flow_y.extend([y0, y1, None])
        if flow_x:
            fig.add_trace(go.Scatter(x=flow_x, y=flow_y, line=dict(width=3, color=ELECTRIC_BLUE),
                                      mode='lines', hoverinfo='skip', showlegend=False))
        _add_flow_arrows(fig, dataflows, pos, animation_tick=animation_tick)

    # --- Nodes ---
    _marks = [n for n in nodes if n.startswith(MISSING_MARK) and n in pos]
    if _marks:
        def _mhover(n):
            parts = []
            for (a, b), v in _missing_edges.items():
                if b != n:
                    continue
                ln = next((m.get('line') for m in (missing or [])
                           if m.get('src') == a and MISSING_MARK + str(m.get('module')) == n), '?')
                parts.append(f"{a} L{ln} ({'only when called' if v else 'on load'})")
            return f"missing module {n[len(MISSING_MARK):]} — imported by " + ', '.join(parts)
        # owner 2026-09-29: the missing module is drawn like any other node, in its line's colour
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in _marks], y=[pos[n][1] for n in _marks], mode='markers',
            marker=dict(size=30, color=[_color(n) for n in _marks], line=dict(width=2, color='white')),
            text=[n[len(MISSING_MARK):] for n in _marks],
            hovertext=[_mhover(n) for n in _marks],
            hovertemplate='%{hovertext}<extra></extra>', showlegend=False))
    _all_regular = [n for n in nodes if not n.startswith('\U0001f4c1') and not n.startswith(MISSING_MARK) and n in pos]
    subdirs_list = [n for n in nodes if n.startswith('\U0001f4c1') and n in pos]

    def _dir_colour(n):
        """M-53: a folder node's fixed colour — scanned / whitelisted, never its links' state."""
        return dir_colors.get(n[len(FOLDER):].strip(), SCANNED_DIR_COLOR)

    # Split regular into Python scripts vs non-Python files
    _is_non_py = lambda n: any(n.endswith(e) for e in NON_PY_EXTS)
    regular = [n for n in _all_regular if not _is_non_py(n)]
    non_py = [n for n in _all_regular if _is_non_py(n)]

    # Dataflow border detection (shared by both groups)
    df_names = set()
    if dataflows:
        for df in dataflows:
            df_names.add(df['src']); df_names.add(df['dst'])

    if regular:
        # owner 2026-10-07 04:15: the search hit is filled amber, not only its label
        colors = ['#f59e0b' if n == highlight_node else _color(n) for n in regular]
        # Item 10: a node a runner reached wears a 3-px AMBER ring (a warning); the dataflow blue and the
        # plain white border are the other two states.
        borders = ['#f59e0b' if n in via_runner else (ELECTRIC_BLUE if n in df_names else 'white') for n in regular]
        widths = [3 if n in via_runner else 2 for n in regular]
        _rn = ', '.join(sorted({e.get('runner') for e in (running_entries or []) if e.get('runner')})) or 'a test runner'
        hovers = [f"{n} — executed via {_rn} (proxy, not the app)" if n in via_runner else n for n in regular]
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in regular], y=[pos[n][1] for n in regular],
            mode='markers',
            marker=dict(size=30, color=colors, line=dict(width=widths, color=borders)),
            text=regular,
            hovertext=hovers, hovertemplate='%{hovertext}<extra></extra>', showlegend=False))

    # Non-Python files: split circle — left half pink, right half parent dir color.
    # Root-level (no parent dir) = pure pink circle.
    # SVG paths for left and right semicircles (radius=1 unit circle)
    _LEFT_HALF = 'M 0,-1 A 1,1 0 0,0 0,1 L 0,0 Z'
    _RIGHT_HALF = 'M 0,-1 A 1,1 0 0,1 0,1 L 0,0 Z'
    if non_py:
        # Determine which have a parent dir (depth 1+) vs root (depth 0)
        root_non_py = [n for n in non_py if not node_subdirs.get(n)]
        deep_non_py = [n for n in non_py if node_subdirs.get(n)]

        # Root-level non-Python: pure pink circle
        if root_non_py:
            fig.add_trace(go.Scatter(
                x=[pos[n][0] for n in root_non_py], y=[pos[n][1] for n in root_non_py],
                mode='markers',
                marker=dict(size=30, color=DARK_PINK, line=dict(width=2, color='white')),
                text=root_non_py,
                hovertemplate='%{text}<extra></extra>', showlegend=False))

        # Depth 1+ non-Python: split circle (pink left, parent-dir-blue right)
        if deep_non_py:
            # Left half — pink
            fig.add_trace(go.Scatter(
                x=[pos[n][0] for n in deep_non_py], y=[pos[n][1] for n in deep_non_py],
                mode='markers',
                marker=dict(symbol='path://' + _LEFT_HALF, size=30,
                            color=DARK_PINK, line=dict(width=0)),
                hoverinfo='skip', showlegend=False))
            # Right half — parent dir's blue shade
            right_colors = [dir_colors.get(node_subdirs[n], WHITELISTED_DIR_COLOR) for n in deep_non_py]
            fig.add_trace(go.Scatter(
                x=[pos[n][0] for n in deep_non_py], y=[pos[n][1] for n in deep_non_py],
                mode='markers',
                marker=dict(symbol='path://' + _RIGHT_HALF, size=30,
                            color=right_colors, line=dict(width=0)),
                text=deep_non_py,
                hovertemplate='%{text}<extra></extra>', showlegend=False))

    if subdirs_list:
        # M-53 (owner 2026-10-06): "the dir's should be a diff color than the nodes" — a folder box wears its
        # folder colour (scanned / whitelisted, as the legend says); its LINKS carry live / possible / broken.
        sub_colors = ['#f59e0b' if n == highlight_node else _dir_colour(n) for n in subdirs_list]   # 04:15 search hit
        sub_labels = [n.replace('\U0001f4c1', '') + '/' for n in subdirs_list]
        # Item 10: a collapsed folder holding a module a RUNNER reached wears the amber ring, as the folder
        # lights green for a module the app ran (F-DASH-DEPTH) — the warning follows the collapse.
        def _folder_via_runner(n):
            d = n.replace('\U0001f4c1', '').strip()
            return any(isinstance(r, str) and r.startswith(d + '/') for r in via_runner)
        sub_widths = [3 if _folder_via_runner(n) else 0 for n in subdirs_list]
        sub_borders = ['#f59e0b' if _folder_via_runner(n) else 'rgba(0,0,0,0)' for n in subdirs_list]
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in subdirs_list], y=[pos[n][1] for n in subdirs_list],
            mode='markers',
            marker=dict(symbol='square', size=_FOLDER_PX,   # owner 2026-10-06: same visual weight as a 30-px circle
                        color=sub_colors,
                        line=dict(width=sub_widths, color=sub_borders)),
            text=sub_labels,
            hovertemplate='%{text}<extra></extra>', showlegend=False, customdata=subdirs_list))

    # The labels' text and size; they are drawn under their nodes and the view fitted to them at the end.
    _texts = _ring_texts(list(pos), _view)

    # --- Seen-only runs (M-48 / C, owner 2026-10-06: "nothing detected as running though pong running the
    # entire time" — the chip line alone was off-screen). Hollow = a process-table sighting; the solid
    # triangle below stays the wrapper's / a dataflow's proof. Nothing here turns a node or link green.
    for _r in (outside_runs or []):
        _node = str((_r or {}).get('node') or '')
        _at = drawn_for(_node, pos) if _node else None
        if not _node or _at not in pos:
            continue
        x, y = pos[_at]
        # owner 2026-10-06 ("the inverted triangle isn't attached to its node"): pinned in PIXELS just above
        # the node's top edge — a data-unit offset drifted off as the shapes grew
        fig.add_annotation(
            x=x, y=y, xref='x', yref='y', text='\u25bd', showarrow=False, yanchor='bottom',
            yshift=(_FOLDER_PX / 2 + 2 if _at != _node else 17), font=dict(size=20, color='#f59e0b'),
            hovertext=(f"{_node} — running outside CodeRadar (pid {_r.get('pid')}, {_r.get('how')}): "
                       "seen, not proof — its links are not lit"))

    # --- Running script indicators ---
    # Item 10 (owner 2026-09-15): a RUNNER's triangle sits above the file it is run on — one file; several
    # files under test are listed as text in the field below the graph, never drawn.
    _runner_targets = []
    for _e in (running_entries or []):
        if not _e.get('runner'):
            continue
        _files = list(_e.get('test_files') or [])
        _tp = _e.get('test_path') or ''
        if _tp.endswith('.py'):
            _runner_targets.append(_tp)
        elif len(_files) == 1:
            _runner_targets.append(_files[0])
    # owner 2026-09-29: every node carrying a CURRENT dataflow is running — lsof saw that process hold the
    # pipe / socket, the same proof of execution as the wrapper's own record. Its triangle shows and it
    # counts as run (green). A bare process-table sighting still never does (Plan item 8, 2026-09-05).
    _flow_ends = [n for df in (dataflows or []) for n in (df.get('src'), df.get('dst')) if n]
    for ep in list(dict.fromkeys(list(running_scripts) + _flow_ends)) + _runner_targets:
        ep_name = ep.replace('.py', '')
        placed = False
        for node in nodes:
            node_bare = node.replace('.py', '')
            node_tail = node_bare.split('/')[-1]
            if node_bare == ep_name or node_tail == ep_name:
                if node in pos:
                    x, y = pos[node]
                    fig.add_trace(go.Scatter(
                        x=[x], y=[y + 0.25], mode='markers',
                        marker=dict(symbol='triangle-down', size=16, color='#f59e0b',
                                    line=dict(width=1, color='white')),
                        hovertext=(f'{node} (under test)' if ep in _runner_targets else f'{node} (running)'),
                        hovertemplate='%{hovertext}<extra></extra>', showlegend=False))
                    placed = True
                break
        # Item 10: the file sits in a COLLAPSED folder at this depth — the triangle sits above that folder
        # (the folder is the file's representative here, as its green is), hover names the file.
        if not placed and '/' in ep_name:
            _d = ep_name.split('/')[0]
            folder = next((f for f in ('\U0001f4c1' + _d, '\U0001f4c1 ' + _d) if f in pos), None)
            if folder is not None:
                x, y = pos[folder]
                fig.add_trace(go.Scatter(
                    x=[x], y=[y + 0.3], mode='markers',
                    marker=dict(symbol='triangle-down', size=16, color='#f59e0b',
                                line=dict(width=1, color='white')),
                    hovertext=(f'{ep} (under test — inside {ep_name.split("/")[0]}/)' if ep in _runner_targets
                               else f'{ep} (running — inside {ep_name.split("/")[0]}/)'),
                    hovertemplate='%{hovertext}<extra></extra>', showlegend=False))

    # --- Change tags ---
    _tx, _ty, _tc, _tt, _th = [], [], [], [], []
    for node in regular:
        x, y = pos[node]
        tags = change_tags.get(node, [])
        for si in range(3):
            _tx.append(x); _ty.append(y - _BADGE_TOP - si * _BADGE_STEP)
            has = si < len(tags)
            _tc.append('rgba(245,158,11,0.6)' if has else 'rgba(74,74,74,0.4)')
            if has:
                txt = tags[si].get('lines', '')
                _tt.append(txt[:8] + '..' if len(txt) > 10 else txt)
                _th.append(f"{txt}\n{tags[si].get('timestamp', '')}")
            else:
                _tt.append(''); _th.append('empty')
    if _tx:
        fig.add_trace(go.Scatter(
            x=_tx, y=_ty, mode='markers+text',
            marker=dict(symbol='square', size=18, color=_tc,
                        line=dict(width=1, color='rgba(102,102,102,0.5)')),
            text=_tt, textposition='middle center',
            textfont=dict(color='#fff', size=6),
            hovertext=_th, hovertemplate='%{hovertext}<extra></extra>', showlegend=False))

    # --- Legend ---
    # Edge legend (always shown)
    edge_parts = [
        '<b style="color:#6366f1">―</b> possible',
        '<b style="color:#10b981">―</b> live',
        '<b style="color:#ef4444">―</b> broken',
        f'<b style="color:{BROKEN_WHEN_CALLED}">―</b> broken when called',
    ]
    if tests_x:   # I-198: only on a library whose tests lit an edge — an app's legend is unchanged
        edge_parts.insert(2, f'<b style="color:{TESTS_TEAL}">―</b> live via tests')
    # FIX_40 / I-51 (owner 2026-09-15): both legend lines sit INSIDE the panel — anchored to the plot's edge and
    # placed in a margin sized for them (paper y=0 / y=1 with yanchor, margin t=b=LEGEND_MARGIN_PX); the old
    # y=-0.03 / y=1.02 with a 5-10 px margin put them half outside the panel (clipped under "Find script…").
    fig.add_annotation(text='   '.join(edge_parts), xref='paper', yref='paper',
                       x=0.5, y=0, yanchor='top', yshift=-4, showarrow=False,
                       font=dict(size=10, color='#9ca3af'))
    # Dir legend (when watchlist active)
    if dir_colors:
        _n_scanned = sum(1 for c in dir_colors.values() if c == SCANNED_DIR_COLOR)
        parts = [f'<b style="color:{SCANNED_DIR_COLOR}">■</b> scanned dir ({_n_scanned})',
                 f'<b style="color:{WHITELISTED_DIR_COLOR}">■</b> dir set aside, not scanned ({len(dir_colors) - _n_scanned})',
                 f'<b style="color:{DARK_PINK}">●</b> root']
        # owner 2026-09-28: left-anchored — centred, it ran under the graph toolbar at the top right
        fig.add_annotation(text='   '.join(parts), xref='paper', yref='paper',
                           x=0, xanchor='left', y=1, yanchor='bottom', yshift=4, showarrow=False,
                           font=dict(size=10, color='#9ca3af'))

    # P4 (B4): the labels are annotations (px offsets from their node — a zoom spreads them apart, never packs
    # them tighter). The search-highlighted node's label is amber; a folder's is its folder colour. The trace
    # points keep their text, so hover and click (a folder's '/'-ending text) are unchanged.
    # (one layout update for them all: an add_annotation per label cost ~2 ms each on a 57-node ring)
    # owner 2026-10-06: "put the titles below the node" — every label is centred under its node (under the
    # badges, for a file), and the view is fitted and centred on everything drawn, labels included.
    _ring_notes, _label_boxes = [], []
    _badged = set(regular)
    # owner 2026-10-07 01:10 ("oddly zooms in automatically — should just start centered"): the view's frame is
    # the air frame below — four unseen corner points a third beyond the farthest node — so its scale is known
    # here: px per data unit = the field's width over the frame's width. Nothing of the page is guessed beyond
    # the field size the page itself reported (plot_px).
    # a single node sits at the origin: the frame is never narrower than a unit (01:38: a one-folder root
    # view divided by a zero reach — ZeroDivisionError, no graph)
    # M-65 rule 4: the frame is ~1.1x the drawing's own reach — no unit floor (a 4-box square reached 0.64 inside a
    # frame of 1.0: the owner's 'a lot more space to use'); a lone node at the origin keeps a small frame (01:38's
    # ZeroDivisionError)
    _reach = max([max(abs(x), abs(y)) for x, y in pos.values()] + [0.4]) * 1.1
    _pw, _ph = _plot_size(plot_px)
    _ux, _uy = 2 * _reach / _pw, 2 * _reach / _ph           # data units per px, x and y
    # owner 2026-10-07 01:11 ("labels need to respect the bounds of the circuit-graph's field"): a label centred
    # under a node near the field's edge ran past it. A label that would cross the field's left or right edge is
    # shifted inward by exactly the overflow (still centred otherwise) — never farther, so neighbours' labels
    # keep their distance and no label is flipped above its node for want of width ("box is uneven", 01:15).
    _half_field = _pw / 2 - 4
    _max_hang = 0.0
    for n in pos:
        if n not in _texts:
            continue
        text, font, r_px = _texts[n]
        colour = ('#f59e0b' if n == highlight_node else
                  _dir_colour(n) if n.startswith('\U0001f4c1') else '#e6edf3')   # M-53: a folder's label = its box
        x, y = pos[n]
        y_at, gap_px = (y - _BADGE_FOOT, _BADGE_HALF_PX + 3) if n in _badged else (y, r_px + 3)
        lines = _wrap_label(text)                            # M-58: wrapped at underscores
        w_px = max(len(l) for l in lines) * _CHAR_PX * font / 11
        h_px = gap_px + len(lines) * font * 1.25 + 4
        _node_px = x / _ux                                   # the node's px offset from the field's centre
        _over_r = _node_px + w_px / 2 - _half_field
        _over_l = -_node_px + w_px / 2 - _half_field
        xshift = -_over_r if _over_r > 0 else _over_l if _over_l > 0 else 0
        _ring_notes.append(dict(x=x, y=y_at, xref='x', yref='y', text='<br>'.join(lines), showarrow=False,
                                xanchor='center', xshift=xshift, yanchor='top', yshift=-gap_px, borderpad=0,
                                align='center', font=dict(size=font, color=colour)))
        _label_boxes.append((x + xshift * _ux, y_at, w_px, h_px))              # the box where the label sits
        _max_hang = max(_max_hang, (y - y_at) / _uy + h_px)                    # px the label hangs below its node
    # a label that would sit on one already placed goes ABOVE its node instead (dense views: 8+ items)
    _flip_crowded_labels(_ring_notes, _label_boxes, pos, _texts, view_range, _plot_size(plot_px))
    fig.update_layout(annotations=list(fig.layout.annotations) + _ring_notes)
    # owner 2026-10-06 ("maps still not centered"): Plotly fits the drawing itself (autorange, which pads
    # for marker sizes in pixels) at 1:1 so a square stays square; the labels get pixel margins, so nothing
    # depends on a guess of the plot's size — the old fit used the page's reported size and drifted.
    _m = _label_margins(_ring_notes, _label_boxes)
    # the air frame (01:10): autorange fitted the drawing edge to edge, which read as a zoom-in. Four unseen
    # corner points, a third beyond the farthest node, give the fit a frame of air on every side — the drawing
    # opens centred at about three quarters of the field; a drill-in and Reverse1 open the same way (the corners
    # sit in the view's own fit, not in a zoom). The bottom corners sit lower by the labels' hang, so the nodes
    # AND their labels are what is centred — not the nodes alone with the labels eating the bottom air.
    _floor = -_reach - _max_hang * _uy
    fig.add_trace(go.Scatter(x=[-_reach, _reach, _reach, -_reach], y=[_floor, _floor, _reach, _reach],
                             mode='markers', marker=dict(size=1, opacity=0), hoverinfo='skip',
                             showlegend=False, name='_air'))

    fig.update_layout(
        showlegend=False, paper_bgcolor='#1a1a1a', plot_bgcolor='#111',
        font=dict(color='#e6edf3', size=12),
        # uirevision keeps the user's zoom/pan across the refresh ticks of ONE view (Plotly reacts in place, no
        # flash). S5b (owner 2026-09-29): it is the view's key — selected folders + depth — so every drill-in
        # and every Reverse1 opens unzoomed at the range below (was the constant 'circuit-zoom', which carried
        # a zoom into the next view). Health FIX_40 checks: stable across ticks, new on a dirs/depth change.
        uirevision=_view_key(selected_dirs, subdirs_list, [_depth(n) for n in nodes]),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                   showline=False, autorange=True, constrain='domain'),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                   showline=False, autorange=True, scaleanchor='x', scaleratio=1, constrain='domain'),
        dragmode='zoom',
        margin=dict(l=5 + _m['l'], r=5 + _m['r'], t=LEGEND_MARGIN_PX + _m['t'],
                    b=LEGEND_MARGIN_PX + _m['b']))   # FIX_40 / I-51
    # Return node positions alongside figure for search/zoom
    node_positions = {name: [float(x), float(y)] for name, (x, y) in pos.items()}
    return fig, node_positions


# =============================================================================
# Helpers
# =============================================================================

def _is_pid_alive(pid):
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


_LSTART_MATCH_S = 2.0   # FIX_20: a reused PID fails the start-time match beyond this


def _ps_field(pid, field):
    """One `ps -o <field>= -p PID` value, '' when ps cannot answer (no such process, no ps)."""
    try:
        out = subprocess.run(["ps", "-o", f"{field}=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.strip()


def _lstart_epoch(text):
    """`ps -o lstart=` ("Tue Sep 15 11:45:04 2026") as epoch seconds; None when unparseable."""
    from datetime import datetime as _dt
    for fmt in ("%a %b %d %H:%M:%S %Y", "%a %d %b %H:%M:%S %Y"):
        try:
            return _dt.strptime(" ".join(text.split()), fmt).timestamp()
        except ValueError:
            continue
    return None


def _wrapper_start_epoch(text):
    """The wrapper's `start_time` (datetime.now().isoformat()) as epoch seconds; None when unparseable."""
    from datetime import datetime as _dt
    try:
        return _dt.fromisoformat(str(text)).timestamp()
    except (TypeError, ValueError):
        return None


def running_entries(running_state_file, repo_path=None):
    """FIX_20 (2026-09-15): the wrapper entries of running.json that are ALIVE — one definition of
    "the app is executing" for the running label and the figure's entry triangle.

    Alive = the PID answers `kill 0` AND `ps -o stat=` does not start with `Z` (a zombie is not
    running) AND `ps -o lstart=` equals the entry's `start_time` within _LSTART_MATCH_S (a PID
    reused by another process fails the match). Entries the wrapper did not write (`source` !=
    "wrapper") and dead entries are ignored; the wrapper's own cleanup of running.json stays as is.
    Returns [{script, pid, start_time}] in file order; [] when the file is absent or unreadable.
    repo_path is accepted for signature symmetry with get_entry_point_from_proof."""
    entries = []
    if not running_state_file.exists():
        return entries
    try:
        with open(running_state_file) as f:
            state = json.load(f)
    except Exception:
        return entries
    if isinstance(state, dict) and 'script' in state and 'pid' in state:
        state = {str(state['pid']): state}
    for _pid_str, info in (state or {}).items():
        if not isinstance(info, dict) or info.get('source', 'wrapper') != 'wrapper':
            continue
        script, pid = info.get('script'), info.get('pid')
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        if not script or not _is_pid_alive(pid):
            continue
        if _ps_field(pid, "stat").startswith("Z"):
            continue
        started, recorded = _lstart_epoch(_ps_field(pid, "lstart")), _wrapper_start_epoch(info.get('start_time'))
        if started is None or recorded is None or abs(started - recorded) > _LSTART_MATCH_S:
            continue
        entries.append({"script": script, "pid": pid, "start_time": info.get('start_time'),
                        "runner": info.get('runner'), "test_path": info.get('test_path')})   # Item 10
    return entries


def get_entry_point_from_proof(running_state_file, monitored_names=None, repo_path=None):
    """Scripts currently EXECUTING under entry_point_wrapper.py (PID alive).

    Plan item 8 (2026-09-05): the inverted triangle means executed — its only
    source is running.json entries the wrapper wrote (source == "wrapper").
    Daemon / process-scan entries and the old `ps` fallback are gone: a proof
    harness or a runner with a write handle on a file is not "the app running".
    monitored_names / repo_path are accepted for signature compatibility.
    FIX_20 (2026-09-15): liveness is running_entries() — stat + lstart checked, one definition.
    """
    # Item 10: a runner's entry is not "the app running" — its triangle sits over the file under test (generate_figure)
    return [e["script"].replace('.py', '') for e in running_entries(running_state_file, repo_path) if not e.get("runner")]


# System scripts to exclude from fallback ps scan
_DASHBOARD_SYSTEM_SCRIPTS = {
    'circuit_daemon', 'proof_dashboard',
    'ast_scanner', 'integration_dashboard', 'kernel_trace_daemon',
    'electricity',
}


def _ps_scan_running(monitored_names, repo_path=None):
    """Lightweight ps scan fallback for detecting running scripts."""
    running = []
    own_pid = os.getpid()
    monitored_stems = {n.replace('.py', '') for n in monitored_names}

    try:
        result = subprocess.run(
            ['ps', '-axww', '-o', 'pid,command'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return running

        for line in result.stdout.strip().split('\n')[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid == own_pid:
                continue

            cmd = parts[1]
            if 'python' not in cmd.lower():
                continue

            for token in cmd.split():
                if not token.endswith('.py'):
                    continue
                stem = Path(token).stem
                if stem in _DASHBOARD_SYSTEM_SCRIPTS:
                    break
                if stem in monitored_stems:
                    # Optional: verify under repo if repo_path given
                    if repo_path and Path(token).is_absolute():
                        try:
                            Path(token).relative_to(repo_path)
                        except ValueError:
                            continue
                    running.append(stem)
                    break
    except Exception:
        pass

    return running


def get_watchlist_display(watchlist_scripts, state, max_depth):
    """Short text describing current view scope."""
    dirs = [s.replace('\U0001f4c1', '') for s in (watchlist_scripts or [])
            if isinstance(s, str) and s.startswith('\U0001f4c1')]
    if dirs:
        return f"{len(dirs)} dir{'s' if len(dirs) != 1 else ''}: {', '.join(dirs)}"
    if watchlist_scripts:
        return f"{len(watchlist_scripts)} script{'s' if len(watchlist_scripts) != 1 else ''}"
    try:
        seen = set()
        count = 0
        for n in (state or {}).get('nodes', []):
            rp = n.get('relative_path', n.get('name', ''))
            if max_depth is None or len(Path(rp).parts) <= max_depth:  # 2026-09-06: no default-4 cap
                count += 1
            else:
                sd = n.get('subdir')
                if sd and sd not in seen:
                    seen.add(sd)
                    count += 1
        return f"{count} scripts"
    except Exception:
        return "..."
